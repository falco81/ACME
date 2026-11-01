# -*- coding: utf-8 -*-
"""
AVM FRITZ!Box: the certificate of its pages (and of MyFRITZ!/remote access,
VPN) uploaded the way the box's own page does it - signed in with the
challenge-response of login_sid.lua (PBKDF2, FRITZ!OS 7.24+, or the old
MD5), then key + full chain posted to /cgi-bin/firmwarecfg.

    GET  /login_sid.lua?version=2               -> <Challenge>2$iter1$salt1$iter2$salt2
    POST /login_sid.lua?version=2   username, response            -> <SID>
    POST /cgi-bin/firmwarecfg   multipart: sid, BoxCertPassword, BoxCertImportFile
    GET  /login_sid.lua?logout=1&sid=<SID>

Rights: a FRITZ!Box user with "FRITZ!Box settings" (System → FRITZ!Box Users),
and two-factor confirmation off for that user's settings changes (a box
asking to press a button cannot be answered by acme).

Sources:
    https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_english_2021-05-03.pdf
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/fritzbox.sh
Uncertain: the box answers the upload with a page, not a status; it is
taken as done when the page speaks of the SSL certificate without an error
(as acme.sh does). Older FRITZ!OS takes RSA keys only.
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    multipart, form, text, served_fingerprint, fp_of)

NO_SID = '0000000000000000'


def pbkdf2_response(challenge, password):
    """The response to a "2$..." challenge (FRITZ!OS 7.24 and later)."""
    _, it1, salt1, it2, salt2 = challenge.split('$')
    h1 = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt1), int(it1))
    h2 = hashlib.pbkdf2_hmac('sha256', h1, bytes.fromhex(salt2), int(it2))
    return '%s$%s' % (salt2, h2.hex())


def md5_response(challenge, password):
    """The old response: md5 of "challenge-password" in UTF-16LE (chars above
    255 as '.')."""
    pw = ''.join(c if ord(c) < 256 else '.' for c in password)
    data = ('%s-%s' % (challenge, pw)).encode('utf-16-le')
    return '%s-%s' % (challenge, hashlib.md5(data).hexdigest())


class FritzBoxTarget(HttpTarget):
    kind = 'fritzbox'
    title = 'AVM FRITZ!Box'
    vendor = 'AVM'
    description = ('Uploads the certificate of the FRITZ!Box\'s pages (also used for MyFRITZ! '
                   'and VPN) the way its own page does it.')
    doc = 'targets.md'
    fields = http_fields(443, 'fritz.box') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = verify_fields()

    sid = None

    def login(self):
        st, hd, raw = self.req('GET', '/login_sid.lua?version=2', what='asking for a challenge',
                               headers={'Accept': 'text/xml'})
        x = text(raw)
        ch = re.search(r'<Challenge>([^<]*)</Challenge>', x)
        if not ch:
            raise PluginError('the FRITZ!Box gave no challenge (is it a FRITZ!Box?)', retry=False)
        c = ch.group(1)
        pw = text(self.c('password'))
        resp = pbkdf2_response(c, pw) if c.startswith('2$') else md5_response(c, pw)
        st, hd, raw = self.req('POST', '/login_sid.lua?version=2',
                               form({'username': self.c('user'), 'response': resp}),
                               {'Content-Type': 'application/x-www-form-urlencoded',
                                'Accept': 'text/xml'}, what='signing in')
        m = re.search(r'<SID>([0-9a-f]+)</SID>', text(raw))
        if not m or m.group(1) == NO_SID:
            block = re.search(r'<BlockTime>(\d+)</BlockTime>', text(raw))
            raise PluginError('the FRITZ!Box does not let acme in: wrong user or password%s'
                              % (' (it blocks sign-ins for %s s now)' % block.group(1)
                                 if block and block.group(1) != '0' else ''), retry=False)
        self.sid = m.group(1)
        return self.sid

    def logout(self):
        if self.sid:
            try:
                self.req('GET', '/login_sid.lua?logout=1&sid=%s' % urllib.parse.quote(self.sid),
                         ok=range(0, 600), headers={'Accept': 'text/xml'})
            except PluginError:
                pass
            self.sid = None

    def test(self):
        self.login()
        self.logout()
        return 'signed in to the FRITZ!Box %s as %s' % (self.c('host'), self.c('user'))

    def served_now(self, bundle):
        try:
            return served_fingerprint(self.c('host'), as_int(self.c('port', 443), 443)) == \
                fp_of(bundle)
        except (OSError, ValueError):
            return False

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the FRITZ!Box')
        pem = bundle.as_format('key-rsa') + bundle.as_format('fullchain-pem')
        self.login()
        try:
            body, ctype = multipart([('sid', self.sid), ('BoxCertPassword', ''),
                                     ('BoxCertImportFile', ('BoxCert.pem', pem,
                                                            'application/octet-stream'))])
            st, hd, raw = self.req('POST', '/cgi-bin/firmwarecfg', body,
                                   {'Content-Type': ctype, 'Accept': 'text/html'},
                                   what='uploading the certificate', timeout=120)
            page = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', text(raw))).strip()
            bad = re.search(r'Fehler|fehlgeschlagen|failed|ungültig|invalid', page, re.I)
            if 'SSL' not in page or bad:
                raise PluginError('the FRITZ!Box did not take the certificate: %s'
                                  % (page[:200] or 'no answer'), detail=text(raw)[:2000],
                                  retry=False)
            self.ctx.step('the FRITZ!Box took the certificate: %s' % page[:120], 'ok')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'certificate uploaded to the FRITZ!Box %s' % self.c('host')

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = '%s:%d' % (self.c('host'), as_int(self.c('port', 443), 443))
        return HttpTarget.verify(self, bundle, options)
