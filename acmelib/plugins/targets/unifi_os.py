# -*- coding: utf-8 -*-
"""
Ubiquiti UniFi OS consoles (UDM, UDM Pro, UCG, UDR, Cloud Key Gen2+, UniFi
OS Server): the certificate added through the console's own certificate
API - the one behind Settings → Control Plane → Console → Certificates -
under a dated name, made the active one, older acme ones deleted. Nothing
is written on the console's disk; it rebuilds its nginx itself.

    POST   /api/auth/login  {username, password, token: "", rememberMe: false}
           -> cookie TOKEN, header X-CSRF-Token
    GET    /api/userCertificates             -> [{id, name, fingerprint (SHA-1)}]
    POST   /api/userCertificates  {name, key, cert}
    PUT    /api/userCertificates/<id>/status  {"active": true}
    DELETE /api/userCertificates/<id>

Rights: a local console admin (not an SSO / UI account with two-factor).

Sources:
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/unifios.sh
    https://help.ui.com/hc/en-us/articles/39542553592855  (custom certificates, UniFi OS 4.2+)
Uncertain: the API is the console's own, not a documented public one
(Ubiquiti documents only the page); it is what acme.sh's hook uses, reported
working on UniFi OS 4.x and 5.x.
"""
from __future__ import annotations

import base64
import json
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, object_name, name_prefix, prune, norm_fp,
    sha1_thumb, http_fields, tls_fields, verify_fields, keep_field, text, as_int)


class UnifiOsTarget(HttpTarget):
    kind = 'unifi_os'
    title = 'UniFi OS console (UDM, UCG, Cloud Key)'
    vendor = 'Ubiquiti'
    description = ('Adds the certificate through the UniFi OS console\'s certificate API, makes '
                   'it the active one and deletes the older ones.')
    doc = 'targets.md'
    fields = http_fields(443, 'unifi.example.local') + [
        field('user', 'User', 'text', required=True, default='acme',
              help='a local admin of the console'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [keep_field(1)] + verify_fields()

    cookie = None
    csrf = None

    def auth_headers(self):
        h = {}
        if self.cookie:
            h['Cookie'] = 'TOKEN=%s' % self.cookie
        if self.csrf:
            h['X-CSRF-Token'] = self.csrf
        return h

    def login(self):
        try:
            st, hd, d = self.req('POST', '/api/auth/login', {
                'username': self.c('user'), 'password': self.c('password') or '',
                'token': '', 'rememberMe': False}, auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=not re.search(r'\((401|403)\)',
                                                                          str(e)))
        cookies = hd.get('set-cookie') or ''
        if isinstance(cookies, (list, tuple)):
            cookies = '; '.join(cookies)
        m = re.search(r'TOKEN=([^;,\s]+)', text(cookies))
        if not m:
            raise PluginError('the console gave no session cookie on signing in')
        self.cookie = m.group(1)
        self.csrf = hd.get('x-csrf-token') or hd.get('x-updated-csrf-token') or \
            self.csrf_of(self.cookie)

    @staticmethod
    def csrf_of(jwt):
        try:
            body = jwt.split('.')[1]
            body += '=' * (-len(body) % 4)
            return json.loads(base64.urlsafe_b64decode(body)).get('csrfToken')
        except (IndexError, ValueError, AttributeError):
            return None

    def listed(self):
        st, hd, d = self.req('GET', '/api/userCertificates', what='listing the certificates')
        if isinstance(d, dict):
            d = d.get('data') or d.get('certificates') or []
        return [c for c in (d or []) if isinstance(c, dict)]

    def test(self):
        self.login()
        n = len(self.listed())
        return 'signed in to %s; %d certificate%s added there' % (self.c('host'), n,
                                                                 '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        self.login()
        have = self.listed()
        mine = [c for c in have if c.get('name') == name or
                norm_fp(c.get('fingerprint')) == sha1_thumb(bundle).lower()]
        if mine and not as_bool(options.get('force')) and \
                (mine[0].get('active') in (True, None)) and self.unchanged(bundle, options):
            return self.same(bundle, 'as %s' % mine[0].get('name'))
        if mine:
            cid = mine[0].get('id')
            self.ctx.step('%s is there already' % mine[0].get('name'))
        else:
            st, hd, d = self.req('POST', '/api/userCertificates', {
                'name': name, 'key': text(bundle.as_format('key-pem')),
                'cert': text(bundle.as_format('fullchain-pem'))}, what='adding %s' % name)
            cid = (d or {}).get('id') if isinstance(d, dict) else None
            if not cid:
                cid = next((c.get('id') for c in self.listed() if c.get('name') == name), None)
            if not cid:
                raise PluginError('the console does not list %s after adding it' % name)
            self.ctx.step('added %s' % name, 'ok')
        self.req('PUT', '/api/userCertificates/%s/status' % cid, {'active': True},
                 what='making %s the active certificate' % name)
        self.ctx.step('%s is the active certificate' % name, 'ok')
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return '%s added and active on %s' % (name, self.c('host'))

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        have = {c.get('name'): c.get('id') for c in self.listed()}
        for old in prune([n for n in have if n], prefix, keep, current):
            try:
                self.req('DELETE', '/api/userCertificates/%s' % have[old],
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays: %s' % (old, e), 'warn')

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = '%s:%d' % (self.c('host'), as_int(self.c('port', 443), 443))
            options.setdefault('verify_tries', 8)
            options.setdefault('verify_wait', 5)
        return HttpTarget.verify(self, bundle, options)
