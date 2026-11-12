# -*- coding: utf-8 -*-
"""
Dell PowerStore (PowerStoreOS 3.0 - 4.4): the cluster management certificate
(service Management_HTTP - PowerStore Manager and the REST API) through the
REST API.

    GET   /api/rest/login_session          basic auth -> DELL-EMC-TOKEN header, auth_cookie
    GET   /api/rest/software_installed?select=release_version&is_cluster=eq.true   (the version)
    POST  /api/rest/x509_certificate  {"type": "Server", "service": "Management_HTTP",
                                       "scope": "External", "certificate": the chain,
                                       "private_key": the key, "is_current": true}  -> {"id"}
    GET   /api/rest/x509_certificate/<id>?select=id,is_current,is_valid
    POST  /api/rest/logout

The POST with "private_key" is the call of Dell's PowerStore SDK
(PyPowerStore configuration.create_certificate: type, service, scope,
certificate, private_key, passphrase, is_current). Dell documents the
management certificate only from a CSR the cluster made itself
(x509_certificate/csr, then a PATCH of the signed chain) - a key from elsewhere
for Management_HTTP is NOT documented: acme then says the cluster's refusal in
words and nothing is changed (the self-signed certificate stays). This is the
uncertain part of this module; try it on your PowerStoreOS first.

The chain is one string (the JSON escapes its line ends as "\\n", the shape
PSTCLI and the REST API want: server, intermediates, root); a certificate
valid for less than 30 days is refused by PowerStore. The certificate is used at
once, nothing restarts (the PowerStore Manager sessions are opened again).
PowerStoreOS 2.x took this only on a single block appliance without replication:
2.x is refused, 3.0 - 4.4 use the same calls.

Sources: Dell KB 000193886, KB 000211671, KB 000223823, InfoHub "Guide for
configuring PowerStore with an SSL certificate", REST API Developers Guide 4.1
(login_session, DELL-EMC-TOKEN), dell/python-powerstore, the Ansible module
dellemc.powerstore.certificate. Role: Security Administrator (or Administrator).
"""
from __future__ import annotations

import base64
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, served_fingerprint, fp_of, split_hostport)


def pstos_tuple(v):
    m = re.match(r'^\s*(\d+)\.(\d+)(?:\.(\d+))?', text(v))
    return tuple(int(x or 0) for x in m.groups()) if m else None


class PowerStoreTarget(HttpTarget):
    kind = 'powerstore'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Dell PowerStore'
    vendor = 'Dell'
    description = ('Puts the certificate with its key on Dell PowerStore 3.0 - 4.4 as the '
                   'cluster management certificate (Management_HTTP: PowerStore Manager and '
                   'the REST API) through the REST API. Dell documents this certificate only '
                   'from the cluster\'s own CSR: the key import is the call of Dell\'s SDK - '
                   'try it first.')
    doc = 'targets.md'
    fields = http_fields(443, 'powerstore.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = verify_fields()

    pstos_min = (3, 0, 0)
    checked_to = (4, 4)
    token = None
    cookie = None

    def auth_headers(self):
        h = {}
        if self.token:
            h['DELL-EMC-TOKEN'] = self.token
        if self.cookie:
            h['Cookie'] = self.cookie
        return h

    def login(self):
        basic = 'Basic ' + base64.b64encode(
            ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()
        try:
            st, hd, d = self.req('GET', '/api/rest/login_session', auth=False,
                                 headers={'Authorization': basic}, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry='(401)' not in str(e))
        self.token = hd.get('dell-emc-token')
        if not self.token:
            raise PluginError('PowerStore gave no DELL-EMC-TOKEN on signing in')
        jar = []
        for part in re.split(r',(?=\s*[A-Za-z0-9_]+=)', text(hd.get('set-cookie'))):
            kv = part.split(';', 1)[0].strip()
            if '=' in kv:
                jar.append(kv)
        self.cookie = '; '.join(jar) or None
        return d

    def logout(self):
        if self.token:
            try:
                self.req('POST', '/api/rest/logout', ok=range(0, 600))
            except PluginError:
                pass
        self.token = self.cookie = None

    def version(self):
        """(release words, (major, minor, patch)) of PowerStoreOS, ('', None) unread."""
        try:
            st, hd, d = self.req('GET', '/api/rest/software_installed?select=release_version,'
                                 'is_cluster&is_cluster=eq.true', what='reading the version')
        except PluginError as e:
            self.ctx.debug('the PowerStoreOS version not read: %s' % e)
            return '', None
        rows = d if isinstance(d, list) else []
        rel = next((text(r.get('release_version')) for r in rows if isinstance(r, dict)
                    and r.get('release_version')), '')
        return rel, pstos_tuple(rel)

    def check_version(self):
        rel, ver = self.version()
        if ver is None:
            self.ctx.step('the PowerStoreOS version cannot be read - the calls of 3.0 - 4.4 '
                          'are used', 'warn')
        elif ver < self.pstos_min:
            raise PluginError('this cluster runs PowerStoreOS %s - acme needs 3.0 or later (2.x '
                              'took a management certificate only on a single block appliance '
                              'without replication)' % rel, retry=False)
        elif ver[:2] > self.checked_to:
            self.ctx.step('PowerStoreOS %s is newer than the documents this module was '
                          'checked against (4.4)' % rel, 'warn')
        return rel

    def test(self):
        self.login()
        try:
            rel = self.check_version()
            st, hd, d = self.req('GET', '/api/rest/x509_certificate?select=id,type,service,'
                                 'scope,is_current&service=eq.Management_HTTP',
                                 what='listing the certificates')
            n = len(d) if isinstance(d, list) else 0
            return 'signed in to %s, PowerStoreOS %s, management certificates: %d' % (
                self.c('host'), rel or '?', n)
        finally:
            self.logout()

    def served_now(self, bundle):
        try:
            host, port = split_hostport('%s:%s' % (self.c('host'), self.c('port') or 443))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by PowerStore')
        self.login()
        try:
            rel = self.check_version()
            body = {'type': 'Server', 'service': 'Management_HTTP',
                    'scope': 'External',
                    'certificate': text(bundle.as_format('fullchain-pem')).strip(),
                    'private_key': text(bundle.as_format('key-pem')).strip(),
                    'is_current': True}
            st, hd, d = self.req('POST', '/api/rest/x509_certificate', body,
                                 ok=range(200, 600), timeout=120,
                                 what='importing the management certificate')
            if st in (400, 422):
                raise PluginError(self.http_error(st, d, d if isinstance(d, bytes) else b'',
                                                  'POST', '/api/rest/x509_certificate',
                                                  'importing the management certificate') +
                                  ' - this PowerStoreOS does not take a key made elsewhere for '
                                  'the management certificate (Dell documents only its own '
                                  'CSR); nothing was changed', detail=text(d)[:4000],
                                  retry=False)
            if st >= 300:
                raise PluginError(self.http_error(st, d, d if isinstance(d, bytes) else b'',
                                                  'POST', '/api/rest/x509_certificate',
                                                  'importing the management certificate'),
                                  detail=text(d)[:4000], retry=st not in (401, 403, 404))
            cid = text((d or {}).get('id')) if isinstance(d, dict) else ''
            self.ctx.step('imported the management certificate%s' % (
                (' (%s)' % cid) if cid else ''), 'ok')
            if cid:
                st, hd, c = self.req('GET', '/api/rest/x509_certificate/%s?select=id,'
                                     'is_current,is_valid' % cid, what='reading it back')
                c = c if isinstance(c, dict) else {}
                if c.get('is_current') is False:
                    raise PluginError('PowerStore took the certificate (%s) but does not use it '
                                      '(is_current false)' % cid, retry=False)
                if c.get('is_valid') is False:
                    self.ctx.step('PowerStore says the certificate is not valid (is_valid '
                                  'false) - check the chain', 'warn')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'the management certificate%s' % ((' on PowerStoreOS %s' % rel) if rel else '')

    served_wait = (5, 6)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []
