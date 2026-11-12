# -*- coding: utf-8 -*-
"""
HPE Aruba Networking ClearPass Policy Manager - the server certificates of one server of the
cluster (HTTPS(RSA), HTTPS(ECC), RADIUS, RadSec) replaced through its REST API. ClearPass
takes the certificate only from a URL it downloads it from, so acme puts the PKCS#12 for a
moment on a web server of yours (over SSH, under a random name), has ClearPass fetch it and
deletes it again.

    POST /api/oauth   {"grant_type": "client_credentials", "client_id", "client_secret"}
                      -> access_token; then Authorization: Bearer
    GET  /api/cluster/server                -> _embedded.items[{server_uuid, name, fqdn, ...}]
    POST /api/cert-trust-list   {"cert_file": PEM, "enabled": true, "cert_usage": [...]}
                                            each CA of the chain (one there already: refused,
                                            and left)
    (ssh) the PKCS#12 written to <directory>/acme-<random>.p12 of the staging web server
    PUT  /api/server-cert/name/<server_uuid>/<service>
         {"pkcs12_file_url": <base URL>/acme-<random>.p12, "pkcs12_passphrase": ...}
    (ssh) the file deleted

One module for ClearPass 6.12 - 6.14 (the API reference 6.14.1 and the official SDK
pyclearpass the guide was checked by; HTTPS(RSA)/HTTPS(ECC) separate since 6.10/6.11).

Sources (the vendor guide navody/certifikaty/aruba/clearpass.md and what it cites):
    https://developer.arubanetworks.com/cppm/reference/servercertnamebyserver_uuidbyservice_nameput.md
    https://developer.arubanetworks.com/cppm/reference/certtrustlistpost.md
    https://developer.arubanetworks.com/cppm/reference/tokenendpointpost.md
    https://github.com/aruba/pyclearpass/blob/main/pyclearpass/api_platformcertificates.py

Less certain: whether cert_file of the trust list is the PEM itself (the reference says only
"Certificate trust list file") - a refused one is said and the import goes on (the chain
may be there already); the restart of the web server / RADIUS after an import is not in the
documents the guide could read; the shape of /cluster/server (HAL "_embedded"."items").
"""
from __future__ import annotations

import posixpath
import secrets
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, random_password, chain_list,
    http_fields, tls_fields, verify_fields, quote)

SERVICES = ('HTTPS(RSA)', 'HTTPS(ECC)', 'RADIUS', 'RadSec')
USAGES = ('AD/LDAP Servers', 'Aruba Infrastructure', 'Aruba Services', 'Database', 'EAP',
          'Endpoint Context Servers', 'RadSec', 'SAML', 'SMTP', 'EST', 'Syslog', 'Others')


class ArubaClearPassTarget(HttpTarget):
    kind = 'aruba_clearpass'
    title = 'HPE Aruba Networking ClearPass Policy Manager'
    vendor = 'HPE Aruba Networking'
    description = ('Replaces the server certificates (HTTPS, RADIUS, RadSec) of a ClearPass '
                   'server through its REST API: the CAs into the trust list, the PKCS#12 '
                   'fetched by ClearPass from a staging web server acme puts it on for a '
                   'moment. ClearPass 6.12 - 6.14.')
    doc = 'targets.md'
    discovery = False
    fields = http_fields(443, 'cppm.example.local') + [
        field('client_id', 'API client ID', 'text', required=True, default='acme',
              help='Administration → API Services → API Clients, grant type Client '
                   'credentials'),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('server', 'Server', 'text', required=True, placeholder='cppm01',
              help='the server of the cluster whose certificates these are: its name, FQDN, '
                   'IP address or server UUID'),
        field('stage_host', 'Staging web server', 'text', required=True,
              placeholder='files.example.local',
              help='a server ClearPass downloads the PKCS#12 from; acme writes it there over '
                   'SSH for a moment'),
        field('stage_port', 'SSH port', 'number', default=22),
        field('stage_user', 'SSH user', 'text', default='acme'),
        field('stage_auth', 'Sign in with', 'select', default='key',
              options=[['key', 'a private key'], ['password', 'a password']]),
        field('stage_key', 'The SSH key', 'sshkey', secret=True, pass_key='stage_key_pass',
              auth_key='stage_auth', ssh_prefix='stage_', howto='linux'),
        field('stage_password', 'SSH password', 'secret', show_if={'stage_auth': ['password']}),
        field('stage_hostkey', 'Host key', 'text', advanced=True),
        field('stage_trust_first', 'Trust the first host key seen', 'bool', default=True,
              advanced=True),
        field('stage_dir', 'Directory', 'text', required=True, placeholder='/var/www/cppm-drop',
              help='a directory the web server serves; the file is world-readable for the '
                   'moment it is there, under a random name'),
        field('stage_url', 'Its URL', 'text', required=True,
              placeholder='https://files.example.local/cppm-drop',
              help='the URL of that directory as ClearPass reaches it'),
    ] + tls_fields()
    deploy_fields = [
        field('services', 'Use it for', 'list', default='HTTPS(RSA)\nRADIUS',
              help='one a line: %s (HTTPS(ECC) takes an ECDSA certificate)' %
                   ', '.join(SERVICES)),
        field('trust_chain', 'Add the CAs to the trust list', 'bool', default=True,
              advanced=True),
        field('trust_usage', 'Trust list usage', 'list', default='EAP\nOthers', advanced=True,
              help='one a line: %s' % ', '.join(USAGES)),
    ] + verify_fields()
    served_wait = (10, 6)

    token = None

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.token} if self.token else {}

    def login(self):
        if self.token:
            return
        try:
            st, hd, d = self.req('POST', '/api/oauth', {
                'grant_type': 'client_credentials', 'client_id': self.c('client_id') or '',
                'client_secret': self.c('client_secret') or ''}, auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), retry=False)
        tok = d.get('access_token') if isinstance(d, dict) else None
        if not tok:
            raise PluginError('ClearPass gave no access_token', retry=False)
        self.token = text(tok)

    def api(self, method, path, body=None, ok=None, what=None):
        self.login()
        st, hd, d = self.req(method, '/api' + path, body, ok=ok, what=what)
        return st, d

    def servers(self):
        st, d = self.api('GET', '/cluster/server', what='listing the servers')
        items = []
        if isinstance(d, dict):
            items = (d.get('_embedded') or {}).get('items') or d.get('items') or []
        elif isinstance(d, list):
            items = d
        return [x for x in items if isinstance(x, dict)]

    def server(self):
        want = text(self.c('server')).strip().lower()
        got = self.servers()
        for s in got:
            if want in [text(s.get(k)).lower() for k in ('server_uuid', 'name', 'fqdn',
                                                          'local_ip', 'management_ip',
                                                          'hostname')]:
                return s
        raise PluginError('ClearPass has no server "%s" (it has: %s)' % (
            self.c('server'), ', '.join(text(s.get('name') or s.get('server_uuid'))
                                        for s in got) or 'none'), retry=False)

    def test(self):
        s = self.server()
        return 'signed in to ClearPass %s; server %s (%s)' % (
            self.c('host'), s.get('name') or s.get('fqdn') or '?', s.get('server_uuid'))

    def served_places(self, options):
        svc = lines((options or {}).get('services') or 'HTTPS(RSA)\nRADIUS')
        if not self.c('host'):
            return []
        out = []
        if 'HTTPS(RSA)' in svc or 'HTTPS(ECC)' in svc:
            out.append((self.c('host'), as_int(self.c('port', 443), 443)))
        if 'RadSec' in svc:
            out.append((self.c('host'), 2083))
        return out

    # -- the staging web server -------------------------------------------------------------
    def stage_conn(self):
        auth = self.c('stage_auth', 'key')
        return {'host': self.c('stage_host'), 'port': as_int(self.c('stage_port', 22), 22),
                'user': self.c('stage_user') or 'acme',
                'password': self.c('stage_password') if auth == 'password' else None,
                'key': self.c('stage_key') if auth == 'key' else None,
                'key_pass': self.c('stage_key_pass') if auth == 'key' else None,
                'hostkey': self.c('stage_hostkey') or None, 'hostkey_field': 'stage_hostkey',
                'trust_first': as_bool(self.c('stage_trust_first', True), True),
                'timeout': as_int(self.c('timeout', 30), 30), 'via': ''}

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        svcs = lines(self.opt(options, 'services', 'HTTPS(RSA)\nRADIUS'))
        bad = [x for x in svcs if x not in SERVICES]
        if bad or not svcs:
            raise PluginError('not a service of a ClearPass server certificate: %s (%s)' % (
                ', '.join(bad) or 'none given', ', '.join(SERVICES)), retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on ClearPass')
        srv = self.server()
        uuid = text(srv.get('server_uuid'))
        if as_bool(self.opt(options, 'trust_chain', True), True):
            usage = lines(self.opt(options, 'trust_usage', 'EAP\nOthers')) or ['Others']
            for pem in chain_list(bundle):
                try:
                    self.api('POST', '/cert-trust-list', {'cert_file': text(pem),
                                                          'enabled': True, 'cert_usage': usage},
                             what='adding a CA to the trust list')
                    self.ctx.step('added a CA of the chain to the trust list', 'ok')
                except PluginError as e:
                    self.ctx.step('a CA of the chain was not added (there already?): %s' % e)
        pw = random_password(20)
        fn = 'acme-%s.p12' % secrets.token_hex(16)
        path = posixpath.join(text(self.c('stage_dir')).rstrip('/') or '/', fn)
        url = text(self.c('stage_url')).rstrip('/') + '/' + urllib.parse.quote(fn)
        did = []
        with self.ctx.ssh(self.stage_conn()) as s:
            s.put(bundle.as_format('pfx', password=pw, alias='acme'), path, mode=0o644)
            self.ctx.step('put the PKCS#12 on the staging server for ClearPass to fetch')
            try:
                self.mark_pending(bundle)
                for svc in svcs:
                    st, d = self.api('PUT', '/server-cert/name/%s/%s' % (
                        urllib.parse.quote(uuid, safe=''), urllib.parse.quote(svc, safe='')),
                        {'pkcs12_file_url': url, 'pkcs12_passphrase': pw},
                        what='replacing the %s certificate' % svc)
                    d = d if isinstance(d, dict) else {}
                    self.ctx.step('%s of %s: %s, until %s' % (
                        svc, srv.get('name') or uuid, d.get('subject') or 'replaced',
                        d.get('expiry_date') or '?'), 'ok')
                    did.append(svc)
            finally:
                try:
                    s.run('rm -f %s' % quote(path), check=True)
                except PluginError as e:
                    self.ctx.step('the staged file %s stays - delete it: %s' % (path, e), 'bad')
        self.done_pending()
        self.ctx.step('ClearPass restarts the services of the certificates replaced (HTTPS: '
                      'its pages, RADIUS: authentications for a moment)', 'warn')
        self.remember(bundle, options)
        return 'replaced %s on %s' % (', '.join(did), srv.get('name') or uuid)
