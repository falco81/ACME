# -*- coding: utf-8 -*-
"""
HPE Aruba Networking AOS-CX switches through the REST API: the CAs of the chain as trust
anchor profiles, the certificate with its key installed under a dated name, the applications
asked (https-server: the WebUI and REST API; syslog-client, captive-portal, radsec-client...)
pointed at it, the configuration saved, older acme certificates no application uses deleted.

    POST   /rest/<v>/login?username=&password=          -> the session cookie (x-csrf-token)
    GET    /rest/<v>/system?attributes=platform_name,software_version,certificate_association
    GET    /rest/<v>/system/pki_ta_profiles             the trust anchor profiles {name: uri}
    POST   /rest/<v>/system/pki_ta_profiles   {"name": "acme-ca-<id>", "certificate": PEM,
                                               "revocation_check_mode": "disabled"}
    GET    /rest/<v>/certificates                       the certificates {name: uri}
    PUT    /rest/<v>/certificates/<name>     {"certificate": key + certificate + chain (PEM)}
    PATCH  /rest/<v>/system   {"certificate_association": {...those there, <app>: <name>}}
           (https-server: the switch's HTTPS server takes it - the session ends; signed in again)
    GET    /rest/<v>/system?attributes=certificate_association_status     as_configured?
    PUT    /rest/<v>/fullconfigs/startup-config?from=/rest/<v>/fullconfigs/running-config
    DELETE /rest/<v>/certificates/<old>
    POST   /rest/<v>/logout

One module for AOS-CX 10.13 - 10.18 (the REST API reference v10.18 the guide was checked by;
`/rest/latest` from 10.09 on).

Sources (the vendor guide navody/certifikaty/aruba/aos-cx.md and what it cites):
    https://developer.arubanetworks.com/aoscx/reference/put_certificates-certificate-name.md
    https://developer.arubanetworks.com/aoscx/reference/post_system-pki-ta-profiles.md
    https://developer.arubanetworks.com/aoscx/reference/get_system.md  (certificate_association)
    https://developer.arubanetworks.com/aoscx/reference/post_login.md
    https://developer.arubanetworks.com/aoscx/docs/api-versioning.md

Less certain:
    - whether PUT /certificates/<name> installs a certificate with its key under a name the
      switch has not made a CSR for (the reference: "may contain a private key if it was
      generated outside of the switch"); a 404 is said in words;
    - whether PATCH /system takes certificate_association alone (the guide found no example):
      acme sends the whole association, the others as they were;
    - saving with PUT fullconfigs/startup-config (copy running-config startup-config of the
      REST API) is AOS-CX's usual call, not in the guide;
    - the x-csrf-token header some versions give at login is sent back when given.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, object_name, name_prefix,
    ours, prune, chain_list, chain_id, http_fields, tls_fields, verify_fields, keep_field)

APPS = ('https-server', 'syslog-client', 'captive-portal', 'radsec-client', 'hsc', 'gnmi',
        'est-client', 'dot1x-supplicant')


def q(s):
    return urllib.parse.quote(text(s), safe='')


def names_of(d):
    """A collection's answer ({name: uri} or [..]) -> its names."""
    if isinstance(d, dict):
        return [text(k) for k in d]
    if isinstance(d, list):
        return [text(x.get('name') if isinstance(x, dict) else x).rsplit('/', 1)[-1]
                for x in d]
    return []


class ArubaAosCxTarget(HttpTarget):
    kind = 'aruba_aoscx'
    title = 'HPE Aruba Networking AOS-CX switch'
    vendor = 'HPE Aruba Networking'
    description = ('Installs the certificate and its key on an AOS-CX switch through its REST '
                   'API (the CAs as trust anchor profiles), uses it for the HTTPS server '
                   '(WebUI, REST) and the other applications asked, saves the configuration '
                   'and deletes older acme certificates. AOS-CX 10.13 - 10.18.')
    doc = 'targets.md'
    discovery = False
    fields = http_fields(443, 'sw01.example.local') + [
        field('user', 'User', 'text', required=True, default='acme',
              help='a user of the group administrators (REST writes need it)'),
        field('password', 'Password', 'secret', required=True),
        field('api', 'REST API version', 'text', default='latest', advanced=True,
              help='latest (10.09 and later), or a version the switch lists at /rest, e.g. '
                   'v10.13'),
    ] + tls_fields()
    deploy_fields = [
        field('applications', 'Use it for', 'list', default='https-server',
              help='one a line: %s' % ', '.join(APPS)),
        field('save', 'Save the configuration', 'bool', default=True),
        keep_field(1),
    ] + verify_fields()
    served_wait = (6, 5)

    cookie = None
    csrf = None

    # -- the session ------------------------------------------------------------------------
    def v(self):
        return '/rest/%s' % (text(self.c('api') or 'latest').strip().strip('/') or 'latest')

    def auth_headers(self):
        h = {}
        if self.cookie:
            h['Cookie'] = self.cookie
        if self.csrf:
            h['X-CSRF-TOKEN'] = self.csrf
        return h

    def login(self):
        qs = urllib.parse.urlencode({'username': self.c('user') or '',
                                     'password': self.c('password') or ''})
        try:
            st, hd, d = self.req('POST', '%s/login?%s' % (self.v(), qs), b'', auth=False,
                                 what='signing in')
        except PluginError as e:
            raise PluginError(str(e).replace(text(self.c('password') or '\0'), '…'),
                              retry=False)
        ck = text(hd.get('set-cookie'))
        if not ck:
            raise PluginError('the switch gave no session cookie', retry=False)
        self.cookie = '; '.join(p.split(';', 1)[0].strip() for p in ck.split(',')
                                if '=' in p.split(';', 1)[0])
        self.csrf = text(hd.get('x-csrf-token')) or None

    def logout(self):
        if not self.cookie:
            return
        try:
            self.req('POST', '%s/logout' % self.v(), b'', what='signing out')
        except PluginError as e:
            self.ctx.debug('signing out: %s' % e)
        self.cookie = self.csrf = None

    def api(self, method, path, body=None, ok=None, what=None):
        if not self.cookie:
            self.login()
        st, hd, d = self.req(method, self.v() + path, body, ok=ok, what=what)
        return st, d

    def system(self, attrs):
        st, d = self.api('GET', '/system?attributes=%s' % ','.join(attrs), what='reading the '
                         'system')
        return d if isinstance(d, dict) else {}

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        try:
            s = self.system(['platform_name', 'software_version', 'hostname'])
            n = len(names_of(self.api('GET', '/certificates', what='listing the '
                                      'certificates')[1]))
        finally:
            self.logout()
        return 'signed in to %s (%s): AOS-CX %s; %d certificate%s' % (
            s.get('hostname') or self.c('host'), s.get('platform_name') or 'AOS-CX',
            s.get('software_version') or '?', n, '' if n == 1 else 's')

    def served_places(self, options):
        apps = lines((options or {}).get('applications') or 'https-server')
        if not self.c('host') or 'https-server' not in apps:
            return []
        return [(self.c('host'), as_int(self.c('port', 443), 443))]

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        apps = lines(self.opt(options, 'applications', 'https-server'))
        bad = [a for a in apps if a not in APPS]
        if bad:
            raise PluginError('not an application of AOS-CX: %s' % ', '.join(bad), retry=False)
        name = object_name(bundle, options, maxlen=32, serial_len=6)
        prefix = name_prefix(bundle, options, maxlen=32, serial_len=6)
        try:
            return self._deploy(bundle, options, apps, name, prefix)
        finally:
            self.logout()

    def _deploy(self, bundle, options, apps, name, prefix):
        have = names_of(self.api('GET', '/certificates', what='listing the certificates')[1])
        if self.unchanged(bundle, options, present=lambda: name in have):
            return self.same(bundle, 'as %s' % name)
        did = []
        tas = names_of(self.api('GET', '/system/pki_ta_profiles',
                                what='listing the trust anchor profiles')[1])
        for pem in chain_list(bundle):
            ta = 'acme-ca-%s' % chain_id(pem)
            if ta in tas:
                self.ctx.step('the trust anchor profile %s is there already' % ta)
                continue
            self.api('POST', '/system/pki_ta_profiles', {
                'name': ta, 'certificate': text(pem), 'revocation_check_mode': 'disabled'},
                what='adding the trust anchor %s' % ta)
            self.ctx.step('added the trust anchor profile %s' % ta, 'ok')
        if name not in have:
            pem = text(bundle.as_format('key-pem')) + text(bundle.as_format('fullchain-pem'))
            self.api('PUT', '/certificates/%s' % q(name), {'certificate': pem},
                     what='installing %s' % name)
            self.ctx.step('installed the certificate %s' % name, 'ok')
            did.append('installed %s' % name)
        else:
            self.ctx.step('the certificate %s is there already' % name)
        if apps:
            cur = self.system(['certificate_association']).get('certificate_association')
            cur = dict(cur) if isinstance(cur, dict) else {}
            want = dict(cur)
            for a in apps:
                want[a] = name
            if want != cur:
                self.mark_pending(bundle)
                try:
                    self.api('PATCH', '/system', {'certificate_association': want},
                             what='using %s for %s' % (name, ', '.join(apps)))
                except PluginError as e:
                    if 'https-server' not in apps or 'cannot be reached' not in str(e):
                        raise
                    # the HTTPS server took the new certificate and cut this session
                    self.ctx.debug('the session ended with the switch: %s' % e)
                self.cookie = self.csrf = None      # https-server: a new session (the guide)
                before = sorted(set(text(cur[a]) for a in apps if cur.get(a)))
                self.ctx.step('%s use%s %s%s' % (', '.join(apps), 's' if len(apps) == 1 else '',
                                                 name, ' (before: %s)' % ', '.join(before)
                                                 if before else ''), 'ok')
                did.append(', '.join(apps))
            self.check_status(apps, name)
        if as_bool(self.opt(options, 'save', True), True):
            self.api('PUT', '/fullconfigs/startup-config?from=%s/fullconfigs/running-config'
                     % self.v(), what='saving the configuration')
            self.ctx.step('saved the configuration', 'ok')
        self.done_pending()
        self.cleanup(prefix, name, self.keep(options), have)
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def check_status(self, apps, name):
        try:
            st = self.system(['certificate_association_status']).get(
                'certificate_association_status') or {}
        except PluginError as e:
            self.ctx.step('the state of the applications cannot be read: %s' % e, 'warn')
            return
        for a in apps:
            s = st.get(a) if isinstance(st, dict) else None
            if not isinstance(s, dict):
                continue
            why = text(s.get('status_reason'))
            if why and why != 'as_configured':
                raise PluginError('%s does not use %s: the switch says %s' % (a, name, why),
                                  detail=text(s), retry=False)

    def cleanup(self, prefix, current, keep, have):
        if keep < 0:
            return
        gone = prune([n for n in have if ours(n, prefix)], prefix, keep, current)
        if not gone:
            return
        try:
            used = set(text(v) for v in (self.system(['certificate_association']).get(
                'certificate_association') or {}).values())
        except PluginError as e:
            self.ctx.step('the older certificates stay - what uses them cannot be read: %s' % e,
                          'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older %s stays: an application still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/certificates/%s' % q(old), what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
