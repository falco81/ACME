# -*- coding: utf-8 -*-
"""
VMware Live Site Recovery (Site Recovery Manager) and vSphere Replication 9.x - the appliance
certificate (HTTPS 443 and the management interface 5480) through the appliance's
Configuration API on 5480, as a PKCS#12 file:

    POST <api>/session                       (basic, admin) -> {"session_id"}; then the
                                             header x-dr-session
    GET  <api>/appliance/certificates/server  the one there now ("certificate", "thumbprint")
    POST <api>/appliance/certificates/ca      [{"value": PEM}, ...]   the chain trusted (when
                                             asked) - 204
    POST <api>/appliance/certificates/server  {"pkcs12_format": {"certificate": <base64 of the
                                             PKCS#12>, "password"}}

<api> is https://<appliance>:5480/configure/requests by default (a field).

After it - acme cannot, it says so: vSphere Replication must be restarted (its documents ask
for it) and the site pairs reconnected (Site Recovery > Site Pair > Reconnect; vSphere
Replication > target sites > Reconnect) - the thumbprint changed.

Requirements (VLSR 9.0, vSphere Replication 9.0): PKCS#12 with exactly one certificate and its
key (the intermediates go to the appliance's CA certificates), a key of 2048 bits or more, a
PKCS#12 password of at most 31 characters, SHA-256 or stronger, the appliance's FQDN in the
SAN, and for Live Site Recovery the extended key usages serverAuth AND clientAuth.

Sources: navody/certifikaty/vmware/site-recovery-replication-vcd.md (2026-11) - VLSR 9.0
"Change the VMware Live Site Recovery Appliance Certificate", "Requirements When Using Custom
SSL/TLS Certificates", VLSR Configuration API (9.0/9.1) Certificates, session; vSphere
Replication 9.0 "Change the SSL Certificate of the vSphere Replication Appliance", VRMS
Appliance Configuration API 2.0.0 (POST /appliance/certificates/server with pkcs12_format,
POST /appliance/certificates/ca).
Less certain (said in the guide): the base path /configure/requests (only {api_host} in the
reference - "Try" signs in with it before anything is changed); the base64 of the PKCS#12 in
"certificate"; in VLSR 9.x POST .../server is marked Deprecated (its successor .../actions/update
takes only a CSR made on the appliance or a self-signed one - no key made elsewhere) - kept as
the one way for a key made elsewhere.
"""
from __future__ import annotations

import base64
import copy

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, random_password, as_int, http_fields,
    tls_fields, verify_fields, norm_fp, fp_of, sha1_thumb)
from acmelib.plugins.targets import _vmware as V

PRODUCTS = {'vlsr': 'VMware Live Site Recovery', 'vr': 'vSphere Replication'}


class VmwareDrApplianceTarget(HttpTarget):
    kind = 'vmware_dr'
    title = 'VMware Live Site Recovery / vSphere Replication appliance'
    vendor = 'VMware'
    discovery = False
    description = ('Live Site Recovery (Site Recovery Manager) and vSphere Replication 9.x: '
                   'replaces the appliance certificate through its Configuration API (port '
                   '5480) as a PKCS#12, the chain added to its CA certificates first; says '
                   'when the appliance must be restarted and the site pairs reconnected.')
    doc = 'targets.md'
    fields = http_fields(5480, 'vlsr01.example.local') + [
        field('product', 'Appliance', 'select', default='vlsr',
              options=[['vlsr', 'VMware Live Site Recovery (Site Recovery Manager)'],
                       ['vr', 'vSphere Replication']]),
        field('user', 'User', 'text', required=True, default='admin',
              help='the appliance\'s admin (the management interface\'s user)'),
        field('password', 'Password', 'secret', required=True),
        field('base_path', 'API path', 'text', default='/configure/requests', advanced=True,
              help='where the Configuration API is on port 5480'),
    ] + tls_fields()
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in, added to the appliance\'s CA certificates; '
                   'empty: the last certificate of the chain when it is a root'),
        field('add_ca', 'Add the chain to the appliance\'s CA certificates', 'bool',
              default=True),
    ] + verify_fields()

    session = None

    def api(self, path):
        b = '/' + text(self.c('base_path') or '/configure/requests').strip().strip('/')
        return (b if b != '/' else '') + path

    def auth_headers(self):
        return {'x-dr-session': self.session} if self.session else {}

    def product(self):
        p = text(self.c('product') or 'vlsr')
        return PRODUCTS.get(p, PRODUCTS['vlsr'])

    def login(self):
        raw = '%s:%s' % (self.c('user') or 'admin', self.c('password') or '')
        try:
            st, hd, d = self.req('POST', self.api('/session'), auth=False, headers={
                'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()},
                what='signing in')
        except PluginError as e:
            if '(404)' in str(e):
                raise PluginError('%s - is the API path (%s) right?' % (e, self.api('')),
                                  detail=e.detail, retry=False)
            raise PluginError(str(e), detail=e.detail,
                              retry=not any(x in str(e) for x in ('(401)', '(403)')))
        sid = text((d or {}).get('session_id') if isinstance(d, dict) else '')
        if not sid:
            raise PluginError('the appliance gave no session_id on signing in', retry=False)
        self.session = sid

    def current(self):
        st, hd, d = self.req('GET', self.api('/appliance/certificates/server'),
                             what='reading the appliance certificate')
        return d if isinstance(d, dict) else {}

    def is_current(self, bundle, info):
        if V.has_cert(info.get('certificate') or '', bundle):
            return True
        tp = norm_fp(info.get('thumbprint'))
        return bool(tp) and tp in (sha1_thumb(bundle).lower(), fp_of(bundle))

    def test(self):
        self.login()
        info = self.current()
        return 'signed in to the %s appliance %s; its certificate: %s, valid to %s' % (
            self.product(), self.c('host'), info.get('subject_dn', '?'),
            info.get('not_after', '?'))

    def deploy(self, bundle, options):
        options = options or {}
        self.login()
        if not as_bool(options.get('force')) and self.is_current(bundle, self.current()):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the appliance')
        if as_bool(self.opt(options, 'add_ca', True), True):
            root = V.root_of(bundle, options.get('root_pem'))
            cas = list(V.intermediates(bundle)) + ([root] if root else [])
            if cas:
                try:
                    self.req('POST', self.api('/appliance/certificates/ca'),
                             [{'value': p.strip() + '\n'} for p in cas],
                             what='adding the chain to the appliance\'s CA certificates')
                    self.ctx.step('the chain is among the appliance\'s CA certificates', 'ok')
                except PluginError as e:
                    self.ctx.step('the chain was not added (there already?): %s' % e, 'warn')
        # exactly one certificate and its key in the PKCS#12 (the requirements): the chain left
        # out of a copy of the certificate - the CA certificates are added above
        leaf = copy.copy(bundle)
        try:
            leaf.chain_pems = []
        except AttributeError:
            leaf = bundle
        pw = random_password(20)            # at most 31 characters
        p12 = leaf.as_format('p12', password=pw, alias='acme')
        self.req('POST', self.api('/appliance/certificates/server'), {
            'pkcs12_format': {'certificate': base64.b64encode(p12).decode(), 'password': pw}},
            what='changing the appliance certificate', timeout=300)
        self.ctx.step('the %s appliance took the certificate' % self.product(), 'ok')
        if text(self.c('product') or 'vlsr') == 'vr':
            self.ctx.step('restart the vSphere Replication appliance now (its documents ask for '
                          'it), then reconnect its target sites (vSphere Replication > Manage)',
                          'warn')
        else:
            self.ctx.step('reconnect the site pair (Site Recovery > Site Pair Summary > '
                          'Reconnect): its thumbprint changed', 'warn')
        self.remember(bundle, options)
        return '%s appliance %s: certificate changed' % (self.product(), self.c('host'))

    served_wait = (10, 10)

    def served_places(self, options):
        if not self.c('host'):
            return []
        return [(self.c('host'), 443), (self.c('host'), as_int(self.c('port', 5480), 5480))]
