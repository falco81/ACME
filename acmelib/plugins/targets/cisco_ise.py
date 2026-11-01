# -*- coding: utf-8 -*-
"""
Cisco Identity Services Engine (ISE 3.1 and later) through its OpenAPI: the
certificate imported as a system certificate of one node under a dated
friendly name, for the roles asked (Admin, EAP, RADIUS DTLS, pxGrid, SAML,
Portal), its intermediates as trusted certificates; older acme ones deleted.

    POST   /api/v1/certs/trusted-certificate/import  {name, data, trustForIseAuth, ...}
    POST   /api/v1/certs/system-certificate/import   {name, data, privateKeyData, password,
           admin, eap, radius, pxgrid, saml, portal, portalGroupTag,
           allowReplacementOfCertificates, allowRoleTransferForSameSubject, ...}
    GET    /api/v1/certs/system-certificate/<node>   -> response[{id, friendlyName}]
    DELETE /api/v1/certs/system-certificate/<node>/<id>

Rights: an ERS / OpenAPI admin (Administration → System → Settings → API
Settings: Open API on), basic authentication. A certificate for the Admin
role restarts the application server of that node (minutes).

Sources:
    https://developer.cisco.com/docs/identity-services-engine/latest/certificates-openapi/
    https://docs.ansible.com/ansible/latest/collections/cisco/ise/system_certificate_import_module.html
    https://www.cisco.com/c/en/us/td/docs/security/ise/3-2/admin_guide/b_ise_admin_3_2/b_ISE_admin_32_basic_setup.html  (certificate roles)
Uncertain: whether the import goes to the node acme speaks to (the API
has no node in it; acme speaks to the node given as Address) - set the
node's own hostname for the listing. The private key goes encrypted (PKCS#8,
AES-256, by the openssl program) with a random password, as the ISE pages
want one; without openssl it goes unencrypted with no password.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, text, chain_list, chain_id, random_password)

ROLES = (('admin', 'Admin (its pages - restarts the node\'s services)'), ('eap', 'EAP'),
         ('radius', 'RADIUS DTLS'), ('pxgrid', 'pxGrid'), ('saml', 'SAML'),
         ('portal', 'Portal'), ('ims', 'ISE messaging'))


class CiscoIseTarget(HttpTarget):
    kind = 'cisco_ise'
    title = 'Cisco ISE'
    vendor = 'Cisco'
    description = ('Imports the certificate as a system certificate of a Cisco ISE node for '
                   'the roles asked (Admin, EAP, Portal, pxGrid...) through its OpenAPI and '
                   'deletes the older ones.')
    doc = 'targets.md'
    fields = http_fields(443, 'ise.example.local') + [
        field('user', 'User', 'text', required=True, default='acme',
              help='an admin with the ERS Admin role (or Super Admin)'),
        field('password', 'Password', 'secret', required=True),
        field('node', 'Node hostname', 'text', required=True, placeholder='ise01',
              help='the node\'s hostname as ISE lists it (Administration → System → '
                   'Deployment)'),
    ] + tls_fields()
    deploy_fields = [
        field('roles', 'Use it for', 'list', default='eap\nportal',
              help='one a line: %s' % ', '.join(k for k, _ in ROLES)),
        field('portal_group_tag', 'Portal group tag', 'text', advanced=True,
              default='Default Portal Certificate Group'),
        field('trust_chain', 'Import the intermediates as trusted', 'bool', default=True,
              advanced=True),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        return {'Authorization': 'Basic ' + base64.b64encode(
            ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()}

    def node(self):
        return urllib.parse.quote(text(self.c('node')).strip(), safe='')

    def listed(self):
        st, hd, d = self.req('GET', '/api/v1/certs/system-certificate/%s?size=100' % self.node(),
                             what='listing the system certificates')
        res = (d or {}).get('response') if isinstance(d, dict) else None
        return [r for r in (res or []) if isinstance(r, dict)]

    def test(self):
        rs = self.listed()
        return 'signed in to %s; node %s has %d system certificate%s' % (
            self.c('host'), self.c('node'), len(rs), '' if len(rs) == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=60)
        prefix = name_prefix(bundle, options, maxlen=60)
        have = {r.get('friendlyName'): r.get('id') for r in self.listed()}
        if self.unchanged(bundle, options, present=lambda: name in have):
            return self.same(bundle, 'as %s' % name)
        roles = {x.strip().lower() for x in text(self.opt(options, 'roles', '')).split()}
        bad = roles - {k for k, _ in ROLES}
        if bad:
            raise PluginError('not a role of ISE: %s' % ', '.join(sorted(bad)), retry=False)
        if as_bool(self.opt(options, 'trust_chain', True), True):
            for pem in chain_list(bundle):
                try:
                    self.req('POST', '/api/v1/certs/trusted-certificate/import', {
                        'name': 'acme-ca-%s' % chain_id(pem), 'data': pem,
                        'trustForIseAuth': True, 'trustForClientAuth': False,
                        'allowBasicConstraintCAFalse': False, 'allowOutOfDateCert': False,
                        'allowSHA1Certificates': False, 'validateCertificateExtensions': False},
                        what='importing an intermediate as trusted')
                    self.ctx.step('imported the intermediate acme-ca-%s' % chain_id(pem))
                except PluginError as e:
                    self.ctx.debug('intermediate not imported (there already?): %s' % e)
        key, pw = self.encrypted_key(bundle)
        body = {'name': name, 'data': text(bundle.as_format('cert-pem')),
                'privateKeyData': key, 'password': pw,
                'allowExtendedValidity': True, 'allowOutOfDateCert': False,
                'allowReplacementOfCertificates': True,
                'allowReplacementOfPortalGroupTag': True,
                'allowPortalTagTransferForSameSubject': True,
                'allowRoleTransferForSameSubject': True,
                'allowSHA1Certificates': False,
                'allowWildCardCertificates': any(n.startswith('*.') for n in bundle.names),
                'validateCertificateExtensions': False}
        for k, _ in ROLES:
            body[k] = k in roles
        if 'portal' in roles:
            body['portalGroupTag'] = self.opt(options, 'portal_group_tag',
                                              'Default Portal Certificate Group')
        st, hd, d = self.req('POST', '/api/v1/certs/system-certificate/import', body,
                             what='importing %s' % name, timeout=180)
        r = (d or {}).get('response') or {} if isinstance(d, dict) else {}
        self.ctx.step('imported %s for %s%s' % (name, ', '.join(sorted(roles)) or 'no role',
                                                ' - %s' % r.get('message') if r.get('message')
                                                else ''), 'ok')
        if 'admin' in roles:
            self.ctx.step('the Admin role restarts the application server of %s (minutes)'
                          % self.c('node'), 'warn')
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return 'imported %s on %s for %s' % (name, self.c('node'), ', '.join(sorted(roles)) or
                                             'no role')

    def encrypted_key(self, bundle):
        """(PEM, password): the key encrypted with a random password."""
        key = bundle.as_format('key-pem')
        pw = random_password(20)
        try:
            enc = self.ctx.openssl(['pkcs8', '-topk8', '-v2', 'aes-256-cbc',
                                    '-passout', 'pass:' + pw], data=key)
            if b'ENCRYPTED PRIVATE KEY' in (enc or b''):
                return text(enc), pw
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('the key could not be encrypted: %s' % e)
        return text(key), ''

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            have = {r.get('friendlyName'): r.get('id') for r in self.listed()}
        except PluginError as e:
            self.ctx.step('the old certificates cannot be listed: %s' % e, 'warn')
            return
        for old in prune([n for n in have if n], prefix, keep, current):
            try:
                self.req('DELETE', '/api/v1/certs/system-certificate/%s/%s'
                         % (self.node(), urllib.parse.quote(text(have[old]), safe='')),
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')
