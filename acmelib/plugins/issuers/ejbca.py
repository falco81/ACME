# -*- coding: utf-8 -*-
"""
Certificates from EJBCA (Keyfactor EJBCA Community or Enterprise) through its
REST API, signed in with a client certificate (an administrator EJBCA knows).

From EJBCA's OpenAPI description (github.com/Keyfactor/ejbca-ce,
modules/ejbca-rest-api/resources/openapi.json, read 2026-11; the same as
https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface):

* POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll with
  {certificate_request (PEM), certificate_profile_name,
  end_entity_profile_name, certificate_authority_name, username, password,
  include_chain, email, account_binding_id} -> {certificate,
  serial_number, response_format, certificate_chain [...]} - the
  certificates base64 (DER; seen base64 twice over as well, both are read).
* PUT .../v1/certificate/{issuer_dn}/{serial (hex)}/revoke?reason=SUPERSEDED.
* GET .../v1/certificate/status and .../v1/ca for "Try it".

The REST interface must be switched on (System Configuration → Protocol
Configuration → REST Certificate Management) and the administrator's role
allowed the profiles and the CA. The end entity is made (or updated) by the
enrollment with the username and the enrollment code given here.

UNCERTAIN: a request that needs approval answers with an error in the
versions read; it is said as it is and asked again at the next try.
"""
from __future__ import annotations

import os
import re
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc

REVOKE = {0: 'UNSPECIFIED', 1: 'KEY_COMPROMISE', 2: 'CA_COMPROMISE', 3: 'AFFILIATION_CHANGED',
          4: 'SUPERSEDED', 5: 'CESSATION_OF_OPERATION', 6: 'CERTIFICATE_HOLD',
          9: 'PRIVILEGES_WITHDRAWN', 10: 'AA_COMPROMISE'}


class EjbcaIssuer(Issuer):
    kind = 'ejbca'
    dual = True                     # where the certificate profile allows both algorithms
    title = 'EJBCA (REST API)'
    description = ('Certificates from EJBCA (Keyfactor, Community or Enterprise) through its '
                   'REST API: the request enrolled with a certificate profile, an end entity '
                   'profile and a CA, signed in with an administrator\'s client certificate.')
    vendor = 'Keyfactor'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('url', 'EJBCA address', 'text', required=True, placeholder='https://ejbca.example.local',
              help='The server; /ejbca/ejbca-rest-api is added when the path does not have it.'),
        field('client_cert', 'Administrator\'s client certificate', 'pem', required=True,
              help='A certificate EJBCA knows as an administrator (a role with "/ra_functionality" '
                   'rights on the profiles and the CA). PEM, its chain after it.'),
        field('client_key', 'Client certificate\'s key', 'pem', secret=True, required=True),
        field('ca_name', 'CA', 'text', required=True, placeholder='IssuingCA',
              help='The name of the CA in EJBCA ("Try it" lists them).'),
        field('cert_profile', 'Certificate profile', 'text', required=True, default='SERVER',
              help='A certificate\'s own profile "template" wins.'),
        field('ee_profile', 'End entity profile', 'text', required=True, placeholder='TLS_SERVERS'),
        field('username', 'End entity name', 'text', default='{cn}',
              help='The end entity the certificate is enrolled for: {cn} is the first name of '
                   'the certificate, {id} acme\'s id of it.'),
        field('enroll_code', 'Enrollment code', 'secret',
              help='The end entity\'s password (enrollment code). Empty: one made for each '
                   'request.'),
        field('email', 'E-mail', 'text', advanced=True),
        field('account_binding', 'Account binding ID', 'text', advanced=True),
        field('ca_pem', 'CA certificate of EJBCA\'s TLS', 'pem', advanced=True),
        field('verify', 'Check EJBCA\'s TLS certificate', 'bool', default=True, advanced=True),
    ]

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+', url):
            raise PluginError('set the EJBCA address (https://...)', retry=False)
        if '/ejbca-rest-api' not in url:
            url += '/ejbca/ejbca-rest-api'
        return url

    def _call(self, method, path, body=None, what='EJBCA'):
        if not self.c('client_cert') or not self.c('client_key'):
            raise PluginError('set the administrator\'s client certificate and its key',
                              retry=False)
        status, _h, data = sc.http(self.ctx, method, self._base() + path, body, {}, who='EJBCA',
                                   verify=sc.as_bool(self.c('verify'), True),
                                   ca_pem=self.c('ca_pem') or None,
                                   client_cert=(self.c('client_cert'), self.c('client_key')))
        parsed = sc.parse_json(data)
        if status not in (200, 201):
            raise sc.refusal(what, status, parsed, data,
                             'the administrator (client certificate) may not do this: its role '
                             'in EJBCA, or the REST interface is off')
        return parsed or {}

    def test(self):
        st = self._call('GET', '/v1/certificate/status', what='EJBCA (status)')
        cas = self._call('GET', '/v1/ca', what='EJBCA (CAs)').get('certificate_authorities') or []
        names = [c.get('name') for c in cas if c.get('name')]
        want = str(self.c('ca_name') or '')
        words = 'EJBCA answers (%s, REST %s); CAs: %s' % (
            st.get('revision') or '?', st.get('status') or '?', ', '.join(names) or 'none seen')
        if want and names and want not in names:
            raise PluginError('%s - there is no CA "%s"' % (words, want), retry=False)
        return words

    def _username(self, req):
        tpl = str(self.c('username') or '{cn}')
        u = tpl.replace('{cn}', (req.names or ['acme'])[0]).replace('{id}', str(req.cert_id or ''))
        u = re.sub(r'[^A-Za-z0-9._@*-]', '_', u)[:200]
        return u or 'acme'

    def issue(self, req):
        for k in ('ca_name', 'cert_profile', 'ee_profile'):
            if not self.c(k):
                raise PluginError('set the CA, the certificate profile and the end entity profile',
                                  retry=False)
        prof = str((req.profile or {}).get('template') or self.c('cert_profile'))
        code = str(self.c('enroll_code') or '') or sc.b64u(os.urandom(18))
        body = {'certificate_request': sc.csr_pem(req), 'certificate_profile_name': prof,
                'end_entity_profile_name': str(self.c('ee_profile')),
                'certificate_authority_name': str(self.c('ca_name')),
                'username': self._username(req), 'password': code, 'include_chain': True}
        if self.c('email'):
            body['email'] = str(self.c('email'))
        if self.c('account_binding'):
            body['account_binding_id'] = str(self.c('account_binding'))
        sc.say(self.ctx, 'the request goes to EJBCA: CA %s, profile %s, end entity %s' % (
            body['certificate_authority_name'], prof, body['username']))
        got = self._call('POST', '/v1/certificate/pkcs10enroll', body, what='EJBCA (enroll)')
        certs = sc.certs_of(got.get('certificate'))
        chain = sc.certs_of(got.get('certificate_chain') or [])
        return sc.finish(self.ctx, req, certs, chain, who='EJBCA',
                         info={'ejbca_serial': got.get('serial_number')})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        issuer_dn = sc.dn_rfc2253(self.ctx, cert_pem, 'issuer')
        serial = sc.serial_hex(cert_pem)
        why = REVOKE.get(sc.reason_code(reason), 'UNSPECIFIED')
        got = self._call('PUT', '/v1/certificate/%s/%s/revoke?reason=%s' % (
            urllib.parse.quote(issuer_dn, safe=''), serial, why), what='EJBCA (revoke)')
        return 'EJBCA: %s' % (got.get('message') or 'revoked serial %s' % serial)
