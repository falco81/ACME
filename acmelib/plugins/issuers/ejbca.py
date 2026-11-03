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
* POST .../v1/certificate/search {max_number_of_results, criteria [{property (CA,
  STATUS, SERIAL_NUMBER...), value, operation (EQUAL...)}]} -> {certificates [...],
  more_results}; GET .../v1/ca/{subject_dn}/certificate/download - the CA's chain
  (PEM): Import from a source (the same openapi.json; STATUS CERT_ACTIVE as
  Keyfactor's own ejbca-go-client searches).

The REST interface must be switched on (System Configuration → Protocol
Configuration → REST Certificate Management) and the administrator's role
allowed the profiles and the CA. The end entity is made (or updated) by the
enrollment with the username and the enrollment code given here.

* The form's lists: GET .../v1/ca -> {certificate_authorities [{name, subject_dn}]};
  GET .../v2/endentity/profiles/authorized -> {end_entitie_profiles [{name, id,
  description}]} (the field's name as the OpenAPI spells it); GET
  .../v2/endentity/profile/{name} -> {available_certificate_profiles, available_cas}
  (openapi.json above; added in EJBCA 7.10.0.1 - its release notes). Both are under
  the /endentity/ resource, which Keyfactor's REST documentation marks "Enterprise":
  EJBCA Community probably does not answer them - the profile is typed then.

UNCERTAIN: a request that needs approval is answered 202 ("Most likely waiting for
administrator approval", the REST documentation's status codes); how it says the
request's id is not documented, so it is said in words and asked again (a new
request) at the next try. Whether the /v2/endentity/ lists answer in EJBCA
Community.
"""
from __future__ import annotations

import os
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
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
    lists_existing = True           # certificate/search: Certificates → Import from a source
    per_cert = [{'key': 'template', 'field': 'cert_profile', 'catalog': 'cert_profiles',
                 'label': 'Certificate profile', 'placeholder': 'SERVER',
                 'help': 'The EJBCA certificate profile for this certificate. Empty: the source\'s own.'}]
    fields = [
        field('url', 'EJBCA address', 'text', required=True, placeholder='https://ejbca.example.local',
              help='The server; /ejbca/ejbca-rest-api is added when the path does not have it.'),
        field('client_cert', 'Administrator\'s client certificate', 'pem', required=True,
              help='A certificate EJBCA knows as an administrator (a role with "/ra_functionality" '
                   'rights on the profiles and the CA). PEM, its chain after it.'),
        field('client_key', 'Client certificate\'s key', 'pem', secret=True, required=True),
        field('ca_name', 'CA', 'catalog', catalog='cas', required=True, placeholder='IssuingCA',
              depends=['url', 'client_cert', 'client_key'],
              help='The name of the CA in EJBCA. Load the list: the CAs (GET /v1/ca); a name can '
                   'be typed too.'),
        field('cert_profile', 'Certificate profile', 'catalog', catalog='cert_profiles',
              required=True, default='SERVER', depends=['url', 'client_cert', 'client_key',
                                                        'ee_profile'],
              help='Load the list: the certificate profiles of the end entity profile (GET '
                   '/v2/endentity/profile/NAME - likely EJBCA Enterprise only); a typed name '
                   'always works. A certificate\'s own profile (Add a certificate → Settings) '
                   'wins.'),
        field('ee_profile', 'End entity profile', 'catalog', catalog='ee_profiles',
              required=True, placeholder='TLS_SERVERS',
              depends=['url', 'client_cert', 'client_key'],
              help='Load the list: the end entity profiles the administrator may use (GET '
                   '/v2/endentity/profiles/authorized - likely EJBCA Enterprise only); a typed '
                   'name always works.'),
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

    def _call(self, method, path, body=None, what='EJBCA', ok=(200, 201)):
        if not self.c('client_cert') or not self.c('client_key'):
            raise PluginError('set the administrator\'s client certificate and its key',
                              retry=False)
        status, _h, data = sc.http(self.ctx, method, self._base() + path, body, {}, who='EJBCA',
                                   verify=sc.as_bool(self.c('verify'), True),
                                   ca_pem=self.c('ca_pem') or None,
                                   client_cert=(self.c('client_cert'), self.c('client_key')))
        parsed = sc.parse_json(data)
        if status == 202 and 202 not in ok:
            raise PluginError('EJBCA holds the request for an administrator\'s approval (%s) - '
                              'approve it in EJBCA; acme asks again at the next try' % what,
                              detail=(data or b'').decode('utf-8', 'replace')[:3000])
        if status not in ok:
            raise sc.refusal(what, status, parsed, data,
                             'the administrator (client certificate) may not do this: its role '
                             'in EJBCA, or the REST interface is off')
        return parsed or {}

    # -- the form's lists (base.py: a field of the type catalog) ------------------------
    def _listed(self, path, what):
        try:
            return self._call('GET', path, what='EJBCA (%s)' % what)
        except PluginError as e:
            if re.search(r'answered (403|404|405|501)\b', str(e)):
                raise PluginError('this EJBCA does not list %s (%s is likely EJBCA Enterprise '
                                  'only, or the administrator may not read it) - type the name'
                                  % (what, path), detail=getattr(e, 'detail', None), retry=False)
            raise

    def catalog(self, key):
        """The CAs (GET /v1/ca), the end entity profiles the administrator may use (GET
        /v2/endentity/profiles/authorized) and the certificate profiles of the end entity
        profile (GET /v2/endentity/profile/{name}) - openapi.json of Keyfactor/ejbca-ce.
        Read-only; the /v2/endentity/ ones are likely EJBCA Enterprise only."""
        if key == 'cas':
            cas = self._call('GET', '/v1/ca', what='the CAs').get('certificate_authorities') or []
            opts = [[str(c['name']), '%s (%s)' % (c['name'], c.get('subject_dn') or '?')]
                    for c in cas if isinstance(c, dict) and c.get('name')]
            return {'options': opts, 'said': '%d CA(s)' % len(opts)}
        if key == 'ee_profiles':
            got = self._listed('/v2/endentity/profiles/authorized', 'the end entity profiles')
            ps = [p for p in got.get('end_entitie_profiles') or got.get('end_entity_profiles')
                  or [] if isinstance(p, dict) and p.get('name')]
            opts = [[str(p['name']), '%s - %s' % (p['name'], p['description'])
                     if p.get('description') else str(p['name'])] for p in ps]
            return {'options': opts, 'said': '%d end entity profile(s)' % len(opts)}
        if key == 'cert_profiles':
            ee = str(self.c('ee_profile') or '').strip()
            if not ee:
                raise PluginError('set the end entity profile first - its certificate profiles '
                                  'are listed', retry=False)
            got = self._listed('/v2/endentity/profile/%s' % urllib.parse.quote(ee, safe=''),
                               'the certificate profiles')
            names = [str(n) for n in got.get('available_certificate_profiles') or [] if n]
            return {'options': [[n, n] for n in names],
                    'said': '%d certificate profile(s) of the end entity profile %s' % (
                        len(names), ee)}
        raise PluginError('there is no list called %s here' % key, retry=False)

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

    # -- the certificates of the CA (Certificates → Import from a source) -----------------
    SEARCH_MOST = 1000

    def _search(self, criteria, most=None):
        if not self.c('ca_name'):
            raise PluginError('set the CA', retry=False)
        body = {'max_number_of_results': int(most or self.SEARCH_MOST),
                'criteria': [{'property': 'CA', 'value': str(self.c('ca_name')),
                              'operation': 'EQUAL'}] + list(criteria)}
        got = self._call('POST', '/v1/certificate/search', body, what='EJBCA (search)')
        return [c for c in (got.get('certificates') or []) if isinstance(c, dict)], \
            bool(got.get('more_results'))

    def list_existing(self):
        """The active certificates of the CA (certificate/search) - read only."""
        from acmelib.certs import pki
        found, more = self._search([{'property': 'STATUS', 'value': 'CERT_ACTIVE',
                                     'operation': 'EQUAL'}])
        if more:
            sc.say(self.ctx, 'EJBCA has more than %d active certificates of the CA: the first '
                             '%d are listed' % (self.SEARCH_MOST, self.SEARCH_MOST), 'warn')
        out, now = [], time.time()
        for c in found:
            certs = sc.certs_of(c.get('certificate'))
            if not certs:
                continue
            try:
                info = pki.cert_info(sc.p7.pem(certs[0]))
            except Exception:                           # noqa: BLE001
                continue
            if info.get('is_ca'):
                continue
            na = info.get('not_after')
            out.append({'ref': info.get('serial'), 'cn': info.get('cn') or '',
                        'names': info.get('names') or [],
                        'product': str(c.get('certificate_profile') or ''),
                        'status': 'expired' if na and na < now else 'active',
                        'not_before': info.get('not_before'), 'not_after': na,
                        'serial': info.get('serial'), 'fingerprint': info.get('sha256'),
                        'downloadable': True, 'renewable': 'issue'})
        return out

    def fetch_existing(self, ref):
        """The certificate of serial `ref` (a search by its serial) and the CA's chain -
        read only."""
        serial = str(ref or '').strip().upper()
        if not re.match(r'^[0-9A-F]{1,64}\Z', serial):
            raise PluginError('%s is not a serial number' % (ref or '?'), retry=False)
        found, _more = self._search([{'property': 'SERIAL_NUMBER', 'value': serial,
                                      'operation': 'EQUAL'}], 10)
        certs = []
        for c in found:
            certs += sc.certs_of(c.get('certificate'))
        if not certs:
            raise PluginError('EJBCA has no certificate %s of the CA %s' % (
                serial, self.c('ca_name')), retry=False)
        chain = []
        for c in found:
            chain += sc.certs_of(c.get('certificate_chain') or [])
        if not chain:
            try:
                dn = sc.dn_rfc2253(self.ctx, sc.p7.pem(certs[0]), 'issuer')
                status, _h, data = sc.http(
                    self.ctx, 'GET', self._base() + '/v1/ca/%s/certificate/download' %
                    urllib.parse.quote(dn, safe=''), None, {}, who='EJBCA',
                    verify=sc.as_bool(self.c('verify'), True), ca_pem=self.c('ca_pem') or None,
                    client_cert=(self.c('client_cert'), self.c('client_key')))
                if status == 200:
                    chain = sc.certs_of(data)
            except PluginError as e:
                sc.say(self.ctx, 'the chain of the CA could not be read: %s' % e, 'warn')
        return sc.existing(certs, chain, who='EJBCA', ref=serial)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        issuer_dn = sc.dn_rfc2253(self.ctx, cert_pem, 'issuer')
        serial = sc.serial_hex(cert_pem)
        why = REVOKE.get(sc.reason_code(reason), 'UNSPECIFIED')
        got = self._call('PUT', '/v1/certificate/%s/%s/revoke?reason=%s' % (
            urllib.parse.quote(issuer_dn, safe=''), serial, why), what='EJBCA (revoke)')
        return 'EJBCA: %s' % (got.get('message') or 'revoked serial %s' % serial)

    # -- discovery (1.0.29): the form filled in from EJBCA ------------------------------------
    # Signing in is the administrator's client certificate: username, enrollment code and
    # account binding are the end entity's, not asked.
    discover_keys = ['url', 'client_cert', 'client_key', 'ca_pem', 'verify']
    DISCOVER_PROFILES = 20          # end entity profiles read one by one

    def discover_setup(self):
        """Read-only: the CAs (GET /v1/ca), the end entity profiles (GET /v2/endentity/
        profiles/authorized), each read (GET /v2/endentity/profile/{name}) for its
        certificate profiles and CAs - the only one of each set with it -, and the
        certificate profiles of the end entity profile set or found."""
        out = Plugin.discover_setup(self)
        ee = out['choices'].get('ee_profile')
        ofs = {}
        for name in [o[0] for o in (ee or {}).get('options') or []][:self.DISCOVER_PROFILES]:
            try:
                got = self._listed('/v2/endentity/profile/%s' % urllib.parse.quote(name, safe=''),
                                   'the end entity profile %s' % name)
            except PluginError as e:
                out['notes'].append('%s: %s' % (name, e))
                continue
            profs = [str(n) for n in got.get('available_certificate_profiles') or [] if n]
            cas = [str(n) for n in got.get('available_cas') or [] if n]
            ofs[name] = profs
            more = {}
            if len(profs) == 1:
                more['cert_profile'] = profs[0]
            if len(cas) == 1:
                more['ca_name'] = cas[0]
            if more:
                ee['sets'][name] = more
        pick = str(self.c('ee_profile') or '').strip() or (ee or {}).get('pick') or ''
        if 'cert_profile' not in out['choices'] and ofs.get(pick):
            self.offer(out, 'cert_profile', ofs[pick])
            out['notes'] = [n for n in out['notes'] if not n.startswith('Certificate profile:')]
        try:
            st = self._call('GET', '/v1/certificate/status', what='EJBCA (status)')
            if st.get('revision'):
                out['facts'].append(['Version', str(st['revision'])])
        except PluginError as e:
            out['notes'].append(str(e))
        return out
