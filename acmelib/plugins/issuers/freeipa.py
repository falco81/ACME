# -*- coding: utf-8 -*-
"""
Certificates from FreeIPA / Red Hat Identity Management (its Dogtag CA)
through the IPA JSON-RPC API, as `ipa cert-request` asks for them.

From FreeIPA's source (github.com/freeipa/freeipa, read 2026-11):
ipaserver/rpcserver.py (/ipa/session/login_password, /ipa/session/json, the
Referer check, the ipa_session cookie) and ipaserver/plugins/cert.py
(cert_request, cert_revoke, cert_show); the same as
https://freeipa.readthedocs.io/en/latest/api/basic_usage.html :

* POST /ipa/session/login_password (form user, password) -> the cookie
  ipa_session; every call after it carries it and
  Referer: https://<server>/ipa.
* POST /ipa/session/json {"method": "cert_request/1", "params": [[csr],
  {"principal": "HTTP/www.example.com@REALM", "profile_id":
  "caIPAserviceCert", "cacn": "ipa", "add": true, "chain": true}]} ->
  result.result {certificate (base64 DER), certificate_chain [...],
  serial_number, request_id}.
* cert_revoke/1 [[serial], {"revocation_reason": n, "cacn": ...}].
* ping/1 for "Try it".

The principal's realm, the service ("HTTP") and whether a missing service is
added are settings; the user needs the "Certificate Administrators" role
(or "Request Certificate" and the CA ACL of the profile).
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc


class FreeIpaIssuer(Issuer):
    kind = 'freeipa'
    title = 'FreeIPA / Red Hat IdM'
    description = ('Certificates from the CA of FreeIPA (Red Hat Identity Management, Dogtag) '
                   'for a service principal, through the IPA JSON-RPC API with a user and '
                   'password. Revocation included.')
    vendor = 'Red Hat'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = False
    ip_names = True
    fields = [
        field('url', 'IPA server', 'text', required=True, placeholder='https://ipa.example.local'),
        field('user', 'User', 'text', required=True, placeholder='svc-acme',
              help='A user with the role "Certificate Administrators" (or rights to request '
                   'certificates for the services, and the CA ACL of the profile).'),
        field('password', 'Password', 'secret', required=True),
        field('realm', 'Realm', 'text', required=True, placeholder='EXAMPLE.LOCAL'),
        field('service', 'Service', 'text', default='HTTP',
              help='The principal is SERVICE/first-name@REALM.'),
        field('add_service', 'Add the service when missing', 'bool', default=True),
        field('profile', 'Profile', 'text', default='caIPAserviceCert',
              help='A certificate profile of IPA. A certificate\'s profile "template" wins.'),
        field('cacn', 'CA', 'text', default='ipa', advanced=True,
              help='A sub-CA of IPA by its name; ipa is the main one.'),
        field('ca_pem', 'IPA\'s CA certificate', 'pem',
              help='/etc/ipa/ca.crt - for the server\'s TLS.'),
        field('verify', 'Check the server\'s TLS certificate', 'bool', default=True, advanced=True),
    ]

    _cookie = None

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if url.endswith('/ipa'):
            url = url[:-4]
        if not re.match(r'^https://[^\s/]+\Z', url):
            raise PluginError('set the IPA server (https://ipa.example.local)', retry=False)
        return url

    def _http(self, path, body, headers):
        h = {'Referer': self._base() + '/ipa', 'Accept': 'application/json'}
        h.update(headers)
        if self._cookie:
            h['Cookie'] = self._cookie
        return sc.http(self.ctx, 'POST', self._base() + path, body, h, who='IPA',
                       verify=sc.as_bool(self.c('verify'), True), ca_pem=self.c('ca_pem') or None)

    def login(self):
        if self._cookie:
            return
        if not self.c('user') or not self.c('password'):
            raise PluginError('set the IPA user and password', retry=False)
        form = urllib.parse.urlencode({'user': self.c('user'), 'password': self.c('password')})
        status, h, data = self._http('/ipa/session/login_password', form,
                                     {'Content-Type': 'application/x-www-form-urlencoded',
                                      'Accept': 'text/plain'})
        if status == 401:
            raise PluginError('IPA does not let the user in (401) - the user, the password, or '
                              'the password expired (%s)' % (h.get('x-ipa-rejection-reason') or
                                                             'no reason said'), retry=False)
        if status != 200:
            raise sc.refusal('IPA (login)', status, None, data)
        m = re.search(r'ipa_session=([^;,\s]+)', str(h.get('set-cookie') or ''))
        if not m:
            raise PluginError('IPA gave no session cookie')
        self._cookie = 'ipa_session=' + m.group(1)

    def rpc(self, method, args, options, what=None):
        self.login()
        body = {'method': method, 'params': [args, options], 'id': 0}
        status, _h, data = self._http('/ipa/session/json', body, {'Content-Type': 'application/json'})
        got = sc.parse_json(data) or {}
        if status != 200:
            raise sc.refusal('IPA (%s)' % (what or method), status, got, data)
        err = got.get('error')
        if err:
            words = err.get('message') if isinstance(err, dict) else str(err)
            raise PluginError('IPA refused %s: %s' % (what or method, words), retry=False,
                              detail=str(err)[:2000])
        return got.get('result') or {}

    def test(self):
        got = self.rpc('ping/1', [], {}, 'ping')
        return 'IPA answers and lets the user in: %s' % (got.get('summary') or 'pong')

    def principal(self, req):
        name = (req.names or [''])[0]
        svc = str(self.c('service') or 'HTTP').strip()
        realm = str(self.c('realm') or '').strip().upper()
        if not re.match(r'^[A-Za-z0-9._-]+\Z', svc) or not re.match(r'^[A-Z0-9._-]+\Z', realm):
            raise PluginError('set the service (HTTP) and the realm (EXAMPLE.LOCAL)', retry=False)
        if not name or name.startswith('*.'):
            raise PluginError('IPA issues for a host or service name, not a wildcard', retry=False)
        return '%s/%s@%s' % (svc, name, realm)

    def issue(self, req):
        principal = self.principal(req)
        opts = {'principal': principal, 'chain': True,
                'profile_id': str((req.profile or {}).get('template') or self.c('profile') or
                                  'caIPAserviceCert'),
                'cacn': str(self.c('cacn') or 'ipa')}
        if sc.as_bool(self.c('add_service'), True):
            opts['add'] = True
        sc.say(self.ctx, 'cert_request to IPA for %s (profile %s)' % (principal, opts['profile_id']))
        got = self.rpc('cert_request/1', [sc.csr_pem(req)], opts, 'the request')
        res = got.get('result') if isinstance(got.get('result'), dict) else got
        certs = sc.certs_of(res.get('certificate'))
        chain = sc.certs_of(res.get('certificate_chain') or [])
        return sc.finish(self.ctx, req, certs, chain, who='IPA',
                         info={'ipa_request_id': res.get('request_id'),
                               'ipa_principal': principal})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = sc.cert_of_pem(cert_pem).serial
        code = sc.reason_code(reason)
        self.rpc('cert_revoke/1', [str(serial)], {'revocation_reason': code,
                                                  'cacn': str(self.c('cacn') or 'ipa')}, 'revoke')
        return 'IPA revoked serial %d' % serial
