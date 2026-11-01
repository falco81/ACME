# -*- coding: utf-8 -*-
"""
Certificates from GlobalSign Atlas through its HVCA API (High Volume CA):
a TLS client certificate (mTLS) and an API key and secret.

From GlobalSign's own client of the API (github.com/globalsign/hvclient -
client.go, client_login.go, client_api.go, request.go, cert_info.go, read
2026-11; the API's documentation: https://www.globalsign.com/en/resources/
apis/api-documentation/globalsign_atlas_certificate_management_api.html):

* https://emea.api.hvca.globalsign.com:8443/v2 (the URL of the account),
  every request over TLS with the account's client certificate.
* POST /login {api_key, api_secret} -> {access_token} (about 10 minutes),
  sent after as "Authorization: Bearer".
* POST /certificates {validity {not_before, not_after (0: the longest the
  policy allows)}, subject_dn {common_name, organization, ...}, san
  {dns_names, ip_addresses}, public_key: the PKCS#10 request (PEM)}
  -> 201, Location: .../certificates/<serial, hex>.
* GET /certificates/<serial> -> {certificate (PEM), status ISSUED|REVOKED,
  updated_at}; 202 or 404 while it is being made (asked again).
* GET /trustchain -> the chain (PEM, a list); GET /validationpolicy for "Try it".
* PATCH /certificates/<serial> {revocation_reason, revocation_time}.

The names must be verified domains of the account (Atlas: Domains → verify,
or the /claims/domains API) - Atlas refuses others.

UNCERTAIN: what Atlas answers for an unverified domain (said as it comes).
"""
from __future__ import annotations

import ipaddress
import re
import time

from acmelib.plugins.base import Issuer, PluginError, field, dual_order_field
from acmelib.plugins.issuers import _source_common as sc

REASONS = {0: 'unspecified', 1: 'keyCompromise', 3: 'affiliationChanged', 4: 'superseded',
           5: 'cessationOfOperation', 9: 'privilegeWithdrawn'}
SUBJECT = {'CN': 'common_name', 'O': 'organization', 'C': 'country', 'ST': 'state',
           'L': 'locality', 'emailAddress': 'email'}


def _is_ip(n):
    try:
        ipaddress.ip_address(n)
        return True
    except ValueError:
        return False


class GlobalSignAtlasIssuer(Issuer):
    kind = 'globalsign_atlas'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'GlobalSign Atlas (HVCA)'
    description = ('Certificates from GlobalSign Atlas through its HVCA API, signed in with the '
                   'account\'s client certificate and an API key; the names must be verified '
                   'domains of the account. Revocation included.')
    vendor = 'GlobalSign'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    public_names = True             # a publicly trusted CA
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    choose_days = True
    fields = [
        field('url', 'API address', 'text', required=True,
              default='https://emea.api.hvca.globalsign.com:8443/v2',
              help='As GlobalSign gave it for the account (with /v2).'),
        field('api_key', 'API key', 'text', required=True),
        field('api_secret', 'API secret', 'secret', required=True),
        field('client_cert', 'mTLS certificate', 'pem', required=True,
              help='The client certificate of the Atlas account (made in the Atlas portal with '
                   'the API credentials).'),
        field('client_key', 'mTLS certificate\'s key', 'pem', secret=True, required=True),
        field('days', 'Validity (days)', 'number', default=0,
              help='0: the longest the account\'s policy allows. A certificate\'s own days win.'),
        field('subject_extra', 'More of the subject', 'list', advanced=True,
              placeholder='organization=Example s.r.o.',
              help='key=value lines added to subject_dn (as the account\'s policy wants: '
                   'organization, country, locality ...).'),
        field('wait', 'Wait for the certificate (s)', 'number', default=60, advanced=True),
        field('ca_pem', 'CA certificate of the API\'s TLS', 'pem', advanced=True),
        field('verify', 'Check the API\'s TLS certificate', 'bool', default=True, advanced=True),
    ]
    fields = fields + [dual_order_field()]

    _token = None
    _token_at = 0.0

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('set the API address (https://…/v2)', retry=False)
        return url

    def _raw(self, method, path, body=None, auth=True):
        if not self.c('client_cert') or not self.c('client_key'):
            raise PluginError('set the mTLS certificate and its key', retry=False)
        h = {'Content-Type': 'application/json;charset=utf-8'} if body is not None else {}
        if auth:
            h['Authorization'] = 'Bearer ' + self.token()
        return sc.http(self.ctx, method, self._base() + path, body, h, who='GlobalSign Atlas',
                       verify=sc.as_bool(self.c('verify'), True), ca_pem=self.c('ca_pem') or None,
                       client_cert=(self.c('client_cert'), self.c('client_key')))

    def _call(self, method, path, body=None, what='Atlas', ok=(200, 201, 204), auth=True):
        status, h, data = self._raw(method, path, body, auth)
        parsed = sc.parse_json(data)
        if status not in ok:
            raise sc.refusal('GlobalSign Atlas (%s)' % what, status, parsed, data,
                             'the API key, secret or mTLS certificate is wrong')
        return status, h, parsed

    def token(self):
        if self._token and time.time() - self._token_at < 540:
            return self._token
        _s, _h, got = self._call('POST', '/login', {'api_key': str(self.c('api_key') or ''),
                                                    'api_secret': str(self.c('api_secret') or '')},
                                 'login', auth=False)
        if not (got or {}).get('access_token'):
            raise PluginError('GlobalSign Atlas gave no access token', retry=False)
        self._token, self._token_at = got['access_token'], time.time()
        return self._token

    def test(self):
        _s, _h, pol = self._call('GET', '/validationpolicy', what='policy')
        val = (pol or {}).get('validity') or {}
        _s, _h, tc = self._call('GET', '/trustchain', what='trust chain')
        certs = sc.certs_of(tc or [])
        return 'GlobalSign Atlas answers: signed in; validity up to %s days; issued under %s' % (
            int(val.get('secondsmax') or 0) // 86400 or '?',
            sc.cert_of_pem(sc.p7.pem(certs[0])).subject_cn if certs else '?')

    def body(self, req):
        names = list(req.names or [])
        days = int(req.days or sc.num(self.c('days'), 0) or 0)
        now = int(time.time())
        subject = {}
        for k, v in (req.subject or {}).items():
            if SUBJECT.get(k) and v:
                subject[SUBJECT[k]] = str(v)
        subject.setdefault('common_name', names[0])
        for line in sc.lines(self.c('subject_extra')):
            if '=' in line:
                k, v = line.split('=', 1)
                if re.match(r'^[a-z_]+\Z', k.strip()):
                    subject[k.strip()] = v.strip()
        san = {}
        dns = [n for n in names if not _is_ip(n)]
        ips = [n for n in names if _is_ip(n)]
        if dns:
            san['dns_names'] = dns
        if ips:
            san['ip_addresses'] = ips
        return {'validity': {'not_before': now, 'not_after': now + days * 86400 if days else 0},
                'subject_dn': subject, 'san': san, 'public_key': sc.csr_pem(req).strip()}

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        slot = sc.pending_slot('atlas', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        if held and held.get('id'):
            serial = held['id']
            sc.say(self.ctx, 'the certificate %s asked for earlier is fetched' % serial)
        else:
            sc.say(self.ctx, 'the request goes to GlobalSign Atlas for %s' % ', '.join(req.names))
            _s, h, _got = self._call('POST', '/certificates', self.body(req), 'request')
            serial = str(h.get('location') or '').rstrip('/').split('/')[-1]
            if not re.match(r'^[0-9A-Fa-f]+\Z', serial):
                raise PluginError('GlobalSign Atlas said no serial for the request (Location: %s)'
                                  % (h.get('location') or 'none'))
            held = sc.pending_put(self.ctx, slot, req, {'id': serial, 'csr_pem': sc.csr_pem(req)})
            r = req
        end = time.time() + sc.num(self.c('wait'), 60)
        while True:
            status, _h, data = self._raw('GET', '/certificates/%s' % serial)
            got = sc.parse_json(data) or {}
            if status == 200 and got.get('certificate'):
                break
            if status in (202, 404, 503) or (status == 200 and not got.get('certificate')):
                if time.time() >= end or self.ctx.cancelled():
                    raise PluginError('GlobalSign Atlas is still making certificate %s - acme '
                                      'fetches it at the next try' % serial)
                time.sleep(2)
                continue
            sc.pending_drop(self.ctx, slot)
            raise sc.refusal('GlobalSign Atlas (certificate %s)' % serial, status, got, data)
        sc.pending_drop(self.ctx, slot)
        chain = []
        try:
            _s, _h, tc = self._call('GET', '/trustchain', what='trust chain')
            chain = sc.certs_of(tc or [])
        except PluginError as e:
            sc.say(self.ctx, 'the trust chain could not be fetched: %s' % e, 'warn')
        return sc.finish(self.ctx, r, sc.certs_of(got['certificate']), chain,
                         who='GlobalSign Atlas', key_pem=r.key_pem if r is not req else None,
                         info={'atlas_serial': serial})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = sc.serial_hex(cert_pem)
        why = REASONS.get(sc.reason_code(reason), 'unspecified')
        self._call('PATCH', '/certificates/%s' % serial, {'revocation_reason': why}, 'revoke')
        return 'GlobalSign Atlas revoked serial %s (%s)' % (serial, why)

