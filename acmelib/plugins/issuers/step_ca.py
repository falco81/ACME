# -*- coding: utf-8 -*-
"""
Certificates from Smallstep step-ca by its own API with a JWK provisioner -
for a step-ca without ACME, or names ACME cannot prove (internal names).
(step-ca with an ACME provisioner is the acme issuer: "Another ACME server".)

From step-ca's source (github.com/smallstep/certificates, read 2026-11):
api/api.go (the routes), api/sign.go, api/revoke.go,
authority/provisioner/jwk.go and collection.go; the same as
https://smallstep.com/docs/step-ca/provisioners/#jwk :

* POST /1.0/sign {csr (PEM), ott, notBefore, notAfter} -> {crt, ca,
  certChain [...]}. The one-time token (ott) is a JWT signed with the
  provisioner's private key (ES256 for the default P-256 key; header kid =
  the key's id): iss = the provisioner's name, aud = https://<ca>/1.0/sign
  (the port is not compared), sub = the common name, sans = the names,
  iat / nbf / exp (5 minutes), jti (once), sha = the root's SHA-256 (as the
  step CLI sends it).
* POST /1.0/revoke {serial (decimal), ott (sub = the serial, aud =
  /1.0/revoke), reasonCode, reason, passive: true}.
* GET /1.0/provisioners and /health for "Try it".

The provisioner's key: step-ca keeps it encrypted (JWE) in ca.json; it is
given here decrypted, as the JWK of
`step crypto jwe decrypt < encrypted-key.json` or as a PEM key - see
docs/sources.md (step-ca).
"""
from __future__ import annotations

import hashlib
import os
import re
import time

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc


class StepCaIssuer(Issuer):
    kind = 'step_ca'
    dual = True
    title = 'Smallstep step-ca (JWK provisioner)'
    description = ('Certificates from step-ca by its own API: each request carries a one-time '
                   'token signed with a JWK provisioner\'s key - no ACME validation, for internal '
                   'names. Revocation included.')
    vendor = 'Smallstep'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    choose_days = True
    fields = [
        field('url', 'step-ca address', 'text', required=True, placeholder='https://ca.example.local:9000'),
        field('root_pem', 'Root certificate of the CA', 'pem', required=True,
              help='step-ca\'s root (root_ca.crt): its TLS is checked against it, and its '
                   'fingerprint goes in the token.'),
        field('provisioner', 'Provisioner', 'text', required=True, placeholder='acme-jwk',
              help='The name of a JWK provisioner (step ca provisioner list).'),
        field('provisioner_key', 'Provisioner key', 'secret', multiline=True, required=True,
              help='The provisioner\'s private key, decrypted: the JWK JSON of `step crypto jwe '
                   'decrypt` (EC or RSA), or a PEM key.'),
        field('kid', 'Key ID', 'text', advanced=True,
              help='The provisioner key\'s id (kid). Empty: the JWK\'s, else asked of the CA.'),
        field('verify', 'Check the CA\'s TLS certificate', 'bool', default=True, advanced=True),
    ]

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+\Z', url):
            raise PluginError('set the step-ca address (https://host:port)', retry=False)
        return url

    def _root(self):
        certs = sc.certs_of(self.c('root_pem') or '')
        if not certs:
            raise PluginError('set the root certificate of step-ca', retry=False)
        return certs[0]

    def _call(self, method, path, body=None, what='step-ca'):
        root = sc.p7.pem(self._root())
        status, _h, data = sc.http(self.ctx, method, self._base() + path, body, {},
                                   who='step-ca', verify=sc.as_bool(self.c('verify'), True),
                                   ca_pem=root)
        parsed = sc.parse_json(data)
        if status not in (200, 201):
            raise sc.refusal(what, status, parsed, data,
                             'the token was refused: the provisioner\'s name, key or the clock')
        return parsed or {}

    def _key(self):
        raw = str(self.c('provisioner_key') or '').strip()
        if not raw:
            raise PluginError('set the provisioner key', retry=False)
        if raw.startswith('{'):
            jwk = sc.parse_json(raw)
            if isinstance(jwk, dict) and jwk.get('protected') and jwk.get('ciphertext'):
                raise PluginError('this is the encrypted key (JWE): decrypt it with `step crypto '
                                  'jwe decrypt` and give the JWK', retry=False)
            return sc.jwk_to_pem(jwk), (jwk or {}).get('kid')
        if 'PRIVATE KEY' in raw and 'ENCRYPTED' not in raw:
            return raw, None
        raise PluginError('the provisioner key is neither a private JWK nor a PEM key without '
                          'a passphrase', retry=False)

    def _kid(self, jwk_kid):
        kid = str(self.c('kid') or '').strip() or jwk_kid
        if kid:
            return kid
        for p in self._provisioners():
            if p.get('name') == self.c('provisioner') and p.get('type') == 'JWK':
                kid = (p.get('key') or {}).get('kid')
                if kid:
                    return kid
        raise PluginError('the CA has no JWK provisioner "%s"' % self.c('provisioner'), retry=False)

    def _provisioners(self):
        out, cursor = [], ''
        for _ in range(20):
            got = self._call('GET', '/1.0/provisioners' + ('?cursor=%s' % cursor if cursor else ''),
                             what='step-ca (provisioners)')
            out += got.get('provisioners') or []
            cursor = got.get('nextCursor') or ''
            if not cursor:
                break
        return out

    def token(self, aud_path, sub, sans=None):
        key_pem, jwk_kid = self._key()
        now = int(time.time())
        claims = {'iss': str(self.c('provisioner')), 'aud': self._base() + aud_path, 'sub': sub,
                  'iat': now, 'nbf': now - 30, 'exp': now + 300, 'jti': sc.b64u(os.urandom(18)),
                  'sha': hashlib.sha256(self._root()).hexdigest()}
        if sans:
            claims['sans'] = list(sans)
        return sc.jwt(self.ctx, key_pem, claims, {'kid': self._kid(jwk_kid)})

    def test(self):
        got = self._call('GET', '/health', what='step-ca (health)')
        names = [p.get('name') for p in self._provisioners() if p.get('type') == 'JWK']
        if self.c('provisioner') not in names:
            raise PluginError('step-ca answers (%s), but has no JWK provisioner "%s" (it has: %s)'
                              % (got.get('status') or '?', self.c('provisioner'),
                                 ', '.join(names) or 'none'), retry=False)
        self._key()
        return 'step-ca answers (%s); the JWK provisioner %s is there, its key reads' % (
            got.get('status') or '?', self.c('provisioner'))

    def issue(self, req):
        names = list(req.names or [])
        if not names:
            raise PluginError('the certificate has no names', retry=False)
        body = {'csr': sc.csr_pem(req), 'ott': self.token('/1.0/sign', names[0], names)}
        if req.days:
            body['notAfter'] = '%dh' % (int(req.days) * 24)
        sc.say(self.ctx, 'the request goes to step-ca (provisioner %s)' % self.c('provisioner'))
        got = self._call('POST', '/1.0/sign', body, what='step-ca (sign)')
        certs = sc.certs_of(got.get('crt'))
        chain = sc.certs_of(got.get('certChain') or []) + sc.certs_of(got.get('ca'))
        return sc.finish(self.ctx, req, certs, chain, who='step-ca')

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = str(sc.cert_of_pem(cert_pem).serial)
        code = sc.reason_code(reason)
        self._call('POST', '/1.0/revoke', {'serial': serial, 'ott': self.token('/1.0/revoke', serial),
                                           'reasonCode': code, 'reason': str(reason or ''),
                                           'passive': True}, what='step-ca (revoke)')
        return 'step-ca revoked serial %s' % serial
