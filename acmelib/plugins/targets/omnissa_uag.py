# -*- coding: utf-8 -*-
"""
Omnissa (formerly VMware) Unified Access Gateway: the TLS server certificate of its
Internet-facing services (end_user - the HTTPS proxy, the PCoIP and Blast Secure Gateway) and/or
of its admin interface (admin, port 9443), replaced through the UAG admin REST API.

    POST /rest/v1/jwt/login  {"username", "password", "refreshTokenExpiryInHours": 3..48}
         -> {"accessToken", "accessTokenExpiryTime", "refreshToken", ...}   (bearer JWT)
    GET  /rest/v1/config/certs/ssl/{end_user|admin}       the certificate in use (still there?)
    PUT  /rest/v1/config/certs/ssl/{end_user|admin}
         {"privateKeyPem": "<the key, PEM>",
          "certChainPem": "<target cert, intermediate certs, root cert if present>"}
    GET  /rest/v1/config/system                            -> SystemSettings {uagName, ...} (Test)

Sources:
    The UAG REST API's OpenAPI 3.0.1 document (rest-api-swagger.json, "Unified Access Gateway
    REST API", servers /rest): the paths above, CertificateChainAndKeyWrapper (both fields
    required), JwtTokenCreationRequest, JWTAuthenticationResponse, SystemSettings, security
    bearerAuth (JWT) - https://developer.omnissa.com/uag-rest-apis/api-docs/
    VMware, Unified Access Gateway (Access Point 2.8) - "Replace the Default TLS/SSL Server
    Certificate": the same PUT with HTTP basic authentication as admin
    https://docs.vmware.com/en/Unified-Access-Gateway/2.8/com.vmware.access-point-28-deploy-config/GUID-EDC244DD-07AB-4841-A893-84ADF8D59838.html
    https://github.com/numerate64/omnissa-uag-cert-automation (renew-and-push-uag.ps1)
    https://github.com/askaresh/scripts/blob/master/vmwareuagcertreplace
Less certain: the body of GET .../certs/ssl/{entity} is not described in the document (the
certificate is looked for in it, whatever its form); HTTP basic sign-in on versions whose API
takes only the token; whether every version takes an ECDSA or a PKCS#8 key.
"""
from __future__ import annotations

import base64
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, http_fields, tls_fields, verify_fields, family_of)

ENTITIES = {'end_user': 'the Internet-facing services', 'admin': 'the admin interface'}


def _b64_body(pem):
    """The base64 of the first certificate of a PEM, without line breaks."""
    m = re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text(pem), re.S)
    return re.sub(r'[^A-Za-z0-9+/=]', '', m.group(1)) if m else ''


class OmnisaUagTarget(HttpTarget):
    kind = 'omnissa_uag'
    title = 'Omnissa Unified Access Gateway (UAG)'
    vendor = 'Omnissa'
    description = ('Replaces the TLS certificate of an Omnissa (VMware) Unified Access Gateway - '
                   'its Internet-facing services (Horizon, Web Reverse Proxy, Tunnel), its admin '
                   'interface, or both - through the UAG admin REST API (port 9443).')
    doc = 'targets.md'
    discovery = False       # nothing to find: its fields are the sign-in
    fields = http_fields(9443, 'uag01.example.local') + [
        field('user', 'Admin user', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('auth', 'Sign-in', 'select', default='jwt', advanced=True,
              options=[['jwt', 'A token (POST /rest/v1/jwt/login)'],
                       ['basic', 'HTTP basic (user and password)']],
              help='a token, as the API of current versions asks; HTTP basic for an older UAG'),
    ] + tls_fields()
    deploy_fields = [
        field('scope', 'Which certificate', 'select', default='end_user',
              options=[['end_user', 'Internet-facing (END_USER)'], ['admin', 'Admin interface (ADMIN)'],
                       ['both', 'Both']],
              help='Internet-facing: what Horizon clients and browsers see on 443. The admin '
                   'interface (9443) is replaced last: its connector restarts with it'),
        field('key_format', 'Key format', 'select', default='traditional', advanced=True,
              options=[['traditional', 'RSA / EC private key (PKCS#1, SEC1)'],
                       ['pkcs8', 'PKCS#8 (BEGIN PRIVATE KEY)']],
              help='the UAG documentation and its scripts send "BEGIN RSA PRIVATE KEY"'),
    ] + verify_fields(443)
    default_verify_port = 443

    _token = None

    def auth_headers(self):
        if (self.c('auth') or 'jwt') == 'jwt':
            if not self._token:
                self._token = self.login()
            return {'Authorization': 'Bearer ' + self._token, 'Accept': 'application/json'}
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode(),
                'Accept': 'application/json'}

    def login(self):
        st, hd, d = self.req('POST', '/rest/v1/jwt/login',
                             {'username': text(self.c('user')), 'password': text(self.c('password')),
                              'refreshTokenExpiryInHours': 3},
                             auth=False, what='signing in to the UAG')
        tok = text((d or {}).get('accessToken') if isinstance(d, dict) else '')
        if not tok:
            raise PluginError('the UAG gave no token at sign-in', retry=False)
        return tok

    def test(self):
        st, hd, d = self.req('GET', '/rest/v1/config/system', what='reading the UAG\'s system settings')
        name = text(d.get('uagName') or '') if isinstance(d, dict) else ''
        return 'signed in to the UAG %s%s' % (self.c('host'), ' (%s)' % name if name else '')

    def entities(self, options):
        s = text(options.get('scope') or 'end_user').lower()
        if s == 'both':
            return ['end_user', 'admin']        # the admin one last: its connector restarts
        if s not in ENTITIES:
            raise PluginError('the certificate is end_user, admin or both, not %s' % s, retry=False)
        return [s]

    def has(self, entity, bundle):
        """Whether the UAG still serves this certificate there: its base64 found in what the GET
        answers - PEM, JSON with \\n escapes, whatever the version gives."""
        st, hd, d = self.req('GET', '/rest/v1/config/certs/ssl/%s' % entity,
                             what='reading the certificate of %s' % ENTITIES[entity])
        raw = d if isinstance(d, (bytes, str)) else repr(d)
        flat = re.sub(r'\\n|[^A-Za-z0-9+/=]', '', text(raw))
        want = _b64_body(bundle.as_format('cert-pem').decode())
        return bool(want) and want in flat

    def key_pem(self, bundle, options):
        if text(options.get('key_format') or 'traditional') == 'pkcs8':
            return bundle.as_format('key-pem').decode()
        if family_of(bundle) not in ('rsa', 'ec'):
            raise PluginError('the UAG takes an RSA or ECDSA key', retry=False)
        return bundle.as_format('key-traditional').decode()

    def deploy(self, bundle, options):
        options = options or {}
        ents = self.entities(options)
        if self.unchanged(bundle, options, present=lambda: all(self.has(e, bundle) for e in ents)):
            return self.same(bundle, 'on the UAG')
        body = {'privateKeyPem': self.key_pem(bundle, options).replace('\r\n', '\n'),
                'certChainPem': bundle.as_format('fullchain-pem').decode().replace('\r\n', '\n')}
        for e in ents:
            self.req('PUT', '/rest/v1/config/certs/ssl/%s' % e, body,
                     what='replacing the certificate of %s' % ENTITIES[e])
            self.ctx.step('%s (%s) takes the certificate' % (ENTITIES[e], e), 'ok')
        self.remember(bundle, options)
        return 'UAG %s: certificate replaced (%s)' % (self.c('host'), ', '.join(ents))
