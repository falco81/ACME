# -*- coding: utf-8 -*-
"""
Azure Key Vault: the certificate imported as a new version of one Key Vault
certificate, so whatever uses it without a version - Application Gateway,
App Service (Key Vault references), Front Door, API Management - takes it by
itself (most within hours; App Service syncs every 24 h, or at once with
"Sync").

    POST https://<vault>.vault.azure.net/certificates/<name>/import?api-version=7.4
         {"value": key + full chain (PEM), "policy": {"secret_props":
          {"contentType": "application/x-pem-file"}, "key_props": {"exportable": true}}}
    GET  .../certificates/<name>?api-version=7.4 -> x5t (base64url SHA-1)

The token: OAuth2 client credentials of an app registration, scope
https://vault.azure.net/.default (as challenges/azure_dns.py).

Sources:
    https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/import-certificate/import-certificate
    https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate
    https://learn.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, label_of, sha1_thumb, text, verify_fields, as_bool)
from acmelib.plugins.targets._cloud import (
    CloudTarget, cloud_fields, entra_token, ENTRA_CLOUDS)

API = '7.4'


def kv_name(bundle, options):
    """A Key Vault certificate's name: 1-127 of 0-9 a-z A-Z and '-'."""
    raw = text((options or {}).get('cert_name')).strip()
    if raw:
        if not re.match(r'^[0-9A-Za-z-]{1,127}$', raw):
            raise PluginError('"%s" is not a Key Vault name (letters, digits and -)' % raw,
                              retry=False)
        return raw
    return ('acme-' + re.sub(r'[^0-9a-z-]+', '-', label_of(bundle, options, 100))).strip('-')


class AzureKeyVaultTarget(CloudTarget):
    kind = 'azure_keyvault'
    title = 'Azure Key Vault'
    vendor = 'Microsoft'
    description = ('Imports the certificate as a new version in Azure Key Vault, where '
                   'Application Gateway, App Service, Front Door and API Management take it.')
    doc = 'targets.md'
    fields = [
        field('vault', 'Key Vault', 'text', required=True, placeholder='kv-firma',
              help='its name, or its URL (https://kv-firma.vault.azure.net)'),
        field('tenant_id', 'Tenant (directory) ID', 'text', required=True),
        field('client_id', 'Client (application) ID', 'text', required=True,
              help='An app registration with the role "Key Vault Certificates Officer" on the '
                   'vault (or, with access policies, Certificates: Get, List, Import).'),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('cloud', 'Cloud', 'select', default='public', advanced=True,
              options=[['public', 'Azure'], ['china', 'Azure China (21Vianet)'],
                       ['usgov', 'Azure US Government']]),
    ] + cloud_fields()
    deploy_fields = [
        field('cert_name', 'Certificate name in the vault', 'text',
              placeholder='www-example-com',
              help='letters, digits and -; empty: acme-<the certificate\'s name>'),
    ] + verify_fields()

    def vault_url(self):
        v = text(self.c('vault')).strip().rstrip('/')
        if v.startswith('https://'):
            return v
        if not re.match(r'^[0-9A-Za-z-]{3,24}$', v):
            raise PluginError('"%s" is not a Key Vault name' % v, retry=False)
        suffix = ENTRA_CLOUDS.get(self.c('cloud', 'public'), ENTRA_CLOUDS['public'])[1]
        return 'https://%s.%s' % (v, suffix)

    def scope(self):
        suffix = ENTRA_CLOUDS.get(self.c('cloud', 'public'), ENTRA_CLOUDS['public'])[1]
        return 'https://%s/.default' % suffix

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % entra_token(self, self.scope())}

    def url(self, path, **q):
        q['api-version'] = API
        return '%s%s?%s' % (self.vault_url(), path, urllib.parse.urlencode(q))

    def test(self):
        st, hd, d = self.req('GET', self.url('/certificates', maxresults=25),
                             what='listing the certificates')
        n = len((d or {}).get('value') or []) if isinstance(d, dict) else 0
        return 'signed in to %s, %d certificate%s seen' % (self.vault_url(), n,
                                                          '' if n == 1 else 's')

    def current_x5t(self, name):
        st, hd, d = self.req('GET', self.url('/certificates/%s' % name), ok=(200, 404),
                             what='reading %s' % name)
        if st == 404 or not isinstance(d, dict):
            return None
        return d.get('x5t')

    def deploy(self, bundle, options):
        options = options or {}
        name = kv_name(bundle, options)
        want = base64.urlsafe_b64encode(bytes.fromhex(sha1_thumb(bundle))).rstrip(b'=').decode()
        if not as_bool(options.get('force')):
            have = self.current_x5t(name)
            if have and have.rstrip('=') == want:
                self.remember(bundle, options)
                return self.same(bundle, 'the current version of %s' % name)
        pem = text(bundle.as_format('key-pem')) + text(bundle.as_format('fullchain-pem'))
        st, hd, d = self.req('POST', self.url('/certificates/%s/import' % name), {
            'value': pem,
            'policy': {'key_props': {'exportable': True},
                       'secret_props': {'contentType': 'application/x-pem-file'}},
            'tags': {'managed-by': 'acme'}}, what='importing %s' % name)
        ver = text((d or {}).get('id') if isinstance(d, dict) else '').rsplit('/', 1)[-1]
        self.ctx.step('imported into %s as version %s' % (name, ver or '?'), 'ok')
        self.remember(bundle, options)
        return 'imported into Key Vault %s: %s (version %s)' % (self.vault_url(), name,
                                                               ver or '?')
