# -*- coding: utf-8 -*-
"""
Certificates from the PKI secrets engine of HashiCorp Vault (or OpenBao,
which keeps its API): the CSR acme made signed by a role.

From Vault's API documentation
(https://developer.hashicorp.com/vault/api-docs/secret/pki - read from its
source, github.com/hashicorp/web-unified-docs, content/vault/v1.20.x/content/
api-docs/secret/pki/index.mdx, 2026-11):

* POST /v1/<mount>/sign/<role> (or /v1/<mount>/issuer/<ref>/sign/<role>)
  with {csr, common_name, alt_names, ip_sans, ttl, format: "pem",
  exclude_cn_from_sans, remove_roots_from_chain}; the answer's data holds
  certificate, issuing_ca, ca_chain [...], serial_number (aa:bb:..).
* POST /v1/<mount>/revoke {serial_number} (or {certificate}).
* GET /v1/<mount>/cert/ca_chain - the default issuer's chain (JSON) - and
  LIST /v1/<mount>/roles for "Try it".
* Signing in: X-Vault-Token, or AppRole: POST /v1/auth/<mount>/login
  {role_id, secret_id} -> auth.client_token
  (https://developer.hashicorp.com/vault/api-docs/auth/approle). Vault
  Enterprise namespaces: the X-Vault-Namespace header.

The private key never goes to Vault (sign, not issue).
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc


def _is_ip(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


class VaultPkiIssuer(Issuer):
    kind = 'vault_pki'
    dual = True                     # where the role's key_type is any
    title = 'HashiCorp Vault PKI'
    description = ('Certificates signed by the PKI secrets engine of HashiCorp Vault (or '
                   'OpenBao) under a role, signed in with a token or AppRole; acme\'s key never '
                   'leaves acme.')
    vendor = 'HashiCorp'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    choose_days = True
    fields = [
        field('url', 'Vault address', 'text', required=True, placeholder='https://vault.example.local:8200'),
        field('mount', 'PKI mount', 'text', default='pki', placeholder='pki_int',
              help='The path the PKI engine is mounted at.'),
        field('role', 'Role', 'text', required=True, placeholder='web-servers',
              help='The role whose rules the certificate follows (allowed domains, TTL, key '
                   'types). A certificate\'s own profile "role" wins.'),
        field('issuer_ref', 'Issuer', 'text', advanced=True, placeholder='default',
              help='An issuer of the mount by its name or id (/issuer/REF/sign/ROLE). Empty: '
                   'the role\'s.'),
        field('auth', 'Signing in', 'select', default='token',
              options=[['token', 'Token'], ['approle', 'AppRole (role ID and secret ID)']]),
        field('token', 'Token', 'secret', show_if={'auth': ['token']},
              help='A token whose policy allows update on MOUNT/sign/ROLE (and MOUNT/revoke to '
                   'revoke).'),
        field('role_id', 'Role ID', 'text', show_if={'auth': ['approle']}),
        field('secret_id', 'Secret ID', 'secret', show_if={'auth': ['approle']}),
        field('approle_mount', 'AppRole mount', 'text', default='approle', advanced=True,
              show_if={'auth': ['approle']}),
        field('namespace', 'Namespace', 'text', advanced=True,
              help='Vault Enterprise / HCP Vault: the namespace (X-Vault-Namespace).'),
        field('ttl', 'TTL', 'text', advanced=True, placeholder='720h',
              help='The validity asked for (a certificate\'s days win). Empty: the role\'s ttl.'),
        field('exclude_cn', 'Common name not in the SANs', 'bool', default=False, advanced=True),
        field('no_roots', 'Leave roots out of the chain', 'bool', default=False, advanced=True),
        field('ca_pem', 'CA certificate of Vault\'s TLS', 'pem', advanced=True),
        field('verify', 'Check Vault\'s TLS certificate', 'bool', default=True, advanced=True),
    ]

    _token = None

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https?://[^\s/]+\Z', url):
            raise PluginError('set the Vault address (https://host:8200)', retry=False)
        return url

    def _mount(self):
        m = str(self.c('mount') or 'pki').strip().strip('/')
        if not re.match(r'^[A-Za-z0-9._/-]+\Z', m) or '..' in m:
            raise PluginError('the PKI mount is a path like pki or pki_int', retry=False)
        return m

    def _call(self, method, path, body=None, token=True, ok=(200, 204), what='Vault'):
        h = {}
        ns = str(self.c('namespace') or '').strip()
        if ns:
            h['X-Vault-Namespace'] = ns
        if token:
            h['X-Vault-Token'] = self.token()
        status, _rh, data = sc.http(self.ctx, method, self._base() + '/v1/' + path, body, h,
                                    who='Vault', verify=sc.as_bool(self.c('verify'), True),
                                    ca_pem=self.c('ca_pem') or None)
        parsed = sc.parse_json(data)
        if status not in ok:
            raise sc.refusal(what, status, parsed, data,
                             'the token\'s policy does not allow %s %s' % (method, path))
        return parsed or {}

    def token(self):
        if self._token:
            return self._token
        if (self.c('auth') or 'token') == 'approle':
            if not self.c('role_id') or not self.c('secret_id'):
                raise PluginError('set the AppRole role ID and secret ID', retry=False)
            mount = str(self.c('approle_mount') or 'approle').strip('/')
            got = self._call('POST', 'auth/%s/login' % urllib.parse.quote(mount, safe='/'),
                             {'role_id': self.c('role_id'), 'secret_id': self.c('secret_id')},
                             token=False, what='Vault (AppRole login)')
            tok = (got.get('auth') or {}).get('client_token')
            if not tok:
                raise PluginError('Vault gave no token for the AppRole', retry=False)
            self._token = tok
        else:
            if not self.c('token'):
                raise PluginError('set the Vault token', retry=False)
            self._token = str(self.c('token')).strip()
        return self._token

    # -- trying it -----------------------------------------------------------------------
    def test(self):
        me = self._call('GET', 'auth/token/lookup-self', what='Vault (token lookup)')
        data = me.get('data') or {}
        chain = self._call('GET', '%s/cert/ca_chain' % self._mount(), token=False,
                           what='Vault (CA chain)')
        certs = sc.certs_of(((chain.get('data') or {}).get('ca_chain')) or
                            (chain.get('data') or {}).get('certificate'))
        cn = sc.cert_of_pem(sc.p7.pem(certs[0])).subject_cn if certs else '?'
        return 'Vault answers: signed in (policies %s); the mount %s has the CA %s' % (
            ', '.join(data.get('policies') or []) or '?', self._mount(), cn)

    # -- a certificate -------------------------------------------------------------------
    def issue(self, req):
        role = str((req.profile or {}).get('role') or self.c('role') or '').strip()
        if not role or not re.match(r'^[A-Za-z0-9._-]+\Z', role):
            raise PluginError('set the role (letters, digits and . _ -)', retry=False)
        names = list(req.names or [])
        if not names:
            raise PluginError('the certificate has no names', retry=False)
        dns = [n for n in names if not _is_ip(n)]
        ips = [n for n in names if _is_ip(n)]
        body = {'csr': sc.csr_pem(req), 'common_name': names[0], 'format': 'pem'}
        if [n for n in dns if n != names[0]]:
            body['alt_names'] = ','.join(n for n in dns if n != names[0])
        if ips:
            body['ip_sans'] = ','.join(ips)
        if req.days:
            body['ttl'] = '%dh' % (int(req.days) * 24)
        elif self.c('ttl'):
            body['ttl'] = str(self.c('ttl')).strip()
        if sc.as_bool(self.c('exclude_cn')):
            body['exclude_cn_from_sans'] = True
        if sc.as_bool(self.c('no_roots')):
            body['remove_roots_from_chain'] = True
        ref = str(self.c('issuer_ref') or '').strip()
        if ref:
            if not re.match(r'^[A-Za-z0-9._-]+\Z', ref):
                raise PluginError('the issuer is a name or an id', retry=False)
            path = '%s/issuer/%s/sign/%s' % (self._mount(), ref, role)
        else:
            path = '%s/sign/%s' % (self._mount(), role)
        sc.say(self.ctx, 'the request goes to Vault: %s' % path)
        got = self._call('POST', path, body, what='Vault (sign)')
        d = got.get('data') or {}
        certs = sc.certs_of(d.get('certificate'))
        chain = sc.certs_of(d.get('ca_chain') or []) + sc.certs_of(d.get('issuing_ca'))
        for w in got.get('warnings') or []:
            sc.say(self.ctx, 'Vault warns: %s' % w, 'warn')
        return sc.finish(self.ctx, req, certs, chain, who='Vault',
                         info={'vault_serial': d.get('serial_number'), 'vault_role': role})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = sc.serial_hex(cert_pem, ':').lower()
        got = self._call('POST', '%s/revoke' % self._mount(), {'serial_number': serial},
                         what='Vault (revoke)')
        when = (got.get('data') or {}).get('revocation_time')
        return 'Vault revoked serial %s%s (Vault records no reason)' % (
            serial, (' at %s' % when) if when else '')
