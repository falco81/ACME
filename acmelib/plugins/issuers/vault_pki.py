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
* LIST /v1/<mount>/certs (sent as GET ...?list=true) -> data.keys: the serial
  numbers of the current certificates; GET /v1/<mount>/cert/<serial> -> data.
  certificate (PEM) - "List certificates" and "Read certificate" of the same page
  (https://developer.hashicorp.com/vault/api-docs/secret/pki): Import from a source.
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
import time
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
    lists_existing = True           # LIST certs + read: Certificates → Import from a source
    per_cert = [{'key': 'role', 'field': 'role', 'catalog': 'roles', 'label': 'Role',
                 'placeholder': 'web-servers',
                 'help': 'The Vault PKI role for this certificate. Empty: the source\'s own.'}]
    fields = [
        field('url', 'Vault address', 'text', required=True, placeholder='https://vault.example.local:8200'),
        field('mount', 'PKI mount', 'text', default='pki', placeholder='pki_int',
              help='The path the PKI engine is mounted at.'),
        field('role', 'Role', 'catalog', catalog='roles', required=True, placeholder='web-servers',
              depends=['url', 'mount', 'token'],
              help='The role whose rules the certificate follows (allowed domains, TTL, key '
                   'types). Load the list: the roles of the mount (LIST roles); one can be '
                   'typed too. A certificate\'s own role (Add a certificate → Settings) wins.'),
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

    # -- what the mount holds (Certificates → Import from a source) ----------------------
    READ_MOST = 150                 # certificates read one by one in a listing

    def _read_cert(self, serial):
        if not re.match(r'^[0-9A-Fa-f:-]{1,200}\Z', str(serial or '')):
            raise PluginError('%s is not a serial number' % (serial or '?'), retry=False)
        got = self._call('GET', '%s/cert/%s' % (self._mount(), serial), token=False,
                         what='Vault (the certificate %s)' % serial)
        return (got.get('data') or {}).get('certificate') or ''

    # -- the form's lists (base.py: a field of the type catalog) ------------------------
    def catalog(self, key):
        """The roles of the mount: LIST /v1/<mount>/roles -> data.keys (sent as GET
        ...?list=true; developer.hashicorp.com/vault/api-docs/secret/pki "List roles",
        hashicorp/web-unified-docs). Read-only."""
        if key != 'roles':
            raise PluginError('there is no list called %s here' % key, retry=False)
        got = self._call('GET', '%s/roles?list=true' % self._mount(), ok=(200, 204, 404),
                         what='Vault (the list of roles)')
        keys = sorted(str(k) for k in ((got or {}).get('data') or {}).get('keys') or [])
        return {'options': [[k, k] for k in keys],
                'said': '%d role(s) of the mount %s' % (len(keys), self._mount())}

    def list_existing(self):
        """The current certificates of the mount (LIST certs, each read) - read only."""
        from acmelib.certs import pki
        got = self._call('GET', '%s/certs?list=true' % self._mount(), ok=(200, 204, 404),
                         what='Vault (the list of certificates)')
        keys = [str(k) for k in ((got.get('data') or {}).get('keys') or [])]
        out, now = [], time.time()
        for i, serial in enumerate(keys):
            if self.ctx.cancelled():
                break
            if i >= self.READ_MOST:
                out.append({'ref': serial, 'serial': serial, 'downloadable': True,
                            'renewable': 'issue', 'cn': '', 'names': [],
                            'note': 'more than %d certificates: this one is read when it is '
                                    'imported' % self.READ_MOST})
                continue
            try:
                info = pki.cert_info(self._read_cert(serial))
            except Exception as e:                      # noqa: BLE001
                out.append({'ref': serial, 'serial': serial, 'downloadable': False,
                            'renewable': 'none', 'note': 'it cannot be read: %s' % e})
                continue
            if info.get('is_ca'):
                continue
            na = sc.num(info.get('not_after'), 0) or None
            out.append({'ref': serial, 'cn': info.get('cn') or '', 'names': info.get('names') or [],
                        'product': self.c('role') or '', 'status': 'expired' if na and na < now
                        else 'valid', 'not_before': info.get('not_before'), 'not_after': na,
                        'serial': info.get('serial'), 'fingerprint': info.get('sha256'),
                        'downloadable': True, 'renewable': 'issue'})
        return out

    def fetch_existing(self, ref):
        """The certificate of serial `ref` and the mount's chain - read only."""
        certs = sc.certs_of(self._read_cert(ref))
        chain = []
        try:
            got = self._call('GET', '%s/cert/ca_chain' % self._mount(), token=False,
                             what='Vault (CA chain)')
            chain = sc.certs_of(((got.get('data') or {}).get('ca_chain')) or
                                (got.get('data') or {}).get('certificate'))
        except PluginError as e:
            sc.say(self.ctx, 'the chain of the mount could not be read: %s' % e, 'warn')
        return sc.existing(certs, chain, who='Vault', ref=ref)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = sc.serial_hex(cert_pem, ':').lower()
        got = self._call('POST', '%s/revoke' % self._mount(), {'serial_number': serial},
                         what='Vault (revoke)')
        when = (got.get('data') or {}).get('revocation_time')
        return 'Vault revoked serial %s%s (Vault records no reason)' % (
            serial, (' at %s' % when) if when else '')

    # -- discovery (1.0.29): the form filled in from Vault -----------------------------------
    discover_keys = ['url', 'auth', 'token', 'role_id', 'secret_id', 'approle_mount',
                     'namespace', 'ca_pem', 'verify']

    def discover_setup(self):
        """Read-only: the PKI mounts the token sees (GET sys/internal/ui/mounts, type pki),
        the roles of the mount set or found (LIST roles) and its issuers (LIST issuers) -
        an issuer never picked by itself (empty: the role's)."""
        out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        mounts = []
        try:
            got = self._call('GET', 'sys/internal/ui/mounts', what='Vault (the mounts)')
            for path, m in ((got.get('data') or {}).get('secret') or {}).items():
                if isinstance(m, dict) and str(m.get('type') or '') == 'pki':
                    mounts.append(str(path).strip('/'))
        except PluginError as e:
            out['notes'].append('PKI mount: %s' % e)
        mounts.sort()
        self.offer(out, 'mount', mounts)
        mount = str(self.config.get('mount') or '').strip().strip('/') or \
            (out['choices'].get('mount') or {}).get('pick') or ''
        if not mount and mounts:
            out['notes'].append('Role: pick the PKI mount, then ask again')
            return out
        with sc.assumed(self, {'mount': mount}):
            sc.merge_found(out, sc.discover_lists(self))     # the roles, either way of signing in
            try:
                got = self._call('GET', '%s/issuers?list=true' % self._mount(), ok=(200, 204, 404),
                                 what='Vault (the list of issuers)')
                data = (got or {}).get('data') or {}
                info = data.get('key_info') if isinstance(data.get('key_info'), dict) else {}
                opts = [[str(k), '%s (%s)' % ((info.get(k) or {}).get('issuer_name'), k)
                         if (info.get(k) or {}).get('issuer_name') else str(k)]
                        for k in data.get('keys') or []]
                if len(opts) > 1:
                    self.offer(out, 'issuer_ref', [['', 'Empty: the issuer of the role']] + opts,
                               pick='')
                out['facts'].append(['Issuers', str(len(opts))])
            except PluginError as e:
                out['notes'].append('Issuer: %s' % e)
        return out
