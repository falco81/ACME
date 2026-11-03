# -*- coding: utf-8 -*-
"""
HashiCorp Vault (or OpenBao): the certificate written as a secret of a KV
version 2 engine, for whatever reads it from there. A dual certificate: the
twin in the same secret, its fields with alt_ before them (alt_certificate,
alt_fullchain, alt_private_key, alt_key_type...).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, fp_of, label_of, subst, stamp, tls_fields,
    verify_fields, text, alt_of, dual_fp)


class VaultTarget(HttpTarget):
    kind = 'vault'
    title = 'HashiCorp Vault (KV v2)'
    vendor = 'HashiCorp'
    description = 'Writes the certificate, chain and key as a secret of a KV v2 engine.'
    doc = 'targets.md'
    dual = True             # a dual certificate: the twin's fields beside, alt_*
    fields = [
        field('host', 'Vault address', 'text', required=True,
              placeholder='https://vault.example.local:8200'),
        field('auth', 'Sign in with', 'select', default='token',
              options=[['token', 'a token'], ['approle', 'AppRole']]),
        field('token', 'Token', 'secret', show_if={'auth': ['token']}),
        field('role_id', 'Role ID', 'text', show_if={'auth': ['approle']}),
        field('secret_id', 'Secret ID', 'secret', show_if={'auth': ['approle']}),
        field('approle_mount', 'AppRole mount', 'text', default='approle', advanced=True,
              show_if={'auth': ['approle']}),
        field('namespace', 'Namespace', 'text', advanced=True, help='Vault Enterprise'),
        field('mount', 'KV mount', 'text', default='secret'),
    ] + tls_fields()
    deploy_fields = [
        field('path', 'Path', 'text', default='acme/{name}',
              help='inside the mount; {name} is the certificate\'s name'),
        field('include_key', 'With the private key', 'bool', default=True),
    ] + verify_fields()

    token = None

    def auth_headers(self):
        h = {}
        if self.token:
            h['X-Vault-Token'] = self.token
        if self.c('namespace'):
            h['X-Vault-Namespace'] = self.c('namespace')
        return h

    def login(self):
        if (self.c('auth') or 'token') == 'token':
            self.token = self.c('token')
            if not self.token:
                raise PluginError('no token is set', retry=False)
            return
        st, hd, d = self.req('POST', '/v1/auth/%s/login' % (self.c('approle_mount') or 'approle'),
                             {'role_id': self.c('role_id'), 'secret_id': self.c('secret_id')},
                             what='signing in (AppRole)')
        try:
            self.token = d['auth']['client_token']
        except (TypeError, KeyError):
            raise PluginError('Vault gave no token', detail=text(d))

    def url(self, path):
        mount = (self.c('mount') or 'secret').strip('/')
        return '/v1/%s/data/%s' % (urllib.parse.quote(mount),
                                   urllib.parse.quote(path.strip('/')))

    def test(self):
        self.login()
        st, hd, d = self.req('GET', '/v1/auth/token/lookup-self', what='reading the token')
        data = (d or {}).get('data') or {}
        return 'signed in to Vault as %s (policies %s)' % (
            data.get('display_name', '?'), ', '.join(data.get('policies') or []))

    # -- discovery (1.0.29): the form filled in from Vault -----------------------------------
    discover_keys = ['host', 'auth', 'token', 'role_id', 'secret_id', 'approle_mount',
                     'namespace', 'verify_tls']

    def discover_setup(self):
        """Read-only: signed in as test() is, the token read (auth/token/lookup-self) and the
        secrets engines it may see (GET sys/internal/ui/mounts) - those of KV version 2
        offered as the KV mount."""
        out = Plugin.discover_setup(self)
        self.login()
        st, hd, d = self.req('GET', '/v1/auth/token/lookup-self', what='reading the token')
        data = (d or {}).get('data') or {} if isinstance(d, dict) else {}
        if data.get('display_name'):
            out['facts'].append(['Signed in as', text(data['display_name'])])
        st, hd, d = self.req('GET', '/v1/sys/internal/ui/mounts',
                             what='listing the secrets engines')
        mounts = (((d or {}).get('data') or {}).get('secret') or {}) if isinstance(d, dict) \
            else {}
        opts, other = [], 0
        for path, m in sorted(mounts.items() if isinstance(mounts, dict) else []):
            m = m if isinstance(m, dict) else {}
            if text(m.get('type')) != 'kv':
                continue
            if text((m.get('options') or {}).get('version')) != '2':
                other += 1
                continue
            name = text(path).strip('/')
            if name:
                desc = text(m.get('description')).strip()
                opts.append([name, '%s (%s)' % (name, desc) if desc else name])
        out['facts'].append(['KV version 2 engines', str(len(opts))])
        if other:
            out['notes'].append('%d KV engine(s) of version 1 left out - acme writes KV '
                                'version 2' % other)
        self.offer(out, 'mount', opts, pick='secret' if any(o[0] == 'secret' for o in opts)
                   else None)
        return out

    def deploy(self, bundle, options):
        options = options or {}
        self.login()
        path = subst(self.opt(options, 'path', 'acme/{name}'),
                     {'name': label_of(bundle, options), 'date': stamp(bundle)})
        url = self.url(path)
        fp = fp_of(bundle)
        alt = alt_of(bundle)
        if not as_bool(options.get('force')):
            st, hd, d = self.req('GET', url, ok=(200, 404), what='reading %s' % path)
            have = (((d or {}).get('data') or {}).get('data') or {}) if st == 200 else {}
            if have.get('fingerprint') == fp and (have.get('alt_fingerprint') or '') == \
                    (fp_of(alt) if alt is not None else ''):
                return self.same(bundle, 'at %s' % path)
        data = {'certificate': bundle.cert_pem, 'chain': ''.join(bundle.chain_pems or []),
                'fullchain': bundle.fullchain_pem, 'fingerprint': fp, 'serial': bundle.serial,
                'names': ','.join(bundle.names or []), 'not_before': bundle.not_before,
                'not_after': bundle.not_after}
        if as_bool(self.opt(options, 'include_key', True), True):
            data['private_key'] = text(bundle.key_pem)
        if alt is not None:
            data.update(alt_certificate=alt.cert_pem, alt_chain=''.join(alt.chain_pems or []),
                        alt_fullchain=alt.fullchain_pem, alt_fingerprint=fp_of(alt),
                        alt_serial=alt.serial, alt_not_after=alt.not_after,
                        key_type=getattr(bundle, 'key_type', ''),
                        alt_key_type=getattr(alt, 'key_type', ''), dual_fingerprint=dual_fp(bundle))
            if 'private_key' in data:
                data['alt_private_key'] = text(alt.key_pem)
        st, hd, d = self.req('POST', url, {'data': data}, what='writing %s' % path)
        ver = (((d or {}).get('data') or {}).get('version'))
        self.ctx.step('wrote %s (version %s)' % (path, ver), 'ok')
        self.remember(bundle, options)
        return 'wrote %s/%s version %s' % (self.c('mount') or 'secret', path, ver)
