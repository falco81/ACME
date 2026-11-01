# -*- coding: utf-8 -*-
"""
F5 BIG-IP over iControl REST: key and certificate uploaded and installed under
dated names, the chain as a certificate of its own, client-ssl profiles
pointed at them, the configuration saved and synced to the device group.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id)

CHUNK = 512 * 1024
DOWNLOADS = '/var/config/rest/downloads'


def tilde(path):
    """/Common/name -> ~Common~name (a path in a URL)."""
    return urllib.parse.quote(path.replace('/', '~'), safe='~.-_')


class F5Target(HttpTarget):
    kind = 'f5'
    title = 'F5 BIG-IP'
    vendor = 'F5'
    description = ('Installs the key, certificate and chain through iControl REST, points '
                   'client-ssl profiles at them, saves and syncs the configuration.')
    doc = 'targets.md'
    fields = http_fields(443, 'bigip.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
        field('login_provider', 'Login provider', 'text', default='tmos', advanced=True,
              help='tmos for local users; the name of a remote auth provider otherwise'),
        field('partition', 'Partition', 'text', default='Common'),
        field('device_group', 'Sync to device group', 'text', advanced=True,
              placeholder='dg-failover',
              help='after saving, config-sync to this group (HA pair); empty: no sync'),
    ] + tls_fields()
    deploy_fields = [
        field('profiles', 'Client SSL profiles', 'list', placeholder='/Common/www_clientssl',
              help='one a line; the cert-key-chain entry of the old acme certificate (or '
                   'the only/default one) is replaced'),
        field('create_profile', 'Make missing profiles', 'bool', default=False, advanced=True,
              help='a profile not found is made with clientssl as its parent'),
        field('partition', 'Partition', 'text', advanced=True,
              help='empty: the target\'s'),
        keep_field(2),
    ] + verify_fields()

    token = None

    def auth_headers(self):
        return {'X-F5-Auth-Token': self.token} if self.token else {}

    def login(self):
        st, hd, d = self.req('POST', '/mgmt/shared/authn/login', {
            'username': self.c('user'), 'password': self.c('password'),
            'loginProviderName': self.c('login_provider') or 'tmos'}, auth=False,
            what='signing in')
        try:
            self.token = d['token']['token']
        except (TypeError, KeyError):
            raise PluginError('the BIG-IP gave no token on signing in', detail=str(d))
        return self.token

    def logout(self):
        if self.token:
            try:
                self.req('DELETE', '/mgmt/shared/authz/tokens/%s' % self.token, ok=range(0, 600))
            except PluginError:
                pass
            self.token = None

    def test(self):
        self.login()
        try:
            st, hd, d = self.req('GET', '/mgmt/tm/sys/version')
            ver = '?'
            try:
                entry = list(d['entries'].values())[0]['nestedStats']['entries']
                ver = '%s %s' % (entry['Product']['description'], entry['Version']['description'])
            except (KeyError, IndexError, TypeError, AttributeError):
                pass
            return 'signed in to %s, %s' % (self.c('host'), ver)
        finally:
            self.logout()

    # -- pieces ---------------------------------------------------------------
    def upload(self, name, data):
        total = len(data)
        start = 0
        while True:
            chunk = data[start:start + CHUNK]
            end = start + len(chunk) - 1
            self.req('POST', '/mgmt/shared/file-transfer/uploads/%s' % name, chunk,
                     {'Content-Type': 'application/octet-stream',
                      'Content-Range': '%d-%d/%d' % (start, end, total)},
                     what='uploading %s' % name)
            start += len(chunk)
            if start >= total:
                break
        return '%s/%s' % (DOWNLOADS, name)

    def exists(self, what, path):
        st, hd, d = self.req('GET', '/mgmt/tm/sys/crypto/%s/%s' % (what, tilde(path)),
                             ok=(200, 404))
        return st == 200

    def install(self, what, path, local):
        self.req('POST', '/mgmt/tm/sys/crypto/%s' % what,
                 {'command': 'install', 'name': path, 'from-local-file': local},
                 what='installing %s %s' % (what, path))

    def rm_upload(self, local):
        try:
            self.req('POST', '/mgmt/tm/util/unix-rm', {'command': 'run', 'utilCmdArgs': local},
                     ok=range(0, 600))
        except PluginError:
            pass

    def point_profile(self, profile, part, cert, key, chain, prefix, create):
        if not profile.startswith('/'):
            profile = '/%s/%s' % (part, profile)
        url = '/mgmt/tm/ltm/profile/client-ssl/%s' % tilde(profile)
        st, hd, d = self.req('GET', url, ok=(200, 404))
        entry = {'cert': cert, 'key': key}
        if chain:
            entry['chain'] = chain
        if st == 404:
            if not create:
                raise PluginError('there is no client-ssl profile %s' % profile, retry=False)
            p_part, _, p_name = profile[1:].partition('/')
            self.req('POST', '/mgmt/tm/ltm/profile/client-ssl', {
                'name': p_name, 'partition': p_part, 'defaultsFrom': '/Common/clientssl',
                'certKeyChain': [dict(entry, name='default')]},
                what='making the profile %s' % profile)
            return 'made'
        chains = list((d or {}).get('certKeyChain') or [])
        idx = None
        for i, e in enumerate(chains):
            if str(e.get('cert', '')).startswith(prefix):
                idx = i
                break
        if idx is None:
            for i, e in enumerate(chains):
                if e.get('name') == 'default':
                    idx = i
                    break
        if idx is None and chains:
            idx = 0
        if idx is None:
            chains.append(dict(entry, name='default'))
        else:
            old = chains[idx]
            if old.get('cert') == cert and old.get('key') == key and \
                    old.get('chain', 'none') == entry.get('chain', 'none'):
                return 'unchanged'
            chains[idx] = dict({'name': old.get('name') or 'default'}, **entry)
            for k in ('passphrase', 'usage', 'ocspStapling'):
                if old.get(k) is not None:
                    chains[idx][k] = old[k]
        self.req('PATCH', url, {'certKeyChain': [
            {k: v for k, v in e.items() if k in ('name', 'cert', 'key', 'chain', 'passphrase',
                                                   'usage')} for e in chains]},
            what='updating the profile %s' % profile)
        return 'updated'

    # -- deploy -----------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        part = (options.get('partition') or self.c('partition') or 'Common').strip('/')
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        cert_path = '/%s/%s' % (part, name)
        self.login()
        try:
            if self.unchanged(bundle, options, present=lambda: self.exists('cert', cert_path)):
                return self.same(bundle, 'on %s' % self.c('host'))
            did = []
            if self.exists('cert', cert_path) and self.exists('key', cert_path) and \
                    not as_bool(options.get('force')):
                self.ctx.step('%s is there already' % cert_path)
            else:
                local = self.upload(name + '.key', bundle.as_format('key-pem'))
                self.install('key', cert_path, local)
                self.rm_upload(local)
                local = self.upload(name + '.crt', bundle.as_format('cert-pem'))
                self.install('cert', cert_path, local)
                self.rm_upload(local)
                self.ctx.step('installed %s' % cert_path, 'ok')
                did.append('installed %s' % name)
            chain_path = None
            chain = chain_list(bundle)
            if chain:
                cname = 'acme-chain-%s' % chain_id(''.join(chain))
                chain_path = '/%s/%s' % (part, cname)
                if not self.exists('cert', chain_path):
                    local = self.upload(cname + '.crt', ''.join(chain).encode())
                    self.install('cert', chain_path, local)
                    self.rm_upload(local)
                    self.ctx.step('installed the chain as %s' % chain_path, 'ok')
            for p in lines(options.get('profiles')):
                how = self.point_profile(p, part, cert_path, cert_path, chain_path,
                                         '/%s/%s' % (part, prefix),
                                         as_bool(options.get('create_profile')))
                self.ctx.step('profile %s %s' % (p, how), 'ok')
                did.append('%s %s' % (p, how))
            self.cleanup(part, prefix, name, self.keep(options))
            self.req('POST', '/mgmt/tm/sys/config', {'command': 'save'},
                     what='saving the configuration', timeout=120)
            dg = (self.c('device_group') or '').strip()
            if dg:
                self.req('POST', '/mgmt/tm/cm', {'command': 'run',
                                                 'utilCmdArgs': 'config-sync to-group %s' % dg},
                         what='syncing to %s' % dg, timeout=120)
                self.ctx.step('synced to %s' % dg, 'ok')
                did.append('synced to %s' % dg)
            self.remember(bundle, options)
            return '; '.join(did) or 'profiles already used %s' % name
        finally:
            self.logout()

    def cleanup(self, part, prefix, current, keep):
        if keep < 0:
            return
        st, hd, d = self.req('GET', '/mgmt/tm/sys/crypto/cert?$filter=partition+eq+%s'
                             % urllib.parse.quote(part), ok=(200, 404))
        names = [i.get('name', '') for i in ((d or {}).get('items') or [])
                 if isinstance(d, dict)]
        for n in prune(names, prefix, keep, current):
            path = tilde('/%s/%s' % (part, n))
            try:
                self.req('DELETE', '/mgmt/tm/sys/crypto/cert/%s' % path)
                self.req('DELETE', '/mgmt/tm/sys/crypto/key/%s' % path, ok=(200, 404))
                self.ctx.step('deleted the old %s' % n)
            except PluginError as e:
                self.ctx.step('the old %s stays: %s' % (n, e), 'warn')

    def remove(self, bundle, options):
        part = ((options or {}).get('partition') or self.c('partition') or 'Common').strip('/')
        path = tilde('/%s/%s' % (part, object_name(bundle, options)))
        self.login()
        try:
            self.req('DELETE', '/mgmt/tm/sys/crypto/cert/%s' % path, ok=(200, 404))
            self.req('DELETE', '/mgmt/tm/sys/crypto/key/%s' % path, ok=(200, 404))
        finally:
            self.logout()
