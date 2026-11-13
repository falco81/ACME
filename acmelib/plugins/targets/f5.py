# -*- coding: utf-8 -*-
"""
F5 BIG-IP over iControl REST: key and certificate uploaded and installed under
dated names, the chain as a certificate of its own, client-ssl profiles
pointed at them, the configuration saved and synced to the device group.

A dual certificate (ECDSA and RSA of the same names): both installed - the
twin under acme-<name>-<kind>-<date>-<serial> - and each client-ssl profile
given two cert-key-chain entries, one of each kind; the BIG-IP offers each
client the one it takes.
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, alt_of,
    family_of, label_of, text)

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
    dual = True             # a dual certificate: two cert-key-chain entries in each profile
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

    # -- discovery (1.0.29): the form filled in from the BIG-IP ----------------------------
    discover_keys = ['host', 'port', 'user', 'password', 'login_provider', 'verify_tls']

    def discover_setup(self):
        """Read-only, signed in as test() is (the token deleted after): the version, and the
        partitions that hold SSL certificates (GET sys/crypto/cert, each item's partition)
        offered as the partition. The device group is not looked up - typed by hand."""
        out = Plugin.discover_setup(self)
        self.login()
        try:
            st, hd, d = self.req('GET', '/mgmt/tm/sys/version', what='reading the version')
            try:
                entry = list(d['entries'].values())[0]['nestedStats']['entries']
                out['facts'].append(['BIG-IP', '%s %s' % (entry['Product']['description'],
                                                          entry['Version']['description'])])
            except (KeyError, IndexError, TypeError, AttributeError):
                pass
            st, hd, d = self.req('GET', '/mgmt/tm/sys/crypto/cert',
                                 what='listing the certificates')
            count = {}
            for i in (d.get('items') if isinstance(d, dict) else None) or []:
                part = text((i or {}).get('partition') if isinstance(i, dict) else '').strip()
                if part:
                    count[part] = count.get(part, 0) + 1
            if count:
                out['facts'].append(['Partitions with certificates', str(len(count))])
                order = sorted(count, key=lambda p: (p != 'Common', p.lower()))
                self.offer(out, 'partition', [[p, '%s (%d)' % (p, count[p])] for p in order],
                           pick='Common' if 'Common' in count else None)
        finally:
            self.logout()
        return out

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

    @staticmethod
    def _ours(cert, prefix):
        """The cert of an entry is one acme put there under this prefix (prefix +
        date + serial - not the twin's, whose prefix is longer)."""
        c = str(cert or '')
        return c.startswith(prefix) and bool(re.match(r'^\d{8}-[0-9a-f]+$', c[len(prefix):]))

    def point_profile(self, profile, part, cert, key, chain, prefix, create, more=()):
        """The profile's cert-key-chain entry of acme's certificate pointed at it;
        `more`: [(cert, key, chain, prefix, name)] - a dual certificate's twin, an
        entry of its own (found by its prefix, else by its name, else added)."""
        if not profile.startswith('/'):
            profile = '/%s/%s' % (part, profile)
        url = '/mgmt/tm/ltm/profile/client-ssl/%s' % tilde(profile)
        st, hd, d = self.req('GET', url, ok=(200, 404))
        entry = {'cert': cert, 'key': key}
        if chain:
            entry['chain'] = chain
        extra = []
        for c2, k2, ch2, p2, n2 in more:
            e2 = {'cert': c2, 'key': k2}
            if ch2:
                e2['chain'] = ch2
            extra.append((e2, p2, n2))
        if st == 404:
            if not create:
                raise PluginError('there is no client-ssl profile %s' % profile, retry=False)
            p_part, _, p_name = profile[1:].partition('/')
            self.req('POST', '/mgmt/tm/ltm/profile/client-ssl', {
                'name': p_name, 'partition': p_part, 'defaultsFrom': '/Common/clientssl',
                'certKeyChain': [dict(entry, name='default')] +
                                [dict(e2, name=n2) for e2, _p2, n2 in extra]},
                what='making the profile %s' % profile)
            return 'made'
        chains = list((d or {}).get('certKeyChain') or [])
        twins = [p2 for _e2, p2, _n2 in extra]
        idx = None
        for i, e in enumerate(chains):
            if self._ours(e.get('cert'), prefix):
                idx = i
                break
        if idx is None:
            for i, e in enumerate(chains):
                if e.get('name') == 'default':
                    idx = i
                    break
        if idx is None and chains:
            idx = next((i for i, e in enumerate(chains)
                        if not any(self._ours(e.get('cert'), p2) for p2 in twins)), None)
        changed = False

        def put(i, new, default_name):
            old = chains[i]
            if old.get('cert') == new['cert'] and old.get('key') == new['key'] and \
                    old.get('chain', 'none') == new.get('chain', 'none'):
                return False
            self.ctx.step('%s: its cert-key-chain entry %s holds %s - pointed at %s' % (
                profile, old.get('name') or default_name, old.get('cert') or '-', new['cert']))
            chains[i] = dict({'name': old.get('name') or default_name}, **new)
            for k in ('passphrase', 'usage', 'ocspStapling'):
                if old.get(k) is not None:
                    chains[i][k] = old[k]
            return True
        if idx is None:
            chains.append(dict(entry, name='default'))
            changed = True
        else:
            changed = put(idx, entry, 'default') or changed
        for e2, p2, n2 in extra:
            j = next((i for i, e in enumerate(chains) if self._ours(e.get('cert'), p2)), None)
            if j is None:
                j = next((i for i, e in enumerate(chains) if e.get('name') == n2), None)
            if j is None:
                chains.append(dict(e2, name=n2))
                changed = True
            else:
                changed = put(j, e2, n2) or changed
        if not changed:
            return 'unchanged'
        self.req('PATCH', url, {'certKeyChain': [
            {k: v for k, v in e.items() if k in ('name', 'cert', 'key', 'chain', 'passphrase',
                                                   'usage')} for e in chains]},
            what='updating the profile %s' % profile)
        return 'updated'

    # -- deploy -----------------------------------------------------------------
    @staticmethod
    def twin_options(bundle, options):
        """The options a twin is named by: acme-<name>-<kind>-<date>-<serial>."""
        alt = alt_of(bundle)
        return dict(options or {}, object_name='%s-%s' % (label_of(bundle, options, 34),
                                                          family_of(alt)))

    def put_one(self, b, opts, part, did):
        """Key, certificate and chain of one certificate installed. -> (path, chain path)."""
        name = object_name(b, opts)
        cert_path = '/%s/%s' % (part, name)
        if self.exists('cert', cert_path) and self.exists('key', cert_path) and \
                not as_bool(opts.get('force')):
            self.ctx.step('%s is there already' % cert_path)
        else:
            local = self.upload(name + '.key', b.as_format('key-pem'))
            self.install('key', cert_path, local)
            self.rm_upload(local)
            local = self.upload(name + '.crt', b.as_format('cert-pem'))
            self.install('cert', cert_path, local)
            self.rm_upload(local)
            self.ctx.step('installed %s' % cert_path, 'ok')
            did.append('installed %s' % name)
        chain_path = None
        chain = chain_list(b)
        if chain:
            cname = 'acme-chain-%s' % chain_id(''.join(chain))
            chain_path = '/%s/%s' % (part, cname)
            if not self.exists('cert', chain_path):
                local = self.upload(cname + '.crt', ''.join(chain).encode())
                self.install('cert', chain_path, local)
                self.rm_upload(local)
                self.ctx.step('installed the chain as %s' % chain_path, 'ok')
        return cert_path, chain_path

    def deploy(self, bundle, options):
        options = options or {}
        part = (options.get('partition') or self.c('partition') or 'Common').strip('/')
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        cert_path = '/%s/%s' % (part, name)
        alt = alt_of(bundle)
        topts = self.twin_options(bundle, options) if alt is not None else None
        self.login()
        try:
            if self.unchanged(bundle, options, present=lambda: self.exists('cert', cert_path)
                              and (alt is None or self.exists(
                                  'cert', '/%s/%s' % (part, object_name(alt, topts))))):
                return self.same(bundle, 'on %s' % self.c('host'))
            did = []
            cert_path, chain_path = self.put_one(bundle, options, part, did)
            more = []
            if alt is not None:
                a_path, a_chain = self.put_one(alt, topts, part, did)
                more = [(a_path, a_path, a_chain, '/%s/%s' % (part, name_prefix(alt, topts)),
                         'acme-%s' % family_of(alt))]
                self.ctx.step('dual: the twin (%s) beside it, an entry of its own in each '
                              'profile' % alt.key_type if getattr(alt, 'key_type', '') else
                              'dual: the twin beside it')
            for p in lines(options.get('profiles')):
                how = self.point_profile(p, part, cert_path, cert_path, chain_path,
                                         '/%s/%s' % (part, prefix),
                                         as_bool(options.get('create_profile')), more)
                self.ctx.step('profile %s %s' % (p, how), 'ok')
                did.append('%s %s' % (p, how))
            self.cleanup(part, prefix, name, self.keep(options))
            if alt is not None:
                self.cleanup(part, name_prefix(alt, topts), object_name(alt, topts),
                             self.keep(options))
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
