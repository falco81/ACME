# -*- coding: utf-8 -*-
"""
FortiADC (REST API, 7.4.0 and later for the upload): the certificate
uploaded as a local certificate under a dated name, put into the local
certificate group in place of the older acme one, the client SSL profiles and
virtual servers asked for pointed at that group, older acme certificates no
group holds deleted; signed out.

    POST   /api/user/login  {"username", "password"} -> {"token"}; then
           Authorization: Bearer <token> (and the cookie it set) - or a REST API admin's key
    GET    /api/user/logout
    GET    /api/system_certificate_local[?mkey=<name>]&vdom=<vdom>   there already? older ones
    POST   /api/upload/certificate_local?vdom=<vdom | false>   multipart: type=CertKey,
           mkey=<name>, passwd, cert=<PEM>, key=<PEM>, upload=text, vdom
    GET    /api/system_certificate_local_cert_group                   the groups (the list)
    GET    /api/system_certificate_local_cert_group_child_group_member?pkey=<group>
    POST   /api/system_certificate_local_cert_group_child_group_member?pkey=<group>
           {"OCSP_stapling", "default", "extra_local_cert", "intermediate_cag", "local_cert"}
    DELETE /api/system_certificate_local_cert_group_child_group_member?pkey=<group>&mkey=<id>
    GET|PUT /api/load_balance_client_ssl_profile?mkey=<p>    "local_certificate_group"
    GET|PUT /api/load_balance_virtual_server?mkey=<vs>       "client_ssl_profile"
    DELETE /api/system_certificate_local?mkey=<name>

Checked against (the user's collection of the vendor's documents, api-docs/fortinet/):
    fortiadc.md (and notes.md) - quotes from Fortinet's official Ansible collection
      https://github.com/fortinet-ansible-dev/ansible-galaxy-fortiadc-collection
      (plugins/httpapi/fadcos.py; plugins/modules/fadcos_system_certificate_local_upload.py,
      fadcos_system_certificate_local.py, fadcos_local_cert_group.py,
      fadcos_client_ssl_profile.py, fadcos_virtual_server.py)
      https://ansible-galaxy-fortiadc-docs.readthedocs.io/en/latest/gen/fadcos_system_certificate_local_upload.html
      https://docs.fortinet.com/document/fortiadc/7.2.0/handbook/286206 (REST API admin)

Less certain (the reference is on fndn.fortinet.net, behind a sign-in):
    - how a REST API admin's key is sent (taken as Authorization: Bearer <key>);
    - the vdom form field of the upload without VDOMs ("false", as the Ansible module puts
      it in the address);
    - the values of a group member's "default" and "OCSP_stapling" (enable / disable) and
      the answers' shape ("payload": the object(s), or a number below 0 for an error);
    - the intermediates: FortiADC takes an intermediate CA group by name
      ("intermediate_cag"); uploading one is not in the documents, so the group is one
      you made in FortiADC.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, object_name, name_prefix, ours, prune,
    http_fields, tls_fields, verify_fields, keep_field, multipart)


def q(s):
    return urllib.parse.quote(text(s), safe='')


def items(d):
    """The object(s) of an answer: under "payload" (a list or one object)."""
    p = d.get('payload') if isinstance(d, dict) else d
    if isinstance(p, list):
        return [x for x in p if isinstance(x, dict)]
    if isinstance(p, dict):
        return [p]
    return []


class FortiAdcTarget(HttpTarget):
    kind = 'fortiadc'
    discovery = False       # nothing to find: FortiADC lists no VDOMs through the calls acme makes
    title = 'FortiADC'
    vendor = 'Fortinet'
    description = ('Uploads the certificate to FortiADC as a local certificate, puts it into a '
                   'local certificate group in place of the older one and points client SSL '
                   'profiles and virtual servers at the group.')
    doc = 'targets.md'
    fields = http_fields(443, 'fortiadc.example.local') + [
        field('auth', 'Sign in with', 'select', default='password',
              options=[['password', 'a user and password'],
                       ['api_key', 'the key of a REST API admin']]),
        field('user', 'User', 'text', default='admin', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('api_key', 'API key', 'secret', show_if={'auth': ['api_key']},
              help='System → Administrator → Create New → REST API Admin'),
        field('vdom', 'VDOM', 'text', placeholder='root',
              help='empty on a FortiADC without VDOMs'),
    ] + tls_fields()
    deploy_fields = [
        field('cert_group', 'Local certificate group', 'catalog', catalog='groups',
              autoload=False, required=True,
              help='the group the client SSL profile presents; the older acme member of it is '
                   'replaced by the new certificate'),
        field('intermediate_cag', 'Intermediate CA group', 'text',
              help='the intermediate CA group (made in FortiADC) of the new member; empty: none'),
        field('client_ssl_profiles', 'Client SSL profiles to point at the group', 'list',
              placeholder='LB_CLIENT_SSL_PROF_DEFAULT',
              help='one a line; empty: the profiles are left as they are (they use the group '
                   'already)'),
        field('virtual_servers', 'Virtual servers to point at the profile', 'list',
              placeholder='vs-www',
              help='one a line: their client SSL profile is set to the first profile above'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the certificate groups',
                'help': 'Lists the local certificate groups and their members - it changes '
                        'nothing.',
                'changes': False}]

    token = None
    cookie = None

    # -- the session ------------------------------------------------------------------------
    def auth_headers(self):
        if self.c('auth', 'password') == 'api_key':
            return {'Authorization': 'Bearer %s' % (self.c('api_key') or '')}
        h = {}
        if self.token:
            h['Authorization'] = 'Bearer %s' % self.token
        if self.cookie:
            h['Cookie'] = self.cookie
        return h

    def vq(self, path, upload=False):
        v = text(self.c('vdom')).strip()
        if not v and not upload:
            return path
        return '%s%svdom=%s' % (path, '&' if '?' in path else '?', q(v or 'false'))

    def api(self, method, path, body=None, ok=None, what=None, headers=None, upload=False):
        st, hd, d = self.req(method, self.vq(path, upload), body, headers, ok=ok, what=what)
        d = d if isinstance(d, (dict, list)) else {}
        p = d.get('payload') if isinstance(d, dict) else None
        if isinstance(p, int) and p < 0:
            raise PluginError('%s: FortiADC said error %d' % (what or path, p),
                              detail=text(d)[:4000])
        return st, d, hd

    def login(self):
        if self.c('auth', 'password') == 'api_key':
            return
        try:
            st, d, hd = self.api('POST', '/api/user/login', {
                'username': self.c('user') or '', 'password': self.c('password') or ''},
                what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        tok = d.get('token') if isinstance(d, dict) else None
        if not tok:
            raise PluginError('FortiADC gave no token on signing in', retry=False)
        self.token = text(tok)
        ck = text(hd.get('set-cookie'))
        self.cookie = '; '.join(c.split(';', 1)[0].strip() for c in ck.split(',')
                                if '=' in c.split(';', 1)[0]) or None

    def logout(self):
        if self.token:
            try:
                self.req('GET', '/api/user/logout', ok=range(0, 600))
            except PluginError:
                pass
        self.token = self.cookie = None

    # -- what is there ----------------------------------------------------------------------
    def local_certs(self):
        st, d, hd = self.api('GET', '/api/system_certificate_local',
                             what='listing the local certificates')
        return [text(x.get('mkey') or x.get('name')) for x in items(d)
                if x.get('mkey') or x.get('name')]

    def groups(self):
        st, d, hd = self.api('GET', '/api/system_certificate_local_cert_group',
                             what='listing the local certificate groups')
        return [text(x.get('mkey') or x.get('name')) for x in items(d)
                if x.get('mkey') or x.get('name')]

    def members(self, group):
        st, d, hd = self.api('GET', '/api/system_certificate_local_cert_group_child_group_member'
                             '?pkey=%s' % q(group), what='reading the group %s' % group)
        return items(d)

    def test(self):
        self.login()
        try:
            n = len(self.local_certs())
            g = len(self.groups())
            return 'signed in to FortiADC %s; %d local certificate%s, %d group%s' % (
                self.c('host'), n, '' if n == 1 else 's', g, '' if g == 1 else 's')
        finally:
            self.logout()

    def catalog(self, key):
        if key != 'groups':
            raise PluginError('there is no list called %s here' % key, retry=False)
        self.login()
        try:
            opts = [[g, g] for g in self.groups()]
            return {'options': opts, 'sets': {}, 'said': '%d groups' % len(opts)}
        finally:
            self.logout()

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        self.login()
        try:
            gs = self.groups()
            for g in gs:
                ms = self.members(g)
                self.ctx.step('%s: %s' % (g, ', '.join(
                    '%s%s' % (m.get('local_cert'), ' (default)' if m.get('default') == 'enable'
                              else '') for m in ms) or 'empty'))
            return '%d group%s' % (len(gs), '' if len(gs) == 1 else 's')
        finally:
            self.logout()

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        group = text(options.get('cert_group')).strip()
        if not group:
            raise PluginError('no local certificate group is set', retry=False)
        self.login()
        try:
            there = name in self.local_certs()
            if self.unchanged(bundle, options, present=lambda: there):
                return self.same(bundle, 'as %s' % name)
            did = []
            if not there:
                v = text(self.c('vdom')).strip() or 'false'
                body, ctype = multipart([
                    ('type', 'CertKey'), ('mkey', name), ('passwd', ''),
                    ('cert', text(bundle.as_format('cert-pem'))),
                    ('key', text(bundle.as_format('key-pem'))),
                    ('upload', 'text'), ('vdom', v)])
                self.api('POST', '/api/upload/certificate_local', body,
                         headers={'Content-Type': ctype}, upload=True,
                         what='uploading %s' % name)
                self.ctx.step('uploaded the local certificate %s' % name, 'ok')
                did.append('uploaded %s' % name)
            else:
                self.ctx.step('the local certificate %s is there already' % name)
            ms = self.members(group)
            old = [m for m in ms if ours(text(m.get('local_cert')), prefix) and
                   text(m.get('local_cert')) != name]
            if not any(text(m.get('local_cert')) == name for m in ms):
                default = 'enable' if (not ms or any(m.get('default') == 'enable'
                                                      for m in old)) else 'disable'
                self.api('POST', '/api/system_certificate_local_cert_group_child_group_member'
                         '?pkey=%s' % q(group), {
                             'OCSP_stapling': 'disable', 'default': default,
                             'extra_local_cert': '',
                             'intermediate_cag': text(options.get('intermediate_cag')).strip(),
                             'local_cert': name},
                         what='adding %s to the group %s' % (name, group))
                self.ctx.step('the group %s holds %s%s' % (
                    group, name, ' (default)' if default == 'enable' else ''), 'ok')
                did.append(group)
            for m in old:
                try:
                    self.api('DELETE', '/api/system_certificate_local_cert_group_child_group_'
                             'member?pkey=%s&mkey=%s' % (q(group), q(m.get('mkey'))),
                             what='taking %s out of %s' % (m.get('local_cert'), group))
                    self.ctx.step('took the older %s out of %s' % (m.get('local_cert'), group))
                except PluginError as e:
                    self.ctx.step('the older %s stays in %s: %s' % (m.get('local_cert'), group,
                                                                    e), 'warn')
            profiles = lines(options.get('client_ssl_profiles'))
            for p in profiles:
                self.point('/api/load_balance_client_ssl_profile', p, 'local_certificate_group',
                           group, 'the client SSL profile', did)
            vss = lines(options.get('virtual_servers'))
            if vss and not profiles:
                raise PluginError('virtual servers are given but no client SSL profile to point '
                                  'them at', retry=False)
            for vs in vss:
                self.point('/api/load_balance_virtual_server', vs, 'client_ssl_profile',
                           profiles[0], 'the virtual server', did)
            self.cleanup(prefix, name, self.keep(options))
            self.remember(bundle, options)
            return ', '.join(did) or 'already %s' % name
        finally:
            self.logout()

    def point(self, path, mkey, key, value, words, did):
        st, d, hd = self.api('GET', '%s?mkey=%s' % (path, q(mkey)),
                             what='reading %s %s' % (words, mkey))
        got = items(d)
        if not got:
            raise PluginError('FortiADC has no %s "%s"' % (words.replace('the ', ''), mkey),
                              retry=False)
        obj = dict(got[0])
        if text(obj.get(key)) == value:
            self.ctx.step('%s %s uses %s already' % (words, mkey, value))
            return
        obj[key] = value
        self.api('PUT', '%s?mkey=%s' % (path, q(mkey)), obj,
                 what='pointing %s %s at %s' % (words, mkey, value))
        self.ctx.step('%s %s uses %s' % (words, mkey, value), 'ok')
        did.append(mkey)

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            gone = prune([n for n in self.local_certs() if ours(n, prefix)], prefix, keep,
                         current)
            used = set()
            if gone:
                for g in self.groups():
                    used.update(text(m.get('local_cert')) for m in self.members(g))
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older %s stays: a group still holds it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/api/system_certificate_local?mkey=%s' % q(old),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
