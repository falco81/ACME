# -*- coding: utf-8 -*-
"""
MikroTik RouterOS: the files put on the router over SSH (SCP/SFTP), imported
and bound to services through the REST API (RouterOS 7) or the CLI over SSH
(RouterOS 6, or no REST); the old certificates removed.

Checked against api-docs/mikrotik/notes.md (RouterOS manual, CLI reference
7.24-7.26, changelogs): a file + /certificate/import (the certificate, then
its key), services by the certificate's name under a new name each renewal;
/ip/service's certificate "applies to www-ssl, api-ssl and reverse-proxy"
(reverse-proxy from 7.22, so it may be named here too); the OpenVPN server is
a menu of records in 7.26 - its set command first, each record changed when
that is refused. Less certain: the REST shapes are the manual's general
mapping (POST runs a command, PATCH changes a record), not examples of these
menus; whether import takes a certificate under a name already there is not
documented, so the names stay dated.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    HttpTarget, SshMixin, PluginError, field, lines, as_bool, as_int, object_name,
    name_prefix, prune, tls_fields, verify_fields, keep_field,
    norm_fp, fp_of, text, put_scp)

IP_SERVICES = ('www-ssl', 'api-ssl', 'reverse-proxy')     # reverse-proxy: RouterOS 7.22+
SINGLETONS = {'sstp': '/interface/sstp-server/server', 'ovpn': '/interface/ovpn-server/server'}


def ros_str(s):
    return '"%s"' % text(s).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')


class MikroTikTarget(SshMixin, HttpTarget):
    kind = 'mikrotik'
    title = 'MikroTik RouterOS'
    vendor = 'MikroTik'
    description = ('Puts the certificate on the router over SSH, imports it and binds it to '
                   'www-ssl, api-ssl, SSTP or OpenVPN through the REST API (v7) or the CLI '
                   '(v6), and removes the old ones.')
    doc = 'targets.md'
    fields = [
        field('host', 'Address', 'text', required=True, placeholder='router.example.local'),
        field('mode', 'Speak through', 'select', default='rest',
              options=[['rest', 'REST API (RouterOS 7) + SSH for the files'],
                       ['ssh', 'SSH only (RouterOS 6)']]),
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret',
              help='for REST, and for SSH when no key is given'),
        field('port', 'HTTPS port', 'number', default=443, show_if={'mode': ['rest']}),
        field('ssh_port', 'SSH port', 'number', default=22),
        field('ssh_key', 'The SSH key', 'sshkey', secret=True, pass_key='ssh_key_pass',
              howto='mikrotik', try_command='/system identity print',
              help='for the files over SSH (and for everything in SSH mode); without one '
                   'the password is used'),
        field('hostkey', 'SSH host key', 'text', advanced=True),
        field('trust_first', 'Trust the first host key seen', 'bool', default=True,
              advanced=True),
    ] + tls_fields()
    deploy_fields = [
        field('services', 'Use it for', 'list', default='www-ssl\napi-ssl',
              help='one a line: www-ssl, api-ssl, reverse-proxy (RouterOS 7.22+), sstp, ovpn'),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        import base64
        tok = base64.b64encode(('%s:%s' % (self.c('user'), self.c('password') or ''))
                               .encode()).decode()
        return {'Authorization': 'Basic ' + tok}

    def ssh(self):
        key = self.c('ssh_key')
        return self.ctx.ssh({
            'host': self.c('host'), 'port': as_int(self.c('ssh_port', 22), 22),
            'user': self.c('user'), 'password': None if key else self.c('password'),
            'key': key or None, 'key_pass': self.c('ssh_key_pass') or None,
            'hostkey': self.c('hostkey') or None,
            'trust_first': as_bool(self.c('trust_first', True), True),
            'timeout': as_int(self.c('timeout', 30), 30)})

    def rest(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, '/rest' + path, body, ok=ok, what=what)
        return d

    def ros(self, s, cmd, check=True):
        rc, out, err = s.run(cmd, timeout=60, check=False)
        out = text(out)
        if check and (rc not in (0, None) or re.search(r'^(failure|bad command|syntax error|'
                                                       r'expected end)', out.strip(), re.I | re.M)):
            raise PluginError('RouterOS: %s - %s' % (cmd[:80], (out.strip() or text(err))[-200:]),
                              detail=out + text(err))
        return out

    def rest_mode(self):
        return (self.c('mode') or 'rest') == 'rest'

    def test(self):
        if self.rest_mode():
            d = self.rest('GET', '/system/resource', what='signing in')
            return 'signed in to %s, RouterOS %s on %s' % (
                self.c('host'), d.get('version', '?'), d.get('board-name', '?'))
        with self.ssh() as s:
            out = self.ros(s, '/system resource print')
        m = re.search(r'version:\s*(\S+)', out)
        return 'signed in to %s over SSH, RouterOS %s' % (self.c('host'),
                                                         m.group(1) if m else '?')

    def services(self, options):
        out = [x.lower() for x in lines(self.opt(options, 'services'))]
        bad = [x for x in out if x not in IP_SERVICES and x not in SINGLETONS]
        if bad:
            raise PluginError('not a service acme can bind on RouterOS: %s' % ', '.join(bad),
                              retry=False)
        # the one acme speaks REST through goes last
        return sorted(out, key=lambda x: x == 'www-ssl')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        services = self.services(options)
        if self.rest_mode():
            return self._deploy_rest(bundle, options, name, prefix, services)
        return self._deploy_ssh(bundle, options, name, prefix, services)

    def _upload(self, s, name, bundle):
        crt, key = name + '.crt', name + '.key'
        put_scp(s, bundle.as_format('fullchain-pem'), crt)
        put_scp(s, bundle.as_format('key-pem'), key)
        return crt, key

    # -- RouterOS 7, REST ---------------------------------------------------------
    def _find(self, want_fp):
        for c in self.rest('GET', '/certificate') or []:
            if norm_fp(c.get('fingerprint')) == want_fp:
                return c
        return None

    def _deploy_rest(self, bundle, options, name, prefix, services):
        fp = fp_of(bundle)
        found = self._find(fp)
        if found and self.unchanged(bundle, options):
            return self.same(bundle, 'as %s' % found.get('name'))
        if not found or found.get('private-key') not in ('true', True):
            with self.ssh() as s:
                crt, key = self._upload(s, name, bundle)
            self.ctx.step('put %s and %s on the router' % (crt, key))
            for fn in (crt, key):
                try:
                    self.rest('POST', '/certificate/import',
                              {'file-name': fn, 'passphrase': '', 'name': name},
                              what='importing %s' % fn)
                except PluginError:
                    self.rest('POST', '/certificate/import', {'file-name': fn, 'passphrase': ''},
                              what='importing %s' % fn)
            found = self._find(fp)
            if not found:
                raise PluginError('the router did not take the certificate (its fingerprint '
                                  'is not among its certificates)')
            if found.get('private-key') not in ('true', True):
                raise PluginError('the router took the certificate without its key')
            for fn in (crt, key):
                for f in self.rest('GET', '/file?name=%s' % fn, ok=(200, 404)) or []:
                    if isinstance(f, dict) and f.get('.id'):
                        self.rest('DELETE', '/file/%s' % f['.id'], ok=range(0, 600))
        if found.get('name') != name:
            self.rest('PATCH', '/certificate/%s' % found['.id'], {'name': name},
                      what='naming the certificate')
        self.ctx.step('imported as %s' % name, 'ok')
        did = ['imported %s' % name]
        ip_services = {s_.get('name'): s_ for s_ in (self.rest('GET', '/ip/service') or [])}
        for svc in services:
            try:
                if svc in IP_SERVICES:
                    cur = ip_services.get(svc)
                    if not cur:
                        raise PluginError('there is no service %s' % svc, retry=False)
                    if cur.get('certificate') != name:
                        self.rest('PATCH', '/ip/service/%s' % cur['.id'],
                                  {'certificate': name}, what='binding %s' % svc)
                else:
                    self.bind_server(svc, name)
            except PluginError as e:
                if svc != 'www-ssl' or 'cannot be reached' not in str(e):
                    raise
                # the router changed the certificate under this very connection
                cur = {x.get('name'): x for x in self.rest('GET', '/ip/service') or []}
                if cur.get('www-ssl', {}).get('certificate') != name:
                    raise
            self.ctx.step('%s uses %s' % (svc, name), 'ok')
            did.append(svc)
        keep = self.keep(options)
        if keep >= 0:
            certs = self.rest('GET', '/certificate') or []
            used = set(x.get('certificate') for x in self.rest('GET', '/ip/service') or [])
            by = {c.get('name'): c for c in certs}
            for old in prune(by, prefix, keep, name):
                if old in used:
                    self.ctx.step('the old %s is still used: kept' % old, 'warn')
                    continue
                self.rest('DELETE', '/certificate/%s' % by[old]['.id'], ok=range(200, 300),
                          what='removing %s' % old)
                self.ctx.step('removed the old %s' % old)
        self.remember(bundle, options)
        return ', '.join(did)

    def bind_server(self, svc, name):
        """SSTP / OpenVPN server: its settings' set command (POST .../set); on a
        RouterOS where the OpenVPN server is a menu of records (7.26 lists it as a
        Directory), each record is changed (PATCH) when set is refused."""
        try:
            self.rest('POST', SINGLETONS[svc] + '/set', {'certificate': name},
                      what='binding %s' % svc)
            return
        except PluginError as e:
            first = e
        recs = self.rest('GET', SINGLETONS[svc], ok=range(200, 300), what='reading %s' % svc)
        recs = [r for r in (recs if isinstance(recs, list) else []) if isinstance(r, dict)
                and r.get('.id')]
        if not recs:
            raise first
        for r in recs:
            if r.get('certificate') != name:
                self.rest('PATCH', '%s/%s' % (SINGLETONS[svc], r['.id']), {'certificate': name},
                          what='binding %s %s' % (svc, r.get('name') or r['.id']))

    # -- RouterOS 6, CLI over SSH -------------------------------------------------
    def _names(self, s, prefix):
        out = self.ros(s, ':foreach c in=[/certificate find where name~%s] do={:put '
                          '[/certificate get $c name]}' % ros_str('^' + re.escape(prefix)),
                       check=False)
        return [x.strip() for x in out.splitlines() if x.strip()]

    def _deploy_ssh(self, bundle, options, name, prefix, services):
        with self.ssh() as s:
            have = self._names(s, prefix)
            if name in have and self.unchanged(bundle, options):
                return self.same(bundle, 'as %s' % name)
            if name not in have or as_bool(options.get('force')):
                crt, key = self._upload(s, name, bundle)
                if name in have:
                    self.ros(s, '/certificate remove [find where name=%s]' % ros_str(name))
                self.ros(s, '/certificate import file-name=%s passphrase=""' % ros_str(crt))
                self.ros(s, '/certificate import file-name=%s passphrase=""' % ros_str(key))
                # v6 names it after the file: <file>_0
                self.ros(s, ':foreach c in=[/certificate find where name~%s] do={'
                            '/certificate set $c name=%s}'
                         % (ros_str('^' + re.escape(crt) + '_0$'), ros_str(name)), check=False)
                self.ros(s, '/file remove [find where name=%s or name=%s]'
                         % (ros_str(crt), ros_str(key)), check=False)
                if name not in self._names(s, prefix):
                    raise PluginError('the router did not take the certificate as %s' % name)
            self.ctx.step('imported as %s' % name, 'ok')
            for svc in services:
                if svc in IP_SERVICES:
                    self.ros(s, '/ip service set [find where name=%s] certificate=%s'
                             % (ros_str(svc), ros_str(name)))
                else:
                    cli = '/' + ' '.join(SINGLETONS[svc].strip('/').split('/'))
                    self.ros(s, '%s set certificate=%s' % (cli, ros_str(name)))
                self.ctx.step('%s uses %s' % (svc, name), 'ok')
            keep = self.keep(options)
            if keep >= 0:
                for old in prune(self._names(s, prefix), prefix, keep, name):
                    self.ros(s, '/certificate remove [find where name=%s]' % ros_str(old),
                             check=False)
                    self.ctx.step('removed the old %s' % old)
        self.remember(bundle, options)
        return 'imported %s, %s' % (name, ', '.join(services) or 'not bound')
