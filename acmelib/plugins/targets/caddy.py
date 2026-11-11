# -*- coding: utf-8 -*-
"""
Caddy 2 over SSH, one of two ways:

  api    the certificate loaded into the running Caddy through its admin API
         (curl on the machine to localhost:2019): the entries of
         apps.tls.certificates.load_pem tagged with this certificate's name
         replaced - no file, no reload. For a Caddy run from JSON or with
         --resume; a Caddyfile reload loses it.
  files  the certificate and key written to the paths the Caddyfile names
         (tls /etc/caddy/certs/x.crt /etc/caddy/certs/x.key), then
         "caddy reload" (or the command given).

    GET   http://localhost:2019/config/apps/tls/certificates
    PATCH http://localhost:2019/config/apps/tls/certificates/load_pem   [..]
    POST  http://localhost:2019/config/apps/tls/certificates  {"load_pem": [..]}  (none yet)

Rights: SSH to the machine; for "files" a user who may write the files
(root, or through sudo); curl there.

Sources:
    https://caddyserver.com/docs/api
    https://caddyserver.com/docs/json/apps/tls/certificates/load_pem/
    https://caddyserver.com/docs/caddyfile/directives/tls
    https://caddyserver.com/docs/command-line#caddy-reload
"""
from __future__ import annotations

import json
import re
import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, label_of, ssh_fields, verify_fields, quote,
    text, parse_outputs)
from acmelib.plugins.targets import _files as F


class CaddyTarget(SshMixin, Base):
    kind = 'caddy'
    discovery = False       # nothing to find: a server over SSH
    title = 'Caddy'
    vendor = 'Caddy'
    description = ('Loads the certificate into a running Caddy through its admin API, or writes '
                   'the files a Caddyfile names and reloads Caddy - over SSH.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('admin', 'Admin API on the machine', 'text', default='localhost:2019',
              help='Caddy\'s "admin" address, reached with curl on the machine itself'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('mode', 'How', 'select', default='api',
              options=[['api', 'admin API: load_pem, no reload (JSON config)'],
                       ['files', 'files + reload (Caddyfile)']]),
        field('cert_file', 'Certificate file', 'text', show_if={'mode': ['files']},
              placeholder='/etc/caddy/certs/{name}.crt',
              help='the path the Caddyfile\'s tls line names; {name}: the certificate\'s name'),
        field('key_file', 'Key file', 'text', show_if={'mode': ['files']},
              placeholder='/etc/caddy/certs/{name}.key'),
        field('owner', 'Owner of the files', 'text', default='caddy:caddy',
              show_if={'mode': ['files']}),
        field('reload_cmd', 'Reload', 'text', default='caddy reload --config /etc/caddy/Caddyfile',
              show_if={'mode': ['files']}),
    ] + F.file_fields(show_if={'mode': ['files']}) + verify_fields()

    def admin(self):
        a = text(self.c('admin') or 'localhost:2019').strip()
        a = re.sub(r'^https?://', '', a).rstrip('/')
        if not re.match(r'^[A-Za-z0-9.\-\[\]:]+$', a):
            raise PluginError('"%s" is not host:port' % a, retry=False)
        return 'http://' + a

    def curl(self, s, method, path, data=None, what=None):
        """-> (http status, parsed JSON or text)."""
        tmp = None
        cmd = 'curl -sS -w "\\n%%{http_code}" -X %s -H %s' % (
            method, quote('Content-Type: application/json'))
        if data is not None:
            tmp = '/tmp/.acme-caddy-%s' % secrets.token_hex(6)
            s.put(json.dumps(data).encode(), tmp, 0o600)
            cmd += ' --data-binary @%s' % quote(tmp)
        cmd += ' %s' % quote(self.admin() + path)
        try:
            rc, out, err = self.sh(s, cmd, sudo=False, check=False)
        finally:
            if tmp:
                s.run('rm -f %s' % quote(tmp), check=False)
        if rc != 0:
            raise PluginError('%s: Caddy\'s admin API cannot be reached on %s: %s'
                              % (what or path, self.admin(),
                                 (text(err) or text(out)).strip()[-200:]))
        body, _, code = text(out).rstrip('\n').rpartition('\n')
        try:
            st = int(code)
        except ValueError:
            st, body = 0, text(out)
        try:
            parsed = json.loads(body) if body.strip() else None
        except ValueError:
            parsed = body
        if st >= 300 or st == 0:
            msg = parsed.get('error') if isinstance(parsed, dict) else text(parsed)
            raise PluginError('%s: Caddy said %s - %s' % (what or path, st, text(msg)[:300]))
        return st, parsed

    def test(self):
        with self.ssh() as s:
            st, d = self.curl(s, 'GET', '/config/apps/tls/certificates', what='reading the config')
            n = len((d or {}).get('load_pem') or []) if isinstance(d, dict) else 0
        return 'signed in; Caddy\'s admin API answers, %d certificate%s loaded through it' % (
            n, '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        if (self.opt(options, 'mode', 'api')) == 'files':
            return self.deploy_files(bundle, options)
        tag = 'acme-%s' % label_of(bundle, options)
        entry = {'certificate': text(bundle.as_format('fullchain-pem')),
                 'key': text(bundle.as_format('key-pem')), 'tags': [tag]}
        with self.ssh() as s:
            st, certs = self.curl(s, 'GET', '/config/apps/tls/certificates',
                                  what='reading the certificates')
            certs = certs if isinstance(certs, dict) else None
            have = list((certs or {}).get('load_pem') or [])
            mine = [e for e in have if tag in (e.get('tags') or [])]
            if not as_bool(options.get('force')) and len(mine) == 1 and \
                    mine[0].get('certificate', '').strip() == entry['certificate'].strip():
                self.remember(bundle, options)
                return self.same(bundle, 'loaded in Caddy (tag %s)' % tag)
            new = [e for e in have if tag not in (e.get('tags') or [])] + [entry]
            if certs is None:
                st, tls = self.curl(s, 'GET', '/config/apps/tls', what='reading the tls app')
                if tls is None:
                    raise PluginError('Caddy has no tls app in its config: give it one (or use '
                                      '"files" with a Caddyfile)', retry=False)
                self.curl(s, 'POST', '/config/apps/tls/certificates', {'load_pem': new},
                          what='loading the certificate')
            elif 'load_pem' in certs:
                self.curl(s, 'PATCH', '/config/apps/tls/certificates/load_pem', new,
                          what='loading the certificate')
            else:
                self.curl(s, 'POST', '/config/apps/tls/certificates/load_pem', new,
                          what='loading the certificate')
        self.ctx.step('Caddy took the certificate (load_pem, tag %s)' % tag, 'ok')
        self.remember(bundle, options)
        return 'loaded into Caddy as %s' % tag

    def deploy_files(self, bundle, options):
        cert = text(options.get('cert_file')).strip()
        key = text(options.get('key_file')).strip()
        if not cert or not key:
            raise PluginError('give the certificate and key files the Caddyfile names',
                              retry=False)
        owner = text(self.opt(options, 'owner', '')).strip()
        # one word each (1.0.51): a line break in the file's name made a line of its own ("key-pem
        # /home/eve/k.pem"), an owner of "0644" the key's mode
        for what, v in (('certificate file', cert), ('key file', key), ('owner', owner)):
            if re.search(r'\s', v):
                raise PluginError('the %s has a space or a line break in it' % what, retry=False)
        if owner and (not re.match(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$',
                                   owner) or re.match(r'^0[0-7]{3}$', owner)):
            raise PluginError('%r is not an owner (user or user:group)' % owner, retry=False)
        spec = 'fullchain-pem %s 0644 %s\nkey-pem %s 0640 %s' % (cert, owner, key, owner)
        outs = parse_outputs(spec, {'name': label_of(bundle, options)})
        files = [dict(o, data=bundle.as_format(o['format'])) for o in outs]
        cmd = text(self.opt(options, 'reload_cmd', '')).strip()
        with self.ssh() as s:
            if not as_bool(options.get('force')) and F.skip_same(options) and \
                    F.all_same(self, s, files):
                self.remember(bundle, options)
                return self.same(bundle, 'in %s' % files[0]['path'])
            existed = F.write_files(self, s, files, options=options)
            self.ctx.step('wrote %s and %s' % (files[0]['path'], files[1]['path']), 'ok')
            if cmd:
                rc, out, err = self.sh(s, cmd, check=False, timeout=120)
                if rc != 0:
                    F.put_back(self, s, files, existed)
                    self.sh(s, cmd, check=False)
                    raise PluginError('"%s" failed, the previous files are back: %s'
                                      % (cmd, (text(err) or text(out)).strip()[-300:]))
                self.ctx.step('ran %s' % cmd, 'ok')
            F.drop_previous(self, s, files, options)
        self.remember(bundle, options)
        return 'files written%s' % (', Caddy reloaded' if cmd else '')
