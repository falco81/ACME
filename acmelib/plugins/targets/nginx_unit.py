# -*- coding: utf-8 -*-
"""
NGINX Unit through its control API (curl on the machine to the control
socket, over SSH): the certificate bundle (full chain + key) uploaded under a
dated name, the listeners asked for pointed at it, older acme bundles
deleted. Unit takes it at once, without a restart.

    PUT    --unix-socket /var/run/control.unit.sock http://localhost/certificates/<name>
    GET    .../config/listeners
    PUT    .../config/listeners/<listener>/tls/certificate   "<name>"  (or a list)
    GET    .../certificates          DELETE .../certificates/<name>

Rights: a user who may use the control socket (root, or through sudo); curl
there.

Sources:
    https://unit.nginx.org/certificates/
    https://unit.nginx.org/controlapi/
    https://unit.nginx.org/configuration/#ssl-tls-configuration
"""
from __future__ import annotations

import json
import secrets
import urllib.parse

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    ssh_fields, verify_fields, keep_field, quote, text, ours, SEG_PATTERN)


class NginxUnitTarget(SshMixin, Base):
    kind = 'nginx_unit'
    discovery = False       # nothing to find: a server over SSH
    title = 'NGINX Unit'
    vendor = 'NGINX'
    description = ('Uploads the certificate bundle to NGINX Unit\'s control API over SSH, points '
                   'the listeners at it and deletes the older bundles - no restart.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('socket', 'Control socket', 'text', default='/var/run/control.unit.sock',
              help='unitd --control; /run/unit/control.sock on some systems'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('listeners', 'Listeners', 'list', pattern=SEG_PATTERN, default='*:443',
              help='one a line, as in Unit\'s config ("*:443", "127.0.0.1:8443")'),
        keep_field(1),
    ] + verify_fields()

    def curl(self, s, method, path, data=None, raw=None, what=None, ok404=False):
        sock = text(self.c('socket') or '/var/run/control.unit.sock').strip()
        cmd = 'curl -sS -w "\\n%%{http_code}" -X %s --unix-socket %s' % (method, quote(sock))
        tmp = None
        if data is not None or raw is not None:
            tmp = '/tmp/.acme-unit-%s' % secrets.token_hex(6)
            s.put(raw if raw is not None else json.dumps(data).encode(), tmp, 0o600)
            cmd += ' --data-binary @%s' % quote(tmp)
        cmd += ' %s' % quote('http://localhost' + path)
        try:
            rc, out, err = self.sh(s, cmd, check=False)
        finally:
            if tmp:
                s.run('rm -f %s' % quote(tmp), check=False)
        if rc != 0:
            raise PluginError('%s: the control socket %s cannot be reached: %s'
                              % (what or path, sock, (text(err) or text(out)).strip()[-200:]))
        body, _, code = text(out).rstrip('\n').rpartition('\n')
        st = int(code) if code.strip().isdigit() else 0
        try:
            parsed = json.loads(body) if body.strip() else None
        except ValueError:
            parsed = body
        if st == 404 and ok404:
            return st, None
        if st >= 300 or st == 0:
            msg = ''
            if isinstance(parsed, dict):
                msg = ' '.join(text(parsed.get(k)) for k in ('error', 'detail') if parsed.get(k))
            raise PluginError('%s: Unit said %s - %s' % (what or path, st,
                                                         msg or text(parsed)[:200]),
                              retry=st >= 500)
        return st, parsed

    def test(self):
        with self.ssh() as s:
            st, d = self.curl(s, 'GET', '/certificates', what='listing the certificates')
        n = len(d or {}) if isinstance(d, dict) else 0
        return 'signed in; Unit answers, %d certificate bundle%s' % (n, '' if n == 1 else 's')

    def lpath(self, listener):
        return '/config/listeners/%s' % urllib.parse.quote(listener, safe='')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        lis = lines(self.opt(options, 'listeners', '*:443'))
        did = []
        with self.ssh() as s:
            st, have = self.curl(s, 'GET', '/certificates', what='listing the certificates')
            have = have if isinstance(have, dict) else {}
            st, conf = self.curl(s, 'GET', '/config/listeners', what='reading the listeners')
            conf = conf if isinstance(conf, dict) else {}

            def points(li):
                c = ((conf.get(li) or {}).get('tls') or {}).get('certificate')
                return c == name or (isinstance(c, list) and name in c)
            if not as_bool(options.get('force')) and name in have and all(points(x) for x in lis):
                self.remember(bundle, options)
                return self.same(bundle, 'as %s' % name)
            if name not in have:
                self.curl(s, 'PUT', '/certificates/%s' % name,
                          raw=bundle.as_format('fullchain-pem') + bundle.as_format('key-pem'),
                          what='uploading %s' % name)
                self.ctx.step('uploaded the bundle %s' % name, 'ok')
                did.append('uploaded %s' % name)
            for li in lis:
                if li not in conf:
                    raise PluginError('Unit has no listener "%s"' % li, retry=False)
                cur = ((conf.get(li) or {}).get('tls') or {}).get('certificate')
                if isinstance(cur, list):
                    # only this certificate's own replaced, once (1.0.51)
                    new = []
                    for c in cur:
                        c = name if ours(text(c), prefix) else c
                        if c not in new:
                            new.append(c)
                    if name not in new:
                        new.append(name)
                else:
                    new = name
                self.curl(s, 'PUT', self.lpath(li) + '/tls/certificate', new,
                          what='pointing %s at %s' % (li, name))
                self.ctx.step('listener %s uses %s' % (li, name), 'ok')
                did.append(li)
            self.cleanup(s, list(have) + [name], prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, s, names, prefix, current, keep):
        if keep < 0:
            return
        for old in prune(names, prefix, keep, current):
            try:
                self.curl(s, 'DELETE', '/certificates/%s' % old, what='deleting %s' % old)
                self.ctx.step('deleted the old bundle %s' % old)
            except PluginError as e:
                self.ctx.step('the old bundle %s stays (still used?): %s' % (old, e), 'warn')

