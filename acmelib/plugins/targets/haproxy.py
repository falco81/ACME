# -*- coding: utf-8 -*-
"""
HAProxy without a reload: the certificate (key + full chain in one PEM)
written to its file over SSH and swapped into the running HAProxy through
its Runtime API on the stats socket - "set ssl cert" + "commit ssl cert" -
so no connection is dropped. A certificate HAProxy does not know yet is made
with "new ssl cert" and added to a crt-list.

    echo 'show ssl cert <path>'           | socat stdio <socket>   (serial there now)
    printf 'set ssl cert <path> <<\\n<PEM>\\n' | socat stdio <socket>  -> Transaction created
    echo 'commit ssl cert <path>'         | socat stdio <socket>   -> Success!
    echo 'new ssl cert <path>'            | ...    (unknown to HAProxy yet)
    echo 'add ssl crt-list <list> <path>' | ...

Rights: a user who may write the file and the stats socket (root, or through
sudo); the socket with "level admin" (stats socket /run/haproxy/admin.sock
mode 660 level admin); socat on the machine. HAProxy 2.2 or later.

Sources:
    https://docs.haproxy.org/2.8/management.html#9.3-set%20ssl%20cert
    https://docs.haproxy.org/2.8/management.html#9.3-commit%20ssl%20cert
    https://www.haproxy.com/documentation/haproxy-runtime-api/reference/set-ssl-cert/
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/haproxy.sh
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, ssh_fields, verify_fields, quote, text,
    norm_fp)
from acmelib.plugins.targets import _files as F


class HaproxyTarget(SshMixin, Base):
    kind = 'haproxy'
    title = 'HAProxy (Runtime API, no reload)'
    vendor = 'HAProxy'
    description = ('Writes the PEM over SSH and swaps the certificate in the running HAProxy '
                   'through its Runtime API (set ssl cert, commit) - no reload, no dropped '
                   'connection.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('socket', 'Stats socket', 'text', default='/run/haproxy/admin.sock',
              help='the "stats socket" of haproxy.cfg, with level admin'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('cert_path', 'Certificate file', 'text', required=True,
              placeholder='/etc/haproxy/certs/www.example.com.pem',
              help='the PEM as haproxy.cfg (crt) or a crt-list names it; key + full chain'),
        field('crt_list', 'crt-list for a new certificate', 'text', advanced=True,
              placeholder='/etc/haproxy/crt-list.txt',
              help='a certificate HAProxy does not know yet is added to this crt-list; '
                   'empty: it must be known already (named in haproxy.cfg)'),
        field('reload_cmd', 'Reload when the Runtime API cannot', 'text', advanced=True,
              placeholder='systemctl reload haproxy',
              help='run instead when the socket is not there or refuses; empty: fail'),
    ] + verify_fields()

    def path(self, options):
        p = text((options or {}).get('cert_path')).strip()
        if not p.startswith('/') or re.search(r'[\s\'"`$;&|<>\\]', p) or '..' in p.split('/'):
            raise PluginError('the certificate file must be an absolute path without spaces or '
                              'shell characters', retry=False)
        return p

    def sock(self):
        s = text(self.c('socket') or '/run/haproxy/admin.sock').strip()
        if s.startswith(('ipv4@', 'tcp:', 'TCP:')) or re.match(r'^[\w.-]+:\d+$', s):
            return 'TCP:' + s.split('@')[-1].replace('tcp:', '').replace('TCP:', '')
        return 'UNIX-CONNECT:' + s

    def runtime(self, s, command, check=True):
        rc, out, err = self.sh(s, 'echo %s | socat stdio %s' % (quote(command), quote(self.sock())),
                               check=False)
        if check and rc != 0:
            raise PluginError('the Runtime API cannot be reached on %s: %s'
                              % (self.c('socket'), (text(err).strip() or text(out).strip())[-200:]))
        return rc, text(out)

    def served_serial(self, s, path):
        rc, out = self.runtime(s, 'show ssl cert %s' % path, check=False)
        m = re.search(r'^Serial:\s*([0-9A-Fa-f]+)', out, re.M)
        return norm_fp(m.group(1)) if m else None

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'command -v socat >/dev/null || echo NO-SOCAT; id -un',
                                   what='signing in')
            if 'NO-SOCAT' in out:
                raise PluginError('signed in, but socat is not on the machine '
                                  '(apt install socat / dnf install socat)', retry=False)
            rc, info = self.runtime(s, 'show info')
            ver = re.search(r'^Version:\s*(\S+)', info, re.M)
            return 'signed in; HAProxy %s answers on %s' % (ver.group(1) if ver else '?',
                                                           self.c('socket'))

    def deploy(self, bundle, options):
        options = options or {}
        path = self.path(options)
        pem = bundle.as_format('combined-pem')
        files = [{'path': path, 'data': pem, 'mode': 0o600, 'owner': None}]
        want = norm_fp(bundle.serial).lstrip('0')
        with self.ssh() as s:
            if not as_bool(options.get('force')) and F.all_same(self, s, files) and \
                    (self.served_serial(s, path) or '').lstrip('0') == want:
                self.remember(bundle, options)
                return self.same(bundle, 'in %s and served' % path)
            existed = F.write_files(self, s, files)
            F.drop_previous(self, s, files)
            self.ctx.step('wrote %s' % path, 'ok')
            try:
                how = self.swap(s, path, pem, options, known=existed[0])
            except PluginError as e:
                cmd = text(options.get('reload_cmd')).strip()
                if not cmd:
                    raise
                self.ctx.step('the Runtime API did not take it (%s): reloading instead' % e,
                              'warn')
                self.sh(s, cmd, what='"%s"' % cmd)
                how = 'reloaded with %s' % cmd
        self.remember(bundle, options)
        return '%s written, %s' % (path, how)

    def swap(self, s, path, pem, options, known):
        rc, out = self.runtime(s, 'show ssl cert')
        listed = [x.strip().lstrip('*') for x in out.splitlines()]
        new = path not in listed
        if new:
            lst = text(options.get('crt_list')).strip()
            if not lst:
                raise PluginError('HAProxy does not know %s: name it in haproxy.cfg (crt) or '
                                  'give a crt-list for new certificates' % path, retry=False)
            rc, out = self.runtime(s, 'new ssl cert %s' % path)
            if 'New empty' not in out:
                raise PluginError('new ssl cert %s: %s' % (path, out.strip()[-200:]))
        tmp = '/tmp/.acme-haproxy-%s' % re.sub(r'[^a-z0-9]', '', path.lower())[-24:]
        s.put(pem, tmp, 0o600)
        try:
            script = ('{ printf %%s\\\\n %s; cat %s; printf \\\\n; } | socat stdio %s'
                      % (quote('set ssl cert %s <<' % path), quote(tmp), quote(self.sock())))
            rc, out, err = self.sh(s, script, check=False)
        finally:
            s.run('rm -f %s' % quote(tmp), check=False)
        if not re.search(r'Transaction (created|updated)', text(out)):
            raise PluginError('set ssl cert %s: %s' % (path, (text(out).strip() or
                                                               text(err).strip())[-300:]))
        rc, out = self.runtime(s, 'commit ssl cert %s' % path)
        if 'Success!' not in out:
            self.runtime(s, 'abort ssl cert %s' % path, check=False)
            raise PluginError('commit ssl cert %s: %s' % (path, out.strip()[-300:]))
        self.ctx.step('HAProxy serves it now (set ssl cert, commit)', 'ok')
        if new:
            lst = text(options.get('crt_list')).strip()
            rc, out = self.runtime(s, 'add ssl crt-list %s %s' % (lst, path))
            if 'Success!' not in out:
                raise PluginError('add ssl crt-list %s: %s' % (lst, out.strip()[-300:]))
            self.ctx.step('added to the crt-list %s (add it to the file as well, for a restart)'
                          % lst, 'ok')
            return 'new in HAProxy and its crt-list'
        return 'swapped in the running HAProxy'
