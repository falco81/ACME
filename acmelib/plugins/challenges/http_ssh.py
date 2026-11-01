# -*- coding: utf-8 -*-
"""HTTP-01 answered by web servers elsewhere: acme signs in over SSH to every
one of them (they stand behind DNS round-robin or a load balancer) and writes
the token file into their webroot, so acme itself is never reachable from the
internet. docs/validation.md has the nginx server block for those machines."""
from __future__ import annotations

import binascii
import os
import posixpath

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (HttpChallenge, as_bool, as_list, shq, ssh_conn,
                                                ssh_fields)

WEBROOT = '/var/www/acme-challenge/.well-known/acme-challenge'


class HttpSsh(HttpChallenge):
    kind = 'http_ssh'
    title = 'HTTP-01 on web servers over SSH'
    vendor = 'HTTP'
    description = ('The token file is written over SSH into the webroot of every web server the '
                   'name points at (nginx, Apache, …); the CA fetches it from them. acme itself '
                   'stays unreachable from the internet. Not for wildcards.')
    fields = [
        field('hosts', 'Web servers', 'list', required=True,
              placeholder='192.0.2.21\n192.0.2.22:2222\nweb3.example.com',
              help='Every machine that answers http://NAME/ - all of them get the file, and '
                   'all must succeed (the CA may ask any of them). host or host:port (SSH).'),
    ] + ssh_fields(user='acme') + [
        field('webroot', 'Folder of the tokens', 'text', default=WEBROOT,
              help='Where http://NAME/.well-known/acme-challenge/TOKEN is read from on those '
                   'machines. Made when missing.'),
        field('sudo', 'Write through sudo', 'bool', default=False,
              help='The file is written to /tmp and put in place with "sudo -n install" (a '
                   'sudoers line for install and rm in that folder).'),
        field('mode', 'File mode', 'text', default='0644', advanced=True),
        field('command_after', 'Command after writing', 'text', default='', advanced=True,
              placeholder='rsync -a /var/www/acme-challenge/ web-dr:/var/www/acme-challenge/',
              help='Run on each machine after the file is written (and after it is taken away).'),
        field('check', 'Check before the CA is asked', 'select', default='each',
              options=[['each', 'each machine by its address (Host: NAME)'],
                       ['name', 'http://NAME/ as the CA will (needs this machine to reach it)'],
                       ['none', 'no check']],
              help='The token is fetched over HTTP on port 80 and compared.'),
        field('check_port', 'HTTP port for the check', 'number', default=80, advanced=True),
    ]
    parallel = True

    # -- where -------------------------------------------------------------------
    def hosts(self):
        out = []
        for h in as_list(self.c('hosts', '')):
            host, port = D.split_hostport(h, 22)
            if not host or not all(c.isalnum() or c in '.-:_' for c in host):
                raise PluginError('"%s" is not a host' % h, retry=False)
            out.append((host, port))
        if not out:
            raise PluginError('no web server is set', retry=False)
        return out

    def webroot(self):
        w = posixpath.normpath(str(self.c('webroot', WEBROOT) or WEBROOT))
        if not w.startswith('/') or w == '/' or any(c in w for c in '\'"`$;&|\n\\'):
            raise PluginError('the folder %r will not be written to' % w, retry=False)
        return w

    def _mode(self):
        try:
            return int(str(self.c('mode', '0644')), 8) & 0o777
        except ValueError:
            return 0o644

    def _sudo(self):
        return as_bool(self.c('sudo', False))

    # -- on one machine ------------------------------------------------------------
    def _write(self, s, path, data):
        root = posixpath.dirname(path)
        if self._sudo():
            tmp = '/tmp/.acme-%s' % binascii.hexlify(os.urandom(6)).decode()
            s.put(data, tmp, mode=0o644)
            s.run('sudo -n mkdir -p %s && sudo -n install -m %o %s %s; rc=$?; rm -f %s; exit $rc'
                  % (shq(root), self._mode(), shq(tmp), shq(path), shq(tmp)), check=True)
        else:
            s.run('mkdir -p %s' % shq(root), check=True)
            s.put(data, path, mode=self._mode())
        self._after(s)

    def _remove(self, s, path):
        s.run('%srm -f %s' % ('sudo -n ' if self._sudo() else '', shq(path)), check=False)
        self._after(s)

    def _after(self, s):
        cmd = str(self.c('command_after', '') or '').strip()
        if cmd:
            s.run(cmd, check=True)

    def _each(self, fn, what):
        """fn(session, host) on every machine; [(host, error)] of those it failed on."""
        failed = []
        for host, port in self.hosts():
            if self.ctx.cancelled():
                failed.append((host, 'the job was stopped'))
                break
            try:
                with self.ctx.ssh(ssh_conn(self, host, port)) as s:
                    fn(s, host)
            except Exception as e:                      # noqa: BLE001
                failed.append((host, str(e) or type(e).__name__))
        return failed

    # -- the contract ---------------------------------------------------------------
    def present(self, name, token, key_authorization, txt_value):
        n = self.check_name(name)
        self.check_token(token)
        path = posixpath.join(self.webroot(), token)
        data = key_authorization.encode('ascii')
        done = []

        def put(s, host):
            self._write(s, path, data)
            done.append(host)
        failed = self._each(put, 'write')
        if failed:
            # all or nothing: the CA may ask any of them
            self._each(lambda s, h: self._remove(s, path) if h in done else None, 'remove')
            raise PluginError('the token could not be written on %s' % '; '.join(
                '%s: %s' % f for f in failed))
        self.ctx.step('%s written on %s' % (path, ', '.join(done)))
        return {'token': token, 'ka': key_authorization, 'name': n, 'path': path,
                'hosts': done}

    def ready(self, name, handle):
        handle = handle or {}
        how = self.c('check', 'each')
        if how == 'none':
            return True
        port = int(float(self.c('check_port', 80) or 80))
        sport = '' if port == 80 else ':%d' % port
        token, ka, n = handle.get('token'), handle.get('ka'), handle.get('name') or name
        if how == 'name':
            ok, words = self.fetch('http://%s%s/.well-known/acme-challenge/%s' % (n, sport, token),
                                   ka)
            self.ctx.step(words, 'ok' if ok else 'info')
            return ok
        bad = []
        for host, _p in self.hosts():
            h = '[%s]' % host if ':' in host else host
            ok, words = self.fetch('http://%s%s/.well-known/acme-challenge/%s' % (h, sport, token),
                                   ka, host=n)
            if not ok:
                bad.append(words)
        if bad:
            self.ctx.step('not answered yet: %s' % '; '.join(bad))
            return False
        self.ctx.step('every web server answers the token for %s' % n, 'ok')
        return True

    def cleanup(self, name, handle):
        handle = handle or {}
        path = handle.get('path')
        if not path or posixpath.dirname(path) != self.webroot():
            return
        failed = self._each(lambda s, h: self._remove(s, path), 'remove')
        for host, err in failed:
            self.ctx.step('%s could not be taken away on %s: %s' % (path, host, err), 'warn')

    def test(self):
        root = self.webroot()
        token = 'acme-probe-' + binascii.hexlify(os.urandom(8)).decode()
        data = ('acme probe ' + binascii.hexlify(os.urandom(8)).decode()).encode()
        path = posixpath.join(root, token)
        good = []

        def probe(s, host):
            self._write(s, path, data)
            try:
                try:
                    back = s.get(path)
                except Exception:                       # noqa: BLE001
                    back = s.run('cat %s' % shq(path), check=True)[1]
                if isinstance(back, str):
                    back = back.encode()
                if back.strip() != data:
                    raise PluginError('wrote a probe file but read back something else')
                if self.c('check', 'each') == 'each':
                    port = int(float(self.c('check_port', 80) or 80))
                    h = '[%s]' % host if ':' in host else host
                    ok, words = self.fetch('http://%s%s/.well-known/acme-challenge/%s' % (
                        h, '' if port == 80 else ':%d' % port, token), data.decode())
                    if not ok:
                        raise PluginError('the file is written but not served over HTTP: %s - '
                                          'is the webroot the one nginx serves (docs/'
                                          'validation.md)?' % words)
            finally:
                self._remove(s, path)
            good.append(host)
        failed = self._each(probe, 'probe')
        lines = ['%s: a probe file written to %s, read back and taken away' % (h, root)
                 for h in good]
        if failed:
            raise PluginError('; '.join('%s: %s' % f for f in failed),
                              detail='\n'.join(lines + ['%s: %s' % f for f in failed]))
        return '\n'.join(lines)
