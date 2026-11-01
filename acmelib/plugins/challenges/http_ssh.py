# -*- coding: utf-8 -*-
"""HTTP-01 answered by web servers elsewhere: acme signs in over SSH to every
one of them (they stand behind DNS round-robin or a load balancer) and writes
the token file into their webroot, so acme itself is never reachable from the
internet. docs/validation.md has the nginx server block for those machines."""
from __future__ import annotations

import binascii
import os
import posixpath

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (HttpChallenge, as_bool, as_list, shq, ssh_conn,
                                                ssh_fields)

WEBROOT = '/var/www/acme-challenge/.well-known/acme-challenge'
NGINX_CONF = '/etc/nginx/conf.d/acme-challenge.conf'


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
        field('balancer', 'Load balancer in front', 'list', default='', advanced=True,
              placeholder='198.51.100.20',
              help='The addresses the names point at when a load balancer stands in front of '
                   'the web servers: the guide takes a name pointing there as right.'),
        field('nginx_conf', 'nginx file "Prepare" writes', 'text', default=NGINX_CONF,
              advanced=True,
              help='The server block for /.well-known/acme-challenge/ that the action '
                   '"Prepare the hosts" puts on each machine.'),
        field('prepare_names', 'Names that block answers for', 'list', default='',
              advanced=True, placeholder='www.example.com\nexample.com',
              help='Empty: it is the default server of port 80 (it answers for any name). '
                   'Where another block is the default server already, name the names here.'),
        field('prepare_ipv6', 'That block listens on IPv6 too', 'bool', default=True,
              advanced=True),
        field('prepare_redirect', 'Everything else to HTTPS', 'bool', default=True,
              advanced=True,
              help='Off: the block answers 404 for anything but the challenge files.'),
    ]
    parallel = True
    actions = [{'key': 'prepare', 'label': 'Prepare the hosts',
                'help': 'On every web server: find nginx, write the server block for '
                        '/.well-known/acme-challenge/ (nginx_conf) and make the webroot, check '
                        'it with nginx -t, reload nginx - then the probe of Test. Needs root or '
                        'sudo there.',
                'confirm': 'Write the nginx server block for the challenge files on every web '
                           'server and reload nginx there?',
                'changes': True}]

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

    # -- a commercial CA's DCV file: beside the tokens, under the same web root ----------
    @classmethod
    def _docroot_of(cls, webroot):
        w = posixpath.normpath(str(webroot or WEBROOT))
        if w.endswith('/.well-known/acme-challenge'):
            return posixpath.dirname(posixpath.dirname(w))
        return None

    @classmethod
    def proofs_for(cls, config):
        out = ['acme-http-01']
        if cls._docroot_of((config or {}).get('webroot') or WEBROOT):
            out.append('http-file-any')
        return out

    @classmethod
    def place_problem(cls, proof, where, config, settings):
        if proof == 'http-file-any' and not cls._docroot_of((config or {}).get('webroot') or
                                                             WEBROOT):
            return ('its folder does not end in /.well-known/acme-challenge, so acme cannot tell '
                    'where /.well-known/pki-validation/ is on the web servers')
        return HttpChallenge.place_problem.__func__(cls, proof, where, config, settings)

    def place_file(self, name, path, data):
        root = self._docroot_of(self.webroot())
        if not root:
            raise PluginError('the folder does not end in /.well-known/acme-challenge: acme cannot '
                              'tell where %s goes' % path, retry=False)
        full = posixpath.join(root, path.lstrip('/'))
        done = []

        def put(s, host):
            self._write(s, full, data)
            done.append(host)
        failed = self._each(put, 'write')
        if failed:
            self._each(lambda s, h: self._remove(s, full) if h in done else None, 'remove')
            raise PluginError('the DCV file could not be written on %s' % '; '.join(
                '%s: %s' % f for f in failed))
        return {'file': full, 'hosts': done}

    def unplace_file(self, handle):
        full = ((handle or {}).get('h') or {}).get('file')
        root = self._docroot_of(self.webroot())
        if not full or not root or not full.startswith(root + '/.well-known/'):
            return
        for host, err in self._each(lambda s, h: self._remove(s, full), 'remove'):
            self.ctx.step('%s could not be taken away on %s: %s' % (full, host, err), 'warn')

    def dcv_self_check(self):
        return self.c('check', 'each') != 'none'

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

    # -- the action "prepare": nginx made ready on every machine ------------------------
    def nginx_block(self):
        """The server block written by prepare: the challenge files from the webroot,
        everything else to HTTPS (or 404)."""
        names = [n for n in as_list(self.c('prepare_names', '')) if n]
        for n in names:
            if not all(c.isalnum() or c in '.-*_' for c in n):
                raise PluginError('"%s" is not a name for nginx' % n, retry=False)
        dflt = '' if names else ' default_server'
        lines = ['# acme: the answers to HTTP-01 (written by acme, "Prepare the hosts" -',
                 '# docs/validation.md). Written again by the same action; changed by hand,',
                 '# it is replaced then.',
                 'server {',
                 '    listen 80%s;' % dflt]
        if as_bool(self.c('prepare_ipv6', True)):
            lines.append('    listen [::]:80%s;' % dflt)
        lines += ['    server_name %s;' % (' '.join(names) if names else '_'),
                  '',
                  '    location ^~ /.well-known/acme-challenge/ {',
                  '        alias %s/;' % self.webroot(),
                  '        default_type text/plain;',
                  '        autoindex off;',
                  '    }',
                  '']
        root = self._docroot_of(self.webroot())
        if root:
            # a commercial CA's DCV file (DigiCert, Sectigo), written beside the tokens
            lines += ['    location ^~ /.well-known/pki-validation/ {',
                      '        alias %s/.well-known/pki-validation/;' % root,
                      '        default_type text/plain;',
                      '        autoindex off;',
                      '    }',
                      '']
        lines += ['    location / {',
                  '        return %s;' % ('301 https://$host$request_uri'
                                          if as_bool(self.c('prepare_redirect', True)) else '404'),
                  '    }',
                  '}', '']
        return '\n'.join(lines)

    def nginx_conf(self):
        p = posixpath.normpath(str(self.c('nginx_conf', NGINX_CONF) or NGINX_CONF))
        if not p.startswith('/etc/') or not p.endswith('.conf') or \
                any(c in p for c in '\'"`$;&|\n\\ '):
            raise PluginError('the nginx file %r will not be written (a .conf under /etc)' % p,
                              retry=False)
        return p

    def prepare_script(self, owner=''):
        """What runs on one machine (as root, or through sudo -n), as sh -s."""
        conf, root = self.nginx_conf(), self.webroot()
        block = self.nginx_block()
        if 'ACME_EOF' in block:
            raise PluginError('that block cannot be written', retry=False)
        return '\n'.join([
            'set -u',
            'conf=%s' % shq(conf),
            'root=%s' % shq(root),
            'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"',
            'command -v nginx >/dev/null 2>&1 || { echo "ACME: no nginx here"; exit 3; }',
            '[ -d "$(dirname "$conf")" ] || { echo "ACME: no folder $(dirname "$conf")"; exit 4; }',
            'mkdir -p "$root" && chmod 755 "$root" || exit 7',
            ('chown %s "$root" || exit 7' % shq(owner)) if owner else ':',
            'new=$(mktemp) || exit 7',
            "cat > \"$new\" <<'ACME_EOF'",
            block.rstrip('\n'),
            'ACME_EOF',
            'if [ -f "$conf" ] && cmp -s "$new" "$conf"; then',
            '    rm -f "$new"',
            '    nginx -t >/dev/null 2>&1 || { nginx -t 2>&1; echo "ACME: nginx -t fails"; exit 5; }',
            '    echo "ACME: already in place"; exit 0',
            'fi',
            '[ -f "$conf" ] && cp -p "$conf" "$conf.acme-old"',
            'install -m 644 "$new" "$conf"; rc=$?; rm -f "$new"; [ $rc -eq 0 ] || exit 7',
            'if ! nginx -t 2>&1; then',
            '    if [ -f "$conf.acme-old" ]; then mv -f "$conf.acme-old" "$conf"; else rm -f "$conf"; fi',
            '    echo "ACME: nginx -t fails - put back as it was"; exit 5',
            'fi',
            'rm -f "$conf.acme-old"',
            '{ systemctl reload nginx 2>/dev/null || nginx -s reload; } || '
            '{ echo "ACME: nginx did not reload"; exit 6; }',
            'echo "ACME: written and reloaded"', ''])

    def prepare_one(self, s, host):
        """One machine made ready: (words). Raises PluginError."""
        rc, out, _err = s.run('id -u', check=False)
        root = (out.decode() if isinstance(out, bytes) else str(out or '')).strip() == '0'
        user = str(self.c('user', '') or '')
        # Written as the SSH account later (no sudo for the token files): the
        # folder made its own.
        owner = user if (not root and not self._sudo() and user and
                         all(c.isalnum() or c in '._-' for c in user)) else ''
        script = self.prepare_script(owner)
        rc, out, err = s.run('sh -s' if root else 'sudo -n sh -s', input=script.encode(),
                             timeout=120, check=False)
        said = (out.decode('utf-8', 'replace') if isinstance(out, bytes) else str(out or '')) + \
            (err.decode('utf-8', 'replace') if isinstance(err, bytes) else str(err or ''))
        last = [ln for ln in said.splitlines() if ln.startswith('ACME: ')]
        words = last[-1][6:] if last else said.strip()[-300:]
        if rc:
            if 'duplicate default server' in said:
                words += ' (another server block is the default server of port 80: name the ' \
                         'names in "Names that block answers for", or put the location into ' \
                         'that block by hand - docs/validation.md)'
            elif 'a password is required' in said or 'a terminal is required' in said:
                words = 'sudo asks for a password: root, or a sudoers line for sh (NOPASSWD)'
            elif rc == 3:
                words = 'nginx is not installed there - for Apache or another server put the ' \
                        'alias in by hand (docs/validation.md)'
            raise PluginError(words or 'exit %d' % rc, detail=said[-4000:])
        self.ctx.step('%s: %s (%s)' % (host, words, self.nginx_conf()), 'ok')
        return words

    def action(self, key):
        if key != 'prepare':
            return HttpChallenge.action(self, key)
        self.webroot()
        self.nginx_conf()
        self.nginx_block()
        done = []

        def one(s, host):
            done.append('%s: %s' % (host, self.prepare_one(s, host)))
        failed = self._each(one, 'prepare')
        if failed:
            raise PluginError('; '.join('%s: %s' % f for f in failed),
                              detail='\n'.join(done + ['%s: %s' % f for f in failed]))
        if str(self.c('check', 'each')) != 'none':
            self.ctx.step('the probe of Test, on every machine')
            done.append(self.test())
        return '\n'.join(done)

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

    # -- what a person is told ---------------------------------------------------------
    def answering(self, name):
        out = []
        try:
            hosts = self.hosts()
        except PluginError:
            return out
        for host, _p in hosts:
            for a in (self.lookup(host) or [host]):
                if a not in out:
                    out.append(a)
        return out

    def guide(self, name):
        bad = self.guide_wildcard(name)
        if bad:
            return guide_of(bad)
        n = D.norm(name)
        try:
            hosts = self.hosts()
        except PluginError as e:
            return guide_of([guide_step('hosts', 'The web servers are set', where='acme',
                                        done=False, said=str(e),
                                        fix='Set the web servers of the validation')])
        old_port = self.http_port
        self.http_port = int(float(self.c('check_port', 80) or 80))
        try:
            return guide_of(self._guide(n, hosts))
        finally:
            self.http_port = old_port

    def _guide(self, n, hosts):
        addrs = self.answering(n)
        front = as_list(self.c('balancer', ''))
        steps = [self.guide_points(
            n, front + addrs, (front or addrs or [''])[0],
            'Point %s at the web servers (%s); if a load balancer stands in front of them, put '
            'its address under "Load balancer in front"' % (n, ', '.join(addrs)),
            soft=not front)]
        for host, port in hosts:
            where = 'the web server %s' % host
            try:
                with self.ctx.ssh(ssh_conn(self, host, port)) as s:
                    s.run('true', timeout=30, check=True)
                steps.append(guide_step('ssh', 'acme signs in to %s over SSH' % host,
                                        where=where, done=True, said='signed in'))
            except Exception as e:                      # noqa: BLE001
                steps.append(guide_step('ssh', 'acme signs in to %s over SSH' % host,
                                        where=where, done=False, said=str(e) or type(e).__name__,
                                        fix='Put acme\'s public key into ~%s/.ssh/authorized_keys '
                                            'there, and pin the host key (docs/validation.md)'
                                            % (self.c('user', 'acme') or 'acme')))
            url = self.url(host, 'acme-guide-' + binascii.hexlify(os.urandom(6)).decode())
            try:
                st, _h, _b = self.ctx.http('GET', url, headers={'Host': n,
                                                                 'User-Agent': 'acme-guide'},
                                           timeout=10, verify=False, proxy=False)
                steps.append(guide_step(
                    'web', '%s answers HTTP on port %d' % (host, self.http_port), where=where,
                    done=True, said='it answers (%s for a file that is not there)' % st))
            except Exception as e:                      # noqa: BLE001
                steps.append(guide_step(
                    'web', '%s answers HTTP on port %d' % (host, self.http_port), where=where,
                    done=False, said=str(e) or type(e).__name__,
                    fix='Open port %d on %s and serve /.well-known/acme-challenge/ from %s (the '
                        'action "Prepare the hosts" writes the nginx block)'
                        % (self.http_port, host, self.webroot())))
        return steps

    def seen_outside(self, name, handle):
        old_port = self.http_port
        self.http_port = int(float(self.c('check_port', 80) or 80))
        try:
            return HttpChallenge.seen_outside(self, name, handle)
        finally:
            self.http_port = old_port
