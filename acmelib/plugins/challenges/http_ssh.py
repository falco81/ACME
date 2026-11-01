# -*- coding: utf-8 -*-
"""HTTP-01 answered by web servers elsewhere: acme signs in over SSH to every
one of them (they stand behind DNS round-robin or a load balancer) and writes
the token file into their webroot, so acme itself is never reachable from the
internet. docs/validation.md has the nginx server block for those machines."""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import posixpath
import re
import time

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges import _nginx as NG
from acmelib.plugins.challenges._common import (HttpChallenge, as_bool, as_list, pinned, shq, ssh_conn,
                                                ssh_fields)

WEBROOT = '/var/www/acme-challenge/.well-known/acme-challenge'
NGINX_CONF = '/etc/nginx/conf.d/acme-challenge.conf'
SNIPPET = '/etc/nginx/snippets/acme-challenge.conf'
INCLUDE = 'include %s;  ' + NG.MARK


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
                       ['at', 'at other addresses - a load balancer, a public IP, NAT (Host '
                              'and SNI: NAME)'],
                       ['name', 'http://NAME/ as the CA will (needs this machine to reach it)'],
                       ['none', 'no check']],
              help='The token is fetched over HTTP on port 80 and compared.'),
        field('check_at', 'Check at', 'list', default='',
              placeholder='203.0.113.10\n203.0.113.10:8080\nhttps://203.0.113.10',
              show_if={'check': ['at']},
              help='Where the check connects instead of the web servers\' own addresses: an IP '
                   'or a name, with :port, or https:// for TLS. The request still carries the '
                   'certificate\'s name - Host and SNI - so a load balancer or a virtual host '
                   'answers as it answers the CA; redirects are followed the same way.'),
        field('check_name', 'Name for Test', 'text', default='', placeholder='www.example.com',
              show_if={'check': ['at', 'each']},
              help='The name Test sends (Host, SNI) - Test has no certificate. Empty: the '
                   'address itself.'),
        field('check_port', 'HTTP port for the check', 'number', default=80, advanced=True),
        field('balancer', 'Load balancer in front', 'list', default='', advanced=True,
              placeholder='198.51.100.20',
              help='The addresses the names point at when a load balancer stands in front of '
                   'the web servers: the guide takes a name pointing there as right.'),
        field('prepare_names', 'Names acme\'s own block answers for', 'list', default='',
              placeholder='www.example.com\nexample.com',
              help='acme\'s own server block on port 80 listens for these names only - not the '
                   'default server. Empty: it is the default server (any name). A name another '
                   'block on port 80 answers already: the include goes into that block instead.'),
        field('prepare_how', 'How "Prepare" sets nginx up', 'select', default='auto',
              options=[['auto', 'by itself - its own block, or into the blocks already on port 80'],
                       ['manual', 'I put it in myself - "Prepare" only checks'],
                       ['own', 'always its own server block (default, or for the names below)']],
              help='nginx answering port 80 already (your sites, a redirect to HTTPS): one line, '
                   'include ' + SNIPPET + ', goes at the top of each of its port-80 server '
                   'blocks - nothing else in them changes, every file is kept as it was and put '
                   'back when nginx -t fails. "I put it in myself": "Download the nginx config" '
                   'gives the file and the line; "Prepare" then only checks every block has it.'),
        field('auto_prepare', 'Set nginx up by itself', 'bool', default=False,
              help='On: before Test and before every validation acme makes sure the nginx '
                   'server block for /.well-known/acme-challenge/ is on each web server (as '
                   '"Prepare the hosts") - written and nginx reloaded only when it is missing '
                   'or different; checked with nginx -t, put back when it fails. Needs root or '
                   'sudo there. Off: put in place once by the action, or by hand.'),
        field('prepare_firewall', 'Open port 80 in their firewall', 'bool', default=False,
              help='With "Prepare" (and "Set nginx up by itself"): port 80/tcp opened in '
                   'firewalld or ufw on each web server when it is closed there. Nothing else '
                   'is touched; another firewall is said, not changed.'),
        field('nginx_conf', 'nginx file "Prepare" writes', 'text', default=NGINX_CONF,
              advanced=True,
              help='The server block for /.well-known/acme-challenge/ that the action '
                   '"Prepare the hosts" puts on each machine.'),
        field('prepare_ipv6', 'That block listens on IPv6 too', 'bool', default=True,
              advanced=True),
        field('prepare_redirect', 'Everything else to HTTPS', 'bool', default=True,
              advanced=True,
              help='Off: the block answers 404 for anything but the challenge files.'),
    ]
    parallel = True
    actions = [{'key': 'nginx_files', 'label': 'Download the nginx config',
                'help': 'The snippet for ' + SNIPPET + ' and how to include it in your port-80 '
                        'server blocks - to put in place yourself; then "Prepare the hosts" '
                        'checks it.',
                'changes': False, 'file': True},
               {'key': 'prepare', 'label': 'Prepare the hosts',
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
        self.ensure_prepared()
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
        self.ensure_prepared()
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

    def check_targets(self):
        """[(scheme, address, port)] of "Check at"."""
        out = []
        dport = int(float(self.c('check_port', 80) or 80))
        for raw in as_list(self.c('check_at', '')):
            v = str(raw).strip()
            if not v:
                continue
            scheme = 'http'
            m = re.match(r'^(https?)://(.+?)/*$', v, re.I)
            if m:
                scheme, v = m.group(1).lower(), m.group(2)
            host, port = D.split_hostport(v, 443 if scheme == 'https' else dport)
            if not host or not all(c.isalnum() or c in '.-:_' for c in host):
                raise PluginError('"%s" is not an address to check at' % raw, retry=False)
            out.append((scheme, host, port))
        if not out:
            raise PluginError('"Check at" is empty - an address, or another kind of check',
                              retry=False)
        return out

    def fetch_at(self, name, token, want):
        """[(ok, words)] of the token fetched at every "Check at" address as NAME."""
        got = []
        for scheme, addr, port in self.check_targets():
            n = name or addr
            sport = '' if port == (443 if scheme == 'https' else 80) else ':%d' % port
            hn = '[%s]' % n if ':' in n else n
            url = '%s://%s%s/.well-known/acme-challenge/%s' % (scheme, hn, sport, token)
            with pinned({n: addr} if name else {}):
                ok, words = self.fetch(url, want)
            got.append((ok, '%s (at %s)' % (words, addr) if name else words))
        return got

    def ready(self, name, handle):
        handle = handle or {}
        how = self.c('check', 'each')
        if how == 'none':
            return True
        port = int(float(self.c('check_port', 80) or 80))
        sport = '' if port == 80 else ':%d' % port
        token, ka, n = handle.get('token'), handle.get('ka'), handle.get('name') or name
        if how == 'at':
            bad = [w for ok, w in self.fetch_at(n, token, ka) if not ok]
            if bad:
                self.ctx.step('not answered yet: %s' % '; '.join(bad))
                return False
            self.ctx.step('every "Check at" address answers the token for %s' % n, 'ok')
            return True
        if how == 'name':
            ok, words = self.fetch('http://%s%s/.well-known/acme-challenge/%s' % (n, sport, token),
                                   ka)
            self.ctx.step(words, 'ok' if ok else 'info')
            return ok
        bad = []
        for host, _p in self.hosts():
            # the name's URL (Host and a redirect's SNI the name's), connected to this machine
            hn = '[%s]' % n if ':' in n else n
            with pinned({n: host}):
                ok, words = self.fetch('http://%s%s/.well-known/acme-challenge/%s'
                                       % (hn, sport, token), ka)
            if not ok:
                bad.append('%s (at %s)' % (words, host))
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
        fw = self.firewall_lines() if as_bool(self.c('prepare_firewall', False)) else []
        return self._own_script(conf, root, block, owner, fw)

    def firewall_lines(self):
        return [
                'if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then',
                '    if firewall-cmd --query-service=http >/dev/null 2>&1 || '
                'firewall-cmd --query-port=80/tcp >/dev/null 2>&1; then :; else',
                '        firewall-cmd --permanent --add-service=http >/dev/null && '
                'firewall-cmd --reload >/dev/null && echo "ACME-FW: port 80 opened in firewalld" '
                '|| echo "ACME-FW: firewalld refused to open port 80"',
                '    fi',
                'elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then',
                '    ufw status 2>/dev/null | grep -Eq "^(80|80/tcp|Nginx HTTP|Nginx Full|WWW)[[:space:]]+ALLOW" || '
                '{ ufw allow 80/tcp >/dev/null && echo "ACME-FW: port 80 opened in ufw" '
                '|| echo "ACME-FW: ufw refused to open port 80"; }',
                'else',
                '    echo "ACME-FW: no firewalld or ufw running - port 80 left as it is"',
                'fi']

    @staticmethod
    def _own_script(conf, root, block, owner, fw):
        return '\n'.join([
            'set -u',
            'conf=%s' % shq(conf),
            'root=%s' % shq(root),
            'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"',
            'command -v nginx >/dev/null 2>&1 || { echo "ACME: no nginx here"; exit 3; }',
            '[ -d "$(dirname "$conf")" ] || { echo "ACME: no folder $(dirname "$conf")"; exit 4; }',
            'mkdir -p "$root" && chmod 755 "$root" || exit 7'] + fw + [
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
                  'sleep 1',
            'echo "ACME: written and reloaded"', ''])

    # -- nginx already answering port 80: the include ---------------------------------
    def _as_root(self, s, root, script, timeout=120):
        rc, out, err = s.run('sh -s' if root else 'sudo -n sh -s', input=script.encode(),
                             timeout=timeout, check=False)
        said = (out.decode('utf-8', 'replace') if isinstance(out, bytes) else str(out or '')) + \
            (err.decode('utf-8', 'replace') if isinstance(err, bytes) else str(err or ''))
        if rc and ('a password is required' in said or 'a terminal is required' in said):
            raise PluginError('sudo asks for a password: root, or a sudoers line for sh '
                              '(NOPASSWD)', detail=said[-4000:])
        return rc, said

    def nginx_dump(self, s, root):
        """{file: text} of the nginx running there (nginx -T), or raises."""
        rc, said = self._as_root(s, root, 'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"\n'
                                 'command -v nginx >/dev/null 2>&1 || { echo "ACME: no nginx '
                                 'here"; exit 3; }\nnginx -T 2>/dev/null\n')
        if rc == 3:
            raise PluginError('nginx is not installed there - for Apache or another server put '
                              'the alias in by hand (docs/validation.md)')
        files = NG.split_dump(said)
        if rc or not files:
            raise PluginError('nginx -T fails there - its configuration has an error of its own',
                              detail=said[-4000:])
        # The files to be changed read as they are (nginx -T adds lines between them).
        want = [p for p, t in files.items()
                if any(NG.on_port_80(b) for b in NG.server_blocks(t))]
        if want:
            rc, said = self._as_root(s, root, ''.join(
                'printf "ACME-FILE %%s " %s; base64 -w0 %s 2>/dev/null || base64 %s | tr -d '
                '"\\n"; echo\n' % (shq(p), shq(p), shq(p)) for p in want))
            for ln in said.splitlines():
                if ln.startswith('ACME-FILE '):
                    path, _sp, b64 = ln[10:].partition(' ')
                    try:
                        files[path] = base64.b64decode(b64).decode('utf-8')
                    except (ValueError, UnicodeDecodeError):
                        files[path] = files.get(path, '')
        return files

    def _docroot_needed(self):
        root = self._docroot_of(self.webroot())
        if not root:
            raise PluginError('the folder of the tokens does not end in /.well-known/'
                              'acme-challenge: the include needs one that does (the default)',
                              retry=False)
        return root

    def snippet(self):
        return NG.snippet_text(self._docroot_needed())

    def port80_plan(self, files):
        """{file: (new text, [blocks patched], [left])} for every file with a port-80
        server block but acme's own."""
        own = self.nginx_conf()
        line = INCLUDE % SNIPPET
        plan = {}
        for path, text in files.items():
            if path == own or path == SNIPPET:
                continue
            new, done, left = NG.patch(text, line)
            blocks = [b for b in NG.server_blocks(text) if NG.on_port_80(b)]
            if blocks:
                plan[path] = (new if done else None, done, left, len(blocks))
        return plan

    def include_one(self, s, host, root, files, check_only=False, owner=''):
        """The include put into every port-80 block (or, check_only, looked for)."""
        plan = self.port80_plan(files)
        snippet = self.snippet()
        have = files.get(SNIPPET)
        missing = [(p, d) for p, (new, d, _l, _n) in plan.items() if d]
        left = ['%s: %s' % (p, ' / '.join('%s %s' % x for x in l))
                for p, (_n, _d, l, _c) in plan.items() if l]
        if check_only:
            probs = []
            if have is None:
                probs.append('%s is not there (nginx does not include it anywhere)' % SNIPPET)
            elif have.strip() != snippet.strip():
                probs.append('%s differs from what "Download the nginx config" gives' % SNIPPET)
            for p, d in missing:
                probs.append('%s: no "include %s;" in the server block of %s'
                             % (p, SNIPPET, ', '.join(d)))
            if probs:
                raise PluginError('nginx is not set up yet: ' + '; '.join(probs) +
                                  ' - put it in as "Download the nginx config" says, reload '
                                  'nginx, then Prepare again')
            words = 'the include is in every port-80 server block (%d file(s)) - checked, ' \
                    'nothing changed' % len(plan)
            for x in left:
                self.ctx.step('%s: %s' % (host, x), 'warn')
            self.ctx.step('%s: %s' % (host, words), 'ok')
            return words
        if not missing and have is not None and have.strip() == snippet.strip() and \
                s.run('test -d %s' % shq(self.webroot()), check=False)[0] == 0:
            words = 'already in place in every port-80 server block (%d file(s))' % len(plan)
            self.ctx.step('%s: %s' % (host, words), 'ok')
            return words
        sums = {p: hashlib.sha256(files[p].encode('utf-8')).hexdigest() for p, _d in missing}
        lines = ['set -u', 'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"',
                 'snip=%s' % shq(SNIPPET), 'changed=""',
                 # the copies outside nginx's folders: a sites-enabled/* would load them
                 'bk=/var/backups/acme-nginx/$(date +%Y%m%d-%H%M%S)',
                 'restore() { for f in $changed; do [ -f "$bk$f" ] && cat "$bk$f" > "$f"; done; '
                 'if [ -n "${snipnew:-}" ]; then rm -f "$snip"; elif [ -f "$bk$snip" ]; then '
                 'cat "$bk$snip" > "$snip"; fi; }']
        # every file still as it was read (changed since: nothing is written)
        for p, _d in missing:
            lines.append('[ "$(sha256sum %s | cut -d" " -f1)" = %s ] || { echo "ACME: %s '
                         'changed while it was read - nothing written"; exit 8; }'
                         % (shq(p), sums[p], p.replace('"', '')))
        lines += ['mkdir -p %s && chmod 755 %s || exit 7' % (shq(self.webroot()),
                                                             shq(self.webroot())),
                  ('chown %s %s || exit 7' % (shq(owner), shq(self.webroot()))) if owner else ':',
                  'mkdir -p "$(dirname "$snip")" || exit 7',
                  'snipnew=""; [ -f "$snip" ] || snipnew=1',
                  'mkdir -p "$bk" && chmod 700 /var/backups/acme-nginx || exit 7',
                  '[ -f "$snip" ] && cp -p --parents "$snip" "$bk"',
                  'printf %%s %s | base64 -d > "$snip" || { restore; exit 7; }'
                  % shq(base64.b64encode(snippet.encode()).decode())]
        for p, _d in missing:
            new = plan[p][0]
            lines += ['cp -p --parents %s "$bk" || { restore; exit 7; }' % shq(p),
                      'changed="$changed %s"' % p,
                      # cat > keeps the file's owner and mode
                      'printf %%s %s | base64 -d > %s || { restore; exit 7; }'
                      % (shq(base64.b64encode(new.encode('utf-8')).decode()), shq(p))]
        lines += ['if ! nginx -t 2>&1; then restore; echo "ACME: nginx -t fails - put back as '
                  'it was"; exit 5; fi',
                  'echo "ACME-BK: $bk"',
                  '{ systemctl reload nginx 2>/dev/null || nginx -s reload; } || '
                  '{ echo "ACME: nginx did not reload"; exit 6; }',
                  'sleep 1',
                  'echo "ACME: written and reloaded"', '']
        rc, said = self._as_root(s, root, '\n'.join(lines))
        last = [ln for ln in said.splitlines() if ln.startswith('ACME: ')]
        words = last[-1][6:] if last else said.strip()[-300:]
        if rc:
            raise PluginError(words or 'exit %d' % rc, detail=said[-4000:])
        bk = ([ln[8:].strip() for ln in said.splitlines() if ln.startswith('ACME-BK: ')]
              or ['/var/backups/acme-nginx'])[-1]
        for p, d in missing:
            self.ctx.step('%s: %s - "include %s;" put at the top of the server block of %s '
                          '(the file as it was: %s%s)' % (host, p, SNIPPET, ', '.join(d), bk, p),
                          'ok')
        for x in left:
            self.ctx.step('%s: %s' % (host, x), 'warn')
        words = 'written and reloaded - the include in %d server block(s) of %d file(s), ' \
                'nothing else changed' % (sum(len(d) for _p, d in missing), len(missing))
        self.ctx.step('%s: %s' % (host, words), 'ok')
        return words

    def nginx_files(self):
        """What "Download the nginx config" gives: one text file, the snippet and how."""
        snippet = self.snippet()
        how = ['# acme - the nginx config for HTTP-01 on your web servers',
               '#',
               '# 1. Save the part between the lines below as %s' % SNIPPET,
               '# 2. Put this line at the top of EVERY server block that listens on port 80',
               '#    (sites-enabled/*, conf.d/*.conf - before any return, rewrite or if):',
               '#',
               '#        include %s;' % SNIPPET,
               '#',
               '# 3. nginx -t && systemctl reload nginx',
               '# 4. In acme: "Prepare the hosts" (with "I put it in myself" it only checks).',
               '#',
               '# Nothing else in your blocks needs to change: the rewrite ... break in it',
               '# lets these paths past a return 301 / if ($host ...) of the block.',
               '# ---------------------------------------------------------------------------']
        return '\n'.join(how) + '\n' + snippet + \
            '# ---------------------------------------------------------------------------\n'

    def prepare_one(self, s, host):
        """One machine made ready: (words). Raises PluginError."""
        how = str(self.c('prepare_how', 'auto') or 'auto')
        if how in ('auto', 'manual'):
            rc0, out0, _e0 = s.run('id -u', check=False)
            root0 = (out0.decode() if isinstance(out0, bytes) else str(out0 or '')).strip() == '0'
            files = self.nginx_dump(s, root0)
            plan = self.port80_plan(files)
            names = [n.lower() for n in as_list(self.c('prepare_names', '')) if n]
            if how == 'auto' and plan and names:
                taken = NG.port80_names(files, skip=(self.nginx_conf(), SNIPPET))
                clash = [n for n in names if n in taken]
                if not clash:
                    # Its own block for these names only: the other blocks never see them.
                    self.ctx.step('%s: nginx answers port 80 already, but not for %s - acme\'s '
                                  'own server block for those names only (not the default '
                                  'server)' % (host, ', '.join(names)))
                    return self.prepare_own(s, host)
                self.ctx.step('%s: %s answered by another block already (%s) - the include '
                              'goes into the blocks instead' % (
                                  host, ', '.join(clash), ', '.join(sorted(
                                      set(taken[n] for n in clash)))), 'warn')
            if how == 'manual' or plan:
                if how == 'auto':
                    self.ctx.step('%s: nginx answers port 80 already (%s) - the include goes '
                                  'into those blocks, nothing else is changed'
                                  % (host, ', '.join(sorted(plan))))
                    self._fw_only(s, root0, host)
                user = str(self.c('user', '') or '')
                owner = user if (not root0 and not self._sudo() and user and
                                 all(c.isalnum() or c in '._-' for c in user)) else ''
                return self.include_one(s, host, root0, files, check_only=(how == 'manual'),
                                        owner=owner)
        return self.prepare_own(s, host)

    def _fw_only(self, s, root, host):
        if not as_bool(self.c('prepare_firewall', False)):
            return
        rc, said = self._as_root(s, root, '\n'.join(self.firewall_lines()) + '\n')
        for ln in said.splitlines():
            if ln.startswith('ACME-FW: '):
                self.ctx.step('%s: %s' % (host, ln[9:]),
                              'warn' if 'refused' in ln or 'no firewalld' in ln else 'ok')

    def prepare_own(self, s, host):
        """acme's own server block (nothing else on port 80): (words)."""
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
        for ln in said.splitlines():
            if ln.startswith('ACME-FW: '):
                self.ctx.step('%s: %s' % (host, ln[9:]),
                              'warn' if 'refused' in ln or 'no firewalld' in ln else 'ok')
                words += '; ' + ln[9:]
        self.ctx.step('%s: %s (%s)' % (host, words, self.nginx_conf()), 'ok')
        return words

    def ensure_prepared(self):
        """With "Set nginx up by itself": the block on every machine (once a job)."""
        if not as_bool(self.c('auto_prepare', False)) or getattr(self, '_prepared', False):
            return
        self.webroot()
        self.nginx_conf()
        self.nginx_block()
        failed = self._each(lambda s, host: self.prepare_one(s, host), 'prepare')
        if failed:
            raise PluginError('nginx could not be set up on %s' % '; '.join(
                '%s: %s' % f for f in failed))
        self._prepared = True

    def action(self, key):
        if key == 'nginx_files':
            return {'said': 'the nginx config to put in place yourself',
                    'file': {'name': 'acme-challenge.conf', 'text': self.nginx_files()}}
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
        self.ensure_prepared()
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
                if self.c('check', 'each') == 'at':
                    keep.append(host)
                    return
                if self.c('check', 'each') == 'each':
                    port = int(float(self.c('check_port', 80) or 80))
                    name = str(self.c('check_name', '') or '').strip()
                    h = name or host
                    h = '[%s]' % h if ':' in h else h
                    url = 'http://%s%s/.well-known/acme-challenge/%s' % (
                        h, '' if port == 80 else ':%d' % port, token)
                    # nginx reloads its workers a moment after it is told to
                    for wait in (0, 1, 2):
                        if wait:
                            time.sleep(wait)
                        with pinned({name: host} if name else {}):
                            ok, words = self.fetch(url, data.decode())
                        if ok:
                            break
                    if name:
                        words = '%s (at %s)' % (words, host)
                    if not ok:
                        low = str(words).lower()
                        if 'no route to host' in low or 'refused' in low or 'timed out' in low:
                            raise PluginError(
                                'the file is written but port %d of %s does not answer (%s) - '
                                'SSH reaches it, so most likely its firewall closes port %d '
                                '(firewalld answers "No route to host"): switch on "Open port 80 '
                                'in their firewall" and "Set nginx up by itself", or open it '
                                'by hand' % (port, host, words, port))
                        raise PluginError('the file is written but not served over HTTP: %s - '
                                          'is the webroot the one nginx serves (docs/'
                                          'validation.md)? "Set nginx up by itself" puts the '
                                          'server block there' % words)
            finally:
                if host not in keep:
                    self._remove(s, path)
            good.append(host)
        keep, at_words = [], []
        failed = self._each(probe, 'probe')
        if self.c('check', 'each') == 'at':
            try:
                if not failed:
                    name = str(self.c('check_name', '') or '').strip()
                    for wait in (0, 1, 2):
                        if wait:
                            time.sleep(wait)
                        got = self.fetch_at(name, token, data.decode())
                        if all(ok for ok, _w in got):
                            break
                    for ok, words in got:
                        self.ctx.step(words, 'ok' if ok else 'warn')
                    bad = [w for ok, w in got if not ok]
                    if bad:
                        failed.append(('check at', '; '.join(bad)))
                    else:
                        good.extend(keep)
                        at_words.extend(w for _ok, w in got)
            finally:
                self._each(lambda s, h: self._remove(s, path) if h in keep else None, 'remove')
        lines = ['%s: a probe file written to %s, read back and taken away' % (h, root)
                 for h in good] + at_words
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
