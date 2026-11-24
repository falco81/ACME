#!/usr/bin/env python3
"""Hunt w9, install: install.sh, the nginx file it writes and brings up to date, the docs of it.

    python3 test/test_hunt_rw9_install.py

- install.sh --uninstall stopped half way: php_fpm_units (taking php-fpm's units in hand
  once acme's pool is gone) called php_fpm_bin, defined only further down the script -
  "php_fpm_bin: command not found", two ERROR lines, and php-fpm went on running acme's pool.
- An nginx file kept from before 1.0.13x (every upgrade keeps it) never got
  /.well-known/pki-validation/ on port 80: a commercial CA's file validation (DigiCert
  http-token, Sectigo FILE, ...) answered by acme itself went to HTTPS and was refused.
- Port 80 - the server everybody reaches - handed a multipart body on to PHP: only 443 refused
  one, though install.sh and php2shell.md said nginx refuses every multipart body.
- /calendar.ics: a request PHP did not answer (php-fpm restarting, a timeout) was written to
  nginx's error log with its request line - the secret of a person's calendar link in it.
- The upload guard printed its count ("1") into the installer's output.
- php2shell.md promised Remi's PHP 8.4 (php:remi-8.4); install.sh takes php:remi-8.3.

nginx -t / a real nginx are used where nginx is installed (skipped otherwise); nothing is
written outside a temporary folder.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-w9-install-')
NGINX = shutil.which('nginx') or ('/usr/sbin/nginx' if os.path.exists('/usr/sbin/nginx') else '')


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


INSTALL = read('install.sh')
SHIPPED = read('deploy/nginx-acme.conf')


def updater_script():
    """install.sh's update of an nginx file that is there (the first python3 - "$NGINX_CONF")."""
    m = re.search(r'python3 - "\$NGINX_CONF" <<\'PY\'\n(.*?)\nPY\n', INSTALL, re.S)
    path = os.path.join(TMP, 'nginx_update.py')
    with open(path, 'w') as f:
        f.write(m.group(1))
    return path


def guard_script():
    m = re.search(r'nginx_upload_guard\(\) \{.*?python3 - "\$NGINX_CONF" <<\'PY\'[^\n]*\n(.*?)\nPY\n',
                  INSTALL, re.S)
    path = os.path.join(TMP, 'nginx_guard.py')
    with open(path, 'w') as f:
        f.write(m.group(1))
    return path


def update(text, script):
    p = os.path.join(TMP, 'acme.conf')
    with open(p, 'w') as f:
        f.write(text)
    r = subprocess.run([sys.executable, '-I', script, p], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=60)
    with open(p) as f:
        return f.read(), r.stdout.decode()


def nginx_site(conf, sock=None, prefix=None):
    """A prefix of its own for nginx with acme's file in it: high ports, a throwaway certificate."""
    prefix = prefix or tempfile.mkdtemp(dir=TMP)
    logs = os.path.join(prefix, 'logs')
    os.makedirs(logs, exist_ok=True)
    key, pem = os.path.join(prefix, 'acme.key'), os.path.join(prefix, 'acme.pem')
    if not os.path.exists(pem):
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
                        '-keyout', key, '-out', pem, '-subj', '/CN=x'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    text = conf.replace('/etc/nginx/certs/acme.pem', pem).replace('/etc/nginx/certs/acme.key', key)
    text = text.replace('/var/log/nginx/', logs + '/')
    text = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', text)
    text = re.sub(r'(?m)^(\s*)listen\s+80;', r'\1listen 127.0.0.1:%d;' % PORT80, text)
    text = re.sub(r'(?m)^(\s*)listen\s+443 ssl http2;', r'\1listen 127.0.0.1:%d ssl;' % PORT443, text)
    if sock:
        text = re.sub(r'fastcgi_pass\s+unix:[^;]+;', 'fastcgi_pass unix:%s;' % sock, text)
    for name in ('fastcgi_params', 'mime.types'):
        src = os.path.join('/etc/nginx', name)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(prefix, name))
        else:
            open(os.path.join(prefix, name), 'w').close()
    with open(os.path.join(prefix, 'site.conf'), 'w') as f:
        f.write(text)
    user = 'user root;\n' if os.geteuid() == 0 else ''
    with open(os.path.join(prefix, 'nginx.conf'), 'w') as f:
        f.write('%sworker_processes 1;\nerror_log %s/error.log;\npid %s/nginx.pid;\nevents {}\n'
                'http {\n include %s/mime.types;\n access_log %s/access.log;\n'
                ' client_body_temp_path %s; fastcgi_temp_path %s; proxy_temp_path %s;'
                ' uwsgi_temp_path %s; scgi_temp_path %s;\n include %s/site.conf;\n}\n'
                % (user, logs, logs, prefix, logs, logs, logs, logs, logs, logs, prefix))
    return prefix


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


PORT80, PORT443 = free_port(), free_port()


def nginx_t(prefix):
    r = subprocess.run([NGINX, '-p', prefix, '-c', os.path.join(prefix, 'nginx.conf'), '-t'],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    return r.returncode, r.stdout.decode('utf-8', 'replace')


def older_file():
    """The shipped file as one of before: no DCV location, no multipart line on port 80,
    the calendar's place logging."""
    old = re.sub(r'(?ms)^[ \t]*# A commercial CA\'s file-based.*?location \^~ /\.well-known/pki-validation/ \{.*?^[ \t]*\}\n',
                 '', SHIPPED)
    old = re.sub(r'(?ms)^[ \t]*# php2shell \(CVE-2026-109618, CVE-2026-109619\), as on 443:.*?'
                 r'^[ \t]*if \(\$http_content_type ~\* "multipart"\) \{ return 403; \}\n', '', old, count=1)
    old = re.sub(r'(?ms)^[ \t]*# \.\.\.and so is every request PHP did not answer.*?^[ \t]*error_log /dev/null;\n',
                 '', old)
    return old


def port80(text):
    m = re.search(r'(?ms)^server \{\n\s*listen\s+80;.*?^\}\n', text)
    return m.group(0)


class Uninstall(unittest.TestCase):
    def test_no_function_is_called_before_it_is_defined(self):
        """Every function the script's top-level lines reach - through other functions too -
        is defined above them (bash runs it line by line)."""
        lines = INSTALL.split('\n')
        defs, body, cur = {}, {}, None
        for i, line in enumerate(lines):
            m = re.match(r'^\s*([a-z_0-9]+)\(\) *\{', line)
            if m and m.group(1) not in defs:
                defs[m.group(1)] = i
                if line.rstrip().endswith('}') and line.count('{') == line.count('}'):
                    body[m.group(1)] = [i]
                    continue
                cur = m.group(1)
                body[cur] = []
                continue
            if cur:
                if re.match(r'^\s*\}\s*$', line) and (not line.startswith(' ') or cur == 'upgrade_rescue'):
                    cur = None
                    continue
                body[cur].append(i)
        inside = {x for v in body.values() for x in v} | set(defs.values())

        def calls(i):
            code = lines[i].split(' #')[0]
            if code.lstrip().startswith('#'):
                return []
            return [n for n in defs if re.search(r'(^|[\s;&|(`$!{])%s(\s|$|;|\)|")' % re.escape(n), code)]

        def reach(n, seen):
            for i in body.get(n, []):
                for c in calls(i):
                    if c not in seen:
                        seen.add(c)
                        reach(c, seen)
            return seen
        late = set()
        for i in range(len(lines)):
            if i in inside:
                continue
            for n in calls(i):
                for c in reach(n, {n}):
                    # upgrade_rescue: asked with declare -F first, defined in the block it serves
                    if defs[c] > i and c != 'upgrade_rescue':
                        late.add('line %d -> %s needs %s (line %d)' % (i + 1, n, c, defs[c] + 1))
        self.assertEqual(sorted(late), [])

    def test_php_fpm_units_runs_where_uninstall_asks_it(self):
        """The functions defined above --uninstall, then php_fpm_units as it calls it."""
        cut = INSTALL.index('if [[ -n "$DO_UNINSTALL" ]]; then')
        head = INSTALL[:cut]
        funcs = ''.join(m.group(0) for m in re.finditer(
            r'(?ms)^[a-z_0-9]+\(\) *\{(?:[ \t]*#[^\n]*)?\n.*?^\}\n', head))
        bin_dir = os.path.join(TMP, 'bin')
        os.makedirs(bin_dir, exist_ok=True)
        with open(os.path.join(bin_dir, 'systemctl'), 'w') as f:
            f.write('#!/bin/sh\n[ "$1" = cat ] && [ "$2" = php9.9-fpm.service ] && exit 0\n'
                    '[ "$1" = list-unit-files ] && echo "php9.9-fpm.service disabled enabled" && exit 0\n'
                    'exit 1\n')
        with open(os.path.join(bin_dir, 'php-fpm'), 'w') as f:
            f.write('#!/bin/sh\nexit 0\n')
        for n in ('systemctl', 'php-fpm'):
            os.chmod(os.path.join(bin_dir, n), 0o755)
        script = 'set -Eeuo pipefail\n%s\nfor u in $(php_fpm_units); do echo "unit:$u"; done\necho end\n' % funcs
        r = subprocess.run(['bash', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=dict(os.environ, PATH=bin_dir + ':/usr/bin:/bin'), timeout=60)
        out, err = r.stdout.decode(), r.stderr.decode()
        self.assertNotIn('command not found', err)
        self.assertIn('unit:php9.9-fpm', out)
        self.assertTrue(out.rstrip().endswith('end'), out + err)


class NginxUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = updater_script()

    def test_shipped_file_left_as_it_is(self):
        got, said = update(SHIPPED, self.script)
        self.assertEqual(got, SHIPPED)
        self.assertEqual(said.strip(), '')

    def test_shipped_file_has_them(self):
        p80 = port80(SHIPPED)
        self.assertIn('location ^~ /.well-known/pki-validation/', p80)
        self.assertIn('if ($http_content_type ~* "multipart") { return 403; }', p80)
        cal = re.search(r'(?ms)^\s*location = /calendar\.ics \{.*?^\s*\}', SHIPPED).group(0)
        self.assertIn('error_log /dev/null;', cal)
        self.assertIn('access_log off;', cal)

    def test_an_older_file_brought_up(self):
        old = older_file()
        self.assertNotIn('pki-validation', old)
        self.assertNotIn('multipart', port80(old))
        self.assertNotIn('error_log /dev/null', old)
        got, said = update(old, self.script)
        p80 = port80(got)
        # the DCV files beside the HTTP-01 challenges, with the same socket and limit
        dcv = re.search(r'(?ms)^(\s*)location \^~ /\.well-known/pki-validation/ \{\n(.*?)^\1\}', p80)
        self.assertTrue(dcv, p80)
        self.assertIn('fastcgi_param SCRIPT_FILENAME /var/www/acme/acme.php;', dcv.group(2))
        self.assertIn('fastcgi_pass  unix:/run/php-fpm/acme.sock;', dcv.group(2))
        self.assertIn('limit_req     zone=acme_all burst=20 nodelay;', dcv.group(2))
        self.assertLess(p80.index('acme-challenge'), p80.index('pki-validation'))
        self.assertLess(p80.index('multipart'), p80.index('location '))
        cal = re.search(r'(?ms)^\s*location = /calendar\.ics \{.*?^\s*\}', got).group(0)
        self.assertIn('error_log /dev/null;', cal)
        for words in ('pki-validation', 'multipart', 'error log'):
            self.assertIn(words, said)
        again, said2 = update(got, self.script)
        self.assertEqual(again, got)                       # a second run changes nothing
        self.assertEqual(said2.strip(), '')
        # the 443 server: still one multipart line
        self.assertEqual(got.count('if ($http_content_type ~* "multipart")'), 2)

    def test_debian_socket_followed(self):
        old = older_file().replace('unix:/run/php-fpm/acme.sock;', 'unix:/run/php/acme.sock;')
        got, _ = update(old, self.script)
        dcv = re.search(r'(?ms)location \^~ /\.well-known/pki-validation/ \{\n(.*?)\}', got).group(1)
        self.assertIn('unix:/run/php/acme.sock;', dcv)
        self.assertNotIn('/run/php-fpm/', got)

    @unittest.skipUnless(NGINX, 'nginx is not installed')
    def test_nginx_takes_them(self):
        guard = guard_script()
        for start in (SHIPPED, older_file()):
            got, _ = update(start, self.script)
            got, out = update(got, guard)
            self.assertEqual(out.strip(), '1')             # the guard put in (its count, for here)
            rc, said = nginx_t(nginx_site(got))
            self.assertEqual(rc, 0, said)


@unittest.skipUnless(NGINX, 'nginx is not installed')
class NginxLive(unittest.TestCase):
    """The file as shipped, run: what nginx does with a multipart body on port 80, and what it
    writes to its error log when PHP does not answer."""

    @classmethod
    def setUpClass(cls):
        cls.prefix = tempfile.mkdtemp(dir=TMP)
        cls.sock = os.path.join(cls.prefix, 'nobody-here.sock')      # PHP down: no socket
        nginx_site(SHIPPED, sock=cls.sock, prefix=cls.prefix)
        rc, said = nginx_t(cls.prefix)
        if rc != 0:
            raise unittest.SkipTest('nginx -t here: %s' % said[-300:])
        cls.proc = subprocess.Popen([NGINX, '-p', cls.prefix, '-c',
                                     os.path.join(cls.prefix, 'nginx.conf'), '-g', 'daemon off;'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', PORT80), 0.2).close()
                break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def ask(self, port, request):
        s = socket.create_connection(('127.0.0.1', port), 5)
        if port == PORT443:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname='acme.example.local')
        s.sendall(request.encode())
        got = b''
        while True:
            lump = s.recv(65536)
            if not lump:
                break
            got += lump
        s.close()
        return int(got.split(b' ', 2)[1])

    def logs(self):
        text = ''
        for top, _d, files in os.walk(os.path.join(self.prefix, 'logs')):
            for n in files:
                if n.endswith('.log'):
                    with open(os.path.join(top, n), errors='replace') as f:
                        text += f.read()
        return text

    def test_multipart_refused_on_port_80(self):
        body = '--b\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n--b--\r\n'
        for path in ('/.well-known/acme-challenge/x', '/.well-known/pki-validation/x', '/pki/x'):
            code = self.ask(PORT80, 'POST %s HTTP/1.1\r\nHost: a.example\r\nContent-Type: '
                            'multipart/form-data; boundary=b\r\nContent-Length: %d\r\n'
                            'Connection: close\r\n\r\n%s' % (path, len(body), body))
            self.assertEqual(code, 403, path)
        # a CA's plain GET still goes to PHP (502 here: no PHP)
        code = self.ask(PORT80, 'GET /.well-known/pki-validation/fileauth.txt HTTP/1.1\r\n'
                        'Host: a.example\r\nConnection: close\r\n\r\n')
        self.assertEqual(code, 502)

    def test_calendar_secret_not_in_the_error_log(self):
        code = self.ask(PORT443, 'GET /calendar.ics?t=SECRETw9abc HTTP/1.1\r\nHost: acme.example.local'
                        '\r\nConnection: close\r\n\r\n')
        self.assertEqual(code, 502)
        code = self.ask(PORT443, 'GET /metrics?x=OTHERw9 HTTP/1.1\r\nHost: acme.example.local'
                        '\r\nConnection: close\r\n\r\n')
        self.assertEqual(code, 502)
        time.sleep(0.2)
        logs = self.logs()
        self.assertIn('OTHERw9', logs)                     # the log works - for the others
        self.assertNotIn('SECRETw9abc', logs)


class Words(unittest.TestCase):
    def test_upload_guard_says_nothing_of_its_own(self):
        m = re.search(r'nginx_upload_guard\(\) \{.*?(python3 - "\$NGINX_CONF" <<\'PY\'[^\n]*)\n', INSTALL, re.S)
        self.assertIn('>/dev/null', m.group(1))

    def test_php2shell_doc_names_the_remi_stream_taken(self):
        stream = re.search(r'dnf module enable -y php:(remi-[0-9.]+)', INSTALL).group(1)
        doc = read('docs/php2shell.md')
        self.assertIn('php:%s' % stream, doc)
        self.assertNotIn('remi-8.4', doc)
        self.assertIn('port 80', doc)


if __name__ == '__main__':
    unittest.main()
