#!/usr/bin/env python3
"""The certificate's own port as root's helper gives it to nginx (1.0.106) - with a real nginx
from a prefix of its own (its own pid, its own conf.d) standing in for the system's:

    python3 test/test_certlogin_port.py

A listener on two addresses is one process, not one plus "a program that cannot be told"; nginx
listening on the node's own address only is listening (the port was taken away again, nginx
reloaded twice at every request); another site of nginx on the port is refused, not made TLS;
--uninstall's leftovers take acme_certlogin.conf away with acme.conf (nginx -t failed, nginx did
not start again); systemctl's answer to the reload is said; SELinux is never told to take a port
from another service; a port refused as taken is asked for again (request.json written), with
its own words; the card shows root's words only for the port asked for.
Nothing under /etc is touched. Skipped cleanly without nginx or root.
"""
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, 'deploy', 'acme_web.py')
HAVE_NGINX = bool(shutil.which('nginx')) and os.geteuid() == 0 and \
    os.path.exists('/etc/nginx/fastcgi_params') and bool(shutil.which('openssl'))


def load_web(tag):
    spec = importlib.util.spec_from_file_location('acme_web_' + tag, WEB)
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ss(port):
    return subprocess.run(['ss', '-ltnH', 'sport = :%d' % port], capture_output=True,
                          text=True).stdout.strip()


class RealNginx:
    """A real nginx as "the system's nginx" for acme_web.nginx_part: NGINX_DIR, CERT_DIR and the
    state are temp; nginx -t and systemctl reload are pointed at it."""

    def __init__(self, base, listens, port):
        T = self.T = tempfile.mkdtemp(dir=base)
        for d in ('conf.d', 'certs', 'state/web', 'logs', 'www'):
            os.makedirs(os.path.join(T, d))
        self.env = {k: os.environ.get(k) for k in ('ACME_STATE', 'ACME_VIP_NGINX_DIR',
                                                   'ACME_VIP_CERT_DIR', 'ACME_ETC')}
        os.environ.update(ACME_STATE=T + '/state', ACME_VIP_NGINX_DIR=T + '/conf.d',
                          ACME_VIP_CERT_DIR=T + '/certs', ACME_ETC=T + '/etc')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', '/CN=n1', '-keyout', T + '/certs/acme.key', '-out',
                        T + '/certs/acme.pem'], check=True, capture_output=True)
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            tpl = f.read()
        tpl = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', tpl)
        tpl = re.sub(r'(?m)^\s*listen\s+80;\n', '    listen 127.0.0.2:%d;\n' % free_port(), tpl)
        tpl = re.sub(r'(?m)^\s*listen\s+443 ssl http2;\n',
                     ''.join('    listen      %s:443 ssl;\n' % a for a in listens), tpl)
        tpl = tpl.replace('/etc/nginx/certs', T + '/certs').replace('/var/log/nginx', T + '/logs')
        tpl = tpl.replace('/var/www/acme', T + '/www')
        with open(T + '/conf.d/acme.conf', 'w') as f:
            f.write(tpl)
        shutil.copy('/etc/nginx/fastcgi_params', T + '/fastcgi_params')
        self.conf = conf = T + '/nginx.conf'
        with open(conf, 'w') as f:
            f.write('user root; worker_processes 2; pid %s/nginx.pid; error_log %s/logs/error.log;\n'
                    'events {}\nhttp { include %s/conf.d/*.conf; }\n' % (T, T, T))
        w = self.w = load_web('real%d' % port)
        self._restore_env()
        w.NO_SERVICES = False
        w.NGINX_PID_FILES = [T + '/nginx.pid']
        w.NGINX_CONF = conf
        w.certlogin_selinux = lambda p: ''
        w.ACTIVE = [True]
        w.nginx_active = lambda: w.ACTIVE[0]
        w.RELOADS = []
        real = subprocess.run

        def run(args, *a, **k):
            if args[:2] == ['nginx', '-t']:
                return real(['nginx', '-t', '-p', T, '-c', conf], *a, **k)
            if args[:2] == ['nginx', '-T']:
                return real(['nginx', '-T', '-p', T, '-c', conf], *a, **k)
            if args == ['systemctl', 'reload', 'nginx']:
                w.RELOADS.append(time.time())
                r = real(['nginx', '-p', T, '-c', conf, '-s', 'reload'], *a, **k)
                time.sleep(0.5)
                return r
            if args[:1] == ['systemctl']:
                return real(['true'])
            return real(args, *a, **k)
        w.subprocess = type('S', (), {})()
        for name in dir(subprocess):
            if not name.startswith('__'):
                setattr(w.subprocess, name, getattr(subprocess, name))
        w.subprocess.run = run
        po = w._proc_of

        def proc_of(pid):       # the prefix (-p T) hidden: the system's nginx runs without -p
            got = po(pid)
            if got:
                got = (got[0], got[1], [x.replace(' -p ' + T, '') for x in got[2]
                                        if x not in ('-p', T)])
            return got
        w._proc_of = proc_of
        got = real(['nginx', '-p', T, '-c', conf], capture_output=True, text=True)
        if got.returncode != 0:
            raise unittest.SkipTest('a test nginx does not start here: %s' % got.stderr.strip()[-200:])
        time.sleep(0.5)
        def main_pid():
            with open(T + '/nginx.pid') as f:
                return int(f.read())
        w.nginx_main_pid = main_pid
        with open(T + '/certs/acme.pem') as f:
            cas = f.read()
        self.r = {'id': 'x', 'hash': 'y', 'node': 'n1', 'tls_node': None, 'tls_vip': None,
                  'vip': {'on': False},
                  'certlogin': w.certlogin_checked({'port': port, 'cas': cas, 'admin': True})}

    def _restore_env(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def reload(self):
        subprocess.run(['nginx', '-p', self.T, '-c', self.conf, '-s', 'reload'], capture_output=True)
        time.sleep(0.5)

    def test(self):
        return subprocess.run(['nginx', '-t', '-p', self.T, '-c', self.conf], capture_output=True,
                              text=True)

    def stop(self):
        subprocess.run(['nginx', '-p', self.T, '-c', self.conf, '-s', 'stop'], capture_output=True)
        time.sleep(0.3)


class PortUsers(unittest.TestCase):
    def test_two_addresses_one_process(self):
        """F4: a process listening on two addresses of the port (0.0.0.0 and [::] on a
        dual-stack node) is that process - not it and "a program that cannot be told"."""
        w = load_web('users')
        s4 = socket.socket()
        s4.bind(('127.0.0.1', 0))
        s4.listen()
        port = s4.getsockname()[1]
        s6 = socket.socket()
        try:
            s6.bind(('127.0.0.2', port))
        except OSError:
            s4.close()
            self.skipTest('127.0.0.2 not to be bound here')
        s6.listen()
        try:
            with open('/proc/self/comm') as f:
                me = f.read().strip()
            self.assertEqual(w.certlogin_port_users(port), [(me, os.getpid())])
            busy = w.certlogin_busy(port, 'n1')
            self.assertIn(me, busy)
            self.assertNotIn('cannot be told', busy)
        finally:
            s4.close()
            s6.close()

    def test_engine_two_addresses(self):
        """The same in the daemon's own look at the port (393 cl_port_users)."""
        s4 = socket.socket()
        s4.bind(('127.0.0.1', 0))
        s4.listen()
        port = s4.getsockname()[1]
        s6 = socket.socket()
        try:
            s6.bind(('127.0.0.2', port))
        except OSError:
            s4.close()
            self.skipTest('127.0.0.2 not to be bound here')
        s6.listen()
        try:
            got = engine_run('print(json.dumps(E.cl_port_users(%d)))' % port)
            with open('/proc/self/comm') as f:
                me = f.read().strip()
            self.assertEqual([tuple(x) for x in got], [(me, os.getpid())])
        finally:
            s4.close()
            s6.close()


class Reload(unittest.TestCase):
    def _w(self, answers, active):
        w = load_web('reload')
        w.NO_SERVICES = False
        calls = []

        class R:
            def __init__(self, rc, err='', out=''):
                self.returncode, self.stderr, self.stdout = rc, err, out

        def run(args, *a, **k):
            calls.append(list(args))
            return R(*answers.get(' '.join(args), (0,)))
        w.subprocess = type('S', (), {'run': staticmethod(run)})()
        w.nginx_active = lambda: active
        return w, calls

    def test_reload_said_as_it_went(self):
        """F5: "nginx reloaded" only when systemctl says so; a failed unit (its port taken at
        boot) is started again with reload-or-restart; a refusal is said."""
        w, calls = self._w({}, True)
        said = []
        self.assertTrue(w.nginx_reload(said))
        self.assertEqual(said, ['nginx reloaded'])
        failed = {'systemctl is-failed nginx': (0, '', 'failed\n')}
        w, calls = self._w(dict(failed, **{'systemctl reload nginx':
                                           (1, 'nginx.service is not active')}), False)
        said = []
        self.assertTrue(w.nginx_reload(said))
        self.assertIn(['systemctl', 'reload-or-restart', 'nginx'], calls)
        self.assertIn('started again', said[0])
        w, calls = self._w(dict(failed, **{
            'systemctl reload nginx': (1, 'Job failed'),
            'systemctl reload-or-restart nginx': (1, 'bind() to 0.0.0.0:8443 failed')}), False)
        said = []
        self.assertFalse(w.nginx_reload(said))
        self.assertIn('could NOT be reloaded', said[0])
        self.assertIn('bind()', said[0])
        w, calls = self._w({'systemctl reload nginx': (1, 'Job failed'),
                            'systemctl is-failed nginx': (1, '', 'active\n')}, True)
        said = []
        self.assertFalse(w.nginx_reload(said))
        self.assertNotIn(['systemctl', 'reload-or-restart', 'nginx'], calls)
        self.assertIn('Job failed', said[0])

    def test_stopped_nginx_left_stopped(self):
        """An nginx the admin stopped (inactive, not failed) is never started by a reload: it is
        left so and said; the port is not taken away for not listening then."""
        w, calls = self._w({'systemctl reload nginx': (1, 'nginx.service is not active, cannot reload.'),
                            'systemctl is-failed nginx': (1, '', 'inactive\n')}, False)
        said = []
        self.assertIsNone(w.nginx_reload(said))
        self.assertNotIn(['systemctl', 'reload-or-restart', 'nginx'], calls)
        self.assertFalse(any(c[:2] in (['systemctl', 'restart'], ['systemctl', 'start'])
                             for c in calls), calls)
        self.assertIn('left stopped', said[0])
        # only exactly 'inactive' is stopped (final review, 1.0.106): one on its way somewhere
        # is not left as stopped - its port is checked as ever
        for state in ('activating', 'deactivating', 'reloading', 'unknown', ''):
            w2, calls2 = self._w({'systemctl reload nginx': (1, 'Job failed'),
                                  'systemctl is-failed nginx': (1, '', state + '\n')}, False)
            said2 = []
            self.assertIs(w2.nginx_reload(said2), False, state)
            self.assertNotIn(['systemctl', 'reload-or-restart', 'nginx'], calls2)
        with open(WEB) as f:
            src = f.read()
        part = src[src.index('took = nginx_reload(said)'):]
        self.assertIn('if took is not None and c', part[:600])


class OtherSites(unittest.TestCase):
    """Another site on the port is what nginx loads (nginx -T) with a `listen` that takes the
    port here - not a file in sites-available or below conf.d, nor a `listen` on an address
    that is not this node's."""

    def test_listens_counted(self):
        import ipaddress
        w = load_web('osites')
        w.NGINX_CERTLOGIN = '/x/conf.d/acme_certlogin.conf'
        w.node_own_addresses = lambda: {ipaddress.ip_address(a) for a in
                                        ('127.0.0.1', '::1', '192.0.2.5', '2001:db8::5')}
        cases = [('server { listen 8443; }', True), ('server { listen *:8443 ssl; }', True),
                 ('server { listen 0.0.0.0:8443; }', True), ('server { listen [::]:8443; }', True),
                 ('server { listen 192.0.2.5:8443; }', True),
                 ('server { listen [2001:db8::5]:8443; }', True),
                 ('server { listen 127.0.0.1:8443; }', True),
                 ('server { listen 10.9.9.9:8443; }', False),
                 ('server { listen [2001:db8::9]:8443; }', False),
                 ('server { listen 18443; listen 84430; }', False),
                 ('upstream b { server 127.0.0.1:8443; }', False),
                 ('server { listen 80; location / { proxy_pass https://127.0.0.1:8443; } }', False),
                 ('# listen 8443 ssl;', False),
                 ('server { listen unix:/run/x.sock; }', False),
                 ('server { listen 81; add_header X "a#b"; }\nserver { listen 8443; }', True),
                 ('server { listen 81; return 200 a#b; listen 8443; }', True),
                 # a quote opens a string only at the start of a word (final review, 1.0.106)
                 ("server { listen 81; add_header X-Note don't;\n# listen 8443;\n}", False),
                 ("server { listen 81; add_header X-Note don't;\nlisten 8443; }", True),
                 # a listen within a quoted string is none
                 ('server { listen 83; return 200 "x; listen 8443"; }', False),
                 ("server { listen 83; return 200 'x { listen 8443'; }", False),
                 ('server { set $a listen; set $b 8443; }', False),
                 ('server { listen "8443" ssl; }', True),
                 ('server{listen 8443;}', True)]
        for text, refused in cases:
            w.nginx_loaded_files = lambda: {'/x/conf.d/site.conf': text,
                                            '/x/conf.d/acme_certlogin.conf': 'server { listen 8443 ssl; }'}
            self.assertEqual(w.certlogin_other_sites(8443),
                             ['/x/conf.d/site.conf'] if refused else [], text)
        # nginx cannot say (nginx -T refused): nothing said, the port not taken away for it
        w.nginx_loaded_files = lambda: None
        self.assertEqual(w.certlogin_other_sites(8443), [])

    def test_dump_headers(self):
        """Final review of 1.0.106: a `# configuration file X:` line within a file was taken
        as nginx's own header - the listen after it put on X (acme's own file, left out). Taken
        only for a regular file not printed before, at the end of a statement."""
        w = load_web('dumph')
        base = tempfile.mkdtemp(prefix='acme-dumph-')
        self.addCleanup(shutil.rmtree, base, True)
        main, site, mine = base + '/nginx.conf', base + '/site.conf', base + '/acme.conf'
        for p in (main, site, mine):
            with open(p, 'w') as f:
                f.write('#\n')

        def dump(*parts):
            return ''.join('# configuration file %s:\n%s\n' % (p, t) for p, t in parts)
        # the real shape: each file once
        got = w.nginx_dump_files(dump((main, 'http { include x; }\n'),
                                      (site, 'server { listen 81; }\n'),
                                      (mine, 'server { listen 8443 ssl; }\n')))
        self.assertEqual(sorted(got), sorted([main, site, mine]))
        self.assertIn('listen 81', got[site])
        # a header within a statement: no boundary
        got = w.nginx_dump_files(dump((main, 'http { include x; }\n'), (site,
            'server { listen\n# configuration file %s:\n8443; }\n' % mine)))
        self.assertEqual(sorted(got), sorted([main, site]))
        self.assertIn('8443', got[site])
        # a file printed already, or no such file: no boundary
        for fake in (main, base + '/none.conf', base):
            got = w.nginx_dump_files(dump((main, 'http { include x; }\n'), (site,
                'server { listen 82;\n# configuration file %s:\nlisten 8443; }\n' % fake)))
            self.assertEqual(sorted(got), sorted([main, site]), fake)
            self.assertIn('listen 8443', got[site])
        # after a comment or a block's end: a boundary (as nginx prints it)
        got = w.nginx_dump_files(dump((main, 'http { include x; }\n# the end\n'),
                                      (site, 'server { listen 81; }')))
        self.assertEqual(sorted(got), sorted([main, site]))

    @unittest.skipUnless(HAVE_NGINX, 'nginx (and root) wanted')
    def test_what_nginx_loads(self):
        base = tempfile.mkdtemp(prefix='acme-osites-')
        try:
            E = base + '/nginx'
            for d in ('conf.d', 'sites-available', 'sites-enabled', 'conf.d/old'):
                os.makedirs(os.path.join(E, d))
            w = load_web('osites2')
            w.NGINX_CONF = E + '/nginx.conf'
            w.NGINX_CERTLOGIN = E + '/conf.d/acme_certlogin.conf'
            with open(E + '/nginx.conf', 'w') as f:
                f.write('pid %s/nginx.pid; error_log %s/error.log;\nevents {}\n'
                        'http { include conf.d/*.conf; include sites-enabled/*; }\n' % (base, base))
            with open(w.NGINX_CERTLOGIN, 'w') as f:
                f.write('server { listen 8443; }\n')
            if subprocess.run(['nginx', '-T', '-c', w.NGINX_CONF], capture_output=True).returncode:
                self.skipTest('nginx -T does not take a temp configuration here')
            for k in ('sites-available/disabled.conf', 'conf.d/old/backup.conf'):
                with open(os.path.join(E, k), 'w') as f:
                    f.write('server { listen 8443; }\n')
            self.assertEqual(w.certlogin_other_sites(8443), [])
            with open(E + '/sites-enabled/on', 'w') as f:
                f.write('server { listen 8443; }\n')
            self.assertEqual(w.certlogin_other_sites(8443), [E + '/sites-enabled/on'])
        finally:
            shutil.rmtree(base, ignore_errors=True)


class SELinux(unittest.TestCase):
    def test_never_another_services_port(self):
        """semanage -m is never run: a port another service's type has is said, not taken; a
        port acme added is kept in a list --leftovers says at --uninstall."""
        d = tempfile.mkdtemp(prefix='acme-sel-')
        try:
            os.environ['ACME_VIP_NGINX_DIR'] = os.path.join(d, 'conf.d')
            os.environ['ACME_VIP_CERT_DIR'] = os.path.join(d, 'certs')
            try:
                w = load_web('sel')
            finally:
                del os.environ['ACME_VIP_NGINX_DIR'], os.environ['ACME_VIP_CERT_DIR']
            w.NO_SERVICES = False
            w.SELINUX_PORTS = os.path.join(d, 'selinux-ports')
            w.shutil = type('Sh', (), {'which': staticmethod(lambda n: '/usr/sbin/' + n)})()
            calls = []

            class R:
                def __init__(self, rc=0, out=''):
                    self.returncode, self.stdout, self.stderr = rc, out, ''
            listing = ('http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000\n'
                       'jboss_management_port_t        tcp      4447, 4712, 7600, 9123, 9990, 9999, 18001\n'
                       'unreserved_port_t              tcp      61000-61999, 1024-32767\n')

            def run(args, *a, **k):
                calls.append(list(args))
                if args[:3] == ['semanage', 'port', '-l']:
                    return R(0, listing)
                return R(0)
            w.subprocess = type('S', (), {'run': staticmethod(run)})()
            self.assertEqual(w.certlogin_selinux(8443), '')
            got = w.certlogin_selinux(9990)
            self.assertIn('jboss_management_port_t', got)
            self.assertIn('choose another port', got)
            self.assertFalse([c for c in calls if '-m' in c or '-a' in c])
            self.assertIn('http_port_t', w.certlogin_selinux(9443))
            self.assertIn(['semanage', 'port', '-a', '-t', 'http_port_t', '-p', 'tcp', '9443'], calls)
            self.assertFalse([c for c in calls if '-m' in c])
            self.assertEqual(w.selinux_ports_read(), [9443])
            left = [x for x in w.nginx_leftovers(dry=True) if 'SELinux' in x]
            self.assertTrue(left and 'semanage port -d -t http_port_t -p tcp 9443' in left[0], left)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(HAVE_NGINX, 'no nginx here, or not root')
class WithRealNginx(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix='acme-clport-')
        self.h = None

    def tearDown(self):
        if self.h:
            self.h.stop()
        shutil.rmtree(self.base, ignore_errors=True)

    def start(self, listens):
        port = free_port()
        self.h = RealNginx(self.base, listens, port)
        return port, self.h.w

    def test_listening_on_its_own_address(self):
        """F3: nginx's `listen` on the node's own address (not 127.0.0.1): the port is served,
        kept, and nginx reloaded once - not taken away again at every request."""
        port, w = self.start(['127.0.0.2'])
        # the servers acme writes listen where acme.conf's 443 does
        said, _ = w.nginx_part(self.h.r, {})
        self.assertIn('127.0.0.2:%d' % port, ss(port))
        self.assertEqual(w.CERTLOGIN_NOW.get('port'), port, said)
        self.assertTrue(os.path.exists(w.NGINX_CERTLOGIN))
        self.assertIn('nginx reloaded', said)
        self.assertEqual(len(w.RELOADS), 1)
        said, _ = w.nginx_part(self.h.r, {})
        self.assertEqual([x for x in said if x], [])
        self.assertEqual(len(w.RELOADS), 1)

    def test_two_addresses_still_ours(self):
        """F4: nginx on two addresses of the port: one listener, nginx - acme's own still when
        systemctl does not say nginx is active (the slow path)."""
        port, w = self.start(['127.0.0.1', '127.0.0.2'])
        w.nginx_part(self.h.r, {})
        self.assertEqual(w.CERTLOGIN_NOW.get('port'), port)
        self.assertEqual(ss(port).count('LISTEN'), 2)
        self.assertEqual([n for n, _p in w.certlogin_port_users(port)], ['nginx'])
        w.ACTIVE[0] = False
        self.assertEqual(w.certlogin_busy(port, 'n1'), '')
        said, _ = w.nginx_part(self.h.r, {})
        self.assertEqual(w.CERTLOGIN_NOW.get('port'), port, said)
        self.assertTrue(os.path.exists(w.NGINX_CERTLOGIN))

    def test_another_site_on_the_port(self):
        """F6: another site of the system's nginx on the port (plain HTTP): refused with the
        file named; that site is left answering plain HTTP."""
        port, w = self.start(['127.0.0.1'])
        with open(os.path.join(self.h.T, 'conf.d', 'zz_other.conf'), 'w') as f:
            f.write('server { listen 127.0.0.1:%d; server_name other.example; '
                    'location / { return 200 "other site\\n"; } }\n' % port)
        self.h.reload()

        def get():
            return subprocess.run(['curl', '-sS', '-m', '3', 'http://127.0.0.1:%d/' % port],
                                  capture_output=True, text=True).stdout
        self.assertEqual(get(), 'other site\n')
        busy = w.certlogin_busy(port, 'n1')
        self.assertIn('another site of nginx listens on %d' % port, busy)
        self.assertIn('zz_other.conf', busy)
        said, _ = w.nginx_part(self.h.r, {})
        self.assertEqual(w.CERTLOGIN_NOW.get('port'), 0)
        self.assertEqual(w.CERTLOGIN_NOW.get('want'), port)
        self.assertFalse(os.path.exists(w.NGINX_CERTLOGIN))
        self.assertEqual(get(), 'other site\n')
        # the same when nginx listens there through a file the scan does not see
        os.rename(os.path.join(self.h.T, 'conf.d', 'zz_other.conf'),
                  os.path.join(self.h.T, 'conf.d', 'zz_other.inc'))
        with open(os.path.join(self.h.T, 'conf.d', 'zz_inc.conf'), 'w') as f:
            f.write('include %s;\n' % os.path.join(self.h.T, 'conf.d', 'zz_other.inc'))
        w.certlogin_other_sites = lambda p: []
        self.h.reload()
        self.assertIn('another site of nginx', w.certlogin_busy(port, 'n1'))

    def test_uninstall_leaves_nginx_whole(self):
        """F1: what --uninstall takes away (acme.conf, acme_vip.conf) and --leftovers after it:
        acme_certlogin.conf (acme.conf's limit_req zone) and the authorities go too - nginx -t
        passes; install.sh says so and asks nginx -t before the reload."""
        port, w = self.start(['127.0.0.1'])
        w.nginx_part(self.h.r, {})
        self.assertTrue(os.path.exists(w.NGINX_CERTLOGIN))
        self.assertTrue(os.path.exists(w.CERTLOGIN_CA))
        os.unlink(w.NGINX_MAIN)
        self.assertNotEqual(self.h.test().returncode, 0)        # as 1.0.105 left it
        w.NO_SERVICES = True
        dry = w.nginx_leftovers(dry=True)
        self.assertTrue(any('acme_certlogin.conf' in x and x.startswith('[would remove]') for x in dry), dry)
        self.assertTrue(os.path.exists(w.NGINX_CERTLOGIN))
        got = w.nginx_leftovers()       # (the rest of --leftovers is the machine's /etc)
        self.assertTrue(any('acme_certlogin.conf' in x and x.startswith('removed:') for x in got), got)
        self.assertTrue(any('acme-certlogin-ca.pem' in x for x in got), got)
        self.assertFalse(os.path.exists(w.NGINX_CERTLOGIN))
        self.assertFalse(os.path.exists(w.CERTLOGIN_CA))
        t = self.h.test()
        self.assertEqual(t.returncode, 0, t.stderr)
        with open(os.path.join(ROOT, 'install.sh')) as f:
            sh = f.read()
        part = sh[sh.index('if [[ -n "$DO_UNINSTALL" ]]'):]
        part = part[:part.index('\nfi\n')]
        self.assertIn('rm -f /etc/nginx/conf.d/acme_certlogin.conf', part)
        self.assertIn('rm -f /etc/nginx/certs/acme-certlogin-ca.pem', part)
        self.assertIn(w.MARK, part)
        self.assertLess(part.index('nginx -t'), part.index('run systemctl reload nginx 2>/dev/null'))


def engine_run(code, files=None):
    """`code` in a daemon of its own (a temp state), its stdout's last line as JSON."""
    d = tempfile.mkdtemp(prefix='acme-clport-e-')
    try:
        with open(os.path.join(d, 'config.json'), 'w') as f:
            f.write('{"node_name": "acme1", "upgrade_check": 0}')
        os.makedirs(os.path.join(d, 'web'))
        for name, text in (files or {}).items():
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        env = dict(os.environ, ACME_CONFIG=os.path.join(d, 'config.json'), ACME_STATE=d,
                   ACME_RUN=d, ACME_LOGDIR=d, ACME_PLUGINS=os.path.join(d, 'plugins'),
                   ACME_VIP_CERT_DIR=os.path.join(d, 'certs'), ACME_HA_CA=os.path.join(d, 'ha-ca.pem'))
        pre = ('import json, os, sys, time\nsys.path.insert(0, %r)\nimport acme  # noqa\n'
               'from acmelib import engine as E\n' % ROOT)
        r = subprocess.run([sys.executable, '-c', pre + code], env=env, capture_output=True,
                           text=True, timeout=120, cwd=d)
        if r.returncode != 0:
            raise AssertionError(r.stderr[-2000:])
        return json.loads(r.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(d, ignore_errors=True)


class Engine(unittest.TestCase):
    def test_port_taken_is_asked_again(self):
        """F2: root said the port was taken, longer ago than WEB_RETRY_S: request.json is written
        (it never was), with words of the port - not "the certificate nginx has is not the one
        saved" - in Events once, and not again before its own 15 minutes."""
        got = engine_run('''
STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
desired = {'node': 'acme1', 'vip': {'on': False}, 'tls': {'node': None, 'vip': None},
           'certlogin': {'port': 8443, 'cas': 'x', 'admin': True, 'portal': False}}
E.web_desired = lambda store: desired
E.web_self_check = lambda store, st: None
E.web_drift = lambda desired: ''
h = E.web_hash(desired)
w = os.path.join(os.environ['ACME_STATE'], 'web')
def status(at):
    open(os.path.join(w, 'status.json'), 'w').write(json.dumps(
        {'at': at, 'state': 'done', 'hash': h,
         'certlogin': {'port': 0, 'busy': 'port 8443 is used by haproxy (pid 1) on acme1', 'want': 8443}}))
status(time.time() - 3600)
out = []
E.web_tick(STORE)
req = os.path.join(w, 'request.json')
out.append(os.path.exists(req))
os.unlink(req)
E.WEB_ASKED['at'] -= 2000              # root answered the same again, a while after
status(time.time() - 1000)
E.web_tick(STORE)
out.append(os.path.exists(req))         # its own timer: not before 15 minutes
E.WEB_DRIFT['port_at'] = time.time() - 1000
E.web_tick(STORE)
out.append(os.path.exists(req))
out.append([r['words'] for r in STORE.db.rows("SELECT * FROM events")])
print(json.dumps(out))
''')
        self.assertEqual(got[:3], [True, False, True])
        self.assertEqual(len(got[3]), 1, got[3])
        self.assertIn("the certificate's port 8443 was not given to nginx", got[3][0])
        self.assertNotIn('not the one saved', got[3][0])

    def test_could_not_listen_backs_off(self):
        """"nginx could not listen on N" answered again and again: each ask reloads nginx twice,
        so it is asked after 15 minutes, then 30, 60 ... up to 6 hours; another answer (or
        anything else wanted) starts over at 15 minutes."""
        got = engine_run('''
STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
desired = {'node': 'acme1', 'vip': {'on': False}, 'tls': {'node': None, 'vip': None},
           'certlogin': {'port': 8443, 'cas': 'x', 'admin': True, 'portal': False}}
E.web_desired = lambda store: desired
E.web_self_check = lambda store, st: None
E.web_drift = lambda desired: ''
h = E.web_hash(desired)
w = os.path.join(os.environ['ACME_STATE'], 'web')
req = os.path.join(w, 'request.json')
def status(ago, busy='nginx could not listen on 8443'):
    open(os.path.join(w, 'status.json'), 'w').write(json.dumps(
        {'at': time.time() - ago, 'state': 'done', 'hash': h,
         'certlogin': {'port': 0, 'busy': busy, 'want': 8443}}))
def ask(ago, since_ask, busy='nginx could not listen on 8443'):
    """root answered `ago` seconds ago; acme asked `since_ask` seconds ago: asked now?"""
    if os.path.exists(req):
        os.unlink(req)
    E.WEB_ASKED['at'] = time.time() - since_ask - 1
    E.WEB_DRIFT['port_at'] = time.time() - since_ask
    status(ago, busy)
    E.web_tick(STORE)
    return os.path.exists(req)
out = [ask(1000, 1000)]                 # first: 15 minutes
out.append(ask(1000, 1000))             # second: not before 30 minutes
out.append(ask(1900, 1900))
out.append(ask(3000, 3000))             # third: 60 minutes
out.append(ask(3700, 3700))
out.append(ask(30000, 30000))           # up to 6 hours, never more
for _ in range(6):
    ask(30000, 30000)
out.append(ask(21000, 21000))
out.append(ask(21700, 21700))
out.append(ask(1000, 1000, 'port 8443 is used by haproxy (pid 1) on acme1'))   # another answer
out.append(ask(1000, 1000, 'nginx could not listen on 8443'))                 # starts over
out.append(ask(1000, 1000, 'nginx could not listen on 8443'))
print(json.dumps(out + [[r['words'] for r in STORE.db.rows("SELECT * FROM events")]]))
''')
        self.assertEqual(got[:-1], [True, False, True, False, True, True, False, True, True,
                                    True, False], got)
        self.assertIn('up to every 6 hours', got[-1][0])

    def test_drift_is_asked_again(self):
        """F2: a drift of the certificate (done, nginx has another one) writes request.json -
        the gate of a failed request no longer returns before it."""
        got = engine_run('''
STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
desired = {'node': 'acme1', 'vip': {'on': False}, 'tls': {'node': None, 'vip': None},
           'certlogin': {'port': 8443, 'cas': 'x', 'admin': True, 'portal': False}}
E.web_desired = lambda store: desired
E.web_self_check = lambda store, st: None
E.web_drift = lambda desired: 'nginx sends another certificate'
h = E.web_hash(desired)
w = os.path.join(os.environ['ACME_STATE'], 'web')
open(os.path.join(w, 'status.json'), 'w').write(json.dumps({'at': time.time() - 60, 'state': 'done', 'hash': h}))
E.web_tick(STORE)
print(json.dumps(os.path.exists(os.path.join(w, 'request.json'))))
''')
        self.assertTrue(got)

    def test_card_root_words_of_this_port(self):
        """Minor: the card shows root's words of a taken port only for the port asked for."""
        st = json.dumps({'at': time.time(), 'state': 'done', 'hash': 'x',
                         'certlogin': {'port': 0, 'busy': 'port 9443 is used by java (pid 7) on acme1',
                                       'want': 9443}})
        old = json.dumps({'at': time.time(), 'state': 'done', 'hash': 'x',
                          'certlogin': {'port': 0, 'busy': 'port 9443 is used by java (pid 7) on acme1'}})
        code = ('E.cl_port_busy = lambda port, served=False: "here"\n'
                'print(json.dumps([E.cl_busy_now(9443, False), E.cl_busy_now(%d, False)]))' % free_port())
        got = engine_run(code, {'web/status.json': st})
        self.assertIn('java', got[0])
        self.assertEqual(got[1], 'here')
        got = engine_run(code, {'web/status.json': old})       # a root before 1.0.106
        self.assertIn('java', got[0])
        self.assertEqual(got[1], 'here')


if __name__ == '__main__':
    unittest.main(verbosity=2)
