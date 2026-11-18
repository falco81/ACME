#!/usr/bin/env python3
"""Is the administration published through the load balancer? (1.0.128)

    python3 test/test_lb_admin_exposure.py      (or python3 -m unittest test.test_lb_admin_exposure)

otp's guide says, for an L4 balancer with TLS passed through, that the administration is for
everybody unless the nodes keep it out. acme publishes everything on 443 too; what keeps
/admin/ from the internet is its allow list, judged by the client's address - so the nodes
must see it. This covers what was built for that:

- deploy/acme_web.py: web_proxy_header=proxy_protocol puts `proxy_protocol` on the 443 listen
  lines of the HTTPS server (IPv4 and IPv6), marked, with `set_real_ip_from` the balancers and
  `real_ip_header proxy_protocol`; loopback lines without it for the node's own checks; port
  80 never; off again, the file exactly as before; a hand edit of the old guide adopted. The
  VIP address's server and the agents' port never get the loopback lines. The certificate's
  port (acme_certlogin.conf) gets the PROXY protocol only when asked (`proxy`), whatever 443
  has - and with the defaults its text is exactly as before. nginx -t refusing puts it all
  back. With a real nginx (root, free high ports, never 8443): nginx -t takes the result.
- The daemon: the setting's validation; web_desired asks the port's PROXY protocol only when
  switched on (the request of everybody else, and its hash, as before); lb_facts tells the
  guide what nginx has; split_peer_says sends "PROXY UNKNOWN" to a peer behind one.
- install.sh's nginx update keeps the proxy_protocol lines and acme's markers.
- The guide (admin.js, in node): who may reach the administration pages and the red warning
  when passed through; the blocks of "ended on the balancer" publish the enrolment pages only;
  the certificate sign-in's port per kind; the new texts in Czech.
- No pages-only port (otp's web_proxy_port) was built: acme's allow lists are per page, and
  see the client once the PROXY protocol is written - docs/load-balancers.md says why.
"""
import importlib.util
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-lbexp-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_VIP_NO_SERVICES='1')
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def helper():
    spec = importlib.util.spec_from_file_location('acme_web_lbexp', os.path.join(
        ROOT, 'deploy', 'acme_web.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


W = helper()
with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as _f:
    SHIPPED = _f.read()
PP = {'from': ['192.0.2.5/32'], 'header': 'proxy_protocol', 'recursive': True}
XFF = {'from': ['192.0.2.5/32'], 'header': 'X-Forwarded-For', 'recursive': True}
OFF = {'from': [], 'header': '', 'recursive': False}
CL = {'port': 8443, 'cas': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
      'admin': True, 'portal': True}


def tls_block(text):
    a, b = W.server_block(text)
    return text[a:b]


def port80_block(text):
    m = re.search(r'(?ms)^server \{\n    listen      80;.*?^\}', text)
    return m.group(0)


def listens(text):
    return re.findall(r'(?m)^\s*listen\s+[^\n]*', text)


class RootHelperText(unittest.TestCase):
    def test_proxy_protocol_on_443_only(self):
        new = W.realip_into(SHIPPED, PP)
        block = tls_block(new)
        self.assertIn('listen      443 ssl http2 proxy_protocol;   # ACME-PROXY-PROTOCOL', block)
        self.assertIn('listen      [::]:443 ssl http2 proxy_protocol;   # ACME-PROXY-PROTOCOL', block)
        self.assertIn('set_real_ip_from 192.0.2.5/32;', block)
        self.assertIn('real_ip_header proxy_protocol;', block)
        # The node's own checks (the VIP address's, install.sh's) from the loopback, without it.
        self.assertRegex(block, r'listen\s+127\.0\.0\.1:443 ssl http2;\s+# ACME-PROXY-LOCAL')
        self.assertRegex(block, r'listen\s+\[::1\]:443 ssl http2;\s+# ACME-PROXY-LOCAL')
        # Port 80 (HTTP-01, /pki/) never.
        self.assertEqual(port80_block(new), port80_block(SHIPPED))
        self.assertNotIn('proxy_protocol', port80_block(new))
        self.assertEqual(new.count('# ACME-REALIP-BEGIN'), 1)
        # Once is once; off again: the file as shipped.
        self.assertEqual(W.realip_into(new, PP), new)
        self.assertEqual(W.realip_into(new, OFF), SHIPPED)
        # Back to a header: the listen lines as shipped, the header's lines in.
        back = W.realip_into(new, XFF)
        self.assertNotIn('proxy_protocol', back)
        self.assertNotIn('ACME-PROXY', back)
        self.assertIn('real_ip_header X-Forwarded-For;', back)
        self.assertEqual(W.realip_into(back, OFF), SHIPPED)

    def test_defaults_unchanged(self):
        # A header as before: not one listen line touched.
        self.assertEqual(listens(tls_block(W.realip_into(SHIPPED, XFF))), listens(tls_block(SHIPPED)))
        self.assertEqual(W.realip_into(SHIPPED, OFF), SHIPPED)
        self.assertEqual(W.proxy_listens(tls_block(SHIPPED), False), tls_block(SHIPPED))
        # The certificate's port without `proxy`: exactly as before, whatever 443 has.
        before = W.certlogin_text(SHIPPED, None, dict(CL))
        self.assertNotIn('proxy_protocol', before)
        self.assertNotIn('real_ip', before)
        self.assertEqual(W.certlogin_text(W.realip_into(SHIPPED, PP), None, dict(CL)), before)
        self.assertEqual(W.certlogin_text(W.realip_into(SHIPPED, XFF), None, dict(CL)), before)
        for watch in (True, False):
            c = dict(CL, watch=True) if watch else dict(CL)
            self.assertEqual(W.certlogin_text(W.realip_into(SHIPPED, PP), None, c),
                             W.certlogin_text(SHIPPED, None, c))

    def test_hand_edit_of_the_old_guide_adopted(self):
        a, b = W.server_block(SHIPPED)
        block = SHIPPED[a:b].replace('listen      443 ssl http2;', 'listen      443 ssl http2 proxy_protocol;')
        head = block.index('\n', block.index('{')) + 1
        block = block[:head] + '    set_real_ip_from 192.0.2.5;\n    real_ip_header proxy_protocol;\n' + block[head:]
        by_hand = SHIPPED[:a] + block + SHIPPED[b:]
        new = W.realip_into(by_hand, PP)
        nb = tls_block(new)
        self.assertEqual(len(re.findall(r'(?m)^\s*real_ip_header\s', nb)), 1)
        self.assertEqual(nb.count('proxy_protocol;   # ACME-PROXY-PROTOCOL'), 2)
        self.assertNotIn('proxy_protocol proxy_protocol', nb)

    def test_certificate_port_with_proxy(self):
        main = W.realip_into(SHIPPED, XFF)          # 443 ended on the balancer
        text = W.certlogin_text(main, None, dict(CL, proxy=['192.0.2.5/32', '2001:db8::5/128']))
        ls = listens(text)
        self.assertEqual(len(ls), 2)
        for x in ls:
            self.assertRegex(x, r'listen\s+(\[::\]:)?8443 ssl http2 proxy_protocol;$')
        self.assertIn('set_real_ip_from       192.0.2.5/32;', text)
        self.assertIn('set_real_ip_from       2001:db8::5/128;', text)
        self.assertIn('real_ip_header         proxy_protocol;', text)
        # Still nothing but the sign-in there: 404 for the rest, /admin/ only for cert-login/try.
        self.assertIn('location / { return 404; }', text)
        self.assertIn('if ($args !~ "^api=cert-(login|try)&n=', text)
        # 443 passed through as well: no loopback lines, no doubled proxy_protocol.
        text2 = W.certlogin_text(W.realip_into(SHIPPED, PP), None, dict(CL, proxy=['192.0.2.5/32']))
        self.assertNotIn('ACME-PROXY', text2)
        self.assertNotIn('127.0.0.1', ''.join(listens(text2)))
        self.assertEqual(listens(text2), ls)
        # The VIP address's server (made from the node's block) gets its server too.
        vb = tls_block(W.realip_into(SHIPPED, PP)).replace('server_name acme.example.local;',
                                                           'server_name vip.example.local;')
        both = W.certlogin_text(W.realip_into(SHIPPED, PP), vb, dict(CL, proxy=['192.0.2.5/32']))
        self.assertEqual(both.count('real_ip_header         proxy_protocol;'), 2)

    def test_certlogin_checked(self):
        cas = CL['cas']
        try:
            got = W.certlogin_checked(dict(CL, cas=cas))
        except W.Refused as e:
            self.skipTest('the authorities need more here: %s' % e)
        self.assertNotIn('proxy', got)
        got = W.certlogin_checked(dict(CL, proxy=['192.0.2.5']))
        self.assertEqual(got['proxy'], ['192.0.2.5/32'])
        for bad in (['192.0.2.5;\n  evil'], ['not-a-net']):
            with self.assertRaises(W.Refused):
                W.certlogin_checked(dict(CL, proxy=bad))

    def test_realip_checked_takes_proxy_protocol(self):
        nets, head, _rec = W.realip_checked(PP)
        self.assertEqual(head, 'proxy_protocol')
        with self.assertRaises(W.Refused):
            W.realip_checked({'from': ['192.0.2.5'], 'header': 'proxy_protocol;\n evil'})

    def test_agents_port_never_gets_the_loopback(self):
        main = W.realip_into(SHIPPED, PP)
        c = {'port': 8444}
        self.assertEqual(listens(W.agents_text(main, c)), listens(W.agents_text(SHIPPED, c)))


class RootHelperRun(unittest.TestCase):
    """nginx_part with the system mocked: nginx -t, the reload, the port's checks."""

    def setUp(self):
        d = tempfile.mkdtemp(prefix='ngx-', dir=TMP)
        self.main = os.path.join(d, 'acme.conf')
        with open(self.main, 'w') as f:
            f.write(SHIPPED)
        self.saved = {k: getattr(W, k) for k in (
            'NGINX_MAIN', 'NGINX_VIP', 'NGINX_CERTLOGIN', 'CERTLOGIN_CA', 'NODE_FILES',
            'VIP_FILES', 'NO_SERVICES', 'certlogin_busy', 'certlogin_selinux',
            'certlogin_listening', 'nginx_reload')}
        W.NGINX_MAIN = self.main
        W.NGINX_VIP = os.path.join(d, 'acme_vip.conf')
        W.NGINX_CERTLOGIN = os.path.join(d, 'acme_certlogin.conf')
        W.CERTLOGIN_CA = os.path.join(d, 'ca.pem')
        W.NODE_FILES = {k: os.path.join(d, 'node-' + k) for k in W.NODE_FILES}
        W.VIP_FILES = {k: os.path.join(d, 'vip-' + k) for k in W.VIP_FILES}
        # 8443 only through mocks: nothing listens, nothing is asked of the machine.
        W.certlogin_busy = lambda port, node: ''
        W.certlogin_selinux = lambda port: ''
        W.certlogin_listening = lambda port: True
        W.nginx_reload = lambda said: True
        self.real_run = W.subprocess.run

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(W, k, v)
        W.subprocess.run = self.real_run

    def nginx_t(self, rc):
        class Done:
            def __init__(self, code, err=''):
                self.returncode, self.stderr, self.stdout = code, err, ''

        def fake(cmd, *a, **k):
            if cmd[:2] == ['nginx', '-t']:
                return Done(rc, '' if rc == 0 else 'nginx: [emerg] invalid parameter "proxy_protocol"')
            return Done(0)
        W.subprocess.run = fake
        W.NO_SERVICES = False

    def request(self, **kw):
        r = {'node': 'n1', 'tls_node': None, 'tls_vip': None, 'vip': {'on': False}}
        r.update(kw)
        return r

    def test_written_then_refused_put_back(self):
        self.nginx_t(0)
        r = self.request(realip=PP, certlogin=dict(CL, proxy=['192.0.2.5/32']))
        said, _ = W.nginx_part(r, {})
        with open(self.main) as f:
            text = f.read()
        self.assertIn('proxy_protocol;   # ACME-PROXY-PROTOCOL', text)
        with open(W.NGINX_CERTLOGIN) as f:
            cl = f.read()
        self.assertIn('8443 ssl http2 proxy_protocol;', cl)
        self.assertIn('real_ip_header         proxy_protocol;', cl)
        self.assertTrue(any('PROXY protocol' in s and '443' in s for s in said), said)
        self.assertTrue(any('port 8443' in s and 'PROXY protocol' in s for s in said), said)
        # Off again, nginx refusing: everything as it was before this request.
        before_main, before_cl = text, cl
        self.nginx_t(1)
        with self.assertRaises(W.Refused):
            W.nginx_part(self.request(realip=OFF, certlogin=dict(CL)), {})
        with open(self.main) as f:
            self.assertEqual(f.read(), before_main)
        with open(W.NGINX_CERTLOGIN) as f:
            self.assertEqual(f.read(), before_cl)
        # Taken: as shipped, the port's server as before.
        self.nginx_t(0)
        W.nginx_part(self.request(realip=OFF, certlogin=dict(CL)), {})
        with open(self.main) as f:
            self.assertEqual(f.read(), SHIPPED)
        with open(W.NGINX_CERTLOGIN) as f:
            self.assertEqual(f.read(), W.certlogin_text(SHIPPED, None, dict(CL)))

    def test_defaults_write_nothing_new(self):
        self.nginx_t(0)
        W.nginx_part(self.request(certlogin=dict(CL)), {})
        with open(self.main) as f:
            self.assertEqual(f.read(), SHIPPED)
        with open(W.NGINX_CERTLOGIN) as f:
            self.assertNotIn('proxy_protocol', f.read())

    @unittest.skipUnless(shutil.which('nginx') and os.geteuid() == 0, 'nginx and root needed')
    def test_real_nginx_takes_it(self):
        """nginx -t binds the ports it is given: free high ports here, never 80, 443 or 8443."""
        d = tempfile.mkdtemp(prefix='ngx-real-', dir=TMP)
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
                        '-keyout', d + '/k.key', '-out', d + '/c.pem', '-subj', '/CN=x'],
                       check=True, capture_output=True)
        ports = []
        for _ in range(3):
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            ports.append(s.getsockname()[1])
            s.close()
        main = W.realip_into(SHIPPED, PP)
        W.CERTLOGIN_CA = d + '/c.pem'
        cl = W.certlogin_text(main, None, dict(CL, port=ports[2], proxy=['192.0.2.5/32'], watch=True))
        no6 = not os.path.exists('/proc/net/if_inet6')

        def fix(x):
            x = x.replace('/etc/nginx/certs/acme.pem', d + '/c.pem') \
                .replace('/etc/nginx/certs/acme.key', d + '/k.key').replace('/var/log/nginx', d)
            x = re.sub(r'(?m)^(\s*listen\s+)80;', r'\g<1>127.0.0.1:%d;' % ports[0], x)
            x = re.sub(r'(?m)^(\s*listen\s+(?:[0-9.]+:)?)443\b', r'\g<1>%d' % ports[1], x)
            x = re.sub(r'(?m)^(\s*listen\s+\[[^\]]*\]:)443\b', r'\g<1>%d' % ports[1], x)
            if no6:
                x = re.sub(r'(?m)^\s*listen\s+\[[^\n]*\n', '', x)
            return x
        with open(d + '/acme.conf', 'w') as f:
            f.write(fix(main))
        with open(d + '/cl.conf', 'w') as f:
            f.write(fix(cl))
        shutil.copy('/etc/nginx/fastcgi_params', d) if os.path.exists('/etc/nginx/fastcgi_params') \
            else open(d + '/fastcgi_params', 'w').close()
        with open(d + '/nginx.conf', 'w') as f:
            f.write('pid %s/n.pid; error_log %s/e.log; events {} http { include %s/acme.conf; '
                    'include %s/cl.conf; }' % (d, d, d, d))
        got = subprocess.run(['nginx', '-t', '-c', d + '/nginx.conf', '-p', d], capture_output=True,
                             text=True)
        self.assertEqual(got.returncode, 0, got.stderr)


class Daemon(unittest.TestCase):
    KEYS = ('web_proxy', 'web_proxy_from', 'web_proxy_header', 'certlogin_proxy_protocol')

    def setUp(self):
        for k in self.KEYS:
            STORE.drop_setting(k)
            E.CONFIG[k] = E.DEFAULTS[k]
        E.SAVED_KEYS['at'] = 0.0
        self.real_cl = E.certlogin_desired

    def tearDown(self):
        E.certlogin_desired = self.real_cl
        for k in self.KEYS:
            E.CONFIG[k] = E.DEFAULTS[k]

    def test_setting_validation(self):
        self.assertEqual(E.check_setting('web_proxy_header', 'proxy_protocol'), 'proxy_protocol')
        self.assertEqual(E.check_setting('web_proxy_header', 'PROXY_PROTOCOL'), 'proxy_protocol')
        self.assertEqual(E.check_setting('web_proxy_header', 'X-Forwarded-For'), 'X-Forwarded-For')
        for bad in ('proxy protocol', 'proxy_protocol;', 'Host', 'X_Forwarded'):
            with self.assertRaises(E.BadSetting):
                E.check_setting('web_proxy_header', bad)
        self.assertEqual(E.DEFAULTS['certlogin_proxy_protocol'], 0)
        self.assertEqual(int(E.check_setting('certlogin_proxy_protocol', 1)), 1)
        with self.assertRaises(E.BadSetting):
            E.check_setting('certlogin_proxy_protocol', 2)
        self.assertIn('certlogin_proxy_protocol', E.PANES['fw'])
        self.assertIn('certlogin_proxy_protocol', E.NAMES)
        self.assertIn('certlogin_proxy_protocol', E.SAYS)
        self.assertIn('proxy_protocol', E.SAYS['web_proxy_header'])

    def cl(self):
        E.certlogin_desired = lambda store: {'admin': True, 'portal': False, 'port': 8443,
                                             'cas': CL['cas']}

    def test_port_proxy_asked_only_when_on(self):
        self.cl()
        d = E.web_desired(STORE)
        self.assertNotIn('proxy', d['certlogin'])
        self.assertNotIn('realip', d)
        # Behind a balancer with a header: the port as before.
        E.CONFIG.update(web_proxy=1, web_proxy_from='192.0.2.5')
        d = E.web_desired(STORE)
        self.assertNotIn('proxy', d['certlogin'])
        self.assertEqual(d['realip']['header'], 'X-Forwarded-For')
        # The port alone (443 ended on the balancer).
        E.CONFIG['certlogin_proxy_protocol'] = 1
        self.assertEqual(E.web_desired(STORE)['certlogin']['proxy'], ['192.0.2.5/32'])
        # 443 passed through: both.
        E.CONFIG.update(certlogin_proxy_protocol=0, web_proxy_header='proxy_protocol')
        d = E.web_desired(STORE)
        self.assertEqual(d['realip']['header'], 'proxy_protocol')
        self.assertEqual(d['certlogin']['proxy'], ['192.0.2.5/32'])
        # Not behind a balancer: never, whatever the rest says.
        E.CONFIG.update(web_proxy=0, certlogin_proxy_protocol=1)
        self.assertNotIn('proxy', E.web_desired(STORE)['certlogin'])

    def test_lb_facts_tells_the_guide(self):
        p = os.path.join(TMP, 'acme-facts.conf')
        with open(p, 'w') as f:
            f.write(W.realip_into(SHIPPED, PP))
        real = E.NGINX_CONF_PATHS
        E.NGINX_CONF_PATHS = (p,)
        try:
            got = E.lb_facts(STORE)
            self.assertTrue(got['proxy_protocol'])
            self.assertEqual(got['header'], 'proxy_protocol')
            self.assertEqual(got['trusted'], ['192.0.2.5/32'])
            self.assertFalse(got['access']['admin']['any'])
            self.assertIn('10.0.0.0/8', got['access']['admin']['from'])
            self.assertIn('certlogin', got)
            with open(p, 'w') as f:
                f.write(W.access_into(SHIPPED, {
                    'portal': {'any': True, 'from': []}, 'admin': {'any': True, 'from': []},
                    'health': {'any': True, 'from': []}}))
            got = E.lb_facts(STORE)
            self.assertFalse(got['proxy_protocol'])
            self.assertTrue(got['access']['admin']['any'])
        finally:
            E.NGINX_CONF_PATHS = real

    def test_peer_health_with_proxy_unknown(self):
        """The other node behind an L4 balancer: its 443 wants the PROXY header first."""
        d = tempfile.mkdtemp(prefix='peer-', dir=TMP)
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
                        '-keyout', d + '/k.key', '-out', d + '/c.pem', '-subj', '/CN=x'],
                       check=True, capture_output=True)
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(2)
        port = srv.getsockname()[1]
        seen = []

        def serve():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(d + '/c.pem', d + '/k.key')
            conn, _a = srv.accept()
            head = b''
            while not head.endswith(b'\r\n'):
                head += conn.recv(1)
            seen.append(head)
            s = ctx.wrap_socket(conn, server_side=True)
            s.recv(4096)
            s.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 30\r\n\r\n'
                      b'down: the database does not op')
            s.close()
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        real = E.socket.create_connection
        E.socket.create_connection = lambda addr, timeout=None: real(('127.0.0.1', port), timeout)
        E.CONFIG.update(web_proxy=1, web_proxy_from='192.0.2.5', web_proxy_header='proxy_protocol')
        try:
            self.assertEqual(E.split_peer_says_proxied('192.0.2.12', 5), 'down')
        finally:
            E.socket.create_connection = real
            srv.close()
        self.assertEqual(seen, [b'PROXY UNKNOWN\r\n'])


class InstallMigration(unittest.TestCase):
    def test_install_sh_keeps_proxy_protocol(self):
        with open(os.path.join(ROOT, 'install.sh')) as f:
            text = f.read()
        m = re.search(r'python3 - "\$NGINX_CONF" <<\'PY\'\n(.*?)\nPY\n', text, re.S)
        script = os.path.join(TMP, 'nginx_update.py')
        with open(script, 'w') as f:
            f.write(m.group(1))
        conf = os.path.join(TMP, 'acme-mig.conf')
        for start in (SHIPPED, re.sub(r'(?m)^[^\n]*api=(kerberos-login|cert-nonce)[^\n]*\n', '',
                                      SHIPPED)):
            on = W.realip_into(start, PP)
            with open(conf, 'w') as f:
                f.write(on)
            subprocess.run([sys.executable, '-I', script, conf], check=True, stdout=subprocess.PIPE)
            with open(conf) as f:
                got = f.read()
            self.assertEqual(listens(got), listens(on))
            self.assertIn('real_ip_header proxy_protocol;', got)
            self.assertEqual(got.count('# ACME-PROXY-PROTOCOL'), 2)
            self.assertEqual(got.count('# ACME-PROXY-LOCAL'), 2)
            # And acme takes it out again after the update.
            self.assertNotIn('proxy_protocol', W.realip_into(got, OFF))


NODE_GUIDE = r"""
const vm = require('vm'), fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const a = src.indexOf('function lbServers('), b = src.indexOf('function drawHaLb(');
const ctx = {console};
vm.createContext(ctx);
vm.runInContext(src.slice(a, b) + ';this.LB_GUIDES = LB_GUIDES;', ctx);
const nodes = [{name: 'acme1', address: '10.0.0.11'}, {name: 'acme2', address: '10.0.0.12'}];
const base = {lb: '10.0.0.5', name: 'acme.example.cz', hc: '/healthz', nodes};
const priv = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
const out = {};
out.inNet = [ctx.lbInNet('10.0.0.5', '10.0.0.0/8'), ctx.lbInNet('10.0.0.5', '192.168.0.0/16'),
             ctx.lbInNet('2001:db8::5', '2001:db8::/32'), ctx.lbInNet('2001:db9::5', '2001:db8::/32'),
             ctx.lbInNet('10.0.0.5', '10.0.0.5/32'), ctx.lbInNet('10.0.0.5', '2001:db8::/32'),
             ctx.lbInNet('::ffff:10.0.0.5', '::ffff:10.0.0.0/104')];
const ex = (lb, tls) => ctx.lbAdminExposure(lb, Object.assign({}, base, {tls}));
out.ex = {
  pass_any: ex({access: {admin: {any: true, from: []}}, trusted: [], proxy_protocol: false}, 'pass'),
  pass_balancer: ex({access: {admin: {any: false, from: priv}}, trusted: [], proxy_protocol: false}, 'pass'),
  pass_outside: ex({access: {admin: {any: false, from: ['192.168.5.0/24']}}, trusted: [], proxy_protocol: false}, 'pass'),
  pass_xff: ex({access: {admin: {any: false, from: ['192.168.5.0/24']}}, trusted: ['10.0.0.5/32'], header: 'X-Forwarded-For', proxy_protocol: false}, 'pass'),
  pass_pp: ex({access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.5/32'], header: 'proxy_protocol', proxy_protocol: true}, 'pass'),
  pass_pp_any: ex({access: {admin: {any: true, from: []}}, trusted: ['10.0.0.5/32'], header: 'proxy_protocol', proxy_protocol: true}, 'pass'),
  end_ok: ex({access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.5/32'], header: 'X-Forwarded-For'}, 'end'),
  end_any: ex({access: {admin: {any: true, from: []}}}, 'end'),
  unknown: ex({}, 'pass'),
};
out.guides = {};
for (const tls of ['end', 'pass']) {
  for (const g of ctx.LB_GUIDES) {
    out.guides[g[0] + ':' + tls] = g[3](Object.assign({}, base, {tls, cp: 8443})).map(p => p[0] + '\n' + p[1]).join('\n');
  }
}
out.cert = {};
for (const k of ['haproxy', 'nginx', 'f5', 'netscaler', 'apache']) {
  out.cert[k] = ctx.lbCertPort(k, Object.assign({}, base, {tls: 'end', cp: 8443})).map(p => p[0] + '\n' + p[1]).join('\n');
}
console.log(JSON.stringify(out));
"""

# the pack as acme-page.php cuts it, and i18n.js run on texts (as test_hunt_r7_i18n)
NODE_I18N = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const root = process.argv[2];
const all = JSON.parse(fs.readFileSync(path.join(root, 'web', 'lang', 'cs.json'), 'utf8'));
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) for (const e of Object.values(all[part] || {})) {
  const from = String(e.source || ''), to = String(e.text || '');
  if (!from || !to || (to === from && part !== 'patterns')) continue;
  if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
}
const ctx = {window: {}, Map, Set, WeakMap, console, ACME_LANG_PACK: pack,
  document: {readyState: 'loading', addEventListener() {}, documentElement: {setAttribute() {}, classList: {remove() {}}},
             querySelectorAll: () => [], createTreeWalker() { return {nextNode: () => null}; }},
  MutationObserver: function () { this.observe = () => {}; this.takeRecords = () => []; }, setTimeout: () => {}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(root, 'web', 'assets', 'i18n.js'), 'utf8')
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;', ctx);
ctx.i18nInit(pack);
const out = {};
for (const s of JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which('node'), 'node needed')
class Guide(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = os.path.join(TMP, 'guide.js')
        with open(p, 'w') as f:
            f.write(NODE_GUIDE)
        got = subprocess.run(['node', p, os.path.join(ROOT, 'web', 'assets', 'admin.js')],
                             capture_output=True, text=True, check=True)
        cls.out = json.loads(got.stdout)

    def test_in_net(self):
        self.assertEqual(self.out['inNet'], [True, False, True, False, True, False, True])

    def test_red_when_passed_through_and_open(self):
        ex = self.out['ex']
        self.assertEqual((ex['pass_any']['level'], ex['pass_any']['why']), ('crit', 'any'))
        self.assertEqual((ex['pass_balancer']['level'], ex['pass_balancer']['why']), ('crit', 'balancer'))
        self.assertEqual((ex['pass_xff']['level'], ex['pass_xff']['why']), ('crit', 'xff'))
        self.assertEqual((ex['pass_pp_any']['level'], ex['pass_pp_any']['why']), ('crit', 'any'))
        self.assertEqual(ex['pass_outside']['level'], 'warn')
        self.assertEqual((ex['pass_pp']['level'], ex['pass_pp']['why']), ('good', 'proxy'))
        self.assertEqual(ex['end_ok']['level'], 'good')
        self.assertEqual(ex['end_any']['level'], 'warn')
        self.assertEqual(ex['unknown']['why'], 'unknown')

    def test_ended_publishes_the_enrolment_pages_only(self):
        g = self.out['guides']
        self.assertIn('http-request deny deny_status 404 unless acme_portal', g['haproxy:end'])
        self.assertIn('acl acme_portal path / /index.php /favicon.ico', g['haproxy:end'])
        self.assertIn('location ~ ^/(|index\\.php|favicon\\.ico|assets/.*|pki/.*)$', g['nginx:end'])
        self.assertIn('location / { return 404; }', g['nginx:end'])
        self.assertNotIn('location / {\n        proxy_pass', g['nginx:end'])
        self.assertIn('<LocationMatch "^/(?!$|index\\.php$|favicon\\.ico$|assets/|pki/)">', g['apache:end'])
        self.assertIn('rules { acme_portal_only }', g['f5:end'])
        self.assertIn('default { HTTP::respond 404 }', g['f5:end'])
        self.assertIn('-policyName acme_portal_only', g['netscaler:end'])
        for k, text in g.items():
            if k.endswith(':end'):
                # a path the filters let through is never an admin one
                for allowed in re.findall(r'"(/[a-z./*]*)"', text):
                    self.assertFalse(allowed.startswith(('/admin', '/healthz', '/metrics', '/api')),
                                     (k, allowed))

    def test_passed_through_is_l4_with_proxy(self):
        g = self.out['guides']
        self.assertIn('send-proxy-v2', g['haproxy:pass'])
        self.assertIn('proxy_protocol on;', g['nginx:pass'])
        self.assertIn('TCP::respond "PROXY', g['f5:pass'])
        self.assertNotIn('clientssl serverssl', g['f5:pass'])
        self.assertIn('-proxyProtocol ENABLED', g['netscaler:pass'])
        self.assertIn('acme_https', g['netscaler:pass'])

    def test_certificate_port_per_kind(self):
        c = self.out['cert']
        self.assertIn('mode tcp', c['haproxy'])
        self.assertIn('send-proxy-v2', c['haproxy'])
        self.assertIn('{cp}', c['haproxy'])
        self.assertIn('proxy_protocol on;', c['nginx'])
        self.assertIn('stream {', c['nginx'])
        self.assertIn('profiles add { tcp }', c['f5'])
        self.assertNotIn('clientssl', c['f5'].split('\n', 1)[1])
        self.assertIn('acme_proxy_v1', c['f5'])
        self.assertIn('SNAT', c['f5'])
        self.assertIn('add lb vserver acme_cert_vs TCP', c['netscaler'])
        self.assertIn('-proxyProtocol ENABLED', c['netscaler'])
        self.assertIn('HAProxy or nginx (stream)', c['apache'])

    def test_texts_in_czech(self):
        texts = [
            'The administration pages are for everybody now: through the balancer that is the '
            'internet. Passed through, the balancer cannot see the paths - what keeps the '
            'administration from the internet is the nodes themselves: who may reach the '
            'administration pages must be your own networks only.',
            'Settings → Firewall and access',
            'The administration pages are published through the balancer: without the PROXY '
            'protocol every client reaches the nodes as the balancer 10.0.0.5 - which is among '
            'those who may reach the administration pages (10.0.0.0/8, 192.168.0.0/16). Switch '
            'the PROXY protocol on (above) - or take the balancer\'s network out of the list.',
            'The certificate sign-in\'s port 8443: passed through the balancer (L4), the nodes '
            'take the client\'s address from its PROXY protocol.',
            '/etc/haproxy/haproxy.cfg - the certificate sign-in\'s port 8443, passed through, the '
            'client\'s address in the PROXY protocol',
            'The nodes take the client\'s own address from the PROXY protocol sent by 10.0.0.5 '
            '(port 443).',
        ]
        p = os.path.join(TMP, 'i18n.js')
        with open(p, 'w') as f:
            f.write(NODE_I18N)
        q = os.path.join(TMP, 'texts.json')
        with open(q, 'w') as f:
            json.dump(texts, f)
        got = json.loads(subprocess.run(['node', p, ROOT, q], capture_output=True, text=True,
                                        check=True).stdout)
        for s in texts:
            self.assertTrue(got.get(s), s)
            self.assertNotEqual(got[s], s)
        self.assertIn('10.0.0.5', got[texts[2]])
        self.assertIn('8443', got[texts[3]])


if __name__ == '__main__':
    unittest.main(verbosity=2)
