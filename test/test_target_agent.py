#!/usr/bin/env python3
"""Target agents (1.0.116, docs/target-agent.md): a real acme-agent - both processes, the
network side as an account of its own (setpriv, never root) - against acme's engine in this
process, both modes.

    python3 test/test_target_agent.py

What is tried: the policy and its CLI; the join (the fingerprint confirmed, a wrong one refused;
a code run out, used, of another authority refused); passive and active deployments of PEM and
PFX files with their owners and modes; a reload of an allowed unit (a systemctl of the test's
own); what the policy does not allow refused (a folder, an owner, a mode, a unit, a script's
hash, a path with .., a symbolic link) with the lines that allow it; the previous files back when
the test fails; the same certificate again changes nothing; a signed job sent twice refused, one
for another agent refused; a target switched off refused at once; the agent's certificate renewed
over the channel; an active agent's job queued in the database on one node and served by the
other; the agents' port: off (the default) - no nginx server, no firewall rule, nothing listening
- on, and off again; the package, signed.

Needs root (the agent's root side, setpriv, chown), openssl, setpriv and useradd; never touches
port 8092 nor PostgreSQL - temporary folders and ports only.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import pwd
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import http.server

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-tagent-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, runtime, store as S, agents as G  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.targets import agent as AT  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()
USER = 'acmeagt'
CAN = os.geteuid() == 0 and bool(shutil.which('setpriv')) and bool(shutil.which('openssl'))
CERTS = {}


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def read(p, mode='r'):
    with open(p, mode) as fh:
        return fh.read()


def agent_mod():
    spec = importlib.util.spec_from_file_location('acme_agent_t', AGENT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AG = agent_mod()


def setUpModule():
    if not CAN:
        return
    try:
        pwd.getpwnam(USER)
    except KeyError:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin',
                        USER], check=True)
    j = lambda n: os.path.join(TMP, n)  # noqa: E731
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '30', '-subj', '/CN=Test CA')
    for leaf in ('a', 'b'):
        openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'), '-subj',
                '/CN=www.example.test')
        with open(j('ext'), 'w') as fh:
            fh.write('subjectAltName=DNS:www.example.test\n')
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
                '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'), '-extfile', j('ext'))
        CERTS[leaf] = (j(leaf + '.crt'), j(leaf + '.key'))
    # a systemctl of the test's own (the agent is told it in agent.json): every call written
    # down; reload of broken.service fails; is-active says active
    os.makedirs(j('bin'))
    with open(j('bin/systemctl'), 'w') as fh:
        fh.write('#!/bin/sh\necho "$@" >> %s\ncase "$1 $2" in\n  "reload broken.service") exit 1;;\n'
                 '  "is-active "*) echo active;;\nesac\nexit 0\n' % j('systemctl.log'))
    os.chmod(j('bin/systemctl'), 0o755)


def tearDownModule():
    for a in list(Agent.ALL):
        a.stop()
    for s in list(Wire.ALL):
        s.stop()
    shutil.rmtree(TMP, ignore_errors=True)
    if CAN:
        subprocess.run(['userdel', USER], capture_output=True)


class Bundle(base.Bundle):
    def __init__(self, leaf='a'):
        crt, key = CERTS[leaf]
        self.cert_pem, self.key_pem = read(crt), read(key)
        self.chain_pems = [read(os.path.join(TMP, 'ca.crt'))]
        self.fullchain_pem = self.cert_pem + self.chain_pems[0]
        self.name = 'www.example.test'
        self.names = ['www.example.test']
        der = ssl.PEM_cert_to_DER_cert(self.cert_pem)
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.not_after = time.time() + 86400 * 10
        self.serial = leaf
        self.key_type = 'ec-256'
        self.alt = None
        self.crt_file, self.key_file = crt, key

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'fullchain-pem':
            return self.fullchain_pem.encode()
        if fmt == 'cert-pem':
            return self.cert_pem.encode()
        if fmt == 'key-pem':
            return self.key_pem.encode()
        if fmt in ('pfx', 'p12'):
            return openssl('pkcs12', '-export', '-inkey', self.key_file, '-in', self.crt_file,
                           '-passout', 'pass:%s' % (password or ''), '-name', alias or 'x')
        raise ValueError(fmt)


class Agent(object):
    """One acme-agent: its folders in TMP, its root side (root), its network side (setpriv to
    the test's account), its command line."""
    ALL = []

    def __init__(self, name):
        self.d = os.path.join(TMP, 'agent-' + name)
        os.makedirs(self.d)
        os.chmod(self.d, 0o755)
        self.env = dict(os.environ, ACME_AGENT_ETC=self.d + '/etc', ACME_AGENT_STATE=self.d + '/st',
                        ACME_AGENT_ROOT_STATE=self.d + '/rs', ACME_AGENT_RUN=self.d + '/run',
                        ACME_AGENT_USER=USER, ACME_AGENT_NO_SYSTEMD='1')
        os.makedirs(self.d + '/etc')
        with open(self.d + '/etc/agent.json', 'w') as fh:
            json.dump({'systemctl': os.path.join(TMP, 'bin/systemctl')}, fh)
        self.root = self.net = None
        self.www = os.path.join(self.d, 'www')
        os.makedirs(self.www + '/ssl')
        Agent.ALL.append(self)

    def cli(self, *args, ok=True):
        got = subprocess.run([sys.executable, '-I', AGENT] + list(args), env=self.env,
                             capture_output=True, text=True, timeout=60)
        if ok and got.returncode != 0:
            raise AssertionError('acme-agent %s: %s %s' % (args, got.stdout, got.stderr))
        return got

    def start_root(self):
        self.root = subprocess.Popen([sys.executable, '-I', AGENT, 'root'], env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if os.path.exists(self.d + '/run/root.sock'):
                return
            time.sleep(0.05)
        raise AssertionError('the root side did not start: %s' % self.root.stderr.read())

    def start_net(self):
        pw = pwd.getpwnam(USER)
        self.net = subprocess.Popen(['setpriv', '--reuid=%d' % pw.pw_uid, '--regid=%d' % pw.pw_gid,
                                     '--clear-groups', sys.executable, '-I', AGENT, 'serve'],
                                    env=self.env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
        time.sleep(0.6)
        if self.net.poll() is not None:
            raise AssertionError('the network side ended: %s' % self.net.stderr.read())

    def status(self):
        try:
            return json.loads(read(self.d + '/st/join-status.json'))
        except (OSError, ValueError):
            return {}

    def wait(self, state, most=30):
        end = time.time() + most
        while time.time() < end:
            if self.status().get('state') == state:
                return True
            time.sleep(0.2)
        return False

    def policy(self, *lines):
        path = self.d + '/etc/policy'
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        os.chmod(path, 0o644)

    def stop(self):
        for p in (self.net, self.root):
            if p is not None and p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
        self.net = self.root = None
        if self in Agent.ALL:
            Agent.ALL.remove(self)


class WireHandler(http.server.BaseHTTPRequestHandler):
    """What nginx's server of the agents' port and web/agent.php do: the client certificate
    checked against the agent authority (nginx), handed with the body to the daemon's wire."""
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def do_POST(self):
        op = {'/agent/v1/join': 'join', '/agent/v1/join/status': 'status',
              '/agent/v1/poll': 'poll'}.get(self.path)
        n = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(n) or b'{}')
        der = self.connection.getpeercert(True)
        if op is None:
            st, out = 404, {'ok': False}
        elif op == 'poll' and not der:
            st, out = 403, {'ok': False, 'said': 'nginx: no certificate'}
        else:
            self.server.seen.append(op)
            st, out = G.wire(self.server.store, op, body,
                             ssl.DER_cert_to_PEM_cert(der) if der else '',
                             'SUCCESS' if der else 'NONE', self.client_address[0])
        raw = json.dumps(out).encode()
        self.send_response(st)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Wire(object):
    """One node's agents' port: its own database connection (as the other node of a cluster
    has its own), the same database."""
    ALL = []

    def __init__(self, store, port=None):
        self.port = port or free_port()
        c = G.ctl(store)
        a = G.ca(store)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        for n, v in (('c.pem', c['cert_pem']), ('k.pem', c['key_pem']), ('a.pem', a['cert_pem'])):
            with open(os.path.join(TMP, 'w%d-%s' % (self.port, n)), 'w') as fh:
                fh.write(v)
        ctx.load_cert_chain(os.path.join(TMP, 'w%d-c.pem' % self.port),
                            os.path.join(TMP, 'w%d-k.pem' % self.port))
        ctx.load_verify_locations(os.path.join(TMP, 'w%d-a.pem' % self.port))
        ctx.verify_mode = ssl.CERT_OPTIONAL
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), WireHandler)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.srv.store = store
        self.srv.seen = []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        Wire.ALL.append(self)

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        if self in Wire.ALL:
            Wire.ALL.remove(self)


def target(name, **cfg):
    rid = A.family_save(STORE, 'target', {'name': name, 'kind': 'agent', 'config': cfg,
                                         'enabled': 1}, 'tester')
    return S.plugin_row(STORE, 'target', rid)


def module(row, deploy_id=1):
    ctx = runtime.RunContext(STORE, None, scope='target:%s' % row['name'])
    ctx.target_name = row['name']
    ctx.deploy_id = deploy_id
    t = S.plugin_class('target', 'agent')(S.plugin_config('target', row), ctx)
    t._sleep = lambda s: None
    return t, ctx


def join_passive(test, name, port):
    row = target(name, mode='passive', host='127.0.0.1', port=port, timeout=20)
    code = G.code_new(STORE, row, 'tester')['code']
    ag = Agent(name)
    ag.start_root()
    out = ag.cli('join', code, '--no-wait', '--listen', '127.0.0.1')
    test.assertIn('confirm it there', out.stdout)
    ag.start_net()
    for _ in range(50):
        got = G.look(STORE, row, 'tester')
        if got.get('pending'):
            break
        time.sleep(0.2)
    test.assertTrue(got.get('pending'), got)
    fp = ag.cli('fingerprint').stdout.strip()
    test.assertEqual(fp, got['pending']['fp_words'])
    G.confirm(STORE, row, fp, 'tester')
    got = G.look(STORE, row, 'tester')
    test.assertTrue(ag.wait('joined'), ag.status())
    return row, ag


ALLOW_WWW = None


def www_policy(ag, *more):
    ag.policy('allow file %s owner=root:%s mode=0644' % (ag.www + '/ssl', USER),
              'allow unit nginx reload', 'allow test -- /bin/true', 'allow test -- /bin/false',
              *more)


DEPLOY = {'outputs': 'fullchain-pem {www}/ssl/site.crt 0644 root:%s\n'
                     'key-pem {www}/ssl/site.key 0640 root:%s\n'
                     'pfx {www}/ssl/site.pfx 0640 root:%s' % (USER, USER, USER),
          'test_cmd': '/bin/true', 'reload_cmd': 'systemctl reload nginx',
          'pfx_password': 'secret-pw', 'backup': True, 'backup_format': 'dated'}


def opts(ag, **more):
    o = {k: (v.replace('{www}', ag.www) if isinstance(v, str) else v) for k, v in DEPLOY.items()}
    o.update(more)
    return o


def reloads():
    try:
        return read(os.path.join(TMP, 'systemctl.log')).count('reload nginx.service')
    except OSError:
        return 0


# ---------------------------------------------------------------------------------------------
class Policy(unittest.TestCase):
    def test_default_allows_nothing_and_lines(self):
        pol = AG.parse_policy('')
        self.assertEqual(pol['files'], [])
        with self.assertRaises(AG.Refused) as e:
            AG.plan_check(pol, {'files': [{'path': '/etc/x/a.pem', 'mode': 0o600}],
                                'reload': [{'unit': 'nginx', 'verb': 'reload'}]})
        allow = [n['allow'] for n in e.exception.needs]
        self.assertIn('acme-agent allow unit nginx.service reload', allow)
        self.assertTrue(any(a.startswith('acme-agent allow file /etc/x ') for a in allow))
        pol = AG.parse_policy('allow file /etc/x owner=root:root mode=0640\n'
                              'allow unit nginx reload\nnonsense here\nallow test -- nginx -t\n')
        self.assertEqual(len(pol['problems']), 1)
        plan = AG.plan_check(pol, {'files': [{'path': '/etc/x/a.pem', 'mode': 0o600}],
                                   'reload': [{'unit': 'nginx', 'verb': 'reload'}],
                                   'test': [{'argv': ['nginx', '-t']}]})
        self.assertEqual(plan['files'][0]['owner'], 'root')
        for bad in ({'files': [{'path': '/etc/x/a.pem', 'mode': 0o644}]},
                    {'files': [{'path': '/etc/x/a.pem', 'mode': 0o600, 'owner': 'nobody:root'}]},
                    {'files': [{'path': '/etc/xy/a.pem', 'mode': 0o600}]},
                    {'reload': [{'unit': 'nginx', 'verb': 'restart'}]},
                    {'test': [{'argv': ['nginx', '-T']}]},
                    {'script': {'mode': 'inline', 'body': 'echo hi', 'interp': 'sh'}}):
            with self.assertRaises(AG.Refused):
                AG.plan_check(pol, bad)
        for bad in ('/etc/x/../shadow', '/etc/x/./../y', 'relative', '/etc/x/a\nb'):
            with self.assertRaises(AG.Refused):
                AG.plan_check(pol, {'files': [{'path': bad, 'mode': 0o600}]})

    def test_commands_as_operations(self):
        self.assertEqual(AT.cmd_ops('systemctl reload nginx'), [{'unit': 'nginx', 'verb': 'reload'}])
        self.assertEqual(AT.cmd_ops('nginx -t'), [{'argv': ['nginx', '-t']}])
        self.assertEqual(AT.cmd_ops('doveconf -n >/dev/null'), [{'argv': ['doveconf', '-n']}])
        self.assertEqual(AT.cmd_ops('systemctl reload apache2 2>/dev/null || systemctl reload httpd'),
                         [{'any': [{'unit': 'apache2', 'verb': 'reload'},
                                   {'unit': 'httpd', 'verb': 'reload'}]}])
        self.assertEqual(AT.cmd_ops('/usr/local/bin/x.sh a b'),
                         [{'script': '/usr/local/bin/x.sh', 'args': ['a', 'b']}])
        for bad in ('kubectl x | kubectl apply -f -', 'rm -rf /; true', 'echo $(id)', 'a > /etc/x',
                    'systemctl stop nginx'):
            with self.assertRaises(base.PluginError):
                AT.cmd_ops(bad)

    @unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
    def test_cli_allow_deny_show(self):
        ag = Agent('cli')
        os.makedirs(ag.d + '/real')
        os.symlink(ag.d + '/real', ag.d + '/link')
        ag.cli('allow', 'file', ag.d + '/link', '--owner', 'root:root', '--mode', '0640')
        ag.cli('allow', 'unit', 'nginx', 'reload')
        ag.cli('allow', 'unit', 'nginx', 'restart')
        ag.cli('allow', 'test', '--', 'nginx', '-t')
        with open(ag.d + '/s.sh', 'w') as fh:
            fh.write('#!/bin/sh\necho hi\n')
        ag.cli('allow', 'script', ag.d + '/s.sh')
        ag.cli('deny', 'unit', 'nginx', 'restart')
        show = ag.cli('policy', 'show', '--json').stdout
        pol = json.loads(show)
        self.assertEqual(pol['files'][0]['dir'], ag.d + '/real')      # the real folder
        self.assertEqual(pol['units'], {'nginx.service': ['reload']})
        self.assertEqual(pol['tests'], [['nginx', '-t']])
        self.assertEqual(pol['scripts'][0]['sha256'],
                         hashlib.sha256(b'#!/bin/sh\necho hi\n').hexdigest())
        self.assertEqual(os.stat(ag.d + '/etc/policy').st_mode & 0o777, 0o644)
        # a policy somebody but root may write is no policy
        os.chmod(ag.d + '/etc/policy', 0o666)
        self.assertEqual(json.loads(ag.cli('policy', 'show', '--json').stdout)['files'], [])
        ag.stop()


# ---------------------------------------------------------------------------------------------
@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class Passive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.row, cls.ag = join_passive(cls(), 'web1', cls.port)
        www_policy(cls.ag)

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def t(self, n=1):
        return module(S.plugin_row(STORE, 'target', 'web1'), n)

    def test_0_unprivileged_network_side(self):
        uid = None
        for line in read('/proc/%d/status' % self.ag.net.pid).splitlines():
            if line.startswith('Uid:'):
                uid = [int(x) for x in line.split()[1:]]
        self.assertEqual(set(uid), {pwd.getpwnam(USER).pw_uid})
        self.assertTrue(any(line.startswith('NoNewPrivs:\t1')
                            for line in read('/proc/%d/status' % self.ag.net.pid).splitlines()))
        # it refuses to run as root
        got = self.ag.cli('serve', ok=False)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('never as root', got.stderr)

    def test_1_hello_and_policy(self):
        t, _ctx = self.t()
        said = t.test()
        self.assertIn('1 folder', said)
        info = G.info(STORE, S.plugin_row(STORE, 'target', 'web1'))
        self.assertEqual(info['state'], 'answers')
        self.assertEqual(info['policy_summary']['units'], 1)
        self.assertEqual(info['mode'], 'passive')

    def test_2_deploy_pem_pfx_then_the_same(self):
        t, ctx = self.t(1)
        n0 = reloads()
        said = t.deploy(Bundle('a'), opts(self.ag))
        self.assertIn('3 files written', said)
        crt, key, pfx = (os.path.join(self.ag.www, 'ssl', n) for n in ('site.crt', 'site.key',
                                                                        'site.pfx'))
        self.assertEqual(read(crt), Bundle('a').fullchain_pem)
        st = os.stat(key)
        self.assertEqual(st.st_mode & 0o777, 0o640)
        self.assertEqual(st.st_uid, 0)
        self.assertEqual(st.st_gid, pwd.getpwnam(USER).pw_gid)
        self.assertEqual(read(key), Bundle('a').key_pem)
        self.assertGreater(len(read(pfx, 'rb')), 100)
        self.assertEqual(reloads(), n0 + 1)
        # the same certificate again: nothing replaced, nothing run
        t, ctx = self.t(1)
        said = t.deploy(Bundle('a'), opts(self.ag))
        self.assertTrue(said.startswith('unchanged'), said)
        self.assertEqual(reloads(), n0 + 1)
        # another one: replaced, the old ones kept as dated copies
        t, ctx = self.t(1)
        t.deploy(Bundle('b'), opts(self.ag))
        self.assertEqual(read(key), Bundle('b').key_pem)
        self.assertTrue([n for n in os.listdir(os.path.dirname(key))
                         if n.startswith('site.key.') and n.endswith('.bak')])
        self.assertEqual(reloads(), n0 + 2)
        # no secret in what the agent says or in its audit log
        audit = read(self.ag.d + '/rs/audit.log')
        self.assertNotIn('PRIVATE KEY', audit)
        self.assertNotIn('secret-pw', audit)

    def test_3_rollback_on_a_failed_test(self):
        t, ctx = self.t(1)
        t.deploy(Bundle('a'), opts(self.ag))
        before = read(os.path.join(self.ag.www, 'ssl', 'site.key'))
        n0 = reloads()
        t, ctx = self.t(1)
        with self.assertRaises(base.PluginError) as e:
            t.deploy(Bundle('b'), opts(self.ag, test_cmd='/bin/false'))
        self.assertIn('previous files are back', str(e.exception))
        self.assertEqual(read(os.path.join(self.ag.www, 'ssl', 'site.key')), before)
        self.assertEqual(reloads(), n0)

    def test_4_refused_outside_the_policy(self):
        os.makedirs(self.ag.d + '/other', exist_ok=True)
        for o, want in (({'outputs': 'fullchain-pem %s/other/x.crt 0644' % self.ag.d},
                         'acme-agent allow file %s/other' % self.ag.d),
                        ({'reload_cmd': 'systemctl restart nginx'},
                         'acme-agent allow unit nginx.service restart'),
                        ({'outputs': 'fullchain-pem %s/ssl/x.crt 0666 root:%s' % (self.ag.www, USER)},
                         '--mode 0666'),
                        ({'script_mode': 'inline', 'script_body': 'echo hello', 'script_interp': 'sh'},
                         'acme-agent allow script-hash ' + hashlib.sha256(b'echo hello').hexdigest()),
                        ({'test_cmd': 'nginx -t'}, 'acme-agent allow test -- nginx -t')):
            t, ctx = self.t(2)
            with self.assertRaises(base.PluginError) as e:
                t.deploy(Bundle('a'), opts(self.ag, **o))
            self.assertIn('not allowed by the policy', str(e.exception))
            self.assertIn(want, e.exception.detail or '', o)
        self.assertFalse(os.path.exists(self.ag.d + '/other/x.crt'))
        # the preview says it before anything runs
        t, ctx = self.t(2)
        pv = t.preview(Bundle('a'), opts(self.ag, reload_cmd='systemctl restart nginx'))
        bad = [i for i in pv['agent']['items'] if i['ok'] is False]
        self.assertEqual([i['allow'] for i in bad], ['acme-agent allow unit nginx.service restart'])
        self.assertTrue(all(i['ok'] for i in pv['agent']['items'] if i['kind'] == 'file'))

    def test_5_script_by_its_hash(self):
        body = '#!/bin/sh\necho "the script saw $ACME_CN"\n'
        o = opts(self.ag, script_mode='inline', script_body=body, script_interp='sh')
        t, ctx = self.t(3)
        with self.assertRaises(base.PluginError):
            t.deploy(Bundle('b'), o)
        www_policy(self.ag, 'allow script-hash %s' % hashlib.sha256(body.encode()).hexdigest())
        t, ctx = self.t(3)
        t.deploy(Bundle('b'), dict(o, skip_same=False))
        self.assertTrue(any('the script saw www.example.test' in str(s) for s in ctx.steps),
                        ctx.steps)
        www_policy(self.ag)

    def test_6_traversal_and_links(self):
        row = S.plugin_row(STORE, 'target', 'web1')
        os.symlink('/etc', self.ag.www + '/ssl/evil')
        try:
            for path in (self.ag.www + '/ssl/../../x.pem', self.ag.www + '/ssl/evil/x.pem'):
                got = G.call(STORE, row, 'deploy', {'files': [
                    {'path': path, 'mode': 0o644, 'owner': 'root:' + USER,
                     'data': base64.b64encode(b'x').decode()}]}, timeout=20)
                self.assertFalse(got['ok'], path)
            self.assertFalse(os.path.exists('/etc/x.pem'))
            # a link where the file goes
            os.symlink('/etc/hostname', self.ag.www + '/ssl/link.pem')
            got = G.call(STORE, row, 'deploy', {'files': [
                {'path': self.ag.www + '/ssl/link.pem', 'mode': 0o644, 'owner': 'root:' + USER,
                 'data': base64.b64encode(b'x').decode()}]}, timeout=20)
            self.assertFalse(got['ok'])
            self.assertIn('symbolic link', got['said'])
        finally:
            for n in ('evil', 'link.pem'):
                try:
                    os.unlink(self.ag.www + '/ssl/' + n)
                except OSError:
                    pass

    def test_7_replay_and_foreign_id(self):
        row = S.plugin_row(STORE, 'target', 'web1')
        st = G.state(STORE, row['id'])
        _jid, env = G.sign_job(STORE, st['agent_id'], 'hello', {})
        got, _p = G._passive_post(STORE, row, '/v1/job', env)
        self.assertTrue(got['ok'])
        got, _p = G._passive_post(STORE, row, '/v1/job', env)
        self.assertFalse(got['ok'])
        self.assertIn('seen before', got['said'])
        _jid, env = G.sign_job(STORE, 'ag-000000000000', 'hello', {})
        got, _p = G._passive_post(STORE, row, '/v1/job', env)
        self.assertIn('another agent', got['said'])
        # signed by another key
        job = json.loads(G.sign_job(STORE, st['agent_id'], 'hello', {})[1]['job'])
        forged = json.dumps(job, sort_keys=True, separators=(',', ':'))
        sig = E.ed25519_sign(b'\x01' * 32, b'acme-agent/1 job\n' + forged.encode())
        got, _p = G._passive_post(STORE, row, '/v1/job', {'job': forged,
                                                         'sig': base64.b64encode(sig).decode()})
        self.assertIn('not signed by the acme', got['said'])
        # a client certificate that is not acme's: refused by the agent's TLS
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with self.assertRaises((ssl.SSLError, OSError, ConnectionError)):
            with socket.create_connection(('127.0.0.1', self.port), 5) as s:
                with ctx.wrap_socket(s) as tls:
                    tls.sendall(b'POST /v1/job HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}')
                    if not tls.recv(100):
                        raise ConnectionError('closed')

    def test_8_renewal(self):
        row = S.plugin_row(STORE, 'target', 'web1')
        old = G.state(STORE, row['id'])['cert_fp']
        G.renew_cert(STORE, row, 'tester')
        st = G.state(STORE, row['id'])
        self.assertNotEqual(st['cert_fp'], old)
        self.assertGreater(st['cert_end'], time.time() + 29 * 86400)
        t, _ctx = self.t()
        t.test()                                        # with the new certificate
        cur = ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(read(self.ag.d + '/st/tls.crt')))
        self.assertEqual(G.fp_of_pem(cur), st['cert_fp'])

    def test_9_switched_off_refused(self):
        row = S.plugin_row(STORE, 'target', 'web1')
        STORE.db.run('UPDATE cert_targets SET enabled = 0 WHERE id = ?', (row['id'],))
        try:
            t, _ctx = self.t()
            with self.assertRaises(base.PluginError) as e:
                t.test()
            self.assertIn('switched off', str(e.exception))
        finally:
            STORE.db.run('UPDATE cert_targets SET enabled = 1 WHERE id = ?', (row['id'],))


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class JoinRefused(unittest.TestCase):
    def test_wrong_fingerprint_expired_used_and_wrong_pin(self):
        port = free_port()
        row = target('web3', mode='passive', host='127.0.0.1', port=port, timeout=10)
        code = G.code_new(STORE, row, 'tester')['code']
        # another authority named in the code: the agent refuses acme's answer
        raw = json.loads(base64.urlsafe_b64decode(code[6:] + '=' * (-len(code[6:]) % 4)))
        raw['ca'] = 'ab' * 32
        bad = 'ACAG1.' + base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip('=')
        ag = Agent('web3')
        ag.start_root()
        ag.cli('join', bad, '--no-wait', '--listen', '127.0.0.1')
        ag.start_net()
        got = G.look(STORE, row, 'tester')
        self.assertFalse(got.get('pending'))
        self.assertIn('authority', got.get('said', ''))
        self.assertTrue(ag.wait('refused', 5))
        ag.stop()
        # the right code, a wrong fingerprint confirmed
        ag = Agent('web3b')
        ag.start_root()
        ag.cli('join', code, '--no-wait', '--listen', '127.0.0.1')
        ag.start_net()
        got = G.look(STORE, row, 'tester')
        self.assertTrue(got.get('pending'), got)
        with self.assertRaises(base.PluginError):
            G.confirm(STORE, row, 'ab' * 32, 'tester')
        # used: another agent with the same code is refused
        ag2 = Agent('web3c')
        ag2.start_root()
        ag2.cli('join', code, '--no-wait', '--listen', '127.0.0.1')
        st = G.state(STORE, row['id'])
        self.assertTrue(st['code']['used'])
        ag.stop()
        ag2.stop()
        # run out: refused by acme (the agent's request)
        st = G.state(STORE, row['id'])
        st['code']['used'] = False
        st['code']['until'] = time.time() - 1
        st.pop('pending', None)
        G.state_put(STORE, row['id'], st)
        c = st['code']
        with self.assertRaises(base.PluginError) as e:
            G.join_take(STORE, row, st, c, 'x', {'csr': '', 'enc_pub': '', 'nonce': '0' * 32,
                                                'proof': ''})
        self.assertIn('ran out', str(e.exception))
        # the agent refuses a code that ran out itself
        ag3 = Agent('web3d')
        raw['u'] = int(time.time()) - 5
        late = 'ACAG1.' + base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip('=')
        got = ag3.cli('join', late, '--no-wait', ok=False)
        self.assertIn('ran out', got.stderr)
        ag3.stop()


# ---------------------------------------------------------------------------------------------
@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class Active(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0

    def test_active_join_deploy_ha_and_off(self):
        E.CONFIG['certs_agents_active'] = 0
        with self.assertRaises(ValueError):
            target('web2', mode='active', host='web2.example.test')
        E.CONFIG['certs_agents_active'] = 1
        # two nodes: each its own connection to the one database, its own agents' port
        node_a = Wire(STORE)
        other = E.Storage(E.open_db())
        node_b = Wire(other)
        E.CONFIG['certs_agents_names'] = '127.0.0.1:%d 127.0.0.1:%d' % (node_a.port, node_b.port)
        row = target('web2', mode='active', host='web2.example.test')
        code = G.code_new(STORE, row, 'tester')
        self.assertEqual(code['endpoints'], ['127.0.0.1:%d' % node_a.port,
                                             '127.0.0.1:%d' % node_b.port])
        ag = Agent('web2')
        www_policy(ag)
        ag.start_root()
        ag.cli('join', code['code'], '--no-wait')
        ag.start_net()
        for _ in range(100):
            if G.info(STORE, row).get('pending'):
                break
            time.sleep(0.1)
        info = G.info(STORE, row)
        self.assertEqual(info['pending']['fp_words'], ag.cli('fingerprint').stdout.strip())
        self.assertTrue(ag.wait('confirm', 10))
        G.confirm(STORE, row, info['pending']['fp'], 'tester')
        self.assertTrue(ag.wait('joined', 20), ag.status())
        # node A goes away: its jobs are queued in the database, node B hands them over
        node_a.stop()
        b_seen = len(node_b.srv.seen)
        t, ctx = module(row, 7)
        said = t.deploy(Bundle('a'), opts(ag))
        self.assertIn('3 files written', said)
        self.assertEqual(read(os.path.join(ag.www, 'ssl', 'site.key')), Bundle('a').key_pem)
        self.assertGreater(len(node_b.srv.seen), b_seen)
        self.assertIn('waiting for the agent', ' '.join(str(s) for s in ctx.steps))
        t, ctx = module(row, 7)
        self.assertTrue(t.deploy(Bundle('a'), opts(ag)).startswith('unchanged'))
        # switched off: the agent's next poll is refused at once
        STORE.db.run('UPDATE cert_targets SET enabled = 0 WHERE id = ?', (row['id'],))
        pem = read(ag.d + '/st/tls.crt')
        st, out = G.wire(STORE, 'poll', {}, pem, 'SUCCESS')
        self.assertEqual(st, 403)
        STORE.db.run('UPDATE cert_targets SET enabled = 1 WHERE id = ?', (row['id'],))
        st, out = G.wire(STORE, 'poll', {'results': []}, pem, 'SUCCESS')
        self.assertEqual(st, 200)
        self.assertEqual(G.wire(STORE, 'poll', {}, pem, 'NONE')[0], 403)
        # forgotten: refused
        G.forget(STORE, row, 'tester')
        self.assertEqual(G.wire(STORE, 'poll', {}, pem, 'SUCCESS')[0], 403)
        # the port off: nothing is answered
        E.CONFIG['certs_agents_active'] = 0
        self.assertEqual(G.wire(STORE, 'poll', {}, pem, 'SUCCESS')[0], 404)
        ag.stop()
        node_b.stop()


# ---------------------------------------------------------------------------------------------
class AgentsPort(unittest.TestCase):
    """Off (the default) as before: no server of nginx, no rule of the firewall, nothing in the
    request to root; on: all of it; off again: taken away."""

    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k = 'agents:port_was_on'")
        E.CONFIG['certs_agents_active'] = 0

    def test_off_as_before_on_off_again(self):
        self.assertIsNone(E.agents_desired(STORE))
        d = E.web_desired(STORE)
        self.assertNotIn('agents', d)
        self.assertEqual(E.certs_agents_firewall(STORE, E.node_name()), [])
        self.assertNotIn('agents', [x['key'] for x in E.fw_auto(STORE, E.node_name())])
        # root's helper given exactly what it was before (nothing of the agents)
        w = load_web()
        self.assertIsNone(w.agents_checked(None))
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_port'] = 8444
        d = E.web_desired(STORE)
        self.assertEqual(d['agents']['port'], 8444)
        self.assertEqual([r['port'] for r in E.certs_agents_firewall(STORE, 'n1')[0]['rules']],
                         ['8444', '8444'])
        self.assertIn('agents', [x['key'] for x in E.fw_auto(STORE, E.node_name())])
        got = w.agents_checked(d['agents'])
        self.assertEqual(got['port'], 8444)
        E.CONFIG['certs_agents_active'] = 0
        self.assertEqual(E.agents_desired(STORE), {'port': 0})
        self.assertEqual(w.agents_checked({'port': 0}), {'port': 0})

    @unittest.skipUnless(shutil.which('nginx') and os.path.exists('/etc/nginx/fastcgi_params'),
                         'needs nginx')
    def test_nginx_server_written_taken_away_and_valid(self):
        T = tempfile.mkdtemp(dir=TMP)
        for d in ('conf.d', 'certs', 'logs'):
            os.makedirs(os.path.join(T, d))
        tpl = read(os.path.join(ROOT, 'deploy', 'nginx-acme.conf'))
        p80, p443 = free_port(), free_port()
        tpl = tpl.replace('listen      [::]:80;', '').replace('listen      [::]:443 ssl http2;', '')
        import re
        tpl = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', tpl)
        tpl = re.sub(r'(?m)^\s*listen\s+80;\n', '    listen 127.0.0.1:%d;\n' % p80, tpl)
        tpl = re.sub(r'(?m)^\s*listen\s+443 ssl http2;\n', '    listen 127.0.0.1:443 ssl;\n', tpl)
        tpl = tpl.replace('/etc/nginx/certs', T + '/certs').replace('/var/log/nginx', T + '/logs')
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-days', '2', '-subj', '/CN=n1', '-keyout', T + '/certs/acme.key', '-out',
                T + '/certs/acme.pem')
        with open(T + '/conf.d/acme.conf', 'w') as fh:
            fh.write(tpl)
        before = {n: read(os.path.join(T, 'conf.d', n)) for n in os.listdir(T + '/conf.d')}
        os.environ.update(ACME_VIP_NGINX_DIR=T + '/conf.d', ACME_VIP_CERT_DIR=T + '/certs')
        try:
            w = load_web('nginx')
        finally:
            for k in ('ACME_VIP_NGINX_DIR', 'ACME_VIP_CERT_DIR'):
                os.environ.pop(k, None)
        w.NO_SERVICES = True
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_port'] = p443 if p443 != 443 else 8444
        ag = E.agents_desired(STORE)
        main = read(T + '/conf.d/acme.conf')
        text = w.agents_text(main, w.agents_checked(ag))
        self.assertIn('ssl_verify_client      optional', text)
        self.assertIn('if ($ssl_client_verify != SUCCESS) { return 403; }', text)
        self.assertIn('listen      127.0.0.1:%d ssl;' % ag['port'], text)
        self.assertIn('ssl_protocols          TLSv1.3;', text)
        for k, v in (('ca', ag['ca']), ('cert', ag['cert']), ('key', ag['key'])):
            with open(w.AGENTS_FILES[k], 'w') as fh:
                fh.write(v)
        with open(w.NGINX_AGENTS, 'w') as fh:
            fh.write(text)
        conf = T + '/nginx.conf'
        shutil.copy('/etc/nginx/fastcgi_params', T + '/fastcgi_params')
        with open(conf, 'w') as fh:
            fh.write('pid %s/nginx.pid; error_log %s/logs/error.log;\nevents {}\n'
                     'http { include %s/conf.d/*.conf; }\n' % (T, T, T))
        got = subprocess.run(['nginx', '-t', '-p', T, '-c', conf], capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        # off again: root takes the server and its files away - conf.d as it was
        r = {'agents': {'port': 0}}
        for p in [w.NGINX_AGENTS] + list(w.AGENTS_FILES.values()):
            self.assertTrue(os.path.exists(p))
        gone = [p for p in [w.NGINX_AGENTS] + list(w.AGENTS_FILES.values()) if os.path.exists(p)]
        for p in gone:
            os.unlink(p)
        self.assertEqual(r['agents'], w.agents_checked({'port': 0}))
        after = {n: read(os.path.join(T, 'conf.d', n)) for n in os.listdir(T + '/conf.d')}
        self.assertEqual(before, after)
        E.CONFIG['certs_agents_active'] = 0


def load_web(tag='x'):
    spec = importlib.util.spec_from_file_location('acme_web_ag_' + tag,
                                                  os.path.join(ROOT, 'deploy', 'acme_web.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


class Package(unittest.TestCase):
    def test_built_and_signed(self):
        d = tempfile.mkdtemp(dir=TMP)
        key = os.path.join(d, 'k.pem')
        openssl('genpkey', '-algorithm', 'ed25519', '-out', key)
        pub = os.path.join(d, 'keys')
        os.makedirs(pub)
        openssl('pkey', '-in', key, '-pubout', '-out', os.path.join(pub, 'test-1.pub'))
        dest = os.path.join(d, 'acme-agent-9.9.9.tar.gz')
        G.build_package(dest, '9.9.9', key=key, keys_dir=pub, epoch=1700000000)
        import tarfile
        with tarfile.open(dest) as tar:
            names = tar.getnames()
            man = tar.extractfile('acme-agent-9.9.9/MANIFEST').read()
            sig = tar.extractfile('acme-agent-9.9.9/MANIFEST.sig').read()
            prog = tar.extractfile('acme-agent-9.9.9/acme_agent.py').read()
        for n in ('acme_agent.py', 'install.sh', 'acme-agent.service', 'acme-agent-root.service',
                  'README.md', 'release', 'release-keys/test-1.pub'):
            self.assertIn('acme-agent-9.9.9/' + n, names)
        self.assertIn(hashlib.sha256(prog).hexdigest().encode() + b'  acme_agent.py', man)
        with open(os.path.join(d, 'm'), 'wb') as fh:
            fh.write(man)
        with open(os.path.join(d, 's'), 'wb') as fh:
            fh.write(sig)
        got = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
                              os.path.join(pub, 'test-1.pub'), '-rawin', '-in',
                              os.path.join(d, 'm'), '-sigfile', os.path.join(d, 's')],
                             capture_output=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        # the same bytes again (reproducible)
        again = os.path.join(d, 'again.tar.gz')
        G.build_package(again, '9.9.9', key=key, keys_dir=pub, epoch=1700000000)
        self.assertEqual(read(dest, 'rb'), read(again, 'rb'))
        # tools/release.py: acme's package holds the agent's, signed by the same key (into a
        # temporary folder - never release/, never the real key)
        spec = importlib.util.spec_from_file_location('release_t', os.path.join(ROOT, 'tools',
                                                                                 'release.py'))
        R = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(R)
        R.RELEASE_DIR = os.path.join(d, 'release')
        R.KEYS_DIR = pub
        os.makedirs(R.RELEASE_DIR)
        ver = R.read_version()
        R.checks_before = lambda version, files: True
        built, why = R.build(ver, key, force=True, epoch=1700000000)
        self.assertTrue(built, why)
        side = os.path.join(R.RELEASE_DIR, 'acme-agent-%s.tar.gz' % ver)
        self.assertTrue(os.path.exists(side))
        with tarfile.open(built['path']) as tar:
            man = tar.extractfile('acme-%s/MANIFEST' % ver).read().decode()
            inner = tar.extractfile('acme-%s/deploy/agent/acme-agent-%s.tar.gz' % (ver, ver)).read()
        self.assertIn('%s  deploy/agent/acme-agent-%s.tar.gz' % (hashlib.sha256(inner).hexdigest(),
                                                                 ver), man)
        self.assertEqual(inner, read(side, 'rb'))
        # unsigned, for a source tree
        p = G.package()
        self.assertFalse(p['signed'])
        self.assertEqual(p['sha256'], hashlib.sha256(read(p['path'], 'rb')).hexdigest())



# ---- phase 3: the key made by the agent, tests through it, the connector, What happens -------
def sign_csr_test(csr_pem, days=10):
    """A certificate of the test CA for a CSR (as a source signs one the device made)."""
    d = tempfile.mkdtemp(dir=TMP)
    with open(os.path.join(d, 'r.csr'), 'w') as fh:
        fh.write(csr_pem)
    with open(os.path.join(d, 'ext'), 'w') as fh:
        fh.write('subjectAltName=DNS:www.example.test\n')
    openssl('x509', '-req', '-in', os.path.join(d, 'r.csr'), '-CA', os.path.join(TMP, 'ca.crt'),
            '-CAkey', os.path.join(TMP, 'ca.key'), '-CAcreateserial', '-days', str(days),
            '-out', os.path.join(d, 'r.crt'), '-extfile', os.path.join(d, 'ext'))
    return read(os.path.join(d, 'r.crt'))


class KeylessBundle(base.Bundle):
    """A certificate whose key the agent made: acme holds none (bundle.key_pem None)."""
    def __init__(self, cert_pem):
        self.cert_pem, self.key_pem = cert_pem, None
        self.chain_pems = [read(os.path.join(TMP, 'ca.crt'))]
        self.fullchain_pem = self.cert_pem + self.chain_pems[0]
        self.name = 'www.example.test'
        self.names = ['www.example.test']
        self.fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem)).hexdigest()
        self.not_after = time.time() + 86400 * 10
        self.serial = self.fingerprint[:8]
        self.key_type = 'ec-256'
        self.alt = None

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'fullchain-pem':
            return self.fullchain_pem.encode()
        if fmt == 'cert-pem':
            return self.cert_pem.encode()
        raise base.PluginError('no key here', retry=False)


def spki(pem):
    return AG.spki_fp(pem)


def req_for(o, keep=False):
    r = base.CertRequest(names=['www.example.test'], sans=['www.example.test'], key_type='ec-256',
                         subject={'CN': 'www.example.test'}, profile={}, options=o,
                         name='www.example.test', cert_id=1, target='web4')
    r.reuse_key = keep
    return r


class TlsServer(object):
    """A TLS server on 127.0.0.1 serving the test certificate `leaf` (a probe's other end)."""
    def __init__(self, leaf='a'):
        self.port = free_port()
        crt, key = CERTS[leaf]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        both = os.path.join(TMP, 'srv-%d.pem' % self.port)
        with open(both, 'w') as fh:
            fh.write(read(crt) + read(os.path.join(TMP, 'ca.crt')))
        ctx.load_cert_chain(both, key)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(8)
        self.ctx = ctx
        self.stop_ = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop_:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(c, server_side=True) as t:
                    t.settimeout(3)
                    try:
                        t.recv(10)
                    except (OSError, ssl.SSLError):
                        pass
            except (OSError, ssl.SSLError):
                pass

    def stop(self):
        self.stop_ = True
        self.sock.close()


class Echo(object):
    """A TCP echo server on 127.0.0.1 (what a connector reaches)."""
    def __init__(self):
        self.port = free_port()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(8)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        with c:
            while True:
                d = c.recv(4096)
                if not d:
                    return
                c.sendall(b'echo:' + d)

    def stop(self):
        self.sock.close()


class PolicyPhase3(unittest.TestCase):
    def test_probe_connect_self_update_entries(self):
        pol = AG.parse_policy('allow probe local\nallow probe www.example.test:443\n'
                              'allow connect [2001:db8::1]:22\nallow connect 10.0.0.5:22\n'
                              'allow self-update\nallow probe nonsense\n')
        self.assertEqual(len(pol['problems']), 1)
        self.assertTrue(pol['probe_local'])
        self.assertTrue(AG.dest_allowed(pol, '127.0.0.1', 8443, 'probe'))
        self.assertTrue(AG.dest_allowed(pol, '::1', 993, 'probe'))
        self.assertTrue(AG.dest_allowed(pol, 'www.example.test', 443, 'probe'))
        self.assertFalse(AG.dest_allowed(pol, 'www.example.test', 8443, 'probe'))
        self.assertFalse(AG.dest_allowed(pol, '127.0.0.1', 22, 'connect'))  # probes are not hops
        self.assertTrue(AG.dest_allowed(pol, '2001:db8::1', 22, 'connect'))
        self.assertTrue(AG.dest_allowed(pol, '10.0.0.5', 22, 'connect'))
        self.assertFalse(AG.dest_allowed(pol, '10.0.0.6', 22, 'connect'))
        self.assertTrue(pol['self_update'])
        lines = AG.policy_lines(pol)
        for want in ('allow probe local', 'allow probe www.example.test:443',
                     'allow connect [2001:db8::1]:22', 'allow self-update'):
            self.assertIn(want, lines)
        # a policy of phase 2 keeps its hash (nothing of probe in it)
        old = AG.parse_policy('allow unit nginx reload\n')
        self.assertNotIn('probe', json.loads(AG.policy_canon(old)))
        for bad in ('allow probe', 'allow connect example', 'allow connect a b:1',
                    'allow probe -x:1', 'allow connect host:70000'):
            self.assertTrue(AG.parse_policy(bad)['problems'], bad)

    def test_formats_of_a_key_made_there(self):
        kpem = openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256')
        self.assertEqual(AG.key_type_of(kpem.decode()), 'ec-256')
        trad = AG.key_file('key-traditional', kpem.decode(), b'', None, None, 'ec-256')
        self.assertIn(b'BEGIN EC PRIVATE KEY', trad)
        der = AG.key_file('key-der', kpem.decode(), b'', None, None, 'ec-256')
        self.assertEqual(der[:1], b'\x30')
        with self.assertRaises(AG.Refused):
            AG.key_file('key-rsa', kpem.decode(), b'', None, None, 'ec-256')
        with self.assertRaises(AG.Refused):
            AG.key_file('jks', kpem.decode(), b'', None, None, 'ec-256')
        csr = AG.make_key_csr(kpem.decode(), ['www.example.test', '192.0.2.7'])
        info = subprocess.run(['openssl', 'req', '-noout', '-text'], input=csr, text=True,
                              capture_output=True).stdout
        self.assertIn('DNS:www.example.test', info)
        self.assertIn('IP Address:192.0.2.7', info)
        for bad in (['a b'], ['x;rm'], [], ['-x.example']):
            with self.assertRaises(AG.Refused):
                AG.make_key_csr(kpem.decode(), bad)


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class AgentKeys(unittest.TestCase):
    """The key made by the agent (phase 3): made by root on the server, kept there, written into
    the allowed files with its certificate - never in acme."""
    @classmethod
    def setUpClass(cls):
        cls.row, cls.ag = join_passive(cls(), 'web4', free_port())
        www_policy(cls.ag)

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def test_1_made_there_deployed_renewed_kept(self):
        o = opts(self.ag)
        t, ctx = module(self.row, 41)
        csr = t.device_csr(req_for(o))
        self.assertIn('CERTIFICATE REQUEST', csr)
        self.assertTrue(any('the key stays there' in str(x) for x in ctx.steps), ctx.steps)
        keys = os.path.join(self.ag.d, 'rs', 'keys')
        self.assertTrue(os.path.exists(os.path.join(keys, 'dep-41.pending')))
        self.assertEqual(os.stat(os.path.join(keys, 'dep-41.pending')).st_mode & 0o777, 0o600)
        crt = sign_csr_test(csr)
        t, ctx = module(self.row, 41)
        said = t.deploy(KeylessBundle(crt), o)
        self.assertIn('3 files written', said)
        kfile = os.path.join(self.ag.www, 'ssl', 'site.key')
        key1 = read(kfile)
        self.assertIn('PRIVATE KEY', key1)
        self.assertEqual(spki(key1), spki(crt))                # the key the certificate is for
        self.assertEqual(os.stat(kfile).st_mode & 0o777, 0o640)
        self.assertEqual(read(os.path.join(self.ag.www, 'ssl', 'site.crt')),
                         crt + read(os.path.join(TMP, 'ca.crt')))
        p12 = subprocess.run(['openssl', 'pkcs12', '-in', os.path.join(self.ag.www, 'ssl',
                                                                       'site.pfx'),
                              '-nodes', '-passin', 'pass:secret-pw'], capture_output=True,
                             text=True)
        self.assertEqual(p12.returncode, 0, p12.stderr)
        self.assertEqual(spki(re.search(r'-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----',
                                        p12.stdout, re.S).group(0)), spki(crt))
        self.assertTrue(os.path.exists(os.path.join(keys, 'dep-41.key')))
        self.assertFalse(os.path.exists(os.path.join(keys, 'dep-41.pending')))
        # the key never reached acme: not in its database, its events or its log
        db = b''
        for n in os.listdir(TMP):
            if n.endswith(('.db', '.sqlite', '.sqlite3', '.log')):
                with open(os.path.join(TMP, n), 'rb') as fh:
                    db += fh.read()
        body = key1.split('-----')[2].strip().split('\n')[1][:40].encode()
        self.assertNotIn(body, db)
        # the same certificate again: unchanged
        t, ctx = module(self.row, 41)
        self.assertTrue(t.deploy(KeylessBundle(crt), o).startswith('unchanged'))
        # a renewal: a new key
        t, ctx = module(self.row, 41)
        csr2 = t.device_csr(req_for(o))
        self.assertNotEqual(spki(csr2), spki(crt))
        self.assertEqual(spki(read(kfile)), spki(crt))          # in use until its certificate
        crt2 = sign_csr_test(csr2)
        t, ctx = module(self.row, 41)
        t.deploy(KeylessBundle(crt2), o)
        self.assertEqual(spki(read(kfile)), spki(crt2))
        # keep the key: the CSR is of the key in use
        t, ctx = module(self.row, 41)
        csr3 = t.device_csr(req_for(o, keep=True))
        self.assertEqual(spki(csr3), spki(crt2))
        # a certificate not of a key the agent made for this deployment: refused
        t, ctx = module(self.row, 41)
        with self.assertRaises(base.PluginError) as e:
            t.deploy(KeylessBundle(read(CERTS['a'][0])), o)
        self.assertIn('not for a key this agent made', str(e.exception))
        self.assertEqual(spki(read(kfile)), spki(crt2))

    def test_2_refused_before_any_key(self):
        t, ctx = module(self.row, 42)
        o = opts(self.ag, outputs='fullchain-pem %s/x.crt 0644\nkey-pem %s/x.key 0600' % (
            self.ag.d + '/other', self.ag.d + '/other'))
        with self.assertRaises(base.PluginError) as e:
            t.device_csr(req_for(o))
        self.assertIn('acme-agent allow file %s/other' % self.ag.d, e.exception.detail or '')
        self.assertFalse(os.path.exists(os.path.join(self.ag.d, 'rs', 'keys', 'dep-42.pending')))
        # a format the agent does not write its key in
        t, ctx = module(self.row, 42)
        with self.assertRaises(base.PluginError) as e:
            t.device_csr(req_for(opts(self.ag, outputs='jks %s/ssl/x.jks 0640 root:%s' % (
                self.ag.www, USER))))
        self.assertIn('cannot be written as jks', str(e.exception))
        # no file for the key
        t, ctx = module(self.row, 42)
        with self.assertRaises(base.PluginError) as e:
            t.device_csr(req_for(opts(self.ag, outputs='fullchain-pem %s/ssl/x.crt 0644 root:%s'
                                      % (self.ag.www, USER))))
        self.assertIn('no file that holds the key', str(e.exception))
        # the preview says which file the key goes to, judged by the policy
        t, ctx = module(self.row, 41)
        pv = t.preview(KeylessBundle(read(CERTS['a'][0])), opts(self.ag))
        kinds = [i['kind'] for i in pv['agent']['items']]
        self.assertIn('key', kinds)
        self.assertTrue(pv['agent']['agent_key'])


    def test_3_the_whole_flow_and_what_happens(self):
        """A certificate whose key the agent makes (csr_from = the agent target): issued by an
        authority of acme's own for the agent's CSR, deployed right after with the agent's key;
        acme holds none; What happens shows every step with the policy's verdict."""
        from acmelib.certs import ca as CA, jobs, renewer, runplan
        ca_id = CA.ca_create(STORE, 'Agent Root', {'CN': 'Agent Root'}, key_type='ec-256',
                             by='tester')
        STORE.db.insert('cert_issuers', {'name': 'own-ag', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': ca_id, 'days': 60}),
                                         'state': '{}', 'enabled': 1, 'created': time.time()})
        o = opts(self.ag, outputs='fullchain-pem %s/ssl/flow.crt 0644 root:%s\n'
                 'key-pem %s/ssl/flow.key 0640 root:%s' % (self.ag.www, USER, self.ag.www, USER))
        cid = A.cert_save(STORE, {'name': 'flow', 'names': ['www.example.test'],
                                  'issuer': 'own-ag', 'key_type': 'ec-256', 'csr_from': 'web4'},
                          'tester', full=True)
        cid = cid[0] if isinstance(cid, tuple) else cid
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))
        self.assertEqual(dep['target'], 'web4')
        A.deploy_save(STORE, {'id': dep['id'], 'options': o}, 'tester')
        job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, True, 'tester'), cert_id=cid,
                           by='tester')
        said = '\n'.join(str(x[2]) for x in job.steps)
        self.assertTrue(job.ok, said)
        self.assertIn('the key stays there', said)
        row = S.cert_get(STORE, cid)
        self.assertFalse(row.get('key_sealed'))
        key = read(os.path.join(self.ag.www, 'ssl', 'flow.key'))
        self.assertEqual(spki(key), spki(row['cert_pem']))
        # a renewal: a new key made there
        job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, True, 'tester'), cert_id=cid,
                           by='tester')
        self.assertTrue(job.ok)
        key2 = read(os.path.join(self.ag.www, 'ssl', 'flow.key'))
        self.assertNotEqual(spki(key2), spki(key))
        self.assertEqual(spki(key2), spki(S.cert_get(STORE, cid)['cert_pem']))
        # kept: the same key (Keep the key - allowed where the agent makes it)
        A.cert_save(STORE, {'id': cid, 'reuse_key': True}, 'tester', full=True)
        job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, True, 'tester'), cert_id=cid,
                           by='tester')
        self.assertTrue(job.ok)
        self.assertEqual(spki(read(os.path.join(self.ag.www, 'ssl', 'flow.key'))), spki(key2))
        # an agent makes keys of several certificates; it takes acme's too
        cid2 = A.cert_save(STORE, {'name': 'flow2', 'names': ['www.example.test'],
                                   'issuer': 'own-ag', 'csr_from': 'web4'}, 'tester', full=True)
        self.assertTrue(cid2)
        cid3 = A.cert_save(STORE, {'name': 'flow3', 'names': ['www.example.test'],
                                   'issuer': 'own-ag'}, 'tester', full=True)
        cid3 = cid3[0] if isinstance(cid3, tuple) else cid3
        A.deploy_save(STORE, {'cert_id': cid3, 'target': 'web4', 'options': opts(
            self.ag, outputs='fullchain-pem %s/ssl/f3.crt 0644 root:%s\nkey-pem '
            '%s/ssl/f3.key 0640 root:%s' % (self.ag.www, USER, self.ag.www, USER))}, 'tester')
        # ...but one whose key it makes goes there alone
        with self.assertRaises(ValueError):
            A.deploy_save(STORE, {'cert_id': cid, 'target': 'web1', 'options': {}}, 'tester')
        # What happens: the key made there, each file and command with the policy's verdict
        row = S.cert_get(STORE, cid)
        deps = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))
        plan = runplan.plan(STORE, row, deps, full=True)
        keyp = json.dumps([p for p in plan['phases'] if p['key'] == 'key'][0])
        self.assertIn('The agent makes a CSR of the key in use', keyp)
        depp = [p for p in plan['phases'] if p['key'] == 'deploy'][0]
        text = json.dumps(depp)
        self.assertIn('Sends a signed job (deploy) to the agent of web4', text)
        self.assertIn('The agent writes the key it made into %s/ssl/flow.key' % self.ag.www, text)
        self.assertIn('The agent reloads systemctl reload nginx', text)
        self.assertIn('"policy": {"ok": true', text)
        self.assertIn('allows every file, command and script', text)
        if os.environ.get('ACME_AGENT_PLAN_OUT'):
            with open(os.environ['ACME_AGENT_PLAN_OUT'], 'w') as fh:
                json.dump(plan, fh, default=str)
        www_policy(self.ag, 'allow test -- /bin/true')
        # a policy that does not allow the reload: said, with the line
        st = G.state(STORE, self.row['id'])
        st['policy']['units'] = {}
        G.state_put(STORE, self.row['id'], st)
        plan = runplan.plan(STORE, S.cert_get(STORE, cid), deps, full=True)
        text = json.dumps([p for p in plan['phases'] if p['key'] == 'deploy'][0])
        self.assertIn('acme-agent allow unit nginx.service reload', text)
        self.assertIn('does not allow 1 of it', text)
        G.hello(STORE, self.row)


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class ThroughTheAgent(unittest.TestCase):
    """Tests of what is served through the agent (allow probe), and the agent as a connector
    (allow connect) - nothing of either without the policy's word."""
    @classmethod
    def setUpClass(cls):
        cls.row, cls.ag = join_passive(cls(), 'web6', free_port())
        www_policy(cls.ag)
        cls.tls = TlsServer('a')
        cls.echo = Echo()

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()
        cls.tls.stop()
        cls.echo.stop()

    def test_1_probe_refused_then_allowed(self):
        with self.assertRaises(base.PluginError) as e:
            G.probe(STORE, self.row, '127.0.0.1', self.tls.port, 'www.example.test')
        self.assertIn('acme-agent allow probe 127.0.0.1:%d' % self.tls.port,
                      e.exception.detail or '')
        www_policy(self.ag, 'allow probe local')
        got = G.probe(STORE, self.row, '127.0.0.1', self.tls.port, 'www.example.test')
        self.assertEqual(got['chain'][0], ssl.PEM_cert_to_DER_cert(read(CERTS['a'][0])))
        self.assertEqual(len(got['chain']), 2)
        self.assertTrue(got['tls'].startswith('TLS'))
        # only what the policy names: another address refused
        with self.assertRaises(base.PluginError):
            G.probe(STORE, self.row, '192.0.2.1', 443, 'www.example.test')
        www_policy(self.ag)

    def test_2_a_test_of_a_certificate_through_the_agent(self):
        from acmelib.certs import checks as CK
        cid = A.cert_import(STORE, {'data_b64': base64.b64encode(
            (read(CERTS['a'][0]) + read(CERTS['a'][1])).encode()).decode(),
            'filename': 'a.pem', 'name': 'www-probe'}, 'tester')
        cid = cid[0] if isinstance(cid, tuple) else cid
        www_policy(self.ag, 'allow probe local')
        got = CK.probe(STORE, {'cert_id': cid, 'kind': 'tls', 'config': {
            'host': '127.0.0.1', 'port': self.tls.port, 'sni': 'www.example.test',
            'via': 'web6'}})
        self.assertIn(got['state'], ('ok', 'warn'), got)
        self.assertTrue(got['detail'].get('via_agent'))
        www_policy(self.ag)
        got = CK.probe(STORE, {'cert_id': cid, 'kind': 'tls', 'config': {
            'host': '127.0.0.1', 'port': self.tls.port, 'via': 'web6'}})
        self.assertEqual(got['state'], 'unreachable')
        self.assertIn('allow probe', got['said'])
        # what the agent cannot speak: said
        got = CK.probe(STORE, {'cert_id': cid, 'kind': 'rdp', 'config': {
            'host': '127.0.0.1', 'port': 3389, 'via': 'web6'}})
        self.assertIn('cannot speak', got['said'])
        # the tests made from a deployment on it go through it, at 127.0.0.1
        dep = STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'web6', 'enabled': 1,
                                               'options': json.dumps({'preset': 'nginx'}),
                                               'state': 'new'})
        made = CK.served_tests(STORE, STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?',
                                                   (dep,)), 'tester')
        self.assertTrue(made)
        cfg = S.plugin_config('check', S.plugin_row(STORE, 'check', made[0]))
        self.assertEqual((cfg.get('via'), cfg.get('host')), ('web6', '127.0.0.1'))

    def test_3_connector_tunnel(self):
        with self.assertRaises(base.PluginError) as e:
            G.tunnel(STORE, self.row, '127.0.0.1', self.echo.port)
        self.assertIn('acme-agent allow connect 127.0.0.1:%d' % self.echo.port,
                      e.exception.detail or '')
        www_policy(self.ag, 'allow connect 127.0.0.1:%d' % self.echo.port)
        s = G.tunnel(STORE, self.row, '127.0.0.1', self.echo.port)
        s.sendall(b'hello')
        got = b''
        while len(got) < 10:
            got += s.recv(100)
        self.assertEqual(got, b'echo:hello')
        s.close()
        www_policy(self.ag)
        # offered as a connector of SSH targets (passive), marked
        opts_ = A.options_for(STORE, 'connectors')
        self.assertIn(['web6', 'web6 (through its acme-agent)'], opts_)
        self.assertIn(['web6', 'web6 (through its acme-agent)'],
                      A.options_for(STORE, 'test_connectors'))
        self.assertNotIn('web6', [o[0] for o in A.options_for(STORE, 'agent_hops')])

    @unittest.skipUnless(shutil.which('sshd') or os.path.exists('/usr/sbin/sshd'), 'needs sshd')
    def test_4_an_ssh_target_through_the_agent_and_the_agent_through_ssh(self):
        d = tempfile.mkdtemp(dir=TMP)
        os.chmod(d, 0o700)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/hostkey'],
                       check=True)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/id'],
                       check=True)
        shutil.copy(d + '/id.pub', d + '/authorized_keys')
        port = free_port()
        with open(d + '/sshd_config', 'w') as fh:
            fh.write('Port %d\nListenAddress 127.0.0.1\nHostKey %s/hostkey\nPidFile %s/pid\n'
                     'AuthorizedKeysFile %s/authorized_keys\nPermitRootLogin prohibit-password\n'
                     'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
                     'StrictModes no\nAllowTcpForwarding yes\n' % (port, d, d, d))
        os.makedirs('/run/sshd', exist_ok=True)
        sshd = subprocess.Popen([shutil.which('sshd') or '/usr/sbin/sshd', '-D', '-e', '-f',
                                 d + '/sshd_config'], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    socket.create_connection(('127.0.0.1', port), 1).close()
                    break
                except OSError:
                    time.sleep(0.2)
            key = read(d + '/id')
            rid = A.family_save(STORE, 'target', {'name': 'behind', 'kind': 'ssh', 'config': {
                'host': '127.0.0.1', 'port': port, 'user': 'root', 'auth': 'key', 'key': key,
                'trust_first': True, 'via': 'web6'}, 'enabled': 1}, 'tester')
            trow = S.plugin_row(STORE, 'target', rid)
            ctx = runtime.RunContext(STORE, None, scope='target:behind')
            t = S.plugin_instance(STORE, 'target', trow, ctx)
            with self.assertRaises(base.PluginError):
                t.test()                                    # no allow connect: refused
            www_policy(self.ag, 'allow connect 127.0.0.1:%d' % port)
            ctx = runtime.RunContext(STORE, None, scope='target:behind')
            t = S.plugin_instance(STORE, 'target', S.plugin_row(STORE, 'target', rid), ctx)
            said = t.test()
            self.assertIn('signed in as root', said)
            self.assertTrue(any('through the agent of web6' in str(x) for x in ctx.steps))
            www_policy(self.ag)
            # a passive agent reached through an SSH connector (ssh -W to its port)
            A.family_save(STORE, 'target', {'name': 'hop', 'kind': 'ssh_connector', 'config': {
                'host': '127.0.0.1', 'port': port, 'user': 'root', 'auth': 'key', 'key': key,
                'trust_first': True, 'hostkey': read(d + '/hostkey.pub').strip().replace(
                    'ssh-ed25519', '127.0.0.1 ssh-ed25519', 1)}, 'enabled': 1}, 'tester')
            row = S.plugin_row(STORE, 'target', 'web6')
            cfg = S.plugin_config('target', row)
            STORE.db.update('cert_targets', row['id'], {'config': json.dumps(dict(cfg,
                                                                                  via='hop'))})
            try:
                got = G.hello(STORE, S.plugin_row(STORE, 'target', 'web6'))
                self.assertTrue(got['ok'])
            finally:
                STORE.db.update('cert_targets', row['id'], {'config': json.dumps(cfg)})
        finally:
            sshd.terminate()
            sshd.wait(10)


# ---- phase 4: updates, monitoring, backup and HA ------------------------------------------------
@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class SelfUpdate(unittest.TestCase):
    """allow self-update: only a package signed by a release key the agent was installed with,
    only a newer version; without the entry only "a newer one is there"."""
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)
        os.chmod(self.d, 0o755)
        self.key = os.path.join(self.d, 'rel.pem')
        openssl('genpkey', '-algorithm', 'ed25519', '-out', self.key)
        self.lib = os.path.join(self.d, 'lib')
        os.makedirs(self.lib + '/release-keys')
        openssl('pkey', '-in', self.key, '-pubout', '-out', self.lib + '/release-keys/rel-1.pub')
        shutil.copy(AGENT, self.lib + '/acme_agent.py')
        with open(self.lib + '/release', 'w') as fh:
            fh.write('1.0.115\n')
        for n in os.listdir(self.lib):
            os.chmod(os.path.join(self.lib, n), 0o755)

    def pkg(self, ver, key=None):
        dest = os.path.join(self.d, 'acme-agent-%s.tar.gz' % ver)
        G.build_package(dest, ver, key=key, keys_dir=self.lib + '/release-keys', epoch=1700000000)
        return dest

    def test_signed_newer_only(self):
        global AGENT
        was = AGENT
        AGENT = self.lib + '/acme_agent.py'
        try:
            row, ag = join_passive(self, 'web8', free_port())
        finally:
            AGENT = was
        try:
            ag.root_prog = self.lib + '/acme_agent.py'
            st = G.state(STORE, row['id'])
            self.assertEqual(st['version'] if st.get('version') else
                             G.hello(STORE, row)['version'], '1.0.115')

            def send(path, ver):
                with open(path, 'rb') as fh:
                    data = fh.read()
                return G.call(STORE, row, 'update', {'package': base64.b64encode(data).decode(),
                                                     'version': ver}, timeout=120)
            good = self.pkg('1.0.117', self.key)
            pkg_was = G.package
            G.package = lambda build=True: {'path': good, 'signed': True, 'version': '1.0.117',
                                            'name': os.path.basename(good)}
            try:
                # acme offers it: without `allow self-update` only "a newer one is there"
                self.assertTrue(G.info(STORE, row)['update']['newer'])
                self.assertFalse(G.info(STORE, row)['update']['allowed'])
                with self.assertRaises(base.PluginError) as e:
                    G.update_agent(STORE, row, 'tester')
                self.assertIn('acme-agent allow self-update', e.exception.detail or '')
            finally:
                G.package = pkg_was
            got = send(good, '1.0.117')
            self.assertFalse(got['ok'])
            self.assertEqual(got['needs'][0]['allow'], 'acme-agent allow self-update')
            ag.policy('allow self-update')
            # unsigned: refused
            got = send(self.pkg('1.0.118'), '1.0.118')
            self.assertIn('not signed', got['said'])
            # signed by another key: refused
            other = os.path.join(self.d, 'other.pem')
            openssl('genpkey', '-algorithm', 'ed25519', '-out', other)
            got = send(self.pkg('1.0.119', other), '1.0.119')
            self.assertIn('not of a release key', got['said'])
            # older: refused
            got = send(self.pkg('1.0.100', self.key), '1.0.100')
            self.assertIn('never put back to an older', got['said'])
            # a file changed after signing: refused
            import tarfile
            import io
            bad = os.path.join(self.d, 'bad.tar.gz')
            with tarfile.open(good) as src, tarfile.open(bad, 'w:gz') as dst:
                for m in src.getmembers():
                    data = src.extractfile(m).read() if m.isfile() else None
                    if m.name.endswith('/acme_agent.py'):
                        data = data + b'\n# changed\n'
                        m.size = len(data)
                    dst.addfile(m, io.BytesIO(data) if data is not None else None)
            got = send(bad, '1.0.117')
            self.assertIn('not the file MANIFEST names', got['said'])
            self.assertEqual(read(self.lib + '/release').strip(), '1.0.115')
            # signed and newer: installed (as acme sends it - Update the agent)
            G.hello(STORE, row)
            G.package = lambda build=True: {'path': good, 'signed': True, 'version': '1.0.117',
                                            'name': os.path.basename(good)}
            try:
                self.assertTrue(G.info(STORE, row)['update']['allowed'])
                got = G.update_agent(STORE, row, 'tester')
            finally:
                G.package = pkg_was
            self.assertTrue(got['ok'], got)
            self.assertIn('acme-agent 1.0.117 is installed', got['said'])
            self.assertTrue(STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE ?",
                                           ('%web8 was updated to 1.0.117%',), 0))
            self.assertEqual(read(self.lib + '/release').strip(), '1.0.117')
            self.assertEqual(read(self.lib + '/acme_agent.py', 'rb'), read(AGENT, 'rb'))
            # the pages: a newer one offered, whether the policy allows it
            st = G.state(STORE, row['id'])
            st['version'] = '1.0.115'
            G.state_put(STORE, row['id'], st)
            f = G.update_facts(G.state(STORE, row['id']), {'version': '1.0.116', 'signed': True})
            self.assertTrue(f['newer'])
        finally:
            ag.stop()


class Monitoring(unittest.TestCase):
    def test_snmp_metrics_isemon_alert(self):
        from acmelib.certs import monitor as MO
        rows = MO.snmp_rows(STORE)
        names = {}
        for oid, kind, v in rows:
            if oid[:3] == (6, 9, 1) and oid[3] == 2:
                names[v] = oid[4]
        agents_now = [r['name'] for r in G.rows(STORE)]
        self.assertEqual(sorted(names), sorted(agents_now))
        if agents_now:
            got = {m[0] for m in MO.metrics(STORE)}
            self.assertIn('acme_agent_up', got)
        # isemon / SIEM fields of the agents' events
        f = MO.event_fields('certificates', 'the policy of the agent of target web1 blocks a '
                            'deployment: /etc/x/a.pem - allow it on the server (acme-agent allow '
                            'file /etc/x)', 'warn')
        self.assertEqual((f['action'], f['target'], f['result']),
                         ('agent_policy_blocks', 'web1', 'failed'))
        f = MO.event_fields('certificates', 'the agent of target web1 was updated to 1.0.117 by x',
                            'info')
        self.assertEqual((f['action'], f['version']), ('agent_updated', '1.0.117'))
        # a deployment the policy blocks: an alert until one goes through
        row = target('blk', mode='passive', host='127.0.0.1', port=1)
        st = G.state(STORE, row['id'])
        st.update(cert_fp='ab' * 32, agent_id='ag-0123456789ab', last_seen=time.time())
        G._blocked_seen(STORE, row, st, {'ok': False, 'needs': [
            {'what': '/etc/x/a.pem', 'allow': 'acme-agent allow file /etc/x'}]}, 'deploy')
        G.state_put(STORE, row['id'], st)
        al = [a for a in G.alerts(STORE) if a['key'] == 'agent-policy:%d' % row['id']]
        self.assertEqual(len(al), 1)
        self.assertIn('acme-agent allow file /etc/x', al[0]['words'])
        G._blocked_seen(STORE, row, st, {'ok': True}, 'deploy')
        G.state_put(STORE, row['id'], st)
        self.assertFalse([a for a in G.alerts(STORE) if a['key'].startswith('agent-policy:%d'
                                                                           % row['id'])])
        G.target_gone(STORE, row)
        STORE.db.run('DELETE FROM cert_targets WHERE id = ?', (row['id'],))



SECOND_NODE = r"""
import json, sys, base64
import acmelib.engine as E
E.load_config()
st = E.Storage(E.open_db())
E.HA_STORE['store'] = st
from acmelib.certs import agents as G, store as S
want = json.loads(sys.stdin.read())
out = {'meta': {}}
for r in st.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:%' OR k LIKE 'agentq:%'"):
    out['meta'][r['k']] = r['v']
row = G.target_row(st, want['target'])
got = G.hello(st, row)
out['hello'] = bool(got.get('ok'))
got = G.call(st, row, 'deploy', {'files': [{'path': want['path'], 'mode': 0o644,
         'owner': want['owner'], 'data': base64.b64encode(b'from the second node\n').decode()}],
         'backup': 'none'}, timeout=60)
out['deploy'] = got
out['ca_fp'] = G.ca_public(st)['fp']
print(json.dumps(out, default=str))
"""


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class BackupAndSecondNode(unittest.TestCase):
    """The agent authority, the command key, the agents' states and the jobs queued come back
    with a backup on a clean installation - which then commands the very agent (it is the same
    acme to it: the second node of a cluster, or the machine put back)."""
    def test_backup_restored_works(self):
        row, ag = join_passive(self, 'web9', free_port())
        try:
            www_policy(ag)
            STORE.set_meta('agentq:%d:keptjob' % row['id'], json.dumps(
                {'env': {'job': '{}', 'sig': ''}, 'state': 'queued', 'at': time.time(),
                 'by': 'n1'}))
            before = {r['k']: r['v'] for r in STORE.db.rows(
                "SELECT k, v FROM meta WHERE k LIKE 'agents:%' OR k LIKE 'agentq:%'")}
            self.assertIn('agents:ca', before)
            self.assertIn('agents:cmd', before)
            self.assertIn('agents:t:%d' % row['id'], before)
            work = tempfile.mkdtemp(dir=TMP)
            bundle = E.rb_build(STORE, work)[0]
            base_ = os.path.join(TMP, 'node2')
            for d in ('etc', 'state', 'log', 'run', 'plugins'):
                os.makedirs(os.path.join(base_, d), exist_ok=True)
            conf = os.path.join(base_, 'etc', 'config.json')
            with open(conf, 'w') as fh:
                json.dump({'node_name': 'n2', 'upgrade_check': 0}, fh)
            env = dict(os.environ, ACME_CONFIG=conf, ACME_STATE=os.path.join(base_, 'state'),
                       ACME_RUN=os.path.join(base_, 'run'), ACME_LOGDIR=os.path.join(base_, 'log'),
                       ACME_PLUGINS=os.path.join(base_, 'plugins'))
            got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'),
                                  '--restore-bundle', bundle, '--yes'], env=env, cwd=ROOT,
                                 capture_output=True, text=True, timeout=300)
            self.assertEqual(got.returncode, 0, got.stdout[-2000:] + got.stderr[-2000:])
            path = os.path.join(ag.www, 'ssl', 'second.txt')
            got = subprocess.run([sys.executable, '-c', SECOND_NODE], env=env, cwd=ROOT,
                                 input=json.dumps({'target': 'web9', 'path': path,
                                                   'owner': 'root:' + USER}),
                                 capture_output=True, text=True, timeout=300)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            out = json.loads(got.stdout.strip().splitlines()[-1])
            # every row of the agents back as it was (their keys still sealed - the sealing key
            # came back with the backup)
            for k in ('agents:ca', 'agents:cmd', 'agents:ctl', 'agents:t:%d' % row['id'],
                      'agentq:%d:keptjob' % row['id']):
                self.assertIn(k, out['meta'], k)
            self.assertEqual(json.loads(out['meta']['agents:ca'])['cert'],
                             json.loads(before['agents:ca'])['cert'])
            self.assertEqual(json.loads(out['meta']['agents:cmd'])['at'],
                             json.loads(before['agents:cmd'])['at'])
            self.assertEqual(out['meta']['agents:t:%d' % row['id']],
                             before['agents:t:%d' % row['id']])
            self.assertEqual(out['ca_fp'], G.ca_public(STORE)['fp'])
            # and the agent obeys it: the same authority, the same command key
            self.assertTrue(out['hello'])
            self.assertTrue(out['deploy']['ok'], out['deploy'])
            self.assertEqual(read(path), 'from the second node\n')
        finally:
            STORE.db.run("DELETE FROM meta WHERE k LIKE 'agentq:%'")
            ag.stop()



WITHOUT = r"""
import json
import acmelib.engine as E
E.load_config()
st = E.Storage(E.open_db())
E.HA_STORE['store'] = st
from acmelib.certs import api as A, monitor as MO, store as S, runplan
from acmelib.plugins import base
S.registry()
out = {'connectors': A.options_for(st, 'connectors'),
       'test_connectors': A.options_for(st, 'test_connectors'),
       'agent_hops': A.options_for(st, 'agent_hops'),
       'snmp_69': [list(o) for o, k, v in MO.snmp_rows(st) if o[:2] == (6, 9)],
       'metrics': sorted(m[0] for m in MO.metrics(st) if m[0].startswith('acme_agent')),
       'optional': sorted(k for k, c in base.REGISTRY.found['target'].items()
                          if 'device_key_optional' in c.describe()),
       'vias': runplan._agent_vias(st, [{'detail': {'pairs': [['Through', 'the connector x - ']]}}]),
       'agents_meta': [r['k'] for r in st.db.rows("SELECT k FROM meta WHERE k LIKE 'agent%'")]}
print(json.dumps(out))
"""


class NothingWithoutAnAgent(unittest.TestCase):
    """No target with acme-agent (and active mode off): nothing of phases 3 and 4 shows - no
    connector offered, no SNMP row, no metric, no other module described otherwise, What
    happens as it was, nothing kept."""
    def test_as_before(self):
        base_ = tempfile.mkdtemp(dir=TMP)
        for d in ('etc', 'state', 'log', 'run', 'plugins'):
            os.makedirs(os.path.join(base_, d))
        conf = os.path.join(base_, 'etc', 'config.json')
        with open(conf, 'w') as fh:
            json.dump({'node_name': 'n0', 'upgrade_check': 0}, fh)
        env = dict(os.environ, ACME_CONFIG=conf, ACME_STATE=os.path.join(base_, 'state'),
                   ACME_RUN=os.path.join(base_, 'run'), ACME_LOGDIR=os.path.join(base_, 'log'),
                   ACME_PLUGINS=os.path.join(base_, 'plugins'))
        got = subprocess.run([sys.executable, '-c', WITHOUT], env=env, cwd=ROOT,
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertEqual(out['connectors'], [])
        self.assertEqual(out['test_connectors'], [])
        self.assertEqual(out['agent_hops'], [])
        self.assertEqual(out['snmp_69'], [])
        self.assertEqual(out['metrics'], [])
        self.assertEqual(out['optional'], ['agent'])
        self.assertEqual(out['vias'][0]['detail']['pairs'][0][1], 'the connector x - ')
        self.assertEqual(out['agents_meta'], [])



class PagesWiring(unittest.TestCase):
    """agents.js is loaded after certs.js on the page (web/admin/index.php): what certs.js hands
    it (its API, the targets, a new certificate whose key the agent makes) must reach it all the
    same - the card said "the page is not ready" before."""
    def test_hands_whatever_the_order(self):
        certs = read(os.path.join(ROOT, 'web', 'assets', 'certs.js'))
        agents = read(os.path.join(ROOT, 'web', 'assets', 'agents.js'))
        index = read(os.path.join(ROOT, 'web', 'admin', 'index.php'))
        self.assertLess(index.index('/assets/certs.js'), index.index('/assets/agents.js'))
        self.assertIn('window.ACME_AGENTS_HANDS = {capi: capi, over: over', certs)
        self.assertIn('if (window.ACME_AGENTS_HANDS) init(window.ACME_AGENTS_HANDS);', agents)
        self.assertIn('newCert: function (row, host)', certs)


if __name__ == '__main__':
    unittest.main(verbosity=2)
