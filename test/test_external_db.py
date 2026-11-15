#!/usr/bin/env python3
"""The database on servers of their own, looked after by acme-db-agent (1.0.113).

    python3 test/test_external_db.py        (as root, with PostgreSQL 16 installed)

Every "database server" here is a PostgreSQL 16 of its own, made for the test
(initdb into a folder of its own, its own port - the clusters on 5432/5433 are
not touched), with deploy/acme_db_agent.py run for it as root on a port of its
own, as acme-db-agent.service would. The acme nodes are daemons in folders of
their own, as test_ha.py starts them.

* Agent: the closed set - an unknown verb, an unsigned request, one signed with
  the wrong key, a replayed one, no client certificate, a certificate acme did
  not issue, one acme issued but not enrolled: each refused. A join code used
  twice is refused. The side that faces the network does not run as root; the
  audit log has what was done.
* Standalone (layout A): one acme node, its database on one server with an
  agent. Joined with the code; the database and its account made through the
  agent; acme --db-move onto it; Database -> TLS: the server's certificate from
  acme's authority put in by the agent, the connection verify-full; renewed
  (a new certificate on the server); a backup (pg_dump over the network); the
  agent stopped -> the alert; the meter of the database server (/api/load).
* Replicated (layout B): two acme nodes, each with its own database server and
  agent. acme --ha-setup / --ha-join with the agents (wal_level, listen, the
  restart, pg_hba, the publication all done by them); both directions
  replicate; the link's TLS through the agents (verify-full, hostssl); a
  rebuild of the second node (acme --ha-resync); no move of a node of the pair.
* EngineMoves: PostgreSQL with agent A -> MariaDB with agent B and back (--db-make through the
  target's agent, the TLS of the old server not carried), then off the agents' servers onto
  this machine's PostgreSQL, MariaDB and SQLite (the agent let go, nothing asked of it).
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_ha import Node, free_port, wait_for, passphrase_of, PW  # noqa: E402,F401

PGBIN = os.environ.get('ACME_TEST_PGBIN', '/usr/lib/postgresql/16/bin')
DB_PW = 'Ext-Db-Pw-4711'
BASE = os.environ.get('ACME_TEST_EXTDB_DIR', '/var/tmp')
AGENT = os.path.join(ROOT, 'deploy', 'acme_db_agent.py')


AGENT_USER = 'acme-db-agent'


def can_run():
    return os.geteuid() == 0 and os.path.exists(os.path.join(PGBIN, 'initdb')) and \
        shutil.which('runuser') and shutil.which('psql')


def agent_user():
    """The agent's own account, as install.sh --db-agent makes it: its network side never runs
    as nobody (1.0.113)."""
    if subprocess.run(['id', AGENT_USER], capture_output=True).returncode != 0:
        subprocess.run(['useradd', '--system', '--no-create-home', '--home-dir',
                        '/var/lib/acme-db-agent', '--shell', '/sbin/nologin', AGENT_USER],
                       capture_output=True, check=True)
    return AGENT_USER


class PgServer(object):
    """A PostgreSQL 16 of its own: its folder, its port, the socket in /var/run/postgresql."""

    def __init__(self, name):
        self.name = name
        self.top = tempfile.mkdtemp(prefix='acme-extdb-%s-' % name, dir=BASE)
        os.chmod(self.top, 0o755)
        self.dir = os.path.join(self.top, 'pg')
        os.makedirs(self.dir)
        shutil.chown(self.dir, 'postgres', 'postgres')
        self.data = os.path.join(self.dir, 'data')
        self.log = os.path.join(self.dir, 'log.txt')
        self.port = free_port()
        self.pg('initdb', '-D', self.data, '-U', 'postgres', '--auth-local=peer',
                '--auth-host=scram-sha-256', '-E', 'UTF8', '--locale=C.UTF-8')
        with open(os.path.join(self.data, 'postgresql.auto.conf'), 'a') as f:
            f.write("port = %d\nlisten_addresses = 'localhost'\nlogging_collector = on\n" % self.port)
        self.start()

    def pg(self, prog, *args):
        got = subprocess.run(['runuser', '-u', 'postgres', '--', os.path.join(PGBIN, prog)] +
                             list(args), capture_output=True, text=True, cwd='/', timeout=120)
        if got.returncode != 0:
            raise RuntimeError('%s %s: %s' % (prog, args, got.stderr or got.stdout))
        return got.stdout

    def restart_cmd(self):
        return ['/usr/sbin/runuser', '-u', 'postgres', '--', os.path.join(PGBIN, 'pg_ctl'), '-D',
                self.data, '-l', self.log, '-w', '-m', 'fast', 'restart']

    def start(self):
        self.pg('pg_ctl', '-D', self.data, '-l', self.log, '-w', 'start')

    def stop(self):
        try:
            self.pg('pg_ctl', '-D', self.data, '-w', '-m', 'immediate', 'stop')
        except RuntimeError:
            pass

    def sql(self, text, db='postgres'):
        got = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-p',
                              str(self.port), '-d', db, '-c', text], capture_output=True,
                             text=True, cwd='/')
        return got.stdout.strip()

    def cleanup(self):
        self.stop()
        if not os.environ.get('ACME_TEST_KEEP'):
            shutil.rmtree(self.top, ignore_errors=True)


class Agent(object):
    """acme_db_agent.py for one server, as root (it gives root up on the network side)."""

    def __init__(self, server, cadir, fail_burst=100000):
        self.server = server
        self.dir = os.path.join(server.top, 'agent')
        os.makedirs(self.dir, mode=0o700)
        self.port = free_port()
        self.conf = os.path.join(self.dir, 'agent.json')
        with open(self.conf, 'w') as f:
            # Every request of the tests comes from 127.0.0.1: the refusals they make on purpose
            # would block it (fail_burst) - a test of its own has the default.
            json.dump({'listen': '127.0.0.1', 'port': self.port, 'engine': 'postgres',
                       'pg_port': server.port, 'user': agent_user(), 'fail_burst': fail_burst,
                       'state': os.path.join(self.dir, 'state'),
                       'log': os.path.join(self.dir, 'audit.log'),
                       'ha_ca': os.path.join(cadir, server.name + '.pem'),
                       'advertise': '127.0.0.1', 'pg_restart_cmd': server.restart_cmd()}, f)
        self.proc = None
        self.out = os.path.join(self.dir, 'agent.out')

    def start(self):
        env = dict(os.environ, ACME_AGENT_NO_FIREWALL='1')
        with open(self.out, 'ab') as out:
            self.proc = subprocess.Popen([sys.executable, '-I', AGENT, '--config', self.conf],
                                         stdout=out, stderr=subprocess.STDOUT, env=env)
        wait_for(lambda: self.hello(), 20, 0.2, 'the agent answering')
        return self

    def hello(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as s:
            with ctx.wrap_socket(s) as t:
                t.sendall(b'GET /v1/hello HTTP/1.1\r\nHost: x\r\n\r\n')
                return b'acme-db-agent' in t.recv(4096)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.proc = None

    def code(self):
        got = subprocess.run([sys.executable, '-I', AGENT, '--config', self.conf, '--new-code'],
                             capture_output=True, text=True, check=True)
        return got.stdout.strip()

    def audit(self):
        try:
            with open(os.path.join(self.dir, 'audit.log')) as f:
                return [json.loads(x) for x in f if x.strip()]
        except OSError:
            return []


def quietly(*fns):
    """Each of these, whatever the one before did (a teardown that stops at the first error
    leaves PostgreSQLs and agents running)."""
    for fn in fns:
        try:
            fn()
        except Exception as e:                          # noqa: BLE001
            sys.stderr.write('cleanup: %s\n' % e)


def set_up_or_clean(cls, fn):
    try:
        fn()
    except BaseException:
        cls.tearDownClass()
        raise


def node_conf_agent(node):
    with open(os.path.join(node.tmp, 'state', 'db-agent', 'agent.json')) as f:
        return json.load(f)


def raw_op(agent, node, op, args=None, key_hex=None, cert=True, ts=None, nonce=None,
           client=None):
    """A request to the agent made by hand: (status, answer)."""
    import http.client
    d = os.path.join(node.tmp, 'state', 'db-agent')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(*(client or (os.path.join(d, 'client.crt'), os.path.join(d, 'client.key'))))
    body = json.dumps({'op': op, 'args': args or {}}).encode()
    ts = ts or '%.3f' % time.time()
    nonce = nonce or os.urandom(16).hex()
    text = '\n'.join(['acme-db-agent/1', 'POST', '/v1/op', 'n0' if node.name == 'n0' else node.name,
                      ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    sig = hmac.new(bytes.fromhex(key_hex), text, 'sha256').hexdigest() if key_hex else ''
    c = http.client.HTTPSConnection('127.0.0.1', agent.port, context=ctx, timeout=30)
    try:
        c.request('POST', '/v1/op', body=body, headers={
            'X-Acme-Node': node.name, 'X-Acme-Time': ts, 'X-Acme-Nonce': nonce,
            'X-Acme-Sign': sig})
        r = c.getresponse()
        return r.status, json.loads(r.read().decode() or '{}')
    finally:
        c.close()


def sign_key_of(node):
    with open(os.path.join(node.tmp, 'state', 'db-agent', 'sign.key')) as f:
        return f.read().strip()


def server_cert_der(port):
    """The certificate a PostgreSQL answers with over TLS."""
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
    assert s.recv(1) == b'S'
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s)
    try:
        return t.getpeercert(True)
    finally:
        t.close()


def network_side_pid(agent):
    kids = subprocess.run(['pgrep', '-P', str(agent.proc.pid)], capture_output=True,
                          text=True).stdout.split()
    return int(kids[0]) if kids else None


def memory_holds(pid, needles):
    """Which of `needles` (bytes) are anywhere in the readable memory of process `pid`."""
    found = set()
    with open('/proc/%d/maps' % pid) as maps, open('/proc/%d/mem' % pid, 'rb', 0) as mem:
        for line in maps:
            f = line.split()
            if 'r' not in f[1]:
                continue
            lo, hi = (int(x, 16) for x in f[0].split('-'))
            if hi - lo > (1 << 29):
                continue
            try:
                mem.seek(lo)
                chunk = mem.read(hi - lo)
            except (OSError, ValueError, OverflowError):
                continue
            for n in needles:
                if n in chunk:
                    found.add(n)
    return found


def agent_status(agent):
    got = subprocess.run([sys.executable, '-I', AGENT, '--config', agent.conf, '--status'],
                         capture_output=True, text=True, check=True)
    return json.loads(got.stdout)


def post_plain(port, path, body, cert=None):
    """A POST to the agent without acme's client: (status, answer)."""
    import http.client
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(*cert)
    c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=30)
    try:
        c.request('POST', path, body=json.dumps(body).encode())
        r = c.getresponse()
        return r.status, json.loads(r.read().decode() or '{}')
    finally:
        c.close()


def code_data(code):
    raw = code[6:]
    return json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))


def read_file(path):
    with open(path) as f:
        return f.read()


def last_json(out):
    return json.loads(out.strip().splitlines()[-1])


def dbtls_wait(node, ident, secs=180):
    def done():
        got = node.ok('POST', '/api/dbtls', {'action': 'result', 'id': ident})['nodes']
        one = got.get(node.name)
        return one if one and (one.get('ok') is not None) else None
    return wait_for(done, secs, 1, 'the database TLS step on %s' % node.name)


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (%s) and runuser' % PGBIN)
class Standalone(unittest.TestCase):
    """Layout A: one acme node, its database on a server of its own with an agent."""

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        os.chmod(cls.cadir, 0o755)
        cls.db = PgServer('dba')
        cls.agent = Agent(cls.db, cls.cadir).start()
        cls.n = Node('n0', extra={'perf_meter': True})
        cls.n.env.update(ACME_HA_NO_RESTART='1', ACME_NO_RESTART='1',
                         ACME_HA_CA=os.path.join(cls.cadir, 'dba.pem'),
                         ACME_DBAGENT_EVERY='2', ACME_DBAGENT_DOWN_S='3')
        os.makedirs(os.path.join(cls.n.tmp, 'state', 'web'), exist_ok=True)
        cls.n.add_account()
        cls.code = cls.agent.code()
        got = cls.n.cli('--db-agent-join', cls.code)
        cls.join_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--db-agent-join: %s' % cls.join_out)
        # The database and its account made on the server through the agent, then moved onto.
        cls.n.py("print(acme.db_make_here({'db_engine': 'postgres', 'db_host': '127.0.0.1', "
                 "'db_port': %d, 'db_name': 'acme', 'db_user': 'acme', 'db_password': %r}))"
                 % (cls.db.port, DB_PW))
        got = cls.n.cli('--db-move', 'postgres', '--db-host', '127.0.0.1', '--db-port',
                        str(cls.db.port), '--yes', stdin='')
        env_out = got.stdout + got.stderr
        if got.returncode != 0:
            got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move',
                                  'postgres', '--db-host', '127.0.0.1', '--db-port',
                                  str(cls.db.port), '--yes'],
                                 env=dict(cls.n.env, ACME_DB_PASSWORD=DB_PW),
                                 capture_output=True, text=True, timeout=300)
            env_out = got.stdout + got.stderr
        if got.returncode != 0 or cls.n.conf.get('db_engine') != 'postgres':
            raise RuntimeError('--db-move: %s' % env_out)
        cls.n.start()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('n',) if getattr(cls, x, None)],
                *[getattr(cls, x).stop for x in ('agent',) if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db',) if getattr(cls, x, None)],
                lambda: shutil.rmtree(cls.cadir, ignore_errors=True))

    def test_01_joined(self):
        a = node_conf_agent(self.n)
        self.assertEqual(a['db_admin'], 'agent:127.0.0.1:%d' % self.agent.port)
        self.assertEqual(len(a['pins']), 1)
        self.assertNotIn('sign_key', a)                         # a file of its own, 0600
        self.assertEqual(os.stat(os.path.join(self.n.tmp, 'state', 'db-agent', 'sign.key'))
                         .st_mode & 0o077, 0)
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('running', got.stdout)
        # The code is used up.
        again = self.n.cli('--db-agent-join', self.code)
        self.assertNotEqual(again.returncode, 0)
        # refused: the code is used up, and it pins the certificate the agent no longer has
        self.assertRegex(again.stdout + again.stderr, 'used up|did not pin')
        self.assertEqual(self.db.sql("SELECT rolname FROM pg_roles WHERE rolname = 'acme'"), 'acme')

    def test_02_refused(self):
        key = sign_key_of(self.n)
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key)
        self.assertEqual(st, 200, got)
        st, got = raw_op(self.agent, self.n, 'shell', {'cmd': 'id'}, key_hex=key)
        self.assertEqual(st, 400)
        self.assertIn('not something this agent does', got['said'])
        st, got = raw_op(self.agent, self.n, 'status')                  # unsigned
        self.assertEqual(st, 400)
        self.assertIn('not signed', got['said'])
        st, got = raw_op(self.agent, self.n, 'status', key_hex='11' * 32)   # another key
        self.assertIn('not signed', got['said'])
        nonce = os.urandom(16).hex()
        st, _ = raw_op(self.agent, self.n, 'status', key_hex=key, nonce=nonce)
        self.assertEqual(st, 200)
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key, nonce=nonce)   # replayed
        self.assertIn('seen before', got['said'])
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key, ts='%.3f' % (time.time() - 600))
        self.assertIn('time', got['said'])
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key, cert=False)
        self.assertEqual(st, 401)
        # A certificate acme did not issue: the handshake fails.
        t = tempfile.mkdtemp(dir=BASE)
        try:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
                            os.path.join(t, 'k.pem'), '-out', os.path.join(t, 'c.pem'), '-days',
                            '2', '-subj', '/CN=intruder'], capture_output=True, check=True)
            with self.assertRaises((ssl.SSLError, OSError, ConnectionError)):
                raw_op(self.agent, self.n, 'status', key_hex=key,
                       client=(os.path.join(t, 'c.pem'), os.path.join(t, 'k.pem')))
            # One acme's authority issued, but never enrolled here: 403.
            self.n.py("k, c = acme.hatls_issue(st, [], eku='clientAuth', cn='other'); "
                      "open(%r, 'w').write(c); open(%r, 'w').write(k)"
                      % (os.path.join(t, 'o.crt'), os.path.join(t, 'o.key')))
            st, got = raw_op(self.agent, self.n, 'status', key_hex=key,
                             client=(os.path.join(t, 'o.crt'), os.path.join(t, 'o.key')))
            self.assertEqual(st, 403, got)
        finally:
            shutil.rmtree(t, ignore_errors=True)
        # A bad value is refused by the shared checks: a file of the server's own.
        st, got = raw_op(self.agent, self.n, 'pg_allow', {'db': 'postgres', 'user': 'acme',
                                                           'peers': ['192.0.2.1']}, key_hex=key)
        self.assertEqual(st, 400)
        self.assertIn('server\'s own', got['said'])
        st, got = raw_op(self.agent, self.n, 'pg_allow', {'db': 'acme', 'user': 'acme',
                                                           'peers': ['1.2.3.4\nhost all all']},
                         key_hex=key)
        self.assertIn('plain addresses', got['said'])
        ops = [x.get('op') for x in self.agent.audit()]
        self.assertIn('enroll', ops)
        self.assertIn('status', ops)
        # The refusals are in the audit log too (1.0.113) - never a key, a signature or a code.
        bad = [x for x in self.agent.audit() if x.get('ok') is False]
        said = ' '.join(str(x.get('said')) for x in bad)
        for words in ('not signed', 'seen before', 'time', 'not enrolled', 'client certificate',
                      'not something this agent does', 'plain addresses'):
            self.assertIn(words, said)
        with open(os.path.join(self.agent.dir, 'audit.log')) as f:
            text = f.read()
        self.assertNotIn(key, text)
        self.assertNotIn(code_data(self.code)['s'], text)

    def test_03_network_side_not_root(self):
        kids = subprocess.run(['pgrep', '-P', str(self.agent.proc.pid)], capture_output=True,
                              text=True).stdout.split()
        self.assertTrue(kids)
        with open('/proc/%s/status' % kids[0]) as f:
            uids = [x for x in f.read().splitlines() if x.startswith('Uid:')][0].split()[1:]
        self.assertNotIn('0', uids)
        with open('/proc/%s/status' % self.agent.proc.pid) as f:
            self.assertIn('Uid:\t0\t', f.read())

    def test_04_db_tls_through_agent(self):
        got = self.n.ok('GET', '/api/dbtls')
        self.assertEqual(got['kind'], 'local')
        self.assertEqual(got['db_admin'], 'agent:127.0.0.1:%d' % self.agent.port)
        self.assertEqual(len(got['dbservers']), 1)
        ident = self.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'server',
                                                 'mode': 'verify-full', 'ca_source': 'acme'})['id']
        one = dbtls_wait(self.n, ident)
        self.assertTrue(one['ok'], one)
        self.assertEqual(self.db.sql('SHOW ssl'), 'on')
        self.assertTrue(self.db.sql('SHOW ssl_cert_file').endswith('acme-ha.crt'))
        first = server_cert_der(self.db.port)
        ident = self.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'connect',
                                                 'mode': 'verify-full', 'ca_source': 'acme'})['id']
        one = dbtls_wait(self.n, ident)
        self.assertTrue(one['ok'], one)
        self.assertEqual(self.n.conf.get('db_tls'), 'verify-full')
        got = self.n.py("print(st.db.value('SELECT ssl FROM pg_stat_ssl WHERE pid = "
                        "pg_backend_pid()'))")
        self.assertIn('True', got)
        # Renewed: a new certificate on the server, through the agent, the connection on.
        ident = self.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'server',
                                                 'mode': 'verify-full', 'ca_source': 'acme',
                                                 'renew': True})['id']
        one = dbtls_wait(self.n, ident)
        self.assertTrue(one['ok'], one)
        self.assertNotEqual(server_cert_der(self.db.port), first)
        self.n.ok('GET', '/api/certs/overview')

    def test_05_backup_over_network(self):
        got = self.n.cli('--backup')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)

    def test_06_meter_and_views(self):
        got = self.n.ok('GET', '/api/load')
        rows = got.get('dbservers') or []
        self.assertEqual(len(rows), 1, got)
        self.assertEqual(rows[0]['kind'], 'db')
        for k in ('mem_total', 'cores', 'db'):
            self.assertIn(k, rows[0])
        self.assertTrue(rows[0]['db']['running'])
        v = self.n.ok('GET', '/api/db-agent')
        self.assertEqual(v['db_admin'], 'agent:127.0.0.1:%d' % self.agent.port)
        # what the card of the database server and its wizard read (1.0.113)
        self.assertEqual(v['where']['kind'], 'agent')
        self.assertIsInstance(v['addresses'], list)
        wait_for(lambda: v['servers'] or self.n.ok('GET', '/api/db-agent')['servers'], 20, 1,
                 'the agent looked at')

    def test_07_renew_agent_certs(self):
        before = node_conf_agent(self.n)
        got = self.n.cli('--db-agent-renew')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        after = node_conf_agent(self.n)
        self.assertNotEqual(before['pins'], after['pins'])
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)

    def test_09_agent_down_alert(self):
        self.agent.stop()
        try:
            def alerted():
                out = self.n.py("print(json.dumps(acme._db_agent_alerts(st)))")
                return [a for a in json.loads(out) if a['key'] == 'dbagent:n0']
            got = wait_for(alerted, 60, 2, 'the alert of the agent away')
            self.assertEqual(got[0]['level'], 'bad')
            # in the mail's language too (1.0.113: the hook takes lang)
            cs = json.loads(self.n.py("print(json.dumps(acme._db_agent_alerts(st, lang='cs')))"))
            self.assertIn('neodpovídá', [a for a in cs if a['key'] == 'dbagent:n0'][0]['title'])
            got = json.loads(self.n.py("print(json.dumps(acme.alert_problems(st, 'cs')))"))
            self.assertIn('neodpovídá', got['mod:dbagent:n0']['title'])
            # --ha-join / --ha-setup say the agent does not answer - not "install PostgreSQL
            # there" (1.0.113).
            out = self.n.py("try:\n    acme.pg_install_local(16, print)\nexcept ValueError as e:\n"
                            "    print('SAID', e)")
            self.assertIn('does not answer', out)
            self.assertIn('acme-db-agent', out)
            self.assertNotIn('install it there', out)
        finally:
            self.agent.start()
        wait_for(lambda: not json.loads(self.n.py("print(json.dumps(acme._db_agent_alerts(st)))")),
                 60, 2, 'the alert gone: %s' % self.n.py(
                     "print(st.get_meta('dbagent:node:n0'))"))


    def test_10_cli_opens_the_real_database(self):
        """acme --db-agent-* opens the database config.json names (1.0.113): on a node already
        on PostgreSQL, not a SQLite file made anew with an authority of its own."""
        sq = os.path.join(self.n.tmp, 'state', 'acme.db')
        if os.path.exists(sq):
            os.rename(sq, sq + '.gone')
        try:
            ca_file = self.n.env['ACME_HA_CA']
            before = read_file(ca_file) if os.path.exists(ca_file) else None
            for args in (('--db-agent-status',), ('--db-agent-status', '--json')):
                got = self.n.cli(*args)
                self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertFalse(os.path.exists(sq), 'a SQLite file was made by the command line')
            real = last_json(self.n.py("print(json.dumps(acme.hatls_trust(acme.hatls_ca(st))))"))
            if before is not None:
                self.assertEqual(read_file(ca_file), before)
            cc = read_file(os.path.join(self.n.tmp, 'state', 'db-agent', 'client.crt'))
            with tempfile.NamedTemporaryFile('w', dir=BASE, suffix='.pem') as t:
                t.write(real)
                t.flush()
                ok = subprocess.run(['openssl', 'verify', '-CAfile', t.name], input=cc,
                                    capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        finally:
            if os.path.exists(sq + '.gone'):
                os.rename(sq + '.gone', sq)

    def test_11_nonce_kept_across_a_restart(self):
        key = sign_key_of(self.n)
        nonce = os.urandom(16).hex()
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key, nonce=nonce)
        self.assertEqual(st, 200, got)
        self.agent.stop()
        self.agent.start()
        st, got = raw_op(self.agent, self.n, 'status', key_hex=key, nonce=nonce)
        self.assertEqual(st, 400, got)
        self.assertIn('seen before', got['said'])

    def test_12_trust_never_locks_out(self):
        key = sign_key_of(self.n)
        st, got = raw_op(self.agent, self.n, 'trust', {'ca': ''}, key_hex=key)
        self.assertEqual(st, 400, got)
        self.assertIn('locked out', got['said'])
        t = tempfile.mkdtemp(dir=BASE)
        try:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
                            os.path.join(t, 'k.pem'), '-out', os.path.join(t, 'c.pem'), '-days',
                            '2', '-subj', '/CN=another authority'], capture_output=True, check=True)
            st, got = raw_op(self.agent, self.n, 'trust',
                             {'ca': read_file(os.path.join(t, 'c.pem'))}, key_hex=key)
            self.assertEqual(st, 400, got)
            self.assertIn('not from that authority', got['said'])
        finally:
            shutil.rmtree(t, ignore_errors=True)
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)

    def test_13_pg_prepare_restart_is_not_the_agents(self):
        """pg_prepare says pg_restart_needed - never `restart`, read once as the agent's own
        restart (1.0.113): the network side goes on as it was."""
        pid = network_side_pid(self.agent)
        st, got = raw_op(self.agent, self.n, 'pg_prepare', {
            'db': 'acme', 'user': 'acme', 'password': DB_PW, 'peers': [], 'replicate': False},
            key_hex=sign_key_of(self.n))
        self.assertEqual(st, 200, got)
        self.assertIn('pg_restart_needed', got)
        self.assertNotIn('restart', got)
        self.assertNotIn('agent_restart', got)
        time.sleep(1.5)
        self.assertEqual(network_side_pid(self.agent), pid)

    def test_14_only_its_database(self):
        """The agent is asked only when this node's database IS the one on its server: with the
        agent joined but the database elsewhere, every path is the root helper's (1.0.113)."""
        got = last_json(self.n.py(
            "out = [acme.db_agent_here(), acme.dbtls_kind()]\n"
            "acme._engine.CONFIG['db_port'] = 1\n"
            "out += [acme.db_agent_here(), acme.db_agent_here({'db_engine': 'sqlite'}), "
            "acme.db_agent_where()['kind']]\n"
            "acme.pgtls_send({'id': 'abcdef0123', 'do': 'hba_off', 'port': 1, 'db': 'acme', "
            "'user': 'acme'})\n"
            "print(json.dumps(out))"))
        self.assertEqual(got, [True, 'local', False, False, 'here'])
        ask = os.path.join(self.n.tmp, 'state', 'web', 'pgtls.ask')
        self.assertTrue(os.path.exists(ask))
        os.unlink(ask)

    def test_15_node_moved(self):
        """This node at a new address: let into its database server (pg_hba.conf, the firewall)
        through the agent before the network changes, and said to the other node."""
        got = last_json(self.n.py(
            "print(json.dumps(acme.db_agent_node_moved(st, '127.0.0.1', '192.0.2.77')))"))
        self.assertTrue(got)
        hba = self.db.sql('SHOW hba_file')
        self.assertIn('192.0.2.77/32', read_file(hba))
        ops = [x.get('op') for x in self.agent.audit()]
        self.assertIn('pg_allow', ops)
        self.assertIn('fw_allow', ops)
        row = last_json(self.n.py("print(st.get_meta('dbagent:addr:' + acme.node_name()))"))
        self.assertEqual(row['address'], '192.0.2.77')
        self.n.py("st.db.run(\"DELETE FROM meta WHERE k LIKE 'dbagent:addr:%'\")")

    def test_16_alerts_client_cert_and_version(self):
        got = last_json(self.n.py(
            "a = acme.db_agent(); was = a.get('client_cert_end')\n"
            "acme.db_agent_put({'client_cert_end': acme.time.time() + 5 * 86400})\n"
            "acme._engine.__version__ = '9.9.9'\n"
            "row = acme.db_agent_look(st)\n"
            "keys = [x['key'] for x in acme._db_agent_alerts(st)]\n"
            "cs = [x['title'] for x in acme._db_agent_alerts(st, lang='cs')]\n"
            "lines = acme._db_agent_status_lines(st, None)\n"
            "acme.db_agent_put({'client_cert_end': was})\n"
            "print(json.dumps([keys, row['version_skew'], lines, cs]))"))
        keys, skew, lines, cs = got
        self.assertIn('dbagent:client:n0', keys)
        self.assertIn('dbagent:version:n0', keys)
        self.assertEqual(skew['agent'], '1.0.113')
        self.assertTrue(any('upgrade' in x for x in lines), lines)
        self.assertTrue(any('jinou verzi' in x for x in cs), cs)
        # The daemon's own look puts the row right again (its version is acme's).
        wait_for(lambda: not last_json(self.n.py(
            "print(json.dumps(acme._meta_obj(st, 'dbagent:node:n0').get('version_skew')))")),
            30, 1, 'the version said right again')

    def test_17_code_on_stdin(self):
        """The join code read from standard input (acme --db-agent-join -) or
        ACME_DB_AGENT_CODE - never on a command line (1.0.113)."""
        got = self.n.cli('--db-agent-join', '-', stdin='\n')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('no join code', got.stderr)
        got = self.n.cli('--db-agent-join', stdin=self.agent.code() + '\n')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.n.env['ACME_DB_AGENT_CODE'] = self.agent.code()
        try:
            got = self.n.cli('--db-agent-join', '-')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        finally:
            del self.n.env['ACME_DB_AGENT_CODE']
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(agent_status(self.agent)['clients'], ['n0'])


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (%s) and runuser' % PGBIN)
class TwoNodesOneAgent(unittest.TestCase):
    """Two acme nodes joined to one agent (layout A shared, or an operator joining both): the
    second never locks the first out, the agent's certificate is renewed by itself and put in
    use once both took it in, each node's client certificate is its own, and the side that
    faces the network never holds a signing key."""

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        os.chmod(cls.cadir, 0o755)
        cls.db = PgServer('dbt')
        cls.agent = Agent(cls.db, cls.cadir).start()
        cls.nodes = []
        for name in ('t1', 't2'):
            n = Node(name)
            cls.nodes.append(n)
            n.env.update(ACME_HA_NO_RESTART='1', ACME_NO_RESTART='1',
                         ACME_HA_CA=os.path.join(cls.cadir, 'dbt-%s.pem' % name))
            os.makedirs(os.path.join(n.tmp, 'state', 'web'), exist_ok=True)
            n.add_account()
        cls.fp0 = agent_status(cls.agent)['cert_fp']

    @classmethod
    def tearDownClass(cls):
        quietly(*[n.cleanup for n in getattr(cls, 'nodes', [])],
                *[getattr(cls, x).stop for x in ('agent',) if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db',) if getattr(cls, x, None)],
                lambda: shutil.rmtree(cls.cadir, ignore_errors=True))

    def status_ok(self, n):
        got = n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, '%s: %s' % (n.name, got.stdout + got.stderr))

    def test_01_both_work(self):
        t1, t2 = self.nodes
        got = t1.cli('--db-agent-join', '-', stdin=self.agent.code() + '\n')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.status_ok(t1)
        got = t2.cli('--db-agent-join', '-', stdin=self.agent.code() + '\n')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        # The second joined: the agent answers with the certificate the first pinned.
        self.assertEqual(agent_status(self.agent)['cert_fp'], self.fp0)
        for n in (t1, t2):
            self.status_ok(n)
            self.assertEqual(node_conf_agent(n)['pins'], [self.fp0])
        self.assertEqual(sorted(agent_status(self.agent)['clients']), ['t1', 't2'])
        # Each node's authorities its own (two clusters' authorities side by side).
        with open(os.path.join(self.agent.dir, 'clients.json')) as f:
            cl = json.load(f)
        self.assertTrue(all(x.get('ca') for x in cl))
        self.assertNotEqual(cl[0]['ca'], cl[1]['ca'])

    def test_02_network_side_holds_no_key(self):
        pid = network_side_pid(self.agent)
        self.assertTrue(pid)
        with open('/proc/%d/cmdline' % pid, 'rb') as f:
            self.assertIn(b'--network-side', f.read())
        keys = [sign_key_of(n) for n in self.nodes]
        needles = [k.encode() for k in keys] + [bytes.fromhex(k) for k in keys]
        # (what it does hold is found: the scan sees its memory)
        self.assertEqual(memory_holds(pid, needles + [b'acme-db-agent/1']), {b'acme-db-agent/1'})

    def test_03_renewed_by_the_agent(self):
        """t1 asks the agent for its next certificate: announced, pinned by t1 - not in use
        until t2 took it in too; then in use, both nodes on it."""
        t1, t2 = self.nodes
        got = t1.cli('--db-agent-renew')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        st = agent_status(self.agent)
        nxt = st['cert_next_fp']
        self.assertTrue(nxt)
        self.assertEqual(st['cert_fp'], self.fp0)               # t2 has not taken it in yet
        self.assertEqual(node_conf_agent(t1)['pins'], [self.fp0, nxt])
        self.status_ok(t2)                                      # t2 takes it in: in use now
        wait_for(lambda: agent_status(self.agent)['cert_fp'] == nxt, 30, 0.5,
                 'the next certificate in use')
        for n in (t1, t2):
            self.status_ok(n)
            self.assertEqual(node_conf_agent(n)['pins'], [nxt])
        # t1's client certificate renewed too: t2's is untouched, both get in.
        for n in (t1, t2):
            self.status_ok(n)

    def test_04_burning_codes_and_the_limit(self):
        """Wrong join codes count against the address (and the code only when its id is
        right); failures do block an address (1.0.113)."""
        sys.path.insert(0, os.path.join(ROOT, 'deploy'))
        import acme_db_agent as A
        b = A.Bucket(0.2, 20)
        for _ in range(5):
            b.charge('x', 5)
        self.assertFalse(b.ok('x'))
        self.assertTrue(b.ok('y'))
        # A stranger guessing (no id, or another): the code of the node is not burnt.
        code = self.agent.code()
        for _ in range(6):
            st, got = post_plain(self.agent.port, '/v1/enroll/begin',
                                 {'secret': 'x' * 24, 'node': 'evil'})
            self.assertEqual(st, 400, got)
        data = code_data(code)
        st, got = post_plain(self.agent.port, '/v1/enroll/begin',
                             {'secret': data['s'], 'code_id': data['i'], 'node': 'late'})
        self.assertEqual(st, 200, got)
        tok = got['token']
        # A second begin with the same code (somebody who saw it): the first one's token still
        # finishes - and a finish without a token of a begin is refused.
        st, got2 = post_plain(self.agent.port, '/v1/enroll/begin',
                              {'secret': data['s'], 'code_id': data['i'], 'node': 'other'})
        self.assertEqual(st, 200, got2)
        st, got = post_plain(self.agent.port, '/v1/enroll/finish',
                             {'secret': data['s'], 'code_id': data['i'], 'node': 'late',
                              'token': 'nope', 'sign_key': '0' * 64, 'ca': '', 'client_cert': ''})
        self.assertEqual(st, 400, got)
        self.assertIn('begun', got['said'])
        self.assertTrue(tok)
        # The code's id right, the secret wrong: that code is burnt after five.
        code2 = self.agent.code()
        d2 = code_data(code2)
        for _ in range(5):
            post_plain(self.agent.port, '/v1/enroll/begin',
                       {'secret': 'y' * 24, 'code_id': d2['i'], 'node': 'evil'})
        st, got = post_plain(self.agent.port, '/v1/enroll/begin',
                             {'secret': d2['s'], 'code_id': d2['i'], 'node': 'late'})
        self.assertEqual(st, 400, got)
        # The address is refused after ten wrong codes in an hour, the right one too.
        st, got = post_plain(self.agent.port, '/v1/enroll/begin',
                             {'secret': data['s'], 'code_id': data['i'], 'node': 'late'})
        self.assertEqual(st, 400, got)
        self.assertIn('too many', got['said'])
        refused = [x for x in self.agent.audit() if x.get('ok') is False and
                   str(x.get('op')).startswith('enroll')]
        self.assertGreaterEqual(len(refused), 10)
        # The nodes joined are not disturbed.
        for n in self.nodes:
            self.status_ok(n)


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (%s) and runuser' % PGBIN)
class AgentLimits(unittest.TestCase):
    """An agent with the default limits: failures from an address do block it (429)."""

    def test_failures_block(self):
        cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        db = PgServer('dbl')
        agent = None
        try:
            agent = Agent(db, cadir, fail_burst=20).start()
            seen = []
            for _ in range(8):
                st, _ = post_plain(agent.port, '/v1/op', {'op': 'status'})
                seen.append(st)
            self.assertEqual(seen[0], 401)
            self.assertIn(429, seen)
        finally:
            quietly(*([agent.stop] if agent else []), db.cleanup,
                    lambda: shutil.rmtree(cadir, ignore_errors=True))

    def test_never_nobody(self):
        got = subprocess.run([sys.executable, '-I', '-c',
                              'import sys; sys.path.insert(0, %r); import acme_db_agent as A; '
                              'A.drop_to({"user": "nobody"})' % os.path.join(ROOT, 'deploy')],
                             capture_output=True, text=True)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('not nobody', got.stderr)
        got = subprocess.run([sys.executable, '-I', '-c',
                              'import sys; sys.path.insert(0, %r); import acme_db_agent as A; '
                              'A.drop_to({"user": "no-such-account-x"})'
                              % os.path.join(ROOT, 'deploy')], capture_output=True, text=True)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('not there', got.stderr)


class DeployParts(unittest.TestCase):
    """The unit, install.sh and db-server.sh: hardening, no password on a command line, the
    firewall's lines said, pg_hba.conf written link-safe (1.0.113)."""

    def read(self, *p):
        with open(os.path.join(ROOT, *p)) as f:
            return f.read()

    def test_unit(self):
        u = self.read('deploy', 'acme-db-agent.service')
        for want in ('ProtectSystem=strict', 'PrivateDevices=yes', 'CapabilityBoundingSet=',
                     'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK',
                     '-/etc/pki/acme', '/etc/acme-db-agent', '-/var/lib/pgsql', '-/etc/my.cnf.d'):
            self.assertIn(want, u)
        self.assertNotIn('ProtectSystem=full', u)

    def test_no_password_on_a_command_line(self):
        s = self.read('deploy', 'db-server.sh')
        for line in s.splitlines():
            if "'$DBS_PASSWORD'" in line and not line.lstrip().startswith(
                    ('pg_psql_secret ', 'my_q_secret ')):
                self.fail('a password on a command line: %s' % line.strip())
        self.assertNotIn('cp -p "$hba"', s)
        self.assertIn('O.hba_add(', s)
        i = self.read('install.sh')
        self.assertIn('--db-password-file)', i)

    def shell(self, script, env=None):
        stubs = ('run() { if [[ -n "$DRY_RUN" ]]; then echo "[would run] $*"; return 0; fi; '
                 '"$@"; }\nsay() { echo "$*"; }\nnote() { echo "$*"; }\nwarn() { echo "$*"; }\n'
                 'good() { echo "$*"; }\nstep() { echo "$*"; }\nfail() { echo "FAIL $*"; '
                 'exit 1; }\nC_BAD=""; C_OFF=""\n')
        return subprocess.run(['bash', '-c', stubs + '. %s\n' % os.path.join(
            ROOT, 'deploy', 'db-server.sh') + script], capture_output=True, text=True,
            env=dict(os.environ, **(env or {})))

    def test_dry_run_masks_the_password(self):
        got = self.shell('DRY_RUN=yes; DBS_PASSWORD="Secret-Pw-4711"; DBS_USER=acme\n'
                         'pg_psql_secret "CREATE ROLE acme LOGIN PASSWORD \'…\'" '
                         '"CREATE ROLE acme LOGIN PASSWORD \'$DBS_PASSWORD\'"\n'
                         'my_q_secret "CREATE USER" "CREATE USER x IDENTIFIED BY \'$DBS_PASSWORD\'"\n')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('the password not shown', got.stdout)
        self.assertNotIn('Secret-Pw-4711', got.stdout + got.stderr)

    def test_firewall_lines_without_acme_node(self):
        t = tempfile.mkdtemp(dir=BASE)
        try:
            with open(os.path.join(t, 'firewall-cmd'), 'w') as f:
                f.write('#!/bin/sh\nexit 0\n')
            os.chmod(os.path.join(t, 'firewall-cmd'), 0o755)
            got = self.shell('ACME_NODES=""; DB_AGENT_PORT=9443; DBS_PORT=5432; DRY_RUN=\n'
                             'dbs_firewall\n', env={'PATH': t + ':' + os.environ['PATH']})
        finally:
            shutil.rmtree(t, ignore_errors=True)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('port port="9443" protocol="tcp" accept', got.stdout)
        self.assertIn('port port="5432" protocol="tcp" accept', got.stdout)
        self.assertIn('firewall-cmd --permanent --add-rich-rule=', got.stdout)
        self.assertIn('firewall-cmd --reload', got.stdout)


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (%s) and runuser' % PGBIN)
class ReplicatedExternal(unittest.TestCase):
    """Layout B: acme1 -> db1, acme2 -> db2, db1 <-> db2 replicating, through the agents."""

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        os.chmod(cls.cadir, 0o755)
        cls.db1, cls.db2 = PgServer('db1'), PgServer('db2')
        cls.ag1, cls.ag2 = Agent(cls.db1, cls.cadir).start(), Agent(cls.db2, cls.cadir).start()
        extra = {'dns_server': 1, 'dns_zone': 'acme.test', 'certs_check_min': 1}
        cls.a, cls.b = Node('n1', extra=extra), Node('n2', extra=extra)
        for n, db in ((cls.a, cls.db1), (cls.b, cls.db2)):
            n.env.update(ACME_HA_NO_RESTART='1', ACME_NO_RESTART='1',
                         ACME_HA_CA=os.path.join(cls.cadir, db.name + '.pem'))
            os.makedirs(os.path.join(n.tmp, 'state', 'web'), exist_ok=True)
        cls.a.add_account()
        cls.b.add_account()
        for n, ag in ((cls.a, cls.ag1), (cls.b, cls.ag2)):
            got = n.cli('--db-agent-join', ag.code())
            if got.returncode != 0:
                raise RuntimeError('%s --db-agent-join: %s %s' % (n.name, got.stdout, got.stderr))
        cls.a.py("print(acme.db_make_here({'db_engine': 'postgres', 'db_host': '127.0.0.1', "
                 "'db_port': %d, 'db_name': 'acme', 'db_user': 'acme', 'db_password': %r}))"
                 % (cls.db1.port, DB_PW))
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move',
                              'postgres', '--db-host', '127.0.0.1', '--db-port',
                              str(cls.db1.port), '--yes'],
                             env=dict(cls.a.env, ACME_DB_PASSWORD=DB_PW), capture_output=True,
                             text=True, timeout=300)
        if got.returncode != 0:
            raise RuntimeError('--db-move: %s %s' % (got.stdout, got.stderr))
        bundle = os.path.join(cls.a.tmp, 'bundle.json')
        got = cls.a.cli('--ha-setup', '--ha-peer', '127.0.0.1', '--ha-peer-port',
                        str(cls.db2.port), '--ha-peer-node', '127.0.0.1', '--ha-address',
                        '127.0.0.1', '--node-name', 'n1', '--ha-bundle', bundle, '--yes')
        cls.setup_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--ha-setup: %s' % cls.setup_out)
        cls.b.env['ACME_HA_PASSPHRASE'] = passphrase_of(got.stdout)
        got = cls.b.cli('--ha-join', bundle, '--node-name', 'n2', '--yes')
        cls.join_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--ha-join: %s' % cls.join_out)
        for n in (cls.a, cls.b):
            n.set_conf(api_port=n.port, dns_port=n.dns_port)
        cls.a.start()
        cls.b.start()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('a', 'b') if getattr(cls, x, None)],
                *[getattr(cls, x).stop for x in ('ag1', 'ag2') if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db1', 'db2') if getattr(cls, x, None)],
                lambda: shutil.rmtree(cls.cadir, ignore_errors=True))

    def rows(self, db, sql):
        return db.sql(sql, 'acme')

    def sync(self):
        mark = 'sync:%s' % time.time()
        for n, mine, other in ((self.a, self.db1, self.db2), (self.b, self.db2, self.db1)):
            mine.sql("INSERT INTO meta (k, v) VALUES ('%s', '1')" % (mark + n.name), 'acme')
            wait_for(lambda: other.sql("SELECT 1 FROM meta WHERE k = '%s'" % (mark + n.name),
                                       'acme') == '1', 60, 0.3, 'replication from %s' % n.name)

    def test_00_wizard(self):
        c1, c2 = self.a.conf, self.b.conf
        self.assertEqual((c1['ha_mode'], c1['ha_slot']), ('replicated', 1))
        self.assertEqual((c2['ha_mode'], c2['ha_slot']), ('replicated', 2))
        self.assertEqual(c2['db_port'], self.db2.port)
        self.assertEqual(c1['ha_peer_port'], self.db2.port)
        for db in (self.db1, self.db2):
            self.assertEqual(db.sql('SHOW wal_level'), 'logical')
            self.assertEqual(db.sql('SHOW listen_addresses'), '*')
        self.assertIn('acme_from_2', self.rows(self.db1, 'SELECT subname FROM pg_subscription'))
        self.assertIn('acme_from_1', self.rows(self.db2, 'SELECT subname FROM pg_subscription'))
        self.assertTrue(self.b.session)
        ops1 = [x.get('op') for x in self.ag1.audit()]
        for op in ('pg_prepare', 'pg_restart', 'pg_publication'):
            self.assertIn(op, ops1, self.setup_out)
        self.assertIn('pg_prepare', [x.get('op') for x in self.ag2.audit()], self.join_out)

    def test_01_both_ways(self):
        self.sync()

    def test_02_link_tls(self):
        def steps(n):
            v = n.ok('GET', '/api/ha').get('link_tls') or {}
            return {x['name']: x.get('step') for x in v.get('nodes') or []}
        self.a.ok('POST', '/api/ha', {'action': 'tls_link'})
        for n in (self.a, self.b):
            wait_for(lambda: steps(n) == {'n1': 'done', 'n2': 'done'} or
                     'failed' in steps(n).values(), 300, 2, 'the link encrypted (%s)' % n.name)
            self.assertEqual(steps(n), {'n1': 'done', 'n2': 'done'},
                             (n.ok('GET', '/api/ha').get('link_tls'), n.out()[-3000:]))
            self.assertEqual(n.conf.get('ha_tls'), 'verify-full')
        for db in (self.db1, self.db2):
            self.assertEqual(db.sql('SHOW ssl'), 'on')
            conn = db.sql("SELECT subconninfo FROM pg_subscription", 'acme')
            self.assertIn("sslmode='verify-full'", conn)
        self.assertIn('pgtls', [x.get('op') for x in self.ag1.audit()])
        self.sync()
        # Both database servers beside the nodes, each node's agent's word (carried over).
        got = wait_for(lambda: [x for x in self.a.ok('GET', '/api/ha').get('dbservers') or []
                                if x.get('alive')] if len(self.a.ok('GET', '/api/ha')
                                                         .get('dbservers') or []) == 2 else None,
                       90, 2, 'both database servers on the High availability page')
        self.assertEqual(sorted(x['node'] for x in got), ['n1', 'n2'])
        self.assertTrue(all(x['kind'] == 'db' for x in got))

    def test_03_rebuild_second(self):
        self.b.stop()
        got = self.b.cli('--ha-resync', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.b.start()
        self.sync()

    def test_04_the_other_node_is_peer_node(self):
        """Layout B: ha_peer is the other DATABASE server; what is the nodes' own (the clocks'
        peers, the addresses the firewall always lets in, the VIP's other node) takes the other
        acme node (--ha-peer-node) - the database server only for the database (1.0.113)."""
        got = last_json(self.a.py(
            "a = acme.db_agent(); a['peer_node'] = '192.0.2.50'\n"
            "c = acme._engine.CONFIG; c['ha_peer'] = '192.0.2.60'\n"
            "print(json.dumps([acme.ha_peer_node(), sorted(acme.cluster_addresses(st, "
            "acme.node_name())), acme.db_agent_link_peers()]))"))
        node, addrs, link = got
        self.assertEqual(node, '192.0.2.50')
        self.assertIn('192.0.2.50', addrs)
        self.assertNotIn('192.0.2.60', addrs)
        self.assertEqual(link, ['192.0.2.60', '192.0.2.50'])     # the database's: both

    def test_05_other_node_moved(self):
        """acme1 at a new address: acme2's agent lets it into db2 (pg_hba.conf, firewall) and
        acme2's peer_node follows."""
        had = node_conf_agent(self.b).get('peer_node')
        self.assertTrue(had)
        self.a.py("st.set_meta('dbagent:addr:n1', json.dumps({'address': '192.0.2.88', "
                  "'old': %r, 'at': 1}))" % had)
        wait_for(lambda: node_conf_agent(self.b).get('peer_node') == '192.0.2.88', 90, 2,
                 'acme2 letting acme1 in at its new address')
        self.assertIn('192.0.2.88/32', read_file(self.db2.sql('SHOW hba_file')))
        self.assertIn('fw_allow', [x.get('op') for x in self.ag2.audit()])
        self.b.py("acme.db_agent_put({'peer_node': %r}); "
                  "st.db.run(\"DELETE FROM meta WHERE k LIKE 'dbagent:addr:%%'\")" % had)

    def test_06_moves_refused(self):
        """Each node's database on its own server, replicating: no move breaks it (1.0.113) -
        not to another engine, server or this machine, from the command line nor the wizard;
        nor another agent joined in the place of the one its database is on."""
        for args in (['sqlite'], ['postgres', '--db-host', '127.0.0.1', '--db-port', '5'],
                     ['mariadb', '--db-port', '6']):
            got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move'] +
                                 args + ['--db-make', '--yes'],
                                 env=dict(self.a.env, ACME_DB_PASSWORD=DB_PW), capture_output=True,
                                 text=True, timeout=120)
            self.assertEqual(got.returncode, 3, got.stdout + got.stderr)
            self.assertIn('each node\'s database on a server of its own', got.stderr)
            self.assertIn('acme --ha-standalone', got.stderr)
        g = self.a.ok('POST', '/api/db', {'action': 'wiz_start'})['guard']
        self.assertTrue(g['refused'])
        self.assertIn('another engine, another server or back onto this machine', g['why'])
        st, got = self.a.call('POST', '/api/db', {'action': 'wiz_make', 'how': 'local', 'settings': {
            'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': self.db2.port,
            'db_name': 'other', 'db_user': 'other', 'db_password': DB_PW}})
        self.assertEqual(st, 409, got)
        got = self.a.cli('--db-agent-join', '-', stdin=self.ag2.code() + '\n')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('one of a cluster and its database is on', got.stderr)
        self.assertEqual(node_conf_agent(self.a)['port'], self.ag1.port)


def can_run_my():
    return os.geteuid() == 0 and shutil.which('mariadb-install-db') and shutil.which('mariadbd') \
        and shutil.which('mariadb')


class MyServer(object):
    """A MariaDB of its own: its folder, its port and socket; started again by a script the
    agent's configuration names (as systemctl restart mariadb would)."""

    def __init__(self, name):
        self.name = name
        self.top = tempfile.mkdtemp(prefix='acme-extdb-%s-' % name, dir=BASE)
        os.chmod(self.top, 0o755)
        self.dir = os.path.join(self.top, 'my')
        self.data = os.path.join(self.dir, 'data')
        self.cnf_dir = os.path.join(self.dir, 'conf.d')
        os.makedirs(self.cnf_dir)
        self.port = free_port()
        self.sock = os.path.join(self.dir, 'mysqld.sock')
        self.cnf = os.path.join(self.dir, 'my.cnf')
        with open(self.cnf, 'w') as f:
            f.write('[mariadb]\ndatadir=%s\nsocket=%s\nport=%d\nbind-address=127.0.0.1\n'
                    'pid-file=%s/mysqld.pid\nlog-error=%s/err.log\n!includedir %s\n'
                    % (self.data, self.sock, self.port, self.dir, self.dir, self.cnf_dir))
        shutil.chown(self.dir, 'mysql', 'mysql')
        subprocess.run(['mariadb-install-db', '--defaults-file=' + self.cnf, '--user=mysql',
                        '--auth-root-authentication-method=socket', '--skip-test-db'],
                       capture_output=True, check=True)
        self.script = os.path.join(self.top, 'restart.sh')
        with open(self.script, 'w') as f:
            f.write('#!/bin/sh\nmariadb-admin --socket=%s -u root shutdown 2>/dev/null\n'
                    'for i in $(seq 50); do [ -S %s ] || break; sleep 0.2; done\n'
                    'nohup mariadbd --defaults-file=%s --user=mysql >/dev/null 2>&1 &\n'
                    'for i in $(seq 100); do mariadb --socket=%s -u root -e "SELECT 1" '
                    '>/dev/null 2>&1 && exit 0; sleep 0.2; done\nexit 1\n'
                    % (self.sock, self.sock, self.cnf, self.sock))
        os.chmod(self.script, 0o755)
        subprocess.run(['/bin/sh', self.script], check=True)

    def restart_cmd(self):
        return ['/bin/sh', self.script]

    def sql(self, text):
        return subprocess.run(['mariadb', '--socket=' + self.sock, '-u', 'root', '-N', '-B',
                               '-e', text], capture_output=True, text=True).stdout.strip()

    def cleanup(self):
        subprocess.run(['mariadb-admin', '--socket=' + self.sock, '-u', 'root', 'shutdown'],
                       capture_output=True)
        try:
            with open(os.path.join(self.dir, 'mysqld.pid')) as f:
                os.kill(int(f.read().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        if not os.environ.get('ACME_TEST_KEEP'):
            shutil.rmtree(self.top, ignore_errors=True)


@unittest.skipUnless(can_run_my(), 'needs root and MariaDB (mariadb-install-db, mariadbd)')
class StandaloneMariaDb(unittest.TestCase):
    """Layout A with MariaDB: the database and its account made through the agent, the move,
    MariaDB given a certificate from acme's authority (and restarted) by the agent, the
    connection verify-full - and a renewal taken by FLUSH SSL without a restart."""

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        cls.db = MyServer('mya')
        cls.agent = Agent(cls.db, cls.cadir)
        with open(cls.agent.conf) as f:
            c = json.load(f)
        c.update(engine='mariadb', my_port=cls.db.port, my_socket=cls.db.sock,
                 my_cnf_dir=cls.db.cnf_dir, my_tls_dir=os.path.join(cls.db.top, 'tls'),
                 my_restart_cmd=['/bin/sh', cls.db.script])
        c.pop('pg_restart_cmd', None)
        with open(cls.agent.conf, 'w') as f:
            json.dump(c, f)
        cls.agent.start()
        cls.n = Node('m0')
        cls.n.env.update(ACME_HA_NO_RESTART='1', ACME_NO_RESTART='1',
                         ACME_HA_CA=os.path.join(cls.cadir, 'mya.pem'))
        cls.n.add_account()
        got = cls.n.cli('--db-agent-join', cls.agent.code())
        if got.returncode != 0:
            raise RuntimeError('--db-agent-join: %s %s' % (got.stdout, got.stderr))
        cls.n.py("print(acme.db_make_here({'db_engine': 'mariadb', 'db_host': '127.0.0.1', "
                 "'db_port': %d, 'db_name': 'acme', 'db_user': 'acme', 'db_password': %r}))"
                 % (cls.db.port, DB_PW))
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move',
                              'mariadb', '--db-host', '127.0.0.1', '--db-port', str(cls.db.port),
                              '--yes'], env=dict(cls.n.env, ACME_DB_PASSWORD=DB_PW),
                             capture_output=True, text=True, timeout=300)
        if got.returncode != 0 or cls.n.conf.get('db_engine') != 'mariadb':
            raise RuntimeError('--db-move: %s %s' % (got.stdout, got.stderr))
        cls.n.start()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('n',) if getattr(cls, x, None)],
                *[getattr(cls, x).stop for x in ('agent',) if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db',) if getattr(cls, x, None)],
                lambda: shutil.rmtree(cls.cadir, ignore_errors=True))

    def test_01_status(self):
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('mariadb', got.stdout)
        self.assertGreaterEqual(int(self.db.sql("SELECT COUNT(*) FROM mysql.user WHERE User = 'acme'")), 3)

    def test_02_tls_then_verify_full(self):
        got = self.n.cli('--db-agent-mariadb-tls')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('restart', got.stdout.lower())
        self.assertEqual(self.db.sql('SELECT @@have_ssl'), 'YES')
        # MariaDB was started again: the daemon's connection comes back by itself
        wait_for(lambda: self.n.call('GET', '/api/dbtls')[0] == 200, 60, 1,
                 'the daemon on its database again')
        ident = self.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'connect',
                                                 'mode': 'verify-full', 'ca_source': 'acme'})['id']
        one = dbtls_wait(self.n, ident)
        self.assertTrue(one['ok'], one)
        self.assertEqual(self.n.conf.get('db_tls'), 'verify-full')
        started = self.db.sql('SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS '
                              "WHERE VARIABLE_NAME = 'UPTIME'")
        # renewed: FLUSH SSL, no restart
        got = self.n.cli('--db-agent-mariadb-tls')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('FLUSH SSL', got.stdout)
        later = self.db.sql('SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS '
                            "WHERE VARIABLE_NAME = 'UPTIME'")
        self.assertGreaterEqual(int(later), int(started))
        self.n.ok('GET', '/api/certs/overview')

    def test_03_renewed_by_itself(self):
        """The MariaDB's certificate from acme renewed through the agent 45 days before it ends
        (1.0.113), as the agent thread does every hour - not a day sooner."""
        # given through the daemon's own path (as the page's Turn TLS on): its row is kept
        self.n.py("acme.db_agent_mariadb_tls(st, 'tester')")
        out = self.n.py("print(acme.db_agent_mariadb_renew(st) is None)")
        self.assertIn('True', out)                              # far from its end: left alone
        out = self.n.py(
            "k = 'dbtls:server:' + acme.node_name(); v = json.loads(st.get_meta(k)); "
            "v['cert_end'] = acme.time.time() + 10 * 86400; st.set_meta(k, json.dumps(v)); "
            "got = acme.db_agent_mariadb_renew(st); "
            "print(json.dumps([bool(got), json.loads(st.get_meta(k))['cert_end'] - acme.time.time()]))")
        done, left = json.loads(out.strip().splitlines()[-1])
        self.assertTrue(done)
        self.assertGreater(left, 300 * 86400)



def my_agent(db, cadir):
    """An agent for a MariaDB of its own (as StandaloneMariaDb makes it), started."""
    ag = Agent(db, cadir)
    with open(ag.conf) as f:
        c = json.load(f)
    c.update(engine='mariadb', my_port=db.port, my_socket=db.sock, my_cnf_dir=db.cnf_dir,
             my_tls_dir=os.path.join(db.top, 'tls'), my_restart_cmd=['/bin/sh', db.script])
    c.pop('pg_restart_cmd', None)
    with open(ag.conf, 'w') as f:
        json.dump(c, f)
    return ag.start()


@unittest.skipUnless(can_run() and can_run_my(), 'needs root, PostgreSQL 16 and MariaDB')
class EngineMoves(unittest.TestCase):
    """Moves between engines and servers with the database servers' agents (1.0.113), from the
    command line (acme --db-move ... --db-make): a PostgreSQL with its agent -> a MariaDB with
    another agent and back, each made through the target's agent, the TLS of the server left
    behind never carried; then off the agents' servers onto this machine's PostgreSQL, MariaDB
    and SQLite - the agent let go (db_admin local), nothing asked of it any more.

    One agent a node: joining another replaces the one there was (agent.json.replaced, said);
    a move off the agent's server lets it go (agent.json.forgotten, said)."""

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.cadir = tempfile.mkdtemp(prefix='acme-extdb-ca-', dir=BASE)
        os.chmod(cls.cadir, 0o755)
        cls.pga = PgServer('mva')                       # PostgreSQL with agent A
        cls.aga = Agent(cls.pga, cls.cadir).start()
        cls.myb = MyServer('mvb')                       # MariaDB with agent B
        cls.agb = my_agent(cls.myb, cls.cadir)
        cls.pgl = PgServer('mvl')                       # "this machine's" PostgreSQL, no agent
        cls.myl = MyServer('mvm')                       # "this machine's" MariaDB, no agent
        cls.myl.sql("CREATE DATABASE acme CHARACTER SET utf8mb4 COLLATE utf8mb4_bin; "
                    "CREATE USER 'acme'@'127.0.0.1' IDENTIFIED BY '%s'; "
                    "GRANT ALL PRIVILEGES ON acme.* TO 'acme'@'127.0.0.1'; FLUSH PRIVILEGES" % DB_PW)
        cls.n = Node('mv0', extra={'perf_meter': True})
        cls.n.env.update(ACME_HA_NO_RESTART='1', ACME_NO_RESTART='1',
                         ACME_HA_CA=os.path.join(cls.cadir, 'mva.pem'),
                         ACME_DBAGENT_EVERY='2', ACME_DBAGENT_DOWN_S='3')
        os.makedirs(os.path.join(cls.n.tmp, 'state', 'web'), exist_ok=True)
        cls.n.add_account()
        cls.n.py("st.add_event('settings', 'a row to carry along')")
        got = cls.n.cli('--db-agent-join', '-', stdin=cls.aga.code() + '\n')
        if got.returncode != 0:
            raise RuntimeError('--db-agent-join: %s %s' % (got.stdout, got.stderr))
        out = cls.move('postgres', cls.pga.port, make=True)
        if 'made ' not in out:
            raise RuntimeError('--db-make said nothing: %s' % out)
        cls.n.start()
        cls.tls_on()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('n',) if getattr(cls, x, None)],
                *[getattr(cls, x).stop for x in ('aga', 'agb') if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('pga', 'myb', 'pgl', 'myl')
                  if getattr(cls, x, None)],
                lambda: shutil.rmtree(cls.cadir, ignore_errors=True))

    @classmethod
    def move(cls, engine, port=None, make=False, pw=None, more=(), ok=True):
        """acme --db-move with the daemon stopped (it is started again by the test)."""
        cls.n.stop()
        args = ['--db-move', engine]
        if engine != 'sqlite':
            args += ['--db-host', '127.0.0.1', '--db-port', str(port)]
        args += (['--db-make'] if make else []) + list(more) + ['--yes']
        env = dict(cls.n.env)
        env.pop('ACME_DB_PASSWORD', None)
        if pw:
            env['ACME_DB_PASSWORD'] = pw
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + args, env=env,
                             capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        out = got.stdout + got.stderr
        if ok and got.returncode != 0:
            raise AssertionError('--db-move %s: %s' % (' '.join(args), out))
        return out

    @classmethod
    def tls_on(cls):
        for phase in ('server', 'connect'):
            ident = cls.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': phase,
                                                    'mode': 'verify-full', 'ca_source': 'acme'})['id']
            one = dbtls_wait(cls.n, ident)
            if not one.get('ok'):
                raise AssertionError('Database -> TLS %s: %s' % (phase, one))

    def agent_dir(self):
        return os.path.join(self.n.tmp, 'state', 'db-agent')

    def view(self):
        return self.n.ok('GET', '/api/db-agent')

    def join(self, agent):
        got = self.n.cli('--db-agent-join', '-', stdin=agent.code() + '\n')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        return got.stdout + got.stderr

    def events(self):
        return self.n.py("print(json.dumps([r['words'] for r in st.db.rows("
                         "'SELECT words FROM events ORDER BY id')]))")

    def test_01_pg_agent_to_mariadb_agent(self):
        self.assertEqual(self.n.conf.get('db_tls'), 'verify-full')
        # Another agent joined: it takes the place of the first, and says the database is
        # still on the first one's server.
        out = self.join(self.agb)
        self.assertIn('NOTE: this node\'s database is still on 127.0.0.1', out)
        self.assertIn('--forget mv0', out)
        a = node_conf_agent(self.n)
        self.assertEqual((a['engine'], a['port']), ('mariadb', self.agb.port))
        self.assertNotIn('peer_node', a)
        with open(os.path.join(self.agent_dir(), 'agent.json.replaced')) as f:
            self.assertEqual(json.load(f)['port'], self.aga.port)
        # Not on the agent's server yet: nothing of the agent is asked meanwhile.
        self.assertIn('False', self.n.py('print(acme.db_agent_here())'))
        out = self.move('mariadb', self.myb.port, make=True)
        self.assertIn('made ', out)
        self.assertIn("the account 'acme'", out)
        self.assertIn('not carried', out)                       # verify-full of PostgreSQL
        self.assertIn('acme --db-agent-mariadb-tls', out)
        c = self.n.conf
        self.assertEqual((c['db_engine'], c['db_port']), ('mariadb', self.myb.port))
        self.assertFalse(c.get('db_tls'))
        self.assertFalse(c.get('db_tls_ca'))
        # A MariaDB asked for TLS it does not offer is never used in the clear.
        out = self.n.py("c = {k: acme._engine.CONFIG.get(k) for k in acme.DB_KEYS}; "
                        "c['db_tls'] = 'require'\n"
                        "try:\n    acme.db_open(c).value('SELECT 1'); print('PLAIN')\n"
                        "except acme.DbError as e:\n    print('REFUSED', e)")
        self.assertIn('REFUSED', out)
        self.assertIn('does not offer it', out)
        # The rows of the PostgreSQL server were left behind; the card is the MariaDB's.
        self.assertEqual(self.n.py("print(st.get_meta('dbtls:server:mv0'))").strip(), 'None')
        self.n.start()
        v = wait_for(lambda: (lambda x: x if x['servers'] else None)(self.view()), 30, 1,
                     'the MariaDB server on the card')
        self.assertEqual(v['where']['kind'], 'agent')
        self.assertEqual(v['engine'], 'mariadb')
        me = [x for x in v['servers'] if x['me']][0]
        self.assertEqual((me['engine'], me['port']), ('mariadb', self.agb.port))
        self.assertEqual(me['facts']['engine'], 'mariadb')
        # TLS through the new agent, then verify-full
        got = self.n.cli('--db-agent-mariadb-tls')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        wait_for(lambda: self.n.call('GET', '/api/dbtls')[0] == 200, 60, 1, 'the daemon back')
        ident = self.n.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'connect',
                                                 'mode': 'verify-full', 'ca_source': 'acme'})['id']
        self.assertTrue(dbtls_wait(self.n, ident)['ok'])
        self.assertEqual(self.n.conf.get('db_tls'), 'verify-full')
        self.assertIn('a row to carry along', self.events())

    def test_02_mariadb_agent_back_to_pg_agent(self):
        out = self.join(self.aga)
        self.assertIn('NOTE', out)
        self.assertEqual(node_conf_agent(self.n)['engine'], 'postgres')
        # The old copy is still there (the way back): thrown away as said; the account made
        # again through agent A.
        out = self.move('postgres', self.pga.port, make=True, more=['--db-overwrite'])
        self.assertIn('not carried', out)
        c = self.n.conf
        self.assertEqual((c['db_engine'], c['db_port']), ('postgres', self.pga.port))
        self.assertFalse(c.get('db_tls'))
        self.n.start()
        v = self.view()
        self.assertEqual((v['where']['kind'], v['engine']), ('agent', 'postgres'))
        self.assertIn('True', self.n.py('print(acme.db_agent_here())'))
        self.tls_on()
        self.assertEqual(self.n.conf.get('db_tls'), 'verify-full')
        self.assertIn('a row to carry along', self.events())

    def test_03_agent_to_this_machines_postgres(self):
        before = len(self.aga.audit())
        out = self.move('postgres', self.pgl.port, make=True)
        self.assertIn('made ', out)
        self.assertIn('no longer looks after this node\'s database', out)
        self.assertIn('db_admin is local again', out)
        self.assertFalse(os.path.exists(os.path.join(self.agent_dir(), 'agent.json')))
        self.assertTrue(os.path.exists(os.path.join(self.agent_dir(), 'agent.json.forgotten')))
        self.assertFalse(self.n.conf.get('db_tls'))
        self.n.start()
        v = self.view()
        self.assertEqual(v['db_admin'], 'local')
        self.assertEqual(v['where']['kind'], 'here')
        self.assertEqual(v['servers'], [])
        got = json.loads(self.n.py(
            "print(json.dumps([acme.db_admin(), acme.db_agent_here(), acme.dbtls_kind()]))"))
        self.assertEqual(got, ['local', False, 'local'])
        for path in ('/api/ha', '/api/load'):
            self.assertNotIn('dbservers', self.n.ok('GET', path), path)
        self.assertNotIn('dbservers', self.n.call('GET', '/api/dbtls')[1])
        time.sleep(6)                   # the agent's look every 2 s, were it still asked
        asked = [x.get('op') for x in self.aga.audit()[before:] if x.get('node') == 'mv0']
        self.assertEqual(asked, [])
        self.assertIn('a row to carry along', self.events())

    def test_04_local_postgres_to_sqlite(self):
        out = self.move('sqlite', more=['--db-path', os.path.join(self.n.tmp, 'state', 'b.db')])
        self.assertNotIn('no longer looks after', out)
        self.n.start()
        self.assertEqual(self.view()['db_admin'], 'local')
        self.assertIn('a row to carry along', self.events())

    def test_05_agent_to_sqlite_and_mariadb(self):
        # SQLite -> MariaDB with agent B -> this machine's MariaDB: the agent let go
        self.join(self.agb)
        self.move('mariadb', self.myb.port, make=True, more=['--db-overwrite'])
        self.n.start()
        self.assertEqual(self.view()['where']['kind'], 'agent')
        out = self.move('mariadb', self.myl.port, pw=DB_PW)
        self.assertIn('db_admin is local again', out)
        self.n.start()
        v = self.view()
        self.assertEqual((v['db_admin'], v['where']['kind'], v['servers']), ('local', 'here', []))
        # ... and agent A's server -> SQLite: let go too
        self.join(self.aga)
        self.move('postgres', self.pga.port, make=True, more=['--db-overwrite'])
        out = self.move('sqlite', more=['--db-path', os.path.join(self.n.tmp, 'state', 'c.db')])
        self.assertIn('db_admin is local again', out)
        self.n.start()
        v = self.view()
        self.assertEqual((v['db_admin'], v['where']['kind']), ('local', 'file'))
        self.assertIn('a row to carry along', self.events())

    def test_06_make_refused_elsewhere(self):
        # --db-make on a server neither here nor the agent's: refused, the SQL said
        self.n.stop()
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move', 'postgres',
                              '--db-host', '192.0.2.77', '--db-make', '--db-check'],
                             env=dict(self.n.env, ACME_DB_PASSWORD=DB_PW), capture_output=True,
                             text=True, timeout=120)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('neither on this machine nor the server', got.stderr)
        self.assertIn('CREATE ROLE', got.stderr)
        self.assertNotIn(DB_PW, got.stderr)
        # A join code on the command line still works - with a warning (1.0.113)
        got = self.n.cli('--db-agent-join', self.aga.code())
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('WARNING: the join code was given on the command line', got.stderr)
        self.assertIn('acme --db-agent-join -', got.stderr)


class LocalUnchanged(unittest.TestCase):
    """db_admin local (no agent file - every installation until now): nothing of it runs, no
    key is added to what the pages get, the root helper is asked as ever."""

    @classmethod
    def setUpClass(cls):
        cls.n = Node('l0', extra={'perf_meter': True})
        os.makedirs(os.path.join(cls.n.tmp, 'state', 'web'), exist_ok=True)
        cls.n.add_account()
        cls.n.start()

    @classmethod
    def tearDownClass(cls):
        cls.n.cleanup()

    def test_nothing_new(self):
        got = json.loads(self.n.py(
            "print(json.dumps([acme.db_admin(), acme.db_agent_on(), acme._db_agent_alerts(st), "
            "acme._db_agent_metrics(st), acme._db_agent_status_lines(st, None), "
            "acme.dbtls_kind()]))"))
        self.assertEqual(got, ['local', False, [], [], [], 'sqlite'])
        # The gates of 1.0.113 say nothing either: no agent, its database not the agent's, the
        # other node ha_peer as ever.
        got = json.loads(self.n.py(
            "print(json.dumps([acme.db_agent_here(), acme.ha_peer_node() == "
            "str(acme._engine.CONFIG.get('ha_peer') or ''), "
            "acme.db_agent_node_moved(st, '127.0.0.1', '192.0.2.9'), "
            "acme.db_agent_peer_moved(st)]))"))
        self.assertEqual(got, [False, True, [], None])
        for path in ('/api/ha', '/api/dbtls', '/api/load'):
            v = self.n.ok('GET', path) if path != '/api/dbtls' else self.n.call('GET', path)[1]
            self.assertNotIn('dbservers', v, path)
            self.assertNotIn('db_admin', v, path)
        self.assertNotIn('dbagent', self.n.out())
        self.assertFalse(os.path.exists(os.path.join(self.n.tmp, 'state', 'db-agent')))
        # pgtls_send still lays the ask down for the root helper (pgtls.ask)
        self.n.py("acme.pgtls_send({'id': 'abcdef0123', 'do': 'hba_off', 'port': 5432, "
                  "'db': 'acme', 'user': 'acme'})")
        self.assertTrue(os.path.exists(os.path.join(self.n.tmp, 'state', 'web', 'pgtls.ask')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
