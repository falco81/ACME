#!/usr/bin/env python3
"""The database on servers of their own, looked after by acme-db-agent (1.0.110).

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
  rebuild of the second node (acme --ha-resync).
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


def can_run():
    return os.geteuid() == 0 and os.path.exists(os.path.join(PGBIN, 'initdb')) and \
        shutil.which('runuser') and shutil.which('psql')


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

    def __init__(self, server, cadir):
        self.server = server
        self.dir = os.path.join(server.top, 'agent')
        os.makedirs(self.dir, mode=0o700)
        self.port = free_port()
        self.conf = os.path.join(self.dir, 'agent.json')
        with open(self.conf, 'w') as f:
            json.dump({'listen': '127.0.0.1', 'port': self.port, 'engine': 'postgres',
                       'pg_port': server.port, 'user': 'nobody',
                       'state': os.path.join(self.dir, 'state'),
                       'log': os.path.join(self.dir, 'audit.log'),
                       'ha_ca': os.path.join(cadir, server.name + '.pem'),
                       'advertise': '127.0.0.1', 'pg_restart_cmd': server.restart_cmd()}, f)
        self.proc = None
        self.out = os.path.join(self.dir, 'agent.out')

    def start(self):
        env = dict(os.environ, ACME_AGENT_NO_FIREWALL='1')
        self.proc = subprocess.Popen([sys.executable, '-I', AGENT, '--config', self.conf],
                                     stdout=open(self.out, 'ab'), stderr=subprocess.STDOUT,
                                     env=env)
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
    return node.py("print(acme.unseal_secret(json.load(open(str(acme.DBAGENT_FILE)))"
                   "['sign_key'], bind='dbagent:sign'))").strip()


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
        for x in ('n',):
            if getattr(cls, x, None):
                getattr(cls, x).cleanup()
        if getattr(cls, 'agent', None):
            cls.agent.stop()
        if getattr(cls, 'db', None):
            cls.db.cleanup()
        shutil.rmtree(cls.cadir, ignore_errors=True)

    def test_01_joined(self):
        a = node_conf_agent(self.n)
        self.assertEqual(a['db_admin'], 'agent:127.0.0.1:%d' % self.agent.port)
        self.assertEqual(len(a['pins']), 1)
        self.assertTrue(a['sign_key'].startswith('sealed'))     # never in clear
        got = self.n.cli('--db-agent-status')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('running', got.stdout)
        # The code is used up.
        again = self.n.cli('--db-agent-join', self.code)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('used up', again.stdout + again.stderr)
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
        finally:
            self.agent.start()
        wait_for(lambda: not json.loads(self.n.py("print(json.dumps(acme._db_agent_alerts(st)))")),
                 60, 2, 'the alert gone')


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (%s) and runuser' % PGBIN)
class ReplicatedExternal(unittest.TestCase):
    """Layout B: acme1 -> db1, acme2 -> db2, db1 <-> db2 replicating, through the agents."""

    @classmethod
    def setUpClass(cls):
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
        for x in ('a', 'b'):
            if getattr(cls, x, None):
                getattr(cls, x).cleanup()
        for x in ('ag1', 'ag2'):
            if getattr(cls, x, None):
                getattr(cls, x).stop()
        for x in ('db1', 'db2'):
            if getattr(cls, x, None):
                getattr(cls, x).cleanup()
        shutil.rmtree(cls.cadir, ignore_errors=True)

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
        v = self.a.ok('GET', '/api/ha')
        self.assertEqual(sorted(x['node'] for x in v.get('dbservers') or []), [])\
            if not v.get('dbservers') else self.assertEqual(v['dbservers'][0]['kind'], 'db')

    def test_03_rebuild_second(self):
        self.b.stop()
        got = self.b.cli('--ha-resync', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.b.start()
        self.sync()


if __name__ == '__main__':
    unittest.main(verbosity=2)
