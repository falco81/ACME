#!/usr/bin/env python3
"""The certificate manager on every database engine and in both HA layouts.

    python3 test/test_ha.py                (or python3 -m unittest test.test_ha)
    python3 test/test_ha.py --make-backup DIR    (a backup with certificates,
                                                  for test/engines.sh)

Daemons are started in folders of their own (ACME_CONFIG, ACME_STATE,
ACME_RUN, ACME_LOGDIR; unusual ports; their own node names; the VIP address
off), the way test_certs_core.py starts one. The HA wizards are run for real,
as root: they change the PostgreSQL clusters given (wal_level = logical,
listen_addresses, pg_hba.conf lines for 127.0.0.1, the acme role's
REPLICATION) and restart them with pg_ctlcluster. Every acme table in the
databases given is dropped first - use servers kept for testing.

What is tried, each part skipped when what it needs is not there:

* RestoreIntoEngines: a SQLite database with certificates, an authority, two
  sources, a target, a deployment, jobs and a DNS record, and its backup
  (Populated), put back into MariaDB and PostgreSQL: every row there, the
  sealed keys and the target's password opened, new rows numbered past them.
* EngineMove: Settings -> The database (try, move, use) from SQLite into
  PostgreSQL, and on into MariaDB, the daemon started again on each.
* MariaDbSingle: the engine's types (MEDIUMTEXT, VARCHAR(190) utf8mb4_bin), a
  130 KB PEM, byte-for-byte UNIQUE names, renewals and a deployment.
* LeaseRace: the certificate leader's lease on each engine - taken, kept,
  taken over once run out, and of eight takers at once exactly one wins.
* SharedPair: acme --ha-setup --ha-shared / --ha-join, two daemons on one
  PostgreSQL. One leader; renewals run once, by it; jobs and certificates seen
  on both; both DNS servers answer the same TXT record; the leader killed,
  the other takes over.
* ReplicatedPair: acme --ha-setup / --ha-join with two PostgreSQL clusters
  (5432 and ACME_TEST_PG2_PORT, 5433), replicating both ways (acme_pub,
  acme_from_1 / acme_from_2). The same checks, and: odd numbers on one node,
  even on the other; with replication paused both ways still one leader; a
  DNS record made on the second node answered by both.
* SameRowsGuard: a row coming in by replication under a key that is here
  already (a name, a certificate's version, an authority's serial) is
  settled, not refused.

The servers to use (all on 127.0.0.1, database "acme", account acme, password
optpw unless ACME_TEST_DB_PW says otherwise):
    ACME_TEST_PG_PORT (5432)  ACME_TEST_PG2_PORT (5433)  ACME_TEST_MY_PORT (3306)
(the second node's database is "acme" too, on the second cluster; the
replicated wizard makes it there.)
"""
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_certs_core import FAKE_TARGET  # noqa: E402

PW = 'Test-Password-4711!'
DB_PW = os.environ.get('ACME_TEST_DB_PW', 'optpw')
PG_PORT = int(os.environ.get('ACME_TEST_PG_PORT', '5432'))
PG2_PORT = int(os.environ.get('ACME_TEST_PG2_PORT', '5433'))
PG2_DB = 'acme'                   # the bundle names the first node's database
MY_PORT = int(os.environ.get('ACME_TEST_MY_PORT', '3306'))


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_udp_port():
    while True:
        p = free_port()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(('127.0.0.1', p))
            return p
        except OSError:
            continue
        finally:
            u.close()


def pg_conn(port=PG_PORT, db='acme'):
    import psycopg2
    c = psycopg2.connect(host='127.0.0.1', port=port, dbname=db, user='acme', password=DB_PW,
                         connect_timeout=3)
    c.autocommit = True
    return c


def my_conn():
    import pymysql
    return pymysql.connect(host='127.0.0.1', port=MY_PORT, database='acme', user='acme',
                           password=DB_PW, connect_timeout=3, autocommit=True)


def have_pg(port=PG_PORT, db='acme'):
    try:
        pg_conn(port, db).close()
        return True
    except Exception:                                   # noqa: BLE001
        return False


def have_my():
    try:
        my_conn().close()
        return True
    except Exception:                                   # noqa: BLE001
        return False


def pg_empty(port=PG_PORT, db='acme'):
    """Every table of the acme schema dropped, every subscription and
    publication of it with them: a fresh database for the next test."""
    c = pg_conn(port, db)
    cur = c.cursor()
    cur.execute("SELECT subname FROM pg_subscription WHERE subdbid = (SELECT oid FROM "
                "pg_database WHERE datname = current_database())")
    for (name,) in cur.fetchall():
        try:
            cur.execute('ALTER SUBSCRIPTION %s DISABLE' % name)
            cur.execute('ALTER SUBSCRIPTION %s SET (slot_name = NONE)' % name)
            cur.execute('DROP SUBSCRIPTION %s' % name)
        except Exception:                               # noqa: BLE001
            pass
    cur.execute('SELECT pubname FROM pg_publication')
    for (name,) in cur.fetchall():
        try:
            cur.execute('DROP PUBLICATION IF EXISTS %s' % name)
        except Exception:                               # noqa: BLE001
            # FOR ALL TABLES: made by the postgres account (the wizard's).
            if os.geteuid() == 0 and shutil.which('runuser'):
                subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-p',
                                str(port), '-d', db, '-c', 'DROP PUBLICATION IF EXISTS %s' % name],
                               capture_output=True)
    cur.execute("SELECT slot_name FROM pg_replication_slots WHERE database = current_database() "
                "AND NOT active")
    for (name,) in cur.fetchall():
        try:
            cur.execute('SELECT pg_drop_replication_slot(%s)', (name,))
        except Exception:                               # noqa: BLE001
            pass
    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
    for (t,) in cur.fetchall():
        cur.execute('DROP TABLE IF EXISTS "%s" CASCADE' % t)
    cur.execute("SELECT sequence_name FROM information_schema.sequences "
                "WHERE sequence_schema = current_schema()")
    for (s,) in cur.fetchall():
        cur.execute('DROP SEQUENCE IF EXISTS "%s" CASCADE' % s)
    c.close()


def my_empty():
    c = my_conn()
    cur = c.cursor()
    cur.execute('SET FOREIGN_KEY_CHECKS = 0')
    cur.execute('SHOW TABLES')
    for (t,) in cur.fetchall():
        cur.execute('DROP TABLE IF EXISTS `%s`' % t)
    c.close()


def dns_txt(port, name, tcp=False):
    """The TXT strings a DNS server on 127.0.0.1:port answers for name."""
    qid = 0x4242
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip('.').split('.'):
        q += bytes([len(label)]) + label.encode()
    q += b'\x00' + struct.pack('>HH', 16, 1)
    if tcp:
        s = socket.create_connection(('127.0.0.1', port), timeout=3)
        s.sendall(struct.pack('>H', len(q)) + q)
        n = struct.unpack('>H', s.recv(2))[0]
        data = b''
        while len(data) < n:
            data += s.recv(n - len(data))
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(q, ('127.0.0.1', port))
        data = s.recv(4096)
        s.close()
    _id, flags, qd, an, _ns, _ar = struct.unpack('>HHHHHH', data[:12])
    off = 12

    def skip_name(o):
        while True:
            n = data[o]
            if n == 0:
                return o + 1
            if n & 0xC0 == 0xC0:
                return o + 2
            o += n + 1
    for _ in range(qd):
        off = skip_name(off) + 4
    out = []
    for _ in range(an):
        off = skip_name(off)
        rtype, _cls, _ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        off += rdlen
        if rtype == 16:
            i = 0
            while i < len(rd):
                n = rd[i]
                out.append(rd[i + 1:i + 1 + n].decode())
                i += n + 1
    return out


class Node(object):
    """One acme daemon in a folder of its own."""

    def __init__(self, name, db=None, extra=None, tmp=None):
        self.name = name
        self.tmp = tmp or tempfile.mkdtemp(prefix='acme-ha-%s-' % name)
        for d in ('state', 'run', 'log', 'plugins/targets', 'out'):
            os.makedirs(os.path.join(self.tmp, d), exist_ok=True)
        with open(os.path.join(self.tmp, 'plugins/targets/fake_target.py'), 'w') as f:
            f.write(FAKE_TARGET)
        self.port = free_port()
        self.dns_port = free_udp_port()
        conf = {'api_port': self.port, 'node_name': name, 'upgrade_check': 0, 'isemon': 0,
                'dns_listen': '127.0.0.1', 'dns_port': self.dns_port}
        conf.update(db or {'db_engine': 'sqlite'})
        conf.update(extra or {})
        self.conf_path = os.path.join(self.tmp, 'config.json')
        with open(self.conf_path, 'w') as f:
            json.dump(conf, f)
        self.env = dict(os.environ, ACME_CONFIG=self.conf_path,
                        ACME_STATE=os.path.join(self.tmp, 'state'),
                        ACME_RUN=os.path.join(self.tmp, 'run'),
                        ACME_LOGDIR=os.path.join(self.tmp, 'log'),
                        ACME_PLUGINS=os.path.join(self.tmp, 'plugins'),
                        ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        self.proc = None
        self.token = None
        self.session = None

    @property
    def conf(self):
        with open(self.conf_path) as f:
            return json.load(f)

    def set_conf(self, **kw):
        c = self.conf
        c.update(kw)
        with open(self.conf_path, 'w') as f:
            json.dump(c, f)

    def py(self, code, timeout=180):
        """Python run in this node's settings, with `acme` imported, the
        configuration read and `st` its Storage."""
        got = subprocess.run([sys.executable, '-c', (
            'import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db())\n' % ROOT) + code],
            env=self.env, capture_output=True, text=True, timeout=timeout)
        if got.returncode != 0:
            raise RuntimeError('%s: %s' % (self.name, (got.stderr or got.stdout)[-3000:]))
        return got.stdout

    def cli(self, *args, stdin=None, timeout=300):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=self.env, capture_output=True, text=True, input=stdin,
                              timeout=timeout)

    def add_account(self, name='tester', role='fulladmin'):
        self.py('st.add_account(%r, %r, %r)' % (name, role, PW))

    def start(self, wait=90):
        if getattr(self, "log", None):
            self.log.close()
        self.log = open(os.path.join(self.tmp, 'daemon.out'), 'ab')
        self.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                     env=self.env, stdout=self.log, stderr=subprocess.STDOUT,
                                     cwd=self.tmp)
        end = time.time() + wait
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError('%s: the daemon stopped: %s' % (self.name, self.out()[-3000:]))
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % self.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('%s: the daemon did not answer: %s' % (self.name, self.out()[-3000:]))
        with open(os.path.join(self.tmp, 'run', 'api-token')) as f:
            self.token = f.read().strip()
        st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': PW})
        if st != 200:
            raise RuntimeError('%s: signing in: %s %s' % (self.name, st, got))
        self.session = got['token']
        return self

    def out(self):
        try:
            with open(os.path.join(self.tmp, 'daemon.out'), 'rb') as f:
                return f.read().decode('utf-8', 'replace')
        except OSError:
            return ''

    def stop(self, kill=False):
        p = self.proc
        if p is not None and p.poll() is None:
            p.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
            try:
                p.wait(30)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(10)
        self.proc = None

    def cleanup(self):
        self.stop()
        if getattr(self, 'log', None):
            self.log.close()
        if os.environ.get('ACME_TEST_KEEP'):
            print('kept: %s' % self.tmp)
        else:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, method, path, body=None, args=None, timeout=120):
        url = 'http://127.0.0.1:%d%s' % (self.port, path)
        if args:
            url += '?' + urllib.parse.urlencode(args)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('X-Acme-Token', self.token or '')
        req.add_header('Content-Type', 'application/json')
        if self.session:
            req.add_header('X-Acme-Session', self.session)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def ok(self, method, path, body=None, args=None):
        st, got = self.call(method, path, body, args)
        if st != 200 or not got.get('ok'):
            raise AssertionError('%s: %s %s -> %s %s' % (self.name, method, path, st, got))
        return got

    def wait_job(self, job_id, secs=120):
        end = time.time() + secs
        while time.time() < end:
            got = self.ok('GET', '/api/certs/job', args={'id': job_id})['job']
            if got['state'] not in ('queued', 'running'):
                return got
            time.sleep(0.3)
        raise AssertionError('%s: job %s did not end' % (self.name, job_id))

    def leader(self):
        return (self.ok('GET', '/api/certs/overview').get('leader') or {}).get('node')


def populate(node):
    """Certificates, an authority, sources, a target, a deployment, jobs and
    DNS records - through the API of a running node."""
    node.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                          'config': {'days': 40}})
    out = os.path.join(node.tmp, 'out')
    node.ok('POST', '/api/targets/save', {'name': 'fake1', 'kind': 'fake',
                                          'config': {'dir': out, 'password': 's3cret'}})
    cid = node.ok('POST', '/api/certs/save', {
        'name': 'web', 'names': ['www.example.test', 'example.test'], 'issuer': 'self',
        'key_type': 'ec-256', 'auto_renew': 0, 'tags': ['test'], 'owner': 'novak'})['id']
    node.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'fake1',
                                          'options': {'file': 'web.pem', 'pfx_password': 'pfxpw'}})
    job = node.wait_job(node.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
    assert job['state'] == 'ok', job
    job = node.wait_job(node.ok('POST', '/api/certs/renew', {'id': cid, 'force': True})['job_id'])
    assert job['state'] == 'ok', job
    caid = node.ok('POST', '/api/cas/create', {'name': 'Test Root',
                                               'subject': {'CN': 'Test Root CA', 'O': 'Example'},
                                               'key_type': 'ec-256', 'days': 3650})['id']
    node.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                          'config': {'ca': 'Test Root', 'days': 90}})
    iid = node.ok('POST', '/api/certs/save', {'name': 'intranet',
                                              'names': ['intranet.example.test'],
                                              'issuer': 'own', 'auto_renew': 0})['id']
    job = node.wait_job(node.ok('POST', '/api/certs/renew', {'id': iid})['job_id'])
    assert job['state'] == 'ok', job
    node.ok('POST', '/api/cas/crl', {'id': caid})
    node.ok('POST', '/api/dns/record', {'name': '_acme-challenge.www.example.test',
                                        'rtype': 'TXT', 'value': 'populated-txt', 'ttl': 30})
    return {'web': cid, 'intranet': iid, 'ca': caid}


COUNTED = ('certs', 'cert_versions', 'cert_cas', 'cert_ca_issued', 'cert_issuers',
           'cert_targets', 'cert_deploys', 'cert_jobs', 'dns_records', 'accounts')

# What is read back from a node's database: the counts, and the sealed things
# opened (a certificate's key, an authority's key, a target's password).
READ_BACK = r'''
from acmelib.certs import store as cs, ca as cca
out = {t: int(st.db.value('SELECT COUNT(*) FROM %s' % t)) for t in COUNTED}
web = st.db.row("SELECT * FROM certs WHERE name = 'web'")
out['web_key'] = 'PRIVATE KEY' in (cs.cert_key(dict(web)) or '')
out['web_version'] = int(web['version'])
out['ca_key'] = 'PRIVATE KEY' in cca._key(dict(st.db.row("SELECT * FROM cert_cas WHERE name = 'Test Root'")))
t = st.db.row("SELECT * FROM cert_targets WHERE name = 'fake1'")
out['target_pw'] = cs.plugin_config('target', dict(t)).get('password')
out['max_id'] = int(st.db.value('SELECT MAX(id) FROM certs') or 0)
print(json.dumps(out, default=str))
'''.replace('COUNTED', repr(COUNTED))


class Populated(object):
    """A populated SQLite database and a backup of it, made once."""
    made = None

    @classmethod
    def get(cls):
        if cls.made:
            return cls.made
        node = Node('src')
        node.add_account()
        node.start()
        try:
            ids = populate(node)
            got = node.cli('--backup')
            if got.returncode != 0:
                raise RuntimeError('--backup: %s %s' % (got.stdout, got.stderr))
            node.stop()
            bdir = os.path.join(node.tmp, 'state', 'backups')
            files = sorted(f for f in os.listdir(bdir) if f.endswith('.json.gz'))
            counts = json.loads(node.py(READ_BACK))
        except Exception:
            node.cleanup()
            raise
        cls.made = {'node': node, 'backup': os.path.join(bdir, files[-1]), 'ids': ids,
                    'counts': counts}
        return cls.made


PG = {'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': PG_PORT, 'db_name': 'acme',
      'db_user': 'acme', 'db_password': DB_PW}
PG2 = dict(PG, db_port=PG2_PORT, db_name=PG2_DB)
MY = {'db_engine': 'mariadb', 'db_host': '127.0.0.1', 'db_port': MY_PORT, 'db_name': 'acme',
      'db_user': 'acme', 'db_password': DB_PW}


def wait_for(fn, secs, every=1.0, what='it'):
    end = time.time() + secs
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:                          # noqa: BLE001
            last = e
        time.sleep(every)
    raise AssertionError('%s did not happen within %d s (last: %r)' % (what, secs, last))


def need_pg(test):
    try:
        import psycopg2  # noqa: F401
    except ImportError:
        raise unittest.SkipTest('psycopg2 is not in this python')
    if not have_pg():
        raise unittest.SkipTest('no PostgreSQL with a database acme for acme/%s on 127.0.0.1:%d'
                                % (DB_PW, PG_PORT))


def need_my(test):
    try:
        import pymysql  # noqa: F401
    except ImportError:
        raise unittest.SkipTest('pymysql is not in this python')
    if not have_my():
        raise unittest.SkipTest('no MariaDB with a database acme for acme/%s on 127.0.0.1:%d'
                                % (DB_PW, MY_PORT))


def pg_admin_ok(port):
    """psql as postgres on this machine reaches the cluster on `port` (the
    wizard of the replicated layout needs root and that)."""
    if os.geteuid() != 0 or not shutil.which('runuser'):
        return False
    got = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-p', str(port),
                          '-c', 'SELECT 1'], capture_output=True, text=True)
    return got.returncode == 0 and got.stdout.strip() == '1'


def read_back(node):
    return json.loads(node.py(READ_BACK).strip().splitlines()[-1])


# ---------------------------------------------------------------------------------------------
class RestoreIntoEngines(unittest.TestCase):
    """The SQLite backup with certificates put back into MariaDB and PostgreSQL:
    every row there, every sealed thing opened."""

    def restore_into(self, db, empty):
        src = Populated.get()
        empty()
        node = Node('restored', db)
        try:
            key = src['backup'][:-len('.json.gz')] + '.key'
            shutil.copy(key, os.path.join(node.tmp, 'state', 'secrets.key'))
            got = node.cli('--restore', src['backup'], '--yes')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            here = read_back(node)
            for k, v in src['counts'].items():
                self.assertEqual(here.get(k), v, '%s: %s here, %s in the copy' % (k, here.get(k), v))
            # A new row numbered past those put back.
            got = node.cli('--renew', 'intranet')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertIn('issued: version 2', got.stdout)
            again = read_back(node)
            self.assertEqual(again['cert_versions'], here['cert_versions'] + 1)
            self.assertEqual(again['cert_jobs'], here['cert_jobs'] + 1)
        finally:
            node.cleanup()

    def test_postgres(self):
        need_pg(self)
        self.restore_into(PG, pg_empty)

    def test_mariadb(self):
        need_my(self)
        self.restore_into(MY, my_empty)


# ---------------------------------------------------------------------------------------------
class EngineMove(unittest.TestCase):
    """Settings → The database: everything carried from SQLite into PostgreSQL,
    the daemon started again on it; then from PostgreSQL into MariaDB."""

    def move(self, node, target):
        st, got = node.call('POST', '/api/db', {'action': 'try', 'settings': target})
        self.assertEqual(st, 200, got)
        self.assertTrue(got.get('reached'), got)
        st, got = node.call('POST', '/api/db', {'action': 'move', 'settings': target})
        self.assertEqual(st, 200, got)

        def done():
            st, j = node.call('POST', '/api/db', {'action': 'job'})
            j = j.get('job') or j
            return j if not j.get('running') and j.get('ended') else None
        job = wait_for(done, 300, 1, 'the move')
        self.assertFalse(job.get('error'), job)
        self.assertFalse((job.get('result') or {}).get('short'), job)
        st, got = node.call('POST', '/api/db', {'action': 'use', 'settings': target})
        self.assertEqual(st, 200, got)
        self.assertTrue(got.get('restarting'), got)
        wait_for(lambda: node.proc.poll() is not None, 60, 0.5, 'the daemon stopping')
        self.assertEqual(node.conf['db_engine'], target['db_engine'])
        node.start()
        here = read_back(node)
        return here

    def test_sqlite_postgres_mariadb(self):
        need_pg(self)
        need_my(self)
        pg_empty()
        my_empty()
        node = Node('mover')
        try:
            node.add_account()
            node.start()
            populate(node)
            before = read_back(node)
            on_pg = self.move(node, PG)
            for k in COUNTED:
                self.assertEqual(on_pg[k], before[k], k)
            for k in ('web_key', 'ca_key'):
                self.assertTrue(on_pg[k], k)
            self.assertEqual(on_pg['target_pw'], 's3cret')
            on_my = self.move(node, MY)
            for k in COUNTED:
                self.assertEqual(on_my[k], on_pg[k], k)
            self.assertTrue(on_my['web_key'] and on_my['ca_key'])
            self.assertEqual(on_my['target_pw'], 's3cret')
            job = node.wait_job(node.ok('POST', '/api/certs/renew',
                                        {'id': node.ok('GET', '/api/certs',
                                                       args={'search': 'intranet'})['rows'][0]['id']}
                                        )['job_id'])
            self.assertEqual(job['state'], 'ok', job)
        finally:
            node.cleanup()


# ---------------------------------------------------------------------------------------------
class MariaDbSingle(unittest.TestCase):
    """One node on MariaDB: the certificate manager's tables in the engine's
    types, a long PEM, names compared byte for byte, the daemon at work."""

    @classmethod
    def setUpClass(cls):
        need_my(cls)
        my_empty()
        cls.node = Node('maria', MY)
        cls.node.add_account()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.cleanup()

    def test_01_types(self):
        c = my_conn()
        cur = c.cursor()
        cur.execute("SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, COLLATION_NAME FROM "
                    "information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()")
        cols = {(t, n): (ty, co) for t, n, ty, co in cur.fetchall()}
        c.close()
        for t in ('certs', 'cert_versions', 'cert_cas', 'cert_ca_issued', 'cert_issuers',
                  'cert_challenges', 'cert_targets', 'cert_deploys', 'cert_jobs', 'dns_records'):
            self.assertIn((t, 'id'), cols, t)
        self.assertEqual(cols[('certs', 'cert_pem')][0], 'mediumtext')
        self.assertEqual(cols[('cert_jobs', 'steps')][0], 'mediumtext')
        self.assertEqual(cols[('certs', 'name')], ('varchar(190)', 'utf8mb4_bin'))
        self.assertEqual(cols[('certs', 'not_after')][0], 'double')
        self.assertEqual(cols[('meta', 'k')][0], 'varchar(255)')

    def test_02_long_pem_and_names(self):
        out = self.node.py(r'''
long = '-----BEGIN CERTIFICATE-----\n' + ('A' * 64 + '\n') * 2000 + '-----END CERTIFICATE-----\n'
ident = st.db.insert('cert_versions', {'cert_id': 999999, 'version': 1, 'cert_pem': long,
                                      'chain_pem': long, 'created': 1.5})
back = st.db.value('SELECT cert_pem FROM cert_versions WHERE id = ?', (ident,))
print(json.dumps({'id': ident, 'same': back == long}))
n190 = 'n' * 189 + 'X'
st.db.insert('cert_targets', {'name': n190, 'kind': 'fake'})
st.db.insert('cert_targets', {'name': n190[:-1] + 'x', 'kind': 'fake'})  # another, by case
try:
    st.db.insert('cert_targets', {'name': n190, 'kind': 'fake'})
    print('DUPLICATE TAKEN')
except Exception as e:
    print('refused', type(e).__name__)
st.db.insert('cert_targets', {'name': 'novák', 'kind': 'fake'})
st.db.insert('cert_targets', {'name': 'novak', 'kind': 'fake'})
print(json.dumps({'n': st.db.value("SELECT COUNT(*) FROM cert_targets WHERE name IN ('novák', 'novak')")}))
st.db.run('DELETE FROM cert_versions WHERE cert_id = 999999')
st.db.run("DELETE FROM cert_targets WHERE kind = 'fake'")
''')
        lines = out.strip().splitlines()
        self.assertTrue(json.loads(lines[0])['same'])
        self.assertTrue(lines[1].startswith('refused'), lines[1])
        self.assertEqual(int(json.loads(lines[2])['n']), 2)

    def test_03_at_work(self):
        populate(self.node)
        here = read_back(self.node)
        self.assertEqual(here['certs'], 2)
        self.assertEqual(here['cert_versions'], 3)
        self.assertTrue(here['web_key'] and here['ca_key'])
        self.assertEqual(here['target_pw'], 's3cret')
        # The deployment did go out, with the PFX's password opened.
        with open(os.path.join(self.node.tmp, 'out', 'web.pem.opts')) as f:
            self.assertIn("('pfx_password', 'pfxpw')", f.read())
        self.assertEqual(self.node.leader(), 'maria')
        self.assertEqual(dns_txt_api(self.node), ['populated-txt'])


def dns_txt_api(node, name='_acme-challenge.www.example.test'):
    return [r['value'] for r in node.ok('GET', '/api/dns')['records'] if r['name'] == name]


# ---------------------------------------------------------------------------------------------
LEASE_WAIT = 90 + 30 + 20        # renewer.LEASE_S + LEASE_EVERY + a scan's pause, and some


def leader_events(node):
    """How often a node took the lead, by the events (both nodes' events are
    in the database, or come over)."""
    return json.loads(node.py(
        "print(json.dumps([r['words'] for r in st.db.rows(\"SELECT words FROM events WHERE "
        "kind = 'certificates' AND words LIKE '%now renews and deploys%' ORDER BY id\")]))")
        .strip().splitlines()[-1])


def passphrase_of(out):
    for line in out.splitlines():
        if 'passphrase' in line and ':' in line:
            return line.rsplit(':', 1)[1].strip()
    raise AssertionError('no passphrase in: %s' % out)


class PairChecks(object):
    """What both layouts must do; a, b are the two nodes, running."""

    def test_01_one_leader(self):
        lead = wait_for(lambda: self.a.leader() if self.a.leader() == self.b.leader() else None,
                        60, 1, 'one leader seen alike by both nodes')
        self.assertIn(lead, ('n1', 'n2'))
        time.sleep(35)                  # a look of the lease more on each
        self.assertEqual(self.a.leader(), lead)
        self.assertEqual(self.b.leader(), lead)
        took = leader_events(self.a)
        self.assertEqual(len(took), 1, took)
        self.__class__.lead = lead

    def test_02_renewed_once_seen_on_both(self):
        self.a.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                                'config': {'days': 40}})
        self.sync()
        ids = []
        for i in range(4):
            on = (self.a, self.b)[i % 2]
            ids.append(on.ok('POST', '/api/certs/save', {
                'name': 'auto%d' % i, 'names': ['auto%d.example.test' % i], 'issuer': 'self',
                'auto_renew': 1})['id'])
            self.sync()
        self.assertEqual(len(set(ids)), 4, ids)

        def all_ok(node):
            rows = {r['id']: r for r in node.ok('GET', '/api/certs', args={'per': 100})['rows']}
            return all(rows.get(i, {}).get('state') == 'ok' for i in ids)
        wait_for(lambda: all_ok(self.a) and all_ok(self.b), 200, 2, 'the four renewed')
        time.sleep(10)
        for node in (self.a, self.b):
            for cid in ids:
                jobs = node.ok('GET', '/api/certs/jobs', args={'cert_id': cid})['rows']
                renews = [j for j in jobs if j['kind'] == 'renew']
                self.assertEqual(len(renews), 1, (node.name, cid, jobs))
                self.assertEqual(renews[0]['node'], self.lead, renews[0])
                one = node.ok('GET', '/api/certs/one', args={'id': cid})
                self.assertEqual(one['cert']['version'], 1)
                self.assertEqual([v['version'] for v in one['versions']], [1])
        self.__class__.ids = ids

    def test_03_dns_both(self):
        self.a.ok('POST', '/api/dns/record', {'name': '_acme-challenge.both.acme.test',
                                              'rtype': 'TXT', 'value': 'same-on-both', 'ttl': 30})
        self.sync()
        for node in (self.a, self.b):
            got = wait_for(lambda: dns_txt(node.dns_port, '_acme-challenge.both.acme.test'),
                           30, 1, '%s answering the TXT record' % node.name)
            self.assertEqual(got, ['same-on-both'])
            self.assertEqual(dns_txt(node.dns_port, '_acme-challenge.both.acme.test', tcp=True),
                             ['same-on-both'])

    def test_09_leader_killed(self):
        lead = self.lead
        dead, live = (self.a, self.b) if lead == self.a.name else (self.b, self.a)
        t0 = time.time()
        dead.stop(kill=True)
        got = wait_for(lambda: live.leader() == live.name, self.TAKEOVER, 2,
                       '%s taking over' % live.name)
        took = time.time() - t0
        self.assertTrue(got)
        print('\n  %s led again %.0f s after %s was killed' % (live.name, took, dead.name))
        # And renews by itself there.
        cid = live.ok('POST', '/api/certs/save', {'name': 'after', 'names': ['after.example.test'],
                                                  'issuer': 'self', 'auto_renew': 1})['id']
        wait_for(lambda: live.ok('GET', '/api/certs/one', args={'id': cid})['cert']['state'] == 'ok',
                 120, 2, 'a renewal on the node left')


class SharedPair(PairChecks, unittest.TestCase):
    """Two daemons on one PostgreSQL, set up with the wizard
    (acme --ha-setup --ha-shared on the first, acme --ha-join on the second)."""
    TAKEOVER = LEASE_WAIT

    def sync(self):
        pass

    @classmethod
    def setUpClass(cls):
        need_pg(cls)
        if os.geteuid() != 0:
            raise unittest.SkipTest('the wizard runs as root')
        pg_empty()
        extra = {'dns_server': 1, 'dns_zone': 'acme.test', 'certs_check_min': 1}
        cls.a = Node('n1', PG, extra)
        cls.b = Node('n2', {'db_engine': 'sqlite'}, extra)
        cls.a.add_account()
        bundle = os.path.join(cls.a.tmp, 'bundle.json')
        for n in (cls.a, cls.b):
            n.env['ACME_HA_NO_RESTART'] = '1'
        got = cls.a.cli('--ha-setup', '--ha-shared', '--ha-peer', '127.0.0.1', '--ha-db-host',
                        '127.0.0.1', '--node-name', 'n1', '--ha-bundle', bundle, '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-setup --ha-shared: %s %s' % (got.stdout, got.stderr))
        phrase = passphrase_of(got.stdout)
        cls.b.env['ACME_HA_PASSPHRASE'] = phrase
        got = cls.b.cli('--ha-join', bundle, '--node-name', 'n2', '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-join: %s %s' % (got.stdout, got.stderr))
        for n in (cls.a, cls.b):
            # Each its own ports on this one machine.
            n.set_conf(api_port=n.port, dns_port=n.dns_port)
        cls.setup_said = got.stdout
        cls.a.start()
        cls.b.start()

    @classmethod
    def tearDownClass(cls):
        for n in ('a', 'b'):
            if getattr(cls, n, None):
                getattr(cls, n).cleanup()

    def test_00_wizard(self):
        self.assertEqual(self.b.conf['db_engine'], 'postgres')
        self.assertEqual(self.b.conf['node_name'], 'n2')
        for n in (self.a, self.b):
            self.assertEqual(n.conf.get('ha_mode'), 'shared', n.name)
        with open(os.path.join(self.a.tmp, 'state', 'secrets.key')) as f1, \
                open(os.path.join(self.b.tmp, 'state', 'secrets.key')) as f2:
            self.assertEqual(f1.read(), f2.read())
        nodes = wait_for(lambda: [x for x in self.a.ok('GET', '/api/ha')['nodes']
                                  if x.get('alive')] if len([
                                      x for x in self.a.ok('GET', '/api/ha')['nodes']
                                      if x.get('alive')]) == 2 else None, 40, 1, 'both nodes alive')
        self.assertEqual(sorted(x['name'] for x in nodes), ['n1', 'n2'])


LEASE_RACE = r'''
import threading
import acmelib.engine as E
from acmelib.certs import renewer
st.db.run('DELETE FROM meta WHERE k = ?', (renewer.LEASE_KEY,))

def as_node(name, fn, *a):
    E.CONFIG['node_name'] = name
    return fn(*a)

out = {}
out['n1_takes'] = as_node('n1', renewer.lease_tick, st)
out['n2_waits'] = as_node('n2', renewer.lease_tick, st)
out['n1_keeps'] = as_node('n1', renewer.lease_tick, st)
st.set_meta(renewer.LEASE_KEY, json.dumps({'node': 'n1', 'until': 1, 'vip': False}))
out['n2_takes_run_out'] = as_node('n2', renewer.lease_tick, st)
out['n1_waits'] = as_node('n1', renewer.lease_tick, st)
as_node('n1', renewer.lease_drop, st)
out['drop_not_mine'] = renewer.lease_read(st)['node']
as_node('n2', renewer.lease_drop, st)
out['dropped'] = renewer.lease_read(st)

# Eight takers of a lease that ran out (and of none at all), at the same moment.
for start in ('run out', 'none'):
    if start == 'none':
        st.db.run('DELETE FROM meta WHERE k = ?', (renewer.LEASE_KEY,))
    else:
        st.set_meta(renewer.LEASE_KEY, json.dumps({'node': 'gone', 'until': 1, 'vip': False}))
    raw = st.get_meta(renewer.LEASE_KEY)
    go = threading.Barrier(8)
    won = []
    def one(i):
        s2 = acme.Storage(acme.open_db())
        go.wait()
        won.append(renewer.lease_swap(s2, raw, json.dumps({'node': 't%d' % i, 'until': 2e9})))
    ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out['winners ' + start] = sum(1 for w in won if w)
st.db.run('DELETE FROM meta WHERE k = ?', (renewer.LEASE_KEY,))
print(json.dumps(out))
'''


class LeaseRace(unittest.TestCase):
    """The lease of one database (alone, or shared by two nodes): taken by one,
    kept, taken over once it ran out, and of many asking at once one wins."""

    def check(self, db, empty=None):
        if empty:
            empty()
        node = Node('lease', db)
        try:
            node.py('st.db.make_tables()')
            got = json.loads(node.py(LEASE_RACE).strip().splitlines()[-1])
        finally:
            node.cleanup()
        self.assertEqual(got, {'n1_takes': True, 'n2_waits': False, 'n1_keeps': True,
                               'n2_takes_run_out': True, 'n1_waits': False,
                               'drop_not_mine': 'n2', 'dropped': None,
                               'winners run out': 1, 'winners none': 1})

    def test_sqlite(self):
        self.check({'db_engine': 'sqlite'})

    def test_postgres(self):
        need_pg(self)
        self.check(PG, pg_empty)

    def test_mariadb(self):
        need_my(self)
        self.check(MY, my_empty)


def db_rows(port, sql, args=()):
    c = pg_conn(port)
    try:
        cur = c.cursor()
        cur.execute(sql, args)
        return cur.fetchall()
    finally:
        c.close()


def pg2_empty():
    """The second cluster's acme database emptied, if it is there yet (the
    wizard makes it)."""
    if have_pg(PG2_PORT):
        pg_empty(PG2_PORT)


class ReplicatedPair(PairChecks, unittest.TestCase):
    """Two daemons, each on its own PostgreSQL (127.0.0.1:5432 and :5433),
    replicating both ways - set up with the wizard: acme --ha-setup on the
    first (it sets wal_level, pg_hba.conf, the publication and the odd
    numbering, restarting PostgreSQL through pg_ctlcluster), acme --ha-join
    on the second (the same there, every row copied, both subscriptions)."""
    TAKEOVER = 120 + 30 + 90 + 20   # its heartbeat stale in its own database, a
    #                                 look of the lease, its lease run out here

    def sync(self):
        """Both directions caught up (what was written before this is on both)."""
        mark = 'sync:%s' % time.time()
        for n, port, other in ((self.a, PG_PORT, PG2_PORT), (self.b, PG2_PORT, PG_PORT)):
            c = pg_conn(port)
            c.cursor().execute("INSERT INTO meta (k, v) VALUES (%s, '1')",
                               (mark + ':' + n.name,))
            c.close()
            wait_for(lambda: db_rows(other, 'SELECT 1 FROM meta WHERE k = %s',
                                     (mark + ':' + n.name,)), 30, 0.3,
                     'replication %s -> the other' % n.name)

    @classmethod
    def setUpClass(cls):
        need_pg(cls)
        if not (pg_admin_ok(PG_PORT) and pg_admin_ok(PG2_PORT)):
            raise unittest.SkipTest('the replicated wizard needs root and psql as postgres on '
                                    'both clusters (%d, %d): pg_createcluster 16 second --port '
                                    '%d' % (PG_PORT, PG2_PORT, PG2_PORT))
        pg_empty()
        pg2_empty()
        extra = {'dns_server': 1, 'dns_zone': 'acme.test', 'certs_check_min': 1}
        cls.a = Node('n1', PG, extra)
        cls.b = Node('n2', PG2, extra)
        cls.a.add_account()
        bundle = os.path.join(cls.a.tmp, 'bundle.json')
        for n in (cls.a, cls.b):
            n.env['ACME_HA_NO_RESTART'] = '1'
        got = cls.a.cli('--ha-setup', '--ha-peer', '127.0.0.1', '--ha-peer-port', str(PG2_PORT),
                        '--ha-address', '127.0.0.1', '--node-name', 'n1', '--ha-bundle', bundle,
                        '--yes')
        cls.setup_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--ha-setup: %s' % cls.setup_out)
        cls.b.env['ACME_HA_PASSPHRASE'] = passphrase_of(got.stdout)
        got = cls.b.cli('--ha-join', bundle, '--node-name', 'n2', '--ha-address', '127.0.0.1',
                        '--yes')
        cls.join_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--ha-join: %s' % cls.join_out)
        for n in (cls.a, cls.b):
            n.set_conf(api_port=n.port, dns_port=n.dns_port)
        cls.a.start()
        cls.b.start()

    @classmethod
    def tearDownClass(cls):
        for n in ('a', 'b'):
            if getattr(cls, n, None):
                getattr(cls, n).cleanup()
        if not os.environ.get('ACME_TEST_KEEP'):
            for port in (PG_PORT, PG2_PORT):
                try:
                    pg_empty(port)
                except Exception:                       # noqa: BLE001
                    pass

    def test_00_wizard(self):
        c1, c2 = self.a.conf, self.b.conf
        self.assertEqual((c1['ha_mode'], c1['ha_slot']), ('replicated', 1))
        self.assertEqual((c2['ha_mode'], c2['ha_slot']), ('replicated', 2))
        self.assertEqual(c2['db_port'], PG2_PORT)
        self.assertEqual(c1.get('ha_peer_port'), PG2_PORT)
        self.assertEqual(c2.get('ha_peer_port', 5432), PG_PORT)
        for port, sub in ((PG_PORT, 'acme_from_2'), (PG2_PORT, 'acme_from_1')):
            got = db_rows(port, 'SELECT subname, subenabled FROM pg_subscription')
            self.assertIn((sub, True), got, (port, got, self.setup_out, self.join_out))
        # The accounts came over with the rows: the second node signs in with them.
        self.assertTrue(self.b.session)
        status = self.a.cli('--ha-status')
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        self.assertIn('n2', status.stdout)

    def test_05_numbers_odd_and_even(self):
        ids = self.ids
        self.assertEqual([i % 2 for i in ids], [1, 0, 1, 0], ids)
        for port in (PG_PORT, PG2_PORT):
            names = dict(db_rows(port, 'SELECT id, name FROM certs'))
            for i, cid in enumerate(ids):
                self.assertEqual(names.get(cid), 'auto%d' % i, (port, names))
        # Every table of SCHEMA in steps of two on each side, the certificates' too.
        for port, odd in ((PG_PORT, 1), (PG2_PORT, 0)):
            seqs = dict(db_rows(port, "SELECT sequencename, increment_by FROM pg_sequences"))
            for t in ('certs', 'cert_versions', 'cert_jobs', 'dns_records', 'cert_cas'):
                self.assertEqual(seqs.get('%s_id_seq' % t), 2, (port, t, seqs))
            jobs = [r[0] for r in db_rows(port, 'SELECT id FROM cert_jobs WHERE node = %s',
                                         ('n1' if odd else 'n2',))]
            self.assertTrue(all(j % 2 == odd for j in jobs), (port, jobs))

    def test_06_paused_one_leader(self):
        """Replication paused both ways: the heartbeats and the lease of the
        other stop coming - and still only the first node leads (it is asked
        in its own database). A certificate made on the second node then
        waits, and is renewed once by the first after the resume."""
        lead, other = (self.a, self.b) if self.lead == 'n1' else (self.b, self.a)
        got = self.a.cli('--ha-pause', 'both')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        try:
            cid = other.ok('POST', '/api/certs/save', {'name': 'paused',
                                                       'names': ['paused.example.test'],
                                                       'issuer': 'self',
                                                       'auto_renew': 1})['id']
            time.sleep(LEASE_WAIT + 30)   # the other's lease ran out in each copy
            one = other.ok('GET', '/api/certs/one', args={'id': cid})
            self.assertEqual(one['cert']['state'], 'new', one['cert'])
            self.assertEqual(one['jobs'], [])
            # Nobody else took the lead in either database.
            for port in (PG_PORT, PG2_PORT):
                took = [r[0] for r in db_rows(
                    port, "SELECT words FROM events WHERE kind = 'certificates' AND words "
                    "LIKE %s", ('%now renews and deploys%',))]
                self.assertEqual(len(took), 1, (port, took))
            self.assertEqual(lead.leader(), lead.name)
        finally:
            got = self.a.cli('--ha-resume', 'both')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        wait_for(lambda: other.ok('GET', '/api/certs/one', args={'id': cid})['cert']['state']
                 == 'ok', 150, 2, 'the renewal after the resume')
        self.sync()
        for node in (self.a, self.b):
            jobs = node.ok('GET', '/api/certs/jobs', args={'cert_id': cid})['rows']
            self.assertEqual([(j['kind'], j['node']) for j in jobs], [('renew', lead.name)])

    def test_07_dns_record_from_the_other(self):
        self.b.ok('POST', '/api/dns/record', {'name': '_acme-challenge.from2.acme.test',
                                              'rtype': 'TXT', 'value': 'made-on-n2', 'ttl': 30})
        self.sync()
        for node in (self.a, self.b):
            got = wait_for(lambda: dns_txt(node.dns_port, '_acme-challenge.from2.acme.test'),
                           30, 1, '%s answering' % node.name)
            self.assertEqual(got, ['made-on-n2'])



class SameRowsGuard(unittest.TestCase):
    """Replicated: a row that comes in from the other node under a key this
    node has already (a name; a certificate's version; an authority's serial)
    does not stop the replication - the same one of the two is kept on both."""

    def test_postgres(self):
        need_pg(self)
        if not pg_admin_ok(PG_PORT):
            raise unittest.SkipTest('needs root and psql as postgres')
        pg_empty()
        node = Node('guard', PG)
        try:
            node.py('st.db.make_tables()')
            c = pg_conn()
            cur = c.cursor()
            cur.execute("INSERT INTO cert_versions (cert_id, version, cert_pem) VALUES (7, 1, 'a')")
            cur.execute("INSERT INTO cert_ca_issued (ca_id, serial, names) VALUES (3, '0A', 'a')")
            cur.execute("INSERT INTO certs (name, note) VALUES ('web', 'a')")
            c.close()
            # As the replication's apply worker writes: session_replication_role = replica.
            sql = ("SET session_replication_role = replica;\n"
                   "INSERT INTO cert_versions (id, cert_id, version, cert_pem) VALUES (1000, 7, 1, 'b');\n"
                   "INSERT INTO cert_ca_issued (id, ca_id, serial, names) VALUES (1000, 3, '0A', 'b');\n"
                   "INSERT INTO certs (id, name, note) VALUES (1000, 'web', 'b');\n")
            got = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-p',
                                  str(PG_PORT), '-d', 'acme', '-v', 'ON_ERROR_STOP=1', '-f', '-'],
                                 input=sql, capture_output=True, text=True)
            self.assertEqual(got.returncode, 0, got.stderr)
            for table, where in (('cert_versions', 'cert_id = 7'), ('cert_ca_issued', 'ca_id = 3'),
                                 ('certs', "name = 'web'")):
                rows = db_rows(PG_PORT, 'SELECT id FROM %s WHERE %s' % (table, where))
                # row_to_json of id 1000 sorts after id 1's: the one that came is kept.
                self.assertEqual(rows, [(1000,)], table)
        finally:
            node.cleanup()
            pg_empty()

def tearDownModule():
    if Populated.made:
        Populated.made['node'].cleanup()
        Populated.made = None


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--make-backup':
        # A SQLite database with certificates, an authority, sources, a target,
        # a deployment, jobs and a DNS record - its backup (and the key beside
        # it) put into DIR, for test/engines.sh.
        made = Populated.get()
        os.makedirs(sys.argv[2], exist_ok=True)
        for f in (made['backup'], made['backup'][:-len('.json.gz')] + '.key'):
            shutil.copy(f, sys.argv[2])
        made['node'].cleanup()
        print(os.path.join(sys.argv[2], os.path.basename(made['backup'])))
        sys.exit(0)
    unittest.main(verbosity=2)
