#!/usr/bin/env python3
"""The certificate manager on every database engine and in both HA layouts.

    python3 test/test_ha.py                (or python3 -m unittest test.test_ha)

No root changes to the machine: daemons are started in folders of their own
(ACME_CONFIG, ACME_STATE, ACME_RUN, ACME_LOGDIR; unusual ports; the VIP
address off), the way test_certs_core.py starts one.

What is tried, each part skipped when what it needs is not there:

* SQLite: a database with certificates, an authority, a source, a target, a
  deployment, jobs and DNS records - made, and a backup of it taken
  (Populated). The backup is put back into MariaDB and PostgreSQL, and every
  row, the sealed key among them, read back and opened there (Restore*).
* MariaDB alone (MariaDbSingle): the tables, a long PEM, the byte-for-byte
  UNIQUE names, a renewal and a deployment through a daemon.
* Shared (SharedPair): two daemons, one PostgreSQL. One leader; a renewal job
  runs once; the jobs and the certificates seen on both; both DNS servers say
  the same TXT record; the leader killed, the other takes over in the lease.
* Replicated (ReplicatedPair): two PostgreSQL clusters (5432 and the one
  given by ACME_TEST_PG2_PORT, 5433), logical replication both ways the way
  `acme --ha-setup` / `--ha-join` lay it out (odd/even numbers, acme_pub,
  acme_sub_*). Rows made on each node reach the other, no number twice, and
  only one node leads, also while replication is paused.

The servers to use (all on 127.0.0.1, database "acme", account acme, password
optpw unless said otherwise):
    ACME_TEST_PG_PORT (5432)  ACME_TEST_PG2_PORT (5433)  ACME_TEST_MY_PORT (3306)
    ACME_TEST_PG2_DB (acme2: the second node's database, on the second cluster)
"""
import base64
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
PG2_DB = os.environ.get('ACME_TEST_PG2_DB', 'acme')
MY_PORT = int(os.environ.get('ACME_TEST_MY_PORT', '3306'))
LONG_PEM = '-----BEGIN CERTIFICATE-----\n' + ('A' * 64 + '\n') * 2000 + '-----END CERTIFICATE-----\n'


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
        cur.execute('DROP PUBLICATION IF EXISTS %s' % name)
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
