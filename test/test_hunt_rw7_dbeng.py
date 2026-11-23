#!/usr/bin/env python3
"""Hunt w7 - the same flows on SQLite, PostgreSQL and MariaDB (dbeng).

    python3 test/test_hunt_rw7_dbeng.py

* A DNS name may be 253 characters: the record _acme-challenge.NAME of a name past 174 was
  "Data too long" on MariaDB alone (dns_records.name was VARCHAR(190)) - DNS-01 through
  acme's own DNS server failed there; a set's server name for TLS likewise. Made 255 on a new
  database and on one made before; a record saved by hand longer than 253 is refused on every
  engine (it was kept, never answered - and a 500 on MariaDB).
* The view that opens by itself of a person whose name has a backslash (CORP\\novak, as typed
  at a directory sign-in): PostgreSQL and MariaDB took the backslash for LIKE's escape and the
  default was never found there.

PostgreSQL and MariaDB run privately on free ports (never 5432/5433/3306/8092), skipped where
they are not installed.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw7-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import store as S  # noqa: E402,F401  (its tables)
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import history as H  # noqa: E402
from acmelib.certs import runtime as R  # noqa: E402

PG_BIN = next((p for p in sorted(
    ('/usr/lib/postgresql/%s/bin' % v for v in os.listdir('/usr/lib/postgresql')), reverse=True)
    if os.path.exists(os.path.join(p, 'initdb'))), None) \
    if os.path.isdir('/usr/lib/postgresql') else None
MY_BIN = shutil.which('mariadbd')
MY_INSTALL = shutil.which('mariadb-install-db')
try:
    import psycopg2
except ImportError:
    psycopg2 = None
try:
    import pymysql
except ImportError:
    pymysql = None

LONG = '.'.join(['a' * 60] * 3) + '.example.com'           # 194 characters


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    if port in (5432, 5433, 8092, 8443, 3306) or port < 20000:
        return free_port()
    return port


def wait_port(port, s=40):
    end = time.time() + s
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def as_user(user, cmd, **kw):
    if os.geteuid() == 0:
        cmd = ['runuser', '-u', user, '--'] + cmd
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


class Flows(object):
    """A mixin: `db()` gives an empty database of the engine."""

    def store(self):
        st = E.Storage(self.db())
        E.HA_STORE['store'] = st
        self.addCleanup(st.db.close)
        return st

    def test_long_dns_record_name(self):
        st = self.store()
        ctx = R.RunContext(st, None, scope='challenge:own')
        name = '_acme-challenge.' + LONG
        ctx.dns_put(name, 'TXT', 'v' * 43)
        self.assertEqual([r['name'] for r in st.db.rows('SELECT name FROM dns_records')], [name])
        ctx.dns_drop(name, 'TXT', 'v' * 43)
        self.assertEqual(st.db.rows('SELECT name FROM dns_records'), [])

    def test_record_by_hand_253_at_most(self):
        st = self.store()
        ok = '.'.join(['b' * 61] * 3) + '.example.com'       # 197
        self.assertTrue(A.dns_record_save(st, {'name': ok, 'rtype': 'TXT', 'value': 'x'}, 'me'))
        top = '.'.join(['c' * 61] * 4)                      # 247
        self.assertTrue(A.dns_record_save(st, {'name': top, 'rtype': 'TXT', 'value': 'x'}, 'me'))
        with self.assertRaises(ValueError):
            A.dns_record_save(st, {'name': top + '.example', 'rtype': 'TXT', 'value': 'x'}, 'me')
        self.assertEqual(sorted(r['name'] for r in st.db.rows('SELECT name FROM dns_records')),
                         sorted([ok, top]))

    def test_default_view_of_a_backslash_name(self):
        st = self.store()
        for i, name in enumerate(('novak', 'CORP\\novak', 'CORP\\xnovak', 'a_b%c!d')):
            s = {'name': name, 'role': 'fulladmin'}
            got = H.view_save(st, s, {'table': 'ct-q', 'name': 'mine', 'view': {},
                                      'scope': 'user', 'default': True})
            ident = got['view']['id']
            self.assertEqual(H.views(st, s, 'ct-q').get('default'), ident, name)
            self.assertEqual(H.views(st, s).get('defaults'), {'ct-q': ident}, name)


class OnSqlite(Flows, unittest.TestCase):
    n = 0

    def db(self):
        OnSqlite.n += 1
        return E.Db('sqlite', path=os.path.join(TMP, 'w7-%d.db' % OnSqlite.n))


@unittest.skipUnless(PG_BIN and psycopg2, 'PostgreSQL is not installed')
class OnPostgres(Flows, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rw7-pg-')
        os.chmod(cls.dir, 0o777)
        cls.port, cls.data, cls.n = free_port(), os.path.join(cls.dir, 'data'), 0
        r = as_user('postgres', [os.path.join(PG_BIN, 'initdb'), '-D', cls.data, '-A', 'trust',
                                 '-U', 'postgres', '-E', 'UTF8'])
        if r.returncode != 0:
            shutil.rmtree(cls.dir, ignore_errors=True)
            raise unittest.SkipTest('initdb: %s' % r.stdout[-300:])
        r = as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', cls.data, '-w', '-l',
                                 cls.data + '.log', '-o', '-p %d -k %s -c listen_addresses=127.0.0.1'
                                 % (cls.port, cls.dir), 'start'])
        if r.returncode != 0 or not wait_port(cls.port):
            cls.tearDownClass()
            raise unittest.SkipTest('PostgreSQL did not start: %s' % r.stdout[-300:])

    @classmethod
    def tearDownClass(cls):
        as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', cls.data, '-m', 'immediate',
                             'stop'])
        shutil.rmtree(cls.dir, ignore_errors=True)

    def db(self):
        OnPostgres.n += 1
        name = 'acme%d' % OnPostgres.n
        c = psycopg2.connect(host='127.0.0.1', port=self.port, dbname='postgres', user='postgres')
        c.autocommit = True
        c.cursor().execute('CREATE DATABASE %s' % name)
        c.close()
        return E.Db('postgres', '127.0.0.1', self.port, name, 'postgres', '', 10)


@unittest.skipUnless(MY_BIN and MY_INSTALL and pymysql, 'MariaDB is not installed')
class OnMariadb(Flows, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rw7-my-')
        cls.port, cls.data, cls.n, cls.proc = free_port(), os.path.join(cls.dir, 'data'), 0, None
        user = ['--user=root'] if os.geteuid() == 0 else []
        r = subprocess.run([MY_INSTALL, '--no-defaults', '--datadir=%s' % cls.data,
                            '--auth-root-authentication-method=normal'] + user,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            shutil.rmtree(cls.dir, ignore_errors=True)
            raise unittest.SkipTest('mariadb-install-db: %s' % r.stdout[-300:])
        cls.proc = subprocess.Popen(
            [MY_BIN, '--no-defaults', '--datadir=%s' % cls.data, '--port=%d' % cls.port,
             '--bind-address=127.0.0.1', '--socket=%s' % os.path.join(cls.dir, 'm.sock'),
             '--pid-file=%s' % os.path.join(cls.dir, 'm.pid')] + user,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(cls.port):
            cls.tearDownClass()
            raise unittest.SkipTest('MariaDB did not start')

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(30)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def admin(self, sql):
        c = pymysql.connect(host='127.0.0.1', port=self.port, user='root', password='')
        try:
            cur = c.cursor()
            cur.execute(sql)
            return cur.fetchall()
        finally:
            c.close()

    def db(self, name=None):
        if name is None:
            OnMariadb.n += 1
            name = 'acme%d' % OnMariadb.n
        self.admin('CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4' % name)
        return E.Db('mariadb', '127.0.0.1', self.port, name, 'root', '', 10)

    def width(self, db, table, col):
        return int(db.value("SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS "
                            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND "
                            "COLUMN_NAME = ?", (table, col)))

    def test_dns_names_widened_on_a_database_made_before(self):
        db = self.db()
        db.run('CREATE TABLE dns_records (id BIGINT AUTO_INCREMENT PRIMARY KEY, name '
               'VARCHAR(190) COLLATE utf8mb4_bin NOT NULL, rtype VARCHAR(190) COLLATE utf8mb4_bin '
               'NOT NULL, value TEXT)')
        db.run("INSERT INTO dns_records (name, rtype, value) VALUES ('kept.example', 'TXT', 'x')")
        db.run('CREATE TABLE dns_sets (id BIGINT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(190) '
               'COLLATE utf8mb4_bin NOT NULL UNIQUE, tls_name VARCHAR(190) COLLATE utf8mb4_bin)')
        st = E.Storage(db)
        self.addCleanup(db.close)
        self.assertEqual(self.width(db, 'dns_records', 'name'), 255)
        self.assertEqual(self.width(db, 'dns_sets', 'tls_name'), 255)
        self.assertEqual(self.width(db, 'meta', 'k'), 255)
        self.assertEqual(db.rows('SELECT name, value FROM dns_records'),
                         [{'name': 'kept.example', 'value': 'x'}])
        R.RunContext(st, None, scope='x').dns_put('_acme-challenge.' + LONG, 'TXT', 'y')
        self.assertEqual(db.value('SELECT COUNT(*) FROM dns_records'), 2)
        # once: a second start finds it wide already
        E.Storage(db)
        self.assertEqual(self.width(db, 'dns_records', 'name'), 255)


if __name__ == '__main__':
    unittest.main(verbosity=2)
