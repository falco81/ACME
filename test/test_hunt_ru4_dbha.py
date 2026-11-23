#!/usr/bin/env python3
"""Hunt u4 - the database layer: LIKE on SQLite, PostgreSQL and MariaDB alike.

    python3 test/test_hunt_ru4_dbha.py

- a validation renamed by names.migrate (an unsafe name of an older version, with a letter
  outside ASCII or a quote): the certificates' challenge_map and their own settings of it
  (profile.over.validation) kept the old name on PostgreSQL and MariaDB - the JSON holds
  \\u00e9 and \\", and both engines took the backslash for LIKE's escape. Run on SQLite, and
  on a private PostgreSQL and MariaDB of this test on free ports (never 5432/5433/3306),
  skipped where they are not installed;
- "used by" of a validation counted with LIKE alone: dns_a was used by the certificate of
  dns-a ("_" any letter, SQLite ignoring case too) - an unused dns-persist-01 validation was
  "in use (1)" and could not be deleted with its records.
"""
import json
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
TMP = tempfile.mkdtemp(prefix='acme-ru4-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import names as N  # noqa: E402
from acmelib.certs import store as S  # noqa: E402

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


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    if port in (5432, 5433, 8092, 3306) or port < 20000:
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


OLD = 'Ověření "DNS"'          # an unsafe name an older version took


class Engines(object):
    """The rename on one engine (a mixin: `db()` gives an empty database)."""

    def test_unsafe_validation_renamed_in_the_certificates_too(self):
        st = E.Storage(self.db())
        st.db.insert('cert_challenges', {'name': OLD, 'kind': 'http_local', 'config': '{}',
                                         'enabled': 1})
        cid = st.db.insert('certs', {
            'name': 'c1', 'challenge': 'other', 'names': '["a.example", "b.example"]',
            'challenge_map': json.dumps({'a.example': OLD}),
            'profile': json.dumps({'over': {'validation': {OLD: {'k': 1}}}})})
        N.migrate(st, 'test')
        new = st.db.value('SELECT name FROM cert_challenges')
        self.assertNotEqual(new, OLD)
        r = st.db.row('SELECT challenge_map, profile FROM certs WHERE id = ?', (cid,))
        self.assertEqual(json.loads(r['challenge_map']), {'a.example': new})
        self.assertEqual(json.loads(r['profile']), {'over': {'validation': {new: {'k': 1}}}})
        st.db.close()

    def test_used_by_counts_its_own_certificates_only(self):
        st = E.Storage(self.db())
        for n in ('val_a', 'val-a', 'VAL'):
            st.db.insert('cert_challenges', {'name': n, 'kind': 'dns_persist', 'config': '{}',
                                             'enabled': 1})
        st.db.insert('certs', {'name': 'c1', 'challenge': 'x', 'names': '["a.example"]',
                               'challenge_map': json.dumps({'a.example': 'val-a'})})
        st.db.insert('certs', {'name': 'c2', 'challenge': 'x', 'names': '["b.example"]',
                               'challenge_map': json.dumps({'b.example': 'val'})})
        st.db.insert('certs', {'name': 'c3', 'challenge': 'VAL', 'names': '["c.example"]'})
        got = {n: S.plugin_public(st, 'challenge', st.db.row(
            'SELECT * FROM cert_challenges WHERE name = ?', (n,)))['used_by']
            for n in ('val_a', 'val-a', 'VAL')}
        self.assertEqual(got, {'val_a': 0, 'val-a': 1, 'VAL': 1})
        st.db.close()


class OnSqlite(Engines, unittest.TestCase):
    n = 0

    def db(self):
        OnSqlite.n += 1
        return E.Db('sqlite', path=os.path.join(TMP, 'db%d.sqlite' % OnSqlite.n))

    def test_like_escaped(self):
        self.assertEqual(E.like_escaped('a_b%c!d\\e'), 'a!_b!%c!!d\\e')
        db = self.db()
        db.make_tables()
        for k in ('x:a_b', 'x:aXb', 'x:A_B', 'x:a\\u00e9'):
            db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, '1'))
        def like(pat):
            return sorted(r['k'] for r in db.rows("SELECT k FROM meta WHERE k LIKE ? ESCAPE '!'",
                                                  (E.like_escaped(pat) + '%',)))
        # "_" itself, not any letter (SQLite's LIKE still ignores the case of ASCII letters)
        self.assertEqual(like('x:a_b'), ['x:A_B', 'x:a_b'])
        self.assertEqual(like('x:a\\u00e9'), ['x:a\\u00e9'])
        db.close()


@unittest.skipUnless(PG_BIN and psycopg2, 'PostgreSQL is not installed')
class OnPostgres(Engines, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-ru4-pg-')
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
class OnMariadb(Engines, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-ru4-my-')
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
             '--pid-file=%s' % os.path.join(cls.dir, 'm.pid'), '--skip-grant-tables'] + user,
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

    def db(self):
        OnMariadb.n += 1
        name = 'acme%d' % OnMariadb.n
        c = pymysql.connect(host='127.0.0.1', port=self.port, user='root', password='')
        try:
            c.cursor().execute('CREATE DATABASE %s CHARACTER SET utf8mb4' % name)
        finally:
            c.close()
        return E.Db('mariadb', '127.0.0.1', self.port, name, 'root', '', 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
