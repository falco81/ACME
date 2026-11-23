#!/usr/bin/env python3
"""Hunt 140 - a backup is one moment of the database, on SQLite, PostgreSQL and MariaDB.

    python3 test/test_hunt_r140_snapshot.py

dump_tables (every backup: make_backup, the remote backup, the copy downloaded, --dump-copy)
read the tables one by one, each SELECT a moment of its own: a renewal committed while the
copy was between `certs` and `cert_versions` left the certificate at its old version in the
copy and its new version beside it. Here a change touching both tables is committed from
another connection right after `certs` was read; the copy must show both tables before it.
PostgreSQL and MariaDB run privately on free ports (never 5432/5433/3306/8092), skipped where
they are not installed.
"""
import gzip
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-r140-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import store as S  # noqa: E402,F401  (its tables)

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


def read_copy(path):
    """The copy, table by table: {table: [rows]}."""
    out, table = {}, None
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        f.readline()
        for line in f:
            got = json.loads(line)
            if set(got) == {'table'}:
                table = got['table']
                out[table] = []
            else:
                out[table].append(got)
    return out


class Snapshot(object):
    """A mixin: `db()` gives an empty database of the engine."""

    def again(self, db):
        """A second connection to the same database - the daemon writing."""
        return E.Db(db.engine, db.host, db.port, db.name, db.user, db.password, 10,
                    path=db.path)

    def fill(self, db):
        E.Storage(db)
        cid = db.insert('certs', {'name': 'web', 'names': '["a.example"]', 'version': 1,
                                  'serial': 'S1', 'state': 'ok'})
        db.insert('cert_versions', {'cert_id': cid, 'version': 1, 'serial': 'S1', 'why': 'new'})
        return cid

    def with_renewal_between_tables(self, db, cid, make):
        """make() run with a renewal committed by another connection right after `certs`
        was read (certs and cert_versions both changed, in one transaction)."""
        writer = self.again(db)
        real, done = E.Db.rows, []

        def rows(this, sql, args=()):
            got = real(this, sql, args)
            if this is not writer and not done and 'FROM certs WHERE' in sql:
                done.append(1)
                with writer.transaction():
                    writer.run('UPDATE certs SET version = 2, serial = ? WHERE id = ?',
                               ('S2', cid))
                    writer.insert('cert_versions', {'cert_id': cid, 'version': 2,
                                                    'serial': 'S2', 'why': 'renewal'})
            return got
        E.Db.rows = rows
        try:
            out = make()
        finally:
            E.Db.rows = real
        self.assertTrue(done, 'the renewal was not made between the tables')
        # the renewal itself went in meanwhile - nothing waited for the copy
        self.assertEqual(writer.value('SELECT MAX(version) FROM cert_versions WHERE cert_id = ?',
                                      (cid,)), 2)
        self.assertEqual(writer.value('SELECT version FROM certs WHERE id = ?', (cid,)), 2)
        writer.close()
        return str(out)

    def check_one_moment(self, out, cid):
        got = read_copy(out)
        cert = [r for r in got['certs'] if r['id'] == cid][0]
        vers = sorted(int(r['version']) for r in got['cert_versions'] if r['cert_id'] == cid)
        # the certificate and its versions of the same moment: here, before the renewal
        self.assertEqual((int(cert['version']), cert['serial']), (1, 'S1'))
        self.assertEqual(vers, [1])
        # ...and put back, the same
        back = E.Db('sqlite', path=os.path.join(TMP, 'back-%d.sqlite' % id(out)))
        E.Storage(back)
        E.load_tables(back, out)
        self.assertEqual(back.value('SELECT version FROM certs WHERE id = ?', (cid,)), 1)
        self.assertEqual(back.value('SELECT MAX(version) FROM cert_versions WHERE cert_id = ?',
                                    (cid,)), 1)
        back.close()

    def test_backup_is_one_moment(self):
        db = self.db()
        cid = self.fill(db)
        path = os.path.join(TMP, 'copy-%s-%d.json.gz' % (db.engine, id(db)))
        out = self.with_renewal_between_tables(db, cid, lambda: E.dump_tables(db, path))
        self.check_one_moment(out, cid)
        # the connection is out of its transaction again, and writes
        self.assertFalse(db.in_tx)
        db.run('UPDATE certs SET note = ? WHERE id = ?', ('after', cid))
        self.assertEqual(db.value('SELECT note FROM certs WHERE id = ?', (cid,)), 'after')
        db.close()


class OnSqlite(Snapshot, unittest.TestCase):
    n = 0

    def db(self):
        OnSqlite.n += 1
        return E.Db('sqlite', path=os.path.join(TMP, 'db%d.sqlite' % OnSqlite.n))

    def test_wal_in_use(self):
        db = self.db()
        self.assertEqual(db.value('PRAGMA journal_mode'), 'wal')
        db.close()

    def test_not_wal_read_from_sqlites_own_backup(self):
        """A file not in WAL mode (a read transaction would hold every writer off): read
        from SQLite's own backup of it, made at once, and left nowhere."""
        db = self.db()
        cid = self.fill(db)
        db.run('PRAGMA journal_mode=DELETE')
        self.assertEqual(db.value('PRAGMA journal_mode'), 'delete')
        path = os.path.join(TMP, 'copy-delete.json.gz')
        out = self.with_renewal_between_tables(db, cid, lambda: E.dump_tables(db, path))
        self.check_one_moment(out, cid)
        self.assertEqual([f for f in os.listdir(TMP) if 'snapshot' in f], [])
        db.close()

    def test_make_backup(self):
        db = self.db()
        cid = self.fill(db)
        st = E.Storage(db)
        out = self.with_renewal_between_tables(db, cid, lambda: E.make_backup(st, 'test'))
        self.check_one_moment(out, cid)
        db.close()


@unittest.skipUnless(PG_BIN and psycopg2, 'PostgreSQL is not installed')
class OnPostgres(Snapshot, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-r140-pg-')
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
class OnMariadb(Snapshot, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-r140-my-')
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

    def test_tables_are_innodb(self):
        db = self.db()
        E.Storage(db)
        other = db.rows("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = "
                        "DATABASE() AND ENGINE <> 'InnoDB'")
        self.assertEqual(other, [])
        db.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
