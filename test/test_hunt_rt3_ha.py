#!/usr/bin/env python3
"""Hunt Rt3 - the 1.0.125 data (teams, roles) through backups, dumps, export and import.

    python3 test/test_hunt_rt3_ha.py

- a copy without cert_roles (an older version's) put back: the custom roles here are emptied
  as every table the copy does not have, and the people's capabilities follow at once;
- a dump of PostgreSQL made by an older version (no cert_roles) put back over a database that
  has it: pg_restore could not drop acme_same_key() (the trigger of cert_roles uses it), so
  nothing was put back - now it is, cert_roles emptied as a copy empties it, its trigger back;
- the same with a dump of MariaDB: the roles stayed beside the dump's teams - now emptied.

PostgreSQL and MariaDB run as private servers of this test on free ports (never 5432/5433),
skipped where their programs are not installed.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_teams_enterprise as TE  # noqa: E402  (its database, its helpers)

T, E, STORE = TE.T, TE.E, TE.STORE
import acme  # noqa: E402

PG_BIN = next((p for p in sorted(
    ('/usr/lib/postgresql/%s/bin' % v for v in os.listdir('/usr/lib/postgresql')), reverse=True)
    if os.path.exists(os.path.join(p, 'initdb'))), None) \
    if os.path.isdir('/usr/lib/postgresql') else None
MY_BIN = shutil.which('mariadbd', path=os.environ.get('PATH', '') + ':/usr/sbin')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    if port in (5432, 5433, 8092, 3306):
        return free_port()
    return port


def as_user(user, cmd, **kw):
    if os.geteuid() == 0:
        cmd = ['runuser', '-u', user, '--'] + cmd
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


def wait_port(port, s=30):
    end = time.time() + s
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def a_team_and_a_role(store):
    T.changed()
    T.save_role(store, {'name': 'Ops', 'caps': ['cert.view', 'cert.renew']}, 'x')
    T.save_team(store, {'name': 'Top', 'members': [{'who': 'local:eva', 'roles': ['Ops']}]},
                'x')
    return T.person_caps(store, {'local:eva'}, [])['top']['caps']


class CopyWithout(unittest.TestCase):
    def setUp(self):
        TE.clean()

    def test_copy_without_roles(self):
        T.save_team(STORE, {'name': 'Top', 'members': ['local:eva=view']}, 'x')
        p = os.path.join(TE.TMP, 'no-roles.json.gz')
        E.dump_tables(STORE.db, p, [t for t in E.TABLES if t != 'cert_roles'])
        STORE.db.run("DELETE FROM cert_teams")
        T.changed()
        self.assertIn('cert.renew', a_team_and_a_role(STORE))
        E.load_tables(STORE.db, p)
        self.assertEqual(T.role_rows(STORE), [])
        self.assertNotIn('cert.renew', T.person_caps(STORE, {'local:eva'}, [])['top']['caps'])


class _Server(unittest.TestCase):
    engine = None
    live = None

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.update(cls.saved)
        try:
            cls.live.close()
        except Exception:                               # noqa: BLE001
            pass
        cls.stop()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def put_back(self, dump, name):
        db = E.Db(self.engine, '127.0.0.1', self.port, name, 'acme', 'optpw', 10)
        db.make_tables()
        store = acme.Storage(db)
        type(self).live = db
        type(self).saved = {k: E.CONFIG.get(k) for k in E.DB_KEYS}
        E.CONFIG.update(db_engine=self.engine, db_host='127.0.0.1', db_port=self.port,
                        db_name=name, db_user='acme', db_password='optpw')
        self.assertIn('cert.renew', a_team_and_a_role(store))
        E.db_file_restore(store, dump, 'test', need_admin=False, machine=False)
        T.changed()
        self.assertEqual(T.role_rows(store), [])
        self.assertEqual([r['name'] for r in db.rows('SELECT name FROM cert_teams')], ['Old'])
        self.assertIn('parent', db.columns('cert_teams'))
        self.assertIn('owner', db.columns('cert_targets'))
        # the roles are saved again as before
        T.save_role(store, {'name': 'Ops2', 'caps': ['cert.view']}, 'x')
        return db

    def old_db(self, name):
        db = E.Db(self.engine, '127.0.0.1', self.port, name, 'acme', 'optpw', 10)
        db.make_tables()
        db.insert('cert_teams', {'name': 'Old', 'kind': 'team', 'members': '[]'})
        db.run('DROP TABLE cert_roles')                 # as 1.0.124 had it
        db.close()


@unittest.skipUnless(PG_BIN and shutil.which('pg_dump') and shutil.which('pg_restore'),
                     'PostgreSQL is not installed')
class PgDump(_Server):
    engine = 'postgres'

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rt3-pg-')
        os.chmod(cls.dir, 0o777)
        cls.port = free_port()
        data = os.path.join(cls.dir, 'data')
        r = as_user('postgres', [os.path.join(PG_BIN, 'initdb'), '-D', data, '-A', 'trust',
                                 '-U', 'postgres'])
        if r.returncode != 0:
            raise unittest.SkipTest('initdb: %s' % r.stdout[-300:])
        r = as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', data, '-w', '-l',
                                 os.path.join(cls.dir, 'log'), '-o',
                                 '-p %d -k %s -c listen_addresses=127.0.0.1' % (cls.port, cls.dir),
                                 'start'])
        if r.returncode != 0 or not wait_port(cls.port):
            raise unittest.SkipTest('PostgreSQL did not start: %s' % r.stdout[-300:])
        cls.data = data
        cls.saved = {}
        for sql in ("CREATE USER acme PASSWORD 'optpw' SUPERUSER", 'CREATE DATABASE old OWNER acme',
                    'CREATE DATABASE live OWNER acme'):
            subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(cls.port), '-U', 'postgres',
                            '-qc', sql], check=True, stdout=subprocess.PIPE)

    @classmethod
    def stop(cls):
        as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', cls.data, '-m', 'immediate',
                             'stop'])

    def test_older_dump_put_back(self):
        self.old_db('old')
        dump = os.path.join(self.dir, 'old.pgdump')
        subprocess.run(['pg_dump', '-h', '127.0.0.1', '-p', str(self.port), '-U', 'acme',
                        '--format=custom', '--no-owner', '--no-privileges', '--file=' + dump,
                        '--dbname=old'], check=True, env=dict(os.environ, PGPASSWORD='optpw'))
        db = self.put_back(dump, 'live')
        self.assertTrue(db.value("SELECT 1 FROM pg_trigger WHERE tgname = 'acme_same_cert_roles'"))


@unittest.skipUnless(MY_BIN and shutil.which('mariadb-install-db') and
                     shutil.which('mariadb-dump'), 'MariaDB is not installed')
class MyDump(_Server):
    engine = 'mariadb'

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rt3-my-')
        os.chmod(cls.dir, 0o777)
        cls.port = free_port()
        data = os.path.join(cls.dir, 'data')
        user = ['--user=mysql'] if os.geteuid() == 0 else []
        r = subprocess.run(['mariadb-install-db', '--datadir=' + data,
                            '--auth-root-authentication-method=normal'] + user,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise unittest.SkipTest('mariadb-install-db: %s' % r.stdout[-300:])
        cls.sock = os.path.join(cls.dir, 's.sock')
        cls.proc = subprocess.Popen([MY_BIN, '--no-defaults'] + user + [
            '--datadir=' + data, '--port=%d' % cls.port, '--bind-address=127.0.0.1',
            '--socket=' + cls.sock, '--pid-file=' + os.path.join(cls.dir, 'p.pid'),
            '--log-error=' + os.path.join(cls.dir, 'log')],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(cls.port):
            cls.proc.kill()
            raise unittest.SkipTest('MariaDB did not start')
        cls.saved = {}
        subprocess.run(['mariadb', '-S', cls.sock, '-uroot', '-e',
                        "CREATE DATABASE old CHARACTER SET utf8mb4; CREATE DATABASE live "
                        "CHARACTER SET utf8mb4; CREATE USER 'acme'@'%' IDENTIFIED BY 'optpw'; "
                        "CREATE USER 'acme'@'localhost' IDENTIFIED BY 'optpw'; GRANT ALL ON *.* "
                        "TO 'acme'@'%'; GRANT ALL ON *.* TO 'acme'@'localhost';"], check=True)

    @classmethod
    def stop(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(20)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def test_older_dump_put_back(self):
        self.old_db('old')
        dump = os.path.join(self.dir, 'old.sql.gz')
        with open(dump, 'wb') as out:
            p1 = subprocess.Popen(['mariadb-dump', '-h127.0.0.1', '-P%d' % self.port, '-uacme',
                                   '-poptpw', '--single-transaction', '--add-drop-table',
                                   '--skip-comments', 'old'], stdout=subprocess.PIPE)
            subprocess.run(['gzip'], stdin=p1.stdout, stdout=out, check=True)
            p1.stdout.close()
            p1.wait()
        self.put_back(dump, 'live')


if __name__ == '__main__':
    unittest.main(verbosity=2)
