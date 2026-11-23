#!/usr/bin/env python3
"""Hunt w6 - data integrity under concurrency.

    python3 test/test_hunt_rw6_race.py

- two approvers of a request that wants two approvals, approving at the same moment: each
  read the approvals before the other's was written, each counted only its own - both
  recorded, the request waiting for good (nobody left to approve it);
- a certificate's new version saved twice at once (a renewal beside an import or a CSR's
  answer; the same connection, another connection to the same SQLite file, PostgreSQL and
  MariaDB on free ports - never 5432/5433/3306/8092 - where installed): the one that took the
  older number wrote its row last, and the certificate held the older version while a newer
  one was kept beside it;
- two administrators saving the same team (the page sends it whole, its members too): the one
  saving last wrote the members it had read over those the other had just added or removed -
  now refused with 409 when the team was saved since the page read it (was_updated), and
  written only over the row that was read;
- the same for a request profile, its version written with it in one transaction: two saves
  at once recorded the second one's settings as the first one's version, and a stop between
  the profile and its version left a change with no version;
- a certificate deleted: all of it or nothing (a stop in the middle left it without its
  deployments and versions), and a second Delete at once answered "there is none" - not
  "deleted" again with a second event;
- a team's governance (access reviews, elevation, separation of duties, channels, the digest)
  is one column: two parts saved at once each wrote the column over the other's - the
  separation of duties just set was gone;
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import itertools
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw6-race-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import teams as T, teampolicy as TP  # noqa: E402
from acmelib.certs import portal as P  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.certs import api_teams  # noqa: E402,F401
from acmelib.certs import reqprofiles as R, reqprofiles_more as RM  # noqa: E402
from acmelib.certs import api_reqprofiles  # noqa: E402,F401

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


class FakeH(object):
    def __init__(self, who='boss', role='fulladmin', body=None, portal=None):
        self.store, self._body = STORE, dict(body or {})
        self.who, self.role, self.portal = who, role, portal
        self.headers, self.args = {}, {}
        self.d = type('D', (), {'dirs': {}})()

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local',
                            'dn': '', 'group_list': ''}}

    def session(self, kind):
        return self.portal if kind == 'portal' else self.me()

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)


def portal(s, method, path, body=None):
    return E.ROUTES[(method, path)](FakeH(portal=s, body=body))


def person(name):
    data = {'kind': 'local', 'mail': '', 'about': {'upn': ''}, 'cert_groups': [],
            'cert_groups_at': time.time(), 'dn': '', 'dir_checked': time.time()}
    return {'name': name, 'data': data, 'kind': 'portal'}


def wait_jobs():
    from acmelib.certs import jobs
    end = time.time() + 20
    while time.time() < end and (jobs.RUNNING or jobs.BUSY_CERTS):
        time.sleep(0.05)


def clean():
    wait_jobs()
    for t in ('certs', 'cert_teams', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_req_profiles', 'cert_req_profile_versions'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:%' OR k LIKE 'teams:%'")
    T.changed()
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1, mail_mode='off',
                    portal_cert_auto=0, portal_cert_suffixes='example.test',
                    portal_cert_issuers='self', portal_cert_max=100)
    for n in ('eva', 'lead1', 'lead2', 'boss'):
        if not STORE.account(n):
            STORE.add_account(n, 'readonly', 'Local-Only-Pw-77!x' + n)
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


class TwoApproversAtOnce(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Web', 'members': [
            'local:eva=request', 'local:lead1=approve', 'local:lead2=approve'],
            'policy': {'approval': {'mode': 'always', 'count': 2}}}, 'x')

    def tearDown(self):
        wait_jobs()

    def approve(self, who, cid):
        return portal(person(who), 'POST', '/api/portal/cert_approve',
                      {'id': cid, 'ok': 1, 'why': 'fine'})

    def state(self, cid):
        return STORE.db.value('SELECT state FROM certs WHERE id = ?', (cid,))

    def test_both_at_once_let_through(self):
        cid = portal(person('eva'), 'POST', '/api/portal/cert_request',
                     {'names': ['race.example.test'], 'issuer': 'self', 'team': 'Web'})['id']
        self.assertEqual(self.state(cid), P.WAITING)
        real, got = TP._record, {}

        def record(store, c, entry):
            # lead1 has read the approvals (none); lead2 approves whole before lead1 writes
            if str(entry.get('by')).endswith('lead1') and 'lead2' not in got:
                got['lead2'] = self.approve('lead2', cid)
            return real(store, c, entry)
        TP._record = record
        try:
            got['lead1'] = self.approve('lead1', cid)
        finally:
            TP._record = real
        self.assertTrue(got['lead2'].get('recorded'))
        # both approvals are there - two of two: let through, not waiting for a third
        self.assertEqual(len(TP.approval_state(STORE, STORE.db.row(
            'SELECT * FROM certs WHERE id = ?', (cid,)))['approvals']), 2)
        self.assertNotEqual(self.state(cid), P.WAITING)
        self.assertIn('job_id', got['lead1'])


class TeamSavedByTwo(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Ops', 'members': ['local:eva=view']}, 'x')

    def members(self):
        return sorted(m['who'] for m in T.team_public(T.team_get(STORE, 'Ops'))['members'])

    def save(self, members, **more):
        b = {'old_name': 'Ops', 'name': 'Ops', 'members': members}
        b.update(more)
        return E.ROUTES[('POST', '/api/teams/save')](FakeH(body=b))

    def test_stale_page_refused(self):
        seen = T.team_public(T.team_get(STORE, 'Ops'))          # both pages read the team
        time.sleep(0.01)
        self.save(['local:eva=view', 'local:lead1=view'], was_updated=seen['updated'])
        with self.assertRaises(E.ApiError) as e:                 # the second page, read before
            self.save(['local:eva=view', 'local:lead2=view'], was_updated=seen['updated'])
        self.assertEqual(e.exception.status, 409)
        self.assertIn('load it again', str(e.exception))
        self.assertEqual(self.members(), ['local:eva', 'local:lead1'])
        # read again: saved
        now = T.team_public(T.team_get(STORE, 'Ops'))
        self.save(['local:eva=view', 'local:lead1=view', 'local:lead2=view'],
                  was_updated=now['updated'])
        self.assertEqual(self.members(), ['local:eva', 'local:lead1', 'local:lead2'])
        # without it (the command line, the console, the API as before): saved as before
        self.save(['local:eva=view'])
        self.assertEqual(self.members(), ['local:eva'])
        with self.assertRaises(ValueError):
            self.save(['local:eva=view'], was_updated='yesterday')

    def test_saved_between_read_and_write(self):
        real, done = T._clean_parent, []

        def between(*a, **kw):
            if not done:
                done.append(1)
                T.save_team(STORE, {'old_name': 'Ops', 'name': 'Ops',
                                    'members': ['local:eva=view', 'local:lead1=view']}, 'other')
            return real(*a, **kw)
        T._clean_parent = between
        try:
            with self.assertRaises(E.ApiError) as e:
                self.save(['local:eva=view', 'local:lead2=view'])
        finally:
            T._clean_parent = real
        self.assertEqual(e.exception.status, 409)
        self.assertEqual(self.members(), ['local:eva', 'local:lead1'])


def profile(**more):
    b = {'name': 'Web', 'description': 'one', 'issuer': 'self', 'suffixes': ['example.test'],
         'max_names': 3, 'make_key': True, 'csr': False, 'key_types': ['ec-256'],
         'key_default': 'ec-256', 'auto_renew': True, 'owner': 'person', 'teams': []}
    b.update(more)
    return b


class ProfileSavedByTwo(unittest.TestCase):
    def setUp(self):
        clean()
        R.save_profile(STORE, profile(), 'x')

    def save(self, **more):
        return E.ROUTES[('POST', '/api/reqprofiles/save')](FakeH(body=profile(
            old_name='Web', **more)))

    def vers(self):
        return [(v['version'], v['by'], v['snapshot']['description'])
                for v in RM.versions(STORE, 'Web')['versions']]

    def test_stale_page_refused(self):
        seen = R.public(STORE, R.profile_get(STORE, 'Web'))
        time.sleep(0.01)
        self.save(description='two', was_updated=seen['updated'])
        with self.assertRaises(E.ApiError) as e:
            self.save(description='three', was_updated=seen['updated'])
        self.assertEqual(e.exception.status, 409)
        self.assertEqual(R.profile_get(STORE, 'Web')['description'], 'two')
        now = R.public(STORE, R.profile_get(STORE, 'Web'))
        self.save(description='three', was_updated=now['updated'])
        self.save(description='four')                         # without it: as before
        self.assertEqual([v[2] for v in self.vers()], ['four', 'three', 'two', 'one'])

    def test_saved_between_read_and_write(self):
        real, done = R.build_cfg, []

        def between(store, b):
            if not done:
                done.append(1)
                R.save_profile(STORE, profile(old_name='Web', description='other'), 'other')
            return real(store, b)
        R.build_cfg = between
        try:
            with self.assertRaises(E.ApiError) as e:
                R.save_profile(STORE, profile(old_name='Web', description='mine'), 'me')
        finally:
            R.build_cfg = real
        self.assertEqual(e.exception.status, 409)
        self.assertEqual(R.profile_get(STORE, 'Web')['description'], 'other')
        # each version is what its author saved
        self.assertEqual([(v[1], v[2]) for v in self.vers()], [('other', 'other'), ('x', 'one')])

    def test_profile_and_version_together(self):
        real = RM._insert

        def broken(*a, **kw):
            raise RuntimeError('the database went away')
        RM._insert = broken
        try:
            with self.assertRaises(RuntimeError):
                R.save_profile(STORE, profile(old_name='Web', description='lost'), 'me')
        finally:
            RM._insert = real
        # nothing of it written: the profile as it was, no change without its version
        self.assertEqual(R.profile_get(STORE, 'Web')['description'], 'one')
        self.assertEqual([v[2] for v in self.vers()], ['one'])
        self.assertFalse(STORE.db.in_tx)


class DeleteTwice(unittest.TestCase):
    def setUp(self):
        clean()
        STORE.db.run("DELETE FROM cert_targets WHERE name = 'w6t'")
        self.cid = STORE.db.insert('certs', {'name': 'gone', 'names': '["gone.example.test"]',
                                             'state': 'ok', 'version': 1, 'enabled': 1,
                                             'created_by': 'x'})
        STORE.db.insert('cert_versions', {'cert_id': self.cid, 'version': 1, 'variant': ''})
        STORE.db.insert('cert_targets', {'name': 'w6t', 'kind': 'ssh', 'config': '{}'})
        STORE.db.insert('cert_deploys', {'cert_id': self.cid, 'target': 'w6t', 'enabled': 1})

    def tearDown(self):
        STORE.db.run("DELETE FROM cert_targets WHERE name = 'w6t'")

    def delete(self):
        return E.ROUTES[('POST', '/api/certs/delete')](FakeH(body={'id': self.cid}))

    def count(self, table, col='cert_id'):
        return STORE.db.value('SELECT COUNT(*) FROM %s WHERE %s = ?' % (table, col), (self.cid,))

    def test_half_a_delete_is_none(self):
        real = S.cert_meta_drop

        def broken(*a):
            raise RuntimeError('the database went away')
        S.cert_meta_drop = broken
        try:
            with self.assertRaises(RuntimeError):
                self.delete()
        finally:
            S.cert_meta_drop = real
        self.assertEqual((self.count('certs', 'id'), self.count('cert_deploys'),
                          self.count('cert_versions')), (1, 1, 1))
        self.assertFalse(STORE.db.in_tx)

    def test_deleted_twice(self):
        row = S.cert_need(STORE, self.cid)
        events = lambda: STORE.db.value(                 # noqa: E731
            "SELECT COUNT(*) FROM events WHERE words LIKE 'certificate gone deleted%'")
        before = events()
        self.assertTrue(A.cert_drop(STORE, row, 'one'))
        self.assertFalse(A.cert_drop(STORE, row, 'two'))   # read before the first went
        self.assertEqual(events() - before, 1)
        self.assertEqual((self.count('certs', 'id'), self.count('cert_deploys'),
                          self.count('cert_versions')), (0, 0, 0))


class TeamExtrasAtOnce(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Gov'}, 'x')

    def test_two_parts_at_once(self):
        from acmelib.certs import teamgov as G, digest as D
        real, done = G.extras_of, []

        def between(t):
            got = real(t)
            if not done and t and t.get('name') == 'Gov':
                done.append(1)            # read by the first save: the second one goes in whole
                G.set_extras(STORE, 'Gov', 'sod', {'exclusive': [['Requester', 'Approver']]},
                             'other')
            return got
        G.extras_of = between
        try:
            G.set_extras(STORE, 'Gov', 'jit', {'roles': ['Approver'], 'max_hours': 4}, 'me')
        finally:
            G.extras_of = real
        ex = G.extras_of(T.team_get(STORE, 'Gov'))
        self.assertEqual(sorted(ex), ['jit', 'sod'])
        # the digest too keeps what is beside it
        D.save(STORE, 'Gov', {'on': False}, 'me')
        self.assertEqual(sorted(G.extras_of(T.team_get(STORE, 'Gov'))), ['digest', 'jit', 'sod'])


# ---- a version saved twice at once ------------------------------------------------------------
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


def info(serial):
    return {'serial': serial, 'sha256': 'FP' + serial, 'not_before': time.time() - 60,
            'not_after': time.time() + 86400 * 60, 'issuer_dn': 'CN=t', 'subject_dn': 'CN=t'}


SEQ = itertools.count(1)


class VersionTwice(object):
    """A mixin: `stores()` gives (the store A saves through, the store B saves through)."""

    def check_twice(self, a, b):
        cid = a.db.insert('certs', {'name': 'twice', 'names': '["twice.example.test"]',
                                    'issuer': '', 'state': 'ok', 'version': 1, 'serial': 'S1',
                                    'cert_pem': 'PEM-1', 'created_by': 'test', 'enabled': 1})
        a.db.insert('cert_versions', {'cert_id': cid, 'version': 1, 'serial': 'S1',
                                      'cert_pem': 'PEM-1', 'why': 'new', 'variant': ''})
        real, other = E.Db.insert, {}

        def b_saves():
            other['v'] = S.save_version(b, cid, 'PEM-B', [], None, 'renew', 'job',
                                        info=info('SB'))

        def insert(this, table, row):
            got = real(this, table, row)
            if table == 'cert_versions' and row.get('cert_pem') == 'PEM-A' and 't' not in other:
                # A has its number and its version's row: B saves meanwhile
                other['t'] = threading.Thread(target=b_saves, name='w6-b')
                other['t'].start()
                other['t'].join(1.5)
            return got
        E.Db.insert = insert
        try:
            va = S.save_version(a, cid, 'PEM-A', [], None, 'import', 'admin', info=info('SA'))
        finally:
            E.Db.insert = real
        other['t'].join(30)
        self.assertEqual(sorted([va, other.get('v')]), [2, 3])
        row = a.db.row('SELECT version, cert_pem, serial FROM certs WHERE id = ?', (cid,))
        newest = a.db.row('SELECT version, cert_pem FROM cert_versions WHERE cert_id = ? '
                          'ORDER BY version DESC', (cid,))
        # the certificate holds the newest version kept - not the older one written last
        self.assertEqual(int(row['version']), 3)
        self.assertEqual((int(row['version']), row['cert_pem']),
                         (int(newest['version']), newest['cert_pem']))
        self.assertEqual(a.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = ?',
                                    (cid,)), 3)

    def test_unique_key_said_as_saved_twice(self):
        """The API answers a unique key's refusal 409 "saved at the same moment", not 500."""
        a, b = self.stores()
        try:
            a.db.insert('cert_tags', {'name': 'w6dup'})
            with self.assertRaises(Exception) as e:
                b.db.insert('cert_tags', {'name': 'w6dup'})
            self.assertTrue(E.is_taken_already(e.exception), repr(e.exception))
            self.assertFalse(E.is_taken_already(ValueError('UNIQUE constraint')))
            a.db.run('DELETE FROM cert_tags WHERE name = ?', ('w6dup',))
        finally:
            for st in {id(a.db): a, id(b.db): b}.values():
                st.db.close()

    def test_version_saved_twice(self):
        a, b = self.stores()
        try:
            self.check_twice(a, b)
        finally:
            for st in {id(a.db): a, id(b.db): b}.values():
                st.db.close()


class VersionTwiceOneConnection(VersionTwice, unittest.TestCase):
    def stores(self):
        db = E.Db('sqlite', path=os.path.join(TMP, 'v1-%d.sqlite' % next(SEQ)))
        st = E.Storage(db)
        return st, st


class VersionTwiceTwoConnections(VersionTwice, unittest.TestCase):
    def stores(self):
        path = os.path.join(TMP, 'v2-%d.sqlite' % next(SEQ))
        a = E.Storage(E.Db('sqlite', path=path))
        return a, E.Storage(E.Db('sqlite', path=path))


@unittest.skipUnless(PG_BIN and psycopg2, 'PostgreSQL is not installed')
class VersionTwiceOnPostgres(VersionTwice, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rw6-pg-')
        os.chmod(cls.dir, 0o777)
        cls.port, cls.data = free_port(), os.path.join(cls.dir, 'data')
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

    def stores(self):
        c = psycopg2.connect(host='127.0.0.1', port=self.port, dbname='postgres', user='postgres')
        c.autocommit = True
        name = 'acmew6_%d' % next(SEQ)
        c.cursor().execute('CREATE DATABASE %s' % name)
        c.close()

        def one():
            return E.Storage(E.Db('postgres', '127.0.0.1', self.port, name, 'postgres', '', 10))
        a = one()
        return a, one()


@unittest.skipUnless(MY_BIN and MY_INSTALL and pymysql, 'MariaDB is not installed')
class VersionTwiceOnMariadb(VersionTwice, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rw6-my-')
        cls.port, cls.data, cls.proc = free_port(), os.path.join(cls.dir, 'data'), None
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

    def stores(self):
        c = pymysql.connect(host='127.0.0.1', port=self.port, user='root', password='')
        try:
            name = 'acmew6_%d' % next(SEQ)
            c.cursor().execute('CREATE DATABASE %s CHARACTER SET utf8mb4' % name)
        finally:
            c.close()

        def one():
            return E.Storage(E.Db('mariadb', '127.0.0.1', self.port, name, 'root', '', 10))
        a = one()
        return a, one()


def tearDownModule():
    wait_jobs()
    try:
        STORE.db.close()
    except Exception:                                   # noqa: BLE001
        pass
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
