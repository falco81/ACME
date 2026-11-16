#!/usr/bin/env python3
"""Alerts for what the nodes already saw (as otp 1.0.242), and the quiet rows (1.0.234).

    python3 test/test_alerts_more.py     (or python3 -m unittest test.test_alerts_more)

Each new alert raised from what a node wrote in its health row (or the database holds) and
gone once that is over, each with its own switch; the opt-in ones off by default. What is
said as it happens comes from the events - and the very first look, with no event at all
yet, no longer leaves it at 0 for ever (nothing was ever said). The 'quiet' row is each
node's own, and a test alert from the node that does not send writes nothing back.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-alerts-more-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
ME = E.node_name()


def health(**kw):
    row = {'at': time.time()}
    row.update(kw)
    STORE.set_meta('host:health:' + ME, json.dumps(row))


def keys():
    return set(E.alert_problems(STORE))


class TestNew(unittest.TestCase):
    def setUp(self):
        for k in list(E.CONFIG):
            if k.startswith('alerts_'):
                E.CONFIG[k] = E.DEFAULTS.get(k)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'host:%' OR k LIKE 'acme:state:%' OR "
                     "k LIKE 'mailq:%' OR k LIKE 'alerts:%'")
        health()

    def test_defaults(self):
        on = ('alerts_shipping', 'alerts_snmp', 'alerts_acme', 'alerts_upgrade', 'alerts_trial',
              'alerts_dbguard', 'alerts_mailq', 'alerts_split', 'alerts_clock')
        off = ('alerts_repl_behind_mb', 'alerts_selinux', 'alerts_hisec', 'alerts_sso')
        self.assertEqual([E.DEFAULTS[k] for k in on], [1] * len(on))
        self.assertEqual([E.DEFAULTS[k] for k in off], [0] * len(off))
        for k in on + off:
            self.assertIn(k, E.PANES['alerts'])
            self.assertIn(k, E.NAMES)
            self.assertIn(k, E.SAYS)

    def test_logs_not_shipped(self):
        health(isemon={'on': True, 'trouble': {'isemon.example:6514': 'refused'}, 'dropped': 12})
        k = 'ship:isemon:' + ME
        al = E.alert_problems(STORE)
        self.assertIn(k, al)
        self.assertIn('12 lines dropped', al[k]['said'])
        E.CONFIG['alerts_shipping'] = 0
        self.assertNotIn(k, keys())
        E.CONFIG['alerts_shipping'] = 1
        health(isemon={'on': True, 'trouble': {}})
        self.assertNotIn(k, keys())

    def test_snmp(self):
        E.CONFIG['snmp'] = 1
        try:
            health(snmp={'listening': False, 'error': 'the port 161 is taken'})
            self.assertIn('snmp:' + ME, keys())
            health(snmp={'listening': True, 'trap_error': 'nms: refused'})
            self.assertIn('snmp:trap:' + ME, keys())
            health(snmp={'listening': True})
            self.assertFalse([k for k in keys() if k.startswith('snmp')])
        finally:
            E.CONFIG['snmp'] = 0

    def test_the_ca_did_not_renew(self):
        E.CONFIG['acme'] = 1
        try:
            STORE.set_meta('acme:state:' + ME, json.dumps({'ok': False, 'failed_at': time.time(),
                                                            'said': 'the CA said no'}))
            al = E.alert_problems(STORE)
            self.assertIn('acme:' + ME, al)
            self.assertEqual(al['acme:' + ME]['said'], 'the CA said no')
            STORE.set_meta('acme:state:' + ME, json.dumps({'ok': True}))
            self.assertNotIn('acme:' + ME, keys())
        finally:
            E.CONFIG['acme'] = 0

    def test_key_and_name_clash(self):
        health(key_lost=True, name_clash='two machines call themselves %s' % ME)
        al = E.alert_problems(STORE)
        self.assertEqual(al['key:' + ME]['level'], 'bad')
        self.assertIn('sealed secrets', al['key:' + ME]['title'])
        self.assertIn('clash:' + ME, al)
        self.assertIn('zapečetěná', E.alert_problems(STORE, 'cs')['key:' + ME]['title'])

    def test_updates_failed(self):
        STORE.set_meta('host:osup:plan', json.dumps({'state': 'failed', 'ended': time.time(),
                                                      'failed_on': ME}))
        STORE.set_meta('host:osup:check:' + ME, json.dumps({'state': 'failed', 'at': time.time(),
                                                             'error': 'no repository'}))
        got = keys()
        self.assertIn('osup:failed', got)
        self.assertIn('osup:check:' + ME, got)

    def test_internal_certificates(self):
        E.CONFIG['alerts_cert_days'] = 14
        STORE.set_meta('dbtls:server:' + ME, json.dumps({'cert_end': time.time() + 3 * 86400}))
        STORE.set_meta('hatls:node:' + ME, json.dumps({'cert_end': time.time() + 300 * 86400}))
        got = E.alert_problems(STORE)
        self.assertEqual(got['cert:pg:' + ME]['level'], 'bad')
        self.assertNotIn('cert:link:' + ME, got)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'dbtls:%' OR k LIKE 'hatls:%'")

    def test_dbguard_refused(self):
        health(dbguard_refused=[{'what': 'fw:conf', 'why': 'it is not signed', 'at': time.time()}])
        al = E.alert_problems(STORE)
        self.assertIn('fw:conf (it is not signed)', al['dbguard:' + ME]['said'])
        E.CONFIG['alerts_dbguard'] = 0
        self.assertNotIn('dbguard:' + ME, keys())

    def test_mails_that_do_not_go(self):
        STORE.set_meta('mailq:1', json.dumps({'state': 'failed', 'kind': 'code', 'created': time.time(),
                                               'said': '550 no such user'}))
        STORE.set_meta('mailq:2', json.dumps({'state': 'failed', 'kind': 'alert', 'created': time.time()}))
        al = E.alert_problems(STORE)
        self.assertIn('mailq', al)
        self.assertIn('1 mail', al['mailq']['title'])

    def test_opt_in_ones_off(self):
        got = keys()
        self.assertFalse([k for k in got if k.startswith(('selinux:', 'hisec', 'repl:behind'))])

    def test_selinux_when_switched_on(self):
        E.CONFIG['alerts_selinux'] = 1
        had = getattr(E, 'selinux_problems', None)
        try:
            # Ported by another part: asked only when there.
            E.__dict__['selinux_problems'] = lambda store, n: ['SELinux refused 2 things', 'ready for enforcing']
            al = E.alert_problems(STORE)
            self.assertEqual(al['selinux:' + ME]['said'], 'SELinux refused 2 things')
        finally:
            if had is None:
                E.__dict__.pop('selinux_problems', None)
            else:
                E.__dict__['selinux_problems'] = had


class TestEvents(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:%'")
        STORE.db.run('DELETE FROM events')
        E.CONFIG['alerts'] = 0           # nothing mailed - what would be said is counted

    def test_first_look_with_no_event(self):
        got = E.alerts_evaluate(STORE)
        st = json.loads(STORE.get_meta('alerts:state'))
        self.assertIn('event_id', st)
        self.assertEqual(st['event_id'], 0)
        self.assertEqual(got['events'], 0)
        # What comes later is said - it was never, with no event at the first look.
        STORE.add_event('settings', 'the firewall and access went back to what they were before '
                                    '(not kept in 5 min)', 'warn')
        STORE.add_event('settings', 'somebody saved the settings')
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 1)
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 0)       # said once
        E.CONFIG['alerts_trial'] = 0
        STORE.add_event('settings', 'the change of the SSH server went back on n1', 'warn')
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 0)
        E.CONFIG['alerts_trial'] = 1


class TestQuiet(unittest.TestCase):
    def test_each_node_its_own_row(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:quiet%'")
        STORE.set_meta('alerts:quiet:other', json.dumps({'why': 'other in maintenance',
                                                         'until': time.time() + 300}))
        self.assertGreater(E.alerts_quiet_until(STORE), time.time())
        self.assertIn('other in maintenance', E.alerts_quiet(STORE, [ME]))
        self.assertIsNone(STORE.get_meta('alerts:quiet'))

    def test_a_test_from_the_other_node_writes_nothing_back(self):
        STORE.db.run("DELETE FROM meta WHERE k = 'alerts:state'")
        was = E.alerts_lead
        E.__dict__['alerts_lead'] = lambda store: False
        try:
            def boom(*a, **kw):
                raise E.MailError('nobody to send to')
            had = E.mail_deliver
            E.__dict__['mail_deliver'] = boom
            try:
                E.alert_send(STORE, {'Subject': 'test'}, ['a@example.cz'], 'test', [])
            finally:
                E.__dict__['mail_deliver'] = had
            self.assertIsNone(STORE.get_meta('alerts:state'))
        finally:
            E.__dict__['alerts_lead'] = was


class TestReportDue(unittest.TestCase):
    def test_a_missed_day_goes_later_in_its_period(self):
        from datetime import datetime
        E.CONFIG.update(report_every='weekly', report_day=3, report_at='07:30')
        wed_early = time.mktime(datetime(2026, 11, 4, 6, 0).timetuple())    # a Wednesday
        wed_late = time.mktime(datetime(2026, 11, 4, 8, 0).timetuple())
        fri = time.mktime(datetime(2026, 11, 6, 3, 0).timetuple())
        tue = time.mktime(datetime(2026, 11, 3, 9, 0).timetuple())
        self.assertEqual([E.report_due(t) for t in (wed_early, wed_late, fri, tue)],
                         [False, True, True, False])
        # One period: the same mark whichever day of it.
        self.assertEqual(E.report_period(wed_late)[2], E.report_period(fri)[2])
        E.CONFIG.update(report_every='monthly')
        self.assertTrue(E.report_due(time.mktime(datetime(2026, 11, 9, 3, 0).timetuple())))
        self.assertFalse(E.report_due(time.mktime(datetime(2026, 11, 1, 3, 0).timetuple())))
        E.CONFIG.update(report_every=E.DEFAULTS['report_every'], report_day=E.DEFAULTS['report_day'])


class TestTrialEvents(unittest.TestCase):
    def test_network_going_back_said(self):
        with open(os.path.join(ROOT, 'acmelib/engine/305_changes_that_could_cut.py')) as f:
            src = f.read()
        self.assertIn('went back to the network it had before', src)
        rule = [r for r in E.ALERT_EVENTS if r[0] == 'alerts_trial'][0]
        self.assertIn('went back to the network it had before', rule[2])



class TestDbTrouble(unittest.TestCase):
    """1.0.115: the database's own trouble written down where the daemon's statements fail (it
    was written by the RADIUS server only, gone since) - in the health row, the alert and
    acmeDbTrouble; a statement's own mistake is no trouble of the database's."""

    def setUp(self):
        E.DB_TROUBLE_SEEN.update(at=0.0, said='')
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'host:%'")

    def tearDown(self):
        E.DB_TROUBLE_SEEN.update(at=0.0, said='')

    def test_forced_error_seen_by_the_alert_and_snmp(self):
        import sqlite3
        import types
        db = STORE.db
        real = db._run

        def locked(sql, args, fetch):
            raise sqlite3.OperationalError('database is locked')
        db._run = locked
        try:
            with self.assertRaises(sqlite3.OperationalError):
                db.value('SELECT COUNT(*) FROM accounts')
        finally:
            db._run = real
        self.assertEqual(E.DB_TROUBLE_SEEN['said'], 'database is locked')
        self.assertLess(time.time() - E.DB_TROUBLE_SEEN['at'], 5)
        row = E.health_publish(types.SimpleNamespace(store=STORE, dirs={}))
        self.assertEqual(row['db_trouble'], 'database is locked')
        al = E.alert_problems(STORE)
        self.assertIn('db:' + ME, al)
        self.assertIn('database is locked', al['db:' + ME]['said'])
        stored = json.loads(STORE.get_meta('host:health:' + ME))
        self.assertEqual(E._sf_db(STORE, stored)['trouble'], 'database is locked')
        was = E.snmp_facts
        E.snmp_facts = lambda daemon, fresh=False: {'db': E._sf_db(STORE, stored)}
        try:
            rows = {sub: v for sub, _k, v in E.snmp_more_rows(None)}
        finally:
            E.snmp_facts = was
        self.assertEqual(rows[(3, 6, 0)], 'database is locked')       # acmeDbTrouble
        # 5 minutes on, gone
        E.DB_TROUBLE_SEEN['at'] = time.time() - 301
        self.assertEqual(E.health_publish(types.SimpleNamespace(store=STORE, dirs={}))
                         ['db_trouble'], '')
        self.assertNotIn('db:' + ME, keys())

    def test_a_statements_own_mistake_is_not_trouble(self):
        for sql in ('SELECT nothing_here FROM accounts', 'SELEC 1',
                    'SELECT * FROM no_such_table'):
            with self.assertRaises(Exception):
                STORE.db.value(sql)
        self.assertEqual(E.DB_TROUBLE_SEEN['said'], '')
        import sqlite3
        self.assertFalse(E.db_trouble(sqlite3.OperationalError('duplicate column name: x')))
        self.assertTrue(E.db_trouble(sqlite3.OperationalError('database is locked')))
        self.assertTrue(E.db_trouble(E.DbError('MariaDB could not be reached')))

    def test_real_sqlite_errors(self):
        """1.0.115: a file that is no database, or a broken one, is the database's trouble -
        SQLite says it as a plain DatabaseError; a constraint is the request's."""
        import sqlite3
        d = tempfile.mkdtemp(prefix='acme-dbt-sqlite-', dir=TMP)
        junk = os.path.join(d, 'junk.db')
        with open(junk, 'wb') as f:
            f.write(b'this is no database at all ' * 200)
        broken = os.path.join(d, 'broken.db')
        c = sqlite3.connect(broken)
        c.execute('CREATE TABLE t (a)')
        c.executemany('INSERT INTO t VALUES (?)', [('x' * 500,)] * 200)
        c.commit()
        c.close()
        with open(broken, 'rb') as f:
            b = bytearray(f.read())
        for i in range(4096, len(b), 7):
            b[i] = 0xff
        with open(broken, 'wb') as f:
            f.write(bytes(b))
        got = {}
        for name, path, sql in (('junk', junk, 'SELECT 1 FROM sqlite_master'),
                                ('broken', broken, 'SELECT * FROM t')):
            try:
                sqlite3.connect(path).execute(sql).fetchall()
            except Exception as e:                      # noqa: BLE001
                got[name] = e
        self.assertEqual(type(got['junk']).__name__, 'DatabaseError')
        self.assertIn('not a database', str(got['junk']))
        self.assertIn('malformed', str(got['broken']))
        self.assertTrue(E.db_trouble(got['junk']))
        self.assertTrue(E.db_trouble(got['broken']))
        c = sqlite3.connect(':memory:')
        c.execute('CREATE TABLE t (a UNIQUE)')
        c.execute('INSERT INTO t VALUES (1)')
        with self.assertRaises(sqlite3.IntegrityError) as cm:
            c.execute('INSERT INTO t VALUES (1)')
        self.assertFalse(E.db_trouble(cm.exception))

    def test_real_postgres_errors(self):
        """1.0.115: PostgreSQL's by its SQLSTATE - a statement cancelled, a lock not to be had,
        a connection lost or refused are the database's; a column, a syntax, a constraint, a
        value out of range are the request's (every OperationalError and InternalError was)."""
        import shutil
        import socket
        import subprocess
        pgbin = os.environ.get('ACME_TEST_PGBIN', '/usr/lib/postgresql/16/bin')
        try:
            import psycopg2
        except ImportError:
            self.skipTest('no psycopg2 here')
        if os.geteuid() != 0 or not os.path.exists(os.path.join(pgbin, 'initdb')) or \
                not shutil.which('runuser'):
            self.skipTest('no PostgreSQL to start here')
        top = tempfile.mkdtemp(prefix='acme-dbt-pg-', dir='/var/tmp')
        os.chmod(top, 0o755)
        d = os.path.join(top, 'pg')
        os.makedirs(d)
        shutil.chown(d, 'postgres', 'postgres')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()

        def pg(*a):
            return subprocess.run(['runuser', '-u', 'postgres', '--'] + list(a), capture_output=True,
                                  text=True, cwd='/', timeout=120)
        self.assertEqual(pg(os.path.join(pgbin, 'initdb'), '-D', d + '/data', '-U', 'postgres',
                            '--auth=trust').returncode, 0)
        with open(d + '/data/postgresql.auto.conf', 'a') as f:
            f.write("port = %d\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '%s'\n"
                    % (port, d))
        self.assertEqual(pg(os.path.join(pgbin, 'pg_ctl'), '-D', d + '/data', '-l', d + '/log', '-w',
                            'start').returncode, 0)
        try:
            def conn(auto=True):
                c = psycopg2.connect(host='127.0.0.1', port=port, user='postgres', dbname='postgres')
                c.autocommit = auto
                return c
            c = conn()
            cur = c.cursor()
            cur.execute('CREATE TABLE u (a int UNIQUE)')
            cur.execute('INSERT INTO u VALUES (1)')

            def err(sql, cn=None):
                try:
                    (cn or c).cursor().execute(sql)
                except psycopg2.Error as e:
                    if (cn or c).autocommit and not (cn or c).closed:
                        try:
                            (cn or c).cursor().execute('ROLLBACK')
                        except psycopg2.Error:
                            pass
                    return e
                self.fail('no error: ' + sql)
            for sql in ('SELECT nope', 'SELEC 1', 'INSERT INTO u VALUES (1)', 'SELECT 1/0',
                        'SELECT 2147483647::int + 1'):
                self.assertFalse(E.db_trouble(err(sql)), sql)
            e = err('SET statement_timeout = 50; SELECT pg_sleep(1)')
            self.assertEqual((e.pgcode, E.db_trouble(e)), ('57014', True))
            cur.execute('SET statement_timeout = 0')
            other = conn(False)
            other.cursor().execute('LOCK TABLE u IN ACCESS EXCLUSIVE MODE')
            e = err('SET lock_timeout = 100; SELECT * FROM u')
            self.assertEqual((e.pgcode, E.db_trouble(e)), ('55P03', True))
            other.rollback()
            gone = conn()
            cur.execute('SELECT pg_terminate_backend(%s)', (gone.get_backend_pid(),))
            time.sleep(0.3)
            e = err('SELECT 1', gone)
            self.assertIsNone(e.pgcode)
            self.assertTrue(E.db_trouble(e))
            self.assertTrue(E.db_trouble(err('SELECT 1', gone)))        # closed: InterfaceError
            with self.assertRaises(psycopg2.OperationalError) as cm:
                psycopg2.connect(host='127.0.0.1', port=1, user='postgres', connect_timeout=2)
            self.assertTrue(E.db_trouble(cm.exception))
        finally:
            pg(os.path.join(pgbin, 'pg_ctl'), '-D', d + '/data', '-w', '-m', 'immediate', 'stop')
            shutil.rmtree(top, ignore_errors=True)

    def test_real_mariadb_errors(self):
        """1.0.115: MariaDB's by its number - a table full, a lock wait, read-only, the
        connection gone are the database's; a column, a syntax, a duplicate, a value too big,
        a password refused are not."""
        import shutil
        import socket
        import subprocess
        try:
            import pymysql
        except ImportError:
            self.skipTest('no pymysql here')
        if os.geteuid() != 0 or not shutil.which('mariadbd') or \
                not shutil.which('mariadb-install-db'):
            self.skipTest('no MariaDB to start here')
        top = tempfile.mkdtemp(prefix='acme-dbt-my-', dir='/var/tmp')
        os.chmod(top, 0o755)
        shutil.chown(top, 'mysql', 'mysql')
        d = os.path.join(top, 'data')
        os.makedirs(d)
        shutil.chown(d, 'mysql', 'mysql')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        subprocess.run(['mariadb-install-db', '--user=mysql', '--datadir=' + d,
                        '--auth-root-authentication-method=normal', '--skip-test-db'],
                       capture_output=True, check=True, timeout=300)
        srv = subprocess.Popen(['mariadbd', '--no-defaults', '--user=mysql', '--datadir=' + d,
                                '--port=%d' % port, '--bind-address=127.0.0.1',
                                '--socket=' + top + '/s', '--pid-file=' + top + '/pid',
                                '--innodb-lock-wait-timeout=1', '--max-heap-table-size=16384'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            c = None
            for _ in range(150):
                try:
                    c = pymysql.connect(host='127.0.0.1', port=port, user='root', autocommit=True)
                    break
                except pymysql.Error:
                    time.sleep(0.2)
            self.assertIsNotNone(c, 'MariaDB did not start')

            def err(sql, cn=None):
                try:
                    with (cn or c).cursor() as cu:
                        cu.execute(sql)
                except pymysql.Error as e:
                    return e
                self.fail('no error: ' + sql)
            cur = c.cursor()
            cur.execute('CREATE DATABASE x')
            cur.execute('USE x')
            cur.execute('CREATE TABLE u (a INT PRIMARY KEY) ENGINE=InnoDB')
            cur.execute('INSERT INTO u VALUES (1)')
            for sql in ('SELECT nope FROM u', 'SELEC 1', 'INSERT INTO u VALUES (1)',
                        'INSERT INTO u VALUES (99999999999999)'):
                self.assertFalse(E.db_trouble(err(sql)), sql)
            cur.execute('CREATE TABLE h (a CHAR(200)) ENGINE=MEMORY')
            e = err("INSERT INTO h SELECT REPEAT('x', 200) FROM information_schema.columns a, "
                    "information_schema.columns b LIMIT 100000")
            self.assertEqual((e.args[0], E.db_trouble(e)), (1114, True))
            other = pymysql.connect(host='127.0.0.1', port=port, user='root', database='x')
            other.cursor().execute('BEGIN')
            other.cursor().execute('SELECT * FROM u FOR UPDATE')
            e = err('UPDATE u SET a = 2 WHERE a = 1')
            self.assertEqual((e.args[0], E.db_trouble(e)), (1205, True))
            other.rollback()
            cur.execute("CREATE USER 'w'@'%' IDENTIFIED BY 'pw'")
            cur.execute("GRANT ALL ON x.* TO 'w'@'%'")
            cur.execute('SET GLOBAL read_only = 1')
            w = pymysql.connect(host='127.0.0.1', port=port, user='w', password='pw', database='x',
                                autocommit=True)
            e = err('INSERT INTO u VALUES (7)', w)
            self.assertEqual((e.args[0], E.db_trouble(e)), (1290, True))
            cur.execute('SET GLOBAL read_only = 0')
            k = pymysql.connect(host='127.0.0.1', port=port, user='root', autocommit=True)
            cur.execute('KILL %d' % k.thread_id())
            time.sleep(0.3)
            self.assertTrue(E.db_trouble(err('SELECT 1', k)))
            with self.assertRaises(pymysql.Error) as cm:
                pymysql.connect(host='127.0.0.1', port=port, user='w', password='bad')
            self.assertFalse(E.db_trouble(cm.exception))
            # the numbers of 1.0.115, whatever class the driver files them under
            for code in (1290, 1836, 1114, 1037, 1038, 1041, 4031, 2014):
                for cls in (pymysql.err.OperationalError, pymysql.err.InternalError,
                            pymysql.err.InterfaceError):
                    self.assertTrue(E.db_trouble(cls(code, 'x')), (code, cls))
        finally:
            srv.terminate()
            try:
                srv.wait(30)
            except subprocess.TimeoutExpired:
                srv.kill()
            shutil.rmtree(top, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
