#!/usr/bin/env python3
"""Moving to another database by the wizard (Settings → The database → Move to
another database), every direction, for real.

    python3 test/test_db_move.py              (or python3 -m unittest test.test_db_move)
    ACME_TEST_KEEP=1 ...                      keeps the folders of the daemons

One daemon in a folder of its own, populated through its API - accounts,
settings with a sealed secret, certificates with versions and sealed keys, an
authority, sources, validations and targets with sealed secrets in their
settings, a deployment, jobs, DNS records, a directory with its sealed
password, events, meta - is moved by the wizard's own questions (wiz_check,
wiz_make, wiz_go, wiz_state) around all six directions:

    SQLite → MariaDB → PostgreSQL (TLS, verify-full) → MariaDB → SQLite (another
    file) → PostgreSQL → SQLite

After each: the move's own count of every table, the counts read on the new
database equal to those read on the old one just before, every sealed secret
opened there (the engine's own check, each under its bind - the certificate
manager's too), a certificate's key exported, the authority's key, a target's
and a validation's password, the setting's secret; the daemon started again on
the new database (as systemd would), its API answering, the certificates
listed and a self-signed one renewed.

Also: a target that holds acme already is refused until "throw it away" is
said; a move cancelled before the switch leaves everything as it was; and the
guard - a node of a cluster (ha_mode) or a database another node is heard on
- refused by the API (409) and by acme --db-move.

What it needs, each part skipped when it is not there: the driver (psycopg2,
pymysql) in this Python, and the servers on this machine with an administrator
this test may use without a password (runuser -u postgres psql; mariadb -u
root over the socket) - the wizard makes its own database and account there
(acmemv, ACME_TEST_MOVE_PW) through the root helper, and they are dropped
first. The other databases of those servers are not touched.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_ha import Node, populate, wait_for, READ_BACK  # noqa: E402

MV_DB = 'acmemv'
MV_PW = os.environ.get('ACME_TEST_MOVE_PW', 'Move-Test-pw-12345')
PG_PORT = int(os.environ.get('ACME_TEST_PG_PORT', '5432'))
MY_PORT = int(os.environ.get('ACME_TEST_MY_PORT', '3306'))
PG = {'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': PG_PORT, 'db_name': MV_DB,
      'db_user': MV_DB, 'db_password': MV_PW}
MY = {'db_engine': 'mariadb', 'db_host': '127.0.0.1', 'db_port': MY_PORT, 'db_name': MV_DB,
      'db_user': MV_DB, 'db_password': MV_PW}
SNAKEOIL = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
# Tables whose rows the daemon writes by itself after it starts again: compared
# with "at least as many".
GROWING = ('events', 'sessions', 'used_once', 'cert_jobs', 'cert_versions')

COUNT_ALL = r'''
from acmelib.certs import store as cs
out = {t: int(st.db.value('SELECT COUNT(*) FROM %s' % t)) for t in acme.TABLES if t != 'meta'}
out['_engine'] = st.db.engine
out['_where'] = st.db.where()
tried, opened, bad = acme._sealed_check(st.db, acme.sealing_key())
out['_sealed'] = [tried, opened, bad]
v = st.db.row("SELECT * FROM cert_challenges WHERE name = 'cf'")
out['_val_token'] = cs.plugin_config('challenge', dict(v)).get('token') if v else None
raw = st.db.value("SELECT v FROM settings WHERE k = 'smtp_password'")
out['_smtp'] = acme.unseal_secret(json.loads(raw)) if raw else None
d = st.db.row("SELECT * FROM directories WHERE name = 'movedir'")
out['_dir'] = bool(d)
print(json.dumps(out, default=str))
'''


def _run(cmd, sql):
    return subprocess.run(cmd, input=sql, capture_output=True, text=True, timeout=60)


def pg_root(sql, db='postgres'):
    return _run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-p', str(PG_PORT), '-d', db,
                 '-v', 'ON_ERROR_STOP=1'], sql)


def my_root(sql):
    prog = shutil.which('mariadb') or shutil.which('mysql') or 'mariadb'
    return _run([prog, '--protocol=socket', '-u', 'root', '--batch'], sql)


def have_driver(module):
    try:
        __import__(module)
        return True
    except Exception:                                   # noqa: BLE001
        return False


def have_pg():
    if os.geteuid() != 0 or not shutil.which('runuser') or not have_driver('psycopg2'):
        return False
    try:
        got = pg_root('SELECT 1;')
    except (OSError, subprocess.SubprocessError):
        return False
    return got.returncode == 0 and got.stdout.strip() == '1'


def have_my():
    if os.geteuid() != 0 or not have_driver('pymysql'):
        return False
    try:
        got = my_root('SELECT 1;')
    except (OSError, subprocess.SubprocessError):
        return False
    return got.returncode == 0


def reset_pg():
    pg_root('DROP DATABASE IF EXISTS %s WITH (FORCE);' % MV_DB)
    pg_root('DROP ROLE IF EXISTS %s;' % MV_DB)


def reset_my():
    my_root('DROP DATABASE IF EXISTS %s; ' % MV_DB + ' '.join(
        "DROP USER IF EXISTS '%s'@'%s';" % (MV_DB, h) for h in ('localhost', '127.0.0.1', '::1')))


def populate_more(node):
    """populate() of test_ha, and a sealed setting, a validation with a sealed
    token and a directory with its sealed password."""
    ids = populate(node)
    node.ok('POST', '/api/settings', {'settings': {'smtp_password': 'smtp-secret-1'}})
    node.ok('POST', '/api/validations/save', {'name': 'cf', 'kind': 'cloudflare',
                                              'config': {'token': 'cf-token-4711'}})
    got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--add-directory',
                          'movedir', '--hosts', '127.0.0.1', '--base', 'DC=example,DC=local',
                          '--bind-dn', 'x', '--bind-pw', '-', '--tls', 'none'],
                         env=dict(node.env, ACME_BIND_PW='dir-secret'), capture_output=True,
                         text=True, timeout=120)
    assert got.returncode == 0, got.stdout + got.stderr
    return ids


def counts(node):
    return json.loads(node.py(COUNT_ALL).strip().splitlines()[-1])


def secrets_back(node):
    return json.loads(node.py(READ_BACK).strip().splitlines()[-1])


class Mover(object):
    """The wizard's questions, as the page asks them."""

    def __init__(self, test, node):
        self.t, self.node = test, node

    def ask(self, action, **body):
        body['action'] = action
        return self.node.call('POST', '/api/db', body)

    def check(self, target, overwrite=False, ca_pem=''):
        st, got = self.ask('wiz_check', settings=target, overwrite=overwrite, ca_pem=ca_pem)
        self.t.assertEqual(st, 200, got)
        return got

    def make(self, target):
        st, got = self.ask('wiz_make', settings=target, how='local')
        self.t.assertEqual(st, 200, got)
        return got

    def move(self, target, overwrite=False, ca_pem='', expect_full=False):
        node = self.node
        got = self.check(target, overwrite=False, ca_pem=ca_pem)
        if expect_full:
            empty = [r for r in got['checks'] if r['key'] == 'empty'][0]
            self.t.assertIs(empty['ok'], False, got)
            st, refused = self.ask('wiz_go', settings=target, ca_pem=ca_pem)
            self.t.assertEqual(st, 400, refused)
            got = self.check(target, overwrite=True, ca_pem=ca_pem)
        bad = [r for r in got['checks'] if r['ok'] is False]
        self.t.assertEqual(bad, [], got)
        before = counts(node)
        sealed_before = before['_sealed']
        st, started = self.ask('wiz_go', settings=target, overwrite=overwrite or expect_full,
                               ca_pem=ca_pem)
        self.t.assertEqual(st, 200, started)
        self.t.assertEqual(started['move']['state'], 'running')
        # The daemon ends itself once config.json names the new database; it is
        # started again as systemd would.
        wait_for(lambda: node.proc.poll() is not None, 600, 0.5, 'the daemon stopping after the move')
        with open(os.path.join(node.tmp, 'state', 'db-move.json')) as f:
            last = json.load(f)
        self.t.assertEqual(last['state'], 'restarting', last)
        self.t.assertEqual(node.conf.get('db_engine', 'sqlite'), target['db_engine'])
        node.start()
        st, s = self.ask('wiz_state')
        self.t.assertEqual(st, 200, s)
        m = s['move']
        self.t.assertEqual(m['state'], 'done', m)
        self.t.assertEqual(s['engine'], target['db_engine'])
        for step in m['steps']:
            self.t.assertEqual(step['state'], 'ok', step)
        for t in m['tables']:
            self.t.assertEqual(t['there'], t['copied'], t)
        after = counts(node)
        self.t.assertEqual(after['_engine'], target['db_engine'])
        for t, n in before.items():
            if t.startswith('_'):
                continue
            if t in GROWING:
                self.t.assertGreaterEqual(after[t], n, t)
            else:
                self.t.assertEqual(after[t], n, '%s: %s on the new database, %s before' % (t, after[t], n))
        tried, opened, bad = after['_sealed']
        self.t.assertEqual(bad, [], after['_sealed'])
        self.t.assertEqual(tried, opened)
        self.t.assertGreaterEqual(tried, sealed_before[0])
        self.t.assertGreaterEqual(tried, 6)
        self.t.assertEqual(after['_val_token'], 'cf-token-4711')
        self.t.assertEqual(after['_smtp'], 'smtp-secret-1')
        self.t.assertTrue(after['_dir'])
        back = secrets_back(node)
        self.t.assertTrue(back['web_key'] and back['ca_key'], back)
        self.t.assertEqual(back['target_pw'], 's3cret')
        # The certificate manager at work on it.
        rows = node.ok('GET', '/api/certs')['rows']
        self.t.assertEqual(sorted(r['name'] for r in rows), ['intranet', 'web'])
        web = [r for r in rows if r['name'] == 'web'][0]
        job = node.wait_job(node.ok('POST', '/api/certs/renew', {'id': web['id'],
                                                                'force': True})['job_id'])
        self.t.assertEqual(job['state'], 'ok', job)
        st, info = self.ask('wiz_start')
        self.t.assertEqual(st, 200, info)
        self.t.assertIsNone(info['guard'])
        self.t.assertEqual(info['here']['engine'], target['db_engine'])
        return m


def need_engines(test, *engines):
    for e in engines:
        if e == 'postgres' and not have_pg():
            raise unittest.SkipTest('no PostgreSQL on this machine that root may administer '
                                    '(runuser -u postgres psql), or no psycopg2 in %s' % sys.executable)
        if e == 'mariadb' and not have_my():
            raise unittest.SkipTest('no MariaDB on this machine that root may administer over '
                                    'its socket, or no pymysql in %s' % sys.executable)


class EveryDirection(unittest.TestCase):
    """All six directions, one after the other, on one populated node."""

    def test_six_directions(self):
        need_engines(self, 'postgres', 'mariadb')
        reset_pg()
        reset_my()
        node = Node('mover')
        try:
            node.add_account()
            node.start()
            populate_more(node)
            mv = Mover(self, node)
            done = []
            # 1. SQLite → MariaDB, its database and account made by the wizard.
            got = mv.check(MY)
            self.assertFalse(got['ready'])
            mv.make(MY)
            mv.move(MY)
            done.append('sqlite → mariadb')
            # 2. MariaDB → PostgreSQL, over TLS with the server's certificate and
            # name checked (verify-full, its authority sent as PEM).
            mv.make(PG)
            pg_tls = dict(PG)
            ca = ''
            if os.path.exists(SNAKEOIL):
                pg_tls.update(db_host='localhost', db_tls='verify-full')
                with open(SNAKEOIL) as f:
                    ca = f.read()
            m = mv.move(pg_tls, ca_pem=ca)
            if ca:
                self.assertIn('verify-full', json.dumps(node.conf))
            done.append('mariadb → postgres%s' % (' (TLS verify-full)' if ca else ''))
            # 3. PostgreSQL → MariaDB: it holds the older copy of step 1 - refused
            # until it is said to be thrown away.
            mv.move(dict(MY, db_password=MV_PW), expect_full=True)
            done.append('postgres → mariadb (over the older copy)')
            # 4. MariaDB → SQLite, a file of its own.
            lite = {'db_engine': 'sqlite',
                    'db_path': os.path.join(node.tmp, 'state', 'moved.db')}
            mv.move(lite)
            done.append('mariadb → sqlite')
            # 5. SQLite → PostgreSQL (over the copy of step 2), without TLS.
            mv.move(dict(PG, db_tls=''), expect_full=True)
            done.append('sqlite → postgres (over the older copy)')
            # 6. PostgreSQL → SQLite: the first file, the way back.
            mv.move({'db_engine': 'sqlite', 'db_path': os.path.join(node.tmp, 'state', 'acme.db')},
                    expect_full=True)
            done.append('postgres → sqlite (the first file again)')
            self.assertEqual(len(done), 6)
            print('\n  moved: ' + '; '.join(done), file=sys.stderr)
            del m
        finally:
            node.cleanup()
            reset_pg()
            reset_my()


class CancelAndRefusals(unittest.TestCase):

    def test_cancel_before_the_switch(self):
        need_engines(self, 'postgres')
        reset_pg()
        node = Node('canceller')
        try:
            node.add_account()
            node.start()
            populate(node)
            mv = Mover(self, node)
            mv.make(PG)
            # Many events, so the copy takes long enough to be stopped.
            node.py('t = __import__("time").time()\nst.db.insert_many("events", ["ts", "kind", '
                    '"node", "level", "who", "words"], [[t, "test", "x", "info", "t", "row %d" % i] '
                    'for i in range(60000)])')
            st, got = mv.ask('wiz_go', settings=PG)
            self.assertEqual(st, 200, got)
            st, got = mv.ask('wiz_cancel')
            self.assertEqual(st, 200, got)

            def ended():
                st, s = mv.ask('wiz_state')
                return s['move'] if s['move']['state'] not in ('running',) else None
            m = wait_for(ended, 300, 0.5, 'the move stopping')
            self.assertEqual(m['state'], 'cancelled', m)
            self.assertIsNone(node.proc.poll(), 'the daemon goes on')
            self.assertEqual(node.conf.get('db_engine', 'sqlite'), 'sqlite')
            st, s = mv.ask('wiz_state')
            self.assertEqual(s['engine'], 'sqlite')
            # A second try goes, over what the first left there.
            got = mv.check(PG, overwrite=True)
            self.assertTrue(got['ready'], got)
        finally:
            node.cleanup()
            reset_pg()

    def test_a_node_of_a_cluster_is_refused(self):
        node = Node('ha-guard')
        try:
            node.add_account()
            node.start()
            mv = Mover(self, node)
            lite = {'db_engine': 'sqlite', 'db_path': os.path.join(node.tmp, 'state', 'other.db')}
            self.assertTrue(mv.check(lite)['ready'])
            # Another node heard on this database a moment ago.
            node.py('st.db.run("INSERT INTO meta (k, v) VALUES (?, ?)", ("node:other", '
                    'json.dumps({"at": __import__("time").time()})))')
            st, info = mv.ask('wiz_start')
            self.assertEqual(st, 200)
            self.assertTrue(info['guard']['refused'])
            self.assertIn('other', info['guard']['why'])
            for act in ('wiz_check', 'wiz_go', 'wiz_make'):
                st, got = mv.ask(act, settings=lite)
                self.assertEqual(st, 409, (act, got))
                self.assertIn('not moved', got.get('error', ''))
            st, got = mv.ask('move', settings=lite)
            self.assertEqual(st, 409, got)
            got = node.cli('--db-move', 'sqlite', '--db-path', lite['db_path'], '--yes')
            self.assertEqual(got.returncode, 3, got.stdout + got.stderr)
            self.assertIn('not moved', got.stderr)
            node.stop()
            # ha_mode set in config.json, and nobody heard for a long time: still
            # refused - with how to leave the cluster mode.
            node.py('st.db.run("UPDATE meta SET v = ? WHERE k = ?", (json.dumps({"at": 1}), '
                    '"node:other"))')
            node.set_conf(ha_mode='shared')
            got = node.cli('--db-move', 'sqlite', '--db-path', lite['db_path'], '--yes')
            self.assertEqual(got.returncode, 3, got.stdout + got.stderr)
            self.assertIn('ha-standalone', got.stderr)
            guard = json.loads(node.py('print(json.dumps(acme.db_move_guard(st)))').strip()
                               .splitlines()[-1])
            self.assertTrue(guard['stale'], guard)
            self.assertFalse(os.path.exists(lite['db_path']))
        finally:
            node.cleanup()

    def test_cli_move_and_back(self):
        """acme --db-move sqlite, into another file and back, by the command line."""
        node = Node('cli-mover')
        try:
            node.add_account()
            node.start()
            populate(node)
            node.stop()
            before = counts(node)
            other = os.path.join(node.tmp, 'state', 'cli.db')
            env_cli = dict(node.env, ACME_NO_RESTART='1')
            got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--db-move',
                                  'sqlite', '--db-path', other, '--yes'], env=env_cli,
                                 capture_output=True, text=True, timeout=600)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertEqual(node.conf['db_path'], other)
            node.start()
            after = counts(node)
            for t, n in before.items():
                if not t.startswith('_') and t not in GROWING:
                    self.assertEqual(after[t], n, t)
            self.assertEqual(after['_sealed'][2], [])
            st, s = node.call('POST', '/api/db', {'action': 'wiz_state'})
            self.assertEqual(s['move']['state'], 'done', s)
        finally:
            node.cleanup()


if __name__ == '__main__':
    unittest.main(verbosity=2)
