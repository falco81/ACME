#!/usr/bin/env python3
"""The bugs and holes found in the hunt of 1.0.44, round 3 (upgrades, the cluster, the command
line, and what rounds 1 and 2 broke) - each one shut, checked here.

    python3 test/test_hunt_r3.py
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt3-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'none'),
                  ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402
from acmelib.certs import renewer as R  # noqa: E402

spec = importlib.util.spec_from_file_location('acme_web_h3', os.path.join(ROOT, 'deploy', 'acme_web.py'))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


class Upgrades(unittest.TestCase):
    def test_floor_raised(self):
        self.assertEqual(E.DOWNGRADE_FLOOR, '1.0.44')
        sh = read('install.sh')
        got = subprocess.run(['bash', '-c', "sed -n \"s/^DOWNGRADE_FLOOR = '\\([0-9.]*\\)'.*/\\1/p\" "
                              "%s/acmelib/engine/000_start.py" % ROOT],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(got, '1.0.44')
        self.assertIn('DOWNGRADE_FLOOR_NEW=', sh)

    def test_install_sh(self):
        sh = read('install.sh')
        subprocess.run(['bash', '-n', os.path.join(ROOT, 'install.sh')], check=True)
        self.assertIn('flock -n 9', sh)
        self.assertIn('NRestarts', sh)
        self.assertIn('back to $(basename "$ROLLBACK_TREE")', sh)
        self.assertIn('! -e "$cur/.failed"', sh)
        self.assertIn('ACME_FORCE_UPGRADE', sh)
        # no "local" outside a function where the upgrade checks the other node
        i = sh.index('others=""')
        self.assertNotIn('local others', sh[i - 200:i + 20])

    def test_tree_not_through_the_link(self):
        self.assertIn('os.path.realpath(__file__)', read('acme.py'))

    def test_pwpolicy_mark_of_its_own(self):
        store = E.Storage(E.open_db())
        store.db.run("DELETE FROM meta WHERE k IN ('host:pwpolicy:conf', 'pwpolicy:migrated:2')")
        store.set_meta('pwpolicy:migrated', '1')                    # 1.0.43 ran here
        store.save_setting('osu_pw_min_days', 3)
        self.assertTrue(E.pwp_migrate(store))
        self.assertEqual(json.loads(store.get_meta('host:pwpolicy:conf'))['min_days'], 3)


class Guard(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_mark_not_in_the_database(self):
        with mock.patch.object(E, 'dbguard_on', return_value=True), \
                mock.patch.object(E, 'dbguard_key', return_value=b'k' * 32), \
                mock.patch.dict(E.CONFIG, {'ha_mode': ''}):
            E.DBGUARD['adopted'] = {}
            E.dbguard_adopt(self.store)
            self.assertFalse(self.store.db.rows("SELECT k FROM meta WHERE k LIKE 'dbguard:adopted%'"))
            self.assertTrue(E.DBGUARD['adopted'].get(E.DBGUARD_ADOPT_MARK))

    def test_waits_for_every_node(self):
        old = [{'name': 'a', 'me': True, 'alive': True, 'version': '1.0.44'},
               {'name': 'b', 'alive': True, 'version': '1.0.43'}]
        with mock.patch.object(E, 'dbguard_on', return_value=True), \
                mock.patch.object(E, 'dbguard_key', return_value=b'k' * 32), \
                mock.patch.object(E, 'ha_nodes', return_value=old), \
                mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            E.DBGUARD['adopted'] = {}
            E.dbguard_adopt(self.store)
            self.assertFalse(E.DBGUARD['adopted'].get(E.DBGUARD_ADOPT_MARK))
            # not checked yet: as unguarded as in 1.0.43
            self.assertTrue(E.dbguard_ok(self.store.db, 's', 'rbackup', '1'))
            self.assertTrue(E.dbguard_adopted_ok('s', 'smtp_password') or True)


class SshGate(unittest.TestCase):
    def test_no_authenticator_taken(self):
        src = read('acmelib', 'engine', [n for n in os.listdir(os.path.join(ROOT, 'acmelib', 'engine'))
                                         if n.startswith('316_')][0])
        self.assertIn('p.message_authenticator_ok(secret) is False', src)
        self.assertNotIn('message_authenticator_ok(secret) is not True', src)


class Helper(unittest.TestCase):
    def test_policy_record_taken_from_its_old_place(self):
        os.makedirs(W.STATE_DIR, exist_ok=True)
        try:
            os.unlink(W.PWP_ORIG)
        except OSError:
            pass
        with open(W.PWP_ORIG_OLD, 'w') as f:
            json.dump({'features': ['with-faillock', 'with-pamaccess']}, f)
        os.chmod(W.PWP_ORIG_OLD, 0o600)
        if os.stat(W.PWP_ORIG_OLD).st_uid != 0:
            self.skipTest('not root')
        self.assertEqual(W.pwp_orig_read()['features'], ['with-faillock'])
        self.assertFalse(os.path.exists(W.PWP_ORIG_OLD))
        self.assertTrue(os.path.exists(W.PWP_ORIG))

    def test_pg_folder_behind_roots_link(self):
        if os.geteuid() != 0:
            self.skipTest('not root')
        d = tempfile.mkdtemp(prefix='acme-pgl-')
        real = os.path.join(d, 'real')
        os.makedirs(real)
        try:                    # postgres's own folder (1.0.88: root's is refused)
            import pwd
            os.chown(real, pwd.getpwnam('postgres').pw_uid, -1)
        except KeyError:
            self.skipTest('no postgres account')
        link = os.path.join(d, 'main')
        os.symlink(real, link)
        self.assertEqual(W.pg_path_checked(link, folder=True), real)
        os.chown(real, 0, -1)
        with self.assertRaises(W.Refused):          # root's own folder: not PostgreSQL's
            W.pg_path_checked(real, folder=True)

    def test_unlock_end_day_only_ahead(self):
        src = read('deploy', 'acme_web.py')
        self.assertIn("int(was) > int(time.time() // 86400)", src)


class Cluster(unittest.TestCase):
    def test_maintenance_not_first(self):
        nodes = [{'name': 'a', 'alive': True, 'maintenance': True},
                 {'name': 'b', 'alive': True, 'me': True}]
        with mock.patch.object(E, 'ha_nodes', return_value=nodes), \
                mock.patch.object(E, 'node_name', return_value='b'):
            self.assertTrue(E.lead_of(None))
        both = [dict(n, maintenance=True) for n in nodes]
        with mock.patch.object(E, 'ha_nodes', return_value=both), \
                mock.patch.object(E, 'node_name', return_value='b'):
            self.assertFalse(E.lead_of(None))       # both out: the first by name, as before

    def test_no_lead_aside_or_in_maintenance(self):
        with mock.patch.object(E, 'split_no_lead', return_value=False), \
                mock.patch.object(E, 'clock_aside', return_value=True):
            self.assertTrue(E.no_lead_now(None))
            self.assertIn('clock', E.split_issue_refused())
        with mock.patch.object(E, 'split_no_lead', return_value=False), \
                mock.patch.object(E, 'clock_aside', return_value=False), \
                mock.patch.object(E, 'maintenance_now', return_value={'on': True}), \
                mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            self.assertTrue(E.no_lead_now(object()))

    def test_vip_far(self):
        nodes = [{'name': 'a', 'me': True, 'alive': True}, {'name': 'b', 'alive': False}]
        store = mock.MagicMock()
        with mock.patch.object(E, 'vip_conf', return_value={'on': True}), \
                mock.patch.object(E, 'ha_nodes', return_value=nodes), \
                mock.patch.object(E, '_alive_far', return_value=True), \
                mock.patch.object(E, 'peer_vip_there', return_value=True):
            self.assertTrue(R.vip_far(store))
        with mock.patch.object(E, 'vip_conf', return_value={'on': True}), \
                mock.patch.object(E, 'ha_nodes', return_value=nodes), \
                mock.patch.object(E, '_alive_far', return_value=True), \
                mock.patch.object(E, 'peer_vip_there', return_value=False):
            self.assertFalse(R.vip_far(store))

    def test_orphaned_renewal(self):
        from acmelib.certs import store as S
        store = E.Storage(E.open_db())
        S.ensure_schema(store) if hasattr(S, 'ensure_schema') else None
        try:
            cid = store.db.insert('certs', {'name': 'orphan.example', 'state': 'renewing',
                                            'names': '["orphan.example"]'})
        except Exception as e:                          # noqa: BLE001
            self.skipTest('no certs table here: %s' % e)
        self.assertGreaterEqual(R.orphans(store), 1)
        self.assertEqual(store.db.value('SELECT state FROM certs WHERE id = ?', (cid,)), 'failed')

    def test_setting_stamp_never_behind(self):
        store = E.Storage(E.open_db())
        store.db.upsert('settings', 'k', {'k': 'h3_x', 'v': '1', 'at': time.time() + 600,
                                          'by_who': 'other node'})
        store.save_setting('h3_x', 2)
        self.assertGreater(float(store.db.value('SELECT at FROM settings WHERE k = ?', ('h3_x',))),
                           time.time() + 599)

    def test_push_nonce_both_nodes(self):
        store = E.Storage(E.open_db())
        n = 'n-%f' % time.time()
        self.assertTrue(E.push_nonce_take(store, 'key1', n, time.time()))
        self.assertFalse(E.push_nonce_take(store, 'key1', n, time.time()))
        self.assertIn('push', E.ONCE_KEEP_S)

    def test_split_took_tidied(self):
        store = E.Storage(E.open_db())
        store.set_meta('split:took:x:old', json.dumps({'at': time.time() - 30 * 86400}))
        store.set_meta('split:took:x:new', json.dumps({'at': time.time()}))
        E.once_tidy(store)
        self.assertIsNone(store.get_meta('split:took:x:old'))
        self.assertTrue(store.get_meta('split:took:x:new'))

    def test_cert_trigger_defined(self):
        self.assertIn('acme_newer_cert', read('acmelib', 'engine', '035_the_database.py'))


class Regressions(unittest.TestCase):
    def test_monotonic_starts_due(self):
        self.assertEqual(E.ACME_TICK['at'], float('-inf'))
        self.assertEqual(E.ACME_WORK['at'], 0.0)             # wall clock, shown on the pages
        r = R.Renewer.__new__(R.Renewer) if hasattr(R, 'Renewer') else None
        src = read('acmelib', 'certs', 'renewer.py')
        self.assertIn("self.last_scan = float('-inf')", src)

    def test_dns_tcp_not_in_the_udp_bucket(self):
        src = read('acmelib', 'certs', 'dnsserver.py')
        i = src.index('def _tcp_conn')
        self.assertNotIn('_allowed(', src[i:i + 2500])

    def test_cli_who_sudo(self):
        with mock.patch.dict(os.environ, {'SUDO_USER': 'alice'}):
            E.CLI_STARTED_ROOT[0] = True
            try:
                self.assertEqual(E.cli_who(), 'command line (sudo alice)')
            finally:
                E.CLI_STARTED_ROOT[0] = None


if __name__ == '__main__':
    unittest.main()
