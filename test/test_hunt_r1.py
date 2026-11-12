#!/usr/bin/env python3
"""The bugs and holes found in the hunt of 1.0.44, round 1 - each one shut, checked here.

    python3 test/test_hunt_r1.py
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt1-')
os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402

spec = importlib.util.spec_from_file_location('acme_web_h1', os.path.join(ROOT, 'deploy', 'acme_web.py'))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class Helper(unittest.TestCase):
    def test_dbmake_never_the_servers_own(self):
        base = {'engine': 'postgres', 'name': 'acme', 'user': 'acme', 'password': 'Long-Enough-1'}
        W.dbmake_checked(base)
        for user in ('postgres', 'pg_monitor', 'replication'):
            with self.assertRaises(W.Refused):
                W.dbmake_checked(dict(base, user=user))
        for name in ('postgres', 'template1'):
            with self.assertRaises(W.Refused):
                W.dbmake_checked(dict(base, name=name))
        my = dict(base, engine='mariadb')
        for user in ('root', 'mysql'):
            with self.assertRaises(W.Refused):
                W.dbmake_checked(dict(my, user=user))
        for name in ('mysql', 'information_schema', 'performance_schema', 'sys'):
            with self.assertRaises(W.Refused):
                W.dbmake_checked(dict(my, name=name))

    def test_dbmake_pg_superuser_not_taken_over(self):
        said = []

        def fake(port, sql, db=None):
            said.append(sql)
            if 'rolsuper' in sql:
                return '1'
            if 'FROM pg_roles' in sql:
                return '1'
            return ''
        with mock.patch.object(W, 'pg_sql', side_effect=fake):
            with self.assertRaises(W.Refused):
                W.dbmake_pg({'name': 'acme', 'user': 'boss', 'password': 'Long-Enough-1', 'port': 5432})
        self.assertFalse([x for x in said if 'PASSWORD' in x])

    def test_authselect_features_from_root_only_and_two_only(self):
        os.makedirs(os.path.dirname(W.PWP_ORIG), exist_ok=True)
        with open(W.PWP_ORIG, 'w') as f:
            json.dump({'features': ['without-nullok', 'with-pwhistory', 'with-pamaccess']}, f)
        os.chmod(W.PWP_ORIG, 0o600)
        self.assertEqual(W.pwp_orig_read()['features'], ['with-pwhistory'])
        self.assertTrue(W.PWP_ORIG.startswith(W.NET_SNAP_DIR))

    def test_pg_paths_only_its_own(self):
        d = tempfile.mkdtemp(prefix='acme-pgpath-')
        f = os.path.join(d, 'pg_hba.conf')
        with open(f, 'w') as fh:
            fh.write('x\n')
        try:                    # postgres's own file (1.0.88: root's is refused)
            import pwd
            os.chown(f, pwd.getpwnam('postgres').pw_uid, -1)
        except (KeyError, OSError):
            pass
        self.assertEqual(W.pg_path_checked(f), f)
        link = os.path.join(d, 'link.conf')
        os.symlink('/etc/passwd', link)
        try:
            import pwd
            os.lchown(link, pwd.getpwnam('postgres').pw_uid, -1)   # postgres's link to root's
        except (KeyError, OSError):
            os.lchown(link, 65534, -1) if os.geteuid() == 0 else None
        with self.assertRaises(W.Refused):
            W.pg_path_checked(link)
        with self.assertRaises(W.Refused):
            W.pg_path_checked('relative/path')
        os.chmod(d, 0o777)
        with self.assertRaises(W.Refused):
            W.pg_path_checked(f)

    def test_ciphers_not_an_option(self):
        self.assertTrue(W.re.match(r'^(?!-)[A-Za-z0-9_+!@=:.-]{1,2000}\Z', 'ECDHE+AESGCM:!aNULL'))
        self.assertIsNone(W.re.match(r'^(?!-)[A-Za-z0-9_+!@=:.-]{1,2000}\Z', '-provider=x'))

    def test_authorized_keys_looked_at_capped(self):
        calls = []
        with mock.patch.object(W, 'key_facts', side_effect=lambda t: calls.append(t) or None):
            W.auth_keys(['ssh-ed25519 AAAA%d x' % i for i in range(W.AUTH_KEYS_MOST + 50)])
        self.assertEqual(len(calls), W.AUTH_KEYS_MOST)

    def test_code_users_without_sudo_left_out_of_aging(self):
        spare = {'all': False, 'names': ['jan']}
        self.assertTrue(W.lu_coded('jan', spare, False))
        self.assertFalse(W.lu_coded('jan', spare, True))
        self.assertFalse(W.lu_coded('eva', spare, False))
        self.assertTrue(W.lu_coded('eva', {'all': True}, False))
        self.assertFalse(W.lu_coded('eva', None, False))

    def test_pam_radius_secret_where_root_alone_writes(self):
        self.assertIn('/security/', W.pam_radius_conf_path())
        self.assertNotIn('/acme/', W.pam_radius_conf_path())

    def test_selinux_applied_time_root_only(self):
        self.assertTrue(W.SE_APPLIED_ROOT.startswith(W.NET_SNAP_DIR))


class Daemon(unittest.TestCase):
    def test_long_names_fit_the_key(self):
        k = E.node_key('adpw', 'x' * 400 + '|example.cz')
        self.assertLessEqual(len(k), 190)
        self.assertEqual(k, E.node_key('adpw', 'x' * 400 + '|example.cz'))
        self.assertNotEqual(k, E.node_key('adpw', 'x' * 400 + '|example.org'))
        self.assertEqual(E.node_key('adpw', 'jan'), 'adpw:jan@@' + E.node_name())

    def test_code_users_said_to_the_helper(self):
        conf = {'manage': True, 'radius': True, 'radius_users': ['jan', 'root']}
        with mock.patch.object(E, 'sshd_conf', return_value=conf):
            self.assertEqual(E.osu_coded(object()), {'all': False, 'names': ['jan']})
            pol = dict(E.PWP_DEFAULT, managed=True, existing=True)
            self.assertNotEqual(E.pwp_want(object(), pol), E.pwp_hash(pol))

    def test_a_code_that_went_is_no_refusal_for_the_guard(self):
        class H(object):
            pass
        h = H()
        h._guard = ('192.0.2.1', 'jan')
        h._held = []
        h.d = None
        with mock.patch.object(E, 'guard_on', return_value=True), \
                mock.patch.object(E, 'guard_count') as gc:
            E.ApiHandler.failed(h, 'k', guard=False)
            gc.assert_not_called()
            E.ApiHandler.failed(h, 'k')
            gc.assert_called_once()

    def test_beat_asked_a_row_each(self):
        store = E.Storage(E.open_db())
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            E.settings_in_effect(store, ask=True)
        self.assertTrue(store.get_meta('beat_asked:' + E.node_name()))
        self.assertIsNone(store.get_meta('beat_asked'))

    def test_machine_change_keeps_dbtls(self):
        self.assertNotIn('dbtls:server:', E.MACHINE_ROWS)

    def test_new_machine_no_keep_from_before(self):
        store = E.Storage(E.open_db())
        me = E.node_name()
        store.set_meta('node:' + me, json.dumps({'at': time.time() - 7200, 'mid': 'other'}))
        store.set_meta('host:sshd:now:' + me, json.dumps({'hash': 'h1'}))
        E.machine_changed_check(store)
        now = json.loads(store.get_meta('host:sshd:now:' + me))
        self.assertNotIn('hash', now)
        self.assertGreater(now['kept_at'], time.time() - 60)


if __name__ == '__main__':
    unittest.main()
