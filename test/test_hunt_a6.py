#!/usr/bin/env python3
"""The hunt of 1.0.46 (round 6): what the rounds of 1.0.45 changed, looked at again.

    python3 test/test_hunt_a6.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunta6-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402
from acmelib.certs import teams as T  # noqa: E402


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


class Guard(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())
        E._dbguard_load()

    def test_a_setting_taken_away_stays_refused(self):
        E.DBGUARD['refused']['sig:s:x:*'] = {'kind': 's', 'what': 'admin_2fa', 'why': 'gone',
                                             'at': time.time(), 'first': time.time()}
        self.store.db.run("DELETE FROM settings WHERE k = 'admin_2fa'")
        E.dbguard_refused_prune(self.store)
        self.assertIn('sig:s:x:*', E.DBGUARD['refused'])
        E.DBGUARD['refused'].pop('sig:s:x:*', None)

    def test_a_meta_row_gone_leaves(self):
        E.DBGUARD['refused']['sig:m:y:*'] = {'kind': 'm', 'what': 'rbackup:now:a@@b', 'why': 'x',
                                             'at': time.time(), 'first': time.time()}
        self.assertEqual(E.dbguard_refused_prune(self.store), 1)
        self.assertNotIn('sig:m:y:*', E.DBGUARD['refused'])


class Backups(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())
        self.store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:%'")

    def test_tried_again_only_where_it_failed(self):
        self.store.set_meta('rbackup:targets', json.dumps([
            {'id': 'aa', 'name': 'nas', 'kind': 'folder', 'enabled': True},
            {'id': 'bb', 'name': 's3', 'kind': 'folder', 'enabled': True}]))
        E.rb_history_add(self.store, {
            'at': time.time(), 'node': E.node_name(), 'by': 'acme (scheduled)', 'ok': False,
            'targets': [{'id': 'aa', 'ok': False}, {'id': 'bb', 'ok': True}]})

        class D:
            store = self.store
            _rb_day = __import__('datetime').datetime.now().strftime('%Y-%m-%d')
        with mock.patch.dict(E.CONFIG, {'rbackup': 1, 'ha_mode': ''}), \
                mock.patch.object(E, 'rb_verify_due', return_value=False), \
                mock.patch.object(E, 'rb_job_start') as start:
            E.rb_tick(D())
        start.assert_called_once()
        self.assertEqual(start.call_args.kwargs.get('only'), ['aa'])

    def test_a_long_node_name_tidies_its_asks(self):
        long = 'n' * 70
        with mock.patch.object(E, 'node_name', return_value=long):
            k = E.node_key('rbackup:now', 'peer')
            self.store.set_meta(k, json.dumps({'id': 'a', 'at': time.time() - 7200}))
            E.rb_now_tidy(self.store)
        self.assertIsNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (k,)))

    def test_forgotten_by_the_lines_own_time(self):
        self.store.set_meta('rbackup:runs@@peer', json.dumps([{'at': 100.0004, 'node': 'peer', 'file': 'c'}]))
        self.assertEqual(E.rb_history_forget(self.store, 100.0011, 'c'), 1)
        self.assertEqual(E.rb_history(self.store), [])
        self.store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:%'")


class Jobs(unittest.TestCase):
    def test_jobs_of_no_certificate_for_their_own(self):
        store = E.Storage(E.open_db())
        s = {'name': 'eva', 'role': 'certadmin'}
        with mock.patch.object(T, 'unscoped', return_value=False), \
                mock.patch.object(T, '_cert_of_job', return_value=None), \
                mock.patch.object(store.db, 'value', return_value='Eva'):
            T.need_job(store, s, 5, 'manage', 'stop a job of')       # her own: no error
        with mock.patch.object(T, 'unscoped', return_value=False), \
                mock.patch.object(T, '_cert_of_job', return_value=None), \
                mock.patch.object(store.db, 'value', return_value='adam'), \
                mock.patch.object(T, 'deny', side_effect=PermissionError) as deny:
            with self.assertRaises(PermissionError):
                T.need_job(store, s, 5, 'manage', 'stop a job of')
            deny.assert_called_once()

    def test_every_job_route_guarded(self):
        src = read('acmelib', 'certs', 'teams.py')
        for route in ("'/api/certs/job'", "'/api/certs/dry_run_result'", "'/api/certs/job_stop'"):
            i = src.index(route)
            self.assertIn('need_job(', src[i:i + 200], route)


class Shapes(unittest.TestCase):
    """Rows of another shape (an older version's) never break a look for good (1.0.46)."""

    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_meta_obj(self):
        for v in ('"text"', '[1]', 'null', '5'):
            self.store.set_meta('x:shape', v)
            self.assertEqual(E._meta_obj(self.store, 'x:shape'), {})
        self.store.set_meta('x:shape', '{"a": 1}')
        self.assertEqual(E._meta_obj(self.store, 'x:shape'), {'a': 1})

    def test_no_meta_json_or_dict_left(self):
        import glob
        import re
        for p in glob.glob(os.path.join(ROOT, 'acmelib', 'engine', '*.py')):
            self.assertFalse(re.search(r'_meta_json\(.*\) or \{\}', read(p)), p)

    def test_policy_text_of_1_0_42(self):
        me = E.node_name()
        self.store.set_meta('host:users:now:' + me, json.dumps({'policy': 'sig-of-1.0.42', 'at': 1}))
        with mock.patch.object(E, 'pwp_refused', return_value=True), \
                mock.patch.object(E, 'pwp_conf', return_value={'managed': False}):
            try:
                E.pwp_password_check(self.store, 'Some-Long-Pw-2026!', 'eva')
            except AttributeError as e:
                self.fail(e)
            except Exception:                           # noqa: BLE001
                pass                                    # refused by the rules: not the point

    def test_backups_of_null(self):
        self.store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:%'")
        self.store.set_meta('rbackup:targets', 'null')
        self.assertEqual(E.rb_targets(self.store), [])
        self.store.set_meta('rbackup:runs@@peer', '{"a": 1}')
        self.store.set_meta('rbackup:forgot@@peer', '[1, 2]')
        self.assertEqual(E.rb_history(self.store), [])
        self.store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:%'")

    def test_heartbeat_of_another_shape(self):
        self.store.set_meta('node:weird', '"x"')
        self.assertNotIn('weird', [n['name'] for n in E.ha_nodes(self.store)])
        self.store.db.run("DELETE FROM meta WHERE k = 'node:weird'")


class Cluster(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_a_node_away_for_a_while_still_counts(self):
        nodes = [{'name': 'a', 'me': True, 'age': 0, 'alive': True, 'version': '1.0.46'},
                 {'name': 'b', 'me': False, 'age': 600, 'alive': False, 'version': '1.0.43'}]
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}), \
                mock.patch.object(E, 'ha_nodes', return_value=nodes):
            self.assertFalse(E.cluster_runs_at_least(self.store, '1.0.44'))
            nodes[1]['age'] = 3 * 86400                 # gone for days: not waited for
            self.assertTrue(E.cluster_runs_at_least(self.store, '1.0.44'))

    def test_accounts_signed_as_before_until_adopted(self):
        row = {'name': 'x', 'role': 'portal', 'pw': 'h', 'source': 'local', 'disabled': 0,
               'must_change': 0, 'dn': '', 'mail': 'a@b.cz', 'mfa_on': 1}
        E._dbguard_load()
        with mock.patch.object(E, 'dbguard_on', return_value=True), \
                mock.patch.object(E, 'dbguard_key', return_value=b'k' * 32):
            E.DBGUARD['adopted'] = {}
            self.assertEqual(E.account_signed_cols(row), E.ACCOUNT_SIGNED)
            E.DBGUARD['adopted'] = {E.DBGUARD_ADOPT_MARK: 1}
            self.assertEqual(E.account_signed_cols(row), E.ACCOUNT_SIGNED + ('mail', 'mobile', 'mfa_on'))
        E.DBGUARD['adopted'] = {}

    def test_asks_for_a_node_forgotten_taken_away(self):
        me = E.node_name()
        gone = 'users:want' and ('host:users:want:gone' + E.NODE_KEY_SEP + me[:63])
        kept = 'host:users:want:' + E.nk_name('host:users:want', 'peer') + E.NODE_KEY_SEP + me[:63]
        self.store.set_meta(gone, '[{"hash": "sealed"}]')
        self.store.set_meta(kept, '[]')
        nodes = [{'name': me}, {'name': 'peer'}]
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}), \
                mock.patch.object(E, 'ha_nodes', return_value=nodes):
            self.assertEqual(E.node_asks_of_gone_tidy(self.store), 1)
        self.assertIsNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (gone,)))
        self.assertIsNotNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (kept,)))


class Pages(unittest.TestCase):
    def test_no_mbstring_needed(self):
        self.assertNotIn('mb_substr(', read('web', 'admin', 'index.php'))

    def test_back_to_the_pane(self):
        php = read('web', 'admin', 'index.php')
        self.assertIn("preg_replace('~[^A-Za-z0-9/_.-]~', ''", php)
        self.assertIn("'&back='", read('web', 'assets', 'admin.js'))

    def test_ticket_statuses(self):
        php = read('web', 'admin', 'index.php')
        i = php.index("$what === 'dl-ticket'")
        part = php[i:i + 1600]
        self.assertIn('http_response_code(503)', part)
        self.assertIn('http_response_code(401)', part)


if __name__ == '__main__':
    unittest.main()
