#!/usr/bin/env python3
"""The hunt of 1.0.45, round 3 - and what a cluster upgraded from 1.0.43 to 1.0.44 showed.

    python3 test/test_hunt_a3.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunta3-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


class FromTheField(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_a_users_row_of_another_shape_is_none(self):
        me = E.node_name()
        self.store.set_meta('host:users:now:' + me, json.dumps('something else'))
        self.assertEqual(E.osu_now(self.store, me), {})
        self.store.set_meta('host:users:now:' + me, json.dumps({'policy': 'text', 'at': 1}))

        class D:
            store = self.store
        with mock.patch.object(E, 'root_ask', return_value={'users': []}):
            E.osu_tick(D())             # no AttributeError on a policy that is no object
        with self.assertRaises(ValueError):
            E.osu_keep({}, 'not a dict')

    def test_back_up_now_of_an_older_node_not_refused_before_adoption(self):
        with mock.patch.object(E, 'dbguard_on', return_value=True), \
                mock.patch.object(E, 'dbguard_key', return_value=b'k' * 32):
            E.DBGUARD['adopted'] = {}
            self.assertTrue(E.dbguard_ok(self.store.db, 'm', 'rbackup:now:acme2@@acme1', '{}'))
            E.DBGUARD['adopted'] = {E.DBGUARD_ADOPT_MARK: 1}
            self.assertFalse(E.dbguard_ok(self.store.db, 'm', 'rbackup:now:acme2@@acme1', '{}',
                                          quiet=True))
            E.DBGUARD['adopted'] = {}

    def test_old_asks_of_back_up_now_tidied_by_their_node(self):
        me = E.node_name()
        old = 'rbackup:now:peer' + E.NODE_KEY_SEP + me
        new = 'rbackup:now:peer2' + E.NODE_KEY_SEP + me
        other = 'rbackup:now:' + me + E.NODE_KEY_SEP + 'peer'
        self.store.set_meta(old, json.dumps({'id': 'a', 'at': time.time() - 3600}))
        self.store.set_meta(new, json.dumps({'id': 'b', 'at': time.time()}))
        self.store.set_meta(other, json.dumps({'id': 'c', 'at': time.time() - 3600}))
        E.rb_now_tidy(self.store)
        self.assertIsNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (old,)))
        self.assertIsNotNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (new,)))
        self.assertIsNotNone(self.store.db.value('SELECT v FROM meta WHERE k = ?', (other,)))

    def test_where_it_broke(self):
        try:
            E.osu_keep({}, 'x')
        except ValueError:
            self.assertIn('425_', E.where_it_broke())


class Backups(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_a_copy_of_a_newer_acme_refused(self):
        import gzip
        p = os.path.join(TMP, 'newer.json.gz')
        with gzip.open(p, 'wt') as f:
            f.write(json.dumps({'acme': '9.9.9', 'engine': 'sqlite'}) + '\n')
            f.write(json.dumps({'table': 'accounts'}) + '\n')
            f.write(json.dumps({'id': 1, 'name': 'a', 'role': 'fulladmin'}) + '\n')
        said, why = E.db_file_peek(p, 'sqlite', need_admin=False)
        self.assertIsNone(said)
        self.assertIn('newer than this one', why)

    def test_how_a_destination_went_is_each_nodes_own(self):
        self.store.set_meta('rbackup:targets', json.dumps([{'id': 'ab12', 'name': 'nas', 'kind': 'folder'}]))
        E.rb_last_set(self.store, 'ab12', {'at': time.time(), 'ok': True})
        self.assertTrue(self.store.get_meta(E.node_key('rbackup:last', 'ab12')))
        t = E.rb_targets(self.store)[0]
        self.assertTrue(t['last']['ok'])
        self.assertNotIn('last', json.loads(self.store.get_meta('rbackup:targets'))[0])

    def test_the_move_holds_before_the_copy(self):
        src = open(os.path.join(ROOT, 'acmelib', 'engine', [n for n in os.listdir(
            os.path.join(ROOT, 'acmelib', 'engine')) if n.startswith('137_')][0])).read()
        self.assertLess(src.index("RESTORE_RUNNING.set()"), src.index("copy = make_backup(store, 'before moving"))

    def test_a_failed_scheduled_backup_tried_again(self):
        src = open(os.path.join(ROOT, 'acmelib', 'engine', [n for n in os.listdir(
            os.path.join(ROOT, 'acmelib', 'engine')) if n.startswith('175_')][0])).read()
        self.assertIn("'acme (scheduled, again: the one before failed)'", src)


if __name__ == '__main__':
    unittest.main()
