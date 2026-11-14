#!/usr/bin/env python3
"""HA edge cases (1.0.58):

    python3 test/test_ha_edges.py

The subscription's host read back as acme last set it (subconninfo is the superuser's alone);
the preferred node taken for down only when its own /healthz says so (not a TCP connection to
443); a signed row deleted with its signatures; acme 1.0.42's password policy taken over by
the lead alone in a replicated cluster.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-haedges-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
N = sys.modules['acmelib.engine'].__dict__


class Resp(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Edges(unittest.TestCase):
    def test_sub_host_as_acme_set_it(self):
        E.CONFIG['ha_slot'] = 1
        p = mock.patch.dict(N, {'ha_sub_here': lambda db, n: 'acme_from_2'})
        p.start()
        self.addCleanup(p.stop)
        real = STORE.db.run

        def fake(sql, *a, **k):
            if 'ALTER SUBSCRIPTION' in str(getattr(sql, 'sql', sql)) or 'log_' in str(sql):
                return 0
            return real(sql, *a, **k)
        with mock.patch.object(STORE.db, 'run', side_effect=fake):
            E.sub_connection_set(STORE, 'acme_from_2', "host=10.0.0.12 port=5432 dbname=acme "
                                 "user=acme password='x y'")
        sub = 'acme_from_2'
        row = json.loads(STORE.get_meta('ha:subhost:' + E.node_name()))
        self.assertEqual(row['host'], '10.0.0.12')
        self.assertNotIn('password', json.dumps(row))
        if row['sub'] == sub:
            self.assertEqual(E._sub_host(STORE), '10.0.0.12')
        STORE.set_meta('ha:subhost:' + E.node_name(), json.dumps({'sub': 'other', 'host': '1.2.3.4'}))
        self.assertEqual(E._sub_host(STORE), '')        # another subscription's: not known

    def test_peer_health(self):
        with mock.patch('urllib.request.urlopen', return_value=Resp(200, b'ok acme2\n')):
            self.assertEqual(E.split_peer_says('192.0.2.2'), 'up')
        err = urllib.error.HTTPError('u', 503, 'x', {}, io.BytesIO(b'down: the database does not open\n'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), 'down')
        err = urllib.error.HTTPError('u', 503, 'x', {}, io.BytesIO(b'maintenance acme2\n'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')    # maintenance is not "down"
        err = urllib.error.HTTPError('u', 403, 'x', {}, io.BytesIO(b'forbidden'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')
        with mock.patch('urllib.request.urlopen', side_effect=OSError('refused')):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')

    def test_meta_drop_with_signatures(self):
        k = 'host:rootkey:again:' + E.node_name()
        self.assertTrue(E.dbguard_meta_signed(k))
        STORE.set_meta(k, '1')
        head = 'sig:m:%s:' % E._dbguard_hash(k)
        STORE.set_meta(head + 'acme2', 'x')             # the other node's signature too
        E.meta_drop(STORE, k)
        self.assertIsNone(STORE.get_meta(k))
        self.assertEqual([r for r in E._dbguard_head_rows(STORE.db, head) if r['k'].startswith(head)], [])

    def test_policy_taken_over_by_the_lead_alone(self):
        STORE.db.run("DELETE FROM meta WHERE k IN ('host:pwpolicy:conf', 'pwpolicy:migrated:2')")
        saved = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'
        try:
            with mock.patch.dict(N, {'ha_lead': lambda st: False, 'ha_lead_heard': lambda st: False}):
                self.assertFalse(E.pwp_migrate(STORE))
                self.assertIsNone(STORE.get_meta('pwpolicy:migrated:2'))
            with mock.patch.dict(N, {'ha_lead': lambda st: True, 'ha_lead_heard': lambda st: True}):
                E.pwp_migrate(STORE)
                self.assertTrue(STORE.get_meta('pwpolicy:migrated:2'))
        finally:
            E.CONFIG['ha_mode'] = saved


class GuardAfterRebuild(unittest.TestCase):
    """`acme --ha-resync` and `acme --ha-join` start the guard's counts again (1.0.101), as the
    pages' rebuild does: node B, rebuilt from node A, had seen its own newer signatures and
    refused A's rows as older ones put back - it went on acting on its own old values. Both
    nodes are played on this SQLite database, each signing as itself."""

    PROXY = 'proxy_url'

    def setUp(self):
        self.saved = {k: E.CONFIG.get(k) for k in ('db_guard', 'ha_mode', 'ha_peer', 'ha_slot')}
        E.CONFIG.update(db_guard=1, ha_mode='replicated', ha_peer='192.0.2.1', ha_slot=2)
        E.dbguard_forget_seen('test')

    def tearDown(self):
        E.CONFIG.update(self.saved)
        E.DBGUARD.pop('hold', None)
        E.dbguard_forget_seen('test')

    def save_as(self, node, value):
        with mock.patch.dict(N, {'node_name': lambda: node}):
            v = json.dumps(value)
            STORE.db.run('DELETE FROM settings WHERE k = ?', (self.PROXY,))
            STORE.db.run('INSERT INTO settings (k, v) VALUES (?, ?)', (self.PROXY, v))
            E.dbguard_sign(STORE.db, 's', self.PROXY, v)
            time.sleep(0.01)
            return E.dbguard_settings(STORE.settings_saved(), STORE).get(self.PROXY)

    def tables(self):
        return {t: [dict(r) for r in STORE.db.rows('SELECT k, v FROM %s' % t)]
                for t in ('settings', 'meta')}

    def put(self, rows):
        for t, got in rows.items():
            STORE.db.run('DELETE FROM %s' % t)
            for r in got:
                STORE.db.run('INSERT INTO %s (k, v) VALUES (?, ?)' % t, (r['k'], r['v']))

    def acted_on(self):
        with mock.patch.dict(N, {'node_name': lambda: 'acme2'}):
            got = E.dbguard_settings(STORE.settings_saved(), STORE).get(self.PROXY)
        return got, [v['why'] for v in E.DBGUARD['refused'].values()]

    def apart(self):
        """A saves the proxy, then B: B's database is replaced with A's rows."""
        self.assertEqual(self.save_as('acme1', 'http://proxy-a.example.test:3128'),
                         'http://proxy-a.example.test:3128')
        a_rows = self.tables()
        self.assertEqual(self.save_as('acme2', 'http://proxy-b.example.test:3128'),
                         'http://proxy-b.example.test:3128')
        return a_rows

    def test_the_trouble_itself(self):
        a_rows = self.apart()
        self.put(a_rows)
        got, refused = self.acted_on()
        self.assertEqual(got, 'http://proxy-b.example.test:3128')
        self.assertIn('it is an older one put back', refused)

    def test_ha_resync_on_the_command_line(self):
        a_rows = self.apart()

        def rebuild(local, remote, *a):
            self.put(a_rows)
            return {'rows': 2}
        args = type('A', (), {'yes': True})()
        with mock.patch.dict(N, {'load_config': lambda *a, **k: None, 'open_db': lambda: STORE.db,
                                 'make_backup': lambda st, why: 'kept.tar',
                                 'ha_peer_db': lambda: object(), 'ha_rebuild': rebuild}), \
                mock.patch('os.geteuid', return_value=0), \
                mock.patch.dict(os.environ, {'ACME_HA_NO_RESTART': '1'}), \
                mock.patch('sys.stdout', io.StringIO()):
            self.assertEqual(E.cli_ha_resync(args, E.Palette(False)), 0)
        got, refused = self.acted_on()
        self.assertEqual(got, 'http://proxy-a.example.test:3128')
        self.assertEqual(refused, [])
        # as the daemon started again reads it: from guard.json
        E.DBGUARD['seen'] = None
        got, refused = self.acted_on()
        self.assertEqual((got, refused), ('http://proxy-a.example.test:3128', []))

    def test_shared_join_starts_from_an_empty_guard_file(self):
        self.apart()
        E.dbguard_flush(force=True)
        self.assertTrue(json.loads(E.DBGUARD_FILE.read_text())['seen'])
        key = E.sealing_key_path().read_text()
        data = {'db': {'db_engine': 'postgres', 'db_host': '192.0.2.1', 'db_port': 5432,
                       'db_name': 'acme', 'db_user': 'acme', 'db_password': 'pw'},
                'key': os.urandom(32).hex(), 'peer': {'name': 'acme1', 'address': '192.0.2.1'}}
        try:
            with mock.patch.dict(N, {'ha_join_open': lambda *a: {'state': 'off', 'said': ''},
                                     'db_try': lambda db: {'reached': True, 'rows': 3},
                                     'write_file_settings': lambda ch: None}):
                E.ha_join(data, even_if_data=True, by='test')
            on_disk = json.loads(E.DBGUARD_FILE.read_text())
            self.assertEqual((on_disk['seen'], on_disk['good'], on_disk['seen_h']), ({}, {}, {}))
            # The process going on with its old database until it restarts writes nothing more.
            E.DBGUARD['dirty'] = time.time()
            E.dbguard_flush(force=True)
            self.assertEqual(json.loads(E.DBGUARD_FILE.read_text())['seen'], {})
        finally:
            E.sealing_key_path().write_text(key)


class ApiPortNotTheCertificates(unittest.TestCase):
    """api_port never the certificate sign-in's port (1.0.101), on any node, both ways: nginx
    listens on certlogin_port on every node, the daemon on 127.0.0.1:api_port."""

    def test_check_setting(self):
        with self.assertRaises(E.BadSetting) as e:
            E.check_setting('api_port', '8443')
        self.assertIn('certlogin_port', str(e.exception))
        self.assertEqual(E.check_setting('api_port', '9862'), 9862)

    def test_saved_on_this_node(self):
        d = E.Daemon(STORE, serve=False)
        with self.assertRaises(E.BadSetting) as e:
            d.save_settings({'api_port': 8443}, by='test')
        self.assertIn('sign-in with a certificate', str(e.exception))
        self.assertNotEqual(int(E.CONFIG.get('api_port') or 9861), 8443)

    def test_every_node(self):
        saved = {'api_port@acme2': 8444}
        # certlogin_port onto another node's API port
        why = E.cl_api_port_clash(saved, {'certlogin_port': 8444}, 'acme1', True)
        self.assertIn('on acme2', why)
        self.assertIn('certlogin_port: 8444', why)
        self.assertEqual(E.cl_api_port_clash(saved, {'certlogin_port': 8445}, 'acme1', True), '')
        # another node's own api_port onto the certificate's port
        why = E.cl_api_port_clash({}, {'api_port': 8443}, 'acme2', True)
        self.assertIn('api_port: 8443', why)
        self.assertIn('on acme2', why)
        # the cluster's own value, for every node without one of its own
        why = E.cl_api_port_clash({'api_port@acme2': 9870}, {'api_port': 8443}, 'acme1', False)
        self.assertIn('api_port: 8443', why)
        # a node's own port elsewhere is fine, even with the cluster's one changing
        self.assertEqual(E.cl_api_port_clash({'api_port@acme2': 9870}, {'api_port': 9871},
                                             'acme1', False), '')


if __name__ == '__main__':
    unittest.main(verbosity=1)
