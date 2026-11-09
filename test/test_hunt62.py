#!/usr/bin/env python3
"""The bug hunt of 1.0.62 over what came since 1.0.53:

    python3 test/test_hunt62.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt62-')
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


class Hunt62(unittest.TestCase):
    def test_permissive_asked_is_not_switched_off(self):
        me = E.node_name()
        STORE.set_meta('handseen:selinux:' + me, 'enforcing')
        STORE.set_meta('host:selinux:want:' + me, json.dumps({'id': 'a', 'do': 'permissive'}))
        with mock.patch.dict(N, {'_hand_read': lambda p, most=0: '0'}):
            self.assertEqual(E.hand_selinux(STORE), [])
        self.assertIsNone(STORE.get_meta('handseen:selinux:' + me))
        # switched off behind its back after it was enforcing again: said
        STORE.set_meta('host:selinux:want:' + me, json.dumps({'id': 'b', 'do': 'enforce'}))
        with mock.patch.dict(N, {'_hand_read': lambda p, most=0: '1'}):
            E.hand_selinux(STORE)
        with mock.patch.dict(N, {'_hand_read': lambda p, most=0: '0'}):
            self.assertEqual([i['id'] for i in E.hand_selinux(STORE)], ['selinux-off'])

    def test_forgotten_node_takes_its_attention(self):
        STORE.set_meta('attention:gone', json.dumps({'at': time.time(), 'items': [{'id': 'x'}]}))
        STORE.set_meta('handlog:gone', '[]')
        with mock.patch.dict(N, {'ha_nodes': lambda st: []}):
            E.ha_forget(STORE, 'gone')
        self.assertIsNone(STORE.get_meta('attention:gone'))
        self.assertIsNone(STORE.get_meta('handlog:gone'))

    def test_osroots_applied_only_in_the_bundle(self):
        want = {'hash': 'h', 'certs': [{'fp': 'f'}]}
        row = {'at': time.time(), 'hash': 'h', 'ok': True,
               'state': {'ours': [{'fp': 'f', 'cn': 'Firma CA', 'in_bundle': False}]}}
        st, words = E.osr_node_status(want, row, True)
        self.assertEqual(st, 'failed')
        self.assertIn('Firma CA', words)
        row['state']['ours'][0]['in_bundle'] = True
        self.assertEqual(E.osr_node_status(want, row, True)[0], 'applied')

    def test_osroots_tool_forced_after_a_failure(self):
        me = E.node_name()
        want = {'hash': 'h1', 'v': 1, 'certs': [{'pem': 'P', 'fp': 'f'}]}
        STORE.set_meta('oscerts:node:' + me, json.dumps({'hash': 'h1', 'ok': False, 'error': 'x'}))
        asked = []

        def ask(name, ans, data, wait):
            asked.append(data)
            return {'said': [], 'refused': []}
        with mock.patch.dict(N, {'root_ask': ask}):
            E.osroots_run(STORE, want)
        self.assertTrue(asked[0].get('force'))
        asked.clear()
        with mock.patch.dict(N, {'root_ask': ask}):
            E.osroots_run(STORE, want)          # it went this time: not forced again
        self.assertFalse(asked[0].get('force'))

    def test_lead_heard(self):
        saved = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'
        try:
            E.LEAD_HEARD['since'] = time.monotonic()
            with mock.patch.dict(N, {'ha_nodes': lambda st: [{'name': E.node_name(), 'me': True, 'alive': True},
                                                             {'name': 'acme2', 'alive': False}],
                                     'lead_of': lambda st: True}):
                self.assertFalse(E.ha_lead_heard(STORE))    # nobody heard, just started
                E.LEAD_HEARD['since'] = time.monotonic() - 700
                self.assertTrue(E.ha_lead_heard(STORE))     # ten minutes of nobody: it leads
            E.LEAD_HEARD['since'] = time.monotonic()
            with mock.patch.dict(N, {'ha_nodes': lambda st: [{'name': E.node_name(), 'me': True, 'alive': True},
                                                             {'name': 'acme2', 'alive': True}],
                                     'lead_of': lambda st: True}):
                self.assertTrue(E.ha_lead_heard(STORE))
        finally:
            E.CONFIG['ha_mode'] = saved

    def test_ca_made_by_one_node(self):
        saved = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'
        made = []
        try:
            STORE.db.run("DELETE FROM meta WHERE k = 'hatls:ca'")
            with mock.patch.dict(N, {'ha_lead_heard': lambda st: False,
                                     'hatls_ca_make': lambda st, by: made.append(by)}):
                with self.assertRaises(ValueError):
                    E.hatls_ca_ensure(STORE, 'x', wait=0)
            self.assertEqual(made, [])
            src = open(os.path.join(ROOT, 'acmelib/engine/330_isemon_over_tls.py')).read()
            self.assertNotIn('hatls_ca_make(', src)
        finally:
            E.CONFIG['ha_mode'] = saved

    def test_dbtls_again_after_the_clock_went_back(self):
        k = 'dbtls:rescued:' + E.node_name()
        STORE.set_meta(k, json.dumps({'at': time.time() + 3600, 'was': 'verify-full', 'ca': ''}))
        tried = []
        saved = {x: E.CONFIG.get(x) for x in ('db_engine', 'db_host', 'db_tls')}
        E.CONFIG.update(db_engine='postgres', db_host='127.0.0.1', db_tls='')
        try:
            with mock.patch.dict(N, {'dbtls_probe': lambda m, c: tried.append(m) or {'ok': False}}):
                E._dbtls_again(type('D', (), {'store': STORE}))
            self.assertEqual(tried, ['verify-full'])
        finally:
            E.CONFIG.update(saved)
            STORE.db.run('DELETE FROM meta WHERE k = ?', (k,))

    def test_health_waits_longer_than_the_daemon(self):
        import inspect
        self.assertGreaterEqual(inspect.signature(E.split_peer_says).parameters['timeout'].default, 4)

    def test_czech_of_the_new_events(self):
        cs = json.load(open(os.path.join(ROOT, 'web/lang/cs.json')))
        pats = {v['source'] for v in cs['patterns'].values()}
        for p in ('waits for a person on {0}: {1}', 'done on {0}: {1}', 'gone by itself on {0}: {1}',
                  '"done lately" cleared by {0} ({1})'):
            self.assertIn(p, pats)
        txt = [v['text'] for v in cs['patterns'].values() if v['source'] == '{0} authorities'][0]
        self.assertIn('{0} ', txt)


if __name__ == '__main__':
    unittest.main(verbosity=1)
