"""Hunt t1, the guard against writes and the database agent.

    python3 test/test_hunt_rt1_dbguard.py
"""
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt-t1-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def forged(k, v):
    STORE.db.upsert('meta', 'k', {'k': k, 'v': v})


class TestSwitchedOnFresh(unittest.TestCase):
    """Switched on where it had never been on: the rows of 1.0.44 and 1.0.95 were not checked
    until the hourly adoption, which then signed whatever was written there meanwhile."""

    def test_checked_at_once(self):
        E.CONFIG['db_guard'] = 0
        E._dbguard_load()
        for m in (E.DBGUARD_ADOPT_MARK, E.DBGUARD_ADOPT2_MARK):
            E.DBGUARD['adopted'].pop(m, None)
        STORE.set_meta('module-file:x.py', 'good')
        STORE.set_meta('rbackup:targets', '[]')
        E.dbguard_resign(STORE, 'switched on')
        E.CONFIG['db_guard'] = 1
        try:
            forged('module-file:x.py', 'evil')
            forged('rbackup:targets', '[{"url": "sftp://elsewhere"}]')
            self.assertIsNone(STORE.get_meta('module-file:x.py'))
            self.assertIsNone(STORE.get_meta('rbackup:targets'))
            E.dbguard_adopt(STORE)                      # the hourly adoption takes nothing in
            self.assertIsNone(STORE.get_meta('module-file:x.py'))
            self.assertIsNone(STORE.get_meta('rbackup:targets'))
            STORE.set_meta('rbackup:targets', '[]')      # written by acme: taken
            self.assertEqual(STORE.get_meta('rbackup:targets'), '[]')
        finally:
            E.CONFIG['db_guard'] = 0


class TestPeerMovedMalformed(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'dbagent:addr:%'")
        self.g = E.db_agent_peer_moved.__globals__
        self.saved = {n: self.g[n] for n in ('db_agent', 'db_agent_here', 'db_agent_call',
                                             'db_agent_fw', 'db_agent_put')}
        self.peer = {'peer_node': '10.0.0.2', 'engine': 'postgres', 'db_admin': 'x'}
        self.g['db_agent'] = lambda: dict(self.peer)
        self.g['db_agent_here'] = lambda: True
        self.g['db_agent_call'] = lambda *a, **k: {}
        self.g['db_agent_fw'] = lambda *a, **k: {}
        self.g['db_agent_put'] = lambda d: self.peer.update(d)
        self.ha = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'

    def tearDown(self):
        self.g.update(self.saved)
        E.CONFIG['ha_mode'] = self.ha
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'dbagent:addr:%'")

    def test_a_row_not_an_object_does_not_stop_the_others(self):
        for i, bad in enumerate(('null', '[1]', '"x"', '7')):
            forged('dbagent:addr:a%d' % i, bad)
        STORE.set_meta('dbagent:addr:node2', json.dumps({'address': '10.0.0.9',
                                                         'old': '10.0.0.2'}))
        self.assertEqual(E.db_agent_peer_moved(STORE), '10.0.0.9')
        self.assertEqual(self.peer['peer_node'], '10.0.0.9')


class TestLoadRowsMalformed(unittest.TestCase):
    def test_not_an_object(self):
        forged('load:db:zz1', 'null')
        forged('load:db:zz2', '{"at": "soon"}')
        forged('load:db:zz3', json.dumps({'at': time.time(), 'cpu': 1}))
        try:
            got = E.db_agent_load_rows(STORE)
            self.assertEqual([v['node'] for v in got if v['node'].startswith('zz')], ['zz3'])
        finally:
            STORE.db.run("DELETE FROM meta WHERE k LIKE 'load:db:zz%'")


if __name__ == '__main__':
    unittest.main()
