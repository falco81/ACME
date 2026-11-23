#!/usr/bin/env python3
"""Hunt R, run 2, area habackup: backups put back, the cluster's nodes - each bug found, checked.

    python3 test/test_hunt_r2_habackup.py
"""
import json
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hr2-habackup-')
os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


class SelinuxStepNotRedone(unittest.TestCase):
    """A backup put back (or the node on another machine): the backup's last step of SELinux -
    done long ago - was done again here at once, as its "done" was forgotten with the machine."""

    def _tick_asks(self, store):
        asked = []

        def fake(name, f, ask, t):
            asked.append(ask.get('do'))
            return {}

        class D(object):
            pass
        d = D()
        d.store = store
        with mock.patch.object(E, 'root_ask', fake):
            E.SE_WORK.update(seen=time.time(), busy=False, tried='')
            E.selinux_tick(d)
            for _ in range(50):
                if not E.SE_WORK['busy']:
                    break
                time.sleep(0.05)
        return asked

    def test_put_back_does_not_redo_permissive(self):
        store = E.Storage(E.open_db())
        me = E.node_name()
        store.set_meta('host:selinux:want:' + me, json.dumps(
            {'id': 'aaaaaaaaaaaa', 'do': 'permissive', 'by': 'x', 'at': time.time() - 30 * 86400}))
        store.set_meta('host:selinux:now:' + me, json.dumps(
            {'done': 'aaaaaaaaaaaa', 'data': {'mode': 'Enforcing'}, 'at': time.time()}))
        E.machine_changed_check(store, put_back=True)
        self.assertEqual(self._tick_asks(store), ['check'])
        want = json.loads(store.get_meta('host:selinux:want:' + me))
        self.assertEqual(want['do'], 'check')

    def test_a_check_left_as_it_is(self):
        store = E.Storage(E.open_db())
        me = E.node_name()
        row = json.dumps({'id': 'bbbbbbbbbbbb', 'do': 'check', 'by': 'x', 'at': time.time()})
        store.set_meta('host:selinux:want:' + me, row)
        store.set_meta('host:selinux:now:' + me, json.dumps({'done': 'bbbbbbbbbbbb'}))
        E.machine_changed_check(store, put_back=True)
        self.assertEqual(store.get_meta('host:selinux:want:' + me), row)


class DbAgentRowsOfGoneNodes(unittest.TestCase):
    """The database server's row of a node forgotten or renamed: a server of nobody's on the
    cards, and alerts nothing could take away."""

    def test_forgotten_node_not_listed(self):
        store = E.Storage(E.open_db())
        me = E.node_name()
        now = time.time()
        store.set_meta('node:peer', json.dumps({'at': now}))
        for n in (me, 'peer', 'gone'):
            store.set_meta('dbagent:node:' + n, json.dumps(
                {'at': now - 86400 if n == 'gone' else now, 'ok': n != 'gone',
                 'down_since': now - 86400, 'host': '192.0.2.1', 'port': 8447}))
        names = [v['node'] for v in E.db_agent_servers(store)]
        self.assertEqual(sorted(names), sorted([me, 'peer']))
        with mock.patch.object(E, 'db_agent_on', lambda: True):
            keys = [a['key'] for a in E._db_agent_alerts(store)]
        self.assertNotIn('dbagent:gone', keys)
        E.ha_forget(store, 'peer')
        self.assertEqual([v['node'] for v in E.db_agent_servers(store)], [me])


if __name__ == '__main__':
    unittest.main()
