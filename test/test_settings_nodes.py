#!/usr/bin/env python3
"""Settings in a cluster: what is saved, in effect on every node? (1.0.42)

    python3 test/test_settings_nodes.py

Each node says in its heartbeat the mark of the change of the settings it read in, and when;
GET /api/settings/nodes says of each node whether that is the one saved - this node as it is
now, the others by their heartbeats; one not heard from, or of a version that does not say it,
as such. Asked again (POST), the other node is asked to say it at once.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-setnodes-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


class D:
    pass


class InEffect(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())
        self.me = E.node_name()
        self.store.set_meta('conf_serial', '100.000000:%s' % self.me)
        self.d = D()
        self.d.conf_serial = '100.000000:%s' % self.me
        self.d.conf_loaded_at = time.time() - 3
        self.d.started = time.time() - 100

    def beat(self, name, **kw):
        self.store.set_meta('node:' + name, json.dumps(dict({'at': time.time(), 'version': '1.0.42'}, **kw)))

    def test_in_the_heartbeat(self):
        with mock.patch.dict(E.CONFIG, {'ha_mode': ''}):
            b = E.heartbeat(self.store, self.d)
        self.assertEqual(b['conf_seen'], self.d.conf_serial)
        self.assertEqual(b['conf_seen_at'], self.d.conf_loaded_at)

    def test_each_node_said(self):
        self.beat(self.me, conf_seen='old')            # its heartbeat behind: itself as it is now
        self.beat('peer-ok', conf_seen='100.000000:%s' % self.me, conf_seen_at=time.time() - 9)
        self.beat('peer-behind', conf_seen='99.000000:x', conf_seen_at=time.time() - 60)
        self.beat('peer-old')                           # 1.0.41 says nothing of it
        self.store.set_meta('node:peer-gone', json.dumps({'at': time.time() - 3600,
                                                          'conf_seen': '100.000000:%s' % self.me}))
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            got = E.settings_in_effect(self.store, daemon=self.d)
        by = {n['name']: n for n in got['nodes']}
        self.assertTrue(got['cluster'])
        self.assertTrue(by[self.me]['seen'] and by[self.me]['me'])
        self.assertTrue(by['peer-ok']['seen'])
        self.assertFalse(by['peer-behind']['seen'])
        self.assertTrue(by['peer-behind']['known'])
        self.assertFalse(by['peer-old']['known'])
        self.assertFalse(by['peer-gone']['alive'])

    def test_standalone_says_nothing(self):
        with mock.patch.dict(E.CONFIG, {'ha_mode': ''}):
            self.assertFalse(E.settings_in_effect(self.store, daemon=self.d)['cluster'])

    def test_asked_again(self):
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            E.settings_in_effect(self.store, ask=True, daemon=self.d)
        self.assertTrue(self.store.get_meta('beat_asked:' + E.node_name(), ''))
        self.assertTrue(E.beat_asked_last(self.store))

    def test_on_the_page(self):
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            page = f.read()
        self.assertEqual(page.count("'settings-nodes' => '/api/settings/nodes'"), 2)
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            js = f.read()
        for fn in ('function snPills', 'function snAgain', 'function snPace'):
            self.assertIn(fn, js)


if __name__ == '__main__':
    unittest.main()
