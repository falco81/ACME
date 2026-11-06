#!/usr/bin/env python3
"""What waits for a person (1.0.54, docs/things-to-do-by-hand.md):

    python3 test/test_hand.py

The checks of each node, the row they keep, every node's read for the pages and the status,
the alerts made of them, a step of a version gone by itself once done, a check that fails
not taking the others with it.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hand-')
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
DAEMON = E.Daemon(STORE, serve=False)
FILES = {}
REAL_READ = E._hand_read


def fake_read(path, most=2000000):
    return FILES.get(path)


class Hand(unittest.TestCase):
    def setUp(self):
        FILES.clear()
        E._hand_read = fake_read
        E.HAND.update(at=0.0, cache_at=0.0, cache=[])
        for r in STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'attention:%' OR k LIKE 'hand%'"):
            STORE.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))

    def tearDown(self):
        E._hand_read = REAL_READ

    def ids(self):
        E.HAND['cache_at'] = 0.0
        return sorted(i['id'] for i in E.hand_all(STORE))

    def test_selinux_switched_off(self):
        # Never seen enforcing: as it was set up, nothing said.
        FILES['/sys/fs/selinux/enforce'] = '0'
        E.hand_tick(STORE, force=True)
        self.assertNotIn('selinux-off', self.ids())
        # Enforcing, then permissive: said, with the command.
        FILES['/sys/fs/selinux/enforce'] = '1'
        E.hand_tick(STORE, force=True)
        self.assertEqual(STORE.get_meta('handseen:selinux:' + E.node_name()), 'enforcing')
        FILES['/sys/fs/selinux/enforce'] = '0'
        E.hand_tick(STORE, force=True)
        it = [i for i in E.hand_all(STORE) if i['id'] == 'selinux-off']
        self.assertEqual(len(it), 1)
        self.assertEqual(it[0]['level'], 'bad')
        self.assertEqual(it[0]['node'], E.node_name())
        self.assertIn('setenforce 1', it[0]['cmd'])
        self.assertTrue(it[0]['cs']['title'])
        # Off altogether (no /sys/fs/selinux): the config and a restart.
        del FILES['/sys/fs/selinux/enforce']
        E.hand_tick(STORE, force=True)
        it = [i for i in E.hand_all(STORE) if i['id'] == 'selinux-off'][0]
        self.assertIn('SELINUX=enforcing', it['cmd'])
        self.assertIn('reboot', it['cmd'])
        # Back on: gone by itself.
        FILES['/sys/fs/selinux/enforce'] = '1'
        E.hand_tick(STORE, force=True)
        self.assertNotIn('selinux-off', self.ids())

    def test_a_step_of_a_version(self):
        conf = '/etc/nginx/conf.d/acme.conf'
        FILES[conf] = 'server { location / { } }'
        E.hand_tick(STORE, force=True)
        self.assertIn('nginx-manifest', self.ids())
        FILES[conf] += '\nlocation ~ \\.webmanifest$ { }'
        E.hand_tick(STORE, force=True)
        self.assertNotIn('nginx-manifest', self.ids())
        del FILES[conf]                 # not an installed node: nothing
        E.hand_tick(STORE, force=True)
        self.assertNotIn('nginx-manifest', self.ids())

    def test_once_a_minute_and_a_failing_check(self):
        calls = []

        def bad(store):
            calls.append(1)
            raise RuntimeError('broken')

        def good(store):
            return [{'id': 'x-test', 'level': 'warn', 'title': 'T', 'words': 'W', 'cmd': '', 'pane': ''}]
        E.HAND_CHECKS[:0] = [bad, good]
        try:
            E.hand_tick(STORE, force=True)
            self.assertIn('x-test', self.ids())
            E.hand_tick(STORE)              # within the minute: not again
            self.assertEqual(len(calls), 1)
        finally:
            E.HAND_CHECKS.remove(bad)
            E.HAND_CHECKS.remove(good)
        ev = STORE.db.rows("SELECT words FROM events WHERE words LIKE 'waits for a person%'")
        self.assertTrue(any('T' in r['words'] for r in ev))

    def test_other_nodes_and_old_rows(self):
        STORE.set_meta('attention:acme2', json.dumps({'at': time.time(), 'items': [
            {'id': 'selinux-off', 'level': 'bad', 'title': 'SELinux was switched off', 'words': 'w',
             'cmd': 'sudo setenforce 1', 'pane': 'hisec', 'node': 'acme2'}]}))
        STORE.set_meta('attention:acme3', json.dumps({'at': time.time() - 86400 * 3, 'items': [
            {'id': 'old', 'level': 'warn', 'title': 'gone', 'node': 'acme3'}]}))
        STORE.set_meta('attention:acme4', 'not json')
        self.assertEqual(self.ids(), ['selinux-off'])
        # In the status, and in the alerts (mail, SNMP) in the language asked.
        E.HAND['cache_at'] = 0.0
        self.assertEqual([i['node'] for i in DAEMON.status()['attention']], ['acme2'])
        E.CONFIG['ha_mode'] = ''
        E.HAND['cache_at'] = 0.0
        p = E.alert_problems(STORE, 'en')
        self.assertIn('hand:selinux-off:acme2', p)
        self.assertEqual(p['hand:selinux-off:acme2']['level'], 'bad')
        self.assertIn('sudo setenforce 1', p['hand:selinux-off:acme2']['said'])
        E.CONFIG['alerts_hand'] = 0
        try:
            E.HAND['cache_at'] = 0.0
            self.assertNotIn('hand:selinux-off:acme2', E.alert_problems(STORE, 'en'))
        finally:
            E.CONFIG['alerts_hand'] = 1

    def api(self, method, body=None):
        h = E.CliApiHandler(DAEMON, 'boss', body or {}, {}, '/api/attention')
        return E.ROUTES[(method, '/api/attention')](h)

    def test_a_manual_step_done_and_written_down(self):
        step = {'id': 'x-manual', 'manual': True, 'level': 'bad', 'pane': 'upgrade',
                'title': 'Run the step by hand', 'words': 'w', 'cmd': 'sudo true'}
        E.HAND_STEPS.append(step)
        try:
            E.hand_tick(STORE, force=True)
            got = self.api('GET')
            it = [i for i in got['items'] if i['id'] == 'x-manual'][0]
            self.assertEqual(it['kind'], 'manual')
            since = it['since']
            self.assertTrue(since)
            E.HAND['at'] = 0
            E.hand_tick(STORE, force=True)          # the time it waits since is kept
            self.assertEqual([i for i in self.api('GET')['items'] if i['id'] == 'x-manual'][0]['since'], since)
            with self.assertRaises(E.ApiError):     # a checked one is not pressed away
                FILES['/etc/nginx/conf.d/acme.conf'] = 'old'
                E.hand_tick(STORE, force=True)
                self.api('POST', {'action': 'done', 'id': 'nginx-manifest', 'node': E.node_name()})
            got = self.api('POST', {'action': 'done', 'id': 'x-manual', 'node': E.node_name()})
            self.assertNotIn('x-manual', [i['id'] for i in got['items']])
            d = [x for x in got['done'] if x['what'] == 'Run the step by hand'][0]
            self.assertEqual((d['how'], d['who']), ('done', 'boss'))
            with self.assertRaises(E.ApiError):
                self.api('POST', {'action': 'done', 'id': 'x-manual', 'node': E.node_name()})
            # a checked one gone: "gone by itself"
            FILES['/etc/nginx/conf.d/acme.conf'] = 'webmanifest'
            got = self.api('POST', {'action': 'look'})
            self.assertNotIn('nginx-manifest', [i['id'] for i in got['items']])
            self.assertEqual(got['done'][0]['how'], 'gone by itself')
            self.assertTrue(STORE.get_meta('handlook'))
        finally:
            E.HAND_STEPS.remove(step)

    def test_look_asked_elsewhere(self):
        E.hand_tick(STORE, force=True)
        calls = []
        E.HAND_CHECKS.append(lambda st: calls.append(1) or [])
        try:
            E.hand_tick(STORE)
            self.assertEqual(calls, [])             # within the minute
            STORE.set_meta('handlook', '%.3f' % (time.time() + 1))
            E.hand_tick(STORE)
            self.assertEqual(calls, [1])            # Look again pressed on another node
        finally:
            E.HAND_CHECKS.pop()

    def test_pages(self):
        js = open(os.path.join(ROOT, 'web/assets/admin.js')).read()
        self.assertIn('function drawAttention(s)', js)
        self.assertIn('drawAttention(s);', js)
        php = open(os.path.join(ROOT, 'web/admin/index.php')).read()
        self.assertIn('id="attention"', php)
        self.assertIn('id="att-card"', php)
        self.assertIn("'attention' => '/api/attention'", php)
        cs = json.load(open(os.path.join(ROOT, 'web/lang/cs.json')))
        flat = json.dumps(cs, ensure_ascii=False)
        for st in E.HAND_STEPS:
            self.assertIn(json.dumps(st['title'])[1:-1], flat)


if __name__ == '__main__':
    unittest.main(verbosity=1)
