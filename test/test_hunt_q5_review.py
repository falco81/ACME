#!/usr/bin/env python3
"""The hunt of 1.0.119, round Q5 - the regression review of everything fixed in Q1-Q4.

    python3 test/test_hunt_q5_review.py

- a configuration exported by 1.0.118 with "behind a load balancer" on and the balancers as
  every address (0.0.0.0/0, which 1.0.119 refuses) is still imported: the balancers and the
  switch are left out and said - the switch on without them stopped every setting of the file;
- a backup's config.json settings carried with such a value: left out, never a failure;
- the same value already saved (an upgrade) is used as before - nothing stops at startup;
- the Czech file holds the new words of the round, and stays JSON;
- the CHANGELOG's 1.0.119 section: one list, no line twice.
"""
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-q5review-')
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


class EveryAddressFromAnOlderVersion(unittest.TestCase):
    def setUp(self):
        DAEMON.save_settings({'web_proxy': 0, 'web_proxy_from': ''}, 'tester')

    def test_a_file_of_1_0_118_is_imported(self):
        said = E.config_import(STORE, DAEMON, {'settings': {
            'web_proxy': 1, 'web_proxy_from': '0.0.0.0/0', 'session_idle_min': 77}}, 'tester')
        self.assertEqual(E.CONFIG.get('session_idle_min'), 77)      # the rest of it taken
        self.assertFalse(E.CONFIG.get('web_proxy'))
        self.assertEqual(str(E.CONFIG.get('web_proxy_from') or ''), '')
        self.assertEqual(said.get('settings left out: refused here (web_proxy_from)'), 1)
        self.assertEqual(said.get('settings left out: refused here (web_proxy)'), 1)

    def test_the_switch_kept_where_the_balancers_are_named_here(self):
        DAEMON.save_settings({'web_proxy_from': '10.0.0.1'}, 'tester')
        said = E.config_import(STORE, DAEMON, {'settings': {
            'web_proxy': 1, 'web_proxy_from': '::/0'}}, 'tester')
        self.assertTrue(E.CONFIG.get('web_proxy'))
        self.assertEqual(E.CONFIG.get('web_proxy_from'), '10.0.0.1')
        self.assertNotIn('settings left out: refused here (web_proxy)', said)

    def test_a_good_file_as_before(self):
        said = E.config_import(STORE, DAEMON, {'settings': {
            'web_proxy': 1, 'web_proxy_from': '192.0.2.0/24'}}, 'tester')
        self.assertTrue(E.CONFIG.get('web_proxy'))
        self.assertEqual(E.CONFIG.get('web_proxy_from'), '192.0.2.0/24')
        self.assertFalse([k for k in said if 'left out' in k])

    def test_carried_from_a_backup_left_out(self):
        got = E.carry_file_settings(STORE, {'web_proxy_from': '0.0.0.0/0'})
        self.assertNotIn('web_proxy_from', got)

    def test_saved_before_is_used_as_before(self):
        # an upgrade: the value is in the database already - read, never a failure
        STORE.db.upsert('settings', 'k', {'k': 'web_proxy_from', 'v': json.dumps('0.0.0.0/0')})
        STORE.db.upsert('settings', 'k', {'k': 'web_proxy', 'v': json.dumps(1)})
        E.CONFIG.update(web_proxy=1, web_proxy_from='0.0.0.0/0')
        got = E.realip_desired(STORE)
        self.assertEqual(got['from'], ['0.0.0.0/0'])


class Czech(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            self.cs = json.load(f)

    def test_the_new_patterns(self):
        pats = {v['source'] for v in self.cs['patterns'].values()}
        for src in ('it went wrong after the files were written, the previous files are back: {0}',
                    'settings left out: refused here ({0})'):
            self.assertIn(src, pats)

    def test_the_round_s_entries_once(self):
        # those of 1.0.119 (z_589 on, pz_152 on): each source once in its part
        for part, pre, first in (('strings', 'z_', 589), ('patterns', 'pz_', 152)):
            srcs = [v['source'] for v in self.cs[part].values()]
            for k, v in self.cs[part].items():
                m = re.fullmatch(re.escape(pre) + r'(\d+)', k)
                if m and int(m.group(1)) >= first:
                    self.assertEqual(srcs.count(v['source']), 1, k)
                    self.assertTrue(v['text'].strip(), k)


class Changelog(unittest.TestCase):
    def test_one_list_no_line_twice(self):
        with open(os.path.join(ROOT, 'CHANGELOG.md'), encoding='utf-8') as f:
            text = f.read()
        sec = re.search(r'^## 1\.0\.119 .*?\n(.*?)^## ', text, re.S | re.M).group(1)
        items = [ln for ln in sec.strip().split('\n')]
        self.assertTrue(all(ln.startswith('- ') for ln in items), 'a blank line in the list')
        self.assertEqual(len(items), len(set(items)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
