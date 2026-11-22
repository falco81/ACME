"""1.0.139 polish: built-in role names in Czech events, whole-sentence refusals of the team
governance, the DNS sets' row tools at phone width.

    python3 test/test_hunt_r139_polish.py
"""
import json
import sys
import os
import shutil
import subprocess
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def say(*texts):
    out = subprocess.run(['node', os.path.join(HERE, 'i18n_cs_say.js'), ROOT] + list(texts),
                         capture_output=True, text=True, timeout=120, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


@unittest.skipUnless(shutil.which('node'), 'no node here')
class Czech(unittest.TestCase):
    def test_builtin_role_after_the_role(self):
        got = say('jan asks for the role Approver on the team Web for 4 hour(s): x',
                  'the role Viewer was saved', 'the role Approvers was saved')
        self.assertIn('roli Schvalovatel', got['jan asks for the role Approver on the team Web for 4 hour(s): x'])
        self.assertEqual(got['the role Viewer was saved'], 'role Čtenář je uložena')
        # a role of one's own is a name - never translated
        self.assertEqual(got['the role Approvers was saved'], 'role Approvers je uložena')

    def test_one_word_names_elsewhere_stay(self):
        got = say('done · 0 s', 'Account “Viewer”')
        self.assertEqual(got['done · 0 s'], 'hotovo · 0 s')

    def test_refusals_whole_sentences(self):
        from acmelib.certs import teamgov as G
        for st in ('granted', 'declined', 'cancelled', 'ended', 'expired'):
            words = G._already(st)
            self.assertTrue(words.endswith(' already'))
            self.assertIsNotNone(say(words)[words], words)
        for words in list(G._REVIEW_ALREADY.values()) + [x % 'jan' for x in G._ITEM_ALREADY.values()] + [
                'it was decided meanwhile', 'you may not see that', 'that is you',
                'only a full administrator views the pages as somebody else', 'you may not see the team Web']:
            self.assertIsNotNone(say(words)[words], words)


class RotateSchedule(unittest.TestCase):
    """An agent that refused acme's new command key once is tried again a day later (1.0.139)."""
    def run_due(self, st):
        from unittest import mock
        from acmelib.certs import agent_guard as AG
        moved = []

        class FakeG:
            QUIET_S = 3600

            @staticmethod
            def state(store, i):
                return st
        with mock.patch.object(AG, 'opts', lambda s, i: {'rotate': True, 'rotate_days': 90}), \
                mock.patch.object(AG, '_G', lambda: FakeG), \
                mock.patch.object(AG, '_cmd_current', lambda s: ({'fp': 'b' * 64}, time.time())), \
                mock.patch.object(AG, 'pinned_fp', lambda s, x: 'a' * 64), \
                mock.patch.object(AG, 'can', lambda x, w: True), \
                mock.patch.object(AG, 'cmd_move', lambda s, r, by: moved.append(by)):
            AG._rotate_due(None, {'id': 1, 'name': 'x'}, st)
        return moved

    def base(self, **kw):
        st = {'cert_fp': 'f', 'last_seen': time.time(), 'features': ['cmdkey']}
        st.update(kw)
        return st

    def test_retried_after_a_day(self):
        from acmelib.certs import agent_guard as AG
        self.assertEqual(self.run_due(self.base()), ['the schedule'])
        self.assertEqual(self.run_due(self.base(key_said='busy', key_said_at=time.time())), [])
        self.assertEqual(self.run_due(self.base(key_said='busy', key_said_at=time.time() - AG.RETRY_S - 5)),
                         ['the schedule'])
        # set before 1.0.139 (no time kept): tried again too
        self.assertEqual(self.run_due(self.base(key_said='busy')), ['the schedule'])
        self.assertEqual(self.run_due(self.base(key_said=AG.TOO_OLD)), [])


class RestoreGap(unittest.TestCase):
    """The jobs sent between a backup and its restore are no stranger's in the chain (1.0.139)."""
    class Store:
        def __init__(self, newest):
            self.meta = {}
            self.newest = newest
            outer = self

            class Db:
                @staticmethod
                def row(sql, args=()):
                    return {'ts': outer.newest if outer.newest < args[0] else None}
            self.db = Db

        def get_meta(self, k):
            return self.meta.get(k)

        def set_meta(self, k, v):
            self.meta[k] = v

    def test_gap(self):
        from unittest import mock
        from acmelib.certs import agent_guard as AG
        now = time.time()
        store = self.Store(now - 3 * 86400)
        AG.restore_mark(store, now - 5)
        problems = []
        st = {'enabled_at': now - 30 * 86400}
        with mock.patch.object(AG, '_problem', lambda *a, **k: problems.append(a[4])):
            self.assertEqual(AG._mark(store, {'id': 1, 'name': 'x'}, st,
                                      {'job': 'j1', 'ts': now - 86400, 'op': 'deploy', 'n': 4}),
                             'restore')
            self.assertEqual(problems, [])
            # older than the backup: still a stranger's
            self.assertEqual(AG._mark(store, {'id': 1, 'name': 'x'}, st,
                                      {'job': 'j2', 'ts': now - 10 * 86400, 'op': 'deploy', 'n': 3}),
                             'unknown')
            self.assertEqual(len(problems), 1)
        self.assertIn("restore: ['between a backup and its restore'",
                      open(os.path.join(ROOT, 'web/assets/agents.js'), encoding='utf-8').read())
        self.assertEqual(say('between a backup and its restore')['between a backup and its restore'],
                         'mezi zálohou a její obnovou')


class Source(unittest.TestCase):
    def test_dnssets_tools_header(self):
        with open(os.path.join(ROOT, 'web/assets/dnssets.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("'Used for', {words: '', cls: 'rowtools'}]", js)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, ROOT)
    unittest.main()
