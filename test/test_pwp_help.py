#!/usr/bin/env python3
"""The password policy of the local users explained as on otp (1.0.47): an (i) on every rule,
its words, the command line's name of it and the built-in default - and the command line taking
its switches as on/off.

    python3 test/test_pwp_help.py
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-pwph-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


class Page(unittest.TestCase):
    def setUp(self):
        self.js = read('web', 'assets', 'admin.js')
        i = self.js.index('var PWP_HELP = {')
        self.help = self.js[i:self.js.index('};', i)]

    def test_every_rule_explained(self):
        keys = set(re.findall(r'^\s+(\w+): \'', self.help, re.M))
        self.assertEqual(keys, set(E.PWP_DEFAULT) | {'runs'})

    def test_every_field_has_its_i(self):
        i = self.js.index('function pwpCard(d) {')
        card = self.js[i:self.js.index('/* What each node has in effect', i)]
        for k in set(E.PWP_DEFAULT) - {'managed'}:
            self.assertRegex(card, r"'%s'[,)]" % k, k)
        self.assertIn("pwpInfoOn(on.box, 'managed')", card)
        self.assertIn("pwpInfoOn(runs.box, 'runs')", card)

    def test_the_command_line_named(self):
        self.assertIn("acme --local-policy-set ", self.help + self.js)
        self.assertNotIn('otp', self.help.replace('as otp 1.0.251', ''))

    def test_in_czech(self):
        cs = json.loads(read('web', 'lang', 'cs.json'))
        have = {v['source'] for sec in ('strings', 'patterns') for v in cs[sec].values()}
        for t in re.findall(r":\s*'((?:[^'\\]|\\.)*)'", self.help):
            self.assertIn(t.replace("\\'", "'"), have)


class CommandLine(unittest.TestCase):
    def run_set(self, *kv):
        store = E.Storage(E.open_db())
        args = types.SimpleNamespace(local_policy_set=list(kv))
        out = io.StringIO()
        with mock.patch.object(E, 'cli_store', return_value=store), \
                mock.patch.object(E, 'cli_who', return_value='test'), \
                mock.patch.object(E, 'osu_view', return_value={'nodes': []}), \
                contextlib.redirect_stdout(out):
            rc = E.cli_local_policy(args, None)
        return rc, out.getvalue(), E.pwp_conf(store)

    def test_switches_as_words(self):
        rc, said, c = self.run_set('managed=on', 'dictcheck=off', 'usercheck=no')
        self.assertFalse(rc, said)
        self.assertTrue(c['managed'])
        self.assertEqual((c['dictcheck'], c['usercheck']), (0, 0))
        rc, said, c = self.run_set('dictcheck=on')
        self.assertEqual(c['dictcheck'], 1)

    def test_a_switch_of_another_word_refused(self):
        rc, said, _ = self.run_set('dictcheck=maybe')
        self.assertEqual(rc, 2)
        self.assertIn('on or off', said)


if __name__ == '__main__':
    unittest.main()
