"""1.0.139 polish: built-in role names in Czech events, whole-sentence refusals of the team
governance, the DNS sets' row tools at phone width.

    python3 test/test_hunt_r139_polish.py
"""
import json
import sys
import os
import shutil
import subprocess
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


class Source(unittest.TestCase):
    def test_dnssets_tools_header(self):
        with open(os.path.join(ROOT, 'web/assets/dnssets.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("'Used for', {words: '', cls: 'rowtools'}]", js)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, ROOT)
    unittest.main()
