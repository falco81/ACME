#!/usr/bin/env python3
"""Hunt R t9 (the portal's team workspace, web/assets/portal-teams.js):

    python3 test/test_hunt_rt9_portalteams.py

- the file parses: an apostrophe inside a single-quoted string ("the team's actions") was a
  syntax error - the whole team workspace never started (sign-in hung on an empty page);
- a declined action shows its reason to the person who asked (the one declining is told so);
- an action's server words (English) are not shown raw - a revocation's reason in the page's
  language;
- "Enrol servers": a code made for another team is named after that team, and the codes of the
  teams below are listed (and revoked) there.
"""
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JS = os.path.join(ROOT, 'web', 'assets', 'portal-teams.js')


def src():
    with open(JS, encoding='utf-8') as f:
        return f.read()


def fn(text, name):
    at = text.index('function %s(' % name)
    nxt = re.search(r'\nfunction \w+\(', text[at + 10:])
    return text[at:at + 10 + (nxt.start() if nxt else len(text))]


class PortalTeamsRt9(unittest.TestCase):
    def test_parses(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        got = subprocess.run([node, '--check', JS], capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)

    def test_declined_reason_shown(self):
        card = fn(src(), 'actionCard')
        self.assertIn("a.state === 'declined'", card)
        self.assertIn('.why', card)

    def test_action_words_not_raw(self):
        card = fn(src(), 'actionCard')
        self.assertNotIn("if (a.words) meta.appendChild(data('span', 'muted', a.words));", card)
        self.assertIn("'reason: {0}'", card)

    def test_enrol_title_and_list(self):
        d = fn(src(), 'enrolDialog')
        self.assertIn("tr('Servers of {0}').replace('{0}', forTeam)", d)
        self.assertNotIn("tr('Servers of {0}').replace('{0}', team)", d)
        self.assertIn("'&below=1'", d)


if __name__ == '__main__':
    unittest.main(verbosity=2)
