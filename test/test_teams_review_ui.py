#!/usr/bin/env python3
"""Enterprise teams, review C2 (1.0.125): the look of the teams' pages.

    python3 test/test_teams_review_ui.py

In Chromium (test/teams_review_ui_page.js) against a real daemon and php -S, seeded as
test/test_teams_admin_ui.py and test/test_teams_portal_ui.py seed theirs, in Czech:

- the administration's team Overview: no tile label broken inside a word (CERTIFIKÁTY was cut
  CERTIFIKA / TY at 1400 px) or cut; the seven tiles in one row (1400), four and three (1024),
  two a row with the last across (390) - never one left alone;
- the portal: the members' built-in roles in Czech (Čtenář, not Viewer), the limit above a team
  said in Czech (90 dní, not 90 days), the tiles' lines whole ("ke schválení nebo zamítnutí",
  not "ke schválení nebo za…"), six tiles in rows of six, three or two;
- no error on either page.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_teams_admin_ui as TA      # noqa: E402  (the administration's seed)
import test_teams_portal_ui as TP     # noqa: E402  (the portal's seed)


def browser_here():
    node = shutil.which('node')
    if not node or not shutil.which('php'):
        return None
    if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                      cwd=ROOT).returncode:
        return None
    return node


def page(node, base, pw, mode):
    got = subprocess.run([node, os.path.join(HERE, 'teams_review_ui_page.js'), base, pw, mode,
                          os.environ.get('ACME_SHOTS', '')],
                         capture_output=True, text=True, timeout=600, cwd=ROOT)
    lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
    if not lines:
        raise AssertionError(got.stderr[-3000:])
    return json.loads(lines[-1])


def only_ours(base):
    """The seeding class without its own tests (they run in their own file)."""
    ns = {k: None for k in dir(base) if k.startswith('test_')}
    return type('Seeded' + base.__name__, (base,), ns)


class AdminLook(only_ours(TA.Pages)):
    def test_overview_tiles(self):
        node = browser_here()
        if not node:
            self.skipTest('no node, php or playwright here')
        php, base = self.pages()
        try:
            seen = page(node, base, self.pw, 'admin')
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen)
        self.assertEqual(seen['errors'], [], seen)
        for width, t in seen['tiles'].items():
            self.assertEqual(t['split'], [], (width, t))
            self.assertEqual(t['cut'], [], (width, t))
            self.assertIn('Certifikáty', t['labels'], (width, t))
            self.assertEqual(t['value'], '6', (width, t))
        self.assertEqual(seen['tiles']['1400']['rows'], [7])
        self.assertEqual(seen['tiles']['1024']['rows'], [4, 3])
        self.assertEqual(seen['tiles']['390']['rows'], [2, 2, 2, 1])
        self.assertTrue(seen['tiles']['390']['lastWide'])


class PortalLook(only_ours(TP.TeamsPortalUi)):
    def test_portal(self):
        node = browser_here()
        if not node:
            self.skipTest('no node, php or playwright here')
        base = self.serve()
        # a request waiting for the owner: the tile "Waiting for you" says its longest line
        st, got = self.call('POST', '/api/portal/login', {'name': 'treq', 'password': self.pw})
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/portal/cert_request', {
            'names': ['c2-waits.example.test'], 'issuer': 'self', 'team': 'Web'}, got['token'])
        self.assertEqual(st, 200, got)
        seen = page(node, base, self.pw, 'portal')
        self.assertNotIn('error', seen, seen)
        self.assertEqual(seen['errors'], [], seen)
        for width, t in seen['tiles'].items():
            self.assertEqual(t['split'], [], (width, t))
            self.assertEqual(t['cut'], [], (width, t))
        self.assertEqual(seen['tiles']['1400']['rows'], [6])
        self.assertEqual(seen['tiles']['1024']['rows'], [3, 3])
        self.assertEqual(seen['tiles']['390']['rows'], [2, 2, 2])
        # the built-in roles in Czech, none in English
        self.assertIn('Čtenář', seen['roles'])
        self.assertIn('Vlastník týmu', seen['roles'])
        for en in ('Viewer', 'Requester', 'Team owner', 'Approver'):
            self.assertNotIn(en, seen['roles'])
        # the longest validity above WebDev: Web's 90 days, in Czech
        self.assertTrue(any('90 dní' in a for a in seen['above']), seen['above'])
        self.assertFalse(any('days' in a for a in seen['above']), seen['above'])


class Source(unittest.TestCase):
    """What the pages are made of, read without a browser."""

    def read(self, name):
        with open(os.path.join(ROOT, 'web', 'assets', name), encoding='utf-8') as f:
            return f.read()

    def test_tile_label_never_inside_a_word(self):
        css = self.read('teams.css')
        rule = css[css.index('.tmx-tile-h{'):]
        rule = rule[:rule.index('}')]
        self.assertNotIn('anywhere', rule)
        self.assertIn('word-break:normal', rule)
        self.assertIn('hyphens:none', rule)
        self.assertNotIn('.tmx-tile-h > span{min-width:0;overflow-wrap:anywhere}', css)

    def test_portal_words(self):
        js = self.read('portal-teams.js')
        self.assertIn("tr(nW(eff[key], unit))", js)
        self.assertIn('builtin[String(x).toLowerCase()]', js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
