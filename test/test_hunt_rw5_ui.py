#!/usr/bin/env python3
"""Hunt w5, area ui: every page after the rounds w1-w4 changed the assets.

    python3 test/test_hunt_rw5_ui.py
    ACME_SHOTS=DIR     screenshots there
    ACME_RW5_CS=FILE   {English: Czech} merged into a copy of cs.json for the pages

The sweep (test/hunt_rw5_ui_page.js): every main tab as a full administrator, a reader and a
certificate administrator of one team, every Settings pane at 390 px, the portal's every view
for a member - English and Czech, 1400 and 390 px: no error, no page wider than the window.
Compared side by side with the pages of 1.0.142 nothing moved; what was found:

- Ctrl+K in Czech: the events it found were said in English ("shop ends in 2 days 23 h and is
  not renewed by itself", "certificates") - the whole row was data. The Events tab says the
  same words and kind in Czech; so does the palette now (the time and who stay data).
- The column menu opened with the mouse put the focus on its first line, which wore the
  browser's focus ring as if chosen from the keyboard. The menu itself takes the focus then
  (the arrows go on from there); from the keyboard its first line, as before.
- The portal's form to ask for a certificate, a team whose request profiles are "none at all"
  (an empty list): "only from the profiles" with nothing after it, in English in Czech too.
  An empty list of names under the same.
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

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts, php -S)

SHOTS = os.environ.get('ACME_SHOTS', '')
CS = os.environ.get('ACME_RW5_CS', '')


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):
    def test_palette_event_words_translated(self):
        js = src('web/assets/palette.js')
        self.assertIn("said: kind === 'event', subParts: parts", js)
        self.assertIn("t.appendChild(it.data && !it.said ? noI18n(el('span', '', it.label))", js)

    def test_cols_menu_mouse_focus(self):
        js = src('web/assets/cols.js')
        self.assertIn('if (!menu._kb) { menu.tabIndex = -1; want = menu; }', js)
        self.assertIn('.cols-menu:focus{outline:none}', src('web/assets/acme.css'))

    def test_empty_policy_lists(self):
        js = src('web/assets/portal-teams.js')
        self.assertIn("'from no request profile'", js)
        self.assertIn("'no names at all'", js)


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        if CS and os.path.isfile(CS):
            os.environ['ACME_EXTRA_CS'] = CS
        RP.Pages.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'wreq', 'role': 'readonly',
                                        'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'WNone', 'members': [{'who': 'local:wreq', 'roles': ['Requester']}],
            'policy': {'profiles': [], 'suffixes': ['web.example.test']}})

    def test_pages_rw5(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw5_ui_page.js'), base, self.pw,
                                  SHOTS], capture_output=True, text=True, timeout=2400, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(seen['overflow'], {})
        # every role saw its tabs, every pane at 390, every portal view
        self.assertEqual(len(seen['tabs']), 12)
        for tag, tabs in seen['tabs'].items():
            self.assertIn('certs', tabs, tag)
            self.assertIn('settings', tabs, tag)
        for tag, n in seen['panes'].items():
            self.assertGreater(n, 10, tag)
        self.assertEqual(len(seen['views']), 4)
        for tag, views in seen['views'].items():
            self.assertIn('certs', views, tag)
        # Ctrl+K: events in the page's language
        for lang in ('en', 'cs'):
            ev = seen['palette'][lang]
            self.assertTrue(ev, lang)
            words = ' '.join(r[0] for r in ev)
            kinds = [r[1] for r in ev]
            if lang == 'cs':
                self.assertNotIn(' added by ', words)
                self.assertIn('přidal', words)
                self.assertTrue(any('certifikáty' in k for k in kinds), kinds)
            else:
                self.assertIn('added by', words)
                self.assertTrue(any('certificates' in k for k in kinds), kinds)
            # the time and who stay as they are
            self.assertTrue(any('tester' in k for k in kinds), kinds)
        # the column menu by the mouse
        for lang in ('en', 'cs'):
            c = seen['cols'][lang]
            self.assertEqual((c['open'], c['menuFocused'], c['lineFocused']), (True, True, False),
                             (lang, c))
            self.assertEqual(c['down'], 0, (lang, c))
            self.assertTrue(c['closed'], (lang, c))
            self.assertTrue(c['kbLine'], (lang, c))
        # the portal: no request profile at all, said so
        self.assertEqual(len(seen['ask']), 4)
        for tag, parts in seen['ask'].items():
            text = ' | '.join(parts)
            self.assertNotIn('only from the profiles', text, tag)
            if '-en-' in tag:
                self.assertIn('from no request profile', text, tag)
                self.assertIn('only names under web.example.test', text, tag)
            else:
                self.assertIn('jen jména pod web.example.test', text, tag)
                if CS:
                    self.assertIn('ze žádného profilu žádosti', text, tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
