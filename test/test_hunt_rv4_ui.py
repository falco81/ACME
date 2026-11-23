#!/usr/bin/env python3
"""Hunt v4, area ui: the forms and dialogs of the administration pages.

    python3 test/test_hunt_rv4_ui.py
    ACME_RV4_CS=FILE   {English: Czech} merged into the copy's cs.json (before they are in it)
    ACME_SHOTS=DIR     screenshots there

- "Add a key for …" (Settings → SSH keys), a backup destination's "Use my own" key and client
  certificate, and the import of a locked configuration closed their popup before the daemon
  had looked at what was pasted: a line it refused, or a wrong passphrase, and the key pasted
  into it was gone (the file chosen again). They now close once it is taken, and are pressed
  once.
- "Add the user" (Settings → Local users) could be pressed again while the first was on its way.
- Add a certificate: names pasted into "Paste many…" and not added yet were left behind by Next
  ("it needs at least one name", or a certificate with only the rows' names); Next takes them.
- Long names ran out of the wizard's right edge: the name chips at 390 px (nowrap on a phone),
  the name-by-name table of the validation and the review's common name at any width.
- The daemon's refusals of a directory's form ("say which servers to ask first", ...), of a
  team's webhooks, reviews and exclusive pairs stayed English on the Czech page
  (cs_rv4_ui.json).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts, php -S)

CS = os.environ.get('ACME_RV4_CS', '')
SHOTS = os.environ.get('ACME_SHOTS', '')


def src(name):
    with open(os.path.join(ROOT, 'web', 'assets', name), encoding='utf-8') as f:
        return f.read()


def button(js, words):
    """The source of one popup button {words: '<words>' ... go: function ... }"""
    i = js.index("words: '%s'" % words)
    j = js.index('}}', i)
    return js[i:j]


class Source(unittest.TestCase):
    def test_closed_once_taken(self):
        js = src('admin.js')
        for words in ('Keep this key', 'Keep this certificate', 'Exactly the file',
                      'Add to what is here'):
            b = button(js, words)
            self.assertNotIn('close: true', b, words)
        add = js[js.index('function skAdd()'):js.index('function skDrop(')]
        self.assertNotIn("icon: 'add', close: true", add)
        self.assertIn('busy(b, true)', add)
        self.assertIn('modalStill(tk)', add)
        imp = js[js.index("$('ex-file').onchange"):js.index('/* ---- about')]
        self.assertIn('function importGo(b, replace)', imp)
        self.assertIn('busy(b, true)', imp)

    def test_add_user_once(self):
        js = src('admin.js')
        add = js[js.index('function osuAdd('):js.index('function osuEdit(')]
        self.assertIn('busy(b, true)', add)
        self.assertIn('busy(b, false)', add)

    def test_pasted_names_taken(self):
        js = src('certs.js')
        names = js[js.index('function drawNames(host)'):js.index('function drawKey(host)')]
        read = names[names.index('read = function'):]
        self.assertIn('pasteGo.onclick()', read[:600])

    def test_long_names_css(self):
        css = src('certs.css')
        self.assertTrue(re.search(r'#modal-body \.ct-name \{ white-space: normal; \}', css))
        self.assertIn('table.ct-cmaptable td:first-child > .mono{display:inline-block;'
                      'width:max-content', css)
        self.assertIn('.ct-wbody table.plain.tight td > span.mono{white-space:normal', css)

    def test_czech_file(self):
        if not CS or not os.path.isfile(CS):
            self.skipTest('ACME_RV4_CS not given')
        with open(CS, encoding='utf-8') as f:
            cs = json.load(f)
        for en in ('say which servers to ask first',
                   'say where to look (the base) first: DC=example,DC=local',
                   "a webhook's address starts with https://"):
            self.assertIn(en, cs)
            self.assertNotEqual(cs[en], en)


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        if CS and os.path.isfile(CS):
            os.environ['ACME_EXTRA_CS'] = CS
        RP.Pages.setUpClass.__func__(cls)

    def test_pages_rv4(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rv4_ui_page.js'), base, self.pw,
                                  SHOTS], capture_output=True, text=True, timeout=1500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4)
        for r in seen['runs']:
            tag = '%s %s' % (r['lang'], r['w'])
            # the refused key: the popup and what was pasted stay, the refusal said, sent once
            self.assertEqual(r['skPresses'], 1, tag)
            self.assertTrue(r['sk']['open'], (tag, r['sk']))
            self.assertEqual(r['sk']['kept'], 'ssh-ed25519 notakey me@laptop', tag)
            self.assertTrue(r['sk']['toast'], tag)
            self.assertTrue(r['rb']['open'], (tag, r['rb']))
            self.assertIn('not a key at all', r['rb']['kept'], tag)
            self.assertTrue(r['rb']['toast'], tag)
            self.assertTrue(r['imp']['open'], (tag, r['imp']))
            self.assertEqual(r['imp']['kept'], 'not-the-passphrase', tag)
            self.assertTrue(r['imp']['toast'], tag)
            if r['lang'] == 'cs':
                self.assertIn('heslová fráze', r['imp']['toast'], tag)
                if CS:
                    self.assertEqual(r['dirSaid'], 'nejdřív uveďte, kterých serverů se ptát', tag)
            else:
                self.assertEqual(r['dirSaid'], 'say which servers to ask first', tag)
            # the wizard: the pasted names taken by Next, no step wider than the popup
            steps = r['steps']
            self.assertGreaterEqual(len(steps), 7, (tag, steps))
            self.assertEqual(steps[0]['toast'], '', (tag, steps[0]))
            self.assertTrue(any(s['rows'] == 12 for s in steps), (tag, steps))
            self.assertEqual(steps[-1]['chips'], 12, (tag, steps[-1]))
            for s in steps:
                self.assertEqual(s['hs'], 0, (tag, s))
            self.assertEqual(r['pageHs'], 0, tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
