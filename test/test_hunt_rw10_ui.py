#!/usr/bin/env python3
"""Hunt w10, area ui: a last pass over every page after the asset changes of w6-w9.

    python3 test/test_hunt_rw10_ui.py

Every tab and Settings pane for a full administrator, a reader and a certificate administrator,
the portal's every view (a reader and a requester), the dialogs the panes and tabs open - English
and Czech, 1400 and 390 px: no error, no page wider than the window, nothing left in English.
What was found:

- The time picker (Events, the cluster's history): Escape left its window open - over the next
  tab too - and the keyboard never reached it (put at the end of the page); it stayed where it
  was opened when the page scrolled. Now as the other pickers: it opens with the focus on the
  window chosen, Escape closes it and gives the focus back (a dialog around it stays), the focus
  going elsewhere closes it, it follows its button and goes when the button does.
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


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):
    def test_time_picker_keys(self):
        js = src('web/assets/core.js')
        at = js.index('function timePicker(')
        body = js[at:js.index('function tpQuery(', at)]
        self.assertIn("if (e.key === 'Escape' && pop) { e.preventDefault(); e.stopPropagation(); close(); main.focus(); }", body)
        self.assertIn("document.addEventListener('keydown', keys, true);", body)
        self.assertIn("document.removeEventListener('keydown', keys, true);", body)
        self.assertIn("document.addEventListener('focusin', away, true);", body)
        self.assertIn("window.addEventListener('scroll', place, true);", body)
        self.assertIn("pop.querySelector('.tp-q.on') || pop.querySelector('.tp-q')", body)


class Pages(RP.Pages):
    test_pages = None

    def test_time_picker_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw10_ui_page.js'), base, self.pw],
                                 capture_output=True, text=True, timeout=1200, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4)
        for tag, r in seen['runs'].items():
            for k in ('open', 'focusOn', 'escClosed', 'focusBack', 'kbOpen', 'kbPicked', 'kbClosed',
                      'tabClosed'):
                self.assertTrue(r[k], (tag, k, r))
            self.assertEqual(r['expanded'], 'true', (tag, r))
            if 'modalPickOpen' in r:
                self.assertTrue(r['modalPickOpen'] and r['modalPickClosed'] and r['modalStays'],
                                (tag, r))


if __name__ == '__main__':
    unittest.main(verbosity=2)
