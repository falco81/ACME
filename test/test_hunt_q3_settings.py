#!/usr/bin/env python3
"""Bug hunt q3 (1.0.119): the Settings tab - accounts, message texts, backups.

    python3 test/test_hunt_q3_settings.py

The pages in a browser (test/hunt_q3_settings_page.js) when node and Playwright are here:

* Message texts: the portal's sign-in code by mail and SSH's were both "The sign-in code by mail"
  in the list of e-mails (and the same for SMS) - now by their whole titles.
* Backups: the list of what was sent, the backups at a destination and the question before one is
  put back said the time as the browser's language has it (11/17/2026, 2:06:09 AM), not as every
  other column (17-11-2026 02:06:09).
* A backup put back: the settings and the Backups pane drawn again, not left as they were until F5.
* Accounts at a phone's width: the box to find the directory's groups by (min-width 340 px) put
  the page 4 px wider than the screen.
"""
import json
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            return json.loads(line)
    raise AssertionError('no JSON in %r' % text[-2000:])


class Source(unittest.TestCase):

    def test_no_browser_dates_in_backups(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            js = f.read()
        a = js.index('function drawRbRuns(')
        b = js.index('function rbRestoreWatch(')
        self.assertNotIn('toLocaleString(numLang())', js[a:b])

    def test_group_box_fits_a_phone(self):
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            page = f.read()
        tag = re.search(r'<input[^>]*id="ag-like"[^>]*>', page, re.S).group(0)
        self.assertNotIn('min-width:340px', tag)


class Pages(unittest.TestCase):

    def test_settings_pages(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60, cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'hunt_q3_settings_page.js'),
                              os.path.join(ROOT, 'web')], capture_output=True, text=True,
                             timeout=300, cwd=ROOT)
        out = last_json(got.stdout or '{}')
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
