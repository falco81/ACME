#!/usr/bin/env python3
"""Bug hunt r4 (1.0.124): the Settings panes of the administration.

    python3 test/test_hunt_r4_settingsui.py

- The administration's sign-in form had `required` and no check of its own: an empty name or
  password got the browser's own bubble, in the browser's language. Now `novalidate` and the
  page's words ("type your name" / "type your password"), as the portal.
- Find a setting: "Sign in with a password" of the administration and of the portal said
  "adminsignin" / "portalsignin" as its place, and choosing it opened the first pane.
- Find a setting as read only (or cert admin): the settings of panes and cards only a full
  administrator opens (Alerts and reports, Proxy, the firewall's settings…) were offered, and
  choosing one opened the first pane.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_r4_settingsui_page.js) when node, php and Playwright are here.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):

    def test_signin_form_checks_itself(self):
        page = read('web/admin/index.php')
        form = re.search(r'<form id="signin-form" autocomplete="on"[^>]*>', page).group(0)
        self.assertIn('novalidate', form)
        self.assertIn("said.textContent = noName ? 'type your name' : 'type your password';", page)

    def test_find_knows_the_signin_cards(self):
        js = read('web/assets/admin.js')
        self.assertIn("adminsignin: 'people', portalsignin: 'portal'", js)
        self.assertIn('&& mayOpen(s);', js)


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'hunt_r4_settingsui_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, timeout=300, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # the sign-in: the page's own words, in Czech
        self.assertTrue(seen['novalidate'], seen)
        self.assertEqual(seen['emptySaid'], 'napište své jméno', seen)
        self.assertEqual(seen['noPassSaid'], 'napište své heslo', seen)
        self.assertEqual(seen['focused'], 'in-pass', seen)
        # a full administrator: the sign-in cards by their panes
        self.assertEqual(seen['adminHits'][0][1], 'Accounts', seen)
        self.assertEqual(seen['adminPane'], 'people', seen)
        self.assertTrue(seen['adminItemShown'], seen)
        self.assertEqual(seen['portalHits'][0][1], 'The enrolment pages', seen)
        self.assertGreater(seen['alertsForAdmin'], 0, seen)
        # read only: nothing it cannot open; what it can, still found
        self.assertEqual(seen['roAlerts'], [], seen)
        self.assertEqual(seen['roFw'], [], seen)
        self.assertGreater(seen['roCodes'], 0, seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
