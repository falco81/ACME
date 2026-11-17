#!/usr/bin/env python3
"""Bug hunt r5 (1.0.124), review of the pages changed in runs 1-4.

    python3 test/test_hunt_r5_reviewfront.py

- Find a setting (1.0.124 offered only what the account can open): a read-only account no longer
  found the settings of Monitoring - a pane whose rail button it does not see but any account may
  open (data-reads="all", as showPane lets it); found and opened again.
- The administration's sign-in in EN/CS at 1400 and 390: the page's own words for an empty name
  or password, and the real sign-in still goes through.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_r5_reviewfront_page.js) when node, php and Playwright are here.
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

    def test_find_lets_readers_find_what_showpane_opens(self):
        js = read('web/assets/admin.js')
        self.assertIn("if (nb && nb.hidden && nb.dataset.reads !== 'all') return false;", js)


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
            got = subprocess.run([node, os.path.join(HERE, 'hunt_r5_reviewfront_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, timeout=300, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        words = {'en': ('type your name', 'type your password'),
                 'cs': ('napište své jméno', 'napište své heslo')}
        for lang in ('en', 'cs'):
            for width in (1400, 390):
                s = seen['signin'][lang + str(width)]
                self.assertEqual((s['empty'], s['noPass']), words[lang], s)
                self.assertTrue(s['signedIn'], s)
                self.assertLessEqual(s['wide'], 0, s)
        self.assertTrue(seen['monKeys'], seen)
        self.assertTrue(seen['adminMon'], seen)
        # read only: Monitoring's settings found and opened, Alerts and reports' still not
        self.assertTrue(seen['roMon'], seen)
        self.assertEqual(seen.get('roMonPane'), 'monitor', seen)
        self.assertEqual(seen['roAlerts'], [], seen)

if __name__ == '__main__':
    unittest.main(verbosity=2)
