#!/usr/bin/env python3
"""Bug hunt t8 (1.0.127): a sweep of the administration's pages.

    python3 test/test_hunt_rt8_uisweep.py

- Settings -> Request profiles at a phone's width: the table is wider than its box and the
  browser laid every column out at its narrowest word, so the profile's name and description
  stood one word a line (the Profile column 92 px). Its first column keeps 160 px under 640 px
  (reqprofiles.css); at 768 and 1400 px nothing changes, and no other table is touched.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_rt8_uisweep_page.js) when node, php and Playwright are here.
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

    def test_profile_column_kept_on_a_phone_only(self):
        css = read('web/assets/reqprofiles.css')
        rule = '.rp-table td:first-child{min-width:160px}'
        self.assertEqual(css.count(rule), 1)
        # only inside the phone's media query
        m = re.search(r'@media \(max-width:640px\)\{(.*?)\n\}', css, re.S)
        self.assertIsNotNone(m)
        self.assertIn(rule, m.group(1))


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

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
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        self.ok('POST', '/api/reqprofiles/save', {
            'name': 'Web server certificate', 'issuer': 'own',
            'description': 'For the intranet web servers of the company, issued at once',
            'suffixes': ['example.test', 'intranet.example.test'],
            'key_types': ['ec-256', 'rsa-2048'], 'key_default': 'ec-256'})
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
            drv = subprocess.run([node, os.path.join(HERE, 'hunt_rt8_uisweep_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=300)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['seen']), 6, seen)
        for one in seen['seen']:
            self.assertEqual(one['hscroll'], 0, one)
            # "Web server certificate" on at most two lines, never a word a line
            self.assertLessEqual(one['nameLines'], 2, one)
            self.assertGreaterEqual(one['profile'], 150, one)


if __name__ == '__main__':
    unittest.main(verbosity=2)
