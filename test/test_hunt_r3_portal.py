#!/usr/bin/env python3
"""Bug hunt R run 3: the certificate portal.

    python3 test/test_hunt_r3_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_r3_portal_page.js) when node, php and Playwright are
here - in English and in Czech, at a phone's width.

- A certificate not issued yet that nothing issues (not renewed by itself, or its approval never
  recorded): its state tag in the list and in its dialog said "being issued" and pulsed for good
  (1.0.119 put only its Expires right) - now "not issued yet", as the administration says it. One
  a job is issuing still says "being issued".
"""
import json
import os
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

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class HuntR3Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/certs/save', {
            'name': 'r3-idle', 'names': ['r3-idle.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'local:viewer'})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def test_01_the_row_is_idle(self):
        st, got = self.call('POST', '/api/portal/login', {'name': 'viewer', 'password': self.pw})
        self.assertEqual(st, 200, got)
        st, got = self.call('GET', '/api/portal/certs', None, got['token'])
        self.assertEqual(st, 200, got)
        row = [r for r in got['rows'] if r['name'] == 'r3-idle'][0]
        # what the page reads: new, nothing issued, not renewed by itself, no job at work
        self.assertEqual(row['state'], 'new')
        self.assertFalse(row.get('not_after'))
        self.assertFalse(row.get('auto_renew'))
        self.assertFalse((row.get('job') or {}).get('live'))

    def test_02_the_page(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
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
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        seen = {}
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            for lang in ('en', 'cs'):
                got = subprocess.run([node, os.path.join(HERE, 'hunt_r3_portal_page.js'),
                                      'http://127.0.0.1:%d' % port, 'viewer', self.pw, lang],
                                     capture_output=True, text=True, timeout=240, cwd=ROOT)
                self.assertEqual(got.returncode, 0, got.stderr[-2000:])
                seen[lang] = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        words = {'en': ('not issued yet', 'being issued'), 'cs': ('zatím nevystaven', 'vydává se')}
        for lang, one in seen.items():
            self.assertNotIn('error', one, one.get('error'))
            self.assertEqual(one['errors'], [], lang)
            idle, busy = words[lang]
            # nothing at work: "not issued yet", dimmed, not pulsing - in the list and its dialog
            for where in ('idleRow', 'idleDialog'):
                self.assertEqual(one[where]['words'].lower(), idle, (lang, where, one))
                self.assertFalse(one[where]['pulse'], (lang, where, one))
                self.assertTrue(one[where]['dim'], (lang, where, one))
            # a job issuing it: "being issued", pulsing - as before
            self.assertEqual(one['busyRow']['words'].lower(), busy, (lang, one))
            self.assertTrue(one['busyRow']['pulse'], (lang, one))
            self.assertLessEqual(one['wide'], 0, (lang, one))


if __name__ == '__main__':
    unittest.main(verbosity=2)
