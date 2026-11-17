#!/usr/bin/env python3
"""Bug hunt q3 (1.0.119): the DNS server, DNS sets, Owners and teams, SSH keys.

    python3 test/test_hunt_q3_tabs.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_q3_tabs_page.js) when node, php and Playwright are
here.

- DNS server: a record of its own with TTL 0 was kept with the default TTL; one the server
  cannot write (an MX of a name alone) was kept and never answered - said only among the
  server's problems.
- ssh-keyscan: a host beginning with '-' was taken as an option of it.
- DNS sets: a set chosen for a function, waiting for Save, then renamed or deleted - Save said
  "there is no DNS set".
- Owners and teams: "Make it an owner" pressed twice - the second said "there is an owner ...
  already".
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
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class KeyscanArgs(unittest.TestCase):
    def test_host_is_never_an_option(self):
        from acmelib.certs import runtime
        seen = []

        def run(argv, **kw):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, 'h ssh-ed25519 AAAA\n', '')
        with mock.patch.object(runtime.shutil, 'which', return_value='/usr/bin/ssh-keyscan'), \
                mock.patch.object(runtime.subprocess, 'run', run):
            runtime.keyscan('-f/etc/passwd', 22, 5)
        argv = seen[0]
        self.assertEqual(argv[-2:], ['--', '-f/etc/passwd'])


class HuntQ3Tabs(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/certs/save', {
            'name': 'q3-legacy', 'names': ['q3-legacy.example.test'], 'issuer': '',
            'key_type': 'ec-256', 'auto_renew': False, 'owner': 'q3-legacy-owner'})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def records(self):
        return self.must('GET', '/api/dns')['records']

    def test_01_dns_record_values(self):
        st, got = self.call('POST', '/api/dns/record', {
            'name': 'q3mx.example.test', 'rtype': 'MX', 'value': 'mail.example.test'}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('10 mail.example.com', got['error'])
        st, got = self.call('POST', '/api/dns/record', {
            'name': 'q3srv.example.test', 'rtype': 'SRV', 'value': '1 2 3'}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertFalse([r for r in self.records() if r['name'] in ('q3mx.example.test',
                                                                      'q3srv.example.test')])
        # what the server writes is taken as before
        for rtype, value in (('MX', '10 mail.example.test.'), ('CNAME', 'Other.Example.test.'),
                             ('TXT', '"v=spf1 -all"'), ('CAA', '0 issue "letsencrypt.org"'),
                             ('SRV', '10 5 443 host.example.test'), ('NS', 'ns1.example.test'),
                             ('A', '192.0.2.10'), ('AAAA', '2001:db8::10')):
            st, got = self.call('POST', '/api/dns/record', {
                'name': 'q3ok.example.test', 'rtype': rtype, 'value': value}, self.admin)
            self.assertEqual(st, 200, (rtype, got))

    def test_02_dns_record_ttl_zero(self):
        self.must('POST', '/api/dns/record', {'name': 'q3ttl.example.test', 'rtype': 'TXT',
                                              'value': 'zero', 'ttl': 0})
        self.must('POST', '/api/dns/record', {'name': 'q3ttl2.example.test', 'rtype': 'TXT',
                                              'value': 'default'})
        got = {r['name']: r['ttl'] for r in self.records()}
        self.assertEqual(got['q3ttl.example.test'], 0)
        self.assertEqual(got['q3ttl2.example.test'], 60)

    def test_03_the_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
        self.must('POST', '/api/dns/record', {'name': 'q3ttl.example.test', 'rtype': 'TXT',
                                              'value': 'zero-again', 'ttl': 0})
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
            got = subprocess.run([node, os.path.join(HERE, 'hunt_q3_tabs_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw],
                                 capture_output=True, text=True, timeout=300, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # the choice followed the rename; the one of the set deleted went with it
        self.assertEqual(seen['pickShown'], 'q3 renamed', seen)
        self.assertEqual(seen['validation'], 'q3 renamed', seen)
        self.assertEqual(seen['mail'], '', seen)
        self.assertEqual(seen['dnsBad'], [], seen)
        # pressed twice: asked once, nothing refused
        self.assertEqual(seen['adopts'], 1, seen)
        self.assertEqual(seen['teamBad'], [], seen)
        self.assertEqual(seen['ttlCell'], '0', seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
