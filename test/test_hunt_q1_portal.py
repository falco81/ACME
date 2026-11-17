#!/usr/bin/env python3
"""Bug hunt q1 (1.0.119): the certificate portal.

    python3 test/test_hunt_q1_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way) and a directory that is
not there (test/mockldap.py); the pages from a copy of web/ through php -S, in Chromium
(test/hunt_q1_portal_page.js) when node, php and Playwright are here.

- A certificate owned by "group:" and a directory group's DN is in its members' list - it was
  theirs to download, and missing from the list (owner_of took the DN, mine() never asked).
- "Ask for a certificate", off at the limit and on again, says nothing of the limit any more.
- A certificate not issued yet that nothing issues (not renewed by itself) is not "being
  issued…", and the list is not asked for every 3 s for good because of it.
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
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
GROUP_DN = 'CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc'

# The sign-in of index.php with a certificate as the only way (no password, no Windows), as
# it is drawn then - back to it after the sign-in ran out (core.js notes that in the tab).
CERT_ONLY_PAGE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"></head><body class="app-shell">
<div class="wrap portal"><div class="signin"><div class="signbox"><div class="card">
<h1>Certificates</h1>
<p class="lede">Sign in with a certificate to see your certificates.</p>
<div id="mfa-box" data-stage="" hidden></div>
<form id="signin-form" hidden></form>
<div class="krb-box cert-box" id="cert-box" data-part="portal" data-auto="0" data-only="1"
     data-ready="1">
  <button class="btn cmd primary" type="button" id="cert-go"><span>Sign in with a
    certificate</span></button>
  <div class="said" id="cert-said"></div>
</div>
<span class="langpick" id="langpick"></span>
</div></div></div></div>
<script src="/assets/core.js"></script>
<script src="/assets/portal.js"></script>
<script>var PORTAL_GATE = null;</script>
<script>try { sessionStorage.setItem('acme-signed-out', '1'); } catch (e) { } portalDoor();</script>
</body></html>
'''


class HuntQ1Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_directory': 'corp',
            'portal_tries': 50, 'portal_cert_suffixes': 'example.test',
            'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.ids = {}
        for name, owner in (('q1-groupdn', 'group:' + GROUP_DN), ('q1-dn', GROUP_DN),
                            ('q1-cn', 'group:CERT_USERS'), ('q1-new', 'local:viewer')):
            cls.ids[name] = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': owner})['id']

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def portal(self, name, password):
        st, got = self.call('POST', '/api/portal/login', {'name': name, 'password': password})
        self.assertEqual(st, 200, got)
        return got['token']

    def test_01_group_dn_owner_in_the_list(self):
        tok = self.portal('falco', 'falco-password-1')
        st, got = self.call('GET', '/api/portal/certs', None, tok)
        self.assertEqual(st, 200, got)
        seen = {r['name']: r['via'] for r in got['rows']}
        for name in ('q1-groupdn', 'q1-dn', 'q1-cn'):
            self.assertEqual(seen.get(name), 'CERT_USERS', (name, seen))
        # ...and one of somebody else stays out of it
        self.assertNotIn('q1-new', seen)
        # a person of no such group sees none of them
        st, got = self.call('GET', '/api/portal/certs', None,
                            self.portal('outsider', 'outsider-password-1'))
        self.assertEqual(st, 200, got)
        self.assertFalse({'q1-groupdn', 'q1-dn', 'q1-cn'} & {r['name'] for r in got['rows']})

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
        with open(os.path.join(web, 'q1-certonly.html'), 'w', encoding='utf-8') as f:
            f.write(CERT_ONLY_PAGE)
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            got = subprocess.run([node, os.path.join(HERE, 'hunt_q1_portal_page.js'),
                                  'http://127.0.0.1:%d' % port, 'viewer', self.pw],
                                 capture_output=True, text=True, timeout=240, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # at the limit: off, and why
        self.assertTrue(seen['full']['disabled'], seen)
        self.assertIn('as many certificates as one person may', seen['full']['help'])
        # free again: on, and nothing of the limit left on it
        self.assertFalse(seen['free']['disabled'], seen)
        self.assertEqual(seen['free']['help'], '', seen)
        self.assertIsNone(seen['free']['label'], seen)
        # not issued, not renewed by itself: nothing at work - said so, and not asked every 3 s
        self.assertNotIn('being issued', seen['newRow'])
        self.assertEqual(seen['asksIn10s'], 0, seen)
        self.assertLessEqual(seen['wide'], 0, seen)
        # the certificate the only way in: why the page is back, said there
        self.assertEqual(seen['certOnly'], 'your sign-in has run out - sign in again', seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
