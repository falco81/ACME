#!/usr/bin/env python3
"""Signed in by a load balancer or WAF in front of the enrolment pages (otp 1.0.239).

    python3 test/test_portal_sso.py      (or python3 -m unittest test.test_portal_sso)

A real daemon in a folder of its own (test/test_certs_core.py's way) and the directory of
test/mockldap.py. Off by default, and refused on without the balancers named or without a
key. Switched on, the name in the balancer's header is believed only from the balancers' own
address (X-Acme-Peer - nginx's $realip_remote_addr), with the key in X-Acme-Sso-Key - every
refusal in Events with its reason, the last of each kind on the card. A name the directory
does not know is refused; the same person again goes on in the same sign-in; switched off,
a sign-in by the balancer ends. And the page itself (web/index.php through php -S): headers
forged from a machine that is not a balancer give the password page, and an event.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
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
LB = '10.20.30.40'


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class PortalSso(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py

    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_directory': 'corp', 'portal_tries': 50, 'portal_wait_min': 5}})

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

    def setUp(self):
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)

    def sso(self, name, key, peer=LB, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d/api/portal/sso' % self.port,
                                     data=json.dumps({'name': name, 'key': key}).encode(),
                                     method='POST')
        req.add_header('X-Acme-Token', self.token)
        req.add_header('Content-Type', 'application/json')
        if peer is not None:
            req.add_header('X-Acme-Peer', peer)
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def events(self, text):
        got = self.ok('GET', '/api/events', args={'q': text})
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    def switched_on(self):
        st, got = self.call('POST', '/api/portal-sso', {'action': 'key'}, self.admin)
        self.assertEqual(st, 200, got)
        self.key = got['key']
        st, got = self.call('POST', '/api/settings', {'settings': {
            'portal_sso': 1, 'portal_sso_from': LB + '/32'}}, self.admin)
        self.assertEqual(st, 200, got)

    # -------------------------------------------------------------------------------------
    def test_01_off_by_default_and_refused_on_without_what_it_needs(self):
        self.assertEqual(self.py('print(json.dumps([E.DEFAULTS["portal_sso"], '
                                 'E.DEFAULTS["web_proxy"], E.DEFAULTS["portal_sso_header"], '
                                 'E.DEFAULTS["alerts_sso"]]))'), [0, 0, 'X-Acme-User', 0])
        st, got = self.call('POST', '/api/portal/sso', {'name': 'falco', 'key': 'x'})
        self.assertEqual(st, 404, got)
        st, info = self.call('GET', '/api/portal/info')
        self.assertIsNone(info.get('sso'))
        # No balancers named, no key: not switched on.
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_sso': 1}}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('balancers first', got.get('error', ''))
        st, got = self.call('POST', '/api/settings', {'settings': {
            'portal_sso': 1, 'portal_sso_from': LB}}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('make the key first', got.get('error', ''))
        # Behind a balancer: never on without the balancers named.
        st, got = self.call('POST', '/api/settings', {'settings': {'web_proxy': 1}}, self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_sso_header': 'Cookie'}},
                            self.admin)
        self.assertEqual(st, 400, got)

    def test_02_trust_chain(self):
        self.switched_on()
        st, info = self.call('GET', '/api/portal/info')
        self.assertEqual(info['sso']['header'], 'X-Acme-User')
        # Not from the balancer.
        st, got = self.sso('falco', self.key, peer='192.0.2.99')
        self.assertEqual(st, 401, got)
        self.assertNotIn('token', got)
        # No peer said at all: nginx not set up.
        st, got = self.sso('falco', self.key, peer=None)
        self.assertEqual(st, 503, got)
        # The key wrong, and missing.
        st, got = self.sso('falco', 'not-the-key-at-all-not-the-key')
        self.assertEqual(st, 401, got)
        st, got = self.sso('falco', '')
        self.assertEqual(st, 401, got)
        # A name the directory does not have.
        st, got = self.sso('nobody-here', self.key)
        self.assertEqual(st, 401, got)
        words = self.events('load balancer was refused')
        for why in ('not from the balancers named', 'has not been set up for it yet',
                    'is not the one set', 'is not there', 'the directory: there is no such account'):
            self.assertTrue(any(why in w for w in words), (why, words))
        # The key never in an event.
        self.assertFalse(any(self.key in w for w in words))
        # Right: a sign-in, the same person again the same one.
        st, got = self.sso('falco', self.key)
        self.assertEqual(st, 200, got)
        tok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertEqual(st, 200, me)
        self.assertTrue(me['me']['sso'])
        self.assertEqual(me['me']['name'], 'falco@corpnet.cz')
        st, again = self.sso('falco', self.key, session=tok)
        self.assertEqual((st, again.get('same')), (200, True), again)
        # Somebody else on the same browser: the one before ends.
        st, other = self.sso('marta', self.key, session=tok)
        self.assertEqual(st, 200, other)
        st, _ = self.call('GET', '/api/portal/me', None, tok)
        self.assertEqual(_.get('me'), None)
        # The card: the last of each kind on this node, refused and signed in.
        st, view = self.call('GET', '/api/portal-sso', None, self.admin)
        self.assertEqual(st, 200, view)
        self.assertTrue(view['on'] and view['key_set'])
        self.assertEqual(view['from'], [LB + '/32'])
        kinds = sorted(x['ok'] for x in view['last'])
        self.assertEqual(kinds, [False, True], view['last'])
        # Switched off: a sign-in by the balancer ends.
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_sso': 0}}, self.admin)
        self.assertEqual(st, 200, got)
        st, me = self.call('GET', '/api/portal/me', None, other['token'])
        self.assertIsNone(me.get('me'))
        # Kept as a row off (KEPT_OFF_KEYS): "switched off", not "never on".
        self.assertEqual(self.py('print(json.dumps(st.settings_saved().get("portal_sso")))'), 0)
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_sso': 1}}, self.admin)
        self.assertEqual(st, 200, got)

    def test_03_the_page_with_forged_headers(self):
        """From a machine that is not the balancer, with the header and a guessed key: the
        password page, and the refusal in Events."""
        if not shutil.which('php'):
            self.skipTest('no php here')
        self.switched_on() if not getattr(self, 'key', None) else None
        web = tempfile.mkdtemp(prefix='acme-sso-web-')
        shutil.rmtree(web)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        with open(os.path.join(web, 'router.php'), 'w') as f:
            # nginx passes ACME_PEER as a fastcgi_param; php -S has none - set from here.
            f.write("<?php\n$_SERVER['ACME_PEER'] = getenv('T_PEER') ?: '';\n"
                    "$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
                    "if ($p === '/' || $p === '/index.php') { chdir(__DIR__); require __DIR__ . '/index.php'; return true; }\n"
                    "return false;\n")
        port = free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                               env=dict(os.environ, T_PEER='192.0.2.99'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/router.php' % port, timeout=2)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.1)
            req = urllib.request.Request('http://127.0.0.1:%d/' % port)
            req.add_header('X-Acme-User', 'falco')
            req.add_header('X-Acme-Sso-Key', 'a-guessed-key-a-guessed-key-1234')
            with urllib.request.urlopen(req, timeout=60) as r:
                page = r.read().decode('utf-8', 'replace')
                cookies = r.headers.get_all('Set-Cookie') or []
            self.assertIn('id="in-pass"', page)
            self.assertIn('id="sso-said"', page)
            self.assertFalse(any(c.startswith('acme_portal=') and 'expires' not in c.lower()
                                 for c in cookies), cookies)
            self.assertTrue(any('from 192.0.2.99' in w and 'not from the balancers named' in w
                                for w in self.events('load balancer was refused')))
        finally:
            php.terminate()
            php.wait(10)
            shutil.rmtree(web, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
