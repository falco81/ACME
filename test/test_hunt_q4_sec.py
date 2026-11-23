#!/usr/bin/env python3
"""The hunt of 1.0.119, round Q4 - the request path and signing in: each hole shut, checked here.

    python3 test/test_hunt_q4_sec.py

- whoami (the PHP pages' gates: nginx's question before a big body, a package or a database
  sent) reads the account as every other route does: signed by acme, of a role of these pages;
- web_proxy_from never every address (0.0.0.0/0, ::/0): anybody's X-Forwarded-For was the
  client's address then - past the counts of wrong passwords and the sign-in protection;
- the PHP pages count a session's cookies as PHP names them: a planted "acme.session" is
  $_COOKIE['acme_session'] to PHP, and was not counted as a second one.
"""
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-q4sec-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)


class Api(object):
    """The daemon's API as the pages reach it: HTTP on 127.0.0.1, with the token."""
    srv = None

    @classmethod
    def start(cls):
        if cls.srv is None:
            cls.token = E.api_token(make=True)
            cls.srv = E.ApiHttpServer(('127.0.0.1', 0), E.ApiHandler)
            cls.srv.daemon_threads = True
            cls.srv.daemon = DAEMON
            threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        return cls

    @classmethod
    def stop(cls):
        if cls.srv is not None:
            cls.srv.shutdown()
            cls.srv.server_close()
            cls.srv = None

    @classmethod
    def ask(cls, method, path, session='', body=None):
        c = http.client.HTTPConnection('127.0.0.1', cls.srv.server_address[1], timeout=20)
        head = {'X-Acme-Token': cls.token, 'X-Acme-Client': '192.0.2.7'}
        if session:
            head['X-Acme-Session'] = session
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            head['Content-Type'] = 'application/json'
        c.request(method, path, body=data, headers=head)
        r = c.getresponse()
        got = json.loads(r.read().decode() or '{}')
        c.close()
        return r.status, got


class WhoamiAsMeReadsIt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Api.start()

    def tearDown(self):
        E.CONFIG['db_guard'] = 0

    def session(self, name, role='fulladmin'):
        if not STORE.account(name):
            STORE.add_account(name, role, 'A-Long-Password-1!x')
        return STORE.session_new('admin', name, role, '192.0.2.7', 1)

    def test_a_signed_account_is_who_it_is(self):
        tok = self.session('q4alice')
        st, got = Api.ask('GET', '/api/auth/whoami', tok)
        self.assertEqual(st, 200)
        self.assertEqual(got['who']['role'], 'fulladmin')

    def test_an_account_changed_past_acme_is_nobody_with_the_guard_on(self):
        tok = self.session('q4bob', 'readonly')
        STORE.set_account('q4bob', role='readonly')
        E.CONFIG['db_guard'] = 1
        # sanity: a signed row reads as it is
        st, got = Api.ask('GET', '/api/auth/whoami', tok)
        self.assertEqual(got['who']['role'], 'readonly')
        # the role written past acme: the routes refuse it (me) - and whoami no longer says
        # "fulladmin" to the PHP gates that let a package or a database be sent
        STORE.db.run("UPDATE accounts SET role = 'fulladmin' WHERE name = 'q4bob'")
        st, got = Api.ask('GET', '/api/status', tok)
        self.assertEqual(st, 401)
        st, got = Api.ask('GET', '/api/auth/whoami', tok)
        self.assertEqual(st, 200)
        self.assertIsNone(got['who'])

    def test_an_account_of_the_enrolment_pages_only_is_nobody_here(self):
        tok = self.session('q4carol', 'readonly')
        STORE.set_account('q4carol', role='portal')
        st, got = Api.ask('GET', '/api/auth/whoami', tok)
        self.assertIsNone(got['who'])


class WebProxyNeverEveryAddress(unittest.TestCase):
    def test_every_address_refused(self):
        for bad in ('0.0.0.0/0', '::/0', '10.0.0.1 0.0.0.0/0'):
            with self.assertRaises(E.BadSetting) as e:
                E.check_setting('web_proxy_from', bad)
            self.assertIn('every address', str(e.exception))

    def test_the_balancers_themselves_taken(self):
        for good in ('10.0.0.1', '10.0.0.0/8 192.0.2.5', '2001:db8::/64', '0.0.0.0/8'):
            E.check_setting('web_proxy_from', good)


PHP = shutil.which('php')


@unittest.skipUnless(PHP, 'php is not on this machine')
class CookiesCountedAsPhpNamesThem(unittest.TestCase):
    def session_of(self, cookie):
        code = ("require %s; echo json_encode([acme_cookie_session('acme_session'), "
                "acme_cookie_count('acme_session')]);" % json.dumps(os.path.join(ROOT, 'web',
                                                                                'acme-api.php')))
        # The browser's header as php-fpm hands it on; $_COOKIE as PHP makes it of that header.
        pre = ('$_SERVER["HTTP_COOKIE"] = %s; $_COOKIE = []; '
               'foreach (explode(";", $_SERVER["HTTP_COOKIE"]) as $p) { $e = strpos($p, "="); '
               '$k = strtr(ltrim(substr($p, 0, $e)), " .[", "___"); '
               'if (!isset($_COOKIE[$k])) { $_COOKIE[$k] = substr($p, $e + 1); } } '
               % json.dumps(cookie))
        out = subprocess.run([PHP, '-r', pre + code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_one_session_cookie(self):
        self.assertEqual(self.session_of('acme_session=REALREALREALREAL1'),
                         ['REALREALREALREAL1', 1])

    def test_a_planted_one_of_another_spelling_is_a_second(self):
        for planted in ('acme.session', 'acme[session', ' acme session'):
            got = self.session_of('%s=EVILEVILEVILEVIL1; acme_session=REALREALREALREAL1' % planted)
            self.assertEqual(got, ['', 2], planted)

    def test_other_cookies_are_not_counted(self):
        self.assertEqual(self.session_of('acme_lang=cs; acme_sessionx=x; '
                                         'acme_session=REALREALREALREAL1'),
                         ['REALREALREALREAL1', 1])


@unittest.skipUnless(PHP, 'php is not on this machine')
class CookiesThroughPhpItself(unittest.TestCase):
    """The same through PHP's own parsing of the header (its built-in server)."""

    def test_planted_dot_name(self):
        d = tempfile.mkdtemp(prefix='q4php-', dir=TMP)
        with open(os.path.join(d, 'index.php'), 'w') as f:
            f.write("<?php require %s; echo json_encode(acme_cookie_session('acme_session'));"
                    % json.dumps(os.path.join(ROOT, 'web', 'acme-api.php')))
        import socket
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        p = subprocess.Popen([PHP, '-S', '127.0.0.1:%d' % port, '-t', d],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            got = None
            for _ in range(50):
                try:
                    c = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    c.request('GET', '/', headers={
                        'Cookie': 'acme.session=EVILEVILEVILEVIL1; acme_session=REALREALREALREAL1'})
                    got = json.loads(c.getresponse().read().decode())
                    break
                except (ConnectionError, OSError):
                    time.sleep(0.1)
            self.assertEqual(got, '')
        finally:
            p.terminate()
            p.wait(10)


def tearDownModule():
    Api.stop()


if __name__ == '__main__':
    unittest.main()
