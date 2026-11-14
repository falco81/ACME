"""Block a place that keeps guessing (1.0.40, as otp's guard of 1.0.137 for the sign-ins to the
pages and the portal), and the cap of wrong directory passwords that goes with it (otp 1.0.241).

    python3 test/test_login_guard.py
"""
import collections
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-guard2-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())


class D(object):
    def __init__(self):
        self.login_fails = collections.defaultdict(list)
        self.login_info = {}
        self.store = STORE


class TestGuard(unittest.TestCase):
    def setUp(self):
        E.CONFIG.update(login_guard=1, login_guard_tries=5, login_guard_names=3,
                        login_guard_window_min=15, login_guard_block_min=30, login_guard_trusted='')

    def tearDown(self):
        E.CONFIG['login_guard'] = 0

    def test_off_by_default(self):
        self.assertEqual(E.DEFAULTS['login_guard'], 0)
        self.assertIn('login_guard', E.PANES['guard'])

    def test_blocked_after_the_tries(self):
        d = D()
        for _ in range(4):
            E.guard_count(d, '198.51.100.7', 'novak')
        self.assertIsNone(E.guard_blocked(d, '198.51.100.7'))
        E.guard_count(d, '198.51.100.7', 'novak')
        self.assertTrue(E.guard_blocked(d, '198.51.100.7'))

    def test_blocked_by_the_names(self):
        d = D()
        for n in ('a', 'b', 'c'):
            E.guard_count(d, '198.51.100.8', n)
        until, why = E.guard_blocked(d, '198.51.100.8')
        self.assertIn('different names', why)

    def test_listed_as_a_place(self):
        d = D()
        E.guard_count(d, '198.51.100.9', 'x')
        rows = [r for r in E.lockouts_view(d) if r['kind'] == 'guard-src']
        self.assertEqual(rows[0]['by'], 'place')
        self.assertEqual(rows[0]['who'], '198.51.100.9')

    def test_trusted_never_blocked(self):
        E.CONFIG['login_guard_trusted'] = '203.0.113.0/24'
        self.assertTrue(E.guard_trusted('203.0.113.5'))
        self.assertFalse(E.guard_trusted('198.51.100.1'))
        with self.assertRaises(E.BadSetting):
            E.check_setting('login_guard_trusted', 'nonsense!')

    def test_the_directory_cap_goes_with_it(self):
        E.CONFIG['dir_pw_tries'] = 3
        try:
            self.assertEqual(E.dir_pw_cap_of(STORE, 'corp')[0], 3)
            E.CONFIG['login_guard'] = 0
            self.assertEqual(E.dir_pw_cap_of(STORE, 'corp')[0], 0)
            self.assertFalse(E.dir_pw_caps_list(STORE)['in_use'])
        finally:
            E.CONFIG['dir_pw_tries'] = 0


PHP_COOKIES = r"""<?php
define('ACME_COOKIE', getenv('T_BASE'));
define('ACME_COOKIE_PATH', getenv('T_PATH'));
if (getenv('T_HTTPS') === '1') { $_SERVER['HTTPS'] = 'on'; }
$_SERVER['HTTP_COOKIE'] = (string) getenv('T_COOKIE');
foreach (explode(';', $_SERVER['HTTP_COOKIE']) as $part) {
    $eq = strpos($part, '=');
    if ($eq === false) { continue; }
    $k = trim(substr($part, 0, $eq));
    if (!isset($_COOKIE[$k])) { $_COOKIE[$k] = trim(substr($part, $eq + 1)); }   // PHP: the first
}
require getenv('T_API');
$before = acme_session();
$portal = acme_cookie_session('acme_portal');
acme_set_session('NEW-token-NEW-token-NEW');
echo json_encode(['session' => $before, 'portal' => $portal, 'name' => acme_cookie_name(),
                  'path' => acme_cookie_path(), 'after' => acme_session()]);
"""


class TestCookieToss(unittest.TestCase):
    """The session cookies (1.0.101): __Host- over https, and two of one name - one planted by a
    sibling host or over http, sent first, taken by PHP - no sign-in at all."""

    def run_php(self, base, cookie, https=True, path='/'):
        import json
        import shutil
        import subprocess
        if not shutil.which('php'):
            self.skipTest('no php here')
        script = os.path.join(TMP, 'cookies.php')
        with open(script, 'w') as f:
            f.write(PHP_COOKIES)
        out = subprocess.run(['php', script], capture_output=True, text=True, timeout=60, env=dict(
            os.environ, T_BASE=base, T_PATH=path, T_HTTPS='1' if https else '0', T_COOKIE=cookie,
            T_API=os.path.join(ROOT, 'web', 'acme-api.php')))
        self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_host_prefix_over_https(self):
        tok = 'A' * 43
        got = self.run_php('acme_session', '__Host-acme_session=' + tok, path='/admin/')
        self.assertEqual((got['name'], got['path'], got['session']),
                         ('__Host-acme_session', '/', tok))
        self.assertEqual(got['after'], 'NEW-token-NEW-token-NEW')
        # The plain name over https is no sign-in any more (a page over http could plant it).
        self.assertEqual(self.run_php('acme_session', 'acme_session=' + tok)['session'], '')
        # Plain http (a test server): the name as it was, the page's own path.
        got = self.run_php('acme_session', 'acme_session=' + tok, https=False, path='/admin/')
        self.assertEqual((got['name'], got['path'], got['session']), ('acme_session', '/admin/', tok))

    def test_two_of_one_name_signed_out(self):
        planted, mine = 'P' * 43, 'M' * 43
        for https, name in ((True, '__Host-acme_session'), (False, 'acme_session')):
            got = self.run_php('acme_session', '%s=%s; acme_lang=cs; %s=%s'
                               % (name, planted, name, mine), https=https)
            self.assertEqual(got['session'], '', (https, got))
        got = self.run_php('acme_portal', '__Host-acme_portal=%s; __Host-acme_portal=%s'
                           % (planted, mine))
        self.assertEqual(got['session'], '')
        # ...the administration's look at the portal's sign-in too.
        got = self.run_php('acme_session', '__Host-acme_session=%s; __Host-acme_portal=%s; '
                           '__Host-acme_portal=%s' % (mine, planted, mine))
        self.assertEqual((got['session'], got['portal']), (mine, ''))
        got = self.run_php('acme_session', '__Host-acme_session=%s; __Host-acme_portal=%s'
                           % (mine, planted))
        self.assertEqual((got['session'], got['portal']), (mine, planted))


if __name__ == '__main__':
    unittest.main()
