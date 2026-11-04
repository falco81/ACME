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


if __name__ == '__main__':
    unittest.main()
