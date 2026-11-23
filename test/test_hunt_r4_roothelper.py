#!/usr/bin/env python3
"""Hunt R run 4, the root helper (deploy/acme_web.py): what was found and is fixed - each checked.

    python3 test/test_hunt_r4_roothelper.py

* login.defs: the password policy put in and taken out again left one more empty line at the
  end of the file each time (and PASS_WARN_AGE after it) - now it is the file it was.
* chrony.conf: with the servers not set by acme (only the time zone saved), a file of the
  system's own was "tidied" (its end of line), copied, rewritten and chronyd restarted - now it
  is left as it is.
"""
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntr4rh-')
DEFS = os.path.join(TMP, 'login.defs')
CHRONY = os.path.join(TMP, 'chrony.conf')
os.environ.update(ACME_STATE=TMP, ACME_VIP_NO_SERVICES='1', ACME_LOGIN_DEFS=DEFS,
                  ACME_CHRONY_CONF=CHRONY, ACME_NTP_NO_SERVICE='1', ACME_CHRONYC='true',
                  ACME_TIMEDATECTL='true', ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, os.path.join(ROOT, 'deploy'))
import acme_web as W  # noqa: E402


def cat(p):
    with open(p) as f:
        return f.read()


def put(p, text):
    with open(p, 'w') as f:
        f.write(text)


class LoginDefs(unittest.TestCase):
    ORIG = 'MAIL_DIR /var/spool/mail\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nUID_MIN 1000\n'
    V = {'PASS_MAX_DAYS': 90, 'PASS_MIN_DAYS': 1, 'PASS_WARN_AGE': 14}

    def test_on_off_cycles_leave_the_file_as_it_was(self):
        put(DEFS, self.ORIG)
        for _ in range(3):
            W.pwp_defs_put(self.V)
            W.pwp_defs_put(self.V)
            W.pwp_defs_put(None)
        self.assertEqual(cat(DEFS), self.ORIG)

    def test_put_in_no_empty_line_before_the_new_key(self):
        put(DEFS, self.ORIG)
        W.pwp_defs_put(self.V)
        text = cat(DEFS)
        self.assertIn('UID_MIN 1000\nPASS_WARN_AGE\t14\n', text)
        self.assertNotIn('\n\n', text)
        W.pwp_defs_put(dict(self.V, PASS_MAX_DAYS=60))
        self.assertIn('PASS_MAX_DAYS\t60\n', cat(DEFS))
        W.pwp_defs_put(None)
        self.assertEqual(cat(DEFS), self.ORIG)

    def test_blank_lines_of_the_file_own_kept(self):
        orig = 'A 1\n\nPASS_MAX_DAYS 99999\n\n'
        put(DEFS, orig)
        W.pwp_defs_put(self.V)
        W.pwp_defs_put(None)
        self.assertEqual(cat(DEFS), orig)


class ChronyLeftAlone(unittest.TestCase):
    def test_not_managed_file_not_rewritten(self):
        orig = 'pool 2.almalinux.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\n\n\n'
        put(CHRONY, orig)
        for p in (CHRONY + '.acme-before',):
            if os.path.exists(p):
                os.unlink(p)
        n = W.ntp_checked({'manage': False, 'timezone': 'Europe/Prague'})
        with mock.patch.object(W, 'write_root', side_effect=AssertionError('written')):
            W.ntp_apply(n)
        self.assertEqual(cat(CHRONY), orig)
        self.assertFalse(os.path.exists(CHRONY + '.acme-before'))

    def test_managed_then_not_puts_the_file_back(self):
        orig = 'pool 2.almalinux.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\n'
        put(CHRONY, orig)
        W.ntp_apply(W.ntp_checked({'manage': True, 'servers': [{'host': 'ntp.example.cz'}]}))
        self.assertIn(W.NTP_BEGIN, cat(CHRONY))
        self.assertIn('#acme# pool 2.almalinux', cat(CHRONY))
        W.ntp_apply(W.ntp_checked({'manage': False}))
        self.assertEqual(cat(CHRONY), orig)

    def test_lines_of_acme_left_without_marks_still_put_back(self):
        put(CHRONY, '#acme# pool 2.almalinux.pool.ntp.org iburst\n')
        W.ntp_apply(W.ntp_checked({'manage': False}))
        self.assertEqual(cat(CHRONY), 'pool 2.almalinux.pool.ntp.org iburst\n')


if __name__ == '__main__':
    unittest.main()
