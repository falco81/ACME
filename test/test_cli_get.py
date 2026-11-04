#!/usr/bin/env python3
"""acme --get KEY: the counterpart of --set (1.0.41).

    python3 test/test_cli_get.py

One key: its value alone; more: KEY=VALUE a line; --json: {key: value}. A secret
shown hidden, as --settings shows it; a key that is no setting refused.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-get-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = dict(os.environ, ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'),
           ACME_STATE=TMP, ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1')


def run(*args, stdin=''):
    return subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True,
                          input=stdin, timeout=120)


class Get(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        got = run('--set', 'session_hours=7', '--set', 'smtp_host=mail.example.test')
        assert got.returncode == 0, got.stdout + got.stderr
        got = run('--set', 'smtp_password=-', stdin='Tajne-Heslo-2026\n')
        assert got.returncode == 0, got.stdout + got.stderr

    def test_one_alone(self):
        got = run('--get', 'session_hours')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(got.stdout, '7\n')

    def test_more_as_set_takes_them(self):
        got = run('--get', 'session_hours', '--get', 'smtp_host')
        self.assertEqual(got.stdout, 'session_hours=7\nsmtp_host=mail.example.test\n')

    def test_json(self):
        got = run('--get', 'session_hours', '--get', 'smtp_host', '--json')
        self.assertEqual(json.loads(got.stdout), {'session_hours': 7,
                                                  'smtp_host': 'mail.example.test'})

    def test_a_secret_hidden(self):
        got = run('--get', 'smtp_password')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertNotIn('Tajne-Heslo-2026', got.stdout + got.stderr)
        self.assertTrue(got.stdout.strip(), 'a secret that is set says so (hidden)')
        got = run('--get', 'smtp_password', '--json')
        self.assertNotIn('Tajne-Heslo-2026', got.stdout)

    def test_a_card_drawn_one_read_too(self):
        got = run('--get', 'split_mode')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertTrue(got.stdout.strip())

    def test_no_such_setting(self):
        got = run('--get', 'session_hours', '--get', 'no_such_one')
        self.assertNotEqual(got.returncode, 0)
        self.assertEqual(got.stdout, '')
        self.assertIn('no_such_one', got.stderr)


if __name__ == '__main__':
    unittest.main()
