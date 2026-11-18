#!/usr/bin/env python3
"""Bug hunt R, run t7, area "regress": what the fixes of 1.0.126/1.0.127 broke, kept fixed.

    python3 test/test_hunt_rt7_regress.py

- the command line: --owner TEAM (1.0.126, a team's device and enrollment code) is a global
  option - `acme --cert-add NAME --owner TEAM` was taken and the owner silently left out
  ("added", no owner), `acme --cert-edit NAME --owner TEAM` said "nothing to change"; before
  1.0.126 the option was refused, the console and the pages set a certificate's owner.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rt7regress-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))


def run(*args):
    got = subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True, timeout=120,
                         input='')
    assert 'Traceback' not in got.stderr, got.stderr
    return got


def owner_of(name):
    got = json.loads(run('--cert', name, '--json').stdout)
    return (got.get('cert') or got).get('owner')


class CertOwnerOption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        got = run('--team-add', 'Web')
        assert got.returncode == 0, got.stdout + got.stderr

    def test_add_with_owner(self):
        got = run('--cert-add', 'rt7a', '--names', 'rt7a.example.com', '--owner', 'Web')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(owner_of('rt7a'), 'Web')

    def test_edit_owner_and_back(self):
        got = run('--cert-add', 'rt7b', '--names', 'rt7b.example.com')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(owner_of('rt7b'), '')
        got = run('--cert-edit', 'rt7b', '--owner', 'Web')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(owner_of('rt7b'), 'Web')
        got = run('--cert-edit', 'rt7b', '--owner', '-')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(owner_of('rt7b'), '')
        # --set owner= as before, and over --owner when both are given
        got = run('--cert-edit', 'rt7b', '--owner', 'Web', '--set', 'owner=')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(owner_of('rt7b'), '')

    def test_targets_and_others_as_before(self):
        got = run('--validation-edit', 'This server HTTP-01', '--owner', 'Web')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--owner goes with --target-add', got.stderr)
        got = run('--cert-edit', 'rt7a')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--owner', got.stderr)       # said among what can be changed


if __name__ == '__main__':
    unittest.main(verbosity=2)
