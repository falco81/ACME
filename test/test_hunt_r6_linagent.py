#!/usr/bin/env python3
"""Hunt R run 6 (linagent): regressions of the Linux agent's fixes.

    python3 test/test_hunt_r6_linagent.py

- places whose files give root that a broad `allow file /etc` (or /usr/local, /usr/share) still
  let a job write: /etc/tmpfiles.d, /etc/sudo.conf, /etc/ld.so.cache, /etc/binfmt.d, D-Bus,
  /usr/share/polkit-1, /usr/local/lib (Python's site-packages, the release keys an update is
  checked with), Debian's /etc/python3.X/sitecustomize.py - now never written nor taken away;
- `acme-agent deny script PATH` of a script changed or deleted since it was allowed: refused
  ("no such entry" / "cannot be read") - now taken away by its path; `allow script` again
  replaces the line of that path instead of adding a second one;
- `acme-agent allow file DIR --owner` (no value): an IndexError traceback - now the usage.
"""
import os
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
sys.path.insert(0, os.path.join(ROOT, 'deploy', 'agent'))

import acme_agent as AG  # noqa: E402

ROOT_GIVING = ('/etc/python3.13/sitecustomize.py', '/etc/python3/x.py',
               '/etc/python2.7/sitecustomize.py', '/etc/tmpfiles.d/x.conf', '/etc/sudo.conf',
               '/etc/ld.so.cache', '/etc/binfmt.d/x.conf', '/etc/dbus-1/system.d/x.conf',
               '/usr/share/dbus-1/system-services/x.service',
               '/usr/share/polkit-1/rules.d/x.rules',
               '/usr/local/lib/python3.13/dist-packages/x.pth',
               '/usr/local/lib/release-keys/x.pub')


class Protected(unittest.TestCase):
    POL = AG.parse_policy('allow file /etc owner=root:root mode=0644\n'
                          'allow file /usr/local owner=root:root mode=0644\n'
                          'allow file /usr/share owner=root:root mode=0644')

    def test_root_giving_places_never_written(self):
        for bad in ROOT_GIVING:
            self.assertTrue(AG.protected(bad), bad)
            with self.assertRaises(AG.Refused) as e:
                AG.plan_check(self.POL, {'files': [{'path': bad, 'mode': 0o644}]})
            self.assertIn('gives root', str(e.exception))
            self.assertEqual(e.exception.needs, [], bad)
            self.assertEqual(AG.plan_check(self.POL, {'stale': [bad]})['stale'], [], bad)

    def test_neighbours_still_allowed(self):
        for ok in ('/etc/ssl/a.pem', '/etc/pythonista/a.pem', '/etc/sudo.config/a.pem',
                   '/usr/local/share/a.pem', '/usr/share/certs/a.pem', '/etc/nginx/ssl/a.pem'):
            self.assertEqual(AG.protected(ok), '', ok)
            got = AG.plan_check(self.POL, {'files': [{'path': ok, 'mode': 0o644}]})
            self.assertEqual(got['files'][0]['path'], ok)

    def test_policy_check_says_so(self):
        got = AG.policy_check('allow file /etc/tmpfiles.d\nallow file /etc/python3.11\n'
                              'allow file /usr/local/lib/x\nallow file /usr/local\n')
        codes = [(e['line'], e['code']) for e in got['errors']]
        self.assertEqual(codes, [(1, 'protected'), (2, 'protected'), (3, 'protected')])
        self.assertIn('above-protected', [w['code'] for w in got['warnings']])


@unittest.skipUnless(os.geteuid() == 0, 'the policy is root\'s')
class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-r6la-')
        os.makedirs(self.d + '/etc')
        self.env = dict(os.environ, ACME_AGENT_ETC=self.d + '/etc',
                        ACME_AGENT_STATE=self.d + '/st', ACME_AGENT_ROOT_STATE=self.d + '/rs',
                        ACME_AGENT_RUN=self.d + '/run', ACME_AGENT_NO_SYSTEMD='1')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-I', AGENT] + list(args), env=self.env,
                              capture_output=True, text=True, timeout=60)

    def scripts(self):
        with open(self.d + '/etc/policy') as fh:
            return [x for x in fh.read().splitlines() if x.startswith('allow script ')]

    def test_deny_script_changed_or_gone(self):
        s = self.d + '/s.sh'
        with open(s, 'w') as fh:
            fh.write('#!/bin/sh\necho hi\n')
        self.assertEqual(self.cli('allow', 'script', s).returncode, 0)
        self.assertIn('already allowed', self.cli('allow', 'script', s).stdout)
        with open(s, 'a') as fh:
            fh.write('echo more\n')
        # allowed again once checked: one line of that path, the new hash
        self.assertEqual(self.cli('allow', 'script', s).returncode, 0)
        lines = self.scripts()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(AG._sha(b'#!/bin/sh\necho hi\necho more\n'), lines[0])
        with open(s, 'a') as fh:
            fh.write('echo changed\n')
        got = self.cli('deny', 'script', s)                 # changed since: taken away all the same
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.scripts(), [])
        self.cli('allow', 'script', s)
        os.unlink(s)
        got = self.cli('deny', 'script', s)                 # deleted since
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.scripts(), [])
        got = self.cli('deny', 'script', s)
        self.assertEqual(got.returncode, 1)
        self.assertIn('no such entry', got.stderr)

    def test_allow_file_option_without_value(self):
        for opt in ('--owner', '--mode'):
            got = self.cli('allow', 'file', self.d + '/x', opt)
            self.assertNotEqual(got.returncode, 0)
            self.assertNotIn('Traceback', got.stderr)
            self.assertIn('allow file DIR', got.stderr)


if __name__ == '__main__':
    unittest.main()
