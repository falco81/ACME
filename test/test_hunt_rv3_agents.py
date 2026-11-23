#!/usr/bin/env python3
"""Hunt v3 (agents): regressions of the target agent's command line and acme's policy compare.

    python3 test/test_hunt_rv3_agents.py

- `acme-agent deny limit files` (the limit back to its default, no number) was refused with
  "an entry begins with allow or limit"; `acme-agent limit files` (no number) said the same;
- `acme-agent discover --kind KIND` with a kind it does not know, and `acme-agent allow issuer
  FILE.pem` with a PEM block openssl cannot read, stopped with a Python traceback;
- `allow self-update no` (any word after it) allowed self-update;
- a design / fleet template with `audit chain` said "differs" (+audit chain) of a server whose
  policy has the line;
- `install.sh --help` printed two lines of the script after its comment.
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
sys.path.insert(0, ROOT)

import acme_agent as AG  # noqa: E402


@unittest.skipUnless(os.geteuid() == 0, 'the policy commands run as root')
class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-rv3-')
        self.env = dict(os.environ, ACME_AGENT_USER='root', ACME_AGENT_NO_SYSTEMD='1')
        for k, sub in (('ETC', 'etc'), ('STATE', 'st'), ('ROOT_STATE', 'rst'), ('RUN', 'run')):
            os.makedirs(os.path.join(self.d, sub))
            self.env['ACME_AGENT_' + k] = os.path.join(self.d, sub)
        self.policy = os.path.join(self.d, 'etc', 'policy')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_cli(self, *args):
        r = subprocess.run([sys.executable, AGENT] + list(args), env=self.env,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertNotIn('Traceback', r.stderr)
        return r

    def entries(self):
        with open(self.policy) as f:
            return [x for x in f.read().splitlines() if x.strip() and not x.startswith('#')]

    def test_deny_limit_without_number(self):
        self.assertEqual(self.run_cli('limit', 'files', '30').returncode, 0)
        self.assertEqual(self.run_cli('limit', 'size', '1000').returncode, 0)
        self.assertEqual(self.entries(), ['limit files 30', 'limit size 1000'])
        r = self.run_cli('deny', 'limit', 'files')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('back to the default: limit files', r.stdout)
        self.assertEqual(self.entries(), ['limit size 1000'])
        # with the number, as before
        self.assertEqual(self.run_cli('deny', 'limit', 'size', '1000').returncode, 0)
        self.assertEqual(self.entries(), [])

    def test_limit_without_number_says_its_words(self):
        for args in (('limit', 'files'), ('limit',), ('allow', 'limit', 'x', '1')):
            r = self.run_cli(*args)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('limit files N | limit size BYTES', r.stderr)

    def test_discover_unknown_kind(self):
        r = self.run_cli('discover', '--kind', 'bogus')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("acme-agent: 'bogus' is not a kind of service", r.stderr)

    def test_issuer_of_a_bad_pem(self):
        bad = os.path.join(self.d, 'bad.pem')
        with open(bad, 'w') as f:
            f.write('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')
        r = self.run_cli('allow', 'issuer', bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('holds no certificate', r.stderr)
        self.assertFalse(os.path.exists(self.policy) and self.entries())

    def test_self_update_words(self):
        self.assertEqual(self.run_cli('allow', 'self-update').returncode, 0)
        self.assertEqual(self.entries(), ['allow self-update'])
        r = self.run_cli('policy', 'show')
        self.assertNotIn('NOT READ', r.stdout)


class Parse(unittest.TestCase):
    def test_self_update_takes_no_word(self):
        pol = AG.parse_policy('allow self-update no\n')
        self.assertFalse(pol['self_update'])
        self.assertIn('allow self-update (no word after it)', pol['problems'][0])
        self.assertTrue(AG.parse_policy('allow self-update\n')['self_update'])


class Compare(unittest.TestCase):
    def test_audit_chain_matches(self):
        from acmelib.certs import agent_policy as P
        text = 'allow file /srv/c owner=root:root mode=0640\naudit chain\n'
        pol = AG.parse_policy(text)
        rep = AG.policy_report(pol, AG._sha(AG.policy_canon(pol)))
        self.assertEqual(P.compare(text, rep, AG)['state'], 'matches')
        # a server without the line still differs
        pol = AG.parse_policy('allow file /srv/c owner=root:root mode=0640\n')
        rep = AG.policy_report(pol, AG._sha(AG.policy_canon(pol)))
        c = P.compare(text, rep, AG)
        self.assertEqual((c['state'], c['added']), ('differs', ['audit chain']))


class InstallHelp(unittest.TestCase):
    def test_help_is_the_comment(self):
        r = subprocess.run(['bash', os.path.join(ROOT, 'deploy', 'agent', 'install.sh'),
                            '--help'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        lines = r.stdout.splitlines()
        self.assertTrue(lines and all(x.startswith('#') for x in lines), lines[-3:])
        self.assertIn('--uninstall', r.stdout)


if __name__ == '__main__':
    unittest.main()
