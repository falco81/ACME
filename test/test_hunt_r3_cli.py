#!/usr/bin/env python3
"""Bug hunt R, run 3, the command line and the console (1.0.124).

    python3 test/test_hunt_r3_cli.py

- acme --selinux fix ... --json and rules --take-away ID --json answer JSON alone on stdout (what
  root will do went before the JSON, and each line said after it, so the output was not JSON);
- acme --target-agent NAME look ends non-zero when the agent could not be reached (it ended 0 with
  the error only in "said");
- acme --target-agent NAME code of a Windows target says an elevated prompt and the MSI, not "as
  root";
- the console's Target agents has Update all agents, as the pages do.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-r3cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_selinux_findings as SF          # noqa: E402 - its stand-in machine and fixtures


def run(*args):
    return subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True, timeout=120,
                          input='')


class SelinuxJson(SF.CommandLine):
    test_parser = None                      # those of its own run in test_selinux_findings.py
    test_look_fix_rules = None

    def test_fix_and_take_away_json(self):
        f = self.by_name(self.look())
        rc, out = self.cli('--selinux', 'fix', f['port_sshd']['id'], '--yes', '--json')
        self.assertEqual(rc, 0, out)
        got = json.loads(out)                                  # JSON alone
        self.assertTrue(any('ssh_port_t' in x for x in got['said']), got['said'])
        self.assertNotIn('Root does exactly this', out)
        rc, out = self.cli('--selinux', 'fix', '--all', '--yes', '--json')
        self.assertEqual(rc, 0, out)
        self.assertIn('said', json.loads(out))
        rc, out = self.cli('--selinux', 'rules', '--json')
        rids = [r['id'] for r in json.loads(out)]
        self.assertTrue(rids)
        rc, out = self.cli('--selinux', 'rules', '--take-away', rids[0], '--yes', '--json')
        self.assertEqual(rc, 0, out)
        self.assertTrue(json.loads(out)['said'])
        # without --json as before: the plan and each line said
        rc, out = self.cli('--selinux', 'rules')
        rid = json.loads(self.cli('--selinux', 'rules', '--json')[1])[0]['id']
        rc, out = self.cli('--selinux', 'rules', '--take-away', rid, '--yes')
        self.assertIn('taken away', out)

    def test_nothing_to_fix_json(self):
        err = io.StringIO()
        with mock.patch('sys.stderr', err):
            rc, out = self.cli('--selinux', 'fix', '--all', '--yes', '--json')
            self.assertEqual(rc, 0)
            rc, out = self.cli('--selinux', 'fix', '--all', '--yes', '--json')
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {'said': []})


class TargetAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name, kind in (('r3lin', 'agent'), ('r3win', 'agent_windows')):
            got = run('--target-add', name, '--kind', kind, '--set', 'mode=passive',
                      '--set', 'host=127.0.0.1', '--set', 'port=1')
            assert got.returncode == 0, got.stdout + got.stderr

    def test_look_unreachable_fails(self):
        run('--target-agent', 'r3lin', 'code')
        got = run('--target-agent', 'r3lin', 'look')
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn('does not answer', got.stdout)
        got = run('--target-agent', 'r3lin', 'look', '--json')
        self.assertEqual(got.returncode, 1)
        self.assertIn('does not answer', json.loads(got.stdout)['said'])
        self.assertEqual(run('--target-agent', 'r3lin', 'show').returncode, 0)

    def test_windows_code_words(self):
        got = run('--target-agent', 'r3win', 'code')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('elevated prompt', got.stderr)
        self.assertIn('JOINCODE=', got.stderr)
        self.assertNotIn('as root', got.stderr)
        self.assertTrue(got.stdout.strip().startswith('ACAG1.'))
        got = run('--target-agent', 'r3lin', 'code')
        self.assertIn('as root', got.stderr)


class Console(unittest.TestCase):
    def test_update_all_agents(self):
        from acmelib.certs import console as C
        seen = {}

        class Con(object):
            def sub(self, title, items):
                seen['items'] = items

            def confirm(self, *a, **k):
                return True

            def live(self, fn):
                fn()

            def cmd(self, *a):
                seen['cmd'] = a

            def pause(self):
                pass
        con = Con()
        C.agents_menu(con)
        item = [x for x in seen['items'] if 'Update all agents' in x[1]]
        self.assertEqual(len(item), 1)
        item[0][2]()
        self.assertEqual(seen['cmd'], ('--target-agent', 'all', 'update'))


if __name__ == '__main__':
    unittest.main()
