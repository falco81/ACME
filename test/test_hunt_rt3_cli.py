#!/usr/bin/env python3
"""Bug hunt R, run t3, the command line of the 1.0.125 features (teams, AD CS, discovery).

    python3 test/test_hunt_rt3_cli.py

- acme --roles and --team-access said the capabilities cut at 48 characters (most of a Team
  owner's unsaid); --team-access did not say the limits in force (the API does);
- acme --role-del NAME of no such role asked for --yes first; refusals said the API's words
  ("delete it with reparent", "with strip") instead of the options (--parent, --strip);
- a team's device and a team's enrollment code had no command line (--owner TEAM), and
  --target-show did not say the team owning the target;
- acme --target-agent NAME discover cached, with no discovery asked yet, said "0 services
  found" as if one had found nothing;
- acme --target-agent NAME adcs-templates ended 0 when the agent refused without naming a
  policy line (an agent older than 1.0.125, Linux's refusal, the CA not reached);
- the team's Activity and Teams from directory groups had no command line
  (--team-activity, --teams-from-groups).
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rt3cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"certs_agents_active": 1}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
for k, v in ENV.items():
    if k.startswith('ACME_'):
        os.environ[k] = v
sys.path.insert(0, ROOT)


def run(*args):
    got = subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True, timeout=120,
                         input='')
    assert 'Traceback' not in got.stderr, got.stderr
    return got


class Teams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for args in (('--team-add', 'Top', '--team-kind', 'unit'),
                     ('--team-add', 'Web', '--parent', 'Top', '--policy', '{"max_days": 90}',
                      '--members', 'local:jan=Team owner'),
                     ('--role-add', 'Auditor', '--caps', 'cert.view,team.activity'),
                     ('--team-edit', 'Top', '--members', 'local:eva=Auditor')):
            got = run(*args)
            assert got.returncode == 0, got.stdout + got.stderr

    def test_roles_whole(self):
        got = run('--roles')
        self.assertEqual(got.returncode, 0, got.stderr)
        owner = [ln for ln in got.stdout.splitlines() if 'Team owner' in ln][0]
        self.assertIn('team.activity', owner)               # its last capability, not cut
        self.assertIn('cert.approve', owner)
        got = json.loads(run('--roles', '--json').stdout)  # --json as before
        self.assertIn('caps', got)

    def test_access_whole_and_limits(self):
        got = run('--team-access', 'local:jan')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('team.activity', got.stdout)
        self.assertIn('limits of Web: max_days 90', got.stdout)
        got = json.loads(run('--team-access', 'local:jan', '--json').stdout)
        self.assertEqual(got['groups_count'], 0)
        self.assertEqual([t['team'] for t in got['teams']], ['Web'])

    def test_refusals_in_options(self):
        got = run('--role-del', 'NoSuchRole')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no role NoSuchRole', got.stderr)
        self.assertNotIn('--yes', got.stderr)
        got = run('--role-del', 'Auditor', '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('with --strip', got.stderr)
        got = run('--team-del', 'Top', '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('with --parent TEAM (- for the top level)', got.stderr)
        self.assertNotIn('reparent', got.stderr)

    def test_activity(self):
        got = run('--team-activity', 'Top', '--below', '--limit', '1')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(len(got.stdout.splitlines()), 2, got.stdout)
        self.assertIn('--limit N for more', got.stdout)
        got = json.loads(run('--team-activity', 'Top', '--below', '--json').stdout)
        self.assertEqual(got['team'], 'Top')
        self.assertTrue(any('Web' in r['words'] for r in got['rows']))
        got = run('--team-activity', 'Nope')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no team Nope', got.stderr)

    def test_from_groups(self):
        from acmelib import engine as E
        from acmelib.certs import api_teams, cli, teams as T
        store = E.cli_store()

        class AD(object):
            name = 'corp'

            def find_groups(self, literal, limit=5000):
                return [{'cn': 'PKI-Web', 'dn': 'CN=PKI-Web,DC=corp', 'description': 'web'},
                        {'cn': 'PKI-Mail', 'dn': 'CN=PKI-Mail,DC=corp'},
                        {'cn': 'Other', 'dn': 'CN=Other,DC=corp'}]

        class Args(object):
            member_role = 'Requester'
            parent = 'Top'
            team_kind = None
            yes = False
        c = cli.Cli.__new__(cli.Cli)
        c.store, c.WHO, c.args, c.json = store, 'command line', Args(), False
        c.table = lambda rows, heads: print(rows)
        c.pal = E.Palette(False)
        out = io.StringIO()
        with mock.patch.object(api_teams, '_need_dir', lambda h, n=None: AD()), \
                contextlib.redirect_stdout(out):
            self.assertEqual(api_teams._cli_from_groups(c, 'PKI-*'), 0)
        self.assertIn('2 team(s) would be made', out.getvalue())
        self.assertIn('again with --yes', out.getvalue())
        self.assertIsNone(T.team_get(store, 'PKI-Web'))
        c.args.yes = True
        with mock.patch.object(api_teams, '_need_dir', lambda h, n=None: AD()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(api_teams._cli_from_groups(c, 'PKI-*'), 0)
        t = T.team_get(store, 'PKI-Web')
        self.assertEqual(t['parent'], 'Top')
        self.assertEqual(json.loads(t['members'])[0]['roles'], ['Requester'])
        self.assertIsNone(T.team_get(store, 'Other'))
        got = run('--teams-from-groups', 'PKI-*')            # no directory: said, not a traceback
        self.assertEqual(got.returncode, 1)
        self.assertIn('no directory', got.stderr)

    def test_old_ones_as_before(self):
        got = run('--team-add', 'Old', '--members', 'local:a=view+request,local:b')
        self.assertEqual(got.returncode, 0, got.stderr)
        got = json.loads(run('--teams', '--json').stdout)
        old = [t for t in got['teams'] if t['name'] == 'Old'][0]
        self.assertEqual([m['rights'] for m in old['members']], [['view', 'request']] * 2)
        self.assertEqual(run('--team-del', 'Old', '--yes').returncode, 0)


class Targets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        got = run('--team-add', 'Ops', '--policy', '{"agents": true}')
        assert got.returncode == 0, got.stderr
        for name, kind in (('rt3lin', 'agent'), ('rt3win', 'agent_windows')):
            got = run('--target-add', name, '--kind', kind, '--set', 'mode=passive',
                      '--set', 'host=127.0.0.1', '--set', 'port=1')
            assert got.returncode == 0, got.stdout + got.stderr

    def test_owner(self):
        got = run('--target-add', 'rt3own', '--kind', 'agent', '--set', 'mode=passive',
                  '--set', 'host=127.0.0.1', '--owner', 'Ops')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(run('--target-show', 'rt3own', '--json').stdout)['owner'],
                         'Ops')
        self.assertRegex(run('--target-show', 'rt3own').stdout, r'owner\s+Ops')
        got = run('--target-edit', 'rt3own', '--owner', '-')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(run('--target-show', 'rt3own', '--json').stdout)['owner'],
                         '')
        self.assertNotRegex(run('--target-show', 'rt3own').stdout, r'owner\s')
        got = run('--target-edit', 'rt3own', '--owner', 'NoTeam')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no team NoTeam', got.stderr)
        got = run('--validation-edit', 'This server HTTP-01', '--owner', 'Ops')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--owner goes with --target-add', got.stderr)

    def test_team_enrollment_code(self):
        got = run('--target-agent', 'enroll', 'new', '--title', 'ops', '--owner', 'Ops', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(got.stdout)['team'], 'Ops')
        got = run('--target-agent', 'enroll', 'list')
        self.assertIn('(the team Ops)', got.stdout)
        got = run('--target-agent', 'enroll', 'new', '--owner', 'NoTeam')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no team NoTeam', got.stderr)
        got = run('--target-agent', 'enroll', 'new', '--title', 'plain', '--json')
        self.assertIsNone(json.loads(got.stdout)['team'])

    def test_discover_cached_none(self):
        got = run('--target-agent', 'rt3lin', 'discover', 'cached')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('no discovery was asked on rt3lin yet', got.stdout)
        self.assertNotIn('0 services found', got.stdout)
        got = json.loads(run('--target-agent', 'rt3lin', 'discover', 'cached', '--json').stdout)
        self.assertEqual(got['found'], [])

    def test_adcs_refusal_exit(self):
        from acmelib import engine as E
        from acmelib.certs import agents as G, cli
        store = E.cli_store()
        row = G.target_row(store, 'rt3win')
        c = cli.Cli.__new__(cli.Cli)
        c.store, c.WHO, c.json = store, 'command line', False
        c.out = lambda x: None
        answers = {}

        def call(store, row, op, args=None, timeout=900, step=None):
            return answers[args['action']]
        cases = [
            # an older agent: no policy line named - it ended 0
            ({'cas': {'ok': False, 'said': "'adcs' is not an operation of this agent"}}, 1),
            ({'cas': {'ok': False, 'said': 'not allowed', 'needs': [
                {'kind': 'adcs', 'allow': 'acme-agent allow adcs-read'}]}}, 1),
            ({'cas': {'ok': True, 'adcs': {'cas': []}}}, 0),          # a domain with no CA
            ({'cas': {'ok': True, 'adcs': {'cas': [{'config': 'ca1\\CA', 'name': 'CA'}]}},
              'templates': {'ok': True, 'adcs': {'templates': [{'name': 'WebServer'}]}}}, 0),
            ({'cas': {'ok': True, 'adcs': {'cas': [{'config': 'ca1\\CA', 'name': 'CA'}]}},
              'templates': {'ok': False, 'said': 'the CA cannot be reached'}}, 1)]
        for json_ in (False, True):
            c.json = json_
            for ans, rc in cases:
                answers.clear()
                answers.update(ans)
                with mock.patch.object(G, 'call', call), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(c.target_agent_adcs(row, []), rc, (ans, out.getvalue()))
        with mock.patch.object(G, 'call', call), contextlib.redirect_stdout(io.StringIO()):
            answers.update({'templates': {'ok': False, 'said': 'no'}})
            self.assertEqual(c.target_agent_adcs(row, ['ca1\\CA']), 1)    # the one asked failed

    def test_usage_names_new_words(self):
        got = run('--target-agent', 'rt3lin')
        self.assertEqual(got.returncode, 1)
        self.assertIn('adcs-templates|discover', got.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
