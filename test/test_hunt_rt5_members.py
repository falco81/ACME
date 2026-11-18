#!/usr/bin/env python3
"""Bug hunt R, run t5, area members (1.0.126).

    python3 test/test_hunt_rt5_members.py

- acme --team-add/-edit --members: the simple form parses as before; a JSON list says what it
  cannot - a member given by its DN, a role with + in its name, a member's note, an end at an
  exact time (the help allowed a DN: it was split at its commas and =);
- acme --team-edit --note '' takes the note away (it was ignored); --description '' too;
- acme --team-show NAME: one team whole (--teams cuts members and limits at 48 characters);
- the console writes such members back (it refused to change the members of such a team), keeps
  a member's note and an end at an exact time (rounded to the end of its day before), and takes a
  team's note away when it is emptied;
- the target agent and the policy designer quote a unit name with a backslash (a systemd escape,
  a\\x2d.service): unquoted, the agent read it back as ax2d.service.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rt5members-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))

from acmelib.certs import api_teams as AT  # noqa: E402
from acmelib.certs import console as C  # noqa: E402

sys.path.insert(0, HERE)
from test_hunt_rt4_console import Con as _Con  # noqa: E402

DN = 'CN=PKI,OU=Groups,DC=example,DC=com'


def run(*args):
    return subprocess.run(ACME + [str(a) for a in args], env=ENV, capture_output=True,
                          text=True, timeout=120, input='')


def teams():
    return {t['name']: t for t in json.loads(run('--teams', '--json').stdout)['teams']}


class Con(_Con):
    def act(self, *args, env=None, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        return json.loads(got.stdout or 'null')


class Members(unittest.TestCase):
    def test_1_simple_form_as_before(self):
        self.assertEqual(AT._members('local:jan=manage, group:Web=Requester+Deployer@2026-12-31,'
                                     'bob'),
                         [{'who': 'local:jan', 'rights': 'manage'},
                          {'who': 'group:Web', 'rights': [], 'roles': ['Requester', 'Deployer'],
                           'until': '2026-12-31'},
                          {'who': 'bob', 'rights': None}])
        self.assertEqual(AT._members(''), [])

    def test_2_json_form(self):
        got = AT._members(json.dumps([{'who': DN, 'roles': ['A+B'], 'note': 'x, y',
                                       'until': '2030-06-30 14:30'}, 'group:Web',
                                      {'who': 'local:a', 'until': '2030-06-30'}]))
        self.assertEqual(got[0]['who'], DN)
        self.assertEqual(got[0]['roles'], ['A+B'])
        self.assertEqual(got[0]['until'], time.mktime(time.strptime('2030-06-30 14:30',
                                                                    '%Y-%m-%d %H:%M')))
        self.assertEqual(got[1], {'who': 'group:Web'})
        self.assertEqual(got[2]['until'], '2030-06-30')
        for bad in ('[oops', '[{"who": "a", "rihgts": ["view"]}]', '[1]',
                    '[{"who": "a", "until": "2030-02-30 10:00"}]'):
            with self.assertRaises(ValueError):
                AT._members(bad)

    def test_3_cli(self):
        r = run('--team-add', 'Web', '--note', 'hello', '--description', 'web',
                '--members', json.dumps([{'who': DN, 'rights': ['view'], 'note': 'audit, Q3',
                                          'until': '2030-06-30 14:30'}, 'local:eva']))
        self.assertEqual(r.returncode, 0, r.stderr)
        t = teams()['Web']
        m = {x['who']: x for x in t['members']}
        self.assertEqual(m[DN]['note'], 'audit, Q3')
        self.assertEqual(C._day(m[DN]['until']), '2030-06-30')
        self.assertEqual(time.strftime('%H:%M', time.localtime(m[DN]['until'])), '14:30')
        self.assertEqual(m['local:eva']['rights'], ['view', 'request'])
        # --team-show: whole
        out = run('--team-show', 'web').stdout
        self.assertIn(DN, out)
        self.assertIn('until 2030-06-30 14:30 - audit, Q3', out)
        self.assertEqual(json.loads(run('--team-show', 'Web', '--json').stdout)['team']['name'],
                         'Web')
        self.assertNotEqual(run('--team-show', 'Nope').returncode, 0)
        # --note '' / --description '' take them away; a note not given kept
        self.assertEqual(run('--team-edit', 'Web', '--contact-mail', 'a@example.com').returncode,
                         0)
        self.assertEqual(teams()['Web']['note'], 'hello')
        self.assertEqual(run('--team-edit', 'Web', '--note', '', '--description', '').returncode,
                         0)
        t = teams()['Web']
        self.assertEqual((t['note'], t['description']), ('', ''))
        self.assertEqual(run('--team-edit', 'Web', '--note=again').returncode, 0)
        self.assertEqual(teams()['Web']['note'], 'again')
        self.assertEqual(run('--team-edit', 'Web', '--note=').returncode, 0)
        self.assertEqual(teams()['Web']['note'], '')

    def test_4_console(self):
        exact = time.mktime(time.strptime('2031-03-01 09:15', '%Y-%m-%d %H:%M'))
        assert run('--team-add', 'Con', '--note', 'n', '--members', json.dumps(
            [{'who': DN, 'roles': ['Viewer'], 'note': 'kept'},
             {'who': 'local:eva', 'rights': ['view'], 'until': exact}])).returncode == 0
        before = {m['who']: m for m in teams()['Con']['members']}
        # a member added: the others written back as they were (a DN, a note, an exact end)
        con = Con(forms=[{'who': 'group:New', 'roles': 'Viewer', 'until': '2031-01-31'}])
        C.team_members(con, 'Con')
        con.pick_act(con.rows[0])
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1][2])
        got = {m['who']: m for m in teams()['Con']['members']}
        self.assertEqual(got[DN], before[DN])
        self.assertEqual(got['local:eva'], before['local:eva'])
        self.assertEqual(got['group:New']['until'],
                         time.mktime(time.strptime('2031-01-31', '%Y-%m-%d')) + 86399)
        # a member changed, its day left: its exact time and its note kept
        con = Con(chooses=['edit'], forms=[{'roles': 'Requester'}])
        C.team_members(con, 'Con')
        con.pick_act([r for r in con.rows if r.get('who') == 'local:eva'][0])
        got = {m['who']: m for m in teams()['Con']['members']}
        self.assertEqual((got['local:eva']['roles'], got['local:eva']['until']),
                         (['Requester'], exact))
        con = Con(chooses=['edit'], forms=[{'roles': 'Viewer+Requester'}])
        C.team_members(con, 'Con')
        con.pick_act([r for r in con.rows if r.get('who') == DN][0])
        got = {m['who']: m for m in teams()['Con']['members']}
        self.assertEqual((got[DN]['roles'], got[DN]['note']), (['Viewer', 'Requester'], 'kept'))
        # a DN typed in the form
        con = Con(forms=[{'who': 'CN=X,DC=example,DC=com', 'roles': 'Viewer'}])
        C.team_members(con, 'Con')
        con.pick_act(con.rows[0])
        self.assertIn('CN=X,DC=example,DC=com', {m['who'] for m in teams()['Con']['members']})
        # simple members: still the simple form
        self.assertEqual(C._members_arg([{'who': 'local:j', 'rights': ['view'],
                                          'until': time.mktime(time.strptime(
                                              '2031-01-31', '%Y-%m-%d')) + 86399}]),
                         'local:j=view@2031-01-31')
        # the team's note emptied: taken away
        con = Con(forms=[{'note': ''}])
        C.team_edit(con, teams()['Con'])
        self.assertEqual(con.acts[0][0], ('--team-edit', 'Con', '--note', ''))
        self.assertEqual(teams()['Con']['note'], '')


def load_agent():
    d = os.path.join(TMP, 'agent')
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    spec = importlib.util.spec_from_file_location(
        'acme_agent_rt5', os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class AgentUnit(unittest.TestCase):
    UNIT = 'a\\x2db.service'

    def test_policy_lines_round_trip(self):
        A = load_agent()
        pol = A.parse_policy("allow unit '%s' restart\nallow unit nginx reload" % self.UNIT)
        self.assertEqual(sorted(pol['units']), ['a\\x2db.service', 'nginx.service'])
        lines = A.policy_lines(pol)
        self.assertIn("allow unit 'a\\x2db.service' restart", lines)
        self.assertIn('allow unit nginx.service reload', lines)        # as before
        self.assertEqual(A.parse_policy('\n'.join(lines))['units'], pol['units'])
        self.assertEqual(A.policy_words(['unit', self.UNIT, 'restart']),
                         "allow unit 'a\\x2db.service' restart")
        need = []
        A.cmd_check(A.parse_policy(''), {'unit': self.UNIT, 'verb': 'restart'}, need)
        self.assertIn("'a\\x2db.service'", need[0]['allow'])

    @unittest.skipIf(os.geteuid() != 0, 'acme-agent allow writes root\'s policy')
    def test_policy_edit(self):
        A = load_agent()
        if os.path.exists(A.POLICY):
            os.unlink(A.POLICY)
        with open(os.devnull, 'w') as dn:
            old, sys.stdout = sys.stdout, dn
            try:
                A.policy_edit(True, ['unit', self.UNIT, 'restart'])
                A.policy_edit(True, ['unit', self.UNIT, 'reload'])
            finally:
                sys.stdout = old
        with open(A.POLICY) as f:
            self.assertEqual(A.parse_policy(f.read())['units'],
                             {self.UNIT: ['restart', 'reload']})

    @unittest.skipIf(not shutil.which('node'), 'no node')
    def test_designer_same_lines(self):
        A = load_agent()
        want = A.policy_lines(A.parse_policy("allow unit '%s' restart" % self.UNIT))
        js = ("var C = require(%s); C.setFacts(%s); var s = C.empty(); s.units = [{name: %s, "
              "verbs: ['restart']}]; var R = C.check(s); console.log(JSON.stringify([R.lines, "
              "C.allowLines(R)]));") % (
            json.dumps(os.path.join(ROOT, 'web', 'assets', 'policybuilder.js')),
            json.dumps(dict(A.policy_facts(), platform='linux')), json.dumps(self.UNIT))
        lines, allow = json.loads(subprocess.run(['node', '-e', js], capture_output=True,
                                                 check=True, text=True).stdout)
        self.assertEqual(lines, want)
        self.assertIn("sudo acme-agent allow unit 'a\\x2db.service' restart", allow)
        self.assertEqual(A.parse_policy('\n'.join(lines))['units'], {self.UNIT: ['restart']})


if __name__ == '__main__':
    unittest.main(verbosity=1)
