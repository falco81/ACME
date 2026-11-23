#!/usr/bin/env python3
"""Bug hunt R, run u5, the command line (acme ...) and the console - the 1.0.128-1.0.134
features.

    python3 test/test_hunt_ru5_cli.py

- acme --check-show NAME did not say the team whose test it is (--check-add/-edit --owner
  TEAM): only --json did;
- the console's Tests could neither show nor set a test's team (Targets could): no owner
  column, not asked when added, no "Its owner" - and deleting a team that owned only tests
  never asked where they go (they became acme's own);
- the console's form of a deployment made with no options of its own (acme --deploy-add
  CERT TARGET) opened and left as it was saved every default (mode=new, replace_via=api,
  admin=0, sslvpn=0 of a FortiGate) - its options changed, so it was deployed again;
- acme --teams-from-groups had no way to the groups picked from the directory (the API's
  `groups`, 1.0.128): --group DN|NAME (again for more), FILTER - for only those, and the ones
  the directory does not know said.
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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-ru5cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
for k, v in ENV.items():
    if k.startswith('ACME_'):
        os.environ[k] = v

from acmelib.certs import console as C  # noqa: E402


def run(*args, env=None):
    got = subprocess.run(ACME + [str(a) for a in args], env=dict(ENV, **(env or {})),
                         capture_output=True, text=True, timeout=120, input='')
    assert 'Traceback' not in got.stdout + got.stderr, got.stderr
    return got


class Con(object):
    """The console as the menus see it, its commands run for real."""
    def __init__(self, forms=(), chooses=(), confirms=(), asks=()):
        self.forms, self.chooses = list(forms), list(chooses)
        self.confirms, self.asks = list(confirms), list(asks)
        self.acts, self.cmds, self.notes, self.offered = [], [], [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        return json.loads(got.stdout or 'null')

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)),
        got if isinstance(got, list) else []))

    def act(self, *args, env=None, **kw):
        got = run(*args, env=env)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def cmd(self, *args):
        self.cmds.append(args)
        return 0

    def live(self, fn):
        fn()

    def pause(self):
        pass

    def form(self, title, fields, words='', check=None, ok='OK'):
        vals = {f['key']: str(f.get('value') or '') if f.get('kind') != 'choice' else (
            f.get('value') if f.get('value') in [o[0] for o in f['options']]
            else f['options'][0][0]) for f in fields}
        ans = self.forms.pop(0) if self.forms else {}
        if ans is None:
            return None
        vals.update(ans)
        return vals

    def ask_one(self, *a, **k):
        return self.asks.pop(0)

    def choose(self, title, options, words='', cur=0):
        self.offered.append((title, options, cur))
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def confirm(self, *a, **k):
        return self.confirms.pop(0) if self.confirms else False

    def note(self, title, words, tone=''):
        self.notes.append((title, words, tone))

    def pick(self, title, load, cols, act=None, empty='', words=''):
        self.rows = load()
        self.cols = cols
        return None


def tests():
    return {r['name']: r for r in json.loads(run('--tests', '--json').stdout)['rows']}


class TeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for args in (('--team-add', 'Web'), ('--team-add', 'Ops'),
                     ('--check-add', 'u5t', '--kind', 'https', '--set', 'host=a.example.com',
                      '--owner', 'Web')):
            got = run(*args)
            assert got.returncode == 0, got.stdout + got.stderr

    def test_check_show_owner(self):
        got = run('--check-show', 'u5t')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertRegex(got.stdout, r'owner\s+Web')
        run('--check-add', 'u5own', '--kind', 'https', '--set', 'host=b.example.com')
        self.assertNotRegex(run('--check-show', 'u5own').stdout, r'\bowner\b')

    def test_console_test_owner(self):
        con = Con()
        C.family(con, 'check')
        self.assertIn('owner', [c[0] for c in con.cols])
        row = tests()['u5t']
        orig = C._plugin
        C._plugin = lambda *a, **k: {}
        try:
            con = Con(chooses=['owner', 'Ops'])
            C.fam_do(con, 'check', row)
            self.assertIn('owner', [o[0] for o in con.offered[0][1]])
            self.assertEqual(con.acts[0][0], ('--check-edit', 'u5t', '--owner', 'Ops'))
            self.assertEqual(con.acts[0][1], 0, con.acts[0][2])
            self.assertEqual(tests()['u5t']['owner'], 'Ops')
            con = Con(chooses=['owner', ''])
            C.fam_do(con, 'check', tests()['u5t'])
            self.assertEqual(con.acts[0][0], ('--check-edit', 'u5t', '--owner', '-'))
            self.assertEqual(tests()['u5t']['owner'], '')
            run('--check-edit', 'u5t', '--owner', 'Web')
        finally:
            C._plugin = orig
        # a new test: whose it is asked, as a target's device
        con = Con(chooses=['https', 'Web'], asks=['u5new'],
                  forms=[{'host': 'c.example.com'}])
        C.fam_add(con, 'check')
        self.assertTrue(any('Whose test' in o[0] for o in con.offered), con.offered)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1][2])
        self.assertEqual(tests()['u5new']['owner'], 'Web')

    def test_team_del_with_only_tests(self):
        run('--team-add', 'OnlyTests')
        run('--check-add', 'u5del', '--kind', 'https', '--set', 'host=d.example.com',
            '--owner', 'OnlyTests')
        teams = json.loads(run('--teams', '--json').stdout)['teams']
        r = [t for t in teams if t['name'] == 'OnlyTests'][0]
        con = Con(chooses=['Ops'], confirms=[True])
        C.team_del(con, r, teams)
        self.assertTrue(any('1 test(s)' in o[0] for o in con.offered), con.offered)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1][2])
        self.assertIn('--reassign', con.acts[-1][0])
        self.assertEqual(tests()['u5del']['owner'], 'Ops')


class DeployForm(unittest.TestCase):
    def test_unchanged_form_changes_nothing(self):
        from acmelib.plugins.targets import fortigate
        fields = fortigate.FortiGateTarget.deploy_fields
        # a deployment made with no options of its own, its form left as it was
        self.assertEqual(C.module_form(Con(), 'x', fields, {}, []), ([], {}))
        self.assertEqual(C.module_form(Con(), 'x', fields, {'mode': 'new'}, []), ([], {}))
        # one thing changed: only that one
        got = C.module_form(Con(forms=[{'mode': 'replace'}]), 'x', fields, {}, [])
        self.assertEqual(got[0], ['--set', 'mode=replace'])
        # a new one as before: what is not empty
        got = C.module_form(Con(), 'x', fields)
        self.assertIn('mode=new', got[0])


class FromGroups(unittest.TestCase):
    def setUp(self):
        from acmelib import engine as E
        from acmelib.certs import api_teams, cli
        self.api_teams = api_teams
        self.store = E.cli_store()

        class AD(object):
            name = 'corp'

            def find_groups(self, literal, limit=5000):
                return [{'cn': 'PKI-Web', 'dn': 'CN=PKI-Web,DC=corp', 'description': 'web'},
                        {'cn': 'Other', 'dn': 'CN=Other,DC=corp'}]

        known = {'cn=pki-db,dc=corp': ('CN=PKI-Db,DC=corp', 'PKI-Db', 'db'),
                 'pki-db': ('CN=PKI-Db,DC=corp', 'PKI-Db', 'db'),
                 'cn=pki-web,dc=corp': ('CN=PKI-Web,DC=corp', 'PKI-Web', 'web')}
        self.patches = [mock.patch.object(api_teams, '_need_dir', lambda h, n=None: AD()),
                        mock.patch.object(api_teams, 'group_entry',
                                          lambda ad, name: known.get(name.lower()))]
        for p in self.patches:
            p.start()

        class Args(object):
            member_role = None
            parent = None
            team_kind = None
            yes = False
            group = None
        self.c = cli.Cli.__new__(cli.Cli)
        self.c.store, self.c.WHO, self.c.args, self.c.json = self.store, 'command line', \
            Args(), True
        self.c.out = lambda data: setattr(self, 'got', data)

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_picked(self):
        f = self.api_teams._cli_from_groups
        self.c.args.group = ['CN=PKI-Db,DC=corp', 'cn=pki-web,dc=corp']
        self.assertEqual(f(self.c, 'PKI-*'), 0)
        self.assertEqual(sorted(g['cn'] for g in self.got['groups']), ['PKI-Db', 'PKI-Web'])
        self.assertEqual(self.got['picked'], 2)
        # only those picked
        self.c.args.group = ['PKI-Db', 'nowhere']
        self.assertEqual(f(self.c, '-'), 0)
        self.assertEqual([g['cn'] for g in self.got['groups']], ['PKI-Db'])
        self.assertEqual(self.got['missing'], ['nowhere'])
        self.assertTrue(self.got['dry_run'])
        # - without a group picked
        self.c.args.group = None
        with self.assertRaises(SystemExit) as e:
            f(self.c, '-')
        self.assertIn('--group', str(e.exception.code))
        # the words: what the directory does not know
        self.c.json = False
        self.c.args.group = ['nowhere']
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(f(self.c, '-'), 1)
        self.assertIn('does not know: nowhere', err.getvalue())

    def test_group_refused_elsewhere(self):
        got = run('--teams', '--group', 'x')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--group goes with --teams-from-groups', got.stderr)
        got = run('--teams-from-groups', '-')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--group DN|NAME', got.stderr)
        self.assertIn('--group DN|NAME', run('--help').stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
