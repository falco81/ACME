#!/usr/bin/env python3
"""Bug hunt R, run t4, the console (acme --console) and the 1.0.125 features (1.0.126).

    python3 test/test_hunt_rt4_console.py

- Owners and teams in the console: the tree, a team shown (members, roles, limits), a team or a
  unit added, changed, moved, its limits, its members added / changed / taken away with their
  roles (the others written back as they were), the roles, the access check of a person, what
  happened in a team, a team deleted (the teams below it and its certificates moved) - each one
  the command line's own acme --teams, --team-add/-edit/-del, --roles, --team-access,
  --team-activity, run here for real on a state of its own;
- a member the command line cannot write back (a DN, a note) is not changed from here;
- a certificate's owner is a team chosen, as the page's Owner (it was typed as text: a misspelt
  team made a free-text owner), one typed before kept as it is;
- a target's owner (the team whose device it is): a column, set and changed; an enrollment code
  of a team; the target agent's discovery (only some kinds, the last one) and the Microsoft CAs'
  templates (adcs-templates).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rt4console-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))

from acmelib.certs import console as C  # noqa: E402


def run(*args):
    return subprocess.run(ACME + [str(a) for a in args], env=ENV, capture_output=True,
                          text=True, timeout=120, input='')


def teams():
    return {t['name']: t for t in json.loads(run('--teams', '--json').stdout)['teams']}


class Con(object):
    """The console as the menus see it, its commands run for real; what a person answers
    given in order."""
    def __init__(self, forms=(), chooses=(), confirms=(), asks=()):
        self.forms, self.chooses = list(forms), list(chooses)
        self.confirms, self.asks = list(confirms), list(asks)
        self.acts, self.cmds, self.notes, self.shown, self.offered = [], [], [], [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        self.out_err = '' if got.returncode == 0 else got.stderr
        return json.loads(got.stdout or 'null')

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)),
        got if isinstance(got, list) else []))

    def act(self, *args, env=None, **kw):
        got = run(*args)
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
        self.shown.append((title, fields))
        vals = {f['key']: str(f.get('value') or '') if f.get('kind') != 'choice' else (
            f.get('value') if f.get('value') in [o[0] for o in f['options']]
            else f['options'][0][0]) for f in fields}
        ans = self.forms.pop(0)
        if ans is None:
            return None
        vals.update(ans)
        for f in fields:
            if f.get('check'):
                bad = f['check'](vals[f['key']], vals)
                if bad:
                    raise AssertionError('%s: %s' % (f['key'], bad))
        return vals

    def ask_one(self, title, label, value='', help_='', need=True, secret=False, check=None):
        got = self.asks.pop(0)
        if got is not None and check:
            assert check(got, {}) is None, check(got, {})
        return got

    def choose(self, title, options, words='', cur=0):
        self.offered.append((title, options, cur))
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def confirm(self, *a, **k):
        return self.confirms.pop(0) if self.confirms else True

    def note(self, title, words, tone=''):
        self.notes.append((title, words, tone))

    def sub(self, title, items):
        self.items = items

    def pick(self, title, load, cols, act=None, empty='', words=''):
        self.rows = load()
        self.cols = cols
        self.pick_act = act
        return None


class Teams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert run('--team-add', 'IT', '--team-kind', 'unit').returncode == 0

    def test_1_menu_and_add(self):
        self.assertTrue(any(k == 'o' and 'teams' in w for k, w, _f in C.main_items(Con())))
        con = Con()
        C.teams_menu(con)
        self.assertEqual([x[0] for x in con.items], ['1', '2', '3', '4', '5', '6'])
        # a team under IT, with a member added at once
        con = Con(forms=[{'name': 'Web', 'kind': 'team', 'parent': 'IT', 'description': 'web',
                          'contact_mail': 'web@example.com'}], confirms=[False])
        C.team_add(con)
        self.assertEqual(con.acts[0][1], 0, con.acts[0][2])
        t = teams()['Web']
        self.assertEqual((t['parent'], t['kind'], t['description'], t['contact_mail']),
                         ('IT', 'team', 'web', 'web@example.com'))
        # the tree: indented under its unit
        con = Con()
        C.teams_tree(con)
        names = [con.cols[0][1](r) for r in con.rows]
        self.assertIn('  Web', names)
        self.assertIn('IT', names)

    def test_2_members(self):
        run('--team-add', 'Mail', '--members', 'local:eva=view+request@2030-06-30')
        before = teams()['Mail']['members'][0]
        # one added with roles and an end
        con = Con(forms=[{'who': 'local:jan', 'roles': 'Requester+Deployer',
                          'until': '2031-01-31'}])
        C.team_members(con, 'Mail')
        con.pick_act(con.rows[0])
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1][2])
        got = {m['who']: m for m in teams()['Mail']['members']}
        self.assertEqual(got['local:jan']['roles'], ['Requester', 'Deployer'])
        self.assertEqual(C._day(got['local:jan']['until']), '2031-01-31')
        self.assertEqual(got['local:eva'], before)          # the other one as it was
        # its roles changed
        con = Con(chooses=['edit'], forms=[{'roles': 'Viewer', 'until': ''}])
        C.team_members(con, 'Mail')
        con.pick_act([r for r in con.rows if r.get('who') == 'local:jan'][0])
        got = {m['who']: m for m in teams()['Mail']['members']}
        self.assertEqual((got['local:jan']['roles'], got['local:jan'].get('until')),
                         (['Viewer'], None))
        self.assertEqual(got['local:eva'], before)
        # taken away
        con = Con(chooses=['del'])
        C.team_members(con, 'Mail')
        con.pick_act([r for r in con.rows if r.get('who') == 'local:jan'][0])
        self.assertEqual([m['who'] for m in teams()['Mail']['members']], ['local:eva'])
        # a role that does not exist: said in the form
        con = Con(forms=[{'who': 'local:x', 'roles': 'Nobody'}])
        C.team_members(con, 'Mail')
        with self.assertRaises(AssertionError):
            con.pick_act(con.rows[0])

    def test_3_member_not_written_back(self):
        # a DN member and a member's note, as the pages give them: the command line cannot say
        # them, so nothing is written from here
        self.assertTrue(C._member_said({'who': 'CN=PKI,OU=Groups,DC=example,DC=com'}))
        self.assertTrue(C._member_said({'who': 'local:a', 'note': 'until the audit'}))
        self.assertFalse(C._member_said({'who': 'group:Web', 'roles': ['Requester']}))
        con = Con()
        orig = C._teams
        C._teams = lambda _c: [{'name': 'Dn', 'members': [
            {'who': 'CN=PKI,OU=Groups,DC=example,DC=com', 'rights': ['view']}]}]
        try:
            C.team_members(con, 'Dn')
            con.pick_act(con.rows[0])
        finally:
            C._teams = orig
        self.assertEqual(con.acts, [])
        self.assertEqual(con.notes[0][2], 'bad')
        self.assertEqual(C._member_word({'who': 'local:j', 'rights': ['view'], 'roles': ['Deployer'],
                                         'until': 1798847999.0}),
                         'local:j=view+Deployer@%s' % C._day(1798847999.0))

    def test_4_edit_move_limits_show(self):
        run('--team-add', 'Ops', '--note', 'n1')
        t = teams()['Ops']
        con = Con(forms=[{'description': 'operations', 'kind': 'unit'}])
        C.team_edit(con, t)
        self.assertEqual(con.acts[0][0], ('--team-edit', 'Ops', '--team-kind', 'unit',
                                          '--description', 'operations'))
        con = Con(forms=[{}])
        C.team_edit(con, teams()['Ops'])
        self.assertEqual(con.acts, [])
        self.assertIn('Nothing', con.notes[0][1])
        # moved under IT, then to the top level again
        con = Con(chooses=['move', 'IT'])
        C.team_do(con, teams()['Ops'])
        self.assertEqual(teams()['Ops']['parent'], 'IT')
        self.assertNotIn('Ops', [o[0] for o in con.offered[1][1]])     # not under itself
        con = Con(chooses=['move', ''])
        C.team_do(con, teams()['Ops'])
        self.assertIsNone(teams()['Ops']['parent'])
        # its limits
        con = Con(asks=['{"max_days": 90}'])
        C.team_limits(con, teams()['Ops'])
        self.assertEqual(teams()['Ops']['policy'], {'max_days': 90})
        con = Con(asks=['{"max_days": 90}'])
        C.team_limits(con, teams()['Ops'])
        self.assertEqual(con.acts, [])
        # shown: kind, members, limits
        text = C.team_text(teams()['Ops'], list(teams().values()))
        self.assertIn('max_days 90', text)
        self.assertIn('unit', text)

    def test_5_roles_access_activity(self):
        con = Con()
        C.roles_list(con)
        self.assertIn('Viewer', [r['name'] for r in con.rows])
        con.pick_act([r for r in con.rows if r['name'] == 'Viewer'][0])
        self.assertIn('cert.view', con.notes[0][1])
        run('--team-add', 'Acc', '--members', 'local:petr=Requester')
        con = Con(asks=['local:petr'])
        C.team_access(con)
        self.assertEqual(con.acts[0][1], 0, con.acts[0][2])
        self.assertIn('Acc', con.acts[0][2])
        con = Con(chooses=['Acc'], forms=[{'below': '1', 'limit': '5'}])
        C.team_activity(con)
        self.assertEqual(con.acts[0][0], ('--team-activity', 'Acc', '--limit', '5', '--below'))
        self.assertEqual(con.acts[0][1], 0, con.acts[0][2])
        self.assertIn('Acc', con.acts[0][2])

    def test_6_delete(self):
        run('--team-add', 'Top', '--team-kind', 'unit')
        run('--team-add', 'Child', '--parent', 'Top')
        run('--team-add', 'Heir')
        run('--cert-add', 'rt4c', '--names', 'rt4c.example.com', '--challenge',
            'This server HTTP-01', '--set', 'owner=Top')
        # the team below it to the top level, its certificate to Heir
        con = Con(chooses=['', 'Heir'])
        C.team_del(con, teams()['Top'], list(teams().values()))
        self.assertEqual(con.acts[0][1], 0, con.acts[0][2])
        got = teams()
        self.assertNotIn('Top', got)
        self.assertIsNone(got['Child']['parent'])
        cert = json.loads(run('--cert', 'rt4c', '--json').stdout)['cert']
        self.assertEqual(cert['owner'], 'Heir')
        # nothing asked of a team with nothing in it
        con = Con(confirms=[True])
        C.team_del(con, got['Child'], list(got.values()))
        self.assertEqual(con.acts[0][0], ('--team-del', 'Child', '--yes'))
        self.assertNotIn('Child', teams())


class Owners(unittest.TestCase):
    def test_cert_owner_is_a_team(self):
        run('--team-add', 'Own')
        opts = C._owner_options(Con(), '')
        self.assertEqual(opts[0][0], '')
        self.assertIn('Own', [o[0] for o in opts])
        # one typed before, in other letters or not a team at all: kept as it is
        self.assertIn('own', [o[0] for o in C._owner_options(Con(), 'own')])
        self.assertNotIn('Own', [o[0] for o in C._owner_options(Con(), 'own')])
        self.assertIn('legacy-x', [o[0] for o in C._owner_options(Con(), 'legacy-x')])
        # the edit form: a choice; nothing changed - nothing sent
        run('--cert-add', 'rt4o', '--names', 'rt4o.example.com', '--challenge',
            'This server HTTP-01', '--set', 'owner=legacy-x')
        con = Con(forms=[{}])
        C.cert_edit(con, {'name': 'rt4o'})
        f = [x for x in con.shown[0][1] if x['key'] == 'owner'][0]
        self.assertEqual(f['kind'], 'choice')
        self.assertEqual(con.acts, [])
        con = Con(forms=[{'owner': 'Own'}])
        C.cert_edit(con, {'name': 'rt4o'})
        self.assertEqual(con.acts[0][0], ('--cert-edit', 'rt4o', '--set', 'owner=Own'))
        self.assertEqual(json.loads(run('--cert', 'rt4o', '--json').stdout)['cert']['owner'],
                         'Own')

    def test_target_owner(self):
        run('--team-add', 'Dev')
        self.assertEqual(run('--target-add', 'rt4t', '--kind', 'webhook', '--set',
                             'url=https://hook.example.com/').returncode, 0)
        con = Con()
        C.family(con, 'target')
        self.assertIn('owner', [c[0] for c in con.cols])
        row = [r for r in con.rows if r.get('name') == 'rt4t'][0]
        orig = C._plugin
        C._plugin = lambda *a, **k: {}
        try:
            con = Con(chooses=['owner', 'Dev'])
            C.fam_do(con, 'target', row)
            self.assertEqual(con.acts[0][0], ('--target-edit', 'rt4t', '--owner', 'Dev'))
            rows = Con().out('--targets')['rows']
            self.assertEqual([r['owner'] for r in rows if r['name'] == 'rt4t'], ['Dev'])
            row = [r for r in rows if r['name'] == 'rt4t'][0]
            con = Con(chooses=['owner', ''])
            C.fam_do(con, 'target', row)
            self.assertEqual(con.acts[0][0], ('--target-edit', 'rt4t', '--owner', '-'))
            self.assertEqual([r['owner'] for r in Con().out('--targets')['rows']
                              if r['name'] == 'rt4t'], [''])
        finally:
            C._plugin = orig

    def test_enroll_code_of_a_team(self):
        run('--team-add', 'Srv')
        con = Con(forms=[{'title': 'x', 'team': 'Srv'}])
        C.enroll_new(con)
        self.assertIn('Srv', [o[0] for o in [f for f in con.shown[0][1]
                                             if f['key'] == 'team'][0]['options']])
        self.assertEqual(con.cmds[0][-2:], ('--owner', 'Srv'))


class Agent(unittest.TestCase):
    def test_discover_and_adcs(self):
        for what, more, want in (
                ('discover-cached', [], ('--target-agent', 'w1', 'discover', 'cached')),
                ('discover-kinds', ['iis,rdp'], ('--target-agent', 'w1', 'discover', '--kind',
                                                 'iis,rdp')),
                ('adcs', [], ('--target-agent', 'w1', 'adcs-templates')),
                ('adcs-one', ['ca01.example.local\\Issuing CA'],
                 ('--target-agent', 'w1', 'adcs-templates', 'ca01.example.local\\Issuing CA'))):
            con = Con(chooses=[what], asks=more)
            con.act = lambda *a, **k: con.cmds.append(a)
            C.target_agent(con, 'w1', 'agent_windows')
            self.assertEqual(con.cmds, [want], what)
        # a Linux agent is not offered the Microsoft CAs
        con = Con(chooses=[None])
        C.target_agent(con, 'l1', 'agent')
        keys = [o[0] for o in con.offered[0][1]]
        self.assertNotIn('adcs', keys)
        self.assertIn('discover-cached', keys)
        # the last discovery of a target never asked: said, not "0 services found"
        run('--target-add', 'rt4a', '--kind', 'agent', '--set', 'host=a.example.com')
        got = run('--target-agent', 'rt4a', 'discover', 'cached')
        self.assertIn('no discovery was asked', got.stdout + got.stderr)



class MultilineSecret(unittest.TestCase):
    """A secret of several lines (ms_adcs client_key, a PEM key) was a one-line hidden box:
    a key pasted there ended at its first line's end, and that line alone was saved."""
    def test_read_from_a_file(self):
        from acmelib.plugins.issuers import ms_adcs
        fields = [f for f in ms_adcs.MsAdcsIssuer.fields if f['key'] in ('client_key', 'password')]
        got = {x['key']: x for x in C._form_fields(fields, {}, ())}
        self.assertEqual(got['password']['kind'], 'secret')        # one line: as before
        self.assertNotEqual(got['client_key'].get('kind'), 'secret')
        self.assertIn('(file)', got['client_key']['label'])
        key = os.path.join(TMP, 'client.key')
        pem = '-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n'
        with open(key, 'w') as f:
            f.write(pem)
        argv, env = C.module_form(Con(forms=[{'client_key': key, 'password': 'pw'}]), 'x',
                                  fields)
        self.assertIn('client_key=@file:%s' % key, argv)
        self.assertEqual(env, {'ACME_VALUE_PASSWORD': 'pw'})
        # empty: kept as it is
        argv, env = C.module_form(Con(forms=[{'client_key': ''}]), 'x', fields,
                                  {'client_key': '\u2022' * 8}, ('client_key',))
        self.assertNotIn('client_key', ' '.join(argv))
        # the command line saves the whole key from the file
        got = run('--source-add', 'rt4adcs', '--kind', 'ms_adcs', '--set',
                  'url=https://ca.example.com/certsrv', '--set', 'template=WebServer',
                  '--set', 'auth=cert', '--set', 'client_key=@file:%s' % key)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        # read back as the daemon reads it: the whole key, every line
        code = ('import sys; sys.path.insert(0, %r); from acmelib import engine as E; '
                'from acmelib.certs import store as S; st = E.cli_store(); '
                'print(S.plugin_config("issuer", S.plugin_row(st, "issuer", "rt4adcs"))'
                '["client_key"], end="")' % ROOT)
        got = subprocess.run([sys.executable, '-c', code], env=ENV, capture_output=True,
                             text=True, timeout=120)
        self.assertEqual(got.stdout.strip(), pem.strip(), got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
