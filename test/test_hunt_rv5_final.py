#!/usr/bin/env python3
"""Bug hunt 1.0.142, run v5, final: the command line and the console of what 1.0.138-1.0.142
gave the pages, run end to end in a realistic order on a state of its own, and the leftovers of
the parity table closed:

- `--ca-revoke ... --reason privilegeWithdrawn` was stored as `unspecified` without a word (the
  CRL then said something else than what was asked; openssl's `ca -gencrl` cannot take the
  reason at all): refused clearly, before it is asked, and so is the own CA's revocation through
  `--revoke`; after `--ca-revoke` the CLI said "acme --ca-crl CA makes its CRL now" though the
  CRL was made already;
- the console's authority menu changes an authority in a form (`acme --ca-edit`, only what was
  changed is sent);
- `acme --local-user add NAME --local-sudo` (the page and the console had sudo for a new user);
- a team's console menu saves it as a team template (the templates' list pointed there and it
  was not), *Who can* and *Teams from a CSV file* in the console (the command line only);
- every console item of the features run against the state.

    python3 test/test_hunt_rv5_final.py
"""
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
TMP = tempfile.mkdtemp(prefix='acme-rv5final-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))


def run(*args, stdin=''):
    return subprocess.run(ACME + [str(a) for a in args], env=ENV, capture_output=True,
                          text=True, timeout=180, input=stdin)


def ok(test, *args, stdin=''):
    got = run(*args, stdin=stdin)
    test.assertEqual(got.returncode, 0, '%s: %s%s' % (args, got.stdout, got.stderr))
    return got


def js(test, *args):
    return json.loads(ok(test, *(list(args) + ['--json'])).stdout)


def setUpModule():
    for args in (('--ca-create', 'Root T', '--subject', 'CN=Root T,O=Example'),
                 ('--ca-sub', 'Issuing T', '--parent', 'Root T', '--subject', 'CN=Issuing T'),
                 ('--source-add', 'Own', '--kind', 'internal_ca', '--set', 'ca=Issuing T'),
                 ('--cert-add', 'web1', '--names', 'a.example.com', '--issuer', 'Own'),
                 ('--renew', 'web1'),
                 ('--team-add', 'Web', '--members', 'local:jan=manage,local:eva=view',
                  '--contact-mail', 'web@example.com'),
                 ('--target-add', 'srv1', '--kind', 'agent', '--set', 'host=a.example.com'),
                 ('--profile-from-template', 'web', '--name', 'Pw', '--names', 'example.com'),
                 ('--profile-from-template', 'web', '--name', 'Pw2', '--names', 'example.org'),
                 ('--report-add', 'R1', '--report-kind', 'expiry', '--report-formats',
                  'csv,pdf', '--report-days', '30')):
        got = run(*args)
        assert got.returncode == 0, (args, got.stdout + got.stderr)


def issued(test, ca='Issuing T'):
    return js(test, '--ca-show', ca)['issued']


# ---------------------------------------------------------------------------------------------
class RevocationReason(unittest.TestCase):
    def test_norm_reason(self):
        from acmelib.certs import ca as CA
        from acmelib.certs.pki import PkiError
        for r in ('privilegeWithdrawn', 'AACompromise', 'removeFromCRL', '9'):
            with self.assertRaises(PkiError) as e:
                CA.norm_reason(r)
            self.assertIn('openssl does not take it', str(e.exception))
        self.assertEqual(CA.norm_reason('cACompromise'), 'CACompromise')
        self.assertEqual(CA.norm_reason('hold'), 'certificateHold')
        self.assertEqual(CA.norm_reason(''), 'unspecified')

    def test_ca_revoke_refused_then_held_and_released(self):
        s = issued(self)[0]['serial']
        got = run('--ca-revoke', 'Issuing T', s, '--reason', 'privilegeWithdrawn')
        self.assertEqual(got.returncode, 1)
        self.assertIn('openssl does not take it', got.stderr)
        self.assertNotIn('again with --yes', got.stderr)        # refused before it is asked
        self.assertEqual(issued(self)[0].get('revoked'), None)
        got = ok(self, '--ca-revoke', 'Issuing T', s, '--reason', 'certificateHold', '--yes')
        self.assertIn('its CRL is made anew', got.stdout)
        self.assertNotIn('makes its CRL now', got.stdout)
        crl = js(self, '--ca-show', 'Issuing T')['ca']['crl_pem']
        from acmelib.certs import pki
        self.assertEqual([r['reason'] for r in pki.crl_info(crl)['revoked']], ['certificateHold'])
        ok(self, '--ca-unrevoke', 'Issuing T', s)

    def test_revoke_through_the_own_ca_source(self):
        ok(self, '--cert-add', 'web9', '--names', 'z.example.com', '--issuer', 'Own')
        ok(self, '--renew', 'web9')
        got = run('--revoke', 'web9', '--reason', 'privilegeWithdrawn', '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('openssl does not take it', got.stdout + got.stderr)
        row = next(r for r in issued(self) if 'z.example.com' in (r.get('names') or
                                                                  r.get('subject_dn') or ''))
        self.assertIsNone(row.get('revoked'))                  # nothing stored as unspecified
        ok(self, '--revoke', 'web9', '--reason', 'superseded', '--yes')


class LocalSudo(unittest.TestCase):
    """acme --local-user add NAME --local-sudo: asked of the nodes as the page asks."""

    def cli(self, *argv):
        import acme  # noqa: F401
        from acmelib import engine as E
        asked = []
        args = E.build_parser().parse_args(list(argv))
        view = {'nodes': [{'name': 'acme1', 'pending': 0, 'said': [
            {'name': 'jnovak', 'ok': True, 'said': 'added'}]}]}
        with mock.patch.object(E, 'cli_store', lambda: object()), \
                mock.patch.object(E, 'host_nodes', lambda store: ['acme1']), \
                mock.patch.object(E, 'cli_who', lambda: 'root (command line)'), \
                mock.patch.object(E, 'osu_view', lambda store: view), \
                mock.patch.object(E, 'osu_ask', lambda store, nodes, do, by, **f:
                                  asked.append((do, f)) or list(nodes)), \
                mock.patch.object(sys.stdin, 'isatty', lambda: True), \
                mock.patch('getpass.getpass', lambda prompt='': 'Secret-pw-1'):
            rc = E.cli_osusers(args, E.Palette(False))
        return rc, [a for a in asked if a[0] != 'list']

    def test_add_with_and_without_sudo(self):
        rc, asked = self.cli('--local-user', 'add', 'jnovak', '--local-sudo')
        self.assertEqual(rc, 0)
        self.assertEqual(asked[-1][0], 'add')
        self.assertTrue(asked[-1][1]['sudo'])
        self.assertEqual(asked[-1][1]['shell'], '/bin/bash')
        rc, asked = self.cli('--local-user', 'add', 'jnovak')
        self.assertFalse(asked[-1][1]['sudo'])

    def test_documented(self):
        with open(os.path.join(ROOT, 'docs', 'local-users.md'), encoding='utf-8') as f:
            self.assertIn('--local-sudo', f.read())


# ---------------------------------------------------------------------------------------------
class Con(object):
    """The console as its menus see it; what a person answers given in order."""
    def __init__(self, chooses=(), asks=(), forms=(), confirms=True):
        self.chooses, self.asks, self.forms = list(chooses), list(asks), list(forms)
        self.confirms = confirms
        self.acts, self.notes, self.subs, self.forms_seen = [], [], [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        try:
            return json.loads(got.stdout or 'null')
        except ValueError:
            return None

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)), []))

    def act(self, *args, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def cmd(self, *args, **kw):
        return self.act(*args)

    def live(self, fn):
        fn()

    def pause(self):
        pass

    def sub(self, title, items):
        self.subs.append((title, items))

    def pick(self, title, load, cols, act=None, empty='', words=''):
        rows = load()
        for c in cols:
            for r in rows:
                c[1](r)
        want = getattr(self, 'row', None)
        if act and rows and self.chooses:
            row = next((r for r in rows if want and want(r)), rows[0])
            act(row)
        return rows

    def choose(self, title, options, words='', cur=0):
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def ask_one(self, *a, **k):
        return self.asks.pop(0)

    def form(self, title, fields, words='', check=None, ok='OK'):
        self.forms_seen.append((title, fields))
        vals = {}
        for f in fields:
            v = f.get('value')
            if f.get('kind') == 'choice' and v not in [o[0] for o in f['options']]:
                v = f['options'][0][0]
            vals[f['key']] = str(v if v is not None else '')
        vals.update(self.forms.pop(0))
        return vals

    def confirm(self, *a, **k):
        return self.confirms

    def note(self, title, words, tone=''):
        self.notes.append((title, words))

    def details(self, *a, **k):
        pass


def last(test, con, want_rc=0):
    test.assertTrue(con.acts, con.notes)
    args, rc, text = con.acts[-1]
    test.assertEqual(rc, want_rc, '%s: %s' % (args, text))
    return args, text


class ConsoleAuthority(unittest.TestCase):
    def test_edit_form_sends_what_was_changed(self):
        from acmelib.certs import console as C
        con = Con(chooses=['edit'], forms=[{'note': 'kept by PKI', 'days_default': '120'}])
        C.ca_do(con, {'name': 'Issuing T'})
        args, _t = last(self, con)
        self.assertEqual(args[:2], ('--ca-edit', 'Issuing T'))
        self.assertEqual(sorted(args[2:]), sorted(['--set', 'days_default=120', '--set',
                                                   'note=kept by PKI']))
        one = js(self, '--ca-show', 'Issuing T')['ca']
        self.assertEqual((one['note'], one['days_default']), ('kept by PKI', 120))
        # nothing changed: nothing run
        con = Con(chooses=['edit'], forms=[{}])
        C.ca_do(con, {'name': 'Issuing T'})
        self.assertEqual(con.acts, [])
        self.assertEqual(con.notes[-1][0], 'Nothing changed')
        # switched off and on, renamed and back - the form's own values
        con = Con(chooses=['edit'], forms=[{'disabled': 'yes'}])
        C.ca_do(con, {'name': 'Issuing T'})
        last(self, con)
        self.assertTrue(js(self, '--ca-show', 'Issuing T')['ca']['disabled'])
        con = Con(chooses=['edit'], forms=[{'disabled': 'no', 'name': 'Issuing T2'}])
        C.ca_do(con, {'name': 'Issuing T'})
        last(self, con)
        ok(self, '--ca-edit', 'Issuing T2', '--set', 'name=Issuing T')
        self.assertFalse(js(self, '--ca-show', 'Issuing T')['ca']['disabled'])

    def test_revoke_form_offers_only_what_a_crl_takes(self):
        from acmelib.certs import ca as CA
        from acmelib.certs import console as C
        con = Con(chooses=['revoke'], forms=[{'serial': 'AB'}], confirms=False)
        C.ca_do(con, {'name': 'Issuing T'})
        fields = con.forms_seen[-1][1]
        for value, _w in next(f for f in fields if f['key'] == 'reason')['options']:
            CA.norm_reason(value)


class ConsoleWalk(unittest.TestCase):
    """Every console item of 1.0.138-1.0.142 run in order; each command it runs must work."""

    def test_h_menu(self):
        from acmelib.certs import cli_138 as M
        from acmelib.certs import console as C
        con = Con()
        dict((k, f) for k, _w, f in C.main_items(con))['h']()
        items = {k: f for k, _w, f in con.subs[-1][1]}
        for k in ('4', '5', '9'):
            items[k]()
            last(self, con)
        items['7']()                                    # drift: 0, or 1 when one differs
        self.assertIn(con.acts[-1][1], (0, 1))
        # history (show, restore) and the trash (restore under a name, purge)
        ok(self, '--team-add', 'Walk1')
        ok(self, '--team-edit', 'Walk1', '--note', 'n1')
        con = Con(chooses=['show'])
        M._con_history(con)
        last(self, con)
        con = Con(chooses=['restore'])
        M._con_history(con)
        last(self, con)
        ok(self, '--team-del', 'Walk1', '--yes')
        con = Con(chooses=['restore-as'], asks=['Walk1b'])
        con.row = lambda r: r.get('name') == 'Walk1'
        M._con_trash(con)
        last(self, con)
        ok(self, '--tag-add', 'walktag')
        ok(self, '--tag-del', 'walktag', '--yes')
        con = Con(chooses=['purge'])
        con.row = lambda r: r.get('name') == 'walktag'
        M._con_trash(con)
        last(self, con)
        # request profiles: every item
        for chooses, asks in ((['show'], []), (['versions'], []), (['diff'], ['1']),
                              (['restore'], ['1']), (['dry'], ['www.example.com'])):
            con = Con(chooses=chooses, asks=asks)
            con.row = lambda r: r.get('name') == 'Pw'
            M._con_profiles(con)
            last(self, con)
        con = Con(chooses=['end'], asks=['Pw2'])
        con.row = lambda r: r.get('name') == 'Pw'
        M._con_profiles(con)
        last(self, con)
        con = Con(chooses=['unend'])
        con.row = lambda r: r.get('name') == 'Pw'
        M._con_profiles(con)
        last(self, con)
        # groups: a new one, changed, its plan, deleted
        con = Con(chooses=['new'], forms=[{'name': 'G1', 'members': 'srv1', 'canary': 'yes'}])
        M._con_groups(con)
        last(self, con)
        for what in ('edit', 'plan', 'del'):
            con = Con(chooses=[what], forms=[{'members': 'srv1', 'canary': 'no'}])
            con.row = lambda r: r.get('name') == 'G1'
            M._con_groups(con)
            last(self, con)
        self.assertEqual(js(self, '--fleet')['groups'], [])
        con = Con(chooses=['plan'])
        M._con_rollout(con)
        last(self, con)
        con = Con(chooses=['new'])
        M._con_unmanaged(con)                            # nothing found: no row, nothing run
        self.assertEqual(con.acts, [])

    def test_certificates_menu_items_of_1_0_140(self):
        from acmelib.certs import console_ui as U
        con = Con(chooses=['x'], asks=['example'])
        con.row = lambda r: r.get('name') == 'web1'
        U.find(con)
        last(self, con)
        con = Con()
        U.calendar(con)
        items = {k: f for k, _w, f in con.subs[-1][1]}
        con.forms = [{'weeks': '8', 'team': 'Web'}, {'path': os.path.join(TMP, 'c.ics'),
                                                    'lang': 'cs'}]
        con.asks = ['all']
        for k in ('1', '2', '3', '4'):
            items[k]()
            last(self, con)
        self.assertTrue(os.path.exists(os.path.join(TMP, 'c.ics')))
        con = Con(chooses=['x'], forms=[{'name': 'FromTpl', 'names': 'example.net'}])
        con.row = lambda r: r.get('id') == 'web'
        U.templates(con)
        last(self, con)

    def test_agents_and_an_agent(self):
        from acmelib.certs import console as C
        con = Con()
        C.agents_menu(con)
        items = {k: f for k, _w, f in con.subs[-1][1]}
        items['8']()
        last(self, con)
        for what, forms, rc in (('watch', [], 0), ('guard', [], 0),
                                ('watch-set', [{'audit': 'on', 'anomaly': 'on'}], 0),
                                ('watch-set', [{'audit': 'off', 'anomaly': 'off'}], 0)):
            con = Con(chooses=[what], forms=forms)
            C.target_agent(con, 'srv1', 'agent')
            last(self, con, rc)

    def test_teams_menu_and_a_team(self):
        from acmelib.certs import console as C
        con = Con()
        C.teams_menu(con)
        items = {k: f for k, _w, f in con.subs[-1][1]}
        self.assertEqual(len(items), len(con.subs[-1][1]))
        for k in ('7', '9'):
            items[k]()
            last(self, con)
        con.asks = ['team:Web']
        items['w']()
        last(self, con)
        con.forms = [{'cap': 'cert.renew', 'where': 'Web'}]
        items['n']()
        args, text = last(self, con)
        self.assertEqual(args, ('--who-can', 'cert.renew', 'Web'))
        self.assertIn('local:jan', text)
        # a team: its governance in forms, reviews, channels, saved as a template
        for chooses, forms, asks in (
                (['health'], [], []), (['gov'], [], []),
                (['gov-set', 'review'], [{'on': 'on', 'every_days': '90', 'answer_days': '14'}],
                 []),
                (['gov-set', 'jit'], [{'on': 'on', 'roles': 'Requester', 'max_hours': '4'}], []),
                (['gov-set', 'sod'], [{'no_self_approval': 'yes',
                                       'exclusive': 'Requester + Approver'}], []),
                (['gov-set', 'notify'], [{'on': 'on', 'mail': 'web@example.com'}], []),
                (['reviews', 'open'], [], []), (['reviews', 'show'], [], []),
                (['reviews', 'answer'], [{'id': '1', 'who': 'local:eva', 'keep': 'keep'}], []),
                (['template-save'], [{'tpl': 'WebTpl', 'members': 'yes'}], [])):
            con = Con(chooses=chooses, forms=forms, asks=asks)
            C.team_do(con, {'name': 'Web'})
            last(self, con)
        gov = js(self, '--team-gov', 'Web')['gov']
        self.assertEqual(gov['jit']['max_hours'], 4)
        self.assertTrue(gov['sod']['no_self_approval'])
        tpl = next(t for t in js(self, '--team-templates')['templates'] if t['name'] == 'WebTpl')
        self.assertEqual(len(tpl['config'].get('members') or []), 2)     # --template-members
        con = Con(chooses=['notify-test'])
        C.team_do(con, {'name': 'Web'})
        self.assertIn(con.acts[-1][1], (0, 1))           # mail is off here: said, exit 1
        # the templates: a team from one, deleted
        con = Con()
        C.teams_menu(con)
        items = {k: f for k, _w, f in con.subs[-1][1]}
        con.chooses, con.asks = ['make'], ['FromWebTpl']
        con.row = lambda r: r.get('name') == 'WebTpl'
        items['m']()
        last(self, con)
        con.chooses = ['del']
        items['m']()
        last(self, con)
        # teams from a CSV file: said first, then made
        path = os.path.join(TMP, 'teams.csv')
        with open(path, 'w') as f:
            f.write('name,parent,members\nCsvWalk,,local:jan=manage\n')
        con.asks = [path]
        items['i']()
        self.assertEqual(con.acts[-2][0], ('--teams-import-csv', path))
        self.assertEqual(con.acts[-1][0], ('--teams-import-csv', path, '--yes'))
        last(self, con)
        self.assertIn('CsvWalk', [t['name'] for t in js(self, '--teams')['teams']])
        n = len(con.acts)
        con.asks = [path]
        items['i']()                                     # there already: nothing asked
        self.assertEqual(len(con.acts), n + 1)

    def test_reports_and_digests(self):
        from acmelib.certs import reports_cli as R
        con = Con()
        R.console_menu(con)
        items = {k: f for k, _w, f in con.subs[-1][1]}
        con.forms = [{'name': 'R5', 'kind': 'inventory', 'every': 'weekly', 'day': '2',
                      'hour': '6', 'to': 'a@example.com'}]
        items['2']()
        last(self, con)
        for what, forms in (('show', []), ('run', []), ('runs', []),
                            ('get', [{'format': 'csv', 'path': os.path.join(TMP, 'r5.csv')}]),
                            ('edit', [{'name': 'R6', 'keep': '5', 'off': 'yes'}])):
            con = Con(chooses=[what], forms=forms)
            con.row = lambda r: r.get('name') == 'R5'
            R._con_reports(con)
            last(self, con)
        self.assertTrue(os.path.exists(os.path.join(TMP, 'r5.csv')))
        rep = next(r for r in js(self, '--reports')['reports'] if r['name'] == 'R6')
        self.assertEqual((rep['keep'], rep['enabled']), (5, False))
        con = Con(chooses=['del'])
        con.row = lambda r: r.get('name') == 'R6'
        R._con_reports(con)
        last(self, con)
        for what, forms in (('show', []), ('set', [{'on': 'on', 'every': 'daily',
                                                    'lang': 'en'}]),
                            ('preview', [])):
            con = Con(chooses=[what], forms=forms)
            con.row = lambda r: r.get('name') == 'Web'
            R._con_teams(con)
            last(self, con)
        self.assertTrue(js(self, '--team-digest', 'Web')['digest']['on'])
        ok(self, '--team-digest-set', 'Web', '--digest', 'off')


if __name__ == '__main__':
    unittest.main()
