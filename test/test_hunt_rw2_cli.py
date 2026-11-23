#!/usr/bin/env python3
"""Bug hunt 1.0.143, run w2, the command line and the console as an operator uses them - a
fresh state taken from nothing to a working setup with the command line only (a source with
a sealed secret, a validation, a target, a certificate, its deployment, a team with members
and roles, a report, a backup, an agent's join code), then the same through the console:

- --deploy-preview of a deployment whose target writes no files (a webhook) said
  "deployment 2: 2 to wh" and "acme --run-plan  says" - the certificate's name was missing;
- --report-run --report-out DIR cut the paths of the files saved at 200 characters ("…");
- --import-config of a file that is no JSON said only "Expecting value: line 1 column 1";
- the console's backups listed the key beside each copy (acme-....key) as a copy to look in
  and to "put back, replacing everything";
- the console's accounts had no e-mail address and mobile number (the page's envelope button,
  acme --user-contact) and a new account had no note, e-mail or mobile (the page's has them);
- the console's report form took day 10 of a weekly report and a wrong address, and the
  team form a wrong "told at" address - refused only after the form closed, what was typed
  lost (the page and acme refuse them).

    python3 test/test_hunt_rw2_cli.py
"""
import gzip
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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rw2cli-')
OUT = os.path.join(TMP, 'out')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
os.environ.update({k: v for k, v in ENV.items() if k.startswith('ACME_')})
SECRETS = ('eabhmac-secret-4711', 'cf-token-secret-0815', 'hook-secret-777',
           'Bearer tok-888-secret', 'pfx-pass-999', 'Very-long-pass-123')


def run(*args, stdin='', env=None):
    return subprocess.run(ACME + [str(a) for a in args], env=dict(ENV, **(env or {})),
                          capture_output=True, text=True, timeout=240, input=stdin)


def ok(test, *args, stdin='', env=None):
    got = run(*args, stdin=stdin, env=env)
    test.assertEqual(got.returncode, 0, '%s: %s%s' % (args, got.stdout, got.stderr))
    for s in SECRETS:
        test.assertNotIn(s, got.stdout + got.stderr, args)
    return got


def js(test, *args, stdin='', env=None):
    return json.loads(ok(test, *(list(args) + ['--json']), stdin=stdin, env=env).stdout)


# ---------------------------------------------------------------------------------------------
class A_FromNothing(unittest.TestCase):
    """The operator's day one, the command line only, in order."""

    def test_whole_setup(self):
        os.makedirs(OUT, exist_ok=True)
        ok(self, '--source-add', 'ZS', '--kind', 'acme', '--set', 'directory=zerossl',
           '--set', 'eab_kid=kid1', '--set', 'eab_hmac=-', stdin='eabhmac-secret-4711\n')
        self.assertEqual(js(self, '--source-show', 'ZS')['config']['eab_hmac'][-2:],
                         '11')
        ok(self, '--validation-add', 'CF', '--kind', 'cloudflare', '--set', 'token=-',
           stdin='cf-token-secret-0815\n')
        ok(self, '--target-add', 'files', '--kind', 'local', '--set', 'base=' + OUT)
        ok(self, '--cert-add', 'web1', '--names', 'web1.example.com', '--issuer', 'ZS',
           '--challenge', 'CF')
        ok(self, '--deploy-add', 'web1', 'files', '--set', 'outputs=fullchain-pem web1.pem')
        # a secret written out is refused, said how
        got = run('--validation-add', 'CF2', '--kind', 'cloudflare', '--set', 'token=abc')
        self.assertEqual(got.returncode, 1)
        self.assertIn('=-', got.stderr)
        # people, a role of one's own, a team with them
        ok(self, '--add-user', 'jan', '--role', 'certadmin', '--mail', 'jan@example.com',
           env={'ACME_PASSWORD': 'Very-long-pass-123'})
        ok(self, '--role-add', 'Ops', '--caps', 'cert.view,deploy.run', '--description', 'ops')
        ok(self, '--team-add', 'Web', '--members', 'local:jan=Ops+Viewer',
           '--contact-mail', 'web@example.com')
        t = js(self, '--team-show', 'Web')['team']
        self.assertEqual(t['members'][0]['roles'], ['Ops', 'Viewer'])
        got = run('--team-add', 'Web2', '--members', 'local:jan=Nope')
        self.assertEqual(got.returncode, 1)
        self.assertIn('no role Nope', got.stderr)
        # deleting asks first; a script says --yes
        got = run('--role-del', 'Ops')
        self.assertEqual(got.returncode, 1)
        # a report, a backup, a join code
        ok(self, '--report-add', 'Inv', '--report-kind', 'inventory', '--report-every', 'weekly',
           '--report-day', '1', '--report-recipients', 'boss@example.com')
        got = run('--report-add', 'R2', '--report-kind', 'expiry', '--report-every', 'weekly',
                  '--report-day', '10')
        self.assertEqual(got.returncode, 1)
        self.assertIn('1 to 7', got.stderr)
        self.assertTrue(js(self, '--backup')['file'].endswith('.json.gz'))
        ok(self, '--target-add', 'srv1', '--kind', 'agent', '--set', 'host=srv1.example.com')
        code = js(self, '--target-agent', 'srv1', 'code')
        self.assertTrue(code['code'].startswith('ACAG1.'))
        self.assertIn('waiting to be used', ok(self, '--target-agent', 'srv1', 'show').stdout)
        # nothing secret anywhere in what the whole setup says
        for args in (('--sources', '--json'), ('--validation-show', 'CF', '--json'),
                     ('--source-show', 'ZS'), ('--export-config', '-'), ('--history', '--json'),
                     ('--users', '--json'), ('--find', 'ZS', '--json')):
            ok(self, *args)


class B_DeployPreviewNoFiles(unittest.TestCase):
    def test_names_the_certificate(self):
        ok(self, '--selfsigned', 'ss1', '--names', 'ss1.example.com')
        ok(self, '--target-add', 'wh', '--kind', 'webhook', '--set',
           'url=https://hook.example.com/x', '--set', 'secret=-', stdin='hook-secret-777\n')
        ok(self, '--target-edit', 'wh', '--set', 'headers=-', stdin='Bearer tok-888-secret\n')
        ok(self, '--deploy-add', 'ss1', 'wh', '--set', 'pfx_password=-',
           stdin='pfx-pass-999\n')
        dep = [r for r in js(self, '--deploys')['rows'] if r['target'] == 'wh'][0]
        out = ok(self, '--deploy-preview', dep['id']).stdout
        self.assertIn('deployment %s: ss1 to wh' % dep['id'], out)
        self.assertIn('acme --run-plan ss1 says', out)
        for args in (('--deploy-preview', dep['id'], '--json'), ('--deploys', '--json'),
                     ('--target-show', 'wh', '--json'), ('--run-plan', 'ss1', '--json')):
            ok(self, *args)


class C_ReportSavedWhole(unittest.TestCase):
    def test_paths_not_cut(self):
        ok(self, '--report-add', 'Long', '--report-kind', 'inventory', '--report-formats',
           'csv,pdf')
        folder = os.path.join(TMP, 'a-rather-long-folder-name-for-the-reports-' + 'x' * 60)
        out = ok(self, '--report-run', 'Long', '--report-out', folder).stdout
        files = sorted(os.listdir(folder))
        self.assertEqual(len(files), 2)
        for f in files:
            self.assertIn(os.path.join(folder, f), out)
        self.assertNotIn('…', out)
        d = js(self, '--report-run', 'Long', '--report-out', folder)
        self.assertEqual(len(d['saved']), 2)


class D_ImportConfigWords(unittest.TestCase):
    def test_not_json(self):
        bad = os.path.join(TMP, 'bad.json')
        with open(bad, 'w') as f:
            f.write('hello')
        got = run('--import-config', bad, '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('is not a configuration of acme', got.stderr)
        self.assertIn('--export-config', got.stderr)
        with open(bad, 'w') as f:
            f.write('[1, 2]')
        got = run('--import-config', bad, '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('is not a configuration of acme', got.stderr)
        self.assertNotIn('Traceback', got.stderr)


# ---------------------------------------------------------------------------------------------
def _engine_console():
    """The engine's real Console, its windows answered from lists, its commands run for real."""
    from acmelib import engine as E

    class C(E.Console):
        def __init__(self, chooses=(), forms=(), confirms=()):
            E.Console.__init__(self, E.Palette(False))
            self.chooses, self.forms, self.confirms = list(chooses), list(forms), list(confirms)
            self.acts, self.notes, self.shown, self.items, self.picked = [], [], [], None, None

        def out(self, *args):
            got = run(*(list(args) + ['--json']))
            return json.loads(got.stdout or 'null')

        def act(self, *args, env=None, **kw):
            got = run(*args, env=env)
            self.acts.append((args, got.returncode, got.stdout + got.stderr))
            return got.returncode

        def sub(self, title, items):
            self.items = items

        def pick(self, title, load, cols, act=None, empty='', words=''):
            rows = load()
            for r in rows:
                for c in cols:
                    c[1](r)
            self.picked = rows
            return rows

        def choose(self, title, options, words='', cur=0):
            want = self.chooses.pop(0)
            assert want in [o[0] for o in options], (want, options)
            return want

        def form(self, title, fields, words='', check=None, ok='OK'):
            self.shown.append((title, fields))
            vals = {f['key']: str(f.get('value') or '') if f.get('kind') != 'choice' else (
                f.get('value') if f.get('value') in [o[0] for o in f['options']]
                else f['options'][0][0]) for f in fields}
            ans = self.forms.pop(0)
            if ans is None:
                return None
            vals.update(ans)
            bad = {}
            for f in fields:
                if f.get('check') and vals[f['key']] != '':
                    said = f['check'](vals[f['key']], vals)
                    if said:
                        bad[f['key']] = said
            if bad:
                self.notes.append(('form refused', bad))
                return None
            return vals

        def confirm(self, *a, **k):
            return self.confirms.pop(0) if self.confirms else True

        def note(self, title, words, tone=''):
            self.notes.append((title, words))
    return C


class E_ConsoleEngine(unittest.TestCase):
    def test_backups_list_no_key(self):
        ok(self, '--backup')
        C = _engine_console()
        con = C()
        con.m_backups()
        con.items[1][2]()                       # The copies kept here
        names = [r['name'] for r in con.picked]
        self.assertTrue(names)
        self.assertTrue(all(n.endswith('.json.gz') for n in names), names)

    def test_account_contact_and_new(self):
        C = _engine_console()
        con = C(forms=[{'name': 'petr', 'role': 'readonly', 'pw': 'Very-long-pass-123',
                        'again': 'Very-long-pass-123', 'note': 'night shift',
                        'mail': 'petr@example.com', 'mobile': '+420 603 123 456'}])
        con.account_new()
        self.assertEqual(con.acts[-1][1], 0, con.acts)
        self.assertNotIn('Very-long-pass-123', ' '.join(map(str, con.acts[-1][0])))
        u = [x for x in js(self, '--users')['users'] if x['name'] == 'petr'][0]
        self.assertEqual((u['mail'], u['mobile'], u['note']),
                         ('petr@example.com', '+420603123456', 'night shift'))
        # a wrong address is said in the form, nothing run
        con = C(forms=[{'name': 'olga', 'role': 'readonly', 'pw': 'Very-long-pass-123',
                        'again': 'Very-long-pass-123', 'mail': 'not-a-mail'}])
        con.account_new()
        self.assertEqual(con.acts, [])
        self.assertIn('mail', con.notes[-1][1])
        # its e-mail and mobile changed, then taken away
        con = C(chooses=['contact'], forms=[{'mail': 'p2@example.com', 'mobile': ''}])
        con.account_do(u)
        self.assertEqual(con.acts[-1][0][:2], ('--user-contact', 'petr'))
        u = [x for x in js(self, '--users')['users'] if x['name'] == 'petr'][0]
        self.assertEqual((u['mail'], u['mobile']), ('p2@example.com', ''))
        con = C(chooses=['contact'], forms=[{'mail': 'p2@example.com', 'mobile': ''}])
        con.account_do(u)
        self.assertEqual(con.acts, [])
        self.assertIn('Nothing was changed', con.notes[-1][1])
        con = C(chooses=['contact'], forms=[{'mobile': 'abc'}])
        con.account_do(u)
        self.assertEqual(con.acts, [])


class F_ConsoleForms(unittest.TestCase):
    def test_report_form(self):
        from acmelib.certs import reports_cli as R
        C = _engine_console()
        con = C(forms=[{'name': 'Wk', 'every': 'weekly', 'day': '10'}])
        R._con_report_form(con, None)
        self.assertEqual(con.acts, [])
        self.assertIn('1 (Monday) to 7', str(con.notes[-1][1]))
        con = C(forms=[{'name': 'Wk', 'every': 'weekly', 'day': '3', 'to': 'a@example.com, x'}])
        R._con_report_form(con, None)
        self.assertEqual(con.acts, [])
        self.assertIn('not a mail address', str(con.notes[-1][1]))
        con = C(forms=[{'name': 'Mo', 'every': 'monthly', 'day': '20',
                        'to': 'a@example.com, b@example.com'}])
        R._con_report_form(con, None)
        self.assertEqual(con.acts[-1][1], 0, con.acts)

    def test_team_form(self):
        from acmelib.certs import console as K
        C = _engine_console()
        con = C(forms=[{'name': 'Ops', 'contact_mail': 'nope'}])
        K.team_add(con)
        self.assertEqual(con.acts, [])
        self.assertIn('not a mail address', str(con.notes[-1][1]))
        con = C(forms=[{'name': 'Ops', 'contact_mail': 'ops@example.com'}], confirms=[False])
        K.team_add(con)
        self.assertEqual(con.acts[-1][1], 0, con.acts)


class G_AccountsAnswer(unittest.TestCase):
    """The account options said only "done" and printed text with --json."""

    def test_json_and_words(self):
        pw = {'ACME_PASSWORD': 'Very-long-pass-123'}
        d = js(self, '--add-user', 'kim', '--role', 'readonly', env=pw)
        self.assertEqual((d['ok'], d['name'], d['role']), (True, 'kim', 'readonly'))
        self.assertEqual(js(self, '--passwd', 'kim', env=pw)['said'], 'the password of kim is set')
        self.assertIn('certadmin', js(self, '--set-role', 'kim', '--role', 'certadmin')['said'])
        d = js(self, '--user-contact', 'kim', '--mail', 'k@example.com')
        self.assertEqual((d['mail'], d['mobile']), ('k@example.com', ''))
        self.assertIn('can no longer sign in', ok(self, '--disable-user', 'kim').stdout)
        self.assertIn('may sign in again', js(self, '--enable-user', 'kim')['said'])
        self.assertFalse(js(self, '--reset-2fa', 'kim')['reset'])
        got = run('--del-user', 'kim')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--yes', got.stderr)
        self.assertIn('the account kim is removed', js(self, '--del-user', 'kim', '--yes')['said'])


class H_TargetAgentWords(unittest.TestCase):
    def test_words(self):
        ok(self, '--target-add', 'plain', '--kind', 'local', '--set', 'base=' + OUT)
        got = run('--target-agent', 'plain', 'code')
        self.assertEqual(got.returncode, 1)
        self.assertIn('plain is a local one, not a "Server with acme-agent"', got.stderr)
        ok(self, '--target-add', 'srv9', '--kind', 'agent', '--set', 'host=srv9.example.com')
        a, b = run('--target-agent', 'srv9'), run('--target-agent', 'srv9', 'bogus')
        self.assertEqual((a.returncode, b.returncode), (1, 1))
        self.assertEqual(a.stderr, b.stderr)
        for verb in ('watch-set', 'served', 'keys-rotate', 'enroll new', 'waiting'):
            self.assertIn(verb, a.stderr)


class I_Roles(unittest.TestCase):
    """--role-add NAME --name NEW dropped --name and said "changed"; the console only showed
    the roles - one of your own is added, changed and deleted there now."""

    def test_cli_rename(self):
        ok(self, '--role-add', 'Night', '--caps', 'cert.view')
        ok(self, '--team-add', 'Shift', '--members', 'local:ota=Night')
        ok(self, '--role-add', 'Night', '--name', 'Night2')
        t = js(self, '--team-show', 'Shift')['team']
        self.assertEqual(t['members'][0]['roles'], ['Night2'])
        got = run('--role-add', 'Nope9', '--name', 'X')
        self.assertEqual(got.returncode, 1)
        self.assertIn('no role of your own called Nope9', got.stderr)
        self.assertNotIn('Nope9', [r['name'] for r in js(self, '--roles')['roles']])

    def test_console(self):
        from acmelib.certs import console as K
        C = _engine_console()
        roles = lambda: {r['name']: r for r in js(self, '--roles')['roles']}  # noqa: E731
        con = C(forms=[{'name': 'Viewer', 'caps': 'cert.view'}])
        K.role_form(con, None)
        self.assertEqual(con.acts, [])
        self.assertIn('built-in', str(con.notes[-1][1]))
        con = C(forms=[{'name': 'Audit', 'caps': 'cert.view, bogus'}])
        K.role_form(con, None)
        self.assertEqual(con.acts, [])
        self.assertIn('bogus', str(con.notes[-1][1]))
        con = C(forms=[{'name': 'Audit', 'caps': 'cert.view, team.activity',
                        'description': 'auditors'}])
        K.role_form(con, None)
        self.assertEqual(con.acts[-1][1], 0, con.acts)
        self.assertEqual(roles()['Audit']['caps'], ['cert.view', 'team.activity'])
        con = C(forms=[{'name': 'Audit', 'caps': 'cert.view'}])
        K.role_form(con, None)                       # a new one of a name there: said
        self.assertEqual(con.acts, [])
        ok(self, '--team-add', 'Aud', '--members', 'local:ivo=Audit')
        con = C()
        K.roles_list(con)                            # the list as the console shows it
        self.assertTrue(con.picked[0].get('_add'))
        row = [r for r in con.picked if r.get('name') == 'Audit'][0]
        con2 = C(chooses=['edit'], forms=[{'name': 'Auditors', 'caps': 'cert.view',
                                           'description': ''}])
        con2.pick = lambda title, load, cols, act=None, empty='', words='': act(row)
        K.roles_list(con2)
        self.assertEqual(con2.acts[-1][0][:2], ('--role-add', 'Audit'))
        self.assertIn('--name', con2.acts[-1][0])
        r = roles()['Auditors']
        self.assertEqual((r['caps'], r['description'], r['used']), (['cert.view'], '', 1))
        self.assertEqual(js(self, '--team-show', 'Aud')['team']['members'][0]['roles'],
                         ['Auditors'])
        con3 = C(chooses=['del'])
        con3.pick = lambda title, load, cols, act=None, empty='', words='': act(r)
        K.roles_list(con3)
        self.assertIn('--strip', con3.acts[-1][0])
        self.assertEqual(con3.acts[-1][1], 0, con3.acts)
        self.assertNotIn('Auditors', roles())


if __name__ == '__main__':
    unittest.main(verbosity=2)
