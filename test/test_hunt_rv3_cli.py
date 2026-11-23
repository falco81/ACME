#!/usr/bin/env python3
"""Bug hunt 1.0.141, run v3, the command line and the console (second pass) - each run here for
real against a state of its own, as `acme ...` is typed:

- the read-only views of the pages that had no option: --run-plan NAME (What happens),
  --inspect FILE|- [--password] (Show a certificate), --deploy-preview ID [--set] (a
  deployment's files and its script's variables) and --deploy-dry-run ID [--set] (its test) -
  with and without --json, their exit codes, in --help and in docs/command-line.md;
- the console: on a certificate What happens, on a deployment Preview and Test it, Show what a
  file holds (v); a team's governance set in forms (reviews, temporary roles, separation of
  duties, channels; each on and off); the groups of agents (h → g: made, changed, deleted);
- the whole console menu tree walked (every menu, every item that only reads, forms opened and
  cancelled): nothing crashes, every list reads, every item does something;
- --local-users and --local-policy answer JSON with --json (they printed text);
- docs/command-line.md names every option of the certificate manager's groups of --help.

    python3 test/test_hunt_rv3_cli.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rv3cli-')
OUT = os.path.join(TMP, 'out')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
# the console's own process reads these (the walker below runs the real Console class)
os.environ.update({k: v for k, v in ENV.items() if k.startswith('ACME_')})


def run(*args, stdin='', env=None):
    return subprocess.run(ACME + [str(a) for a in args], env=dict(ENV, **(env or {})),
                          capture_output=True, text=True, timeout=240, input=stdin)


def ok(test, *args, stdin='', env=None):
    got = run(*args, stdin=stdin, env=env)
    test.assertEqual(got.returncode, 0, '%s: %s%s' % (args, got.stdout, got.stderr))
    return got


def js(test, *args, stdin='', env=None):
    return json.loads(ok(test, *(list(args) + ['--json']), stdin=stdin, env=env).stdout)


def setUpModule():
    os.makedirs(OUT, exist_ok=True)
    for args in (('--selfsigned', 'web1', '--names', 'web1.example.com,www.example.com'),
                 ('--target-add', 'files', '--kind', 'local', '--set', 'base=' + OUT),
                 ('--deploy-add', 'web1', 'files', '--set', 'outputs=fullchain-pem web1.pem'),
                 ('--deploy-run', '1'),
                 ('--cert-add', 'pending1', '--names', 'p.example.com'),
                 ('--team-add', 'Web', '--members', 'local:jan=manage,local:eva=view'),
                 ('--target-add', 'srv1', '--kind', 'agent', '--set', 'host=a.example.com'),
                 ('--target-add', 'srv2', '--kind', 'agent', '--set', 'host=b.example.com'),
                 ('--fleet-group-save', 'Canary', '--fleet-members', 'srv1')):
        got = run(*args)
        assert got.returncode == 0, (args, got.stdout + got.stderr)


# ---------------------------------------------------------------------------------------------
class RunPlan(unittest.TestCase):
    def test_what_happens(self):
        out = ok(self, '--run-plan', 'web1').stdout
        for words in ('nothing of it was done', 'Key and request', 'Deployments', 'files',
                      'web1.pem', 'After'):
            self.assertIn(words, out)
        p = js(self, '--run-plan', 'web1')['plan']
        self.assertEqual(p['cert']['name'], 'web1')
        self.assertEqual([x['key'] for x in p['phases']][:2], ['key', 'source'])
        # an ACME one, not issued yet: the calls to the CA, the first time and the later ones
        out = ok(self, '--run-plan', 'pending1').stdout
        self.assertIn('new-order', out)
        self.assertIn('Only the first time', out)
        got = run('--run-plan', 'nope')
        self.assertEqual(got.returncode, 1)
        self.assertIn('no certificate nope', got.stderr)
        got = run('--run-plan', 'web1', '--set', 'x=1')            # takes no --set
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('--set does not go with --run-plan', got.stderr)


class Inspect(unittest.TestCase):
    def test_a_file(self):
        pem = os.path.join(OUT, 'web1.pem')
        out = ok(self, '--inspect', pem).stdout
        self.assertIn('c1 certificate', out)
        self.assertIn('DNS:www.example.com', out)
        d = js(self, '--inspect', pem)
        self.assertEqual(d['things'][0]['cn'], 'web1.example.com')
        with open(pem) as f:
            self.assertIn('c1 certificate', ok(self, '--inspect', '-', stdin=f.read()).stdout)
        junk = os.path.join(TMP, 'junk.txt')
        with open(junk, 'w') as f:
            f.write('hello\n')
        got = run('--inspect', junk)
        self.assertEqual(got.returncode, 1)
        self.assertIn('holds no certificate', got.stderr)
        got = run('--inspect', os.path.join(TMP, 'not-there.pem'))
        self.assertEqual(got.returncode, 1)
        self.assertNotIn('Traceback', got.stderr)

    def test_locked(self):
        pfx = os.path.join(TMP, 'w.pfx')
        ok(self, '--export', 'web1', '--format', 'pfx', '--out', pfx, '--password',
           env={'ACME_FILE_PASSWORD': 'secret12'})
        got = run('--inspect', pfx)
        self.assertEqual(got.returncode, 1)
        self.assertIn('add --password', got.stdout)
        got = run('--inspect', pfx, '--password', env={'ACME_FILE_PASSWORD': 'wrong'})
        self.assertEqual(got.returncode, 1)
        self.assertIn('wrong', got.stdout)
        out = ok(self, '--inspect', pfx, '--password',
                 env={'ACME_FILE_PASSWORD': 'secret12'}).stdout
        self.assertIn('private key', out)
        self.assertIn('belongs to   c1', out)
        self.assertNotIn('PRIVATE KEY-----', out)


class DeployPreviewAndTest(unittest.TestCase):
    def test_preview(self):
        out = ok(self, '--deploy-preview', '1').stdout
        self.assertIn(os.path.join(OUT, 'web1.pem'), out)
        self.assertIn('ACME_CERT_NAME=web1', out)
        d = js(self, '--deploy-preview', '1')
        self.assertEqual(d['files'][0]['format'], 'fullchain-pem')
        self.assertTrue(d['issued'])
        # with other options over its own - nothing saved
        out = ok(self, '--deploy-preview', '1', '--set', 'outputs=key-pem k.pem,pfx a.pfx').stdout
        self.assertIn('k.pem', out)
        self.assertIn('holds the private key', out)
        self.assertIn('has no password', out)
        self.assertEqual(json.loads(run('--deploys', 'web1', '--json').stdout)['rows'][0][
            'options']['outputs'], ['fullchain-pem web1.pem'])
        got = run('--deploy-preview', '99')
        self.assertEqual(got.returncode, 1)
        self.assertIn('no deployment 99', got.stderr)
        got = run('--deploy-preview', '1', '--set', 'nosuch=1')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('has no setting nosuch', got.stderr)

    def test_dry_run(self):
        before = os.listdir(OUT)
        out = ok(self, '--deploy-dry-run', '1').stdout
        self.assertIn('the test passed', out)
        d = js(self, '--deploy-dry-run', '1')
        self.assertTrue(d['ok'])
        self.assertEqual(sorted(os.listdir(OUT)), sorted(before))      # nothing put in place

    def test_help_and_docs(self):
        out = ok(self, '--help').stdout
        for opt in ('--run-plan', '--inspect', '--deploy-preview', '--deploy-dry-run'):
            self.assertIn(opt, out)
        got = run('--deploy-preview', '1', '--run-plan', 'web1')
        self.assertIn('one of them at a time', got.stderr)


class Rollout(unittest.TestCase):
    def test_the_canary_group_first(self):
        """As the page: without GROUP the group marked the canary ring is the canary ring (it
        took 5 % of the agents); - : 5 %."""
        ok(self, '--fleet-group-save', 'Canary', '--fleet-canary', 'yes')
        try:
            self.assertEqual(js(self, '--fleet-rollout', 'plan')['how'], 'group')
            self.assertIn('canary ring (the group)', ok(self, '--fleet-rollout', 'plan').stdout)
            self.assertEqual(js(self, '--fleet-rollout', 'plan', '-')['how'], 'share')
            self.assertEqual(js(self, '--fleet-rollout', 'plan', 'Canary')['how'], 'group')
        finally:
            ok(self, '--fleet-group-save', 'Canary', '--fleet-canary', 'no')
        self.assertEqual(js(self, '--fleet-rollout', 'plan')['how'], 'share')


# ---------------------------------------------------------------------------------------------
class EngineJson(unittest.TestCase):
    def test_local_users_and_policy(self):
        d = js(self, '--local-policy')
        self.assertIn('minlen', d['policy'])
        self.assertIsInstance(d['nodes'], list)
        d = js(self, '--local-users')
        self.assertIsInstance(d['nodes'], list)


class Docs(unittest.TestCase):
    def test_every_option_of_the_certificate_manager_is_in_the_docs(self):
        """Each option of the certificate manager's groups of --help is named in
        docs/command-line.md (the engine's own are in --help and their own pages)."""
        out = ok(self, '--help').stdout
        group, mine = None, []
        for ln in out.splitlines():
            if re.match(r'^[A-Z]', ln):
                group = ln
            m = re.match(r'^  (--[a-z0-9-]+)', ln)
            if m and group and (group.startswith(('CERTIFICATES', 'DNS SETS', 'OWNERS',
                                                  'TARGET AGENTS', 'REPORTS', 'HISTORY'))):
                mine.append(m.group(1))
        with open(os.path.join(ROOT, 'docs', 'command-line.md'), encoding='utf-8') as f:
            doc = f.read()
        named = set(re.findall(r'(?<![\w-])(--[a-z][a-z0-9-]*[a-z0-9])', doc))
        # --validation-x / --target-x / --check-x: "the same as --source-..."
        same = {o for o in mine if re.match(r'^--(validation|target|check)-(edit|del|test|'
                                            r'action|discover|default|show|add)$', o)}
        self.assertTrue(mine)
        self.assertEqual([o for o in mine if o not in named and o not in same], [])


# ---------------------------------------------------------------------------------------------
class Con(object):
    """The console as its menus see it, its commands run for real; what a person answers
    given in order."""
    def __init__(self, chooses=(), asks=(), forms=(), confirms=()):
        self.chooses, self.asks, self.forms = list(chooses), list(asks), list(forms)
        self.confirms = list(confirms)
        self.acts, self.cmds, self.notes, self.shown, self.items = [], [], [], [], None

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        self.out_err = '' if got.returncode == 0 else got.stderr
        return json.loads(got.stdout or 'null')

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)), []))

    def act(self, *args, env=None, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def cmd(self, *args, **kw):
        got = run(*args)
        self.cmds.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def live(self, fn):
        fn()

    def pause(self):
        pass

    def sub(self, title, items):
        self.items = items

    def pick(self, title, load, cols, act=None, empty='', words=''):
        rows = load()
        for r in rows:
            for c in cols:
                c[1](r)
        if act and self.chooses and isinstance(self.chooses[0], tuple) and \
                self.chooses[0][0] == 'row':
            want = self.chooses.pop(0)[1]
            act(next(r for r in rows if r.get('name') == want))
        return rows

    def choose(self, title, options, words='', cur=0):
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def ask_one(self, *a, **k):
        return self.asks.pop(0)

    def form(self, title, fields, words='', check=None, ok='OK'):
        self.shown.append((title, fields))
        vals = {f['key']: (str(f.get('value') or '') if f.get('kind') != 'choice' else (
            f.get('value') if f.get('value') in [o[0] for o in f['options']]
            else f['options'][0][0])) for f in fields}
        ans = self.forms.pop(0)
        if ans is None:
            return None
        vals.update(ans)
        shown = [f for f in fields if not f.get('when') or f['when'](vals)]
        for f in shown:
            if f.get('check') and vals[f['key']] != '':
                bad = f['check'](vals[f['key']], vals)
                if bad:
                    raise AssertionError('%s: %s' % (f['key'], bad))
        return {f['key']: vals[f['key']] for f in shown}         # only those shown, as Console

    def confirm(self, *a, **k):
        return self.confirms.pop(0) if self.confirms else True

    def note(self, title, words, tone=''):
        self.notes.append((title, words, tone))


class ConsoleNew(unittest.TestCase):
    def test_certificate_deployment_inspect(self):
        from acmelib.certs import console as C
        con = Con(chooses=['plan'])
        C.cert_do(con, {'name': 'web1', 'issuer': 'self-signed'})
        self.assertEqual(con.acts[-1][:2], (('--run-plan', 'web1'), 0))
        con = Con(chooses=['preview'])
        C.deploy_do(con, {'id': 1, 'cert_name': 'web1', 'target': 'files'})
        self.assertEqual(con.acts[-1][:2], (('--deploy-preview', '1'), 0))
        con = Con(chooses=['test'])
        C.deploy_do(con, {'id': 1, 'cert_name': 'web1', 'target': 'files'})
        self.assertEqual(con.cmds[-1][:2], (('--deploy-dry-run', '1'), 0))
        con = Con()
        C.menu(con)
        v = dict((k, f) for k, _w, f in con.items)['v']
        con.forms = [{'path': os.path.join(OUT, 'web1.pem'), 'locked': 'no'}]
        v()
        self.assertEqual(con.acts[-1][:2], (('--inspect', os.path.join(OUT, 'web1.pem')), 0))
        con.forms = [None]                                  # Esc: nothing run
        v()
        self.assertEqual(len(con.acts), 1)
        self.assertEqual(len({k for k, _w, _f in con.items}), len(con.items))

    def test_governance_in_forms(self):
        from acmelib.certs import cli_138 as M

        def gov():
            return js(self, '--team-gov', 'Web')['gov']
        con = Con(chooses=['review'], forms=[{'on': 'on', 'every_days': '60',
                                              'answer_days': '10', 'action': 'expire'}])
        M._con_gov(con, 'Web')
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertEqual(gov()['review'], {'every_days': 60, 'answer_days': 10,
                                           'action': 'expire'})
        # the form opens on what is set
        con = Con(chooses=['review'], forms=[{}])
        M._con_gov(con, 'Web')
        f = {x['key']: x['value'] for x in con.shown[-1][1]}
        self.assertEqual((f['on'], f['every_days'], f['action']), ('on', '60', 'expire'))
        con = Con(chooses=['jit'], forms=[{'on': 'on', 'roles': 'Requester, Deployer',
                                           'max_hours': '4'}])
        M._con_gov(con, 'Web')
        self.assertEqual(gov()['jit'], {'roles': ['Requester', 'Deployer'], 'max_hours': 4})
        con = Con(chooses=['sod'], forms=[{'no_self_approval': 'yes',
                                           'exclusive': 'Requester + Approver'}])
        M._con_gov(con, 'Web')
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertTrue(gov()['sod']['no_self_approval'])
        self.assertEqual(gov()['sod']['exclusive'], [['Requester', 'Approver']])
        con = Con(chooses=['sod'], forms=[{}])               # shown as it is set
        M._con_gov(con, 'Web')
        f = {x['key']: x['value'] for x in con.shown[-1][1]}
        self.assertEqual(f['exclusive'], 'Requester + Approver')
        con = Con(chooses=['notify'], forms=[{'on': 'on', 'mail': 'web@example.com',
                                              'oncall_mail': 'oncall@example.com',
                                              'expiry_days': '20', 'manager_days': '5',
                                              'deploy_failed': '-', 'reviews': 'no'}])
        M._con_gov(con, 'Web')
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        n = gov()['notify']
        self.assertEqual((n['mail'], n['oncall_mail'], n['expiry_days'], n['deploy_failed'],
                          n['reviews'], n['elevations']),
                         ('web@example.com', 'oncall@example.com', 20, '', False, True))
        # refused by the daemon: said, nothing changed
        con = Con(chooses=['notify'], forms=[{'on': 'on', 'expiry_days': '2',
                                              'manager_days': '9'}])
        M._con_gov(con, 'Web')
        self.assertNotEqual(con.acts[-1][1], 0)
        self.assertEqual(gov()['notify']['expiry_days'], 20)
        # each off again
        for part in ('review', 'jit', 'notify'):
            con = Con(chooses=[part], forms=[{'on': 'off'}])
            M._con_gov(con, 'Web')
            self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
            self.assertNotIn(part, gov())
        con = Con(chooses=['sod'], forms=[{'no_self_approval': 'no', 'exclusive': ''}])
        M._con_gov(con, 'Web')
        self.assertNotIn('sod', gov())
        # Esc: nothing run
        con = Con(chooses=['jit'], forms=[None])
        M._con_gov(con, 'Web')
        self.assertEqual(con.acts, [])
        con = Con(chooses=[None])
        M._con_gov(con, 'Web')
        self.assertEqual(con.acts, [])
        # from the team's own menu: shown as before, changed by an item of its own
        from acmelib.certs import console as C
        con = Con(chooses=['gov'])
        C.team_do(con, {'name': 'Web'})
        self.assertEqual(con.acts[-1][:2], (('--team-gov', 'Web'), 0))
        con = Con(chooses=['gov-set', 'jit'], forms=[{'on': 'on', 'roles': 'Requester',
                                                      'max_hours': '2'}])
        C.team_do(con, {'name': 'Web'})
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertEqual(gov()['jit'], {'roles': ['Requester'], 'max_hours': 2})

    def test_groups_of_agents(self):
        from acmelib.certs import cli_138 as M

        def groups():
            return {g['name']: g for g in js(self, '--fleet')['groups']}
        con = Con()
        M.console_menu(con)
        g = dict((k, f) for k, _w, f in con.items)['g']
        self.assertEqual(len({k for k, _w, _f in con.items}), len(con.items))
        con.chooses = [('row', '+ a new group')]
        con.forms = [{'name': 'Ring2', 'members': 'srv1, srv2', 'template': 'builtin:nginx-web',
                      'canary': 'yes'}]
        g()
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        r = groups()['Ring2']
        self.assertEqual((len(r['members']), r['template'], r['canary']),
                         (2, 'builtin:nginx-web', True))
        # changed: what the form shows is what is set
        con.chooses = [('row', 'Ring2'), 'edit']
        con.forms = [{'members': 'srv2', 'template': '-', 'canary': 'no'}]
        g()
        f = {x['key']: x.get('value') for x in con.shown[-1][1]}
        self.assertEqual((f['members'], f['template'], f['canary']),
                         ('srv1, srv2', 'builtin:nginx-web', 'yes'))
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        r = groups()['Ring2']
        self.assertEqual((len(r['members']), r['template'], r['canary']), (1, '', False))
        # an agent that is none: said in the form, nothing run
        con.chooses = [('row', 'Ring2'), 'edit']
        con.forms = [{'members': 'nosuch'}]
        n = len(con.acts)
        with self.assertRaises(AssertionError):
            g()
        self.assertEqual(len(con.acts), n)
        con.chooses = [('row', 'Ring2'), 'plan']
        g()
        self.assertEqual(con.acts[-1][:2], (('--fleet-rollout', 'plan', 'Ring2'), 0))
        con.chooses = [('row', 'Ring2'), 'del']
        g()
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertNotIn('Ring2', groups())


# ---------------------------------------------------------------------------------------------
READS = set('''--status --check --events --hand --directories --dir-caps --settings --get --users
--os-roots --local-policy --rbackup-status --acme --restarts --ssh-tokens --lockouts --db-tls
--isemon-tls --ntp --net --hisec --guard-status --sso-status --kerberos --cert-login
--cert-login-crl --cert-login-ocsp --upgrade-status --ha-status --ha-tls --split --web-status
--certs --cert --jobs --job --cert-check --sources --validations --targets --tests --source-show
--validation-show --target-show --check-show --plugins --checks --plugin --deploys --cas
--ca-show --ca-versions --dns-records --dns-sets --teams --team-show --roles --team-access
--team-activity --find --calendar --calendar-feeds --profile-templates --agent-keys --agent-guard
--agent-cas --reports --report-show --report-runs --team-digest --team-digest-preview --history
--trash --profiles --profile-show --profile-versions --profile-diff --profile-compliance --fleet
--fleet-unmanaged --fleet-templates --fleet-drift --team-health --team-gov --who-may --who-can
--elevations --reviews --team-templates --run-plan --deploy-preview --module-marks-export'''.split())


def _reads(args):
    a = [str(x) for x in args]
    if not a:
        return False
    if a[0] == '--target-agent':
        return a[2:3] in (['show'], ['policy'], ['system'], ['watch'], ['guard']) or \
            a[1:3] in (['all', 'keys'], ['enroll', 'list']) or a[1:2] == ['waiting'] or \
            a[2:4] in (['design', 'show'], ['discover', 'cached'])
    if a[0] == '--fleet-rollout':
        return a[1:2] == ['plan']
    return a[0] in READS


class Walker(object):
    """The real Console of the engine, its screens answered here: every menu item and every
    choice taken (one run each), the first rows of a list, a form cancelled, a confirmation
    answered no; a command that only reads run for real, the others written down."""
    def __init__(self, E):
        self.E = E
        self.problems, self.ran, self.cache = [], [], {}

        class W(E.Console):
            pass
        w = W(E.Palette(False))
        walker = self

        class Scr(object):
            def getmaxyx(self):
                return (50, 120)

            def __getattr__(self, k):
                return lambda *a, **kw: None
        w.scr = Scr()
        for name in ('menu', 'sub', 'choose', 'pick', 'form', 'ask_one', 'confirm', 'note',
                     'details', 'page', 'go_plain', 'live', 'act', 'act_argv', 'cmd', 'show',
                     'show_live', 'capture', 'out'):
            setattr(w, name, getattr(self, name))
        for name in ('working', 'clear_screen', 'pause', 'shell', 'live_log', 'journal',
                     'settings_tui', '_edit_one'):
            setattr(w, name, (lambda *a, **k: walker._step()))
        w.ask = self._esc
        w.yes = lambda *a, **k: False
        self.w, self.Scr = w, Scr

    # -- the main menu, as Console.run() makes it
    def main_items(self):
        import curses
        got = {}
        w = self.w
        w.menu = lambda title, items, path='': got.setdefault('items', items)
        w.status_thread = lambda: None
        w._colours = lambda: None
        old, oldenv = curses.wrapper, os.environ.get('ACME_CONSOLE_START')
        curses.wrapper = lambda body: body(self.Scr())
        os.environ['ACME_CONSOLE_START'] = 'menu'
        try:
            w.run()
        finally:
            curses.wrapper = old
            if oldenv is None:
                os.environ.pop('ACME_CONSOLE_START', None)
            w.menu = self.menu
        return got['items']

    def walk(self, keys=None, depth=6):
        import traceback
        self.depth = depth
        n = 0
        for key, words, fn in [it[:3] for it in self.main_items()]:
            if keys and key not in keys:
                continue
            todo = [[]]
            while todo:
                prefix = todo.pop()
                self.prefix, self.trace, self.steps = prefix, [], 0
                self.path = 'main %s (%s)' % (key, words[:24])
                try:
                    fn()
                except self.E.ConsoleBack:
                    pass
                except Exception as e:                     # noqa: BLE001
                    self.bad('%s: %s %s' % (type(e).__name__, e, traceback.format_exc()[-600:]))
                if not self.steps:
                    self.bad('the item does nothing')
                n += 1
                for j in range(len(prefix), len(self.trace)):
                    for alt in range(1, self.trace[j][1]):
                        todo.append([t[0] for t in self.trace[:j]] + [alt])
        return n

    def _step(self):
        self.steps += 1
        if self.steps > 300:
            raise RuntimeError('a menu that does not return')

    def _esc(self, *a, **k):
        raise self.E.ConsoleBack()

    def bad(self, words):
        self.problems.append('%s > %s: %s' % (self.path, ' > '.join(t[2] for t in self.trace),
                                              words))

    def decide(self, what, labels):
        self._step()
        i = len(self.trace)
        c = min(self.prefix[i] if i < len(self.prefix) else 0, len(labels) - 1)
        self.trace.append((c, len(labels) if i < self.depth else 1,
                           '%s: %s' % (what, labels[c])))
        return c

    # -- the screens
    def menu(self, title, items, path=''):
        if len({it[0] for it in items}) != len(items):
            self.bad('menu %r: a key twice' % title)
        it = items[self.decide(title, ['%s %s' % (x[0], x[1]) for x in items])]
        try:
            r = it[2]()
        except self.E.ConsoleBack:
            r = None
        return 'quit' if r == 'quit' else 'back'

    def sub(self, title, items):
        return 'quit' if self.menu(title, items, 'x') == 'quit' else None

    def choose(self, title, options, words='', cur=0):
        if not options:
            return None
        if len({o[0] for o in options}) != len(options):
            self.bad('choose %r: a value twice' % title)
        c = self.decide(title, [o[1] for o in options] + ['(Esc)'])
        return None if c >= len(options) else options[c][0]

    def pick(self, title, load, cols, act=None, empty='', words=''):
        self.w.out_err = ''
        rows = load() or []
        if not rows and self.w.out_err:
            self.bad('the list %r could not be read: %s' % (title, self.w.out_err))
        for r in rows:
            for head, fn, _w, tone in cols:
                try:
                    str(fn(r))
                    if tone:
                        tone(r)
                except Exception as e:                     # noqa: BLE001
                    self.bad('list %r, column %r: %s %s' % (title, head, type(e).__name__, e))
        if not act:
            return None
        some = rows[:2]
        c = self.decide(title, [str(cols[0][1](r)) for r in some] + ['(look)'])
        return act(some[c]) if c < len(some) else None

    def form(self, title, fields, words='', check=None, ok='OK'):
        self._step()
        for f in fields:
            kind = f.get('kind', 'text')
            if kind == 'choice':
                opts = [o[0] for o in f.get('options') or []]
                if not opts or (f.get('value') not in (None, '') and f['value'] not in opts):
                    self.bad('form %r: the choice %s (%r of %s)' % (title, f['key'],
                                                                   f.get('value'), opts))
            elif kind == 'number':
                if str(f.get('value') or '').strip():
                    lo, hi = f.get('range') or (None, None)
                    v = int(str(f['value']))
                    if (lo is not None and v < lo) or (hi is not None and v > hi):
                        self.bad('form %r: %s=%s out of %s' % (title, f['key'], v, f['range']))
            elif kind not in ('text', 'secret'):
                self.bad('form %r: %s of kind %r' % (title, f['key'], kind))
        return None                                         # Esc

    def ask_one(self, title, label, value='', help_='', need=True, secret=False, check=None):
        return self.form(title, [{'key': 'v', 'label': label, 'value': value}])

    def confirm(self, *a, **k):
        self._step()
        return False

    def note(self, title, text, tone=''):
        self._step()
        if 'Traceback' in str(text):
            self.bad('note %r: %s' % (title, str(text)[-300:]))

    def details(self, *a, **k):
        self._step()

    def page(self, title, text):
        self._step()
        if 'Traceback' in str(text):
            self.bad('page %r: %s' % (title, str(text)[-300:]))

    def go_plain(self, fn):
        try:
            return fn()
        except self.E.ConsoleBack:
            return None

    def live(self, fn):
        self.go_plain(fn)

    # -- the commands
    def run(self, args):
        self._step()
        args = tuple(str(a) for a in args)
        if not _reads(args):
            return 0, ''
        if args not in self.cache:
            got = run(*args)
            self.cache[args] = (got.returncode, got.stdout + got.stderr)
        rc, text = self.cache[args]
        self.ran.append(args)
        if 'Traceback' in text or rc not in (0, 1):
            self.bad('acme %s: %d %s' % (' '.join(args), rc, text[-400:]))
        return rc, text

    def act(self, *args, env=None, title=None, quiet_ok=None):
        return self.run(args)[0]

    def act_argv(self, argv, title, env=None, quiet_ok=None):
        return self.run(argv[len(self.E.acme_argv(self.w.me)):])[0]

    def cmd(self, *args, show=True):
        return self.run(args)[0]

    def show(self, *args):
        if all(a is not None and str(a).strip() for a in args):
            self.run(args)

    def show_live(self, *args):
        self.show(*args)

    def capture(self, argv, env=None):
        rc, text = self.run(argv[len(self.E.acme_argv(self.w.me)):])
        return text, rc

    def out(self, *args):
        self._step()
        args = tuple(str(a) for a in args) + ('--json',)
        if not _reads(args):
            self.w.out_err = ''
            return None
        if args not in self.cache:
            got = run(*args)
            self.cache[args] = (got.returncode, got.stdout, got.stderr)
        rc, out, err = self.cache[args]
        self.ran.append(args[:-1])
        self.w.out_err = '' if rc == 0 else (err or out).strip()[-300:]
        if 'Traceback' in out + err:
            self.bad('acme %s: %s' % (' '.join(args), (out + err)[-400:]))
        try:
            return json.loads(out or 'null')
        except ValueError:
            self.bad('acme %s: not JSON: %r' % (' '.join(args), out[:200]))
            return None


class ConsoleWalk(unittest.TestCase):
    def test_every_menu(self):
        from acmelib import engine as E
        w = Walker(E)
        keys = [it[0] for it in w.main_items()]
        self.assertEqual(len(keys), len(set(keys)))
        for k in ('c', 'o', 'p', 'h', '1', '4', '11'):
            self.assertIn(k, keys)
        n = w.walk(depth=int(os.environ.get('WALK_DEPTH', '5')))
        self.assertEqual(w.problems, [])
        self.assertGreater(n, 300)
        self.assertGreater(len(set(w.ran)), 40)
        for want in (('--run-plan', 'web1'), ('--deploy-preview', '1'), ('--team-gov', 'Web'),
                     ('--fleet',), ('--status',)):
            self.assertIn(want, w.ran)


if __name__ == '__main__':
    unittest.main()
