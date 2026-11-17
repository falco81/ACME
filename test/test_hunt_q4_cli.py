#!/usr/bin/env python3
"""The command line and the console, bugs found by running them (1.0.119).

    python3 test/test_hunt_q4_cli.py

- --set KEY-=VALUE takes one out of a list (the key swallowed the '-': "no tags-");
- a number of a module's settings given as nan or inf refused, no traceback;
- --target-agent NAME forget|confirm|update and design text|forget answer JSON with --json;
- --console-users / --console-at-login on|off answer JSON with --json;
- NO_COLOR set but empty does not switch colour off (no-color.org); the console's menus
  are not coloured with --no-color or NO_COLOR;
- the console's live log follows acme.log once it is there (it stayed empty);
- the console makes no account whose name begins with '-', and offers the design of an
  agent's policy as the command line does.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-q4cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = dict(os.environ, ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'),
           ACME_STATE=TMP, ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
for k, v in ENV.items():
    if k.startswith('ACME_'):
        os.environ[k] = v
sys.path.insert(0, ROOT)


def run(*args, stdin=''):
    return subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True,
                          input=stdin, timeout=120)


class CommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        got = run('--selfsigned', 'q4web', '--names', 'q4.example.test')
        assert got.returncode == 0, got.stdout + got.stderr
        got = run('--target-add', 'q4ag', '--kind', 'agent', '--set', 'mode=passive',
                  '--set', 'host=127.0.0.1', '--set', 'port=1')
        assert got.returncode == 0, got.stdout + got.stderr

    def tags(self):
        return json.loads(run('--cert', 'q4web', '--json').stdout)['cert']['tags']

    def test_minus_equals_takes_one_out(self):
        self.assertEqual(run('--cert-edit', 'q4web', '--set', 'tags=a,b,c').returncode, 0)
        got = run('--cert-edit', 'q4web', '--set', 'tags-=b')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.tags(), ['a', 'c'])
        got = run('--cert-edit', 'q4web', '--set', 'tags+=d')
        self.assertEqual(self.tags(), ['a', 'c', 'd'])
        # a value holding -= is a value
        self.assertEqual(run('--cert-edit', 'q4web', '--set', 'note=x-=y').returncode, 0)
        self.assertEqual(json.loads(run('--cert', 'q4web', '--json').stdout)['cert']['note'],
                         'x-=y')

    def test_nan_and_inf_refused(self):
        from acmelib.certs import cli
        for raw in ('nan', 'inf', '-inf', 'NaN'):
            with self.assertRaises(SystemExit) as c:
                cli.field_value({'key': 'port', 'type': 'number'}, raw)
            self.assertIn('is a number', str(c.exception))
        self.assertEqual(cli.field_value({'key': 'port', 'type': 'number'}, '443'), 443)

    def test_target_agent_json(self):
        got = run('--target-agent', 'q4ag', 'forget', '--yes', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertTrue(json.loads(got.stdout)['ok'])
        got = run('--target-agent', 'q4ag', 'forget', '--yes')
        self.assertIn('forgotten: the agent of q4ag', got.stdout)
        from acmelib import engine as E
        from acmelib.certs import agents as G, agent_policy as P
        store = E.cli_store()
        row = G.target_row(store, 'q4ag')
        P.design_save(store, row, 'allow file /etc/nginx/ssl owner=root:root mode=0644\n', {},
                      'nginx', '', 'tester')
        got = run('--target-agent', 'q4ag', 'design', 'text', '--json')
        self.assertIn('allow file /etc/nginx/ssl', json.loads(got.stdout)['text'])
        got = run('--target-agent', 'q4ag', 'design', 'forget', '--yes', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertTrue(json.loads(got.stdout)['ok'])

    @unittest.skipUnless(os.geteuid() == 0, 'root sets the console at login')
    def test_console_users_json(self):
        got = run('--console-users', 'alice,bob', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        d = json.loads(got.stdout)
        self.assertEqual((d['on'], d['users']), (False, ['alice', 'bob']))
        got = run('--console-users', 'none', '--json')
        self.assertEqual(json.loads(got.stdout)['users'], [])


class Colour(unittest.TestCase):
    def test_no_color_empty_is_not_set(self):
        from acmelib import engine as E

        class Tty(object):
            def isatty(self):
                return True
        keep = {k: os.environ.get(k) for k in ('NO_COLOR', 'FORCE_COLOR', 'CLICOLOR_FORCE',
                                               'TERM')}
        try:
            os.environ.pop('FORCE_COLOR', None)
            os.environ.pop('CLICOLOR_FORCE', None)
            os.environ['TERM'] = 'xterm'
            os.environ['NO_COLOR'] = ''
            self.assertTrue(E.colour_wanted(False, Tty()))
            os.environ['NO_COLOR'] = '1'
            self.assertFalse(E.colour_wanted(False, Tty()))
        finally:
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_console_menus_plain_without_colour(self):
        from acmelib import engine as E

        class Curses(object):
            A_REVERSE, A_BOLD, A_DIM = 1, 2, 4
            started = False

            def has_colors(self):
                return True

            def start_color(self):
                Curses.started = True

            def __getattr__(self, name):
                return lambda *a: 0
        for on, want in ((False, False), (True, True)):
            Curses.started = False
            con = E.Console(E.Palette(on))
            con.curses = Curses()
            con._colours()
            self.assertEqual(Curses.started, want)


class Console(unittest.TestCase):
    def test_live_log_follows_a_log_made_later(self):
        from acmelib import engine as E
        d = tempfile.mkdtemp(prefix='acme-q4log-')
        was = E.LOG_DIR
        E.LOG_DIR = __import__('pathlib').Path(d)
        seen = {}
        con = E.Console(E.Palette(False))

        def view(title, first, more, paint, find=''):
            seen.update(first=first(), more1=more())
            with open(os.path.join(d, 'acme.log'), 'w') as f:
                f.write('one\ntwo\n')
            seen['more2'] = more()
        con.live_view = view
        try:
            con.live_log('')
        finally:
            E.LOG_DIR = was
        self.assertIn('cannot be read', seen['first'][0])
        self.assertEqual(seen['more1'], [])
        self.assertEqual(seen['more2'], ['one', 'two'])

    def test_account_name_begins_with_a_letter(self):
        from acmelib import engine as E
        con = E.Console(E.Palette(False))
        forms = []
        con.form = lambda title, fields, *a, **k: forms.append(fields) or None
        con.account_new()
        check = [f for f in forms[0] if f['key'] == 'name'][0]['check']
        self.assertIsNotNone(check('-bob', {}))
        self.assertIsNotNone(check('.bob', {}))
        self.assertIsNone(check('bob', {}))
        self.assertIsNone(check('bob.novak@corp', {}))

    def test_agent_design_offered(self):
        from acmelib.certs import console as C

        class Con(object):
            def __init__(self):
                self.acts, self.offered = [], []

            def choose(self, title, opts, *a, **k):
                self.offered = [o[0] for o in opts]
                return 'design'

            def act(self, *args, **k):
                self.acts.append(args)
                return 0
        con = Con()
        C.target_agent(con, 'web')
        self.assertIn('design', con.offered)
        self.assertEqual(con.acts, [('--target-agent', 'web', 'design', 'show')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
