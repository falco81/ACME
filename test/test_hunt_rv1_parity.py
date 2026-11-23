#!/usr/bin/env python3
"""Bug hunt 1.0.140, run v1, parity: what 1.0.138 gave the pages, on the command line and in the
console (acmelib/certs/cli_138.py) - each run here for real against a state of its own, as
`acme ...` is typed:

- history and trash: --history (the latest, one object's), --history-restore, --trash,
  --trash-restore, --trash-purge; --api GET /api/history and /api/trash answer (the routes were
  only the daemon's); --team-del, --tag-del, --dns-set-del go to the trash and their changes to
  the history (they were gone for good, unrecorded);
- request profiles: --profiles, --profile-show, --profile-versions, --profile-diff,
  --profile-restore, --profile-compliance, --profile-dry-run, --profile-end, --profile-del;
- the agent fleet: --fleet, groups, --fleet-assign, --fleet-drift, --fleet-rollout plan,
  --fleet-unmanaged, --fleet-templates; --target-agent NAME watch / watch-set / audit-verify /
  served / ack / rotate and --target-agent all keys;
- the governance of teams: --team-gov(-set), --team-health, --reviews, --review-open,
  --review-answer, --elevations, --elevation-approve (never one's own), --who-may, --who-can,
  team templates and the CSV import;
- options that do not go together refused, nothing done;
- the console's menus run those commands.

    python3 test/test_hunt_rv1_parity.py
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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rv1parity-')
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


def js(test, *args, stdin=''):
    return json.loads(ok(test, *(list(args) + ['--json']), stdin=stdin).stdout)


def inproc(code):
    """A few lines in a process of its own, on the same state (what a person of the portal or
    the pages does that the command line never does - asking for a temporary role)."""
    got = subprocess.run([sys.executable, '-c', 'import sys; sys.path.insert(0, %r)\n' % ROOT
                          + code], env=ENV, capture_output=True, text=True, timeout=120)
    assert got.returncode == 0, got.stdout + got.stderr
    return got.stdout


def setUpModule():
    for args in (('--team-add', 'Web', '--members', 'local:jan=manage,local:eva=view'),
                 ('--target-add', 'srv1', '--kind', 'agent', '--set', 'host=a.example.com'),
                 ('--profile-from-template', 'web', '--name', 'Web', '--names', 'example.com'),
                 ('--profile-from-template', 'web', '--name', 'Web2', '--names',
                  'example.org')):
        got = run(*args)
        assert got.returncode == 0, (args, got.stdout + got.stderr)


# ---------------------------------------------------------------------------------------------
class HistoryAndTrash(unittest.TestCase):
    def test_api_routes_on_the_command_line(self):
        got = run('--api', 'GET', '/api/trash')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('items', json.loads(got.stdout))
        got = run('--api', 'GET', '/api/history?feed=1')
        self.assertEqual(got.returncode, 0, got.stderr)

    def test_team_tag_dnsset_deleted_go_to_the_trash(self):
        ok(self, '--team-add', 'Gone1')
        ok(self, '--team-edit', 'Gone1', '--contact-mail', 'g@example.com')
        ok(self, '--team-del', 'Gone1', '--yes')
        ok(self, '--tag-add', 'gonetag')
        ok(self, '--tag-del', 'gonetag', '--yes')
        ok(self, '--dns-set-add', 'GoneSet', '--servers', '10.0.0.1')
        ok(self, '--dns-set-del', 'GoneSet', '--yes')
        items = js(self, '--trash')['items']
        names = {(i['type'], i['name']) for i in items}
        for want in (('team', 'Gone1'), ('tag', 'gonetag'), ('dnsset', 'GoneSet')):
            self.assertIn(want, names)
        h = js(self, '--history', 'team', 'Gone1')
        self.assertEqual([e['action'] for e in h['entries']], ['delete', 'change', 'create'])
        self.assertTrue(all(e['who'] == 'command line' for e in h['entries']))
        # brought back from the trash, then gone for good
        tid = next(i['id'] for i in items if i['name'] == 'Gone1')
        ok(self, '--trash-restore', tid)
        self.assertIn('Gone1', ok(self, '--teams').stdout)
        tid = next(i['id'] for i in items if i['name'] == 'gonetag')
        got = run('--trash-purge', tid)                  # no terminal, no --yes: refused
        self.assertNotEqual(got.returncode, 0)
        ok(self, '--trash-purge', tid, '--yes')
        self.assertNotIn('gonetag', [i['name'] for i in js(self, '--trash')['items']])

    def test_history_restore(self):
        ok(self, '--team-add', 'Hist1', '--contact-mail', 'a@example.com')
        ok(self, '--team-edit', 'Hist1', '--contact-mail', 'b@example.com')
        h = js(self, '--history', 'team', 'Hist1')
        first = h['entries'][-1]['id']
        feed = js(self, '--history', '--limit', '5')
        self.assertTrue(feed['entries'])
        self.assertIn('Hist1', ok(self, '--history').stdout)
        ok(self, '--history-restore', first, '--yes')
        t = next(t for t in js(self, '--teams')['teams'] if t['name'] == 'Hist1')
        self.assertEqual(t['contact_mail'], 'a@example.com')
        got = run('--history', 'team')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('TYPE NAME', got.stderr)


# ---------------------------------------------------------------------------------------------
class Profiles(unittest.TestCase):
    def test_versions_diff_restore(self):
        p = js(self, '--profile-show', 'Web2')
        self.assertEqual(p['name'], 'Web2')
        p['old_name'] = p['name']
        p['description'] = 'changed on the command line'
        ok(self, '--api', 'POST', '/api/reqprofiles/save', '-', stdin=json.dumps(p))
        v = js(self, '--profile-versions', 'Web2')
        self.assertGreaterEqual(v['current'], 2)
        self.assertIn('description', ok(self, '--profile-diff', 'Web2', '1').stdout)
        d = js(self, '--profile-diff', 'Web2', '1')
        self.assertTrue(any(not r['same'] and r['key'] == 'description' for r in d['rows']))
        ok(self, '--profile-restore', 'Web2', '1', '--yes')
        self.assertNotEqual(js(self, '--profile-show', 'Web2')['description'],
                            'changed on the command line')
        got = run('--profile-restore', 'Web2', 'one', '--yes')
        self.assertNotEqual(got.returncode, 0)

    def test_list_compliance_dry_run(self):
        rows = {p['name']: p for p in js(self, '--profiles')['profiles']}
        self.assertIn('Web', rows)
        self.assertIn('PROFILE', ok(self, '--profiles').stdout)
        self.assertIn('profiles', js(self, '--profile-compliance'))
        run('--profile-compliance', '2030-01-01')            # a day to come: answers
        got = js(self, '--profile-dry-run', 'Web', '--names', 'www.example.com')
        self.assertTrue(got['fits'])
        got = run('--profile-dry-run', 'Web', '--names', 'www.not-ours.test')
        self.assertEqual(got.returncode, 1)
        self.assertIn('refused', got.stdout)
        got = run('--profile-dry-run', 'Web')
        self.assertIn('--names', got.stderr)

    def test_end_and_delete(self):
        ok(self, '--profile-from-template', 'web', '--name', 'Old', '--names', 'example.net')
        ok(self, '--profile-end', 'Old', 'Web', '--yes')
        rows = {p['name']: p for p in js(self, '--profiles')['profiles']}
        self.assertEqual(rows['Old']['ends']['successor'], 'Web')
        ok(self, '--profile-end', 'Old', '-')
        rows = {p['name']: p for p in js(self, '--profiles')['profiles']}
        self.assertFalse(rows['Old'].get('ends'))
        ok(self, '--profile-del', 'Old', '--yes')
        self.assertNotIn('Old', [p['name'] for p in js(self, '--profiles')['profiles']])
        self.assertIn('Old', [i['name'] for i in js(self, '--trash')['items']])
        got = run('--profile-show', 'Nope')
        self.assertIn('no request profile', got.stderr)


# ---------------------------------------------------------------------------------------------
class Fleet(unittest.TestCase):
    def test_fleet_groups_templates_drift(self):
        f = js(self, '--fleet')
        self.assertIn('srv1', [a['name'] for a in f['agents']])
        tpl = js(self, '--fleet-templates')['templates']
        self.assertTrue(any(t['ref'] == 'builtin:nginx-web' for t in tpl))
        ok(self, '--fleet-group-save', 'Canary', '--fleet-members', 'srv1', '--fleet-canary',
           'yes', '--fleet-template', 'builtin:nginx-web')
        g = next(g for g in js(self, '--fleet')['groups'] if g['name'] == 'Canary')
        self.assertTrue(g['canary'])
        self.assertEqual(g['template'], 'builtin:nginx-web')
        ok(self, '--fleet-assign', 'builtin:haproxy', 'srv1')
        d = js(self, '--fleet-drift', 'srv1')['rows']
        self.assertEqual(d[0]['drift']['template']['ref'], 'builtin:haproxy')
        ok(self, '--fleet-assign', '-', 'srv1')
        self.assertIn('canary ring', ok(self, '--fleet-rollout', 'plan', 'Canary').stdout)
        self.assertEqual(js(self, '--fleet-unmanaged')['rows'], [])
        ok(self, '--fleet-group-save', 'Canary', '--fleet-members', '-')
        ok(self, '--fleet-group-del', 'Canary')
        self.assertNotIn('Canary', [g['name'] for g in js(self, '--fleet')['groups']])
        got = run('--fleet-assign', 'no-such-template', 'srv1')
        self.assertIn('no template', got.stderr)
        got = run('--fleet-group-save', 'X', '--fleet-members', 'nosuchtarget')
        self.assertNotEqual(got.returncode, 0)

    def test_watching_an_agent(self):
        w = js(self, '--target-agent', 'srv1', 'watch')['guard']
        self.assertFalse(w['opts']['audit'])
        ok(self, '--target-agent', 'srv1', 'watch-set', 'audit=on', 'anomaly=on',
           'rotate_days=30', 'health=on')
        o = js(self, '--target-agent', 'srv1', 'watch')['guard']['opts']
        self.assertEqual((o['audit'], o['anomaly'], o['rotate_days'], o['health']),
                         (True, True, 30, 'on'))
        self.assertIn('audit chain', ok(self, '--target-agent', 'srv1', 'watch').stdout)
        # not joined: said, not done (the routes' own words)
        got = run('--target-agent', 'srv1', 'audit-verify')
        self.assertIn('not joined', got.stderr)
        got = run('--target-agent', 'srv1', 'served')
        self.assertIn('allow probe local', got.stderr)
        got = run('--target-agent', 'srv1', 'rotate', '--yes')
        self.assertIn('not joined', got.stderr)
        ok(self, '--target-agent', 'srv1', 'ack', 'anomaly')
        for bad in (('watch-set', 'audit=maybe'), ('watch-set', 'colour=red'), ('ack', 'x'),
                    ('rotate', 'nonsense', '--yes')):
            got = run('--target-agent', 'srv1', *bad)
            self.assertNotEqual(got.returncode, 0, bad)
        ok(self, '--target-agent', 'srv1', 'watch-set', 'audit=off', 'anomaly=off', 'health=off')
        self.assertIn('cmd', js(self, '--target-agent', 'all', 'keys')['keys'])
        self.assertIn('COMMAND KEY', ok(self, '--target-agent', 'all', 'keys').stdout)


# ---------------------------------------------------------------------------------------------
class Governance(unittest.TestCase):
    def test_gov_reviews_elevations(self):
        gov = {"review": {"every_days": 90, "answer_days": 14, "action": "report"},
               "jit": {"roles": ["Requester"], "max_hours": 4},
               "sod": {"no_self_approval": True}}
        ok(self, '--team-gov-set', 'Web', json.dumps(gov))
        g = js(self, '--team-gov', 'Web')
        self.assertEqual(g['gov']['jit']['roles'], ['Requester'])
        self.assertTrue(g['sod_in_force']['no_self_approval'])
        ok(self, '--team-gov-set', 'Web', '-', stdin='{"review": null}')
        self.assertNotIn('review', js(self, '--team-gov', 'Web')['gov'])
        got = run('--team-gov-set', 'Web', '{"hooks": {"slack": "https://x"}}')
        self.assertIn('sealed', got.stderr)
        # access reviews
        ok(self, '--review-open', 'Web')
        rid = js(self, '--reviews')['open'][0]['id']
        self.assertIn('local:jan', ok(self, '--reviews', 'Web').stdout)
        ok(self, '--review-answer', rid, 'local:jan', 'keep', '--note', 'still here')
        ok(self, '--review-answer', rid, 'local:eva', 'keep')
        self.assertEqual(js(self, '--reviews', 'Web')['reviews'][0]['state'], 'done')
        # a temporary role asked for by eva (the portal does that) - approved here
        inproc('''
from acmelib import engine as E
from acmelib.certs import api, teamgov as G
st = E.cli_store()
G.elevation_ask(st, {'by': 'eva', 'who': 'local:eva', 'ids': ['local:eva'],
                     'names': {'local:eva'}, 'groups': [], 'all': False,
                     'caps': {'web': {'name': 'Web', 'caps': frozenset(['cert.view'])}}},
                'Web', 'Requester', 2, 'a certificate for the shop')
''')
        todo = js(self, '--elevations')['to_decide']
        self.assertEqual([(r['who'], r['role']) for r in todo], [('local:eva', 'Requester')])
        ok(self, '--elevation-approve', todo[0]['id'], '--why', 'fine')
        rows = js(self, '--elevations', 'Web')['rows']
        self.assertEqual(rows[0]['state'], 'granted')
        self.assertIn('a temporary role', ok(self, '--who-may', 'local:eva').stdout)
        ok(self, '--elevation-end', todo[0]['id'])
        # the command line asks for one itself: never its own to approve
        ok(self, '--api', 'POST', '/api/teams/elevate', '{"team": "Web", "role": "Requester", '
           '"hours": 1, "reason": "a test of mine"}')
        mine = js(self, '--elevations', 'Web')['rows'][0]
        got = run('--elevation-approve', mine['id'])
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('yourself', got.stderr)
        got = run('--elevation-decline', mine['id'], '--why', 'not needed')
        self.assertIn('yourself', got.stderr)
        ok(self, '--elevation-end', mine['id'])          # taken back by who asked

    def test_health_who_templates_csv(self):
        h = js(self, '--team-health')
        self.assertIn('Web', [t['team'] for t in h['teams']])
        self.assertIn('SCORE', ok(self, '--team-health', 'Web').stdout)
        self.assertEqual(js(self, '--who-may', 'team:Web')['mode'], 'team')
        self.assertIn('manage on Web', ok(self, '--who-may', 'local:jan').stdout)
        got = js(self, '--who-can', 'cert.renew', 'Web')
        self.assertIn('local:jan', [p['who'] for p in got['people']])
        ok(self, '--team-template-save', 'Web', 'WebTpl')
        self.assertIn('WebTpl', [t['name'] for t in js(self, '--team-templates')['templates']])
        ok(self, '--team-from-template', 'WebTpl', 'Web3', '--parent', 'Web')
        self.assertEqual(next(t for t in js(self, '--teams')['teams']
                              if t['name'] == 'Web3')['parent'], 'Web')
        csv = os.path.join(TMP, 'teams.csv')
        with open(csv, 'w') as f:
            f.write('name,parent,kind,template,description,contact_mail,members\n'
                    'App1,Web,team,,App one,,local:ivo=view\n')
        got = run('--teams-import-csv', csv)                # a preview, then refused unasked
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('+ App1', got.stdout)
        self.assertNotIn('App1', [t['name'] for t in js(self, '--teams')['teams']])
        ok(self, '--teams-import-csv', csv, '--yes')
        self.assertIn('App1', [t['name'] for t in js(self, '--teams')['teams']])
        with open(csv, 'w') as f:
            f.write('name,parent\nBad1,NoSuchTeam\n')
        got = run('--teams-import-csv', csv, '--yes')
        self.assertIn('errors', got.stderr)
        self.assertNotIn('Bad1', [t['name'] for t in js(self, '--teams')['teams']])


# ---------------------------------------------------------------------------------------------
class Refused(unittest.TestCase):
    def test_one_at_a_time_and_options_that_go_with_others(self):
        for args, words in ((('--profiles', '--trash'), 'one of them at a time'),
                            (('--profiles', '--names', 'x'), '--names goes with'),
                            (('--trash', '--note', 'x'), '--note goes with'),
                            (('--fleet', '--fleet-canary', 'yes'), '--fleet-canary goes with'),
                            (('--fleet-rollout', 'bogus'), 'plan|start'),
                            (('--review-answer', '1', 'x', 'maybe'), 'keep|out')):
            got = run(*args)
            self.assertNotEqual(got.returncode, 0, args)
            self.assertIn(words, got.stderr, args)

    def test_help_lists_them(self):
        out = ok(self, '--help').stdout
        for opt in ('--history', '--trash-restore', '--profile-versions', '--fleet-takeover',
                    '--team-gov-set', '--who-can', '--elevation-approve', '--review-open',
                    '--teams-import-csv'):
            self.assertIn(opt, out)


# ---------------------------------------------------------------------------------------------
class Con(object):
    """The console as its menus see it; what a person answers given in order."""
    def __init__(self, chooses=(), asks=(), forms=()):
        self.chooses, self.asks, self.forms = list(chooses), list(asks), list(forms)
        self.acts, self.notes, self.subs = [], [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        return json.loads(got.stdout or 'null')

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)), []))

    def act(self, *args, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def sub(self, title, items):
        self.subs.append((title, items))

    def pick(self, title, load, cols, act=None, empty='', words=''):
        rows = load()
        for c in cols:
            for r in rows:
                c[1](r)
        if act and rows and self.chooses:
            act(rows[0])
        return rows

    def choose(self, title, options, words='', cur=0):
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def ask_one(self, *a, **k):
        return self.asks.pop(0)

    def form(self, title, fields, words='', check=None, ok='OK'):
        vals = {f['key']: str(f.get('value') or '') for f in fields}
        vals.update(self.forms.pop(0))
        return vals

    def confirm(self, *a, **k):
        return True

    def note(self, title, words, tone=''):
        self.notes.append((title, words))


class Console(unittest.TestCase):
    def test_main_menu_has_it(self):
        from acmelib.certs import console as C
        con = Con()
        keys = [k for k, _w, _f in C.main_items(con)]
        self.assertIn('h', keys)
        self.assertEqual(len(keys), len(set(keys)))
        dict((k, f) for k, _w, f in C.main_items(con))['h']()
        title, items = con.subs[-1]
        self.assertEqual(len({k for k, _w, _f in items}), len(items))
        for k, _w, f in items:
            if k in ('1', '2', '3', '5', '7', '9'):
                f()
        self.assertFalse([a for a in con.acts if a[1] != 0 and '--fleet-drift' not in a[0]],
                         con.acts)

    def test_profiles_menu_runs_the_options(self):
        from acmelib.certs import cli_138 as M
        con = Con(chooses=['versions'])
        M._con_profiles(con)
        self.assertEqual(con.acts[-1][0][:1], ('--profile-versions',))
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        con = Con(chooses=['dry'], asks=['www.example.com'])
        M._con_profiles(con)
        self.assertEqual(con.acts[-1][0][0], '--profile-dry-run')

    def test_teams_menu_and_a_team(self):
        from acmelib.certs import console as C
        con = Con()
        C.teams_menu(con)
        _t, items = con.subs[-1]
        keys = [k for k, _w, _f in items]
        self.assertEqual(len(keys), len(set(keys)))
        dict((k, f) for k, _w, f in items)['7']()
        self.assertEqual(con.acts[-1][0], ('--team-health',))
        self.assertEqual(con.acts[-1][1], 0)
        con = Con(chooses=['gov'])
        C.team_do(con, {'name': 'Web'})
        self.assertEqual(con.acts[-1][0], ('--team-gov', 'Web'))
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])

    def test_agent_menu_watch(self):
        from acmelib.certs import console as C
        con = Con(chooses=['watch'])
        C.target_agent(con, 'srv1', 'agent')
        self.assertEqual(con.acts[-1][0], ('--target-agent', 'srv1', 'watch'))
        self.assertEqual(con.acts[-1][1], 0)
        con = Con(chooses=['watch-set'], forms=[{'anomaly': 'on'}])
        C.target_agent(con, 'srv1', 'agent')
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertTrue(js(self, '--target-agent', 'srv1', 'watch')['guard']['opts']['anomaly'])
        con = Con(chooses=['watch-set'], forms=[{'anomaly': 'off'}])
        C.target_agent(con, 'srv1', 'agent')
        self.assertFalse(js(self, '--target-agent', 'srv1', 'watch')['guard']['opts']['anomaly'])


if __name__ == '__main__':
    unittest.main()
