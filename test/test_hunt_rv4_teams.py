#!/usr/bin/env python3
"""Bug hunt 1.0.142, run v4, teams and roles (acmelib/certs/teams.py, teamgov.py, cli_138.py):

- a custom role renamed: the exclusive pairs of separation of duties, the roles just-in-time
  elevation gives, the templates and the temporary roles waiting or given follow it (the pair
  named a role no longer there and was silently no rule: one member then held both sides);
- a team renamed: the saved views shared with it follow (its members no longer saw them);
- a temporary role ended (or a request taken back) only over the state it was read in - one
  declined or granted meanwhile is not overwritten;
- the deadline of an access review written only over the review as it is: a member confirmed
  just before the deadline is not expired all the same, an answer is not lost;
- the command line deletes a template of teams (--team-template-del), as the page does.

    python3 test/test_hunt_rv4_teams.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import test_teams_enterprise as TE  # noqa: E402  (its database, its helpers)
from acmelib.certs import teamgov as G  # noqa: E402
from acmelib.certs import history as H  # noqa: E402

T, E, STORE = TE.T, TE.E, TE.STORE


def clean():
    TE.clean()
    for table in ('cert_team_elevations', 'cert_team_reviews', 'cert_team_templates',
                  'saved_views'):
        try:
            STORE.db.run('DELETE FROM %s' % table)
        except Exception:                               # noqa: BLE001
            pass
    T.changed()


class RoleRenamed(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_role(STORE, {'name': 'Issuer', 'caps': ['cert.request']}, 'x')
        T.save_role(STORE, {'name': 'Signer', 'caps': ['cert.approve']}, 'x')
        T.save_team(STORE, {'name': 'A'}, 'x')
        G.set_extras(STORE, 'A', 'sod', {'exclusive': [['Issuer', 'Signer']]}, 'x')
        G.set_extras(STORE, 'A', 'jit', {'roles': ['Issuer'], 'max_hours': 4}, 'x')

    def test_sod_and_jit_follow(self):
        T.save_role(STORE, {'old_name': 'Issuer', 'name': 'Asker'}, 'x')
        ex = G.extras_of(T.team_get(STORE, 'A'))
        self.assertEqual(ex['sod']['exclusive'], [['Asker', 'Signer']])
        self.assertEqual(ex['jit']['roles'], ['Asker'])
        with self.assertRaises(ValueError) as cm:
            T.save_team(STORE, {'old_name': 'A', 'name': 'A', 'members': [
                {'who': 'local:bob', 'roles': ['Asker', 'Signer']}]}, 'x')
        self.assertIn('separation of duties', str(cm.exception))

    def test_grants_and_templates_follow(self):
        now = time.time()
        STORE.db.insert('cert_team_elevations', {
            'team': 'A', 'who': 'local:bob', 'ids': '["local:bob"]', 'role': 'Issuer', 'hours': 2,
            'reason': 'need it', 'state': 'granted', 'asked': now, 'asked_by': 'bob',
            'until': now + 3600, 'updated': now})
        STORE.db.insert('cert_team_elevations', {
            'team': 'A', 'who': 'local:eva', 'ids': '["local:eva"]', 'role': 'Issuer', 'hours': 2,
            'reason': 'old one', 'state': 'expired', 'asked': now - 9e5, 'asked_by': 'eva',
            'until': now - 8e5, 'updated': now})
        G.save_template(STORE, {'name': 'Tpl', 'from_team': 'A'}, 'x')
        T.changed()
        self.assertIn('cert.request', T.person_caps(STORE, {'local:bob'}, [])['a']['caps'])
        T.save_role(STORE, {'old_name': 'Issuer', 'name': 'Asker'}, 'x')
        T.changed()
        self.assertIn('cert.request', T.person_caps(STORE, {'local:bob'}, [])['a']['caps'])
        roles = {r['who']: r['role'] for r in STORE.db.rows(
            'SELECT who, role FROM cert_team_elevations')}
        self.assertEqual(roles, {'local:bob': 'Asker', 'local:eva': 'Issuer'})  # history kept
        cfg = G.template_get(STORE, 'Tpl')['config']
        self.assertEqual(cfg['extras']['sod']['exclusive'], [['Asker', 'Signer']])
        self.assertEqual(cfg['extras']['jit']['roles'], ['Asker'])
        made = G.team_from_template(STORE, 'Tpl', 'B', None, 'x')
        self.assertEqual(made['name'], 'B')


class TeamRenamedViews(unittest.TestCase):
    def setUp(self):
        clean()

    def test_team_views_follow(self):
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:jan', 'roles': ['Team manager']}]}, 'x')
        admin = {'name': 'boss', 'role': 'fulladmin'}
        H.view_save(STORE, admin, {'table': 'certs', 'name': 'Ours', 'scope': 'team',
                                   'team': 'Web', 'view': {'filters': {'q': 'x'}}})
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web Ops'}, 'x')
        row = STORE.db.row("SELECT team FROM saved_views WHERE name = 'Ours'")
        self.assertEqual(row['team'], 'Web Ops')


class ElevationEnd(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'A'}, 'x')
        now = time.time()
        self.eid = STORE.db.insert('cert_team_elevations', {
            'team': 'A', 'who': 'local:bob', 'ids': '["local:bob"]', 'role': 'Viewer',
            'hours': 2, 'reason': 'need it', 'state': 'waiting', 'asked': now, 'asked_by': 'bob',
            'updated': now})
        self.actor = {'by': 'bob', 'who': 'local:bob', 'ids': ['local:bob'], 'names': {'local:bob'},
                      'caps': {}, 'all': False}

    def test_decided_meanwhile_not_overwritten(self):
        stale = G._elev_get(STORE, self.eid)
        STORE.db.run("UPDATE cert_team_elevations SET state = 'declined', decided_why = 'no' "
                     "WHERE id = ?", (self.eid,))
        orig = G._elev_get
        G._elev_get = lambda store, eid: stale
        try:
            with self.assertRaises(E.ApiError) as cm:
                G.elevation_end(STORE, self.eid, self.actor)
        finally:
            G._elev_get = orig
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(STORE.db.row('SELECT state FROM cert_team_elevations WHERE id = ?',
                                      (self.eid,))['state'], 'declined')

    def test_taken_back(self):
        got = G.elevation_end(STORE, self.eid, self.actor)
        self.assertEqual(got['state'], 'cancelled')
        with self.assertRaises(E.ApiError):
            G.elevation_end(STORE, self.eid, self.actor)


class ReviewDeadline(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'R', 'members': [
            {'who': 'local:a', 'roles': ['Viewer']}, {'who': 'local:b', 'roles': ['Viewer']}]},
            'x')
        self.rule = {'every_days': 90, 'answer_days': 1, 'action': 'expire'}
        G.set_extras(STORE, 'R', 'review', self.rule, 'x')
        G.review_open(STORE, 'R', 'x', self.rule)
        STORE.db.run('UPDATE cert_team_reviews SET due = ?', (time.time() - 10,))

    def _answer_a(self):
        r = STORE.db.row('SELECT * FROM cert_team_reviews')
        items = json.loads(r['items'])
        for i in items:
            if i['who'] == 'local:a':
                i.update(state='kept', by='jan', at=time.time())
        STORE.db.run('UPDATE cert_team_reviews SET items = ?', (json.dumps(items),))

    def test_confirmed_just_before_is_not_expired(self):
        stale = G.reviews(STORE, 'R', 3)[0]
        self._answer_a()                 # answered after the tick read it
        G._review_late(STORE, T.team_get(STORE, 'R'), stale, self.rule)
        r = STORE.db.row('SELECT * FROM cert_team_reviews')
        states = {i['who']: i['state'] for i in json.loads(r['items'])}
        self.assertEqual(states, {'local:a': 'kept', 'local:b': 'expired'})
        self.assertEqual(r['state'], 'closed')
        ms = {m['who']: m for m in json.loads(T.team_get(STORE, 'R')['members'])}
        self.assertFalse(ms['local:a'].get('until'))
        self.assertTrue(ms['local:b'].get('until'))

    def test_report_keeps_the_answer(self):
        rule = dict(self.rule, action='report')
        STORE.db.run("UPDATE cert_team_reviews SET action = 'report'")
        stale = G.reviews(STORE, 'R', 3)[0]
        self._answer_a()
        G._review_late(STORE, T.team_get(STORE, 'R'), stale, rule)
        r = STORE.db.row('SELECT * FROM cert_team_reviews')
        states = {i['who']: i['state'] for i in json.loads(r['items'])}
        self.assertEqual(states, {'local:a': 'kept', 'local:b': 'pending'})
        self.assertEqual(r['state'], 'overdue')

    def test_closed_meanwhile_left_alone(self):
        stale = G.reviews(STORE, 'R', 3)[0]
        STORE.db.run("UPDATE cert_team_reviews SET state = 'closed', done_by = 'someone'")
        G._review_late(STORE, T.team_get(STORE, 'R'), stale, self.rule)
        self.assertEqual(STORE.db.row('SELECT done_by FROM cert_team_reviews')['done_by'],
                         'someone')
        ms = json.loads(T.team_get(STORE, 'R')['members'])
        self.assertFalse(any(m.get('until') for m in ms))

    def test_removal_failed_stays_overdue(self):
        # the last member taken out of an overdue review, the removal failing: the review is
        # overdue again (it was made "open" - the next tick said it was overdue a second time)
        STORE.db.run("UPDATE cert_team_reviews SET state = 'overdue', action = 'report'")
        self._answer_a()
        rid = STORE.db.row('SELECT id FROM cert_team_reviews')['id']
        orig = T.save_team

        def boom(*a, **k):
            raise ValueError('cannot save now')
        T.save_team = boom
        try:
            with self.assertRaises(ValueError):
                G.review_answer(STORE, rid, 'local:b', False, {'by': 'boss', 'all': True})
        finally:
            T.save_team = orig
        r = STORE.db.row('SELECT * FROM cert_team_reviews')
        self.assertEqual(r['state'], 'overdue')
        states = {i['who']: i['state'] for i in json.loads(r['items'])}
        self.assertEqual(states, {'local:a': 'kept', 'local:b': 'pending'})
        STORE.db.run('DELETE FROM events')
        G._review_tick(STORE)
        self.assertFalse(STORE.db.rows("SELECT * FROM events WHERE message LIKE '%overdue%'"))

    def test_tick_still_works(self):
        G._review_tick(STORE)
        r = STORE.db.row('SELECT * FROM cert_team_reviews')
        self.assertEqual(r['state'], 'closed')


class CommandLine(unittest.TestCase):
    def test_template_delete(self):
        tmp = tempfile.mkdtemp(prefix='acme-rv4teams-')
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            f.write('{}')
        env = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
        env.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(tmp, 'config.json'),
                   ACME_STATE=tmp, ACME_RUN=tmp, ACME_LOGDIR=tmp, NO_COLOR='1')

        def run(*a):
            return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(a),
                                  env=env, capture_output=True, text=True, timeout=240)
        for a in (('--team-add', 'Web'), ('--team-template-save', 'Web', 'Tpl')):
            got = run(*a)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        got = run('--team-template-del', 'Tpl', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('deleted', got.stdout)
        got = run('--team-templates', '--json')
        self.assertEqual(json.loads(got.stdout)['templates'], [])
        got = run('--team-template-del', 'Tpl', '--yes')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('--team-template-del', run('--help').stdout)
        with open(os.path.join(ROOT, 'docs', 'command-line.md'), encoding='utf-8') as f:
            self.assertIn('--team-template-del', f.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
