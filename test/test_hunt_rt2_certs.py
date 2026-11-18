#!/usr/bin/env python3
"""Hunt Rt2 - the certificate lifecycle with teams in play.

    python3 test/test_hunt_rt2_certs.py

- an action approved (approve_actions) that could not be done (a job working on the
  certificate) waits again to be approved - it stayed 'approved', never done, every approval
  refused;
- a request that waits again (a new CSR with other names) does not count the approvals it had
  before - one more approval let it through where its team wants two;
- a new CSR with other names for a team's certificate is held to the team's limits and its
  approval rule - it was issued at once, outside the team's suffixes;
- a request moved to another team (its team deleted with reassign) does not count the first
  team's approvals;
- What happens says a request waiting for approval is issued once approved (not "renewed only
  when somebody asks"), and a declined one is never issued.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_req_profiles as RP  # noqa: E402  (its database, its helpers)

T, STORE, E, P, S, R, jobs, pki = RP.T, RP.STORE, RP.E, RP.P, RP.S, RP.R, RP.jobs, RP.pki
from acmelib.certs import api as A, teampolicy as TP  # noqa: E402
from acmelib.certs import portal_teams, runplan  # noqa: E402,F401

PEOPLE = ('lead1', 'lead2', 'lead3', 'lead4', 'cm', 'eva2', 'mgr')


def me(name):
    return RP.person(name, local=True)


def call(who, method, name, body=None):
    return RP.portal(me(who), method, '/api/portal/' + name, body)


def refusal(who, method, name, body=None):
    try:
        call(who, method, name, body)
    except E.ApiError as e:
        return e.status, str(e)
    return 200, ''


def state(cid):
    return STORE.db.value('SELECT state FROM certs WHERE id = ?', (cid,))


def csr(names):
    return pki.make_csr(pki.make_key('ec-256'), names)[0]


class Base(unittest.TestCase):
    def setUp(self):
        RP.setup()
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'teams:action:%'")
        for n in PEOPLE:
            if not STORE.account(n):
                STORE.add_account(n, 'readonly', 'Local-Only-Pw-77!x' + n)
        R.save_profile(STORE, RP.base_profile(make_key=False, pfx=False), 'x')
        self.saved_issue = P.start_issue
        P.start_issue = lambda *a, **k: None            # approved: not issued here

    def tearDown(self):
        P.start_issue = self.saved_issue

    def team(self, name, members, policy=None):
        have = T.team_get(STORE, name)
        b = {'name': name, 'members': members, 'policy': policy or {}}
        if have:
            b['old_name'] = have['name']
        T.save_team(STORE, b, 'x')

    def ask(self, names):
        return call('eva2', 'POST', 'cert_request', {'profile': 'Web servers',
                                                     'csr': csr(names), 'team': 'Web'})['id']


class ActionNotDone(Base):
    def test_approved_but_busy_waits_again(self):
        self.team('Web', [{'who': 'local:lead1', 'roles': ['Approver']},
                          {'who': 'local:cm', 'roles': ['Certificate manager']}],
                  {'approve_actions': ['delete']})
        cid = A.cert_save(STORE, {'name': 'act1', 'names': ['act1.example.test'],
                                  'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 0,
                                  'owner': 'Web', 'hold': 1}, 'test')
        got = call('cm', 'POST', 'cert_delete', {'id': cid})
        aid = got['action']['id']
        real = jobs.cert_busy
        jobs.cert_busy = lambda *a: True
        try:
            self.assertEqual(refusal('lead1', 'POST', 'action_approve', {'id': aid, 'ok': 1})[0],
                             409)
        finally:
            jobs.cert_busy = real
        self.assertEqual(TP._action_get(STORE, aid)['state'], 'waiting')
        # approved again once the job is done: done
        self.assertEqual(call('lead1', 'POST', 'action_approve', {'id': aid, 'ok': 1})[
            'action']['state'], 'done')
        self.assertIsNone(STORE.db.value('SELECT id FROM certs WHERE id = ?', (cid,)))


class WaitsAgain(Base):
    def test_earlier_approvals_not_counted(self):
        self.team('Web', ['group:WEB_ADMINS=request', 'local:eva2=request', 'local:mgr=manage',
                          'local:lead1=approve', 'local:lead2=approve', 'local:lead3=approve'],
                  {'approval': {'mode': 'always', 'count': 2}})
        cid = self.ask(['four.example.test'])
        self.assertEqual(state(cid), P.WAITING)
        call('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        call('lead2', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), 'new')                 # approved, its issue not done
        got = call('mgr', 'POST', 'cert_csr', {'id': cid, 'csr': csr(['four2.example.test'])})
        self.assertTrue(got['waits'])
        st = TP.approval_state(STORE, S.cert_get(STORE, cid))
        self.assertFalse(st['complete'])
        self.assertEqual(st['approvals'], [])
        # one more approval does not let it through; the earlier approvers may approve again
        call('lead3', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), P.WAITING)
        call('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), 'new')
        # the timeline still shows every approval
        self.assertEqual([e['what'] for e in TP.timeline(STORE, cid)].count('approved'), 4)

    def test_moved_to_another_team(self):
        pol = {'approval': {'mode': 'always', 'count': 2}}
        self.team('Web', ['local:eva2=request', 'local:lead1=approve'], pol)
        self.team('Mail', ['local:lead3=approve', 'local:lead4=approve'], pol)
        cid = self.ask(['moved.example.test'])
        call('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        T.delete_team(STORE, 'Web', 'x', reassign='Mail')
        call('lead3', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), P.WAITING)            # Mail's rule: two of Mail's
        call('lead4', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), 'new')

    def test_renamed_team_keeps_its_approvals(self):
        self.team('Web', ['local:eva2=request', 'local:lead1=approve', 'local:lead2=approve'],
                  {'approval': {'mode': 'always', 'count': 2}})
        cid = self.ask(['ren.example.test'])
        call('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web2'}, 'x')
        call('lead2', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(state(cid), 'new')


class NewCsrWithinLimits(Base):
    def test_other_names_held_to_the_team(self):
        P.start_issue = self.saved_issue
        self.team('Web', ['group:WEB_ADMINS=request', 'local:eva2=request', 'local:mgr=manage',
                          'local:lead1=approve'],
                  {'approval': {'mode': 'always'}, 'suffixes': ['in.example.test']})
        cid = self.ask(['a.in.example.test'])
        call('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        RP.wait_cert(cid)
        # outside the team's suffixes: refused, nothing changed
        st, words = refusal('mgr', 'POST', 'cert_csr', {'id': cid, 'csr': csr(['b.example.test'])})
        self.assertEqual(st, 403)
        self.assertIn('in.example.test', words)
        # inside them, but the team approves every request: other names are a new request
        st, _w = refusal('mgr', 'POST', 'cert_csr', {'id': cid,
                                                     'csr': csr(['c.in.example.test'])})
        self.assertEqual(st, 409)
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['version'], S.jload(row['names'], [])), (1, ['a.in.example.test']))
        # the same names, a new key: issued again as before
        call('mgr', 'POST', 'cert_csr', {'id': cid, 'csr': csr(['a.in.example.test'])})
        RP.wait_cert(cid, 2)


class WhatHappens(unittest.TestCase):
    def test_waiting_and_declined(self):
        def words(st):
            got = runplan.after_phase(STORE, {'id': 999999, 'name': 'w', 'state': st,
                                              'auto_renew': 0}, None, [])
            return ' | '.join(s['words'] for s in got['steps'])
        self.assertIn('it waits for approval', words(P.WAITING))
        self.assertNotIn('renewed only when somebody asks', words(P.WAITING))
        self.assertIn('it was declined', words(P.DECLINED))
        self.assertIn('renewed only when somebody asks', words('ok'))


if __name__ == '__main__':
    unittest.main()
