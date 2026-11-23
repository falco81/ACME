#!/usr/bin/env python3
"""Hunt 1.0.143, run w1, area sec: the security fixes of this round.

- what the services of an agent's server serve (agent_guard B6: the certificate deployed, the
  names and the subject it serves) was named of other teams' certificates to a session kept to
  its teams - in /api/agents, /api/agents/one, /api/agents/builder (the agent's summary),
  /api/agents/guard (the card's "Watching this agent") and on the portal's device; now "another
  owner's certificate" with its state only, as keys_of and the builder's needs already were;
- POST /api/agents/look answered the card without that filter: the certificates whose key the
  agent makes (keys_of) of other teams were named (GET /api/agents/one hid them);
- viewing the pages as a member (read-only): GET /api/agents/discover sent a signed job to the
  server, kept its answer with the target and wrote an event in the member's name - refused now
  (the last discovery kept, cached=1, is still shown).

    python3 test/test_hunt_rw1_sec.py
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_hunt_rv2_sec as V  # noqa: E402  (its store, H, setup())

from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A, api_agents as AA, portal_teams as PT  # noqa: E402

STORE = V.STORE


def call(method, path, body=None, **kw):
    return E.ROUTES[(method, path)](V.H(body=body, **kw))


class ViewAsH(V.H):
    """A full administrator viewing the pages as mgr: the session as engine me() makes it."""
    def me(self, r='readonly'):
        s = V.H.me(self, r)
        s['view_as_by'] = 'boss'
        return s


def served(oc_did, wc_did):
    return {str(oc_did): {'at': 1, 'state': 'old', 'cert': 'opscertq', 'version': 2,
                          'places': [{'host': '127.0.0.1', 'port': 443, 'state': 'old',
                                      'names': ['opsnameq.example.test'],
                                      'subject': 'CN=opsnameq.example.test', 'fp': 'AB'}]},
            str(wc_did): {'at': 1, 'state': 'ok', 'cert': 'webcertq',
                          'places': [{'host': '127.0.0.1', 'port': 8443, 'state': 'ok',
                                      'names': ['webnameq.example.test']}]}}


class Served(unittest.TestCase):
    def setUp(self):
        self.oc, self.wc, self.tid = V.setup()
        self.odid = STORE.db.value('SELECT id FROM cert_deploys WHERE cert_id = ?', (self.oc,), 0)
        self.wdid = STORE.db.value('SELECT id FROM cert_deploys WHERE cert_id = ?', (self.wc,), 0)
        STORE.set_meta('agents:served:%d' % self.tid, json.dumps(served(self.odid, self.wdid)))

    def tearDown(self):
        STORE.db.run("DELETE FROM meta WHERE k = ?", ('agents:served:%d' % self.tid,))
        E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)

    def answers(self, role):
        out = {}
        for path in ('/api/agents', '/api/agents/one', '/api/agents/builder', '/api/agents/guard'):
            out[path] = call('GET', path, who='mgr', role=role, args={'id': str(self.tid)})
        out['look'] = call('POST', '/api/agents/look', {'id': self.tid}, who='mgr', role='certadmin')
        return out

    def test_unscoped_sees_all(self):
        for path, got in self.answers('certadmin').items():
            text = json.dumps(got, default=str)
            self.assertIn('opscertq', text, path)
        g = call('GET', '/api/agents/guard', who='mgr', role='readonly', args={'id': str(self.tid)})
        item = [i for i in g['guard']['served']['items'] if i['deploy_id'] == self.odid][0]
        self.assertEqual(item['places'][0]['names'], ['opsnameq.example.test'])

    def test_scoped_sees_own_only(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        for role in ('readonly', 'certadmin'):
            for path, got in self.answers(role).items():
                text = json.dumps(got, default=str)
                self.assertNotIn('opscertq', text, (role, path))
                self.assertNotIn('opsnameq', text, (role, path))
                self.assertIn('webcertq', text, (role, path))
        g = call('GET', '/api/agents/guard', who='mgr', role='readonly',
                 args={'id': str(self.tid)})['guard']['served']
        by = {i['deploy_id']: i for i in g['items']}
        self.assertEqual(by[self.odid], {'deploy_id': self.odid, 'at': 1, 'state': 'old',
                                         'cert': A.OTHERS_CERT})
        self.assertEqual(by[self.wdid]['places'][0]['names'], ['webnameq.example.test'])
        self.assertEqual(g['old'], 1)
        one = call('GET', '/api/agents/one', who='mgr', role='readonly', args={'id': str(self.tid)})
        self.assertEqual(sorted(i['cert'] for i in one['guard']['served']['items']),
                         [A.OTHERS_CERT, 'webcertq'])
        look = call('POST', '/api/agents/look', {'id': self.tid}, who='mgr', role='certadmin')
        self.assertEqual(look['agent']['keys_of'], [])

    def test_portal_device(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        row = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (self.tid,))
        me = AA._Seer(STORE, {'name': 'mgr', 'role': 'certadmin',
                              'account': {'name': 'mgr', 'role': 'certadmin', 'source': 'local'}})
        self.assertFalse(me.all)
        out = PT._others_hidden(me, PT.device_public(STORE, row, agent=True))
        text = json.dumps(out, default=str)
        self.assertNotIn('opscertq', text)
        self.assertIn('webcertq', text)


class ViewAsDiscover(unittest.TestCase):
    def setUp(self):
        self.oc, self.wc, self.tid = V.setup()

    def run_as(self, h):
        try:
            return 200, E.ROUTES[('GET', '/api/agents/discover')](h)
        except E.ApiError as e:
            return e.status, str(e)
        except Exception as e:                          # noqa: BLE001
            return 500, str(e)

    def test_refused_while_viewing_as(self):
        n0 = STORE.db.value('SELECT MAX(id) FROM events', (), 0) or 0
        st, said = self.run_as(ViewAsH(who='mgr', role='certadmin',
                                       args={'target': 'opstgtq'}))
        self.assertEqual(st, 403)
        self.assertIn('read-only: you are viewing the pages as mgr', said)
        ev = STORE.db.rows('SELECT * FROM events WHERE id > ?', (n0,))
        self.assertEqual([e['who'] for e in ev], ['boss'])
        self.assertIn('boss, viewing the pages as mgr (read-only), was refused', ev[0]['words'])
        # the discovery kept is still shown
        st, got = self.run_as(ViewAsH(who='mgr', role='certadmin',
                                      args={'target': 'opstgtq', 'cached': '1'}))
        self.assertEqual(st, 200)
        self.assertEqual(got['target'], 'opstgtq')

    def test_not_viewing_as_unchanged(self):
        st, said = self.run_as(V.H(who='mgr', role='certadmin', args={'target': 'opstgtq'}))
        self.assertNotIn('read-only', str(said))


if __name__ == '__main__':
    unittest.main()
