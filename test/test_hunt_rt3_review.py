#!/usr/bin/env python3
"""Hunt R run t3, area review: the fixes of the hunt rounds t1 and t2 looked at again.

    python3 test/test_hunt_rt3_review.py

- a team whose parent team is gone: saved with the parent it has (as the administration's page
  sends every save of its members, its note) it was still refused "there is no team ... to put it
  under" - the t1 fix took only a save without `parent`. Now kept at the top level too; a gone
  team named as a new parent is still refused.
- the portal's discovery of a team's agent (GET /api/portal/agent_discover, and the policy
  builder's "From discovery") named the certificate acme holds that was found on the server -
  acme's own or another team's - with its id, where the device and the builder (t2) say
  "another owner's certificate". Now said so; the team's own certificate named as before, and
  the administration's view unchanged.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_teams_enterprise as TE  # noqa: E402  (its database, its helpers)

T, E, A, STORE = TE.T, TE.E, TE.A, TE.STORE
from acmelib.certs import agent_discover as AD  # noqa: E402
from acmelib.certs import portal_teams as PT  # noqa: E402,F401  (the portal's team routes)

OTHERS = "another owner's certificate"


class ParentGone(unittest.TestCase):
    def setUp(self):
        TE.clean()

    def test_saved_with_the_parent_it_has(self):
        T.save_team(STORE, {'name': 'P'}, 'x')
        T.save_team(STORE, {'name': 'Q'}, 'x')
        T.save_team(STORE, {'name': 'K', 'parent': 'P', 'note': 'n'}, 'x')
        STORE.db.run("DELETE FROM cert_teams WHERE name IN ('P', 'Q')")
        T.changed()
        listed = [t for t in T.teams(STORE) if t['name'] == 'K'][0]
        self.assertEqual(listed['parent'], 'P')
        # as web/assets/teams.js saveTeam() sends it: the parent it has, in any case
        with self.assertRaises(LookupError):
            T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'parent': 'Q'}, 'x')
        got = T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'kind': 'team', 'parent': 'p',
                                  'note': 'kept', 'members': ['local:eva=manage']}, 'x')
        self.assertEqual((got['note'], got['parent']), ('kept', None))
        # at the top now: a gone team named is a move, refused
        with self.assertRaises(LookupError):
            T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'parent': 'P'}, 'x')
        # an existing parent as before
        T.save_team(STORE, {'name': 'P'}, 'x')
        self.assertEqual(T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'parent': 'P'},
                                     'x')['parent'], 'P')


class DiscoveryNames(unittest.TestCase):
    def setUp(self):
        TE.clean()
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'agents:%'")
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:eva', 'roles': ['Viewer']}]}, 'x')
        T.save_team(STORE, {'name': 'Other'}, 'x')
        self.ids = {}
        for n, owner in (('rt3-web', 'Web'), ('rt3-other', 'Other'), ('rt3-acme', '')):
            got = TE.cert(n, owner)
            self.ids[n] = got['id'] if isinstance(got, dict) else int(got)
        tid = A.family_save(STORE, 'target', {'name': 'rt3-agent', 'kind': 'agent',
                                              'owner': 'Web', 'config': {
                                                  'mode': 'passive', 'host': 'a.example.test'}},
                            'x')
        self.row = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (tid,))
        found = [{'kind': 'nginx', 'config': '/etc/nginx/nginx.conf', 'names': [],
                  'files': [], 'cert': {'thumbprint': 'T-' + n}} for n in self.ids]
        AD._keep(STORE, self.row, {'platform': 'linux', 'found': found,
                                   'certs': [{'thumbprint': 'T-' + n} for n in self.ids]}, 'x')
        self.mm = AD.managed_map
        AD.managed_map = lambda store: {'T-' + n: {'id': i, 'name': n, 'current': True}
                                        for n, i in self.ids.items()}

    def tearDown(self):
        AD.managed_map = self.mm

    def portal(self, path):
        s = TE.person('eva')
        return E.ROUTES[('GET', '/api/portal/' + path)](TE.FakeH(portal=s, args={
            'id': self.row['id'], 'cached': 1}))

    def names(self, v):
        out = [f['cert']['managed'] for f in v['found']] + [c['managed'] for c in v['certs']]
        return sorted((m['name'], m['id']) for m in out)

    def test_portal_says_another_owner(self):
        want = sorted([(OTHERS, None)] * 4 + [('rt3-web', self.ids['rt3-web'])] * 2)
        got = self.portal('agent_discover')
        self.assertEqual(self.names(got['discovery']), want)
        got = self.portal('agent_builder')
        self.assertEqual(self.names(got['discovered']), want)
        # the administration's view: every name, as before
        v = AD.cached(STORE, self.row)
        self.assertEqual(sorted(n for n, _i in self.names(v)),
                         sorted(['rt3-acme', 'rt3-other', 'rt3-web'] * 2))


if __name__ == '__main__':
    unittest.main(verbosity=2)
