#!/usr/bin/env python3
"""Hunt Rt1 - the enterprise teams backend (acmelib/certs/teams.py, teampolicy.py).

    python3 test/test_hunt_rt1_teams.py

- a team merely below a hand-written circle keeps its parent (only a team of the circle is cut);
- a team whose parent is gone is still saved (kept at the top level, as the tree shows it);
- a certificate a scoped administrator gives to another team is checked against that team's
  limits as it is (its names, its source) - not only against what the body changed;
- a source, a validation or a request profile renamed: the teams' limits naming it follow.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_teams_enterprise as TE  # noqa: E402  (its database, its helpers)

T, TP, E, STORE = TE.T, TE.TP, TE.E, TE.STORE


class Tree(unittest.TestCase):
    def setUp(self):
        TE.clean()

    def test_below_a_circle_keeps_its_parent(self):
        for n in ('A', 'B', 'C'):
            T.save_team(STORE, {'name': n}, 'x')
        STORE.db.run("UPDATE cert_teams SET parent = 'B' WHERE name = 'A'")
        STORE.db.run("UPDATE cert_teams SET parent = 'C' WHERE name = 'B'")
        STORE.db.run("UPDATE cert_teams SET parent = 'B' WHERE name = 'C'")
        T.changed()
        tr = T.tree(STORE)
        self.assertEqual(tr.parent['a'], 'b')           # not in the circle: kept
        self.assertEqual(sorted(k for k in ('b', 'c') if tr.parent[k] is None), ['b'])
        self.assertEqual(sorted(tr.order), ['a', 'b', 'c'])

    def test_parent_gone_still_saved(self):
        T.save_team(STORE, {'name': 'P'}, 'x')
        T.save_team(STORE, {'name': 'K', 'parent': 'P'}, 'x')
        STORE.db.run("DELETE FROM cert_teams WHERE name = 'P'")
        T.changed()
        got = T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'note': 'kept'}, 'x')
        self.assertEqual((got['note'], got['parent']), ('kept', None))
        # a parent named in the body is still checked
        with self.assertRaises(LookupError):
            T.save_team(STORE, {'old_name': 'K', 'name': 'K', 'parent': 'P'}, 'x')


class MovedIntoLimits(unittest.TestCase):
    def setUp(self):
        TE.clean()
        T.save_team(STORE, {'name': 'Free', 'members': ['local:eva=manage']}, 'x')
        T.save_team(STORE, {'name': 'Tight', 'members': ['local:eva=manage'],
                            'policy': {'suffixes': ['inner.test'], 'issuers': ['other']}}, 'x')
        E.CONFIG.update(certs_certadmin_all=0)

    def tearDown(self):
        E.CONFIG.update(certs_certadmin_all=1)

    def test_moved_cert_checked_as_it_is(self):
        TE.cert('wide', 'Free')
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'wide'")
        # its names (wide.example.test) and its source (self) are not the team's
        self.assertEqual(TE.may('POST', '/api/certs/save', {'id': row['id'], 'owner': 'Tight'},
                                who='eva', role='certadmin'), 403)
        self.assertEqual(STORE.db.value("SELECT owner FROM certs WHERE name = 'wide'"), 'Free')
        # within them it moves
        T.save_team(STORE, {'old_name': 'Tight', 'name': 'Tight', 'policy': {
            'suffixes': ['example.test'], 'issuers': ['self']}}, 'x')
        self.assertEqual(TE.may('POST', '/api/certs/save', {'id': row['id'], 'owner': 'Tight'},
                                who='eva', role='certadmin'), 200)
        # a change within the same team is checked as before (only what the body says)
        T.save_team(STORE, {'old_name': 'Tight', 'name': 'Tight', 'policy': {
            'suffixes': ['inner.test']}}, 'x')
        self.assertEqual(TE.may('POST', '/api/certs/save', {'id': row['id'], 'note': 'n'},
                                who='eva', role='certadmin'), 200)


class RenamesFollow(unittest.TestCase):
    def setUp(self):
        TE.clean()

    def test_source_validation_profile_renamed(self):
        from acmelib.certs import reqprofiles as RP
        T.save_team(STORE, {'name': 'Iss', 'policy': {
            'issuers': ['other', 'self'], 'validations': ['dns1'], 'profiles': ['Web', 'Mail'],
            'approval': {'mode': 'outside', 'outside': {'profiles': ['Web']}}}}, 'x')
        T.save_team(STORE, {'name': 'Plain'}, 'x')
        RP.rename_source(STORE, 'issuer', 'other', 'other2')
        RP.rename_source(STORE, 'challenge', 'DNS1', 'dns-new')
        RP.asked_follow(STORE, 'web', 'Web2')
        p = T.policy_of(T.team_get(STORE, 'Iss'))
        self.assertEqual(p['issuers'], ['other2', 'self'])
        self.assertEqual(p['validations'], ['dns-new'])
        self.assertEqual(p['profiles'], ['Web2', 'Mail'])
        self.assertEqual(p['approval']['outside']['profiles'], ['Web2'])
        self.assertIsNone(T.team_get(STORE, 'Plain')['policy'])       # as before: NULL
        # the team may now ask from the renamed source
        TP.need_request(STORE, 'Iss', 'x', profile='', issuer='other2', validation='dns-new')
        self.assertEqual(T.effective_policy(STORE, 'Iss')['issuers'], ['other2', 'self'])


if __name__ == '__main__':
    unittest.main()
