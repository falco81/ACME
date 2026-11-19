#!/usr/bin/env python3
"""Hunt R u1 - the team limits and capabilities of 1.0.128 (docs/teams.md "Limits").

    python3 test/test_hunt_ru1_teamlimits.py

- a scoped certificate administrator making a certificate without a source or a validation:
  the default source and the default validation it is given are checked against `issuers`,
  `validations` and `pairs` (they went through by not being sent);
- a team's test through a connector: checked as the run finds it (a connector of the tests
  first) - a device of the team named as acme's own connector of the tests let the test go
  through acme's own connector.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_team_limits_more as M  # noqa: E402  (its database, its helpers)

A, S, STORE = M.A, M.S, M.STORE


def le_issuer():
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'le'"):
        STORE.db.insert('cert_issuers', {'name': 'le', 'kind': 'acme', 'enabled': 1,
                                         'config': '{"directory": "https://acme.invalid/d"}'})


class ScopedAdminDefaults(unittest.TestCase):
    def setUp(self):
        M.clean()
        M.E.CONFIG.update(certs_certadmin_all=0)
        M.tree()
        le_issuer()
        self.meta = {k: STORE.get_meta(k) for k in ('certs:default_challenge',
                                                    'certs:default_issuer')}
        STORE.set_meta('certs:default_challenge', 'dnsB')

    def tearDown(self):
        for k, v in self.meta.items():
            STORE.set_meta(k, v if v is not None else '')
        M.E.CONFIG.update(certs_certadmin_all=1)

    def save(self, b):
        return M.outcome(M.admin, 'POST', '/api/certs/save', b, who='mgr', role='certadmin')

    def row(self, name):
        return STORE.db.row('SELECT issuer, challenge FROM certs WHERE name = ?', (name,))

    def test_default_validation_of_the_source_sent(self):
        new = {'names': ['x.example.com'], 'issuer': 'le', 'owner': 'Web', 'hold': 1}
        M.setp('Web', {'pairs': {'le': ['dnsA']}})
        st, words = self.save(dict(new, name='d1'))
        self.assertEqual(st, 403, words)
        self.assertIn('proved by dnsA only - not dnsB', words)
        self.assertIsNone(self.row('d1'))
        M.setp('Web', {'validations': ['dnsA']})
        st, words = self.save(dict(new, name='d2'))
        self.assertEqual(st, 403, words)
        self.assertIn('the validation dnsB', words)
        # said: what is said is checked, as before
        self.assertEqual(self.save(dict(new, name='d3', challenge='dnsA'))[0], 200)
        M.setp('Web', {'pairs': {'le': ['dnsB']}, 'validations': ['dnsB']})
        self.assertEqual(self.save(dict(new, name='d4'))[0], 200)
        self.assertEqual(self.row('d4')['challenge'], 'dnsB')

    def test_default_source(self):
        STORE.set_meta('certs:default_issuer', 'other')
        M.setp('Web', {'issuers': ['self']})
        st, words = self.save({'names': ['z.example.test'], 'owner': 'Web', 'hold': 1,
                               'name': 'd5'})
        self.assertEqual(st, 403, words)
        self.assertIn('the source other', words)
        self.assertIsNone(self.row('d5'))
        self.assertEqual(self.save({'names': ['z.example.test'], 'owner': 'Web', 'hold': 1,
                                    'name': 'd6', 'issuer': 'self'})[0], 200)
        # a team without limits: as before
        M.setp('Web', {})
        self.assertEqual(self.save({'names': ['z2.example.test'], 'owner': 'Web', 'hold': 1,
                                    'name': 'd7'})[0], 200)
        self.assertEqual(self.row('d7')['issuer'], 'other')


class TestConnectorOrder(unittest.TestCase):
    def setUp(self):
        M.clean()
        M.tree(members=[{'who': 'local:dm', 'roles': ['Device manager']}])

    def test_named_as_acmes_connector_of_the_tests(self):
        # acme's own connector of the tests, and a device of the team of the same name
        A.family_save(STORE, 'check', {'name': 'relay1', 'kind': 'ssh_relay',
                                       'config': {'host': 'r.example.test', 'user': 'u'}},
                      'test')
        STORE.db.insert('cert_targets', {'name': 'relay1', 'kind': 'ssh_connector',
                                         'owner': 'Web', 'config': '{}', 'state': '{}',
                                         'enabled': 1})
        st, words = M.outcome(M.portal, 'dm', 'POST', 'test_save', {
            'team': 'Web', 'name': 'via-1', 'kind': 'https',
            'config': {'host': 'x.example.test', 'via': 'relay1'}})
        self.assertEqual(st, 403, words)
        self.assertIn('not a connector of the team Web', words)
        # the team's own connector of the tests, named as another's device: taken
        M.T.save_team(STORE, {'name': 'Other', 'members': []}, 'x')
        M.portal('dm', 'POST', 'test_save', {'team': 'Web', 'name': 'relay2',
                                             'kind': 'ssh_relay',
                                             'config': {'host': 'r2.example.test',
                                                        'user': 'u'}})
        STORE.db.insert('cert_targets', {'name': 'relay2', 'kind': 'ssh_connector',
                                         'owner': 'Other', 'config': '{}', 'state': '{}',
                                         'enabled': 1})
        st, words = M.outcome(M.portal, 'dm', 'POST', 'test_save', {
            'team': 'Web', 'name': 'via-2', 'kind': 'https',
            'config': {'host': 'x.example.test', 'via': 'relay2'}})
        self.assertEqual(st, 200, words)


class FreeFormSources(unittest.TestCase):
    def setUp(self):
        M.clean()
        M.tree()

    def tearDown(self):
        M.E.CONFIG.update(portal_cert_challenge='')

    def limits(self):
        return M.portal('eva', 'GET', '/api/portal/certs')['team_limits']

    def test_none_where_every_one_is_refused(self):
        M.E.CONFIG.update(portal_cert_challenge='dnsA')
        M.setp('Web', {'validations': ['dnsB']})
        self.assertEqual(self.limits()['Web']['issuers'], [])
        st, words = M.outcome(M.portal, 'eva', 'POST', 'cert_request', {
            'names': ['f1.example.test'], 'issuer': 'self', 'team': 'Web'})
        self.assertEqual(st, 403, words)
        M.setp('Web', {'validations': ['dnsA']})
        self.assertEqual(sorted(self.limits()['Web']['issuers']), ['other', 'self'])
        M.setp('Web', {'free_form': False})
        self.assertEqual(self.limits()['Web']['issuers'], [])
        # what narrows nothing: as before
        M.setp('Web', {'issuers': ['self']})
        self.assertEqual(self.limits()['Web']['issuers'], ['self'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
