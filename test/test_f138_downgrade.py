"""Going back below 1.0.138 while base profiles or team governance are in use (1.0.138).

    python3 test/test_f138_downgrade.py
"""
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-f138-down-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())


class NewUse(unittest.TestCase):
    def setUp(self):
        STORE.db.query('DELETE FROM cert_req_profiles')
        STORE.db.query('DELETE FROM cert_teams')

    def add_profile(self, name, cfg):
        STORE.db.insert('cert_req_profiles', {'name': name, 'description': '', 'enabled': 1,
                                              'config': json.dumps(cfg), 'created': time.time()})

    def add_team(self, name, extras):
        STORE.db.insert('cert_teams', {'name': name, 'kind': 'team',
                                       'extras': json.dumps(extras) if extras else None})

    def test_nothing_in_use(self):
        self.add_profile('plain', {'issuer': 'x'})
        self.add_team('ops', None)
        self.assertEqual(E.downgrade_new_use(STORE, '1.0.137'), [])

    def test_based_profile_and_governance(self):
        self.add_profile('base', {'issuer': 'x'})
        self.add_profile('child', {'base': 'base', 'inherit': ['source']})
        self.add_team('ops', {'sod': {'no_self_approval': True}})
        got = E.downgrade_new_use(STORE, '1.0.137')
        self.assertEqual(len(got), 2)
        self.assertIn('child', got[0])
        self.assertIn('ops', got[1])
        self.assertEqual(E.downgrade_new_use(STORE, '1.0.138'), [])
        self.assertTrue(any('base profile' in w for w in E.downgrade_why_not(STORE, '1.0.137')))



    def test_agents_on_an_earlier_command_key(self):
        from acmelib.certs import agent_guard
        self.assertEqual(agent_guard.on_old_cmdkey(STORE), [])     # never changed: none
        old = agent_guard.on_old_cmdkey
        agent_guard.on_old_cmdkey = lambda store: ['web1']
        try:
            got = E.downgrade_new_use(STORE, '1.0.137')
            self.assertEqual(len(got), 1)
            self.assertIn('web1', got[0])
            self.assertEqual(E.downgrade_new_use(STORE, '1.0.138'), [])
        finally:
            agent_guard.on_old_cmdkey = old

if __name__ == '__main__':
    unittest.main()
