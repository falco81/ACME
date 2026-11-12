#!/usr/bin/env python3
"""1.0.83: a module in use is not deleted - where it is used is said, and "take it off
everywhere first" takes a deployment or an attached test off before it goes; one look and
order of the popup buttons in every page.

    python3 test/test_hunt_i.py
"""
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-i-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


def cert(name, **kw):
    row = {'name': name, 'cn': name, 'names': json.dumps([name]), 'state': 'valid',
           'issuer': kw.get('issuer', ''), 'challenge': kw.get('challenge', '')}
    return STORE.db.insert('certs', row)


class InUse(unittest.TestCase):
    def test_target_with_a_deployment(self):
        tid = STORE.db.insert('cert_targets', {'name': 'lb-i', 'kind': 'local', 'config': '{}',
                                               'enabled': 1})
        cid = cert('web-i.example.test')
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'lb-i'})
        row = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (tid,))
        uses = A.family_uses(STORE, 'target', row)
        self.assertEqual([(u['name'], u['free']) for u in uses], [('web-i.example.test', True)])
        with self.assertRaises(ValueError) as e:
            A.family_delete(STORE, 'target', {'id': tid}, 'tester')
        self.assertIn('certificate web-i.example.test', str(e.exception))
        self.assertIn('take it off everywhere first', str(e.exception))
        A.family_delete(STORE, 'target', {'id': tid, 'force': 1}, 'tester')
        self.assertFalse(STORE.db.row('SELECT id FROM cert_targets WHERE id = ?', (tid,)))
        self.assertFalse(STORE.db.row("SELECT id FROM cert_deploys WHERE target = 'lb-i'"))
        self.assertTrue(STORE.db.row('SELECT id FROM certs WHERE id = ?', (cid,)))

    def test_test_attached_and_in_a_set(self):
        kid = STORE.db.insert('cert_tests', {'name': 'tls-i', 'kind': 'tls', 'config': '{}',
                                             'enabled': 1})
        STORE.db.insert('cert_tests', {'name': 'relay-i', 'kind': 'ssh_relay', 'enabled': 1,
                                       'config': json.dumps({'tests': ['tls-i', 'other']})})
        cid = cert('app-i.example.test')
        STORE.db.insert('cert_checks', {'cert_id': cid, 'test': 'tls-i'})
        row = STORE.db.row('SELECT * FROM cert_tests WHERE id = ?', (kid,))
        self.assertEqual(sorted(u['where'] for u in A.family_uses(STORE, 'check', row)),
                         ['certificate', 'test'])
        A.family_delete(STORE, 'check', {'id': kid, 'force': True}, 'tester')
        self.assertFalse(STORE.db.row("SELECT id FROM cert_checks WHERE test = 'tls-i'"))
        relay = STORE.db.row("SELECT config FROM cert_tests WHERE name = 'relay-i'")
        self.assertEqual(json.loads(relay['config'])['tests'], ['other'])

    def test_issuer_of_a_certificate_not_taken_off(self):
        iid = STORE.db.insert('cert_issuers', {'name': 'ca-i', 'kind': 'selfsigned',
                                               'config': '{}', 'enabled': 1})
        cert('held-i.example.test', issuer='ca-i')
        with self.assertRaises(ValueError) as e:
            A.family_delete(STORE, 'issuer', {'id': iid, 'force': 1}, 'tester')
        self.assertIn('change those first', str(e.exception))
        self.assertTrue(STORE.db.row('SELECT id FROM cert_issuers WHERE id = ?', (iid,)))


class WhatHappens(unittest.TestCase):
    def test_how_a_test_runs_for_the_certificate(self):
        from acmelib.certs import runplan
        STORE.db.insert('cert_tests', {'name': 'tls-plan', 'kind': 'tls', 'config': '{}',
                                       'enabled': 1})
        cid = cert('plan-i.example.test')
        STORE.db.insert('cert_checks', {'cert_id': cid, 'test': 'tls-plan',
                                        'after_target': 'lb-a\nlb-b'})
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        words = json.dumps(runplan.checks_phase(STORE, row, ['plan-i.example.test']))
        self.assertIn('Runs only after a deployment on lb-a, lb-b', words)
        self.assertIn('that deployment fails', words)
        after = json.dumps(runplan.after_phase(STORE, dict(row, auto_renew=1), None, []))
        self.assertIn('at most every', after)


class FakeJob(object):
    kind = 'deploy'
    version = None

    def __init__(self):
        self.said = []

    def step(self, words, level='info'):
        self.said.append(words)

    def check(self):
        pass


class DeployHold(unittest.TestCase):
    def test_new_version_waits_for_deploy_now(self):
        from acmelib.certs import deployer, store as S
        cid = cert('hold-i.example.test')
        STORE.db.update('certs', cid, {'version': 1, 'cert_pem': 'x'})
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'nowhere-i'})
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        S.deploy_hold_set(STORE, row, True, 'tester')
        self.assertFalse(S.deploy_held(STORE, row))         # the version in use: not held
        STORE.db.update('certs', cid, {'version': 2})       # issued from the new source
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        self.assertTrue(S.deploy_held(STORE, row))
        S.deploy_hold_set(STORE, row, True, 'again')       # held again: v2 still waits
        self.assertTrue(S.deploy_held(STORE, row))
        job = FakeJob()
        ok, said = deployer.run_deploys(STORE, job, cid)
        self.assertTrue(ok)
        self.assertIn('waits for Deploy now', said)
        self.assertFalse(STORE.db.row("SELECT last_try FROM cert_deploys WHERE cert_id = ?",
                                      (cid,))['last_try'])
        # a person deploying it lets it go
        deployer.run_deploys(STORE, FakeJob(), cid, force=True)
        self.assertIsNone(S.deploy_hold(STORE, cid))


class Carry(unittest.TestCase):
    def test_hold_goes_with_the_certificate_in_the_file(self):
        import collections
        from acmelib.certs import store as S
        cid = cert('carry-i.example.test')
        STORE.db.update('certs', cid, {'version': 3, 'cert_pem': 'x'})
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        S.deploy_hold_set(STORE, row, True, 'tester')
        tables = E.carry_export(STORE, False)
        mine = [r for r in tables['certs'] if r['id'] == cid][0]
        self.assertIn('hold', mine.get('_meta') or {})
        S.deploy_hold_set(STORE, row, False)
        E.carry_import(STORE, {'certs': [mine]}, 'tester', False, collections.Counter())
        self.assertIsNotNone(S.deploy_hold(STORE, cid))


class Buttons(unittest.TestCase):
    def test_one_order_in_every_popup(self):
        with open(os.path.join(ROOT, 'web/assets/core.js')) as f:
            src = f.read()
        self.assertIn('var DANGER_WORDS', src)
        self.assertIn('var ACTION_WORDS', src)
        self.assertTrue(re.search(r'lefts\.concat\(closes, mids, mains\)', src))


if __name__ == '__main__':
    unittest.main(verbosity=2)
