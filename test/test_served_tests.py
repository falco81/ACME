#!/usr/bin/env python3
"""What a target serves is checked by tests attached to the certificate only (1.0.92) - and a
target whose module checked its own address until then gets that as a test (1.0.93): with a
new deployment, and once for the deployments already there; the tests after a deployment on a
target that restarts for long (vCenter, a BMC) wait as long as the module did.

    python3 test/test_served_tests.py
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix='acme-served-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A, checks as C, store as S  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def tests_of(cid):
    out = {}
    for r in STORE.db.rows('SELECT c.test, c.after_target, t.config FROM cert_checks c '
                           'JOIN cert_tests t ON t.name = c.test WHERE c.cert_id = ?', (cid,)):
        cfg = json.loads(r['config'] or '{}')
        out[(cfg.get('host'), int(cfg.get('port') or 0))] = r['after_target']
    return out


class Served(unittest.TestCase):
    def test_1_a_new_deployment_gets_its_test(self):
        A.family_save(STORE, 'target', {'kind': 'esxi', 'name': 'esx1', 'config': {
            'host': 'esx1.example.test', 'user': 'root', 'password': 'x'}}, 'tester')
        A.family_save(STORE, 'target', {'kind': 'vcenter', 'name': 'vc1', 'config': {
            'host': 'vc1.example.test', 'user': 'a', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['esx1.example.test', 'vc1.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'esx1', 'options': {}}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'vc1', 'options': {}}, 'tester')
        got = tests_of(cid)
        self.assertEqual(got.get(('esx1.example.test', 443)), 'esx1')
        self.assertEqual(got.get(('vc1.example.test', 443)), 'vc1')
        # saved again: no second one
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ? AND target = ?',
                           (cid, 'esx1'))
        A.deploy_save(STORE, {'id': dep['id'], 'cert_id': cid, 'target': 'esx1',
                              'options': {}}, 'tester')
        self.assertEqual(len(tests_of(cid)), 2)
        # vCenter restarts for minutes: its tests wait as its module did (20 x 15 s)
        chk = STORE.db.row("SELECT * FROM cert_checks WHERE cert_id = ? AND after_target = 'vc1'",
                           (cid,))
        waits = C._tries_for(STORE, chk, {'vc1'})
        self.assertEqual(len(waits), 20)
        self.assertEqual(waits[1], 15)
        self.assertEqual(C._tries_for(STORE, {'after_target': 'x'}, {'x'}), C.AFTER_DEPLOY_TRIES)

    def test_2_once_for_those_there_before(self):
        A.family_save(STORE, 'target', {'kind': 'fritzbox', 'name': 'fb', 'config': {
            'host': 'fritz.example.test', 'user': 'u', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['fritz.example.test']}, 'tester')
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'fb', 'options': '{}',
                                         'enabled': 1, 'state': 'new'})
        self.assertEqual(tests_of(cid), {})
        self.assertGreaterEqual(C.served_migrate(STORE), 1)
        self.assertEqual(tests_of(cid).get(('fritz.example.test', 443)), 'fb')

    def test_3_a_target_without_an_address_of_its_own(self):
        A.family_save(STORE, 'target', {'kind': 'local', 'name': 'files', 'config': {
            'base': os.path.join(TMP, 'out')}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['files.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'files', 'options': {}}, 'tester')
        self.assertEqual(tests_of(cid), {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
