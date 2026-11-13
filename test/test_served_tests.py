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


def new_deployment(cid, target, options=None):
    """A deployment of a device-key target (its certificate needs a CA signing its CSR - not
    the point here): put in as it is, its tests made as deploy_save makes them."""
    STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': target,
                                     'options': json.dumps(options or {}), 'enabled': 1,
                                     'state': 'new'})
    dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ? AND target = ?',
                       (cid, target))
    return C.served_tests(STORE, dep, 'tester')


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

    def test_4_the_key_asked_for_and_the_first_name(self):
        # 1.0.96: a served place may say the key the test asks for (CUCM's Tomcat serves
        # tomcat and tomcat-ECDSA on 8443) and the host CERT_NAME (the certificate's first
        # name); a module that says neither is tested as before
        for name, unit in (('cu1', 'tomcat'), ('cu2', 'tomcat-ECDSA')):
            A.family_save(STORE, 'target', {'kind': 'cucm', 'name': name, 'config': {
                'host': 'cucm.example.test', 'user': 'svc', 'auth': 'password',
                'password': 'x', 'unit': unit}}, 'tester')
        got, names = {}, set()
        for name, kt in (('cu1', 'rsa-2048'), ('cu2', 'ec-256')):
            cid = A.cert_save(STORE, {'names': ['cucm.example.test'], 'key_type': kt},
                              'tester')
            new_deployment(cid, name)
            rows = STORE.db.rows('SELECT c.test, c.after_target, t.config FROM cert_checks c '
                                 'JOIN cert_tests t ON t.name = c.test WHERE c.cert_id = ?',
                                 (cid,))
            got.update({r['after_target']: json.loads(r['config']) for r in rows})
            names.update(r['test'] for r in rows)
        self.assertEqual(got['cu1'], {'port': 8443, 'host': 'cucm.example.test',
                                      'key_want': 'rsa'})
        self.assertEqual(got['cu2'], {'port': 8443, 'host': 'cucm.example.test',
                                      'key_want': 'ecdsa'})
        self.assertEqual(len(names), 2, 'one test each: the key is part of what a test is')
        cid = STORE.db.row("SELECT cert_id FROM cert_deploys WHERE target = 'cu1'")['cert_id']
        # the same place with no key asked for is another test (older tests stay as they are)
        n = C.for_target(STORE, cid, 'cu1', 'tester', 'tls', 'cucm.example.test', 8443)
        self.assertNotIn(n, names)
        with self.assertRaises(ValueError):
            C.for_target(STORE, cid, 'cu1', 'tester', 'tls', 'cucm.example.test', 8443,
                         key_want='dsa')
        # VCF without Component FQDN: deployed for the certificate's first name, tested there
        A.family_save(STORE, 'target', {'kind': 'vcf_component', 'name': 'vcf1', 'config': {
            'host': 'sddc.example.test', 'user': 'u', 'password': 'x', 'csr_country': 'CZ',
            'csr_state': 'P', 'csr_city': 'P', 'csr_org': 'O', 'csr_ou': 'IT'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['vc9.example.test']}, 'tester')
        new_deployment(cid, 'vcf1')
        self.assertEqual(tests_of(cid), {(None, 443): 'vcf1'})
        # vSphere Supervisor: its API endpoint, not for the NSX ingress
        A.family_save(STORE, 'target', {'kind': 'vsphere_supervisor', 'name': 'sup1', 'config': {
            'host': 'vc.example.test', 'user': 'u', 'password': 'x', 'supervisor': 'domain-c8',
            'endpoint_host': 'sup.example.test'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['ingress.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'sup1', 'options': {
            'endpoint': 'DEFAULT_NSX_INGRESS'}}, 'tester')
        self.assertEqual(tests_of(cid), {})

    def test_5_options_changed_the_tests_follow(self):
        # 1.0.96: a Supervisor deployment switched to the NSX ingress kept the test of the API
        # endpoint (failing every deployment after) - the tests acme made follow where the
        # target serves the certificate; switched back, the test comes again
        A.family_save(STORE, 'target', {'kind': 'vsphere_supervisor', 'name': 'sup5', 'config': {
            'host': 'vc.example.test', 'user': 'u', 'password': 'x', 'supervisor': 'domain-c8',
            'endpoint_host': 'sup5.example.test'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['sup5.example.test']}, 'tester')
        did = A.deploy_save(STORE, {'cert_id': cid, 'target': 'sup5', 'options': {
            'endpoint': 'KUBERNETES_API_SERVER'}}, 'tester')
        self.assertEqual(tests_of(cid), {('sup5.example.test', 443): 'sup5'})
        made = STORE.db.value('SELECT test FROM cert_checks WHERE cert_id = ?', (cid,))
        # a test of a person's, attached after the same deployment: stays
        A.family_save(STORE, 'check', {'kind': 'tls', 'name': 'mine5', 'config': {
            'host': 'other.example.test', 'port': 443}}, 'tester')
        C.attach(STORE, cid, ['mine5'], 'tester', after_target='sup5')
        A.deploy_save(STORE, {'id': did, 'cert_id': cid, 'target': 'sup5', 'options': {
            'endpoint': 'DEFAULT_NSX_INGRESS'}}, 'tester')
        self.assertEqual(tests_of(cid), {('other.example.test', 443): 'sup5'})
        self.assertIsNone(S.plugin_row(STORE, 'check', made), 'attached to nothing: deleted')
        ev = [r['words'] for r in STORE.db.rows('SELECT words FROM events WHERE words LIKE ?',
                                                ('%' + made + '%',))]
        self.assertEqual(len([w for w in ev if 'deleted' in w]), 1, ev)
        self.assertIn('serves the certificate elsewhere now', [w for w in ev if 'deleted' in w][0])
        A.deploy_save(STORE, {'id': did, 'cert_id': cid, 'target': 'sup5', 'options': {
            'endpoint': 'KUBERNETES_API_SERVER'}}, 'tester')
        self.assertEqual(tests_of(cid).get(('sup5.example.test', 443)), 'sup5')

    def test_6_a_test_shared_with_another_certificate_stays(self):
        A.family_save(STORE, 'target', {'kind': 'vsphere_supervisor', 'name': 'sup6', 'config': {
            'host': 'vc.example.test', 'user': 'u', 'password': 'x', 'supervisor': 'domain-c8',
            'endpoint_host': 'sup6.example.test'}}, 'tester')
        one = A.cert_save(STORE, {'names': ['a6.example.test']}, 'tester')
        two = A.cert_save(STORE, {'names': ['b6.example.test']}, 'tester')
        d1 = A.deploy_save(STORE, {'cert_id': one, 'target': 'sup6', 'options': {}}, 'tester')
        A.deploy_save(STORE, {'cert_id': two, 'target': 'sup6', 'options': {}}, 'tester')
        name = STORE.db.value('SELECT test FROM cert_checks WHERE cert_id = ?', (one,))
        A.deploy_save(STORE, {'id': d1, 'cert_id': one, 'target': 'sup6', 'options': {
            'endpoint': 'DEFAULT_NSX_INGRESS'}}, 'tester')
        self.assertEqual(tests_of(one), {})
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name))
        self.assertEqual(len(tests_of(two)), 1)

    def test_7_deleted_with_its_certificate_said_once_as_a_test(self):
        A.family_save(STORE, 'target', {'kind': 'vsphere_supervisor', 'name': 'sup7', 'config': {
            'host': 'vc.example.test', 'user': 'u', 'password': 'x', 'supervisor': 'domain-c8',
            'endpoint_host': 'sup7.example.test'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['c7.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'sup7', 'options': {}}, 'tester')
        name = STORE.db.value('SELECT test FROM cert_checks WHERE cert_id = ?', (cid,))
        A.cert_drop(STORE, S.cert_need(STORE, cid), 'tester')
        ev = [r['words'] for r in STORE.db.rows('SELECT words FROM events WHERE words LIKE ?',
                                                ('%' + name + '%',))]
        self.assertEqual(len([w for w in ev if 'deleted' in w]), 1, ev)
        self.assertFalse(any(w.startswith('check ') for w in ev), ev)
        # a test deleted by a person: "test X deleted by"
        A.family_save(STORE, 'check', {'kind': 'tls', 'name': 'gone7', 'config': {
            'host': 'g.example.test', 'port': 443}}, 'tester')
        A.family_delete(STORE, 'check', {'id': S.plugin_row(STORE, 'check', 'gone7')['id']},
                        'tester')
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM events WHERE words = "
                                        "'test gone7 deleted by tester'"), 1)

    def test_8_a_number_below_its_min_refused(self):
        # 1.0.96: a field's min and max held at the save (a Synergy enclosure's bay 3 was
        # refused only when the deployment ran)
        A.family_save(STORE, 'target', {'kind': 'local', 'name': 'files8', 'config': {
            'base': os.path.join(TMP, 'out8')}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['files8.example.test']}, 'tester')
        with self.assertRaises(ValueError) as e:
            A.deploy_save(STORE, {'cert_id': cid, 'target': 'files8',
                                  'options': {'backup_keep': -1}}, 'tester')
        self.assertIn('at least', str(e.exception))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                        (cid,)), 0)
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'files8',
                              'options': {'backup_keep': 0}}, 'tester')

    def test_9_a_test_with_another_key_asked_is_not_made_twice(self):
        # round 3: a person's "Key asked for" on acme's test made a second one at the next save
        A.family_save(STORE, 'target', {'kind': 'esxi', 'name': 'esx9', 'config': {
            'host': 'esx9.example.test', 'user': 'root', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['esx9.example.test']}, 'tester')
        did = A.deploy_save(STORE, {'cert_id': cid, 'target': 'esx9', 'options': {}}, 'tester')
        t = STORE.db.row('SELECT * FROM cert_tests WHERE name = ?', ('esx9-esx9.example.test-443',))
        self.assertTrue(C.auto_made(STORE, t['name']))
        cfg = dict(json.loads(t['config']), key_want='rsa')
        A.family_save(STORE, 'check', {'id': t['id'], 'name': t['name'], 'kind': 'tls',
                                       'config': cfg, 'note': t['note']}, 'person')
        self.assertFalse(C.auto_made(STORE, t['name']), 'changed by a person: theirs')
        A.deploy_save(STORE, {'id': did, 'cert_id': cid, 'target': 'esx9', 'options': {}},
                      'tester')
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_checks WHERE cert_id = ?',
                                        (cid,)), 1)
        # a CUCM test made by 1.0.95 (no key asked for): taken over, not doubled
        A.family_save(STORE, 'target', {'kind': 'cucm', 'name': 'cu9', 'config': {
            'host': 'cucm9.example.test', 'user': 'svc', 'auth': 'password', 'password': 'x',
            'unit': 'tomcat-ECDSA'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['cucm9.example.test'], 'key_type': 'ec-256'},
                          'tester')
        A.family_save(STORE, 'check', {'name': 'cu9-cucm9.example.test-8443', 'kind': 'tls',
                                       'config': {'port': 8443, 'host': 'cucm9.example.test'},
                                       'note': 'what cu9 serves (made from its deployment)'},
                      'acme')
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'cu9', 'options': '{}',
                                         'enabled': 1, 'state': 'ok'})
        C.attach(STORE, cid, ['cu9-cucm9.example.test-8443'], 'acme', after_target='cu9')
        dep = STORE.db.row("SELECT * FROM cert_deploys WHERE target = 'cu9'")
        self.assertEqual(C.served_tests(STORE, dep, 'tester'), ['cu9-cucm9.example.test-8443'])
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_checks WHERE cert_id = ?',
                                        (cid,)), 1)
        self.assertEqual(json.loads(S.plugin_row(STORE, 'check', 'cu9-cucm9.example.test-8443')
                                    ['config']).get('key_want'), 'ecdsa')
        self.assertTrue(C.auto_made(STORE, 'cu9-cucm9.example.test-8443'))
        # taken off by a person under its old name: the new one with the key is not made
        cid2 = A.cert_save(STORE, {'names': ['cucm9b.example.test'], 'key_type': 'ec-256'},
                           'tester')
        A.family_save(STORE, 'target', {'kind': 'cucm', 'name': 'cu9b', 'config': {
            'host': 'cucm9b.example.test', 'user': 'svc', 'auth': 'password', 'password': 'x',
            'unit': 'tomcat-ECDSA'}}, 'tester')
        STORE.db.insert('cert_deploys', {'cert_id': cid2, 'target': 'cu9b', 'options': '{}',
                                         'enabled': 1, 'state': 'ok'})
        STORE.set_meta(C._off_key(cid2, 'cu9b-cucm9b.example.test-8443'), '{}')
        dep = STORE.db.row("SELECT * FROM cert_deploys WHERE target = 'cu9b'")
        self.assertEqual(C.served_tests(STORE, dep, 'tester'), [])

    def test_10_after_any_deployment_is_not_loose(self):
        # round 3: deleting a target deleted a test a person attached elsewhere "after any"
        for n in ('e10a', 'e10b'):
            A.family_save(STORE, 'target', {'kind': 'esxi', 'name': n, 'config': {
                'host': '%s.example.test' % n, 'user': 'root', 'password': 'x'}}, 'tester')
        a = A.cert_save(STORE, {'names': ['e10a.example.test']}, 'tester')
        b = A.cert_save(STORE, {'names': ['e10b.example.test']}, 'tester')
        da = A.deploy_save(STORE, {'cert_id': a, 'target': 'e10a', 'options': {}}, 'tester')
        A.deploy_save(STORE, {'cert_id': b, 'target': 'e10b', 'options': {}}, 'tester')
        name = 'e10a-e10a.example.test-443'
        C.attach(STORE, b, [name], 'person', after_target='')
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (da,))
        C.target_gone(STORE, a, 'e10a')
        A.family_delete(STORE, 'target', {'id': S.plugin_row(STORE, 'target', 'e10a')['id']},
                        'person')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name))
        self.assertTrue(STORE.db.row('SELECT 1 AS x FROM cert_checks WHERE cert_id = ? AND '
                                     'test = ?', (b, name)))

    def test_11_schedule_only_kept_carried_and_cleaned(self):
        # round 3: a '-' whose origin is not known to be target_gone stays with the target
        # deleted; the marks go with the configuration's file and with the certificate
        import collections
        for n in ('e11a', 'e11b'):
            A.family_save(STORE, 'target', {'kind': 'esxi', 'name': n, 'config': {
                'host': '%s.example.test' % n, 'user': 'root', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['e11.example.test']}, 'tester')
        da = A.deploy_save(STORE, {'cert_id': cid, 'target': 'e11a', 'options': {}}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'e11b', 'options': {}}, 'tester')
        name = 'e11a-e11a.example.test-443'
        chk = STORE.db.row('SELECT * FROM cert_checks WHERE test = ?', (name,))
        C.after(STORE, chk['id'], '-', 'person')              # a person's "only by its schedule"
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (da,))
        C.target_gone(STORE, cid, 'e11a')
        self.assertIsNone(STORE.get_meta(C._gone_key(cid, name)), 'not tied: not acme\'s')
        A.family_delete(STORE, 'target', {'id': S.plugin_row(STORE, 'target', 'e11a')['id']},
                        'person')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name), 'a person\'s - stays')
        # one tied to the target, left with none when the deployment went: acme's - deleted
        other = 'e11b-e11b.example.test-443'
        did = STORE.db.value("SELECT id FROM cert_deploys WHERE target = 'e11b'")
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (did,))
        C.target_gone(STORE, cid, 'e11b')
        self.assertTrue(STORE.get_meta(C._gone_key(cid, other)))
        # carried in the configuration's file, by the test's name (with a taken-off one)
        STORE.set_meta(C._off_key(cid, 'some-test'), '{"at": 1}')
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        row = [r for r in tables['certs'] if r['id'] == cid][0]
        self.assertIn(other, row['_meta']['after_gone'])
        self.assertIn('some-test', row['_meta']['served_off'])
        trow = [r for r in tables['cert_tests'] if r['name'] == other][0]
        self.assertIn('auto', trow['_meta'])
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:%'")
        E.carry_import(STORE, tables, 'test', False, collections.Counter())
        self.assertTrue(STORE.get_meta(C._gone_key(cid, other)))
        self.assertTrue(STORE.get_meta(C._off_key(cid, 'some-test')))
        self.assertTrue(C.auto_made(STORE, other))
        A.family_delete(STORE, 'target', {'id': S.plugin_row(STORE, 'target', 'e11b')['id']},
                        'person')
        self.assertIsNone(S.plugin_row(STORE, 'check', other))
        self.assertIsNone(STORE.get_meta(C._gone_key(cid, other)))
        self.assertIsNone(STORE.get_meta(C._auto_key(other)))
        # the certificate deleted: its marks by test name go with it
        A.cert_drop(STORE, S.cert_need(STORE, cid), 'tester')
        self.assertIsNone(STORE.get_meta(C._off_key(cid, 'some-test')))

    def test_12_a_test_a_person_edited_stays_with_the_certificate_deleted(self):
        # round 3: the page keeps acme's note when its box is left empty - an edited test was
        # still "acme's" and deleted with the certificate
        A.family_save(STORE, 'target', {'kind': 'esxi', 'name': 'e12', 'config': {
            'host': 'e12.example.test', 'user': 'root', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['e12.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'e12', 'options': {}}, 'tester')
        t = S.plugin_row(STORE, 'check', 'e12-e12.example.test-443')
        A.family_save(STORE, 'check', {'id': t['id'], 'name': t['name'], 'kind': 'tls',
                                       'config': {'port': 9443, 'host': 'e12.example.test',
                                                  'timeout': 60}, 'note': t['note']}, 'person')
        A.cert_drop(STORE, S.cert_need(STORE, cid), 'tester')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', t['name']))
        # one made by 1.0.95 (no mark) and saved since by a person: theirs too
        A.family_save(STORE, 'check', {'name': 'old12', 'kind': 'tls', 'config': {
            'port': 443, 'host': 'o12.example.test'}, 'note': 'what e12 serves '
            '(made from its deployment)'}, 'acme')
        self.assertTrue(C.auto_made(STORE, 'old12'))
        STORE.db.run("UPDATE cert_tests SET updated = updated + 100 WHERE name = 'old12'")
        self.assertFalse(C.auto_made(STORE, 'old12'))

    def test_13_the_target_changed_the_tests_follow(self):
        # round 3: the target's own host changed - acme's test of the old one stayed
        A.family_save(STORE, 'target', {'kind': 'esxi', 'name': 'e13', 'config': {
            'host': 'e13.example.test', 'user': 'root', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['e13.example.test']}, 'tester')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'e13', 'options': {}}, 'tester')
        t = S.plugin_row(STORE, 'target', 'e13')
        A.family_save(STORE, 'target', {'id': t['id'], 'config': {
            'host': 'e13-new.example.test', 'user': 'root', 'password': 'x'}}, 'tester')
        self.assertEqual(tests_of(cid), {('e13-new.example.test', 443): 'e13'})
        self.assertIsNone(S.plugin_row(STORE, 'check', 'e13-e13.example.test-443'))
        # renamed: its tests are still known as made for it
        A.family_save(STORE, 'target', {'id': t['id'], 'name': 'e13r'}, 'tester')
        self.assertEqual(C.auto_target(STORE, 'e13-e13-new.example.test-443'), 'e13r')

    def test_14_the_first_name_one_test_per_target(self):
        # round 3: VCF targets with no Component FQDN shared the first one's test
        for n in ('vcf14a', 'vcf14b'):
            A.family_save(STORE, 'target', {'kind': 'vcf_component', 'name': n, 'config': {
                'host': 'sddc.example.test', 'user': 'u', 'password': 'x',
                'csr_country': 'CZ', 'csr_state': 'P', 'csr_city': 'P', 'csr_org': 'O',
                'csr_ou': 'IT'}}, 'tester')
        a = A.cert_save(STORE, {'names': ['v14a.example.test']}, 'tester')
        b = A.cert_save(STORE, {'names': ['v14b.example.test']}, 'tester')
        self.assertEqual(new_deployment(a, 'vcf14a'), ['vcf14a-name-443'])
        self.assertEqual(new_deployment(b, 'vcf14b'), ['vcf14b-name-443'])
        STORE.db.run("DELETE FROM cert_deploys WHERE target = 'vcf14b'")
        C.target_gone(STORE, b, 'vcf14b')
        A.family_delete(STORE, 'target', {'id': S.plugin_row(STORE, 'target', 'vcf14b')['id']},
                        'tester')
        self.assertEqual(tests_of(b), {})
        self.assertIsNone(S.plugin_row(STORE, 'check', 'vcf14b-name-443'))

    def test_15_min_max_held_for_a_value_changed_only(self):
        # round 3: a deployment saved before 1.0.96 with backup_keep -1 could not be changed
        A.family_save(STORE, 'target', {'kind': 'local', 'name': 'files15', 'config': {
            'base': os.path.join(TMP, 'out15')}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['files15.example.test']}, 'tester')
        did = A.deploy_save(STORE, {'cert_id': cid, 'target': 'files15',
                                    'options': {'backup_keep': 2}}, 'tester')
        STORE.db.update('cert_deploys', did, {'options': json.dumps({'backup_keep': -1})})
        A.deploy_save(STORE, {'id': did, 'cert_id': cid, 'target': 'files15', 'note': 'x',
                              'options': {'backup_keep': -1}}, 'tester')
        with self.assertRaises(ValueError):
            A.deploy_save(STORE, {'id': did, 'cert_id': cid, 'target': 'files15',
                                  'options': {'backup_keep': -2}}, 'tester')

    def test_16_an_ipv6_host_in_brackets_already(self):
        # round 3: "[{host}]:8443" became [[2001:db8::10]]:8443 - a test that never passed
        A.family_save(STORE, 'target', {'kind': 'ssh', 'name': 'web16', 'config': {
            'host': '2001:db8::16', 'user': 'root', 'password': 'x'}}, 'tester')
        cid = A.cert_save(STORE, {'names': ['web16.example.test']}, 'tester')
        did = A.deploy_save(STORE, {'cert_id': cid, 'target': 'web16', 'options': {}}, 'tester')
        for line in ('[{host}]:8443', '{host}:8443'):
            dep = dict(STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (did,)))
            opts = {'verify': line}
            made = C.verify_to_tests(STORE, dep, opts, 'tester')
            self.assertEqual(opts, {})
            cfg = json.loads(S.plugin_row(STORE, 'check', made[0])['config'])
            self.assertEqual((cfg['host'], cfg['port']), ('2001:db8::16', 8443))


if __name__ == '__main__':
    unittest.main(verbosity=2)
