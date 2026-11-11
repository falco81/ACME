#!/usr/bin/env python3
"""Hunt F (1.0.78): what the bug hunt found and was put right.

    python3 test/test_hunt_f.py
"""
import base64
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-f-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import checks as C  # noqa: E402
from acmelib.certs import monitor as M  # noqa: E402
from acmelib.certs import pki  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
CERTADMIN = {'name': 'ca1', 'role': 'certadmin'}


def imported(name):
    key = pki.make_key('ec-256')
    crt = pki.self_signed(key, [name], days=60)
    return A.cert_import(STORE, {'data_b64': base64.b64encode((crt + key).encode()).decode(),
                                 'filename': name + '.pem'}, 'tester')[0]


class Fixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for n in ('fa', 'fb'):
            A.family_save(STORE, 'target', {'name': n, 'kind': 'webhook',
                                            'config': {'url': 'https://h.test/' + n}}, 't')

    def test_key_formats_by_their_other_words(self):
        for w in ('haproxy /var/www/k.pem', 'combined /x/k.pem', 'rsa /srv/k', 'key-pem /k.pem'):
            self.assertTrue(A._key_lines(w), w)
        self.assertFalse(A._key_lines('fullchain /x/f.pem\ncert /x/c.pem'))

    def test_unsaved_settings_tried_only_by_a_full_admin(self):
        with self.assertRaises(E.ApiError):
            A.saved_only(CERTADMIN, {'kind': 'powerdns', 'config': {'url': 'http://10.0.0.5'}})
        got = A.saved_only(CERTADMIN, {'id': 3, 'kind': 'x', 'config': {'url': 'y'}, 'field': 'f'})
        self.assertEqual(got, {'id': 3, 'field': 'f'})
        b = {'kind': 'x', 'config': {}}
        self.assertIs(A.saved_only({'role': 'fulladmin'}, b), b)

    def test_validation_renamed_keeps_a_certificates_own_settings(self):
        A.family_save(STORE, 'challenge', {'name': 'dnsA', 'kind': 'manual', 'config': {}}, 't')
        cid = imported('over.example.test')
        STORE.db.update('certs', cid, {'profile': json.dumps(
            {'over': {'validation': {'dnsA': {'zone': 'sub.example.test'}}}})})
        row = STORE.db.row("SELECT id FROM cert_challenges WHERE name = 'dnsA'")
        A.family_save(STORE, 'challenge', {'id': row['id'], 'name': 'dnsB'}, 't')
        prof = json.loads(STORE.db.row('SELECT profile FROM certs WHERE id = ?', (cid,))['profile'])
        self.assertEqual(prof['over']['validation'], {'dnsB': {'zone': 'sub.example.test'}})

    def test_deployment_taken_away_leaves_no_after(self):
        cid = imported('after.example.test')
        A.family_save(STORE, 'check', {'name': 'ft1', 'kind': 'tls', 'config': {'port': 443}}, 't')
        d1 = A.deploy_save(STORE, {'cert_id': cid, 'target': 'fa', 'options': {}}, 't')
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'fb', 'options': {}}, 't')
        k = C.attach(STORE, cid, ['ft1'], 't', 'fa\nfb')[0]
        A.deploy_save(STORE, {'id': d1, 'cert_id': cid, 'target': 'fb', 'options': {}}, 't') \
            if False else None
        # moved: fa is gone from its tests
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (d1,))
        C.target_gone(STORE, cid, 'fa')
        self.assertEqual(STORE.db.row('SELECT after_target FROM cert_checks WHERE id = ?', (k,))
                         ['after_target'], 'fb')
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid,))
        C.target_gone(STORE, cid, 'fb')
        self.assertEqual(STORE.db.row('SELECT after_target FROM cert_checks WHERE id = ?', (k,))
                         ['after_target'], C.AFTER_NONE)

    def test_every_state_a_number_of_its_own(self):
        nums = [M.STATE_NUM[s] for s in ('revoke-failed', 'deleting', 'pending-approval',
                                         'declined', 'held')]
        self.assertEqual(len(set(nums)), 5)
        self.assertNotIn(0, nums)

    def test_a_missing_module_keeps_its_secrets(self):
        A.family_save(STORE, 'target', {'name': 'gone1', 'kind': 'webhook',
                                        'config': {'url': 'https://h.test/g'}}, 't')
        STORE.db.run("UPDATE cert_targets SET kind = 'no_such_module' WHERE name = 'gone1'")
        row = STORE.db.row("SELECT id FROM cert_targets WHERE name = 'gone1'")
        with self.assertRaises(ValueError):
            A.family_save(STORE, 'target', {'id': row['id'], 'config': {'url': 'x', 'token': 'p'}}, 't')
        A.family_save(STORE, 'target', {'id': row['id'], 'note': 'still here'}, 't')   # allowed

    def test_verify_moved_to_tests_reads_v6_and_the_targets_port(self):
        cid = imported('v6.example.test')
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (A.deploy_save(
            STORE, {'cert_id': cid, 'target': 'fa', 'options': {}}, 't'),))
        opts = {'verify': '2001:db8::1\n[2001:db8::2]:8443'}
        made = C.verify_to_tests(STORE, dep, opts, 't')
        cfgs = sorted((c.get('host'), int(c.get('port'))) for c in (
            STORE.plugin_config('check', STORE.db.row('SELECT * FROM cert_tests WHERE name = ?', (n,)))
            if hasattr(STORE, 'plugin_config') else
            json.loads(STORE.db.row('SELECT config FROM cert_tests WHERE name = ?', (n,))['config'])
            for n in made))
        self.assertEqual(cfgs, [('2001:db8::1', 443), ('2001:db8::2', 8443)])
        self.assertNotIn('verify', opts)


class Engine(unittest.TestCase):
    def test_trap_error_cleared_when_traps_go(self):
        E.SNMP_STATE['trap_error'] = 'x:162: failed'
        E.CONFIG['snmp'] = 0
        agent = E.SnmpAgent.__new__(E.SnmpAgent)
        try:
            agent.configure()
        except Exception:                               # noqa: BLE001 - only its first lines matter
            pass
        self.assertEqual(E.SNMP_STATE['trap_error'], '')

    def test_unknown_node_said_at_once(self):
        class D(object):
            store = STORE
            serving = False
        with self.assertRaises(ValueError):
            E.node_ask(D(), 'siem', {'only': 'typo-node'}, 't')


if __name__ == '__main__':
    unittest.main(verbosity=2)
