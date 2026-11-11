#!/usr/bin/env python3
"""Hunt E (1.0.77): what the bug hunt found and was put right.

    python3 test/test_hunt_e.py
"""
import base64
import hashlib
import os
import secrets
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-e-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import checks as C  # noqa: E402
from acmelib.certs import jobs, pki  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def imported(name, kt='rsa-2048'):
    key = pki.make_key(kt)
    crt = pki.self_signed(key, [name], days=60)
    return A.cert_import(STORE, {'data_b64': base64.b64encode((crt + key).encode()).decode(),
                                 'filename': name + '.pem'}, 'tester')[0]


class Certs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.family_save(STORE, 'issuer', {'name': 'SS', 'kind': 'selfsigned', 'config': {}}, 't')
        A.family_save(STORE, 'target', {'name': 'w1', 'kind': 'webhook',
                                        'config': {'url': 'https://h.test/x'}}, 't')
        A.family_save(STORE, 'target', {'name': 'w2', 'kind': 'webhook',
                                        'config': {'url': 'https://h.test/y'}}, 't')

    def test_deleting_not_stuck(self):
        cid = imported('del.example.test')
        STORE.db.update('certs', cid, {'state': 'deleting'})
        STORE.db.insert('cert_jobs', {'ts': time.time(), 'kind': 'revoke', 'cert_id': cid,
                                      'node': E.node_name(), 'state': 'queued', 'steps': '[]'})
        jobs.recover(STORE)
        self.assertEqual(STORE.db.row('SELECT state FROM certs WHERE id = ?', (cid,))['state'],
                         'revoke-failed')

    def test_deployment_moved_is_deployed_again(self):
        a, b = imported('mva.example.test'), imported('mvb.example.test')
        did = A.deploy_save(STORE, {'cert_id': a, 'target': 'w1', 'options': {}}, 't')
        STORE.db.update('cert_deploys', did, {'deployed_version': 1, 'deployed_fp': 'X', 'state': 'ok'})
        A.deploy_save(STORE, {'id': did, 'cert_id': b, 'target': 'w2'}, 't')
        r = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (did,))
        self.assertEqual((r['deployed_version'], r['deployed_fp'], r['state']), (None, None, 'new'))

    def test_switched_off_not_renewed_by_hand(self):
        cid = A.cert_save(STORE, {'name': 'off.example.test', 'names': ['off.example.test'],
                                  'issuer': 'SS'}, 't')
        STORE.db.update('certs', cid, {'enabled': 0, 'cert_pem': 'x', 'state': 'disabled'})
        with self.assertRaises(ValueError):
            A.start_renew(STORE, cid, True, 't')
        with self.assertRaises(ValueError):
            A.start_deploy(STORE, cid, None, 't')

    def test_switched_on_after_its_end_is_expired(self):
        cid = imported('ended.example.test')
        STORE.db.update('certs', cid, {'enabled': 0, 'state': 'disabled', 'not_after': time.time() - 86400})
        A.cert_save(STORE, {'id': cid, 'enabled': True}, 't')
        self.assertEqual(STORE.db.row('SELECT state FROM certs WHERE id = ?', (cid,))['state'], 'expired')

    def test_a_twin_is_the_other_kind_of_key(self):
        cid = imported('twin.example.test', 'rsa-2048')
        key = pki.make_key('rsa-2048')
        crt = pki.self_signed(key, ['twin.example.test'], days=60)
        with self.assertRaises(ValueError) as e:
            A.cert_import(STORE, {'data_b64': base64.b64encode((crt + key).encode()).decode(),
                                  'filename': 'twin2.pem', 'into': cid, 'id': cid, 'as': 'alt'}, 't')
        self.assertIn('other kind of key', str(e.exception))

    def test_tags_are_words(self):
        with self.assertRaises(ValueError):
            A.cert_save(STORE, {'name': 'tag.example.test', 'names': ['tag.example.test'],
                                'issuer': 'SS', 'tags': ['x' * 500]}, 't')

    def test_runnable(self):
        cid = imported('run.example.test')
        STORE.db.insert('cert_tests', {'name': 'tt', 'kind': 'tls', 'config': '{}', 'enabled': 0})
        a = STORE.db.insert('cert_checks', {'cert_id': cid, 'test': 'tt', 'enabled': 1, 'position': 0})
        b = STORE.db.insert('cert_checks', {'cert_id': cid, 'test': 'zz', 'enabled': None, 'position': 1})
        self.assertEqual(C.runnable(STORE, [a, b]), [b])          # the test off; NULL is on

    def test_after_target_fits(self):
        with self.assertRaises(ValueError):
            C._after_checked(STORE, 1, ['t' * 120, 'u' * 120])


class Engine(unittest.TestCase):
    def test_2fa_on_ends_other_sign_ins(self):
        d = E.Daemon(STORE, serve=False)
        t = time.time()
        keep = None
        for i in range(3):
            keep = STORE.db.insert('sessions', {
                'token_hash': hashlib.sha256(secrets.token_bytes(8)).hexdigest(), 'kind': 'admin',
                'name': 'a%d' % i, 'role': 'fulladmin', 'created': t, 'last': t, 'expires': t + 3600,
                'ip': '', 'data': '{}'})
        d.save_settings({'admin_2fa': '1'}, by='t', keep_session=keep)
        n = STORE.db.value("SELECT COUNT(*) FROM sessions WHERE kind = 'admin'", (), 0)
        self.assertEqual(int(n), 1)
        d.save_settings({'admin_2fa': '0'}, by='t')

    def test_split_arbiter_only_through_its_card(self):
        d = E.Daemon(STORE, serve=False)
        with self.assertRaises(E.BadSetting):
            d.save_settings({'split_mode': 'arbiter'}, by='t')

    def test_shipper_trouble_goes_with_its_target(self):
        sh = E.Shipper.__new__(E.Shipper)
        sh.trouble, sh.down, sh.missed, sh.backlog, sh.tcp = {'1.2.3.4:514/tcp': 'x', 'file:a': 'y'}, {}, {}, {}, {}
        E.CONFIG['isemon'] = 0
        sh.configure()
        self.assertEqual(sh.trouble, {'file:a': 'y'})


if __name__ == '__main__':
    unittest.main()
