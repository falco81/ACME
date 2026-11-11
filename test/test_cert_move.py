#!/usr/bin/env python3
"""Change the source of a certificate in use (1.0.69).

    python3 test/test_cert_move.py

An imported certificate moved to a source (renewed from it from now on), and one from a
source moved to by hand (renewed by importing): its deployments, tests and versions stay,
the move is an event of its own, and a certificate the new source never issued is not
offered for revoking at it.
"""
import base64
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-cert-move-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import pki  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def imported(name):
    key = pki.make_key('rsa-2048')
    cert = pki.self_signed(key, [name], days=90)
    data = (cert.strip() + '\n' + key.strip() + '\n').encode()
    return A.cert_import(STORE, {'data_b64': base64.b64encode(data).decode(),
                                 'filename': name + '.pem'}, 'tester')[0]


class Move(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.family_save(STORE, 'issuer', {'name': 'Own SS', 'kind': 'selfsigned', 'config': {}}, 'tester')

    def row(self, cid):
        return STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))

    def test_imported_to_a_source_and_back(self):
        cid = imported('move1.example.test')
        self.assertTrue(cid)
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'web1', 'options': '{}', 'enabled': 1})
        STORE.db.insert('cert_checks', {'cert_id': cid, 'test': 't1', 'enabled': 1, 'position': 0})
        r = self.row(cid)
        self.assertEqual(r['issuer'], '')
        self.assertEqual(r['source'], 'import')
        # to a source: renewed from it, by itself
        A.cert_save(STORE, {'id': cid, 'issuer': 'Own SS', 'challenge': '', 'challenge_map': {},
                            'auto_renew': True, 'renew_days': 20}, 'tester')
        r = self.row(cid)
        self.assertEqual((r['issuer'], r['source'], r['auto_renew'], r['renew_days']),
                         ('Own SS', 'issuer', 1, 20))
        self.assertEqual(r['name'], 'move1.example.test')
        self.assertEqual(json.loads(r['names']), ['move1.example.test'])
        self.assertTrue(r['cert_pem'])
        ev = [x['words'] for x in STORE.db.rows('SELECT words FROM events ORDER BY id DESC LIMIT 5')]
        self.assertTrue(any('moved from by hand to Own SS' in x for x in ev), ev)
        # the one in use was imported: the new source cannot revoke it
        self.assertIn('was imported', A.revocable(STORE, r))
        # back to by hand: nothing renews it, nothing proves its names
        A.cert_save(STORE, {'id': cid, 'issuer': '', 'challenge': '', 'challenge_map': {},
                            'auto_renew': False}, 'tester')
        r = self.row(cid)
        self.assertEqual((r['issuer'], r['source'], r['auto_renew'], r['challenge']),
                         ('', 'import', 0, ''))
        self.assertEqual(r['state'], 'ok')
        self.assertEqual(STORE.db.row('SELECT COUNT(*) AS n FROM cert_deploys WHERE cert_id = ?',
                                      (cid,))['n'], 1)
        self.assertEqual(STORE.db.row('SELECT COUNT(*) AS n FROM cert_checks WHERE cert_id = ?',
                                      (cid,))['n'], 1)
        self.assertEqual(STORE.db.row('SELECT COUNT(*) AS n FROM cert_versions WHERE cert_id = ?',
                                      (cid,))['n'], 1)

    def test_to_by_hand_cannot_renew_by_itself(self):
        cid = imported('move2.example.test')
        A.cert_save(STORE, {'id': cid, 'issuer': 'Own SS', 'auto_renew': True}, 'tester')
        # a source on a certificate it issued itself: revocable as before (self-signed: never)
        A.cert_save(STORE, {'id': cid, 'issuer': ''}, 'tester')
        with self.assertRaises(ValueError):
            A.cert_auto(STORE, cid, True, 'tester')


if __name__ == '__main__':
    unittest.main()
