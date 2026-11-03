#!/usr/bin/env python3
"""Importing both halves of a dual certificate (1.0.34).

    python3 test/test_import_dual.py

A dual certificate is two of the same names, an RSA one and an ECDSA one beside
it (nginx gives each client the one it takes). Imported, the other half is kept
as the certificate's twin: from one file holding both, or brought into a
certificate that has the first half - not as its next version, which would put
the half it had away.
"""
import base64
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-dual-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'none'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from test_issuers import TestCA, make_key_csr  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
NAMES = ['dual.example.test']


def b64(text):
    return base64.b64encode(text.encode()).decode()


class TestDual(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = TestCA(cn='Dual Test Root')
        k1, _c, d1 = make_key_csr(NAMES, kind='rsa')
        k2, _c, d2 = make_key_csr(NAMES, kind='ec')
        cls.rsa = (cls.ca.sign_csr(d1, NAMES, serial=201), k1)
        cls.ec = (cls.ca.sign_csr(d2, NAMES, serial=202), k2)
        cls.rsa = tuple(x if isinstance(x, str) else x.decode() for x in cls.rsa)
        cls.ec = tuple(x if isinstance(x, str) else x.decode() for x in cls.ec)
        with open(cls.ca.crt) as f:
            cls.root = f.read()

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()

    def row(self, cid):
        return S.cert_need(STORE, cid)

    def test_one_file_holding_both(self):
        both = self.rsa[0] + self.ec[0] + self.root + self.rsa[1] + self.ec[1]
        out, _got = A.parse_file(both.encode(), 'both.pem', None)
        self.assertTrue(out.get('twin', '').startswith('ec'), out)
        self.assertEqual(sum(1 for c in out['certs'] if c.get('twin')), 1)
        self.assertFalse(any('could each be' in n for n in out['notes']), out['notes'])
        cid, _v = A.cert_import(STORE, {'data_b64': b64(both), 'filename': 'both.pem',
                                        'name': 'dual-one-file'}, 'test')
        r = self.row(cid)
        self.assertIn('RSA', S.info_of(r['cert_pem'])['key_type'].upper())
        self.assertTrue(r.get('alt_cert_pem'), 'the twin kept')
        self.assertTrue(str(r.get('key_type_alt')).startswith('ec'))
        self.assertTrue(S.cert_key(r, 'alt'), 'with its own key')

    def test_brought_into_it_as_its_twin(self):
        cid, v1 = A.cert_import(STORE, {'data_b64': b64(self.rsa[0] + self.rsa[1]),
                                        'filename': 'rsa.pem', 'name': 'dual-two-files'}, 'test')
        fp_main = self.row(cid)['fingerprint']
        # the ECDSA one, nothing said: guessed - the other key type, the same names
        _cid, v2 = A.cert_import(STORE, {'id': cid, 'data_b64': b64(self.ec[0] + self.ec[1]),
                                         'filename': 'ec.pem'}, 'test')
        r = self.row(cid)
        self.assertEqual(r['fingerprint'], fp_main, 'the RSA one stays the certificate')
        self.assertTrue(r.get('alt_cert_pem'))
        self.assertEqual(r['alt_version'], v2)
        self.assertGreater(v2, v1)
        # said as the next version, it is that
        A.cert_import(STORE, {'id': cid, 'data_b64': b64(self.ec[0] + self.ec[1]),
                              'filename': 'ec.pem', 'as': 'main'}, 'test')
        self.assertNotEqual(self.row(cid)['fingerprint'], fp_main)

    def test_exported_both_and_imported_again(self):
        """Export → both (one PEM, the two with their keys) → import: the same pair."""
        both = self.rsa[0] + self.ec[0] + self.root + self.rsa[1] + self.ec[1]
        cid, _v = A.cert_import(STORE, {'data_b64': b64(both), 'filename': 'both.pem',
                                        'name': 'dual-round-trip'}, 'test')
        admin = {'name': 'admin', 'role': 'fulladmin'}
        out = A.cert_export(STORE, {'id': cid, 'format': 'combined-pem', 'variant': 'both'}, admin)
        self.assertTrue(out['filename'].endswith('.both.pem'), out['filename'])
        text = base64.b64decode(out['data_b64']).decode()
        self.assertEqual(text.count('PRIVATE KEY-----') // 2, 2, 'both keys')
        cid2, _v = A.cert_import(STORE, {'data_b64': out['data_b64'], 'filename': out['filename'],
                                         'name': 'dual-round-trip-2'}, 'test')
        r1, r2 = self.row(cid), self.row(cid2)
        self.assertEqual((r1['fingerprint'], r1['alt_fingerprint']),
                         (r2['fingerprint'], r2['alt_fingerprint']))
        with self.assertRaises(ValueError):
            A.cert_export(STORE, {'id': cid, 'format': 'pfx', 'variant': 'both', 'password': 'x'}, admin)

    def test_a_bad_as_refused(self):
        with self.assertRaises(ValueError):
            A.cert_import(STORE, {'data_b64': b64(self.rsa[0]), 'filename': 'x.pem', 'as': 'x'},
                          'test')


if __name__ == '__main__':
    unittest.main(verbosity=2)
