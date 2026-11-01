#!/usr/bin/env python3
"""A backup of the certificate manager checked as Settings → Backups checks it.

    python3 test/test_backup_seals.py

- the private keys (an authority's, a certificate's and its versions') open
  with the key in the backup - they are sealed under binds of their own;
- the configuration's export carries them opened when it is whole;
- the manifest counts meta as the copy holds it (no pieces of an upload).
"""
import gzip
import io
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-bkseal-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import ca as CA, pki, store as S  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)


def make_data():
    ca_id = CA.ca_create(STORE, 'Test Root', {'CN': 'Test Root'}, key_type='ec-256', by='t')
    cid = STORE.db.insert('certs', {'name': 'web', 'names': json.dumps(['web.example']),
                                    'key_type': 'ec-256', 'created': time.time(), 'version': 0})
    for _ in range(2):
        key = pki.make_key('ec-256')
        csr, _der = pki.make_csr(key, ['web.example'])
        cert, chain = CA.ca_sign(STORE, ca_id, csr, 30)
        S.save_version(STORE, cid, cert, chain, key, 'test', 't')
    return ca_id, cid


class BackupSeals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_id, cls.cid = make_data()
        for i in range(5):
            STORE.set_meta('upgrade:piece:%d' % i, 'x' * 10)

    def test_copy_opens_every_sealed_key(self):
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        got = E.copy_read_through(path, E.sealing_key(), child=True)
        self.assertGreaterEqual(got['tried'], 4)        # the CA, the cert, two versions
        self.assertEqual(got['opened'], got['tried'], got)

    def test_manifest_counts_meta_as_the_copy_holds_it(self):
        path = os.path.join(TMP, 'copy2.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        got = E.copy_read_through(path, None, child=True)
        self.assertEqual(E.rb_counts(STORE)['meta'], got['counts']['meta'])

    def test_whole_export_carries_the_keys_opened(self):
        out = E.carry_export(STORE, True)
        ca = [r for r in out.get('cert_cas', []) if r['id'] == self.ca_id][0]
        self.assertIn('PRIVATE KEY', ca.get('key_sealed') or '')
        cert = [r for r in out.get('certs', []) if r['id'] == self.cid][0]
        self.assertIn('PRIVATE KEY', cert.get('key_sealed') or '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
