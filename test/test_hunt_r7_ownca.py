#!/usr/bin/env python3
"""Hunt R run 7, acme's own authorities (acmelib/certs/ca.py, POST /api/cas/import):

- a path length of -1 ("no limit") under a parent with a path length: the child got none and
  acme let authorities under it that no client accepts - now the most the parent allows;
- a leaf (CA:FALSE) with keyCertSign / cRLSign in its key usage: refused;
- POST /api/cas/import ignored the chain pasted in the Import dialog (chain_pem): an
  intermediate from elsewhere kept no chain and handed out what it signed without it.

    python3 test/test_hunt_r7_ownca.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-r7ownca-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as API, ca as CA, pki  # noqa: E402,F401
from acmelib.certs.cli import _Daemon  # noqa: E402
from acmelib.certs.pki import PkiError  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
DAEMON = _Daemon(STORE)


def call(method, path, body=None):
    return E.cli_api(DAEMON, 'tester', method, path, body=body)


def make_ca(name, parent=None, **kw):
    body = {'name': name, 'subject': {'CN': name}, 'key_type': 'ec-256', 'days': 3650}
    if parent:
        body['parent_id'] = parent
    body.update(kw)
    return int(call('POST', '/api/cas/create', body)['id'])


def leaf(ca_id, profile=None):
    csr, _der = pki.make_csr(pki.make_key('ec-256'), ['www.test.example'])
    return CA.ca_sign(STORE, ca_id, csr, 30, profile)


def verify(root, leaf_pem, chain):
    d = tempfile.mkdtemp(prefix='acme-r7v-')
    try:
        for n, v in (('r', root), ('u', ''.join(chain) or root), ('l', leaf_pem)):
            with open(os.path.join(d, n), 'w') as f:
                f.write(v)
        got = subprocess.run(['openssl', 'verify', '-CAfile', os.path.join(d, 'r'), '-untrusted',
                              os.path.join(d, 'u'), os.path.join(d, 'l')], capture_output=True,
                             text=True)
        return got.returncode == 0, got.stdout + got.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


class PathLen(unittest.TestCase):
    def test_minus_one_under_limited_parent(self):
        root = make_ca('PL Root', path_len=1)
        mid = make_ca('PL Mid', root, path_len=-1)
        self.assertEqual(CA._row(STORE, mid)['path_len'], 0)
        self.assertEqual(pki.cert_info(CA._row(STORE, mid)['cert_pem'])['path_len'], 0)
        with self.assertRaises(SystemExit):
            make_ca('PL Sub', mid)
        cert, chain = leaf(mid)
        ok, said = verify(CA._row(STORE, root)['cert_pem'], cert, chain)
        self.assertTrue(ok, said)
        # ca_sign of an authority: -1 is the most allowed too
        csr, _d = pki.make_csr(pki.make_key('ec-256'), ['sub.test.example'])
        got, _c = CA.ca_sign(STORE, root, csr, 30, {'is_ca': True, 'path_len': -1})
        self.assertEqual(pki.cert_info(got)['path_len'], 0)

    def test_minus_one_root_is_no_limit(self):
        root = make_ca('PL Free Root', path_len=-1)
        self.assertIsNone(CA._row(STORE, root)['path_len'])
        self.assertIsNone(pki.cert_info(CA._row(STORE, root)['cert_pem'])['path_len'])
        mid = make_ca('PL Free Mid', root, path_len=-1)
        self.assertIsNone(pki.cert_info(CA._row(STORE, mid)['cert_pem'])['path_len'])
        _ident, csr = CA.ca_csr(STORE, 'PL Csr', 'PL Csr', path_len=-1)
        self.assertNotIn('pathlen', subprocess.run(
            ['openssl', 'req', '-noout', '-text'], input=csr, capture_output=True,
            text=True).stdout)


class LeafKeyUsage(unittest.TestCase):
    def test_no_keycertsign_on_leaf(self):
        root = make_ca('KU Root')
        for ku in (['digitalSignature', 'keyCertSign'], ['cRLSign']):
            with self.assertRaises(PkiError):
                leaf(root, {'key_usage': ku})
        cert, _c = leaf(root, {'key_usage': ['digitalSignature', 'keyAgreement']})
        self.assertNotIn('keyCertSign', pki.cert_info(cert)['key_usage'])


class ImportChain(unittest.TestCase):
    def test_chain_pem_kept(self):
        rk = pki.make_key('ec-256')
        other_root = pki.self_signed(rk, [], subject={'CN': 'Elsewhere Root'}, days=300,
                                     is_ca=True)
        tmp_root = CA.ca_import(STORE, 'tmp elsewhere root', other_root, rk)
        tmp_mid = CA.ca_create(STORE, 'tmp elsewhere mid', 'Elsewhere Mid', parent_id=tmp_root)
        mid = CA._row(STORE, tmp_mid)
        mid_key = CA._key(mid)
        CA.ca_delete(STORE, tmp_mid)
        CA.ca_delete(STORE, tmp_root)
        got = call('POST', '/api/cas/import', {'name': 'Elsewhere Mid', 'cert_pem': mid['cert_pem'],
                                               'key_pem': mid_key, 'chain_pem': other_root})
        row = CA._row(STORE, got['id'])
        self.assertEqual(pki.certs_in(row['chain_pem']), [pki.cert_pem(other_root)])
        cert, chain = leaf(got['id'])
        self.assertEqual(len(chain), 2)
        ok, said = verify(other_root, cert, chain)
        self.assertTrue(ok, said)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
