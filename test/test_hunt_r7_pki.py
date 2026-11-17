#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt r7, area pki: what was found and fixed.

  - key-traditional of an Ed25519 certificate: openssl refused it (no traditional format)
  - read_any (import / parse) of a PEM saved as UTF-16 (Notepad, PowerShell 5): refused
  - a PKCS#12 friendly name with letters past ASCII came back as U+FFFD
  - acme's own web certificate given as fullchain + chain: the intermediate twice in the
    chain; the leaf pasted again with CRLF went into the chain

    python3 test/test_hunt_r7_pki.py
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-hunt-r7-pki-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'),
                  ACME_CHAIN_CA=os.path.join(TMP, 'no-roots.pem'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import bundle as B  # noqa: E402
from acmelib.certs import formats as F  # noqa: E402
from acmelib.certs import pki  # noqa: E402


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=TMP)


def read(n):
    with open(os.path.join(TMP, n)) as f:
        return f.read()


class Formats(unittest.TestCase):
    def test_key_traditional_ed25519(self):
        k = pki.make_key('ed25519')
        b = B.CertBundle('ed', pki.self_signed(k, ['ed.example'], days=5), k, [])
        out = b.as_format('key-traditional').decode()
        self.assertIn('BEGIN PRIVATE KEY', out)
        self.assertEqual(pki.key_plain(out), b.key_pem)
        # RSA and EC as before
        for kt, label in (('rsa-2048', 'RSA PRIVATE KEY'), ('ec-256', 'EC PRIVATE KEY')):
            k = pki.make_key(kt)
            self.assertIn('BEGIN ' + label, pki.key_traditional(k))

    def test_utf16_pem_read(self):
        k = pki.make_key('ec-256')
        c = pki.self_signed(k, ['u16.example'], days=5)
        for enc in ('utf-16', 'utf-16-le', 'utf-16-be'):
            data = (c + k).encode(enc)
            if enc != 'utf-16':
                data = (b'\xff\xfe' if enc.endswith('le') else b'\xfe\xff') + data
            got = F.read_any(data, 'cert.pem')
            self.assertEqual(got['leaf'], c, enc)
            self.assertEqual(got['key'], k, enc)

    def test_p12_friendly_name_non_ascii(self):
        k = pki.make_key('ec-256')
        b = B.CertBundle('x', pki.self_signed(k, ['fn.example'], days=5), k, [])
        for fmt in ('pfx', 'p12-legacy'):
            got = F.read_any(b.as_format(fmt, 'pw', 'Ålias ü'), 'a.pfx', 'pw')
            self.assertEqual(got['aliases'], ['Ålias ü'], fmt)
            got = F.read_any(b.as_format(fmt, 'pw', 'plain-1'), 'a.pfx', 'pw')
            self.assertEqual(got['aliases'], ['plain-1'], fmt)


class WebChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        j = lambda n: os.path.join(TMP, n)              # noqa: E731
        sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
           '-nodes', '-keyout', j('root.key'), '-out', j('root.pem'), '-days', '30',
           '-subj', '/CN=R7 Root', '-addext', 'basicConstraints=critical,CA:true')
        with open(j('ca.ext'), 'w') as f:
            f.write('basicConstraints=critical,CA:true\nkeyUsage=keyCertSign,cRLSign\n')
        sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
           '-nodes', '-keyout', j('int.key'), '-out', j('int.csr'), '-subj', '/CN=R7 Issuing')
        sh('openssl', 'x509', '-req', '-in', j('int.csr'), '-CA', j('root.pem'), '-CAkey',
           j('root.key'), '-CAcreateserial', '-out', j('int.pem'), '-days', '30',
           '-extfile', j('ca.ext'))
        with open(j('l.ext'), 'w') as f:
            f.write('subjectAltName=DNS:r7.example.test\n')
        sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
           '-nodes', '-keyout', j('leaf.key'), '-out', j('leaf.csr'), '-subj', '/CN=r7.example.test')
        sh('openssl', 'x509', '-req', '-in', j('leaf.csr'), '-CA', j('int.pem'), '-CAkey',
           j('int.key'), '-CAcreateserial', '-out', j('leaf.pem'), '-days', '20',
           '-extfile', j('l.ext'))

    def test_fullchain_and_chain(self):
        b = E.cert_bundle(cert=read('leaf.pem') + read('int.pem'), chain=read('int.pem'),
                          key=read('leaf.key'), root=read('root.pem'))
        self.assertEqual(len(E.PEM_CERT.findall(b['chain'])), 1)
        self.assertEqual(len(E.PEM_CERT.findall(b['root'])), 1)
        self.assertEqual(E.cert_info(b['chain'])['cn'], 'R7 Issuing')

    def test_leaf_again_with_crlf(self):
        leaf = read('leaf.pem')
        b = E.cert_bundle(cert=leaf + leaf.replace('\n', '\r\n'), chain=read('int.pem'),
                          key=read('leaf.key'), root=read('root.pem').replace('\n', '\r\n'))
        self.assertEqual(len(E.PEM_CERT.findall(b['chain'])), 1)
        self.assertEqual(E.cert_info(b['chain'])['cn'], 'R7 Issuing')
        self.assertEqual(len(E.PEM_CERT.findall(b['root'])), 1)
        self.assertNotIn('\r', b['cert'])


if __name__ == '__main__':
    unittest.main()
