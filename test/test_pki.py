#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests of the PKI of acme: keys, requests, certificates, own CAs, CRLs, every
import and export format. No root, no daemon: an in-memory SQLite database
stands in for the engine's Storage, the sealing key lives in a temporary
ACME_STATE.

    python3 test/test_pki.py [-v] [TestCase[.test_name]]
"""
import base64
import calendar
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
_STATE = tempfile.mkdtemp(prefix='acme-test-pki-')
os.environ['ACME_STATE'] = _STATE

from acmelib.certs import asn1 as A                         # noqa: E402
from acmelib.certs import bundle as B                       # noqa: E402
from acmelib.certs import ca as CA                          # noqa: E402
from acmelib.certs import formats as F                      # noqa: E402
from acmelib.certs import pki                               # noqa: E402
from acmelib.certs import schema                            # noqa: E402
from acmelib.certs.pki import PkiError                      # noqa: E402
from acmelib.plugins.base import Bundle, CertRequest, PluginError  # noqa: E402

LOGGED = []
CA._log = lambda words, level='info': LOGGED.append((level, words))

HAVE_KEYTOOL = bool(shutil.which('keytool'))


# ---------------------------------------------------------------------------
# A stand-in for the engine's Storage: .db with run/rows/row/value/insert/upsert
# ---------------------------------------------------------------------------
class MemDb(object):
    engine = 'sqlite'

    def __init__(self):
        from acmelib import engine as E
        self.c = sqlite3.connect(':memory:')
        self.c.row_factory = sqlite3.Row
        for _name, sql in schema.SCHEMA:
            self.c.execute(sql.format(**E.TYPES['sqlite']))
        for sql in schema.INDEXES:
            self.c.execute(sql)

    def __del__(self):
        try:
            self.c.close()
        except Exception:                               # noqa: BLE001
            pass

    def rows(self, sql, args=()):
        return [dict(r) for r in self.c.execute(sql, tuple(args))]

    def row(self, sql, args=()):
        got = self.rows(sql, args)
        return got[0] if got else None

    def value(self, sql, args=(), default=None):
        got = self.row(sql, args)
        return list(got.values())[0] if got else default

    def run(self, sql, args=()):
        return self.c.execute(sql, tuple(args)).rowcount

    def insert(self, table, row):
        keys = list(row)
        cur = self.c.execute('INSERT INTO %s (%s) VALUES (%s)' % (
            table, ', '.join(keys), ', '.join('?' for _ in keys)), [row[k] for k in keys])
        return cur.lastrowid

    def upsert(self, table, key, row):
        keys = list(row)
        rest = [k for k in keys if k != key]
        return self.run('INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s' % (
            table, ', '.join(keys), ', '.join('?' for _ in keys), key,
            ', '.join('%s = excluded.%s' % (k, k) for k in rest)), [row[k] for k in keys])


class MemStore(object):
    def __init__(self):
        self.db = MemDb()


class Ctx(object):
    def __init__(self, store=None):
        self.store = store
        self.steps = []

    def step(self, words, level='info'):
        self.steps.append((level, words))


def ossl(args, data=None, env=None):
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run(['openssl'] + args, input=data, capture_output=True, env=e)
    if p.returncode:
        raise AssertionError('openssl %s: %s' % (' '.join(args), p.stderr.decode()))
    return p.stdout


class Tmp(object):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-test-')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def w(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
        return p


_KEYS = {}


def key(kt='ec-256'):
    if kt not in _KEYS:
        _KEYS[kt] = pki.make_key(kt)
    return _KEYS[kt]


# ---------------------------------------------------------------------------
class TestAsn1(unittest.TestCase):
    def test_integers_oids_times(self):
        for n in (0, 1, 127, 128, 255, 256, -1, -128, -129, 2 ** 159, -(2 ** 70)):
            self.assertEqual(A.parse(A.integer(n)).int(), n)
        for o in ('1.2.840.113549.1.1.11', '2.5.29.17', '1.3.6.1.4.1.311.20.2.3', '2.999.1'):
            self.assertEqual(A.parse(A.oid(o)).oid(), o)
        t = 1700000000
        self.assertEqual(A.parse(A.utctime(t)).time(), t)
        self.assertEqual(A.parse(A.gentime(4102444800)).time(), 4102444800)
        self.assertEqual(A.parse(A.time_(4102444800)).tag, A.GENERALIZEDTIME)

    def test_indefinite_length(self):
        ber = bytes([0x30, 0x80]) + A.integer(5) + A.octets(b'x') + b'\x00\x00'
        n = A.parse(ber)
        self.assertEqual(n[0].int(), 5)
        self.assertEqual(n[1].octets(), b'x')
        self.assertEqual(n.end, len(ber))

    def test_bit_flags(self):
        der = A.bit_flags([0, 2, 5])
        self.assertEqual(A.parse(der).bit_list(), [0, 2, 5])


class TestKeys(unittest.TestCase):
    def test_every_key_type(self):
        bits = {'ec-256': 256, 'ec-384': 384, 'rsa-2048': 2048, 'rsa-3072': 3072,
                'rsa-4096': 4096, 'ed25519': 256}
        for kt in pki.KEY_TYPES:
            k = key(kt)
            self.assertIn('-----BEGIN PRIVATE KEY-----', k, kt)
            info = pki.key_info(k)
            self.assertEqual(info['key_type'], kt)
            self.assertEqual(info['key_bits'], bits[kt])
            self.assertEqual(len(info['pub_sha256']), 64)
            self.assertEqual(pki.key_plain(k), k)
            csr, der = pki.make_csr(k, ['k-%s.example.com' % kt])
            self.assertTrue(pki.csr_verify(csr))
            self.assertEqual(pki.csr_info(csr)['key_type'], kt)
            self.assertEqual(pki.csr_info(der)['sha256'], info['pub_sha256'])
            c = pki.self_signed(k, ['k-%s.example.com' % kt], days=2)
            self.assertTrue(pki.key_matches(c, k))
            self.assertEqual(pki.cert_info(c)['key_type'], kt)

    def test_unknown_key_type(self):
        with self.assertRaises(PkiError):
            pki.make_key('rsa-1024')
        with self.assertRaises(PkiError):
            pki.make_key('dsa')

    def test_encrypted_and_other_shapes(self):
        k = key('rsa-2048')
        enc = pki.key_encrypt(k, 'Heslo-ž1')
        self.assertIn('ENCRYPTED PRIVATE KEY', enc)
        self.assertEqual(pki.key_plain(enc, 'Heslo-ž1'), k)
        with self.assertRaises(pki.PasswordError):
            pki.key_plain(enc, 'wrong')
        with self.assertRaises(pki.PasswordError):
            pki.key_plain(enc)
        rsa1 = pki.key_traditional(k)
        self.assertIn('BEGIN RSA PRIVATE KEY', rsa1)
        self.assertEqual(pki.key_plain(rsa1), k)
        sec1 = pki.key_traditional(key('ec-256'))
        self.assertIn('BEGIN EC PRIVATE KEY', sec1)
        self.assertEqual(pki.key_plain(sec1), key('ec-256'))
        self.assertEqual(pki.key_plain(pki.key_der(k)), k)


class TestCsr(unittest.TestCase):
    def test_mixed_sans(self):
        names = ['www.example.com', 'example.com', '*.example.com', '192.0.2.10',
                 '2001:db8::1', 'admin@example.com', 'https://svc.example.com/x',
                 'IP:10.1.2.3', 'DNS:bücher.example', 'URI:urn:uuid:1234']
        csr, der = pki.make_csr(key(), names, subject={'O': 'Příklad s.r.o.', 'C': 'CZ',
                                                       'OU': ['a', 'b']},
                                must_staple=True, eku=['serverAuth', 'clientAuth'])
        self.assertTrue(pki.csr_verify(csr))
        info = pki.csr_info(csr)
        self.assertEqual(info['cn'], 'www.example.com')
        self.assertEqual(info['subject']['O'], 'Příklad s.r.o.')
        self.assertEqual([v for k, v in info['subject_list'] if k == 'OU'], ['a', 'b'])
        self.assertEqual(info['names'], ['www.example.com', 'example.com', '*.example.com',
                                         '192.0.2.10', '2001:db8::1', 'admin@example.com',
                                         'https://svc.example.com/x', '10.1.2.3',
                                         'xn--bcher-kva.example', 'urn:uuid:1234'])
        types = [t for t, _ in info['san']]
        self.assertEqual(types, ['DNS', 'DNS', 'DNS', 'IP', 'IP', 'email', 'URI', 'IP', 'DNS',
                                 'URI'])
        self.assertTrue(info['must_staple'])
        self.assertEqual(info['eku'], ['serverAuth', 'clientAuth'])
        self.assertEqual(der, pki.pem_to_der(csr))
        # openssl reads it the same
        txt = ossl(['req', '-noout', '-text'], csr.encode()).decode()
        self.assertIn('IP Address:2001:DB8:0:0:0:0:0:1', txt)
        self.assertIn('email:admin@example.com', txt)
        self.assertIn('TLS Feature', txt)

    def test_long_first_name_no_cn(self):
        long = 'a' * 60 + '.example.com'
        csr, _ = pki.make_csr(key(), [long, 'short.example.com'])
        info = pki.csr_info(csr)
        self.assertEqual(info['cn'], '')
        self.assertEqual(info['subject_dn'], '')
        self.assertEqual(info['names'][0], long)
        self.assertIn('critical', ossl(['req', '-noout', '-text'], csr.encode()).decode()
                      .split('Subject Alternative Name')[1][:20])

    def test_subject_string(self):
        csr, _ = pki.make_csr(key(), ['x.example'], subject='CN=Other,O=Acme\\, Inc.,C=CZ')
        info = pki.csr_info(csr)
        self.assertEqual(info['subject']['O'], 'Acme, Inc.')
        self.assertEqual(info['cn'], 'Other')
        self.assertEqual(info['subject_dn'], 'CN=Other,O=Acme\\, Inc.,C=CZ')


class TestCertInfo(Tmp, unittest.TestCase):
    def test_self_signed(self):
        c = pki.self_signed(key(), ['host.example', '10.0.0.1'], days=30, eku=['serverAuth'])
        i = pki.cert_info(c)
        self.assertEqual(i['cn'], 'host.example')
        self.assertEqual(i['names'], ['host.example', '10.0.0.1'])
        self.assertTrue(i['self_signed'])
        self.assertFalse(i['is_ca'])
        self.assertEqual(i['eku'], ['serverAuth'])
        self.assertEqual(i['key_usage'], ['digitalSignature'])
        self.assertEqual(i['version'], 3)
        self.assertEqual(i['sig_alg'], 'ecdsa-with-SHA256')
        self.assertAlmostEqual(i['not_after'] - i['not_before'], 30 * 86400, delta=5)
        der = pki.pem_to_der(c)
        self.assertEqual(i['sha256'], __import__('hashlib').sha256(der).hexdigest().upper())
        self.assertEqual(pki.cert_info(der)['sha256'], i['sha256'])
        # against openssl
        p = self.w('c.pem', c)
        self.assertEqual(ossl(['x509', '-in', p, '-noout', '-serial']).decode().strip(),
                         'serial=' + i['serial'])
        fp = ossl(['x509', '-in', p, '-noout', '-fingerprint', '-sha256']).decode()
        self.assertEqual(fp.split('=')[1].strip().replace(':', ''), i['sha256'])
        end = ossl(['x509', '-in', p, '-noout', '-enddate']).decode().strip().split('=')[1]
        self.assertEqual(i['not_after'], calendar.timegm(time.strptime(end,
                                                                       '%b %d %H:%M:%S %Y GMT')))
        self.assertFalse(pki.key_matches(c, key('ec-384')))
        tr = ossl(['x509', '-in', p, '-trustout', '-addtrust', 'serverAuth']).decode()
        self.assertIn('TRUSTED CERTIFICATE', tr)
        self.assertEqual(pki.cert_info(tr)['sha256'], i['sha256'])

    def test_split_pem(self):
        c = pki.self_signed(key(), ['a.example'])
        text = 'Bag Attributes\r\n  friendlyName: x\r\n' + c.replace('\n', '\r\n') + \
               'garbage between\r\n' + key()
        blocks = pki.split_pem(text.encode())
        self.assertEqual([b[0] for b in blocks], ['CERTIFICATE', 'PRIVATE KEY'])
        self.assertEqual(blocks[0][1], c)

    def test_ari_id_rfc9773(self):
        # RFC 9773 section 4.1: this keyIdentifier and serial 00:87:65:43:21
        # give aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE
        aki = '69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4'
        self.assertEqual(pki.ari_id(aki, bytes.fromhex('0087654321')),
                         'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE')
        self.assertEqual(pki.ari_id(aki, '87654321'), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE')
        # and from a real certificate with that AKI and serial
        cak = self.w('ca.key', key('ec-256'))
        self.w('ca.cnf', '[e]\nbasicConstraints=critical,CA:TRUE\nsubjectKeyIdentifier=%s\n'
                         'keyUsage=keyCertSign\n' % aki)
        ossl(['req', '-new', '-x509', '-key', cak, '-subj', '/CN=ARI CA', '-days', '2',
              '-config', os.path.join(self.d, 'ca.cnf'), '-extensions', 'e',
              '-out', os.path.join(self.d, 'ca.pem')])
        csr, _ = pki.make_csr(key('ec-384'), ['ari.example'])
        self.w('l.csr', csr)
        self.w('l.cnf', '[e]\nauthorityKeyIdentifier=keyid:always\n'
                        'subjectAltName=DNS:ari.example\n')
        ossl(['x509', '-req', '-in', os.path.join(self.d, 'l.csr'), '-CA',
              os.path.join(self.d, 'ca.pem'), '-CAkey', cak, '-set_serial', '0x87654321',
              '-days', '2', '-extfile', os.path.join(self.d, 'l.cnf'), '-extensions', 'e',
              '-out', os.path.join(self.d, 'l.pem')])
        with open(os.path.join(self.d, 'l.pem')) as f:
            info = pki.cert_info(f.read())
        self.assertEqual(info['aki'], aki.replace(':', ''))
        self.assertEqual(info['serial'], '87654321')
        self.assertEqual(info['ari_id'], 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE')


class TestCa(Tmp, unittest.TestCase):
    def setUp(self):
        Tmp.setUp(self)
        self.store = MemStore()
        self.root = CA.ca_create(self.store, 'Root', {'CN': 'Test Root CA', 'O': 'Zkouška',
                                                      'C': 'CZ'},
                                 key_type='ec-384', days=3650, path_len=1,
                                 crl_url='http://pki.example/root.crl',
                                 aia_url='http://pki.example/root.crt', by='test')
        self.sub = CA.ca_create(self.store, 'Issuing', 'Test Issuing CA', key_type='ec-256',
                                days=1825, parent_id=self.root,
                                crl_url='http://pki.example/sub.crl',
                                aia_url='http://pki.example/sub.crt',
                                ocsp_url='http://ocsp.example', by='test')

    def leaf(self, names=None, profile=None, days=90, kt='ec-256'):
        csr, _ = pki.make_csr(key(kt), names or ['www.example.com', '192.0.2.1'])
        return CA.ca_sign(self.store, self.sub, csr, days, profile, cert_id=7, by='test')

    def test_chain_verifies(self):
        root = CA.ca_get(self.store, self.root)
        sub = CA.ca_get(self.store, self.sub)
        self.assertTrue(root['root'])
        self.assertFalse(sub['root'])
        self.assertTrue(root['key_set'])
        self.assertNotIn('key_sealed', root)
        self.assertEqual(root['info']['path_len'], 1)
        self.assertEqual(sub['info']['path_len'], 0)
        self.assertEqual(sub['info']['crl'], ['http://pki.example/root.crl'])
        self.assertEqual(sub['info']['ca_issuers'], ['http://pki.example/root.crt'])
        self.assertEqual(sub['info']['aki'], root['info']['ski'])
        self.assertEqual(sub['chain'], [root['cert_pem']])
        cert, chain = self.leaf()
        self.assertEqual(chain, [sub['cert_pem'], root['cert_pem']])
        i = pki.cert_info(cert)
        self.assertEqual(len(i['serial']), 40)
        self.assertEqual(i['names'], ['www.example.com', '192.0.2.1'])
        self.assertEqual(i['eku'], ['serverAuth', 'clientAuth'])
        self.assertEqual(i['crl'], ['http://pki.example/sub.crl'])
        self.assertEqual(i['ocsp'], ['http://ocsp.example'])
        self.assertEqual(i['ca_issuers'], ['http://pki.example/sub.crt'])
        self.assertEqual(i['aki'], sub['info']['ski'])
        self.assertTrue(i['ari_id'].startswith(base64.urlsafe_b64encode(
            bytes.fromhex(sub['info']['ski'])).decode().rstrip('=') + '.'))
        self.assertLess(i['not_before'], time.time() - 3000)       # backdated an hour
        ok, words = pki.verify_chain(cert, chain[:1], [root['cert_pem']])
        self.assertTrue(ok, words)
        ok, words = pki.verify_chain(cert, [], [root['cert_pem']])
        self.assertFalse(ok)
        self.assertIn('issuer', words)
        other = pki.self_signed(key('ec-384'), [], {'CN': 'Stranger'}, is_ca=True)
        self.assertFalse(pki.verify_chain(cert, chain[:1], [other])[0])
        self.assertTrue(pki.verify_chain(cert, [], [sub['cert_pem']])[0])   # partial chain
        self.assertFalse(pki.verify_chain(cert, chain, None)[0])   # not in the system's store
        row = self.store.db.row('SELECT * FROM cert_ca_issued WHERE serial = ?', (i['serial'],))
        self.assertEqual(row['cert_id'], 7)
        self.assertEqual(json.loads(row['names']), ['www.example.com', '192.0.2.1'])
        # order_chain: shuffled, duplicated, with a stranger and the leaf itself
        self.assertEqual(pki.order_chain(cert, [root['cert_pem'], other, cert, sub['cert_pem'],
                                                root['cert_pem']]),
                         [sub['cert_pem'], root['cert_pem']])

    def test_profiles(self):
        cert, _ = self.leaf(['client-1'], {'eku': ['clientAuth'], 'subject': {
            'CN': 'Jan Novák', 'O': 'Zkouška', 'emailAddress': 'jan@example.com'},
            'names': ['jan@example.com'], 'must_staple': True}, kt='rsa-2048')
        i = pki.cert_info(cert)
        self.assertEqual(i['subject']['CN'], 'Jan Novák')
        self.assertEqual(i['names'], ['jan@example.com'])
        self.assertEqual(i['eku'], ['clientAuth'])
        self.assertEqual(i['key_usage'], ['digitalSignature', 'keyEncipherment'])
        self.assertTrue(i['must_staple'])
        # days are cut at the end of the authority
        cert, _ = self.leaf(days=100000)
        self.assertLessEqual(pki.cert_info(cert)['not_after'],
                             CA.ca_get(self.store, self.sub)['not_after'])

    def test_path_len_and_name_constraints(self):
        with self.assertRaises(PkiError):       # Issuing has pathlen 0
            CA.ca_create(self.store, 'Too deep', 'Too deep', parent_id=self.sub)
        with self.assertRaises(PkiError):
            CA.ca_create(self.store, 'Too long', 'x', parent_id=self.root, path_len=3)
        nc = CA.ca_create(self.store, 'Corp', 'Corp CA', key_type='ec-256', parent_id=self.root,
                          name_constraints=['corp.example', 'IP:10.0.0.0/8',
                                            '!DNS:bad.corp.example'])
        info = CA.ca_get(self.store, nc)['info']
        self.assertEqual(info['name_constraints']['permitted'],
                         ['DNS:corp.example', 'IP:10.0.0.0/8'])
        csr, _ = pki.make_csr(key(), ['a.corp.example', '10.1.1.1'])
        cert, chain = CA.ca_sign(self.store, nc, csr, 30)
        self.assertTrue(pki.verify_chain(cert, chain[:-1], chain[-1:])[0])
        for bad in (['www.example.com'], ['x.bad.corp.example'], ['192.168.1.1']):
            with self.assertRaises(PkiError):
                CA.ca_sign(self.store, nc, pki.make_csr(key(), bad)[0], 30)

    def test_sub_ca_by_profile_and_external(self):
        # A sub-CA signed through ca_sign (is_ca), installed for a ca_csr request.
        ident, csr = CA.ca_csr(self.store, 'Pending', {'CN': 'Pending CA', 'O': 'X'})
        self.assertTrue(CA.ca_get(self.store, ident)['pending'])
        self.assertEqual(CA.ca_export(self.store, ident, 'csr')['data'].decode(), csr)
        with self.assertRaises(PkiError):
            CA.ca_sign(self.store, ident, pki.make_csr(key(), ['x.example'])[0], 10)
        self.assertTrue(pki.csr_info(csr)['subject']['CN'] == 'Pending CA')
        root2 = CA.ca_create(self.store, 'Root2', 'Second Root', key_type='ec-256')
        cert, chain = CA.ca_sign(self.store, root2, csr, 365, {'is_ca': True, 'path_len': 0})
        self.assertTrue(pki.cert_info(cert)['is_ca'])
        CA.ca_install_cert(self.store, ident, cert + ''.join(chain))
        got = CA.ca_get(self.store, ident)
        self.assertFalse(got['pending'])
        self.assertEqual(got['parent_id'], root2)
        self.assertEqual(got['external'], 0)
        leaf, lchain = CA.ca_sign(self.store, ident, pki.make_csr(key(), ['p.example'])[0], 30)
        self.assertTrue(pki.verify_chain(leaf, lchain[:-1], lchain[-1:])[0])
        # An intermediate signed by a CA that is not acme's: external.
        ext_key = key('ec-384')
        ext_root = pki.self_signed(ext_key, [], {'CN': 'Corporate Root'}, is_ca=True, days=99)
        ident2, csr2 = CA.ca_csr(self.store, 'UnderCorp', 'Under Corporate')
        self.w('r.pem', ext_root)
        self.w('r.key', ext_key)
        self.w('c.csr', csr2)
        self.w('e.cnf', '[e]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,'
                        'keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n'
                        'authorityKeyIdentifier=keyid\n')
        der = ossl(['x509', '-req', '-in', os.path.join(self.d, 'c.csr'), '-CA',
                    os.path.join(self.d, 'r.pem'), '-CAkey', os.path.join(self.d, 'r.key'),
                    '-days', '30', '-extfile', os.path.join(self.d, 'e.cnf'), '-extensions', 'e',
                    '-outform', 'DER'])
        CA.ca_install_cert(self.store, ident2, der, [ext_root])
        got = CA.ca_get(self.store, ident2)
        self.assertEqual(got['external'], 1)
        self.assertIsNone(got['parent_id'])
        self.assertEqual(got['chain'], [pki.cert_pem(ext_root)])
        # The days of what it signs end with it (30 days).
        leaf, lchain = CA.ca_sign(self.store, ident2, pki.make_csr(key(), ['u.example'])[0], 90)
        self.assertLessEqual(pki.cert_info(leaf)['not_after'], got['not_after'])
        self.assertTrue(pki.verify_chain(leaf, lchain[:1], [ext_root])[0])

    def test_crl(self):
        cert, chain = self.leaf()
        cert2, _ = self.leaf(['other.example'])
        serial = pki.cert_info(cert)['serial']
        crl0 = CA.ca_get(self.store, self.sub)['crl_pem']
        self.assertEqual(pki.crl_info(crl0)['revoked'], [])
        n0 = pki.crl_info(crl0)['number']
        crl = CA.ca_revoke(self.store, self.sub, ':'.join(serial[i:i + 2] for i in
                                                          range(0, len(serial), 2)).lower(),
                           'key_compromise', by='test')
        info = pki.crl_info(crl)
        self.assertEqual([r['serial'] for r in info['revoked']], [serial])
        self.assertEqual(info['revoked'][0]['reason'], 'keyCompromise')
        self.assertEqual(info['number'], n0 + 1)
        self.assertEqual(info['aki'], CA.ca_get(self.store, self.sub)['info']['ski'])
        self.assertAlmostEqual(info['next_update'] - info['this_update'], 7 * 86400, delta=5)
        self.assertEqual(CA.ca_get(self.store, self.sub)['crl_pem'], crl)
        # openssl agrees: the CRL is signed by the CA, the leaf fails a CRL check, the other not
        p = self.w('crl.pem', crl)
        sub_pem = self.w('sub.pem', chain[0])
        self.assertIn(b'verify OK', subprocess.run(
            ['openssl', 'crl', '-in', p, '-CAfile', sub_pem, '-noout'],
            capture_output=True).stderr)
        allc = self.w('all.pem', ''.join(chain))
        crls = self.w('crls.pem', crl + CA.ca_crl(self.store, self.root))
        r = subprocess.run(['openssl', 'verify', '-crl_check', '-CAfile', allc, '-CRLfile', crls,
                            self.w('leaf.pem', cert)], capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b'revoked', r.stdout + r.stderr)
        r = subprocess.run(['openssl', 'verify', '-crl_check', '-CAfile', allc, '-CRLfile', crls,
                            self.w('leaf2.pem', cert2)], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # hold, then release
        s2 = pki.cert_info(cert2)['serial']
        CA.ca_revoke(self.store, self.sub, s2, 'certificateHold')
        self.assertEqual(len(pki.crl_info(CA.ca_get(self.store, self.sub)['crl_pem'])['revoked']),
                         2)
        crl = CA.ca_unrevoke(self.store, self.sub, s2)
        self.assertEqual([r['serial'] for r in pki.crl_info(crl)['revoked']], [serial])
        with self.assertRaises(PkiError):
            CA.ca_unrevoke(self.store, self.sub, serial)
        with self.assertRaises(PkiError):
            CA.ca_revoke(self.store, self.sub, 'ABCDEF', 'superseded')
        with self.assertRaises(PkiError):
            CA.ca_revoke(self.store, self.sub, serial, 'because')
        self.assertFalse(CA.crl_due(self.store, self.sub))

    def test_list_delete_export(self):
        self.leaf()
        lst = CA.ca_list(self.store)
        self.assertEqual([r['name'] for r in lst], ['Root', 'Issuing'])
        self.assertEqual(lst[0]['children'], [self.sub])
        self.assertEqual(lst[1]['depth'], 1)
        self.assertEqual(lst[1]['parent_name'], 'Root')
        self.assertEqual(lst[0]['issued'], 1)       # the intermediate
        self.assertEqual(lst[1]['issued'], 1)
        self.assertTrue(lst[1]['valid'])
        self.assertEqual(len(CA.ca_issued(self.store, self.sub)), 1)
        with self.assertRaises(PkiError):
            CA.ca_delete(self.store, self.root)
        with self.assertRaises(PkiError):
            CA.ca_create(self.store, 'Root', 'dup')
        for what in ('cert', 'cert-der', 'chain', 'crl', 'crl-der', 'p7b', 'bundle', 'key'):
            out = CA.ca_export(self.store, self.sub, what)
            self.assertTrue(out['data'] and out['filename'] and out['mime'], what)
            if what not in ('crl', 'crl-der', 'bundle', 'key'):
                got = F.read_any(out['data'], out['filename'])
                self.assertEqual(got['leaf'], CA.ca_get(self.store, self.sub)['cert_pem'], what)
        z = zipfile.ZipFile(io.BytesIO(CA.ca_export(self.store, self.sub, 'bundle')['data']))
        self.assertEqual(sorted(z.namelist()), ['Issuing-chain.pem', 'Issuing.crl',
                                                'Issuing.crl.pem', 'Issuing.crt'])
        p12 = CA.ca_export(self.store, self.sub, 'p12', password='pw123456')['data']
        got = F.read_any(p12, 'x.p12', 'pw123456')
        self.assertTrue(got['key'] and pki.key_matches(got['leaf'], got['key']))
        self.assertEqual(len(got['chain']), 1)
        enc = CA.ca_export(self.store, self.sub, 'key', password='pw')['data'].decode()
        self.assertIn('ENCRYPTED', enc)
        CA.ca_delete(self.store, self.sub)
        self.assertEqual(self.store.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ?',
                                             (self.sub,)), 0)
        self.assertEqual([r['name'] for r in CA.ca_list(self.store)], ['Root'])

    def test_sealed_key(self):
        row = self.store.db.row('SELECT key_sealed FROM cert_cas WHERE id = ?', (self.root,))
        self.assertTrue(row['key_sealed'].startswith('sealed:2:'))
        self.assertNotIn('PRIVATE', row['key_sealed'])
        # copied into another row, it does not open
        self.store.db.run('UPDATE cert_cas SET key_sealed = ? WHERE id = ?',
                          (row['key_sealed'], self.sub))
        with self.assertRaises(PkiError):
            self.leaf()

    def test_import_and_ed25519(self):
        k = key('rsa-3072')
        root = pki.self_signed(k, [], {'CN': 'Imported Root', 'O': 'Elsewhere'}, is_ca=True,
                               days=400)
        enc = pki.key_encrypt(k, 'tajné')
        with self.assertRaises(pki.PasswordError):
            CA.ca_import(self.store, 'Imp', root, enc)
        with self.assertRaises(PkiError):
            CA.ca_import(self.store, 'Imp', root, key('ec-256'))
        with self.assertRaises(PkiError):
            CA.ca_import(self.store, 'Imp', pki.self_signed(key(), ['leaf.example']), key())
        ident = CA.ca_import(self.store, 'Imp', root, enc, password='tajné', by='test')
        got = CA.ca_get(self.store, ident)
        self.assertEqual(got['external'], 0)
        self.assertTrue(got['root'])
        cert, chain = CA.ca_sign(self.store, ident, pki.make_csr(key(), ['i.example'])[0], 30)
        self.assertTrue(pki.verify_chain(cert, [], chain)[0])
        self.assertEqual(pki.cert_info(cert)['sig_alg'], 'sha256WithRSAEncryption')
        ed = CA.ca_create(self.store, 'Ed', 'Ed25519 Root', key_type='ed25519')
        cert, chain = CA.ca_sign(self.store, ed, pki.make_csr(key('ed25519'), ['e.example'])[0],
                                 30)
        self.assertEqual(pki.cert_info(cert)['sig_alg'], 'ED25519')
        self.assertTrue(pki.verify_chain(cert, [], chain)[0])
        CA.ca_revoke(self.store, ed, pki.cert_info(cert)['serial'], 'superseded')
        self.assertEqual(len(pki.crl_info(CA.ca_get(self.store, ed)['crl_pem'])['revoked']), 1)


class TestFormats(Tmp, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = MemStore()
        r = CA.ca_create(cls.store, 'R', 'Format Root', key_type='ec-256')
        s = CA.ca_create(cls.store, 'S', 'Format Sub', key_type='ec-256', parent_id=r)
        cls.key = key('rsa-2048')
        cls.cert, cls.chain = CA.ca_sign(cls.store, s, pki.make_csr(
            cls.key, ['fmt.example', 'www.fmt.example'])[0], 30)
        cls.ekey = key('ec-256')
        cls.ecert, cls.echain = CA.ca_sign(cls.store, s, pki.make_csr(
            cls.ekey, ['ec.fmt.example'])[0], 30)

    def check(self, got, key=True, chain=2):
        self.assertEqual(got['leaf'], self.cert)
        self.assertEqual(got['chain'], self.chain[:chain])
        if key:
            self.assertEqual(got['key'], self.key)
        self.assertFalse(got['needs_password'])

    def test_every_bundle_format_round_trips(self):
        b = B.CertBundle('fmt', self.cert, self.key, self.chain)
        self.assertIsInstance(b, Bundle)
        self.assertEqual(b.names, ['fmt.example', 'www.fmt.example'])
        self.assertEqual(b.serial, pki.cert_info(self.cert)['serial'])
        self.assertEqual(b.fingerprint, pki.cert_info(self.cert)['sha256'])
        self.assertEqual(b.fullchain_pem, self.cert + ''.join(self.chain))
        for fmt in B.CertBundle.FORMATS:
            data = b.as_format(fmt, password='Secret-123', alias='My Alias')
            self.assertIsInstance(data, bytes, fmt)
            got = F.read_any(data, b.filename(fmt), 'Secret-123' if fmt in (
                'pfx', 'p12', 'p12-legacy', 'jks', 'key-pem-enc') else '')
            if fmt in ('cert-pem', 'cert-der'):
                self.assertEqual(got['certs'], [self.cert], fmt)
            elif fmt in ('key-pem', 'key-rsa', 'key-der', 'key-pem-enc', 'key-traditional'):
                self.assertEqual(got['keys'], [self.key], fmt)
                self.assertIsNone(got['leaf'])
            elif fmt == 'chain-pem':
                self.assertEqual(got['certs'], self.chain)
                self.assertEqual(got['leaf'], self.chain[0])
            elif fmt in ('fullchain-pem', 'p7b', 'p7b-pem'):
                self.check(got, key=False)
            else:                       # combined-pem pfx p12 p12-legacy jks
                self.check(got)
            if fmt in ('p12', 'pfx', 'p12-legacy'):
                self.assertEqual(got['format'], 'pkcs12')
                self.assertIn('My Alias', got['aliases'])
            if fmt == 'jks':
                self.assertEqual(got['format'], 'jks')
                self.assertEqual(got['aliases'], ['my alias'])
        self.assertIn(b'BEGIN RSA PRIVATE KEY', b.as_format('key-rsa'))
        # p12: AES-256 modern, 3DES legacy
        info = subprocess.run(['openssl', 'pkcs12', '-info', '-noout', '-passin', 'env:PW'],
                              input=b.as_format('p12', 'pw'), capture_output=True,
                              env=dict(os.environ, PW='pw')).stderr.decode()
        self.assertIn('AES-256-CBC', info)
        self.assertIn('sha256', info.lower())
        info = subprocess.run(['openssl', 'pkcs12', '-info', '-noout', '-passin', 'env:PW'],
                              input=b.as_format('p12-legacy', 'pw'), capture_output=True,
                              env=dict(os.environ, PW='pw')).stderr.decode()
        self.assertIn('3-KeyTripleDES', info)
        self.assertIn('sha1', info.lower())
        # p7b is DER that openssl reads
        out = ossl(['pkcs7', '-inform', 'DER', '-print_certs'], b.as_format('p7b')).decode()
        self.assertEqual(pki.certs_in(out), [self.cert] + self.chain)

    def test_bundle_refusals(self):
        b = B.CertBundle('ec', self.ecert, self.ekey, self.echain)
        with self.assertRaises(PkiError):
            b.as_format('key-rsa')
        with self.assertRaises(PkiError):
            b.as_format('jks')
        with self.assertRaises(PkiError):
            b.as_format('nothing')
        nokey = B.CertBundle('nokey', self.ecert, None, self.echain)
        with self.assertRaises(PkiError):
            nokey.as_format('p12', 'x')
        self.assertTrue(nokey.as_format('p7b'))
        self.assertIn(b'BEGIN EC PRIVATE KEY', b.as_format('key-traditional'))
        got = F.read_any(b.as_format('jks', 'changeit'), 'x.jks', 'changeit')
        self.assertEqual(got['leaf'], self.ecert)
        self.assertEqual(got['key'], self.ekey)

    def test_openssl_pfx_modern_and_legacy(self):
        k, c = self.w('k.pem', self.key), self.w('c.pem', self.cert)
        ch = self.w('ch.pem', ''.join(self.chain))
        for extra in ([], ['-legacy'], ['-descert']):
            der = ossl(['pkcs12', '-export', '-inkey', k, '-in', c, '-certfile', ch,
                        '-passout', 'env:PW', '-name', 'pfx-alias'] + extra,
                       env={'PW': 'p@ss wörd'})
            got = F.read_any(der, 'x.pfx', 'p@ss wörd')
            self.check(got)
            self.assertEqual(got['format'], 'pkcs12')
            if extra == ['-legacy']:
                self.assertTrue(any('legacy' in n for n in got['notes']), got['notes'])
            got = F.read_any(der, 'x.pfx', 'wrong')
            self.assertTrue(got['needs_password'])
            self.assertIsNone(got['key'])
            got = F.read_any(der, 'x.pfx')
            self.assertTrue(got['needs_password'])
        # no password at all
        der = ossl(['pkcs12', '-export', '-inkey', k, '-in', c, '-passout', 'pass:'])
        got = F.read_any(der, 'x.pfx')
        self.assertEqual(got['key'], self.key)

    def test_p7b(self):
        allc = self.w('all.pem', self.cert + ''.join(reversed(self.chain)))
        for form in ('PEM', 'DER'):
            data = ossl(['crl2pkcs7', '-nocrl', '-certfile', allc, '-outform', form])
            got = F.read_any(data, 'x.p7b')
            self.assertEqual(got['format'], 'pkcs7')
            self.check(got, key=False)
        # BER with indefinite lengths (as Java and some Windows tools write)
        der = ossl(['crl2pkcs7', '-nocrl', '-certfile', allc, '-outform', 'DER'])
        n = A.parse(der)
        sd = n[1][0]
        inner = b''.join(c.raw for c in sd)
        ber = bytes([0x30, 0x80]) + n[0].raw + bytes([0xa0, 0x80, 0x30, 0x80]) + inner + \
            b'\x00\x00\x00\x00\x00\x00'
        got = F.read_any(ber, 'x.p7c')
        self.check(got, key=False)
        # base64 without the PEM lines
        got = F.read_any(base64.encodebytes(der), 'x.p7b')
        self.check(got, key=False)

    def test_pem_bundle_windows_and_text(self):
        text = ('Here is your certificate\r\n' + self.cert.replace('\n', '\r\n') +
                '\r\nintermediate:\r\n' + self.chain[1] + self.chain[0].replace('\n', '\r\n') +
                '\r\n' + pki.key_traditional(self.key) + 'thanks\r\n')
        got = F.read_any(text.encode(), 'bundle.crt')
        self.check(got)
        self.assertEqual(got['format'], 'pem')
        self.assertEqual(got['info']['cn'], 'fmt.example')
        json.dumps(got['info'])

    def test_der_and_encrypted_keys(self):
        got = F.read_any(pki.pem_to_der(self.cert), 'x.cer')
        self.assertEqual(got['format'], 'der')
        self.assertEqual(got['leaf'], self.cert)
        for data, fmt in ((pki.key_der(self.key), 'pkcs8'),
                          (pki.pem_to_der(pki.key_traditional(self.key)), 'pkcs1'),
                          (pki.pem_to_der(pki.key_traditional(self.ekey)), 'sec1')):
            got = F.read_any(data, 'x.key')
            self.assertEqual(got['format'], fmt)
            self.assertIn(got['keys'][0], (self.key, self.ekey))
        enc = pki.key_encrypt(self.key, 'pw')
        got = F.read_any(enc.encode(), 'x.key')
        self.assertTrue(got['needs_password'])
        self.assertEqual(got['format'], 'pkcs8-encrypted')
        got = F.read_any(enc.encode(), 'x.key', 'pw')
        self.assertEqual(got['keys'], [self.key])
        got = F.read_any(pki.pem_to_der(enc), 'x.key', 'pw')
        self.assertEqual(got['format'], 'pkcs8-encrypted')
        self.assertEqual(got['keys'], [self.key])
        # the old OpenSSL encrypted PEM (Proc-Type: 4,ENCRYPTED)
        legacy = ossl(['pkey', '-traditional', '-aes128', '-passout', 'env:PW'],
                      self.key.encode(), env={'PW': 'pw'}).decode()
        self.assertIn('Proc-Type: 4,ENCRYPTED', legacy)
        got = F.read_any((self.cert + legacy).encode(), 'x.pem', 'pw')
        self.check(got, chain=0)
        got = F.read_any((self.cert + legacy).encode(), 'x.pem')
        self.assertTrue(got['needs_password'])
        self.assertIsNone(got['key'])

    def test_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('site/cert.cer', pki.pem_to_der(self.cert))
            z.writestr('site/chain.p7b', B.p7b_der(self.chain))
            z.writestr('site/private.key', self.key)
            z.writestr('__MACOSX/._x', b'junk')
            z.writestr('readme.txt', 'nothing here')
        got = F.read_any(buf.getvalue(), 'x.zip')
        self.assertEqual(got['format'], 'zip')
        self.check(got)

    def test_leaf_choice_without_key(self):
        got = F.read_any((self.chain[1] + self.chain[0] + self.cert + self.ecert).encode())
        self.assertEqual(got['leaf'], self.cert)
        self.assertEqual(got['others'], [self.ecert])
        got = F.read_any((self.chain[1] + self.ecert + self.chain[0] + self.cert +
                          self.ekey).encode())
        self.assertEqual(got['leaf'], self.ecert)
        self.assertEqual(got['key'], self.ekey)
        got = F.read_any(''.join(self.chain).encode())
        self.assertEqual(got['leaf'], self.chain[0])

    def test_rubbish(self):
        for data in (b'', b'hello world', b'\x30\x03\x02\x01'):
            with self.assertRaises(PkiError):
                F.read_any(data, 'x.bin')

    def test_des_vectors(self):
        # FIPS 46 / the classic test vector: one DES block, K = 133457799BBCDFF1
        subs = F._des_subkeys(bytes.fromhex('133457799BBCDFF1'))
        self.assertEqual(F._des_block(bytes.fromhex('0123456789ABCDEF'), subs).hex().upper(),
                         '85E813540F0AB405')
        k, iv = os.urandom(24), os.urandom(8)
        for n in (0, 1, 7, 8, 9, 100):
            msg = os.urandom(n)
            c = F.des3_cbc_encrypt(k, iv, msg)
            self.assertEqual(F.des3_cbc_decrypt(k, iv, c), msg)
            self.assertEqual(c, ossl(['enc', '-des-ede3-cbc', '-K', k.hex(), '-iv', iv.hex()],
                                     msg))

    def test_jks_parse_details(self):
        data = F.jks_write(self.ekey, [self.ecert] + self.echain, 'changeit', 'A',
                           trusted=[('root', self.echain[-1])])
        ks = F.jks_parse(data, 'changeit')
        self.assertTrue(ks['ok'])
        self.assertEqual([e['kind'] for e in ks['entries']], ['key', 'cert'])
        self.assertEqual(len(ks['entries'][0]['certs']), 3)
        self.assertFalse(F.jks_parse(data, 'nope')['ok'])
        got = F.read_any(data, 'x.jks')
        self.assertTrue(got['needs_password'])
        self.assertEqual(got['leaf'], self.ecert)      # certificates are read without it

    @unittest.skipUnless(HAVE_KEYTOOL, 'keytool is not installed')
    def test_keytool_interop(self):
        # Ours read by Java ...
        p = self.w('ours.jks', B.CertBundle('x', self.cert, self.key, self.chain)
                   .as_format('jks', 'changeit', 'web'))
        out = subprocess.run(['keytool', '-list', '-v', '-keystore', p, '-storepass', 'changeit'],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('PrivateKeyEntry', out.stdout)
        self.assertIn('Certificate chain length: 3', out.stdout)
        # ... and the key in it opened by Java (exported to PKCS#12)
        p12 = os.path.join(self.d, 'ours.p12')
        out = subprocess.run(['keytool', '-importkeystore', '-srckeystore', p, '-srcstorepass',
                              'changeit', '-destkeystore', p12, '-deststoretype', 'PKCS12',
                              '-deststorepass', 'changeit'], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(p12, 'rb') as f:
            self.check(F.read_any(f.read(), 'ours.p12', 'changeit'))
        # Java's JKS and JCEKS read by us
        for st in ('JKS', 'JCEKS'):
            ks = os.path.join(self.d, 'java.' + st.lower())
            out = subprocess.run(['keytool', '-importkeystore', '-srckeystore', p12,
                                  '-srcstoretype', 'PKCS12', '-srcstorepass', 'changeit',
                                  '-destkeystore', ks, '-deststoretype', st, '-deststorepass',
                                  'changeit', '-destkeypass', 'changeit'],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            with open(ks, 'rb') as f:
                got = F.read_any(f.read(), 'java.' + st.lower(), 'changeit')
            self.assertEqual(got['format'], st.lower())
            self.check(got)


class TestPlugins(unittest.TestCase):
    def test_internal_ca(self):
        from acmelib.plugins.issuers.internal_ca import InternalCaIssuer
        store = MemStore()
        r = CA.ca_create(store, 'Plug Root', 'Plug Root', key_type='ec-256')
        d = InternalCaIssuer.describe()
        self.assertEqual(d['kind'], 'internal_ca')
        self.assertEqual([f for f in d['fields'] if f['key'] == 'ca'][0]['options_from'], 'cas')
        iss = InternalCaIssuer({'ca': str(r), 'days': 10, 'eku': 'serverAuth'}, Ctx(store))
        self.assertIn('can sign', iss.test())
        k = key()
        csr_pem, csr_der = pki.make_csr(k, ['p.example', '10.9.8.7'])
        out = iss.issue(CertRequest(names=['p.example', '10.9.8.7'], key_pem=k, csr_pem=csr_pem,
                                    csr_der=csr_der, cert_id=3))
        i = pki.cert_info(out.cert_pem)
        self.assertEqual(i['names'], ['p.example', '10.9.8.7'])
        self.assertEqual(i['eku'], ['serverAuth'])
        self.assertAlmostEqual(i['not_after'] - time.time(), 10 * 86400, delta=60)
        self.assertEqual(out.chain_pems, [CA.ca_get(store, r)['cert_pem']])
        self.assertEqual(out.info['ari_id'], i['ari_id'])
        # without a CSR, with a key; then revoke
        out = iss.issue(CertRequest(names=['q.example'], key_pem=k, days=5))
        iss.revoke(out.cert_pem, 'superseded')
        crl = pki.crl_info(CA.ca_get(store, r)['crl_pem'])
        self.assertEqual(crl['revoked'][0]['serial'], pki.cert_info(out.cert_pem)['serial'])
        with self.assertRaises(PluginError):
            InternalCaIssuer({'ca': ''}, Ctx(store)).issue(CertRequest(names=['x'], key_pem=k))
        with self.assertRaises(PluginError):
            InternalCaIssuer({'ca': str(r)}, Ctx(None)).issue(CertRequest(names=['x'],
                                                                         key_pem=k))

    def test_selfsigned(self):
        from acmelib.plugins.issuers.selfsigned import SelfSignedIssuer
        k = key('rsa-2048')
        out = SelfSignedIssuer({'days': 3}, Ctx()).issue(CertRequest(
            names=['s.example', '*.s.example'], key_pem=k, profile={'eku': ['clientAuth']}))
        i = pki.cert_info(out.cert_pem)
        self.assertTrue(i['self_signed'])
        self.assertEqual(i['names'], ['s.example', '*.s.example'])
        self.assertEqual(i['eku'], ['clientAuth'])
        self.assertTrue(pki.key_matches(out.cert_pem, k))
        self.assertEqual(out.chain_pems, [])
        self.assertAlmostEqual(i['not_after'] - i['not_before'], 3 * 86400, delta=5)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2 if '-v' in sys.argv else 1)
    finally:
        shutil.rmtree(_STATE, ignore_errors=True)
