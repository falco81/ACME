#!/usr/bin/env python3
"""Show a certificate (1.0.23): acmelib/certs/certview.py - any file read and described.

    python3 test/test_inspect.py

No daemon, no network: a root, an intermediate and a leaf are made here with
openssl, then given in every form a certificate comes in - PEM (the chain out
of order), DER, PKCS#7, PKCS#12 (modern and legacy, a wrong password), JKS
and JCEKS (made with keytool when it is installed; a JKS also with acme's own
writer), a CSR, a CRL, a private key (never sent back), a public key, base64
without its lines, a ZIP and a broken file. The chain is ordered and each of
its links checked; a forged link is caught.
"""
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.certs import certview, formats, pki   # noqa: E402
from acmelib.certs.pki import PkiError             # noqa: E402

HAVE_KEYTOOL = bool(shutil.which('keytool'))


def read(path):
    with open(path) as f:
        return f.read()


def run(*args, data=None):
    p = subprocess.run(['openssl'] + list(args), input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(p.stderr.decode())
    return p.stdout


class Inspect(unittest.TestCase):
    @classmethod
    def P_(cls, name):
        return os.path.join(cls.d, name)

    def P(self, name):
        return os.path.join(self.d, name)

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='acme-inspect-')
        P = cls.P_
        with open(P('ca.cnf'), 'w') as f:
            f.write('[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
                    'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
                    'certificatePolicies=2.23.140.1.2.1\n'
                    '[int]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n'
                    'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n'
                    'authorityKeyIdentifier=keyid\ncrlDistributionPoints=URI:http://crl.example.test/root.crl\n'
                    '[leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                    'extendedKeyUsage=serverAuth,clientAuth\n'
                    'subjectAltName=DNS:www.example.test,DNS:example.test,IP:192.0.2.7,email:a@example.test\n'
                    'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
                    'authorityInfoAccess=OCSP;URI:http://ocsp.example.test,caIssuers;URI:http://ca.example.test/int.crt\n'
                    'certificatePolicies=2.23.140.1.2.2\ntlsfeature=status_request\n'
                    '1.2.3.4.5.6=DER:0403010203\n'
                    '[noaki]\nbasicConstraints=CA:FALSE\nsubjectAltName=DNS:www.example.test\n'
                    'authorityKeyIdentifier=none\nsubjectKeyIdentifier=none\n')
        run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', P('root.key'))
        run('req', '-new', '-key', P('root.key'), '-subj', '/C=CZ/O=Test Root Org/CN=Test Root',
            '-out', P('root.csr'))
        run('x509', '-req', '-in', P('root.csr'), '-signkey', P('root.key'), '-days', '3650',
            '-extfile', P('ca.cnf'), '-extensions', 'ca', '-out', P('root.pem'))
        run('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', P('int.key'))
        run('req', '-new', '-key', P('int.key'), '-subj', '/C=CZ/O=Test Root Org/CN=Test Issuing CA',
            '-out', P('int.csr'))
        run('x509', '-req', '-in', P('int.csr'), '-CA', P('root.pem'), '-CAkey', P('root.key'),
            '-set_serial', '4097', '-days', '1825', '-extfile', P('ca.cnf'), '-extensions', 'int',
            '-out', P('int.pem'))
        run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', P('leaf.key'))
        run('req', '-new', '-key', P('leaf.key'), '-subj', '/C=CZ/L=Praha/O=Example s.r.o./CN=www.example.test',
            '-addext', 'subjectAltName=DNS:www.example.test,DNS:example.test',
            '-addext', 'extendedKeyUsage=serverAuth', '-out', P('leaf.csr'))
        run('x509', '-req', '-in', P('leaf.csr'), '-CA', P('int.pem'), '-CAkey', P('int.key'),
            '-set_serial', '0x0123456789ABCDEF', '-days', '90', '-extfile', P('ca.cnf'),
            '-extensions', 'leaf', '-out', P('leaf.pem'))
        cls.root = read(P('root.pem'))
        cls.int = read(P('int.pem'))
        cls.leaf = read(P('leaf.pem'))
        cls.leaf_key = read(P('leaf.key'))
        # A CRL of the intermediate, one certificate revoked.
        os.makedirs(P('db'))
        open(P('db/index.txt'), 'w').close()
        with open(P('db/crlnumber'), 'w') as f:
            f.write('1000\n')
        with open(P('crl.cnf'), 'w') as f:
            f.write('[ca]\ndefault_ca=c\n[c]\ndatabase=%s\ncrlnumber=%s\ndefault_md=sha256\n'
                    'default_crl_days=7\n' % (P('db/index.txt'), P('db/crlnumber')))
        run('ca', '-config', P('crl.cnf'), '-revoke', P('leaf.pem'), '-keyfile', P('int.key'),
            '-cert', P('int.pem'), '-crl_reason', 'keyCompromise')
        run('ca', '-config', P('crl.cnf'), '-gencrl', '-keyfile', P('int.key'), '-cert', P('int.pem'),
            '-out', P('int.crl'))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def certs(self, got):
        return [t for t in got['things'] if t['kind'] == 'cert']

    def no_key_out(self, got):
        text = json.dumps(got)
        self.assertNotIn('PRIVATE KEY', text)
        body = ''.join(self.leaf_key.strip().split('\n')[1:-1])
        self.assertNotIn(body[:40], text)

    # ---- PEM: the chain out of order, ordered and verified -------------------------
    def test_pem_chain_ordered_and_links_verified(self):
        got = certview.describe(self.root + self.leaf + self.int, 'bundle.pem')
        self.assertEqual(got['format'], 'pem')
        certs = self.certs(got)
        self.assertEqual(len(certs), 3)
        self.assertEqual(len(got['chains']), 1)
        ch = got['chains'][0]
        by = {t['id']: t for t in certs}
        self.assertEqual([by[i]['cn'] for i in ch['items']],
                         ['www.example.test', 'Test Issuing CA', 'Test Root'])
        self.assertEqual(len(ch['links']), 2)
        self.assertTrue(all(l['ok'] for l in ch['links']), ch['links'])
        self.assertTrue(ch['top']['self_signed'])
        self.assertTrue(ch['top']['self_ok'])
        self.assertFalse(ch['top']['in_store'])
        self.assertEqual([by[i]['role'] for i in ch['items']], ['leaf', 'intermediate', 'root'])

    def test_leaf_in_full(self):
        got = certview.describe(self.leaf)
        c = self.certs(got)[0]
        self.assertEqual(c['serial'], '0123456789ABCDEF')
        self.assertEqual(c['serial_dec'], str(0x0123456789ABCDEF))
        self.assertEqual(c['version'], 3)
        self.assertEqual(c['subject'][0], ['C', 'CZ'])
        self.assertIn(['CN', 'www.example.test'], c['subject'])
        self.assertEqual(c['key']['algo'], 'EC')
        self.assertEqual(c['key']['curve'], 'P-256')
        self.assertEqual(len(c['sha256']), 64)
        self.assertIn(['IP', '192.0.2.7'], c['names'])
        self.assertIn(['email', 'a@example.test'], c['names'])
        self.assertTrue(c['must_staple'])
        ext = {e['name']: e for e in c['extensions']}
        self.assertEqual([x['name'] for x in ext['extendedKeyUsage']['value']],
                         ['serverAuth', 'clientAuth'])
        self.assertTrue(ext['keyUsage']['critical'])
        self.assertEqual(ext['certificatePolicies']['value'][0]['name'],
                         'Organization validated (OV)')
        self.assertEqual(ext['authorityInfoAccess']['value']['ocsp'], ['http://ocsp.example.test'])
        self.assertEqual(ext['tlsfeature']['value'], ['status_request'])
        self.assertTrue(ext['authorityKeyIdentifier']['value']['key_id'])
        self.assertEqual(ext['1.2.3.4.5.6']['kind'], 'other')
        self.assertEqual(ext['1.2.3.4.5.6']['hex'], '0403010203')
        # the chain: its issuer is not given - said so
        self.assertEqual(got['chains'][0]['top']['missing'], c['issuer_dn'])

    def test_forged_link_is_caught(self):
        # A certificate with the intermediate's name and key ids, signed by another key.
        P = self.P
        run('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', P('fake.key'))
        # A fake 'Test Issuing CA' (another key) signs the leaf, which names no key id:
        # by its name the real intermediate is its issuer - and its signature is wrong.
        run('req', '-new', '-key', P('fake.key'), '-subj', '/C=CZ/O=Test Root Org/CN=Test Issuing CA',
            '-out', P('fake.csr'))
        run('x509', '-req', '-in', P('fake.csr'), '-signkey', P('fake.key'), '-days', '5',
            '-extfile', P('ca.cnf'), '-extensions', 'ca', '-out', P('fake.pem'))
        run('x509', '-req', '-in', P('leaf.csr'), '-CA', P('fake.pem'), '-CAkey', P('fake.key'),
            '-set_serial', '7', '-days', '5', '-extfile', P('ca.cnf'), '-extensions', 'noaki',
            '-out', P('forged.pem'))
        got = certview.describe(read(P('forged.pem')) + self.int)
        ch = got['chains'][0]
        self.assertEqual(len(ch['items']), 2)
        self.assertFalse(ch['links'][0]['ok'])
        self.assertIn('signature', ch['links'][0]['words'])

    # ---- DER, PKCS#7, base64, ZIP ----------------------------------------------------
    def test_der(self):
        got = certview.describe(pki.pem_to_der(self.leaf), 'leaf.cer')
        self.assertEqual(got['format'], 'der')
        self.assertEqual(self.certs(got)[0]['cn'], 'www.example.test')

    def test_pkcs7(self):
        der = run('crl2pkcs7', '-nocrl', '-certfile', self.P('leaf.pem'), '-certfile',
                  self.P('int.pem'), '-certfile', self.P('root.pem'), '-outform', 'DER')
        got = certview.describe(der, 'chain.p7b')
        self.assertEqual(got['format'], 'pkcs7')
        self.assertEqual(got['container']['certs'], 3)
        self.assertEqual(len(got['chains'][0]['items']), 3)
        pem = run('crl2pkcs7', '-nocrl', '-certfile', self.P('leaf.pem'))
        got = certview.describe(pem, 'chain.p7c')
        self.assertEqual(len(self.certs(got)), 1)

    def test_base64_without_lines_and_zip(self):
        b64 = base64.b64encode(pki.pem_to_der(self.int)).decode()
        got = certview.describe(b64)
        self.assertEqual(self.certs(got)[0]['cn'], 'Test Issuing CA')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('cert/leaf.crt', self.leaf)
            z.writestr('cert/chain.pem', self.int + self.root)
        got = certview.describe(buf.getvalue(), 'certs.zip')
        self.assertEqual(got['format'], 'zip')
        self.assertEqual(len(self.certs(got)), 3)

    # ---- PKCS#12 ---------------------------------------------------------------------
    def p12(self, password, legacy=False, name='web'):
        args = ['pkcs12', '-export', '-in', self.P('leaf.pem'), '-inkey', self.P('leaf.key'),
                '-certfile', self.P('int.pem'), '-name', name, '-passout', 'pass:' + password]
        if legacy:
            args.append('-legacy')
        return run(*args)

    def test_pkcs12_with_password(self):
        data = self.p12('s3cret')
        got = certview.describe(data, 'web.pfx', 's3cret')
        self.assertEqual(got['format'], 'pkcs12')
        self.assertFalse(got['password']['needed'])
        self.assertIn('AES-256-CBC', got['container']['cert_encryption'])
        self.assertEqual(len(self.certs(got)), 2)
        keys = [t for t in got['things'] if t['kind'] == 'key']
        self.assertEqual(len(keys), 1)
        leaf = [c for c in self.certs(got) if c['cn'] == 'www.example.test'][0]
        self.assertEqual(keys[0]['matches'], [leaf['id']])
        self.assertEqual(keys[0]['key']['curve'], 'P-256')
        self.assertIn('web', leaf['aliases'])
        self.assertTrue(any(e['alias'] == 'web' and e['kind'] == 'key' for e in got['entries']))
        self.no_key_out(got)

    def test_pkcs12_password_missing_and_wrong(self):
        data = self.p12('s3cret')
        got = certview.describe(data, 'web.pfx', '')
        self.assertTrue(got['password']['needed'])
        self.assertFalse(got['password']['wrong'])
        self.assertIn('give its password', got['password']['words'][0])
        got = certview.describe(data, 'web.pfx', 'nope')
        self.assertTrue(got['password']['wrong'])
        self.assertIn('password of the PKCS#12 file is wrong', got['password']['words'][0])
        self.assertEqual(got['things'], [])

    def test_pkcs12_legacy(self):
        try:
            data = self.p12('old', legacy=True)
        except RuntimeError:
            self.skipTest('this openssl makes no legacy PKCS#12')
        got = certview.describe(data, 'old.p12', 'old')
        if not self.certs(got):
            self.skipTest('this openssl has no legacy provider: %s' % got['notes'])
        self.assertTrue(got['container']['legacy'])
        self.assertIn('RC2', got['container']['cert_encryption'])
        self.no_key_out(got)

    # ---- Java keystores --------------------------------------------------------------
    def keytool(self, kind):
        path = self.P('ks.' + kind)
        if os.path.exists(path):
            os.remove(path)
        p12 = self.P('kt.p12')
        with open(p12, 'wb') as f:
            f.write(self.p12('changeit', name='web'))
        subprocess.run(['keytool', '-importkeystore', '-srckeystore', p12, '-srcstoretype', 'PKCS12',
                        '-srcstorepass', 'changeit', '-destkeystore', path, '-deststoretype', kind,
                        '-deststorepass', 'changeit', '-destkeypass', 'changeit', '-noprompt'],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['keytool', '-importcert', '-alias', 'theroot', '-file', self.P('root.pem'),
                        '-keystore', path, '-storetype', kind, '-storepass', 'changeit',
                        '-noprompt'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(path, 'rb') as f:
            return f.read()

    def check_keystore(self, data, kind):
        got = certview.describe(data, 'store.' + kind, 'changeit')
        self.assertEqual(got['format'], kind)
        self.assertTrue(got['container']['integrity'])
        self.assertFalse(got['password']['needed'], got['password'])
        aliases = {e['alias']: e for e in got['entries']}
        self.assertEqual(aliases['theroot']['kind'], 'trusted')
        self.assertEqual(aliases['web']['kind'], 'key')
        keys = [t for t in got['things'] if t['kind'] == 'key']
        self.assertTrue(keys[0]['readable'])
        self.assertEqual(len(keys[0]['matches']), 1)
        self.assertEqual(len(got['chains'][0]['items']), 3)       # leaf, int, root (the trusted entry)
        self.assertTrue(all(l['ok'] for l in got['chains'][0]['links']))
        self.no_key_out(got)
        # without the password: the certificates, the keys not
        got = certview.describe(data, 'store.' + kind, '')
        self.assertTrue(got['password']['needed'])
        self.assertEqual(len(self.certs(got)), 3)
        self.assertFalse([t for t in got['things'] if t['kind'] == 'key'][0]['readable'])
        # a wrong one: said
        got = certview.describe(data, 'store.' + kind, 'wrong')
        self.assertTrue(got['password']['wrong'])
        self.assertIn('wrong', got['password']['words'][0])

    @unittest.skipUnless(HAVE_KEYTOOL, 'keytool is not installed')
    def test_jks_from_keytool(self):
        self.check_keystore(self.keytool('JKS'), 'jks')

    @unittest.skipUnless(HAVE_KEYTOOL, 'keytool is not installed')
    def test_jceks_from_keytool(self):
        self.check_keystore(self.keytool('JCEKS'), 'jceks')

    @unittest.skipUnless(HAVE_KEYTOOL, 'keytool is not installed')
    def test_pkcs12_keystore_from_keytool(self):
        got = certview.describe(self.keytool('PKCS12'), 'store.p12', 'changeit')
        self.assertEqual(got['format'], 'pkcs12')
        self.assertEqual(len(self.certs(got)), 3)
        kinds = sorted(e['kind'] for e in got['entries'])
        self.assertIn('trusted', kinds)
        self.assertIn('key', kinds)

    def test_jks_from_acme(self):
        data = formats.jks_write(self.leaf_key, [self.leaf, self.int], 'pw', alias='site',
                                 trusted=[('root', self.root)])
        got = certview.describe(data, 'site.jks', 'pw')
        self.assertEqual(got['format'], 'jks')
        self.assertEqual(len(got['chains'][0]['items']), 3)
        self.assertEqual(got['entries'][0]['alias'], 'site')
        self.no_key_out(got)

    # ---- a CSR, a CRL, keys ----------------------------------------------------------
    def test_csr(self):
        got = certview.describe(read(self.P('leaf.csr')))
        r = got['things'][0]
        self.assertEqual(r['kind'], 'csr')
        self.assertTrue(r['signature_ok'])
        self.assertEqual(r['cn'], 'www.example.test')
        self.assertIn(['DNS', 'example.test'], r['names'])
        self.assertFalse(r['challenge_password'])
        self.assertIn('extendedKeyUsage', [e['name'] for e in r['extensions']])
        # NEW CERTIFICATE REQUEST, DER
        der = pki.pem_to_der(read(self.P('leaf.csr')))
        got = certview.describe(der, 'x.csr')
        self.assertEqual(got['things'][0]['kind'], 'csr')
        b64 = base64.b64encode(der).decode()
        got = certview.describe('-----BEGIN NEW CERTIFICATE REQUEST-----\n%s\n'
                                '-----END NEW CERTIFICATE REQUEST-----\n' % b64)
        self.assertEqual(got['things'][0]['kind'], 'csr')

    def test_crl(self):
        got = certview.describe(read(self.P('int.crl')) + self.int)
        crl = [t for t in got['things'] if t['kind'] == 'crl'][0]
        self.assertEqual(crl['count'], 1)
        self.assertEqual(crl['revoked'][0]['serial'], '0123456789ABCDEF')
        self.assertEqual(crl['revoked'][0]['reason'], 'keyCompromise')
        self.assertEqual(crl['number'], str(0x1000))
        self.assertTrue(crl['next_update'])
        self.assertTrue(crl['signature_ok'])

    def test_private_key_never_returned(self):
        got = certview.describe(self.leaf_key + self.leaf)
        k = [t for t in got['things'] if t['kind'] == 'key'][0]
        self.assertTrue(k['readable'])
        self.assertEqual(k['key']['algo'], 'EC')
        self.assertEqual(len(k['matches']), 1)
        self.no_key_out(got)
        enc = run('pkey', '-in', self.P('leaf.key'), '-aes-256-cbc', '-passout', 'pass:kk').decode()
        got = certview.describe(enc)
        k = got['things'][0]
        self.assertTrue(k['encrypted'])
        self.assertIn('AES-256-CBC'.lower(), k['cipher'].lower())
        self.assertEqual(k['locked'], 'needed')
        self.assertTrue(got['password']['needed'])
        got = certview.describe(enc, '', 'bad')
        self.assertTrue(got['password']['wrong'])
        got = certview.describe(enc, '', 'kk')
        self.assertTrue(got['things'][0]['readable'])
        self.assertNotIn('PRIVATE KEY', json.dumps(got))

    def test_public_key(self):
        pub = run('pkey', '-in', self.P('leaf.key'), '-pubout').decode()
        got = certview.describe(pub + self.leaf)
        p = [t for t in got['things'] if t['kind'] == 'pubkey'][0]
        self.assertEqual(len(p['matches']), 1)

    def test_root_in_the_system_store(self):
        store = certview.trust_store()
        if not store['by_sha']:
            self.skipTest('no trust store on this machine')
        one = next(iter(store['by_sha'].values()))
        got = certview.describe(one['pem'])
        top = got['chains'][0]['top']
        self.assertTrue(top['in_store'])
        self.assertTrue(top['self_ok'])

    def test_broken(self):
        with self.assertRaises(PkiError) as e:
            certview.describe(b'this is not a certificate at all, just words')
        self.assertIn('none of the formats', str(e.exception))
        with self.assertRaises(PkiError):
            certview.describe(b'   ')
        got = None
        try:
            got = certview.describe(self.leaf[:200] + '\n-----END CERTIFICATE-----\n')
        except PkiError as e:
            self.assertIn('cannot be read', str(e))
        if got is not None:
            self.assertTrue(got['notes'])


if __name__ == '__main__':
    unittest.main()
