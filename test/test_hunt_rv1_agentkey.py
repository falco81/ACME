#!/usr/bin/env python3
"""Hunt 1.0.140 v1 (agentkey): ways past the agent's deploy guard (allow names / require key
local) closed - deploy/agent/acme_agent.py guard_check, the same code acme runs before sending.

* a self-signed certificate that says CA:TRUE (with its key) is an end certificate: its names
  are judged (was: skipped as "a CA of the chain");
* a DNS name "CA:TRUE" in subjectAltName does not make a certificate a CA (was: it did - names
  and require key local skipped);
* every common name is judged: a second CN, CN=a+CN=b (was: only the first);
* a PEM block whose BEGIN line ends in spaces (openssl reads it) is looked at (was: unseen);
* a DER certificate with the bytes "-----BEGIN " in a name is read as DER (was: read as an
  empty PEM - nothing checked);
* what worked still works: a full chain (root, intermediate, leaf), DER, PKCS#12.

    python3 test/test_hunt_rv1_agentkey.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_f140_agentkey as F  # noqa: E402

AG = F.AG
EC = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes']


def ossl(*a):
    return subprocess.run(['openssl'] + list(a), capture_output=True, check=True).stdout


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class GuardBypass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k = F.make_pki()
        j = cls.k['j']
        ossl('req', '-x509', *EC, '-keyout', j('h1sca.key'), '-out', j('h1sca.crt'), '-subj',
             '/CN=evil.test', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext',
             'subjectAltName=DNS:evil.test')
        for n, subj, multi in (('h1mcn', '/CN=evil.test/CN=www.example.test', False),
                               ('h1mv', '/CN=www.example.test+CN=evil.test', True)):
            ossl('req', *EC, '-keyout', j(n + '.key'), '-out', j(n + '.csr'), '-subj', subj,
                 *(['-multivalue-rdn'] if multi else []))
            ossl('x509', '-req', '-in', j(n + '.csr'), '-CA', j('int.crt'), '-CAkey',
                 j('int.key'), '-CAcreateserial', '-days', '5', '-out', j(n + '.crt'))
        with open(j('h1ct.ext'), 'w') as fh:
            fh.write('subjectAltName=DNS:CA:TRUE,DNS:evil.test\n')
        ossl('req', *EC, '-keyout', j('h1ct.key'), '-out', j('h1ct.csr'), '-subj', '/CN=x')
        ossl('x509', '-req', '-in', j('h1ct.csr'), '-CA', j('int.crt'), '-CAkey', j('int.key'),
             '-CAcreateserial', '-days', '5', '-out', j('h1ct.crt'), '-extfile', j('h1ct.ext'))
        with open(j('h1b.ext'), 'w') as fh:
            fh.write('subjectAltName=DNS:evil.test,DNS:-----BEGIN X\n')
        ossl('req', *EC, '-keyout', j('h1b.key'), '-out', j('h1b.csr'), '-subj', '/CN=evil.test')
        ossl('x509', '-req', '-in', j('h1b.csr'), '-CA', j('int.crt'), '-CAkey', j('int.key'),
             '-CAcreateserial', '-days', '5', '-out', j('h1b.crt'), '-extfile', j('h1b.ext'))

    def setUp(self):
        self.top = tempfile.mkdtemp(prefix='acme-hv1-')

    def tearDown(self):
        shutil.rmtree(self.top, ignore_errors=True)

    def chk(self, pol, mats, pool=(), own=None):
        return AG.guard_check(AG.parse_policy(pol), mats, pool, own, top=self.top)

    def refused(self, pol, mats, want, own=None):
        with self.assertRaises(AG.Refused) as e:
            self.chk(pol, mats, own=own)
        self.assertIn(want, str(e.exception))

    def test_self_signed_ca_judged(self):
        r = self.k['r']
        self.refused('allow names www.example.test',
                     [('/x/a.crt', r('h1sca.crt').encode(), '', None),
                      ('/x/a.key', r('h1sca.key').encode(), 'key-pem', None)],
                     'holds the name evil.test')
        self.refused('allow names www.example.test',
                     [('/x/a.crt', r('h1sca.crt').encode(), '', None)], 'holds the name evil.test')

    def test_ca_true_as_a_name(self):
        r = self.k['r']
        self.refused('allow names www.example.test', [('/x/a.crt', r('h1ct.crt').encode(), '',
                                                       None)], '(allow names)')
        self.refused('require key local', [('/x/a.crt', r('h1ct.crt').encode(), '', None)],
                     'not for a key this agent made', own=[AG.spki_fp(r('leaf.key'))])

    def test_every_common_name(self):
        r = self.k['r']
        for n in ('h1mcn', 'h1mv'):
            self.refused('allow names www.example.test', [('/x/a.crt', r(n + '.crt').encode(),
                                                           '', None)], 'holds the name evil.test')
        self.assertEqual(AG._dn_values('CN=a\\,b,O=x+CN=c.test', 'CN'), ['a,b', 'c.test'])

    def test_pem_begin_line_with_spaces(self):
        r = self.k['r']
        for tail in (' ', '\t', '\r', ' \r'):
            pem = r('h1sca.crt').replace('-----BEGIN CERTIFICATE-----\n',
                                         '-----BEGIN CERTIFICATE-----%s\n' % tail)
            self.refused('allow names www.example.test', [('/x/a.crt', pem.encode(), '', None)],
                         'holds the name evil.test')

    def test_der_with_begin_bytes(self):
        der = ossl('x509', '-in', self.k['j']('h1b.crt'), '-outform', 'DER')
        self.assertIn(b'-----BEGIN ', der)
        self.refused('allow names www.example.test', [('/x/a.der', der, 'cert-der', None)],
                     'holds the name evil.test')

    def test_allowed_as_before(self):
        r = self.k['r']
        full = (r('leaf.crt') + r('int.crt') + r('root.crt')).encode()
        own = [AG.spki_fp(r('leaf.key'))]
        self.chk('allow names *.example.test', [('/x/a.crt', full, '', None)])
        self.chk('allow names *.example.test\nrequire key local\nallow issuer sha256=%s' %
                 F.fp(r('root.crt')), [('/x/a.crt', full, '', None),
                                       ('/x/a.key', r('leaf.key').encode(), 'key-pem', None)],
                 own=own)
        # the chain in its own file (the leaf in another)
        self.chk('allow names *.example.test', [('/x/c.crt', (r('int.crt') + r('root.crt'))
                                                 .encode(), '', None),
                                                ('/x/l.crt', r('leaf.crt').encode(), '', None)])
        der = ossl('x509', '-in', self.k['j']('leaf.crt'), '-outform', 'DER')
        self.chk('allow names *.example.test', [('/x/a.der', der, 'cert-der', None)])
        p12 = open(self.k['j']('leaf.p12'), 'rb').read()
        self.chk('allow names *.example.test', [('/x/a.pfx', p12, 'pfx', 'pw')])
        self.assertEqual(os.listdir(self.top), [])


if __name__ == '__main__':
    unittest.main()
