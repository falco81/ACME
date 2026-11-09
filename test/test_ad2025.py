#!/usr/bin/env python3
"""Domain controllers on Windows Server 2025 (1.0.61):

    python3 test/test_ad2025.py

LDAP signing required (result 8 said in words, plain LDAP warned of by the directory's check), a
domain controller given by its address (its certificate names it by name), a server's own
certificate kept as the authority (a replaced controller has a new one), "weak" still on.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-ad25-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402


def cert(ca):
    k, c = os.path.join(TMP, 'k.pem'), os.path.join(TMP, 'c.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-keyout', k, '-out', c, '-days', '30', '-subj',
                    '/CN=%s' % ('Firma Root CA' if ca else 'dc1.firma.local'), '-addext',
                    'basicConstraints=critical,CA:%s' % ('TRUE' if ca else 'FALSE')],
                   check=True, capture_output=True)
    return open(c).read()


def directory(**kw):
    row = {'name': 'AD', 'hosts': 'dc1.firma.local,dc2.firma.local', 'port': 636, 'tls': 'ldaps',
           'verify': 1, 'ca': '', 'weak': 0, 'base': 'DC=firma,DC=local'}
    row.update(kw)
    return E.Directory(row)


class AD2025(unittest.TestCase):
    def test_signing_required_said(self):
        self.assertIn('LDAPS', E.LDAP_SAYS[8])
        self.assertIn('strongerAuthRequired', E.LDAP_SAYS[8])

    def test_all_right(self):
        self.assertEqual(directory(ca=cert(True)).ahead(), [])

    def test_plain_ldap(self):
        w = directory(tls='none', port=389).ahead()
        self.assertTrue(any('Plain LDAP' in x for x in w))

    def test_an_address(self):
        w = directory(hosts='10.0.0.10,dc2.firma.local').ahead()
        self.assertEqual(len(w), 1)
        self.assertIn('10.0.0.10 is an address', w[0])
        self.assertEqual(directory(hosts='10.0.0.10', verify=0).ahead(), [])   # not checked: no word

    def test_the_server_s_own_certificate_kept(self):
        w = directory(ca=cert(True) + cert(False)).ahead()
        self.assertEqual(len(w), 1)
        self.assertIn('dc1.firma.local', w[0])
        self.assertIn("server's own", w[0])

    def test_weak(self):
        self.assertTrue(any('weak' in x for x in directory(weak=1).ahead()))

    def test_address_mismatch_said(self):
        import ssl
        one = E.Ldap('10.0.0.10', 636, 'ldaps')
        err = ssl.SSLCertVerificationError('x')
        err.verify_message = "IP address mismatch, certificate is not valid for '10.0.0.10'."

        class Ctx:
            def wrap_socket(self, sock, server_hostname=None):
                raise err
        one._context = lambda: Ctx()
        with self.assertRaises(E.LdapError) as got:
            one._wrap(None)
        self.assertIn('FQDN', str(got.exception))

    def test_page_shows_them(self):
        js = open(os.path.join(ROOT, 'web/assets/admin.js')).read()
        self.assertIn("(c.warnings || []).forEach", js)


if __name__ == '__main__':
    unittest.main(verbosity=1)
