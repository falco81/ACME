#!/usr/bin/env python3
"""Hunt v5, secrets.

    python3 test/test_hunt_rv5_secrets.py

- Cisco ISE: the random password the key is encrypted with never on openssl's command line
  (`-passout pass:...` was seen in ps by every user of the machine); the key still opens with it.
- Settings -> TLS of the pages, a download with the key (acme --tls-export pfx|pemkey): the key
  locked with as many rounds as a certificate's own (600000 PBKDF2 rounds for the PEM key,
  250000 for a PKCS#12 with openssl 3) - openssl's default of 2048 was taken; legacy as it was.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-v5-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_VIP_NO_SERVICES='1')
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

PW = 'a-passphrase-of-length'


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True)


def openssl_major():
    m = re.search(r'(\d+)\.', openssl('version').stdout.decode())
    return int(m.group(1)) if m else 0


class CiscoIseKey(unittest.TestCase):
    def test_password_not_on_the_command_line(self):
        from test_targets import FakeBundle, setUpModule as targets_setup
        targets_setup()
        from acmelib.plugins.targets import cisco_ise as ISE
        seen = []

        class Ctx(object):
            def openssl(self, args, data=None, timeout=60):
                seen.append((list(args), data))
                return subprocess.run(['openssl'] + list(args), input=data,
                                      capture_output=True, check=True).stdout

            def debug(self, words):
                pass
        t = ISE.CiscoIseTarget.__new__(ISE.CiscoIseTarget)
        t.ctx = Ctx()
        b = FakeBundle()
        key, pw = t.encrypted_key(b)
        self.assertTrue(pw)
        self.assertIn('ENCRYPTED PRIVATE KEY', key)
        args = ' '.join(a for call in seen for a in call[0])
        self.assertNotIn(pw, args)
        self.assertNotIn('pass:', args)
        got = openssl('pkey', '-passin', 'pass:' + pw, data=key.encode())
        self.assertEqual(got.returncode, 0)
        self.assertIn(b'PRIVATE KEY', got.stdout)
        # the folder with the plain key is gone
        kf = [a for call in seen for a in call[0] if a.endswith('key.pem')]
        self.assertTrue(kf)
        self.assertFalse(os.path.exists(os.path.dirname(kf[0])))


class TlsExportRounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, cert = E.make_selfsigned('v5.example.test', ['v5.example.test'], 30, 'rsa2048')
        cls.key = key
        cls.prof = {'cert': cert, 'chain': '', 'root': '', 'key': E.seal_secret(key, 'web:tls')}

    def test_pem_key_rounds(self):
        blob, ending = E.tls_export(self.prof, 'pemkey', PW)
        text = blob.decode()
        self.assertEqual(ending, '-with-key.pem')
        m = re.search(r'-----BEGIN ENCRYPTED PRIVATE KEY-----.+?-----END ENCRYPTED PRIVATE KEY-----',
                      text, re.S)
        self.assertTrue(m)
        parsed = openssl('asn1parse', data=m.group(0).encode()).stdout.decode()
        self.assertIn(600000, [int(x, 16) for x in re.findall(r'INTEGER\s*:([0-9A-F]+)', parsed)])
        self.assertIn('hmacWithSHA256', parsed)
        got = openssl('pkey', '-passin', 'pass:' + PW, data=m.group(0).encode())
        self.assertEqual(got.returncode, 0)

    def test_pfx_rounds(self):
        blob, _ = E.tls_export(self.prof, 'pfx', PW)
        info = openssl('pkcs12', '-info', '-noout', '-passin', 'pass:' + PW, data=blob)
        self.assertEqual(info.returncode, 0, info.stderr)
        said = info.stderr.decode() + info.stdout.decode()
        if openssl_major() >= 3:
            self.assertIn('Iteration 250000', said)
            self.assertIn('sha256', said)
            self.assertNotIn('Iteration 2048', said)
        # legacy: as before (3DES, SHA-1)
        old, _ = E.tls_export(self.prof, 'pfx', PW, legacy=True)
        info = openssl('pkcs12', '-info', '-noout', '-legacy', '-passin', 'pass:' + PW, data=old)
        if info.returncode != 0:
            info = openssl('pkcs12', '-info', '-noout', '-passin', 'pass:' + PW, data=old)
        said = info.stderr.decode() + info.stdout.decode()
        self.assertIn('pbeWithSHA1And3-KeyTripleDES-CBC', said)


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
