#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt u5, area regress: what the fixes of hunts u1 - u4 broke themselves.

  - the Windows agent's AD CS check of a CSR (hunt u4) looked for "verify OK" on openssl's
    error output only: OpenSSL 3.2 and later print it on the standard output - every good
    request was refused as "its signature is not good"
  - pki.csr_verify_why (hunt u3) took openssl req -verify's "verify failure" with exit 0 as a
    forged request at once: OpenSSL 3.0 - 3.2 under RHEL 9/10's crypto policy say just that of
    a SHA-1 request (the policy refuses the digest in EVP_DigestVerifyInit, and req answers 0
    with no words of why) - the SHA-1 request was never verified with the configuration that
    lets SHA-1 through, and was "not signed by its own key"

    python3 test/test_hunt_ru5_regress.py
Never port 8092 nor PostgreSQL: temporary folders only.
"""
import base64
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-ru5-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)

from acmelib.certs import pki                                       # noqa: E402

AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
REAL = shutil.which('openssl')


def w(name, data, mode=0o644):
    p = os.path.join(TMP, name)
    with open(p, 'w') as fh:
        fh.write(data)
    os.chmod(p, mode)
    return p


def csr(md='sha256', cn='a.example', keyargs=('-newkey', 'ec', '-pkeyopt',
                                              'ec_paramgen_curve:P-256')):
    k = os.path.join(TMP, 'k-%s.pem' % os.urandom(4).hex())
    cnf = w('r-%s.cnf' % os.urandom(4).hex(),
            '[req]\ndistinguished_name=dn\nreq_extensions=v\nprompt=no\n[dn]\nCN=%s\n'
            '[v]\nsubjectAltName=DNS:a.example\n' % cn)
    return subprocess.run([REAL, 'req', '-new', '-nodes', '-keyout', k, '-config', cnf,
                           '-' + md] + list(keyargs), capture_output=True, check=True,
                          text=True).stdout


def forged(pem):
    der = base64.b64decode(''.join(pem.strip().splitlines()[1:-1]))
    bad = der.replace(b'a.example', b'b.example')
    assert bad != der
    return ('-----BEGIN CERTIFICATE REQUEST-----\n%s-----END CERTIFICATE REQUEST-----\n'
            % base64.encodebytes(bad).decode())


# OpenSSL 3.2 and later: "Certificate request self-signature verify OK" on the standard output
# (apps/req.c: BIO_printf(bio_out, ...)), "verify failure" still on the error output
OSSL_32 = w('openssl-32', '''#!/bin/sh
out=$(mktemp) err=$(mktemp)
"%s" "$@" >"$out" 2>"$err"; rc=$?
grep -v 'self-signature verify OK' "$err" >&2
grep -q 'self-signature verify OK' "$err" && echo 'Certificate request self-signature verify OK'
cat "$out"; rm -f "$out" "$err"; exit $rc
''' % REAL, 0o755)

# OpenSSL 3.0 - 3.2 on RHEL 9/10 (DEFAULT policy): a SHA-1 signature refused in
# EVP_DigestVerifyInit - req -verify says "verify failure" and answers 0, nothing more; with
# rh-allow-sha1-signatures = yes in the configuration given (FAKE_ALLOW=1) it is verified.
# FAKE_SIGN=0: SHA-1 not even signed (the configuration does not help: FIPS mode).
OSSL_RHEL = w('openssl-rhel', '''#!/bin/sh
data=$(cat)
allowed=0
if [ -n "$OPENSSL_CONF" ] && [ "$FAKE_ALLOW" = 1 ] && \
   grep -q "^rh-allow-sha1-signatures = yes" "$OPENSSL_CONF" 2>/dev/null; then allowed=1; fi
unset OPENSSL_CONF    # the real one is no RHEL: its option unknown there
for a in "$@"; do
  if [ "$a" = -sha1 ] && [ "$allowed" = 0 ]; then echo "invalid digest" >&2; exit 1; fi
done
if [ "$1" = req ] && [ "$2" = -verify ] && [ "$allowed" = 0 ]; then
  if printf '%%s\\n' "$data" | "%s" req -noout -text 2>/dev/null | \
     grep -q 'Signature Algorithm: .*sha1'; then
    echo "Certificate request self-signature verify failure" >&2; exit 0
  fi
fi
printf '%%s\\n' "$data" | exec "%s" "$@"
''' % (REAL, REAL), 0o755)


def load_agent(name):
    d = os.path.join(TMP, name)
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
    os.environ['ACME_AGENT_FAKE_ROOT'] = os.path.join(TMP, 'fakewin')
    try:
        spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT_DIR,
                                                                         'acme_agent.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    return m


class WindowsAgentCsrNewOpenssl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.AG = load_agent('acme_agent_ru5_win')
        cls.W = cls.AG._wincert()
        cls.good = csr()
        cls.bad = forged(cls.good)

    def with_openssl(self, path):
        was = self.AG.OPENSSL
        self.AG.OPENSSL = path
        self.addCleanup(setattr, self.AG, 'OPENSSL', was)

    def test_fake_is_like_32(self):
        got = subprocess.run([OSSL_32, 'req', '-noout', '-verify'], input=self.good,
                             capture_output=True, text=True)
        self.assertIn('verify OK', got.stdout)
        self.assertNotIn('verify OK', got.stderr)

    def test_good_csr_read_openssl_32(self):
        self.with_openssl(OSSL_32)
        self.assertEqual(self.W.adcs_csr_names(self.AG, self.good), [('dns', 'a.example')])

    def test_forged_csr_refused_openssl_32(self):
        self.with_openssl(OSSL_32)
        with self.assertRaises(self.AG.Refused) as cm:
            self.W.adcs_csr_names(self.AG, self.bad)
        self.assertIn('signature is not good', str(cm.exception))

    def test_subject_saying_verify_ok_is_no_verdict(self):
        """-text prints the subject on the standard output: a forged request named
        "verify OK" is no "verify OK" of openssl's."""
        self.with_openssl(OSSL_32)
        bad = forged(csr(cn='verify OK'))
        with self.assertRaises(self.AG.Refused):
            self.W.adcs_csr_names(self.AG, bad)

    def test_real_openssl_still(self):
        self.with_openssl(REAL)
        self.assertEqual(self.W.adcs_csr_names(self.AG, self.good), [('dns', 'a.example')])
        with self.assertRaises(self.AG.Refused):
            self.W.adcs_csr_names(self.AG, self.bad)


class ServerChecksNewOpenssl(unittest.TestCase):
    """acme's own checks read both outputs: OpenSSL 3.2+ takes them as before."""

    def test_pki_and_agents(self):
        good = csr()
        was = pki.OPENSSL
        pki.OPENSSL = OSSL_32
        try:
            self.assertIsNone(pki.csr_verify_why(good))
            self.assertEqual(pki.csr_verify_why(forged(good)), pki.CSR_NOT_SIGNED)
        finally:
            pki.OPENSSL = was


class Sha1WherePolicyRefusesQuietly(unittest.TestCase):
    def setUp(self):
        self.was = pki.OPENSSL
        pki.OPENSSL = OSSL_RHEL
        os.environ['FAKE_ALLOW'] = '1'
        self.sha1 = csr('sha1', keyargs=('-newkey', 'rsa:2048'))
        self.sha256 = csr('sha256', keyargs=('-newkey', 'rsa:2048'))

    def tearDown(self):
        pki.OPENSSL = self.was
        os.environ.pop('FAKE_ALLOW', None)

    def test_fake_is_like_rhel(self):
        got = subprocess.run([OSSL_RHEL, 'req', '-verify', '-noout'], input=self.sha1,
                             capture_output=True, text=True)
        self.assertEqual(got.returncode, 0)
        self.assertIn('verify failure', got.stderr)

    def test_sha1_taken_with_the_sha1_configuration(self):
        self.assertIsNone(pki.csr_verify_why(self.sha1))

    def test_sha256_as_before(self):
        self.assertIsNone(pki.csr_verify_why(self.sha256))
        self.assertEqual(pki.csr_verify_why(forged(self.sha256)), pki.CSR_NOT_SIGNED)

    def test_forged_sha1_still_not_signed(self):
        self.assertEqual(pki.csr_verify_why(forged(self.sha1)), pki.CSR_NOT_SIGNED)

    def test_real_openssl_sha1(self):
        """An openssl with no such policy (and no rh-allow-sha1-signatures option): a good
        SHA-1 request taken, a forged one forged - not "the policy refuses SHA-1"."""
        pki.OPENSSL = REAL
        self.assertIsNone(pki.csr_verify_why(self.sha1))
        self.assertEqual(pki.csr_verify_why(forged(self.sha1)), pki.CSR_NOT_SIGNED)

    def test_sha1_refused_whatever_the_configuration(self):
        os.environ['FAKE_ALLOW'] = '0'
        self.assertEqual(pki.csr_verify_why(self.sha1), pki.CSR_SHA1_REFUSED)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
