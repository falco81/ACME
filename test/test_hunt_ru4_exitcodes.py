#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt u4, area exitcodes: where acme takes an external program's exit code (or words) as its
decision, each fed a real bad input.

  - openssl crl -CAfile answers 0 for a CRL whose signature is bad (OpenSSL 3: "verify
    failure" on stderr only, as req -verify): the published CRL's check said "its signature
    is the authority's" and the certificate viewer said signature_ok for a forged CRL
  - the Windows agent's AD CS check of a CSR (req -text -verify) took a forged CSR as signed
  - openssl enc -d answers 0 for a wrong password about once in 256 (the padding happens to
    read right): a backup made before 1.0.139 was then not tried with the old password
  - release signatures (acme_upgrade.py --inspect, the agent's self-update), PKCS#12 with a
    wrong password, an expired certificate, a failing nginx config: refused as they must be

    python3 test/test_hunt_ru4_exitcodes.py
Never port 8092 nor PostgreSQL: temporary folders only.
"""
import base64
import datetime
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-ru4-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)

from cryptography import x509                                       # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization    # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec            # noqa: E402
from cryptography.x509.oid import NameOID                           # noqa: E402

from acmelib.certs import certview, pki, publish                    # noqa: E402
from acmelib.certs.pki import PkiError                              # noqa: E402

AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
NOW = datetime.datetime.now(datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


def w(name, data, mode='w'):
    p = os.path.join(TMP, name)
    with open(p, mode) as fh:
        fh.write(data)
    return p


def ossl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True)


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM).decode()


def flip_last(der, back=3):
    """The DER with one bit of its signature's last integer changed - still DER, the signature
    no longer good."""
    b = bytearray(der)
    b[-back] ^= 1
    return bytes(b)


class Ca(object):
    def __init__(self, cn='U4 CA'):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        self.cert = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name)
                     .public_key(self.key.public_key()).serial_number(1)
                     .not_valid_before(NOW - 100 * DAY).not_valid_after(NOW + 100 * DAY)
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                     .sign(self.key, hashes.SHA256()))

    def crl(self):
        return (x509.CertificateRevocationListBuilder().issuer_name(self.name)
                .last_update(NOW - DAY).next_update(NOW + 7 * DAY)
                .sign(self.key, hashes.SHA256()))

    def leaf(self, nb, na):
        k = ec.generate_private_key(ec.SECP256R1())
        c = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'leaf.example')]))
             .issuer_name(self.name).public_key(k.public_key()).serial_number(7)
             .not_valid_before(nb).not_valid_after(na).sign(self.key, hashes.SHA256()))
        return c, k


# ---- CRLs: openssl crl -CAfile says 0 whatever the signature -------------------------------
class CrlSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = Ca()
        crl = cls.ca.crl()
        cls.good_der = crl.public_bytes(serialization.Encoding.DER)
        cls.bad_der = flip_last(cls.good_der)
        cls.ca_pem = pem(cls.ca.cert)

    def der_to_pem(self, der):
        return ('-----BEGIN X509 CRL-----\n%s-----END X509 CRL-----\n'
                % base64.encodebytes(der).decode())

    def test_the_trap_itself(self):
        """openssl itself (what the fix stands on): a forged CRL, 0 and "verify failure"."""
        ca = w('crl-ca.pem', self.ca_pem)
        bad = w('crl-bad.der', self.bad_der, 'wb')
        r = ossl('crl', '-inform', 'DER', '-in', bad, '-CAfile', ca, '-noout')
        if r.returncode != 0:
            self.skipTest('this openssl says no with its exit code (fine either way)')
        self.assertIn(b'verify fail', r.stderr.lower())

    def test_crl_verified(self):
        ca = w('crl-ca.pem', self.ca_pem)
        self.assertTrue(pki.crl_verified(w('crl-good.der', self.good_der, 'wb'), ca, 'DER'))
        self.assertFalse(pki.crl_verified(w('crl-bad.der', self.bad_der, 'wb'), ca, 'DER'))
        self.assertTrue(pki.crl_verified(w('crl-good.pem', self.der_to_pem(self.good_der)), ca))
        self.assertFalse(pki.crl_verified(w('crl-bad.pem', self.der_to_pem(self.bad_der)), ca))
        # another authority: openssl finds no issuer - an error, not a "yes"
        other = w('crl-other.pem', pem(Ca('U4 Other').cert))
        with self.assertRaises(PkiError):
            pki.crl_verified(w('crl-good.der', self.good_der, 'wb'), other, 'DER')

    def test_certview_signature_ok(self):
        self.assertTrue(certview._crl_ok(self.der_to_pem(self.good_der), self.ca_pem))
        self.assertFalse(certview._crl_ok(self.der_to_pem(self.bad_der), self.ca_pem))
        got = certview.describe(self.der_to_pem(self.bad_der) + self.ca_pem)
        crls = [t for t in got['things'] if t.get('kind') == 'crl']
        self.assertEqual(len(crls), 1)
        self.assertIs(crls[0].get('signature_ok'), False)

    def check(self, der):
        row = {'name': 'U4 CA', 'cert_pem': self.ca_pem, 'fingerprint': ''}
        cert_der = self.ca.cert.public_bytes(serialization.Encoding.DER)

        def fetch(url, timeout=8):
            return (200, 'application/pkix-crl', der) if url.endswith('.crl') else \
                (200, 'application/pkix-cert', cert_der)
        with mock.patch.object(publish, '_row', return_value=row), \
                mock.patch.object(publish, 'on', return_value=True), \
                mock.patch.object(publish, 'is_published', return_value=True), \
                mock.patch.object(publish, 'urls', return_value={
                    'crl': 'http://pki.example/u4.crl', 'cert': 'http://pki.example/u4.crt'}), \
                mock.patch.object(publish, '_fetch', fetch):
            return publish.check(None, 1)

    def test_publish_check(self):
        good = self.check(self.good_der)
        self.assertIn(['ok', 'its signature is the authority\'s'], good['steps'])
        bad = self.check(self.bad_der)
        self.assertFalse(bad['ok'])
        self.assertNotIn(['ok', 'its signature is the authority\'s'], bad['steps'])
        self.assertTrue(any(lv == 'bad' and 'signature does not verify' in t
                            for lv, t in bad['steps']), bad['steps'])


# ---- the backup's password: openssl enc -d answers 0 for a wrong one now and then -------------
class BackupPassword(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import acmelib.engine as E
        cls.E = E
        d = tempfile.mkdtemp(dir=TMP)
        top = os.path.join(d, 'acme-backup-u4')
        os.makedirs(top)
        with open(os.path.join(top, 'data.txt'), 'w') as fh:
            fh.write('u4\n')
        with open(os.path.join(top, 'manifest.json'), 'w') as fh:
            json.dump({'files': {'data.txt': {'sha256': hashlib.sha256(b'u4\n').hexdigest()}}},
                      fh)
        tgz = os.path.join(d, 'b.tar.gz')
        with tarfile.open(tgz, 'w:gz') as tf:
            tf.add(top, arcname='acme-backup-u4')
        cls.locked = os.path.join(d, 'b.tar.gz.enc')
        r = ossl('enc', '-aes-256-cbc', '-pbkdf2', '-iter', '1', '-md', 'sha256', '-salt',
                 '-in', tgz, '-out', cls.locked, '-pass', 'pass:the-old-one')
        assert r.returncode == 0, r.stderr
        # a wrong password openssl takes (its exit code 0, noise out): about one in 256
        cls.wrong = None
        out = os.path.join(d, 'noise')
        for i in range(6000):
            pw = 'wrong-%d' % i
            r = ossl('enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '1', '-md', 'sha256',
                     '-in', cls.locked, '-out', out, '-pass', 'pass:' + pw)
            if r.returncode == 0:
                cls.wrong = pw
                break

    def test_old_password_still_tried(self):
        self.assertIsNotNone(self.wrong, 'no wrong password that openssl takes was found')
        E = self.E
        with mock.patch.object(E, 'RB_ITER', 1), \
                mock.patch.object(E, 'rb_password', return_value=self.wrong), \
                mock.patch.object(E, 'rb_password_old', return_value='the-old-one'):
            top, m = E.rb_open(self.locked, self.wrong, tempfile.mkdtemp(dir=TMP))
        self.assertTrue(top.endswith('acme-backup-u4'))
        self.assertIn('data.txt', m['files'])

    def test_wrong_password_said_so(self):
        self.assertIsNotNone(self.wrong)
        E = self.E
        with mock.patch.object(E, 'RB_ITER', 1), \
                mock.patch.object(E, 'rb_password', return_value='something-else'), \
                mock.patch.object(E, 'rb_password_old', return_value=''):
            with self.assertRaises(E.RbError) as cm:
                E.rb_open(self.locked, self.wrong, tempfile.mkdtemp(dir=TMP))
        self.assertIn('password does not open it', str(cm.exception))


# ---- the Windows agent: the CSR it hands to AD CS ----------------------------------------------
def load_agent(name, windows):
    d = os.path.join(TMP, name)
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    if windows:
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


class WindowsAgentCsr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.AG = load_agent('acme_agent_ru4_win', True)
        cls.W = cls.AG._wincert()
        k = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'a.example')]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName('a.example')]), False)
               .sign(k, hashes.SHA256()))
        der = csr.public_bytes(serialization.Encoding.DER)
        cls.good = pem(csr)
        # forged: the name changed after it was signed (b.example) - still a CSR that reads
        forged = der.replace(b'a.example', b'b.example')
        assert forged != der
        cls.forged = ('-----BEGIN CERTIFICATE REQUEST-----\n%s-----END CERTIFICATE REQUEST-----\n'
                      % base64.encodebytes(forged).decode())

    def test_good_csr_read(self):
        self.assertEqual(self.W.adcs_csr_names(self.AG, self.good), [('dns', 'a.example')])

    def test_forged_csr_refused(self):
        with self.assertRaises(self.AG.Refused) as cm:
            self.W.adcs_csr_names(self.AG, self.forged)
        self.assertIn('signature is not good', str(cm.exception))
        with self.assertRaises(self.AG.Refused):
            self.W.adcs_attrib(self.AG, 'WebServer', self.forged, True)


# ---- release signatures ------------------------------------------------------------------------
def ed_key(d, name):
    k = os.path.join(d, name + '.key')
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', k], check=True,
                   capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', k, '-pubout', '-out',
                    os.path.join(d, 'keys', name + '.pub')], check=True, capture_output=True)
    return k


def make_release(path, key, version='9.9.1', tamper=None):
    """A package as tools/release.py makes it: MANIFEST, MANIFEST.sig over it (Ed25519)."""
    files = {'acme.py': b'print("acme")\n', 'install.sh': b'#!/bin/bash\necho install\n',
             'acmelib/__init__.py': ('__version__ = \'%s\'\n' % version).encode()}
    manifest = ''.join('%s  %s\n' % (hashlib.sha256(b).hexdigest(), n)
                       for n, b in sorted(files.items())).encode()
    with tempfile.TemporaryDirectory(dir=TMP) as t:
        man, sig = os.path.join(t, 'MANIFEST'), os.path.join(t, 'MANIFEST.sig')
        with open(man, 'wb') as fh:
            fh.write(manifest)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', man,
                        '-out', sig], check=True, capture_output=True)
        with open(sig, 'rb') as fh:
            signature = fh.read()
    if tamper == 'file':
        files['acme.py'] = b'print("not acme")\n'
    elif tamper == 'manifest':
        files['acme.py'] = b'print("not acme")\n'
        manifest = ''.join('%s  %s\n' % (hashlib.sha256(b).hexdigest(), n)
                           for n, b in sorted(files.items())).encode()
    elif tamper == 'sig':
        signature = signature[:20] + bytes([signature[20] ^ 1]) + signature[21:]
    top = 'acme-%s' % version
    with tarfile.open(path, 'w:gz') as tar:
        dirs = {top, top + '/acmelib'}
        for dn in sorted(dirs):
            ti = tarfile.TarInfo(dn)
            ti.type, ti.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(ti)
        for n, b in [('MANIFEST', manifest), ('MANIFEST.sig', signature)] + sorted(files.items()):
            ti = tarfile.TarInfo(top + '/' + n)
            ti.size, ti.mode = len(b), 0o644
            tar.addfile(ti, io.BytesIO(b))
    return path


class ReleaseSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(cls.d, 'keys'))
        cls.key = ed_key(cls.d, 'acme-release-u4')
        os.makedirs(os.path.join(cls.d, 'untrusted', 'keys'))
        cls.stranger = ed_key(os.path.join(cls.d, 'untrusted'), 'stranger')

    def inspect(self, path):
        env = dict(os.environ, ACME_RELEASE_KEYS=os.path.join(self.d, 'keys'),
                   ACME_LIB=os.path.join(self.d, 'lib'), ACME_STATE=os.path.join(self.d, 'st'))
        r = subprocess.run([sys.executable, '-I', os.path.join(ROOT, 'deploy', 'acme_upgrade.py'),
                            '--inspect', path], capture_output=True, env=env, timeout=120)
        return json.loads(r.stdout.decode() or '{}')

    def test_signed_package_taken(self):
        got = self.inspect(make_release(os.path.join(self.d, 'good.tar.gz'), self.key))
        self.assertTrue(got.get('ok'), got)
        self.assertEqual(got['signed_by'], 'acme-release-u4')

    def test_tampered_packages_refused(self):
        for how, words in (('file', 'is not the file that was signed'),
                           ('manifest', 'signature is not by any release key'),
                           ('sig', 'signature is not by any release key')):
            got = self.inspect(make_release(os.path.join(self.d, how + '.tar.gz'), self.key,
                                            tamper=how))
            self.assertFalse(got.get('ok'), (how, got))
            self.assertIn(words, got.get('said', ''), how)

    def test_unknown_key_refused(self):
        got = self.inspect(make_release(os.path.join(self.d, 'stranger.tar.gz'), self.stranger))
        self.assertFalse(got.get('ok'), got)
        self.assertIn('signature is not by any release key', got.get('said', ''))

    def test_agent_self_update(self):
        AG = load_agent('acme_agent_ru4_lx', False)
        with open(os.path.join(self.d, 'keys', 'acme-release-u4.pub')) as fh:
            der = base64.b64decode(''.join(fh.read().split('-----')[2].split()))
        keys = {'acme-release-u4': der[12:]}
        dest = os.path.join(self.d, 'agent.tar.gz')
        AG.build_package(dest, '99.0.0', key=self.key, keys_dir=os.path.join(self.d, 'keys'))
        with open(dest, 'rb') as fh:
            raw = fh.read()
        with mock.patch.object(AG, 'release_keys', return_value=keys):
            top, files = AG.read_package(raw)
            self.assertEqual(AG.verify_package(top, dict(files))[0], '99.0.0')
            # a file changed: refused
            bad = dict(files)
            bad['acme_agent.py'] = bad['acme_agent.py'] + b'\n# planted\n'
            with self.assertRaises(AG.Refused):
                AG.verify_package(top, bad)
            # MANIFEST rewritten for the changed file: its signature no longer good
            bad['MANIFEST'] = ''.join('%s  %s\n' % (hashlib.sha256(b).hexdigest(), n)
                                      for n, b in sorted(bad.items())
                                      if n not in ('MANIFEST', 'MANIFEST.sig')).encode()
            with self.assertRaises(AG.Refused) as cm:
                AG.verify_package(top, bad)
            self.assertIn('signature', str(cm.exception))
            # the signature itself changed
            bad = dict(files)
            s = bad['MANIFEST.sig']
            bad['MANIFEST.sig'] = s[:5] + bytes([s[5] ^ 1]) + s[6:]
            with self.assertRaises(AG.Refused):
                AG.verify_package(top, bad)
        # the release key unknown to this agent
        with mock.patch.object(AG, 'release_keys', return_value={'other': os.urandom(32)}):
            with self.assertRaises(AG.Refused):
                AG.verify_package(top, dict(files))


# ---- what the rest stands on: the exit codes really say no -------------------------------------
class ExitCodesSayNo(unittest.TestCase):
    """Each place below takes the exit code as its answer (checked by hand in hunt u4); a real
    bad input must give one that is not 0, or that place takes a failure as success."""

    @classmethod
    def setUpClass(cls):
        cls.ca = Ca()
        cls.ca_pem = w('x-ca.pem', pem(cls.ca.cert))
        exp, cls.exp_key = cls.ca.leaf(NOW - 30 * DAY, NOW - DAY)
        cls.expired = w('x-expired.pem', pem(exp))
        good, cls.good_key = cls.ca.leaf(NOW - DAY, NOW + 30 * DAY)
        cls.good = w('x-good.pem', pem(good))
        der = good.public_bytes(serialization.Encoding.DER)
        cls.badsig = w('x-badsig.pem', '-----BEGIN CERTIFICATE-----\n%s'
                       '-----END CERTIFICATE-----\n' % base64.encodebytes(flip_last(der)).decode())

    def test_verify_expired_and_bad_signature(self):
        import acmelib.engine as E
        self.assertEqual(ossl('verify', '-CAfile', self.ca_pem, self.good).returncode, 0)
        self.assertNotEqual(ossl('verify', '-CAfile', self.ca_pem, self.expired).returncode, 0)
        self.assertNotEqual(ossl('verify', '-CAfile', self.ca_pem, self.badsig).returncode, 0)
        # certificate sign-in: an expired one and a forged one refused, in their words
        with self.assertRaises(E.CertRefused) as cm:
            E._cl_verify(self.ca_pem, self.expired)
        self.assertEqual(cm.exception.args[1] if len(cm.exception.args) > 1 else
                         getattr(cm.exception, 'kind', ''), 'expired')
        with self.assertRaises(E.CertRefused):
            E._cl_verify(self.ca_pem, self.badsig)
        self.assertIsNone(E._cl_verify(self.ca_pem, self.good))

    def test_pkcs12_wrong_password(self):
        import acmelib.engine as E
        kp = w('x-good.key', self.good_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode())
        pfx = os.path.join(TMP, 'x.pfx')
        for extra in ([], ['-nomac']):
            subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', kp, '-in', self.good,
                            '-out', pfx, '-passout', 'pass:right'] + extra, check=True,
                           capture_output=True)
            with open(pfx, 'rb') as fh:
                raw = fh.read()
            self.assertNotEqual(ossl('pkcs12', '-nodes', '-in', pfx, '-passin',
                                     'pass:wrong').returncode, 0, extra)
            with self.assertRaises(ValueError) as cm:
                E.cert_bundle(pfx=raw, password='wrong')
            self.assertIn('password', str(cm.exception))
            self.assertIn('BEGIN CERTIFICATE', E.cert_bundle(pfx=raw, password='right')['cert'])

    def test_signatures(self):
        d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(d, 'keys'))
        k = ed_key(d, 'k')
        pub = os.path.join(d, 'keys', 'k.pub')
        m = w('x-msg', 'hello\n')
        sig = os.path.join(d, 'sig')
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', k, '-rawin', '-in', m, '-out',
                        sig], check=True)
        with open(sig, 'rb') as fh:
            s = fh.read()
        bad = w('x-badsig.bin', s[:3] + bytes([s[3] ^ 1]) + s[4:], 'wb')
        self.assertEqual(ossl('pkeyutl', '-verify', '-pubin', '-inkey', pub, '-rawin', '-in', m,
                              '-sigfile', sig).returncode, 0)
        self.assertNotEqual(ossl('pkeyutl', '-verify', '-pubin', '-inkey', pub, '-rawin', '-in',
                                 m, '-sigfile', bad).returncode, 0)
        # passkeys: Ed25519 and ES256, a bad signature refused
        import acmelib.engine as E
        with open(pub) as fh:
            pem_pub = fh.read()
        self.assertTrue(E.pk_verify(pem_pub, -8, b'hello\n', s))
        self.assertFalse(E.pk_verify(pem_pub, -8, b'hello\n', s[:3] + bytes([s[3] ^ 1]) + s[4:]))
        eck = ec.generate_private_key(ec.SECP256R1())
        es = eck.sign(b'data', ec.ECDSA(hashes.SHA256()))
        ep = eck.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.assertTrue(E.pk_verify(ep, -7, b'data', es))
        self.assertFalse(E.pk_verify(ep, -7, b'datA', es))

    @unittest.skipUnless(shutil.which('nginx'), 'nginx is not here')
    def test_nginx_t_failing_config(self):
        d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(d, 'logs'))

        def conf(body):
            p = os.path.join(d, 'n.conf')
            with open(p, 'w') as fh:
                fh.write('pid %s/n.pid; error_log stderr; events {} http { server { %s } }\n'
                         % (d, body))
            return subprocess.run(['nginx', '-t', '-p', d, '-c', p], capture_output=True)
        # no port is listened on by -t; a high one all the same, never 8092 / 8443
        self.assertEqual(conf('listen 127.0.0.1:18471;').returncode, 0)
        self.assertNotEqual(conf('listen 127.0.0.1:18471; bogus_directive on;').returncode, 0)
        self.assertNotEqual(conf('listen 127.0.0.1:18471 ssl; ssl_certificate /nonexistent.pem; '
                                 'ssl_certificate_key /nonexistent.key;').returncode, 0)


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
