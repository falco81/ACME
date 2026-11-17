#!/usr/bin/env python3
"""Bug hunt q2 (1.0.119): the Certificates and Authorities tabs.

    python3 test/test_hunt_q2_certs.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_q2_certs_page.js) when node, php and Playwright are
here.

- "CSR for an outside CA": the certificate is kept as one of an outside CA (source csr), not
  "–" (the source sent was never kept).
- Enter on a button of a row (Renew it now) did what the row does (opened the certificate).
- Import of a wildcard certificate (or one whose CN has brackets): the CN was offered as its
  name, Import refused it ("the certificate's name: letters a-z...").
- The card on a phone: three sections side by side kept 330 px each, cut at the popup's edge.
- The card of an imported certificate said "only when asked" where its Details said "by
  importing a new one".
- The answer of an outside CA dropped: "Leave what was typed here?" asked over it.
- Add a certificate: "Deployments" ran into "9 Review".
- The list between a phone and a wide screen: its names a letter a line.
- Authorities: the buttons of "Published on acme" indented when they wrapped.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


def wildcard_pem():
    """A self-signed wildcard certificate with its key, as one PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '*.q2wild.example.test')])
    t = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(t - datetime.timedelta(days=1))
         .not_valid_after(t + datetime.timedelta(days=60))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName('*.q2wild.example.test')]),
                        False)
         .sign(k, hashes.SHA256()))
    return (c.public_bytes(serialization.Encoding.PEM) + k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()


class HuntQ2Certs(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cid = cls.must('POST', '/api/certs/save', {
            'name': 'q2-issued', 'names': ['q2-issued.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0})['id']
        job = cls.must('POST', '/api/certs/renew', {'id': cid, 'force': True})['job_id']
        end = time.time() + 60
        while time.time() < end:
            st, got = cls.call('GET', '/api/certs/job', None, cls.admin, {'id': job})
            if st == 200 and got['job']['state'] not in ('queued', 'running'):
                break
            time.sleep(0.3)
        # an outside CA's certificate: its CSR, answered by an authority of acme's own
        cls.csr_id = cls.must('POST', '/api/certs/save', {
            'name': 'q2-csr', 'names': ['q2-csr.example.test'], 'issuer': '', 'source': 'csr',
            'key_type': 'ec-256', 'auto_renew': False})['id']
        csr = cls.must('POST', '/api/certs/csr', {'id': cls.csr_id})['csr_pem']
        ca = cls.must('POST', '/api/cas/create', {'name': 'q2 root', 'subject': {'CN': 'q2 root'},
                                                  'key_type': 'ec-256', 'days': 3650})
        ca_id = ca.get('id') or [r for r in cls.must('GET', '/api/cas')['rows']
                                 if r['name'] == 'q2 root'][0]['id']
        cls.answer = cls.must('POST', '/api/cas/sign_csr', {'id': ca_id, 'csr_pem': csr})['cert_pem']
        cls.plain_id = cls.must('POST', '/api/certs/save', {
            'name': 'q2-plain', 'names': ['q2-plain.example.test'], 'issuer': '',
            'key_type': 'ec-256', 'auto_renew': False})['id']

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def one(self, cid):
        got = self.must('GET', '/api/certs/one?id=%d' % cid)
        return got.get('cert') or got

    def test_01_csr_source_kept(self):
        self.assertEqual(self.one(self.csr_id)['source'], 'csr')
        # one by hand with no word of a CSR stays as before
        self.assertEqual(self.one(self.plain_id)['source'], 'manual')

    def test_02_the_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        files = os.path.join(self.tmp, 'q2files')
        os.makedirs(files, exist_ok=True)
        wild = os.path.join(files, 'wild.pem')
        with open(wild, 'w') as f:
            f.write(wildcard_pem())
        answer = os.path.join(files, 'answer.crt')
        with open(answer, 'w') as f:
            f.write(self.answer)
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'hunt_q2_certs_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw, wild, answer],
                                 capture_output=True, text=True, timeout=300, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # Enter on Renew it now: the question of the renewal, not the certificate
        self.assertTrue(seen['enterTitle'].startswith('Renew'), seen)
        # the wildcard: a name acme takes, Import on, kept and opened
        self.assertEqual(seen['importName'], 'wildcard.q2wild.example.test', seen)
        self.assertFalse(seen['importOff'], seen)
        self.assertEqual(seen['importedTitle'], 'wildcard.q2wild.example.test', seen)
        self.assertEqual(seen['renews'], ['by importing a new one'] * 2, seen)
        # the answer taken: the card, nothing asked
        self.assertEqual(seen['answerAsked'], 0, seen)
        self.assertEqual(seen['answerTitle'], 'q2-csr', seen)
        self.assertEqual(seen['stepsOver'], [], seen)
        self.assertEqual(set(seen['pkiMargins']), {'0px'}, seen)
        self.assertEqual(seen['pkiFlex'], 'flex', seen)
        self.assertGreaterEqual(seen['namesWidth'], 150, seen)
        self.assertEqual(seen['phone'], {'wide': 0, 'page': 0, 'cut': 0}, seen)
        # ...and the certificate is in acme
        rows = self.must('GET', '/api/certs?search=q2wild')['rows']
        self.assertEqual([r['name'] for r in rows], ['wildcard.q2wild.example.test'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
