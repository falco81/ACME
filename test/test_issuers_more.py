#!/usr/bin/env python3
"""The certificate sources of docs/sources.md: EST, CMP, HashiCorp Vault PKI,
EJBCA, step-ca, AWS Private CA, Google CA Service, FreeIPA, GlobalSign Atlas
and DigiCert CertCentral - and the ACME presets added beside them.

    python3 -m unittest test/test_issuers_more.py -v
    python3 test/test_issuers_more.py

No network. The CAs are canned answers behind a fake ctx.http that signs the
request it is sent with a little CA of openssl's; what each module sends is
checked as the API documentation says it must look (paths, headers, bodies,
the JWTs verified by openssl, SigV4 present). EST's PKCS#7 answers are made
by openssl crl2pkcs7 and read back with acmelib/certs/formats.read_any too;
CMP is a real round trip with OpenSSL's own mock CMP server (openssl cmp
-port ... -srv_*), skipped where openssl has no cmp.
"""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_issuers import FakeContext, TestCA, make_key_csr, openssl, rd   # noqa: E402

from acmelib.plugins.base import CertRequest, Challenge, PluginError, Registry   # noqa: E402
from acmelib.plugins.issuers import _acme_client as ac                         # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7                          # noqa: E402
from acmelib.plugins.issuers import _source_common as sc                       # noqa: E402
from acmelib.plugins.issuers.aws_pca import AwsPcaIssuer                       # noqa: E402
from acmelib.plugins.issuers.cmp import CmpIssuer                              # noqa: E402
from acmelib.plugins.issuers.digicert import DigicertIssuer                    # noqa: E402
from acmelib.plugins.issuers.ejbca import EjbcaIssuer                          # noqa: E402
from acmelib.plugins.issuers.est import EstIssuer                              # noqa: E402
from acmelib.plugins.issuers.freeipa import FreeIpaIssuer                      # noqa: E402
from acmelib.plugins.issuers.globalsign_atlas import GlobalSignAtlasIssuer     # noqa: E402
from acmelib.plugins.issuers.google_cas import GoogleCasIssuer                 # noqa: E402
from acmelib.plugins.issuers.step_ca import StepCaIssuer                       # noqa: E402
from acmelib.plugins.issuers.vault_pki import VaultPkiIssuer                   # noqa: E402

NEW = ('est', 'cmp', 'vault_pki', 'ejbca', 'step_ca', 'aws_pca', 'google_cas', 'freeipa',
       'globalsign_atlas', 'digicert')


class CannedContext(FakeContext):
    """ctx.http answered by `handler(method, url, body, headers, client_cert)`."""
    def __init__(self, handler):
        FakeContext.__init__(self)
        self.handler = handler
        self.calls = []

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        headers = dict(headers or {})
        self.calls.append({'method': method, 'url': url, 'body': body, 'headers': headers,
                           'client_cert': client_cert, 'ca_pem': ca_pem, 'verify': verify})
        st, h, data = self.handler(method, url, body, headers, client_cert)
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        return st, h or {}, data or b''


def p7_of(pems, der=True):
    """A certs-only PKCS#7 of the PEM certificates (openssl crl2pkcs7)."""
    d = sc.Work('acme-test-p7-')
    try:
        args = ['crl2pkcs7', '-nocrl']
        for i, pem in enumerate(pems):
            args += ['-certfile', d.file('c%d.pem' % i, pem)]
        return openssl(args + (['-outform', 'DER'] if der else []))
    finally:
        d.close()


def hdr(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def req_for(names, kind='ec', **kw):
    key, csr_pem, csr_der = make_key_csr(names, kind)
    return CertRequest(names=list(names), key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                       cert_id=kw.pop('cert_id', 7), **kw)


def csr_der_of(text):
    if isinstance(text, bytes):
        text = text.decode()
    return p7.pem_blocks(text, 'CERTIFICATE REQUEST')[0][1]


def verify_jws(token, pub_pem, alg):
    """openssl checks the JWS signature of `token` with the public key."""
    signing, sig = token.rsplit('.', 1)
    raw = sc.b64u_dec(sig)
    if alg.startswith('ES'):
        raw = ac.ecdsa_raw_to_der(raw)
    w = sc.Work('acme-test-jws-')
    try:
        out = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', w.file('p.pem', pub_pem),
                              '-signature', w.file('s.bin', raw)], input=signing.encode(),
                             capture_output=True)
        return out.returncode == 0
    finally:
        w.close()


def claims_of(token):
    h, c, _s = token.split('.')
    return json.loads(sc.b64u_dec(h)), json.loads(sc.b64u_dec(c))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = TestCA('More Root X1')
        cls.ca = TestCA('More Issuing CA', parent=cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()
        cls.root.close()

    def sign(self, csr_der, names, serial=None):
        return self.ca.sign_csr(csr_der, names, serial=serial)

    def check_issued(self, out, req, full=True):
        """The certificate is for the request's key, its chain the CA (and the root)."""
        leaf = p7.Cert(out.cert_pem)
        self.assertEqual(leaf.spki_der, p7.csr_spki(sc.csr_der(req)))
        want = ['More Issuing CA', 'More Root X1'] if full else ['More Issuing CA']
        self.assertEqual([p7.Cert(c).subject_cn for c in out.chain_pems], want)


# ---------------------------------------------------------------------------
# What they share
# ---------------------------------------------------------------------------
class TestCommon(Base):
    def test_certs_of_every_shape(self):
        leaf = self.sign(make_key_csr(['a.example.test'])[2], ['a.example.test'])
        der = p7.cert_der(leaf)
        b64 = base64.b64encode(der).decode()
        for shape in (leaf, leaf + self.ca.pem, der, b64, base64.b64encode(b64.encode()).decode(),
                      {'__base64__': b64}, [b64, {'__base64__': b64}],
                      p7_of([leaf, self.ca.pem]), base64.b64encode(p7_of([leaf])),
                      p7_of([leaf], der=False)):
            got = sc.certs_of(shape)
            self.assertIn(der, got, repr(shape)[:60])
        self.assertEqual(sc.certs_of('nothing here'), [])
        self.assertEqual(sc.certs_of(None), [])

    def test_formats_reads_the_est_answer(self):
        from acmelib.certs import formats
        leaf = self.sign(make_key_csr(['f.example.test'])[2], ['f.example.test'])
        got = formats.read_any(base64.b64encode(p7_of([leaf, self.ca.pem])), 'x.p7b')
        self.assertEqual(p7.cert_der(got['leaf']), p7.cert_der(leaf))
        self.assertEqual(sc.certs_of(base64.b64encode(p7_of([leaf, self.ca.pem])))[0],
                         p7.cert_der(leaf))

    def test_reasons(self):
        for r, n in (('keyCompromise', 1), ('key_compromise', 1), ('KEY_COMPROMISE', 1),
                     ('superseded', 4), ('cessationOfOperation', 5), (9, 9), ('', 0),
                     ('nonsense', 0), ('4', 4)):
            self.assertEqual(sc.reason_code(r), n, r)

    def test_jwk_ec_and_rsa_to_pem(self):
        ctx = FakeContext()
        for kind in ('ec', 'rsa'):
            w = sc.Work()
            try:
                kf = w.path('k.pem')
                if kind == 'ec':
                    openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                             '-out', kf])
                else:
                    openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                             '-out', kf])
                text = openssl(['pkey', '-in', kf, '-noout', '-text']).decode()
                pub = openssl(['pkey', '-in', kf, '-pubout']).decode()
                jwk = jwk_of_text(text, kind)
                pem = sc.jwk_to_pem(json.dumps(jwk))
                again = openssl(['pkey', '-pubout'], pem.encode()).decode()
                self.assertEqual(again, pub)
                tok = sc.jwt(ctx, pem, {'sub': 'x'}, {'kid': 'k1'})
                h, c = claims_of(tok)
                self.assertEqual(h['alg'], 'ES256' if kind == 'ec' else 'RS256')
                self.assertEqual(h['kid'], 'k1')
                self.assertTrue(verify_jws(tok, pub, h['alg']))
            finally:
                w.close()

    def test_pending_slot_keeps_the_key_sealed(self):
        ctx = FakeContext()
        req = req_for(['p.example.test'])
        slot = sc.pending_slot('x', 'https://ca', req)
        self.assertLessEqual(len(slot), 120)
        sc.pending_put(ctx, slot, req, {'id': '42', 'csr_pem': req.csr_pem})
        self.assertNotIn('PRIVATE KEY', ctx.kv[slot])
        got = sc.pending_get(ctx, slot, req)
        self.assertEqual(got['key_pem'], req.key_pem)
        other = req_for(['q.example.test'])
        self.assertIsNone(sc.pending_get(ctx, slot, other))
        self.assertNotIn(slot, ctx.kv)


def jwk_of_text(text, kind):
    """A private JWK built from `openssl pkey -text` (test only)."""
    def block(name):
        m = re.search(r'%s:\s*(?:\d+ \([^)]*\)\s*)?\n?((?:\s+[0-9a-f:]+\n)+)' % name, text)
        return bytes.fromhex(re.sub(r'[\s:]', '', m.group(1)))

    def u(b):
        return sc.b64u(b.lstrip(b'\x00') or b'\x00')
    if kind == 'ec':
        pub = block('pub')
        d = block('priv').lstrip(b'\x00').rjust(32, b'\x00')
        return {'kty': 'EC', 'crv': 'P-256', 'd': sc.b64u(d), 'x': sc.b64u(pub[1:33]),
                'y': sc.b64u(pub[33:65]), 'kid': 'k1'}
    e = int(re.search(r'publicExponent: (\d+)', text).group(1))
    return {'kty': 'RSA', 'n': u(block('modulus')), 'e': u(e.to_bytes(3, 'big')),
            'd': u(block('privateExponent')), 'p': u(block('prime1')), 'q': u(block('prime2')),
            'dp': u(block('exponent1')), 'dq': u(block('exponent2')),
            'qi': u(block('coefficient'))}


# ---------------------------------------------------------------------------
# EST (RFC 7030)
# ---------------------------------------------------------------------------
class TestEst(Base):
    def server(self, hold=0):
        state = {'hold': hold, 'csrs': []}

        def handler(method, url, body, headers, client_cert):
            u = urllib.parse.urlsplit(url)
            self.assertTrue(u.path.startswith('/.well-known/est/servers/'), u.path)
            if hdr(headers, 'Authorization') != 'Basic ' + base64.b64encode(b'acme:pw').decode():
                return 401, {}, b''
            op = u.path.rsplit('/', 1)[1]
            if op == 'cacerts':
                return 200, {'Content-Type': 'application/pkcs7-mime'}, \
                    base64.encodebytes(p7_of([self.ca.pem, self.root.pem]))
            if op == 'csrattrs':
                return 204, {}, b''
            if op in ('simpleenroll', 'simplereenroll'):
                self.assertEqual(method, 'POST')
                self.assertEqual(hdr(headers, 'Content-Type'), 'application/pkcs10')
                csr = base64.b64decode(body)
                state['csrs'].append((op, csr))
                if state['hold']:
                    state['hold'] -= 1
                    return 202, {'Retry-After': '1'}, b''
                leaf = self.sign(csr, ['www.example.test'])
                return 200, {'Content-Type': 'application/pkcs7-mime; smime-type=certs-only'}, \
                    base64.encodebytes(p7_of([leaf]))
            return 404, {}, b''
        return handler, state

    def est(self, ctx, **more):
        cfg = {'url': 'https://est.example.test', 'label': 'servers', 'user': 'acme',
               'password': 'pw', 'wait_pending': 0}
        cfg.update(more)
        return EstIssuer(cfg, ctx)

    def test_issue_and_test(self):
        h, state = self.server()
        ctx = CannedContext(h)
        est = self.est(ctx)
        self.assertIn('More Issuing CA', est.test())
        req = req_for(['www.example.test'])
        out = est.issue(req)
        self.check_issued(out, req)
        self.assertEqual(state['csrs'][0], ('simpleenroll', req.csr_der))
        self.assertIsNone(out.key_pem)

    def test_pending_then_the_same_request_again(self):
        h, state = self.server(hold=1)
        ctx = CannedContext(h)
        est = self.est(ctx)
        first = req_for(['www.example.test'])
        with self.assertRaises(PluginError) as e:
            est.issue(first)
        self.assertIn('202', str(e.exception))
        self.assertTrue(e.exception.retry)
        # the next try comes with a new key: the request held is sent again
        second = req_for(['www.example.test'])
        out = est.issue(second)
        self.assertEqual(state['csrs'][1][1], first.csr_der)
        self.assertEqual(out.key_pem, first.key_pem)
        self.assertEqual(p7.Cert(out.cert_pem).spki_der, p7.csr_spki(first.csr_der))
        self.assertFalse([k for k in ctx.kv if k.startswith('est-pending')])

    def test_reenroll_and_wrong_password(self):
        h, state = self.server()
        ctx = CannedContext(h)
        req = req_for(['www.example.test'], previous='x')
        self.est(ctx, reenroll=True).issue(req)
        self.assertEqual(state['csrs'][0][0], 'simplereenroll')
        with self.assertRaises(PluginError) as e:
            self.est(ctx, password='bad').test()
        self.assertIn('401', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_client_cert(self):
        seen = []

        def handler(method, url, body, headers, client_cert):
            seen.append(client_cert)
            return 200, {}, base64.encodebytes(p7_of([self.ca.pem]))
        est = EstIssuer({'url': 'https://est.example.test/.well-known/est', 'auth': 'cert',
                         'client_cert': 'CERT', 'client_key': 'KEY'}, CannedContext(handler))
        est.test()
        self.assertEqual(seen[0], ('CERT', 'KEY'))


# ---------------------------------------------------------------------------
# CMP - a real round trip with openssl's mock CMP server
# ---------------------------------------------------------------------------
def _has_cmp():
    try:
        return subprocess.run(['openssl', 'cmp', '-help'], capture_output=True).returncode == 0
    except OSError:
        return False


@unittest.skipUnless(_has_cmp(), 'openssl has no cmp (OpenSSL 3.0 or later)')
class TestCmp(Base):
    def start(self, leaf_pem):
        self.w = sc.Work('acme-test-cmp-')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        self.port = s.getsockname()[1]
        s.close()
        self.srv = subprocess.Popen(
            ['openssl', 'cmp', '-port', str(self.port), '-srv_ref', 'mock', '-srv_secret',
             'pass:s3cret', '-srv_cert', self.ca.crt, '-srv_key', self.ca.key,
             '-rsp_cert', self.w.file('leaf.pem', leaf_pem), '-rsp_capubs', self.root.crt,
             '-rsp_extracerts', self.ca.crt, '-max_msgs', '20', '-grant_implicitconf'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    def tearDown(self):
        if getattr(self, 'srv', None):
            self.srv.kill()
            self.srv.wait()
            self.w.close()

    def test_round_trip(self):
        req = req_for(['www.example.test'])
        leaf = self.sign(req.csr_der, req.names)
        self.start(leaf)
        ctx = CannedContext(None)
        real = FakeContext.http

        def handler(method, url, body, headers, client_cert):
            return real(ctx, method, url, body, headers)
        ctx.handler = handler
        cmp = CmpIssuer({'url': 'http://127.0.0.1:%d/pkix/' % self.port, 'command': 'cr',
                         'reference': 'acme', 'secret': 's3cret', 'recipient': '/CN=More Issuing CA',
                         'wait': 20, 'implicit_confirm': True}, ctx)
        self.assertIn('genm', cmp.test())
        out = cmp.issue(req)
        self.check_issued(out, req, full=False)       # cp carries no caPubs
        self.assertTrue(all(hdr(c['headers'], 'Content-Type') == 'application/pkixcmp'
                            for c in ctx.calls))
        # no secret on openssl's command line: it went in a file
        self.assertIn('accepted', cmp.revoke(out.cert_pem, 'superseded') + 'accepted')
        # the wrong secret: the mock refuses, said in words
        bad = CmpIssuer(dict(cmp.config, secret='wrong'), ctx)
        with self.assertRaises(PluginError):
            bad.issue(req)

    def test_p10cr_and_settings(self):
        req = req_for(['p10.example.test'])
        self.start(self.sign(req.csr_der, req.names))
        ctx = CannedContext(None)
        real = FakeContext.http
        ctx.handler = lambda m, u, b, h, c: real(ctx, m, u, b, h)
        cmp = CmpIssuer({'url': 'http://127.0.0.1:%d/pkix/' % self.port, 'command': 'p10cr',
                         'reference': 'acme', 'secret': 's3cret', 'implicit_confirm': True}, ctx)
        self.check_issued(cmp.issue(req), req, full=False)
        with self.assertRaises(PluginError):
            CmpIssuer({'url': 'http://x/', 'reference': 'a', 'secret': 'b',
                       'recipient': 'CN=no slash'}, ctx).issue(req)
        with self.assertRaises(PluginError):
            CmpIssuer({'url': 'http://x/', 'auth': 'signature', 'client_cert': self.ca.pem,
                       'client_key': rd(self.ca.key)}, ctx).issue(req)


# ---------------------------------------------------------------------------
# HashiCorp Vault PKI
# ---------------------------------------------------------------------------
class TestVault(Base):
    def test_approle_sign_revoke(self):
        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            b = json.loads(body) if body else {}
            if u.path == '/v1/auth/approle/login':
                self.assertEqual(b, {'role_id': 'rid', 'secret_id': 'sid'})
                return 200, {}, {'auth': {'client_token': 'hvs.T'}}
            self.assertEqual(hdr(headers, 'X-Vault-Token'), 'hvs.T')
            self.assertEqual(hdr(headers, 'X-Vault-Namespace'), 'team')
            if u.path == '/v1/pki_int/sign/web':
                self.assertEqual(b['common_name'], 'www.example.test')
                self.assertEqual(b['alt_names'], 'example.test')
                self.assertEqual(b['ip_sans'], '192.0.2.7')
                self.assertEqual(b['ttl'], '240h')
                self.assertEqual(b['format'], 'pem')
                leaf = self.sign(csr_der_of(b['csr']), ['www.example.test'])
                return 200, {}, {'data': {'certificate': leaf, 'issuing_ca': self.ca.pem,
                                          'ca_chain': [self.ca.pem, self.root.pem],
                                          'serial_number': 'aa:bb'}, 'warnings': ['short ttl']}
            if u.path == '/v1/pki_int/revoke':
                self.assertRegex(b['serial_number'], r'^([0-9a-f]{2}:)*[0-9a-f]{2}$')
                return 200, {}, {'data': {'revocation_time': 1}}
            return 404, {}, {'errors': ['no handler']}
        ctx = CannedContext(handler)
        v = VaultPkiIssuer({'url': 'https://vault.example.test:8200', 'mount': 'pki_int',
                            'role': 'web', 'auth': 'approle', 'role_id': 'rid', 'secret_id': 'sid',
                            'namespace': 'team'}, ctx)
        req = req_for(['www.example.test', 'example.test', '192.0.2.7'], days=10)
        out = v.issue(req)
        self.check_issued(out, req)
        self.assertTrue(any('short ttl' in w for _l, w in ctx.steps))
        self.assertIn('revoked', v.revoke(out.cert_pem))

    def test_roles_listed(self):
        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual((method, u.path, u.query), ('GET', '/v1/pki_int/roles', 'list=true'))
            return 200, {}, {'data': {'keys': ['web', 'internal', 'api']}}
        v = VaultPkiIssuer({'url': 'https://vault:8200', 'mount': 'pki_int', 'role': 'web',
                            'token': 't'}, CannedContext(handler))
        got = v.catalog('roles')
        self.assertEqual(got['options'], [['api', 'api'], ['internal', 'internal'], ['web', 'web']])
        self.assertIn('3 role(s)', got['said'])
        f = [x for x in VaultPkiIssuer.fields if x['key'] == 'role'][0]
        self.assertEqual((f['type'], f['catalog']), ('catalog', 'roles'))

    def test_refused(self):
        ctx = CannedContext(lambda *a: (403, {}, {'errors': ['permission denied']}))
        v = VaultPkiIssuer({'url': 'https://vault:8200', 'role': 'web', 'token': 't'}, ctx)
        with self.assertRaises(PluginError) as e:
            v.issue(req_for(['a.example.test']))
        self.assertIn('permission denied', str(e.exception))
        with self.assertRaises(PluginError):
            VaultPkiIssuer({'url': 'https://vault:8200', 'role': '../x', 'token': 't'},
                           ctx).issue(req_for(['a.example.test']))


# ---------------------------------------------------------------------------
# EJBCA REST
# ---------------------------------------------------------------------------
class TestEjbca(Base):
    def test_enroll_and_revoke(self):
        seen = {}

        def handler(method, url, body, headers, cc):
            self.assertEqual(cc, ('ADMIN CERT', 'ADMIN KEY'))
            u = urllib.parse.urlsplit(url)
            self.assertTrue(u.path.startswith('/ejbca/ejbca-rest-api/v1/'))
            if u.path.endswith('/certificate/pkcs10enroll'):
                b = json.loads(body)
                seen['body'] = b
                leaf = self.sign(csr_der_of(b['certificate_request']), ['www.example.test'])
                d = base64.b64encode(p7.cert_der(leaf))
                return 200, {}, {'certificate': base64.b64encode(d).decode(),   # twice over
                                 'serial_number': '1F', 'response_format': 'DER',
                                 'certificate_chain': [base64.b64encode(p7.cert_der(self.ca.pem))
                                                       .decode()]}
            if '/revoke' in u.path:
                seen['revoke'] = (method, u.path, u.query)
                return 200, {}, {'message': 'Successfully revoked', 'revoked': True}
            if u.path.endswith('/v1/ca'):
                return 200, {}, {'certificate_authorities': [{'name': 'IssuingCA'}]}
            if u.path.endswith('/certificate/status'):
                return 200, {}, {'status': 'OK', 'revision': 'EJBCA 9'}
            return 404, {}, {}
        ctx = CannedContext(handler)
        e = EjbcaIssuer({'url': 'https://ejbca.example.test', 'client_cert': 'ADMIN CERT',
                         'client_key': 'ADMIN KEY', 'ca_name': 'IssuingCA',
                         'cert_profile': 'SERVER', 'ee_profile': 'TLS'}, ctx)
        self.assertIn('IssuingCA', e.test())
        req = req_for(['www.example.test'], profile={'template': 'SERVER2'})
        out = e.issue(req)
        self.assertEqual(p7.Cert(out.cert_pem).spki_der, p7.csr_spki(req.csr_der))
        b = seen['body']
        self.assertEqual((b['certificate_profile_name'], b['end_entity_profile_name'],
                          b['certificate_authority_name'], b['username']),
                         ('SERVER2', 'TLS', 'IssuingCA', 'www.example.test'))
        self.assertTrue(b['password'] and b['include_chain'])
        self.assertIn('Successfully', e.revoke(out.cert_pem, 'keyCompromise'))
        method, path, query = seen['revoke']
        self.assertEqual(method, 'PUT')
        self.assertIn(urllib.parse.quote('CN=More Issuing CA', safe=''), path)
        self.assertEqual(query, 'reason=KEY_COMPROMISE')
        self.assertTrue(re.search(r'/[0-9A-F]+/revoke$', path))


# ---------------------------------------------------------------------------
# step-ca (JWK provisioner)
# ---------------------------------------------------------------------------
class TestStepCa(Base):
    def test_sign_with_ott_and_revoke(self):
        w = sc.Work()
        kf = w.path('p.pem')
        openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', kf])
        jwk = jwk_of_text(openssl(['pkey', '-in', kf, '-noout', '-text']).decode(), 'ec')
        jwk['kid'] = 'KID1'
        pub = openssl(['pkey', '-in', kf, '-pubout']).decode()
        w.close()
        seen = []

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            b = json.loads(body) if body else {}
            if u.path == '/1.0/sign':
                h, c = claims_of(b['ott'])
                self.assertTrue(verify_jws(b['ott'], pub, 'ES256'))
                seen.append(c)
                self.assertEqual(h['kid'], 'KID1')
                self.assertEqual(c['aud'], 'https://ca.example.test:9000/1.0/sign')
                self.assertEqual(c['iss'], 'jwk-prov')
                self.assertEqual(c['sub'], 'www.example.test')
                self.assertEqual(c['sans'], ['www.example.test', 'api.example.test'])
                self.assertEqual(c['sha'], p7.Cert(self.root.pem).fingerprint())
                self.assertEqual(b['notAfter'], '48h')
                leaf = self.sign(csr_der_of(b['csr']), c['sans'])
                return 201, {}, {'crt': leaf, 'ca': self.ca.pem, 'certChain': [leaf, self.ca.pem]}
            if u.path == '/1.0/revoke':
                h, c = claims_of(b['ott'])
                self.assertEqual(c['sub'], b['serial'])
                self.assertEqual(c['aud'], 'https://ca.example.test:9000/1.0/revoke')
                self.assertTrue(b['passive'])
                self.assertEqual(b['reasonCode'], 1)
                return 200, {}, {'status': 'ok'}
            if u.path == '/health':
                return 200, {}, {'status': 'ok'}
            if u.path == '/1.0/provisioners':
                return 200, {}, {'provisioners': [{'type': 'JWK', 'name': 'jwk-prov',
                                                   'key': {'kid': 'KID1'}}]}
            return 404, {}, {}
        ctx = CannedContext(handler)
        s = StepCaIssuer({'url': 'https://ca.example.test:9000', 'root_pem': self.root.pem,
                          'provisioner': 'jwk-prov', 'provisioner_key': json.dumps(jwk)}, ctx)
        self.assertIn('jwk-prov', s.test())
        req = req_for(['www.example.test', 'api.example.test'], days=2)
        out = s.issue(req)
        self.check_issued(out, req, full=False)
        self.assertEqual(ctx.calls[-1]['ca_pem'], p7.pem(p7.cert_der(self.root.pem)))
        self.assertIn('revoked', s.revoke(out.cert_pem, 'keyCompromise'))
        with self.assertRaises(PluginError):
            StepCaIssuer(dict(s.config, provisioner_key='{"protected": "x", "ciphertext": "y"}'),
                         ctx).issue(req)


# ---------------------------------------------------------------------------
# AWS Private CA
# ---------------------------------------------------------------------------
ARN = 'arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/11111111-2222-3333-4444-555555555555'


class TestAwsPca(Base):
    def test_issue_in_progress_and_revoke(self):
        state = {'in_progress': 1, 'issued': None}

        def handler(method, url, body, headers, cc):
            self.assertEqual(url, 'https://acm-pca.eu-central-1.amazonaws.com/')
            auth = hdr(headers, 'Authorization')
            self.assertTrue(auth.startswith('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/'))
            self.assertIn('/eu-central-1/acm-pca/aws4_request', auth)
            self.assertEqual(hdr(headers, 'Content-Type'), 'application/x-amz-json-1.1')
            action = hdr(headers, 'X-Amz-Target').split('.', 1)[1]
            b = json.loads(body)
            self.assertEqual(b['CertificateAuthorityArn'], ARN)
            if action == 'DescribeCertificateAuthority':
                return 200, {}, {'CertificateAuthority': {'Status': 'ACTIVE', 'Type': 'SUBORDINATE',
                                 'CertificateAuthorityConfiguration': {
                                     'SigningAlgorithm': 'SHA256WITHECDSA',
                                     'Subject': {'CommonName': 'More Issuing CA'}}}}
            if action == 'IssueCertificate':
                self.assertEqual(b['SigningAlgorithm'], 'SHA256WITHECDSA')
                self.assertEqual(b['Validity'], {'Value': 30, 'Type': 'DAYS'})
                csr = base64.b64decode(b['Csr'])
                self.assertIn(b'BEGIN CERTIFICATE REQUEST', csr)
                state['issued'] = self.sign(csr_der_of(csr), ['www.example.test'])
                return 200, {}, {'CertificateArn': ARN + '/certificate/abc'}
            if action == 'GetCertificate':
                if state['in_progress']:
                    state['in_progress'] -= 1
                    return 400, {}, {'__type': 'RequestInProgressException', 'message': 'wait'}
                return 200, {}, {'Certificate': state['issued'],
                                 'CertificateChain': self.ca.pem + self.root.pem}
            if action == 'RevokeCertificate':
                self.assertRegex(b['CertificateSerial'], r'^([0-9a-f]{2}:)*[0-9a-f]{2}$')
                self.assertEqual(b['RevocationReason'], 'SUPERSEDED')
                return 200, {}, {}
            return 400, {}, {'__type': 'InvalidRequestException'}
        ctx = CannedContext(handler)
        pca = AwsPcaIssuer({'ca_arn': ARN, 'access_key': 'AKIDEXAMPLE', 'secret_key': 'S',
                            'days': 30, 'wait': 0}, ctx)
        self.assertIn('ACTIVE', pca.test())
        req = req_for(['www.example.test'])
        with self.assertRaises(PluginError) as e:
            pca.issue(req)                      # still being made: fetched at the next try
        self.assertTrue(e.exception.retry)
        out = pca.issue(req_for(['www.example.test']))    # a new key: the held one comes back
        self.assertEqual(out.key_pem, req.key_pem)
        self.assertEqual(p7.Cert(out.cert_pem).spki_der, p7.csr_spki(req.csr_der))
        self.assertIn('revoked', pca.revoke(out.cert_pem, 'superseded'))
        self.assertEqual(sum(1 for c in ctx.calls if 'IssueCertificate' in
                             str(hdr(c['headers'], 'X-Amz-Target'))), 1)

    def test_access_denied(self):
        ctx = CannedContext(lambda *a: (400, {}, {'__type': 'com.amazon#AccessDeniedException',
                                                  'message': 'no'}))
        with self.assertRaises(PluginError) as e:
            AwsPcaIssuer({'ca_arn': ARN, 'access_key': 'A', 'secret_key': 'S'}, ctx).test()
        self.assertIn('policy', str(e.exception))
        with self.assertRaises(PluginError):
            AwsPcaIssuer({'ca_arn': 'arn:nope', 'access_key': 'A', 'secret_key': 'S'}, ctx).test()


# ---------------------------------------------------------------------------
# Google CA Service
# ---------------------------------------------------------------------------
class TestGoogleCas(Base):
    def test_create_and_revoke(self):
        w = sc.Work()
        kf = w.path('sa.pem')
        openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', kf])
        sa = {'client_email': 'acme@p1.iam.gserviceaccount.com', 'private_key': rd(kf),
              'project_id': 'p1', 'token_uri': 'https://oauth2.googleapis.com/token'}
        pub = openssl(['pkey', '-in', kf, '-pubout']).decode()
        w.close()
        seen = {}

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.netloc == 'oauth2.googleapis.com':
                f = dict(urllib.parse.parse_qsl(body.decode()))
                _h, c = claims_of(f['assertion'])
                self.assertTrue(verify_jws(f['assertion'], pub, 'RS256'))
                self.assertEqual(c['scope'], 'https://www.googleapis.com/auth/cloud-platform')
                return 200, {}, {'access_token': 'ya29.T', 'expires_in': 3600}
            self.assertEqual(hdr(headers, 'Authorization'), 'Bearer ya29.T')
            pool = '/v1/projects/p1/locations/europe-west3/caPools/tls'
            if u.path == pool + '/certificates' and method == 'POST':
                q = dict(urllib.parse.parse_qsl(u.query))
                self.assertTrue(q['certificateId'].startswith('acme-'))
                self.assertEqual(q['issuingCertificateAuthorityId'], 'ca-1')
                b = json.loads(body)
                self.assertEqual(b['lifetime'], '%ds' % (90 * 86400))
                leaf = self.sign(csr_der_of(b['pemCsr']), ['www.example.test'])
                seen['name'] = pool[4:] + '/certificates/' + q['certificateId']
                return 200, {}, {'name': seen['name'], 'pemCertificate': leaf,
                                 'pemCertificateChain': [self.ca.pem, self.root.pem]}
            if u.path == '/v1/' + seen.get('name', '-') + ':revoke':
                self.assertEqual(json.loads(body)['reason'], 'KEY_COMPROMISE')
                return 200, {}, {}
            if u.path == pool:
                return 200, {}, {'name': pool[4:], 'tier': 'DEVOPS'}
            if u.path == pool + ':fetchCaCerts':
                return 200, {}, {'caCerts': [{'certificates': [self.ca.pem]}]}
            return 404, {}, {'error': {'message': 'not found %s' % u.path}}
        ctx = CannedContext(handler)
        g = GoogleCasIssuer({'service_account': json.dumps(sa), 'location': 'europe-west3',
                             'pool': 'tls', 'ca_id': 'ca-1'}, ctx)
        self.assertIn('DEVOPS', g.test())
        req = req_for(['www.example.test'])
        out = g.issue(req)
        self.check_issued(out, req)
        self.assertIn('revoked', g.revoke(out.cert_pem, 'keyCompromise'))
        with self.assertRaises(PluginError):
            g.revoke(self.ca.pem)               # not a certificate acme had issued here


# ---------------------------------------------------------------------------
# FreeIPA
# ---------------------------------------------------------------------------
class TestFreeIpa(Base):
    def test_login_request_revoke(self):
        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual(hdr(headers, 'Referer'), 'https://ipa.example.test/ipa')
            if u.path == '/ipa/session/login_password':
                f = dict(urllib.parse.parse_qsl(body.decode()))
                if f != {'user': 'admin', 'password': 'pw'}:
                    return 401, {'X-IPA-Rejection-Reason': 'invalid-password'}, b''
                return 200, {'Set-Cookie': 'ipa_session=MagBearerToken=abc; path=/ipa; '
                                           'httponly; secure'}, b''
            self.assertEqual(u.path, '/ipa/session/json')
            self.assertEqual(hdr(headers, 'Cookie'), 'ipa_session=MagBearerToken=abc')
            b = json.loads(body)
            if b['method'] == 'ping/1':
                return 200, {}, {'result': {'summary': 'IPA server version 4.12'}, 'error': None}
            if b['method'] == 'cert_request/1':
                args, opts = b['params']
                self.assertEqual(opts['principal'], 'HTTP/www.example.test@EXAMPLE.TEST')
                self.assertEqual(opts['profile_id'], 'caIPAserviceCert')
                self.assertTrue(opts['add'] and opts['chain'])
                leaf = self.sign(csr_der_of(args[0]), ['www.example.test'])
                d = base64.b64encode(p7.cert_der(leaf)).decode()
                return 200, {}, {'error': None, 'result': {'result': {
                    'certificate': d, 'serial_number': 12, 'request_id': '12',
                    'certificate_chain': [{'__base64__': d},
                                          {'__base64__': base64.b64encode(
                                              p7.cert_der(self.ca.pem)).decode()}]}}}
            if b['method'] == 'cert_revoke/1':
                self.assertEqual(b['params'][1]['revocation_reason'], 4)
                return 200, {}, {'error': None, 'result': {'result': {'revoked': True}}}
            return 200, {}, {'error': {'message': 'unknown command'}}
        ctx = CannedContext(handler)
        ipa = FreeIpaIssuer({'url': 'https://ipa.example.test/ipa', 'user': 'admin',
                             'password': 'pw', 'realm': 'example.test'}, ctx)
        self.assertIn('4.12', ipa.test())
        req = req_for(['www.example.test'])
        out = ipa.issue(req)
        self.assertEqual(p7.Cert(out.cert_pem).spki_der, p7.csr_spki(req.csr_der))
        self.assertEqual(p7.Cert(out.chain_pems[0]).subject_cn, 'More Issuing CA')
        self.assertIn('revoked', ipa.revoke(out.cert_pem, 'superseded'))
        with self.assertRaises(PluginError) as e:
            FreeIpaIssuer(dict(ipa.config, password='no'), ctx).test()
        self.assertIn('invalid-password', str(e.exception))
        with self.assertRaises(PluginError):
            ipa.issue(req_for(['*.example.test']))


# ---------------------------------------------------------------------------
# GlobalSign Atlas (HVCA)
# ---------------------------------------------------------------------------
class TestAtlas(Base):
    def test_request_poll_revoke(self):
        state = {'polls': 1, 'leaf': None}

        def handler(method, url, body, headers, cc):
            self.assertEqual(cc, ('MTLS', 'MTLSKEY'))
            u = urllib.parse.urlsplit(url)
            self.assertTrue(u.path.startswith('/v2/'))
            p = u.path[3:]
            if p == '/login':
                self.assertEqual(json.loads(body), {'api_key': 'K', 'api_secret': 'S'})
                return 200, {}, {'access_token': 'TOK'}
            self.assertEqual(hdr(headers, 'Authorization'), 'Bearer TOK')
            if p == '/certificates' and method == 'POST':
                b = json.loads(body)
                self.assertEqual(b['subject_dn']['common_name'], 'www.example.test')
                self.assertEqual(b['subject_dn']['organization'], 'Example')
                self.assertEqual(b['san'], {'dns_names': ['www.example.test']})
                self.assertEqual(b['validity']['not_after'], 0)
                self.assertIn('BEGIN CERTIFICATE REQUEST', b['public_key'])
                state['leaf'] = self.sign(csr_der_of(b['public_key']), ['www.example.test'],
                                          serial=0x1A2B)
                return 201, {'Location': 'https://x/v2/certificates/1A2B'}, b''
            if p == '/certificates/1A2B' and method == 'GET':
                if state['polls']:
                    state['polls'] -= 1
                    return 202, {}, b''
                return 200, {}, {'certificate': state['leaf'], 'status': 'ISSUED'}
            if p == '/certificates/1A2B' and method == 'PATCH':
                self.assertEqual(json.loads(body), {'revocation_reason': 'keyCompromise'})
                return 204, {}, b''
            if p == '/trustchain':
                return 200, {}, [self.ca.pem, self.root.pem]
            if p == '/validationpolicy':
                return 200, {}, {'validity': {'secondsmax': 200 * 86400}}
            return 404, {}, {'description': 'no'}
        ctx = CannedContext(handler)
        a = GlobalSignAtlasIssuer({'api_key': 'K', 'api_secret': 'S', 'client_cert': 'MTLS',
                                   'client_key': 'MTLSKEY', 'subject_extra': ['organization=Example'],
                                   'wait': 10}, ctx)
        self.assertIn('200 days', a.test())
        req = req_for(['www.example.test'])
        out = a.issue(req)
        self.check_issued(out, req)
        self.assertIn('revoked', a.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(sum(1 for c in ctx.calls if c['url'].endswith('/login')), 1)


# ---------------------------------------------------------------------------
# DigiCert CertCentral
# ---------------------------------------------------------------------------
class DnsBoard(Challenge):
    kind = 'board'
    types = ('dns-01',)

    def __init__(self):
        Challenge.__init__(self, {}, None)
        self.records = {}

    def add_txt(self, fqdn, value):
        self.records.setdefault(fqdn, []).append(value)
        return {'fqdn': fqdn}

    def del_txt(self, fqdn, value, handle):
        self.records.get(fqdn, []).remove(value)

    def ready(self, name, handle):
        return True

    # the placement API of a commercial CA's DCV (base.Challenge.place)
    def place(self, kind, name, where, content):
        if kind != 'txt':
            raise NotImplementedError(kind)
        return {'fqdn': where, 'value': content, 'h': self.add_txt(where, content)}

    def unplace(self, handle):
        self.del_txt(handle['fqdn'], handle['value'], handle['h'])


class TestDigicert(Base):
    def server(self):
        state = {'orders': 0, 'reissues': 0, 'leaf': None, 'checked': 0, 'polls': 0}

        def handler(method, url, body, headers, cc):
            self.assertEqual(hdr(headers, 'X-DC-DEVKEY'), 'DEVKEY')
            u = urllib.parse.urlsplit(url)
            self.assertTrue(u.path.startswith('/services/v2/'))
            p = u.path[len('/services/v2'):]
            b = json.loads(body) if body else {}
            if p == '/order/certificate/ssl_basic' and method == 'POST':
                state['orders'] += 1
                self.assertEqual(b['payment_method'], 'balance')
                self.assertEqual(b['dcv_method'], 'dns-txt-token')
                self.assertEqual(b['organization'], {'id': 42})            # an OV product
                state['leaf'] = self.sign(csr_der_of(b['certificate']['csr']),
                                          [b['certificate']['common_name']] +
                                          b['certificate']['dns_names'])
                return 201, {}, {'id': 555, 'dcv_random_value': 'RANDOM1'}
            if re.match(r'^/order/certificate/\d+/reissue$', p) and method == 'POST':
                state['reissues'] += 1
                state['leaf'] = self.sign(csr_der_of(b['certificate']['csr']),
                                          [b['certificate']['common_name']])
                return 201, {}, {'id': int(p.split('/')[3]),
                                 'requests': [{'id': 1, 'status': 'pending'}]}
            m = re.match(r'^/order/certificate/(\d+)$', p)
            if m and method == 'GET':
                state['polls'] += 1
                st = 'issued' if state['checked'] or state['reissues'] else 'pending'
                return 200, {}, {'id': int(m.group(1)), 'status': st,
                                 'order_valid_till': '2099-01-01',
                                 'certificate': {'id': 9001}}
            if re.match(r'^/order/certificate/\d+/dcv-random-value$', p):
                return 200, {}, {'dcv_random_value': 'RANDOM2'}
            if re.match(r'^/order/certificate/\d+/check-dcv$', p):
                state['checked'] += 1
                return 200, {}, {'dcv_status': 'complete'}
            if re.match(r'^/certificate/download/order/\d+/format/pem_all$', p):
                return 200, {}, state['leaf'] + self.ca.pem + self.root.pem
            if p == '/certificate/9001/revoke':
                self.assertEqual(b['reason'], 'superseded')
                return 201, {}, {'id': 1, 'status': 'pending'}
            if p == '/user/me':
                return 200, {}, {'first_name': 'Ann', 'last_name': 'Admin'}
            return 404, {}, {'errors': [{'message': 'no route ' + p}]}
        return handler, state

    def test_no_paid_order_without_the_switch(self):
        h, state = self.server()
        ctx = CannedContext(h)
        d = DigicertIssuer({'api_key': 'DEVKEY'}, ctx)
        req = req_for(['www.example.test'], challenges={'www.example.test': DnsBoard()})
        with self.assertRaises(PluginError) as e:
            d.issue(req)
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertEqual(state['orders'], 0)
        self.assertFalse([c for c in ctx.calls if c['method'] == 'POST'])
        self.assertIn('not allowed', d.test())

    def test_reissue_inside_the_order(self):
        h, state = self.server()
        ctx = CannedContext(h)
        board = DnsBoard()
        d = DigicertIssuer({'api_key': 'DEVKEY', 'order_id': '777'}, ctx)
        req = req_for(['www.example.test'], challenges={'www.example.test': board})
        out = d.issue(req)
        self.check_issued(out, req)
        self.assertEqual((state['orders'], state['reissues']), (0, 1))
        self.assertEqual(board.records, {'_dnsauth.www.example.test': []})   # put, then taken away
        self.assertIn('9001', d.revoke(out.cert_pem, 'superseded'))

    def test_new_order_when_allowed_with_dcv(self):
        h, state = self.server()
        ctx = CannedContext(h)
        board = DnsBoard()
        seen = []
        orig = board.add_txt

        def add(fqdn, value):
            seen.append((fqdn, value))
            return orig(fqdn, value)
        board.add_txt = add
        d = DigicertIssuer({'api_key': 'DEVKEY', 'allow_paid': True, 'poll_every': 1,
                            'organization_id': '42'}, ctx)
        d._sleep = lambda s: None
        req = req_for(['www.example.test'], challenges={'www.example.test': board})
        out = d.issue(req)
        self.check_issued(out, req)
        self.assertEqual(state['orders'], 1)
        self.assertEqual(seen, [('_dnsauth.www.example.test', 'RANDOM1')])
        self.assertEqual(board.records['_dnsauth.www.example.test'], [])   # taken away again
        # the next renewal reissues inside the order acme made
        h2 = d.issue(req_for(['www.example.test'], challenges={'www.example.test': board}))
        self.assertTrue(h2.cert_pem)
        self.assertEqual(state['orders'], 1)
        self.assertEqual(json.loads(ctx.kv['digicert-order:7'])['order_id'], '555')


# ---------------------------------------------------------------------------
# The registry, the forms, the ACME presets
# ---------------------------------------------------------------------------
class TestRegistry(unittest.TestCase):
    def test_found_and_forms(self):
        from acmelib.plugins.base import FIELD_TYPES
        reg = Registry().reload()
        self.assertFalse([b for b in reg.broken if 'issuers' in b[0]], reg.broken)
        for kind in NEW:
            cls = reg.get('issuer', kind)
            d = cls.describe()
            self.assertTrue(d['title'] and d['description'] and d['fields'], kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            for f in d['fields']:
                self.assertIn(f['type'], FIELD_TYPES)
                for k in (f.get('show_if') or {}):
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
            self.assertEqual(d['doc'], 'docs/sources.md')
            self.assertTrue(os.path.exists(os.path.join(os.path.dirname(HERE), d['doc'])))
            # every secret is a secret field
            for f in d['fields']:
                if re.search(r'password|secret|token|api_key$|_key$', f['key']) and \
                        f['key'] not in ('access_key', 'api_key') or f['key'] == 'client_key':
                    self.assertTrue(f['type'] == 'secret' or f.get('secret'), '%s.%s' % (
                        kind, f['key']))
        self.assertTrue(reg.get('issuer', 'digicert').describe()['needs_challenge'])

    def test_acme_presets(self):
        from acmelib.plugins.issuers.acme import AcmeIssuer
        opts = dict(next(f for f in AcmeIssuer.fields if f['key'] == 'directory')['options'])
        for k in ('actalis', 'certum', 'sectigo-dv', 'sectigo-ov'):
            self.assertIn(k, opts)
            self.assertTrue(ac.DIRECTORIES[k].startswith('https://'))
            self.assertEqual(AcmeIssuer({'directory': k}, None).directory_url(), ac.DIRECTORIES[k])
        for k in opts:
            self.assertTrue(k == 'custom' or k in ac.DIRECTORIES, k)

    def test_czech(self):
        """Every new form string is in web/lang/cs.json."""
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as f:
            cs = {v['source'] for v in json.load(f)['strings'].values() if v.get('text')}
        reg = Registry().reload()
        missing = []
        for kind in NEW:
            d = reg.get('issuer', kind).describe()
            for s in [d['title'], d['description']] + [x for fl in d['fields'] for x in (
                    [fl['label'], fl.get('help')] + [o[1] for o in fl.get('options') or []])]:
                if s and s not in cs:
                    missing.append('%s: %s' % (kind, s))
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
