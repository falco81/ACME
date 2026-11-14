#!/usr/bin/env python3
"""The issuers acme speaks to by itself: ACME (Let's Encrypt and others),
Microsoft AD CS (Web Enrollment, NTLM) and SCEP.

    python3 -m unittest test/test_issuers.py -v
    python3 test/test_issuers.py

No network: the CAs are mock servers in threads on 127.0.0.1, the crypto is
the openssl program. Checked against what the standards say: JWS signatures
verified by openssl, the ARI id of RFC 9773's example, MD4 (RFC 1320) and
NTLMv2 (MS-NLMP 4.2.4) test vectors, SCEP messages verified and decrypted by
openssl cms. With ACME_TEST_PEBBLE=/path/to/pebble a real order is also made
against pebble (Let's Encrypt's test server).
"""
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.plugins.base import Challenge, CertRequest, Context, PluginError  # noqa: E402
from acmelib.plugins.issuers import _acme_client as ac                       # noqa: E402
from acmelib.plugins.issuers import _ntlm                                     # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7                         # noqa: E402
from acmelib.plugins.issuers.acme import AcmeIssuer                           # noqa: E402
from acmelib.plugins.issuers.ms_adcs import MsAdcsIssuer                      # noqa: E402
from acmelib.plugins.issuers import ms_adcs as ms_adcs_mod                    # noqa: E402
from acmelib.plugins.issuers.scep import ScepIssuer                           # noqa: E402


def openssl(args, data=None, timeout=60):
    p = subprocess.run(['openssl'] + list(args), input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError('openssl %s: %s' % (' '.join(args[:2]), p.stderr.decode()[-400:]))
    return p.stdout


def wr(path, data):
    with open(path, 'wb' if isinstance(data, bytes) else 'w') as f:
        f.write(data)


def rd(path):
    with open(path) as f:
        return f.read()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---------------------------------------------------------------------------
# A Context as acmelib.certs gives one, enough for the issuers
# ---------------------------------------------------------------------------
class FakeContext(Context):
    def __init__(self):
        self.steps = []
        self.kv = {}
        self.node = 'test'
        self.settings = {}

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, words):
        pass

    def cancelled(self):
        return False

    def openssl(self, args, data=None, timeout=60):
        return openssl(args, data, timeout)

    def kv_get(self, key):
        return self.kv.get(key)

    def kv_keys(self, prefix=''):
        return {k: v for k, v in self.kv.items() if k.startswith(prefix)}

    def kv_set(self, key, value, ttl_s=None):
        assert len(key) <= 120, key            # what the real Context keeps
        if value is None:
            self.kv.pop(key, None)
        else:
            self.kv[key] = value

    def seal(self, text, bind):
        return 'sealed:' + base64.b64encode(text.encode()).decode()

    def unseal(self, value, bind):
        return base64.b64decode(value[7:]).decode()

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        u = urllib.parse.urlsplit(url)
        if u.scheme == 'https':
            sc = ssl.create_default_context()
            if ca_pem:
                sc.load_verify_locations(cadata=ca_pem)
            if not verify:
                sc.check_hostname = False
                sc.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=sc)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        path = u.path or '/'
        if u.query:
            path += '?' + u.query
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            data = r.read()
            hdrs = {}
            for k, v in r.getheaders():
                k = k.lower()
                hdrs[k] = hdrs[k] + ', ' + v if k in hdrs else v
            return r.status, hdrs, data
        finally:
            conn.close()


class FakeChallenge(Challenge):
    """Puts its proofs where the mock CA looks."""
    kind = 'fake'

    def __init__(self, types, board, parallel=True):
        Challenge.__init__(self, {}, None)
        self.types = types
        self.board = board
        self.parallel = parallel
        self.log = []
        self.ready_calls = 0

    def present(self, name, token, key_authorization, txt_value):
        self.log.append(('present', name))
        if 'dns-01' in self.types:
            self.board['dns'].setdefault(name, []).append(txt_value)
            return {'name': name, 'txt': txt_value}
        self.board['http'][token] = key_authorization
        return {'token': token}

    def ready(self, name, handle):
        self.ready_calls += 1
        return self.ready_calls > 1          # not at once: the waiting is exercised

    def cleanup(self, name, handle):
        self.log.append(('cleanup', name))
        if 'txt' in handle:
            self.board['dns'][name].remove(handle['txt'])
        else:
            self.board['http'].pop(handle['token'], None)


# ---------------------------------------------------------------------------
# A small CA for the mock servers
# ---------------------------------------------------------------------------
class TestCA(object):
    def __init__(self, cn='Test Root X1', ski=None, rsa=False, parent=None):
        self.dir = tempfile.mkdtemp(prefix='acme-test-ca-')
        self.key = os.path.join(self.dir, 'ca.key')
        self.crt = os.path.join(self.dir, 'ca.crt')
        if rsa:
            openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', self.key])
        else:
            openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', self.key])
        ext = os.path.join(self.dir, 'ext.cnf')
        with open(ext, 'w') as f:
            f.write('[v]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
                    'subjectKeyIdentifier=%s\n' % (ski or 'hash'))
            if parent:
                f.write('authorityKeyIdentifier=keyid\n')
        if parent:
            csr = openssl(['req', '-new', '-key', self.key, '-subj', '/CN=' + cn])
            wr(os.path.join(self.dir, 'ca.csr'), csr)
            openssl(['x509', '-req', '-in', os.path.join(self.dir, 'ca.csr'), '-CA', parent.crt,
                     '-CAkey', parent.key, '-set_serial', '7', '-days', '30', '-extfile', ext,
                     '-extensions', 'v', '-out', self.crt])
        else:
            openssl(['req', '-new', '-x509', '-key', self.key, '-subj', '/CN=' + cn, '-days', '30',
                     '-config', ext, '-extensions', 'v', '-out', self.crt])
        self.pem = rd(self.crt)
        self.serial = 100

    def sign_csr(self, csr_der, names=(), days=7, serial=None, ext_more=''):
        self.serial += 1
        d = tempfile.mkdtemp(dir=self.dir)
        csr = os.path.join(d, 'r.der')
        wr(csr, csr_der)
        ext = os.path.join(d, 'e.cnf')
        san = ','.join(('IP:' if re.match(r'^[\d.]+$', n) else 'DNS:') + n for n in names)
        with open(ext, 'w') as f:
            f.write('[v]\nbasicConstraints=CA:FALSE\nauthorityKeyIdentifier=keyid\n%s%s\n'
                    % (('subjectAltName=' + san + '\n') if san else '', ext_more))
        out = openssl(['x509', '-req', '-inform', 'DER', '-in', csr, '-CA', self.crt, '-CAkey', self.key,
                       '-set_serial', str(serial or self.serial), '-days', str(days), '-extfile', ext,
                       '-extensions', 'v'])
        return out.decode()

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def make_key_csr(names, kind='ec'):
    d = tempfile.mkdtemp(prefix='acme-test-req-')
    key = os.path.join(d, 'k.pem')
    if kind == 'ec':
        openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key])
    else:
        openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
    san = ','.join(('IP:' if re.match(r'^[\d.]+$', n) else 'DNS:') + n for n in names)
    csr_pem = openssl(['req', '-new', '-key', key, '-subj', '/CN=' + names[0], '-addext',
                       'subjectAltName=' + san]).decode()
    csr_der = openssl(['req', '-in', '/dev/stdin', '-outform', 'DER'], csr_pem.encode())
    key_pem = rd(key)
    shutil.rmtree(d)
    return key_pem, csr_pem, csr_der


class Server(object):
    """An http.server in a thread on 127.0.0.1."""
    def __init__(self, handler_cls):
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
        self.httpd.app = self
        self.port = self.httpd.server_address[1]
        self.base = 'http://127.0.0.1:%d' % self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def send(self, status, body=b'', ctype='application/json', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(n) if n else b''


# ---------------------------------------------------------------------------
# A mock ACME CA (RFC 8555) that checks every JWS with openssl
# ---------------------------------------------------------------------------
def verify_jws(jws, jwk):
    """The JWS signature checked by openssl against the JWK (EC or RSA)."""
    prot = json.loads(b64u_dec(jws['protected']))
    signing_input = ('%s.%s' % (jws['protected'], jws['payload'])).encode()
    sig = b64u_dec(jws['signature'])
    d = tempfile.mkdtemp()
    try:
        pub = os.path.join(d, 'pub.pem')
        if jwk['kty'] == 'EC':
            pt = b'\x04' + b64u_dec(jwk['x']) + b64u_dec(jwk['y'])
            curve = {'P-256': '1.2.840.10045.3.1.7', 'P-384': '1.3.132.0.34'}[jwk['crv']]
            spki = p7.seq(p7.seq(p7.der_oid('1.2.840.10045.2.1'), p7.der_oid(curve)), p7.tlv(0x03, b'\x00' + pt))
            sig = ac.ecdsa_raw_to_der(sig)
        else:
            rsa = p7.seq(p7.der_int(int.from_bytes(b64u_dec(jwk['n']), 'big')),
                         p7.der_int(int.from_bytes(b64u_dec(jwk['e']), 'big')))
            spki = p7.seq(p7.seq(p7.der_oid(p7.OID_RSA), p7.der_null()), p7.tlv(0x03, b'\x00' + rsa))
        wr(pub, p7.pem(spki, 'PUBLIC KEY'))
        sigf = os.path.join(d, 'sig')
        wr(sigf, sig)
        dg = {'ES256': '-sha256', 'ES384': '-sha384', 'RS256': '-sha256'}[prot['alg']]
        p = subprocess.run(['openssl', 'dgst', dg, '-verify', pub, '-signature', sigf],
                           input=signing_input, capture_output=True)
        return p.returncode == 0
    finally:
        shutil.rmtree(d)


class MockAcme(object):
    EAB_KID = 'kid-1'
    EAB_KEY = b'0123456789abcdef0123456789abcdef'

    def __init__(self, require_eab=False, bad_nonce_once=True, rate_limit_once=False):
        self.lock = threading.Lock()
        self.nonces = set()
        self.accounts = {}          # kid -> {'jwk':, 'contact':}
        self.orders = {}
        self.authz = {}
        self.chals = {}
        self.certs = {}
        self.board = {'dns': {}, 'http': {}}
        self.require_eab = require_eab
        self.bad_nonce_once = bad_nonce_once
        self.rate_limit_once = rate_limit_once
        self.revoked = []
        self.n = 0
        self.seen = []              # (path, protected header) of every POST
        self.root = TestCA('Test Root X1')
        self.alt_root = TestCA('Other Root R9')
        self.server = Server(self._handler())
        self.base = self.server.base

    def close(self):
        self.server.close()
        self.root.close()
        self.alt_root.close()

    def nid(self):
        self.n += 1
        return str(self.n)

    def nonce(self):
        n = b64u(os.urandom(12))
        with self.lock:
            self.nonces.add(n)
        return n

    def _handler(self):
        app = self

        class H(Quiet):
            def common(self):
                return [('Replay-Nonce', app.nonce()), ('Cache-Control', 'no-store')]

            def do_HEAD(self):
                if self.path == '/nonce':
                    self.send(200, b'', headers=self.common())
                else:
                    self.send(404)

            def do_GET(self):
                if self.path == '/dir':
                    self.send(200, {
                        'newNonce': app.base + '/nonce', 'newAccount': app.base + '/acct',
                        'newOrder': app.base + '/order', 'revokeCert': app.base + '/revoke',
                        'renewalInfo': app.base + '/ari',
                        'meta': {'profiles': {'classic': 'x', 'shortlived': 'y'},
                                 'externalAccountRequired': app.require_eab,
                                 'termsOfService': app.base + '/tos'}})
                elif self.path.startswith('/ari/'):
                    app.seen.append(('ari', self.path[5:]))
                    self.send(200, {'suggestedWindow': {'start': '2026-01-02T03:04:05Z',
                                                        'end': '2026-01-03T03:04:05.5Z'}},
                              headers=[('Retry-After', '21600')])
                elif self.path == '/nonce':
                    self.send(204, b'', headers=self.common())
                else:
                    self.send(404)

            def problem(self, status, typ, detail, more=None):
                self.send(status, {'type': 'urn:ietf:params:acme:error:' + typ, 'detail': detail},
                          'application/problem+json', self.common() + list(more or []))

            def do_POST(self):
                jws = json.loads(self.body())
                prot = json.loads(b64u_dec(jws['protected']))
                payload = json.loads(b64u_dec(jws['payload'])) if jws['payload'] else None
                path = self.path
                app.seen.append((path, prot))
                with app.lock:
                    fresh = prot.get('nonce') in app.nonces
                    app.nonces.discard(prot.get('nonce'))
                if not fresh:
                    return self.problem(400, 'badNonce', 'stale nonce')
                if prot.get('url') != app.base + path:
                    return self.problem(400, 'malformed', 'url mismatch')
                if 'jwk' in prot:
                    jwk = prot['jwk']
                else:
                    acct = app.accounts.get(prot.get('kid'))
                    if not acct:
                        return self.problem(400, 'accountDoesNotExist', 'no such account')
                    jwk = acct['jwk']
                if not verify_jws(jws, jwk):
                    return self.problem(400, 'malformed', 'JWS signature does not verify')
                if path == '/acct':
                    return self.new_account(jwk, payload)
                if path == '/order':
                    if app.bad_nonce_once:
                        app.bad_nonce_once = False
                        return self.problem(400, 'badNonce', 'try again')
                    if app.rate_limit_once:
                        app.rate_limit_once = False
                        return self.problem(429, 'rateLimited', 'slow down', [('Retry-After', '1')])
                    return self.new_order(prot['kid'], payload)
                if path.startswith('/acct/'):
                    app.accounts[prot['kid']]['contact'] = payload.get('contact')
                    return self.send(200, {'status': 'valid'}, headers=self.common())
                if path.startswith('/authz/'):
                    return self.send(200, app.authz[path[7:]], headers=self.common())
                if path.startswith('/chal/'):
                    return self.respond(path[6:], jwk)
                if path.startswith('/o/'):
                    return self.send(200, app.orders[path[3:]], headers=self.common())
                if path.startswith('/fin/'):
                    return self.finalize(path[5:], payload)
                if path.startswith('/cert/'):
                    cid = path[6:]
                    main = cid.split('-')[0]
                    links = [('Link', '<%s/cert/%s-alt>;rel="alternate"' % (app.base, main))]
                    return self.send(200, app.certs[cid], 'application/pem-certificate-chain',
                                     self.common() + (links if '-' not in cid else []))
                if path == '/revoke':
                    app.revoked.append(payload)
                    return self.send(200, b'', headers=self.common())
                self.problem(404, 'malformed', 'no such thing')

            def new_account(self, jwk, payload):
                for kid, a in app.accounts.items():
                    if a['jwk'] == jwk:
                        return self.send(200, {'status': 'valid'},
                                         headers=self.common() + [('Location', kid)])
                if payload.get('onlyReturnExisting'):
                    return self.problem(400, 'accountDoesNotExist', 'none')
                if app.require_eab:
                    eab = payload.get('externalAccountBinding')
                    if not eab:
                        return self.problem(400, 'externalAccountRequired', 'EAB needed')
                    p = json.loads(b64u_dec(eab['protected']))
                    mac = hmac.new(app.EAB_KEY, ('%s.%s' % (eab['protected'], eab['payload'])).encode(),
                                   hashlib.sha256).digest()
                    if p.get('kid') != app.EAB_KID or p.get('alg') != 'HS256' or \
                            b64u_dec(eab['signature']) != mac or \
                            json.loads(b64u_dec(eab['payload'])) != jwk or p.get('url') != app.base + '/acct':
                        return self.problem(400, 'unauthorized', 'EAB wrong')
                kid = app.base + '/acct/' + app.nid()
                app.accounts[kid] = {'jwk': jwk, 'contact': payload.get('contact')}
                self.send(201, {'status': 'valid'}, headers=self.common() + [('Location', kid)])

            def new_order(self, kid, payload):
                oid = app.nid()
                azs = []
                for ident in payload['identifiers']:
                    aid = app.nid()
                    wild = ident['value'].startswith('*.')
                    value = ident['value'][2:] if wild else ident['value']
                    chs = []
                    for t in (('dns-01',) if wild else ('http-01', 'dns-01')):
                        cid = app.nid()
                        app.chals[cid] = {'type': t, 'url': app.base + '/chal/' + cid, 'status': 'pending',
                                          'token': b64u(os.urandom(16)), 'authz': aid}
                        chs.append(app.chals[cid])
                    app.authz[aid] = {'status': 'pending', 'identifier': {'type': ident['type'], 'value': value},
                                      'challenges': chs, 'wildcard': wild, 'expires': '2030-01-01T00:00:00Z'}
                    azs.append(app.base + '/authz/' + aid)
                app.orders[oid] = {'status': 'pending', 'identifiers': payload['identifiers'],
                                   'authorizations': azs, 'finalize': app.base + '/fin/' + oid,
                                   'profile': payload.get('profile'), 'replaces': payload.get('replaces')}
                self.send(201, app.orders[oid], headers=self.common() + [('Location', app.base + '/o/' + oid)])

            def respond(self, cid, jwk):
                ch = app.chals[cid]
                thumb = b64u(hashlib.sha256(json.dumps(jwk, separators=(',', ':'), sort_keys=True).encode()).digest())
                keyauth = ch['token'] + '.' + thumb
                az = app.authz[ch['authz']]
                name = az['identifier']['value']
                if ch['type'] == 'http-01':
                    ok = app.board['http'].get(ch['token']) == keyauth
                else:
                    want = b64u(hashlib.sha256(keyauth.encode()).digest())
                    ok = want in app.board['dns'].get(name, [])
                ch['status'] = 'valid' if ok else 'invalid'
                if not ok:
                    ch['error'] = {'type': 'urn:ietf:params:acme:error:incorrectResponse',
                                   'detail': 'wrong proof for %s' % name}
                az['status'] = ch['status']
                for o in app.orders.values():
                    if all(app.authz[u.rsplit('/', 1)[1]]['status'] == 'valid' for u in o['authorizations']):
                        if o['status'] == 'pending':
                            o['status'] = 'ready'
                self.send(200, ch, headers=self.common())

            def finalize(self, oid, payload):
                o = app.orders[oid]
                if o['status'] != 'ready':
                    return self.problem(403, 'orderNotReady', 'not ready')
                names = [i['value'] for i in o['identifiers']]
                leaf = app.root.sign_csr(b64u_dec(payload['csr']), names)
                app.certs[oid] = leaf + app.root.pem
                app.certs[oid + '-alt'] = leaf + app.alt_root.pem
                o['status'] = 'processing'
                o['certificate'] = app.base + '/cert/' + oid
                self.send(200, o, headers=self.common() + [('Retry-After', '1')])

            def do_GET_order_after(self):
                pass

        # the order turns valid when it is asked about after finalize
        orig = H.do_POST

        def do_POST(self):
            if self.path.startswith('/o/'):
                o = app.orders.get(self.path[3:])
                if o and o['status'] == 'processing':
                    o['status'] = 'valid'
            return orig(self)
        H.do_POST = do_POST
        return H


class TestAcmePieces(unittest.TestCase):
    def test_ari_id_rfc9773_example(self):
        # RFC 9773 4.1: AKI keyIdentifier 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4,
        # serial 0x87654321 -> "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
        ca = TestCA('Ari Root', ski='69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4')
        try:
            _k, _p, csr = make_key_csr(['ari.example'])
            cert = ca.sign_csr(csr, ['ari.example'], serial='0x87654321')
            self.assertEqual(ac.ari_id(cert), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE')
        finally:
            ca.close()

    def test_rfc3339_and_links(self):
        self.assertEqual(ac.rfc3339('2026-01-02T03:04:05Z'), 1767323045.0)
        self.assertEqual(ac.rfc3339('2026-01-02T05:04:05+02:00'), 1767323045.0)
        links = ac.parse_links('<https://a/b>;rel="index", <https://a/c/1>; rel="alternate", <https://a/c/2>;rel=alternate')
        self.assertEqual([l for l, r in links if r == 'alternate'], ['https://a/c/1', 'https://a/c/2'])

    def _jws_roundtrip(self, kind):
        ctx = FakeContext()
        with ac.AcmeClient(ctx, 'https://ca.invalid/dir') as cl:
            key = cl.use_key(cl.new_key(kind))
            jws = key.jws('https://ca.invalid/new-order', {'identifiers': []}, 'nonce-1')
            self.assertTrue(verify_jws(jws, key.jwk), kind)
            prot = json.loads(b64u_dec(jws['protected']))
            self.assertEqual(prot['alg'], ac.ACCOUNT_KEYS[kind][0])
            self.assertEqual(prot['jwk'], key.jwk)
            if kind.startswith('ec'):
                self.assertEqual(len(b64u_dec(jws['signature'])), 2 * ac.ACCOUNT_KEYS[kind][2])
            # tampered: refused
            bad = dict(jws, payload=b64u(b'{"x":1}'))
            self.assertFalse(verify_jws(bad, key.jwk))
            kidded = key.jws('https://ca.invalid/x', None, 'n2', kid='https://ca.invalid/acct/1')
            self.assertEqual(kidded['payload'], '')
            self.assertNotIn('jwk', json.loads(b64u_dec(kidded['protected'])))
            self.assertTrue(verify_jws(kidded, key.jwk))

    def test_jws_es256(self):
        self._jws_roundtrip('ec-256')

    def test_jws_es384(self):
        self._jws_roundtrip('ec-384')

    def test_jws_rs256(self):
        self._jws_roundtrip('rsa-2048')

    def test_thumbprint_rfc7638(self):
        # RFC 7638 3.1's example key -> NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
        class K(ac.AcmeKey):
            def __init__(self):
                self.jwk = {'kty': 'RSA', 'e': 'AQAB', 'n': (
                    '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP'
                    'ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY'
                    '368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f'
                    'M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw')}
        self.assertEqual(K().thumbprint(), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')

    def test_eab(self):
        jwk = {'kty': 'EC', 'crv': 'P-256', 'x': 'a', 'y': 'b'}
        e = ac.eab_jws(jwk, 'kid-9', b64u(b'secretkey'), 'https://ca/acct')
        self.assertEqual(json.loads(b64u_dec(e['protected'])), {'alg': 'HS256', 'kid': 'kid-9', 'url': 'https://ca/acct'})
        self.assertEqual(json.loads(b64u_dec(e['payload'])), jwk)
        mac = hmac.new(b'secretkey', ('%s.%s' % (e['protected'], e['payload'])).encode(), hashlib.sha256).digest()
        self.assertEqual(b64u_dec(e['signature']), mac)

    def test_problem_words(self):
        w, short, d = ac.problem_words({'type': 'urn:ietf:params:acme:error:caa', 'detail': 'CAA forbids'})
        self.assertEqual(short, 'caa')
        self.assertIn('CAA record', w)

    def test_identifiers(self):
        self.assertEqual(ac.identifiers(['WWW.Example.com', '192.0.2.1', '2001:db8::1', 'www.example.com']),
                         [{'type': 'dns', 'value': 'www.example.com'}, {'type': 'ip', 'value': '192.0.2.1'},
                          {'type': 'ip', 'value': '2001:db8::1'}])


class TestAcmeOrder(unittest.TestCase):
    def setUp(self):
        self.ca = MockAcme()
        self.ctx = FakeContext()

    def tearDown(self):
        self.ca.close()

    def issuer(self, **cfg):
        conf = {'directory': 'custom', 'directory_url': self.ca.base + '/dir', 'contacts': ['pki@example.com'],
                'poll_every': 0.2, 'wait_ready': 10, 'wait_valid': 10, 'wait_order': 10}
        conf.update(cfg)
        return AcmeIssuer(conf, self.ctx)

    def test_full_order(self):
        names = ['www.example.com', '*.example.com', 'example.com', '192.0.2.10']
        key, csr_pem, csr_der = make_key_csr(names)
        dns = FakeChallenge(('dns-01',), self.ca.board)
        web = FakeChallenge(('http-01',), self.ca.board)
        req = CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                          profile={'acme_profile': 'shortlived'},
                          challenges={'www.example.com': web, '*.example.com': dns, 'example.com': dns,
                                      '192.0.2.10': web})
        iss = self.issuer(preferred_chain='Other Root R9')
        got = iss.issue(req)
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(len(got.chain_pems), 1)
        self.assertEqual(p7.Cert(got.chain_pems[0]).subject_cn, 'Other Root R9')   # the alternate
        self.assertTrue(got.info['ari_id'])
        self.assertTrue(got.info['account_url'].startswith(self.ca.base + '/acct/'))
        # the order: profile asked, every proof cleaned up, nothing left on the board
        order = list(self.ca.orders.values())[0]
        self.assertEqual(order['profile'], 'shortlived')
        self.assertEqual({i['type'] for i in order['identifiers']}, {'dns', 'ip'})
        self.assertEqual(self.ca.board['http'], {})
        self.assertTrue(all(not v for v in self.ca.board['dns'].values()))
        self.assertEqual(sorted(x[1] for x in dns.log if x[0] == 'cleanup'), ['example.com', 'example.com'])
        # the badNonce of the first newOrder was asked again
        self.assertEqual(sum(1 for path, _p in self.ca.seen if path == '/order'), 2)
        # the account kept, sealed
        slot = [k for k in self.ctx.kv if k.startswith('acme-account:%s/dir:' % self.ca.base)]
        self.assertEqual(len(slot), 1)
        row = json.loads(self.ctx.kv[slot[0]])
        self.assertTrue(row['key'].startswith('sealed:'))
        # a renewal: the same account, `replaces` from ARI
        req2 = CertRequest(names=['www.example.com'], key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                           challenges={'www.example.com': web}, previous=got.cert_pem)
        got2 = iss.issue(req2)
        order2 = list(self.ca.orders.values())[-1]
        self.assertEqual(order2['replaces'], ac.ari_id(got.cert_pem))
        self.assertEqual(got2.info['account_url'], got.info['account_url'])
        self.assertEqual(len(self.ca.accounts), 1)
        # ARI window and revocation
        self.assertEqual(iss.renewal_window(got.cert_pem), (1767323045.0, 1767409445.5))
        iss.revoke(got.cert_pem, 'superseded')
        self.assertEqual(self.ca.revoked[0]['reason'], 4)
        self.assertEqual(b64u_dec(self.ca.revoked[0]['certificate']), p7.cert_der(got.cert_pem))

    def test_wrong_proof_cleans_up(self):
        names = ['bad.example.com']
        key, csr_pem, csr_der = make_key_csr(names)

        class Liar(FakeChallenge):
            def present(self, name, token, ka, txt):
                FakeChallenge.present(self, name, token, ka, txt)
                self.board['http'][token] = 'wrong'
                return {'token': token}
        web = Liar(('http-01',), self.ca.board)
        req = CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                          challenges={'bad.example.com': web})
        with self.assertRaises(PluginError) as cm:
            self.issuer().issue(req)
        self.assertIn('wrong answer', str(cm.exception))
        self.assertIn(('cleanup', 'bad.example.com'), web.log)
        self.assertEqual(self.ca.board['http'], {})

    def test_eab_and_rate_limit(self):
        self.ca.require_eab = True
        self.ca.rate_limit_once = True
        names = ['eab.example.com']
        key, csr_pem, csr_der = make_key_csr(names)
        web = FakeChallenge(('http-01',), self.ca.board)
        req = CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                          challenges={'eab.example.com': web})
        with self.assertRaises(PluginError) as cm:
            self.issuer().issue(req)
        self.assertIn('External Account Binding', str(cm.exception))
        iss = self.issuer(eab_kid=MockAcme.EAB_KID, eab_hmac=b64u(MockAcme.EAB_KEY), account_key='ec-384')
        got = iss.issue(req)
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertTrue(any('rate limit' in w for _l, w in self.ctx.steps))

    def test_account_forgotten_and_rsa_key(self):
        iss = self.issuer(account_key='rsa-2048')
        self.assertIn('account', iss.test())
        self.ca.accounts.clear()                         # the CA forgot it
        names = ['again.example.com']
        key, csr_pem, csr_der = make_key_csr(names)
        web = FakeChallenge(('http-01',), self.ca.board)
        got = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                    challenges={'again.example.com': web}))
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertTrue(any('does not know the account' in w for _l, w in self.ctx.steps))

    def test_no_matching_challenge(self):
        names = ['*.example.org']
        key, csr_pem, csr_der = make_key_csr(names)
        web = FakeChallenge(('http-01',), self.ca.board)
        with self.assertRaises(PluginError) as cm:
            self.issuer().issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                            challenges={'*.example.org': web}))
        self.assertIn('wildcards need dns-01', str(cm.exception))
        self.assertFalse(cm.exception.retry)


# ---------------------------------------------------------------------------
# MD4 and NTLM against the standards
# ---------------------------------------------------------------------------
class TestNtlm(unittest.TestCase):
    def test_md4_rfc1320(self):
        vectors = {
            b'': '31d6cfe0d16ae931b73c59d7e0c089c0',
            b'a': 'bde52cb31de33e46245e05fbdbd6fb24',
            b'abc': 'a448017aaf21d8525fc10ae87aa6729d',
            b'message digest': 'd9130a8164549fe818874806e1c7014b',
            b'abcdefghijklmnopqrstuvwxyz': 'd79e1c308aa5bbcdeea8ed63df412da9',
            b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789':
                '043f8582f241db351ce627e153e7f0e4',
            b'1234567890' * 8: 'e33b4ddc9c38f2199c3e7b164fcc0536',
        }
        for msg, want in vectors.items():
            self.assertEqual(_ntlm.md4_pure(msg).hex(), want, msg)

    def test_rc4(self):
        # RFC 6229, key 0x0102030405, the first 16 bytes of keystream
        self.assertEqual(_ntlm.rc4(bytes([1, 2, 3, 4, 5]), b'\x00' * 16).hex(),
                         'b2396305f03dc027ccc3524a0a1118a8')

    def test_ms_nlmp_4_2_4(self):
        # MS-NLMP 4.2.2.1.2 and 4.2.4: User / Domain / Password, server challenge 0123456789abcdef,
        # client challenge aa*8, time 0, AV pairs NbDomainName "Domain", NbComputerName "Server"
        self.assertEqual(_ntlm.ntowfv1('Password').hex(), 'a4f49c406510bdcab6824ee7c30fd852')
        key = _ntlm.ntowfv2('Password', 'User', 'Domain')
        self.assertEqual(key.hex(), '0c868a403bfd7a93a3001ef22ef02e3f')
        sc = bytes.fromhex('0123456789abcdef')
        cc = b'\xaa' * 8
        av = _ntlm.av_pairs_build([(_ntlm.AV_NB_DOMAIN, 'Domain'.encode('utf-16-le')),
                                   (_ntlm.AV_NB_COMPUTER, 'Server'.encode('utf-16-le'))])
        nt, proof, base = _ntlm.ntlmv2_response(key, sc, cc, b'\x00' * 8, av)
        self.assertEqual(proof.hex(), '68cd0ab851e51c96aabc927bebef6a1c')
        self.assertEqual(base.hex(), '8de40ccadbc14a82f15cb0ad0de95ca3')
        self.assertEqual(_ntlm.lmv2_response(key, sc, cc).hex(),
                         '86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa')
        self.assertEqual(_ntlm.rc4(base, b'\x55' * 16).hex(), 'c5dad2544fc9799094ce1ce90bc9d03e')

    def test_target_name_is_the_host_asked(self):
        """Hunt M round 2 (1.0.101): MsvAvTargetName is HTTP/<the host of the address acme was
        given>, not the name the server's CHALLENGE says - a relay forwarding the real CA's
        challenge got a name the CA took."""
        def target_name(auth):
            ln, _m, off = struct.unpack('<HHI', auth[20:28])
            nt = auth[off:off + ln]
            return dict(_ntlm.av_pairs_parse(nt[16 + 28:])).get(_ntlm.AV_TARGET_NAME, b'') \
                .decode('utf-16-le')
        neg = _ntlm.negotiate_message()
        chal = ntlm_challenge(os.urandom(8))
        auth = _ntlm.authenticate_message(neg, chal, 'svc', 'pw', 'EXAMPLE',
                                          target_host='CA.Example.Test.')
        self.assertEqual(target_name(auth), 'HTTP/ca.example.test')
        auth = _ntlm.authenticate_message(neg, chal, 'svc', 'pw', 'EXAMPLE')
        self.assertEqual(target_name(auth), 'HTTP/ca01.example.local')


def ntlm_challenge(server_challenge, with_time=True):
    av = [(_ntlm.AV_NB_DOMAIN, 'EXAMPLE'.encode('utf-16-le')),
          (_ntlm.AV_NB_COMPUTER, 'CA01'.encode('utf-16-le')),
          (_ntlm.AV_DNS_COMPUTER, 'ca01.example.local'.encode('utf-16-le'))]
    if with_time:
        av.append((_ntlm.AV_TIMESTAMP, _ntlm.filetime()))
    ti = _ntlm.av_pairs_build(av)
    tn = 'EXAMPLE'.encode('utf-16-le')
    flags = _ntlm.FLAGS
    off = 56
    return (_ntlm.SIG + struct.pack('<I', 2) + struct.pack('<HHI', len(tn), len(tn), off) +
            struct.pack('<I', flags) + server_challenge + b'\x00' * 8 +
            struct.pack('<HHI', len(ti), len(ti), off + len(tn)) + _ntlm.VERSION + tn + ti)


def ntlm_check(neg, chal, auth, users):
    """What a domain controller does: the NTProofStr and the MIC checked."""
    def fld(i):
        ln, _m, off = struct.unpack('<HHI', auth[12 + 8 * i:20 + 8 * i])
        return auth[off:off + ln]
    lm, nt, dom, user, _ws, enc_key = (fld(i) for i in range(6))
    user, dom = user.decode('utf-16-le'), dom.decode('utf-16-le')
    pw = users.get(user)
    if pw is None:
        return False
    key = _ntlm.ntowfv2(pw, user, dom)
    sc = _ntlm.Challenge(chal).server_challenge
    proof = hmac.new(key, sc + nt[16:], hashlib.md5).digest()
    if proof != nt[:16]:
        return False
    base = hmac.new(key, proof, hashlib.md5).digest()
    exported = _ntlm.rc4(base, enc_key) if enc_key else base
    mic = auth[72:88]
    zeroed = auth[:72] + b'\x00' * 16 + auth[88:]
    return hmac.new(exported, neg + chal + zeroed, hashlib.md5).digest() == mic


# ---------------------------------------------------------------------------
# A mock AD CS Web Enrollment (IIS with Windows authentication)
# ---------------------------------------------------------------------------
class MockAdcs(object):
    def __init__(self, auth='ntlm'):
        self.ca = TestCA('Example Issuing CA', rsa=True)
        self.auth = auth
        self.users = {'svc-acme': 'S3cret!'}
        self.reqs = {}             # id -> {'csr':, 'state':, 'cert':}
        self.n = 10
        self.connections = 0
        self.server = Server(self._handler())
        self.base = self.server.base

    def close(self):
        self.server.close()
        self.ca.close()

    def approve(self, rid):
        r = self.reqs[rid]
        r['cert'] = self.ca.sign_csr(r['csr'], [])
        r['state'] = 'issued'

    def _handler(self):
        app = self

        class H(Quiet):
            def setup(self):
                Quiet.setup(self)
                app.connections += 1
                self.authed = False
                self.neg = self.chal = None

            def authorized(self):
                h = self.headers.get('Authorization') or ''
                if app.auth == 'basic':
                    if h.startswith('Basic '):
                        u, _, pw = base64.b64decode(h[6:]).decode().partition(':')
                        u = u.split('\\')[-1]
                        if app.users.get(u) == pw:
                            return True
                    self.body()
                    self.send(401, 'no', 'text/html', [('WWW-Authenticate', 'Basic realm="ca01"')])
                    return False
                if self.authed:
                    return True
                scheme, _, tok = h.partition(' ')
                if scheme in ('NTLM', 'Negotiate') and tok:
                    msg = base64.b64decode(tok)
                    kind = struct.unpack('<I', msg[8:12])[0]
                    if kind == 1:
                        self.neg = msg
                        self.chal = ntlm_challenge(os.urandom(8))
                        self.body()
                        self.send(401, 'more', 'text/html', [('WWW-Authenticate', scheme + ' ' +
                                                              base64.b64encode(self.chal).decode())])
                        return False
                    if kind == 3 and self.chal and ntlm_check(self.neg, self.chal, msg, app.users):
                        self.authed = True
                        return True
                self.body()
                self.send(401, 'who are you', 'text/html', [('WWW-Authenticate', 'Negotiate'),
                                                           ('WWW-Authenticate', 'NTLM')])
                return False

            def do_GET(self):
                if not self.authorized():
                    return
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                if u.path == '/certsrv/':
                    return self.send(200, '<html><title>Microsoft Active Directory Certificate Services'
                                          '</title></html>', 'text/html')
                if u.path == '/certsrv/certnew.cer':
                    r = app.reqs.get(q.get('ReqID'))
                    if r and r['state'] == 'issued':
                        return self.send(200, r['cert'], 'application/pkix-cert')
                    if r and r['state'] == 'denied':
                        return self.send(200, '<html>Certificate Request Denied. The disposition message '
                                              'is "Denied by Policy Module". 0x80094012</html>', 'text/html')
                    return self.send(200, '<html>Certificate Pending. Your certificate request is still '
                                          'pending.</html>', 'text/html')
                if u.path == '/certsrv/certrqxt.asp':
                    # the Advanced Certificate Request page, as Web Enrollment draws it
                    return self.send(200, '<html><Form><Select Name="lbCertTemplate" '
                                          'ID="lbCertTemplateID">\r\n<Option Value="E;WebServer;1;2">'
                                          'Web Server\r\n<Option Value="O;Approve;1;2">Approved by '
                                          'hand &amp; kept\r\n<Option Value="E;WebServer;1;2">dup'
                                          '</Select></Form></html>', 'text/html')
                if u.path == '/certsrv/certnew.p7b':
                    certs = [p7.cert_der(app.ca.pem)]
                    r = app.reqs.get(q.get('ReqID'))
                    if r and r.get('cert'):
                        certs.insert(0, p7.cert_der(r['cert']))
                    # what IIS sends: base64 under a CERTIFICATE header
                    return self.send(200, p7.pem(p7.build_degenerate(certs)), 'application/x-pkcs7-certificates')
                self.send(404, 'no', 'text/html')

            def do_POST(self):
                if not self.authorized():
                    return
                form = dict(urllib.parse.parse_qsl(self.body().decode()))
                if self.path != '/certsrv/certfnsh.asp':
                    return self.send(404, 'no', 'text/html')
                tmpl = re.search(r'CertificateTemplate:(\S+)', form.get('CertAttrib', ''))
                tmpl = tmpl.group(1) if tmpl else ''
                app.n += 1
                rid = str(app.n)
                csr = p7.pem_blocks(form['CertRequest'], 'CERTIFICATE REQUEST')[0][1]
                if tmpl == 'WebServer':
                    app.reqs[rid] = {'csr': csr, 'state': 'pending'}
                    app.approve(rid)
                    return self.send(200, '<html>Certificate Issued <a href="certnew.cer?ReqID=%s&amp;Enc=b64">'
                                          'Download</a></html>' % rid, 'text/html')
                if tmpl == 'Approve':
                    app.reqs[rid] = {'csr': csr, 'state': 'pending'}
                    return self.send(200, '<html><P>Your certificate request has been received. However, you '
                                          'must wait for an administrator to issue the certificate you '
                                          'requested.<P>Your Request Id is %s.</html>' % rid, 'text/html')
                self.send(200, '<html>Certificate Request Denied<P>Your certificate request was denied.'
                               '<P>Your Request Id is %s.<P>The disposition message is "Denied by Policy '
                               'Module  0x80094800, The request was for a certificate template that is '
                               'not supported by the Active Directory Certificate Services policy: %s.'
                               '".</html>' % (rid, tmpl), 'text/html')
        return H


class TestMsAdcs(unittest.TestCase):
    def issuer(self, ca, **cfg):
        conf = {'url': ca.base, 'template': 'WebServer', 'auth': ca.auth, 'user': 'svc-acme',
                'password': 'S3cret!', 'domain': 'EXAMPLE'}
        conf.update(cfg)
        return MsAdcsIssuer(conf, self.ctx)

    def setUp(self):
        self.ctx = FakeContext()

    def req(self):
        key, csr_pem, csr_der = make_key_csr(['web01.example.local'], 'rsa')
        return CertRequest(names=['web01.example.local'], key_pem=key, csr_pem=csr_pem, csr_der=csr_der)

    def test_ntlm_issue(self):
        ca = MockAdcs('ntlm')
        try:
            iss = self.issuer(ca)
            self.assertIn('Example Issuing CA', iss.test())
            got = iss.issue(self.req())
            self.assertEqual(p7.Cert(got.cert_pem).issuer_cn, 'Example Issuing CA')
            self.assertEqual([p7.Cert(c).subject_cn for c in got.chain_pems], ['Example Issuing CA'])
            with self.assertRaises(PluginError) as cm:
                self.issuer(ca, password='wrong').test()
            self.assertIn('401', str(cm.exception))
        finally:
            ca.close()

    def test_ca_pem_is_a_pin(self):
        """Hunt M round 2 (1.0.101): the CA certificate given is the only one trusted, as in
        runtime.http - it was added to the system's CAs (any public CA's certificate for the
        name was taken too)."""
        ca = TestCA('Pinned Root P1', rsa=True)
        try:
            h = ms_adcs_mod.AdcsHttp(self.ctx, 'https://ca01.example.local/certsrv', 'ntlm',
                                     ca_pem=ca.pem)
            got = h._ssl().get_ca_certs()
            self.assertEqual(len(got), 1, got)
            self.assertIn(('commonName', 'Pinned Root P1'),
                          [x for rdn in got[0]['subject'] for x in rdn])
            h2 = ms_adcs_mod.AdcsHttp(self.ctx, 'https://ca01.example.local/certsrv', 'ntlm')
            self.assertTrue(h2._ssl().verify_mode)
            with self.assertRaises(PluginError):
                ms_adcs_mod.AdcsHttp(self.ctx, 'https://ca01.example.local/certsrv', 'ntlm',
                                     ca_pem='-----BEGIN CERTIFICATE-----\nnope\n'
                                            '-----END CERTIFICATE-----\n')._ssl()
            f = [x for x in MsAdcsIssuer.fields if x['key'] == 'ca_pem'][0]
            self.assertIn('the only CA', f['help'])
        finally:
            ca.close()

    def test_templates_listed(self):
        ca = MockAdcs('ntlm')
        try:
            got = self.issuer(ca).catalog('templates')
            self.assertEqual(got['options'], [['WebServer', 'Web Server'],
                                              ['Approve', 'Approved by hand & kept']])
            self.assertIn('2 templates', got['said'])
            with self.assertRaises(PluginError):
                self.issuer(ca).catalog('nothing')
            self.assertIsNone(ms_adcs_mod.templates_of('<html>no list</html>'))
            per = MsAdcsIssuer.describe()['per_cert']
            self.assertEqual(per[0]['key'], 'template')
            self.assertEqual(per[0]['catalog'], 'templates')
            f = [x for x in MsAdcsIssuer.fields if x['key'] == 'template'][0]
            self.assertEqual((f['type'], f['catalog']), ('catalog', 'templates'))
        finally:
            ca.close()

    def test_basic_pending_and_denied(self):
        ca = MockAdcs('basic')
        try:
            r = self.req()
            iss = self.issuer(ca, template='Approve')
            with self.assertRaises(PluginError) as cm:
                iss.issue(r)
            self.assertIn('approve', str(cm.exception))
            self.assertTrue(cm.exception.retry)
            rid = str(ca.n)
            with self.assertRaises(PluginError):        # still pending: no new request made
                iss.issue(r)
            self.assertEqual(ca.n, int(rid))
            ca.approve(rid)
            got = iss.issue(r)
            self.assertEqual(got.info['req_id'], rid)
            self.assertEqual(ca.n, int(rid))
            with self.assertRaises(PluginError) as cm:
                self.issuer(ca, template='Nope').issue(self.req())
            self.assertIn('does not offer this template', str(cm.exception))
            self.assertFalse(cm.exception.retry)
        finally:
            ca.close()


# ---------------------------------------------------------------------------
# SCEP: messages and a mock server
# ---------------------------------------------------------------------------
class MockScep(object):
    PASSWORD = 'one-time-7'

    def __init__(self, caps=('POSTPKIOperation', 'SHA-256', 'AES', 'SCEPStandard'), pending=False):
        self.ca = TestCA('Example SCEP CA', rsa=True)
        d = self.ca.dir
        self.ra_key = os.path.join(d, 'ra.key')
        openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', self.ra_key])
        csr = openssl(['req', '-new', '-key', self.ra_key, '-subj', '/CN=Example SCEP RA', '-outform', 'DER'])
        self.ra_pem = self.ca.sign_csr(csr, [], ext_more='keyUsage=critical,digitalSignature,keyEncipherment')
        self.ra_crt = os.path.join(d, 'ra.crt')
        wr(self.ra_crt, self.ra_pem)
        self.caps = caps
        self.pending = pending
        self.held = {}
        self.ops = []
        self.server = Server(self._handler())
        self.base = self.server.base + '/scep/pkiclient.exe'

    def close(self):
        self.server.close()
        self.ca.close()

    def reply(self, req_der):
        """A CertRep for a request, as a SCEP server makes one."""
        cr = p7.Crypto(openssl)
        try:
            msg = p7.SignedMessage(req_der)
            # the request's signature verified by openssl
            content = openssl(['cms', '-verify', '-inform', 'DER', '-noverify', '-binary'], req_der)
            assert content == msg.content and msg.digest_ok()
            inner = openssl(['cms', '-decrypt', '-inform', 'DER', '-recip', self.ra_crt, '-inkey', self.ra_key,
                             '-binary'], content)
            mtype = msg.attr_text(p7.OID_SCEP_MESSAGE_TYPE)
            tid = msg.attr_text(p7.OID_SCEP_TRANSACTION_ID)
            self.ops.append(mtype)
            attrs = [(p7.OID_SCEP_MESSAGE_TYPE, p7.der_printable('3')),
                     (p7.OID_SCEP_TRANSACTION_ID, p7.der_printable(tid)),
                     (p7.OID_SCEP_SENDER_NONCE, p7.der_octets(os.urandom(16))),
                     (p7.OID_SCEP_RECIPIENT_NONCE, p7.der_octets(msg.attr_bytes(p7.OID_SCEP_SENDER_NONCE)))]
            signer = msg.signer_cert()
            if mtype == '19':
                openssl(['req', '-verify', '-inform', 'DER', '-noout'], inner)
                if self.PASSWORD.encode() not in inner:
                    status = ('2', '2')
                elif self.pending:
                    self.held[tid] = inner
                    status = ('3', None)
                else:
                    status = ('0', inner)
            else:
                csr = self.held.get(tid)
                status = ('0', csr) if csr and not self.pending else ('3', None)
            attrs.append((p7.OID_SCEP_PKI_STATUS, p7.der_printable(status[0])))
            if status[0] == '2':
                attrs.append((p7.OID_SCEP_FAIL_INFO, p7.der_printable(status[1])))
                content = b''
            elif status[0] == '3':
                content = b''
            else:
                leaf = self.ca.sign_csr(status[1], ['dev01.example.local'])
                degen = p7.build_degenerate([p7.cert_der(leaf)])
                content = p7.build_enveloped(cr, degen, signer, 'aes256')
            ra_key_file = cr.file(rd(self.ra_key))
            return p7.build_signed(cr, content, p7.cert_der(self.ra_pem), ra_key_file, attrs, 'sha256')
        finally:
            cr.close()

    def _handler(self):
        app = self

        class H(Quiet):
            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                op = q.get('operation')
                if op == 'GetCACaps':
                    return self.send(200, '\n'.join(app.caps), 'text/plain')
                if op == 'GetCACert':
                    d = p7.build_degenerate([p7.cert_der(app.ra_pem), p7.cert_der(app.ca.pem)])
                    return self.send(200, d, 'application/x-x509-ca-ra-cert')
                if op == 'PKIOperation':
                    app.ops.append('GET')
                    return self.send(200, app.reply(base64.b64decode(q['message'])), 'application/x-pki-message')
                self.send(400, 'no', 'text/plain')

            def do_POST(self):
                body = self.body()
                if 'PKIOperation' not in self.path or 'POSTPKIOperation' not in app.caps:
                    return self.send(405, 'no', 'text/plain')
                self.send(200, app.reply(body), 'application/x-pki-message')
        return H


class TestScep(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeContext()

    def req(self, kind='rsa'):
        key, csr_pem, csr_der = make_key_csr(['dev01.example.local'], kind)
        return CertRequest(names=['dev01.example.local'], key_pem=key, csr_pem=csr_pem, csr_der=csr_der)

    def test_message_roundtrip(self):
        ca = TestCA('Round Trip CA', rsa=True)
        cr = p7.Crypto(openssl)
        try:
            r = self.req()
            key_file = cr.file(r.key_pem)
            csr = p7.add_challenge_password(cr, r.csr_der, key_file, 'pw-123')
            openssl(['req', '-verify', '-inform', 'DER', '-noout'], csr)          # signed anew, valid
            self.assertIn('pw-123', openssl(['req', '-inform', 'DER', '-noout', '-text'], csr).decode())
            signer = cr.selfsigned(key_file)
            for cipher in ('aes256', 'aes128', '3des'):
                env = p7.build_enveloped(cr, csr, p7.cert_der(ca.pem), cipher)
                msg = p7.build_signed(cr, env, signer, key_file, [
                    (p7.OID_SCEP_MESSAGE_TYPE, p7.der_printable('19')),
                    (p7.OID_SCEP_TRANSACTION_ID, p7.der_printable('ABC')),
                    (p7.OID_SCEP_SENDER_NONCE, p7.der_octets(b'n' * 16))])
                content = openssl(['cms', '-verify', '-inform', 'DER', '-noverify', '-binary'], msg)
                self.assertEqual(content, env)
                plain = openssl(['cms', '-decrypt', '-inform', 'DER', '-recip', ca.crt, '-inkey', ca.key,
                                 '-binary'], content)
                self.assertEqual(plain, csr)
                parsed = p7.SignedMessage(msg)
                self.assertEqual(parsed.attr_text(p7.OID_SCEP_MESSAGE_TYPE), '19')
                self.assertEqual(parsed.attr_text(p7.OID_SCEP_TRANSACTION_ID), 'ABC')
                self.assertTrue(parsed.digest_ok())
                self.assertEqual(parsed.signer_cert(), signer)
                # and the envelope opened by hand, as the client does when openssl cms cannot
                self.assertEqual(p7.open_enveloped(cr, env, cr.file(rd(ca.key))), csr)
            # openssl's own envelope opened by ours
            env2 = openssl(['cms', '-encrypt', '-binary', '-aes256', '-outform', 'DER', ca.crt], b'hello')
            self.assertEqual(p7.open_enveloped(cr, env2, cr.file(rd(ca.key))), b'hello')
        finally:
            cr.close()
            ca.close()

    def test_issue_post(self):
        srv = MockScep()
        try:
            iss = ScepIssuer({'url': srv.base, 'challenge': MockScep.PASSWORD,
                              'ca_fingerprint': p7.Cert(srv.ca.pem).fingerprint()}, self.ctx)
            self.assertIn('Example SCEP CA', iss.test())
            got = iss.issue(self.req())
            self.assertEqual(p7.Cert(got.cert_pem).issuer_cn, 'Example SCEP CA')
            self.assertEqual([p7.Cert(c).subject_cn for c in got.chain_pems], ['Example SCEP CA'])
            self.assertEqual(srv.ops, ['19'])
            with self.assertRaises(PluginError) as cm:
                ScepIssuer({'url': srv.base, 'challenge': MockScep.PASSWORD, 'ca_fingerprint': 'ab' * 32},
                           self.ctx).issue(self.req())
            self.assertIn('fingerprint', str(cm.exception))
            with self.assertRaises(PluginError) as cm:
                ScepIssuer({'url': srv.base, 'challenge': 'wrong'}, self.ctx).issue(self.req())
            self.assertIn('badRequest', str(cm.exception))
            with self.assertRaises(PluginError) as cm:
                ScepIssuer({'url': srv.base}, self.ctx).issue(self.req('ec'))
            self.assertIn('RSA', str(cm.exception))
        finally:
            srv.close()

    def test_issue_get_3des_pending(self):
        srv = MockScep(caps=('SHA-1', 'DES3'), pending=True)
        try:
            iss = ScepIssuer({'url': srv.base, 'challenge': MockScep.PASSWORD, 'wait_pending': 0.5,
                              'poll_every': 0.2}, self.ctx)
            r = self.req()
            with self.assertRaises(PluginError) as cm:
                iss.issue(r)
            self.assertIn('PENDING', str(cm.exception))
            self.assertIn('GET', srv.ops)
            srv.pending = False
            got = iss.issue(r)                            # CertPoll (GetCertInitial) this time
            self.assertEqual(srv.ops[-1], '20')
            self.assertEqual(p7.Cert(got.cert_pem).spki_der, p7.csr_spki(r.csr_der))
        finally:
            srv.close()


class TestRegistry(unittest.TestCase):
    def test_found(self):
        from acmelib.plugins.base import Registry
        reg = Registry().reload()
        for kind in ('acme', 'ms_adcs', 'scep'):
            cls = reg.get('issuer', kind)
            d = cls.describe()
            self.assertTrue(d['fields'])
        self.assertFalse([b for b in reg.broken if 'issuers' in b[0]])
        self.assertTrue(reg.get('issuer', 'acme').needs_challenge)
        self.assertEqual(reg.get('issuer', 'acme').challenge_types,
                         ('dns-01', 'http-01', 'dns-persist-01'))


# ---------------------------------------------------------------------------
# Pebble (optional): ACME_TEST_PEBBLE=/path/to/pebble
# ---------------------------------------------------------------------------
@unittest.skipUnless(os.environ.get('ACME_TEST_PEBBLE'), 'set ACME_TEST_PEBBLE=/path/to/pebble to order from pebble')
class TestPebble(unittest.TestCase):
    def test_order(self):
        exe = os.environ['ACME_TEST_PEBBLE']
        d = tempfile.mkdtemp(prefix='acme-pebble-')
        try:
            # pebble's own test certificate for its TLS (localhost)
            ca = TestCA('Pebble TLS Root')
            k = os.path.join(d, 'tls.key')
            openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', k])
            csr = openssl(['req', '-new', '-key', k, '-subj', '/CN=localhost', '-outform', 'DER'])
            crt = ca.sign_csr(csr, ['localhost', '127.0.0.1'])
            wr(os.path.join(d, 'tls.crt'), crt)
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
            s.close()
            # an HTTP-01 answerer on a free port
            board = {'dns': {}, 'http': {}}

            class H(Quiet):
                def do_GET(self):
                    tok = self.path.rsplit('/', 1)[-1]
                    if tok in board['http']:
                        self.send(200, board['http'][tok], 'application/octet-stream')
                    else:
                        self.send(404)
            web = Server(H)
            conf = {'pebble': {'listenAddress': '127.0.0.1:%d' % port, 'managementListenAddress': '127.0.0.1:0',
                               'certificate': os.path.join(d, 'tls.crt'), 'privateKey': k,
                               'httpPort': web.port, 'tlsPort': 5001, 'ocspResponderURL': '',
                               'externalAccountBindingRequired': False,
                               'profiles': {'default': {'description': 'x', 'validityPeriod': 7776000}}}}
            wr(os.path.join(d, 'p.json'), json.dumps(conf))
            env = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='20')
            logf = open(os.path.join(d, 'log'), 'w')
            proc = subprocess.Popen([exe, '-config', os.path.join(d, 'p.json')], env=env,
                                    stdout=logf, stderr=subprocess.STDOUT)
            try:
                for _ in range(50):
                    try:
                        socket.create_connection(('127.0.0.1', port), 0.2).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                ctx = FakeContext()
                iss = AcmeIssuer({'directory': 'custom', 'directory_url': 'https://localhost:%d/dir' % port,
                                  'ca_pem': ca.pem, 'contacts': ['pki@example.com'], 'poll_every': 0.5,
                                  'wait_ready': 5, 'wait_valid': 60, 'wait_order': 60}, ctx)
                names = ['localhost']
                key, csr_pem, csr_der = make_key_csr(names)
                ch = FakeChallenge(('http-01',), board)
                got = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                            challenges={'localhost': ch}))
                self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
                self.assertTrue(got.chain_pems)
                win = iss.renewal_window(got.cert_pem)              # ARI
                self.assertTrue(win and win[0] < win[1], win)
                got2 = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                             challenges={'localhost': ch}, previous=got.cert_pem))
                self.assertEqual(got2.info.get('replaces'), ac.ari_id(got.cert_pem))
                iss.revoke(got.cert_pem, 'cessationOfOperation')
            finally:
                proc.terminate()
                proc.wait()
                logf.close()
                web.close()
                ca.close()
                if os.environ.get('ACME_TEST_VERBOSE'):
                    print(rd(os.path.join(d, 'log'))[-3000:])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
