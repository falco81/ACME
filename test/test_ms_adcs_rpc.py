#!/usr/bin/env python3
"""Microsoft AD CS over RPC (issuers/ms_adcs_rpc.py, _krb5.py, _dcerpc.py).

    python3 test/test_ms_adcs_rpc.py

* The crypto against published vectors: RFC 3961 A.1 (n-fold), RFC 3962 B
  (string-to-key, AES-CTS), MIT krb5's AES encrypt/checksum vectors, MS-NLMP
  4.2.4.4 (NTLMv2 sealing with key exchange).
* Kerberos against MIT's own krb5kdc and libgssapi_krb5 where they are on
  this machine (skipped otherwise): AS-REQ/TGS-REQ to a real KDC, the DCE-style
  AP exchange accepted by MIT's GSS-API, Wrap tokens unwrapped by MIT and MIT's
  unwrapped here.
* The issuer end to end against a KDC and an AD CS of this file's own (a
  DCE/RPC server with the endpoint mapper, Kerberos auth type 16 and 9, NTLM
  auth type 10, sealing, NDR of CertServerRequest): issued, pending then
  retrieved, denied, template denied (0x80094012), wrong password, clock skew,
  NTLM fallback, a certificate for another key refused, no secret in the
  steps, the errors or What happens.

Not against a real Windows CA: those are mocks written from the specifications.
"""
import base64
import calendar
import datetime
import hashlib
import hmac
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.plugins.base import CertRequest, Context, PluginError    # noqa: E402
from acmelib.plugins.issuers import _dcerpc as R                     # noqa: E402
from acmelib.plugins.issuers import _krb5 as K                       # noqa: E402
from acmelib.plugins.issuers import _ntlm                            # noqa: E402
from acmelib.plugins.issuers import ms_adcs_rpc as M                 # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:                                 # Kerberos and the CA here need it
    HAVE_CRYPTO = False

h = bytes.fromhex
PASSWORD = 'Very-Secret-Pw-4711!'
REALM = 'EXAMPLE.LOCAL'
SALT = b'EXAMPLE.LOCALsvc-acme'
SPN = 'host/ca01.example.local'
CA_NAME = 'EXAMPLE-CA01-CA'


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------
class Vectors(unittest.TestCase):
    def test_nfold_rfc3961_a1(self):
        for data, bits, want in (
                (b'012345', 64, 'be072631276b1955'),
                (b'password', 56, '78a07b6caf85fa'),
                (b'Rough Consensus, and Running Code', 64, 'bb6ed30870b7f0e0'),
                (b'password', 168, '59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e'),
                (b'MASSACHVSETTS INSTITVTE OF TECHNOLOGY', 192,
                 'db3b0d8f0b061e603282b308a50841229ad798fab9540c1b'),
                (b'Q', 168, '518a54a215a8452a518a54a215a8452a518a54a215'),
                (b'ba', 168, 'fb25d531ae8974499f52fd92ea9857c4ba24cf297e'),
                (b'kerberos', 64, '6b65726265726f73'),
                (b'kerberos', 128, '6b65726265726f737b9b5b2b93132b93'),
                (b'kerberos', 168, '8372c236344e5f1550cd0747e15d62ca7a5a3bcea4'),
                (b'kerberos', 256, '6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6'
                                   'cae4')):
            self.assertEqual(K.nfold(data, bits // 8).hex(), want, (data, bits))

    @unittest.skipUnless(HAVE_CRYPTO, 'python3-cryptography is not installed')
    def test_string_to_key_rfc3962_b(self):
        for it, pw, salt, k128, k256 in (
                (1, 'password', b'ATHENA.MIT.EDUraeburn', '42263c6e89f4fc28b8df68ee09799f15',
                 'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161'),
                (2, 'password', b'ATHENA.MIT.EDUraeburn', 'c651bf29e2300ac27fa469d693bdda13',
                 'a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff'),
                (1200, 'password', b'ATHENA.MIT.EDUraeburn', '4c01cd46d632d01e6dbe230a01ed642a',
                 '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a'),
                (5, 'password', h('1234567878563412'), 'e9b23d52273747dd5c35cb55be619d8e',
                 '97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31'),
                (1200, 'X' * 64, b'pass phrase equals block size',
                 '59d1bb789a828b1aa54ef9c2883f69ed',
                 '89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34'),
                (1200, 'X' * 65, b'pass phrase exceeds block size',
                 'cb8005dc5f90179a7f02104c0018751d',
                 'd78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b'),
                (50, b'\xf0\x9d\x84\x9e', b'EXAMPLE.COMpianist', 'f149c1f2e154a73452d43e7fe62a56e5',
                 '4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e')):
            self.assertEqual(K.string_to_key(K.AES128, pw, salt, it).hex(), k128, it)
            self.assertEqual(K.string_to_key(K.AES256, pw, salt, it).hex(), k256, it)

    @unittest.skipUnless(HAVE_CRYPTO, 'python3-cryptography is not installed')
    def test_aes_cts_rfc3962_b(self):
        key = b'chicken teriyaki'
        msg = b"I would like the General Gau's Chicken, please, and wonton soup."
        for n, want in (
                (17, 'c6353568f2bf8cb4d8a580362da7ff7f97'),
                (31, 'fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5'),
                (32, '39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584'),
                (47, '97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e'
                     '39312523a78662d5be7fcbcc98ebf5'),
                (48, '97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd8'
                     '39312523a78662d5be7fcbcc98ebf5a8'),
                (64, '97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8'
                     '4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8')):
            c = K.cts_encrypt(key, msg[:n])
            self.assertEqual(c.hex(), want, n)
            self.assertEqual(K.cts_decrypt(key, c), msg[:n])

    @unittest.skipUnless(HAVE_CRYPTO, 'python3-cryptography is not installed')
    def test_encrypt_and_checksum_mit_vectors(self):
        # MIT krb5's AES vectors (lib/crypto/crypto_tests), as impacket carries them too
        k = K.Key(K.AES128, h('9062430C8CDA3388922E6D6A509F5B7A'))
        c = k.encrypt(2, b'9 bytesss', h('94B491F481485B9A0678CD3C4EA386AD'))
        self.assertEqual(c.hex(), '68fb9679601f45c78857b2bf820fd6e53eca8d42fd4b1d7024a09205abb7'
                                  'cd2ec26c355d2f')
        self.assertEqual(k.decrypt(2, c), b'9 bytesss')
        k = K.Key(K.AES256, h('F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B1404231398'))
        c = k.encrypt(4, b'30 bytes bytes bytes bytes byt', h('E45CA518B42E266AD98E165E706FFB60'))
        self.assertEqual(c.hex(), 'd1137a4d634cfece924dbc3bf6790648bd5cff7de0e7b99460211d0daef3'
                                  'd79a295c688858f3b34b9cbd6eebae81daf6b734d4d498b6714f1c1d')
        self.assertEqual(K.Key(K.AES128, h('9062430C8CDA3388922E6D6A509F5B7A')).checksum(
            3, b'eight nine ten eleven twelve thirteen').hex(), '01a4b088d45628f6946614e3')
        self.assertEqual(K.Key(K.AES256, h('B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DD'
                                           'BCFEA4EC76D7')).checksum(4, b'fourteen').hex(),
                         'e08739e3279e2903ec8e3836')
        with self.assertRaises(K.KrbError):
            k.decrypt(4, c[:-1] + bytes([c[-1] ^ 1]))

    def test_ntlm_sealing_ms_nlmp_4_2_4_4(self):
        # MS-NLMP 4.2.4.4: RandomSessionKey 55*16, NTLMv2 with key exchange, SeqNum 0
        sign, seal = R.ntlm_keys(b'\x55' * 16, True)
        self.assertEqual(sign.hex(), '4788dc861b4782f35d43fd98fe1a2d39')
        self.assertEqual(seal.hex(), '59f600973cc4960a25480a7c196e4c58')
        text = 'Plaintext'.encode('utf-16-le')
        sealed, sig = R.ntlm_seal(R.Rc4(seal), sign, 0, text, text)
        self.assertEqual(sealed.hex(), '54e50165bf1936dc996020c1811b0f06fb5f')
        self.assertEqual(sig.hex(), '010000007fb38ec5c55d497600000000')
        # the handle goes on: two calls are the stream of one
        a = R.Rc4(b'k3y')
        self.assertEqual(a(b'abc') + a(b'defg'), _ntlm.rc4(b'k3y', b'abcdefg'))

    def test_ndr_cert_server_request(self):
        stub = R.cert_server_request_stub(0x100, 'CA', 0, R.attributes_blob(
            ['CertificateTemplate:WebServer']), b'\x30\x03\x02\x01\x00')
        want = struct.pack('<I', 0x100)
        want += struct.pack('<IIII', 0x20004, 3, 0, 3) + 'CA\x00'.encode('utf-16-le') + b'\x00\x00'
        want += struct.pack('<I', 0)
        a = 'CertificateTemplate:WebServer\x00'.encode('utf-16-le')
        want += struct.pack('<III', len(a), 0x20008, len(a)) + a
        want += struct.pack('<III', 5, 0x2000c, 5) + b'\x30\x03\x02\x01\x00' + b'\x00' * 3
        self.assertEqual(stub, want)
        # a tower for ept_map: 5 floors, the port in its 4th, big-endian
        t = R.tower(R.ICPR, 49712, '10.0.0.5')
        self.assertEqual(R.tower_port(t), 49712)
        self.assertEqual(t[:2], b'\x05\x00')
        self.assertIn(h('0d2060ae913c9ecf118d7c00aa00c091be0000'), t)


# ---------------------------------------------------------------------------
# Kerberos against MIT krb5 (krb5kdc, libgssapi_krb5) where they are installed
# ---------------------------------------------------------------------------
def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(HAVE_CRYPTO and shutil.which('krb5kdc') and shutil.which('kdb5_util')
                     and shutil.which('kadmin.local'), 'MIT krb5 (krb5kdc) is not installed')
class AgainstMitKrb5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-krb5-')
        cls.port = _free_port()
        d = cls.dir
        with open(os.path.join(d, 'krb5.conf'), 'w') as f:
            f.write('[libdefaults]\n default_realm = MIT.TEST\n dns_lookup_kdc = false\n'
                    '[realms]\n MIT.TEST = {\n  kdc = 127.0.0.1:%d\n }\n' % cls.port)
        with open(os.path.join(d, 'kdc.conf'), 'w') as f:
            f.write('[kdcdefaults]\n kdc_ports = %d\n kdc_tcp_ports = %d\n[realms]\n MIT.TEST = {\n'
                    '  database_name = %s/principal\n  key_stash_file = %s/stash\n'
                    '  supported_enctypes = aes256-cts-hmac-sha1-96:normal '
                    'aes128-cts-hmac-sha1-96:normal\n }\n[logging]\n kdc = FILE:%s/kdc.log\n'
                    % (cls.port, cls.port, d, d, d))
        env = dict(os.environ, KRB5_CONFIG=os.path.join(d, 'krb5.conf'),
                   KRB5_KDC_PROFILE=os.path.join(d, 'kdc.conf'))
        cls.env = env
        run = lambda *a: subprocess.run(list(a), env=env, stdout=subprocess.DEVNULL,  # noqa: E731
                                        stderr=subprocess.DEVNULL, check=True)
        run('kdb5_util', 'create', '-s', '-r', 'MIT.TEST', '-P', 'master-pw-x')
        run('kadmin.local', '-q', 'addprinc -pw %s +requires_preauth svc-acme' % PASSWORD)
        run('kadmin.local', '-q', 'addprinc -randkey host/ca01.mit.test')
        run('kadmin.local', '-q', 'ktadd -k %s/ca.keytab host/ca01.mit.test' % d)
        cls.kdc = subprocess.Popen(['krb5kdc', '-n'], env=env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        for _i in range(50):
            try:
                socket.create_connection(('127.0.0.1', cls.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.kdc.terminate()
        cls.kdc.wait()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def client(self, pw=PASSWORD, now=time.time):
        return K.Client('svc-acme', pw, 'mit.test', K.Kdc([('127.0.0.1', self.port)]), now=now)

    def test_tickets_and_errors(self):
        c = self.client()
        tgt = c.login()
        self.assertEqual(tgt.sname, ['krbtgt', 'MIT.TEST'])
        self.assertEqual(c.etype, K.AES256)
        st = c.service_ticket('host/ca01.mit.test')
        self.assertEqual(st.sname, ['host', 'ca01.mit.test'])
        with self.assertRaises(K.KrbError) as e:
            self.client('wrong').login()
        self.assertEqual(e.exception.code, 24)
        self.assertNotIn(PASSWORD, str(e.exception))
        with self.assertRaises(K.KrbError) as e:
            c.service_ticket('host/nosuch.mit.test')
        self.assertEqual(e.exception.code, 7)
        self.assertTrue(e.exception.fallback)
        with self.assertRaises(K.KrbError) as e:
            self.client(now=lambda: time.time() + 3600).login()
        self.assertEqual(e.exception.code, 37)
        self.assertIn('ahead', str(e.exception))
        self.assertIn('60 minutes', str(e.exception))

    def test_dce_style_with_mit_gssapi(self):
        import ctypes
        import ctypes.util
        name = ctypes.util.find_library('gssapi_krb5')
        if not name:
            self.skipTest('libgssapi_krb5 is not there')
        os.environ['KRB5_CONFIG'] = os.path.join(self.dir, 'krb5.conf')
        os.environ['KRB5RCACHETYPE'] = 'none'

        class Buf(ctypes.Structure):
            _fields_ = [('length', ctypes.c_size_t), ('value', ctypes.c_void_p)]

        class Iov(ctypes.Structure):
            _fields_ = [('type', ctypes.c_uint32), ('buffer', Buf)]
        lib = ctypes.CDLL(name)
        P, U, V = ctypes.POINTER, ctypes.c_uint32, ctypes.c_void_p
        lib.gss_accept_sec_context.argtypes = [P(U), P(V), V, P(Buf), V, P(V), P(V), P(Buf),
                                               P(U), P(U), P(V)]
        lib.gss_accept_sec_context.restype = U
        lib.gss_unwrap_iov.argtypes = [P(U), V, P(ctypes.c_int), P(U), P(Iov), ctypes.c_int]
        lib.gss_unwrap_iov.restype = U
        lib.gss_wrap_iov.argtypes = [P(U), V, ctypes.c_int, U, P(ctypes.c_int), P(Iov),
                                     ctypes.c_int]
        lib.gss_wrap_iov.restype = U
        lib.krb5_gss_register_acceptor_identity.argtypes = [ctypes.c_char_p]
        lib.krb5_gss_register_acceptor_identity(os.path.join(self.dir, 'ca.keytab').encode())
        ctx = V()

        def accept(tok):
            minor = U()
            raw = ctypes.create_string_buffer(tok, len(tok))
            inb, out, fl = Buf(len(tok), ctypes.cast(raw, V)), Buf(), U()
            maj = lib.gss_accept_sec_context(ctypes.byref(minor), ctypes.byref(ctx), None,
                                             ctypes.byref(inb), None, None, None,
                                             ctypes.byref(out), ctypes.byref(fl), None, None)
            return maj, (ctypes.string_at(out.value, out.length) if out.length else b''), fl.value
        c = self.client()
        st = c.service_ticket('host/ca01.mit.test')
        ap, when = c.ap_req(st)
        maj, rep, _f = accept(ap)                   # DCE style: an AP-REP, one more leg wanted
        self.assertEqual(maj, 1)
        _p, sub, sseq = K.ap_rep_read(rep, st, when)
        self.assertIsNotNone(sub)
        maj, out, flags = accept(K.ap_rep_dce(st, sseq))
        self.assertEqual(maj, 0)
        self.assertTrue(flags & K.GSS_C_DCE_STYLE and flags & K.GSS_C_CONF)
        # what acme seals MIT unwraps...
        data = bytes(range(48))
        sealed, tok = K.wrap_dce(sub, data, 0, True, True)
        hb = ctypes.create_string_buffer(tok, len(tok))
        db = ctypes.create_string_buffer(sealed, len(sealed))
        iov = (Iov * 2)(Iov(2, Buf(len(tok), ctypes.cast(hb, V))),
                        Iov(1, Buf(len(sealed), ctypes.cast(db, V))))
        minor, conf, qop = U(), ctypes.c_int(), U()
        self.assertEqual(lib.gss_unwrap_iov(ctypes.byref(minor), ctx, ctypes.byref(conf),
                                            ctypes.byref(qop), iov, 2), 0)
        self.assertEqual(ctypes.string_at(db, len(sealed)), data)
        self.assertEqual(conf.value, 1)
        # ...and what MIT seals acme unwraps (MIT's EC of 16, rotated by RRC + EC)
        msg = b'answer of the CA ' * 4
        db2 = ctypes.create_string_buffer(msg, len(msg))
        iov = (Iov * 2)(Iov(2 | 0x10000, Buf(0, None)), Iov(1, Buf(len(msg), ctypes.cast(db2, V))))
        self.assertEqual(lib.gss_wrap_iov(ctypes.byref(minor), ctx, 1, 0, ctypes.byref(conf),
                                          iov, 2), 0)
        tok2 = ctypes.string_at(iov[0].buffer.value, iov[0].buffer.length)
        plain, seqn = K.unwrap_dce(sub, ctypes.string_at(db2, len(msg)), tok2, initiator=False)
        self.assertEqual(plain, msg)
        self.assertEqual(seqn, sseq)


# ---------------------------------------------------------------------------
# A KDC of the tests' own (RFC 4120, TCP)
# ---------------------------------------------------------------------------
def gt(t):
    return K.tlv(0x18, time.strftime('%Y%m%d%H%M%SZ', time.gmtime(int(t))).encode())


class Server(object):
    """A TCP server whose connections `handle(sock)` serves, each in a thread."""
    def __init__(self, handle):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('127.0.0.1', 0))
        self.s.listen(16)
        self.port = self.s.getsockname()[1]
        self.handle = handle
        self.seen = 0
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                c, _a = self.s.accept()
            except OSError:
                return
            self.seen += 1
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            c.settimeout(10)
            self.handle(c)
        except Exception:                           # noqa: BLE001
            pass
        finally:
            c.close()

    def close(self):
        self.s.close()


def recv_exact(s, n):
    out = b''
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError()
        out += chunk
    return out


class MockKdc(object):
    """svc-acme with PASSWORD (its salt SALT), the service SPN; `skew` seconds between its
    clock and the client's; `down` - nobody answers."""
    def __init__(self):
        self.user_key = K.Key(K.AES256, K.string_to_key(K.AES256, PASSWORD, SALT))
        self.tgs_key = K.Key(K.AES256, os.urandom(32))
        self.svc_key = K.Key(K.AES256, os.urandom(32))
        self.skew = 0
        self.asked = []
        self.server = Server(self.serve)

    def serve(self, s):
        n = struct.unpack('>I', recv_exact(s, 4))[0]
        msg = recv_exact(s, n)
        out = self.answer(msg)
        s.sendall(struct.pack('>I', len(out)) + out)

    def error(self, code, edata=None):
        now = time.time() + self.skew
        return K.app(30, K.seq(K.ctx(0, K.der_int(5)), K.ctx(1, K.der_int(30)),
                               K.ctx(4, gt(now)), K.ctx(5, K.der_int(0)),
                               K.ctx(6, K.der_int(code)), K.ctx(9, K.der_gstring(REALM)),
                               K.ctx(10, K.principal(2, ['krbtgt', REALM])),
                               K.ctx(12, K.der_octets(edata)) if edata is not None else None))

    def ticket(self, key, svc_key, sname, cname):
        now = time.time() + self.skew
        enc = K.app(3, K.seq(K.ctx(0, K.der_bits32(0x40e00000)),
                             K.ctx(1, K.seq(K.ctx(0, K.der_int(key.etype)),
                                            K.ctx(1, K.der_octets(key.key)))),
                             K.ctx(2, K.der_gstring(REALM)), K.ctx(3, K.principal(1, cname)),
                             K.ctx(4, K.seq(K.ctx(0, K.der_int(0)), K.ctx(1, K.der_octets(b'')))),
                             K.ctx(5, gt(now)), K.ctx(7, gt(now + 36000))))
        return K.app(1, K.seq(K.ctx(0, K.der_int(5)), K.ctx(1, K.der_gstring(REALM)),
                              K.ctx(2, K.principal(2, sname)),
                              K.ctx(3, K.enc_data(svc_key.etype, svc_key.encrypt(2, enc), 2))))

    def rep(self, tag, enc_tag, cname, sname, key, reply_key, usage, nonce, ticket):
        now = time.time() + self.skew
        part = K.app(enc_tag, K.seq(
            K.ctx(0, K.seq(K.ctx(0, K.der_int(key.etype)), K.ctx(1, K.der_octets(key.key)))),
            K.ctx(1, K.seq_of([K.seq(K.ctx(0, K.der_int(0)), K.ctx(1, gt(now)))])),
            K.ctx(2, K.der_int(nonce)), K.ctx(4, K.der_bits32(0x40e00000)),
            K.ctx(5, gt(now)), K.ctx(7, gt(now + 36000)), K.ctx(9, K.der_gstring(REALM)),
            K.ctx(10, K.principal(2, sname))))
        return K.app(tag, K.seq(K.ctx(0, K.der_int(5)), K.ctx(1, K.der_int(tag)),
                                K.ctx(3, K.der_gstring(REALM)), K.ctx(4, K.principal(1, cname)),
                                K.ctx(5, ticket),
                                K.ctx(6, K.enc_data(reply_key.etype,
                                                    reply_key.encrypt(usage, part)))))

    def answer(self, msg):
        el = K.Der.one(msg)
        f = el.inner().fields()
        padata = {}
        for pa in (f[3].items() if 3 in f else []):
            pf = pa.fields()
            padata[pf[1].int()] = pf[2].content
        body = f[4]
        b = body.fields()
        nonce = b[7].int()
        sname = K.principal_decode(b[3])
        if el.tag == 0x6a:                          # AS-REQ
            self.asked.append('AS-REQ')
            cname = K.principal_decode(b[1])
            if cname != ['svc-acme']:
                return self.error(6)
            if 2 not in padata:
                info = K.seq_of([K.seq(K.ctx(0, K.der_int(18)), K.ctx(1, K.der_gstring(
                    SALT.decode())))])
                return self.error(25, K.seq_of([K.seq(K.ctx(1, K.der_int(19)),
                                                      K.ctx(2, K.der_octets(info)))]))
            enc = K.Der.one(padata[2]).fields()
            try:
                ts = K.Der.one(self.user_key.decrypt(1, enc[2].content)).fields()
            except K.KrbError:
                return self.error(24)
            when = calendar.timegm(time.strptime(ts[0].text(), '%Y%m%d%H%M%SZ'))
            if abs(when - (time.time() + self.skew)) > 300:
                return self.error(37)
            session = K.Key(K.AES256, os.urandom(32))
            tkt = self.ticket(session, self.tgs_key, ['krbtgt', REALM], cname)
            return self.rep(11, 25, cname, ['krbtgt', REALM], session, self.user_key, 3, nonce,
                            tkt)
        # TGS-REQ
        self.asked.append('TGS-REQ ' + '/'.join(sname))
        ap = K.Der.one(padata[1]).inner().fields()
        tgt = K.Der.one(ap[3].whole).inner().fields()
        tpart = K.Der.one(self.tgs_key.decrypt(2, tgt[3].fields()[2].content)).inner().fields()
        kf = tpart[1].fields()
        session = K.Key(kf[0].int(), kf[1].content)
        auth = K.Der.one(session.decrypt(7, ap[4].fields()[2].content)).inner().fields()
        ck = auth[3].fields()
        if session.checksum(6, body.whole) != ck[1].content:
            return self.error(31)
        if sname != SPN.split('/'):
            return self.error(7)
        svc_session = K.Key(K.AES256, os.urandom(32))
        tkt = self.ticket(svc_session, self.svc_key, sname, ['svc-acme'])
        return self.rep(13, 26, ['svc-acme'], sname, svc_session, session, 8, nonce, tkt)


# ---------------------------------------------------------------------------
# An AD CS of the tests' own: the endpoint mapper and ICertPassage over DCE/RPC
# ---------------------------------------------------------------------------
def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1000)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    return key, cert


def sign_csr(ca, csr_der, other_key=False):
    key, cacert = ca
    csr = x509.load_der_x509_csr(csr_der)
    pub = ec.generate_private_key(ec.SECP256R1()).public_key() if other_key else csr.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(cacert.subject)
            .public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert


def ndr_blob(data):
    if not data:
        return struct.pack('<II', 0, 0)
    return struct.pack('<III', len(data), 0x20000 + len(data), len(data)) + data + \
        b'\x00' * ((4 - len(data) % 4) % 4)


class MockCa(object):
    """`mode`: 'issue' | 'pending' | 'deny' | 'template' | 'otherkey'; `kerberos`: which auth
    types it takes (16, 9, 10)."""
    def __init__(self, kdc):
        self.kdc = kdc
        self.ca = make_ca()
        self.mode = 'issue'
        self.takes = {16, 9, 10}
        self.held = {}
        self.calls = []
        self.binds = []
        self.icpr = Server(self.serve_icpr)
        self.epm = Server(self.serve_epm)

    # -- PDUs --------------------------------------------------------------------------
    @staticmethod
    def read_pdu(s):
        hdr = recv_exact(s, 16)
        n = struct.unpack('<H', hdr[8:10])[0]
        raw = hdr + recv_exact(s, n - 16)
        alen = struct.unpack('<H', raw[10:12])[0]
        out = {'type': raw[2], 'flags': raw[3], 'call': struct.unpack('<I', raw[12:16])[0],
               'raw': raw, 'alen': alen}
        if alen:
            t = len(raw) - alen - 8
            out['atype'], out['alevel'], out['apad'] = raw[t], raw[t + 1], raw[t + 2]
            out['token'] = raw[t + 8:]
            out['end'] = t
        else:
            out['end'] = len(raw)
        return out

    @staticmethod
    def pdu(ptype, call, body, auth=b'', alen=0, flags=3):
        return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, b'\x10\x00\x00\x00',
                           16 + len(body) + len(auth), alen, call) + body + auth

    def bind_ack(self, call, token=None, atype=0, result=0):
        sec = b'49712\x00'
        body = struct.pack('<HHI', 4280, 4280, 0x1234) + struct.pack('<H', len(sec)) + sec
        body += b'\x00' * ((4 - (16 + len(body)) % 4) % 4)
        body += struct.pack('<BBH', 1, 0, 0) + struct.pack('<HH', result, 0) + \
            R.syntax(R.NDR)
        if token is None:
            return self.pdu(12, call, body)
        pad = (4 - (16 + len(body)) % 4) % 4
        body += b'\x00' * pad
        return self.pdu(12, call, body, struct.pack('<BBBBI', atype, 6, pad, 0, 1) + token,
                        len(token))

    # -- the endpoint mapper: ept_map answered with a tower at the ICPR server's port ------
    def serve_epm(self, s):
        p = self.read_pdu(s)
        assert p['type'] == 11 and p['alen'] == 0
        s.sendall(self.bind_ack(p['call']))
        p = self.read_pdu(s)
        stub = p['raw'][24:]
        assert struct.unpack('<H', p['raw'][22:24])[0] == 3
        assert bytes.fromhex('0d2060ae913c9ecf118d7c00aa00c091be') in stub
        tw = R.tower(R.ICPR, 49712, '127.0.0.1')     # the port as Windows would say it
        out = b'\x00' * 20 + struct.pack('<I', 1) + struct.pack('<III', 4, 0, 1) + \
            struct.pack('<I', 3) + struct.pack('<II', len(tw), len(tw)) + tw
        out += b'\x00' * ((4 - len(out) % 4) % 4) + struct.pack('<I', 0)
        s.sendall(self.pdu(2, p['call'], struct.pack('<IHBB', len(out), 0, 0, 0) + out))

    # -- ICertPassage ----------------------------------------------------------------
    def serve_icpr(self, s):
        p = self.read_pdu(s)
        assert p['type'] == 11
        atype = p.get('atype')
        self.binds.append(atype)
        assert p.get('alevel') == 6, 'not packet privacy'
        if atype not in self.takes:
            nak = struct.pack('<HB', 8, 1) + struct.pack('<BB', 5, 0)
            s.sendall(self.pdu(13, p['call'], nak))
            return
        sess = Session(self, atype)
        token = sess.first(p['token'])
        s.sendall(self.bind_ack(p['call'], token, atype))
        p = self.read_pdu(s)
        if p['type'] == 16:                         # AUTH3
            sess.third(p['token'])
        elif p['type'] == 14:                       # alter_context (SPNEGO)
            ack = self.bind_ack(p['call'], sess.third(p['token']), atype)
            s.sendall(ack[:2] + b'\x0f' + ack[3:])  # alter_context_resp
        else:
            return
        while True:
            try:
                stub, call = self.read_request(s, sess)
            except EOFError:
                return
            if not sess.ok:
                fault = struct.pack('<IHBBI', 0, 0, 0, 0, 5) + b'\x00' * 4
                s.sendall(self.pdu(3, call, fault))
                return
            out = self.cert_server_request(stub)
            self.send_response(s, call, out, sess)

    def read_request(self, s, sess):
        stub = b''
        while True:
            p = self.read_pdu(s)
            assert p['type'] == 0
            raw = p['raw']
            sealed = raw[24:p['end']]
            plain = sess.unseal(sealed, p['token'], raw[:24], raw[p['end']:p['end'] + 8])
            stub += plain[:len(plain) - p['apad']] if p['apad'] else plain
            if p['flags'] & 2:
                return stub, p['call']

    def send_response(self, s, call, out, sess):
        room = 1024                                 # several fragments for a certificate
        pieces = [out[i:i + room] for i in range(0, len(out), room)]
        for i, piece in enumerate(pieces):
            flags = (1 if i == 0 else 0) | (2 if i == len(pieces) - 1 else 0)
            pad = (16 - len(piece) % 16) % 16
            plain = piece + b'\x00' * pad
            trailer = struct.pack('<BBBBI', sess.atype, 6, pad, 0, 1)
            vlen = sess.vlen()
            head = struct.pack('<IHBB', len(out) - i * room, 0, 0, 0)
            hdr = struct.pack('<BBBB4sHHI', 5, 0, 2, flags, b'\x10\x00\x00\x00',
                              16 + 8 + len(plain) + 8 + vlen, vlen, call)
            sealed, ver = sess.seal(plain, hdr + head + plain + trailer)
            s.sendall(hdr + head + sealed + trailer + ver)

    # -- CertServerRequest -------------------------------------------------------------
    def cert_server_request(self, stub):
        r = R.NdrReader(stub)
        flags = r.u32()
        ref = r.u32()
        ca = ''
        if ref:
            n, _o, a = r.u32(), r.u32(), r.u32()
            ca = r.take(2 * a).decode('utf-16-le').rstrip('\x00')
            assert n == a
        rid = r.u32()
        attribs = r.blob().decode('utf-16-le').rstrip('\x00')
        csr = r.blob()
        self.calls.append({'flags': flags, 'ca': ca, 'id': rid, 'attribs': attribs,
                           'csr': len(csr)})
        msg, cert, chain, disp, ret = '', b'', b'', 3, 0
        if ca != CA_NAME:
            disp, msg = 0x80070057, 'The parameter is incorrect.'
        elif rid and not csr:                       # a retrieval
            got = self.held.get(rid)
            if got is None:
                disp, msg = 0x80094002, 'Request not found.'
            else:
                cert = got
                disp, msg = 3, 'Issued'
        elif self.mode == 'deny':
            disp, msg = 2, 'Denied by Policy Module'
        elif self.mode == 'template':
            disp, msg = 0x80094012, ('Denied by Policy Module 0x80094012, The permissions on the '
                                     'certificate template do not allow the current user to '
                                     'enroll for this type of certificate.')
        else:
            cert = sign_csr(self.ca, csr, other_key=self.mode == 'otherkey').public_bytes(
                serialization.Encoding.DER)
            if self.mode == 'pending':
                rid = 77
                self.held[rid] = cert
                cert, disp, msg = b'', 5, 'Taken Under Submission'
        if cert:
            rid = rid or 4711
            chain = pkcs7.serialize_certificates(
                [x509.load_der_x509_certificate(cert), self.ca[1]], serialization.Encoding.DER)
        out = struct.pack('<II', rid, disp) + ndr_blob(chain) + ndr_blob(cert) + \
            ndr_blob((msg + '\x00').encode('utf-16-le') if msg else b'') + struct.pack('<I', ret)
        return out


class Session(object):
    """The server's side of one sign-in: Kerberos (16, 9) or NTLM (10)."""
    def __init__(self, ca, atype):
        self.ca, self.atype = ca, atype
        self.ok = True

    # -- Kerberos acceptor (RFC 4120 3.2.3, DCE style) --------------------------------------
    def krb_first(self, token):
        ap = K.Der.one(K.gss_unframe(token)).inner().fields()
        tkt = K.Der.one(ap[3].whole).inner().fields()
        part = K.Der.one(self.ca.kdc.svc_key.decrypt(2, tkt[3].fields()[2].content)).inner()
        kf = part.fields()[1].fields()
        self.session = K.Key(kf[0].int(), kf[1].content)
        auth = K.Der.one(self.session.decrypt(11, ap[4].fields()[2].content)).inner().fields()
        ck = auth[3].fields()
        assert ck[0].int() == 0x8003
        gflags = struct.unpack('<I', ck[1].content[20:24])[0]
        assert gflags & K.GSS_C_DCE_STYLE and gflags & K.GSS_C_CONF and gflags & K.GSS_C_MUTUAL
        self.client_seq = auth[7].int()
        self.subkey = K.Key(K.AES256, os.urandom(32))
        self.server_seq = struct.unpack('>I', os.urandom(4))[0] & 0x7fffffff
        enc = K.app(27, K.seq(K.ctx(0, K.tlv(0x18, auth[5].content)),
                              K.ctx(1, K.der_int(auth[4].int())),
                              K.ctx(2, K.seq(K.ctx(0, K.der_int(18)),
                                             K.ctx(1, K.der_octets(self.subkey.key)))),
                              K.ctx(3, K.der_int(self.server_seq))))
        return K.app(15, K.seq(K.ctx(0, K.der_int(5)), K.ctx(1, K.der_int(15)),
                               K.ctx(2, K.enc_data(18, self.session.encrypt(12, enc)))))

    def krb_third(self, token):
        rep = K.Der.one(token).inner().fields()
        p = K.Der.one(self.session.decrypt(12, rep[2].fields()[2].content)).inner().fields()
        assert p[3].int() == self.server_seq, 'the third leg carries the server\'s sequence'

    def first(self, token):
        if self.atype == 16:
            assert token[:1] == b'\x6e', 'DCE style: a bare AP-REQ'
            return self.krb_first(token)
        if self.atype == 9:
            init = K.Der.one(token)
            inner = K.Der.one(init.content[len(K.der_oid(R.SPNEGO_OID)):]).inner().fields()
            mech = inner[2].content
            assert mech[:1] == b'\x60'
            rep = self.krb_first(mech)
            return K.ctx(1, K.seq(K.ctx(0, K.tlv(0x0a, b'\x01')),
                                  K.ctx(1, K.der_oid(K.MS_KRB5_OID)),
                                  K.ctx(2, K.der_octets(rep))))
        return self.ntlm_challenge(token)

    def third(self, token):
        if self.atype == 16:
            self.krb_third(token)
            return None
        if self.atype == 9:
            f = K.Der.one(token).inner().fields()
            self.krb_third(f[2].content)
            return K.ctx(1, K.seq(K.ctx(0, K.tlv(0x0a, b'\x00'))))
        self.ntlm_check(token)
        return None

    # -- NTLM server (MS-NLMP 3.2.5) ---------------------------------------------------------
    def ntlm_challenge(self, neg):
        assert neg[:8] == b'NTLMSSP\x00'
        nflags = struct.unpack('<I', neg[12:16])[0]
        assert nflags & 0x20, 'sealing asked for'
        self.neg = neg
        self.sc = os.urandom(8)
        dom = 'EXAMPLE'.encode('utf-16-le')
        av = b''
        for aid, v in ((2, dom), (1, 'CA01'.encode('utf-16-le')),
                       (4, 'example.local'.encode('utf-16-le')),
                       (3, 'ca01.example.local'.encode('utf-16-le')),
                       (7, _ntlm.filetime())):
            av += struct.pack('<HH', aid, len(v)) + v
        av += b'\x00' * 4
        flags = 0xe28a8235
        off = 56
        msg = b'NTLMSSP\x00' + struct.pack('<I', 2) + struct.pack('<HHI', len(dom), len(dom), off)
        msg += struct.pack('<I', flags) + self.sc + b'\x00' * 8
        msg += struct.pack('<HHI', len(av), len(av), off + len(dom)) + _ntlm.VERSION
        msg += dom + av
        self.chal = msg
        return msg

    def ntlm_check(self, auth):
        def fld(i):
            ln, _m, off = struct.unpack('<HHI', auth[12 + 8 * i:20 + 8 * i])
            return auth[off:off + ln]
        nt, dom, user, enc_key = fld(1), fld(2), fld(3), fld(5)
        user, dom = user.decode('utf-16-le'), dom.decode('utf-16-le')
        nthash = _ntlm.md4(PASSWORD.encode('utf-16-le'))
        key = hmac.new(nthash, (user.upper() + dom).encode('utf-16-le'), hashlib.md5).digest()
        proof = hmac.new(key, self.sc + nt[16:], hashlib.md5).digest()
        if user != 'svc-acme' or not hmac.compare_digest(proof, nt[:16]):
            self.ok = False
            return
        assert 'host/ca01.example.local'.encode('utf-16-le') in nt
        base = hmac.new(key, proof, hashlib.md5).digest()
        exported = _ntlm.rc4(base, enc_key)
        mic = auth[72:88]
        zeroed = auth[:72] + b'\x00' * 16 + auth[88:]
        assert hmac.new(exported, self.neg + self.chal + zeroed, hashlib.md5).digest() == mic
        md5 = lambda b: hashlib.md5(b).digest()                    # noqa: E731
        self.c_sign = md5(exported + b'session key to client-to-server signing key magic '
                                     b'constant\x00')
        self.c_seal = R.Rc4(md5(exported + b'session key to client-to-server sealing key magic '
                                           b'constant\x00'))
        self.s_sign = md5(exported + b'session key to server-to-client signing key magic '
                                     b'constant\x00')
        self.s_seal = R.Rc4(md5(exported + b'session key to server-to-client sealing key magic '
                                           b'constant\x00'))
        self.c_seq = self.s_seq = 0

    # -- sealing ------------------------------------------------------------------------
    def vlen(self):
        return 16 if self.atype == 10 else 60

    def unseal(self, sealed, token, head, trailer):
        if not self.ok:
            return b''
        if self.atype == 10:
            plain = self.c_seal(sealed)
            chk = self.c_seal(token[4:12])
            want = hmac.new(self.c_sign, struct.pack('<I', self.c_seq) + head + plain + trailer,
                            hashlib.md5).digest()[:8]
            assert chk == want and token[12:16] == struct.pack('<I', self.c_seq), 'NTLM sig'
            self.c_seq += 1
            return plain
        # RFC 4121 Wrap, DCE style: rotated right by RRC + EC (as Windows does)
        _t, flags, _f, ec, rrc, seqn = struct.unpack('>HBBHHQ', token[:16])
        assert flags == 6 and seqn == self.client_seq
        self.client_seq += 1
        rot = token[16:] + sealed
        n = (rrc + ec) % len(rot)
        c = rot[n:] + rot[:n]
        plain = self.subkey.decrypt(K.KG_INITIATOR_SEAL, c)
        return plain[:-(16 + ec)]

    def seal(self, plain, to_sign):
        if self.atype == 10:
            sealed = self.s_seal(plain)
            chk = hmac.new(self.s_sign, struct.pack('<I', self.s_seq) + to_sign,
                           hashlib.md5).digest()[:8]
            sig = struct.pack('<I', 1) + self.s_seal(chk) + struct.pack('<I', self.s_seq)
            self.s_seq += 1
            return sealed, sig
        ec = 0
        hdr0 = struct.pack('>HBBHHQ', 0x0504, 7, 0xff, ec, 0, self.server_seq)
        c = self.subkey.encrypt(K.KG_ACCEPTOR_SEAL, plain + hdr0)
        n = 28 + ec
        rot = c[-n:] + c[:-n]
        self.server_seq += 1
        return rot[16 + n:], struct.pack('>HBBHHQ', 0x0504, 7, 0xff, ec, 28,
                                         self.server_seq - 1) + rot[:16 + n]


# ---------------------------------------------------------------------------
# The issuer end to end
# ---------------------------------------------------------------------------
class Ctx(Context):
    def __init__(self):
        self.steps, self.kv, self.node, self.settings = [], {}, 'test', {}

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, words):
        self.steps.append(('debug', words))

    def cancelled(self):
        return False

    def kv_get(self, key):
        return self.kv.get(key)

    def kv_keys(self, prefix=''):
        return {k: v for k, v in self.kv.items() if k.startswith(prefix)}

    def kv_set(self, key, value, ttl_s=None):
        if value is None:
            self.kv.pop(key, None)
        else:
            self.kv[key] = value

    def seal(self, text, bind):
        return 'sealed:' + base64.b64encode(text.encode()).decode()

    def unseal(self, value, bind):
        return base64.b64decode(value[7:]).decode()

    def http(self, *a, **k):
        raise AssertionError('no HTTP expected')


def make_req(names=('www.example.local',)):
    from acmelib.certs import pki
    key = pki.make_key('ec-256')
    csr_pem, csr_der = pki.make_csr(key, list(names))
    return CertRequest(names=list(names), key_type='ec-256', key_pem=key, csr_pem=csr_pem,
                       csr_der=csr_der, profile={}, cert_id=42)


@unittest.skipUnless(HAVE_CRYPTO, 'python3-cryptography is not installed')
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kdc = MockKdc()
        cls.ca = MockCa(cls.kdc)
        cls.closed = _free_port()           # nobody listens there
        cls.real_open = M.OPEN

        def opener(addr, timeout=None):
            host, port = addr
            where = {('ca01.example.local', 135): cls.ca.epm.port,
                     ('dc01.example.local', 88): cls.kdc.server.port,
                     ('dc-down.example.local', 88): cls.closed}.get((host, port))
            if where is None and host == 'ca01.example.local' and port == 49712:
                where = cls.ca.icpr.port
            if where is None:
                raise OSError('no route to %s:%s' % addr)
            return socket.create_connection(('127.0.0.1', where), timeout)
        M.OPEN = opener

    @classmethod
    def tearDownClass(cls):
        M.OPEN = cls.real_open

    def setUp(self):
        self.ca.mode = 'issue'
        self.ca.takes = {16, 9, 10}
        self.ca.calls = []
        self.ca.binds = []
        self.kdc.skew = 0
        self.kdc.asked = []

    def issuer(self, **over):
        cfg = {'host': 'ca01.example.local', 'ca_name': CA_NAME, 'template': 'acmeWebServer',
               'realm': 'example.local', 'user': 'svc-acme', 'password': PASSWORD,
               'kdc': 'dc01.example.local', 'auth': 'kerberos'}
        cfg.update(over)
        ctx = Ctx()
        return M.MsAdcsRpcIssuer(cfg, ctx), ctx

    def no_secret(self, ctx, *more):
        text = repr(ctx.steps) + repr(ctx.kv) + ''.join(str(m) for m in more)
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(base64.b64encode(PASSWORD.encode()).decode(), text)

    def test_issued_with_kerberos(self):
        iss, ctx = self.issuer()
        req = make_req()
        got = iss.issue(req)
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(len(got.chain_pems), 1)
        self.assertEqual(got.info['req_id'], 4711)
        self.assertEqual(self.ca.binds, [16])
        self.assertEqual(self.kdc.asked, ['AS-REQ', 'AS-REQ', 'TGS-REQ host/ca01.example.local'])
        call = self.ca.calls[0]
        self.assertEqual((call['flags'], call['ca'], call['attribs']),
                         (0x100, CA_NAME, 'CertificateTemplate:acmeWebServer'))
        said = ' | '.join(w for _l, w in ctx.steps)
        self.assertIn('ICertPassage listens on port 49712', said)
        self.assertIn('Kerberos (AES256) as svc-acme@EXAMPLE.LOCAL', said)
        self.assertIn('encrypted (packet privacy)', said)
        self.no_secret(ctx)
        # per certificate: its own template
        req2 = make_req()
        req2.profile = {'template': 'OtherTemplate'}
        iss.issue(req2)
        self.assertEqual(self.ca.calls[-1]['attribs'], 'CertificateTemplate:OtherTemplate')

    def test_fixed_port_and_spnego(self):
        self.ca.takes = {9}
        iss, ctx = self.issuer(port=49712)
        got = iss.issue(make_req())
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(self.ca.binds, [16, 9])
        said = ' | '.join(w for _l, w in ctx.steps)
        self.assertNotIn('endpoint mapper', said)
        self.assertIn('Kerberos in SPNEGO', said)

    def test_pending_then_retrieved(self):
        self.ca.mode = 'pending'
        iss, ctx = self.issuer()
        req = make_req()
        with self.assertRaises(PluginError) as e:
            iss.issue(req)
        self.assertTrue(e.exception.retry)
        self.assertIn('request 77', str(e.exception))
        self.assertIn('Taken Under Submission', str(e.exception))
        held = [k for k in ctx.kv if k.startswith('ms_adcs_rpc-pending:')]
        self.assertEqual(len(held), 1)
        self.no_secret(ctx)
        # the next try: a new key and CSR - the request held is asked for, with its own key
        self.ca.mode = 'issue'
        iss2 = M.MsAdcsRpcIssuer(iss.config, ctx)
        got = iss2.issue(make_req())
        last = self.ca.calls[-1]
        self.assertEqual((last['flags'], last['id'], last['csr'], last['attribs']), (0, 77, 0, ''))
        self.assertEqual(got.key_pem, req.key_pem)
        self.assertFalse([k for k in ctx.kv if k.startswith('ms_adcs_rpc-pending:')])

    def test_denied(self):
        self.ca.mode = 'deny'
        iss, ctx = self.issuer()
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertFalse(e.exception.retry)
        self.assertIn('the CA denied the request', str(e.exception))
        self.assertIn('Denied by Policy Module', str(e.exception))
        self.no_secret(ctx, e.exception)

    def test_template_denied(self):
        self.ca.mode = 'template'
        iss, ctx = self.issuer(auth='ntlm')
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('may not enroll for this template', str(e.exception))
        self.assertIn('0x80094012', str(e.exception))
        self.assertEqual(self.ca.binds, [10])

    def test_wrong_ca_name(self):
        iss, _ctx = self.issuer(ca_name='ca01\\NOT-THE-CA')
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('CA name', str(e.exception))

    def test_wrong_password(self):
        iss, ctx = self.issuer(password='not-' + PASSWORD)
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('password is wrong', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertEqual(self.ca.binds, [])         # never got as far as the CA
        # with NTLM the CA finds out (its first call refused)
        iss, ctx = self.issuer(auth='ntlm', password='not-' + PASSWORD)
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('access is denied', str(e.exception))
        self.assertIn('password', str(e.exception))
        self.no_secret(ctx, e.exception)

    def test_clock_skew(self):
        self.kdc.skew = 900
        iss, ctx = self.issuer()
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('15 minutes', str(e.exception))
        self.assertIn('behind', str(e.exception))
        self.assertIn('NTP', str(e.exception))
        self.assertEqual(self.ca.binds, [])         # not hidden behind NTLM

    def test_ntlm_fallback(self):
        iss, ctx = self.issuer(kdc='dc-down.example.local')
        got = iss.issue(make_req())
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(self.ca.binds, [10])
        said = ' | '.join(w for _l, w in ctx.steps)
        self.assertIn('Kerberos cannot be used', said)
        self.assertIn('NTLMv2 as', said)
        # the CA refusing Kerberos: NTLM too
        self.ca.takes = {10}
        self.ca.binds = []
        iss, ctx = self.issuer()
        iss.issue(make_req())
        self.assertEqual(self.ca.binds, [16, 9, 10])
        # ...but not with "Kerberos only"
        self.ca.binds = []
        iss, ctx = self.issuer(auth='kerberos_only')
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('refused the Kerberos sign-in', str(e.exception))
        self.assertEqual(self.ca.binds, [16, 9])
        # an address for the CA server: no Kerberos
        iss, ctx = self.issuer(host='192.0.2.10', auth='kerberos_only')
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())

    def test_key_mismatch_refused(self):
        self.ca.mode = 'otherkey'
        iss, ctx = self.issuer()
        with self.assertRaises(PluginError) as e:
            iss.issue(make_req())
        self.assertIn('another key', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_try_it(self):
        iss, ctx = self.issuer()
        said = iss.test()
        self.assertIn('ca01.example.local:49712', said)
        self.assertIn('Kerberos (AES256)', said)
        self.assertIn('no certificate asked for', said)
        self.assertEqual(self.ca.calls, [])
        iss, ctx = self.issuer(auth='ntlm')
        self.assertIn('NTLMv2', iss.test())
        self.no_secret(ctx)

    def test_unreachable_and_no_endpoint(self):
        iss, ctx = self.issuer(host='ca02.example.local')
        with self.assertRaises(PluginError) as e:
            iss.test()
        self.assertIn('TCP 135', str(e.exception))
        self.assertTrue(e.exception.retry)

    def test_described(self):
        from acmelib.plugins.base import Registry
        reg = Registry().reload()
        cls = reg.get('issuer', 'ms_adcs_rpc')
        d = cls.describe()
        keys = [f['key'] for f in d['fields']]
        for k in ('host', 'ca_name', 'template', 'auth', 'realm', 'user', 'password', 'kdc',
                  'port'):
            self.assertIn(k, keys)
        self.assertEqual([f['type'] for f in d['fields'] if f['key'] == 'password'], ['secret'])
        self.assertFalse([b for b in reg.broken if 'ms_adcs_rpc' in b[0]])
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(HERE), d['doc'])))


@unittest.skipUnless(HAVE_CRYPTO, 'python3-cryptography is not installed')
class WhatHappens(unittest.TestCase):
    """The run plan: the conversation written down step by step, nothing connected, no
    secret in it."""
    def test_plan(self):
        from acmelib.certs import runplan as RP
        from acmelib.certs import plansources as PS
        from acmelib.plugins import base
        base.REGISTRY.reload()
        cls = base.REGISTRY.get('issuer', 'ms_adcs_rpc')
        full = {f['key']: f.get('default') for f in cls.fields if f.get('default') not in
                (None, '')}
        full.update({'host': 'ca01.example.local', 'ca_name': CA_NAME, 'template': 'WebServer',
                     'realm': 'EXAMPLE.LOCAL', 'user': 'svc-acme', 'password': PASSWORD})
        sec = RP.Secrets()
        scfg, marks = sec.stand_ins(RP._fields_of(cls), full)
        r = {'id': 'r1', 'family': 'issuer', 'kind': 'ms_adcs_rpc', 'name': 'adcs', 'seconds': 30,
             'op': 'issue', 'config': scfg, 'marks': marks,
             'answers': RP.answers_of('ms_adcs_rpc', scfg, first=False, family='issuer'),
             'ssh_answers': [], 'names': ['www.example.com'],
             'pinned': PS.PINNED.get('ms_adcs_rpc', []), 'previous': False}
        got, err = RP.record({'runs': [r], 'settings': {}, 'cert': {
            'names': ['www.example.com'], 'key_type': 'ec-256', 'id': None}}, timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), run.get('error'))
        evs = run['events']
        self.assertFalse([e for e in evs if e.get('kind') in ('bypass', 'socket')])
        rpc = [e for e in evs if e['kind'] == 'rpc']
        self.assertEqual([e['words'].split(' ')[0] for e in rpc],
                         ['Asks', 'Asks', 'Connects', 'Sends'])
        self.assertIn('WebServer', rpc[-1]['args'])
        said = [e['words'] for e in evs if e['kind'] == 'say']
        self.assertTrue([w for w in said if w.startswith('the certificate came')], said)
        import json
        self.assertNotIn(PASSWORD, json.dumps(got))
        steps = RP.steps_of(evs) if hasattr(RP, 'steps_of') else None
        if steps is not None:
            self.assertNotIn(PASSWORD, json.dumps(steps))


if __name__ == '__main__':
    unittest.main(verbosity=2)
