# -*- coding: utf-8 -*-
"""
NTLMv2 (MS-NLMP) for HTTP, in pure Python - MD4 too, since hashlib under
OpenSSL 3 usually has none (the legacy provider is off), and RC4 for the
session key exchange. Enough to sign in to IIS (AD CS Web Enrollment) with
"NTLM" or "Negotiate" carrying raw NTLMSSP, with a MIC and, over HTTPS, the
channel binding of Extended Protection.

Not a plugin (its name starts with "_", the registry passes it by).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

# ---------------------------------------------------------------------------
# MD4 (RFC 1320)
# ---------------------------------------------------------------------------


def _lrot(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def md4(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        return hashlib.new('md4', data).digest()
    except (ValueError, TypeError):
        pass
    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', bitlen)
    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    F = lambda x, y, z: (x & y) | (~x & z)            # noqa: E731
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)   # noqa: E731
    H = lambda x, y, z: x ^ y ^ z                     # noqa: E731
    for off in range(0, len(msg), 64):
        X = struct.unpack('<16I', bytes(msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = _lrot(a + F(b, c, d) + X[i], 3)
            d = _lrot(d + F(a, b, c) + X[i + 1], 7)
            c = _lrot(c + F(d, a, b) + X[i + 2], 11)
            b = _lrot(b + F(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _lrot(a + G(b, c, d) + X[i] + 0x5a827999, 3)
            d = _lrot(d + G(a, b, c) + X[i + 4] + 0x5a827999, 5)
            c = _lrot(c + G(d, a, b) + X[i + 8] + 0x5a827999, 9)
            b = _lrot(b + G(c, d, a) + X[i + 12] + 0x5a827999, 13)
        for i in (0, 2, 1, 3):
            a = _lrot(a + H(b, c, d) + X[i] + 0x6ed9eba1, 3)
            d = _lrot(d + H(a, b, c) + X[i + 8] + 0x6ed9eba1, 9)
            c = _lrot(c + H(d, a, b) + X[i + 4] + 0x6ed9eba1, 11)
            b = _lrot(b + H(c, d, a) + X[i + 12] + 0x6ed9eba1, 15)
        a, b, c, d = (a + aa) & 0xffffffff, (b + bb) & 0xffffffff, \
            (c + cc) & 0xffffffff, (d + dd) & 0xffffffff
    return struct.pack('<4I', a, b, c, d)


def md4_pure(data):
    """MD4 without asking hashlib (for the tests)."""
    real = hashlib.new
    try:
        hashlib.new = lambda *a, **k: (_ for _ in ()).throw(ValueError('no'))
        return md4(data)
    finally:
        hashlib.new = real


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)


# ---------------------------------------------------------------------------
# NTLM
# ---------------------------------------------------------------------------
NEGOTIATE_UNICODE = 0x00000001
NEGOTIATE_OEM = 0x00000002
REQUEST_TARGET = 0x00000004
NEGOTIATE_SIGN = 0x00000010
NEGOTIATE_NTLM = 0x00000200
NEGOTIATE_ALWAYS_SIGN = 0x00008000
NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NEGOTIATE_TARGET_INFO = 0x00800000
NEGOTIATE_VERSION = 0x02000000
NEGOTIATE_128 = 0x20000000
NEGOTIATE_KEY_EXCH = 0x40000000
NEGOTIATE_56 = 0x80000000

FLAGS = (NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET | NEGOTIATE_SIGN | NEGOTIATE_NTLM |
         NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO |
         NEGOTIATE_VERSION | NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_56)

AV_EOL, AV_NB_COMPUTER, AV_NB_DOMAIN, AV_DNS_COMPUTER, AV_DNS_DOMAIN = 0, 1, 2, 3, 4
AV_FLAGS, AV_TIMESTAMP, AV_TARGET_NAME, AV_CHANNEL_BINDINGS = 6, 7, 9, 10
VERSION = struct.pack('<BBHxxxB', 10, 0, 19041, 15)      # Windows 10, NTLMSSP revision 15
SIG = b'NTLMSSP\x00'


class NtlmError(ValueError):
    pass


def ntowfv1(password):
    return md4(password.encode('utf-16-le'))


def ntowfv2(password, user, domain):
    return hmac.new(ntowfv1(password), (user.upper() + domain).encode('utf-16-le'),
                    hashlib.md5).digest()


def av_pairs_parse(data):
    out = []
    pos = 0
    while pos + 4 <= len(data):
        aid, ln = struct.unpack('<HH', data[pos:pos + 4])
        if aid == AV_EOL:
            break
        out.append((aid, data[pos + 4:pos + 4 + ln]))
        pos += 4 + ln
    return out


def av_pairs_build(pairs):
    return b''.join(struct.pack('<HH', a, len(v)) + v for a, v in pairs) + b'\x00\x00\x00\x00'


def negotiate_message(flags=FLAGS):
    return SIG + struct.pack('<II', 1, flags) + struct.pack('<HHI', 0, 0, 40) + \
        struct.pack('<HHI', 0, 0, 40) + VERSION


class Challenge(object):
    def __init__(self, data):
        if data[:8] != SIG or struct.unpack('<I', data[8:12])[0] != 2:
            raise NtlmError('not an NTLM CHALLENGE_MESSAGE')
        tl, _tm, toff = struct.unpack('<HHI', data[12:20])
        self.flags = struct.unpack('<I', data[20:24])[0]
        self.server_challenge = data[24:32]
        self.target_name = data[toff:toff + tl]
        self.target_info = b''
        if len(data) >= 48:
            il, _im, ioff = struct.unpack('<HHI', data[40:48])
            self.target_info = data[ioff:ioff + il]
        self.raw = data
        self.pairs = av_pairs_parse(self.target_info)

    def av(self, aid):
        for a, v in self.pairs:
            if a == aid:
                return v
        return None


def ntlmv2_response(response_key_nt, server_challenge, client_challenge, timestamp, target_info):
    """(NtChallengeResponse, NTProofStr, SessionBaseKey) - MS-NLMP 3.3.2.
    `target_info` is the AV pairs as they go into the response (with EOL)."""
    temp = b'\x01\x01' + b'\x00' * 6 + timestamp + client_challenge + b'\x00' * 4 + \
        target_info + b'\x00' * 4
    proof = hmac.new(response_key_nt, server_challenge + temp, hashlib.md5).digest()
    session_base = hmac.new(response_key_nt, proof, hashlib.md5).digest()
    return proof + temp, proof, session_base


def lmv2_response(response_key_lm, server_challenge, client_challenge):
    return hmac.new(response_key_lm, server_challenge + client_challenge,
                    hashlib.md5).digest() + client_challenge


def filetime(t=None):
    t = time.time() if t is None else t
    return struct.pack('<Q', int((t + 11644473600) * 10000000))


def channel_bindings_hash(server_cert_der):
    """MsvAvChannelBindings for TLS: MD5 of a gss_channel_bindings_struct whose
    application data is "tls-server-end-point:" + the hash of the server's
    certificate (RFC 5929: its signature's hash, SHA-256 for MD5/SHA-1)."""
    algo = 'sha256'
    try:
        from acmelib.plugins.issuers import _scep_pkcs7 as der
        sig = der.Cert(server_cert_der).sig_alg
        if sig in ('1.2.840.113549.1.1.12', '1.2.840.10045.4.3.3'):
            algo = 'sha384'
        elif sig in ('1.2.840.113549.1.1.13', '1.2.840.10045.4.3.4'):
            algo = 'sha512'
    except Exception:                               # noqa: BLE001
        pass
    app = b'tls-server-end-point:' + hashlib.new(algo, server_cert_der).digest()
    return hashlib.md5(b'\x00' * 16 + struct.pack('<I', len(app)) + app).digest()


def authenticate_message(negotiate, challenge, user, password, domain=None, workstation='',
                         client_challenge=None, exported_key=None, server_cert_der=None,
                         now=None):
    """The AUTHENTICATE_MESSAGE (NTLMv2, a MIC where the server sent a time)."""
    if isinstance(challenge, (bytes, bytearray)):
        challenge = Challenge(bytes(challenge))
    cc = client_challenge or os.urandom(8)
    flags = challenge.flags & FLAGS | NEGOTIATE_UNICODE
    if not challenge.flags & NEGOTIATE_UNICODE:
        flags &= ~NEGOTIATE_UNICODE
    if domain is None:          # the server's own domain; '' stays '' (a user@domain name)
        domain = (challenge.av(AV_NB_DOMAIN) or b'').decode('utf-16-le')
    key = ntowfv2(password, user, domain)
    ts = challenge.av(AV_TIMESTAMP)
    pairs = [(a, v) for a, v in challenge.pairs if a not in (AV_FLAGS, AV_CHANNEL_BINDINGS,
                                                             AV_TARGET_NAME)]
    use_mic = ts is not None
    if use_mic:
        pairs.append((AV_FLAGS, struct.pack('<I', 0x2)))
    else:
        ts = filetime(now)
    if server_cert_der is not None:
        pairs.append((AV_CHANNEL_BINDINGS, channel_bindings_hash(server_cert_der)))
    else:
        pairs.append((AV_CHANNEL_BINDINGS, b'\x00' * 16))
    pairs.append((AV_TARGET_NAME, ('HTTP/' + ((challenge.av(AV_DNS_COMPUTER) or b'')
                                              .decode('utf-16-le'))).encode('utf-16-le')))
    nt, _proof, session_base = ntlmv2_response(key, challenge.server_challenge, cc, ts,
                                               av_pairs_build(pairs))
    lm = b'\x00' * 24 if use_mic else lmv2_response(key, challenge.server_challenge, cc)
    kek = session_base
    if flags & NEGOTIATE_KEY_EXCH:
        exported = exported_key or os.urandom(16)
        enc_key = rc4(kek, exported)
    else:
        exported = kek
        enc_key = b''
    enc = 'utf-16-le' if flags & NEGOTIATE_UNICODE else 'ascii'
    fields = [lm, nt, domain.encode(enc), user.encode(enc), workstation.encode(enc), enc_key]
    off = 88
    hdr = b''
    body = b''
    for f in fields:
        hdr += struct.pack('<HHI', len(f), len(f), off + len(body))
        body += f
    msg = SIG + struct.pack('<I', 3) + hdr + struct.pack('<I', flags) + VERSION + b'\x00' * 16 + body
    if use_mic:
        mic = hmac.new(exported, negotiate + challenge.raw + msg, hashlib.md5).digest()
        msg = msg[:72] + mic + msg[88:]
    return msg


def header_token(value, scheme):
    """The base64 token of a WWW-Authenticate offering `scheme`, or None/''."""
    for part in str(value or '').split(','):
        part = part.strip()
        if part.lower().startswith(scheme.lower()):
            rest = part[len(scheme):].strip()
            return base64.b64decode(rest) if rest else b''
    return None
