# -*- coding: utf-8 -*-
"""
DER read and written, and the PKCS#7 / CMS messages of SCEP (RFC 8894) put
together and taken apart - by hand, the openssl program doing the crypto
(RSA signing and key transport, the symmetric cipher).

Also used by the other issuers for the little they read out of certificates
(acme.py for the ARI id, ms_adcs.py for the certificates of a PKCS#7).

Not a plugin (its name starts with "_", the registry passes it by).
"""
from __future__ import annotations

import base64
import binascii
import calendar
import hashlib
import os
import re
import shutil
import tempfile
import time

# ---------------------------------------------------------------------------
# DER, read
# ---------------------------------------------------------------------------


class DerError(ValueError):
    pass


def _reads(what):
    """A parser of a server's answer: anything malformed is a DerError in words (1.0.101) -
    a cut certificate, a month 13 or a byte not ASCII in a time was an IndexError, a
    UnicodeDecodeError, ... past the issuer's own `except DerError`."""
    def wrap(fn):
        def run(*a, **k):
            try:
                return fn(*a, **k)
            except DerError:
                raise
            except (IndexError, KeyError, TypeError, ValueError, OverflowError,
                    AttributeError) as e:
                raise DerError('%s does not read (%s)' % (what, type(e).__name__))
        run.__name__, run.__doc__ = fn.__name__, fn.__doc__
        return run
    return wrap


def der_read(data, pos=0):
    """One TLV at `pos`: (tag, content bytes, the whole TLV bytes, end)."""
    if pos + 2 > len(data):
        raise DerError('DER cut short')
    tag = data[pos]
    if tag & 0x1f == 0x1f:
        raise DerError('DER high tag numbers are not used here')
    ln = data[pos + 1]
    hdr = 2
    if ln & 0x80:
        n = ln & 0x7f
        if n == 0 or n > 4 or pos + 2 + n > len(data):
            raise DerError('DER length that does not read')
        ln = int.from_bytes(data[pos + 2:pos + 2 + n], 'big')
        hdr += n
    end = pos + hdr + ln
    if end > len(data):
        raise DerError('DER cut short (%d > %d)' % (end, len(data)))
    return tag, bytes(data[pos + hdr:end]), bytes(data[pos:end]), end


def der_items(content):
    """The TLVs inside a constructed value: [(tag, content, whole)]."""
    out = []
    pos = 0
    while pos < len(content):
        tag, c, whole, pos = der_read(content, pos)
        out.append((tag, c, whole))
    return out


def der_one(data):
    tag, c, whole, end = der_read(data, 0)
    return tag, c, whole


def oid_decode(content):
    if not content:
        raise DerError('an empty OID')
    first = content[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    v = 0
    for b in content[1:]:
        v = (v << 7) | (b & 0x7f)
        if not b & 0x80:
            parts.append(v)
            v = 0
    return '.'.join(str(p) for p in parts)


def int_decode(content):
    return int.from_bytes(content, 'big', signed=True)


# ---------------------------------------------------------------------------
# DER, written
# ---------------------------------------------------------------------------
def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def seq(*items):
    return tlv(0x30, b''.join(items))


def set_of(*items):
    return tlv(0x31, b''.join(sorted(items)))        # DER: SET OF sorted


def ctx_tag(n, content, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | n, content)


def der_int(v):
    if v == 0:
        return tlv(0x02, b'\x00')
    b = v.to_bytes((v.bit_length() + 8) // 8, 'big', signed=True)
    return tlv(0x02, b)


def der_oid(dotted):
    parts = [int(p) for p in dotted.split('.')]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7f]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7f))
            p >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def der_null():
    return b'\x05\x00'


def der_octets(b):
    return tlv(0x04, b)


def der_printable(s):
    return tlv(0x13, s.encode('ascii'))


def der_utf8(s):
    return tlv(0x0c, s.encode('utf-8'))


def der_utctime(t=None):
    t = time.gmtime(time.time() if t is None else t)
    if 1950 <= t.tm_year < 2050:
        return tlv(0x17, time.strftime('%y%m%d%H%M%SZ', t).encode())
    return tlv(0x18, time.strftime('%Y%m%d%H%M%SZ', t).encode())


def der_time_decode(tag, content):
    s = content.decode('ascii')
    if tag == 0x17:
        yy = int(s[:2])
        s = ('19' if yy >= 50 else '20') + s
    m = re.match(r'^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$', s)
    if not m:
        raise DerError('a time that does not read: %s' % s)
    return calendar.timegm(tuple(int(m.group(i) or 0) for i in range(1, 7)) + (0, 0, 0))


# ---------------------------------------------------------------------------
# PEM
# ---------------------------------------------------------------------------
PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----', re.S)


def pem_blocks(text, kind=None):
    """[(kind, der)] of every PEM block (of `kind` when given) in `text`."""
    if isinstance(text, bytes):
        text = text.decode('ascii', 'replace')
    out = []
    for m in PEM_RE.finditer(text or ''):
        if kind and m.group(1) != kind:
            continue
        body = re.sub(r'[^A-Za-z0-9+/=]', '', re.sub(r'(?m)^[A-Za-z-]+:.*$', '', m.group(2)))
        out.append((m.group(1), base64.b64decode(body)))
    return out


def pem(der, kind='CERTIFICATE'):
    b = base64.b64encode(der).decode('ascii')
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (
        kind, '\n'.join(b[i:i + 64] for i in range(0, len(b), 64)), kind)


def cert_der(cert):
    """A certificate as DER, given as PEM text, DER bytes or base64."""
    if isinstance(cert, (bytes, bytearray)) and cert[:1] == b'\x30':
        return bytes(cert)
    blocks = pem_blocks(cert, 'CERTIFICATE')
    if blocks:
        return blocks[0][1]
    raise DerError('not a certificate')


def split_pem_chain(text):
    return [pem(d) for _k, d in pem_blocks(text, 'CERTIFICATE')]


# ---------------------------------------------------------------------------
# What is read out of a certificate
# ---------------------------------------------------------------------------
OID_CN = '2.5.4.3'
OID_AKI = '2.5.29.35'
OID_SKI = '2.5.29.14'
OID_BC = '2.5.29.19'
OID_KU = '2.5.29.15'


class Cert(object):
    """The parts of an X.509 certificate this package needs."""
    @_reads('a certificate')
    def __init__(self, cert):
        self.der = cert_der(cert)
        _t, c, _w = der_one(self.der)
        parts = der_items(c)
        self.tbs = parts[0][2]
        self.sig_alg = oid_decode(der_items(parts[1][1])[0][1])
        tbs = der_items(parts[0][1])
        i = 0
        if tbs[0][0] == 0xa0:
            i = 1
        self.serial_content = tbs[i][1]             # the INTEGER's own bytes (DER, signed)
        self.serial = int_decode(tbs[i][1])
        self.issuer_der = tbs[i + 2][2]
        val = der_items(tbs[i + 3][1])
        self.not_before = der_time_decode(val[0][0], val[0][1])
        self.not_after = der_time_decode(val[1][0], val[1][1])
        self.subject_der = tbs[i + 4][2]
        self.spki_der = tbs[i + 5][2]
        self.extensions = {}
        for tag, content, _whole in tbs[i + 6:]:
            if tag == 0xa3:
                for _t2, ext, _w2 in der_items(der_items(content)[0][1]):
                    e = der_items(ext)
                    oid = oid_decode(e[0][1])
                    critical = len(e) == 3 and e[1][1] == b'\xff'
                    self.extensions[oid] = (critical, e[-1][1])

    def fingerprint(self, algo='sha256'):
        return hashlib.new(algo, self.der).hexdigest()

    @property
    def issuer_cn(self):
        return name_cn(self.issuer_der)

    @property
    def subject_cn(self):
        return name_cn(self.subject_der)

    @property
    @_reads('an extension of a certificate')
    def aki_keyid(self):
        ext = self.extensions.get(OID_AKI)
        if not ext:
            return None
        for tag, content, _w in der_items(der_one(ext[1])[1]):
            if tag == 0x80:
                return content
        return None

    @property
    @_reads('an extension of a certificate')
    def is_ca(self):
        ext = self.extensions.get(OID_BC)
        if not ext:
            return False
        items = der_items(der_one(ext[1])[1])
        return bool(items and items[0][0] == 0x01 and items[0][1] != b'\x00')

    @property
    @_reads('an extension of a certificate')
    def key_usage(self):
        """The KeyUsage bits as an int (bit 0 = digitalSignature … as in X.509), or None."""
        ext = self.extensions.get(OID_KU)
        if not ext:
            return None
        _t, c, _w = der_one(ext[1])
        bits = c[1:]
        v = 0
        for i, byte in enumerate(bits):
            for j in range(8):
                if byte & (0x80 >> j):
                    v |= 1 << (i * 8 + j)
        return v

    def is_rsa(self):
        return spki_algorithm(self.spki_der) == '1.2.840.113549.1.1.1'


@_reads('a name')
def name_cn(name_der):
    """The (last) common name of an X.501 Name."""
    cn = None
    for _t, rdn, _w in der_items(der_one(name_der)[1]):
        for _t2, atv, _w2 in der_items(rdn):
            a = der_items(atv)
            if oid_decode(a[0][1]) == OID_CN:
                cn = a[1][1].decode('utf-8', 'replace')
    return cn


@_reads('a public key')
def spki_algorithm(spki_der):
    alg = der_items(der_items(der_one(spki_der)[1])[0][1])
    return oid_decode(alg[0][1])


def csr_spki(csr_der):
    """The SubjectPublicKeyInfo of a PKCS#10 request (DER)."""
    info = der_items(der_items(der_one(csr_der)[1])[0][1])
    return info[2][2]


def csr_subject(csr_der):
    info = der_items(der_items(der_one(csr_der)[1])[0][1])
    return info[1][2]


@_reads('a PKCS#7 of certificates')
def certs_from_pkcs7(data):
    """The certificates (DER) carried in a PKCS#7 / CMS SignedData - a
    degenerate one (certs only) or any other. `data` DER, PEM or base64."""
    if isinstance(data, str):
        data = data.encode('ascii', 'replace')
    if data[:1] != b'\x30':
        blocks = pem_blocks(data)
        if blocks:
            data = blocks[0][1]
        else:
            data = base64.b64decode(re.sub(rb'[^A-Za-z0-9+/=]', b'', data))
    _t, ci, _w = der_one(data)
    parts = der_items(ci)
    if oid_decode(parts[0][1]) != OID_SIGNED_DATA:
        raise DerError('not a PKCS#7 SignedData')
    sd = der_items(der_items(parts[1][1])[0][1])
    out = []
    for tag, content, _whole in sd:
        if tag == 0xa0:
            for t2, _c2, w2 in der_items(content):
                if t2 == 0x30:
                    out.append(w2)
    return out


# ---------------------------------------------------------------------------
# SCEP's PKCS#7 / CMS
# ---------------------------------------------------------------------------
OID_DATA = '1.2.840.113549.1.7.1'
OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_ENVELOPED_DATA = '1.2.840.113549.1.7.3'
OID_RSA = '1.2.840.113549.1.1.1'
OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
OID_CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7'
# id-VeriSign pki attributes (RFC 8894 3.2.1)
OID_SCEP_MESSAGE_TYPE = '2.16.840.1.113733.1.9.2'
OID_SCEP_PKI_STATUS = '2.16.840.1.113733.1.9.3'
OID_SCEP_FAIL_INFO = '2.16.840.1.113733.1.9.4'
OID_SCEP_SENDER_NONCE = '2.16.840.1.113733.1.9.5'
OID_SCEP_RECIPIENT_NONCE = '2.16.840.1.113733.1.9.6'
OID_SCEP_TRANSACTION_ID = '2.16.840.1.113733.1.9.7'

DIGESTS = {'sha256': ('2.16.840.1.101.3.4.2.1', '-sha256'),
           'sha512': ('2.16.840.1.101.3.4.2.3', '-sha512'),
           'sha1': ('1.3.14.3.2.26', '-sha1')}
DIGEST_BY_OID = {v[0]: k for k, v in DIGESTS.items()}
SIG_WITH_RSA = {'sha256': '1.2.840.113549.1.1.11', 'sha512': '1.2.840.113549.1.1.13',
                'sha1': '1.2.840.113549.1.1.5'}
CIPHERS = {'aes256': ('2.16.840.1.101.3.4.1.42', '-aes-256-cbc', 32, 16),
           'aes128': ('2.16.840.1.101.3.4.1.2', '-aes-128-cbc', 16, 16),
           '3des': ('1.2.840.113549.3.7', '-des-ede3-cbc', 24, 8)}

MESSAGE_TYPES = {'CertRep': '3', 'RenewalReq': '17', 'PKCSReq': '19', 'CertPoll': '20',
                 'GetCert': '21', 'GetCRL': '22'}
PKI_STATUS = {'0': 'SUCCESS', '2': 'FAILURE', '3': 'PENDING'}
FAIL_INFO = {'0': 'badAlg', '1': 'badMessageCheck', '2': 'badRequest', '3': 'badTime',
             '4': 'badCertId'}
FAIL_WORDS = {
    'badAlg': 'the CA does not take the algorithms used (try another encryption or digest '
              'in More)',
    'badMessageCheck': 'the CA could not check the message\'s signature (the challenge password, '
                       'or the RA certificate the request was encrypted to)',
    'badRequest': 'the CA refused the request (a wrong or used challenge password, names the '
                  'CA does not allow)',
    'badTime': 'the CA says the time is wrong (signingTime) - check this machine\'s clock',
    'badCertId': 'the CA does not know the certificate asked about',
}


class Crypto(object):
    """The openssl program through a run(args, data) -> bytes, and a folder of
    its own for the files it needs (keys, certificates) - removed by close()."""
    def __init__(self, run):
        self.run = run
        self.dir = tempfile.mkdtemp(prefix='acme-scep-')
        os.chmod(self.dir, 0o700)
        self.n = 0

    def file(self, data, name=None):
        self.n += 1
        p = os.path.join(self.dir, name or ('f%d' % self.n))
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
        return p

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- the operations --------------------------------------------------------------
    def sign(self, key_file, data, digest='sha256'):
        return self.run(['dgst', DIGESTS[digest][1], '-sign', key_file], data)

    def rsa_encrypt(self, cert_file, data):
        return self.run(['pkeyutl', '-encrypt', '-certin', '-inkey', cert_file], data)

    def cipher(self, cipher, key, iv, data, decrypt=False):
        args = ['enc', CIPHERS[cipher][1], '-K', key.hex(), '-iv', iv.hex()]
        if decrypt:
            args.append('-d')
        return self.run(args, data)

    def selfsigned(self, key_file, cn='acme SCEP request', days=2):
        return self.run(['req', '-new', '-x509', '-key', key_file, '-subj', '/CN=' + cn.replace('/', '-'),
                         '-days', str(days), '-outform', 'DER',
                         '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment'])


def issuer_and_serial(cert):
    return seq(cert.issuer_der, tlv(0x02, cert.serial_content))


def attribute(oid, value_der):
    return seq(der_oid(oid), set_of(value_der))


def build_enveloped(crypto, content, recipient_der, cipher='aes256'):
    """An EnvelopedData (in its ContentInfo) of `content` for the RSA key of
    the certificate `recipient_der`."""
    oid, _name, klen, ivlen = CIPHERS[cipher]
    key, iv = os.urandom(klen), os.urandom(ivlen)
    enc = crypto.cipher(cipher, key, iv, content)
    rcpt = Cert(recipient_der)
    if not rcpt.is_rsa():
        raise DerError('the CA/RA certificate does not have an RSA key - SCEP needs one to '
                       'encrypt the request to')
    ek = crypto.rsa_encrypt(crypto.file(pem(recipient_der)), key)
    ri = seq(der_int(0), issuer_and_serial(rcpt), seq(der_oid(OID_RSA), der_null()), der_octets(ek))
    eci = seq(der_oid(OID_DATA), seq(der_oid(oid), der_octets(iv)), ctx_tag(0, enc, constructed=False))
    env = seq(der_int(0), set_of(ri), eci)
    return seq(der_oid(OID_ENVELOPED_DATA), ctx_tag(0, env))


def build_signed(crypto, content, signer_der, key_file, attrs, digest='sha256', certs=None):
    """A SignedData (in its ContentInfo) of `content` (type data), signed by
    the RSA key `key_file` of `signer_der`, with the authenticated attributes
    `attrs` ([(oid, value DER)]) plus contentType, messageDigest, signingTime."""
    doid = DIGESTS[digest][0]
    md = hashlib.new(digest, content).digest()
    all_attrs = [attribute(OID_CONTENT_TYPE, der_oid(OID_DATA)),
                 attribute(OID_MESSAGE_DIGEST, der_octets(md)),
                 attribute(OID_SIGNING_TIME, der_utctime())]
    all_attrs += [attribute(o, v) for o, v in attrs]
    signed_set = set_of(*all_attrs)                         # what is signed: SET OF, tag 0x31
    sig = crypto.sign(key_file, signed_set, digest)
    signer = Cert(signer_der)
    si = seq(der_int(1), issuer_and_serial(signer), seq(der_oid(doid), der_null()),
             b'\xa0' + signed_set[1:],                     # [0] IMPLICIT in the SignerInfo
             seq(der_oid(OID_RSA), der_null()), der_octets(sig))
    cert_list = [signer_der] + list(certs or [])
    sd = seq(der_int(1), set_of(seq(der_oid(doid), der_null())),
             seq(der_oid(OID_DATA), ctx_tag(0, der_octets(content))),
             ctx_tag(0, b''.join(cert_list)),
             set_of(si))
    return seq(der_oid(OID_SIGNED_DATA), ctx_tag(0, sd))


def build_degenerate(certs):
    """A certs-only PKCS#7 (what a CertRep's envelope holds)."""
    sd = seq(der_int(1), set_of(), seq(der_oid(OID_DATA)), ctx_tag(0, b''.join(certs)), set_of())
    return seq(der_oid(OID_SIGNED_DATA), ctx_tag(0, sd))


class SignedMessage(object):
    """A SignedData taken apart: the content, the signer's attributes, the certificates."""
    @_reads('a PKCS#7 SignedData')
    def __init__(self, der):
        self.der = der
        _t, ci, _w = der_one(der)
        parts = der_items(ci)
        if oid_decode(parts[0][1]) != OID_SIGNED_DATA:
            raise DerError('the answer is not a PKCS#7 SignedData')
        sd = der_items(der_items(parts[1][1])[0][1])
        self.content = b''
        self.certs = []
        self.attrs = {}
        self.signed_attrs_der = b''
        self.signature = b''
        self.digest = 'sha256'
        self.signer_serial = None
        self.signer_issuer = None
        eci = der_items(sd[2][1])
        if len(eci) > 1:
            inner = der_items(eci[1][1])
            if inner:
                t, c, _w = inner[0]
                if t == 0x24:                               # constructed OCTET STRING (BER)
                    c = b''.join(x[1] for x in der_items(c))
                self.content = c
        for tag, content, _whole in sd[3:]:
            if tag == 0xa0:
                self.certs = [w for t2, _c2, w in der_items(content) if t2 == 0x30]
            elif tag == 0x31:
                infos = der_items(content)
                if infos:
                    si = der_items(infos[0][1])
                    ias = der_items(si[1][1])
                    self.signer_issuer = ias[0][2]
                    self.signer_serial = int_decode(ias[1][1])
                    self.digest = DIGEST_BY_OID.get(oid_decode(der_items(si[2][1])[0][1]), 'sha256')
                    for t3, c3, w3 in si[3:]:
                        if t3 == 0xa0:
                            self.signed_attrs_der = b'\x31' + w3[1:]
                            for _t4, a, _w4 in der_items(c3):
                                ai = der_items(a)
                                vals = der_items(ai[1][1])
                                self.attrs[oid_decode(ai[0][1])] = vals[0] if vals else None
                        elif t3 == 0x04:
                            self.signature = c3

    def attr_text(self, oid):
        v = self.attrs.get(oid)
        return v[1].decode('ascii', 'replace') if v else None

    def attr_bytes(self, oid):
        v = self.attrs.get(oid)
        return v[1] if v else None

    @_reads('a certificate of the SignedData')
    def signer_cert(self):
        for c in self.certs:
            x = Cert(c)
            if x.serial == self.signer_serial and x.issuer_der == self.signer_issuer:
                return c
        return None

    def digest_ok(self):
        md = self.attr_bytes(OID_MESSAGE_DIGEST)
        return md is not None and md == hashlib.new(self.digest, self.content).digest()


@_reads('a PKCS#7 EnvelopedData')
def enveloped_parts(der):
    """(recipient issuer DER, serial, encrypted key, cipher name, iv, encrypted content)."""
    _t, ci, _w = der_one(der)
    parts = der_items(ci)
    if oid_decode(parts[0][1]) != OID_ENVELOPED_DATA:
        raise DerError('not an EnvelopedData')
    env = der_items(der_items(parts[1][1])[0][1])
    i = 1 if env[1][0] == 0xa0 else 0               # originatorInfo, never in SCEP
    ri = der_items(der_items(env[1 + i][1])[0][1])
    ias = der_items(ri[1][1])
    eci = der_items(env[2 + i][1])
    alg = der_items(eci[1][1])
    oid = oid_decode(alg[0][1])
    cipher = next((k for k, v in CIPHERS.items() if v[0] == oid), None)
    iv = der_one(alg[1][2])[1]
    enc = eci[2][1]
    if eci[2][0] == 0xa0:                           # constructed (BER) form
        enc = b''.join(x[1] for x in der_items(enc))
    return ias[0][2], int_decode(ias[1][1]), ri[3][1], cipher, iv, enc


def open_enveloped(crypto, der, key_file):
    """The content of an EnvelopedData for our RSA key (`key_file`) - the key
    unwrapped with openssl pkeyutl, the content with openssl enc."""
    _iss, _ser, ek, cipher, iv, enc = enveloped_parts(der)
    if not cipher:
        raise DerError('the answer is encrypted with an algorithm acme does not know')
    key = crypto.run(['pkeyutl', '-decrypt', '-inkey', key_file], ek)
    return crypto.cipher(cipher, key, iv, enc, decrypt=True)


def add_challenge_password(crypto, csr_der, key_file, password, digest='sha256'):
    """The request again with a challengePassword attribute (RFC 2985 5.4.1),
    signed anew with its key (RSA)."""
    _t, c, _w = der_one(csr_der)
    info = der_items(der_items(c)[0][1])
    attrs = []
    for tag, content, whole in info[3:]:
        if tag == 0xa0:
            for _t2, a, w2 in der_items(content):
                if oid_decode(der_items(a)[0][1]) != OID_CHALLENGE_PASSWORD:
                    attrs.append(w2)
    try:
        password.encode('ascii')
        pw = der_printable(password) if re.match(r"^[A-Za-z0-9 '()+,\-./:=?]*\Z", password) \
            else der_utf8(password)
    except UnicodeEncodeError:
        pw = der_utf8(password)
    attrs.append(attribute(OID_CHALLENGE_PASSWORD, pw))
    new_info = seq(info[0][2], info[1][2], info[2][2], ctx_tag(0, b''.join(sorted(attrs))))
    sig = crypto.sign(key_file, new_info, digest)
    return seq(new_info, seq(der_oid(SIG_WITH_RSA[digest]), der_null()), tlv(0x03, b'\x00' + sig))


def transaction_id(spki_der):
    """RFC 8894 3.2.1.1: the hash of the public key, as hex text."""
    return hashlib.sha256(spki_der).hexdigest().upper()


@_reads('a chain of certificates')
def order_chain(leaf_der, others):
    """The chain above the certificate, nearest first."""
    pool = [Cert(c) for c in others]
    out = []
    cur = Cert(leaf_der)
    while True:
        nxt = next((c for c in pool if c.subject_der == cur.issuer_der and c not in out), None)
        if not nxt or nxt.der == cur.der:
            break
        out.append(nxt)
        if nxt.subject_der == nxt.issuer_der:
            break
        cur = nxt
    rest = [c for c in pool if c not in out]
    return [c.der for c in out + rest]


def b64(data):
    return base64.b64encode(data).decode('ascii')


def hexlify(b):
    return binascii.hexlify(b).decode('ascii')
