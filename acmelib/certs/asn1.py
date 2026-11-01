# -*- coding: utf-8 -*-
"""
A small DER (and BER, for reading) reader and writer - enough for X.509
certificates, CSRs, CRLs, PKCS#7, PKCS#8, PKCS#12 bags, SCEP messages and the
Java keystores, with nothing but the standard library.

Reading:

    n = asn1.parse(der)            # the first element (Node); asn1.parse_all(data) -> [Node]
    n.tag, n.cls, n.constructed    # 16 / 'universal' / True for a SEQUENCE
    n.children                     # the elements inside (constructed ones, or n.parse_inner())
    n.raw                          # the whole element (header and content) as bytes
    n.content                      # the content only
    n.int() n.oid() n.text() n.bits() n.bool() n.time()   # the value, by its type
    n[0], len(n), iter(n)          # the children
    n.is_ctx(0)                    # context-specific [0]

Writing (each returns DER bytes):

    seq(a, b, ...)  set_of(a, b, ...)  integer(n)  oid('1.2.3')  octets(b)  null()
    boolean(v)  bitstring(b, unused=0)  utf8(s)  printable(s)  ia5(s)  bmp(s)
    utctime(epoch)  gentime(epoch)  time_(epoch)  ctx(n, inner, constructed=True)
    explicit(n, inner)  implicit(n, inner_der)  tlv(tag_byte, content)

Indefinite lengths (BER, as Java and some Windows tools write PKCS#7/PKCS#12)
are read; only definite DER is written.
"""
from __future__ import annotations

import calendar
import datetime
import ipaddress

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 'universal', 'application', 'context', 'private'
_CLASSES = (UNIVERSAL, APPLICATION, CONTEXT, PRIVATE)

# Universal tag numbers
BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 1, 2, 3, 4, 5, 6
ENUMERATED, UTF8STRING, SEQUENCE, SET = 10, 12, 16, 17
NUMERICSTRING, PRINTABLESTRING, T61STRING, IA5STRING = 18, 19, 20, 22
UTCTIME, GENERALIZEDTIME, VISIBLESTRING, UNIVERSALSTRING, BMPSTRING = 23, 24, 26, 28, 30


class Asn1Error(ValueError):
    """Bytes that are not the ASN.1 they were taken for."""


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
class Node(object):
    __slots__ = ('data', 'start', 'hstart', 'cstart', 'cend', 'end', 'cls', 'constructed',
                 'tag', '_children')

    def __init__(self, data, start, cstart, cend, end, cls, constructed, tag, children=None):
        self.data = data
        self.start = start          # the first byte of the header
        self.cstart = cstart        # the first byte of the content
        self.cend = cend            # past the content (before an end-of-contents)
        self.end = end              # past the whole element
        self.cls = cls
        self.constructed = constructed
        self.tag = tag
        self._children = children

    # -- the bytes ----------------------------------------------------------
    @property
    def raw(self):
        return bytes(self.data[self.start:self.end])

    @property
    def content(self):
        return bytes(self.data[self.cstart:self.cend])

    @property
    def children(self):
        if self._children is None:
            if not self.constructed:
                raise Asn1Error('a primitive element (tag %d) has no elements inside' % self.tag)
            self._children = _parse_range(self.data, self.cstart, self.cend)
        return self._children

    def parse_inner(self):
        """The elements inside a primitive element that wraps DER (an OCTET
        STRING or BIT STRING holding a structure, an IMPLICIT tag)."""
        c = self.content
        if self.tag == BIT_STRING and self.cls == UNIVERSAL:
            c = c[1:]
        return parse_all(c)

    def __getitem__(self, i):
        return self.children[i]

    def __len__(self):
        return len(self.children) if self.constructed else 0

    def __iter__(self):
        return iter(self.children if self.constructed else ())

    def __repr__(self):
        return '<asn1 %s %d%s %d bytes>' % (self.cls, self.tag, ' constructed' if
                                           self.constructed else '', self.cend - self.cstart)

    # -- what it is ---------------------------------------------------------
    def is_(self, tag, cls=UNIVERSAL):
        return self.tag == tag and self.cls == cls

    def is_ctx(self, n):
        return self.cls == CONTEXT and self.tag == n

    @property
    def is_seq(self):
        return self.cls == UNIVERSAL and self.tag == SEQUENCE

    @property
    def is_set(self):
        return self.cls == UNIVERSAL and self.tag == SET

    # -- the value ----------------------------------------------------------
    def _primitive(self):
        """The content of a primitive element - or, for a constructed string
        (BER), its pieces joined."""
        if not self.constructed:
            return self.content
        out = b''
        for ch in self.children:
            out += ch._primitive()[1:] if (self.tag == BIT_STRING and out) else ch._primitive()
        return out

    def int(self):
        c = self.content
        if not c:
            raise Asn1Error('an empty INTEGER')
        return int.from_bytes(c, 'big', signed=True)

    def uint_bytes(self):
        """An INTEGER's bytes without the leading 00 DER puts before a high bit."""
        c = self.content
        while len(c) > 1 and c[0] == 0:
            c = c[1:]
        return c

    def bool(self):
        return self.content not in (b'', b'\x00')

    def oid(self):
        return decode_oid(self.content)

    def octets(self):
        return self._primitive()

    def bits(self):
        """A BIT STRING's bytes (the unused-bits count taken away)."""
        c = self._primitive()
        return c[1:] if c else b''

    def bit_list(self):
        """A BIT STRING as the numbers of the bits set (bit 0 the first)."""
        c = self._primitive()
        if not c:
            return []
        out = []
        for i, b in enumerate(c[1:]):
            for j in range(8):
                if b & (0x80 >> j):
                    out.append(i * 8 + j)
        return out

    def text(self):
        """A string of whichever ASN.1 string type, as str."""
        c = self._primitive()
        if self.tag == BMPSTRING:
            return c.decode('utf-16-be', 'replace')
        if self.tag == UNIVERSALSTRING:
            return c.decode('utf-32-be', 'replace')
        if self.tag in (UTF8STRING,):
            return c.decode('utf-8', 'replace')
        if self.tag == T61STRING:
            # Often UTF-8 in practice; Latin-1 otherwise.
            try:
                return c.decode('utf-8')
            except UnicodeDecodeError:
                return c.decode('latin-1')
        try:
            return c.decode('ascii')
        except UnicodeDecodeError:
            try:
                return c.decode('utf-8')
            except UnicodeDecodeError:
                return c.decode('latin-1')

    def time(self):
        """A UTCTime or GeneralizedTime as epoch seconds (int)."""
        return parse_time(self.content.decode('ascii'), self.tag == UTCTIME)

    def ip(self):
        """An iPAddress of a GeneralName: '192.0.2.1', '2001:db8::1' or,
        with a mask (name constraints), '10.0.0.0/8'."""
        return format_ip(self.content)


def _read_header(data, pos, limit):
    if pos >= limit:
        raise Asn1Error('the data ends where an element should begin')
    b = data[pos]
    cls = _CLASSES[b >> 6]
    constructed = bool(b & 0x20)
    tag = b & 0x1f
    pos += 1
    if tag == 0x1f:
        tag = 0
        while True:
            if pos >= limit:
                raise Asn1Error('the data ends inside a tag')
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7f)
            if not b & 0x80:
                break
    if pos >= limit:
        raise Asn1Error('the data ends before a length')
    b = data[pos]
    pos += 1
    if b < 0x80:
        length = b
    elif b == 0x80:
        if not constructed:
            raise Asn1Error('an indefinite length on a primitive element')
        length = None
    else:
        n = b & 0x7f
        if n > 8 or pos + n > limit:
            raise Asn1Error('a length that does not fit')
        length = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    return cls, constructed, tag, length, pos


def _parse_one(data, pos, limit):
    start = pos
    cls, constructed, tag, length, cstart = _read_header(data, pos, limit)
    if length is None:
        children = []
        p = cstart
        while True:
            if p + 2 > limit:
                raise Asn1Error('an indefinite length without its end')
            if data[p] == 0 and data[p + 1] == 0:
                break
            ch = _parse_one(data, p, limit)
            children.append(ch)
            p = ch.end
        return Node(data, start, cstart, p, p + 2, cls, constructed, tag, children)
    cend = cstart + length
    if cend > limit:
        raise Asn1Error('an element longer than the data (%d > %d)' % (cend, limit))
    return Node(data, start, cstart, cend, cend, cls, constructed, tag)


def _parse_range(data, pos, limit):
    out = []
    while pos < limit:
        n = _parse_one(data, pos, limit)
        out.append(n)
        pos = n.end
    return out


def parse(data, strict=False):
    """The first element of `data` (bytes). With strict, nothing may follow it."""
    data = bytes(data)
    n = _parse_one(data, 0, len(data))
    if strict and n.end != len(data):
        raise Asn1Error('%d bytes after the element' % (len(data) - n.end))
    return n


def parse_all(data):
    data = bytes(data)
    return _parse_range(data, 0, len(data))


def looks_like_der(data):
    """A SEQUENCE that takes up all of `data` (or all but trailing zeros/whitespace)."""
    try:
        if not data or data[0] != 0x30:
            return False
        n = parse(data)
        return n.end == len(data) or not bytes(data[n.end:]).strip(b'\x00\r\n \t')
    except Asn1Error:
        return False


def decode_oid(c):
    if not c:
        raise Asn1Error('an empty OBJECT IDENTIFIER')
    parts = []
    v = 0
    for b in c:
        v = (v << 7) | (b & 0x7f)
        if not b & 0x80:
            parts.append(v)
            v = 0
    first = parts[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return '.'.join(str(x) for x in head + parts[1:])


def parse_time(s, utc=None):
    s = s.strip()
    if utc is None:
        utc = len(s.rstrip('Z').split('.')[0].split('+')[0].split('-')[0]) in (10, 12)
    tz = 0
    if s.endswith('Z'):
        s = s[:-1]
    elif len(s) > 5 and s[-5] in '+-':
        sign = 1 if s[-5] == '+' else -1
        tz = sign * (int(s[-4:-2]) * 3600 + int(s[-2:]) * 60)
        s = s[:-5]
    frac = ''
    if '.' in s:
        s, frac = s.split('.', 1)
    if utc:
        yy = int(s[0:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        rest = s[2:]
    else:
        year = int(s[0:4])
        rest = s[4:]
    month, day, hour = int(rest[0:2]), int(rest[2:4]), int(rest[4:6])
    minute = int(rest[6:8]) if len(rest) >= 8 else 0
    sec = int(rest[8:10]) if len(rest) >= 10 else 0
    return calendar.timegm((year, month, day, hour, minute, sec, 0, 0, 0)) - tz


def format_ip(c):
    if len(c) == 4:
        return str(ipaddress.IPv4Address(c))
    if len(c) == 16:
        return str(ipaddress.IPv6Address(c))
    if len(c) == 8:
        net = ipaddress.IPv4Network((ipaddress.IPv4Address(c[:4]),
                                     str(ipaddress.IPv4Address(c[4:]))), strict=False)
        return str(net)
    if len(c) == 32:
        mask = int.from_bytes(c[16:], 'big')
        plen = bin(mask).count('1')
        return str(ipaddress.IPv6Network((ipaddress.IPv6Address(c[:16]), plen), strict=False))
    return c.hex()


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag_byte, content):
    """One element: the tag byte as given (class, constructed bit and number
    already in it, numbers below 31), the length, the content."""
    content = bytes(content)
    return bytes([tag_byte]) + _len(len(content)) + content


def seq(*items):
    return tlv(0x30, b''.join(items))


def set_of(*items, sort=True):
    """A SET OF - sorted, as DER wants, unless sort=False."""
    items = list(items)
    if sort:
        items.sort()
    return tlv(0x31, b''.join(items))


def integer(n):
    if isinstance(n, (bytes, bytearray)):
        b = bytes(n).lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80:
            b = b'\x00' + b
        return tlv(0x02, b)
    n = int(n)
    if n == 0:
        return tlv(0x02, b'\x00')
    length = (n.bit_length() + 8) // 8 if n > 0 else ((-n - 1).bit_length() + 8) // 8
    return tlv(0x02, n.to_bytes(length, 'big', signed=True))


def enumerated(n):
    return b'\x0a' + integer(n)[1:]


def boolean(v):
    return tlv(0x01, b'\xff' if v else b'\x00')


def null():
    return b'\x05\x00'


def oid(dotted):
    parts = [int(x) for x in str(dotted).split('.')]
    if len(parts) < 2:
        raise Asn1Error('an OID needs two parts at least: %s' % dotted)
    vals = [parts[0] * 40 + parts[1]] + parts[2:]
    out = bytearray()
    for v in vals:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, bytes(out))


def octets(b):
    return tlv(0x04, bytes(b))


def bitstring(b, unused=0):
    return tlv(0x03, bytes([unused]) + bytes(b))


def bit_flags(bits):
    """A named BIT STRING (key usage) from the numbers of the bits set, DER
    style: trailing zero bits are not written."""
    if not bits:
        return bitstring(b'')
    top = max(bits)
    nbytes = top // 8 + 1
    val = bytearray(nbytes)
    for i in bits:
        val[i // 8] |= 0x80 >> (i % 8)
    unused = 7 - (top % 8)
    return bitstring(bytes(val), unused)


def utf8(s):
    return tlv(0x0c, str(s).encode('utf-8'))


def printable(s):
    return tlv(0x13, str(s).encode('ascii'))


def ia5(s):
    return tlv(0x16, str(s).encode('ascii'))


def bmp(s):
    return tlv(0x1e, str(s).encode('utf-16-be'))


def _dt(epoch):
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)


def utctime(epoch):
    return tlv(0x17, _dt(epoch).strftime('%y%m%d%H%M%SZ').encode('ascii'))


def gentime(epoch):
    return tlv(0x18, _dt(epoch).strftime('%Y%m%d%H%M%SZ').encode('ascii'))


def time_(epoch):
    """UTCTime up to 2049, GeneralizedTime from 2050 (RFC 5280)."""
    return utctime(epoch) if _dt(epoch).year < 2050 else gentime(epoch)


def ctx(n, content, constructed=True):
    """A context-specific [n] element around `content` (bytes)."""
    if n > 30:
        raise Asn1Error('context tags above 30 are not written')
    return tlv(0x80 | (0x20 if constructed else 0) | n, content)


def explicit(n, inner_der):
    """[n] EXPLICIT around an element."""
    return ctx(n, inner_der, True)


def implicit(n, inner_der):
    """[n] IMPLICIT in place of an element's own tag (its constructed bit kept)."""
    node = parse(inner_der)
    return ctx(n, node.content, node.constructed)


# ---------------------------------------------------------------------------
# Names of the OIDs this program meets
# ---------------------------------------------------------------------------
OIDS = {
    # name attributes
    '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C',
    '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'street', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.12': 'title', '2.5.4.13': 'description', '2.5.4.15': 'businessCategory',
    '2.5.4.17': 'postalCode', '2.5.4.41': 'name', '2.5.4.42': 'GN', '2.5.4.43': 'initials',
    '2.5.4.44': 'generationQualifier', '2.5.4.46': 'dnQualifier', '2.5.4.65': 'pseudonym',
    '2.5.4.97': 'organizationIdentifier',
    '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
    '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL',
    # public keys
    '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.2.1': 'id-ecPublicKey', '1.3.101.112': 'ED25519', '1.3.101.113': 'ED448',
    '1.3.101.110': 'X25519', '1.3.101.111': 'X448', '1.2.840.10040.4.1': 'dsaEncryption',
    # curves
    '1.2.840.10045.3.1.7': 'prime256v1', '1.3.132.0.34': 'secp384r1',
    '1.3.132.0.35': 'secp521r1', '1.3.132.0.10': 'secp256k1',
    # signatures
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.2.840.10040.4.3': 'dsaWithSHA1', '2.16.840.1.101.3.4.3.2': 'dsa_with_SHA256',
    # digests
    '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512',
    '1.2.840.113549.2.5': 'md5',
    # extended key usages
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection',
    '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
    '1.3.6.1.5.5.7.3.17': 'ipsecIKE', '1.3.6.1.5.5.7.3.5': 'ipsecEndSystem',
    '1.3.6.1.5.5.7.3.6': 'ipsecTunnel', '1.3.6.1.5.5.7.3.7': 'ipsecUser',
    '2.5.29.37.0': 'anyExtendedKeyUsage', '1.3.6.1.4.1.311.20.2.2': 'msSmartcardLogin',
    '1.3.6.1.4.1.311.10.3.4': 'msEFS', '1.3.6.1.4.1.311.10.3.12': 'msDocumentSigning',
    '1.3.6.1.5.2.3.5': 'pkInitKDC', '1.3.6.1.5.5.7.3.21': 'sshClient',
    '1.3.6.1.5.5.7.3.22': 'sshServer',
    # extensions
    '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage', '2.5.29.17': 'subjectAltName',
    '2.5.29.18': 'issuerAltName', '2.5.29.19': 'basicConstraints', '2.5.29.30': 'nameConstraints',
    '2.5.29.31': 'crlDistributionPoints', '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier', '2.5.29.37': 'extendedKeyUsage',
    '2.5.29.20': 'cRLNumber', '2.5.29.21': 'cRLReason', '2.5.29.27': 'deltaCRLIndicator',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '1.3.6.1.5.5.7.1.24': 'tlsfeature',
    '1.3.6.1.4.1.11129.2.4.2': 'ct_precert_scts', '1.3.6.1.4.1.11129.2.4.3': 'ct_precert_poison',
    '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'caIssuers',
    '1.3.6.1.4.1.311.20.2': 'msCertificateTemplateName',
    '1.3.6.1.4.1.311.21.7': 'msCertificateTemplate',
    '1.3.6.1.4.1.311.20.2.3': 'msUPN',
    # PKCS
    '1.2.840.113549.1.7.1': 'data', '1.2.840.113549.1.7.2': 'signedData',
    '1.2.840.113549.1.7.3': 'envelopedData', '1.2.840.113549.1.7.6': 'encryptedData',
    '1.2.840.113549.1.9.3': 'contentType', '1.2.840.113549.1.9.4': 'messageDigest',
    '1.2.840.113549.1.9.5': 'signingTime', '1.2.840.113549.1.9.7': 'challengePassword',
    '1.2.840.113549.1.9.14': 'extensionRequest', '1.2.840.113549.1.9.20': 'friendlyName',
    '1.2.840.113549.1.9.21': 'localKeyID',
    '1.2.840.113549.1.5.13': 'PBES2', '1.2.840.113549.1.5.12': 'PBKDF2',
    '2.16.840.1.101.3.4.1.42': 'aes-256-cbc', '2.16.840.1.101.3.4.1.2': 'aes-128-cbc',
    '1.2.840.113549.3.7': 'des-ede3-cbc',
    '1.2.840.113549.1.12.1.3': 'pbeWithSHA1And3-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.1.6': 'pbeWithSHA1And40BitRC2-CBC',
    '1.3.6.1.4.1.42.2.17.1.1': 'sunJksKeyProtection',
    '1.3.6.1.4.1.42.2.19.1': 'PBEWithMD5AndTripleDES',
}

NAMES = {}
for _k, _v in OIDS.items():
    NAMES.setdefault(_v, _k)
del _k, _v


def oid_name(dotted):
    return OIDS.get(dotted, dotted)


def name_oid(name):
    """The OID of a name ('CN', 'serverAuth') - or the name itself when it is dotted already."""
    if name in NAMES:
        return NAMES[name]
    low = {k.lower(): v for k, v in NAMES.items()}
    if str(name).lower() in low:
        return low[str(name).lower()]
    if all(p.isdigit() for p in str(name).split('.')) and '.' in str(name):
        return str(name)
    raise Asn1Error('an unknown name for an OID: %s' % name)
