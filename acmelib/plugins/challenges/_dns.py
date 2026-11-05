# -*- coding: utf-8 -*-
"""
DNS on the wire, in the standard library alone - what acme's own DNS server
(acmelib/certs/dnsserver.py) and the DNS-01 modules beside this file share:

    parse(data) -> Message           a message read, never more than it holds
                                     (FormErr for anything malformed)
    Message(...).to_wire(limit)      a message written, names compressed
    rdata_to_wire / rdata_to_text    A AAAA NS CNAME PTR MX TXT SOA SRV CAA (others as hex)
    query(server, name, qtype)       one question to one server, UDP then TCP when cut short
    make_update(zone, add, delete)   an RFC 2136 UPDATE
    tsig_sign / tsig_verify          RFC 8945 TSIG (hmac-sha256/-sha512/-sha384/-sha224/-sha1/-md5)
    find_zone / zone_servers / follow_cname / txt_at   what the DNS-01 modules look up

The file name starts with "_" so the registry does not take it for a module.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import struct
import time

# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------
TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15, 'TXT': 16,
         'AAAA': 28, 'SRV': 33, 'OPT': 41, 'DS': 43, 'RRSIG': 46, 'NSEC': 47, 'DNSKEY': 48,
         'HTTPS': 65, 'SVCB': 64, 'TSIG': 250, 'IXFR': 251, 'AXFR': 252, 'ANY': 255, 'CAA': 257}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
CLASS_IN, CLASS_CH, CLASS_NONE, CLASS_ANY = 1, 3, 254, 255

OP_QUERY, OP_NOTIFY, OP_UPDATE = 0, 4, 5
NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5
YXDOMAIN, YXRRSET, NXRRSET, NOTAUTH, NOTZONE = 6, 7, 8, 9, 10
BADVERS = 16
BADSIG, BADKEY, BADTIME, BADTRUNC = 16, 17, 18, 22
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
          5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH',
          10: 'NOTZONE', 16: 'BADVERS'}
TSIG_ERRORS = {16: 'BADSIG', 17: 'BADKEY', 18: 'BADTIME', 22: 'BADTRUNC'}

PUBLIC_RESOLVERS = ('1.1.1.1', '8.8.8.8', '9.9.9.9')


class FormErr(ValueError):
    """A message that cannot be read."""


class DnsError(OSError):
    """A question that got no usable answer (timeouts, a broken answer)."""


def type_code(t):
    if isinstance(t, int):
        return t
    t = str(t).upper()
    if t in TYPES:
        return TYPES[t]
    if t.startswith('TYPE') and t[4:].isdigit():
        return int(t[4:])
    raise ValueError('unknown record type %s' % t)


def type_name(code):
    return TYPE_NAMES.get(code, 'TYPE%d' % code)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def norm(name):
    """A name as acme keeps it: lower case, no dot at the end ('' is the root)."""
    return str(name or '').strip().rstrip('.').lower()


def _label_bytes(label):
    if any(ord(c) > 127 for c in label):
        try:
            return label.encode('idna')
        except UnicodeError:
            raise ValueError('a label that cannot be written: %r' % label)
    return label.encode('ascii')


def _split_labels(name):
    """Labels of a name, with \\. and \\DDD (as read_name writes them) undone
    and a label of letters beyond ASCII written as IDNA."""
    texts, cur, i, n = [], '', 0, len(name)
    while i < n:                                    # split on the dots not escaped
        if name[i] == '\\' and i + 1 < n:
            cur += name[i:i + 2]
            i += 2
            continue
        if name[i] == '.':
            texts.append(cur)
            cur = ''
        else:
            cur += name[i]
        i += 1
    texts.append(cur)
    out = []
    for t in texts:
        if '\\' not in t:
            out.append(_label_bytes(t) if t else b'')
            continue
        raw, i = bytearray(), 0
        while i < len(t):
            if t[i] == '\\' and i + 1 < len(t):
                if len(t[i + 1:i + 4]) == 3 and t[i + 1:i + 4].isdigit():
                    raw.append(int(t[i + 1:i + 4]) & 0xFF)
                    i += 4
                    continue
                raw += t[i + 1].encode('utf-8')
                i += 2
                continue
            raw += t[i].encode('utf-8')
            i += 1
        out.append(bytes(raw))
    return out


def name_labels(name):
    name = str(name or '').strip()
    if name in ('', '.'):
        return []
    if name.endswith('.') and not name.endswith('\\.'):
        name = name[:-1]
    out = _split_labels(name) if ('\\' in name or any(ord(c) > 127 for c in name)) else \
        [lab.encode('ascii') for lab in name.split('.')]
    for raw in out:
        if not raw or len(raw) > 63:
            raise ValueError('a label of %d bytes in %r' % (len(raw), name))
    if sum(len(x) + 1 for x in out) + 1 > 255:
        raise ValueError('a name longer than 255 bytes')
    return out


def name_to_wire(name, comp=None, at=0, lower=False):
    """The name in wire form. `comp` (a dict) makes it compressed: suffixes
    already written are pointed to, new ones are noted at offset `at`."""
    labels = name_labels(name)
    if lower:
        labels = [x.lower() for x in labels]
    out = b''
    for i in range(len(labels)):
        key = b'.'.join(labels[i:]).lower()
        if comp is not None and key in comp:
            return out + struct.pack('>H', 0xC000 | comp[key])
        if comp is not None and at + len(out) < 0x3FFF:
            comp[key] = at + len(out)
        out += bytes([len(labels[i])]) + labels[i]
    return out + b'\x00'


def read_name(data, at):
    """(name, offset after it). Pointers must point backwards, so a loop is
    impossible; a name longer than 255 bytes is malformed."""
    labels = []
    end = None
    total = 0
    hops = 0
    n = len(data)
    while True:
        if at >= n:
            raise FormErr('a name runs past the end')
        ln = data[at]
        if ln == 0:
            at += 1
            break
        if ln & 0xC0 == 0xC0:
            if at + 1 >= n:
                raise FormErr('a pointer runs past the end')
            ptr = ((ln & 0x3F) << 8) | data[at + 1]
            if end is None:
                end = at + 2
            if ptr >= at:
                raise FormErr('a pointer that does not point back')
            hops += 1
            if hops > 64:
                raise FormErr('too many pointers')
            at = ptr
            continue
        if ln & 0xC0:
            raise FormErr('an unknown kind of label')
        if at + 1 + ln > n:
            raise FormErr('a label runs past the end')
        lab = data[at + 1:at + 1 + ln]
        total += ln + 1
        if total > 255:
            raise FormErr('a name longer than 255 bytes')
        labels.append(lab)
        at += 1 + ln
    text = '.'.join(_label_text(x) for x in labels)
    return text, (end if end is not None else at)


def _label_text(raw):
    """A label as text; bytes that are not plain are escaped (\\DDD), so a
    name read is never mistaken for another."""
    out = []
    for b in raw:
        c = chr(b)
        if c == '.' or c == '\\':
            out.append('\\' + c)
        elif 0x21 <= b <= 0x7E:
            out.append(c)
        else:
            out.append('\\%03d' % b)
    return ''.join(out)


def in_zone(name, zone):
    name, zone = norm(name), norm(zone)
    if '\\' in name or '\\' in zone:
        # by the labels (1.0.51): "evil\.acme.example.net" (labels evil.acme, example, net)
        # ended with ".acme.example.net" as text
        try:
            nl, zl = [x.lower() for x in name_labels(name)], [x.lower() for x in name_labels(zone)]
        except ValueError:
            return False
        return not zl or (len(nl) >= len(zl) and nl[len(nl) - len(zl):] == zl)
    return not zone or name == zone or name.endswith('.' + zone)


# ---------------------------------------------------------------------------
# Record data
# ---------------------------------------------------------------------------
def txt_strings(value):
    """The character-strings of a TXT value: a plain value is one text cut
    into pieces of 255; a value written as "a" "b" (zone-file style) is those."""
    if isinstance(value, (list, tuple)):
        parts = [v.encode('utf-8') if isinstance(v, str) else bytes(v) for v in value]
    else:
        s = str(value)
        if s.startswith('"'):
            parts = [p.encode('utf-8') for p in _quoted(s)]
        else:
            raw = s.encode('utf-8')
            parts = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b'']
    out = []
    for p in parts:
        for i in range(0, max(len(p), 1), 255):
            out.append(p[i:i + 255])
    return out


def _quoted(s):
    """"a b" "c\\"d" -> ['a b', 'c"d']; text outside quotes taken word by word."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i].isspace():
            i += 1
            continue
        if s[i] == '"':
            i += 1
            buf = []
            while i < n and s[i] != '"':
                if s[i] == '\\' and i + 1 < n:
                    i += 1
                buf.append(s[i])
                i += 1
            i += 1
            out.append(''.join(buf))
        else:
            j = i
            while j < n and not s[j].isspace():
                j += 1
            out.append(s[i:j])
            i = j
    return out


def rdata_to_wire(rtype, value, comp=None, at=0):
    """The text of a record (as dns_records and the static lines hold it) in
    wire form. Names inside NS/CNAME/PTR/MX/SOA may be compressed (RFC 3597
    says only those)."""
    t = type_code(rtype)
    v = str(value).strip() if not isinstance(value, (list, tuple, bytes)) else value
    if t == 1:
        return socket.inet_pton(socket.AF_INET, v)
    if t == 28:
        return socket.inet_pton(socket.AF_INET6, v)
    if t in (2, 5, 12):
        return name_to_wire(v, comp, at)
    if t == 15:
        pref, host = v.split(None, 1)
        return struct.pack('>H', int(pref)) + name_to_wire(host, comp, at + 2)
    if t == 16:
        return b''.join(bytes([len(p)]) + p for p in txt_strings(v))
    if t == 6:
        bits = v.split()
        if len(bits) != 7:
            raise ValueError('an SOA is "mname rname serial refresh retry expire minimum"')
        m = name_to_wire(bits[0], comp, at)
        r = name_to_wire(bits[1], comp, at + len(m))
        return m + r + struct.pack('>IIIII', *[int(x) & 0xFFFFFFFF for x in bits[2:]])
    if t == 33:
        prio, weight, port, target = v.split()
        return struct.pack('>HHH', int(prio), int(weight), int(port)) + name_to_wire(target)
    if t == 257:
        m = re.match(r'^\s*(\d+)\s+([A-Za-z0-9]+)\s+(.*)$', v)
        if not m:
            raise ValueError('a CAA is "flags tag value", 0 issue "letsencrypt.org"')
        val = m.group(3).strip()
        if val.startswith('"'):
            val = ''.join(_quoted(val))
        tag = m.group(2).encode('ascii')
        return bytes([int(m.group(1)) & 0xFF, len(tag)]) + tag + val.encode('utf-8')
    if isinstance(v, bytes):
        return v
    m = re.match(r'^\\#\s+(\d+)\s*([0-9A-Fa-f\s]*)$', v)        # RFC 3597 \# len hex
    if m:
        raw = binascii.unhexlify(re.sub(r'\s+', '', m.group(2)))
        if len(raw) != int(m.group(1)):
            raise ValueError('the length of \\# data does not match')
        return raw
    raise ValueError('acme cannot write a %s record from text' % type_name(t))


def rdata_to_text(rtype, data, at, size):
    """The text of one record read from a message (names in it may point
    anywhere earlier in `data`)."""
    end = at + size
    if end > len(data):
        raise FormErr('record data runs past the end')
    rd = data[at:end]
    if rtype == 1:
        if size != 4:
            raise FormErr('an A record of %d bytes' % size)
        return socket.inet_ntop(socket.AF_INET, rd)
    if rtype == 28:
        if size != 16:
            raise FormErr('an AAAA record of %d bytes' % size)
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return read_name(data, at)[0]
    if rtype == 15:
        if size < 3:
            raise FormErr('a short MX')
        return '%d %s' % (struct.unpack('>H', rd[:2])[0], read_name(data, at + 2)[0])
    if rtype == 16:
        parts, j = [], 0
        while j < size:
            ln = rd[j]
            if j + 1 + ln > size:
                raise FormErr('a TXT string runs past its record')
            parts.append(rd[j + 1:j + 1 + ln].decode('utf-8', 'replace'))
            j += 1 + ln
        return ''.join(parts)
    if rtype == 6:
        m, p = read_name(data, at)
        r, p = read_name(data, p)
        if p + 20 > end:
            raise FormErr('a short SOA')
        return '%s %s %d %d %d %d %d' % ((m, r) + struct.unpack('>IIIII', data[p:p + 20]))
    if rtype == 33:
        if size < 7:
            raise FormErr('a short SRV')
        a, b, c = struct.unpack('>HHH', rd[:6])
        return '%d %d %d %s' % (a, b, c, read_name(data, at + 6)[0])
    if rtype == 257:
        if size < 2 or 2 + rd[1] > size:
            raise FormErr('a short CAA')
        return '%d %s "%s"' % (rd[0], rd[2:2 + rd[1]].decode('ascii', 'replace'),
                               rd[2 + rd[1]:].decode('utf-8', 'replace'))
    return '\\# %d %s' % (size, binascii.hexlify(rd).decode())


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------
class RR(object):
    """One record. `text` is its data as text (None for an empty one: an
    RFC 2136 delete, an OPT); `raw` its data as it came."""
    __slots__ = ('name', 'rtype', 'rclass', 'ttl', 'text', 'raw', 'offset')

    def __init__(self, name, rtype, rclass=CLASS_IN, ttl=0, text=None, raw=None, offset=0):
        self.name = name
        self.rtype = type_code(rtype)
        self.rclass = rclass
        self.ttl = ttl
        self.text = text
        self.raw = raw
        self.offset = offset

    def __repr__(self):
        return 'RR(%s %d %s %s %r)' % (self.name, self.ttl, self.rclass, type_name(self.rtype),
                                       self.text)


class Message(object):
    def __init__(self, ident=0, flags=0):
        self.id = ident
        self.flags = flags
        self.question = []          # [(name, qtype, qclass)]
        self.answer = []
        self.authority = []
        self.additional = []
        self.raw_question = b''     # the question as it came (0x20 kept)
        self.wire = b''

    # the bits of the flags
    qr = property(lambda s: bool(s.flags & 0x8000))
    opcode = property(lambda s: (s.flags >> 11) & 0xF)
    aa = property(lambda s: bool(s.flags & 0x0400))
    tc = property(lambda s: bool(s.flags & 0x0200))
    rd = property(lambda s: bool(s.flags & 0x0100))
    ra = property(lambda s: bool(s.flags & 0x0080))

    @property
    def rcode(self):
        """The whole rcode: the four bits of the header and the eight of the OPT."""
        rc = self.flags & 0xF
        opt = self.opt
        if opt is not None:
            rc |= ((opt.ttl >> 24) & 0xFF) << 4
        return rc

    @property
    def opt(self):
        for r in self.additional:
            if r.rtype == 41:
                return r
        return None

    def records(self, rtype=None, section='answer'):
        return [r for r in getattr(self, section) if rtype is None or r.rtype == type_code(rtype)]

    def texts(self, rtype, name=None):
        t = type_code(rtype)
        return [r.text for r in self.answer if r.rtype == t and
                (name is None or norm(r.name) == norm(name))]

    def to_wire(self, compress=True):
        comp = {} if compress else None
        out = bytearray(struct.pack('>HHHHHH', self.id & 0xFFFF, self.flags & 0xFFFF,
                                    len(self.question), len(self.answer), len(self.authority),
                                    len(self.additional)))
        for name, qtype, qclass in self.question:
            out += name_to_wire(name, comp, len(out)) + struct.pack('>HH', qtype, qclass)
        for sec in (self.answer, self.authority, self.additional):
            for r in sec:
                out += rr_to_wire(r, comp, len(out))
        return bytes(out)


def rr_to_wire(r, comp=None, at=0):
    head = name_to_wire(r.name, comp, at)
    if r.raw is not None:
        rd = r.raw
    elif r.text is None:
        rd = b''
    else:
        rd = rdata_to_wire(r.rtype, r.text, comp if r.rtype in (2, 5, 6, 12, 15) else None,
                           at + len(head) + 10)
    return head + struct.pack('>HHIH', r.rtype, r.rclass, r.ttl & 0xFFFFFFFF, len(rd)) + rd


def parse(data):
    """A message read whole. Anything wrong in it is a FormErr - never another
    exception, whatever the bytes are."""
    try:
        return _parse(bytes(data))
    except FormErr:
        raise
    except (IndexError, struct.error, ValueError, UnicodeError, OSError) as e:
        raise FormErr('a message that cannot be read: %s' % e)


def _parse(data):
    if len(data) < 12:
        raise FormErr('shorter than a header')
    ident, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', data[:12])
    m = Message(ident, flags)
    m.wire = data
    at = 12
    if qd > 64 or an + ns + ar > 4096:
        raise FormErr('more records than a message can hold')
    for _ in range(qd):
        name, at = read_name(data, at)
        if at + 4 > len(data):
            raise FormErr('a question runs past the end')
        qtype, qclass = struct.unpack('>HH', data[at:at + 4])
        at += 4
        m.question.append((name, qtype, qclass))
    m.raw_question = data[12:at]
    for count, sec in ((an, m.answer), (ns, m.authority), (ar, m.additional)):
        for _ in range(count):
            start = at
            name, at = read_name(data, at)
            if at + 10 > len(data):
                raise FormErr('a record runs past the end')
            rtype, rclass, ttl, size = struct.unpack('>HHIH', data[at:at + 10])
            at += 10
            if at + size > len(data):
                raise FormErr('record data runs past the end')
            if size == 0:
                text = None
            elif rtype in (41, 250):
                text = None
            else:
                text = rdata_to_text(rtype, data, at, size)
            sec.append(RR(name, rtype, rclass, ttl, text, data[at:at + size], start))
            at += size
    return m


def make_query(name, qtype, rd=True, edns=1232, ident=None, do=False):
    m = Message(secrets.randbits(16) if ident is None else ident, 0x0100 if rd else 0)
    m.question.append((name, type_code(qtype), CLASS_IN))
    if edns:
        m.additional.append(RR('', 41, edns, 0x8000 if do else 0, None, b''))
    return m


# ---------------------------------------------------------------------------
# Asking
# ---------------------------------------------------------------------------
def split_hostport(text, port=53):
    """'192.0.2.1', '192.0.2.1:5353', '[2001:db8::1]:53', '2001:db8::1', 'ns.example.com:53'."""
    s = str(text or '').strip()
    m = re.match(r'^\[([^\]]+)\](?::(\d+))?$', s)
    if m:
        return m.group(1), int(m.group(2) or port)
    if s.count(':') > 1:
        return s, port
    host, _, p = s.partition(':')
    return host, int(p) if p.isdigit() else port


def _family(host):
    try:
        return socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def send_udp(server, port, wire, timeout=3.0, match=None):
    fam = _family(server)
    s = socket.socket(fam, socket.SOCK_DGRAM)
    deadline = time.monotonic() + timeout
    try:
        s.connect((server, port))
        s.send(wire)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise DnsError('no answer from %s:%d' % (server, port))
            s.settimeout(left)
            try:
                got = s.recv(65535)
            except socket.timeout:
                raise DnsError('no answer from %s:%d' % (server, port))
            if match is None or match(got):
                return got
    finally:
        s.close()


def _recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsError('the connection closed after %d of %d bytes' % (len(buf), n))
        buf += chunk
    return buf


def send_tcp(server, port, wire, timeout=5.0):
    try:
        s = socket.create_connection((server, port), timeout=timeout)
    except OSError as e:
        raise DnsError('cannot connect to %s:%d over TCP: %s' % (server, port, e))
    try:
        s.settimeout(timeout)
        s.sendall(struct.pack('>H', len(wire)) + wire)
        n = struct.unpack('>H', _recv_exact(s, 2))[0]
        return _recv_exact(s, n)
    except socket.timeout:
        raise DnsError('no answer from %s:%d over TCP' % (server, port))
    except OSError as e:
        if isinstance(e, DnsError):
            raise
        raise DnsError('%s:%d over TCP: %s' % (server, port, e))
    finally:
        s.close()


def exchange(server, wire, port=53, timeout=3.0, tcp=False):
    """A message sent, the answer read (as bytes): UDP and, when the answer is
    cut short (TC), again over TCP."""
    ident = wire[:2]
    q = parse(wire)
    qkey = [(norm(n), t, c) for n, t, c in q.question]

    def mine(got):
        if len(got) < 12 or got[:2] != ident:
            return False
        try:
            a = parse(got)
        except FormErr:
            return len(got) >= 12 and got[:2] == ident        # FORMERR answers may be short
        return [(norm(n), t, c) for n, t, c in a.question] in (qkey, [])
    if not tcp:
        got = send_udp(server, port, wire, timeout, mine)
        if not (struct.unpack('>H', got[2:4])[0] & 0x0200):
            return got
    got = send_tcp(server, port, wire, max(timeout, 3.0))
    if got[:2] != ident:
        raise DnsError('%s answered another question over TCP' % server)
    return got


def query(server, name, qtype, port=53, timeout=3.0, rd=True, tcp=False, edns=1232):
    """One question to one server: the answer, parsed."""
    q = make_query(name, qtype, rd=rd, edns=edns)
    data = exchange(server, q.to_wire(), port=port, timeout=timeout, tcp=tcp)
    try:
        m = parse(data)
    except FormErr as e:
        raise DnsError('%s sent an answer that cannot be read: %s' % (server, e))
    if m.rcode == FORMERR and edns:
        # an old server that does not know EDNS: asked again without it
        return query(server, name, qtype, port, timeout, rd, tcp, edns=0)
    return m


# ---------------------------------------------------------------------------
# TSIG (RFC 8945)
# ---------------------------------------------------------------------------
TSIG_ALGS = {
    'hmac-md5': ('hmac-md5.sig-alg.reg.int', hashlib.md5),
    'hmac-sha1': ('hmac-sha1', hashlib.sha1),
    'hmac-sha224': ('hmac-sha224', hashlib.sha224),
    'hmac-sha256': ('hmac-sha256', hashlib.sha256),
    'hmac-sha384': ('hmac-sha384', hashlib.sha384),
    'hmac-sha512': ('hmac-sha512', hashlib.sha512),
}
_ALG_BY_WIRE = {v[0]: k for k, v in TSIG_ALGS.items()}


def tsig_secret(secret):
    """The key as BIND writes it (base64) - bytes."""
    if isinstance(secret, bytes):
        return secret
    s = re.sub(r'\s+', '', str(secret or ''))
    try:
        return base64.b64decode(s + '=' * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('the TSIG secret is not base64 (as tsig-keygen writes it)')


def _tsig_vars(keyname, alg_wire, time_signed, fudge, error=0, other=b''):
    return (name_to_wire(keyname, lower=True) + struct.pack('>HI', CLASS_ANY, 0) +
            name_to_wire(alg_wire, lower=True) +
            struct.pack('>HIH', (time_signed >> 32) & 0xFFFF, time_signed & 0xFFFFFFFF, fudge) +
            struct.pack('>HH', error, len(other)) + other)


def tsig_sign(wire, keyname, secret, alg='hmac-sha256', time_signed=None, fudge=300,
              request_mac=b''):
    """(the message with a TSIG record added, its MAC). `request_mac` for
    signing an answer to a signed request."""
    alg = alg.lower().rstrip('.')
    alg = _ALG_BY_WIRE.get(alg, alg)
    if alg not in TSIG_ALGS:
        raise ValueError('a TSIG algorithm acme does not know: %s' % alg)
    alg_wire, h = TSIG_ALGS[alg]
    key = tsig_secret(secret)
    ts = int(time.time() if time_signed is None else time_signed)
    signed = b''
    if request_mac:
        signed += struct.pack('>H', len(request_mac)) + request_mac
    signed += wire + _tsig_vars(keyname, alg_wire, ts, fudge)
    mac = hmac.new(key, signed, h).digest()
    orig_id = struct.unpack('>H', wire[:2])[0]
    rdata = (name_to_wire(alg_wire, lower=True) +
             struct.pack('>HIH', (ts >> 32) & 0xFFFF, ts & 0xFFFFFFFF, fudge) +
             struct.pack('>H', len(mac)) + mac + struct.pack('>HHH', orig_id, 0, 0))
    rr = name_to_wire(keyname, lower=True) + struct.pack('>HHIH', 250, CLASS_ANY, 0,
                                                         len(rdata)) + rdata
    ar = struct.unpack('>H', wire[10:12])[0]
    out = wire[:10] + struct.pack('>H', ar + 1) + wire[12:] + rr
    return out, mac


def tsig_read(wire):
    """The TSIG of a message: dict (keyname, alg, time, fudge, mac, orig_id,
    error, other, start) or None. It must be the last record."""
    m = parse(wire)
    if not m.additional or m.additional[-1].rtype != 250:
        return None
    r = m.additional[-1]
    rd_at = len(wire) - len(r.raw)
    alg, p = read_name(wire, rd_at)
    hi, lo, fudge, size = struct.unpack('>HIHH', wire[p:p + 10])
    p += 10
    mac = wire[p:p + size]
    p += size
    orig_id, error, olen = struct.unpack('>HHH', wire[p:p + 6])
    other = wire[p + 6:p + 6 + olen]
    return {'keyname': norm(r.name), 'alg': norm(alg), 'time': (hi << 32) | lo, 'fudge': fudge,
            'mac': mac, 'orig_id': orig_id, 'error': error, 'other': other, 'start': r.offset}


def tsig_verify(wire, keyname, secret, request_mac=b'', now=None):
    """Checks the TSIG of a message (an answer to a request whose MAC was
    `request_mac`, or a request). Returns the dict of tsig_read; raises
    ValueError saying what is wrong."""
    t = tsig_read(wire)
    if t is None:
        raise ValueError('the message is not signed')
    if t['keyname'] != norm(keyname):
        raise ValueError('signed with another key (%s)' % t['keyname'])
    alg = _ALG_BY_WIRE.get(t['alg'], t['alg'])
    if alg not in TSIG_ALGS:
        raise ValueError('signed with an algorithm acme does not know (%s)' % t['alg'])
    if t['error']:
        raise ValueError('the server said %s' % TSIG_ERRORS.get(t['error'], t['error']))
    body = wire[:t['start']]
    ar = struct.unpack('>H', body[10:12])[0]
    body = struct.pack('>H', t['orig_id']) + body[2:10] + struct.pack('>H', ar - 1) + body[12:]
    signed = b''
    if request_mac:
        signed += struct.pack('>H', len(request_mac)) + request_mac
    signed += body + _tsig_vars(keyname, TSIG_ALGS[alg][0], t['time'], t['fudge'], t['error'],
                                t['other'])
    want = hmac.new(tsig_secret(secret), signed, TSIG_ALGS[alg][1]).digest()
    if not hmac.compare_digest(want, t['mac']):
        raise ValueError('the signature does not match (BADSIG)')
    now = time.time() if now is None else now
    if abs(now - t['time']) > t['fudge']:
        raise ValueError('signed %d s away from this clock (BADTIME)' % int(now - t['time']))
    return t


# ---------------------------------------------------------------------------
# RFC 2136 UPDATE
# ---------------------------------------------------------------------------
def make_update(zone, add=(), delete=(), prereq=(), ident=None):
    """add: [(name, type, ttl, text)]; delete: [(name, type, text or None)] -
    None takes the whole RRset away; prereq: [(name, type)] "RRset exists"."""
    m = Message(secrets.randbits(16) if ident is None else ident, OP_UPDATE << 11)
    m.question.append((norm(zone), 6, CLASS_IN))                  # the zone section
    for name, rtype in prereq:
        m.answer.append(RR(name, rtype, CLASS_ANY, 0, None, b''))
    for name, rtype, text in delete:
        if text is None:
            m.authority.append(RR(name, rtype, CLASS_ANY, 0, None, b''))
        else:
            m.authority.append(RR(name, rtype, CLASS_NONE, 0, text))
    for name, rtype, ttl, text in add:
        m.authority.append(RR(name, rtype, CLASS_IN, int(ttl), text))
    return m


def send_update(server, msg, port=53, keyname=None, secret=None, alg='hmac-sha256',
                timeout=5.0, tcp=True):
    """An UPDATE sent (signed when a key is given): the answer parsed; the
    answer's signature checked. tcp: UPDATE over TCP (what nsupdate does
    for anything but tiny messages; never cut short)."""
    wire = msg.to_wire()
    mac = b''
    if keyname:
        wire, mac = tsig_sign(wire, keyname, secret, alg)
    data = exchange(server, wire, port=port, timeout=timeout, tcp=tcp)
    ans = parse(data)
    t = tsig_read(data) if ans.additional and ans.additional[-1].rtype == 250 else None
    if keyname and t is None and getattr(ans, 'rcode', 0) == 0:
        # signed, it must come back signed (1.0.51): an answer without a signature was taken
        raise DnsError('the answer to the signed update is not signed (TSIG %s) - not taken'
                       % keyname)
    if keyname and t is not None:
        if t['error']:
            raise DnsError('the server said %s: the TSIG key %s (or its algorithm %s) is not '
                           'the one it has' % (TSIG_ERRORS.get(t['error'], t['error']), keyname,
                                               alg))
        try:
            tsig_verify(data, keyname, secret, request_mac=mac)
        except ValueError as e:
            raise DnsError('the answer\'s signature does not hold: %s' % e)
    return ans


# ---------------------------------------------------------------------------
# What the DNS-01 modules look up
# ---------------------------------------------------------------------------
def system_resolvers():
    out = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == 'nameserver':
                    out.append(bits[1].split('%')[0])
    except OSError:
        pass
    return out or ['127.0.0.1']


def ask_any(servers, name, qtype, timeout=3.0, rd=True, port=53):
    """The first usable answer of several servers (NOERROR or NXDOMAIN). A set
    of Settings → DNS (acmelib/certs/dnssets.Resolver) asks its own way."""
    if hasattr(servers, 'ask_any'):
        return servers.ask_any(name, qtype, timeout=timeout, rd=rd, port=port)
    last = None
    for srv in servers:
        host, p = split_hostport(srv, port)
        try:
            m = query(host, name, qtype, port=p, timeout=timeout, rd=rd)
        except (DnsError, OSError, FormErr) as e:
            last = e
            continue
        if m.rcode in (NOERROR, NXDOMAIN):
            return m
        last = DnsError('%s said %s' % (srv, RCODES.get(m.rcode, m.rcode)))
    raise DnsError('no DNS server answered for %s (%s)' % (name, last or 'none asked'))


def follow_cname(name, resolvers, timeout=3.0, limit=8):
    """Where a name ends up after its CNAMEs ([name, target, ...])."""
    chain = [norm(name)]
    for _ in range(limit):
        m = ask_any(resolvers, chain[-1], 5, timeout)
        got = [norm(r.text) for r in m.answer if r.rtype == 5 and norm(r.name) == chain[-1]]
        if not got:
            break
        if got[0] in chain:
            raise DnsError('a CNAME loop: %s' % ' -> '.join(chain + got[:1]))
        chain.append(got[0])
    return chain


def find_zone(name, resolvers, timeout=3.0, rd=True):
    """The zone a name is in, by its SOA: the SOA in the answer (the name is
    the apex) or in the authority section (a name inside), else one label
    less and asked again."""
    name = norm(name)
    labels = name.split('.')
    for i in range(len(labels)):
        cand = '.'.join(labels[i:])
        m = ask_any(resolvers, cand, 6, timeout, rd=rd)
        for r in m.answer:
            if r.rtype == 6 and in_zone(name, r.name):
                return norm(r.name)
        for r in m.authority:
            if r.rtype == 6 and in_zone(name, r.name):
                return norm(r.name)
    raise DnsError('no zone found for %s' % name)


def addresses(host, resolvers, timeout=3.0):
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    out = []
    for qt in (1, 28):
        try:
            m = ask_any(resolvers, host, qt, timeout)
        except DnsError:
            continue
        out += [r.text for r in m.answer if r.rtype == qt]
    return out


def zone_servers(zone, resolvers, timeout=3.0):
    """[(ns name, [addresses])] of a zone, as its parent and resolvers say."""
    m = ask_any(resolvers, zone, 2, timeout)
    names = sorted({norm(r.text) for r in m.answer if r.rtype == 2})
    out = []
    for ns in names:
        out.append((ns, addresses(ns, resolvers, timeout)))
    return out


def txt_at(server, name, port=53, timeout=3.0, rd=False):
    """The TXT values one server has for a name (asked straight, no recursion
    by default: what the authoritative server itself holds)."""
    m = query(server, name, 16, port=port, timeout=timeout, rd=rd)
    if m.rcode not in (NOERROR, NXDOMAIN):
        raise DnsError('%s said %s' % (server, RCODES.get(m.rcode, m.rcode)))
    return [r.text for r in m.answer if r.rtype == 16 and norm(r.name) == norm(name)]


def own_server_address(cfg, answering=None):
    """Where acme's own DNS server can be asked from this machine. With the
    server answering on the VIP address only (dns_expose 'vip'), the VIP - it
    does not listen on this machine's own addresses then, 127.0.0.1 neither;
    `answering` is dnsserver.server_info()['answering'] ([the VIP] there)."""
    port = int(cfg.get('dns_port') or 53)
    if str(cfg.get('dns_expose') or 'both').strip().lower() == 'vip' and answering:
        return str(answering[0]), port
    listen = [x.strip() for x in str(cfg.get('dns_listen') or '0.0.0.0,::').split(',') if x.strip()]
    for a in listen:
        if a in ('0.0.0.0', '127.0.0.1'):
            return '127.0.0.1', port
        if a in ('::', '::1'):
            return '::1', port
    return (listen[0] if listen else '127.0.0.1'), port


def random_label(n=10):
    return 'acme-' + binascii.hexlify(os.urandom(n // 2)).decode()


# ---------------------------------------------------------------------------
# The domain a name belongs to, when DNS cannot say (no SOA found)
# ---------------------------------------------------------------------------
# A small public-suffix list: the suffixes under which people register names
# (two labels or more). Anything else: the last two labels.
PUBLIC_SUFFIXES = frozenset("""
co.uk org.uk me.uk ltd.uk plc.uk net.uk ac.uk gov.uk sch.uk nhs.uk
com.au net.au org.au edu.au gov.au asn.au id.au
co.nz net.nz org.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp
co.za org.za net.za gov.za
com.br net.br org.br gov.br
com.cn net.cn org.cn gov.cn
com.tr net.tr org.tr gen.tr
com.mx org.mx gob.mx
com.ar com.co com.pe com.ve com.ec com.uy
co.in net.in org.in firm.in gen.in ind.in
co.il org.il ac.il
co.kr or.kr
com.sg com.my com.hk com.tw com.ua com.pl net.pl org.pl
com.ru net.ru org.ru
co.at or.at gv.at
com.es nom.es org.es
com.pt com.gr com.cy
co.hu
eu.org
""".split())


def registrable(name):
    """The registrable domain of a name by the list above: shop.firma.co.uk ->
    firma.co.uk, www.firma.cz -> firma.cz, *.firma.sk -> firma.sk."""
    n = norm(name)
    while n.startswith('*.'):
        n = n[2:]
    labels = [x for x in n.split('.') if x]
    if len(labels) <= 2:
        return '.'.join(labels)
    if '.'.join(labels[-2:]) in PUBLIC_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


# ---------------------------------------------------------------------------
# Settings → DNS: which servers a function asks (acmelib/certs/dnssets.py)
# ---------------------------------------------------------------------------
def resolver(purpose, given=(), ctx=None):
    """The resolvers a module asks for one function of acme ('validation',
    'public'): its own field (`given`) when it says something, else the set
    chosen under Settings → DNS - else, without the certificate manager, as
    before (the system's; the public resolvers for 'public')."""
    try:
        from acmelib.certs import dnssets
    except Exception:                                   # noqa: BLE001
        given = [str(x).strip() for x in (given or []) if str(x).strip()]
        return given or (list(PUBLIC_RESOLVERS) if purpose == 'public' else system_resolvers())
    return dnssets.for_module(purpose, given, ctx)


def ask_server(servers, srv, name, qtype, timeout=3.0, rd=True):
    """One server of `servers` asked by itself, the way its set asks it."""
    if hasattr(servers, 'ask_one'):
        return servers.ask_one(srv, name, qtype, timeout=timeout, rd=rd)
    host, port = split_hostport(srv)
    return query(host, name, qtype, port=port, rd=rd, timeout=timeout)


def servers_words(servers):
    """How a guide says what it asked: "'Public' (1.1.1.1, 8.8.8.8)", or the list."""
    if hasattr(servers, 'label'):
        return servers.label()
    return ', '.join(servers or [])
