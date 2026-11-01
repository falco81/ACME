# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# RADIUS, the protocol (RFC 2865, 2866, 2869, 3579, 5997)
# ---------------------------------------------------------------------------
# A packet is a code, an identifier, a length, sixteen bytes of authenticator
# and a run of attributes, each a type, a length and a value. The dictionary
# below names the attributes a VPN concentrator and a token server actually
# use; anything else is kept and written down by its number, the way
# FreeRADIUS writes an attribute it has no name for.

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE = 4, 5
ACCESS_CHALLENGE, STATUS_SERVER = 11, 12
CODE_WORDS = {1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject',
              4: 'Accounting-Request', 5: 'Accounting-Response', 11: 'Access-Challenge',
              12: 'Status-Server'}

# number: (name, type) - types: string, octets, integer, ipaddr, date, ipv6addr
RADIUS_ATTRS = {
    1: ('User-Name', 'string'), 2: ('User-Password', 'octets'),
    3: ('CHAP-Password', 'octets'), 4: ('NAS-IP-Address', 'ipaddr'),
    5: ('NAS-Port', 'integer'), 6: ('Service-Type', 'integer'),
    7: ('Framed-Protocol', 'integer'), 8: ('Framed-IP-Address', 'ipaddr'),
    9: ('Framed-IP-Netmask', 'ipaddr'), 10: ('Framed-Routing', 'integer'),
    11: ('Filter-Id', 'string'), 12: ('Framed-MTU', 'integer'),
    13: ('Framed-Compression', 'integer'), 14: ('Login-IP-Host', 'ipaddr'),
    18: ('Reply-Message', 'string'), 22: ('Framed-Route', 'string'),
    24: ('State', 'octets'), 25: ('Class', 'string'), 26: ('Vendor-Specific', 'octets'),
    27: ('Session-Timeout', 'integer'), 28: ('Idle-Timeout', 'integer'),
    29: ('Termination-Action', 'integer'), 30: ('Called-Station-Id', 'string'),
    31: ('Calling-Station-Id', 'string'), 32: ('NAS-Identifier', 'string'),
    33: ('Proxy-State', 'octets'), 40: ('Acct-Status-Type', 'integer'),
    41: ('Acct-Delay-Time', 'integer'), 42: ('Acct-Input-Octets', 'integer'),
    43: ('Acct-Output-Octets', 'integer'), 44: ('Acct-Session-Id', 'string'),
    45: ('Acct-Authentic', 'integer'), 46: ('Acct-Session-Time', 'integer'),
    47: ('Acct-Input-Packets', 'integer'), 48: ('Acct-Output-Packets', 'integer'),
    49: ('Acct-Terminate-Cause', 'integer'), 50: ('Acct-Multi-Session-Id', 'string'),
    52: ('Acct-Input-Gigawords', 'integer'), 53: ('Acct-Output-Gigawords', 'integer'),
    55: ('Event-Timestamp', 'date'), 60: ('CHAP-Challenge', 'octets'),
    61: ('NAS-Port-Type', 'integer'), 62: ('Port-Limit', 'integer'),
    64: ('Tunnel-Type', 'tagint'), 65: ('Tunnel-Medium-Type', 'tagint'),
    66: ('Tunnel-Client-Endpoint', 'tagstr'), 67: ('Tunnel-Server-Endpoint', 'tagstr'),
    77: ('Connect-Info', 'string'), 79: ('EAP-Message', 'octets'),
    80: ('Message-Authenticator', 'octets'), 81: ('Tunnel-Private-Group-Id', 'tagstr'),
    85: ('Acct-Interim-Interval', 'integer'), 87: ('NAS-Port-Id', 'string'),
    88: ('Framed-Pool', 'string'), 95: ('NAS-IPv6-Address', 'ipv6addr'),
    101: ('Error-Cause', 'integer'),
}
RADIUS_NUMBERS = {v[0].lower(): (k, v[1]) for k, v in RADIUS_ATTRS.items()}

# The values worth naming. Everything else is written as its number.
RADIUS_VALUES = {
    'Service-Type': {1: 'Login-User', 2: 'Framed-User', 5: 'Outbound-User',
                     6: 'Administrative-User', 7: 'NAS-Prompt-User', 8: 'Authenticate-Only',
                     10: 'Call-Check'},
    'NAS-Port-Type': {0: 'Async', 5: 'Virtual', 15: 'Ethernet', 19: 'Wireless-802.11'},
    'Acct-Status-Type': {1: 'Start', 2: 'Stop', 3: 'Interim-Update', 7: 'Accounting-On',
                         8: 'Accounting-Off'},
    'Framed-Protocol': {1: 'PPP', 2: 'SLIP'},
    'Tunnel-Type': {3: 'L2TP', 13: 'VLAN'},
    'Tunnel-Medium-Type': {1: 'IPv4', 6: '802'},
    'Acct-Authentic': {1: 'RADIUS', 2: 'Local', 3: 'Remote'},
    'Acct-Terminate-Cause': {1: 'User-Request', 2: 'Lost-Carrier', 4: 'Idle-Timeout',
                             5: 'Session-Timeout', 6: 'Admin-Reset', 10: 'NAS-Request'},
}

# Vendor attributes: (vendor, number) -> (name, type).
VENDORS = {9: 'Cisco', 311: 'Microsoft', 3076: 'Cisco-VPN3000'}
VSA_ATTRS = {
    (9, 1): ('Cisco-AVPair', 'string'),
    (3076, 25): ('ASA-Group-Policy', 'string'),
    (3076, 85): ('ASA-Tunnel-Group-Lock', 'string'),
    (3076, 146): ('ASA-TunnelGroupName', 'string'),
    (3076, 150): ('ASA-ClientType', 'integer'),
    (3076, 151): ('ASA-SessionType', 'integer'),
    (3076, 152): ('ASA-SessionSubtype', 'integer'),
}
VSA_NUMBERS = {v[0].lower(): (k, v[1]) for k, v in VSA_ATTRS.items()}

# What may be put into an answer by name, with how it is written. Listed so
# that a realm's reply lines are checked when they are saved rather than when
# somebody first signs in.
REPLY_ATTRS = ('Reply-Message', 'Class', 'Filter-Id', 'Session-Timeout', 'Idle-Timeout',
               'Service-Type', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Pool',
               'Acct-Interim-Interval', 'Tunnel-Type', 'Tunnel-Medium-Type',
               'Tunnel-Private-Group-Id', 'Cisco-AVPair', 'ASA-Group-Policy',
               'ASA-Tunnel-Group-Lock')


class RadiusError(ValueError):
    pass


def _value_words(name, kind, raw):
    """One attribute's value, as FreeRADIUS writes it in a detail file."""
    try:
        if kind == 'string':
            return raw.decode('utf-8', 'replace')
        if kind in ('integer', 'date'):
            if len(raw) != 4:
                return '0x' + raw.hex()
            n = struct.unpack('>I', raw)[0]
            return RADIUS_VALUES.get(name, {}).get(n, str(n))
        if kind == 'ipaddr':
            return socket.inet_ntoa(raw) if len(raw) == 4 else '0x' + raw.hex()
        if kind == 'ipv6addr':
            return socket.inet_ntop(socket.AF_INET6, raw) if len(raw) == 16 else '0x' + raw.hex()
        if kind == 'tagint':
            if len(raw) == 4:
                n = struct.unpack('>I', b'\x00' + raw[1:])[0]
                return RADIUS_VALUES.get(name, {}).get(n, str(n))
        if kind == 'tagstr':
            if raw and raw[0] < 0x20:
                raw = raw[1:]
            return raw.decode('utf-8', 'replace')
    except (ValueError, OSError, struct.error):
        pass
    return '0x' + raw.hex()


def _value_bytes(name, kind, value):
    text = str(value).strip()
    if kind == 'string':
        return text.encode('utf-8')
    if kind == 'integer' or kind == 'date':
        names = {v.lower(): k for k, v in RADIUS_VALUES.get(name, {}).items()}
        names.update(globals().get('RADIUS_VALUE_ALIASES', {}).get(name, {}))
        n = names.get(text.lower())
        if n is None:
            try:
                n = int(text)
            except ValueError:
                raise RadiusError('%s takes a number%s, not %r' % (
                    name, (' or one of ' + ', '.join(RADIUS_VALUES[name].values()))
                    if name in RADIUS_VALUES else '', text))
        return struct.pack('>I', n)
    if kind == 'ipaddr':
        try:
            return socket.inet_aton(str(ipaddress.IPv4Address(text)))
        except ValueError:
            raise RadiusError('%s takes an IPv4 address, not %r' % (name, text))
    if kind == 'tagint':
        names = {v.lower(): k for k, v in RADIUS_VALUES.get(name, {}).items()}
        names.update(globals().get('RADIUS_VALUE_ALIASES', {}).get(name, {}))
        n = names.get(text.lower())
        if n is None:
            try:
                n = int(text)
            except ValueError:
                raise RadiusError('%s takes a number, not %r' % (name, text))
        if not 0 <= n <= 0xFFFFFF:
            # Three bytes after the tag (1.0.59): 16777229 went out as 13.
            raise RadiusError('%s takes a number from 0 to 16777215, not %r' % (name, text))
        return b'\x00' + struct.pack('>I', n)[1:]
    if kind == 'tagstr':
        return text.encode('utf-8')
    if kind == 'octets':
        if text.lower().startswith('0x'):
            return bytes.fromhex(text[2:])
        return text.encode('utf-8')
    return text.encode('utf-8')


# Vendors whose attributes are not one byte of type and one of length, and
# attributes that are salted (1.0.59): by number they would go out wrong.
VSA_ODD_VENDORS = {24757: 'WiMAX', 429: 'USR', 4846: 'Lucent', 8164: 'Starent'}
VSA_SALTED = {(311, 16), (311, 17)}


def attr_bytes(name, value):
    """`Name = value` as the bytes of one attribute (a vendor one wrapped in
    Vendor-Specific)."""
    out = _attr_bytes(name, value)
    # An attribute is never empty (RFC 2865 5, 1.0.59): some NAS throw the
    # whole answer away for one.
    if (out[0] != 26 and len(out) <= 2) or (out[0] == 26 and len(out) <= 8):
        raise RadiusError('%s has no value: an attribute is never sent empty' % name)
    return out


def _attr_bytes(name, value):
    key = str(name).strip().lower()
    if key in RADIUS_NUMBERS:
        num, kind = RADIUS_NUMBERS[key]
        body = _value_bytes(RADIUS_ATTRS[num][0], kind, value)
        if len(body) > 253:
            raise RadiusError('%s is longer than one attribute may be (253 bytes)' % name)
        return bytes([num, len(body) + 2]) + body
    if key in VSA_NUMBERS:
        (vendor, num), kind = VSA_NUMBERS[key]
        body = _value_bytes(VSA_ATTRS[(vendor, num)][0], kind, value)
        if len(body) > 247:
            raise RadiusError('%s is longer than one attribute may be' % name)
        sub = bytes([num, len(body) + 2]) + body
        inner = struct.pack('>I', vendor) + sub
        return bytes([26, len(inner) + 2]) + inner
    # Any other vendor's attribute, by its numbers (1.0.57): a string, or
    # 0x... bytes.
    m = re.match(r'^vendor-(\d{1,10})-attr-(\d{1,3})\Z', key)
    if m and 0 < int(m.group(1)) < 2 ** 32 and 0 < int(m.group(2)) < 256:
        if int(m.group(1)) in VSA_ODD_VENDORS:
            raise RadiusError('%s: %s attributes are not laid out as one byte of type and one of '
                              'length - this server cannot send them by number'
                              % (name, VSA_ODD_VENDORS[int(m.group(1))]))
        if (int(m.group(1)), int(m.group(2))) in VSA_SALTED:
            raise RadiusError('%s is a salted key (MS-MPPE): it cannot be sent by number' % name)
        body = _value_bytes(name, 'octets', value)
        if len(body) > 247:
            raise RadiusError('%s is longer than one attribute may be' % name)
        inner = struct.pack('>I', int(m.group(1))) + bytes([int(m.group(2)), len(body) + 2]) + body
        return bytes([26, len(inner) + 2]) + inner
    raise RadiusError('%s is not an attribute this server knows how to send. It knows: %s'
                      % (name, ', '.join(REPLY_ATTRS)))


def reply_lines(text):
    """A realm's or a group's reply, `Name = value` a line, as pairs. Raises
    RadiusError naming the line that will not do."""
    out = []
    for n, line in enumerate(str(text or '').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([A-Za-z0-9-]+)\s*:?\+?=\s*(.*)\Z', line)
        if not m:
            raise RadiusError('line %d, %r: write it as Name = value' % (n, line[:60]))
        value = m.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        # Only what an answer may carry (1.0.33): not a Message-Authenticator,
        # a User-Password or a State written into a realm's reply.
        if m.group(1) not in REPLY_ATTRS and not re.match(r'^Vendor-\d{1,10}-Attr-\d{1,3}\Z',
                                                          m.group(1), re.I):
            raise RadiusError('line %d: %s is not something an answer carries here - one of %s'
                              % (n, m.group(1), ', '.join(REPLY_ATTRS)))
        try:
            attr_bytes(m.group(1), value)
        except (struct.error, ValueError) as e:
            raise RadiusError('line %d: %s' % (n, e))
        out.append((m.group(1), value))
    return out


class Packet(object):
    """One RADIUS packet, read or being made."""

    def __init__(self, code=0, ident=0, authenticator=b'\x00' * 16, raw=b''):
        self.code = code
        self.ident = ident
        self.authenticator = authenticator
        self.attrs = []                       # [(number, bytes)] as they came
        self.raw = raw

    @classmethod
    def parse(cls, data):
        if len(data) < 20:
            raise RadiusError('shorter than a RADIUS packet can be')
        code, ident, length = struct.unpack('>BBH', data[:4])
        if length < 20 or length > 4096 or length > len(data):
            raise RadiusError('the length it gives (%d) is not the length it has' % length)
        pkt = cls(code, ident, data[4:20], data[:length])
        at = 20
        while at < length:
            if at + 2 > length:
                raise RadiusError('an attribute is cut off')
            kind, size = data[at], data[at + 1]
            if size < 2 or at + size > length:
                raise RadiusError('an attribute says it is %d bytes long' % size)
            pkt.attrs.append((kind, data[at + 2:at + size]))
            at += size
        return pkt

    def get(self, number):
        for k, v in self.attrs:
            if k == number:
                return v
        return None

    def all(self, number):
        return [v for k, v in self.attrs if k == number]

    def text(self, number):
        got = self.get(number)
        return got.decode('utf-8', 'replace') if got is not None else ''

    def vsa(self):
        """[(vendor, number, bytes)] out of every Vendor-Specific."""
        out = []
        for raw in self.all(26):
            if len(raw) < 6:
                continue
            vendor = struct.unpack('>I', raw[:4])[0]
            at = 4
            while at + 2 <= len(raw):
                num, size = raw[at], raw[at + 1]
                if size < 2 or at + size > len(raw):
                    break
                out.append((vendor, num, raw[at + 2:at + size]))
                at += size
        return out

    def words(self, secret=None):
        """Every attribute as (Name, value), in order, the way FreeRADIUS
        writes them in a detail file. Passwords are never in it."""
        out = []
        for num, raw in self.attrs:
            if num == 26:
                continue
            name, kind = RADIUS_ATTRS.get(num, ('Attr-%d' % num, 'octets'))
            # Passwords, CHAP, EAP and Tunnel-Password: never written down
            # (1.0.57) - an MS-CHAPv2 or EAP exchange in the log is enough to
            # crack the password offline.
            if num in (2, 3, 60, 69, 79):
                out.append((name, '<suppressed>'))
                continue
            if num == 80:
                out.append((name, '0x' + raw.hex()))
                continue
            out.append((name, _value_words(name, kind, raw)))
        for vendor, num, raw in self.vsa():
            name, kind = VSA_ATTRS.get((vendor, num), (None, 'octets'))
            if vendor == 311 and num in (1, 2, 11, 16, 17, 25, 26):
                # Microsoft's MS-CHAP challenge, responses and MPPE keys.
                out.append((name or 'Vendor-311-Attr-%d' % num, '<suppressed>'))
                continue
            if name and (vendor, num) != (3076, 146):
                out.append((name, _value_words(name, kind, raw)))
            else:
                # As FreeRADIUS 2 writes an attribute it has no name for -
                # which is also how isemon reads the ASA's tunnel group.
                out.append(('Vendor-%d-Attr-%d' % (vendor, num), '0x' + raw.hex()))
        return out

    # ---- the passwords and the signatures ------------------------------------
    def password(self, secret):
        """User-Password, undone (RFC 2865 5.2)."""
        raw = self.get(2)
        if raw is None:
            return None
        if len(raw) % 16 or not raw:
            raise RadiusError('the User-Password is not a multiple of sixteen bytes')
        out = b''
        last = self.authenticator
        for at in range(0, len(raw), 16):
            block = raw[at:at + 16]
            pad = hashlib.md5(secret + last).digest()
            out += bytes(a ^ b for a, b in zip(block, pad))
            last = block
        return out.rstrip(b'\x00').decode('utf-8', 'replace')

    def message_authenticator_ok(self, secret, zero_authenticator=False):
        """True where it is right, False where it is wrong, None where there is
        none. Over the packet with the attribute's value as sixteen noughts -
        and, for an Accounting-Request (RFC 5080 2.2.4), the Request
        Authenticator as noughts too."""
        at = 20
        data = bytearray(self.raw)
        if zero_authenticator:
            data[4:20] = b'\x00' * 16
        found = None
        while at < len(data):
            kind, size = data[at], data[at + 1]
            if kind == 80:
                # One, of the one right length - anything else is wrong, not
                # missing (1.0.33): a mangled one was taken for none at all.
                if size != 18 or found is not None:
                    return False
                found = bytes(data[at + 2:at + 18])
                data[at + 2:at + 18] = b'\x00' * 16
            at += size
        if found is None:
            return None
        want = hmac.new(secret, bytes(data), hashlib.md5).digest()
        return hmac.compare_digest(found, want)

    def accounting_ok(self, secret):
        """An Accounting-Request's authenticator (RFC 2866 3)."""
        data = self.raw[:4] + b'\x00' * 16 + self.raw[20:]
        return hmac.compare_digest(hashlib.md5(data + secret).digest(), self.authenticator)


def build_reply(request, code, pairs, secret, with_ma=True):
    """An answer to `request`: its identifier, the attributes in `pairs`
    (already bytes), a Message-Authenticator where asked for (RFC 3579 3.2),
    and the Response Authenticator over all of it."""
    body = b''.join(pairs)
    # Every Proxy-State of the request back, unchanged and in order (RFC 2865
    # 5.33; 1.0.44): a proxy in between throws away an answer without it.
    for ps in (request.all(33) or []):
        body += bytes([33, len(ps) + 2]) + bytes(ps)
    if with_ma:
        # First, as the BlastRADIUS advice has it (1.0.33).
        body = bytes([80, 18]) + b'\x00' * 16 + body
    length = 20 + len(body)
    if length > 4096:
        raise RadiusError('the answer is longer than a RADIUS packet may be')
    head = struct.pack('>BBH', code, request.ident, length)
    if with_ma:
        ma = hmac.new(secret, head + request.authenticator + body, hashlib.md5).digest()
        body = body[:2] + ma + body[18:]
    auth = hashlib.md5(head + request.authenticator + body + secret).digest()
    return head + auth + body


def build_request(code, ident, pairs, secret, password=None, with_ma=True):
    """A request, as a client sends one - for `acme --radtest` and the test
    page. `password` goes in as User-Password, hidden the RFC 2865 way."""
    authenticator = secrets.token_bytes(16) if code != ACCOUNTING_REQUEST else b'\x00' * 16
    body = b''.join(pairs)
    if password is not None:
        pw = str(password).encode('utf-8')
        if len(pw) > 128:
            # RFC 2865 5.2 (1.0.59): past 128 bytes it was out of the rules,
            # past 240 the attribute's length broke.
            raise RadiusError('the password is longer than RADIUS carries (128 bytes)')
        pw += b'\x00' * ((16 - len(pw) % 16) % 16 or (16 if not pw else 0))
        out, last = b'', authenticator
        for at in range(0, len(pw), 16):
            pad = hashlib.md5(secret + last).digest()
            block = bytes(a ^ b for a, b in zip(pw[at:at + 16], pad))
            out += block
            last = block
        body += bytes([2, len(out) + 2]) + out
    if with_ma and code in (ACCESS_REQUEST, STATUS_SERVER):
        body += bytes([80, 18]) + b'\x00' * 16
    head = struct.pack('>BBH', code, ident, 20 + len(body))
    if code == ACCOUNTING_REQUEST:
        authenticator = hashlib.md5(head + b'\x00' * 16 + body + secret).digest()
    elif with_ma and code in (ACCESS_REQUEST, STATUS_SERVER):
        ma = hmac.new(secret, head + authenticator + body, hashlib.md5).digest()
        body = body[:-16] + ma
    return head + authenticator + body, authenticator


def reply_ok(reply, request_auth, secret):
    """Whether an answer really came from a server holding the secret."""
    if len(reply) < 20:
        return False
    # Up to the length the header says (1.0.59), as RFC 2865 3 reads it:
    # what pads the datagram after it is not the answer.
    size = struct.unpack('>H', reply[2:4])[0]
    if size < 20 or size > len(reply):
        return False
    reply = reply[:size]
    want = hashlib.md5(reply[:4] + request_auth + reply[20:] + secret).digest()
    if not hmac.compare_digest(want, reply[4:20]):
        return False
    # Its Message-Authenticator, where it has one, is right too (1.0.59) -
    # over the answer with the request's authenticator in its place.
    try:
        pkt = Packet.parse(reply[:4] + request_auth + reply[20:])
    except Exception:                                   # noqa: BLE001 - malformed
        return False
    return pkt.message_authenticator_ok(secret) is not False


def radius_ask(server, port, secret, user, password, nas_ip='127.0.0.1', timeout=5.0,
               tries=2, extra=(), code=ACCESS_REQUEST):
    """Ask a RADIUS server, the way radtest does. Returns (code, [(Name,
    value)], took_ms) or raises RadiusError."""
    secret_b = str(secret).encode('utf-8')
    pairs = []
    if user is not None:
        pairs.append(attr_bytes('User-Name', user))
    pairs.append(bytes([4, 6]) + socket.inet_aton(nas_ip))
    pairs.append(bytes([5, 6]) + struct.pack('>I', 0))
    for name, value in extra:
        pairs.append(attr_bytes(name, value))
    ident = secrets.randbelow(256)
    data, auth = build_request(code, ident, pairs, secret_b,
                               password=password if code == ACCESS_REQUEST else None)
    family = socket.AF_INET6 if ':' in str(server) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout))
    began = time.time()
    try:
        bad = False
        for _ in range(max(1, int(tries))):
            sock.sendto(data, (server, int(port)))
            # One deadline per try (1.0.57): a stream of other packets reset
            # the timeout on every one and the wait never ended; a forged
            # answer is skipped, not taken for the server's.
            until = time.time() + float(timeout)
            reply = None
            while time.time() < until:
                sock.settimeout(max(0.05, until - time.time()))
                try:
                    got, src = sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(got) < 20 or got[1] != ident or got[0] not in (
                        ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE, ACCOUNTING_RESPONSE):
                    continue
                if not reply_ok(got, auth, secret_b):
                    bad = True
                    continue
                reply = got
                break
            if reply is None:
                continue
            pkt = Packet.parse(reply)
            return pkt.code, pkt.words(), int((time.time() - began) * 1000)
        if bad:
            raise RadiusError('an answer came, and it was not signed with that secret')
        raise RadiusError('no answer from %s:%s in %d tries of %.0f s - wrong secret, a '
                          'firewall, or this address is not one of its clients'
                          % (server, port, tries, timeout))
    finally:
        sock.close()


