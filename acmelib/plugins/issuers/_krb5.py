# -*- coding: utf-8 -*-
"""
A small Kerberos 5 client (RFC 4120) for the sources that sign in to Windows
with it (issuers/ms_adcs_rpc.py): a ticket-granting ticket for a user and a
password (AS-REQ pre-authenticated with an encrypted timestamp), a service
ticket for the CA's name (TGS-REQ), and the AP-REQ / AP-REP of a GSS-API
security context in the DCE style of MS-KILE / MS-RPCE, with RFC 4121 Wrap
tokens to seal what goes over it. Only the AES encryption types (RFC 3962:
aes256-cts-hmac-sha1-96 = 18, aes128-cts-hmac-sha1-96 = 17) - RC4 and DES
are not spoken.

Its crypto (RFC 3961 n-fold, DK, string-to-key with PBKDF2-HMAC-SHA1, AES
in CBC mode with ciphertext stealing, HMAC-SHA1-96) takes AES itself from
the optional package `cryptography` (python3-cryptography); without it,
need_crypto() says so in words. hashlib gives PBKDF2 and HMAC.

Written from the RFCs, checked against the test vectors of RFC 3961 (n-fold)
and RFC 3962 (string-to-key, AES-CTS) in test/test_ms_adcs_rpc.py.

Never logs, keeps or says the password or a key. Not a plugin (its name
starts with "_", the registry passes it by).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import time

try:                                    # optional: AES for the encryption types 17 and 18
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:                       # noqa: BLE001  (missing, or a broken install)
    Cipher = algorithms = modes = None

AES128, AES256 = 17, 18
KEY_SIZE = {AES128: 16, AES256: 32}
CKSUM_OF = {AES128: 15, AES256: 16}         # hmac-sha1-96-aes128 / -aes256
ETYPE_NAMES = {AES128: 'AES128', AES256: 'AES256', 23: 'RC4-HMAC', 3: 'DES', 1: 'DES',
               16: '3DES'}
NT_PRINCIPAL, NT_SRV_INST = 1, 2

# GSS-API flags of the checksum of an AP-REQ (RFC 4121 4.1.1.1; DCE style: MS-KILE 3.4.5.1)
GSS_C_DELEG, GSS_C_MUTUAL, GSS_C_REPLAY, GSS_C_SEQUENCE = 1, 2, 4, 8
GSS_C_CONF, GSS_C_INTEG, GSS_C_DCE_STYLE = 0x10, 0x20, 0x1000

# key usages (RFC 4120 7.5.1, RFC 4121 2)
KU_AS_REQ_PA_ENC_TS = 1
KU_AS_REP_ENC = 3
KU_TGS_REQ_CKSUM = 6
KU_TGS_REQ_AUTH = 7
KU_TGS_REP_ENC = 8
KU_AP_REQ_AUTH = 11
KU_AP_REP_ENC = 12
KG_ACCEPTOR_SEAL, KG_ACCEPTOR_SIGN, KG_INITIATOR_SEAL, KG_INITIATOR_SIGN = 22, 23, 24, 25

KRB5_OID = '1.2.840.113554.1.2.2'
MS_KRB5_OID = '1.2.840.48018.1.2.2'

# What the KDC's errors mean, in words one can act on (RFC 4120 7.5.9; MS-KILE 3.3.5.x)
ERRORS = {
    6: 'the domain does not know the user {user} (KDC_ERR_C_PRINCIPAL_UNKNOWN) - check the user '
       'and the domain (realm)',
    7: 'the domain knows no service {spn} (KDC_ERR_S_PRINCIPAL_UNKNOWN) - Kerberos needs the '
       'CA server\'s full DNS name as its computer account has it (an address, a short name or '
       'an alias does not do)',
    12: 'the domain\'s policy refuses the user (KDC_ERR_POLICY: logon hours, allowed '
        'workstations, a protected account)',
    14: 'the domain controller and acme share no encryption type (KDC_ERR_ETYPE_NOSUPP): acme '
        'speaks AES256 and AES128 only - the account needs AES keys (set its password once more '
        'on a domain at 2008 level or later; "This account supports Kerberos AES 256 bit '
        'encryption")',
    18: 'the account is disabled, locked out or expired (KDC_ERR_CLIENT_REVOKED)',
    23: 'the password of the account has expired (KDC_ERR_KEY_EXPIRED) - set a new one',
    24: 'the password is wrong (KDC_ERR_PREAUTH_FAILED)',
    31: 'the domain controller could not read what acme sent (KRB_AP_ERR_BAD_INTEGRITY) - '
        'the password is wrong',
    32: 'the ticket has expired (KRB_AP_ERR_TKT_EXPIRED)',
    34: 'the request was seen before (KRB_AP_ERR_REPEAT)',
    41: 'the CA server cannot read the ticket (KRB_AP_ERR_MODIFIED): the name {spn} belongs to '
        'another account than the CA server\'s - use the name its computer account has',
    44: 'the CA server says the ticket is not for it (KRB_AP_ERR_BADMATCH)',
    68: 'the realm is wrong (KDC_ERR_WRONG_REALM) - give the domain\'s DNS name as the realm',
}
NTSTATUS = {
    0xC0000234: 'the account is locked out',
    0xC0000072: 'the account is disabled',
    0xC0000193: 'the account has expired',
    0xC0000071: 'the password has expired',
    0xC0000224: 'the password must be changed before the first sign-in',
    0xC000006F: 'the account may not sign in at this time (logon hours)',
    0xC0000070: 'the account may not sign in from this workstation',
    0xC000006A: 'the password is wrong',
}


class KrbError(Exception):
    """Said as it is: `words` in words one can act on; `code` the KDC's error number when one
    was sent; `fallback` True where Kerberos cannot be used at all here (no KDC, no AES, no
    service name) - NTLM may still do."""
    def __init__(self, words, code=None, fallback=False, skew=None):
        Exception.__init__(self, words)
        self.code = code
        self.fallback = fallback
        self.skew = skew


def need_crypto():
    if Cipher is None:
        raise KrbError('Kerberos needs the Python package "cryptography" for AES '
                       '(python3-cryptography: dnf install python3-cryptography, or apt install '
                       'python3-cryptography) - it is not installed; sign in with NTLM instead, '
                       'or install it', fallback=True)


# ---------------------------------------------------------------------------
# DER (X.690), as much as Kerberos needs
# ---------------------------------------------------------------------------
class DerError(ValueError):
    pass


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def seq(*items):
    return tlv(0x30, b''.join(i for i in items if i is not None))


def seq_of(items):
    return tlv(0x30, b''.join(items))


def ctx(n, content):
    """An explicit context tag [n] (constructed)."""
    return tlv(0xa0 | n, content)


def app(n, content):
    """[APPLICATION n] (constructed)."""
    return tlv(0x60 | n, content)


def der_int(v):
    v = int(v)
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, 'big', signed=True))


def der_octets(b):
    return tlv(0x04, bytes(b))


def der_gstring(s):
    """KerberosString / Realm: GeneralString (IA5 in practice)."""
    return tlv(0x1b, str(s).encode('utf-8'))


def der_gtime(t):
    return tlv(0x18, time.strftime('%Y%m%d%H%M%SZ', time.gmtime(int(t))).encode('ascii'))


def der_bool(v):
    return tlv(0x01, b'\xff' if v else b'\x00')


def der_bits32(v):
    """KerberosFlags: a BIT STRING of 32 bits."""
    return tlv(0x03, b'\x00' + struct.pack('>I', v & 0xffffffff))


def der_oid(dotted):
    parts = [int(x) for x in dotted.split('.')]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7f]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


class Der(object):
    """One decoded element: tag, content (bytes), whole (with the header)."""
    __slots__ = ('tag', 'content', 'whole')

    def __init__(self, tag, content, whole):
        self.tag, self.content, self.whole = tag, content, whole

    @classmethod
    def read(cls, data, pos=0):
        """(element, the position after it)."""
        data = bytes(data)
        if pos + 2 > len(data):
            raise DerError('cut short')
        tag = data[pos]
        if tag & 0x1f == 0x1f:
            raise DerError('a tag of more than one byte')
        n = data[pos + 1]
        p = pos + 2
        if n & 0x80:
            k = n & 0x7f
            if k == 0 or k > 4 or p + k > len(data):
                raise DerError('a length that cannot be read')
            n = int.from_bytes(data[p:p + k], 'big')
            p += k
        if p + n > len(data):
            raise DerError('cut short')
        return cls(tag, data[p:p + n], data[pos:p + n]), p + n

    @classmethod
    def one(cls, data):
        el, end = cls.read(data)
        return el

    def items(self):
        out, p = [], 0
        while p < len(self.content):
            el, p = Der.read(self.content, p)
            out.append(el)
        return out

    def fields(self):
        """{n: the element inside [n]} of a SEQUENCE of explicitly tagged fields."""
        out = {}
        for el in self.items():
            if el.tag & 0xe0 == 0xa0:
                out[el.tag & 0x1f] = Der.one(el.content)
        return out

    def inner(self):
        """The element inside an [APPLICATION n] or [n] wrapper."""
        return Der.one(self.content)

    def int(self):
        if self.tag != 0x02:
            raise DerError('not an INTEGER')
        return int.from_bytes(self.content, 'big', signed=True)

    def text(self):
        return self.content.decode('utf-8', 'replace')

    def oid(self):
        c = self.content
        out = [c[0] // 40, c[0] % 40]
        v = 0
        for b in c[1:]:
            v = (v << 7) | (b & 0x7f)
            if not b & 0x80:
                out.append(v)
                v = 0
        return '.'.join(str(x) for x in out)


def gtime_decode(text):
    import calendar
    t = text.rstrip('Z').split('.')[0]
    return calendar.timegm(time.strptime(t, '%Y%m%d%H%M%S'))


# ---------------------------------------------------------------------------
# RFC 3961 / RFC 3962: n-fold, DK, string-to-key, AES-CTS, HMAC-SHA1-96
# ---------------------------------------------------------------------------
def nfold(data, nbytes):
    """RFC 3961 5.1: `data` stretched or folded to `nbytes` - copies of it, each rotated 13
    bits to the right more than the one before, added together in ones' complement."""
    data = bytes(data)
    inlen = len(data)
    a, b = inlen, nbytes
    while b:
        a, b = b, a % b
    lcm = inlen * nbytes // a
    bits = 8 * inlen
    mask = (1 << bits) - 1
    x = int.from_bytes(data, 'big')
    big = 0
    for i in range(lcm // inlen):
        r = (13 * i) % bits
        rot = ((x >> r) | (x << (bits - r))) & mask if r else x
        big = (big << bits) | rot
    nb = 8 * nbytes
    nmask = (1 << nb) - 1
    total = 0
    for i in range(lcm // nbytes):
        total += (big >> (nb * (lcm // nbytes - 1 - i))) & nmask
        while total >> nb:
            total = (total & nmask) + (total >> nb)
    return total.to_bytes(nbytes, 'big')


def _aes_ecb(key, block, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(block) + op.finalize()


def _aes_cbc(key, iv, data, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()


def cts_encrypt(key, data, iv=b'\x00' * 16):
    """AES in CBC mode with ciphertext stealing (RFC 3962 5; the last two blocks swapped
    always - NIST's CS3)."""
    need_crypto()
    data = bytes(data)
    if len(data) < 16:
        raise KrbError('AES-CTS needs at least one block')
    if len(data) == 16:
        return _aes_cbc(key, iv, data)
    r = len(data) % 16 or 16
    padded = data + b'\x00' * (16 - r if r != 16 else 0)
    c = _aes_cbc(key, iv, padded)
    return c[:-32] + c[-16:] + c[-32:-32 + r]


def cts_decrypt(key, data, iv=b'\x00' * 16):
    need_crypto()
    data = bytes(data)
    if len(data) < 16:
        raise KrbError('a cipher text shorter than a block')
    if len(data) == 16:
        return _aes_cbc(key, iv, data, decrypt=True)
    r = len(data) % 16 or 16
    head = data[:-(16 + r)]
    cn = data[-(16 + r):-r]
    cn1_part = data[-r:]
    d = _aes_ecb(key, cn, decrypt=True)
    cn1 = cn1_part + d[r:]
    last = bytes(a ^ b for a, b in zip(d[:r], cn1_part))
    first = _aes_cbc(key, iv, head + cn1, decrypt=True)
    return first + last


def dk(key, constant):
    """RFC 3961 5.1 DK(Key, Constant) = random-to-key(DR(Key, Constant)) - for AES the
    identity, DR the blocks E(Key, n-fold(Constant)), E(Key, that), ... cut to the key size."""
    need_crypto()
    k = nfold(constant, 16)
    out = b''
    while len(out) < len(key):
        k = _aes_ecb(key, k)
        out += k
    return out[:len(key)]


def string_to_key(etype, password, salt, iterations=4096):
    """RFC 3962 4: DK(random-to-key(PBKDF2-HMAC-SHA1(password, salt, iterations, keysize)),
    "kerberos")."""
    if etype not in KEY_SIZE:
        raise KrbError('the encryption type %s is not spoken (AES only)' % ETYPE_NAMES.get(
            etype, etype), code=14)
    pw = password.encode('utf-8') if isinstance(password, str) else bytes(password)
    salt = salt.encode('utf-8') if isinstance(salt, str) else bytes(salt)
    tkey = hashlib.pbkdf2_hmac('sha1', pw, salt, int(iterations), KEY_SIZE[etype])
    return dk(tkey, b'kerberos')


class Key(object):
    """An encryption key of an AES type: encrypt / decrypt with a key usage, checksums."""
    __slots__ = ('etype', 'key')

    def __init__(self, etype, key):
        if etype not in KEY_SIZE:
            raise KrbError('the encryption type %s is not spoken (AES only)' % ETYPE_NAMES.get(
                etype, etype), code=14)
        if len(key) != KEY_SIZE[etype]:
            raise KrbError('a key of the wrong size')
        self.etype, self.key = etype, bytes(key)

    def __repr__(self):                             # never the key itself
        return 'Key(%s)' % ETYPE_NAMES.get(self.etype, self.etype)

    def encrypt(self, usage, plain, confounder=None):
        """RFC 3961 5.3 (simplified profile): AES-CTS(Ke, confounder | plain) | HMAC-SHA1-96(Ki,
        confounder | plain)."""
        u = struct.pack('>I', usage)
        ke, ki = dk(self.key, u + b'\xaa'), dk(self.key, u + b'\x55')
        data = (confounder if confounder is not None else os.urandom(16)) + bytes(plain)
        return cts_encrypt(ke, data) + hmac.new(ki, data, hashlib.sha1).digest()[:12]

    def decrypt(self, usage, cipher):
        cipher = bytes(cipher)
        if len(cipher) < 16 + 12:
            raise KrbError('an encrypted part too short to be read')
        u = struct.pack('>I', usage)
        ke, ki = dk(self.key, u + b'\xaa'), dk(self.key, u + b'\x55')
        data = cts_decrypt(ke, cipher[:-12])
        if not hmac.compare_digest(hmac.new(ki, data, hashlib.sha1).digest()[:12], cipher[-12:]):
            raise KrbError('an encrypted part does not verify (wrong key)', code=31)
        return data[16:]

    def checksum(self, usage, data):
        kc = dk(self.key, struct.pack('>I', usage) + b'\x99')
        return hmac.new(kc, bytes(data), hashlib.sha1).digest()[:12]

    @property
    def cksumtype(self):
        return CKSUM_OF[self.etype]


# ---------------------------------------------------------------------------
# Messages (RFC 4120 5)
# ---------------------------------------------------------------------------
def principal(name_type, parts):
    return seq(ctx(0, der_int(name_type)), ctx(1, seq_of([der_gstring(p) for p in parts])))


def principal_decode(el):
    f = el.fields()
    return [x.text() for x in f[1].items()] if 1 in f else []


def enc_data(etype, cipher, kvno=None):
    return seq(ctx(0, der_int(etype)), ctx(1, der_int(kvno)) if kvno is not None else None,
               ctx(2, der_octets(cipher)))


def kerberos_time(t=None):
    t = time.time() if t is None else t
    return int(t), int((t - int(t)) * 1000000)


def pa_data(ptype, value):
    return seq(ctx(1, der_int(ptype)), ctx(2, der_octets(value)))


PA_TGS_REQ, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_PAC_REQUEST = 1, 2, 19, 128


def _req_body(options, cname, realm, sname, till, nonce, etypes):
    return seq(ctx(0, der_bits32(options)),
               ctx(1, principal(NT_PRINCIPAL, cname)) if cname else None,
               ctx(2, der_gstring(realm)),
               ctx(3, principal(sname[0], sname[1])),
               ctx(5, der_gtime(till)),
               ctx(7, der_int(nonce)),
               ctx(8, seq_of([der_int(e) for e in etypes])))


def _kdc_req(msg_type, padata, body):
    return app(10 if msg_type == 10 else 12, seq(
        ctx(1, der_int(5)), ctx(2, der_int(msg_type)),
        ctx(3, seq_of(padata)) if padata else None, ctx(4, body)))


class KrbErrorMsg(object):
    def __init__(self, el):
        f = el.inner().fields()
        self.code = f[6].int() if 6 in f else 0
        self.stime = gtime_decode(f[4].text()) if 4 in f else None
        self.text = f[11].text() if 11 in f else ''
        self.edata = f[12].content if 12 in f else b''
        self.realm = f[9].text() if 9 in f else ''
        self.sname = principal_decode(f[10]) if 10 in f else []

    def etype_info2(self):
        """[(etype, salt, iterations)] the KDC offers (PA-ETYPE-INFO2 in its METHOD-DATA)."""
        out = []
        try:
            for pa in Der.one(self.edata).items():
                f = pa.fields()
                if f.get(1) is not None and f[1].int() == PA_ETYPE_INFO2:
                    for ent in Der.one(f[2].content).items():
                        e = ent.fields()
                        it = 4096
                        if 2 in e and len(e[2].content) == 4:
                            it = struct.unpack('>I', e[2].content)[0]
                        out.append((e[0].int(), e[1].content if 1 in e else None, it))
        except (DerError, KeyError, IndexError, ValueError):
            pass
        return out

    def ntstatus(self):
        """The NTSTATUS a Windows KDC adds (KERB-ERROR-DATA, MS-KILE 2.2.1/2.2.2), or None."""
        try:
            f = Der.one(self.edata).fields()
            if 1 in f and f[1].int() == 3 and 2 in f and len(f[2].content) >= 4:
                return struct.unpack('<I', f[2].content[:4])[0]
        except (DerError, KeyError, IndexError, ValueError):
            pass
        return None


def is_krb_error(data):
    return bool(data) and data[0] == 0x7e


class Ticket(object):
    def __init__(self, ticket_der, key, realm, sname, end):
        self.der = ticket_der
        self.key = key
        self.realm = realm
        self.sname = sname
        self.end = end


def skew_words(skew):
    ahead = skew < 0
    m = abs(skew) / 60.0
    return ('acme\'s clock and the domain controller\'s differ by %s (acme is %s) - more than '
            'the 5 minutes Kerberos allows (KRB_AP_ERR_SKEW): set this machine\'s time from the '
            'domain (chrony/NTP pointed at a domain controller) and try again'
            % ('%.0f minutes' % m if m >= 1 else '%d seconds' % abs(skew),
               'ahead' if ahead else 'behind'))


def error_words(msg, user='', spn='', now=None):
    """KrbError for a KRB-ERROR the KDC or the server sent."""
    if msg.code == 37:
        skew = (msg.stime - (time.time() if now is None else now)) if msg.stime else 0
        return KrbError(skew_words(skew), code=37, skew=skew)
    words = ERRORS.get(msg.code)
    st = msg.ntstatus()
    if st in NTSTATUS:
        words = '%s (%s)' % (NTSTATUS[st], words or 'error %d' % msg.code)
    if not words:
        words = 'the domain controller refused: Kerberos error %d%s' % (
            msg.code, (' - it says: %s' % msg.text[:200]) if msg.text else '')
    words = words.replace('{user}', user or '?').replace('{spn}', spn or '?')
    return KrbError(words, code=msg.code, fallback=msg.code in (7, 14))


# ---------------------------------------------------------------------------
# The KDC over TCP (RFC 4120 7.2.2)
# ---------------------------------------------------------------------------
class Kdc(object):
    """Where the tickets come from: [(host, port)] tried in turn; `opener(host, port,
    timeout)` makes the connection (socket.create_connection where none is given)."""
    def __init__(self, servers, timeout=10, opener=None):
        self.servers = list(servers)
        self.timeout = timeout
        self.opener = opener or socket.create_connection
        self.used = None

    def ask(self, msg):
        last = None
        for host, port in self.servers:
            try:
                s = self.opener((host, port), self.timeout)
            except OSError as e:
                last = '%s:%d: %s' % (host, port, e)
                continue
            try:
                s.settimeout(self.timeout)
                s.sendall(struct.pack('>I', len(msg)) + msg)
                n = struct.unpack('>I', _recv(s, 4))[0]
                if n > 1 << 20:
                    raise KrbError('the domain controller %s:%d sent more than 1 MB' % (host, port))
                data = _recv(s, n)
                self.used = (host, port)
                return data
            except (OSError, socket.timeout, EOFError) as e:
                last = '%s:%d: %s' % (host, port, e)
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        raise KrbError('no domain controller (KDC, TCP port 88) answered: %s' % (
            last or 'none known'), fallback=True)


def _recv(s, n):
    out = b''
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError('the connection was closed')
        out += chunk
    return out


def split_user(user, realm):
    """(user name, REALM): user, user@REALM or DOMAIN\\user (DOMAIN dropped: the realm
    given counts)."""
    user = str(user or '').strip()
    if '\\' in user:
        user = user.split('\\', 1)[1]
    if '@' in user:
        user, r = user.rsplit('@', 1)
        realm = realm or r
    return user, str(realm or '').strip().upper()


class Client(object):
    """A user's Kerberos: its TGT, service tickets, AP-REQs."""
    def __init__(self, user, password, realm, kdc, now=time.time):
        need_crypto()
        self.user, self.realm = split_user(user, realm)
        if not self.user or not self.realm:
            raise KrbError('Kerberos needs the user and the domain (realm), e.g. svc-acme and '
                           'EXAMPLE.LOCAL')
        self._password = password
        self.kdc = kdc
        self.now = now
        self.tgt = None
        self.etype = None

    @property
    def who(self):
        return '%s@%s' % (self.user, self.realm)

    def _send(self, msg):
        data = self.kdc.ask(msg)
        try:
            el = Der.one(data)
        except DerError as e:
            raise KrbError('the domain controller\'s answer cannot be read: %s' % e)
        return el

    # -- AS-REQ ---------------------------------------------------------------------------
    def login(self, etypes=(AES256, AES128)):
        """The TGT (RFC 4120 3.1): asked without pre-authentication first, the salt taken from
        the KDC's PREAUTH_REQUIRED (ETYPE-INFO2), then with PA-ENC-TIMESTAMP."""
        till = self.now() + 10 * 3600
        pac = pa_data(PA_PAC_REQUEST, seq(ctx(0, der_bool(True))))
        options = 0x40810010                # forwardable, renewable, canonicalize, renewable-ok
        sname = (NT_SRV_INST, ['krbtgt', self.realm])
        nonce = struct.unpack('>I', os.urandom(4))[0] & 0x7fffffff
        body = _req_body(options, [self.user], self.realm, sname, till, nonce, etypes)
        el = self._send(_kdc_req(10, [pac], body))
        info = None
        if el.tag == 0x7e:
            err = KrbErrorMsg(el)
            if err.code != 25:              # not PREAUTH_REQUIRED
                raise error_words(err, self.who, now=self.now())
            info = [x for x in err.etype_info2() if x[0] in etypes]
            if not info:
                offered = ', '.join(ETYPE_NAMES.get(x[0], str(x[0])) for x in err.etype_info2())
                raise KrbError('the domain controller offers the account no AES key (%s) - '
                               'acme speaks AES256 and AES128 only: set the account\'s password '
                               'once more (a domain at 2008 level or later makes AES keys)'
                               % (offered or 'nothing'), code=14, fallback=True)
            etype, salt, iters = info[0]
            if salt is None:
                salt = (self.realm + self.user).encode('utf-8')
            key = Key(etype, string_to_key(etype, self._password, salt, iters))
            t, us = kerberos_time(self.now())
            ts = seq(ctx(0, der_gtime(t)), ctx(1, der_int(us)))
            pa_ts = pa_data(PA_ENC_TIMESTAMP, enc_data(etype, key.encrypt(KU_AS_REQ_PA_ENC_TS, ts)))
            nonce = struct.unpack('>I', os.urandom(4))[0] & 0x7fffffff
            body = _req_body(options, [self.user], self.realm, sname, till, nonce, etypes)
            el = self._send(_kdc_req(10, [pa_ts, pac], body))
            if el.tag == 0x7e:
                raise error_words(KrbErrorMsg(el), self.who, now=self.now())
        else:
            key = None
        if el.tag != 0x6b:
            raise KrbError('the domain controller sent no AS-REP (tag 0x%02x)' % el.tag)
        rep = el.inner().fields()
        enc = rep[6].fields()
        etype = enc[0].int()
        if key is None or key.etype != etype:
            salt = None
            if 2 in rep:                     # PA-ETYPE-INFO2 in the AS-REP itself
                for pa in rep[2].items():
                    f = pa.fields()
                    if f[1].int() == PA_ETYPE_INFO2:
                        for ent in Der.one(f[2].content).items():
                            e = ent.fields()
                            if e[0].int() == etype and 1 in e:
                                salt = e[1].content
            key = Key(etype, string_to_key(etype, self._password, salt or (
                self.realm + self.user).encode('utf-8')))
        try:
            plain = key.decrypt(KU_AS_REP_ENC, enc[2].content)
        except KrbError:
            raise KrbError('the domain controller\'s answer cannot be read with the password\'s '
                           'key - the password is wrong', code=24)
        part = Der.one(plain)
        if part.tag not in (0x79, 0x7a):
            raise KrbError('the AS-REP\'s encrypted part is not EncASRepPart')
        p = part.inner().fields()
        if p[2].int() != nonce:
            raise KrbError('the domain controller\'s answer is not to this request (nonce)')
        k = p[0].fields()
        self.tgt = Ticket(rep[5].whole, Key(k[0].int(), k[1].content), self.realm,
                          ['krbtgt', self.realm], gtime_decode(p[7].text()))
        self.etype = etype
        return self.tgt

    def _authenticator(self, key, usage, cksum=None, seq_number=None, subkey=None):
        t, us = kerberos_time(self.now())
        body = app(2, seq(ctx(0, der_int(5)), ctx(1, der_gstring(self.realm)),
                          ctx(2, principal(NT_PRINCIPAL, [self.user])),
                          ctx(3, cksum) if cksum is not None else None,
                          ctx(4, der_int(us)), ctx(5, der_gtime(t)),
                          ctx(6, seq(ctx(0, der_int(subkey.etype)), ctx(1, der_octets(subkey.key))))
                          if subkey is not None else None,
                          ctx(7, der_int(seq_number)) if seq_number is not None else None))
        return enc_data(key.etype, key.encrypt(usage, body)), (t, us)

    # -- TGS-REQ --------------------------------------------------------------------------
    def service_ticket(self, spn):
        """A ticket for `spn` ("host/ca01.example.local")."""
        if self.tgt is None:
            self.login()
        parts = spn.split('/')
        till = self.now() + 10 * 3600
        nonce = struct.unpack('>I', os.urandom(4))[0] & 0x7fffffff
        body = _req_body(0x40810000, None, self.realm, (NT_SRV_INST, parts), till, nonce,
                         (AES256, AES128))
        key = self.tgt.key
        cksum = seq(ctx(0, der_int(key.cksumtype)),
                    ctx(1, der_octets(key.checksum(KU_TGS_REQ_CKSUM, body))))
        auth, _t = self._authenticator(key, KU_TGS_REQ_AUTH, cksum=cksum)
        ap = app(14, seq(ctx(0, der_int(5)), ctx(1, der_int(14)), ctx(2, der_bits32(0)),
                         ctx(3, self.tgt.der), ctx(4, auth)))
        el = self._send(_kdc_req(12, [pa_data(PA_TGS_REQ, ap)], body))
        if el.tag == 0x7e:
            raise error_words(KrbErrorMsg(el), self.who, spn, now=self.now())
        if el.tag != 0x6d:
            raise KrbError('the domain controller sent no TGS-REP (tag 0x%02x)' % el.tag)
        rep = el.inner().fields()
        enc = rep[6].fields()
        try:
            plain = key.decrypt(KU_TGS_REP_ENC, enc[2].content)
        except KrbError:
            raise KrbError('the domain controller\'s TGS-REP cannot be read')
        part = Der.one(plain)
        p = part.inner().fields()
        if p[2].int() != nonce:
            raise KrbError('the domain controller\'s answer is not to this request (nonce)')
        tkt = Der.one(rep[5].whole).inner().fields()
        sname = principal_decode(tkt[2])
        if sname and sname[0].lower() == 'krbtgt':
            raise KrbError('the CA server %s is in another domain (the domain controller '
                           'sent a referral to %s) - acme asks one domain only: use an account '
                           'of the CA\'s domain and its realm' % (spn, '/'.join(sname)),
                           fallback=True)
        k = p[0].fields()
        return Ticket(rep[5].whole, Key(k[0].int(), k[1].content), self.realm, sname,
                      gtime_decode(p[7].text()))

    # -- AP-REQ (RFC 4120 3.2, RFC 4121 4.1, DCE style) -----------------------------------
    def ap_req(self, ticket, flags=GSS_C_MUTUAL | GSS_C_REPLAY | GSS_C_SEQUENCE | GSS_C_CONF |
               GSS_C_INTEG | GSS_C_DCE_STYLE, seq_number=0):
        """(AP-REQ DER, the authenticator's (ctime, cusec)). The checksum is the GSS-API one
        (0x8003): 16 bytes of channel bindings (none: zeros) and the context's flags."""
        gss = struct.pack('<I', 16) + b'\x00' * 16 + struct.pack('<I', flags)
        cksum = seq(ctx(0, der_int(0x8003)), ctx(1, der_octets(gss)))
        auth, when = self._authenticator(ticket.key, KU_AP_REQ_AUTH, cksum=cksum,
                                         seq_number=seq_number)
        options = 0x20000000 if flags & GSS_C_MUTUAL else 0        # mutual-required
        ap = app(14, seq(ctx(0, der_int(5)), ctx(1, der_int(14)), ctx(2, der_bits32(options)),
                         ctx(3, ticket.der), ctx(4, auth)))
        return ap, when


def gss_frame(token, tok_id=b'\x01\x00', oid=KRB5_OID):
    """RFC 2743 3.1 / RFC 4121 4.1: [APPLICATION 0] { the mechanism's OID, TOK_ID, token }."""
    return app(0, der_oid(oid) + tok_id + token)


def gss_unframe(data):
    """The Kerberos message inside a GSS-API token, or the data as it is when not framed."""
    data = bytes(data)
    if data[:1] != b'\x60':
        return data
    el = Der.one(data)
    oid, p = Der.read(el.content)
    return el.content[p + 2:]


class ApContext(object):
    """The security context after the AP exchange: the key the Wrap tokens use (the
    acceptor's subkey where it sent one), the sequence numbers."""
    def __init__(self, key, acceptor_subkey, send_seq, recv_seq):
        self.key = key
        self.acceptor_subkey = acceptor_subkey
        self.send_seq = send_seq
        self.recv_seq = recv_seq


def ap_rep_read(data, ticket, when):
    """The CA's AP-REP: (EncAPRepPart fields, the subkey Key or None, its seq-number).
    Mutual authentication: its ctime/cusec must be ours (RFC 4120 3.2.5)."""
    data = gss_unframe(data)
    el = Der.one(data)
    if el.tag == 0x7e:
        raise error_words(KrbErrorMsg(el), spn='/'.join(ticket.sname))
    if el.tag != 0x6f:
        raise KrbError('the CA server sent no AP-REP (tag 0x%02x)' % el.tag)
    f = el.inner().fields()
    enc = f[2].fields()
    try:
        plain = ticket.key.decrypt(KU_AP_REP_ENC, enc[2].content)
    except KrbError:
        raise KrbError('the CA server\'s AP-REP does not verify - it is not the server the '
                       'ticket is for')
    p = Der.one(plain).inner().fields()
    ctime, cusec = gtime_decode(p[0].text()), p[1].int()
    if (ctime, cusec) != tuple(when):
        raise KrbError('the CA server\'s AP-REP answers another authenticator (mutual '
                       'authentication failed)')
    sub = None
    if 2 in p:
        k = p[2].fields()
        et = k[0].int()
        if et not in KEY_SIZE:
            raise KrbError('the CA server chose the encryption type %s for its session - acme '
                           'speaks AES only' % ETYPE_NAMES.get(et, et), fallback=True)
        sub = Key(et, k[1].content)
    seqn = p[3].int() if 3 in p else 0
    return p, sub, seqn


def ap_rep_dce(ticket, server_seq, now=None):
    """The third leg of the DCE style (MS-KILE 3.4.5.1, as Windows and impacket send it): an
    AP-REP of the client's - its own time, the server's sequence number - encrypted with the
    ticket's session key."""
    t, us = kerberos_time(now)
    part = app(27, seq(ctx(0, der_gtime(t)), ctx(1, der_int(us)), ctx(3, der_int(server_seq))))
    return app(15, seq(ctx(0, der_int(5)), ctx(1, der_int(15)),
                       ctx(2, enc_data(ticket.key.etype,
                                       ticket.key.encrypt(KU_AP_REP_ENC, part)))))


# ---------------------------------------------------------------------------
# RFC 4121 4.2.6.2 Wrap tokens with confidentiality, in the DCE style of MS-RPCE / MS-KILE
# (3.4.5.4.1): the RPC stub encrypted in place, the token's header, the rotated part and
# the checksum in the auth verifier
# ---------------------------------------------------------------------------
FLAG_SENT_BY_ACCEPTOR, FLAG_SEALED, FLAG_ACCEPTOR_SUBKEY = 1, 2, 4


def _rotate_right(data, n):
    n %= len(data)
    return data[-n:] + data[:-n] if n else data


def _rotate_left(data, n):
    n %= len(data)
    return data[n:] + data[:n]


def wrap_dce(key, data, seq_number, initiator=True, acceptor_subkey=True, confounder=None):
    """(the stub encrypted - as long as `data` -, the token for the auth verifier)."""
    flags = FLAG_SEALED | (FLAG_ACCEPTOR_SUBKEY if acceptor_subkey else 0) | (
        0 if initiator else FLAG_SENT_BY_ACCEPTOR)
    ec = (16 - len(data) % 16) % 16
    hdr0 = struct.pack('>HBBHHQ', 0x0504, flags, 0xff, ec, 0, seq_number & 0xffffffffffffffff)
    c = key.encrypt(KG_INITIATOR_SEAL if initiator else KG_ACCEPTOR_SEAL,
                    bytes(data) + b'\xff' * ec + hdr0, confounder)
    rrc = 28
    hdr = struct.pack('>HBBHHQ', 0x0504, flags, 0xff, ec, rrc, seq_number & 0xffffffffffffffff)
    rot = _rotate_right(c, rrc + ec)
    cut = 16 + rrc + ec
    return rot[cut:], hdr + rot[:cut]


def unwrap_dce(key, stub, token, initiator=False):
    """The plain stub of a sealed one and its token (from the acceptor when initiator is
    False). Raises KrbError when it does not verify."""
    token = bytes(token)
    if len(token) < 16 or token[:2] != b'\x05\x04':
        raise KrbError('the auth verifier holds no Wrap token')
    _tid, flags, filler, ec, rrc, seqn = struct.unpack('>HBBHHQ', token[:16])
    if filler != 0xff or not flags & FLAG_SEALED:
        raise KrbError('the Wrap token is not sealed')
    if bool(flags & FLAG_SENT_BY_ACCEPTOR) == initiator:
        raise KrbError('the Wrap token goes the other way')
    c = _rotate_left(token[16:] + bytes(stub), rrc + ec)
    plain = key.decrypt(KG_INITIATOR_SEAL if initiator else KG_ACCEPTOR_SEAL, c)
    if len(plain) < 16 + ec:
        raise KrbError('the Wrap token is too short')
    inner = plain[-16:]
    if inner[:2] != token[:2] or inner[2] != flags or inner[4:6] != token[4:6] or \
            inner[8:16] != token[8:16]:
        raise KrbError('the Wrap token\'s header does not match its encrypted copy')
    return plain[:-(16 + ec)], seqn
