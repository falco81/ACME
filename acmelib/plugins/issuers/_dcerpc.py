# -*- coding: utf-8 -*-
"""
DCE/RPC over TCP (ncacn_ip_tcp, C706 chapter 12 and MS-RPCE) for the sources
that speak to Windows directly (issuers/ms_adcs_rpc.py): the endpoint mapper
(ept_map, opnum 3, on port 135), a bind with an auth verifier, requests and
responses in fragments - each one sealed at RPC_C_AUTHN_LEVEL_PKT_PRIVACY:

* Kerberos (auth type 16, RPC_C_AUTHN_GSS_KERBEROS): the AP-REQ in the bind,
  the CA's AP-REP in the bind_ack, the client's AP-REP in an AUTH3 - the DCE
  style of MS-RPCE 3.3.1.5.2 / MS-KILE 3.4.5.1 -, then RFC 4121 Wrap tokens
  with the stub encrypted in place (MS-KILE 3.4.5.4.1). The same AP exchange
  can go inside SPNEGO (auth type 9, RPC_C_AUTHN_GSS_NEGOTIATE, the third leg
  an alter_context) where a server takes only that.
* NTLMv2 (auth type 10, RPC_C_AUTHN_WINNT): NEGOTIATE / CHALLENGE /
  AUTHENTICATE in bind, bind_ack and AUTH3, then MS-NLMP 3.4.4 sealing with
  extended session security and key exchange (RC4, HMAC-MD5 over the whole
  PDU). The NTLM pieces are acmelib/plugins/issuers/_ntlm.py's.

And the NDR (C706 chapter 14) of MS-ICPR's CertServerRequest (opnum 0 of
ICertPassage 91ae6020-9e3c-11cf-8d7c-00aa00c091be v0.0) and of ept_map.

Written from the specifications (C706, MS-RPCE, MS-NLMP, MS-KILE, MS-ICPR,
MS-WCCE, RFC 4121), checked against MS-NLMP 4.2.4.4's sealing vector and
against a server of the tests' own (test/test_ms_adcs_rpc.py) - not against a
real Windows CA here.

Never logs, keeps or says a password or a key. Not a plugin.
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import os
import socket
import struct
import uuid

from acmelib.plugins.issuers import _krb5 as K
from acmelib.plugins.issuers import _ntlm

# PDU types (C706 12.6.4)
REQUEST, RESPONSE, FAULT, BIND, BIND_ACK, BIND_NAK = 0, 2, 3, 11, 12, 13
ALTER, ALTER_RESP, AUTH3, SHUTDOWN = 14, 15, 16, 17
FIRST_FRAG, LAST_FRAG, PFC_OBJECT_UUID = 0x01, 0x02, 0x80
DREP = b'\x10\x00\x00\x00'                  # little-endian, ASCII, IEEE

AUTHN_WINNT, AUTHN_GSS_NEGOTIATE, AUTHN_GSS_KERBEROS = 10, 9, 16
LEVEL_PKT_PRIVACY = 6
AUTH_CTX_ID = 79231

NDR = ('8a885d04-1ceb-11c9-9fe8-08002b104860', 2, 0)
EPM = ('e1af8308-5d1f-11c9-91a4-08002b14a0fa', 3, 0)
ICPR = ('91ae6020-9e3c-11cf-8d7c-00aa00c091be', 0, 0)

# What a fault's status means (C706 appendix E, MS-RPCE 2.2.2.x / MS-ERREF)
FAULTS = {
    0x00000005: 'access is denied (the account\'s rights on the CA: Request Certificates)',
    0x000006d3: 'the CA does not take this way of signing in (rpc_s_unknown_authn_service)',
    0x00000721: 'the security package refused the request (RPC_S_SEC_PKG_ERROR)',
    0x000006f7: 'the CA could not read the request (rpc_x_bad_stub_data)',
    0x1c010002: 'the CA does not know the operation (nca_s_op_rng_error)',
    0x1c010003: 'the CA does not offer the interface ICertPassage here (nca_s_unk_if)',
    0x1c00001a: 'the CA could not read the request (nca_s_fault_ndr)',
    0x1c010013: 'the CA could not read the request (nca_s_proto_error)',
    0x1c010014: 'the CA ran out of memory (nca_s_fault_remote_no_memory)',
    0x80070005: 'access is denied (the account\'s rights on the CA: Request Certificates)',
}
BIND_REASONS = {
    0: 'no reason given', 1: 'the server is busy', 2: 'the server\'s limits are reached',
    4: 'the protocol version is not supported',
    8: 'the server does not take this way of signing in (authentication type not recognized)',
    9: 'the sign-in did not verify (invalid checksum)',
}


class RpcError(Exception):
    """Said as it is. `stage`: 'connect' | 'epm' | 'bind' | 'auth' | 'fault' | 'proto';
    `status` a fault's or the endpoint mapper's status where there is one."""
    def __init__(self, words, stage='proto', status=None, auth_refused=False):
        Exception.__init__(self, words)
        self.stage = stage
        self.status = status
        self.auth_refused = auth_refused


def uuid_bytes(u):
    return uuid.UUID(u).bytes_le


def syntax(iface):
    u, major, minor = iface
    return uuid_bytes(u) + struct.pack('<HH', major, minor)


def _align(n, a=4):
    return (a - n % a) % a


# ---------------------------------------------------------------------------
# The connection
# ---------------------------------------------------------------------------
class Transport(object):
    """One TCP connection: whole PDUs out and in. `opener((host, port), timeout)` makes the
    socket (socket.create_connection where none is given)."""
    def __init__(self, host, port, timeout=30, opener=None, what='the CA'):
        self.host, self.port, self.timeout = host, int(port), timeout
        try:
            self.sock = (opener or socket.create_connection)((host, self.port), timeout)
            self.sock.settimeout(timeout)
        except socket.timeout:
            raise RpcError('%s does not answer at %s:%d (no connection within %ss - a firewall?)'
                           % (what, host, self.port, timeout), 'connect')
        except OSError as e:
            raise RpcError('%s cannot be reached at %s:%d: %s' % (what, host, self.port,
                                                                  getattr(e, 'strerror', None) or e),
                           'connect')

    def send(self, data):
        try:
            self.sock.sendall(data)
        except OSError as e:
            raise RpcError('the connection to %s:%d broke: %s' % (self.host, self.port, e),
                           'connect')

    def _recv(self, n):
        out = b''
        while len(out) < n:
            try:
                chunk = self.sock.recv(n - len(out))
            except socket.timeout:
                raise RpcError('%s:%d sent no answer within %ss' % (self.host, self.port,
                                                                     self.timeout), 'connect')
            except OSError as e:
                raise RpcError('the connection to %s:%d broke: %s' % (self.host, self.port, e),
                               'connect')
            if not chunk:
                raise RpcError('%s:%d closed the connection' % (self.host, self.port), 'connect')
            out += chunk
        return out

    def recv_pdu(self):
        hdr = self._recv(16)
        if hdr[0] != 5:
            raise RpcError('%s:%d does not speak DCE/RPC (version %d)' % (self.host, self.port,
                                                                          hdr[0]), 'proto')
        if hdr[4] & 0xf0 != 0x10:
            raise RpcError('%s:%d answers big-endian, which acme does not read' % (
                self.host, self.port), 'proto')
        frag_len = struct.unpack('<H', hdr[8:10])[0]
        if frag_len < 16:
            raise RpcError('a PDU too short', 'proto')
        return Pdu(hdr + self._recv(frag_len - 16))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Pdu(object):
    """A PDU as it came: its header's fields, its body, its auth verifier."""
    def __init__(self, raw):
        self.raw = raw
        self.ptype, self.flags = raw[2], raw[3]
        self.frag_len, self.auth_len, self.call_id = struct.unpack('<HHI', raw[8:16])
        if self.frag_len != len(raw) or (self.auth_len and self.auth_len + 8 + 16 > len(raw)):
            raise RpcError('a PDU whose lengths do not add up', 'proto')
        if self.auth_len:
            t = len(raw) - self.auth_len - 8
            self.auth_type, self.auth_level, self.auth_pad, _r, self.auth_ctx = \
                struct.unpack('<BBBBI', raw[t:t + 8])
            self.auth_value = raw[t + 8:]
            self.body_end = t
        else:
            self.auth_type = self.auth_level = self.auth_pad = self.auth_ctx = None
            self.auth_value = b''
            self.body_end = len(raw)


def pdu(ptype, call_id, body, flags=FIRST_FRAG | LAST_FRAG, auth=b'', auth_len=0):
    frag_len = 16 + len(body) + len(auth)
    return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, DREP, frag_len, auth_len,
                       call_id) + body + auth


def sec_trailer(auth_type, level, pad, ctx_id=AUTH_CTX_ID):
    return struct.pack('<BBBBI', auth_type, level, pad, 0, ctx_id)


# ---------------------------------------------------------------------------
# NTLM over RPC (MS-NLMP 3.1.5 / 3.4.4, connection-oriented, with sealing)
# ---------------------------------------------------------------------------
NEGOTIATE_SEAL = 0x00000020
NTLM_FLAGS = _ntlm.FLAGS | NEGOTIATE_SEAL


class Rc4(object):
    """RC4 whose state goes on from one call to the next (the NTLM sealing handle)."""
    def __init__(self, key):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S, self.i, self.j = S, 0, 0

    def __call__(self, data):
        S, i, j = self.S, self.i, self.j
        out = bytearray()
        for ch in data:
            i = (i + 1) & 0xff
            j = (j + S[i]) & 0xff
            S[i], S[j] = S[j], S[i]
            out.append(ch ^ S[(S[i] + S[j]) & 0xff])
        self.i, self.j = i, j
        return bytes(out)


def ntlm_keys(exported, client=True):
    """(signing key, sealing key) of one direction, MS-NLMP 3.4.5.2 / 3.4.5.3 (128 bits)."""
    who = b'client-to-server' if client else b'server-to-client'
    sign = hashlib.md5(exported + b'session key to ' + who + b' signing key magic constant\x00')\
        .digest()
    seal = hashlib.md5(exported + b'session key to ' + who + b' sealing key magic constant\x00')\
        .digest()
    return sign, seal


def ntlm_seal(handle, sign_key, seq, to_sign, to_encrypt, key_exch=True):
    """MS-NLMP 3.4.4.2 SEAL with extended session security: (sealed, 16-byte signature)."""
    sealed = handle(to_encrypt)
    chk = hmac.new(sign_key, struct.pack('<I', seq) + to_sign, hashlib.md5).digest()[:8]
    if key_exch:
        chk = handle(chk)
    return sealed, struct.pack('<I', 1) + chk + struct.pack('<I', seq)


def ntlm_authenticate(negotiate, challenge, user, password, domain, spn, workstation='ACME',
                      exported=None, client_challenge=None, now=None):
    """(AUTHENTICATE_MESSAGE, exported session key, flags) for RPC: as _ntlm's for HTTP, with
    sealing asked for and MsvAvTargetName the service's name (MS-NLMP 3.1.5.1.2 / 3.3.2)."""
    ch = _ntlm.Challenge(challenge)
    flags = ch.flags & NTLM_FLAGS | _ntlm.NEGOTIATE_UNICODE
    for need, words in ((NEGOTIATE_SEAL, 'sealing'), (_ntlm.NEGOTIATE_KEY_EXCH, 'key exchange'),
                        (_ntlm.NEGOTIATE_128, '128-bit keys'),
                        (_ntlm.NEGOTIATE_EXTENDED_SESSIONSECURITY,
                         'extended session security')):
        if not flags & need:
            raise RpcError('the CA\'s NTLM offers no %s - acme seals only with NTLMv2, 128-bit '
                           'keys and key exchange' % words, 'auth', auth_refused=True)
    if domain is None:
        domain = (ch.av(_ntlm.AV_NB_DOMAIN) or b'').decode('utf-16-le')
    key = _ntlm.ntowfv2(password, user, domain)
    ts = ch.av(_ntlm.AV_TIMESTAMP)
    pairs = [(a, v) for a, v in ch.pairs if a not in (_ntlm.AV_FLAGS, _ntlm.AV_CHANNEL_BINDINGS,
                                                      _ntlm.AV_TARGET_NAME)]
    use_mic = ts is not None
    if use_mic:
        pairs.append((_ntlm.AV_FLAGS, struct.pack('<I', 0x2)))
    else:
        ts = _ntlm.filetime(now)
    pairs.append((_ntlm.AV_CHANNEL_BINDINGS, b'\x00' * 16))
    pairs.append((_ntlm.AV_TARGET_NAME, spn.encode('utf-16-le')))
    cc = client_challenge or os.urandom(8)
    nt, _proof, session_base = _ntlm.ntlmv2_response(key, ch.server_challenge, cc, ts,
                                                     _ntlm.av_pairs_build(pairs))
    lm = b'\x00' * 24 if use_mic else _ntlm.lmv2_response(key, ch.server_challenge, cc)
    exported = exported or os.urandom(16)
    enc_key = _ntlm.rc4(session_base, exported)
    fields = [lm, nt, domain.encode('utf-16-le'), user.encode('utf-16-le'),
              workstation.encode('utf-16-le'), enc_key]
    off, hdr, body = 88, b'', b''
    for f in fields:
        hdr += struct.pack('<HHI', len(f), len(f), off + len(body))
        body += f
    msg = _ntlm.SIG + struct.pack('<I', 3) + hdr + struct.pack('<I', flags) + _ntlm.VERSION + \
        b'\x00' * 16 + body
    if use_mic:
        mic = hmac.new(exported, negotiate + ch.raw + msg, hashlib.md5).digest()
        msg = msg[:72] + mic + msg[88:]
    return msg, exported, flags


class NtlmAuth(object):
    auth_type = AUTHN_WINNT
    name = 'NTLMv2'
    third_leg = 'auth3'

    def __init__(self, user, password, domain=None, spn='', workstation='ACME'):
        if '\\' in user:
            domain, user = user.split('\\', 1)
        elif '@' in user and not domain:
            domain = ''                 # user@domain: the name as it is (a UPN)
        self.user, self._password, self.domain = user, password, domain
        self.spn, self.workstation = spn, workstation
        self.negotiate = None
        self.flags = 0

    @property
    def who(self):
        return ('%s\\%s' % (self.domain, self.user)) if self.domain else self.user

    def first(self):
        self.negotiate = _ntlm.negotiate_message(NTLM_FLAGS)
        return self.negotiate

    def second(self, token):
        if not token or token[:8] != _ntlm.SIG:
            raise RpcError('the CA answered the NTLM sign-in with no CHALLENGE', 'auth',
                           auth_refused=True)
        msg, exported, self.flags = ntlm_authenticate(self.negotiate, token, self.user,
                                                      self._password, self.domain, self.spn,
                                                      self.workstation)
        if self.domain is None:
            self.domain = (_ntlm.Challenge(token).av(_ntlm.AV_NB_DOMAIN) or b'').decode(
                'utf-16-le')
        cs, cl = ntlm_keys(exported, True)
        ss, sl = ntlm_keys(exported, False)
        self._c = (cs, Rc4(cl))
        self._s = (ss, Rc4(sl))
        self.send_seq = self.recv_seq = 0
        return msg

    def done(self, token):
        pass

    def verifier_len(self, n):
        return 16

    def seal(self, plain, to_sign_without_verifier):
        sign, handle = self._c
        sealed, sig = ntlm_seal(handle, sign, self.send_seq, to_sign_without_verifier, plain)
        self.send_seq += 1
        return sealed, sig

    def unseal(self, sealed, verifier, rebuild):
        """`rebuild(plain)`: the PDU as signed (its plain stub in place, no verifier)."""
        sign, handle = self._s
        if len(verifier) != 16:
            raise RpcError('the CA\'s NTLM signature has the wrong size', 'proto')
        plain = handle(sealed)
        chk = handle(verifier[4:12])
        want = hmac.new(sign, struct.pack('<I', self.recv_seq) + rebuild(plain),
                        hashlib.md5).digest()[:8]
        if not hmac.compare_digest(chk, want) or \
                struct.unpack('<I', verifier[12:16])[0] != self.recv_seq:
            raise RpcError('the CA\'s answer does not verify (NTLM signature) - not the CA acme '
                           'signed in to, or changed on the way', 'proto')
        self.recv_seq += 1
        return plain


# ---------------------------------------------------------------------------
# Kerberos over RPC (DCE style)
# ---------------------------------------------------------------------------
SPNEGO_OID = '1.3.6.1.5.5.2'


def spnego_init(mech_token):
    """NegTokenInit (RFC 4178 4.2.1) offering MS Kerberos and Kerberos, the AP-REQ inside."""
    mechs = K.seq_of([K.der_oid(K.MS_KRB5_OID), K.der_oid(K.KRB5_OID)])
    inner = K.ctx(0, K.seq(K.ctx(0, mechs), K.ctx(2, K.der_octets(mech_token))))
    return K.app(0, K.der_oid(SPNEGO_OID) + inner)


def spnego_resp(token):
    return K.ctx(1, K.seq(K.ctx(2, K.der_octets(token))))


def spnego_token(data):
    """(negState or None, responseToken or b'') of a NegTokenResp."""
    try:
        el = K.Der.one(data)
        if el.tag != 0xa1:
            return None, b''
        f = el.inner().fields()
        state = f[0].content[0] if 0 in f and f[0].content else None
        return state, (f[2].content if 2 in f else b'')
    except (K.DerError, IndexError):
        return None, b''


class KerberosAuth(object):
    """`client` a _krb5.Client with a TGT, `ticket` the CA's service ticket."""
    name = 'Kerberos'

    def __init__(self, client, ticket, spnego=False):
        self.client, self.ticket = client, ticket
        self.spnego = spnego
        self.auth_type = AUTHN_GSS_NEGOTIATE if spnego else AUTHN_GSS_KERBEROS
        self.third_leg = 'alter' if spnego else 'auth3'
        self.ctx = None

    @property
    def who(self):
        return self.client.who

    def first(self):
        ap, self._when = self.client.ap_req(self.ticket, seq_number=0)
        if self.spnego:
            return spnego_init(K.gss_frame(ap))
        return ap

    def second(self, token):
        data = token
        if self.spnego:
            state, data = spnego_token(token)
            if state == 2 or not data:
                raise RpcError('the CA refused the Kerberos sign-in (SPNEGO reject)', 'auth',
                               auth_refused=True)
        if not data:
            raise RpcError('the CA answered the Kerberos sign-in with nothing', 'auth',
                           auth_refused=True)
        _part, sub, server_seq = K.ap_rep_read(data, self.ticket, self._when)
        self.ctx = K.ApContext(sub or self.ticket.key, sub is not None, 0, server_seq)
        third = K.ap_rep_dce(self.ticket, server_seq)
        return spnego_resp(third) if self.spnego else third

    def done(self, token):
        if self.spnego and token:
            state, _t = spnego_token(token)
            if state == 2:
                raise RpcError('the CA refused the Kerberos sign-in (SPNEGO reject)', 'auth',
                               auth_refused=True)

    def verifier_len(self, n):
        return 16 + 28 + 16 + (16 - n % 16) % 16

    def seal(self, plain, _to_sign):
        c = self.ctx
        sealed, tok = K.wrap_dce(c.key, plain, c.send_seq, True, c.acceptor_subkey)
        c.send_seq += 1
        return sealed, tok

    def unseal(self, sealed, verifier, _rebuild):
        try:
            plain, _seq = K.unwrap_dce(self.ctx.key, sealed, verifier, initiator=False)
        except K.KrbError as e:
            raise RpcError('the CA\'s answer does not verify (Kerberos Wrap token: %s) - not the '
                           'CA acme signed in to, or changed on the way' % e, 'proto')
        self.ctx.recv_seq += 1
        return plain


def _parses(fn):
    """A PDU or a stub that cannot be taken apart as RpcError in words, not a Python error."""
    @functools.wraps(fn)
    def inner(*a, **k):
        try:
            return fn(*a, **k)
        except (struct.error, IndexError, ValueError, TypeError) as e:
            raise RpcError('an answer that cannot be read (%s)' % e.__class__.__name__, 'proto')
    return inner


# ---------------------------------------------------------------------------
# A client of one interface
# ---------------------------------------------------------------------------
class Client(object):
    def __init__(self, transport, auth=None, level=LEVEL_PKT_PRIVACY):
        self.t = transport
        self.auth = auth
        self.level = level
        self.call_id = 1
        self.max_xmit = 4280
        self.ctx_id = 0

    def _next_call(self):
        c = self.call_id
        self.call_id += 1
        return c

    def _bind_body(self, iface):
        return struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<BBH', 1, 0, 0) + \
            struct.pack('<HBB', self.ctx_id, 1, 0) + syntax(iface) + syntax(NDR)

    @_parses
    def bind(self, iface, what='the CA'):
        body = self._bind_body(iface)
        call = self._next_call()
        if self.auth is not None:
            token = self.auth.first()
            pad = _align(16 + len(body))
            msg = pdu(BIND, call, body + b'\x00' * pad,
                      auth=sec_trailer(self.auth.auth_type, self.level, pad) + token,
                      auth_len=len(token))
        else:
            msg = pdu(BIND, call, body)
        self.t.send(msg)
        ack = self.t.recv_pdu()
        if ack.ptype == BIND_NAK:
            reason = struct.unpack('<H', ack.raw[16:18])[0] if len(ack.raw) >= 18 else 0
            raise RpcError('%s refused the bind: %s' % (what, BIND_REASONS.get(
                reason, 'reason %d' % reason)), 'bind', status=reason,
                auth_refused=reason in (8, 9))
        if ack.ptype == FAULT:
            st = struct.unpack('<I', ack.raw[24:28])[0] if len(ack.raw) >= 28 else 0
            raise RpcError('%s refused the bind: %s' % (what, fault_words(st)), 'bind',
                           status=st, auth_refused=st in (5, 0x6d3, 0x721))
        if ack.ptype != BIND_ACK:
            raise RpcError('%s answered the bind with a PDU of type %d' % (what, ack.ptype),
                           'proto')
        raw = ack.raw
        self.max_xmit = max(1024, min(struct.unpack('<H', raw[18:20])[0], 65535))
        sl = struct.unpack('<H', raw[24:26])[0]
        p = 26 + sl
        p += _align(p)
        n = raw[p]
        result, reason = struct.unpack('<HH', raw[p + 4:p + 8]) if n else (2, 0)
        if result != 0:
            raise RpcError('%s does not take the interface (result %d, reason %d)' % (
                what, result, reason), 'bind')
        if self.auth is not None:
            if not ack.auth_len:
                raise RpcError('%s answered the bind without signing in (no auth verifier)'
                               % what, 'auth', auth_refused=True)
            third = self.auth.second(ack.auth_value)
            if self.auth.third_leg == 'auth3':
                body = b'\x00' * 4
                self.t.send(pdu(AUTH3, call, body,
                                auth=sec_trailer(self.auth.auth_type, self.level, 0) + third,
                                auth_len=len(third)))
            else:
                body = self._bind_body(iface)
                pad = _align(16 + len(body))
                self.t.send(pdu(ALTER, call, body + b'\x00' * pad,
                                auth=sec_trailer(self.auth.auth_type, self.level, pad) + third,
                                auth_len=len(third)))
                r = self.t.recv_pdu()
                if r.ptype != ALTER_RESP:
                    raise RpcError('%s refused the sign-in\'s last step (PDU type %d)' % (
                        what, r.ptype), 'auth', auth_refused=True)
                self.auth.done(r.auth_value)
        return ack

    @_parses
    def call(self, opnum, stub, what='the CA'):
        """The response's stub to a request of `opnum`; a fault raises RpcError('fault')."""
        call = self._next_call()
        stub = bytes(stub)
        if self.auth is not None:
            room = self.max_xmit - 24 - 8 - self.auth.verifier_len(0) - 16
        else:
            room = self.max_xmit - 24
        room = max(16, room - room % 16)
        pieces = [stub[i:i + room] for i in range(0, len(stub), room)] or [b'']
        for i, piece in enumerate(pieces):
            flags = (FIRST_FRAG if i == 0 else 0) | (LAST_FRAG if i == len(pieces) - 1 else 0)
            alloc = len(stub) - i * room
            head = struct.pack('<IHH', alloc, self.ctx_id, opnum)
            if self.auth is None:
                self.t.send(pdu(REQUEST, call, head + piece, flags))
                continue
            pad = _align(len(piece), 16)
            plain = piece + b'\x00' * pad
            trailer = sec_trailer(self.auth.auth_type, self.level, pad)
            vlen = self.auth.verifier_len(len(plain))
            hdr = struct.pack('<BBBB4sHHI', 5, 0, REQUEST, flags, DREP,
                              16 + len(head) + len(plain) + 8 + vlen, vlen, call)
            sealed, verifier = self.auth.seal(plain, hdr + head + plain + trailer)
            if len(verifier) != vlen:
                raise RpcError('an auth verifier of the wrong size', 'proto')
            self.t.send(hdr + head + sealed + trailer + verifier)
        out = b''
        while True:
            r = self.t.recv_pdu()
            if r.call_id != call:
                raise RpcError('%s answered another call' % what, 'proto')
            if r.ptype == FAULT:
                st = struct.unpack('<I', r.raw[24:28])[0] if len(r.raw) >= 28 else 0
                raise RpcError(fault_words(st), 'fault', status=st,
                               auth_refused=st in (5, 0x6d3, 0x721))
            if r.ptype != RESPONSE:
                raise RpcError('%s answered with a PDU of type %d' % (what, r.ptype), 'proto')
            if self.auth is not None:
                if not r.auth_len or r.auth_level != self.level:
                    raise RpcError('%s answered without sealing (the auth level asked: packet '
                                   'privacy)' % what, 'proto')
                sealed = r.raw[24:r.body_end]
                t0 = r.body_end

                def rebuild(plain, r=r, t0=t0):
                    return r.raw[:24] + plain + r.raw[t0:t0 + 8]
                plain = self.auth.unseal(sealed, r.auth_value, rebuild)
                if r.auth_pad:
                    plain = plain[:-r.auth_pad]
                out += plain
            else:
                out += r.raw[24:r.body_end]
            if r.flags & LAST_FRAG:
                return out
            if len(out) > 16 << 20:
                raise RpcError('%s answered more than 16 MB' % what, 'proto')

    def close(self):
        self.t.close()


def fault_words(st):
    w = FAULTS.get(st)
    return '%s (0x%08x)' % (w, st) if w else 'the call failed with status 0x%08x' % st


# ---------------------------------------------------------------------------
# NDR (C706 14): what ept_map and CertServerRequest carry
# ---------------------------------------------------------------------------
class Ndr(object):
    def __init__(self):
        self.b = bytearray()
        self.ref = 0x00020000

    def align(self, n=4):
        self.b += b'\x00' * _align(len(self.b), n)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack('<I', v & 0xffffffff)

    def u16(self, v):
        self.align(2)
        self.b += struct.pack('<H', v)

    def raw(self, data):
        self.b += data

    def referent(self):
        self.ref += 4
        return self.ref

    def wstring(self, s):
        """A [string, unique] wchar_t*: its referent and the conformant varying string."""
        chars = (str(s) + '\x00').encode('utf-16-le')
        n = len(chars) // 2
        self.u32(self.referent())
        self.u32(n)
        self.u32(0)
        self.u32(n)
        self.raw(chars)
        self.align(4)

    def blob(self, data):
        """A CERTTRANSBLOB {cb; [size_is(cb), unique] pb} and its bytes (deferred)."""
        data = bytes(data or b'')
        self.u32(len(data))
        if data:
            self.u32(self.referent())
            self.u32(len(data))
            self.raw(data)
            self.align(4)
        else:
            self.u32(0)


class NdrReader(object):
    def __init__(self, data):
        self.d, self.p = bytes(data), 0

    def align(self, n=4):
        self.p += _align(self.p, n)

    def u32(self):
        self.align(4)
        if self.p + 4 > len(self.d):
            raise RpcError('the CA\'s answer is cut short', 'proto')
        v = struct.unpack('<I', self.d[self.p:self.p + 4])[0]
        self.p += 4
        return v

    def take(self, n):
        if self.p + n > len(self.d):
            raise RpcError('the CA\'s answer is cut short', 'proto')
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def blob(self):
        cb = self.u32()
        ptr = self.u32()
        if not ptr:
            return b''
        n = self.u32()
        if n != cb or n > 16 << 20:
            raise RpcError('a blob of the CA\'s answer whose sizes do not agree', 'proto')
        data = self.take(n)
        self.align(4)
        return data


# -- the endpoint mapper (C706 appendix L, MS-RPCE 2.2.1.2) -----------------------------
def tower(iface, port=0, ip='0.0.0.0'):
    floors = [
        (b'\x0d' + syntax(iface)[:18], syntax(iface)[18:]),
        (b'\x0d' + syntax(NDR)[:18], syntax(NDR)[18:]),
        (b'\x0b', b'\x00\x00'),                         # RPC connection-oriented
        (b'\x07', struct.pack('>H', port)),             # TCP port
        (b'\x09', socket.inet_aton(ip)),                # IPv4 address
    ]
    out = struct.pack('<H', len(floors))
    for lhs, rhs in floors:
        out += struct.pack('<H', len(lhs)) + lhs + struct.pack('<H', len(rhs)) + rhs
    return out


def tower_port(data):
    """The TCP port of a tower (its floor with the protocol 0x07), or None."""
    try:
        n = struct.unpack('<H', data[:2])[0]
        p = 2
        for _i in range(n):
            ll = struct.unpack('<H', data[p:p + 2])[0]
            lhs = data[p + 2:p + 2 + ll]
            p += 2 + ll
            rl = struct.unpack('<H', data[p:p + 2])[0]
            rhs = data[p + 2:p + 2 + rl]
            p += 2 + rl
            if lhs[:1] == b'\x07' and len(rhs) == 2:
                return struct.unpack('>H', rhs)[0]
    except (struct.error, IndexError):
        return None
    return None


def ept_map_stub(iface):
    tw = tower(iface)
    n = Ndr()
    n.u32(1)                            # obj: a pointer (referent 1, as Windows wants)...
    n.raw(b'\x00' * 16)                 # ...to the nil UUID
    n.u32(2)                            # map_tower: referent 2
    n.u32(len(tw))                      # its conformance (tower_length)
    n.u32(len(tw))
    n.raw(tw)
    n.align(4)
    n.raw(b'\x00' * 20)                 # entry_handle: none yet
    n.u32(4)                            # max_towers
    return bytes(n.b)


EPT_NOT_REGISTERED = 0x16c9a0d6


@_parses
def ept_map_ports(stub):
    """([ports], status) of an ept_map response."""
    r = NdrReader(stub)
    r.take(20)                          # entry_handle
    num = r.u32()
    _max, _off, actual = r.u32(), r.u32(), r.u32()
    refs = [r.u32() for _i in range(actual)]
    ports = []
    for ref in refs:
        if not ref:
            continue
        _conf = r.u32()
        ln = r.u32()
        data = r.take(ln)
        r.align(4)
        p = tower_port(data)
        if p:
            ports.append(p)
    status = r.u32()
    return ports[:num] if num else ports, status


def epm_port(host, iface=ICPR, port=135, timeout=30, opener=None):
    """The TCP port where `iface` listens on `host`, from its endpoint mapper."""
    t = Transport(host, port, timeout, opener, what='the endpoint mapper of %s' % host)
    try:
        c = Client(t)
        c.bind(EPM, what='the endpoint mapper of %s' % host)
        try:
            stub = c.call(3, ept_map_stub(iface), what='the endpoint mapper of %s' % host)
        except RpcError as e:
            raise RpcError('the endpoint mapper of %s refused ept_map: %s' % (host, e), 'epm',
                           e.status)
        ports, status = ept_map_ports(stub)
        if status == EPT_NOT_REGISTERED or (not ports and status in (0, EPT_NOT_REGISTERED)):
            raise RpcError('the endpoint mapper of %s knows no ICertPassage over TCP - is Active '
                           'Directory Certificate Services (CertSvc) running there?' % host,
                           'epm', status)
        if status:
            raise RpcError('the endpoint mapper of %s answered status 0x%08x' % (host, status),
                           'epm', status)
        return ports[0]
    finally:
        t.close()


# -- MS-ICPR CertServerRequest (opnum 0) ---------------------------------------------
CR_IN_PKCS10 = 0x00000100
CR_IN_BINARY = 0x00000002
DISPOSITIONS = {0: 'incomplete', 1: 'error', 2: 'denied', 3: 'issued',
                4: 'issued out of band', 5: 'under submission', 6: 'revoked'}


def cert_server_request_stub(flags, authority, request_id, attribs, request):
    n = Ndr()
    n.u32(flags)
    n.wstring(authority)
    n.u32(request_id)
    n.blob(attribs)
    n.blob(request)
    return bytes(n.b)


def attributes_blob(lines):
    """pctbAttribs: "name:value" lines, joined by "\\n", UTF-16LE with its terminating NUL
    (MS-WCCE 2.2.2.7.10 / 3.2.1.4.2.1.1)."""
    text = '\n'.join(str(x) for x in lines if str(x).strip())
    return (text + '\x00').encode('utf-16-le') if text else b''


@_parses
def cert_server_response(stub):
    r = NdrReader(stub)
    out = {'request_id': r.u32(), 'disposition': r.u32()}
    out['cert'] = r.blob()
    out['encoded_cert'] = r.blob()
    msg = r.blob()
    out['message'] = msg.decode('utf-16-le', 'replace').rstrip('\x00').strip()
    out['status'] = r.u32()
    return out
