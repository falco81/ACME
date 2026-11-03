# -*- coding: utf-8 -*-
"""Microsoft SQL Server (MS-TDS 2.2.6.5, 3.2.5.1): a PRELOGIN packet with ENCRYPTION,
the server's PRELOGIN answer, then the TLS handshake carried inside TDS PRELOGIN
packets (type 0x12) - TDS 7.x does not put TLS straight on the connection, so the
handshake runs on an SSLObject and its records are framed here, both ways.
(TDS 8.0 "strict" encryption is TLS at once: the tls test on port 1433 sees that.)"""
from __future__ import annotations

import ssl
import struct

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire

PRELOGIN, TABULAR_RESULT = 0x12, 0x04
STATUS_EOM = 0x01
PACKET = 4096
VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, TERMINATOR = 0, 1, 2, 3, 4, 0xFF
ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3
WHAT = 'the SQL Server'
ROUNDS = 12


def prelogin_body(encryption=ENCRYPT_ON):
    opts = [(VERSION, struct.pack('>IH', 0x0F000000, 0)), (ENCRYPTION, bytes([encryption])),
            (INSTOPT, b'\0'), (THREADID, struct.pack('>I', 0)), (MARS, b'\0')]
    at = len(opts) * 5 + 1
    head, data = b'', b''
    for token, value in opts:
        head += struct.pack('>BHH', token, at + len(data), len(value))
        data += value
    return head + bytes([TERMINATOR]) + data


def packets(typ, body, first_id=1):
    """A TDS message as packets of at most PACKET bytes, the last with EOM."""
    out, pid, at = b'', first_id, 0
    room = PACKET - 8
    while True:
        part = body[at:at + room]
        at += room
        last = at >= len(body)
        out += struct.pack('>BBHHBB', typ, STATUS_EOM if last else 0, 8 + len(part), 0,
                           pid & 0xFF, 0) + part
        pid += 1
        if last:
            return out, pid


def read_message(sock):
    """(type, payload) of one TDS message - packets up to the one with EOM."""
    typ, body = None, b''
    for _ in range(64):
        head = _wire.exact(sock, 8, WHAT)
        t, status, length = head[0], head[1], struct.unpack('>H', head[2:4])[0]
        if t not in (PRELOGIN, TABULAR_RESULT) or not 8 <= length <= 32768:
            raise PluginError('the server does not speak TDS (it sent: %s)'
                              % _wire.shown(head))
        typ = t if typ is None else typ
        body += _wire.exact(sock, length - 8, WHAT)
        if status & STATUS_EOM:
            return typ, body
    raise PluginError('the SQL Server sent a message of too many packets')


def options(body):
    """{token: value} of a PRELOGIN message."""
    out, at = {}, 0
    while at < len(body) and body[at] != TERMINATOR:
        if at + 5 > len(body):
            raise PluginError('the SQL Server\'s PRELOGIN answer is cut short')
        token, off, ln = struct.unpack('>BHH', body[at:at + 5])
        if off + ln > len(body):
            raise PluginError('the SQL Server\'s PRELOGIN answer is cut short')
        out[token] = body[off:off + ln]
        at += 5
    if at >= len(body):
        raise PluginError('the server does not speak TDS (a PRELOGIN answer without its end)')
    return out


class MssqlCheck(Check):
    kind = 'mssql'
    title = 'Microsoft SQL Server'
    protocol = 'TDS (PRELOGIN, TLS)'
    default_port = 1433
    starttls = True
    description = ('A Microsoft SQL Server on port 1433: PRELOGIN with encryption, then '
                   'TLS inside TDS - the certificate SQL Server Management Studio or a '
                   'driver would get.')
    fields = _tls.fields(1433)

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            msg, pid = packets(PRELOGIN, prelogin_body(ENCRYPT_ON))
            _wire.send(sock, msg, WHAT)
            _typ, body = read_message(sock)
            opts = options(body)
            enc = opts.get(ENCRYPTION, b'')
            if len(enc) != 1:
                raise PluginError('the SQL Server did not say whether it encrypts')
            if enc[0] == ENCRYPT_NOT_SUP:
                raise PluginError('the SQL Server does not do encryption (ENCRYPT_NOT_SUP: '
                                  'no certificate for TLS)')
            ver = opts.get(VERSION, b'')
            said = ('SQL Server %d.%d.%d' % (ver[0], ver[1], struct.unpack('>H', ver[2:4])[0])
                    if len(ver) >= 4 else '')
            return self._handshake(sock, sni, verify, t, said, pid)

    def _handshake(self, sock, sni, verify, t, said, pid):
        ctx = _tls.context(sni, verify)
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_side=False, server_hostname=sni or None)
        for _ in range(ROUNDS):
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            except ssl.SSLCertVerificationError:
                raise
            except ssl.SSLError as e:
                raise PluginError('the TLS handshake failed: %s'
                                  % (getattr(e, 'reason', None) or e))
            flight = out.read()
            if flight:
                msg, pid = packets(PRELOGIN, flight, pid)
                _wire.send(sock, msg, WHAT)
            if done:
                r = _tls.result(obj)
                if not r['chain']:
                    raise PluginError('the server sent no certificate')
                if said:
                    r['said'] = said
                return r
            _typ, body = read_message(sock)
            inc.write(body)
        raise PluginError('the TLS handshake inside TDS did not end')
