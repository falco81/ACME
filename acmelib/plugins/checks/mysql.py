# -*- coding: utf-8 -*-
"""MySQL and MariaDB: the server's Initial Handshake Packet (protocol 10) says
CLIENT_SSL; the client answers with an SSLRequest packet (sequence 1: capability
flags, max packet size, character set, 23 zero bytes) and TLS follows at once."""
from __future__ import annotations

import struct

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire

CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
UTF8MB4_GENERAL_CI = 45
MAX_PACKET = 16 * 1024 * 1024
WHAT = 'the MySQL server'


def read_packet(sock):
    """(sequence id, payload) of one packet: a 3-byte length, the sequence id."""
    head = _wire.exact(sock, 4, WHAT)
    n = head[0] | head[1] << 8 | head[2] << 16
    if n > 64 * 1024:
        raise PluginError('the server does not speak MySQL (it sent: %s)' % _wire.shown(head))
    return head[3], _wire.exact(sock, n, WHAT)


def handshake(p):
    """{'version', 'caps'} of an Initial Handshake Packet, or PluginError in words."""
    if not p:
        raise PluginError('the server does not speak MySQL (an empty packet)')
    if p[0] == 0xFF:
        code = struct.unpack('<H', p[1:3])[0] if len(p) >= 3 else 0
        msg = p[3:]
        if msg[:1] == b'#':
            msg = msg[6:]
        raise PluginError('the MySQL server refused the connection (error %d: %s)'
                          % (code, msg.decode('utf-8', 'replace')[:200]))
    if p[0] != 10:
        if p[0] == 9:
            raise PluginError('the MySQL server is too old (protocol 9) - it has no TLS')
        raise PluginError('the server does not speak MySQL (it sent: %s)' % _wire.shown(p[:40]))
    end = p.find(b'\0', 1)
    if end < 0 or len(p) < end + 1 + 4 + 8 + 1 + 2:
        raise PluginError('the MySQL server\'s greeting is cut short')
    version = p[1:end].decode('utf-8', 'replace')
    at = end + 1 + 4 + 8 + 1
    caps = struct.unpack('<H', p[at:at + 2])[0]
    at += 2
    if len(p) >= at + 5:
        caps |= struct.unpack('<H', p[at + 3:at + 5])[0] << 16
    return {'version': version, 'caps': caps}


def ssl_request(server_caps):
    caps = (CLIENT_LONG_PASSWORD | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH) \
        & server_caps | CLIENT_PROTOCOL_41 | CLIENT_SSL
    body = struct.pack('<IIB', caps, MAX_PACKET, UTF8MB4_GENERAL_CI) + b'\0' * 23
    return struct.pack('<I', len(body))[:3] + b'\x01' + body


class MysqlCheck(Check):
    kind = 'mysql'
    title = 'MySQL / MariaDB'
    protocol = 'MySQL (SSLRequest)'
    default_port = 3306
    starttls = True
    description = ('A MySQL or MariaDB database server on port 3306: its greeting, the '
                   'SSLRequest, then TLS - the certificate the mysql client or a driver '
                   'would get.')
    fields = _tls.fields(3306)

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            _seq, p = read_packet(sock)
            hs = handshake(p)
            said = '%s' % hs['version']
            if not hs['caps'] & CLIENT_SSL:
                raise PluginError('the MySQL server does not offer TLS (%s, without '
                                  'CLIENT_SSL: no certificate set, or have_ssl off)'
                                  % hs['version'])
            _wire.send(sock, ssl_request(hs['caps']), WHAT)
            return _wire.starttls(sock, sni, verify, t, said)
