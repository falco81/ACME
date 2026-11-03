# -*- coding: utf-8 -*-
"""RDP (MS-RDPBCGR 1.3.1.1, 2.2.1.1 - 2.2.1.2): the X.224 Connection Request in a TPKT
(RFC 1006) with an RDP_NEG_REQ asking for TLS and CredSSP; the Connection Confirm says
which the server took; TLS then on the same connection. CredSSP is not needed: the
certificate is seen in the TLS handshake already."""
from __future__ import annotations

import struct

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire

PROTOCOL_RDP, PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_RDSTLS, PROTOCOL_HYBRID_EX = 0, 1, 2, 4, 8
TYPE_RDP_NEG_REQ, TYPE_RDP_NEG_RSP, TYPE_RDP_NEG_FAILURE = 0x01, 0x02, 0x03
X224_CR, X224_CC, X224_DR = 0xE0, 0xD0, 0x80

PROTOCOLS = {PROTOCOL_SSL: 'TLS', PROTOCOL_HYBRID: 'CredSSP (NLA)',
             PROTOCOL_RDSTLS: 'RDSTLS', PROTOCOL_HYBRID_EX: 'CredSSP with Early User '
             'Authorization'}
FAILURES = {
    1: 'SSL_REQUIRED_BY_SERVER',
    2: 'SSL_NOT_ALLOWED_BY_SERVER',
    3: 'SSL_CERT_NOT_ON_SERVER',
    4: 'INCONSISTENT_FLAGS',
    5: 'HYBRID_REQUIRED_BY_SERVER',
    6: 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER',
}
FAILURE_WORDS = {
    1: 'the server wants TLS',
    2: 'the server does not allow TLS - it uses standard RDP security, without a '
       'certificate of TLS',
    3: 'the server has no certificate for TLS',
    4: 'the server found the request inconsistent',
    5: 'the server wants CredSSP (NLA)',
    6: 'the server wants TLS with a user certificate',
}


def connection_request():
    neg = struct.pack('<BBHI', TYPE_RDP_NEG_REQ, 0, 8,
                      PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)
    x224 = struct.pack('>BBHHB', 6 + len(neg), X224_CR, 0, 0, 0) + neg
    return struct.pack('>BBH', 3, 0, 4 + len(x224)) + x224


def read_tpkt(sock):
    head = _wire.exact(sock, 4, 'the RDP server')
    if head[0] != 3:
        raise PluginError('the server does not speak RDP (it sent: %s)' % _wire.shown(head))
    n = struct.unpack('>H', head[2:4])[0]
    if not 11 <= n <= 8192:
        raise PluginError('the server does not speak RDP (a TPKT of %d bytes)' % n)
    return _wire.exact(sock, n - 4, 'the RDP server')


def confirm(body):
    """(selected protocol | None, failure code | None) of an X.224 Connection Confirm."""
    li = body[0]
    if len(body) < 7 or li + 1 > len(body):
        raise PluginError('the RDP server\'s answer is cut short (%s)' % _wire.shown(body))
    code = body[1] & 0xF0
    if code == X224_DR:
        raise PluginError('the RDP server refused the connection (X.224 Disconnect Request)')
    if code != X224_CC:
        raise PluginError('the server does not speak RDP (an X.224 answer of type 0x%02x)'
                          % body[1])
    neg = body[7:li + 1]
    if len(neg) < 8:
        return None, None                           # no negotiation: standard RDP security
    typ, _flags, length, value = struct.unpack('<BBHI', neg[:8])
    if typ == TYPE_RDP_NEG_RSP:
        return value, None
    if typ == TYPE_RDP_NEG_FAILURE:
        return None, value
    raise PluginError('the RDP server answered the negotiation with something else '
                      '(type 0x%02x)' % typ)


class RdpCheck(Check):
    kind = 'rdp'
    title = 'RDP (Remote Desktop)'
    protocol = 'RDP (X.224, TLS)'
    default_port = 3389
    starttls = True
    description = ('A Windows remote desktop (or another RDP server) on port 3389: the '
                   'negotiation of the connection, then TLS - the certificate Remote '
                   'Desktop Connection would get.')
    fields = _tls.fields(3389)

    def talk(self, host, sni):
        return [{'send_hex': connection_request().hex(), 'what': 'X.224 Connection Request '
                 'asking for TLS (RDP_NEG_REQ: PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)'},
                {'wait': 'the Connection Confirm - then TLS'}]

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            _wire.send(sock, connection_request(), 'the RDP server')
            selected, failure = confirm(read_tpkt(sock))
            if failure is not None:
                raise PluginError('the RDP server refused TLS: %s (%s)' % (
                    FAILURE_WORDS.get(failure, 'a failure of its own'),
                    FAILURES.get(failure, failure)))
            if selected is None or selected == PROTOCOL_RDP:
                raise PluginError('the RDP server uses standard RDP security - no TLS, so '
                                  'no certificate to test')
            if selected not in PROTOCOLS:
                raise PluginError('the RDP server chose a protocol not asked for (0x%x)'
                                  % selected)
            return _wire.starttls(sock, sni, verify, t, 'RDP: %s' % PROTOCOLS[selected])
