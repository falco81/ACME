# -*- coding: utf-8 -*-
"""LDAP with the StartTLS extended operation (RFC 4511 4.14) and LDAPS (port 636).

The request, in BER (RFC 4511 4.12):
    LDAPMessage ::= SEQUENCE { messageID 1,
        extendedReq [APPLICATION 23] SEQUENCE { requestName [0] "1.3.6.1.4.1.1466.20037" } }
the answer an ExtendedResponse [APPLICATION 24] whose resultCode 0 is success.
"""
from __future__ import annotations

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire
from acmelib.plugins.checks.tls import TlsCheck

STARTTLS_OID = b'1.3.6.1.4.1.1466.20037'
NOTICE_OF_DISCONNECTION = b'1.3.6.1.4.1.1466.20036'
MOST = 256 * 1024

RESULTS = {
    0: 'success', 1: 'operationsError', 2: 'protocolError', 3: 'timeLimitExceeded',
    7: 'authMethodNotSupported', 8: 'strongerAuthRequired', 11: 'adminLimitExceeded',
    12: 'unavailableCriticalExtension', 13: 'confidentialityRequired', 32: 'noSuchObject',
    48: 'inappropriateAuthentication', 49: 'invalidCredentials',
    50: 'insufficientAccessRights', 51: 'busy', 52: 'unavailable', 53: 'unwillingToPerform',
    80: 'other',
}


def tlv(tag, value):
    n = len(value)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + value


def request(message_id=1):
    return tlv(0x30, tlv(0x02, bytes([message_id])) + tlv(0x77, tlv(0x80, STARTTLS_OID)))


def parse(data, at=0):
    """(tag, value, next) of the BER element at `at` (definite lengths: LDAP has only those)."""
    if at + 2 > len(data):
        raise ValueError('short')
    tag, ln = data[at], data[at + 1]
    at += 2
    if ln & 0x80:
        k = ln & 0x7f
        if not 1 <= k <= 4 or at + k > len(data):
            raise ValueError('a length not of LDAP')
        ln = int.from_bytes(data[at:at + k], 'big')
        at += k
    if at + ln > len(data):
        raise ValueError('short')
    return tag, data[at:at + ln], at + ln


def read_message(sock):
    """One whole LDAPMessage from the socket."""
    head = _wire.exact(sock, 2, 'the LDAP server')
    if head[0] != 0x30:
        raise PluginError('the server does not speak LDAP (it sent: %s)' % _wire.shown(head))
    if head[1] & 0x80:
        k = head[1] & 0x7f
        if not 1 <= k <= 4:
            raise PluginError('the server does not speak LDAP (it sent: %s)'
                              % _wire.shown(head))
        more = _wire.exact(sock, k, 'the LDAP server')
        n = int.from_bytes(more, 'big')
        head += more
    else:
        n = head[1]
    if n > MOST:
        raise PluginError('the LDAP server sent an answer of %d bytes - not LDAP' % n)
    return head + _wire.exact(sock, n, 'the LDAP server')


def answer(msg):
    """(messageID, resultCode, diagnosticMessage, responseName) of an ExtendedResponse."""
    try:
        tag, body, _ = parse(msg)
        t, mid, at = parse(body)
        if t != 0x02:
            raise ValueError('no messageID')
        t, op, _ = parse(body, at)
        if t != 0x78:
            raise PluginError('the LDAP server answered StartTLS with something else (an '
                              'operation of tag 0x%02x)' % t)
        t, code, at = parse(op)
        if t != 0x0a:
            raise ValueError('no resultCode')
        _, _, at = parse(op, at)                    # matchedDN
        _, diag, at = parse(op, at)                 # diagnosticMessage
        name = b''
        while at < len(op):
            t, v, at = parse(op, at)
            if t == 0x8a:                           # responseName [10]
                name = v
        return (int.from_bytes(mid, 'big'), int.from_bytes(code, 'big'),
                diag.decode('utf-8', 'replace'), name)
    except ValueError:
        raise PluginError('the LDAP server\'s answer cannot be read (%s)' % _wire.shown(msg))


class LdapCheck(Check):
    kind = 'ldap'
    title = 'LDAP (StartTLS)'
    protocol = 'LDAP (StartTLS)'
    default_port = 389
    starttls = True
    description = ('A directory server: LDAP on port 389 and the StartTLS extended '
                   'operation - the certificate a directory client would get.')
    fields = _tls.fields(389)

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            _wire.send(sock, request(1), 'the LDAP server')
            mid, code, diag, name = answer(read_message(sock))
            if mid == 0 and name == NOTICE_OF_DISCONNECTION:
                raise PluginError('the LDAP server closed the session (Notice of '
                                  'Disconnection: %s%s)' % (RESULTS.get(code, code),
                                                            ', ' + diag if diag else ''))
            if code != 0:
                words = '%s (%d)' % (RESULTS.get(code, 'result'), code)
                raise PluginError('the LDAP server refused StartTLS (it said: %s%s)' % (
                    words, ' - ' + diag if diag else ''))
            return _wire.starttls(sock, sni, verify, t, diag)


class LdapsCheck(TlsCheck):
    kind = 'ldaps'
    title = 'LDAPS (TLS at once)'
    protocol = 'LDAP over TLS'
    default_port = 636
    description = ('A directory server: LDAP over TLS at once (port 636, or 3269 for the '
                   'Active Directory global catalog) - the certificate a directory client '
                   'would get.')
    fields = _tls.fields(636)
