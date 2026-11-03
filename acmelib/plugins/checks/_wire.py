# -*- coding: utf-8 -*-
"""What the tests with a plain start share (STARTTLS, AUTH TLS, X.224, SSLRequest...):

    timeout(check)               the test's time limit in seconds
    exact(sock, n, what)         n bytes, or PluginError in words (closed, no answer)
    send(sock, data, what)       all of data, or PluginError
    shown(data)                  bytes as words for an error ('220 mx ESMTP' / hex)
    starttls(check, sock, sni, verify, said, extra=b'')
                                 TLS on a socket through its plain start; 'said' kept;
                                 bytes the server sent ahead of TLS refused (a
                                 STARTTLS command injection, CVE-2011-0411 and kin)
    closing(sock)                the socket closed whatever happens
"""
from __future__ import annotations

import contextlib
import socket

from acmelib.plugins.base import PluginError
from acmelib.plugins.checks import _tls


def timeout(check):
    try:
        return float(check.c('timeout', 15) or 15)
    except (TypeError, ValueError):
        return 15.0


def exact(sock, n, what='the server'):
    out = b''
    while len(out) < n:
        try:
            got = sock.recv(n - len(out))
        except socket.timeout:
            raise PluginError('%s said nothing more in time (%d of %d bytes)' % (
                what, len(out), n))
        except OSError as e:
            raise PluginError('%s closed the connection: %s' % (what, e))
        if not got:
            raise PluginError('%s closed the connection (%d of %d bytes)' % (what, len(out), n)
                              if out else '%s closed the connection without an answer' % what)
        out += got
    return out


def send(sock, data, what='the server'):
    try:
        sock.sendall(data)
    except OSError as e:
        raise PluginError('%s closed the connection: %s' % (what, e))


def shown(data, most=120):
    data = bytes(data or b'')[:most]
    text = data.decode('utf-8', 'replace')
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data):
        return ' '.join(text.split())
    return data.hex(' ')


def starttls(sock, sni, verify, t, said='', extra=b''):
    if extra:
        raise PluginError('the server sent more before TLS than it may (%s) - not taken'
                          % shown(extra))
    out = _tls.tls(sock, sni, verify, t)
    if said:
        out['said'] = said[:300]
    return out


@contextlib.contextmanager
def closing(sock):
    try:
        yield sock
    finally:
        try:
            sock.close()
        except OSError:
            pass
