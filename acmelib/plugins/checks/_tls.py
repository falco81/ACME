# -*- coding: utf-8 -*-
"""
What every test shares: the connection, TLS on it (at once, or after the
protocol's own start - STARTTLS), the chain the server sent, a line read with a
time limit.

    fields(port)          host, port, SNI, time limit - the fields of a test
    connect(host, port, timeout)          a TCP socket, or PluginError in words
    tls(sock, sni, verify, timeout)       {'chain': [DER...], 'tls', 'cipher'};
                                          verify=True: this machine's CAs and the
                                          name checked (ssl.SSLCertVerificationError
                                          let out - checks.py asks again without)
    Lines(sock)           .line() .lines_until(test) .send(text) for the text
                          protocols (SMTP, IMAP, POP3, FTP, XMPP)

Python 3.13+: SSLSocket.get_unverified_chain() gives the whole chain; older
ones give the leaf only (then the chain is said not to be known).
"""
from __future__ import annotations

import socket
import ssl

from acmelib.plugins.base import PluginError, field

LINE_MOST = 64 * 1024


def fields(port, more=None):
    return [
        field('host', 'Address', 'text', placeholder='empty: the target\'s address',
              help='The name or address to connect to. Empty: the target\'s own address.'),
        field('port', 'Port', 'number', default=port, min=1, max=65535),
        field('sni', 'Name asked for (SNI)', 'text',
              placeholder='empty: the certificate\'s first name',
              help='The server name sent in TLS - a server with several certificates picks '
                   'one by it. Empty: the first name of the certificate tested.'),
    ] + list(more or []) + [
        field('timeout', 'Time limit (s)', 'number', default=15, min=1, max=120,
              advanced=True),
        field('require_trusted', 'Fail when not trusted here', 'bool', default=False,
              advanced=True,
              help='On: the chain must be trusted by this machine\'s CAs and name the '
                   'server - off, that is only said (a CA of acme\'s own is not trusted '
                   'by the system).'),
    ]


def connect(host, port, timeout):
    if not host:
        raise PluginError('no address to connect to - set it in the test, or the target has '
                          'none', retry=False)
    try:
        return socket.create_connection((host, int(port)), timeout=float(timeout))
    except socket.timeout:
        raise PluginError('%s:%s does not answer (no connection in %s s)' % (host, port,
                                                                              timeout))
    except OSError as e:
        raise PluginError('%s:%s cannot be reached: %s' % (host, port, e.strerror or e))


def tls(sock, sni, verify, timeout):
    """TLS over `sock` (already through the protocol's own start)."""
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = bool(sni)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    try:
        ctx.set_ciphers('DEFAULT:@SECLEVEL=0')    # an old server is still read, said below
    except ssl.SSLError:
        pass
    sock.settimeout(float(timeout))
    try:
        s = ctx.wrap_socket(sock, server_hostname=sni or None)
    except ssl.SSLCertVerificationError:
        raise
    except (ssl.SSLError, OSError) as e:
        raise PluginError('the TLS handshake failed: %s' % (getattr(e, 'reason', None) or e))
    try:
        chain = []
        getter = getattr(s, 'get_unverified_chain', None)
        if callable(getter):
            for c in getter() or []:
                chain.append(c if isinstance(c, (bytes, bytearray)) else
                             c.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(c, 'public_bytes')
                             else bytes(c))
        if not chain:
            leaf = s.getpeercert(binary_form=True)
            if leaf:
                chain = [leaf]
        c = s.cipher() or ('', '', 0)
        out = {'chain': [bytes(x) for x in chain], 'tls': s.version() or '', 'cipher': c[0],
               'whole_chain': callable(getter)}
    finally:
        try:
            s.close()
        except OSError:
            pass
    if not out['chain']:
        raise PluginError('the server sent no certificate')
    return out


class Lines(object):
    """A text protocol line by line, CRLF, with the socket's time limit."""
    def __init__(self, sock, what=''):
        self.sock, self.buf, self.what = sock, b'', what or 'the server'
        self.said = []

    def line(self):
        while b'\n' not in self.buf:
            try:
                got = self.sock.recv(4096)
            except socket.timeout:
                raise PluginError('%s said nothing more in time (after: %s)' % (
                    self.what, ' | '.join(self.said[-3:]) or 'nothing'))
            except OSError as e:
                raise PluginError('%s closed the connection: %s' % (self.what, e))
            if not got:
                raise PluginError('%s closed the connection (after: %s)' % (
                    self.what, ' | '.join(self.said[-3:]) or 'nothing'))
            self.buf += got
            if len(self.buf) > LINE_MOST:
                raise PluginError('%s sent a line longer than %d bytes' % (self.what, LINE_MOST))
        raw, _, self.buf = self.buf.partition(b'\n')
        text = raw.rstrip(b'\r').decode('utf-8', 'replace')
        self.said.append(text[:200])
        return text

    def send(self, text):
        try:
            self.sock.sendall(text.encode('utf-8') + b'\r\n')
        except OSError as e:
            raise PluginError('%s closed the connection: %s' % (self.what, e))

    def pending(self):
        """Bytes read past the last line - the server must not send any before TLS."""
        return self.buf
