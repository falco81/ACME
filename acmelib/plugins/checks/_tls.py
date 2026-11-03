# -*- coding: utf-8 -*-
"""
What every test shares: the connection, TLS on it (at once, or after the
protocol's own start - STARTTLS), the chain the server sent, a line read with a
time limit.

    fields(port)          host, port, SNI, time limit - the fields of a test
    connect(host, port, timeout)          a TCP socket, or PluginError in words
    context(sni, verify) / result(s)      the client context; the chain of a finished
                                          handshake (an SSLObject too: TDS)
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
import threading

from acmelib.plugins.base import PluginError, field

LINE_MOST = 64 * 1024
# Where the connection is opened from: here, or - set by checks/ssh_relay.py for the tests
# it runs - through an SSH server (RELAY.fn(host, port, timeout) -> a socket).
RELAY = threading.local()
# The settings of the test running now in this thread (checks.py sets them): what tls()
# and connect() take from them - versions, ALPN, ciphers, the address family.
CURRENT = threading.local()


def opt(key, default=None):
    cfg = getattr(CURRENT, 'cfg', None) or {}
    v = cfg.get(key)
    return default if v in (None, '') else v


TLS_VERSIONS = [['', 'as the server and this machine agree'], ['TLSv1', 'TLS 1.0'],
                ['TLSv1_1', 'TLS 1.1'], ['TLSv1_2', 'TLS 1.2'], ['TLSv1_3', 'TLS 1.3']]


def fields(port, more=None):
    """The fields of a test: where it connects, the name sent and checked, then what is
    its own (`more`), then how TLS is spoken - every one settable."""
    return [
        field('host', 'Connect to', 'text', placeholder='empty: the target\'s address',
              help='The name or IP address connected to - an IP of one node behind a load '
                   'balancer, say. Empty: the target\'s own address.'),
        field('port', 'Port', 'number', default=port, min=1, max=65535),
        field('sni', 'Name asked for (SNI)', 'text',
              placeholder='empty: the certificate\'s first name',
              help='The server name sent in TLS - a server with several certificates picks '
                   'one by it, whatever address was connected to. Empty: the first name of '
                   'the certificate tested; "-": none sent.'),
        field('check_name', 'Name the certificate must hold', 'text',
              placeholder='empty: the SNI',
              help='The name looked for among the names of the certificate served (and for '
                   'trust). Empty: the name sent as SNI.'),
        field('expect', 'The certificate expected', 'select', default='current',
              options=[['current', 'the version deployed now (or its twin)'],
                       ['main', 'the main one only (not the twin of another key type)'],
                       ['alt', 'the twin only (the other key type)'],
                       ['any', 'any version of this certificate - an old one is not a fault']],
              help='What counts as right. A dual certificate (ECDSA beside RSA): the server '
                   'picks one by what the client offers.'),
        field('key_want', 'Key asked for', 'select', default='',
              options=[['', 'whichever the server picks'], ['rsa', 'RSA'], ['ecdsa', 'ECDSA']],
              help='A server with a dual certificate sends the one the client asks for. RSA or '
                   'ECDSA: TLS 1.2 with ciphers of that key only (TLS 1.3 cannot ask for a key '
                   'type here) - the server must still speak TLS 1.2.'),
    ] + list(more or []) + [
        field('tls_min', 'TLS at least', 'select', default='', options=TLS_VERSIONS,
              advanced=True),
        field('tls_max', 'TLS at most', 'select', default='', options=TLS_VERSIONS,
              advanced=True,
              help='TLS 1.2 at most: the server\'s certificate for older clients - an RSA '
                   'twin, say.'),
        field('ciphers', 'Ciphers (OpenSSL)', 'text', advanced=True,
              placeholder='ECDHE-RSA-AES128-GCM-SHA256',
              help='Offer only these (TLS 1.2 and older) - e.g. RSA ones only, to get the RSA '
                   'certificate of a dual one. Empty: what this machine offers.'),
        field('alpn', 'ALPN', 'text', advanced=True, placeholder='h2, http/1.1',
              help='The protocols offered in ALPN, comma between them. Empty: none.'),
        field('family', 'Address family', 'select', default='', advanced=True,
              options=[['', 'whichever the name gives'], ['4', 'IPv4 only'],
                       ['6', 'IPv6 only']]),
        field('source', 'From the address', 'text', advanced=True,
              placeholder='empty: as the system chooses',
              help='The local address connected from (a node with several).'),
        field('timeout', 'Time limit (s)', 'number', default=15, min=1, max=120,
              advanced=True),
        field('require_trusted', 'Fail when not trusted here', 'bool', default=False,
              advanced=True,
              help='On: the chain must be trusted by this machine\'s CAs and hold the name '
                   'checked - off, that is only said (a CA of acme\'s own is not trusted '
                   'by the system).'),
    ]


def connect(host, port, timeout):
    fn = getattr(RELAY, 'fn', None)
    if fn is not None:
        return fn(host, port, timeout)
    if not host:
        raise PluginError('no address to connect to - set it in the test, or the target has '
                          'none', retry=False)
    fam = str(opt('family', '') or '')
    src = str(opt('source', '') or '').strip()
    try:
        if fam in ('4', '6'):
            want = socket.AF_INET if fam == '4' else socket.AF_INET6
            infos = socket.getaddrinfo(host, int(port), want, socket.SOCK_STREAM)
            if not infos:
                raise PluginError('%s has no IPv%s address' % (host, fam))
            last = None
            for af, st, pr, _cn, sa in infos:
                s = socket.socket(af, st, pr)
                s.settimeout(float(timeout))
                try:
                    if src:
                        s.bind((src, 0))
                    s.connect(sa)
                    return s
                except OSError as e:
                    last = e
                    s.close()
            raise last or OSError('no address')
        return socket.create_connection((host, int(port)), timeout=float(timeout),
                                        source_address=(src, 0) if src else None)
    except socket.gaierror as e:
        raise PluginError('%s cannot be looked up: %s' % (host, e.strerror or e))
    except socket.timeout:
        raise PluginError('%s:%s does not answer (no connection in %s s)' % (host, port,
                                                                              timeout))
    except OSError as e:
        raise PluginError('%s:%s cannot be reached: %s' % (host, port, e.strerror or e))


def context(sni, verify):
    """The client context of every test, with the test's settings (versions, ciphers,
    ALPN): verify=True this machine's CAs (the name is judged by checks.py, which may
    look for another one than the SNI); False: nothing checked, old servers still read."""
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = getattr(ssl.TLSVersion, str(opt('tls_min', '') or 'TLSv1'))
    except (ValueError, AttributeError):
        pass
    want = str(opt('key_want', '') or '').lower()
    if opt('tls_max'):
        try:
            ctx.maximum_version = getattr(ssl.TLSVersion, str(opt('tls_max')))
        except (ValueError, AttributeError):
            pass
    if want in ('rsa', 'ecdsa'):
        # the key type asked for (1.0.34): only TLS 1.2 lets a client say it, by its ciphers
        try:
            if ctx.maximum_version in (ssl.TLSVersion.MAXIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_3):
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass
    ciphers = str(opt('ciphers', '') or '')
    if not ciphers and want in ('rsa', 'ecdsa'):
        ciphers = ('aRSA' if want == 'rsa' else 'aECDSA') + ':!aNULL:@SECLEVEL=0'
    try:
        ctx.set_ciphers(ciphers or 'DEFAULT:@SECLEVEL=0')
    except ssl.SSLError as e:
        raise PluginError('the ciphers set are not ones this machine knows: %s' % e,
                          retry=False)
    alpn = [x.strip() for x in str(opt('alpn', '') or '').split(',') if x.strip()]
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


def result(s):
    """{'chain', 'tls', 'cipher', 'whole_chain', 'alpn'} of a finished handshake - an
    SSLSocket or an SSLObject (a protocol that carries TLS in its own packets: TDS)."""
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
    try:
        alpn = s.selected_alpn_protocol() or ''
    except (AttributeError, ValueError):
        alpn = ''
    return {'chain': [bytes(x) for x in chain], 'tls': s.version() or '', 'cipher': c[0],
            'whole_chain': callable(getter), 'alpn': alpn}


def server_name(sni):
    """The SNI sent: "-" sends none."""
    return '' if sni == '-' else (sni or '')


def tls(sock, sni, verify, timeout, keep=False):
    """TLS over `sock` (already through the protocol's own start). `keep`: the TLS
    socket stays open, in out['sock'] (HTTPS asks over it)."""
    sni = server_name(sni)
    ctx = context(sni, verify)
    sock.settimeout(float(timeout))
    try:
        s = ctx.wrap_socket(sock, server_hostname=sni or None)
    except ssl.SSLCertVerificationError:
        raise
    except (ssl.SSLError, OSError) as e:
        raise PluginError('the TLS handshake failed: %s' % (getattr(e, 'reason', None) or e))
    try:
        out = result(s)
        if keep:
            out['sock'] = s
    finally:
        if not keep:
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
