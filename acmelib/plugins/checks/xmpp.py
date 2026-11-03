# -*- coding: utf-8 -*-
"""XMPP with STARTTLS (RFC 6120 5.4): the stream opened, the features read, the
<starttls/> asked for and <proceed/> answered; TLS then on the same connection."""
from __future__ import annotations

import re
import socket

from acmelib.plugins.base import Check, PluginError, field
from acmelib.plugins.checks import _tls, _wire

MOST = 128 * 1024
WHAT = 'the XMPP server'
STREAM_HEAD = re.compile(rb'<(?:[\w.-]+:)?stream\b[^>]*>')
FEATURES_END = re.compile(rb'</(?:[\w.-]+:)?features\s*>')
STREAM_ERROR = re.compile(rb'<stream:error\b[^>]*>\s*<([\w-]+)')
STARTTLS = re.compile(rb'<starttls\b')
PROCEED = re.compile(rb'<proceed\b[^>]*>')
FAILURE = re.compile(rb'<failure\b[^>]*>')
STREAM_END = re.compile(rb'</(?:[\w.-]+:)?stream\s*>')


def quote(s):
    return (s.replace('&', '&amp;').replace("'", '&apos;').replace('<', '&lt;')
            .replace('>', '&gt;'))


class Reader(object):
    """The stream read until a pattern: the text up to its end is given back, what
    follows stays in the buffer."""
    def __init__(self, sock):
        self.sock, self.buf = sock, b''

    def until(self, *patterns):
        while True:
            err = STREAM_ERROR.search(self.buf)
            if err:
                raise PluginError('the XMPP server ended the stream: %s'
                                  % err.group(1).decode('utf-8', 'replace'))
            for i, p in enumerate(patterns):
                m = p.search(self.buf)
                if m:
                    text, self.buf = self.buf[:m.end()], self.buf[m.end():]
                    return i, text
            if STREAM_END.search(self.buf):
                raise PluginError('the XMPP server closed the stream (it said: %s)'
                                  % _wire.shown(self.buf[-200:]))
            try:
                got = self.sock.recv(4096)
            except socket.timeout:
                raise PluginError('the XMPP server said nothing more in time (after: %s)'
                                  % (_wire.shown(self.buf[-160:]) or 'nothing'))
            except OSError as e:
                raise PluginError('the XMPP server closed the connection: %s' % e)
            if not got:
                raise PluginError('the XMPP server closed the connection (after: %s)'
                                  % (_wire.shown(self.buf[-160:]) or 'nothing'))
            self.buf += got
            if len(self.buf) > MOST:
                raise PluginError('the XMPP server sent more than %d bytes before its '
                                  'features' % MOST)


class XmppCheck(Check):
    kind = 'xmpp'
    title = 'XMPP (STARTTLS)'
    protocol = 'XMPP (STARTTLS)'
    default_port = 5222
    starttls = True
    description = ('A chat server (Jabber): XMPP on port 5222, the stream opened and '
                   'STARTTLS - the certificate a chat client would get.')
    fields = _tls.fields(5222, [
        field('domain', 'XMPP domain', 'text', placeholder='empty: the SNI',
              help='The domain the stream is opened to - the part after the @ of the '
                   'addresses. Empty: the name asked for (SNI), else the address.'),
    ])

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        domain = (self.c('domain') or sni or host or '').strip()
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            _wire.send(sock, ("<?xml version='1.0'?><stream:stream to='%s' "
                              "xmlns='jabber:client' "
                              "xmlns:stream='http://etherx.jabber.org/streams' "
                              "version='1.0'>" % quote(domain)).encode('utf-8'), WHAT)
            r = Reader(sock)
            _, head = r.until(STREAM_HEAD)
            said = STREAM_HEAD.search(head).group(0).decode('utf-8', 'replace')
            _, features = r.until(FEATURES_END)
            if not STARTTLS.search(features):
                raise PluginError('the server does not offer STARTTLS (it said: %s)'
                                  % _wire.shown(features, 300))
            _wire.send(sock, b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", WHAT)
            i, ans = r.until(PROCEED, FAILURE)
            if i == 1:
                raise PluginError('the XMPP server refused STARTTLS (it said: %s)'
                                  % _wire.shown(ans[-200:]))
            return _wire.starttls(sock, sni, verify, t, said, r.buf)
