# -*- coding: utf-8 -*-
"""POP3 with STLS (RFC 1939, RFC 2595) and POP3 over TLS at once (RFC 8314)."""
from __future__ import annotations

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire
from acmelib.plugins.checks.tls import TlsCheck


class Pop3Check(Check):
    kind = 'pop3'
    title = 'POP3 (STLS)'
    protocol = 'POP3 (STLS)'
    default_port = 110
    starttls = True
    description = ('A mailbox server: POP3 on port 110 and STLS - the certificate a mail '
                   'program would get.')
    fields = _tls.fields(110)

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            lines = _tls.Lines(sock, 'the POP3 server')
            greet = lines.line()
            if not greet.startswith('+OK'):
                raise PluginError('the server does not speak POP3 or refused the connection '
                                  '(it said: %s)' % greet[:200])
            lines.send('STLS')
            ans = lines.line()
            if not ans.startswith('+OK'):
                raise PluginError('the server does not offer STLS (it said: %s)' % ans[:200])
            return _wire.starttls(sock, sni, verify, t, greet, lines.pending())


class Pop3sCheck(TlsCheck):
    kind = 'pop3s'
    title = 'POP3S (TLS at once)'
    protocol = 'POP3 over TLS'
    default_port = 995
    description = ('A mailbox server: POP3 over TLS at once (port 995) - the certificate a '
                   'mail program would get.')
    fields = _tls.fields(995)
