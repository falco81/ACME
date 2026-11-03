# -*- coding: utf-8 -*-
"""IMAP with STARTTLS (RFC 9051 / RFC 3501) and IMAP over TLS at once (RFC 8314)."""
from __future__ import annotations

import re

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire
from acmelib.plugins.checks.tls import TlsCheck


def tagged(lines, tag):
    """Lines up to the tagged answer: (status 'OK'|'NO'|'BAD', the tagged line, untagged)."""
    untagged = []
    while True:
        line = lines.line()
        if line.startswith(tag + ' '):
            status = line[len(tag) + 1:].split(' ', 1)[0].upper()
            return status, line, untagged
        if line.upper().startswith('* BYE'):
            raise PluginError('the IMAP server closed the session (it said: %s)' % line[:200])
        untagged.append(line)


class ImapCheck(Check):
    kind = 'imap'
    title = 'IMAP (STARTTLS)'
    protocol = 'IMAP (STARTTLS)'
    default_port = 143
    starttls = True
    description = ('A mailbox server: IMAP on port 143, CAPABILITY and STARTTLS - the '
                   'certificate a mail program would get.')
    fields = _tls.fields(143)

    def talk(self, host, sni):
        return [{'wait': 'the greeting * OK'}, {'send': 'a1 CAPABILITY'},
                {'wait': 'a1 OK, STARTTLS among the capabilities'}, {'send': 'a2 STARTTLS'},
                {'wait': 'a2 OK - then TLS'}]

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            lines = _tls.Lines(sock, 'the IMAP server')
            greet = lines.line()
            up = greet.upper()
            if up.startswith('* PREAUTH'):
                raise PluginError('the IMAP server signed in at once (PREAUTH) - STARTTLS '
                                  'cannot follow (it said: %s)' % greet[:200])
            if not up.startswith('* OK'):
                raise PluginError('the server does not speak IMAP or refused the connection '
                                  '(it said: %s)' % greet[:200])
            lines.send('a1 CAPABILITY')
            status, last, said = tagged(lines, 'a1')
            caps = ' '.join(x for x in said if x.upper().startswith('* CAPABILITY'))
            if status != 'OK':
                raise PluginError('the IMAP server refused CAPABILITY (it said: %s)' % last[:200])
            if not re.search(r'(?<![\w-])STARTTLS(?![\w-])', caps, re.I):
                raise PluginError('the server does not offer STARTTLS (it said: %s)'
                                  % (caps or last)[:300])
            lines.send('a2 STARTTLS')
            status, last, _ = tagged(lines, 'a2')
            if status != 'OK':
                raise PluginError('the IMAP server refused STARTTLS (it said: %s)' % last[:200])
            return _wire.starttls(sock, sni, verify, t, greet, lines.pending())


class ImapsCheck(TlsCheck):
    kind = 'imaps'
    title = 'IMAPS (TLS at once)'
    protocol = 'IMAP over TLS'
    default_port = 993
    description = ('A mailbox server over TLS at once (port 993) - the certificate a mail '
                   'program would get.')
    fields = _tls.fields(993)
