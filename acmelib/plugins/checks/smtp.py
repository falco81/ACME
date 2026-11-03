# -*- coding: utf-8 -*-
"""SMTP with STARTTLS (RFC 5321, RFC 3207) and SMTP over TLS at once (RFC 8314)."""
from __future__ import annotations

import re

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire
from acmelib.plugins.checks.tls import TlsCheck

CODE = re.compile(r'^(\d{3})([ -]?)(.*)$')


def reply(lines):
    """One SMTP reply: (code, [text lines]) - '250-...' lines go on, '250 ...' ends it."""
    got = []
    while True:
        line = lines.line()
        m = CODE.match(line)
        if not m:
            raise PluginError('the server does not speak SMTP (it said: %s)' % line[:200])
        got.append(line)
        if m.group(2) != '-':
            return int(m.group(1)), got


class SmtpCheck(Check):
    kind = 'smtp'
    title = 'SMTP (STARTTLS)'
    protocol = 'SMTP (STARTTLS)'
    default_port = 25
    starttls = True
    description = ('A mail server: SMTP on port 25 (or 587 for submission), EHLO and '
                   'STARTTLS - the certificate another mail server would get.')
    fields = _tls.fields(25)
    fields[1] = dict(fields[1], help='25: mail between servers; 587: submission (mail '
                                     'programs sending with a password).')

    def talk(self, host, sni):
        return [{'wait': 'the greeting 220'}, {'send': 'EHLO acme-check.%s' % (sni or 'localhost')},
                {'wait': '250, STARTTLS among what it offers'}, {'send': 'STARTTLS'},
                {'wait': '220 - then TLS'}]

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            lines = _tls.Lines(sock, 'the SMTP server')
            code, greet = reply(lines)
            if code != 220:
                raise PluginError('the SMTP server does not take mail now (it said: %s)'
                                  % ' | '.join(greet)[:300])
            lines.send('EHLO acme-check.%s' % (sni or 'localhost'))
            code, ehlo = reply(lines)
            if code != 250:
                raise PluginError('the SMTP server refused EHLO (it said: %s)'
                                  % ' | '.join(ehlo)[:300])
            if not any(re.match(r'^250[ -]STARTTLS\b', x, re.I) for x in ehlo):
                raise PluginError('the server does not offer STARTTLS (it said: %s)'
                                  % ' | '.join(ehlo[1:] or ehlo)[:300])
            lines.send('STARTTLS')
            code, ans = reply(lines)
            if code != 220:
                raise PluginError('the SMTP server refused STARTTLS (it said: %s)'
                                  % ' | '.join(ans)[:300])
            return _wire.starttls(sock, sni, verify, t, greet[0], lines.pending())


class SmtpsCheck(TlsCheck):
    kind = 'smtps'
    title = 'SMTPS (TLS at once)'
    protocol = 'SMTP over TLS'
    default_port = 465
    description = ('A mail server for submission over TLS at once (port 465, RFC 8314) - '
                   'the certificate a mail program would get.')
    fields = _tls.fields(465)
