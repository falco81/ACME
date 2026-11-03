# -*- coding: utf-8 -*-
"""FTP with AUTH TLS (RFC 959, RFC 4217) and FTPS at once (port 990)."""
from __future__ import annotations

import re

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire
from acmelib.plugins.checks.tls import TlsCheck

CODE = re.compile(r'^(\d{3})([ -])?')


def reply(lines):
    """One FTP reply (RFC 959 4.2): '220-' opens a multi-line one, which ends with a line
    that starts '220 ' - the lines between may be anything."""
    first = lines.line()
    m = CODE.match(first)
    if not m:
        raise PluginError('the server does not speak FTP (it said: %s)' % first[:200])
    got = [first]
    if m.group(2) == '-':
        end = m.group(1) + ' '
        while True:
            line = lines.line()
            got.append(line)
            if line.startswith(end) or line == m.group(1):
                break
    return int(m.group(1)), got


class FtpCheck(Check):
    kind = 'ftp'
    title = 'FTP (AUTH TLS)'
    protocol = 'FTP (AUTH TLS)'
    default_port = 21
    starttls = True
    description = ('A file server: FTP on port 21 and AUTH TLS (explicit FTPS) - the '
                   'certificate an FTP program would get.')
    fields = _tls.fields(21)

    def talk(self, host, sni):
        return [{'wait': 'the greeting 220'}, {'send': 'AUTH TLS'}, {'wait': '234 - then TLS'}]

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            lines = _tls.Lines(sock, 'the FTP server')
            code, greet = reply(lines)
            if code == 120:                     # ready in a few minutes: the 220 follows
                code, greet = reply(lines)
            if code != 220:
                raise PluginError('the FTP server refused the connection (it said: %s)'
                                  % ' | '.join(greet)[:300])
            lines.send('AUTH TLS')
            code, ans = reply(lines)
            if code != 234:
                raise PluginError('the server does not offer AUTH TLS (it said: %s)'
                                  % ' | '.join(ans)[:300])
            return _wire.starttls(sock, sni, verify, t, greet[0], lines.pending())


class FtpsCheck(TlsCheck):
    kind = 'ftps'
    title = 'FTPS (TLS at once)'
    protocol = 'FTP over TLS'
    default_port = 990
    description = ('A file server: FTP over TLS at once (implicit FTPS, port 990) - the '
                   'certificate an FTP program would get.')
    fields = _tls.fields(990)
