# -*- coding: utf-8 -*-
"""PostgreSQL: the SSLRequest message (protocol 3, "SSL Session Encryption") - eight
bytes, the length 8 and the code 80877103; the server answers one byte, 'S' (TLS
follows) or 'N' (SSL is off); a very old server an ErrorResponse 'E'."""
from __future__ import annotations

import struct

from acmelib.plugins.base import Check, PluginError
from acmelib.plugins.checks import _tls, _wire

SSL_REQUEST = struct.pack('>II', 8, 80877103)


class PostgresCheck(Check):
    kind = 'postgres'
    title = 'PostgreSQL'
    protocol = 'PostgreSQL (SSLRequest)'
    default_port = 5432
    starttls = True
    description = ('A PostgreSQL database server on port 5432: the SSLRequest, then TLS - '
                   'the certificate psql or a driver would get.')
    fields = _tls.fields(5432)

    def talk(self, host, sni):
        return [{'send_hex': SSL_REQUEST.hex(), 'what': 'SSLRequest (length 8, code 80877103)'},
                {'wait': "the byte 'S' - then TLS"}]

    def served(self, host, port, sni, verify=True):
        t = _wire.timeout(self)
        sock = _tls.connect(host, port, t)
        with _wire.closing(sock):
            _wire.send(sock, SSL_REQUEST, 'the PostgreSQL server')
            # one byte only: what came with it would be read as TLS (CVE-2021-23222)
            got = _wire.exact(sock, 1, 'the PostgreSQL server')
            if got == b'N':
                raise PluginError('SSL is off on the PostgreSQL server (it answered N to '
                                  'the SSLRequest: ssl = off in postgresql.conf)')
            if got == b'E':
                raise PluginError('the PostgreSQL server refused the SSLRequest (an error '
                                  'message - a server too old for SSL)')
            if got != b'S':
                raise PluginError('the server does not speak PostgreSQL (it answered: %s)'
                                  % _wire.shown(got))
            return _wire.starttls(sock, sni, verify, t, '')
