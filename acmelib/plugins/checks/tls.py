# -*- coding: utf-8 -*-
"""TLS at once on any port, and HTTPS: what most services are."""
from __future__ import annotations

from acmelib.plugins.base import Check
from acmelib.plugins.checks import _tls


class TlsCheck(Check):
    kind = 'tls'
    title = 'TLS (any port)'
    protocol = 'TLS'
    default_port = 443
    description = ('TLS at once on any port - a web server, LDAPS, a reverse proxy, MQTT over '
                   'TLS, an API: the certificate it serves compared with the one acme keeps.')
    fields = _tls.fields(443)

    def served(self, host, port, sni, verify=True):
        t = float(self.c('timeout', 15) or 15)
        sock = _tls.connect(host, port, t)
        return _tls.tls(sock, sni, verify, t)


class HttpsCheck(TlsCheck):
    kind = 'https'
    title = 'HTTPS'
    protocol = 'HTTPS'
    default_port = 443
    description = ('A web server: TLS on port 443 (or another), the name sent as SNI - the '
                   'certificate a browser would get, compared with the one acme keeps.')
    fields = _tls.fields(443)
