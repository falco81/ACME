# -*- coding: utf-8 -*-
"""Services that are TLS at once on a port of their own: MQTT over TLS, SIP over TLS,
DNS over TLS. (SMTPS, IMAPS, POP3S, FTPS and LDAPS are beside their plain ones.)"""
from __future__ import annotations

from acmelib.plugins.checks import _tls
from acmelib.plugins.checks.tls import TlsCheck


class MqttsCheck(TlsCheck):
    kind = 'mqtts'
    title = 'MQTT over TLS'
    protocol = 'MQTT over TLS'
    default_port = 8883
    description = ('A message broker (MQTT - Mosquitto, EMQX, HiveMQ...) over TLS on port '
                   '8883 - the certificate a device or client would get.')
    fields = _tls.fields(8883)


class SipsCheck(TlsCheck):
    kind = 'sips'
    title = 'SIP over TLS'
    protocol = 'SIP over TLS'
    default_port = 5061
    description = ('A telephone exchange or SIP proxy over TLS on port 5061 - the '
                   'certificate a phone or another exchange would get.')
    fields = _tls.fields(5061)


class DotCheck(TlsCheck):
    kind = 'dot'
    title = 'DNS over TLS'
    protocol = 'DNS over TLS'
    default_port = 853
    description = ('A DNS resolver over TLS on port 853 (RFC 7858) - the certificate a '
                   'system resolver or a phone would get.')
    fields = _tls.fields(853)
