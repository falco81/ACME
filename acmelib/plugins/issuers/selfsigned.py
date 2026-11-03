# -*- coding: utf-8 -*-
"""A certificate signed by its own key - for tests, and for what trusts it by its fingerprint."""
from __future__ import annotations

from acmelib.plugins.base import Issued, Issuer, PluginError, field


class SelfSignedIssuer(Issuer):
    kind = 'selfsigned'
    discovery = False               # nothing to ask
    dual = True
    title = 'Self-signed'
    description = ('A certificate signed by its own key: nothing trusts it but what is told '
                   'to (a pinned fingerprint, a test, a device that only wants a certificate).')
    vendor = 'acme'
    doc = 'certificate-formats.md'
    choose_days = True
    ip_names = True
    wildcards = True
    fields = [
        field('days', 'Validity (days)', 'number', default=365),
        field('eku', 'Extended key usage', 'list', default=['serverAuth', 'clientAuth'],
              advanced=True),
    ]

    def test(self):
        return 'nothing to reach: a self-signed certificate is made here'

    def issue(self, req):
        from acmelib.certs import pki
        if not req.key_pem:
            raise PluginError('a self-signed certificate needs the key (none was made)',
                              retry=False)
        names = list(getattr(req, 'sans', None) or req.names or [])
        if not names and req.csr_pem:
            names = pki.csr_info(req.csr_pem)['names']
        eku = (req.profile or {}).get('eku') or self.c('eku') or ['serverAuth', 'clientAuth']
        if isinstance(eku, str):
            eku = [x for x in eku.replace(',', '\n').split() if x]
        cert = pki.self_signed(req.key_pem, names, req.subject or None,
                               days=int(req.days or self.c('days') or 365), eku=eku,
                               must_staple=bool((req.profile or {}).get('must_staple')))
        info = pki.cert_info(cert)
        return Issued(cert, [], info={'serial': info['serial']})
