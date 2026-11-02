# -*- coding: utf-8 -*-
"""Certificates from one of acme's own certificate authorities (docs/own-ca.md)."""
from __future__ import annotations

import time

from acmelib.plugins.base import Issued, Issuer, PluginError, field


def _list(v):
    if v in (None, ''):
        return []
    if isinstance(v, str):
        return [x for x in v.replace(',', '\n').split() if x]
    return [str(x) for x in v if str(x).strip()]


class InternalCaIssuer(Issuer):
    kind = 'internal_ca'
    dual = True
    title = 'Own certificate authority'
    description = ('Signed at once by one of acme\'s own authorities (Settings → Authorities): '
                   'for internal servers, devices and clients that trust your root.')
    vendor = 'acme'
    doc = 'own-ca.md'
    choose_days = True
    ip_names = True
    wildcards = True
    fields = [
        field('ca', 'Certificate authority', 'select', required=True, options=[],
              options_from='cas', help='The authority that signs; its chain goes with the '
              'certificate.'),
        field('days', 'Validity (days)', 'number', default=397,
              help='Never past the end of the authority itself.'),
        field('eku', 'Extended key usage', 'list', default=['serverAuth', 'clientAuth'],
              help='serverAuth, clientAuth, codeSigning, emailProtection, an OID ...',
              advanced=True),
    ]

    def _store(self):
        store = getattr(self.ctx, 'store', None)
        if store is None:
            raise PluginError('the own CA needs the database, and this context has none',
                              retry=False)
        return store

    def _ca(self):
        ca = self.c('ca')
        if ca in (None, ''):
            raise PluginError('no certificate authority is chosen for this issuer', retry=False)
        return int(ca) if str(ca).strip().isdigit() else str(ca)

    def test(self):
        from acmelib.certs import ca as CA
        store = self._store()
        got = CA.ca_get(store, self._ca())
        CA._usable(CA._row(store, got['id']))
        CA._key(CA._row(store, got['id']))
        return 'the authority "%s" can sign (valid until %s)' % (
            got['name'], time.strftime('%Y-%m-%d', time.gmtime(float(got['not_after']))))

    def issue(self, req):
        from acmelib.certs import ca as CA
        from acmelib.certs import pki
        store = self._store()
        csr = req.csr_pem
        if not csr:
            if not req.key_pem:
                raise PluginError('neither a request nor a key to sign for', retry=False)
            csr = pki.make_csr(req.key_pem, list(req.sans or req.names), req.subject or None,
                               must_staple=bool((req.profile or {}).get('must_staple')))[0]
        prof = dict(req.profile or {})
        profile = {'eku': _list(prof.get('eku')) or _list(self.c('eku')) or
                   ['serverAuth', 'clientAuth'],
                   'must_staple': bool(prof.get('must_staple'))}
        if prof.get('key_usage'):
            profile['key_usage'] = prof['key_usage']
        if prof.get('csr_given') and req.subject:
            # A CSR sent in: the subject its request profile says, not whatever the CSR says.
            profile['subject'] = dict(req.subject)
        if req.sans or req.names:
            profile['names'] = list(req.sans or req.names)     # e-mail and URI ones too
        days = req.days or self.c('days') or 397
        cert, chain = CA.ca_sign(store, self._ca(), csr, int(days), profile,
                                 cert_id=req.cert_id, by='issuer:%s' % self.kind)
        info = pki.cert_info(cert)
        if hasattr(self.ctx, 'step'):
            try:
                self.ctx.step('signed by the own authority: serial %s, until %s' % (
                    info['serial'], time.strftime(
                        '%Y-%m-%d', time.gmtime(info['not_after']))), 'ok')
            except NotImplementedError:
                pass
        return Issued(cert, chain, info={'ca': self.c('ca'), 'serial': info['serial'],
                                         'ari_id': info['ari_id']})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        from acmelib.certs import ca as CA
        from acmelib.certs import pki
        store = self._store()
        info = pki.cert_info(cert_pem)
        ca_id = self._ca()
        # The authority that signed it - the one chosen, or another of ours.
        for row in [CA._row(store, ca_id)] + [CA._row(store, r['id']) for r in
                                               store.db.rows('SELECT id FROM cert_cas')]:
            if row.get('cert_pem') and pki._issued_by(info, pki.cert_info(row['cert_pem'])):
                CA.ca_revoke(store, row['id'], info['serial'], reason, by='issuer:%s' % self.kind)
                return 'revoked at "%s"; its CRL is made anew' % row['name']
        raise PluginError('none of acme\'s authorities signed this certificate', retry=False)
