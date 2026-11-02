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
    lists_existing = True           # what the authority signed: Certificates → Import from a source
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

    # -- what the authority signed (Certificates → Import from a source) -----------------
    def list_existing(self):
        """Every certificate the chosen authority signed (cert_ca_issued) - read only."""
        import json
        from acmelib.certs import ca as CA
        store = self._store()
        got = CA.ca_get(store, self._ca())
        now = time.time()
        known = {}
        for v in store.db.rows('SELECT fingerprint FROM cert_versions'):
            if v.get('fingerprint'):
                known[str(v['fingerprint']).upper()] = True
        out = []
        for r in store.db.rows('SELECT * FROM cert_ca_issued WHERE ca_id = ? ORDER BY created '
                               'DESC, id DESC', (int(got['id']),)):
            try:
                names = json.loads(r.get('names') or '[]') or []
            except ValueError:
                names = []
            has = bool(r.get('cert_pem')) or str(r.get('fingerprint') or '').upper() in known
            if r.get('revoked'):
                status = 'revoked'
            elif (r.get('not_after') or 0) < now:
                status = 'expired'
            else:
                status = 'valid'
            cn = ''
            for part in str(r.get('subject_dn') or '').split(','):
                k, _sep, v = part.strip().partition('=')
                if k.strip().upper() == 'CN':
                    cn = v.strip()
            out.append({'ref': r['serial'], 'cn': cn or (names[0] if names else ''),
                        'names': names, 'product': got['name'], 'status': status,
                        'not_before': r.get('not_before'), 'not_after': r.get('not_after'),
                        'serial': r['serial'], 'fingerprint': r.get('fingerprint') or '',
                        'downloadable': has and not r.get('revoked'),
                        'renewable': 'issue' if not r.get('revoked') else 'none',
                        'note': '' if has else 'acme did not keep this certificate (signed '
                                               'before 1.0.21) - import its file instead',
                        'acme_cert_id': r.get('cert_id')})
        return out

    def fetch_existing(self, ref):
        """The certificate of serial `ref` and the authority's chain - read only."""
        from acmelib.certs import ca as CA
        from acmelib.certs import pki
        store = self._store()
        got = CA.ca_get(store, self._ca())
        row = CA._row(store, got['id'])
        try:
            serial = pki.norm_serial(ref)
        except Exception:                               # noqa: BLE001
            raise PluginError('%s is not a serial number' % (ref or '?'), retry=False)
        r = store.db.row('SELECT * FROM cert_ca_issued WHERE ca_id = ? AND serial = ?',
                         (int(got['id']), serial))
        if not r:
            raise PluginError('the authority "%s" signed no certificate %s' % (got['name'],
                                                                                 serial),
                              retry=False)
        if r.get('revoked'):
            raise PluginError('the certificate %s is revoked' % serial, retry=False)
        pem = r.get('cert_pem')
        if not pem and r.get('fingerprint'):
            v = store.db.row('SELECT cert_pem FROM cert_versions WHERE UPPER(fingerprint) = ?',
                             (str(r['fingerprint']).upper(),))
            pem = (v or {}).get('cert_pem')
        if not pem:
            raise PluginError('acme did not keep the certificate %s (signed before 1.0.21) - '
                              'import its file instead' % serial, retry=False)
        return {'cert_pem': pem, 'chain_pems': [row['cert_pem']] + CA._chain(row),
                'ref': serial, 'acme_cert_id': r.get('cert_id')}

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
