# -*- coding: utf-8 -*-
"""
VMware Cloud Foundation - SDDC Manager's trust store: the CA certificates of acme's
certificate (its intermediates and root) added, so SDDC Manager keeps trusting a vCenter, NSX
Manager or other VCF component acme gave a certificate to directly.

Why only the trust: neither SDDC Manager (VCF 5.2) nor VCF Operations fleet management (VCF
9.x) takes a private key made elsewhere - their certificate workflows install only a
certificate signed for a CSR they made themselves ("leaf certificate doesn't match any CSR
stored in the locker"). A certificate replaced on the component itself (the vcenter, nsx_manager,
esxi targets) is supported, and then "must be added to the SDDC Manager trust store, otherwise
the UI shows errors and workflows fail" (navody vcf-sddc-manager.md).

    POST /v1/tokens {"username", "password"}            -> {"accessToken"} (bearer)
    GET  /v1/sddc-manager/trusted-certificates           the ones there (already there?)
    POST /v1/sddc-manager/trusted-certificates {"certificate": PEM,
                                                "certificateUsageType": "TRUSTED_FOR_OUTBOUND"}

The same in VCF 5.2 and 9.0 - 9.1.1 (SDDC Manager API v1 stays in VCF 9, reference 9.0 and
9.1.1). KB 316056 asks for SDDC Manager's services to be restarted after a certificate is added
through the API:  /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh
(as root, after "su -" - acme does not, it says so).

Sources: navody/certifikaty/vmware/vcf-sddc-manager.md (2026-11) - VCF API 5.2.2 Trusted
Certificates and POST /v1/tokens, SDDC Manager API 9.1.1 Certificates, KB 316056 (VCF 4.5.x,
5.x, 9.x). Rights: an SDDC Manager ADMIN (the role matrix is not published; VIEWER is read-only).
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, http_fields, tls_fields)
from acmelib.plugins.targets import _vmware as V

TRUSTED = '/v1/sddc-manager/trusted-certificates'


class SddcManagerTrustTarget(HttpTarget):
    kind = 'sddc_manager'
    title = 'VMware SDDC Manager (trust store)'
    vendor = 'VMware'
    discovery = False
    description = ('VCF 5.2 - 9.1: adds the CA certificates of the certificate (intermediates '
                   'and root) to SDDC Manager\'s trust store, so it keeps trusting a vCenter, '
                   'NSX or ESX acme gave the certificate to. SDDC Manager takes no key made '
                   'elsewhere: the certificate itself goes to the component.')
    doc = 'targets.md'
    fields = http_fields(443, 'sddc-manager.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-vcf-certs@corp.local',
              help='an SDDC Manager ADMIN'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in (ISRG Root X1 for Let\'s Encrypt); empty: the '
                   'last certificate of the chain when it is a root'),
        field('intermediates', 'The intermediates too', 'bool', default=True),
        field('usage', 'Trusted for', 'select', default='TRUSTED_FOR_OUTBOUND',
              options=[['TRUSTED_FOR_OUTBOUND', 'outbound (SDDC Manager connecting to the '
                                                'components)'],
                       ['TRUSTED_FOR_INBOUND', 'inbound']]),
    ]

    token = None

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.token} if self.token else {}

    def login(self):
        try:
            st, hd, d = self.req('POST', '/v1/tokens', {'username': text(self.c('user')),
                                                        'password': text(self.c('password'))},
                                 auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail,
                              retry=not any(x in str(e) for x in ('(401)', '(403)', 'said 400')))
        tok = text((d or {}).get('accessToken') if isinstance(d, dict) else '')
        if not tok:
            raise PluginError('SDDC Manager gave no token on signing in', retry=False)
        self.token = tok

    def trusted(self):
        st, hd, d = self.req('GET', TRUSTED, what='reading the trust store')
        return d

    def test(self):
        self.login()
        d = self.trusted()
        n = len(d.get('elements') or []) if isinstance(d, dict) else (
            len(d) if isinstance(d, list) else '?')
        return 'signed in to SDDC Manager %s; %s trusted certificates' % (self.c('host'), n)

    def wanted(self, bundle, options):
        root = V.root_of(bundle, options.get('root_pem'))
        out = list(V.intermediates(bundle)) if as_bool(self.opt(options, 'intermediates', True),
                                                       True) else []
        if root:
            out.append(root)
        return out

    def deploy(self, bundle, options):
        options = options or {}
        certs = self.wanted(bundle, options)
        if not certs:
            raise PluginError('nothing to add: the chain has no intermediates and no root was '
                              'given - paste the root CA certificate', retry=False)
        self.login()
        have = self.trusted()
        if self.unchanged(bundle, options, present=lambda: all(V.has_cert(have, c)
                                                               for c in certs)):
            return self.same(bundle, 'trusted by SDDC Manager')
        usage = text(options.get('usage') or 'TRUSTED_FOR_OUTBOUND')
        added = 0
        for pem in certs:
            if V.has_cert(have, pem):
                self.ctx.step('a CA certificate is trusted already')
                continue
            self.req('POST', TRUSTED, {'certificate': pem.strip() + '\n',
                                       'certificateUsageType': usage},
                     what='adding a CA certificate to the trust store')
            self.ctx.step('added a CA certificate (%s)' % usage, 'ok')
            added += 1
        if added:
            self.ctx.step('SDDC Manager reads its trust store when its services restart (KB '
                          '316056): as root on it run /opt/vmware/vcf/operationsmanager/scripts/'
                          'cli/sddcmanager_restart_services.sh', 'warn')
        self.remember(bundle, options)
        return '%d CA certificate%s added to the trust store' % (added, '' if added == 1 else 's')
