# -*- coding: utf-8 -*-
"""
VMware vCenter machine SSL certificate - the versions of the "vcenter" target besides the
plain one (1.0.94). The calls are those of the plain one (vcenter.py), the same in vCenter
7.0 - 9.1:

    POST /api/session ; GET|PUT /api/vcenter/certificate-management/vcenter/tls
    POST /api/vcenter/certificate-management/vcenter/trusted-root-chains ; DELETE /api/session

What differs by the version is what vCenter does after PUT .../tls:

  ''        any version (vcenter.py): waits as for a restart of every service (minutes) -
            vCenter 7.0 - 8.0 U1 restarts them
  '8.0.2'   vCenter 8.0 U2 - 9.1: no service restarts, sessions stay (KB 403973; VCF 9.1
            Programming Guide "Change the Machine SSL Certificate of vCenter") - the served
            certificate checked at once; the vCenter version read first (VI JSON API "about",
            no sign-in) and another one refused before anything is changed; an RSA key asked
            for before anything is sent (vSphere 9.0 Certificate Requirements: RSA only, 2048 -
            8192 bits; ECDSA is not used for the machine SSL certificate).

Sources: navody/certifikaty/vmware/vcenter.md (2026-11) - vSphere Automation API (latest =
9.1.x) PUT .../tls (cert / key / root_cert, CertificateManagement.Administer, 400
AlreadyExists for the same thumbprint), trusted-root-chains (CertificateManagement.Manage +
Administer), KB 403973, KB 418126 (RSASSA-PSS refused by 9.0's prechecks).
Less certain: the PowerCLI reference says a restart "prior to 8.0.3", KB 403973 none from
8.0 U2 - this version starts at 8.0 U2, a served check that fails is asked again for a minute.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (join_hostport, 
    HttpTarget, PluginError, as_bool, text, as_int, family_of)
from acmelib.plugins.targets._x509 import split_chain
from acmelib.plugins.targets.vcenter import VCenterTarget, TLS, ROOTS
from acmelib.plugins.targets import _vmware as V


class VCenter802Target(VCenterTarget):
    """vCenter 8.0 U2 - 9.1: the certificate replaced without a restart of the services."""
    module_version = '8.0.2'
    version_label = 'vCenter 8.0 U2 - 9.1'
    description = ('vCenter 8.0 U2 - 9.1: replaces the machine SSL certificate through the '
                   'REST API (the chain added to the trusted roots first) - vCenter keeps its '
                   'services and sessions running, the certificate served is checked at once. '
                   'RSA keys only. Refused on a vCenter that says another version.')
    vc_min = (8, 0, 2)
    vc_checked_to = (9, 1)

    def vc_version(self):
        if '_ver' not in self.__dict__:
            self._ver = V.parse_version(V.vi_about(self).get('version'))
        return self._ver

    def check_version(self):
        ver = self.vc_version()
        if ver is None:
            self.ctx.step('the vCenter version cannot be read - going on as for 8.0 U2 and later',
                          'warn')
            return
        if ver < self.vc_min:
            raise PluginError(
                'this vCenter runs %s - the module version "%s" is for vCenter 8.0 U2 - 9.1 (no '
                'restart); choose the plain version of the target ("VMware vCenter Server"), '
                'which waits for vCenter\'s restart' % (V.version_words(ver), self.version_label),
                retry=False)
        if ver[:2] > self.vc_checked_to:
            self.ctx.step('vCenter %s is newer than the documents this module version was '
                          'checked against (9.1)' % V.version_words(ver), 'warn')

    def test(self):
        self.check_version()
        words = VCenterTarget.test(self)
        ver = self.vc_version()
        return words + ('; vCenter %s' % V.version_words(ver) if ver else '')

    def deploy(self, bundle, options):
        options = options or {}
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('vCenter takes an RSA key only for its machine SSL certificate '
                              '(2048 - 8192 bits): choose an RSA key for this certificate',
                              retry=False)
        self.check_version()
        force = as_bool(options.get('force'))
        self.login()
        try:
            if not force and self.is_current(bundle, self.current()):
                self.remember(bundle, options)
                return self.same(bundle, 'served by vCenter')
            chain, root = split_chain(bundle, options.get('root_pem'))
            if as_bool(self.opt(options, 'trust_chain', True), True):
                certs = chain + ([root] if root else [])
                if certs:
                    try:
                        self.req('POST', ROOTS, {'cert_chain': {'cert_chain': certs}},
                                 what='adding the chain to the trusted roots')
                        self.ctx.step('the chain is among the trusted roots', 'ok')
                    except PluginError as e:
                        self.ctx.step('the chain was not added (there already?): %s' % e, 'warn')
            body = {'cert': text(bundle.as_format('cert-pem')),
                    'key': text(bundle.as_format('key-pem'))}
            if root:
                body['root_cert'] = root
            try:
                self.req('PUT', TLS, body, what='replacing the machine SSL certificate',
                         timeout=300)
            except PluginError as e:
                if 'said 400' not in str(e) or not re.search(
                        r'already[_ ]?exists', '%s %s' % (e, e.detail or ''), re.I):
                    raise
                self.ctx.step('vCenter serves this certificate already (AlreadyExists)')
                self.remember(bundle, options)
                return self.same(bundle, 'served by vCenter')
            self.ctx.step('vCenter took the certificate - no restart from 8.0 U2, new '
                          'connections get it', 'ok')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'machine SSL certificate of %s replaced (no restart)' % self.c('host')

    served_wait = (6, 10)

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = join_hostport(self.c('host'), as_int(self.c('port', 443), 443))
        options.setdefault('verify_tries', 6)
        options.setdefault('verify_wait', 10)
        return HttpTarget.verify(self, bundle, options)
