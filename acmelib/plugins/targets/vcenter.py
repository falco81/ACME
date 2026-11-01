# -*- coding: utf-8 -*-
"""
VMware vCenter Server 7.0 and later (vSphere Automation REST API): the
machine SSL certificate (the one rhttpproxy serves, the vSphere Client's)
replaced; the chain added to the trusted roots first. vCenter restarts its
services after it - the vSphere Client is away for several minutes.

    POST   /api/session                         (basic auth) -> the session id
    GET    /api/vcenter/certificate-management/vcenter/tls      the one there now
    POST   /api/vcenter/certificate-management/vcenter/trusted-root-chains
           {"cert_chain": {"cert_chain": [PEM, ...]}}
    PUT    /api/vcenter/certificate-management/vcenter/tls
           {"cert": PEM, "key": PEM, "root_cert": PEM}
    DELETE /api/session

Rights: a user with CertificateManagement.Administer (Administrators of
vsphere.local have it).

Sources:
    https://developer.broadcom.com/xapis/vsphere-automation-api/latest/vcenter/certificate_management-vcenter/tls
    https://developer.broadcom.com/xapis/vsphere-automation-api/latest/data-structures/Vcenter%20CertificateManagement%20Vcenter%20Tls%20Spec
    https://developer.broadcom.com/xapis/vsphere-automation-api/latest/vcenter/certificate_management-vcenter/trusted_root_chains
    https://github.com/vmware/vsphere-automation-sdk-python/blob/master/samples/vsphere/vcenter/certificatemanagement/replace_tls_certificate.py
Uncertain: whether "cert" should hold the leaf alone or the leaf and its
intermediates (the SDK sample sends one certificate; the intermediates go
into the trusted roots here, which vCenter needs either way); the name of
the TLS info's thumbprint (taken as SHA-1 or SHA-256, either compared).
"""
from __future__ import annotations

import base64

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, fp_of, norm_fp, sha1_thumb,
    http_fields, tls_fields, verify_fields, text, as_int)
from acmelib.plugins.targets._x509 import split_chain

TLS = '/api/vcenter/certificate-management/vcenter/tls'
ROOTS = '/api/vcenter/certificate-management/vcenter/trusted-root-chains'


class VCenterTarget(HttpTarget):
    kind = 'vcenter'
    title = 'VMware vCenter Server'
    vendor = 'VMware'
    description = ('Replaces the machine SSL certificate of vCenter 7/8 through its REST API '
                   '(the chain added to the trusted roots first); vCenter restarts its '
                   'services.')
    doc = 'targets.md'
    fields = http_fields(443, 'vcenter.example.local') + [
        field('user', 'User', 'text', required=True, default='administrator@vsphere.local'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='The root the chain ends in (ISRG Root X1 for Let\'s Encrypt), when vCenter '
                   'does not trust it yet; empty: the last certificate of the chain'),
        field('trust_chain', 'Add the chain to the trusted roots', 'bool', default=True,
              help='vCenter takes a certificate only when it trusts its issuers'),
    ] + verify_fields()

    session = None

    def auth_headers(self):
        return {'vmware-api-session-id': self.session} if self.session else {}

    def login(self):
        basic = base64.b64encode(('%s:%s' % (self.c('user'), self.c('password') or ''))
                                 .encode()).decode()
        try:
            st, hd, d = self.req('POST', '/api/session',
                                 headers={'Authorization': 'Basic ' + basic},
                                 auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry='(401)' not in str(e))
        tok = d if isinstance(d, str) else text(d).strip().strip('"')
        if not tok:
            raise PluginError('vCenter gave no session on signing in')
        self.session = tok
        return tok

    def logout(self):
        if self.session:
            try:
                self.req('DELETE', '/api/session', ok=range(0, 600))
            except PluginError:
                pass
            self.session = None

    def current(self):
        st, hd, d = self.req('GET', TLS, what='reading the certificate there now')
        return d if isinstance(d, dict) else {}

    def is_current(self, bundle, info):
        tp = norm_fp(info.get('thumbprint'))
        return bool(tp) and tp in (sha1_thumb(bundle).lower(), fp_of(bundle))

    def test(self):
        self.login()
        try:
            info = self.current()
            return 'signed in to %s; its certificate: %s, valid to %s' % (
                self.c('host'), info.get('subject_dn', '?'), info.get('valid_to', '?'))
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
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
                        # there already, mostly
                        self.ctx.step('the chain was not added (there already?): %s' % e, 'warn')
            body = {'cert': text(bundle.as_format('cert-pem')),
                    'key': text(bundle.as_format('key-pem'))}
            if root:
                body['root_cert'] = root
            self.req('PUT', TLS, body, what='replacing the machine SSL certificate',
                     timeout=300)
            self.ctx.step('vCenter took the certificate and restarts its services (minutes)',
                          'ok')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'machine SSL certificate of %s replaced; its services restart' % self.c('host')

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = '%s:%d' % (self.c('host'), as_int(self.c('port', 443), 443))
        options.setdefault('verify_tries', 20)
        options.setdefault('verify_wait', 15)
        return HttpTarget.verify(self, bundle, options)

