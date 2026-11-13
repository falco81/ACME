# -*- coding: utf-8 -*-
"""
VMware ESX(i) host certificate - the versions of the "esxi" target besides the plain one
(1.0.94). The plain one (esxi.py) writes rui.crt / rui.key over SSH and restarts hostd and
vpxa: the same on every ESXi, kept as it is.

  '8.0.3'   ESXi 8.0 U3 - 9.1, through vCenter's vSphere Web Services API (VI JSON):
            no SSH, no maintenance mode, no restart. The host's HostCertificateManager
            takes the key and the certificate and tells its services:

    GET  /sdk/vim25/<rel>/ServiceInstance/ServiceInstance/content      (no sign-in) about,
                                                                       sessionManager
    POST /sdk/vim25/<rel>/SessionManager/<sm>/Login {"userName","password"}
                                     -> the header vmware-api-session-id
    GET  /sdk/vim25/<rel>/HostSystem/<host-id>/summary                  the ESX version
    GET  /sdk/vim25/<rel>/HostSystem/<host-id>/configManager            certificateManager
    POST /sdk/vim25/<rel>/HostCertificateManager/<hcm>/ProvisionServerPrivateKey {"key"}
    POST /sdk/vim25/<rel>/HostCertificateManager/<hcm>/InstallServerCertificate  {"cert"}
    POST /sdk/vim25/<rel>/HostCertificateManager/<hcm>/NotifyAffectedServices    {}
    POST /sdk/vim25/<rel>/SessionManager/<sm>/Logout

  and first, when asked, the chain among vCenter's trusted roots (vSphere Automation API):
    POST /api/session (basic) ; POST /api/vcenter/certificate-management/vcenter/
         trusted-root-chains {"cert_chain": {"cert_chain": [PEM, ...]}} ; DELETE /api/session

Sources (navody/certifikaty/vmware/esxi.md, 2026-11): Managing Certificates for ESX Hosts
(vSphere 9.0 / 9.1 - replacement without maintenance mode from 8.0 U3), vSphere Web Services API
HostCertificateManager (ProvisionServerPrivateKey and NotifyAffectedServices: API 8.0.3.0;
"old SSL connections typically survive the transition ... new SSL connections will use the new
SSL credentials"), VI JSON API 8.0.3 - Host Certificate Manager, Getting started; Update the
vCenter TRUSTED_ROOTS Store (the chain first, else the host disconnects); Certificate.Manage.
Less certain (said in the guide): GET HostSystem/<id>/configManager and /summary follow the
API's GET /<type>/<moId>/<property> pattern (the reference shows it for a VM); the release
8.0.3.0 on a vCenter 9.x (it serves the older releases - a release field changes it).
"""
from __future__ import annotations

import base64

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, tls_fields, verify_fields, family_of,
    join_hostport)
from acmelib.plugins.targets import _vmware as V

TRUST = '/api/vcenter/certificate-management/vcenter/trusted-root-chains'


class EsxiApi803Target(HttpTarget):
    """ESXi 8.0 U3 - 9.1 through vCenter's HostCertificateManager: no SSH, no restart."""
    kind = 'esxi'
    module_version = '8.0.3'
    version_label = 'ESXi 8.0 U3 - 9.1 (through vCenter)'
    title = 'VMware ESXi host (SSH)'
    vendor = 'VMware'
    discovery = False
    description = ('ESXi 8.0 U3 - 9.1 (through vCenter): puts the key and the certificate on the '
                   'host through vCenter\'s vSphere API (HostCertificateManager '
                   'ProvisionServerPrivateKey, InstallServerCertificate, '
                   'NotifyAffectedServices) - no SSH, no maintenance mode, no restart; the chain '
                   'added to vCenter\'s trusted roots first. Refused on a host that says an '
                   'older ESXi.')
    doc = 'targets.md'
    fields = [
        field('host', 'vCenter address', 'text', required=True,
              placeholder='vcenter.example.local', help='the vCenter that manages the host'),
        field('port', 'HTTPS port', 'number', default=443),
        field('user', 'User', 'text', required=True, placeholder='svc-esxcert@vsphere.local',
              help='a vCenter user with Certificates > Manage Certificates (Certificate.Manage)'),
        field('password', 'Password', 'secret', required=True),
        field('host_id', 'ESX host (managed object id)', 'text', required=True,
              placeholder='host-12',
              help='its id in vCenter: in the vSphere Client address of the host, or '
                   '(Get-VMHost NAME).ExtensionData.MoRef.Value in PowerCLI'),
        field('esx_name', 'ESX host name', 'text', placeholder='esx01.example.local',
              help='the name the host has in vCenter - where acme checks the certificate served '
                   '(port 443); empty: the one vCenter says'),
        field('release', 'API release', 'text', default='8.0.3.0', advanced=True,
              help='the VI JSON API release in the paths (/sdk/vim25/<release>/...); 8.0.3.0 is '
                   'the first with ProvisionServerPrivateKey'),
    ] + tls_fields()
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in (ISRG Root X1 for Let\'s Encrypt), when vCenter '
                   'does not trust it yet; empty: the last certificate of the chain'),
        field('trust_chain', 'Add the chain to vCenter\'s trusted roots', 'bool', default=True,
              help='needed before the host takes the certificate - without it vCenter '
                   'disconnects the host or puts a VMCA certificate back'),
        field('notify', 'Tell the host\'s services', 'bool', default=True, advanced=True,
              help='NotifyAffectedServices: new connections get the new certificate at once'),
    ] + verify_fields()

    esx_min = (8, 0, 3)
    esx_checked_to = (9, 1)
    session = None
    _sm = None
    about = {}

    def rel(self):
        return text(self.c('release') or '8.0.3.0').strip().strip('/') or '8.0.3.0'

    def vi(self, path):
        return '/sdk/vim25/%s/%s' % (self.rel(), path.lstrip('/'))

    def auth_headers(self):
        return {'vmware-api-session-id': self.session} if self.session else {}

    def login(self):
        st, hd, d = self.req('GET', self.vi('ServiceInstance/ServiceInstance/content'), auth=False,
                             what='reading the service content')
        d = d if isinstance(d, dict) else {}
        self._sm = text((d.get('sessionManager') or {}).get('value'))
        self.about = d.get('about') or {}
        if not self._sm:
            raise PluginError('vCenter gave no session manager - is %s a vCenter 8.0 U3 or '
                              'later?' % self.c('host'), retry=False)
        try:
            st, hd, d = self.req('POST', self.vi('SessionManager/%s/Login' % self._sm),
                                 {'userName': text(self.c('user')),
                                  'password': text(self.c('password'))},
                                 auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail,
                              retry=not any(x in str(e) for x in ('(401)', '(403)', 'said 500')))
        sid = text(hd.get('vmware-api-session-id')).strip()
        if not sid:
            raise PluginError('vCenter gave no session (no vmware-api-session-id) on signing in')
        self.session = sid

    def logout(self):
        if self.session and self._sm:
            try:
                self.req('POST', self.vi('SessionManager/%s/Logout' % self._sm), {},
                         ok=range(0, 600))
            except PluginError:
                pass
        self.session = None

    def summary(self):
        st, hd, d = self.req('GET', self.vi('HostSystem/%s/summary' % self.host_id()),
                             ok=(200, 404), what='reading the host')
        if st == 404:
            raise PluginError('vCenter has no host "%s" (its managed object id, as host-12)'
                              % self.host_id(), retry=False)
        return d if isinstance(d, dict) else {}

    def host_id(self):
        return text(self.c('host_id')).strip()

    def esx_version(self, summ):
        prod = ((summ.get('config') or {}).get('product') or {})
        return V.parse_version(prod.get('version')), text(prod.get('fullName') or
                                                           prod.get('version') or '?')

    def check_version(self, summ):
        """Another ESX than this version is for: refused before anything changes."""
        ver, words = self.esx_version(summ)
        if ver is None:
            self.ctx.step('the ESX version cannot be read - going on as for ESXi 8.0 U3 and '
                          'later', 'warn')
            return
        if ver < self.esx_min:
            raise PluginError(
                'the host runs %s - the module version "%s" needs ESXi 8.0 U3 or later '
                '(ProvisionServerPrivateKey); choose the plain version of the target ("VMware '
                'ESXi host (SSH)": over SSH, any ESXi)' % (words, self.version_label), retry=False)
        if ver[:2] > self.esx_checked_to:
            self.ctx.step('ESX %s is newer than the documents this module version was checked '
                          'against (%s)' % (V.version_words(ver),
                                            V.version_words(self.esx_checked_to)), 'warn')

    def esx_name(self, summ=None):
        n = text(self.c('esx_name')).strip()
        if n or summ is None:
            return n
        return text((summ.get('config') or {}).get('name')).strip()

    def hcm(self):
        st, hd, d = self.req('GET', self.vi('HostSystem/%s/configManager' % self.host_id()),
                             what='finding the host\'s certificate manager')
        v = text(((d if isinstance(d, dict) else {}).get('certificateManager') or {}).get('value'))
        if not v:
            raise PluginError('the host %s has no certificate manager in vCenter\'s answer'
                              % self.host_id(), retry=False)
        return v

    def test(self):
        self.login()
        try:
            summ = self.summary()
            ver, words = self.esx_version(summ)
            self.check_version(summ)
            hcm = self.hcm()
            return 'signed in to vCenter %s (%s); host %s: %s, certificate manager %s' % (
                self.c('host'), self.about.get('version', '?'), self.esx_name(summ) or
                self.host_id(), words, hcm)
        finally:
            self.logout()

    def add_trust(self, certs):
        """The chain among vCenter's trusted roots (vSphere Automation API), its own session."""
        basic = base64.b64encode(('%s:%s' % (self.c('user'), self.c('password') or ''))
                                 .encode()).decode()
        st, hd, tok = self.req('POST', '/api/session', auth=False,
                               headers={'Authorization': 'Basic ' + basic},
                               what='signing in to the vSphere Automation API')
        tok = text(tok).strip().strip('"')
        h = {'vmware-api-session-id': tok}
        try:
            self.req('POST', TRUST, {'cert_chain': {'cert_chain': certs}}, auth=False, headers=h,
                     what='adding the chain to vCenter\'s trusted roots')
            self.ctx.step('the chain is among vCenter\'s trusted roots', 'ok')
        except PluginError as e:
            self.ctx.step('the chain was not added (there already?): %s' % e, 'warn')
        finally:
            try:
                self.req('DELETE', '/api/session', auth=False, headers=h, ok=range(0, 600))
            except PluginError:
                pass

    def deploy(self, bundle, options):
        options = options or {}
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('ESX takes RSA keys only (2048 - 8192 bits): choose an RSA key '
                              'for this certificate', retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the host')
        self.login()
        try:
            summ = self.summary()
            self.check_version(summ)
            hcm = self.hcm()
            if as_bool(self.opt(options, 'trust_chain', True), True):
                root = V.root_of(bundle, options.get('root_pem'))
                certs = V.intermediates(bundle) + ([root] if root else [])
                if certs:
                    self.add_trust(certs)
                if not root:
                    self.ctx.step('no root CA certificate given and none in the chain - vCenter '
                                  'must trust the root already', 'warn')
            p = 'HostCertificateManager/%s/' % hcm
            self.req('POST', self.vi(p + 'ProvisionServerPrivateKey'),
                     {'key': text(bundle.as_format('key-pem'))},
                     what='putting the private key on the host')
            self.ctx.step('the key is on the host', 'ok')
            try:
                self.req('POST', self.vi(p + 'InstallServerCertificate'),
                         {'cert': text(bundle.as_format('cert-pem'))},
                         what='installing the certificate')
            except PluginError as e:
                raise PluginError('%s (HostConfigFault: the certificate is refused or does not '
                                  'match the key)' % e if 'said 500' in str(e) else str(e),
                                  detail=e.detail, retry=False)
            self.ctx.step('the host installed the certificate', 'ok')
            if as_bool(self.opt(options, 'notify', True), True):
                self.req('POST', self.vi(p + 'NotifyAffectedServices'), {},
                         what='telling the host\'s services')
                self.ctx.step('the host\'s services told: new connections get it', 'ok')
            name = self.esx_name(summ)
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'installed on the host %s through vCenter' % (name or self.host_id())

    served_wait = (5, 6)

    def served_places(self, options):
        n = self.esx_name()
        return [(n, 443)] if n else []

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify') and self.esx_name():
            options['verify'] = join_hostport(self.esx_name(), 443)
        options.setdefault('verify_tries', 6)
        options.setdefault('verify_wait', 5)
        return HttpTarget.verify(self, bundle, options)

