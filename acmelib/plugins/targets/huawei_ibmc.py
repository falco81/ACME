# -*- coding: utf-8 -*-
"""
Huawei / xFusion iBMC (FusionServer, TaiShan): the HTTPS certificate of the iBMC imported
as a "custom certificate" (PKCS#12 with its password) through the iBMC's Redfish OEM
action, then the iBMC restarted so it serves it.

    GET  /redfish/v1/                                   -> Links.Sessions
    POST <Sessions> {UserName, Password}                -> X-Auth-Token
    POST /redfish/v1/UpdateService/FirmwareInventory    multipart, field "imgfile" = acme-….pfx
                                                        (the file lands in /tmp/web/)
    POST /redfish/v1/Managers/<id>/SecurityService/HttpsCert/Actions/HttpsCert.ImportCustomCertificate
         {"Type": "URI", "Content": "/tmp/web/acme-….pfx", "Password": "…"}
                                                        -> MessageId iBMC.1.0.CertImportOK
    POST /redfish/v1/Managers/<id>/Actions/Manager.Reset {"ResetType": "ForceRestart"}
    GET  /redfish/v1/Managers/<id>/SecurityService/HttpsCert            (Try: read only)

Sources (2026-11): Huawei iRM / iBMC Redfish API Description ("Importing a Custom
Certificate", "Importing a Server Certificate": the actions under SecurityService/HttpsCert,
the body Type + Content with a file in /tmp, iBMC.1.0.CertImportOK "restart the iBMC for the
certificate to take effect"); Huawei-iBMC-Cmdlets (official, GitHub: the upload to /tmp/web
through FirmwareInventory, form field "imgfile"; the Type "URI" + Content shape of the same
iBMC's HwLdapController.ImportCert); Huawei Ansible plug-in 2.0.6 (pfx/p12 allowed in
/tmp/web, up to 2 MB).

Less certain (Huawei's portal shows only excerpts): the name "Password" of the PKCS#12
password member, and whether newer xFusion firmware keeps these paths. iBMC V2/V3 (Huawei
FusionServer V5/V6, TaiShan 200, xFusion) take the same calls - one module.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, as_int, verify_fields, text, multipart, random_password,
    short_serial)
from acmelib.plugins.targets.redfish import RedfishTarget


class HuaweiIbmcTarget(RedfishTarget):
    kind = 'huawei_ibmc'
    discovery = False
    title = 'Huawei / xFusion iBMC'
    vendor = 'Huawei / xFusion'
    description = ('Imports the HTTPS certificate of a Huawei or xFusion iBMC (FusionServer, '
                   'TaiShan; iBMC V2/V3) as a custom certificate (PKCS#12) with the Redfish OEM '
                   'action HttpsCert.ImportCustomCertificate, then restarts the iBMC so it '
                   'serves it - the server keeps running.')
    doc = 'targets.md'
    fields = [f if f['key'] != 'user' else dict(f, default='svc-cert')
              for f in RedfishTarget.fields if f['key'] != 'basic_auth'] + [
        field('manager', 'Manager ID', 'text', default='1', advanced=True,
              help='1 on a rack server; BladeN on a high-density or blade server'),
    ]
    deploy_fields = [
        field('reset', 'Restart the iBMC afterwards', 'bool', default=True,
              help='Manager.Reset ForceRestart - the iBMC serves the new certificate only after '
                   'a restart (iBMC.1.0.CertImportOK); the server is not touched'),
    ] + verify_fields()

    def mgr(self):
        m = text(self.c('manager') or '1').strip().strip('/') or '1'
        if not all(ch.isalnum() or ch in '._-' for ch in m):
            raise PluginError('the Manager ID is letters and digits only (1, Blade1)', retry=False)
        return '/redfish/v1/Managers/%s' % m

    def test(self):
        self.login()
        try:
            hc = self.get(self.mgr() + '/SecurityService/HttpsCert',
                          what='reading the HTTPS certificate (SecurityService/HttpsCert)')
            acts = hc.get('Actions') or {}
            info = hc.get('X509CertificateInformation') or {}
            can = '#HttpsCert.ImportCustomCertificate' in acts if acts else None
            return 'signed in to %s: the iBMC serves %s, valid to %s%s' % (
                self.c('host'), info.get('Subject') or '?', info.get('ValidNotAfter') or '?',
                '' if can is not False else ' - but it lists no HttpsCert.ImportCustomCertificate')
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the iBMC')
        pw = random_password(16)
        fn = 'acme-%s.pfx' % short_serial(bundle)
        pfx = bundle.as_format('p12-legacy', password=pw, alias='acme')
        body, ctype = multipart([('imgfile', (fn, pfx, 'application/octet-stream'))])
        self.login()
        try:
            self.req('POST', '/redfish/v1/UpdateService/FirmwareInventory', body,
                     headers={'Content-Type': ctype}, what='uploading %s to /tmp/web' % fn,
                     timeout=120)
            self.ctx.step('uploaded %s to the iBMC (/tmp/web)' % fn, 'ok')
            st, hd, d = self.req(
                'POST', self.mgr() + '/SecurityService/HttpsCert/Actions/'
                'HttpsCert.ImportCustomCertificate',
                {'Type': 'URI', 'Content': '/tmp/web/%s' % fn, 'Password': pw},
                ok=(200, 202, 204), what='importing the custom certificate', timeout=120)
            said = ' '.join(text(m.get('MessageId')) for m in
                            ((d or {}).get('@Message.ExtendedInfo') or [] if isinstance(d, dict)
                             else []) if isinstance(m, dict))
            self.ctx.step('the iBMC imported the certificate%s' % (
                ' (%s)' % said if said else ''), 'ok')
            did = 'imported the custom certificate'
            if as_bool(self.opt(options, 'reset', True), True):
                self.req('POST', self.mgr() + '/Actions/Manager.Reset',
                         {'ResetType': 'ForceRestart'}, ok=(200, 202, 204),
                         what='restarting the iBMC')
                self.ctx.step('the iBMC restarts (a few minutes; the server keeps running)', 'ok')
                did += ', the iBMC restarts'
                self.session_uri = None
            else:
                self.ctx.step('no restart asked: the iBMC serves the new certificate after its '
                              'next restart', 'warn')
        finally:
            self.logout()
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        return (30, 15) if as_bool((options or {}).get('reset', True), True) else None

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        options.setdefault('reset', True)
        return RedfishTarget.verify(self, bundle, options)
