# -*- coding: utf-8 -*-
"""
Supermicro BMC (X12/H12, X13/H13, X14/H14): the HTTPS certificate of the BMC (web
interface and Redfish) uploaded with Supermicro's own Redfish action - which needs no
licence, unlike the standard CertificateService (SFT-DCMS-SINGLE).

    GET  /redfish/v1/                                     -> Links.Sessions
    POST <Sessions> {UserName, Password}                  -> X-Auth-Token  (or HTTP Basic)
    GET  /redfish/v1/UpdateService/Oem/Supermicro/SSLCert                   (Try; licence "Standard")
    POST /redfish/v1/UpdateService/Oem/Supermicro/SSLCert/Actions/SmcSSLCert.Upload
         multipart/form-data: cert_file (the certificate + chain, PEM), key_file (the key, PEM)
    POST /redfish/v1/Managers/1/Actions/Manager.Reset {"ResetType": "GracefulRestart"}  (asked)

Sources (2026-11): Supermicro Redfish User's Guide 1.22.2-00.04 / 1.23.2-00.00, "Updating
SSL Certificate and Key" (SmcSSLCert.Upload, form-data cert_file and key_file) and
"Available APIs" (SSLCert and the action: licence "Standard"; CertificateService: SFT-DCMS-
SINGLE), Redfish User Guide 4.0 (X12/H12 - the same, "Standard"). The guide names no HTTP
method for the action: a Redfish action is a POST. The BMC restarts its web server after
an upload; a BMC "cold reset" (Manager.Reset) only when it still serves the old one.

One module: the same call on X12 - X14 / H12 - H14. Not used: X11's
/redfish/v1/UpdateService/SSLCert/Actions/SSLCert.Upload (from a guide not read) and Gen 15's
renamed OEM paths (not documented yet). With the SFT-DCMS-SINGLE licence, the standard
target "redfish" works too ("Send as" PEM: Supermicro's ReplaceCertificate takes PEM only).
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, as_int, verify_fields, multipart)
from acmelib.plugins.targets.redfish import RedfishTarget

SSLCERT = '/redfish/v1/UpdateService/Oem/Supermicro/SSLCert'
UPLOAD = SSLCERT + '/Actions/SmcSSLCert.Upload'


class SupermicroBmcTarget(RedfishTarget):
    kind = 'supermicro_bmc'
    discovery = False
    title = 'Supermicro BMC (SSL certificate upload)'
    vendor = 'Supermicro'
    description = ('Uploads the HTTPS certificate and key of a Supermicro BMC (X12/H12, X13/H13, '
                   'X14/H14) with Supermicro\'s Redfish action SmcSSLCert.Upload - no licence '
                   'needed - and resets the BMC when asked; the server itself is not touched.')
    doc = 'targets.md'
    fields = [f if f['key'] not in ('user', 'host') else dict(f, default='svc-cert') if f['key'] == 'user'
              else dict(f, placeholder='bmc.example.local')
              for f in RedfishTarget.fields]
    deploy_fields = [
        field('with_chain', 'Send the chain with the certificate', 'bool', default=True,
              help='cert_file holds the certificate and the intermediates (off: the '
                   'certificate alone)'),
        field('reset', 'Reset the BMC afterwards', 'bool', default=False,
              help='Manager.Reset GracefulRestart ("BMC cold reset") - only when the BMC still '
                   'serves the old certificate after the upload; the server is not touched'),
    ] + verify_fields()

    def test(self):
        root = self.login()
        try:
            m = self.get(self.manager(), what='reading the manager')
            self.get(SSLCERT, what='reading the SSL certificate (Oem/Supermicro/SSLCert)')
            return 'signed in to %s: %s, BMC firmware %s - the SSL certificate upload is there' % (
                self.c('host'), m.get('Model', m.get('Name', root.get('Vendor', '?'))),
                m.get('FirmwareVersion', '?'))
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the BMC')
        cert = bundle.as_format('fullchain-pem' if as_bool(self.opt(options, 'with_chain', True),
                                                             True) else 'cert-pem')
        body, ctype = multipart([
            ('cert_file', ('acme-cert.pem', cert, 'application/x-pem-file')),
            ('key_file', ('acme-key.pem', bundle.as_format('key-pem'), 'application/x-pem-file')),
        ])
        self.login()
        try:
            try:
                self.req('POST', UPLOAD, body, headers={'Content-Type': ctype},
                         what='uploading the certificate (SmcSSLCert.Upload)', timeout=120)
            except PluginError as e:
                if '(404)' in str(e) or '(405)' in str(e):
                    raise PluginError('%s - this BMC has no SmcSSLCert.Upload (X11 and older '
                                      'firmware: the web interface, Configuration → SSL '
                                      'Certificate)' % e, detail=e.detail, retry=False)
                raise
            self.ctx.step('the BMC took the certificate and the key', 'ok')
            did = 'uploaded the HTTPS certificate'
            if as_bool(options.get('reset')):
                mgr = self.manager()
                self.req('POST', mgr + '/Actions/Manager.Reset', {'ResetType': 'GracefulRestart'},
                         ok=(200, 202, 204), what='resetting the BMC')
                self.ctx.step('the BMC resets (a few minutes)', 'ok')
                did += ', the BMC resets'
                self.session_uri = None
        finally:
            self.logout()
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        """The web server restarts after an upload (a minute); a reset takes minutes."""
        return (20, 15) if as_bool((options or {}).get('reset')) else (8, 10)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        options.setdefault('verify_tries', 8)
        options.setdefault('verify_wait', 10)
        return RedfishTarget.verify(self, bundle, options)

