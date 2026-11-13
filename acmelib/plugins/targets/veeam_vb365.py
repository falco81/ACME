# -*- coding: utf-8 -*-
"""
Veeam Backup for Microsoft 365 v8: the certificate of its REST API (port 4443 - the Restore
Portal, Veeam Service Provider Console and Veeam ONE talk to it), and as asked the server
certificate (backup proxies in a workgroup), the restore operator and the tenant
authentication certificates - each set from a PKCS#12 file by Veeam's own cmdlets, on the
VB365 server over OpenSSH:

    Set-VBORestAPISettings -EnableService -HTTPSPort <port>
                           -CertificateFilePath <pfx> -CertificatePassword <SecureString>
    Set-VBOSecuritySettings -CertificateFilePath <pfx> -CertificatePassword <..> -Force
    Set-VBOOperatorAuthenticationSettings -EnableAuthentication -CertificateFilePath ...
    Set-VBOTenantAuthenticationSettings -EnableAuthentication -CertificateFilePath ...

One module: VB365 8.x (the guide's build 8.6.0.5011) - no versions to tell apart.

Sources (the vendor guide navody/certifikaty/veeam/vb365.md, 2026-11, citing):
    https://helpcenter.veeam.com/docs/vbo365/guide/vbo_ssl_certificates_overview.html?ver=8
    https://helpcenter.veeam.com/docs/vbo365/guide/vbo_rest_api_settings.html?ver=8
    https://helpcenter.veeam.com/docs/vbo365/guide/vbo_security_settings.html?ver=8
    https://helpcenter.veeam.com/docs/vbo365/powershell/set-vborestapisettings.html
    https://helpcenter.veeam.com/docs/vbo365/powershell/set-vbosecuritysettings.html
    https://helpcenter.veeam.com/docs/vbo365/powershell/set-vbooperatorauthenticationsettings.html
    https://helpcenter.veeam.com/docs/vbo365/powershell/set-vbotenantauthenticationsettings.html

Less certain: the module's name Veeam.Archiver.PowerShell (not in the guide); the examples
of the reference give a folder to -CertificateFilePath, a PFX file is what is meant; whether
the REST API service restarts by itself (not said); the Restore Portal certificate is not
set here - it must be the one of its Microsoft Entra application, changed there first.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, as_int, verify_fields)
from acmelib.plugins.targets._veeam import VeeamPsTarget, ps_str

PARTS = (('rest', 'Set-VBORestAPISettings -EnableService -HTTPSPort %d -CertificateFilePath $pfx '
                  '-CertificatePassword $pw', 'the REST API'),
         ('server', 'Set-VBOSecuritySettings -CertificateFilePath $pfx -CertificatePassword $pw '
                    '-Force', 'the server certificate'),
         ('operator', 'Set-VBOOperatorAuthenticationSettings -EnableAuthentication '
                      '-CertificateFilePath $pfx -CertificatePassword $pw',
          'restore operator authentication'),
         ('tenant', 'Set-VBOTenantAuthenticationSettings -EnableAuthentication '
                    '-CertificateFilePath $pfx -CertificatePassword $pw',
          'tenant authentication'))


class VeeamVb365Target(VeeamPsTarget):
    kind = 'veeam_vb365'
    discovery = False
    title = 'Veeam Backup for Microsoft 365'
    description = ('Sets the REST API certificate of Veeam Backup for Microsoft 365 v8 (and, as '
                   'asked, the server, restore operator and tenant authentication ones) from a '
                   'PKCS#12 through its PowerShell cmdlets over SSH.')
    ps_module = 'Veeam.Archiver.PowerShell'
    deploy_fields = [
        field('rest', 'REST API certificate', 'bool', default=True,
              help='Set-VBORestAPISettings: the REST service enabled on the HTTPS port below'),
        field('rest_port', 'REST API HTTPS port', 'number', default=4443,
              help='the Restore Portal\'s address uses the same port'),
        field('server', 'Server certificate (workgroup backup proxies)', 'bool', default=False,
              help='Set-VBOSecuritySettings; VB365 tells the proxies by itself'),
        field('operator', 'Restore operator authentication certificate', 'bool',
              default=False, advanced=True),
        field('tenant', 'Tenant authentication certificate', 'bool', default=False,
              advanced=True),
    ] + verify_fields(4443)
    default_verify_port = 4443

    def chosen(self, options):
        return [p for p in PARTS if as_bool(self.opt(options, p[0], p[0] == 'rest'),
                                            p[0] == 'rest')]

    def test(self):
        with self.ssh() as s:
            who = self.admin_check(s)
            rc, out, err = self.ps(s, '\n'.join([
                self.module_line(),
                "$r = Get-VBORestAPISettings",
                "Write-Output ('REST ' + $r.IsServiceEnabled + ' ' + $r.HTTPSPort)",
            ]), 'reading the REST API settings', timeout=self.timeout_s())
        got = (self.said(out, 'REST') or ['? ?'])[-1]
        return 'signed in as %s; REST API enabled/port: %s' % (who, got)

    def deploy(self, bundle, options):
        options = options or {}
        parts = self.chosen(options)
        if not parts:
            raise PluginError('nothing to set: tick at least one certificate', retry=False)
        port = as_int(self.opt(options, 'rest_port', 4443), 4443)
        if not 0 < port < 65536:
            raise PluginError('the REST API port %s is not a port' % port, retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'as %s' % ', '.join(p[2] for p in parts))
        with self.ssh() as s:
            path, pw = self.upload_pfx(s, bundle, options)
            sc = [self.module_line(),
                  "$pfx = %s" % ps_str(path),
                  "$pw = ConvertTo-SecureString -String %s -AsPlainText -Force" % ps_str(pw)]
            for key, cmd, words in parts:
                sc += [(cmd % port) if key == 'rest' else cmd,
                       "Write-Output %s" % ps_str('STEP ok %s uses the new certificate' % words)]
            sc.append("Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue")
            try:
                rc, out, err = self.ps(s, '\n'.join(sc), 'setting the certificates',
                                       timeout=self.timeout_s())
            except PluginError:
                self.drop_file(s, path)
                raise
            self.steps_of(out)
        self.remember(bundle, options)
        return 'set for %s' % ', '.join(p[2] for p in parts)

    def served_places(self, options):
        if not self.c('host') or not as_bool(self.opt(options, 'rest', True), True):
            return []
        return [(self.c('host'), as_int(self.opt(options, 'rest_port', 4443), 4443))]
