# -*- coding: utf-8 -*-
"""
Veeam Cloud Connect (service provider): the TLS certificate the cloud gateways show the
tenants, replaced on the provider's backup server through Veeam's PowerShell module over
OpenSSH:

    Import-PfxCertificate ... Cert:\\LocalMachine\\My        (a one-time PKCS#12)
    $c = Get-VBRCloudGatewayCertificate -FromStore | Where-Object Thumbprint -eq <thumb>
    Add-VBRCloudGatewayCertificate -Certificate $c
    Get-VBRCloudGatewayCertificate                             (the one used now)

The same in VBR 12.3 and 13.0 - 13.1 (one module, no versions). Unlike the backup server
certificate, Cloud Connect takes a web server certificate of a public or third-party CA,
a wildcard or one with several FQDNs - each cloud gateway's DNS name must be covered.

Sources (the vendor guide navody/certifikaty/veeam/cloud-connect.md, 2026-11, citing):
    https://helpcenter.veeam.com/docs/vbr/cloud/cloud_connect_ssl.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/cloud/cloud_connect_ssl_types.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/cloud/cloud_connect_ssl_rights.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/cloud/cloud_connect_import_ssl.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrcloudgatewaycertificate.html
    https://helpcenter.veeam.com/docs/vbr/powershell/add-vbrcloudgatewaycertificate.html
    https://helpcenter.veeam.com/archive/backup/120/powershell/add-vbrcloudgatewaycertificate.html

Less certain: the property name Thumbprint of the certificate object; the FromFile set of
Add-VBRCloudGatewayCertificate is not used (its reference contradicts itself - the store is);
a gateway on port 6180 speaks Veeam's own protocol, so acme makes no TLS test of it.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import PluginError, field, sha1_thumb, as_bool
from acmelib.plugins.targets._veeam import VeeamPsTarget, keep_field


class VeeamCloudConnectTarget(VeeamPsTarget):
    kind = 'veeam_cloud_connect'
    discovery = False
    title = 'Veeam Cloud Connect (cloud gateway certificate)'
    description = ('Replaces the TLS certificate of Veeam Cloud Connect on the service '
                   'provider\'s backup server (Windows, PowerShell over SSH): imported into '
                   'the machine store, set by Add-VBRCloudGatewayCertificate. Veeam Backup & '
                   'Replication 12.3 and 13.0 - 13.1.')
    deploy_fields = [
        field('trust_chain', 'Add the CA certificates to the machine\'s stores', 'bool',
              default=True, advanced=True,
              help='the intermediates into Intermediate Certification Authorities, a root into '
                   'Trusted Root: Veeam refuses a certificate whose chain is not trusted there'),
        keep_field(1),
    ]

    def current(self, s):
        rc, out, err = self.ps(s, '\n'.join([
            self.module_line(),
            "try { $cur = Get-VBRCloudGatewayCertificate -ErrorAction Stop; Write-Output "
            "('CURRENT ' + $cur.Thumbprint) } catch { Write-Output 'CURRENT' }",
        ]), 'reading the Cloud Connect certificate', timeout=self.timeout_s())
        return (self.said(out, 'CURRENT') or [''])[-1].upper()

    def test(self):
        with self.ssh() as s:
            who = self.admin_check(s)
            cur = self.current(s)
        return 'signed in as %s; Cloud Connect certificate %s' % (who, cur[:12] or 'none yet')

    def deploy(self, bundle, options):
        options = options or {}
        thumb = sha1_thumb(bundle)
        with self.ssh() as s:
            cur = self.current(s)
            if self.unchanged(bundle, options, present=lambda: cur == thumb):
                return self.same(bundle, 'as the Cloud Connect certificate')
            # the decision said (What happens): the certificate there now
            self.ctx.step('Cloud Connect uses %s now - it is replaced' % (cur or 'none read'))
            pfx, pw = self.upload_pfx(s, bundle, options)
            sc = [self.module_line()] + self.import_lines(
                bundle, options, pfx, pw,
                trust_chain=as_bool(self.opt(options, 'trust_chain', True), True)) + [
                "$c = Get-VBRCloudGatewayCertificate -FromStore | Where-Object { "
                "$_.Thumbprint -eq $thumb } | Select-Object -First 1",
                "if (-not $c) { throw ('Get-VBRCloudGatewayCertificate -FromStore does not offer '"
                " + $thumb + ' - is its chain trusted on this server, and may the Veeam Cloud "
                "Connect Service account read its private key?') }",
                "$prev = ''; try { $prev = (Get-VBRCloudGatewayCertificate).Thumbprint } catch { }",
                "Add-VBRCloudGatewayCertificate -Certificate $c | Out-Null",
                "Write-Output 'STEP ok Cloud Connect uses the new certificate'",
                "$used = @($thumb, $prev)",
            ] + self.cleanup_lines(bundle, options)
            try:
                rc, out, err = self.ps(s, '\n'.join(sc), 'setting the Cloud Connect certificate',
                                       timeout=self.timeout_s())
            except PluginError:
                self.drop_file(s, pfx)
                raise
            self.steps_of(out)
        self.ctx.step('tenants that verify the thumbprint (a self-signed or private CA '
                      'certificate) need the new one: %s' % thumb, 'info')
        self.remember(bundle, options)
        return 'Cloud Connect certificate %s set' % thumb[:12]
