# -*- coding: utf-8 -*-
"""
What the Veeam targets share (not a module: the registry skips files starting with "_"):
a Windows server signed in to over OpenSSH, PowerShell run there the way windows_ssh runs
it (as -EncodedCommand, or an uploaded .ps1 that deletes itself when it is too long for
cmd.exe), the certificate put into LocalMachine\\My from a one-time PKCS#12, its CA
certificates into the Intermediate / Trusted Root stores, and older acme ones taken away.

    veeam_vbr.py            Veeam Backup & Replication - the backup server certificate
    veeam_cloud_connect.py  Veeam Cloud Connect - the cloud gateway certificate
    veeam_vb365.py          Veeam Backup for Microsoft 365 - REST API / server certificates
"""
from __future__ import annotations

import re
import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_int, ssh_fields, keep_field, object_name,
    name_prefix, sha1_thumb, random_password, chain_list, put_scp, text)
from acmelib.plugins.targets import _win_roles as WR
from acmelib.plugins.targets.windows_ssh import ps_str

__all__ = ['VeeamPsTarget', 'ps_str', 'win_fields', 'keep_field']


def win_fields():
    """The sign-in to the Windows server (the same as windows_ssh's)."""
    return ssh_fields(sudo=False, user_default='Administrator', howto='windows',
                      try_command='whoami') + [
        field('tmp_dir', 'Folder for uploads', 'text', default='C:/Windows/Temp',
              advanced=True, help='where the one-time PKCS#12 is put before the import; it '
                                  'is deleted right after'),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ]


class VeeamPsTarget(SshMixin, Base):
    """A Veeam server on Windows, reached over OpenSSH (the account an administrator of the
    machine and holding the Veeam role the module says)."""
    kind = ''
    discovery = False           # nothing to find: a server over SSH
    vendor = 'Veeam'
    doc = 'targets.md'
    fields = win_fields()
    ps_module = 'Veeam.Backup.PowerShell'

    # -- PowerShell over SSH (windows_ssh's machinery) -------------------------------------
    def _roles_tmp(self):
        return (self.c('tmp_dir') or 'C:/Windows/Temp').rstrip('/\\')

    def ps(self, s, script, what='PowerShell', check=True, timeout=600):
        """-> (rc, out, err); a failure in words (its last "ERROR: " line)."""
        return WR.RolesMixin.roles_ps(self, s, script, what=what, check=check, timeout=timeout)

    def module_line(self):
        # -WarningAction: Veeam's module warns about its own version on every load
        return ("Import-Module %s -ErrorAction Stop -WarningAction SilentlyContinue "
                "-DisableNameChecking" % self.ps_module)

    @staticmethod
    def said(out, word):
        """The values of the lines 'WORD value' a script wrote."""
        return [ln.strip()[len(word) + 1:].strip() for ln in text(out).splitlines()
                if ln.strip().startswith(word + ' ') or ln.strip() == word]

    def steps_of(self, out):
        for line in text(out).splitlines():
            m = re.match(r'^STEP (ok|info|warn|bad) (.*)$', line.strip())
            if m:
                self.ctx.step(m.group(2), m.group(1))

    def admin_check(self, s):
        rc, out, err = self.ps(s, (
            "$adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
            "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
            "Write-Output (\"WHO $env:USERNAME|$adm\")"), 'signing in')
        who = (self.said(out, 'WHO') or ['?|?'])[-1].split('|') + ['?']
        if who[1].strip().lower() != 'true':
            raise PluginError('signed in as %s, but not as an administrator of the machine '
                              '(elevated) - the certificate store and Veeam\'s cmdlets need one'
                              % who[0], retry=False)
        return who[0]

    # -- the certificate in LocalMachine\My ------------------------------------------------
    def upload_pfx(self, s, bundle, options):
        """The PKCS#12 (3DES - any Windows) with a one-time password. -> (path, password)"""
        pw = random_password()
        data = bundle.as_format('p12-legacy', password=pw, alias=object_name(bundle, options))
        path = '%s/acme-%s.pfx' % (self._roles_tmp(), secrets.token_hex(6))
        put_scp(s, data, path)
        return path, pw

    def import_lines(self, bundle, options, pfx, pw, keep_file=False, trust_chain=True):
        """PowerShell: the certificate into LocalMachine\\My (once: it may be there from the
        last time), named acme-<name>-<date>-<serial>; its CA certificates into the
        Intermediate (CA) and Trusted Root stores - Veeam refuses a certificate whose chain
        the server does not trust. $thumb, $cert, $pw are set for what follows."""
        thumb = sha1_thumb(bundle)
        sc = [
            "$thumb = %s" % ps_str(thumb),
            "$pw = ConvertTo-SecureString -String %s -AsPlainText -Force" % ps_str(pw),
            "$store = 'Cert:\\LocalMachine\\My'",
            "if (-not (Test-Path (Join-Path $store $thumb))) {",
            "  Import-PfxCertificate -FilePath %s -CertStoreLocation $store -Password $pw "
            "| Out-Null" % ps_str(pfx),
            "  Write-Output 'STEP ok imported the certificate into LocalMachine\\My'",
            "} else { Write-Output 'STEP info the certificate is in LocalMachine\\My already' }",
            "$cert = Get-Item (Join-Path $store $thumb)",
            "$cert.FriendlyName = %s" % ps_str(object_name(bundle, options)),
        ]
        if not keep_file:
            sc.append("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue"
                      % ps_str(pfx))
        if trust_chain:
            for pem in chain_list(bundle):
                body = ''.join(pem.strip().splitlines()[1:-1])
                sc += [
                    "$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2"
                    "(,[Convert]::FromBase64String(%s))" % ps_str(body),
                    "$where = if ($ca.Subject -eq $ca.Issuer) { 'Root' } else { 'CA' }",
                    "if (-not (Test-Path (Join-Path ('Cert:\\LocalMachine\\' + $where) "
                    "$ca.Thumbprint))) { $st = New-Object System.Security.Cryptography."
                    "X509Certificates.X509Store($where, 'LocalMachine'); $st.Open('ReadWrite'); "
                    "$st.Add($ca); $st.Close(); Write-Output ('STEP ok ' + $ca.Subject + "
                    "' added to LocalMachine\\' + $where) }",
                ]
        return sc

    def cleanup_lines(self, bundle, options, used_var='$used'):
        """PowerShell: older acme certificates of this one beyond keep - never the new one,
        never one in `used_var` (the thumbprints Veeam still uses)."""
        keep = self.keep(options)
        if keep < 0:
            return []
        return [
            "$old = Get-ChildItem 'Cert:\\LocalMachine\\My' | Where-Object { $_.FriendlyName "
            "-match ('^' + [regex]::Escape(%s) + '\\d{8}-[0-9a-f]+$') -and $_.Thumbprint -ne "
            "$thumb } | Sort-Object NotBefore -Descending | Select-Object -Skip %d"
            % (ps_str(name_prefix(bundle, options)), keep),
            "foreach ($o in $old) { if (@(%s) -contains $o.Thumbprint) { Write-Output ('STEP "
            "warn the old ' + $o.Thumbprint + ' is still used: kept') } else { Remove-Item "
            "-LiteralPath $o.PSPath; Write-Output ('STEP info removed the old ' + "
            "$o.Thumbprint) } }" % used_var,
        ]

    def drop_file(self, s, path):
        if hasattr(self.ctx, 'tidying'):
            with self.ctx.tidying():
                return self.ps(s, "Remove-Item -LiteralPath %s -Force -ErrorAction "
                                  "SilentlyContinue" % ps_str(path), 'cleaning up', check=False)
        return self.ps(s, "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue"
                       % ps_str(path), 'cleaning up', check=False)

    def timeout_s(self):
        return max(60, as_int(self.c('timeout', 60), 60) * 10)
