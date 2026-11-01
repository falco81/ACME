# -*- coding: utf-8 -*-
"""
Windows over OpenSSH: the PFX imported into LocalMachine\\My, bound to IIS
sites, the RDP listener and Exchange as asked; old ones taken away.
"""
from __future__ import annotations

import base64
import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, as_int, object_name, name_prefix,
    ssh_fields, verify_fields, keep_field, sha1_thumb, random_password, text, put_scp)


def ps_str(s):
    """A PowerShell single-quoted string."""
    return "'" + text(s).replace("'", "''") + "'"


def encoded(script):
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


class WindowsSshTarget(SshMixin, Base):
    kind = 'windows_ssh'
    title = 'Windows server (OpenSSH + PowerShell)'
    vendor = 'Microsoft'
    description = ('Imports the certificate into the machine store, binds it to IIS sites, '
                   'the Remote Desktop listener and Exchange as asked, and removes the '
                   'old ones.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='Administrator') + [
        field('tmp_dir', 'Folder for uploads', 'text', default='C:/Windows/Temp', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ]
    deploy_fields = [
        field('iis', 'IIS bindings', 'list',
              placeholder='Default Web Site | www.example.com | 443',
              help='site | host name | port [| ip], one a line. A host name makes an SNI '
                   'binding; none binds the port for all names. Missing https bindings '
                   'are made.'),
        field('rdp', 'Remote Desktop listener', 'bool', default=False),
        field('exchange', 'Exchange services', 'text', advanced=True, placeholder='IIS,SMTP',
              help='Enable-ExchangeCertificate -Services …; empty: not Exchange'),
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (any Windows)'],
                       ['pfx', 'AES-256 (Windows Server 2019 and later)']]),
        field('exportable', 'Key exportable', 'bool', default=False, advanced=True),
        field('post_ps', 'PowerShell after', 'list', advanced=True,
              help='lines run last; $thumb is the new thumbprint'),
        keep_field(1),
    ] + verify_fields()

    def run_ps(self, s, script, what='PowerShell', check=True, timeout=300):
        full = ("$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n"
                "try {\n%s\n} catch { Write-Output ('ERROR: ' + $_.Exception.Message); "
                "exit 1 }\n" % script)
        cmd = ('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
               '-EncodedCommand ' + encoded(full))
        rc, out, err = s.run(cmd, timeout=timeout, check=False)
        out, err = text(out), text(err)
        if check and rc != 0:
            said = [x[7:] for x in out.splitlines() if x.startswith('ERROR: ')]
            raise PluginError('%s failed: %s' % (what, (said[-1] if said else
                                                        (err.strip() or out.strip())[-300:])),
                              detail=out + err)
        return rc, out, err

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.run_ps(s, (
                "$os = (Get-CimInstance Win32_OperatingSystem).Caption\n"
                "$adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
                "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
                "Write-Output (\"$env:USERNAME|$os|$($PSVersionTable.PSVersion)|$adm\")"),
                'signing in')
        last = [x for x in out.splitlines() if '|' in x][-1:] or ['?|?|?|?']
        user, os_, psv, adm = (last[0].split('|') + ['?'] * 4)[:4]
        if adm.strip().lower() != 'true':
            raise PluginError('signed in as %s, but not as an administrator (elevated)' % user,
                              retry=False)
        return 'signed in as %s on %s, PowerShell %s' % (user, os_, psv)

    def script(self, bundle, options, pfx_path, password):
        thumb = sha1_thumb(bundle)
        fname = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        keep = as_int(options.get('keep', 1), 1)
        flags = '-Exportable' if as_bool(options.get('exportable')) else ''
        sc = [
            "$thumb = %s" % ps_str(thumb),
            "$pw = ConvertTo-SecureString -String %s -AsPlainText -Force" % ps_str(password),
            "$store = 'Cert:\\LocalMachine\\My'",
            "if (-not (Test-Path (Join-Path $store $thumb))) {",
            "  Import-PfxCertificate -FilePath %s -CertStoreLocation $store -Password $pw %s "
            "| Out-Null" % (ps_str(pfx_path), flags),
            "}",
            "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % ps_str(pfx_path),
            "$cert = Get-Item (Join-Path $store $thumb)",
            "$cert.FriendlyName = %s" % ps_str(fname),
            "Write-Output \"IMPORTED $thumb\"",
        ]
        iis = []
        for n, line in enumerate(lines(options.get('iis')), 1):
            parts = [p.strip() for p in line.split('|')]
            if not parts[0]:
                raise PluginError('IIS line %d has no site' % n, retry=False)
            site = parts[0]
            host = parts[1] if len(parts) > 1 else ''
            port = as_int(parts[2], 443) if len(parts) > 2 and parts[2] else 443
            ip = parts[3] if len(parts) > 3 and parts[3] else '*'
            iis.append((site, host, port, ip))
        if iis:
            sc.append("Import-Module WebAdministration")
            for site, host, port, ip in iis:
                sni = 1 if host else 0
                sc += [
                    "$b = Get-WebBinding -Name %s -Protocol https -Port %d -HostHeader %s "
                    "| Select-Object -First 1" % (ps_str(site), port, ps_str(host)),
                    "if (-not $b) { New-WebBinding -Name %s -Protocol https -Port %d "
                    "-HostHeader %s -IPAddress %s -SslFlags %d; "
                    "$b = Get-WebBinding -Name %s -Protocol https -Port %d -HostHeader %s "
                    "| Select-Object -First 1 }" % (ps_str(site), port, ps_str(host), ps_str(ip),
                                                    sni, ps_str(site), port, ps_str(host)),
                    "$b.AddSslCertificate($thumb, 'My')",
                    "Write-Output ('IIS ' + %s)" % ps_str('%s %s:%d' % (site, host or ip, port)),
                ]
        if as_bool(options.get('rdp')):
            sc += [
                "$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]"
                "::GetRSAPrivateKey($cert)",
                "if ($rsa -and $rsa.Key) { $kf = $rsa.Key.UniqueName; foreach ($d in "
                "@(\"$env:ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\", "
                "\"$env:ProgramData\\Microsoft\\Crypto\\Keys\")) { $p = Join-Path $d $kf; "
                "if (Test-Path $p) { icacls $p /grant 'NETWORK SERVICE:R' | Out-Null } } }",
                "$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices "
                "-ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\"",
                "Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash=$thumb}",
                "Write-Output 'RDP'",
            ]
        ex = (options.get('exchange') or '').strip()
        if ex:
            services = ','.join(x.strip() for x in ex.replace(';', ',').split(',') if x.strip())
            sc += [
                "if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue))"
                " { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn }",
                "Enable-ExchangeCertificate -Thumbprint $thumb -Services %s -Force "
                "-Confirm:$false" % ps_str(services),
                "Write-Output 'EXCHANGE'",
            ]
        for line in lines(options.get('post_ps')):
            sc.append(line)
        if keep >= 0:
            sc += [
                "$used = @()",
                "if (Get-Module -ListAvailable WebAdministration) { Import-Module WebAdministration;"
                " $used += (Get-ChildItem IIS:\\SslBindings -ErrorAction SilentlyContinue | "
                "ForEach-Object { $_.Thumbprint }) }",
                "$old = Get-ChildItem $store | Where-Object { $_.FriendlyName -like %s -and "
                "$_.Thumbprint -ne $thumb } | Sort-Object NotBefore -Descending | "
                "Select-Object -Skip %d" % (ps_str(prefix + '*'), keep),
                "foreach ($o in $old) { if ($used -contains $o.Thumbprint) { Write-Output "
                "('INUSE ' + $o.Thumbprint) } else { Remove-Item -LiteralPath $o.PSPath; "
                "Write-Output ('REMOVED ' + $o.Thumbprint) } }",
            ]
        return '\n'.join(sc)

    def deploy(self, bundle, options):
        options = options or {}
        thumb = sha1_thumb(bundle)
        with self.ssh() as s:
            if self.unchanged(bundle, options, present=lambda: 'YES' in self.run_ps(
                    s, "if (Test-Path 'Cert:\\LocalMachine\\My\\%s') { 'YES' } else { 'NO' }"
                    % thumb, check=False)[1]):
                return self.same(bundle, 'in the machine store')
            password = random_password()
            fmt = options.get('pfx_format') or 'p12-legacy'
            data = bundle.as_format(fmt, password=password, alias=object_name(bundle, options))
            path = '%s/acme-%s.pfx' % ((self.c('tmp_dir') or 'C:/Windows/Temp').rstrip('/\\'),
                                       secrets.token_hex(6))
            put_scp(s, data, path)
            rc, out, err = self.run_ps(s, self.script(bundle, options, path, password),
                                       'importing the certificate')
        did = ['imported %s' % thumb[:12]]
        for line in out.splitlines():
            if line.startswith('IIS '):
                did.append('IIS %s' % line[4:])
                self.ctx.step('bound to IIS %s' % line[4:], 'ok')
            elif line == 'RDP':
                did.append('RDP')
                self.ctx.step('Remote Desktop listener uses it', 'ok')
            elif line == 'EXCHANGE':
                did.append('Exchange')
                self.ctx.step('Exchange uses it', 'ok')
            elif line.startswith('REMOVED '):
                self.ctx.step('removed the old %s' % line[8:])
            elif line.startswith('INUSE '):
                self.ctx.step('the old %s is still bound: kept' % line[6:], 'warn')
        self.remember(bundle, options)
        return ', '.join(did)
