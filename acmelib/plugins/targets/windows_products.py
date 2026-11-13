# -*- coding: utf-8 -*-
"""
Windows server products the windows_ssh target has no role for (1.0.96), each a kind
of its own over the same machinery - OpenSSH, PowerShell run as windows_ssh runs it,
the PFX imported into LocalMachine\\My under a dated friendly name, the old acme
certificates nothing uses removed afterwards:

    windows_wsus            WSUS: the https binding of the "WSUS Administration" site
                            (8531), Require SSL on its five web services when asked,
                            wsusutil configuressl
    windows_hyperv_replica  Hyper-V Replica with certificate-based authentication: the
                            Replica server's certificate, the primary VMs' certificate
                            (each replica server tested with it first)
    windows_ssrs            Reporting Services / Power BI Report Server: every HTTPS
                            binding of the report server (WMI MSReportServer_
                            ConfigurationSetting) moved to the new certificate
    windows_scom            Operations Manager (management server, gateway, agent): the
                            key imported AT_KEYEXCHANGE into a legacy CSP (certutil), then
                            MOMCertImport, the HealthService restarted
    windows_oos             Office Online Server: the farm's certificate by its friendly
                            name (Set-OfficeWebAppsFarm -CertificateName), the key
                            exportable as it must be, a restart when asked

What the vendor documents give is the same in every version they cover (Windows Server
2016 - 2025; SSRS 2016 - 2022 and Power BI Report Server; Operations Manager 2019 -
2025; Office Online Server): one module each, no versions. IIS sites, RDP, Exchange, SQL Server, AD FS,
RDS, LDAPS, WinRM, SSTP, Skype for Business, SharePoint SE and Windows Admin Center are
windows_ssh's (its roles) - not repeated here.

Each product's PowerShell writes "STEP <level> <words>" lines (the job's steps), and
refuses plainly - before it changes anything where it can - what cannot work: the
product not installed, a certificate without the key usage it needs, a binding never
set up.

Sources (Microsoft Learn, read 2026-11):
  https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus
  https://learn.microsoft.com/en-us/powershell/module/iisadministration/new-iissitebinding
  https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmreplicationserver
  https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmreplication
  https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/configure-replication-single-host
  https://learn.microsoft.com/en-us/sql/reporting-services/security/configure-ssl-connections-on-a-native-mode-report-server
  https://learn.microsoft.com/en-us/sql/reporting-services/wmi-provider-library-reference/configurationsetting-method-createsslcertificatebinding
  https://learn.microsoft.com/en-us/sql/reporting-services/wmi-provider-library-reference/configurationsetting-method-removesslcertificatebinding
  https://learn.microsoft.com/en-us/system-center/scom/obtain-certificate-windows-server-and-operations-manager
  https://learn.microsoft.com/en-us/officeonlineserver/plan-office-online-server
  https://learn.microsoft.com/en-us/powershell/module/officewebapps/set-officewebappsfarm
"""
from __future__ import annotations

import re
import secrets

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, as_int, text, sha1_thumb, name_prefix, object_name,
    random_password, put_scp, ssh_fields, keep_field, family_of)
from acmelib.plugins.targets import _win_roles as WR
from acmelib.plugins.targets.windows_ssh import WindowsSshTarget, ps_str

MASK = WR.MASK
HELPER = dict(WR.HELPERS)

# The probe of "Try": who signed in, on which Windows, elevated or not (as windows_ssh's).
PROBE = ("$os = (Get-CimInstance Win32_OperatingSystem).Caption\n"
         "$adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
         "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
         "Write-Output (\"$env:USERNAME|$os|$($PSVersionTable.PSVersion)|$adm\")")

# Server Authentication and Client Authentication: Hyper-V Replica and Operations Manager
# authenticate both ways with the one certificate (Set-VMReplicationServer, the SCOM
# certificate requirements) - a public CA's certificate without Client Authentication
# is refused before it is used.
EKU_BOTH = [
    "$eku = @($cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })",
    "if (-not $eku.Count) { Say warn ($what + ': the certificate lists no extended key usage "
    "(any purpose)') }",
    "elseif ($eku -notcontains '1.3.6.1.5.5.7.3.1' -or $eku -notcontains '1.3.6.1.5.5.7.3.2') "
    "{ throw ($what + ': the certificate needs both Server Authentication and Client "
    "Authentication in its extended key usage - this one has ' + ($eku -join ', ') + '; ask "
    "the CA (a template) for one with both') }",
]


def first_name(names, fallback=''):
    """The first name of a certificate that is not a wildcard."""
    for n in names or []:
        n = text(n).strip()
        if n and not n.startswith('*'):
            return n
    return fallback


class WinProductTarget(WindowsSshTarget):
    """What the products share: not a module itself (no kind)."""
    kind = ''
    discovery = False
    vendor = 'Microsoft'
    doc = 'targets.md'
    files_ui = None
    product = ''                # its name in the steps and errors
    rsa_only = False
    fields = ssh_fields(sudo=False, user_default='Administrator', howto='windows',
                        try_command='whoami') + [
        field('tmp_dir', 'Folder for uploads', 'text', default='C:/Windows/Temp', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ]
    common_deploy_fields = [
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (any Windows)'],
                       ['pfx', 'AES-256 (Windows Server 2019 and later)']]),
        keep_field(1),
    ]

    # -- what each product says ------------------------------------------------------
    def check_options(self, options, bundle=None):
        """Words of what is wrong with a deployment's options, [] when fine."""
        bad = []
        if self.rsa_only and bundle is not None and family_of(bundle) in ('ec', 'ed'):
            bad.append('%s needs an RSA key: this certificate\'s key is %s - issue it with an '
                       'RSA key' % (self.product, family_of(bundle).upper()))
        return bad

    def body(self, bundle, options):
        """The PowerShell lines that make the product use $cert / $thumb."""
        raise NotImplementedError

    def detect(self):
        """PowerShell writing "FOUND yes|no <words>": is the product on this server?"""
        return ["Write-Output 'FOUND yes'"]

    def used(self):
        """PowerShell lines adding to $used the thumbprints the product still uses (the old
        ones listed there are not removed)."""
        return []

    # -- running -------------------------------------------------------------------------
    def _script(self, bundle, options):
        body = self.body(bundle, options)
        return '\n'.join(WR.head(sha1_thumb(bundle), name_prefix(bundle, options),
                                 '\n'.join(body)) + body)

    def _errors(self, out, err):
        said = [x[7:] for x in text(out).splitlines() if x.startswith('ERROR: ')]
        return said[-1] if said else (text(err).strip() or text(out).strip())[-300:]

    def _found(self, s):
        rc, out, err = self.roles_ps(s, '\n'.join(self.detect()), 'looking for %s' % self.product,
                                     check=False)
        for line in text(out).splitlines():
            m = re.match(r'^FOUND (yes|no) ?(.*)$', line.strip())
            if m:
                return m.group(1) == 'yes', m.group(2).strip()
        return False, self._errors(out, err) or 'no answer'

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.run_ps(s, PROBE, 'signing in')
            found, detail = self._found(s)
        last = [x for x in out.splitlines() if '|' in x][-1:] or ['?|?|?|?']
        user, os_, psv, adm = (last[0].split('|') + ['?'] * 4)[:4]
        if adm.strip().lower() != 'true':
            raise PluginError('signed in as %s, but not as an administrator (elevated)' % user,
                              retry=False)
        if not found:
            raise PluginError('signed in as %s on %s, but %s is not on this server: %s'
                              % (user, os_, self.product, detail), retry=False)
        return 'signed in as %s on %s, PowerShell %s; %s%s' % (
            user, os_, psv, self.product, ' (%s)' % detail if detail else '')

    def import_cert(self, s, bundle, options):
        """The PFX uploaded and imported into LocalMachine\\My (windows_ssh's import, no
        bindings, nothing removed there)."""
        password = random_password()
        fmt = options.get('pfx_format') or 'p12-legacy'
        data = bundle.as_format(fmt, password=password, alias=object_name(bundle, options))
        path = '%s/acme-%s.pfx' % (self._tmp(), secrets.token_hex(6))
        put_scp(s, data, path)
        iopts = {'keep': -1, 'object_name': options.get('object_name'),
                 'exportable': options.get('exportable')}
        try:
            self.run_ps(s, self.script(bundle, iopts, path, password), 'importing the certificate')
        finally:
            # gone already when the import went through; not when it failed half-way
            self.run_ps(s, "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue"
                        % ps_str(path), 'cleaning up', check=False)

    def cleanup(self, s, bundle, options, keep):
        body = WR.cleanup_script(name_prefix(bundle, options), keep)
        body[1:1] = self.used()
        rc, out, err = self.roles_ps(s, '\n'.join(
            WR.head(sha1_thumb(bundle), name_prefix(bundle, options), '\n'.join(body)) + body),
            'removing the old certificates', check=False)
        self._roles_steps(out)
        if rc != 0:
            self.ctx.step('the old certificates could not be removed: %s'
                          % self._errors(out, err), 'warn')

    def deploy(self, bundle, options):
        options = dict(options or {})
        bad = self.check_options(options, bundle)
        if bad:
            raise PluginError('; '.join(bad), retry=False)
        thumb = sha1_thumb(bundle)
        with self.ssh() as s:
            if self.unchanged(bundle, options, present=lambda: 'YES' in self.run_ps(
                    s, "if (Test-Path 'Cert:\\LocalMachine\\My\\%s') { 'YES' } else { 'NO' }"
                    % thumb, check=False)[1]):
                return self.same(bundle, 'in the machine store')
            self.import_cert(s, bundle, options)
            self.ctx.step('imported %s into LocalMachine\\My' % thumb[:12], 'ok')
            rc, out, err = self.roles_ps(s, self._script(bundle, options), self.product,
                                         check=False)
            self._roles_steps(out)
            if rc != 0:
                raise PluginError('%s: %s - the old certificate stays in use, nothing was '
                                  'removed' % (self.product, self._errors(out, err)),
                                  detail=text(out) + text(err))
            self.ctx.step('%s: done' % self.product, 'ok')
            keep = as_int(options.get('keep', 1), 1)
            if keep >= 0:
                self.cleanup(s, bundle, options, keep)
        self.remember(bundle, options)
        return 'imported %s, %s uses it' % (thumb[:12], self.product)

    def dry_run(self, bundle, options, run_script=True):
        """Signed in, the product looked for, the PowerShell shown - nothing changed."""
        options = dict(options or {})
        bad = self.check_options(options, bundle)
        with self.ssh() as s:
            self.run_ps(s, PROBE, 'signing in')
            self.ctx.step('signed in on %s' % self.c('host'), 'ok')
            found, detail = self._found(s)
        if found:
            self.ctx.step('%s is on this server%s' % (self.product, ' (%s)' % detail
                                                       if detail else ''), 'ok')
        else:
            bad.append('%s is not on this server: %s' % (self.product, detail))
            self.ctx.step(bad[-1], 'bad')
        self.ctx.step('the machine store and %s are not touched on a test' % self.product)
        try:
            self.ctx.step('the PowerShell of %s (not run on a test):\n%s'
                          % (self.product, self._script(bundle, options)))
        except PluginError as e:
            bad.append(str(e))
        if bad:
            raise PluginError('; '.join(bad), retry=False)
        return 'the test passed: %s is there' % self.product

    def preview(self, bundle, options):
        options = dict(options or {})
        probs = [{'level': 'bad', 'words': w} for w in self.check_options(options, bundle)]
        try:
            script = self._script(bundle, options)
        except PluginError as e:
            script = ''
            probs.append({'level': 'bad', 'words': str(e)})
        probs.append({'level': 'info', 'words': 'after the import: %s' % self.product})
        return {'files': [], 'env': {}, 'problems': probs,
                'roles': {'on': [{'key': self.kind, 'title': self.product}], 'script': script}}

    def served_places(self, options):
        return []

    def verify(self, bundle, options):
        return None


# ---------------------------------------------------------------------------
# WSUS
# ---------------------------------------------------------------------------
WSUS_VDIRS = ['SimpleAuthWebService', 'DSSAuthWebService', 'ServerSyncWebService',
              'APIremoting30', 'ClientWebService']


class WsusTarget(WinProductTarget):
    discovery = False           # nothing to find: a server over SSH
    kind = 'windows_wsus'
    title = 'WSUS (Windows Server Update Services)'
    product = 'WSUS'
    description = ('WSUS on Windows Server 2016 - 2025 (also as a Configuration Manager software '
                   'update point), over OpenSSH and PowerShell: imports the certificate into '
                   'the machine store, puts it on the https binding of the "WSUS '
                   'Administration" site (8531), runs wsusutil configuressl and removes the '
                   'old ones.')
    deploy_fields = [
        field('wsus_site', 'IIS site of WSUS', 'text', default='WSUS Administration'),
        field('wsus_port', 'HTTPS port', 'number', default=8531,
              help='8531 unless WSUS was installed on 80/443 (then 443); the HTTP port is '
                   'this one minus one'),
        field('wsus_fqdn', 'Server name for clients', 'text',
              placeholder='wsus01.corp.example.com',
              help='the FQDN clients and downstream servers use (wsusutil configuressl); '
                   'empty: the first name of the certificate'),
        field('wsus_configuressl', 'Run wsusutil configuressl', 'select', default='always',
              options=[['always', 'every time'], ['changed', 'when the binding changed'],
                       ['never', 'never']]),
        field('wsus_require_ssl', 'Require SSL on the WSUS web services', 'bool', default=False,
              help='SimpleAuthWebService, DSSAuthWebService, ServerSyncWebService, '
                   'APIremoting30, ClientWebService - never Content, Inventory, '
                   'ReportingWebService or SelfUpdate'),
    ] + WinProductTarget.common_deploy_fields

    def _port(self, options):
        return as_int(options.get('wsus_port'), 8531) or 8531

    def check_options(self, options, bundle=None):
        bad = WinProductTarget.check_options(self, options, bundle)
        if not 0 < self._port(options) < 65536:
            bad.append('WSUS: %s is not a port' % options.get('wsus_port'))
        if not text(options.get('wsus_site') or 'WSUS Administration').strip():
            bad.append('WSUS: name the IIS site')
        return bad

    def fqdn(self, bundle, options):
        return text(options.get('wsus_fqdn')).strip() or \
            first_name(getattr(bundle, 'names', None), self.c('host') or '')

    def detect(self):
        return ["if (Get-Service -Name 'WsusService' -ErrorAction SilentlyContinue) { $v = ''; "
                "$k = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Update Services\\"
                "Server\\Setup' -ErrorAction SilentlyContinue; if ($k) { $v = 'port ' + "
                "[string]$k.PortNumber + ', SSL ' + [string]$k.UsingSSL }; Write-Output "
                "('FOUND yes ' + $v) } else { Write-Output 'FOUND no the WsusService service is "
                "not here - is the WSUS role installed?' }"]

    def body(self, bundle, options):
        site = text(options.get('wsus_site') or 'WSUS Administration').strip()
        port = self._port(options)
        mode = options.get('wsus_configuressl') or 'always'
        store = "-CertStoreLocation 'Cert:\\LocalMachine\\My'"
        sc = [
            "Need-Service 'WsusService' 'WSUS' | Out-Null",
            "Need-Module 'IISAdministration' 'WSUS'",
            "$site = %s" % ps_str(site),
            "$port = %d" % port,
            "if (-not (Get-IISSite -Name $site -WarningAction SilentlyContinue)) { throw ('WSUS: "
            "there is no IIS site ' + $site) }",
            "$b = @(Get-IISSiteBinding -Name $site -Protocol https -WarningAction "
            "SilentlyContinue | Where-Object { ([string]$_.BindingInformation) -match (':' + "
            "$port + ':') }) | Select-Object -First 1",
            "$changed = $false",
            "if ($b) {",
            "  $bi = [string]$b.BindingInformation",
            "  $old = (@($b.CertificateHash) | Where-Object { $_ -ne $null } | ForEach-Object { "
            "'{0:X2}' -f $_ }) -join ''",
            "  if ($old -eq $thumb) { Say ok ('WSUS: ' + $site + ' ' + $bi + ' already uses it') "
            "} else {",
            "    Remove-IISSiteBinding -Name $site -BindingInformation $bi -Protocol https "
            "-Confirm:$false -ErrorAction Stop",
            "    try { New-IISSiteBinding -Name $site -BindingInformation $bi -Protocol https "
            "-CertificateThumbPrint $thumb %s -ErrorAction Stop }" % store,
            "    catch { $why = $_.Exception.Message; if ($old) { New-IISSiteBinding -Name $site "
            "-BindingInformation $bi -Protocol https -CertificateThumbPrint $old %s -ErrorAction "
            "SilentlyContinue }; throw ('WSUS: the binding ' + $bi + ' did not take the new "
            "certificate, the old one is back: ' + $why) }" % store,
            "    $changed = $true; Say ok ('WSUS: ' + $site + ' ' + $bi + ' uses it') }",
            "} else {",
            "  $bi = '*:' + $port + ':'",
            "  New-IISSiteBinding -Name $site -BindingInformation $bi -Protocol https "
            "-CertificateThumbPrint $thumb %s -ErrorAction Stop" % store,
            "  $changed = $true; Say ok ('WSUS: made the https binding ' + $bi + ' of ' + $site)",
            "}",
        ]
        if as_bool(options.get('wsus_require_ssl')):
            sc += [
                "Need-Module 'WebAdministration' 'WSUS'",
                "foreach ($v in @(%s)) {" % ', '.join(ps_str(v) for v in WSUS_VDIRS),
                "  $loc = $site + '/' + $v",
                "  $cur = [string](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' "
                "-Location $loc -Filter 'system.webServer/security/access' -Name sslFlags)",
                "  if ($cur -match 'Ssl') { Say ok ('WSUS: ' + $v + ' already requires SSL') } "
                "else { Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "
                "$loc -Filter 'system.webServer/security/access' -Name sslFlags -Value 'Ssl' "
                "-ErrorAction Stop; Say ok ('WSUS: ' + $v + ' requires SSL') }",
                "}",
            ]
        if mode != 'never':
            fqdn = self.fqdn(bundle, options)
            if not fqdn:
                raise PluginError('WSUS: give the server name for clients (wsusutil configuressl)',
                                  retry=False)
            run = [
                "$wu = Join-Path $env:ProgramFiles 'Update Services\\Tools\\WsusUtil.exe'",
                "if (-not (Test-Path -LiteralPath $wu)) { throw ('WSUS: ' + $wu + ' is not "
                "there') }",
                "$r = Run-Native $wu @('configuressl', %s)" % ps_str(fqdn),
                "if ($r.rc -ne 0) { throw ('WSUS: wsusutil configuressl failed: ' + $r.out) }",
                "$said = @($r.out -split \"`n\" | Where-Object { $_.Trim() }) | Select-Object "
                "-Last 1",
                "Say ok ('WSUS: wsusutil configuressl ' + %s + ' - ' + $said)" % ps_str(fqdn),
            ]
            if mode == 'changed':
                run = ["if ($changed) {"] + ['  ' + x for x in run] + [
                    "} else { Say info 'WSUS: the binding did not change - wsusutil not run' }"]
            sc += run
        return sc

    def served_places(self, options):
        options = options or {}
        host = text(options.get('wsus_fqdn')).strip() or self.c('host')
        return [(host, self._port(options))] if host else []


# ---------------------------------------------------------------------------
# Hyper-V Replica
# ---------------------------------------------------------------------------
class HyperVReplicaTarget(WinProductTarget):
    discovery = False           # nothing to find: a server over SSH
    kind = 'windows_hyperv_replica'
    title = 'Hyper-V Replica (certificate authentication)'
    product = 'Hyper-V Replica'
    description = ('Hyper-V Replica on Windows Server 2016 - 2025 with certificate-based '
                   '(HTTPS) authentication, over OpenSSH and PowerShell: imports the '
                   'certificate, makes the Replica server and the primary VMs of this host use '
                   'it (each replica server tested with it first) and removes the old ones. '
                   'The certificate needs Server and Client Authentication.')
    deploy_fields = [
        field('hvr_server', 'This host receives replication (Replica server)', 'bool',
              default=True, help='Set-VMReplicationServer -CertificateThumbprint'),
        field('hvr_primary', 'Primary VMs of this host', 'bool', default=True,
              help='Set-VMReplication -CertificateThumbprint for the VMs that replicate with '
                   'a certificate'),
        field('hvr_vms', 'Only these VMs', 'list', show_if={'hvr_primary': [True]},
              help='VM names, one a line; empty: every primary VM using a certificate'),
        field('hvr_test', 'Test each replica server first', 'bool', default=True,
              show_if={'hvr_primary': [True]},
              help='Test-VMReplicationConnection with the new certificate; a failure changes '
                   'nothing'),
    ] + WinProductTarget.common_deploy_fields

    def check_options(self, options, bundle=None):
        bad = WinProductTarget.check_options(self, options, bundle)
        if not as_bool(options.get('hvr_server', True)) and \
                not as_bool(options.get('hvr_primary', True)):
            bad.append('Hyper-V Replica: choose the Replica server, the primary VMs or both')
        return bad

    def detect(self):
        return ["if (Get-Command Get-VMReplicationServer -ErrorAction SilentlyContinue) { $x = "
                "Get-VMReplicationServer; Write-Output ('FOUND yes Replica server ' + "
                "[string]$x.ReplicationEnabled + ', ' + [string]$x.AllowedAuthenticationType + ', "
                "primary VMs ' + @(Get-VMReplication -ErrorAction SilentlyContinue | Where-Object "
                "{ [string]$_.ReplicationMode -eq 'Primary' }).Count) } else { Write-Output "
                "'FOUND no the Hyper-V module is not here - is the Hyper-V role installed?' }"]

    def body(self, bundle, options):
        sc = ["Need-Module 'Hyper-V' 'Hyper-V Replica'", "$what = 'Hyper-V Replica'"] + EKU_BOTH
        if as_bool(options.get('hvr_server', True)):
            sc += [
                "$srv = Get-VMReplicationServer -ErrorAction Stop",
                "if (-not $srv.ReplicationEnabled) { throw 'Hyper-V Replica: this host is not a "
                "Replica server - enable it once (Hyper-V Settings, Replication Configuration) "
                "or turn off \"This host receives replication\"' }",
                "if ([string]$srv.AllowedAuthenticationType -notmatch 'Certificate') { throw ("
                "'Hyper-V Replica: the Replica server allows ' + [string]$srv."
                "AllowedAuthenticationType + ' only - choose certificate-based authentication "
                "(HTTPS) once') }",
                "if ([string]$srv.CertificateThumbprint -eq $thumb) { Say ok 'Hyper-V Replica "
                "server already uses it' } else {",
                "  Set-VMReplicationServer -CertificateThumbprint $thumb -Force -ErrorAction Stop",
                "  Say ok 'Hyper-V Replica server uses it' }",
            ]
        if as_bool(options.get('hvr_primary', True)):
            only = lines(options.get('hvr_vms'))
            sc += [
                "$vms = @(Get-VMReplication -ErrorAction Stop | Where-Object { [string]$_."
                "ReplicationMode -eq 'Primary' -and [string]$_.AuthenticationType -eq "
                "'Certificate' })",
            ]
            if only:
                sc += [
                    "$only = @(%s)" % ', '.join(ps_str(v) for v in only),
                    "$missing = @($only | Where-Object { @($vms | ForEach-Object { $_.VMName }) "
                    "-notcontains $_ })",
                    "if ($missing) { throw ('Hyper-V Replica: not primary VMs replicating with a "
                    "certificate here: ' + ($missing -join ', ')) }",
                    "$vms = @($vms | Where-Object { $only -contains $_.VMName })",
                ]
            sc.append("if (-not $vms) { Say info 'Hyper-V Replica: no primary VM of this host "
                      "replicates with a certificate' }")
            if as_bool(options.get('hvr_test', True)):
                sc += [
                    "$tested = @()",
                    "foreach ($r in $vms) {",
                    "  $to = [string]$r.ReplicaServer + ':' + [string]$r.ReplicaPort",
                    "  if ($tested -contains $to) { continue }",
                    "  try { Test-VMReplicationConnection -ReplicaServerName $r.ReplicaServer "
                    "-ReplicaServerPort $r.ReplicaPort -AuthenticationType Certificate "
                    "-CertificateThumbprint $thumb -ErrorAction Stop | Out-Null } catch { throw ("
                    "'Hyper-V Replica: ' + $to + ' does not take the new certificate, nothing "
                    "changed: ' + $_.Exception.Message) }",
                    "  $tested += $to; Say ok ('Hyper-V Replica: ' + $to + ' takes it')",
                    "}",
                ]
            sc += [
                "foreach ($r in $vms) {",
                "  if ([string]$r.CertificateThumbprint -eq $thumb) { Say ok ('Hyper-V Replica: "
                "VM ' + $r.VMName + ' already uses it'); continue }",
                "  Set-VMReplication -VMName $r.VMName -CertificateThumbprint $thumb -ErrorAction "
                "Stop",
                "  Say ok ('Hyper-V Replica: VM ' + $r.VMName + ' uses it')",
                "}",
            ]
        return sc

    def used(self):
        return [
            "try { $used += @((Get-VMReplicationServer -ErrorAction Stop).CertificateThumbprint) "
            "} catch { }",
            "try { $used += @(Get-VMReplication -ErrorAction Stop | ForEach-Object { "
            "$_.CertificateThumbprint }) } catch { }",
        ]


# ---------------------------------------------------------------------------
# Reporting Services / Power BI Report Server
# ---------------------------------------------------------------------------
class SsrsTarget(WinProductTarget):
    discovery = False           # nothing to find: a server over SSH
    kind = 'windows_ssrs'
    title = 'SQL Server Reporting Services / Power BI Report Server'
    product = 'Reporting Services'
    description = ('SQL Server Reporting Services 2016 - 2022 and Power BI Report Server, over '
                   'OpenSSH and PowerShell: imports the certificate and moves every HTTPS '
                   'binding of the report server (web service and web portal) to it through '
                   'its WMI provider, then removes the old ones. HTTPS is set up once in '
                   'Report Server Configuration Manager.')
    deploy_fields = [
        field('ssrs_instance', 'Report server instance', 'text', placeholder='SSRS',
              help='SSRS, PBIRS, MSSQLSERVER...; empty: the only one on the server'),
        field('ssrs_port', 'HTTPS port to check', 'number', default=443,
              help='where the report server serves it, for the test made with the deployment; '
                   '0: none'),
    ] + WinProductTarget.common_deploy_fields

    def check_options(self, options, bundle=None):
        bad = WinProductTarget.check_options(self, options, bundle)
        inst = text(options.get('ssrs_instance')).strip()
        if inst and not re.match(r'^[A-Za-z0-9_$#]{1,32}$', inst):
            bad.append('Reporting Services: "%s" is not an instance name' % inst)
        p = as_int(options.get('ssrs_port'), 443)
        if not 0 <= p < 65536:
            bad.append('Reporting Services: %s is not a port' % options.get('ssrs_port'))
        return bad

    NS = ("$root = 'root\\Microsoft\\SqlServer\\ReportServer'\n"
          "$insts = @(Get-WmiObject -Namespace $root -Class __Namespace -ErrorAction "
          "SilentlyContinue | ForEach-Object { $_.Name } | Where-Object { $_ -like 'RS_*' })")

    def detect(self):
        return [self.NS,
                "if ($insts) { Write-Output ('FOUND yes ' + ($insts -join ', ')) } else { "
                "Write-Output 'FOUND no no report server (SSRS or Power BI Report Server) "
                "answers in WMI here' }"]

    def body(self, bundle, options):
        inst = text(options.get('ssrs_instance')).strip()
        return [
            self.NS,
            "if (-not $insts) { throw 'Reporting Services: no report server (SSRS or Power BI "
            "Report Server) is on this server' }",
            "$want = %s" % ps_str(inst),
            "if ($want) { $inst = 'RS_' + $want; if ($insts -notcontains $inst) { throw ("
            "'Reporting Services: there is no instance ' + $want + '; there are: ' + ($insts "
            "-join ', ')) } }",
            "elseif ($insts.Count -gt 1) { throw ('Reporting Services: there are several "
            "instances (' + ($insts -join ', ') + ') - name the one') } else { $inst = "
            "$insts[0] }",
            "$vers = @(Get-WmiObject -Namespace ($root + '\\' + $inst) -Class __Namespace "
            "-ErrorAction Stop | ForEach-Object { $_.Name } | Where-Object { $_ -match "
            "'^v\\d+$' } | Sort-Object { [int]$_.Substring(1) } -Descending)",
            "if (-not $vers) { throw ('Reporting Services: ' + $inst + ' has no version in WMI') }",
            "$ns = $root + '\\' + $inst + '\\' + $vers[0] + '\\Admin'",
            "$rs = Get-WmiObject -Namespace $ns -Class MSReportServer_ConfigurationSetting "
            "-ErrorAction Stop | Select-Object -First 1",
            "if (-not $rs) { throw ('Reporting Services: ' + $ns + ' has no "
            "MSReportServer_ConfigurationSetting') }",
            "$new = $thumb.ToLowerInvariant()",
            "$l = $rs.ListSSLCertificateBindings(1033)",
            "$apps = @($l.Application | Where-Object { $_ })",
            "$hashes = @($l.CertificateHash)",
            "$ips = @(if ($l.IPAddress) { $l.IPAddress } else { $l.IPAddresses })",
            "$ports = @($l.Port)",
            "if (-not $apps.Count) { throw 'Reporting Services: there is no HTTPS binding yet - "
            "choose the HTTPS certificate once in Report Server Configuration Manager (Web "
            "Service URL, Web Portal URL), then acme replaces it' }",
            "function RsErr($x) { ([string]$x.Error + ' ' + (@($x.ExtendedErrors) -join '; '))"
            ".Trim() }",
            "for ($i = 0; $i -lt $apps.Count; $i++) {",
            "  $a = [string]$apps[$i]; $h = ([string]$hashes[$i]).ToLowerInvariant(); $ip = "
            "[string]$ips[$i]; $p = [int]$ports[$i]",
            "  $where = $a + ' ' + $ip + ':' + $p",
            "  if ($h -eq $new) { Say ok ('Reporting Services: ' + $where + ' already uses it'); "
            "continue }",
            "  $r = $rs.RemoveSSLCertificateBindings($a, $h, $ip, $p, 1033)",
            "  if ($r.HRESULT -ne 0) { throw ('Reporting Services: the binding ' + $where + ' "
            "could not be removed: ' + (RsErr $r)) }",
            "  $r = $rs.CreateSSLCertificateBinding($a, $new, $ip, $p, 1033)",
            "  if ($r.HRESULT -ne 0) { $why = RsErr $r; $rs.CreateSSLCertificateBinding($a, $h, "
            "$ip, $p, 1033) | Out-Null; throw ('Reporting Services: ' + $where + ' did not take "
            "the new certificate, the old one is back: ' + $why) }",
            "  Say ok ('Reporting Services: ' + $where + ' uses it')",
            "}",
        ]

    def served_places(self, options):
        p = as_int((options or {}).get('ssrs_port'), 443)
        return [(self.c('host'), p)] if p and self.c('host') else []


# ---------------------------------------------------------------------------
# Operations Manager
# ---------------------------------------------------------------------------
SCOM_REG = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft Operations Manager\\3.0\\MachineSettings'
# The serial number MOMCertImport writes (ChannelCertificateSerialNumber, REG_BINARY) as hex,
# and both byte orders of a certificate's serial to compare it with.
SCOM_SERIAL = [
    "function ScomSerial { $v = (Get-ItemProperty -LiteralPath '%s' -ErrorAction "
    "SilentlyContinue).ChannelCertificateSerialNumber; if (-not $v) { return '' }; "
    "((@($v) | ForEach-Object { '{0:X2}' -f $_ }) -join '').ToUpperInvariant() }" % SCOM_REG,
    "function Reversed([string]$h) { $p = @([regex]::Matches($h, '..') | ForEach-Object { "
    "$_.Value }); [array]::Reverse($p); $p -join '' }",
]


class ScomTarget(WinProductTarget):
    discovery = False           # nothing to find: a server over SSH
    kind = 'windows_scom'
    title = 'System Center Operations Manager (certificate)'
    product = 'Operations Manager'
    rsa_only = True
    description = ('System Center Operations Manager 2019, 2022 and 2025 - a management server, '
                   'gateway or agent authenticating with a certificate - over OpenSSH and '
                   'PowerShell: imports the certificate with its key in a legacy CSP '
                   '(AT_KEYEXCHANGE, as Operations Manager needs), runs MOMCertImport, restarts '
                   'the Microsoft Monitoring Agent and removes the old ones. RSA, with Server and '
                   'Client Authentication.')
    deploy_fields = [
        field('scom_tool', 'MOMCertImport.exe', 'text',
              placeholder='C:\\Tools\\MOMCertImport.exe',
              help='its path on the server (from the installation media, SupportTools\\amd64); '
                   'empty: the Gateway folder of Operations Manager'),
        field('scom_restart', 'Restart the Microsoft Monitoring Agent', 'bool', default=True,
              help='HealthService, when the certificate changed - it loads it on start'),
    ] + WinProductTarget.common_deploy_fields

    def detect(self):
        return ["if (Get-Service -Name 'HealthService' -ErrorAction SilentlyContinue) { $d = "
                "'no certificate set'; if ((Get-ItemProperty -LiteralPath '%s' -ErrorAction "
                "SilentlyContinue).ChannelCertificateSerialNumber) { $d = 'a certificate is set' "
                "}; Write-Output ('FOUND yes ' + $d) } else { Write-Output 'FOUND no the "
                "HealthService (Microsoft Monitoring Agent) is not here' }" % SCOM_REG]

    def import_cert(self, s, bundle, options):
        """certutil -importPFX ... AT_KEYEXCHANGE: the key into a legacy CSP as key exchange -
        Operations Manager does not take a KSP key (Import-PfxCertificate may put it there)."""
        password = random_password()
        fmt = options.get('pfx_format') or 'p12-legacy'
        thumb = sha1_thumb(bundle)
        path = '%s/acme-%s.pfx' % (self._tmp(), secrets.token_hex(6))
        put_scp(s, bundle.as_format(fmt, password=password, alias=object_name(bundle, options)),
                path)
        sc = [
            HELPER['Run-Native'],
            "$pfx = %s" % ps_str(path),
            "$store = 'Cert:\\LocalMachine\\My'",
            "$thumb = %s" % ps_str(thumb),
            "try {",
            "  if (-not (Test-Path (Join-Path $store $thumb))) {",
            "    $r = Run-Native 'certutil.exe' @('-f', '-p', %s, '-importPFX', 'My', $pfx, "
            "'AT_KEYEXCHANGE')" % ps_str(password),
            "    if ($r.rc -ne 0) { throw ('certutil -importPFX failed: ' + $r.out) }",
            "  }",
            "} finally { Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue }",
            "$cert = Get-Item (Join-Path $store $thumb)",
            "$cert.FriendlyName = %s" % ps_str(object_name(bundle, options)),
            "Write-Output \"IMPORTED $thumb\"",
        ]
        self.run_ps(s, '\n'.join(sc), 'importing the certificate')

    def body(self, bundle, options):
        tool = text(options.get('scom_tool')).strip()
        sc = ["Need-Service 'HealthService' 'Operations Manager' | Out-Null",
              "$what = 'Operations Manager'"] + EKU_BOTH + SCOM_SERIAL + [
            "$ks = ''; try { $ks = [string]$cert.PrivateKey.CspKeyContainerInfo.KeyNumber } "
            "catch { }",
            "if ($ks -ne 'Exchange') { throw ('Operations Manager: the key is not in a legacy "
            "CSP as AT_KEYEXCHANGE (' + $ks + ') - it cannot be used') }",
            "$sn = $cert.SerialNumber.ToUpperInvariant()",
            "$have = ScomSerial",
            "if ($have -and ($have -eq $sn -or $have -eq (Reversed $sn))) { Say ok 'Operations "
            "Manager already uses it' } else {",
            "  $tool = %s" % ps_str(tool),
            "  if (-not $tool) { $tool = Join-Path $env:ProgramFiles 'System Center Operations "
            "Manager\\Gateway\\MOMCertImport.exe' }",
            "  if (-not (Test-Path -LiteralPath $tool)) { throw ('Operations Manager: "
            "MOMCertImport.exe is not at ' + $tool + ' - copy it from the installation media "
            "(SupportTools\\amd64) and give its path') }",
            "  $subj = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates."
            "X509NameType]::SimpleName, $false)",
            "  $r = Run-Native $tool @('/SubjectName', $subj)",
            "  if ($r.rc -ne 0) { throw ('Operations Manager: MOMCertImport /SubjectName ' + "
            "$subj + ' failed: ' + $r.out) }",
            "  $have = ScomSerial",
            "  if (-not ($have -eq $sn -or $have -eq (Reversed $sn))) { throw ('Operations "
            "Manager: MOMCertImport took another certificate with the subject ' + $subj + ' "
            "(serial ' + $have + ') - remove the other ones of that subject from "
            "LocalMachine\\My') }",
            "  Say ok ('Operations Manager uses it (' + $subj + ')')",
        ]
        if as_bool(options.get('scom_restart', True)):
            sc.append("  Restart-Role 'HealthService'")
        else:
            sc.append("  Say warn 'Operations Manager takes it when the HealthService restarts'")
        sc.append("}")
        return sc

    def used(self):
        return [
            "try { %s; $h = ScomSerial; if ($h) { $hr = Reversed $h; $used += @(Get-ChildItem "
            "$store | Where-Object { $_.SerialNumber -eq $h -or $_.SerialNumber -eq $hr } | "
            "ForEach-Object { $_.Thumbprint }) } } catch { }" % '; '.join(SCOM_SERIAL),
        ]


# ---------------------------------------------------------------------------
# Office Online Server
# ---------------------------------------------------------------------------
class OosTarget(WinProductTarget):
    discovery = False           # nothing to find: a server over SSH
    kind = 'windows_oos'
    title = 'Office Online Server'
    product = 'Office Online Server'
    description = ('Office Online Server (on Windows Server 2016 - 2022) for SharePoint and '
                   'Exchange, over OpenSSH and PowerShell: imports the certificate with an '
                   'exportable key under its own friendly name, points the farm at it '
                   '(Set-OfficeWebAppsFarm -CertificateName), restarts the server when asked '
                   'and removes the old ones. Deploy it to every server of the farm.')
    deploy_fields = [
        field('oos_restart', 'Restart this server after the change', 'bool', default=False,
              help='the farm takes the certificate after its servers restart; on: a restart in '
                   'a minute (shutdown /r /t 60) - deploy to one server of the farm at a time'),
        field('oos_port', 'HTTPS port to check', 'number', default=443,
              help='for the test made with the deployment; 0: none'),
    ] + WinProductTarget.common_deploy_fields

    def import_cert(self, s, bundle, options):
        # "the private key must be exportable" (Plan Office Online Server)
        WinProductTarget.import_cert(self, s, bundle, dict(options, exportable=True))

    def detect(self):
        return ["if (Get-Module -ListAvailable -Name 'OfficeWebApps') { Import-Module "
                "OfficeWebApps -WarningAction SilentlyContinue; $f = $null; try { $f = "
                "Get-OfficeWebAppsFarm -ErrorAction Stop } catch { }; if ($f) { Write-Output "
                "('FOUND yes ' + [string]$f.InternalURL + ', certificate ' + "
                "[string]$f.CertificateName) } else { Write-Output 'FOUND no this server is in "
                "no Office Online Server farm (New-OfficeWebAppsFarm)' } } else { Write-Output "
                "'FOUND no the OfficeWebApps module is not here - is Office Online Server "
                "installed?' }"]

    def body(self, bundle, options):
        sc = [
            "Need-Module 'OfficeWebApps' 'Office Online Server'",
            "$farm = Get-OfficeWebAppsFarm -ErrorAction Stop",
            "if ($farm.SSLOffloaded) { throw 'Office Online Server: the farm is SSL offloaded - "
            "the certificate belongs on the load balancer' }",
            "$name = [string]$cert.FriendlyName",
            "$same = @(Get-ChildItem $store | Where-Object { $_.FriendlyName -eq $name })",
            "if ($same.Count -ne 1) { throw ('Office Online Server: the friendly name ' + $name + "
            "' is on ' + $same.Count + ' certificates - it must be unique') }",
            "if ([string]$farm.CertificateName -eq $name) { Say ok ('Office Online Server "
            "already uses it (' + $name + ')') } else {",
            "  Set-OfficeWebAppsFarm -CertificateName $name -Force -ErrorAction Stop",
            "  Say ok ('Office Online Server uses it (' + $name + ')')",
        ]
        if as_bool(options.get('oos_restart')):
            sc += [
                "  $r = Run-Native 'shutdown.exe' @('/r', '/t', '60', '/c', 'acme: Office Online "
                "Server takes the new certificate')",
                "  if ($r.rc -ne 0) { throw ('Office Online Server: the restart could not be "
                "scheduled: ' + $r.out) }",
                "  Say warn 'Office Online Server: this server restarts in a minute'",
            ]
        else:
            sc.append("  Say warn 'Office Online Server takes it after the servers of the farm "
                      "restart'")
        sc.append("}")
        return sc

    def used(self):
        return [
            "try { Import-Module OfficeWebApps -WarningAction SilentlyContinue -ErrorAction Stop; "
            "$n = [string](Get-OfficeWebAppsFarm -ErrorAction Stop).CertificateName; if ($n) { "
            "$used += @(Get-ChildItem $store | Where-Object { $_.FriendlyName -eq $n } | "
            "ForEach-Object { $_.Thumbprint }) } } catch { }",
        ]

    def served_places(self, options):
        p = as_int((options or {}).get('oos_port'), 443)
        return [(self.c('host'), p)] if p and self.c('host') else []

    # a restart in a minute: the tests after the deployment wait for it (up to 6 minutes)
    @staticmethod
    def served_wait(options):
        return (13, 30) if as_bool((options or {}).get('oos_restart')) else None
