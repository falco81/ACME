# -*- coding: utf-8 -*-
"""
Roles on a Windows server, for the windows_ssh target - not a module: the
registry skips "_" files.

The certificate is imported once into LocalMachine\\My (windows_ssh.script());
then, for a deployment that asks, each role in its own PowerShell run, in this
order:

    key_read        read on the private key for the accounts given
    rds             Remote Desktop Services through the Connection Broker
    rdgw            RD Gateway on its own
    adfs            AD FS (SSL, Service-Communications, the service's key read)
    wap             Web Application Proxy (and the published applications)
    sql             SQL Server (SuperSocketNetLib\\Certificate, key read, restart)
    ldaps           LDAPS of a domain controller (NTDS\\Personal, renewServerCertificate)
    winrm           the WinRM HTTPS listener
    sstp            RRAS SSTP VPN
    ccs             IIS Central Certificate Store (<name>.pfx files)
    ftp             IIS FTP over TLS
    exchange        Exchange, the services chosen, old ones removed when unbound
    lync            Skype for Business / Lync
    sharepoint      SharePoint Server (Subscription Edition) - beta
    wac             Windows Admin Center (2410+ module, or the older MSI)

then the old acme certificates beyond "keep" that nothing still uses. A role
that fails is said in words (bad), the others still run; the deployment then
fails as a whole, and the old certificates are kept.

    role_fields()               the deploy fields (a switch per role, its fields shown
                                when it is on)
    enabled(options)            the roles a deployment has on
    role_script(key, ...)       the PowerShell of one role (a list of lines)
    RolesMixin                  what windows_ssh mixes in: deploy_roles(), roles_detect(),
                                roles_preview(), roles_dry_run(), roles_import_options(),
                                verify() (+ LDAPS on 636)

Every role first makes sure what it needs is there (the module, the service,
the snap-in) and says plainly when it is not installed. Each step writes
"STEP <level> <words>" lines, which become the job's steps.
"""
from __future__ import annotations

import base64
import re
import secrets

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, as_int, text, sha1_thumb, name_prefix, object_name,
    random_password, put_scp)


def ps_str(s):
    """A PowerShell single-quoted string (the same as windows_ssh.ps_str)."""
    t = text(s)
    for q in ("'", '\u2018', '\u2019', '\u201a', '\u201b'):    # the curly ones end it too (1.0.48)
        t = t.replace(q, q + q)
    return "'" + t + "'"


def encoded(script):
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


CMD_MOST = 8000         # cmd.exe (OpenSSH's default shell) takes 8191 characters at most
MASK = '********'


# ---------------------------------------------------------------------------
# The fields
# ---------------------------------------------------------------------------
def _on(role):
    return {'role_' + role: [True]}


def _f(role, key, label, type='text', **more):
    more.setdefault('show_if', _on(role))
    return field(key, label, type, **more)


ROLES = [
    # key, switch label, title in the steps, needs ('pfx' | 'ccs' | None)
    ('rds', 'Role: Remote Desktop Services (Connection Broker)', 'Remote Desktop Services', 'pfx'),
    ('rdgw', 'Role: RD Gateway (standalone)', 'RD Gateway', None),
    ('adfs', 'Role: AD FS', 'AD FS', None),
    ('wap', 'Role: Web Application Proxy', 'Web Application Proxy', None),
    ('sql', 'Role: SQL Server', 'SQL Server', None),
    ('ldaps', 'Role: LDAPS (domain controller)', 'LDAPS', None),
    ('winrm', 'Role: WinRM HTTPS listener', 'WinRM HTTPS', None),
    ('sstp', 'Role: RRAS SSTP VPN', 'SSTP VPN', None),
    ('ccs', 'Role: IIS Central Certificate Store', 'IIS Central Certificate Store', 'ccs'),
    ('ftp', 'Role: IIS FTP over TLS', 'IIS FTP', None),
    ('exchange', 'Role: Exchange (extended)', 'Exchange', None),
    ('lync', 'Role: Skype for Business / Lync', 'Skype for Business', None),
    ('sharepoint', 'Role: SharePoint Server (beta)', 'SharePoint', 'pfx'),
    ('wac', 'Role: Windows Admin Center', 'Windows Admin Center', None),
]
TITLE = {r[0]: r[2] for r in ROLES}
NEEDS = {r[0]: r[3] for r in ROLES}

ROLE_HELP = {
    'rds': 'Set-RDCertificate for the roles chosen, through the Connection Broker',
    'rdgw': 'the RD Gateway service on this server (RDS:\\GatewayServer), no broker',
    'adfs': 'Set-AdfsSslCertificate, and the Service-Communications certificate when asked; '
            'the service-communications one is set on the primary server only',
    'wap': 'Set-WebApplicationProxySslCertificate; published applications that used an old '
           'certificate move to the new one',
    'sql': 'the instance\'s certificate (SuperSocketNetLib), read on the key for its service '
           'account; the certificate must hold the server\'s FQDN',
    'ldaps': 'the NTDS service store (or LocalMachine\\My), then renewServerCertificate - '
             'no restart',
    'winrm': 'the thumbprint of the HTTPS listener, or a new listener',
    'sstp': 'Set-RemoteAccess -SslCertificate',
    'ccs': 'PFX files named after the host names (_.domain.pfx for a wildcard) in the '
           'store\'s folder, no binding',
    'ftp': 'ftpServer.security.ssl.serverCertHash of a site, or of every site',
    'exchange': 'Enable-ExchangeCertificate for the services chosen (the default SMTP '
                'certificate replaced without asking)',
    'lync': 'Set-CsCertificate for the types chosen',
    'sharepoint': 'beta: Import-SPCertificate, then Set-SPWebApplication for the zone - '
                  'SharePoint Server Subscription Edition only',
    'wac': 'the module of 2410 and later, or (older) the installer run again with '
           'SME_THUMBPRINT - check after the first run',
}

EX_SERVICES = [('ex_iis', 'IIS', True), ('ex_smtp', 'SMTP', True), ('ex_imap', 'IMAP', False),
               ('ex_pop', 'POP', False), ('ex_um', 'UM', False),
               ('ex_umcr', 'UMCallRouter', False)]
RDS_ROLES = [('rds_gateway', 'RDGateway', 'RD Gateway'),
             ('rds_webaccess', 'RDWebAccess', 'RD Web Access'),
             ('rds_publishing', 'RDPublishing', 'RD Publishing'),
             ('rds_redirector', 'RDRedirector', 'RD Connection Broker (redirector)')]
CS_TYPES = [('cs_default', 'Default', 'Default'),
            ('cs_internal', 'WebServicesInternal', 'Web services, internal'),
            ('cs_external', 'WebServicesExternal', 'Web services, external')]
SP_ZONES = ['Default', 'Intranet', 'Internet', 'Extranet', 'Custom']


def _role_own_fields(key):
    if key == 'rds':
        return [_f('rds', k, label, 'bool', default=True) for k, _r, label in RDS_ROLES] + [
            _f('rds', 'rds_broker', 'Connection Broker', placeholder='broker.example.local',
               help='its FQDN; empty: this server')]
    if key == 'rdgw':
        return [_f('rdgw', 'rdgw_restart', 'Restart the RD Gateway service', 'bool',
                   default=True, help='when the certificate changed; open connections drop')]
    if key == 'adfs':
        return [
            _f('adfs', 'adfs_service_comm', 'Also the Service-Communications certificate',
               'bool', default=True, help='Set-AdfsCertificate - on the primary server'),
            _f('adfs', 'adfs_grant', 'Read on the key for the AD FS service account', 'bool',
               default=True, help='the account is read from the adfssrv service'),
            _f('adfs', 'adfs_restart', 'Restart AD FS', 'bool', default=True,
               help='when the certificate changed')]
    if key == 'wap':
        return [_f('wap', 'wap_apps', 'Move published applications to it', 'bool', default=True,
                   help='applications whose external certificate was the old one')]
    if key == 'sql':
        return [
            _f('sql', 'sql_instance', 'SQL Server instance', default='MSSQLSERVER',
               help='MSSQLSERVER is the default instance'),
            _f('sql', 'sql_force', 'Force encryption', 'select', default='keep',
               options=[['keep', 'leave as it is'], ['on', 'on'], ['off', 'off']]),
            _f('sql', 'sql_restart', 'Restart SQL Server', 'bool', default=True,
               help='when something changed; SQL Agent and the other services depending on it '
                    'are started again')]
    if key == 'ldaps':
        return [
            _f('ldaps', 'ldaps_store', 'Store for LDAPS', 'select', default='ntds',
               options=[['ntds', 'NTDS\\Personal (the service store; chosen first)'],
                        ['my', 'LocalMachine\\My only']]),
            _f('ldaps', 'ldaps_verify', 'Check port 636 after', 'bool', default=True,
               help='a TLS handshake to the server on 636')]
    if key == 'winrm':
        return [
            _f('winrm', 'winrm_create', 'Create the HTTPS listener when there is none', 'bool',
               default=False),
            _f('winrm', 'winrm_hostname', 'Host name of a new listener',
               show_if=dict(_on('winrm'), winrm_create=[True]),
               help='empty: the first name of the certificate'),
            _f('winrm', 'winrm_firewall', 'Open 5986 in the firewall', 'bool', default=False)]
    if key == 'sstp':
        return [_f('sstp', 'sstp_restart', 'Restart Remote Access', 'bool', default=True,
                   help='when the certificate changed; VPN connections drop')]
    if key == 'ccs':
        return [
            _f('ccs', 'ccs_path', 'Folder of the store', required=True,
               placeholder='\\\\fileserver\\ccs',
               help='a UNC path or a folder of this server; with key sign-in a UNC path '
                    'needs the computer account (no second hop)'),
            _f('ccs', 'ccs_password', 'Password of the store\'s files', 'secret',
               help='the one set in IIS (Central Certificate Store → private key password)'),
            _f('ccs', 'ccs_names', 'Files for', 'select', default='all',
               options=[['all', 'every name of the certificate'], ['first', 'the first name']])]
    if key == 'ftp':
        return [
            _f('ftp', 'ftp_site', 'FTP site', placeholder='Default FTP Site',
               help='empty: the defaults of every site'),
            _f('ftp', 'ftp_restart', 'Restart the FTP service', 'bool', default=False,
               help='open FTP sessions drop')]
    if key == 'exchange':
        return [_f('exchange', k, 'Exchange: ' + svc, 'bool', default=d)
                for k, svc, d in EX_SERVICES] + [
            _f('exchange', 'ex_remove_old', 'Remove old Exchange certificates no longer bound',
               'bool', default=False, help='acme\'s own (of the same name) whose Services are '
                                           'None'),
            _f('exchange', 'ex_restart', 'Restart IMAP / POP', 'bool', default=True,
               help='those services, when chosen and the certificate changed')]
    if key == 'lync':
        return [_f('lync', k, 'Type: ' + label, 'bool', default=True)
                for k, _t, label in CS_TYPES] + [
            _f('lync', 'cs_restart', 'Restart the Skype for Business services', 'bool',
               default=False, help='Stop-CsWindowsService, Start-CsWindowsService')]
    if key == 'sharepoint':
        return [
            _f('sharepoint', 'sp_url', 'Web application', required=True,
               placeholder='https://intranet.example.com'),
            _f('sharepoint', 'sp_zone', 'Zone', 'select', default='Default',
               options=[[z, z] for z in SP_ZONES]),
            _f('sharepoint', 'sp_port', 'Port', 'number', default=443),
            _f('sharepoint', 'sp_host', 'Host header',
               help='empty: none; with one, SNI is used')]
    if key == 'wac':
        return [
            _f('wac', 'wac_msi', 'Installer (older versions)',
               placeholder='C:\\Install\\WindowsAdminCenter.msi', advanced=True,
               help='only for a version before 2410: the .msi on the server, run again with '
                    'SME_THUMBPRINT'),
            _f('wac', 'wac_port', 'Port (older versions)', 'number', advanced=True,
               help='empty: the one installed')]
    return []


def role_fields():
    """The deploy fields of the roles: a switch each, its own fields shown when it is on;
    then the accounts given read on the key."""
    out = []
    for key, label, _t, _n in ROLES:
        out.append(field('role_' + key, label, 'bool', default=False, help=ROLE_HELP[key]))
        out += _role_own_fields(key)
    out.append(field('key_read', 'Read on the key for', 'list', advanced=True,
                     placeholder='NT Service\\MyService',
                     help='accounts, one a line: given read on the private key after the '
                          'import, before the roles'))
    return out


FIELDS = role_fields()
DEFAULTS = {f['key']: f.get('default') for f in FIELDS}


class Opts(object):
    def __init__(self, options):
        self.o = options or {}

    def get(self, k):
        v = self.o.get(k)
        return DEFAULTS.get(k) if v in (None, '') else v

    def on(self, k):
        return as_bool(self.get(k))

    def s(self, k):
        return text(self.get(k) if self.get(k) is not None else '').strip()


def enabled(options):
    o = Opts(options)
    return [r[0] for r in ROLES if o.on('role_' + r[0])]


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------
HELPERS = [
    ('Say', "function Say([string]$l, [string]$w) { Write-Output ('STEP ' + $l + ' ' + $w) }"),
    ('Run-Native',
     "function Run-Native([string]$exe, [string[]]$a) { $ErrorActionPreference = 'Continue'; "
     "$o = & $exe @a 2>&1 | ForEach-Object { \"$_\" }; "
     "[pscustomobject]@{ rc = $LASTEXITCODE; out = ($o -join \"`n\") } }"),
    ('Need-Module',
     "function Need-Module([string]$m, [string]$r) {\n"
     "  if (-not (Get-Module -ListAvailable -Name $m)) { throw ($r + ': the PowerShell module ' + "
     "$m + ' is not on this server - is the role installed?') }\n"
     "  Import-Module -Name $m -ErrorAction Stop -WarningAction SilentlyContinue "
     "-DisableNameChecking\n}"),
    ('Need-Service',
     "function Need-Service([string]$n, [string]$r) {\n"
     "  $x = Get-Service -Name $n -ErrorAction SilentlyContinue\n"
     "  if (-not $x) { throw ($r + ': the service ' + $n + ' is not on this server - is the "
     "role installed?') }\n  $x\n}"),
    ('Restart-Role',
     "function Restart-Role([string]$n) {\n"
     "  $deps = @((Get-Service -Name $n).DependentServices | Where-Object { $_.Status -eq "
     "'Running' })\n"
     "  Restart-Service -Name $n -Force -ErrorAction Stop\n"
     "  foreach ($d in $deps) { if ((Get-Service -Name $d.Name).Status -ne 'Running') { "
     "Start-Service -Name $d.Name -ErrorAction Stop } }\n"
     "  $also = ''; if ($deps) { $also = ' (and ' + (($deps | ForEach-Object { $_.Name }) "
     "-join ', ') + ')' }\n"
     "  Say ok ('restarted ' + $n + $also)\n}"),
    ('Grant-KeyRead',
     "function Grant-KeyRead($c, [string]$who) {\n"
     "  if ($who -match '^(LocalSystem|NT AUTHORITY\\\\SYSTEM)$') { Say info ('read on the key: ' "
     "+ $who + ' (SYSTEM) has it'); return }\n"
     "  if ($who -match '^(NT AUTHORITY\\\\)?NetworkService$') { $who = 'NT AUTHORITY\\NETWORK "
     "SERVICE' }\n"
     "  if ($who -match '^(NT AUTHORITY\\\\)?LocalService$') { $who = 'NT AUTHORITY\\LOCAL "
     "SERVICE' }\n"
     "  $k = $null; $name = $null\n"
     "  try { $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::"
     "GetRSAPrivateKey($c) } catch { }\n"
     "  if (-not $k) { try { $k = [System.Security.Cryptography.X509Certificates."
     "ECDsaCertificateExtensions]::GetECDsaPrivateKey($c) } catch { } }\n"
     "  if ($k -and ($k.PSObject.Properties.Name -contains 'Key') -and $k.Key) { $name = "
     "$k.Key.UniqueName } elseif ($k -and $k.CspKeyContainerInfo) { $name = "
     "$k.CspKeyContainerInfo.UniqueKeyContainerName }\n"
     "  if (-not $name) { throw ('the private key of ' + $c.Thumbprint + ' was not found') }\n"
     "  $files = @(@(\"$env:ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\", "
     "\"$env:ProgramData\\Microsoft\\Crypto\\Keys\") | ForEach-Object { Join-Path $_ $name } | "
     "Where-Object { Test-Path -LiteralPath $_ })\n"
     "  if (-not $files) { throw ('the key file ' + $name + ' is not under "
     "ProgramData\\Microsoft\\Crypto') }\n"
     "  try { $sid = (New-Object System.Security.Principal.NTAccount($who)).Translate("
     "[System.Security.Principal.SecurityIdentifier]).Value } catch { throw ('the account ' + "
     "$who + ' is not known here') }\n"
     "  foreach ($f in $files) { $r = Run-Native 'icacls.exe' @($f, '/grant', ('*' + $sid + "
     "':(R)')); if ($r.rc -ne 0) { throw ('icacls ' + $f + ': ' + $r.out) } }\n"
     "  Say ok ('read on the key for ' + $who)\n}"),
]
_HELPER_DEPS = {'Restart-Role': ['Say'], 'Grant-KeyRead': ['Say', 'Run-Native']}


def head(thumb, prefix, body):
    """What every role run starts with: the new certificate (it must be in the store)
    and the helpers the body uses."""
    want = set()
    for name, _code in HELPERS:
        if re.search(r'(?<![\w-])%s(?![\w-])' % re.escape(name), body):
            want.add(name)
            want.update(_HELPER_DEPS.get(name, []))
    out = [
        "$thumb = %s" % ps_str(thumb),
        "$prefix = %s" % ps_str(prefix),
        "$store = 'Cert:\\LocalMachine\\My'",
        "$cert = Get-Item -LiteralPath (Join-Path $store $thumb) -ErrorAction SilentlyContinue",
        "if (-not $cert) { throw ('the new certificate ' + $thumb + ' is not in "
        "LocalMachine\\My') }",
    ]
    for name, code in HELPERS:
        if name in want:
            out.append(code)
    return out


def _secure(var, pw):
    if pw:
        return "%s = ConvertTo-SecureString -String %s -AsPlainText -Force" % (var, ps_str(pw))
    return "%s = New-Object System.Security.SecureString" % var


def ccs_file_names(names, which='all'):
    """The file names of the Central Certificate Store: <host>.pfx, _.<domain>.pfx for
    a wildcard."""
    out = []
    for n in (names if which != 'first' else names[:1]):
        n = text(n).strip().lower()
        if not n:
            continue
        if not re.match(r'^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*'
                        r'[a-z0-9_])?)*$', n):
            raise PluginError('%s cannot be a file name of the Central Certificate Store' % n,
                              retry=False)
        f = ('_' + n[1:] if n.startswith('*.') else n) + '.pfx'
        if f not in out:
            out.append(f)
    return out


def check_options(options, names=None):
    """What can be refused before anything is done: words of what is wrong, [] when fine."""
    o = Opts(options)
    bad = []
    on = enabled(options)
    if 'rds' in on and not any(o.on(k) for k, _r, _l in RDS_ROLES):
        bad.append('Remote Desktop Services: choose at least one of its roles')
    if 'sql' in on and not re.match(r'^[A-Za-z0-9_#$]{1,16}$', o.s('sql_instance') or 'x'):
        bad.append('SQL Server: "%s" is not an instance name' % o.s('sql_instance'))
    if 'ccs' in on:
        if not o.s('ccs_path'):
            bad.append('IIS Central Certificate Store: give the folder of the store')
        try:
            ccs_file_names(list(names or []), o.s('ccs_names'))
        except PluginError as e:
            bad.append('IIS Central Certificate Store: %s' % e)
    if 'exchange' in on and not any(o.on(k) for k, _s, _d in EX_SERVICES):
        bad.append('Exchange: choose at least one service')
    if 'lync' in on and not any(o.on(k) for k, _t, _l in CS_TYPES):
        bad.append('Skype for Business: choose at least one certificate type')
    if 'sharepoint' in on:
        if not re.match(r'^https?://[^\s]+$', o.s('sp_url')):
            bad.append('SharePoint: the web application is an URL (https://…)')
        if o.s('sp_zone') not in SP_ZONES:
            bad.append('SharePoint: the zone is one of %s' % ', '.join(SP_ZONES))
    for k in ('sp_port', 'wac_port'):
        if o.s(k) and not (0 < as_int(o.get(k), 0) < 65536):
            bad.append('%s is not a port' % o.s(k))
    return bad


def role_script(key, options, env):
    """The PowerShell lines of one role (without the head). env: names, pfx, pfx_pw,
    ccs_pfx, ccs_pw."""
    o = Opts(options)
    T = TITLE[key]
    t = ps_str(T)
    sc = []
    if key == 'rds':
        roles = [r for k, r, _l in RDS_ROLES if o.on(k)]
        broker = o.s('rds_broker')
        sc += [
            "Need-Module 'RemoteDesktop' %s" % t,
            "$broker = %s" % (ps_str(broker) if broker else
                              "[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName"),
            _secure('$pfxpw', env.get('pfx_pw')),
            "foreach ($r in @(%s)) {" % ', '.join(ps_str(r) for r in roles),
            "  try { $cur = Get-RDCertificate -Role $r -ConnectionBroker $broker -ErrorAction "
            "Stop } catch { throw ('Remote Desktop Services: the Connection Broker ' + $broker + "
            "' could not be asked: ' + $_.Exception.Message) }",
            "  if ($cur -and $cur.Thumbprint -eq $thumb) { Say ok ('RDS ' + $r + ' already uses "
            "it'); continue }",
            "  Set-RDCertificate -Role $r -ImportPath %s -Password $pfxpw -ConnectionBroker "
            "$broker -Force -ErrorAction Stop" % ps_str(env.get('pfx') or ''),
            "  Say ok ('RDS ' + $r + ' uses it')",
            "}",
        ]
    elif key == 'rdgw':
        sc += [
            "Need-Service 'TSGateway' %s | Out-Null" % t,
            "Need-Module 'RemoteDesktopServices' %s" % t,
            "Grant-KeyRead $cert 'NT AUTHORITY\\NETWORK SERVICE'",
            "$p = 'RDS:\\GatewayServer\\SSLCertificate\\Thumbprint'",
            "$cur = [string](Get-Item -Path $p -ErrorAction Stop).CurrentValue",
            "if ($cur -eq $thumb) { Say ok 'RD Gateway already uses it' } else {",
            "  Set-Item -Path $p -Value $thumb -ErrorAction Stop",
            "  Say ok 'RD Gateway uses it'",
        ]
        if o.on('rdgw_restart'):
            sc.append("  Restart-Role 'TSGateway'")
        sc.append("}")
    elif key == 'adfs':
        sc += [
            "$svc = Get-CimInstance -ClassName Win32_Service -Filter \"Name='adfssrv'\"",
            "if (-not $svc) { throw 'AD FS: the service adfssrv is not on this server - is the "
            "role installed?' }",
            "Need-Module 'ADFS' %s" % t,
        ]
        if o.on('adfs_grant'):
            sc.append("Grant-KeyRead $cert $svc.StartName")
        sc += [
            "$changed = $false",
            "$ssl = @(Get-AdfsSslCertificate -ErrorAction Stop)",
            "if ($ssl.Count -and -not @($ssl | Where-Object { [string]$_.CertificateHash -ne "
            "$thumb }).Count) { Say ok 'AD FS SSL already uses it' } else {",
            "  Set-AdfsSslCertificate -Thumbprint $thumb -ErrorAction Stop; $changed = $true; "
            "Say ok 'AD FS SSL uses it' }",
        ]
        if o.on('adfs_service_comm'):
            sc += [
                "$sc = Get-AdfsCertificate -CertificateType Service-Communications -ErrorAction "
                "Stop | Select-Object -First 1",
                "if ($sc -and $sc.Thumbprint -eq $thumb) { Say ok 'AD FS Service-Communications "
                "already uses it' } else {",
                "  Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumb "
                "-ErrorAction Stop; $changed = $true; Say ok 'AD FS Service-Communications uses "
                "it' }",
            ]
        if o.on('adfs_restart'):
            sc.append("if ($changed) { Restart-Role 'adfssrv' }")
    elif key == 'wap':
        sc += [
            "Need-Module 'WebApplicationProxy' %s" % t,
            "$cur = @(Get-WebApplicationProxySslCertificate -ErrorAction Stop)",
            "$olds = @($cur | ForEach-Object { [string]$_.CertificateHash } | Where-Object { $_ "
            "-and $_ -ne $thumb })",
            "$olds += @(Get-ChildItem $store | Where-Object { $_.FriendlyName -match ('^' + "
            "[regex]::Escape($prefix) + '\\d{8}-[0-9a-f]+$') -and $_.Thumbprint -ne $thumb } | "
            "ForEach-Object { $_.Thumbprint })",
            "if ($cur.Count -and -not @($cur | Where-Object { [string]$_.CertificateHash -ne "
            "$thumb }).Count) { Say ok 'Web Application Proxy already uses it' } else {",
            "  Set-WebApplicationProxySslCertificate -Thumbprint $thumb -ErrorAction Stop; Say "
            "ok 'Web Application Proxy uses it' }",
        ]
        if o.on('wap_apps'):
            sc += [
                "$apps = @(Get-WebApplicationProxyApplication -ErrorAction Stop | Where-Object { "
                "$_.ExternalCertificateThumbprint -and ($olds -contains "
                "$_.ExternalCertificateThumbprint) })",
                "foreach ($a in $apps) { Set-WebApplicationProxyApplication -ID $a.ID "
                "-ExternalCertificateThumbprint $thumb -ErrorAction Stop; Say ok ('WAP "
                "application ' + $a.Name + ' uses it') }",
                "if (-not $apps) { Say info 'no published application was on an old "
                "certificate' }",
            ]
    elif key == 'sql':
        inst = o.s('sql_instance') or 'MSSQLSERVER'
        force = o.s('sql_force') or 'keep'
        sc += [
            "$inst = %s" % ps_str(inst),
            "$map = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL'",
            "if (-not (Test-Path -LiteralPath $map)) { throw 'SQL Server: no instance is "
            "installed on this server' }",
            "$names = Get-ItemProperty -LiteralPath $map",
            "$id = $names.$inst",
            "if (-not $id) { throw ('SQL Server: there is no instance ' + $inst + '; there are: ' "
            "+ (($names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | "
            "ForEach-Object { $_.Name }) -join ', ')) }",
            "$key = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\' + $id + "
            "'\\MSSQLServer\\SuperSocketNetLib'",
            "if (-not (Test-Path -LiteralPath $key)) { throw ('SQL Server: ' + $key + ' is not "
            "there') }",
            "if ($inst -eq 'MSSQLSERVER') { $svcName = 'MSSQLSERVER' } else { $svcName = "
            "'MSSQL$' + $inst }",
            "$svc = Get-CimInstance -ClassName Win32_Service -Filter (\"Name='\" + $svcName + "
            "\"'\")",
            "if (-not $svc) { throw ('SQL Server: the service ' + $svcName + ' is not there') }",
            "Grant-KeyRead $cert $svc.StartName",
            "$changed = $false",
            "$want = $thumb.ToLowerInvariant()",
            "$cur = [string](Get-ItemProperty -LiteralPath $key -ErrorAction "
            "SilentlyContinue).Certificate",
            "if ($cur -ceq $want) { Say ok ('SQL Server ' + $inst + ' already uses it') } else {",
            "  New-ItemProperty -LiteralPath $key -Name 'Certificate' -Value $want -PropertyType "
            "String -Force | Out-Null; $changed = $true; Say ok ('SQL Server ' + $inst + ' uses "
            "it') }",
        ]
        if force in ('on', 'off'):
            v = 1 if force == 'on' else 0
            sc += [
                "$fe = (Get-ItemProperty -LiteralPath $key -ErrorAction "
                "SilentlyContinue).ForceEncryption",
                "if ($fe -ne %d) { New-ItemProperty -LiteralPath $key -Name 'ForceEncryption' "
                "-Value %d -PropertyType DWord -Force | Out-Null; $changed = $true; Say ok "
                "'SQL Server ForceEncryption %s' }" % (v, v, force),
            ]
        if o.on('sql_restart'):
            sc.append("if ($changed) { Restart-Role $svcName } ")
        else:
            sc.append("if ($changed) { Say warn ('SQL Server takes it when ' + $svcName + ' is "
                      "restarted') }")
    elif key == 'ldaps':
        sc += [
            "Need-Service 'NTDS' %s | Out-Null" % t,
            "if (-not (Get-Command ldifde.exe -ErrorAction SilentlyContinue)) { throw 'LDAPS: "
            "ldifde.exe is not on this server - is it a domain controller?' }",
        ]
        if o.s('ldaps_store') != 'my':
            sc += [
                "$src = 'HKLM:\\SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates\\' + "
                "$thumb",
                "$dst = 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\Services\\NTDS\\"
                "SystemCertificates\\My\\Certificates'",
                "if (-not (Test-Path -LiteralPath $src)) { throw ('LDAPS: ' + $src + ' is not "
                "there') }",
                "if (-not (Test-Path -LiteralPath $dst)) { New-Item -Path $dst -Force | Out-Null }",
                "if (Test-Path -LiteralPath (Join-Path $dst $thumb)) { Say ok 'LDAPS: already in "
                "NTDS\\Personal' } else { Copy-Item -LiteralPath $src -Destination $dst -Recurse "
                "-ErrorAction Stop; Say ok 'LDAPS: put into NTDS\\Personal' }",
                "$olds = @(Get-ChildItem $store | Where-Object { $_.FriendlyName -match ('^' + "
                "[regex]::Escape($prefix) + '\\d{8}-[0-9a-f]+$') -and $_.Thumbprint -ne $thumb } | "
            "ForEach-Object { $_.Thumbprint })",
                "foreach ($x in @(Get-ChildItem -LiteralPath $dst)) { if ($olds -contains "
                "$x.PSChildName) { Remove-Item -LiteralPath $x.PSPath -Recurse -Force; Say info "
                "('LDAPS: the old ' + $x.PSChildName + ' left NTDS\\Personal') } }",
            ]
        sc += [
            "$ldf = Join-Path $env:TEMP ('acme-ldaps-' + [guid]::NewGuid().ToString('N') + "
            "'.ldf')",
            "Set-Content -LiteralPath $ldf -Value \"dn:`r`nchangetype: modify`r`nadd: "
            "renewServerCertificate`r`nrenewServerCertificate: 1`r`n-`r`n\" -Encoding ASCII",
            "try { $r = Run-Native 'ldifde.exe' @('-i', '-f', $ldf) } finally { Remove-Item "
            "-LiteralPath $ldf -Force -ErrorAction SilentlyContinue }",
            "if ($r.rc -ne 0) { throw ('LDAPS: ldifde could not ask for renewServerCertificate: ' "
            "+ $r.out) }",
            "Say ok 'LDAPS: the domain controller took the certificate (renewServerCertificate)'",
        ]
    elif key == 'winrm':
        hostname = o.s('winrm_hostname') or next(
            (n for n in env.get('names') or [] if not text(n).startswith('*.')), '')
        sc += [
            "Need-Service 'WinRM' %s | Out-Null" % t,
            "$changed = $false",
            "$ls = @(Get-ChildItem -Path WSMan:\\localhost\\Listener | Where-Object { $_.Keys "
            "-contains 'Transport=HTTPS' })",
            "foreach ($l in $ls) {",
            "  $p = 'WSMan:\\localhost\\Listener\\' + $l.Name + '\\CertificateThumbprint'",
            "  $cur = [string](Get-Item -Path $p).Value",
            "  if ($cur -eq $thumb) { Say ok ('WinRM ' + $l.Name + ' already uses it') } else { "
            "Set-Item -Path $p -Value $thumb -Force -ErrorAction Stop; $changed = $true; Say ok "
            "('WinRM ' + $l.Name + ' uses it') }",
            "}",
        ]
        if o.on('winrm_create'):
            sc += [
                "$h = %s" % (ps_str(hostname) if hostname else
                             "[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName"),
                "if (-not $ls) { New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS "
                "-Address * -HostName $h -CertificateThumbPrint $thumb -Force -ErrorAction Stop | "
                "Out-Null; $changed = $true; Say ok ('WinRM: an HTTPS listener for ' + $h + ' was "
                "made') }",
            ]
        else:
            sc.append("if (-not $ls) { throw 'WinRM: there is no HTTPS listener - turn on "
                      "\"Create the HTTPS listener\"' }")
        if o.on('winrm_firewall'):
            sc += [
                "if (Get-NetFirewallRule -Name 'acme-WinRM-HTTPS-In' -ErrorAction "
                "SilentlyContinue) { Say ok 'firewall: 5986 already open' } else {",
                "  New-NetFirewallRule -Name 'acme-WinRM-HTTPS-In' -DisplayName 'Windows Remote "
                "Management (HTTPS-In, acme)' -Direction Inbound -Protocol TCP -LocalPort 5986 "
                "-Action Allow -Profile Any -ErrorAction Stop | Out-Null; Say ok 'firewall: 5986 "
                "open' }",
            ]
        sc.append("if ($changed) { Restart-Role 'WinRM' }")
    elif key == 'sstp':
        sc += [
            "Need-Service 'RemoteAccess' %s | Out-Null" % t,
            "Need-Module 'RemoteAccess' %s" % t,
            "$cur = (Get-RemoteAccess -ErrorAction Stop).SslCertificate",
            "if ($cur -and $cur.Thumbprint -eq $thumb) { Say ok 'SSTP already uses it' } else {",
            "  Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop",
            "  Say ok 'SSTP uses it'",
        ]
        if o.on('sstp_restart'):
            sc.append("  Restart-Role 'RemoteAccess'")
        sc.append("}")
    elif key == 'ccs':
        files = ccs_file_names(list(env.get('names') or []), o.s('ccs_names'))
        sc += [
            "$dir = %s" % ps_str(o.s('ccs_path')),
            "if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw ('IIS Central "
            "Certificate Store: the folder ' + $dir + ' cannot be reached from this session') }",
            _secure('$ccspw', env.get('ccs_pw')),
            "$src = %s" % ps_str(env.get('ccs_pfx') or ''),
            "foreach ($n in @(%s)) {" % ', '.join(ps_str(f) for f in files),
            "  $dstf = Join-Path $dir $n",
            "  $same = $false",
            "  if (Test-Path -LiteralPath $dstf) { try { $same = [bool](@((Get-PfxData -FilePath "
            "$dstf -Password $ccspw -ErrorAction Stop).EndEntityCertificates) | Where-Object { "
            "$_.Thumbprint -eq $thumb }) } catch { $same = $false } }",
            "  if ($same) { Say ok ('CCS: ' + $n + ' already holds it') } else { Copy-Item "
            "-LiteralPath $src -Destination $dstf -Force -ErrorAction Stop; Say ok ('CCS: wrote ' "
            "+ $n) }",
            "}",
        ]
    elif key == 'ftp':
        site = o.s('ftp_site')
        sc += [
            "Need-Service 'ftpsvc' %s | Out-Null" % t,
            "Add-Type -Path \"$env:windir\\System32\\inetsrv\\Microsoft.Web.Administration.dll\"",
            "$sm = New-Object Microsoft.Web.Administration.ServerManager",
        ]
        if site:
            sc += [
                "$site = %s" % ps_str(site),
                "$s = $sm.Sites[$site]",
                "if (-not $s) { throw ('IIS FTP: there is no site ' + $site) }",
                "$ssl = $s.GetChildElement('ftpServer').GetChildElement('security')."
                "GetChildElement('ssl')",
                "$where = 'FTP site ' + $site",
            ]
        else:
            sc += [
                "$ssl = $sm.SiteDefaults.GetChildElement('ftpServer').GetChildElement('security')"
                ".GetChildElement('ssl')",
                "$where = 'FTP (every site)'",
            ]
        sc += [
            "if ([string]$ssl.GetAttributeValue('serverCertHash') -eq $thumb) { Say ok ($where + "
            "' already uses it') } else {",
            "  $ssl.SetAttributeValue('serverCertHash', $thumb); $ssl.SetAttributeValue("
            "'serverCertStoreName', 'My'); $sm.CommitChanges(); Say ok ($where + ' uses it')",
        ]
        if o.on('ftp_restart'):
            sc.append("  Restart-Role 'ftpsvc'")
        sc.append("}")
    elif key == 'exchange':
        want = [svc for k, svc, _d in EX_SERVICES if o.on(k)]
        sc += [
            "if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue)) {",
            "  $snap = 'Microsoft.Exchange.Management.PowerShell.SnapIn'",
            "  if (-not (Get-PSSnapin -Registered -Name $snap -ErrorAction SilentlyContinue)) { "
            "throw 'Exchange: the Exchange Management Shell is not on this server - is Exchange "
            "installed?' }",
            "  Add-PSSnapin $snap",
            "}",
            "$ec = Get-ExchangeCertificate -Thumbprint $thumb -ErrorAction Stop",
            "$have = @(([string]$ec.Services) -split '[,\\s]+' | Where-Object { $_ })",
            "$want = @(%s)" % ', '.join(ps_str(x) for x in want),
            "$missing = @($want | Where-Object { $have -notcontains $_ })",
            "$changed = $false",
            "if (-not $missing) { Say ok ('Exchange already uses it for ' + ($want -join ', ')) "
            "} else {",
            "  Enable-ExchangeCertificate -Thumbprint $thumb -Services ($want -join ',') -Force "
            "-Confirm:$false -ErrorAction Stop; $changed = $true",
            "  Say ok ('Exchange uses it for ' + ($want -join ', ')) }",
        ]
        if o.on('ex_restart'):
            if 'IMAP' in want:
                sc.append("if ($changed) { foreach ($n in @('MSExchangeIMAP4', "
                          "'MSExchangeIMAP4BE')) { if (Get-Service -Name $n -ErrorAction "
                          "SilentlyContinue) { Restart-Role $n } } }")
            if 'POP' in want:
                sc.append("if ($changed) { foreach ($n in @('MSExchangePOP3', "
                          "'MSExchangePOP3BE')) { if (Get-Service -Name $n -ErrorAction "
                          "SilentlyContinue) { Restart-Role $n } } }")
        if o.on('ex_remove_old'):
            sc += [
                "foreach ($x in @(Get-ExchangeCertificate | Where-Object { $_.Thumbprint -ne "
                "$thumb -and $_.FriendlyName -match ('^' + [regex]::Escape($prefix) + "
                "'\\d{8}-[0-9a-f]+$') })) {",
                "  if ([string]$x.Services -eq 'None') { Remove-ExchangeCertificate -Thumbprint "
                "$x.Thumbprint -Confirm:$false -ErrorAction Stop; Say ok ('Exchange: removed the "
                "old ' + $x.Thumbprint) }",
                "  else { Say warn ('Exchange: the old ' + $x.Thumbprint + ' is still bound to ' + "
                "$x.Services + ' - kept') }",
                "}",
            ]
    elif key == 'lync':
        types = [ty for k, ty, _l in CS_TYPES if o.on(k)]
        sc += [
            "$m = @('SkypeForBusiness', 'Lync') | Where-Object { Get-Module -ListAvailable -Name "
            "$_ } | Select-Object -First 1",
            "if (-not $m) { throw 'Skype for Business: neither the SkypeForBusiness nor the Lync "
            "module is on this server - is it installed?' }",
            "Import-Module -Name $m -ErrorAction Stop -WarningAction SilentlyContinue",
            "$cur = @(Get-CsCertificate -ErrorAction Stop)",
            "$changed = $false",
            "foreach ($ty in @(%s)) {" % ', '.join(ps_str(x) for x in types),
            "  if (@($cur | Where-Object { [string]$_.Use -eq $ty -and $_.Thumbprint -eq $thumb })"
            ".Count) { Say ok ('Skype for Business ' + $ty + ' already uses it'); continue }",
            "  Set-CsCertificate -Type $ty -Thumbprint $thumb -Confirm:$false -ErrorAction Stop; "
            "$changed = $true",
            "  Say ok ('Skype for Business ' + $ty + ' uses it')",
            "}",
        ]
        if o.on('cs_restart'):
            sc.append("if ($changed) { Stop-CsWindowsService -ErrorAction Stop; "
                      "Start-CsWindowsService -ErrorAction Stop; Say ok 'Skype for Business "
                      "services restarted' }")
    elif key == 'sharepoint':
        args = "-Identity $url -Zone %s -Port %d -SecureSocketsLayer -Certificate $spc" % (
            ps_str(o.s('sp_zone') or 'Default'), as_int(o.get('sp_port'), 443) or 443)
        if o.s('sp_host'):
            args += " -HostHeader %s -UseServerNameIndication" % ps_str(o.s('sp_host'))
        sc += [
            "$snap = 'Microsoft.SharePoint.PowerShell'",
            "if (-not (Get-PSSnapin -Name $snap -ErrorAction SilentlyContinue)) {",
            "  if (-not (Get-PSSnapin -Registered -Name $snap -ErrorAction SilentlyContinue)) { "
            "throw 'SharePoint: the SharePoint snap-in is not on this server - is SharePoint "
            "Server installed?' }",
            "  Add-PSSnapin $snap }",
            "if (-not (Get-Command Import-SPCertificate -ErrorAction SilentlyContinue)) { throw "
            "'SharePoint: Import-SPCertificate is missing - certificate management needs "
            "SharePoint Server Subscription Edition' }",
            "$url = %s" % ps_str(o.s('sp_url')),
            _secure('$pfxpw', env.get('pfx_pw')),
            "$spc = Get-SPCertificate -ErrorAction SilentlyContinue | Where-Object { "
            "$_.Thumbprint -eq $thumb } | Select-Object -First 1",
            "if ($spc) { Say ok 'SharePoint already has it' } else {",
            "  Import-SPCertificate -Path %s -Password $pfxpw -Exportable -ErrorAction Stop | "
            "Out-Null" % ps_str(env.get('pfx') or ''),
            "  $spc = Get-SPCertificate | Where-Object { $_.Thumbprint -eq $thumb } | "
            "Select-Object -First 1",
            "  if (-not $spc) { throw 'SharePoint: the certificate is not in SharePoint after the "
            "import' }",
            "  Say ok 'SharePoint: imported' }",
            "Set-SPWebApplication %s -ErrorAction Stop" % args,
            "Say ok ('SharePoint: ' + $url + ' uses it')",
        ]
    elif key == 'wac':
        port = as_int(o.get('wac_port'), 0)
        sc += [
            "$new = Get-Service -Name 'WindowsAdminCenter' -ErrorAction SilentlyContinue",
            "$old = Get-Service -Name 'ServerManagementGateway' -ErrorAction SilentlyContinue",
            "if ($new) {",
            "  $mod = Get-Module -ListAvailable -Name 'Microsoft.WindowsAdminCenter.Configuration' "
            "| Select-Object -First 1",
            "  if (-not $mod) { $psd = Join-Path $env:ProgramFiles 'WindowsAdminCenter\\"
            "PowerShellModules\\Microsoft.WindowsAdminCenter.Configuration\\"
            "Microsoft.WindowsAdminCenter.Configuration.psd1'; if (Test-Path -LiteralPath $psd) "
            "{ $mod = $psd } else { throw 'Windows Admin Center: the module "
            "Microsoft.WindowsAdminCenter.Configuration is not there' } }",
            "  Import-Module $mod -ErrorAction Stop -WarningAction SilentlyContinue "
            "-DisableNameChecking",
            "  $subj = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates."
            "X509NameType]::SimpleName, $false)",
            "  $cmd = Get-Command Set-WACCertificateSubjectName -ErrorAction Stop",
            "  $a = @{ SubjectName = $subj }",
            "  if ($cmd.Parameters.ContainsKey('Thumbprint')) { $a['Thumbprint'] = $thumb }",
            "  Set-WACCertificateSubjectName @a -ErrorAction Stop",
            "  if (Get-Command Set-WACCertificateAcl -ErrorAction SilentlyContinue) { "
            "Set-WACCertificateAcl -SubjectName $subj -ErrorAction Stop }",
            "  Say ok ('Windows Admin Center uses it (' + $subj + ')')",
            "  Restart-Role 'WindowsAdminCenter'",
            "} elseif ($old) {",
            "  $port = %d" % port,
            "  if (-not $port) { $port = [int](Get-ItemProperty -LiteralPath "
            "'HKLM:\\SOFTWARE\\Microsoft\\ServerManagementGateway' -ErrorAction "
            "SilentlyContinue).SmePort }",
            "  if (-not $port) { $port = 443 }",
            "  $r = Run-Native 'netsh.exe' @('http', 'show', 'sslcert', ('ipport=0.0.0.0:' + "
            "$port))",
            "  if ($r.out -match $thumb) { Say ok ('Windows Admin Center (older) already uses it "
            "on ' + $port) } else {",
            "    $msi = %s" % ps_str(o.s('wac_msi')),
            "    if (-not $msi) { throw 'Windows Admin Center: this is a version before 2410 - "
            "give the path of its .msi (Installer) to set the certificate' }",
            "    if (-not (Test-Path -LiteralPath $msi)) { throw ('Windows Admin Center: ' + $msi "
            "+ ' is not there') }",
            "    $log = Join-Path $env:TEMP 'acme-wac-msi.log'",
            "    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('\"' + $msi + "
            "'\"'), '/qn', '/L*v', ('\"' + $log + '\"'), ('SME_PORT=' + $port), "
            "('SME_THUMBPRINT=' + $thumb), 'SSL_CERTIFICATE_OPTION=installed') -Wait -PassThru",
            "    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw ('Windows Admin Center: "
            "msiexec ended with ' + $p.ExitCode + ' (its log: ' + $log + ')') }",
            "    Say ok ('Windows Admin Center (older) uses it on ' + $port) }",
            "} else { throw 'Windows Admin Center is not on this server (no service "
            "WindowsAdminCenter or ServerManagementGateway)' }",
        ]
    return sc


def key_read_script(accounts):
    return ["Grant-KeyRead $cert %s" % ps_str(a) for a in accounts]


def cleanup_script(prefix, keep):
    """The old acme certificates beyond `keep` that nothing uses (IIS, http.sys - AD FS,
    WAP, SSTP, RD Gateway -, RDP, SQL Server, WinRM) leave LocalMachine\\My."""
    return [
        "$used = @()",
        "if (Get-Module -ListAvailable WebAdministration) { Import-Module WebAdministration; "
        "$used += @(Get-ChildItem IIS:\\SslBindings -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Thumbprint }) }",
        "$r = Run-Native 'netsh.exe' @('http', 'show', 'sslcert')",
        "$used += @([regex]::Matches($r.out, '(?im):\\s*([0-9a-f]{40})\\s*$') | ForEach-Object { "
        "$_.Groups[1].Value })",
        "try { $used += @(Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName "
        "Win32_TSGeneralSetting -ErrorAction Stop | ForEach-Object { $_.SSLCertificateSHA1Hash }) "
        "} catch { }",
        "$used += @(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server' -ErrorAction "
        "SilentlyContinue | ForEach-Object { $p = Join-Path $_.PSPath "
        "'MSSQLServer\\SuperSocketNetLib'; if (Test-Path -LiteralPath $p) { (Get-ItemProperty "
        "-LiteralPath $p -ErrorAction SilentlyContinue).Certificate } })",
        "try { $used += @(Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction Stop | "
        "ForEach-Object { (Get-Item -Path ('WSMan:\\localhost\\Listener\\' + $_.Name + "
        "'\\CertificateThumbprint')).Value }) } catch { }",
        "$used = @($used | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpperInvariant() "
        "})",
        "$old = Get-ChildItem $store | Where-Object { $_.FriendlyName -match ('^' + "
        "[regex]::Escape(%s) + '\\d{8}-[0-9a-f]+$') -and $_.Thumbprint "
        "-ne $thumb } | Sort-Object NotBefore -Descending | Select-Object -Skip %d"
        % (ps_str(prefix), keep),
        "foreach ($x in $old) { if ($used -contains $x.Thumbprint) { Say warn ('the old ' + "
        "$x.Thumbprint + ' is still used: kept') } else { Remove-Item -LiteralPath $x.PSPath; "
        "Say info ('removed the old ' + $x.Thumbprint) } }",
    ]


DETECT = [
    "function R([string]$k, $y, [string]$d) { if ($y) { $w = 'yes' } else { $w = 'no' }; "
    "Write-Output ('ROLE ' + $k + ' ' + $w + ' ' + $d) }",
    "function HasSvc([string]$n) { [bool](Get-Service -Name $n -ErrorAction SilentlyContinue) }",
    "function HasMod([string]$n) { [bool](Get-Module -ListAvailable -Name $n) }",
    "try { $d = ''; if (HasSvc 'Tssdis') { $d = 'Connection Broker here' }; R rds (HasMod "
    "'RemoteDesktop') $d } catch { R rds $false '?' }",
    "try { R rdgw (HasSvc 'TSGateway') '' } catch { R rdgw $false '?' }",
    "try { R adfs (HasSvc 'adfssrv') '' } catch { R adfs $false '?' }",
    "try { R wap (HasMod 'WebApplicationProxy') '' } catch { R wap $false '?' }",
    "try { $k = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL "
    "Server\\Instance Names\\SQL' -ErrorAction SilentlyContinue; $n = @(); if ($k) { $n = "
    "@($k.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "
    "$_.Name }) }; R sql ($n.Count -gt 0) ($n -join ', ') } catch { R sql $false '?' }",
    "try { R ldaps (HasSvc 'NTDS') '' } catch { R ldaps $false '?' }",
    "try { $n = 0; if (HasSvc 'WinRM') { try { $n = @(Get-ChildItem WSMan:\\localhost\\Listener "
    "-ErrorAction Stop | Where-Object { $_.Keys -contains 'Transport=HTTPS' }).Count } catch { } "
    "}; R winrm (HasSvc 'WinRM') ([string]$n + ' HTTPS listener(s)') } catch { R winrm $false "
    "'?' }",
    "try { R sstp ((HasSvc 'RemoteAccess') -and (HasMod 'RemoteAccess')) '' } catch { R sstp "
    "$false '?' }",
    "try { $c = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\IIS\\"
    "CentralCertProvider' -ErrorAction SilentlyContinue; $d = 'not set up'; if ($c -and "
    "$c.Enabled -eq 1) { $d = [string]$c.CertStoreLocation }; R ccs (HasSvc 'W3SVC') $d } catch "
    "{ R ccs $false '?' }",
    "try { R ftp (HasSvc 'ftpsvc') '' } catch { R ftp $false '?' }",
    "try { R exchange ([bool](Get-PSSnapin -Registered -Name "
    "'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) '' } "
    "catch { R exchange $false '?' }",
    "try { R lync ((HasMod 'SkypeForBusiness') -or (HasMod 'Lync')) '' } catch { R lync $false "
    "'?' }",
    "try { R sharepoint ([bool](Get-PSSnapin -Registered -Name 'Microsoft.SharePoint.PowerShell' "
    "-ErrorAction SilentlyContinue)) '' } catch { R sharepoint $false '?' }",
    "try { if (HasSvc 'WindowsAdminCenter') { R wac $true '2410 or later' } elseif (HasSvc "
    "'ServerManagementGateway') { R wac $true 'before 2410' } else { R wac $false '' } } catch "
    "{ R wac $false '?' }",
]


def parse_detect(out):
    """-> {role: (yes, detail)}"""
    got = {}
    for line in text(out).splitlines():
        m = re.match(r'^ROLE (\w+) (yes|no) ?(.*)$', line.strip())
        if m:
            got[m.group(1)] = (m.group(2) == 'yes', m.group(3).strip())
    return got


# ---------------------------------------------------------------------------
# What windows_ssh mixes in
# ---------------------------------------------------------------------------
class RolesMixin(object):
    """The roles of a deployment: run after the import, before the files."""

    def _roles_tmp(self):
        return (self.c('tmp_dir') or 'C:/Windows/Temp').rstrip('/\\')

    def roles_ps(self, s, script, what='PowerShell', check=True, timeout=600):
        """Run a script: as -EncodedCommand while it fits cmd.exe's line, else uploaded as
        a .ps1 that deletes itself as it starts. -> (rc, out, err)"""
        body = ("$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n"
                "try {\n%s\n} catch { Write-Output ('ERROR: ' + $_.Exception.Message); "
                "exit 1 }\n" % script)
        base_cmd = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
        cmd = base_cmd + '-EncodedCommand ' + encoded(body)
        if len(cmd) > CMD_MOST:
            path = '%s/acme-%s.ps1' % (self._roles_tmp(), secrets.token_hex(6))
            first = "Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\n"
            put_scp(s, b'\xef\xbb\xbf' + (first + body).encode('utf-8'), path)
            cmd = base_cmd + '-File "%s"' % path
        rc, out, err = s.run(cmd, timeout=timeout, check=False)
        out, err = text(out), text(err)
        if check and rc != 0:
            said = [x[7:] for x in out.splitlines() if x.startswith('ERROR: ')]
            raise PluginError('%s failed: %s' % (what, (said[-1] if said else
                                                        (err.strip() or out.strip())[-300:])),
                              detail=out + err)
        return rc, out, err

    def _roles_steps(self, out):
        for line in text(out).splitlines():
            m = re.match(r'^STEP (ok|info|warn|bad) (.*)$', line.strip())
            if m:
                self.ctx.step(m.group(2), m.group(1))

    # -- before the import ----------------------------------------------------------
    def roles_import_options(self, options, bundle=None):
        """The options for windows_ssh.script(): with a role on, the old certificates are
        removed after the roles (here), not by the import. Refuses what cannot work before
        anything is done."""
        options = options or {}
        bad = check_options(options, getattr(bundle, 'names', None) or [])
        if bad:
            raise PluginError('; '.join(bad), retry=False)
        if enabled(options):
            o = dict(options)
            o['keep'] = -1
            return o
        return options

    # -- the scripts -------------------------------------------------------------------
    def _roles_plan(self, bundle, options, env):
        """[(key, title, full script)] - the key-read step first, then the roles."""
        thumb = sha1_thumb(bundle)
        prefix = name_prefix(bundle, options)
        plan = []
        accounts = lines((options or {}).get('key_read'))
        if accounts:
            body = key_read_script(accounts)
            plan.append(('key_read', 'read on the key',
                         '\n'.join(head(thumb, prefix, '\n'.join(body)) + body)))
        for key in enabled(options):
            body = role_script(key, options, env)
            plan.append((key, TITLE[key], '\n'.join(head(thumb, prefix, '\n'.join(body)) + body)))
        return plan

    def _roles_env(self, bundle, masked=False):
        return {'names': list(getattr(bundle, 'names', None) or [getattr(bundle, 'name', '')]),
                'pfx': '%s/acme-roles-<random>.pfx' % self._roles_tmp() if masked else None,
                'pfx_pw': MASK if masked else None,
                'ccs_pfx': '%s/acme-ccs-<random>.pfx' % self._roles_tmp() if masked else None,
                'ccs_pw': MASK if masked else None}

    def roles_script_text(self, bundle, options):
        """All of it, as it would run (passwords as ********) - for a preview."""
        plan = self._roles_plan(bundle, options, self._roles_env(bundle, masked=True))
        return '\n\n'.join('# --- %s ---\n%s' % (title, sc) for _k, title, sc in plan)

    # -- deploying ---------------------------------------------------------------------
    def deploy_roles(self, s, bundle, options):
        """After the import: key read, each role, then the old certificates. -> words for
        the result ([] with no role). Raises when a role failed (the others still ran)."""
        options = options or {}
        on = enabled(options)
        accounts = lines(options.get('key_read'))
        if not on and not accounts:
            return []
        o = Opts(options)
        env = self._roles_env(bundle)
        uploads = []
        failed, did = [], []
        if on:
            self.ctx.step('roles on the server: %s' % ', '.join(TITLE[k] for k in on))
        try:
            fmt = options.get('pfx_format') or 'p12-legacy'
            alias = object_name(bundle, options)
            if any(NEEDS[k] == 'pfx' for k in on):
                env['pfx_pw'] = random_password()
                env['pfx'] = '%s/acme-roles-%s.pfx' % (self._roles_tmp(), secrets.token_hex(6))
                put_scp(s, bundle.as_format(fmt, password=env['pfx_pw'], alias=alias), env['pfx'])
                uploads.append(env['pfx'])
            if 'ccs' in on:
                env['ccs_pw'] = o.s('ccs_password')
                env['ccs_pfx'] = '%s/acme-ccs-%s.pfx' % (self._roles_tmp(), secrets.token_hex(6))
                put_scp(s, bundle.as_format(fmt, password=env['ccs_pw'], alias=alias),
                        env['ccs_pfx'])
                uploads.append(env['ccs_pfx'])
            for key, title, sc in self._roles_plan(bundle, options, env):
                if self.ctx.cancelled():
                    raise PluginError('stopped before %s' % title)
                try:
                    rc, out, err = self.roles_ps(s, sc, title)
                except PluginError as e:
                    if key == 'key_read':
                        raise PluginError('read on the key could not be given: %s' % e,
                                          detail=e.detail)
                    self._roles_steps(e.detail or '')
                    self.ctx.step(str(e), 'bad')
                    failed.append(title)
                    continue
                self._roles_steps(out)
                if key != 'key_read':
                    self.ctx.step('%s: done' % title, 'ok')
                    did.append(title)
            if failed:
                raise PluginError('%s failed (%s done); the old certificates are kept' % (
                    ', '.join(failed), ', '.join(did) or 'nothing else'), retry=True)
            keep = as_int(options.get('keep', self.deploy_default('keep', 1)), 1)
            if on and keep >= 0:
                body = cleanup_script(name_prefix(bundle, options), keep)
                rc, out, err = self.roles_ps(s, '\n'.join(
                    head(sha1_thumb(bundle), name_prefix(bundle, options), '\n'.join(body)) +
                    body), 'removing the old certificates', check=False)
                self._roles_steps(out)
                if rc != 0:
                    self.ctx.step('the old certificates could not be removed: %s' % (
                        [x[7:] for x in out.splitlines() if x.startswith('ERROR: ')] or
                        [(err or out).strip()[-200:]])[-1], 'warn')
        finally:
            if uploads:
                self.roles_ps(s, '\n'.join("Remove-Item -LiteralPath %s -Force -ErrorAction "
                                           "SilentlyContinue" % ps_str(p) for p in uploads),
                              'cleaning up', check=False)
        return did

    # -- trying ------------------------------------------------------------------------
    def roles_detect(self, s):
        """Which roles this server has: {role: (yes, detail)} - one run, nothing changed."""
        rc, out, err = self.roles_ps(s, '\n'.join(DETECT), 'looking for the roles', check=False)
        return parse_detect(out)

    def roles_found_words(self, found):
        if not found:
            return '; the roles on this server could not be listed'
        here = []
        for key, _l, title, _n in ROLES:
            yes, detail = found.get(key, (False, ''))
            if yes:
                here.append('%s (%s)' % (title, detail) if detail else title)
        return ('; roles on this server: %s' % ', '.join(here)) if here else \
            '; none of the roles acme knows is on this server'

    def roles_dry_run(self, s, bundle, options):
        """On a test of a deployment: are the roles it has on installed? Their PowerShell
        into the steps, not run."""
        on = enabled(options)
        if not on and not lines((options or {}).get('key_read')):
            return
        bad = check_options(options, getattr(bundle, 'names', None) or [])
        found = self.roles_detect(s)
        missing = []
        for key in on:
            yes, detail = found.get(key, (False, ''))
            if yes:
                self.ctx.step('%s is on this server%s' % (TITLE[key],
                                                          ' (%s)' % detail if detail else ''), 'ok')
            else:
                missing.append(TITLE[key])
                self.ctx.step('%s is not installed on this server' % TITLE[key], 'bad')
        for _k, title, sc in self._roles_plan(bundle, options, self._roles_env(bundle, True)):
            self.ctx.step('the PowerShell of %s (not run on a test):\n%s' % (title, sc))
        if bad or missing:
            raise PluginError('; '.join(bad + ['not installed: %s' % ', '.join(missing)]
                                        if missing else bad), retry=False)

    def roles_preview(self, bundle, options, got):
        """Into windows_ssh.preview()'s answer: got['roles'] = {on, script}, problems."""
        on = enabled(options)
        if not on and not lines((options or {}).get('key_read')):
            return got
        probs = got.setdefault('problems', [])
        for words in check_options(options, getattr(bundle, 'names', None) or []):
            probs.append({'level': 'bad', 'words': words})
        try:
            script = self.roles_script_text(bundle, options)
        except PluginError as e:
            script = ''
            probs.append({'level': 'bad', 'words': str(e)})
        got['roles'] = {'on': [{'key': k, 'title': TITLE[k]} for k in on], 'script': script}
        if on:
            probs.append({'level': 'info', 'words': 'after the import: %s' % ', '.join(
                TITLE[k] for k in on)})
        return got

    # -- checking ----------------------------------------------------------------------
    def verify(self, bundle, options):
        options = options or {}
        o = Opts(options)
        if 'ldaps' in enabled(options) and o.on('ldaps_verify') and self.c('host'):
            hp = lines(options.get('verify'))
            extra = '%s:636' % self.c('host')
            if extra not in hp:
                options = dict(options, verify=hp + [extra])
        return super(RolesMixin, self).verify(bundle, options)
