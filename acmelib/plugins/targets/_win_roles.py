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
     "  if ($who -match '^(NT AUTHORITY\\\\)?(NetworkService|NETWORK SERVICE)$') { $who = 'NT "
     "AUTHORITY\\NETWORK SERVICE' }\n"
     "  if ($who -match '^(NT AUTHORITY\\\\)?(LocalService|LOCAL SERVICE)$') { $who = 'NT "
     "AUTHORITY\\LOCAL SERVICE' }\n"
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
     # by the well-known SID (S-1-5-20, S-1-5-19): those names are translated on a Windows
     # not in English, and NTAccount does not find the English one there
     "  $wk = @{ 'NT AUTHORITY\\NETWORK SERVICE' = 'S-1-5-20'; 'NT AUTHORITY\\LOCAL SERVICE' = "
     "'S-1-5-19' }\n"
     "  if ($who -match '^\\*?(S-1-[0-9-]+)$') { $sid = $Matches[1] } elseif ($wk.ContainsKey($who)) "
     "{ $sid = $wk[$who] } else {\n"
     "  try { $sid = (New-Object System.Security.Principal.NTAccount($who)).Translate("
     "[System.Security.Principal.SecurityIdentifier]).Value } catch { throw ('the account ' + "
     "$who + ' is not known here') } }\n"
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


# ---------------------------------------------------------------------------
# The roles' PowerShell - written ONCE, as templates, and rendered two ways
# (1.0.120, the Windows agent's parity with this target):
#
#   'ssh'    for windows_ssh: each value put into the text as a PowerShell literal
#            (ps_str), a part that is off left out - the very text this module made
#            before templates (test_agent_windows_parity.py compares it with
#            test/win_roles_before.json);
#   'agent'  for acme-agent on Windows (deploy/agent/acme_agent_winroles.py, made by
#            tools/gen_agent_winroles.py): FIXED text that reads every value from the
#            object $o (a JSON file the agent writes in its own stage folder) - the same
#            logic, nothing of a job ever put into the text of a script.
#
# A template is a list of:
#   'a line'              {v:key} a string value, {i:key} a number, {l:key} the items of a
#                         list (inside @( ... )), {item} the item of an 'each'
#   ('if', key, [then], [else])    a part on / off by the value (true, a non-empty text,
#                                  a non-empty list, a number but 0)
#   ('each', key, [lines])         the lines once per item of a list
#   ('secure', '$var', key, ENV)   a SecureString of a password (ssh: in the text; the
#                                  agent: from the environment variable ENV, never a file)
# ---------------------------------------------------------------------------
_PH = re.compile(r'\{([vil]):(\w+)\}|\{item\}')


def _ph_ssh(line, params, item=None):
    def one(m):
        if m.group(0) == '{item}':
            return ps_str(item)
        kind, key = m.group(1), m.group(2)
        v = params.get(key)
        if kind == 'v':
            return ps_str(v if v is not None else '')
        if kind == 'i':
            return '%d' % as_int(v, 0)
        return ', '.join(ps_str(x) for x in (v or []))
    return _PH.sub(one, line)


def _ph_agent(line, item=None):
    def one(m):
        if m.group(0) == '{item}':
            return '([string]%s)' % item
        kind, key = m.group(1), m.group(2)
        return {'v': '([string]$o.%s)', 'i': '([int]$o.%s)', 'l': '$o.%s'}[kind] % key
    return _PH.sub(one, line)


def render(tpl, params=None, mode='ssh', item=None):
    """A template as PowerShell lines: mode 'ssh' with params (the values in the text),
    'agent' (the values read from $o)."""
    out = []
    for part in tpl:
        if isinstance(part, str):
            out.append(_ph_ssh(part, params, item) if mode == 'ssh' else _ph_agent(part, item))
            continue
        kind = part[0]
        if kind == 'if':
            key, then = part[1], part[2]
            other = part[3] if len(part) > 3 else []
            if mode == 'ssh':
                out += render(then if params.get(key) else other, params, mode, item)
            else:
                out.append('if ($o.%s) {' % key)
                out += render(then, None, mode, item)
                if other:
                    out.append('} else {')
                    out += render(other, None, mode, item)
                out.append('}')
        elif kind == 'each':
            key, body = part[1], part[2]
            if mode == 'ssh':
                for x in params.get(key) or []:
                    out += render(body, params, mode, x)
            else:
                out.append('foreach ($it in @($o.%s)) {' % key)
                out += render(body, None, mode, '$it')
                out.append('}')
        elif kind == 'secure':
            var, key, env = part[1], part[2], part[3]
            if mode == 'ssh':
                out.append(_secure(var, params.get(key)))
            else:
                out += ['%s = New-Object System.Security.SecureString' % var,
                        'if ([string]$env:%s) { %s = ConvertTo-SecureString -String $env:%s '
                        '-AsPlainText -Force }' % (env, var, env)]
        else:
            raise ValueError(kind)
    return out


TEMPLATES = {
    'rds': [
        "Need-Module 'RemoteDesktop' 'Remote Desktop Services'",
        ('if', 'rds_broker', ["$broker = {v:rds_broker}"],
         ["$broker = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName"]),
        ('secure', '$pfxpw', 'pfx_pw', 'ACME_PFX_PASSWORD'),
        "foreach ($r in @({l:rds_roles})) {",
        "  try { $cur = Get-RDCertificate -Role $r -ConnectionBroker $broker -ErrorAction "
        "Stop } catch { throw ('Remote Desktop Services: the Connection Broker ' + $broker + "
        "' could not be asked: ' + $_.Exception.Message) }",
        "  if ($cur -and $cur.Thumbprint -eq $thumb) { Say ok ('RDS ' + $r + ' already uses "
        "it'); continue }",
        "  Set-RDCertificate -Role $r -ImportPath {v:pfx} -Password $pfxpw -ConnectionBroker "
        "$broker -Force -ErrorAction Stop",
        "  Say ok ('RDS ' + $r + ' uses it')",
        "}",
    ],
    'rdgw': [
        "Need-Service 'TSGateway' 'RD Gateway' | Out-Null",
        "Need-Module 'RemoteDesktopServices' 'RD Gateway'",
        "Grant-KeyRead $cert 'NT AUTHORITY\\NETWORK SERVICE'",
        "$p = 'RDS:\\GatewayServer\\SSLCertificate\\Thumbprint'",
        "$cur = [string](Get-Item -Path $p -ErrorAction Stop).CurrentValue",
        "if ($cur -eq $thumb) { Say ok 'RD Gateway already uses it' } else {",
        "  Set-Item -Path $p -Value $thumb -ErrorAction Stop",
        "  Say ok 'RD Gateway uses it'",
        ('if', 'rdgw_restart', ["  Restart-Role 'TSGateway'"]),
        "}",
    ],
    'adfs': [
        "$svc = Get-CimInstance -ClassName Win32_Service -Filter \"Name='adfssrv'\"",
        "if (-not $svc) { throw 'AD FS: the service adfssrv is not on this server - is the "
        "role installed?' }",
        "Need-Module 'ADFS' 'AD FS'",
        ('if', 'adfs_grant', ["Grant-KeyRead $cert $svc.StartName"]),
        "$changed = $false",
        "$ssl = @(Get-AdfsSslCertificate -ErrorAction Stop)",
        "if ($ssl.Count -and -not @($ssl | Where-Object { [string]$_.CertificateHash -ne "
        "$thumb }).Count) { Say ok 'AD FS SSL already uses it' } else {",
        "  Set-AdfsSslCertificate -Thumbprint $thumb -ErrorAction Stop; $changed = $true; "
        "Say ok 'AD FS SSL uses it' }",
        ('if', 'adfs_service_comm', [
            "$sc = Get-AdfsCertificate -CertificateType Service-Communications -ErrorAction "
            "Stop | Select-Object -First 1",
            "if ($sc -and $sc.Thumbprint -eq $thumb) { Say ok 'AD FS Service-Communications "
            "already uses it' } else {",
            "  Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumb "
            "-ErrorAction Stop; $changed = $true; Say ok 'AD FS Service-Communications uses "
            "it' }"]),
        ('if', 'adfs_restart', ["if ($changed) { Restart-Role 'adfssrv' }"]),
    ],
    'wap': [
        "Need-Module 'WebApplicationProxy' 'Web Application Proxy'",
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
        ('if', 'wap_apps', [
            "$apps = @(Get-WebApplicationProxyApplication -ErrorAction Stop | Where-Object { "
            "$_.ExternalCertificateThumbprint -and ($olds -contains "
            "$_.ExternalCertificateThumbprint) })",
            "foreach ($a in $apps) { Set-WebApplicationProxyApplication -ID $a.ID "
            "-ExternalCertificateThumbprint $thumb -ErrorAction Stop; Say ok ('WAP "
            "application ' + $a.Name + ' uses it') }",
            "if (-not $apps) { Say info 'no published application was on an old "
            "certificate' }"]),
    ],
    'sql': [
        "$inst = {v:sql_instance}",
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
        ('if', 'sql_fe_set', [('if', 'sql_fe_on', [
            "$fe = (Get-ItemProperty -LiteralPath $key -ErrorAction "
            "SilentlyContinue).ForceEncryption",
            "if ($fe -ne 1) { New-ItemProperty -LiteralPath $key -Name 'ForceEncryption' "
            "-Value 1 -PropertyType DWord -Force | Out-Null; $changed = $true; Say ok "
            "'SQL Server ForceEncryption on' }"], [
            "$fe = (Get-ItemProperty -LiteralPath $key -ErrorAction "
            "SilentlyContinue).ForceEncryption",
            "if ($fe -ne 0) { New-ItemProperty -LiteralPath $key -Name 'ForceEncryption' "
            "-Value 0 -PropertyType DWord -Force | Out-Null; $changed = $true; Say ok "
            "'SQL Server ForceEncryption off' }"])]),
        ('if', 'sql_restart', ["if ($changed) { Restart-Role $svcName } "],
         ["if ($changed) { Say warn ('SQL Server takes it when ' + $svcName + ' is "
          "restarted') }"]),
    ],
    'ldaps': [
        "Need-Service 'NTDS' 'LDAPS' | Out-Null",
        "if (-not (Get-Command ldifde.exe -ErrorAction SilentlyContinue)) { throw 'LDAPS: "
        "ldifde.exe is not on this server - is it a domain controller?' }",
        ('if', 'ldaps_ntds', [
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
            "('LDAPS: the old ' + $x.PSChildName + ' left NTDS\\Personal') } }"]),
        "$ldf = Join-Path $env:TEMP ('acme-ldaps-' + [guid]::NewGuid().ToString('N') + "
        "'.ldf')",
        "Set-Content -LiteralPath $ldf -Value \"dn:`r`nchangetype: modify`r`nadd: "
        "renewServerCertificate`r`nrenewServerCertificate: 1`r`n-`r`n\" -Encoding ASCII",
        "try { $r = Run-Native 'ldifde.exe' @('-i', '-f', $ldf) } finally { Remove-Item "
        "-LiteralPath $ldf -Force -ErrorAction SilentlyContinue }",
        "if ($r.rc -ne 0) { throw ('LDAPS: ldifde could not ask for renewServerCertificate: ' "
        "+ $r.out) }",
        "Say ok 'LDAPS: the domain controller took the certificate (renewServerCertificate)'",
    ],
    # 1.0.120 (checked against Microsoft's docs): a listener's CertificateThumbprint is set
    # with Set-WSManInstance (about_WSMan_Provider: the WSMan: drive takes it only with
    # New-Item); when WinRM refuses it for a host name the certificate does not hold, the
    # listener's Hostname is set with it
    'winrm': [
        "Need-Service 'WinRM' 'WinRM HTTPS' | Out-Null",
        "$changed = $false",
        ('if', 'winrm_host', ["$h = {v:winrm_host}"],
         ["try { $h = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $h = "
          "$env:COMPUTERNAME }"]),
        "$ls = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction "
        "Stop | Where-Object { [string]$_.Transport -eq 'HTTPS' })",
        "foreach ($l in $ls) {",
        "  $sel = @{ Address = [string]$l.Address; Transport = 'HTTPS' }",
        "  if ([string]$l.CertificateThumbprint -eq $thumb) { Say ok ('WinRM HTTPS ' + "
        "$l.Address + ' already uses it') } else {",
        "    try { Set-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet $sel "
        "-ValueSet @{ CertificateThumbprint = $thumb } -ErrorAction Stop | Out-Null } catch { "
        "Set-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet $sel -ValueSet @{ "
        "Hostname = $h; CertificateThumbprint = $thumb } -ErrorAction Stop | Out-Null; Say "
        "info ('WinRM HTTPS ' + $l.Address + ': its host name is now ' + $h) }",
        "    $changed = $true; Say ok ('WinRM HTTPS ' + $l.Address + ' uses it') }",
        "}",
        ('if', 'winrm_create', [
            "if (-not $ls) { New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS "
            "-Address * -HostName $h -CertificateThumbPrint $thumb -Force -ErrorAction Stop | "
            "Out-Null; $changed = $true; Say ok ('WinRM: an HTTPS listener for ' + $h + ' was "
            "made') }"], [
            "if (-not $ls) { throw 'WinRM: there is no HTTPS listener - turn on "
            "\"Create the HTTPS listener\"' }"]),
        ('if', 'winrm_firewall', [
            "if (Get-NetFirewallRule -Name 'acme-WinRM-HTTPS-In' -ErrorAction "
            "SilentlyContinue) { Say ok 'firewall: 5986 already open' } else {",
            "  New-NetFirewallRule -Name 'acme-WinRM-HTTPS-In' -DisplayName 'Windows Remote "
            "Management (HTTPS-In, acme)' -Direction Inbound -Protocol TCP -LocalPort 5986 "
            "-Action Allow -Profile Any -ErrorAction Stop | Out-Null; Say ok 'firewall: 5986 "
            "open' }"]),
        "if ($changed) { Restart-Role 'WinRM' }",
    ],
    'sstp': [
        "Need-Service 'RemoteAccess' 'SSTP VPN' | Out-Null",
        "Need-Module 'RemoteAccess' 'SSTP VPN'",
        "$cur = (Get-RemoteAccess -ErrorAction Stop).SslCertificate",
        "if ($cur -and $cur.Thumbprint -eq $thumb) { Say ok 'SSTP already uses it' } else {",
        "  Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop",
        "  Say ok 'SSTP uses it'",
        ('if', 'sstp_restart', ["  Restart-Role 'RemoteAccess'"]),
        "}",
    ],
    'ccs': [
        "$dir = {v:ccs_path}",
        "if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw ('IIS Central "
        "Certificate Store: the folder ' + $dir + ' cannot be reached from this session') }",
        ('secure', '$ccspw', 'ccs_pw', 'ACME_CCS_PASSWORD'),
        "$src = {v:ccs_pfx}",
        "foreach ($n in @({l:ccs_files})) {",
        "  $dstf = Join-Path $dir $n",
        "  $same = $false",
        "  if (Test-Path -LiteralPath $dstf) { try { $same = [bool](@((Get-PfxData -FilePath "
        "$dstf -Password $ccspw -ErrorAction Stop).EndEntityCertificates) | Where-Object { "
        "$_.Thumbprint -eq $thumb }) } catch { $same = $false } }",
        "  if ($same) { Say ok ('CCS: ' + $n + ' already holds it') } else { Copy-Item "
        "-LiteralPath $src -Destination $dstf -Force -ErrorAction Stop; Say ok ('CCS: wrote ' "
        "+ $n) }",
        "}",
    ],
    'ftp': [
        "Need-Service 'ftpsvc' 'IIS FTP' | Out-Null",
        "Add-Type -Path \"$env:windir\\System32\\inetsrv\\Microsoft.Web.Administration.dll\"",
        "$sm = New-Object Microsoft.Web.Administration.ServerManager",
        ('if', 'ftp_site', [
            "$site = {v:ftp_site}",
            "$s = $sm.Sites[$site]",
            "if (-not $s) { throw ('IIS FTP: there is no site ' + $site) }",
            "$ssl = $s.GetChildElement('ftpServer').GetChildElement('security')."
            "GetChildElement('ssl')",
            "$where = 'FTP site ' + $site"], [
            "$ssl = $sm.SiteDefaults.GetChildElement('ftpServer').GetChildElement('security')"
            ".GetChildElement('ssl')",
            "$where = 'FTP (every site)'"]),
        "if ([string]$ssl.GetAttributeValue('serverCertHash') -eq $thumb) { Say ok ($where + "
        "' already uses it') } else {",
        "  $ssl.SetAttributeValue('serverCertHash', $thumb); $ssl.SetAttributeValue("
        "'serverCertStoreName', 'My'); $sm.CommitChanges(); Say ok ($where + ' uses it')",
        ('if', 'ftp_restart', ["  Restart-Role 'ftpsvc'"]),
        "}",
    ],
    'exchange': [
        "if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue)) {",
        "  $snap = 'Microsoft.Exchange.Management.PowerShell.SnapIn'",
        "  if (-not (Get-PSSnapin -Registered -Name $snap -ErrorAction SilentlyContinue)) { "
        "throw 'Exchange: the Exchange Management Shell is not on this server - is Exchange "
        "installed?' }",
        "  Add-PSSnapin $snap",
        "}",
        "$ec = Get-ExchangeCertificate -Thumbprint $thumb -ErrorAction Stop",
        "$have = @(([string]$ec.Services) -split '[,\\s]+' | Where-Object { $_ })",
        "$want = @({l:ex_services})",
        "$missing = @($want | Where-Object { $have -notcontains $_ })",
        "$changed = $false",
        "if (-not $missing) { Say ok ('Exchange already uses it for ' + ($want -join ', ')) "
        "} else {",
        "  Enable-ExchangeCertificate -Thumbprint $thumb -Services ($want -join ',') -Force "
        "-Confirm:$false -ErrorAction Stop; $changed = $true",
        "  Say ok ('Exchange uses it for ' + ($want -join ', ')) }",
        ('if', 'ex_restart_imap', [
            "if ($changed) { foreach ($n in @('MSExchangeIMAP4', "
            "'MSExchangeIMAP4BE')) { if (Get-Service -Name $n -ErrorAction "
            "SilentlyContinue) { Restart-Role $n } } }"]),
        ('if', 'ex_restart_pop', [
            "if ($changed) { foreach ($n in @('MSExchangePOP3', "
            "'MSExchangePOP3BE')) { if (Get-Service -Name $n -ErrorAction "
            "SilentlyContinue) { Restart-Role $n } } }"]),
        ('if', 'ex_remove_old', [
            "foreach ($x in @(Get-ExchangeCertificate | Where-Object { $_.Thumbprint -ne "
            "$thumb -and $_.FriendlyName -match ('^' + [regex]::Escape($prefix) + "
            "'\\d{8}-[0-9a-f]+$') })) {",
            "  if ([string]$x.Services -eq 'None') { Remove-ExchangeCertificate -Thumbprint "
            "$x.Thumbprint -Confirm:$false -ErrorAction Stop; Say ok ('Exchange: removed the "
            "old ' + $x.Thumbprint) }",
            "  else { Say warn ('Exchange: the old ' + $x.Thumbprint + ' is still bound to ' + "
            "$x.Services + ' - kept') }",
            "}"]),
    ],
    'lync': [
        "$m = @('SkypeForBusiness', 'Lync') | Where-Object { Get-Module -ListAvailable -Name "
        "$_ } | Select-Object -First 1",
        "if (-not $m) { throw 'Skype for Business: neither the SkypeForBusiness nor the Lync "
        "module is on this server - is it installed?' }",
        "Import-Module -Name $m -ErrorAction Stop -WarningAction SilentlyContinue",
        "$cur = @(Get-CsCertificate -ErrorAction Stop)",
        "$changed = $false",
        "foreach ($ty in @({l:cs_types})) {",
        "  if (@($cur | Where-Object { [string]$_.Use -eq $ty -and $_.Thumbprint -eq $thumb })"
        ".Count) { Say ok ('Skype for Business ' + $ty + ' already uses it'); continue }",
        "  Set-CsCertificate -Type $ty -Thumbprint $thumb -Confirm:$false -ErrorAction Stop; "
        "$changed = $true",
        "  Say ok ('Skype for Business ' + $ty + ' uses it')",
        "}",
        ('if', 'cs_restart', [
            "if ($changed) { Stop-CsWindowsService -ErrorAction Stop; "
            "Start-CsWindowsService -ErrorAction Stop; Say ok 'Skype for Business "
            "services restarted' }"]),
    ],
    'sharepoint': [
        "$snap = 'Microsoft.SharePoint.PowerShell'",
        "if (-not (Get-PSSnapin -Name $snap -ErrorAction SilentlyContinue)) {",
        "  if (-not (Get-PSSnapin -Registered -Name $snap -ErrorAction SilentlyContinue)) { "
        "throw 'SharePoint: the SharePoint snap-in is not on this server - is SharePoint "
        "Server installed?' }",
        "  Add-PSSnapin $snap }",
        "if (-not (Get-Command Import-SPCertificate -ErrorAction SilentlyContinue)) { throw "
        "'SharePoint: Import-SPCertificate is missing - certificate management needs "
        "SharePoint Server Subscription Edition' }",
        "$url = {v:sp_url}",
        ('secure', '$pfxpw', 'pfx_pw', 'ACME_PFX_PASSWORD'),
        "$spc = Get-SPCertificate -ErrorAction SilentlyContinue | Where-Object { "
        "$_.Thumbprint -eq $thumb } | Select-Object -First 1",
        "if ($spc) { Say ok 'SharePoint already has it' } else {",
        "  Import-SPCertificate -Path {v:pfx} -Password $pfxpw -Exportable -ErrorAction Stop | "
        "Out-Null",
        "  $spc = Get-SPCertificate | Where-Object { $_.Thumbprint -eq $thumb } | "
        "Select-Object -First 1",
        "  if (-not $spc) { throw 'SharePoint: the certificate is not in SharePoint after the "
        "import' }",
        "  Say ok 'SharePoint: imported' }",
        ('if', 'sp_host', [
            "Set-SPWebApplication -Identity $url -Zone {v:sp_zone} -Port {i:sp_port} "
            "-SecureSocketsLayer -Certificate $spc -HostHeader {v:sp_host} "
            "-UseServerNameIndication -ErrorAction Stop"], [
            "Set-SPWebApplication -Identity $url -Zone {v:sp_zone} -Port {i:sp_port} "
            "-SecureSocketsLayer -Certificate $spc -ErrorAction Stop"]),
        "Say ok ('SharePoint: ' + $url + ' uses it')",
    ],
    # 1.0.120 (checked against Microsoft's docs, "Update the Administration Mode
    # certificate"): -SubjectName and -Thumbprint of Set-WACCertificateSubjectName are two
    # ways, not one call - by the thumbprint where the module has it (the older acme
    # certificates of the same subject stay in the store); NETWORK SERVICE given read on this
    # very key, Set-WACCertificateAcl (by subject name) only a help after it
    'wac': [
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
        "  if ($cmd.Parameters.ContainsKey('Thumbprint')) { $a = @{ Thumbprint = $thumb } } "
        "else { $a = @{ SubjectName = $subj } }",
        "  Set-WACCertificateSubjectName @a -ErrorAction Stop",
        "  Grant-KeyRead $cert 'NT AUTHORITY\\NETWORK SERVICE'",
        "  if (Get-Command Set-WACCertificateAcl -ErrorAction SilentlyContinue) { try { "
        "Set-WACCertificateAcl -SubjectName $subj -ErrorAction Stop } catch { Say warn "
        "('Set-WACCertificateAcl: ' + $_.Exception.Message + ' - NETWORK SERVICE has read on "
        "the key already') } }",
        "  Say ok ('Windows Admin Center uses it (' + $subj + ')')",
        "  Restart-Role 'WindowsAdminCenter'",
        "} elseif ($old) {",
        "  $port = {i:wac_port}",
        "  if (-not $port) { $port = [int](Get-ItemProperty -LiteralPath "
        "'HKLM:\\SOFTWARE\\Microsoft\\ServerManagementGateway' -ErrorAction "
        "SilentlyContinue).SmePort }",
        "  if (-not $port) { $port = 443 }",
        "  $r = Run-Native 'netsh.exe' @('http', 'show', 'sslcert', ('ipport=0.0.0.0:' + "
        "$port))",
        "  if ($r.out -match $thumb) { Say ok ('Windows Admin Center (older) already uses it "
        "on ' + $port) } else {",
        "    $msi = {v:wac_msi}",
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
    ],
}
KEY_READ_TEMPLATE = [('each', 'accounts', ["Grant-KeyRead $cert {item}"])]

# the values of each role: (type, check) - the agent checks a job's values with these before
# a script runs ('str' a text of one line, 'int' 0-65535, 'bool', 'list' of texts); 'agent':
# put in by the agent itself (a file of its stage folder), never taken from acme; the
# passwords never go into the values (the agent: an environment variable)
_NAME_RE = r'[^\x00-\x1f\x7f]{0,256}'
SCHEMA = {
    'rds': {'rds_roles': ('list', r'(RDGateway|RDWebAccess|RDPublishing|RDRedirector)'),
            'rds_broker': ('str', r'([A-Za-z0-9_][A-Za-z0-9_.-]{0,252})?'),
            'pfx': ('agent', None)},
    'rdgw': {'rdgw_restart': ('bool', None)},
    'adfs': {'adfs_grant': ('bool', None), 'adfs_service_comm': ('bool', None),
             'adfs_restart': ('bool', None)},
    'wap': {'wap_apps': ('bool', None)},
    'sql': {'sql_instance': ('str', r'[A-Za-z0-9_#$]{1,16}'), 'sql_fe_set': ('bool', None),
            'sql_fe_on': ('bool', None), 'sql_restart': ('bool', None)},
    'ldaps': {'ldaps_ntds': ('bool', None)},
    'winrm': {'winrm_host': ('str', r'([A-Za-z0-9_][A-Za-z0-9_.-]{0,252})?'),
              'winrm_create': ('bool', None), 'winrm_firewall': ('bool', None)},
    'sstp': {'sstp_restart': ('bool', None)},
    'ccs': {'ccs_path': ('str', r'[^\x00-\x1f\x7f]{1,1024}'),
            'ccs_files': ('list', r'(_\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]'
                                  r'([a-z0-9_-]*[a-z0-9_])?)*\.pfx'),
            'ccs_pfx': ('agent', None)},
    'ftp': {'ftp_site': ('str', _NAME_RE), 'ftp_restart': ('bool', None)},
    'exchange': {'ex_services': ('list', r'(IIS|SMTP|IMAP|POP|UM|UMCallRouter|Federation)'),
                 'ex_restart_imap': ('bool', None), 'ex_restart_pop': ('bool', None),
                 'ex_remove_old': ('bool', None)},
    'lync': {'cs_types': ('list', r'(Default|WebServicesInternal|WebServicesExternal)'),
             'cs_restart': ('bool', None)},
    'sharepoint': {'sp_url': ('str', r'https?://[^\s]{1,1000}'),
                   'sp_zone': ('str', r'(Default|Intranet|Internet|Extranet|Custom)'),
                   'sp_port': ('int', None),
                   'sp_host': ('str', r'([A-Za-z0-9_*][A-Za-z0-9_.-]{0,252})?'),
                   'pfx': ('agent', None)},
    'wac': {'wac_port': ('int', None), 'wac_msi': ('str', r'([A-Za-z]:\\[^\x00-\x1f\x7f]{1,1000}'
                                                          r'\.msi)?')},
    'key_read': {'accounts': ('list', r'[^\x00-\x1f\x7f"]{1,256}')},
}
SECRETS = ('pfx_pw', 'ccs_pw')


def role_params(key, options, env=None):
    """The values of one role's template, from the deployment's options (and env: names,
    pfx, pfx_pw, ccs_pfx, ccs_pw - what windows_ssh uploads; the agent fills its own)."""
    o = Opts(options)
    env = env or {}
    p = {}
    if key == 'rds':
        p = {'rds_roles': [r for k, r, _l in RDS_ROLES if o.on(k)],
             'rds_broker': o.s('rds_broker'), 'pfx': env.get('pfx') or '',
             'pfx_pw': env.get('pfx_pw')}
    elif key == 'rdgw':
        p = {'rdgw_restart': o.on('rdgw_restart')}
    elif key == 'adfs':
        p = {'adfs_grant': o.on('adfs_grant'), 'adfs_service_comm': o.on('adfs_service_comm'),
             'adfs_restart': o.on('adfs_restart')}
    elif key == 'wap':
        p = {'wap_apps': o.on('wap_apps')}
    elif key == 'sql':
        force = o.s('sql_force') or 'keep'
        p = {'sql_instance': o.s('sql_instance') or 'MSSQLSERVER',
             'sql_fe_set': force in ('on', 'off'), 'sql_fe_on': force == 'on',
             'sql_restart': o.on('sql_restart')}
    elif key == 'ldaps':
        p = {'ldaps_ntds': o.s('ldaps_store') != 'my'}
    elif key == 'winrm':
        p = {'winrm_host': o.s('winrm_hostname') or next(
            (text(n) for n in env.get('names') or [] if not text(n).startswith('*.')), ''),
            'winrm_create': o.on('winrm_create'), 'winrm_firewall': o.on('winrm_firewall')}
    elif key == 'sstp':
        p = {'sstp_restart': o.on('sstp_restart')}
    elif key == 'ccs':
        p = {'ccs_path': o.s('ccs_path'),
             'ccs_files': ccs_file_names(list(env.get('names') or []), o.s('ccs_names')),
             'ccs_pfx': env.get('ccs_pfx') or '', 'ccs_pw': env.get('ccs_pw')}
    elif key == 'ftp':
        p = {'ftp_site': o.s('ftp_site'), 'ftp_restart': o.on('ftp_restart')}
    elif key == 'exchange':
        want = [svc for k, svc, _d in EX_SERVICES if o.on(k)]
        p = {'ex_services': want, 'ex_restart_imap': o.on('ex_restart') and 'IMAP' in want,
             'ex_restart_pop': o.on('ex_restart') and 'POP' in want,
             'ex_remove_old': o.on('ex_remove_old')}
    elif key == 'lync':
        p = {'cs_types': [ty for k, ty, _l in CS_TYPES if o.on(k)],
             'cs_restart': o.on('cs_restart')}
    elif key == 'sharepoint':
        p = {'sp_url': o.s('sp_url'), 'sp_zone': o.s('sp_zone') or 'Default',
             'sp_port': as_int(o.get('sp_port'), 443) or 443, 'sp_host': o.s('sp_host'),
             'pfx': env.get('pfx') or '', 'pfx_pw': env.get('pfx_pw')}
    elif key == 'wac':
        p = {'wac_port': as_int(o.get('wac_port'), 0), 'wac_msi': o.s('wac_msi')}
    return p


def role_script(key, options, env):
    """The PowerShell lines of one role (without the head). env: names, pfx, pfx_pw,
    ccs_pfx, ccs_pw."""
    return render(TEMPLATES[key], role_params(key, options, env), 'ssh')


def key_read_script(accounts):
    return render(KEY_READ_TEMPLATE, {'accounts': list(accounts)}, 'ssh')


# what still uses a certificate: IIS, http.sys (AD FS, WAP, SSTP, RD Gateway, WAC before
# 2410), RDP, SQL Server, WinRM - never removed while one does (the agent's cleanup too)
USED = [
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
]


def cleanup_script(prefix, keep):
    """The old acme certificates beyond `keep` that nothing uses (IIS, http.sys - AD FS,
    WAP, SSTP, RD Gateway -, RDP, SQL Server, WinRM) leave LocalMachine\\My."""
    return USED + [
        "$old = Get-ChildItem $store | Where-Object { $_.FriendlyName -match ('^' + "
        "[regex]::Escape(%s) + '\\d{8}-[0-9a-f]+$') -and $_.Thumbprint "
        "-ne $thumb } | Sort-Object NotBefore -Descending | Select-Object -Skip %d"
        % (ps_str(prefix), keep),
        "foreach ($x in $old) { if ($used -contains $x.Thumbprint) { Say warn ('the old ' + "
        "$x.Thumbprint + ' is still used: kept') } else { Remove-Item -LiteralPath $x.PSPath; "
        "Say info ('removed the old ' + $x.Thumbprint) } }",
    ]


# the Remote Desktop listener (TermService, NETWORK SERVICE) reads the private key: read on its
# file for S-1-5-20 - by the SID (the account's name is translated on a Windows not in
# English), for a CNG key (RSA, ECDSA: Crypto\Keys) and a CryptoAPI one (what a 3DES PKCS#12
# is imported as: Crypto\RSA\MachineKeys) - windows_ssh's import and the agent's bind alike
RDP_KEY_READ = [
    "$rk = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]"
    "::GetRSAPrivateKey($cert)",
    "if (-not $rk) { try { $rk = [System.Security.Cryptography.X509Certificates."
    "ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert) } catch { } }",
    "$kf = ''",
    "if ($rk -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $kf = "
    "[string]$rk.CspKeyContainerInfo.UniqueKeyContainerName } elseif ($rk -and "
    "($rk.PSObject.Properties.Name -contains 'Key') -and $rk.Key) { $kf = "
    "[string]$rk.Key.UniqueName }",
    "if ($kf) { foreach ($d in @(\"$env:ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\", "
    "\"$env:ProgramData\\Microsoft\\Crypto\\Keys\")) { $kp = Join-Path $d $kf; if (Test-Path "
    "-LiteralPath $kp) { icacls.exe $kp /grant '*S-1-5-20:R' | Out-Null } } }",
]


# ---- the agent's side: the same templates, rendered with $o ------------------------------
def head_agent(body):
    """The head of a role run in acme-agent: the new certificate's thumbprint and the prefix
    of acme's names from the job ($j), the helpers the body uses."""
    want = set()
    for name, _code in HELPERS:
        if re.search(r'(?<![\w-])%s(?![\w-])' % re.escape(name), body):
            want.add(name)
            want.update(_HELPER_DEPS.get(name, []))
    out = [
        "$thumb = [string]$j.thumb",
        "$prefix = [string]$j.prefix",
        "$o = $j.o",
        "$store = 'Cert:\\LocalMachine\\My'",
        "$cert = Get-Item -LiteralPath (Join-Path $store $thumb) -ErrorAction SilentlyContinue",
        "if (-not $cert) { throw ('the new certificate ' + $thumb + ' is not in "
        "LocalMachine\\My') }",
    ]
    for name, code in HELPERS:
        if name in want:
            out.append(code)
    return out


def agent_scripts():
    """{key: the whole PowerShell of a role as acme-agent runs it} - every role, the key read
    ('key_read'), what still uses a certificate ('used'), the roles found ('detect'), the
    listener's key read ('rdp_key_read')."""
    out = {}
    for key in [r[0] for r in ROLES] + ['key_read']:
        body = render(TEMPLATES[key] if key != 'key_read' else KEY_READ_TEMPLATE, None, 'agent')
        out[key] = '\n'.join(head_agent('\n'.join(body)) + body)
    out['used'] = '\n'.join([code for name, code in HELPERS if name == 'Run-Native'] + USED)
    out['detect'] = '\n'.join(DETECT)
    out['rdp_key_read'] = '\n'.join(RDP_KEY_READ)
    return out


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
    def served_places(self, options):
        options = options or {}
        out = list(super(RolesMixin, self).served_places(options))
        if 'ldaps' in enabled(options) and Opts(options).on('ldaps_verify') and self.c('host'):
            out.append((self.c('host'), 636))
        return out

    def verify(self, bundle, options):
        options = options or {}
        o = Opts(options)
        if 'ldaps' in enabled(options) and o.on('ldaps_verify') and self.c('host'):
            hp = lines(options.get('verify'))
            extra = '%s:636' % self.c('host')
            if extra not in hp:
                options = dict(options, verify=hp + [extra])
        return super(RolesMixin, self).verify(bundle, options)
