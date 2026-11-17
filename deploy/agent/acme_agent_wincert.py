"""acme_agent_wincert.py - acme-agent on Windows: the certificate in the machine store, the https
bindings of IIS sites, the Remote Desktop listener (1.0.120, docs/target-agent.md "Windows: the
machine store, IIS, Remote Desktop").

Loaded by acme_agent.py only for a deployment job that has `win`; a Linux job never loads it.

    win = {'store': {'pfx_index': N | None, 'password_sealed': ..., 'cert_pem': PEM (leaf first),
                     'friendly': 'acme www.example.com 2026-11-17', 'exportable': False,
                     'keep': 1, 'slot': 'dep-12', 'legacy': True},
           'iis': [{'site': 'Default Web Site', 'host': 'www.example.com', 'port': 443,
                    'ip': '*'}],
           'rdp': False}

  * the PKCS#12 imported is one of the job's files (`pfx_index`; its path '' when it is only
    for the store - its bytes are then never written outside root's stage folder), or - the key
    made by this agent (pfx_index None, the job's agent_key) - made here by root with openssl
    from its own key;
  * every change is made by powershell.exe run by the root side (SYSTEM) with FIXED scripts:
    what they act on comes only from a JSON file in root's stage folder (ACME_WIN_IN) and the
    PKCS#12 password from an environment variable - nothing of a job is ever put into the text
    of a script. Every run goes through powershell() (the tests replace it);
  * the order of a deployment: before -> files -> the store -> the bindings (IIS, RDP) -> test
    -> script -> reload -> after; anything failing after the store step puts the bindings back
    to the certificate they had, takes the new certificate out of the store again (only when
    this job put it there) and puts the files back;
  * the certificates this agent imported for a deployment are kept in root\\store.json (their
    thumbprints): beyond `keep` the older ones are removed - never one it did not import, never
    one still bound to a site or the listener.

The policy: `allow store`, `allow iis SITE` (or `allow iis *`), `allow rdp`.
"""
import base64
import hashlib
import ipaddress
import json
import ntpath
import os
import re
import secrets
import subprocess
import time

PFX_FORMATS = ('pfx', 'p12', 'p12-legacy')
IIS_MOST = 16
KEEP_MOST = 10
PS_TIMEOUT = 300
STORE_FILE = 'store.json'
STORE_RECORDS_MOST = 200            # deployments whose imported certificates are remembered
SITE_RE = re.compile(r'[^\x00-\x1f\x7f"]{1,256}\Z')
HOSTNAME_RE = re.compile(r'(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_]'
                         r'([A-Za-z0-9_-]{0,62}))*\Z')
SLOT_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
THUMB_RE = re.compile(r'[0-9A-F]{40}\Z')


def is_windows(A=None):
    """This agent runs on Windows (or the tests' fake of it)."""
    if A is not None and getattr(A, 'WINDOWS', None) is not None:
        return bool(getattr(A, 'WINDOWS'))
    return os.name == 'nt' or bool(os.environ.get('ACME_AGENT_FAKE_WINDOWS'))


# ---- the policy's words -----------------------------------------------------------------------
def pol_store(pol):
    return bool((pol or {}).get('store'))


def pol_iis(pol):
    v = (pol or {}).get('iis') or []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else []


def pol_rdp(pol):
    return bool((pol or {}).get('rdp'))


def iis_allowed(pol, site):
    sites = pol_iis(pol)
    return '*' in sites or str(site).lower() in [s.lower() for s in sites]


def cmd_word(s):
    """A word of a command line as an administrator types it (cmd.exe, PowerShell)."""
    s = str(s)
    return '"%s"' % s if (not s or re.search(r'[\s&|<>^%;,()\'`$]', s)) else s


def allow_iis_words(site):
    return 'acme-agent allow iis %s' % cmd_word(site)


def thumb_of(pem):
    """The SHA-1 thumbprint (upper-case hex) of the first certificate of a PEM text."""
    m = re.search(r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----',
                  str(pem or ''))
    if not m:
        return ''
    try:
        der = base64.b64decode(re.sub(r'\s+', '', m.group(1)), validate=True)
    except (ValueError, TypeError):
        return ''
    return hashlib.sha1(der).hexdigest().upper()


def _clean(v, most):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(v if v is not None else ''))[:most]


# ---- the job's `win` against the policy (plan_check) -----------------------------------------
def take_store_file(A, args):
    """The PKCS#12 only for the store (its path '') taken out of the job's files - into
    win.store.pfx_file - so the files of the job are the files written. Said once: the same
    job checked again finds it moved already."""
    win = args.get('win')
    if not isinstance(win, dict):
        raise A.Refused('win is an object')
    st = win.get('store')
    files = args.get('files') if isinstance(args.get('files'), list) else []
    blank = [i for i, f in enumerate(files) if isinstance(f, dict) and f.get('path') == '']
    if not blank:
        return win
    if not isinstance(st, dict) or len(blank) > 1 or st.get('pfx_index') != blank[0] or \
            isinstance(st.get('pfx_file'), dict):
        raise A.Refused('a file without a path is only the PKCS#12 for the machine store')
    f = files[blank[0]]
    if str(f.get('format') or '') not in PFX_FORMATS or f.get('agent_key'):
        raise A.Refused('the file for the machine store is a PKCS#12 (pfx)')
    args['files'] = files[:blank[0]] + files[blank[0] + 1:]
    win = dict(win, store=dict(st, pfx_index=None, pfx_file=f))
    args['win'] = win
    return win


def win_check(A, pol, args, needs):
    """The `win` part of a deployment against the policy -> what it does (needs appended with
    what the policy lacks: allow store, allow iis SITE, allow rdp)."""
    win = args.get('win')
    if not isinstance(win, dict):
        raise A.Refused('win is an object')
    files = args.get('files') if isinstance(args.get('files'), list) else []
    out = {'store': None, 'iis': [], 'rdp': bool(win.get('rdp'))}
    st = win.get('store')
    if st is not None and not isinstance(st, dict):
        raise A.Refused('win.store is an object')
    iis = win.get('iis') or []
    if not isinstance(iis, list) or len(iis) > IIS_MOST:
        raise A.Refused('%d IIS bindings at most' % IIS_MOST)
    if (iis or out['rdp']) and not st:
        raise A.Refused('IIS bindings and the Remote Desktop listener take the certificate from '
                        'the machine store: the job puts none there')
    if st:
        thumb = thumb_of(st.get('cert_pem'))
        if not THUMB_RE.match(thumb):
            raise A.Refused('the job holds no certificate for the machine store')
        try:
            keep = int(st.get('keep', 1))
        except (TypeError, ValueError):
            raise A.Refused('keep is a number')
        if not 0 <= keep <= KEEP_MOST:
            raise A.Refused('keep is 0 to %d' % KEEP_MOST)
        slot = str(st.get('slot') or '')
        if not SLOT_RE.match(slot):
            raise A.Refused('%r is not a deployment' % slot[:40])
        one = {'thumb': thumb, 'cert_pem': str(st.get('cert_pem')),
               'friendly': _clean(st.get('friendly') or 'acme %s' % thumb[:12], 120),
               'exportable': bool(st.get('exportable')), 'keep': keep, 'slot': slot,
               'legacy': st.get('legacy', True) not in (False, 0, '0'),
               'password_sealed': st.get('password_sealed')}
        idx = st.get('pfx_index')
        if isinstance(st.get('pfx_file'), dict):
            one['from'] = 'stage'
            one['file'] = st['pfx_file']
        elif idx is None:
            if not isinstance(args.get('agent_key'), dict):
                raise A.Refused('the machine store needs a PKCS#12 of the job or the key this '
                                'agent made')
            one['from'] = 'agent_key'
        else:
            if isinstance(idx, bool) or not isinstance(idx, int) or not 0 <= idx < len(files):
                raise A.Refused('the PKCS#12 for the machine store is not a file of the job')
            f = files[idx]
            if not isinstance(f, dict) or str(f.get('format') or '') not in PFX_FORMATS or \
                    f.get('agent_key'):
                raise A.Refused('the file for the machine store is a PKCS#12 (pfx) acme sends')
            one['from'] = 'file'
            one['index'] = idx
        out['store'] = one
        if not pol_store(pol):
            needs.append({'kind': 'store', 'what': 'the certificate imported into the machine '
                          'store (LocalMachine\\My)', 'allow': 'acme-agent allow store'})
    seen, asked = set(), set()
    for b in iis:
        if not isinstance(b, dict):
            raise A.Refused('an IIS binding is an object')
        site = str(b.get('site') or '').strip()
        if not SITE_RE.match(site):
            raise A.Refused('%r is not the name of an IIS site' % site[:80])
        host = str(b.get('host') or '').strip().lower().rstrip('.')
        if host and (not HOSTNAME_RE.match(host) or len(host) > 253):
            raise A.Refused('%r is not a host name of a binding' % host[:80])
        try:
            port = int(b.get('port') or 443)
        except (TypeError, ValueError):
            raise A.Refused('the port of a binding is a number')
        if not 0 < port < 65536:
            raise A.Refused('%d is not a port' % port)
        ip = str(b.get('ip') or '*').strip()
        if ip != '*':
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                raise A.Refused('%r is not an address of a binding (or *)' % ip[:60])
        key = (host, port, ip)
        if key in seen:
            raise A.Refused('the binding %s:%d twice' % (host or ip, port))
        seen.add(key)
        out['iis'].append({'site': site, 'host': host, 'port': port, 'ip': ip})
        if not iis_allowed(pol, site) and site.lower() not in asked:
            asked.add(site.lower())
            needs.append({'kind': 'iis', 'what': 'the https bindings of the IIS site %s' % site,
                          'allow': allow_iis_words(site)})
    if out['rdp'] and not pol_rdp(pol):
        needs.append({'kind': 'rdp', 'what': 'the certificate of the Remote Desktop listener',
                      'allow': 'acme-agent allow rdp'})
    roles_check(A, pol, win, out, needs)
    return out


# ---- the roles (1.0.120: what the OpenSSH target's roles do, docs/target-agent.md "Windows: the
# roles") - the PowerShell is acme_agent_winroles.SCRIPTS, generated from acme's _win_roles ----
ROLES_MOST = 16
KEY_READ_MOST = 16
PREFIX_RE = re.compile(r'[A-Za-z0-9._-]{0,63}\Z')
ACCOUNT_RE = re.compile(r'[^\x00-\x1f\x7f"]{1,256}\Z')


def pol_roles(pol):
    """{role: [what more it allows: the folder of the Central Certificate Store, the .msi of
    Windows Admin Center]} of the policy's `allow role NAME [path=|msi=]` (Windows only)."""
    v = (pol or {}).get('roles') or {}
    return v if isinstance(v, dict) else {}


def pol_key_read(pol):
    v = (pol or {}).get('key_read') or []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else []


def role_extra_word(key):
    return {'ccs': 'path', 'wac': 'msi'}.get(key)


def allow_role_words(key, extra=None):
    if extra:
        return 'acme-agent allow role %s %s=%s' % (key, role_extra_word(key), cmd_word(extra))
    return 'acme-agent allow role %s' % key


def allow_key_read_words(account):
    return 'acme-agent allow key-read %s' % cmd_word(account)


def _same_path(a, b):
    return str(a).replace('/', '\\').rstrip('\\').lower() == \
        str(b).replace('/', '\\').rstrip('\\').lower()


def role_values(A, key, o):
    """A role's values from a job, checked by its SCHEMA - only the values it knows, of their
    type, each matching its pattern; a path of the agent's own ('agent') never taken."""
    schema = _roles().SCHEMA.get(key)
    if schema is None:
        raise A.Refused('%r is not a role this agent knows (%s)' % (str(key)[:40], ', '.join(
            r[0] for r in _roles().ROLES)))
    if not isinstance(o, dict):
        raise A.Refused('the values of the role %s are an object' % key)
    for name in o:
        if name not in schema or schema[name][0] == 'agent':
            raise A.Refused('%s: %r is not a value of this role' % (key, str(name)[:40]))
    out = {}
    for name, (typ, rx) in sorted(schema.items()):
        v = o.get(name)
        if typ == 'agent':
            continue
        if typ == 'bool':
            if v is not None and not isinstance(v, bool):
                raise A.Refused('%s: %s is true or false' % (key, name))
            out[name] = bool(v)
        elif typ == 'int':
            if v is None:
                v = 0
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < 65536:
                raise A.Refused('%s: %s is a number 0-65535' % (key, name))
            out[name] = v
        elif typ == 'str':
            v = '' if v is None else v
            if not isinstance(v, str) or (rx and not re.fullmatch(rx, v)):
                raise A.Refused('%s: %r is not a %s' % (key, str(v)[:80], name))
            out[name] = v
        elif typ == 'list':
            v = [] if v is None else v
            if not isinstance(v, list) or len(v) > 32 or not all(
                    isinstance(x, str) and (not rx or re.fullmatch(rx, x)) for x in v):
                raise A.Refused('%s: %s is a list of %s' % (key, name, rx or 'texts'))
            out[name] = list(v)
    return out


def roles_check(A, pol, win, out, needs):
    """The roles of a job, the accounts given read on the key, the PowerShell after, the roles
    looked for (a test) - each against the policy: allow role NAME (ccs: path=FOLDER, wac:
    msi=FILE), allow key-read ACCOUNT, allow script-hash HASH."""
    R = _roles()
    titles = {r[0]: r[1] for r in R.ROLES}
    roles = win.get('roles') or []
    if not isinstance(roles, list) or len(roles) > ROLES_MOST:
        raise A.Refused('the roles are a list (%d at most)' % ROLES_MOST)
    accounts = win.get('key_read') or []
    if not isinstance(accounts, list) or len(accounts) > KEY_READ_MOST or not all(
            isinstance(a, str) and ACCOUNT_RE.match(a) for a in accounts):
        raise A.Refused('read on the key: a list of accounts (%d at most)' % KEY_READ_MOST)
    post = win.get('post_ps')
    if post is not None and (not isinstance(post, str) or not post.strip()):
        raise A.Refused('the PowerShell after is a text')
    prefix = str(win.get('prefix') or '')
    if not PREFIX_RE.match(prefix):
        raise A.Refused('%r is not the beginning of acme\'s names' % prefix[:80])
    out['prefix'] = prefix
    out['detect'] = bool(win.get('detect'))
    out['roles'], out['key_read'], out['post_ps'] = [], [], None
    if (roles or accounts or post) and not out.get('store'):
        raise A.Refused('the roles take the certificate from the machine store: the job puts '
                        'none there')
    order = [r[0] for r in R.ROLES]
    seen = set()
    for r in roles:
        if not isinstance(r, dict):
            raise A.Refused('a role is an object')
        key = str(r.get('key') or '')
        o = role_values(A, key, r.get('o') or {})
        if key in seen:
            raise A.Refused('the role %s twice' % key)
        seen.add(key)
        allowed = pol_roles(pol)
        extra = None
        if key == 'ccs':
            extra = o['ccs_path']
            if not extra:
                raise A.Refused('IIS Central Certificate Store: the folder of the store is not '
                                'given')
        elif key == 'wac' and o.get('wac_msi'):
            extra = o['wac_msi']
        ok = key in allowed and (extra is None or any(_same_path(extra, x) for x in
                                                       allowed.get(key) or []))
        if not ok:
            needs.append({'kind': 'role', 'what': '%s (the Windows role%s)' % (
                titles[key], ', %s' % extra if extra else ''),
                'allow': allow_role_words(key, extra)})
        if key == 'ccs':
            c = win.get('ccs')
            if not isinstance(c, dict):
                raise A.Refused('IIS Central Certificate Store: the job holds no PKCS#12 for '
                                'its files')
            out['ccs'] = c              # a deployment without it is refused when it runs
        out['roles'].append({'key': key, 'title': titles[key], 'o': o})
    out['roles'].sort(key=lambda x: order.index(x['key']))
    have = [x.lower() for x in pol_key_read(pol)]
    for a in accounts:
        if a.lower() in [x.lower() for x in out['key_read']]:
            continue
        out['key_read'].append(a)
        if a.lower() not in have:
            needs.append({'kind': 'key-read', 'what': 'read on the private key for %s' % a,
                          'allow': allow_key_read_words(a)})
    if post is not None:
        body = post
        if len(body.encode('utf-8')) > getattr(A, 'SCRIPT_MOST', 65536):
            raise A.Refused('the PowerShell after is 64 KiB at most')
        h = hashlib.sha256(body.encode('utf-8')).hexdigest()
        if h not in [str(x).lower() for x in (pol or {}).get('script_hashes') or []]:
            needs.append({'kind': 'script-hash', 'what': 'the PowerShell after the import '
                          '(written in acme, sha256 %s)' % h,
                          'allow': 'acme-agent allow script-hash %s' % h})
        out['post_ps'] = {'body': body, 'sha256': h}


# a role run: the job's values in $j (a JSON file of root's stage folder), STEP lines said, an
# error said as ERROR: - as acme's windows_ssh runs the same scripts (_win_roles.roles_ps)
ROLE_PRELUDE = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
$j = Get-Content -LiteralPath $env:ACME_WIN_IN -Raw -Encoding UTF8 | ConvertFrom-Json
try {
"""
ROLE_END = r"""
} catch { Write-Output ('ERROR: ' + ($_.Exception.Message -replace '[\r\n]+', ' ')); exit 1 }
"""
# the PowerShell after (post_ps): acme's lines - allowed by their hash - with $thumb, $store and
# $cert of the new certificate, as windows_ssh runs them after the import
POST_PS_HEAD = r"""$thumb = [string]$j.thumb
$store = 'Cert:\LocalMachine\My'
$cert = Get-Item -LiteralPath (Join-Path $store $thumb)
"""


def role_ps(key):
    """The whole script of a role (or 'key_read', 'detect') as it runs."""
    return ROLE_PRELUDE + _roles().SCRIPTS[key] + ROLE_END


def run_lines(A, script, values, env_more=None, timeout=PS_TIMEOUT * 2):
    """A fixed script run with `values` (JSON in root's stage folder, deleted after) ->
    (ok, [(level, words)] of its STEP lines, the error it said, all it wrote)."""
    fn = os.path.join(stage_dir(A), 'acme-%s.json' % secrets.token_hex(8))
    env = dict(os.environ)
    for k in ('ACME_PFX_PASSWORD', 'ACME_CCS_PASSWORD'):
        env.pop(k, None)
    env['ACME_WIN_IN'] = fn
    env.update(env_more or {})
    try:
        _new_file(fn, json.dumps(values).encode('utf-8'))
        rc, said = powershell(script, env, timeout)
    finally:
        _gone(fn)
    steps, err = [], ''
    for line in (said or '').splitlines():
        line = line.strip()
        m = re.match(r'^STEP (ok|info|warn|bad) (.*)$', line)
        if m:
            steps.append((m.group(1), m.group(2)[:600]))
        elif line.startswith('ERROR: '):
            err = line[7:].strip()
    if rc != 0 and not err:
        rest = [x.strip() for x in (said or '').splitlines() if x.strip() and
                not x.strip().startswith('STEP ')]
        err = rest[-1] if rest else 'exit %s' % rc
    return rc == 0, steps, err[-300:], said or ''


def detect(A):
    """The roles of this server: {role: (yes, detail)} - one run, nothing changed (the same
    lines as windows_ssh's "Test the connection")."""
    ok, _steps, err, said = run_lines(A, role_ps('detect'), {}, timeout=PS_TIMEOUT)
    got = {}
    for line in said.splitlines():
        m = re.match(r'^ROLE (\w+) (yes|no) ?(.*)$', line.strip())
        if m:
            got[m.group(1)] = (m.group(2) == 'yes', m.group(3).strip()[:200])
    return got, ('' if got else (err or 'the roles could not be listed'))


def win_words(w):
    """What the `win` part does, in a few words."""
    out = []
    if w.get('store'):
        out.append('the machine store')
    if w.get('iis'):
        out.append('%d IIS binding%s' % (len(w['iis']), '' if len(w['iis']) == 1 else 's'))
    if w.get('rdp'):
        out.append('the Remote Desktop listener')
    return ', '.join(out)


def _roles():
    """acme_agent_winroles.py beside this file: the roles' PowerShell, generated from acme's
    _win_roles (tools/gen_agent_winroles.py) - data only."""
    import sys
    m = sys.modules.get('acme_agent_winroles')
    if m is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location('acme_agent_winroles', os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'acme_agent_winroles.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        sys.modules['acme_agent_winroles'] = m
    return m


# ---- PowerShell: fixed scripts, values through a JSON file -----------------------------------
PRELUDE = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
trap { Write-Output ('ACME-ERROR ' + ($_.Exception.Message -replace '[\r\n]+', ' ')); exit 1 }
$j = Get-Content -LiteralPath $env:ACME_WIN_IN -Raw -Encoding UTF8 | ConvertFrom-Json
function Say($o) { Write-Output ('ACME ' + ($o | ConvertTo-Json -Compress -Depth 5)) }
$store = 'Cert:\LocalMachine\My'
function Iis-Ready { if (@($j.iis).Count -gt 0) { Import-Module WebAdministration } }
function Find-Binding($w) {
  Get-WebBinding -Name ([string]$w.site) -Protocol https -Port ([int]$w.port) `
    -HostHeader ([string]$w.host) | Select-Object -First 1
}
function Site-There($name) { [bool](Get-Website | Where-Object { $_.Name -eq $name }) }
function Rdp-Setting {
  Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting `
    -Filter "TerminalName='RDP-tcp'"
}
"""

# what is there now: the certificate in the store, each binding's certificate, the listener's
PS_STATE = PRELUDE + r"""# acme-agent: state
$thumb = [string]$j.thumb
$out = @{ present = [bool](Test-Path -LiteralPath (Join-Path $store $thumb)); iis = @(); rdp = '' }
Iis-Ready
foreach ($w in @($j.iis)) {
  $one = @{ site = [string]$w.site; host = [string]$w.host; port = [int]$w.port;
            ip = [string]$w.ip; site_there = $false; binding = $false; thumb = '' }
  if (Site-There ([string]$w.site)) {
    $one.site_there = $true
    $b = Find-Binding $w
    if ($b) { $one.binding = $true; $one.thumb = [string]$b.certificateHash }
  }
  $out.iis += $one
}
if ($j.rdp) { $out.rdp = [string](Rdp-Setting).SSLCertificateSHA1Hash }
Say $out
"""

# the PKCS#12 into LocalMachine\My (not exportable unless asked); nothing else of it is kept
PS_IMPORT = PRELUDE + r"""# acme-agent: import
$thumb = [string]$j.thumb
$had = Test-Path -LiteralPath (Join-Path $store $thumb)
if (-not $had) {
  $before = @(Get-ChildItem -LiteralPath $store | ForEach-Object { $_.Thumbprint })
  # a PKCS#12 without a password: an empty SecureString (ConvertTo-SecureString refuses '')
  $pw = New-Object System.Security.SecureString
  if ([string]$env:ACME_PFX_PASSWORD) {
    $pw = ConvertTo-SecureString -String $env:ACME_PFX_PASSWORD -AsPlainText -Force
  }
  if ($j.exportable) {
    $got = @(Import-PfxCertificate -FilePath ([string]$j.pfx) -CertStoreLocation $store `
      -Password $pw -Exportable)
  } else {
    $got = @(Import-PfxCertificate -FilePath ([string]$j.pfx) -CertStoreLocation $store `
      -Password $pw)
  }
  if (-not (Test-Path -LiteralPath (Join-Path $store $thumb))) {
    foreach ($g in $got) {
      if ($before -notcontains $g.Thumbprint) {
        Remove-Item -LiteralPath (Join-Path $store $g.Thumbprint) -ErrorAction SilentlyContinue
      }
    }
    throw 'the PKCS#12 holds another certificate than the one of this deployment'
  }
}
$cert = Get-Item -LiteralPath (Join-Path $store $thumb)
if (-not $cert.HasPrivateKey) { throw 'the certificate in the machine store has no private key' }
if (-not $had) { $cert.FriendlyName = [string]$j.friendly }
Say @{ imported = (-not $had); thumb = $thumb }
"""

# the bindings set to the certificate - each said before it is changed (what it had), so a
# failure half way is put back exactly
PS_BIND = PRELUDE + r"""# acme-agent: bind
$thumb = [string]$j.thumb
Iis-Ready
foreach ($w in @($j.iis)) {
  $site = [string]$w.site
  if (-not (Site-There $site)) { throw ('there is no IIS site ' + $site) }
  $b = Find-Binding $w
  $created = $false
  $old = ''
  if (-not $b) {
    $sni = 0
    if ([string]$w.host) { $sni = 1 }
    New-WebBinding -Name $site -Protocol https -Port ([int]$w.port) -HostHeader ([string]$w.host) `
      -IPAddress ([string]$w.ip) -SslFlags $sni
    $b = Find-Binding $w
    $created = $true
  } else {
    $old = [string]$b.certificateHash
  }
  Say @{ step = 'iis'; site = $site; host = [string]$w.host; port = [int]$w.port;
         ip = [string]$w.ip; old = $old; created = $created }
  if ($old -ne $thumb) {
    # as acme's windows_ssh: AddSslCertificate replaces the one there; only when IIS refuses
    # that (an http.sys binding left behind) is it taken away first and added again
    try { $b.AddSslCertificate($thumb, 'My') }
    catch { if ($old) { $b.RemoveSslCertificate(); $b.AddSslCertificate($thumb, 'My') } else { throw } }
  }
  Say @{ step = 'iis-done'; site = $site; host = [string]$w.host; port = [int]$w.port }
}
if ($j.rdp) {
  $cert = Get-Item -LiteralPath (Join-Path $store $thumb)
  # the listener (TermService, NETWORK SERVICE) reads the private key: read on its file for
  # S-1-5-20 - the lines of acme's windows_ssh (_win_roles.RDP_KEY_READ, generated)
""" + _roles().SCRIPTS['rdp_key_read'] + r"""
  $ts = Rdp-Setting
  Say @{ step = 'rdp'; old = [string]$ts.SSLCertificateSHA1Hash }
  Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = $thumb }
  Say @{ step = 'rdp-done' }
}
"""

# what a binding step changed, put back: a binding made is removed, one there gets its old
# certificate again; the listener its old thumbprint
PS_UNBIND = PRELUDE + r"""# acme-agent: unbind
$bad = @()
if (@($j.iis).Count -gt 0) { Import-Module WebAdministration }
foreach ($w in @($j.iis)) {
  try {
    $b = Find-Binding $w
    if ($b) {
      if ($w.created) {
        try { $b.RemoveSslCertificate() } catch { }
        Remove-WebBinding -Name ([string]$w.site) -Protocol https -Port ([int]$w.port) `
          -HostHeader ([string]$w.host)
      } elseif ([string]$w.old -ne [string]$j.thumb) {
        if ([string]$w.old) {
          try { $b.AddSslCertificate([string]$w.old, 'My') }
          catch { $b.RemoveSslCertificate(); $b.AddSslCertificate([string]$w.old, 'My') }
        } else { try { $b.RemoveSslCertificate() } catch { } }
      }
    }
    Say @{ step = 'iis'; site = [string]$w.site; port = [int]$w.port; host = [string]$w.host }
  } catch { $bad += ([string]$w.site + ': ' + $_.Exception.Message) }
}
if ($j.rdp_back) {
  try {
    $ts = Rdp-Setting
    Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = [string]$j.rdp_old }
    Say @{ step = 'rdp' }
  } catch { $bad += ('Remote Desktop: ' + $_.Exception.Message) }
}
if ($bad.Count -gt 0) { throw ($bad -join '; ') }
"""

# certificates taken out of the store - never one still used: by IIS, http.sys (AD FS, WAP,
# SSTP, RD Gateway, WAC), the Remote Desktop listener, SQL Server, WinRM - the lines of acme's
# windows_ssh (_win_roles.USED, generated)
PS_REMOVE = PRELUDE + r"""# acme-agent: remove
""" + _roles().SCRIPTS['used'] + r"""
foreach ($t in @($j.thumbs)) {
  $t = [string]$t
  $p = Join-Path $store $t
  if (-not (Test-Path -LiteralPath $p)) { Say @{ thumb = $t; was = 'gone' }; continue }
  if ($used -contains $t) { Say @{ thumb = $t; was = 'inuse' }; continue }
  Remove-Item -LiteralPath $p
  Say @{ thumb = $t; was = 'removed' }
}
"""


def powershell_exe():
    root = os.environ.get('SystemRoot') or os.environ.get('windir') or 'C:\\Windows'
    return ntpath.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')


def powershell(script, env, timeout=PS_TIMEOUT):
    """THE one place a PowerShell script is run (the root side: SYSTEM) -> (exit code, what it
    wrote). The tests replace it."""
    enc = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        got = subprocess.run([powershell_exe(), '-NoLogo', '-NoProfile', '-NonInteractive',
                              '-ExecutionPolicy', 'Bypass', '-EncodedCommand', enc],
                             env=env, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=timeout, creationflags=flags)
    except FileNotFoundError:
        return 127, 'powershell.exe is not on this machine'
    except subprocess.TimeoutExpired:
        return 124, 'PowerShell did not end in %d s' % timeout
    except OSError as e:
        return 126, str(e)
    return got.returncode, (got.stdout.decode('utf-8', 'replace') + '\n' +
                            got.stderr.decode('utf-8', 'replace'))


def stage_dir(A):
    d = os.path.join(A.ROOT_STATE, 'stage')
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def _gone(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def run(A, script, values, password=None, timeout=PS_TIMEOUT):
    """A fixed script run with `values` (a JSON file in root's stage folder, deleted after) ->
    (ok, [what it said: the ACME objects], the error it said or its last words)."""
    fn = os.path.join(stage_dir(A), 'acme-%s.json' % secrets.token_hex(8))
    env = dict(os.environ)
    env.pop('ACME_PFX_PASSWORD', None)
    env['ACME_WIN_IN'] = fn
    if password is not None:
        env['ACME_PFX_PASSWORD'] = password
    try:
        _new_file(fn, json.dumps(values).encode('utf-8'))
        rc, said = powershell(script, env, timeout)
    finally:
        _gone(fn)
    objs, err = [], ''
    for line in (said or '').splitlines():
        line = line.strip()
        if line.startswith('ACME {') or line.startswith('ACME ['):
            try:
                objs.append(json.loads(line[5:]))
            except ValueError:
                pass
        elif line.startswith('ACME-ERROR '):
            err = line[11:].strip()
    if rc != 0 and not err:
        rest = [x.strip() for x in (said or '').splitlines() if x.strip() and
                not x.strip().startswith('ACME')]
        err = (rest[-1] if rest else 'exit %s' % rc)
    return rc == 0, objs, err[-300:]


def _openssl_exe(A):
    for name in ('OPENSSL', 'OPENSSL_EXE'):
        v = getattr(A, name, None)
        if isinstance(v, str) and v:
            return v
    fn = getattr(A, 'openssl_exe', None)
    if callable(fn):
        try:
            return fn()
        except Exception:                               # noqa: BLE001
            pass
    return os.environ.get('ACME_AGENT_OPENSSL') or 'openssl'


def make_pfx(A, key_pem, chain_pem, password, alias, legacy=True):
    """A PKCS#12 of the key this agent made and its certificate (and chain): by openssl, in
    root's stage folder; 3DES (any Windows) unless the job says AES."""
    t = os.path.join(stage_dir(A), 'p12-%s' % secrets.token_hex(8))
    os.mkdir(t, 0o700)
    kf, cf = os.path.join(t, 'k.pem'), os.path.join(t, 'c.pem')
    try:
        _new_file(kf, key_pem.encode() if isinstance(key_pem, str) else key_pem)
        _new_file(cf, chain_pem.encode() if isinstance(chain_pem, str) else chain_pem)
        argv = [_openssl_exe(A), 'pkcs12', '-export', '-inkey', kf, '-in', cf, '-name',
                str(alias or 'acme')[:64], '-passout', 'env:ACME_AGENT_P12']
        if legacy:
            argv += ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1']
        env = dict(os.environ)
        env['ACME_AGENT_P12'] = password
        got = subprocess.run(argv, capture_output=True, env=env, stdin=subprocess.DEVNULL)
        if got.returncode != 0:
            raise A.Refused('openssl pkcs12: %s' % got.stderr.decode('utf-8', 'replace')
                            .strip()[-200:])
        return got.stdout
    finally:
        for fn in (kf, cf):
            _gone(fn)
        try:
            os.rmdir(t)
        except OSError:
            pass


# ---- root\store.json: the certificates this agent imported, by deployment ----------------------
def records_path(A):
    return os.path.join(A.ROOT_STATE, STORE_FILE)


def records_load(A):
    try:
        with open(records_path(A), 'rb') as f:
            got = json.loads(f.read(1024 * 1024).decode('utf-8'))
    except (OSError, ValueError):
        return {}
    return got if isinstance(got, dict) else {}


def records_save(A, recs):
    if len(recs) > STORE_RECORDS_MOST:
        newest = sorted(recs, key=lambda k: max([x.get('at') or 0 for x in recs[k]] + [0]))
        for k in newest[:len(recs) - STORE_RECORDS_MOST]:
            recs.pop(k, None)
    data = json.dumps(recs, sort_keys=True)
    w = getattr(A, '_write', None)
    if callable(w):
        try:
            w(records_path(A), data, 0o600)
            return
        except Exception:                               # noqa: BLE001
            pass
    tmp = records_path(A) + '.%s' % secrets.token_hex(4)
    _new_file(tmp, data.encode('utf-8'))
    os.replace(tmp, records_path(A))


# ---- one deployment's `win` ---------------------------------------------------------------------
def _short(t):
    return (t or '')[:12] + '…' if t else 'none'


def _bind_words(b):
    return 'IIS %s %s:%d' % (b['site'], b['host'] or (b['ip'] if b['ip'] != '*' else '*'),
                             b['port'])


def _needs(key):
    return {r[0]: r[2] for r in _roles().ROLES}.get(key)


class WinJob(object):
    """The store, the bindings and the listener of one deployment - and their undo."""

    def __init__(self, A, dep, w, priv=None, datas=None, ak=None):
        if not is_windows(A):
            raise A.Refused('this agent does not run on Windows: the machine store, IIS and the '
                            'Remote Desktop listener are not here')
        self.A, self.dep, self.w = A, dep, w
        self.st = w.get('store') or {}
        self.thumb = self.st.get('thumb') or ''
        self.imported = False
        self.bound = []                 # [{site, host, port, ip, old, created}] - changed
        self.rdp_old = None             # the listener's thumbprint before (when changed)
        self.did = []
        self.pfx, self.password = (None, None)
        self.key_pem = None             # the key this agent made (agent_key), for the CCS files
        self.priv = priv
        if self.st and priv is not False:
            self.pfx, self.password = self._pfx(priv, datas or [], ak)
        # a role that imports a PKCS#12 itself (RDS, SharePoint): the one of the store
        self.role_pfx = self.pfx if any(_needs(r['key']) == 'pfx' for r in
                                        w.get('roles') or []) else None
        self.now = self.state() if self.st else {'present': False, 'iis': [], 'rdp': ''}
        self.same = self._same()

    # -- the PKCS#12 ----------------------------------------------------------------------
    def _password(self, priv):
        sealed = self.st.get('password_sealed')
        if not sealed:
            return ''
        if priv is None:
            raise self.A.Refused('this agent has no key to open secrets with (join again)')
        return self.A.unseal(sealed, priv, self.dep.agent_id, 'win store password').decode(
            'utf-8')

    def _pfx(self, priv, datas, ak):
        A = self.A
        how = self.st.get('from')
        if how == 'stage':
            f = self.st['file']
            if f.get('sealed'):
                if priv is None:
                    raise A.Refused('this agent has no key to open secrets with (join again)')
                data = A.unseal(f['sealed'], priv, self.dep.agent_id, 'win store')
            else:
                data = A._unb64(f.get('data'), None, 'the PKCS#12 for the machine store')
            return data, self._password(priv)
        if how == 'file':
            return datas[self.st['index']], self._password(priv)
        # the key this agent made: root makes the PKCS#12 of it here
        key_pem = None
        kf = getattr(self.dep, 'key_from', None)
        if kf:
            key_pem = A._read(kf[1] if kf[0] == 'pending' else kf[2], '') or None
        if not key_pem:
            key_pem, _kt = self.dep.agent_key(ak)
        if self.thumb != thumb_of(str((ak or {}).get('cert_pem') or '')):
            raise A.Refused('the certificate for the machine store is not the one of the key '
                            'this agent made')
        pw = secrets.token_urlsafe(24)
        self.key_pem = key_pem
        return make_pfx(A, key_pem, self.st['cert_pem'], pw, self.st.get('friendly'),
                        self.st.get('legacy', True)), pw

    # -- what is there --------------------------------------------------------------------
    def state(self):
        ok, objs, err = run(self.A, PS_STATE, {'thumb': self.thumb, 'iis': self.w['iis'],
                                               'rdp': self.w['rdp']})
        if not ok or not objs or not isinstance(objs[-1], dict):
            raise self.A.Refused('the machine store and the bindings could not be read: %s'
                                 % (err or 'PowerShell said nothing'))
        got = objs[-1]
        iis = got.get('iis') or []
        got['iis'] = iis if isinstance(iis, list) else [iis]
        return got

    def _same(self):
        if not self.st or not self.now.get('present'):
            return not self.st
        for want in self.w['iis']:
            have = [b for b in self.now['iis'] if isinstance(b, dict) and
                    str(b.get('site')) == want['site'] and int(b.get('port') or 0) == want['port']
                    and str(b.get('host') or '') == want['host']]
            if not have or str(have[0].get('thumb') or '').upper() != self.thumb:
                return False
        if self.w['rdp'] and str(self.now.get('rdp') or '').upper() != self.thumb:
            return False
        return True

    def say_same(self):
        self.dep.step('the machine store holds %s already%s - left as it is' % (
            _short(self.thumb), ', every binding uses it' if self.w['iis'] or self.w['rdp']
            else ''), 'ok')

    # -- the store, then the bindings -------------------------------------------------------
    def apply(self):
        """The store, the bindings, then the PowerShell after (post_ps) - any failing raises:
        the deployment puts everything back."""
        self._apply()
        post = self.w.get('post_ps')
        if self.st and post:
            ok, steps, err, _said = run_lines(self.A, ROLE_PRELUDE + POST_PS_HEAD + post['body'] +
                                              ROLE_END, {'thumb': self.thumb})
            for lv, words in steps:
                self.dep.step(words, lv)
            if not ok:
                raise self.A.Refused('the PowerShell after the import failed: %s' % err)
            self.dep.step('the PowerShell after the import ran (sha256 %s…)' % post['sha256'][:16],
                          'ok')
            self.did.append('the PowerShell after')

    def _apply(self):
        if not self.st:
            return
        A = self.A
        fn = os.path.join(stage_dir(A), 'acme-%s.pfx' % secrets.token_hex(8))
        try:
            _new_file(fn, self.pfx)
            ok, objs, err = run(A, PS_IMPORT, {
                'pfx': fn, 'thumb': self.thumb, 'friendly': self.st['friendly'],
                'exportable': self.st['exportable']}, password=self.password or '')
        finally:
            _gone(fn)
            self.pfx = None
        said = objs[-1] if objs and isinstance(objs[-1], dict) else {}
        if not ok:
            raise A.Refused('the import into the machine store failed: %s' % err)
        self.imported = bool(said.get('imported'))
        self.dep.step('the certificate %s %s the machine store (LocalMachine\\My)%s' % (
            _short(self.thumb), 'imported into' if self.imported else 'is in',
            '' if self.imported else ' already'), 'ok')
        if self.imported:
            self.did.append('imported %s' % self.thumb[:12])
        if not self.w['iis'] and not self.w['rdp']:
            return
        ok, objs, err = run(A, PS_BIND, {'thumb': self.thumb, 'iis': self.w['iis'],
                                         'rdp': self.w['rdp']})
        for o in objs:
            if not isinstance(o, dict):
                continue
            if o.get('step') == 'iis':
                self.bound.append({'site': str(o.get('site') or ''),
                                   'host': str(o.get('host') or ''),
                                   'port': int(o.get('port') or 443),
                                   'ip': str(o.get('ip') or '*'),
                                   'old': str(o.get('old') or '').upper(),
                                   'created': bool(o.get('created'))})
            elif o.get('step') == 'iis-done' and self.bound:
                b = self.bound[-1]
                self.dep.step('%s: %s' % (_bind_words(b), 'a new https binding, with it'
                              if b['created'] else 'uses it already' if b['old'] == self.thumb
                              else 'bound to it (was %s)' % _short(b['old'])), 'ok')
                self.did.append(_bind_words(b))
            elif o.get('step') == 'rdp':
                self.rdp_old = str(o.get('old') or '').upper()
            elif o.get('step') == 'rdp-done':
                self.dep.step('the Remote Desktop listener uses it (was %s)' % _short(
                    self.rdp_old), 'ok')
                self.did.append('Remote Desktop')
        if not ok:
            raise A.Refused('binding the certificate failed: %s' % err)

    # -- put back -----------------------------------------------------------------------
    def undo(self):
        """The bindings back to what they had, the new certificate out of the store (only
        when this job put it there)."""
        A = self.A
        bad = []
        if self.bound or self.rdp_old is not None:
            ok, _objs, err = run(A, PS_UNBIND, {
                'thumb': self.thumb, 'iis': list(reversed(self.bound)),
                'rdp_back': self.rdp_old is not None, 'rdp_old': self.rdp_old or ''})
            if ok:
                self.dep.step('the bindings are back as they were (%s)' % ', '.join(
                    [_bind_words(b) for b in self.bound] + (['Remote Desktop'] if
                                                            self.rdp_old is not None else [])),
                    'warn')
            else:
                bad.append(err)
        if self.imported:
            ok, objs, err = run(A, PS_REMOVE, {'thumbs': [self.thumb]})
            was = [o.get('was') for o in objs if isinstance(o, dict)]
            if ok and was[-1:] in (['removed'], ['gone']):
                self.dep.step('the new certificate %s is out of the machine store again'
                              % _short(self.thumb), 'warn')
            else:
                bad.append(err or 'the new certificate %s is still bound: left in the store'
                           % _short(self.thumb))
        if bad:
            self.dep.step('putting the store and the bindings back failed: %s' % '; '.join(
                bad)[:300], 'bad')
        self.bound, self.rdp_old, self.imported = [], None, False

    # -- the roles (after the store, the bindings, the test, the script and the reload) -----
    def has_roles(self):
        return bool(self.st and (self.w.get('roles') or self.w.get('key_read')))

    def _ccs_pfx(self):
        """(the PKCS#12 of the Central Certificate Store's files, its password): sent by acme
        (sealed, with the store's password), or made here from this agent's own key."""
        A, c = self.A, self.w.get('ccs') or {}
        pw = ''
        if c.get('password_sealed'):
            if self.priv is None:
                raise A.Refused('this agent has no key to open secrets with (join again)')
            pw = A.unseal(c['password_sealed'], self.priv, self.dep.agent_id,
                          'win ccs password').decode('utf-8')
        if c.get('sealed'):
            if self.priv is None:
                raise A.Refused('this agent has no key to open secrets with (join again)')
            return A.unseal(c['sealed'], self.priv, self.dep.agent_id, 'win ccs'), pw
        if c.get('data'):
            return A._unb64(c.get('data'), None, 'the PKCS#12 of the Central Certificate '
                                                 'Store'), pw
        if self.key_pem:
            return make_pfx(A, self.key_pem, self.st['cert_pem'], pw, self.st.get('friendly'),
                            self.st.get('legacy', True)), pw
        raise A.Refused('IIS Central Certificate Store: the job holds no PKCS#12 for its files')

    def run_roles(self):
        """Read on the key for the accounts given, then each role - a role failing is said, the
        others run (as acme's windows_ssh) -> '' or what failed (the old certificates are then
        kept, nothing put back)."""
        A = self.A
        on = self.w.get('roles') or []
        if on:
            self.dep.step('roles on the server: %s' % ', '.join(r['title'] for r in on))
        temp = []
        try:
            env, paths = {}, {}
            if any(_needs(r['key']) == 'pfx' for r in on):
                paths['pfx'] = os.path.join(stage_dir(A), 'acme-roles-%s.pfx' % secrets.token_hex(8))
                _new_file(paths['pfx'], self.role_pfx or b'')
                temp.append(paths['pfx'])
                env['ACME_PFX_PASSWORD'] = self.password or ''
            if any(r['key'] == 'ccs' for r in on):
                data, pw = self._ccs_pfx()
                paths['ccs_pfx'] = os.path.join(stage_dir(A), 'acme-ccs-%s.pfx' % secrets.token_hex(8))
                _new_file(paths['ccs_pfx'], data)
                temp.append(paths['ccs_pfx'])
                env['ACME_CCS_PASSWORD'] = pw
            base = {'thumb': self.thumb, 'prefix': self.w.get('prefix') or ''}
            if self.w.get('key_read'):
                ok, steps, err, _s = run_lines(A, role_ps('key_read'), dict(
                    base, o={'accounts': self.w['key_read']}))
                for lv, words in steps:
                    self.dep.step(words, lv)
                if not ok:
                    return 'read on the key could not be given: %s - no role was run, the old ' \
                           'certificates are kept' % err
            failed, did = [], []
            for r in on:
                o = dict(r['o'])
                for k, v in paths.items():
                    if k in _roles().SCHEMA.get(r['key'], {}):
                        o[k] = v
                ok, steps, err, _s = run_lines(A, role_ps(r['key']), dict(base, o=o),
                                               env if _needs(r['key']) else None)
                for lv, words in steps:
                    self.dep.step(words, lv)
                if not ok:
                    self.dep.step('%s failed: %s' % (r['title'], err), 'bad')
                    failed.append(r['title'])
                    continue
                self.dep.step('%s: done' % r['title'], 'ok')
                did.append(r['title'])
            self.did += did
            if failed:
                return '%s failed (%s done); the old certificates are kept' % (
                    ', '.join(failed), ', '.join(did) or 'nothing else')
            return ''
        finally:
            for fn in temp:
                _gone(fn)

    # -- after a deployment that worked ----------------------------------------------------
    def remember(self):
        """This certificate remembered as imported by this agent (a later deployment removes it
        beyond its keep) - nothing removed now."""
        if not self.st or not self.imported:
            return
        recs = records_load(self.A)
        slot = self.st['slot']
        mine = [x for x in recs.get(slot) or [] if isinstance(x, dict) and
                THUMB_RE.match(str(x.get('thumb') or ''))]
        if self.thumb not in [x['thumb'] for x in mine]:
            mine.append({'thumb': self.thumb, 'at': time.time()})
        recs[slot] = mine
        records_save(self.A, recs)

    def finish(self):
        """This certificate remembered as imported by this agent; the older ones it imported
        for this deployment removed beyond `keep` (never one still used)."""
        if not self.st:
            return
        A = self.A
        recs = records_load(A)
        slot = self.st['slot']
        mine = [x for x in recs.get(slot) or [] if isinstance(x, dict) and
                THUMB_RE.match(str(x.get('thumb') or ''))]
        if self.imported and self.thumb not in [x['thumb'] for x in mine]:
            mine.append({'thumb': self.thumb, 'at': time.time()})
        old = sorted([x for x in mine if x['thumb'] != self.thumb],
                     key=lambda x: -(x.get('at') or 0))[self.st['keep']:]
        if old:
            ok, objs, err = run(A, PS_REMOVE, {'thumbs': [x['thumb'] for x in old]})
            gone = set()
            for o in objs:
                if not isinstance(o, dict):
                    continue
                t = str(o.get('thumb') or '').upper()
                if o.get('was') == 'removed':
                    gone.add(t)
                    self.dep.step('removed the older certificate %s (imported by this agent '
                                  'for this deployment)' % _short(t))
                elif o.get('was') == 'gone':
                    gone.add(t)
                elif o.get('was') == 'inuse':
                    self.dep.step('the older certificate %s is still bound: kept' % _short(t),
                                  'warn')
            if not ok:
                self.dep.step('the older certificates could not all be removed: %s' % err,
                              'warn')
            mine = [x for x in mine if x['thumb'] not in gone]
        if mine:
            recs[slot] = mine
        else:
            recs.pop(slot, None)
        records_save(A, recs)

    def words(self):
        return (', ' + ', '.join(self.did)) if self.did else ''


def dry_check(A, w):
    """The `win` part of a check (nothing changed): what each step would do -> entries as the
    check's files are said ({path, said, bad})."""
    out = []
    if not is_windows(A):
        return [{'path': 'the machine store', 'said': 'this agent does not run on Windows',
                 'bad': True}]
    st = w.get('store') or {}
    if w.get('detect') or w.get('roles'):
        # the roles of this server (as windows_ssh's "Test the connection" and its test of a
        # deployment): each role the job has on must be installed
        found, err = detect(A)
        R = _roles()
        if w.get('detect'):
            here = ['%s (%s)' % (t, found[k][1]) if found[k][1] else t
                    for k, t, _n in R.ROLES if found.get(k, (False, ''))[0]]
            out.append({'path': 'the roles on this server', 'roles': {
                k: [bool(v[0]), v[1]] for k, v in found.items()},
                'said': err or (', '.join(here) if here else 'none of the roles acme knows')})
        for r in w.get('roles') or []:
            yes, detail = found.get(r['key'], (False, ''))
            out.append({'path': 'the role %s' % r['title'], 'role': r['key'],
                        'said': ('is on this server%s' % (' (%s)' % detail if detail else ''))
                        if yes else 'is not installed on this server', 'bad': not yes})
        for a in w.get('key_read') or []:
            out.append({'path': 'read on the key', 'said': 'given to %s after the import' % a})
        if w.get('post_ps'):
            out.append({'path': 'the PowerShell after', 'said': 'allowed by its hash (sha256 '
                        '%s…) - not run on a test' % w['post_ps']['sha256'][:16]})
    if not st:
        return out
    try:
        now = WinJob(A, _Quiet(), w, priv=False).now
    except A.Refused as e:
        return out + [{'path': 'the machine store', 'said': str(e), 'bad': True}]
    out.append({'path': 'the machine store (LocalMachine\\My)',
                'said': 'holds %s already' % _short(st['thumb']) if now.get('present') else
                'the certificate %s is imported' % _short(st['thumb'])})
    have = [b for b in now.get('iis') or [] if isinstance(b, dict)]
    for want in w['iis']:
        b = next((x for x in have if str(x.get('site')) == want['site'] and
                  int(x.get('port') or 0) == want['port'] and
                  str(x.get('host') or '') == want['host']), {})
        if not b.get('site_there'):
            out.append({'path': _bind_words(want), 'said': 'there is no IIS site %s'
                        % want['site'], 'bad': True})
        elif not b.get('binding'):
            out.append({'path': _bind_words(want), 'said': 'no https binding yet - it is made'})
        else:
            out.append({'path': _bind_words(want), 'said': 'its certificate %s is replaced' %
                        _short(str(b.get('thumb') or '').upper()) if str(b.get('thumb') or '')
                        .upper() != st['thumb'] else 'uses this certificate already'})
    if w.get('rdp'):
        out.append({'path': 'the Remote Desktop listener', 'said': 'its certificate %s is '
                    'replaced' % _short(str(now.get('rdp') or '').upper())})
    return out


class _Quiet(object):
    agent_id = ''
    key_from = None

    def step(self, *_a, **_k):
        pass


def keygen_check(A, pol):
    """A key made here for a deployment into the machine store: only where it may go there."""
    if not is_windows(A):
        raise A.Refused('this agent does not run on Windows: there is no machine store here')
    if not pol_store(pol):
        raise A.Refused('not allowed by the policy of this machine: the certificate imported '
                        'into the machine store (LocalMachine\\My)',
                        [{'kind': 'store', 'what': 'the certificate imported into the machine '
                          'store (LocalMachine\\My)', 'allow': 'acme-agent allow store'}])
