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

The roles (1.0.120 - what acme's OpenSSH target windows_ssh does, docs/target-agent.md "Windows:
what the OpenSSH target does, the agent does"): `win.roles` [{key, o}], `win.key_read`
[accounts], `win.post_ps` (PowerShell lines), `win.prefix`, `win.ccs` (the Central Certificate
Store's PKCS#12 and its password, sealed). Each role's script is acme_agent_winroles.SCRIPTS
(generated from acme's _win_roles - the same text windows_ssh renders), run with the job's values
checked by its SCHEMA in a JSON file ($o) - allowed by `allow role NAME` (ccs: `path=FOLDER`, wac:
`msi=FILE` for the installer it runs again), `allow key-read ACCOUNT`, the PowerShell after by
`allow script-hash HASH`. Order: ... reload -> read on the key -> each role (one failing is said,
the others run, the deployment fails, the old certificates are kept, nothing is put back).
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
    """A word of a command line as an administrator types it (cmd.exe, PowerShell). The lines
    are typed in an elevated PowerShell: a word PowerShell would expand inside "..." ($name,
    $(...), ${...}, a backtick) is put in '...' (a ' in it doubled) - "Shop $live" was typed as
    "Shop " and the policy got another name."""
    s = str(s)
    if re.search(r'`|\$[A-Za-z0-9_?^${(]', s):
        return "'%s'" % s.replace("'", "''")
    return '"%s"' % s if (not s or re.search(r'[\s&|<>^%;,()\'`${}]', s) or
                          s[0] in '#@') else s


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


def detect(A, timeout=PS_TIMEOUT):
    """The roles of this server: {role: (yes, detail)} - one run, nothing changed (the same
    lines as windows_ssh's "Test the connection")."""
    ok, _steps, err, said = run_lines(A, role_ps('detect'), {}, timeout=timeout)
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
  # exactly the binding IP:PORT:HOST (Get-WebBinding takes an empty -HostHeader as any host
  # and has no say on the address): never another site's host or address on the same port
  $ip = [string]$w.ip
  if (-not $ip) { $ip = '*' }
  $tail = ':' + [string][int]$w.port + ':' + [string]$w.host
  $want = @(($ip + $tail), ('[' + $ip + ']' + $tail))
  if ($ip -eq '*') {
    # no address in the line ('*', as the server sends it then): the binding of this host and
    # port on any address, the *: one first - as before, and as windows_ssh (hunt R t10: a
    # binding on 10.0.0.5:443 was "not found", a second one made on *:443 beside it)
    $t = $tail.ToLower()
    Get-WebBinding -Name ([string]$w.site) -Protocol https |
      Where-Object { ([string]$_.bindingInformation).ToLower().EndsWith($t) } |
      Sort-Object { -not ([string]$_.bindingInformation).StartsWith('*:') } | Select-Object -First 1
    return
  }
  Get-WebBinding -Name ([string]$w.site) -Protocol https |
    Where-Object { $want -contains [string]$_.bindingInformation } | Select-Object -First 1
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
if (-not $cert.HasPrivateKey) {
  # imported by this run: taken out again (the deployment's undo knows of no import)
  if (-not $had) { Remove-Item -LiteralPath (Join-Path $store $thumb) -ErrorAction SilentlyContinue }
  throw 'the certificate in the machine store has no private key'
}
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
  if (-not $b) { throw ('the new https binding of the IIS site ' + $site + ' is not found') }
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
        $b | Remove-WebBinding
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


# ---- a Microsoft CA (AD CS) without its web service (1.0.125, docs/ms-adcs-agent.md) -------------
# acme sends a CSR (op `adcs`); this agent - a member server of the domain, its root side running
# as LocalSystem - submits it to the CA over the CA's own request interface (ICertRequest: RPC /
# DCOM, MS-ICPR - what `certreq -submit -config "HOST\CA" -attrib "CertificateTemplate:NAME"` does),
# signed in by Kerberos as the computer account. acme holds no credential at all.
#
#   allow adcs "HOST\CA Name" template=WebServer,WebServer2     that CA, those templates
#   allow adcs "HOST\CA Name" template=*                        that CA, any template it offers
#   allow adcs-read                                             list every CA and its templates
#
# A job names its action: submit {ca, template, csr, san_attr}, retrieve {ca, template, req_id},
# templates {ca}, cas {}. Nothing else of a job reaches the CA: the request is the CSR acme made
# (checked to be one, no Windows sign-in name in it), the attributes are the template's name and
# - asked for - a SAN attribute made here of the CSR's own DNS names and addresses. The values go
# to a FIXED PowerShell script through a JSON file in root's stage folder (run()), never into
# its text.
ADCS_CA_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\[^\x00-\x1f\x7f"\\/:*?<>|]{1,128}\Z')
ADCS_TEMPLATE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.()-]{0,63}\Z')
ADCS_ACTIONS = ('submit', 'retrieve', 'templates', 'cas')
ADCS_CSR_MOST = 16 * 1024
ADCS_TIMEOUT = 120
# the CA's dispositions (CR_DISP_*, certcli.h)
ADCS_DISP = {0: 'incomplete', 1: 'error', 2: 'denied', 3: 'issued', 4: 'issued out of band',
             5: 'pending', 6: 'revoked'}


def adcs_ca(text, A=None):
    """'HOST\\CA Name' as a CA's config string - or Refused (A given) / ValueError."""
    t = str(text or '').strip()
    if not ADCS_CA_RE.match(t) or t.endswith(' ') or '\\ ' in t:
        err = '%r is not the config string of a CA: HOST\\CA Name (ca01.example.local\\Example ' \
              'Issuing CA)' % t[:120]
        if A is not None:
            raise A.Refused(err)
        raise ValueError(err)
    return t


def adcs_template(text, A=None):
    t = str(text or '').strip()
    if not ADCS_TEMPLATE_RE.match(t):
        err = '%r is not the name of a template (its name, not its display name: WebServer)' \
              % t[:80]
        if A is not None:
            raise A.Refused(err)
        raise ValueError(err)
    return t


def pol_adcs(pol):
    """[{'ca', 'templates'}] the policy allows (templates ['*'] for any)."""
    v = (pol or {}).get('adcs') or []
    return [x for x in v if isinstance(x, dict) and x.get('ca')] if isinstance(v, list) else []


def pol_adcs_read(pol):
    return bool((pol or {}).get('adcs_read'))


def adcs_entry(rest, A):
    """The words after `allow adcs` -> {'ca', 'templates'} (a line a CA, template= needed)."""
    kv, rest = A._kv(rest, ('template',))
    if len(rest) != 1 or not kv.get('template'):
        raise A.Refused('allow adcs "HOST\\CA Name" template=NAME,NAME (or template=*)')
    ca = adcs_ca(rest[0], A)
    names = [x.strip() for x in kv['template'].split(',') if x.strip()]
    if not names:
        raise A.Refused('template= names a template or more (template=WebServer,WebServer2) or '
                        'is * (any template of the CA)')
    if '*' in names:
        if len(names) > 1:
            raise A.Refused('template=* is any template of the CA - no names beside it')
        return {'ca': ca, 'templates': ['*']}
    out = []
    for n in names:
        n = adcs_template(n, A)
        if n.lower() not in [x.lower() for x in out]:
            out.append(n)
    if len(out) > 64:
        raise A.Refused('template= names 64 templates at most')
    return {'ca': ca, 'templates': out}


def adcs_add(pol, entry):
    """The entry into the policy: a CA said twice has the templates of both lines."""
    have = pol.setdefault('adcs', [])
    for x in have:
        if x['ca'].lower() == entry['ca'].lower():
            if '*' in x['templates'] or '*' in entry['templates']:
                x['templates'] = ['*']
            else:
                for t in entry['templates']:
                    if t.lower() not in [y.lower() for y in x['templates']]:
                        x['templates'].append(t)
            return
    have.append({'ca': entry['ca'], 'templates': list(entry['templates'])})


def adcs_line(entry):
    """An entry as the line of the policy (and of `acme-agent allow`). Template names with a
    space or brackets are quoted: unquoted, the policy's own line read back (or typed in a
    prompt) split the name into words and the whole line was refused."""
    return 'adcs "%s" template=%s' % (entry['ca'], adcs_names_word(entry['templates']))


def adcs_names_word(templates):
    """The value of template= as a policy line (and a prompt) reads it back as one word."""
    names = ','.join(templates)
    if re.search(r'[^A-Za-z0-9_.,*-]', names):
        names = '"%s"' % names
    return names


def allow_adcs_words(ca, templates):
    return 'acme-agent allow %s' % adcs_line({'ca': ca, 'templates': list(templates)})


def adcs_rule(pol, ca):
    return next((x for x in pol_adcs(pol) if x['ca'].lower() == str(ca).lower()), None)


def adcs_allowed(pol, ca, template=None):
    rule = adcs_rule(pol, ca)
    if rule is None:
        return False
    if template is None:
        return True
    return '*' in rule['templates'] or str(template).lower() in [
        t.lower() for t in rule['templates']]


def adcs_needs(pol, args):
    """What the policy lacks for a job of op `adcs` -> [{kind, what, allow}] (acme's plan and the
    agent judge it alike)."""
    act = str((args or {}).get('action') or '')
    ca = str((args or {}).get('ca') or '')
    if act in ('cas',):
        if pol_adcs_read(pol) or pol_adcs(pol):
            return []
        return [{'kind': 'adcs-read', 'what': 'the list of the CAs of the domain',
                 'allow': 'acme-agent allow adcs-read'}]
    if act == 'templates':
        if pol_adcs_read(pol) or adcs_rule(pol, ca):
            return []
        return [{'kind': 'adcs-read', 'what': 'the templates of the CA %s' % ca,
                 'allow': 'acme-agent allow adcs-read'}]
    template = str((args or {}).get('template') or '')
    if adcs_allowed(pol, ca, template):
        return []
    rule = adcs_rule(pol, ca)
    want = (list(rule['templates']) + [template]) if rule else [template]
    return [{'kind': 'adcs', 'what': 'a certificate of the template %s from the CA %s' % (
        template, ca), 'allow': allow_adcs_words(ca, want)}]


ADCS_PS = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }
$j = Get-Content -LiteralPath $env:ACME_WIN_IN -Raw -Encoding UTF8 | ConvertFrom-Json
function Say($o) { Write-Output ('ACME ' + ($o | ConvertTo-Json -Compress -Depth 5)) }
# 0xffffffffL: a 64-bit mask (PowerShell reads 0xffffffff as the Int32 -1, which kept an
# HRESULT negative: 0xffffffff80094012, a code no word of ADCS_CODES matched)
function Hx($n) { '0x{0:x8}' -f ([int64]$n -band 0xffffffffL) }
# acme-agent: adcs (ICertRequest / ICertConfig - as certreq and certutil ask the CA)
$out = @{ action = [string]$j.action }
try {
  if ($j.action -eq 'cas') {
    $c = New-Object -ComObject CertificateAuthority.Config
    $list = @()
    [void]$c.Reset(0)
    while ($c.Next() -ge 0) {
      $list += @{ config = [string]$c.GetField('Config'); name = [string]$c.GetField('CommonName');
                  server = [string]$c.GetField('Server') }
    }
    $out.cas = $list
  } elseif ($j.action -eq 'templates') {
    $r = New-Object -ComObject CertificateAuthority.Request
    # CR_PROP_TEMPLATES (0x1d), PROPTYPE_STRING: "name`noid`n" a template - a template of
    # schema 1 (WebServer) has an empty OID line: the OID line (empty or not) is skipped by
    # what it is, not dropped before pairing (that paired the next template's name as an OID)
    $raw = [string]$r.GetCAProperty([string]$j.ca, 0x1d, 0, 4, 0)
    $parts = @($raw -split "`n" | ForEach-Object { $_.Trim() })
    $names = @()
    $i = 0
    while ($i -lt $parts.Count) {
      if ($parts[$i] -ne '') { $names += $parts[$i] }
      if ($i + 1 -lt $parts.Count -and ($parts[$i + 1] -eq '' -or $parts[$i + 1] -match '^[0-9]+(\.[0-9]+)+$')) { $i += 2 } else { $i += 1 }
    }
    $disp = @{}
    try {
      $cfg = [string]([ADSI]'LDAP://RootDSE').configurationNamingContext
      $ds = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $cfg), '(objectClass=pKICertificateTemplate)')
      [void]$ds.PropertiesToLoad.Add('cn'); [void]$ds.PropertiesToLoad.Add('displayName')
      foreach ($x in $ds.FindAll()) { $disp[[string]$x.Properties['cn'][0]] = [string]$x.Properties['displayname'][0] }
    } catch { }
    $out.templates = @($names | ForEach-Object { @{ name = [string]$_; display = [string]$disp[[string]$_] } })
  } else {
    $r = New-Object -ComObject CertificateAuthority.Request
    if ($j.action -eq 'submit') {
      # CR_IN_BASE64HEADER | CR_IN_PKCS10: the CSR as acme made it
      $d = $r.Submit(0x100, [string]$j.csr, [string]$j.attrib, [string]$j.ca)
    } else {
      $d = $r.RetrievePending([int]$j.req_id, [string]$j.ca)
    }
    $out.disposition = [int]$d
    $out.req_id = [int]$r.GetRequestId()
    $out.status = Hx ([int64]$r.GetLastStatus())
    try { $out.message = [string]$r.GetDispositionMessage() } catch { }
    if ($d -eq 3) {
      $out.cert = [string]$r.GetCertificate(1)                       # CR_OUT_BASE64
      try { $out.chain = [string]$r.GetCertificate(0x101) } catch { } # ... | CR_OUT_CHAIN
    }
  }
} catch {
  $out.error = ($_.Exception.Message -replace '[\r\n]+', ' ')
  $out.code = Hx ([int64]$_.Exception.HResult)
}
Say $out
"""

# the CA's words for its codes - the same as the Web Enrollment source's (issuers/ms_adcs.py)
ADCS_CODES = {
    '0x80094800': 'the CA does not offer this template (CA: Certificate Templates - New - '
                  'Certificate Template to Issue), or it is the display name - give its name',
    '0x80094801': 'the request has no template',
    '0x80094012': 'the computer account of this server may not enroll for this template '
                  '(the template - Security: Read and Enroll)',
    '0x80094005': 'the CA refused the request\'s names (the template builds the subject from '
                  'Active Directory: set it to "Supply in the request")',
    '0x80094004': 'the template needs a subject the computer account does not have - set the '
                  'template to "Supply in the request"',
    '0x80094006': 'the CA refused the request\'s key',
    '0x80094009': 'the request has a key smaller than the template wants',
    '0x80094811': 'the template needs a key the request does not have (its kind, its size, '
                  'its provider)',
    '0x80070005': 'access is denied (the computer account\'s rights on the CA: Request '
                  'Certificates)',
    '0x800706ba': 'the CA cannot be reached over RPC (the RPC server is unavailable: its name, '
                  'the firewall - TCP 135 and the dynamic ports)',
    '0x80094011': 'the CA needs a certificate manager to approve the request',
    '0x80070057': 'the CA did not take the request as it was sent',
    '0x800b0110': 'the certificate is not for that purpose',
}


def adcs_csr_names(A, csr):
    """The CSR checked (a PKCS#10, its signature good) -> its DNS names and addresses. A CSR
    naming a Windows sign-in (a UPN, otherName) or anything but DNS names, addresses, e-mail
    and URIs is refused: this agent asks the CA for server certificates."""
    if not isinstance(csr, str) or len(csr) > ADCS_CSR_MOST or \
            not re.fullmatch(r'\s*-----BEGIN (NEW )?CERTIFICATE REQUEST-----[A-Za-z0-9+/=\s]+'
                             r'-----END (NEW )?CERTIFICATE REQUEST-----\s*', csr):
        raise A.Refused('the request is not a CSR (PEM, %d KiB at most)' % (ADCS_CSR_MOST // 1024))
    # openssl req -verify answers 0 for a bad signature too (OpenSSL 3: only "verify failure"
    # on its error output) - its words decide, as acme's own check (hunt u3/u4)
    try:
        got = subprocess.run([A.OPENSSL, 'req'] + list(getattr(A, 'STDIN_IN', [])) +
                             ['-noout', '-text', '-verify'], input=csr, capture_output=True,
                             text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise A.Refused('the CSR cannot be read or its signature is not good (openssl: %s)' % e)
    said = '%s\n%s' % (got.stdout or '', got.stderr or '')
    # its own line, on either output (hunt u5: OpenSSL 3.2+ prints "verify OK" on the standard
    # output - every good request was refused; -text's subject line is never one of its own)
    if got.returncode != 0 or 'verify fail' in said.lower() or not re.search(
            r'(?m)^(?:Certificate request self-signature )?verify OK\s*$', said):
        raise A.Refused('the CSR cannot be read or its signature is not good (openssl: %s)'
                        % ((got.stderr or '').strip()[-200:] or 'verify failure'))
    text = got.stdout
    m = re.search(r'X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]*)', text)
    names = []
    for part in [x.strip() for x in (m.group(1) if m else '').split(',') if x.strip()]:
        kind, _, value = part.partition(':')
        kind = kind.strip().lower()
        if kind == 'dns':
            names.append(('dns', value.strip()))
        elif kind == 'ip address':
            names.append(('ipaddress', value.strip()))
        elif kind in ('email', 'uri'):
            continue
        else:
            raise A.Refused('the CSR names %s - this agent asks the CA for server certificates '
                            'only (DNS names, addresses): no Windows sign-in name (UPN), no '
                            'other name' % part[:80])
    return names


def adcs_attrib(A, template, csr, san_attr):
    attrs = ['CertificateTemplate:%s' % template]
    names = adcs_csr_names(A, csr)
    if san_attr:
        if not names:
            raise A.Refused('the CSR has no DNS name or address for a SAN attribute')
        for kind, value in names:
            if not re.fullmatch(r'[A-Za-z0-9*_.:-]{1,253}', value):
                raise A.Refused('%r cannot go into a SAN attribute' % value[:80])
        attrs.append('SAN:' + '&'.join('%s=%s' % p for p in names))
    return '\n'.join(attrs)


def adcs_run(A, values, timeout):
    """ADCS_PS run with `values` -> its answer (a dict), or Refused."""
    ok, objs, err = run(A, ADCS_PS, values, timeout=timeout)
    got = objs[-1] if objs and isinstance(objs[-1], dict) else None
    if got is None:
        raise A.Refused('PowerShell did not answer (%s)' % (err or 'nothing said'))
    return got


def adcs_code(v):
    """An HRESULT as the script says it -> '0x8009xxxx' (a sign-extended one, 0xffffffff8009xxxx
    or a negative number, as 32 bits), '' when there is none."""
    t = str(v or '').strip().lower()
    try:
        n = int(t, 16) if t.startswith(('0x', '-0x')) else int(t)
    except ValueError:
        return t[:12]
    return '0x%08x' % (n & 0xffffffff)


def adcs_said(got):
    """The words of the CA's refusal (its code, its message)."""
    code = adcs_code(got.get('code') or got.get('status'))
    words = ADCS_CODES.get(code)
    said = _clean(got.get('error') or got.get('message') or '', 300).strip()
    bits = [words or ('the CA denied the request' if got.get('disposition') == 2 else
                      'the CA did not issue the certificate')]
    if said:
        bits.append('it says: %s' % said)
    if code and code != '0x00000000':
        bits.append(code)
    return ' - '.join(bits)


def adcs(A, pol, args):
    """The job of op `adcs` (the root side, LocalSystem) -> its answer."""
    if not is_windows(A):
        raise A.Refused('a Microsoft CA is asked only by acme-agent on Windows (a member server '
                        'of the domain) - this agent runs on %s' % getattr(A, 'PLATFORM', 'Linux'))
    act = str(args.get('action') or '')
    if act not in ADCS_ACTIONS:
        raise A.Refused('%r is not an action of adcs (%s)' % (act[:20], ', '.join(ADCS_ACTIONS)))
    try:
        timeout = max(10, min(int(args.get('timeout') or ADCS_TIMEOUT), 600))
    except (TypeError, ValueError):
        timeout = ADCS_TIMEOUT
    ca = adcs_ca(args.get('ca'), A) if act != 'cas' else ''
    template = adcs_template(args.get('template'), A) if act in ('submit', 'retrieve') else ''
    needs = adcs_needs(pol, {'action': act, 'ca': ca, 'template': template})
    if needs:
        raise A.Refused('not allowed by the policy of this machine: %s' % needs[0]['what'], needs)
    if act == 'cas':
        got = adcs_run(A, {'action': 'cas'}, timeout)
        if got.get('error'):
            raise A.Refused('the CAs of the domain cannot be listed: %s' % adcs_said(got))
        cas = []
        for c in (got.get('cas') or [])[:64]:
            if not isinstance(c, dict):
                continue
            try:
                cfg = adcs_ca(c.get('config'))
            except ValueError:
                continue
            if not pol_adcs_read(pol) and not adcs_rule(pol, cfg):
                continue                    # only adcs-read lists a CA the policy does not name
            rule = adcs_rule(pol, cfg)
            cas.append({'config': cfg, 'name': _clean(c.get('name'), 128),
                        'server': _clean(c.get('server'), 253),
                        'allowed': list(rule['templates']) if rule else []})
        return {'ok': True, 'adcs': {'action': 'cas', 'cas': cas},
                'said': '%d CA%s' % (len(cas), '' if len(cas) == 1 else 's')}
    if act == 'templates':
        got = adcs_run(A, {'action': 'templates', 'ca': ca}, timeout)
        if got.get('error'):
            raise A.Refused('the templates of %s cannot be listed: %s' % (ca, adcs_said(got)))
        out = []
        for t in (got.get('templates') or [])[:500]:
            if not isinstance(t, dict):
                continue
            try:
                name = adcs_template(t.get('name'))
            except ValueError:
                continue
            out.append({'name': name, 'display': _clean(t.get('display'), 128),
                        'allowed': adcs_allowed(pol, ca, name)})
        return {'ok': True, 'adcs': {'action': 'templates', 'ca': ca, 'templates': out},
                'said': '%d template%s the CA %s offers' % (len(out), '' if len(out) == 1
                                                             else 's', ca)}
    if act == 'submit':
        values = {'action': 'submit', 'ca': ca, 'csr': str(args.get('csr') or ''),
                  'attrib': adcs_attrib(A, template, args.get('csr'), bool(args.get('san_attr')))}
    else:
        rid = str(args.get('req_id') or '')
        if not re.fullmatch(r'[0-9]{1,10}', rid) or not 0 < int(rid) < 2 ** 31:
            raise A.Refused('%r is not the id of a request' % rid[:20])
        values = {'action': 'retrieve', 'ca': ca, 'req_id': int(rid)}
    got = adcs_run(A, values, timeout)
    try:
        rid = int(got.get('req_id') or values.get('req_id') or 0)
    except (TypeError, ValueError):
        rid = 0
    if got.get('error') and got.get('disposition') is None:
        raise A.Refused('the CA %s: %s' % (ca, adcs_said(got)))
    disp = got.get('disposition')
    state = ADCS_DISP.get(disp, 'error') if isinstance(disp, int) else 'error'
    out = {'action': act, 'ca': ca, 'template': template, 'state': state,
           'req_id': str(rid) if rid > 0 else '',
           'code': _clean(adcs_code(got.get('status') or got.get('code')), 12)}
    if state == 'issued':
        cert = re.sub(r'\s+', '', str(got.get('cert') or ''))
        chain = re.sub(r'\s+', '', str(got.get('chain') or ''))
        try:
            base64.b64decode(cert, validate=True)
            if chain:
                base64.b64decode(chain, validate=True)
        except (ValueError, TypeError):
            raise A.Refused('the CA\'s certificate for request %s cannot be read' % rid)
        if not cert:
            raise A.Refused('the CA issued request %s but sent no certificate' % rid)
        out.update(cert=cert, chain=chain)
        said = 'the CA %s issued the certificate (request %s)' % (ca, rid)
    elif state == 'pending':
        said = 'the CA %s holds request %s for a certificate manager to approve' % (ca, rid)
    else:
        out['said'] = adcs_said(got)
        said = 'the CA %s did not issue it (%s): %s' % (ca, state, out['said'])
    return {'ok': True, 'adcs': out, 'said': said}


def adcs_cli(A, argv):
    """`acme-agent adcs cas | templates --config "HOST\\CA Name" [--json]`: what the
    administrator sees of the CAs and their templates - as acme's policy designer lists them,
    run as the administrator who types it (no policy asked: read-only)."""
    as_json = '--json' in argv
    argv = [a for a in argv if a != '--json']
    usage = 'acme-agent adcs cas [--json] | adcs templates --config "HOST\\CA Name" [--json]'
    if not argv or argv[0] not in ('cas', 'templates'):
        raise SystemExit(usage)
    if not is_windows(A):
        raise SystemExit('acme-agent: a Microsoft CA is listed only on Windows')
    try:
        pol = dict(A.policy_load()[0])
    except Exception:                                   # noqa: BLE001
        pol = {}
    pol['adcs_read'] = True                 # the administrator at the console: read-only
    try:
        if argv[0] == 'cas':
            got = adcs(A, pol, {'action': 'cas'})['adcs']
            cas = got['cas']
            for c in cas:
                try:
                    c['templates'] = adcs(A, pol, {'action': 'templates', 'ca': c['config']})[
                        'adcs']['templates']
                except A.Refused as e:
                    c['templates'] = []
                    c['problem'] = str(e)
            if as_json:
                print(json.dumps({'cas': cas}, indent=1))
                return 0
            for c in cas:
                print('%s   (%s)' % (c['config'], c['name']))
                for t in c['templates']:
                    print('    %-32s %s' % (t['name'], t['display']))
                if c.get('problem'):
                    print('    ! %s' % c['problem'])
                print('    -> acme-agent allow adcs %s template=%s' % (
                    cmd_word(c['config']),
                    adcs_names_word([t['name'] for t in c['templates']] or ['*'])))
            return 0
        if len(argv) != 3 or argv[1] != '--config':
            raise SystemExit(usage)
        got = adcs(A, pol, {'action': 'templates', 'ca': argv[2]})['adcs']
        if as_json:
            print(json.dumps(got, indent=1))
            return 0
        for t in got['templates']:
            print('%-32s %s' % (t['name'], t['display']))
        return 0
    except A.Refused as e:
        raise SystemExit('acme-agent: %s' % e)


# ---- discovery (1.0.125, docs/target-agent.md "Discovery") ----------------------------------------
# What of this Windows server takes certificates, and which: the IIS sites and their https
# bindings, the Remote Desktop listener, the roles acme deploys to (as the roles' own detection
# finds them, with the certificate a role is bound to where that is cheap to read), the machine
# store's certificates (subject, names, issuer, the end, thumbprint, serial; whether acme
# imported it). Read-only - one fixed script, nothing changed; never a key nor a password.
DISCOVER_STORE_MOST = 300
DISCOVER_PS_S = 120             # the script reading the store, IIS, the listener, the roles
DISCOVER_ALL_S = 150            # the whole discovery (the roles' detection too): acme waits 180 s
DISCOVER_PS = PRELUDE + r"""# acme-agent: discover
$k = @($j.kinds)
$out = @{ store = @(); iis = @(); rdp = ''; roles = @{} }
function Epoch($d) { [int64](($d.ToUniversalTime() - [datetime]'1970-01-01T00:00:00').TotalSeconds) }
$n = 0
function Facts($c) {
  $san = @()
  try { $san = @($c.DnsNameList | ForEach-Object { [string]$_.Unicode }) } catch { }
  @{ thumb = [string]$c.Thumbprint; subject = [string]$c.Subject;
     issuer = [string]$c.Issuer; not_after = (Epoch $c.NotAfter);
     serial = [string]$c.SerialNumber; sans = $san;
     friendly = [string]$c.FriendlyName; has_key = [bool]$c.HasPrivateKey }
}
foreach ($c in @(Get-ChildItem -LiteralPath $store)) {
  if ($n -ge 300) { break }
  $n += 1
  $out.store += (Facts $c)
}
# a certificate a binding or the listener takes from another store of the machine (IIS' Web
# Hosting, the listener's own Remote Desktop store): read there - it is not missing
$out.other = @()
function Other-Cert([string]$t, [string]$sn) {
  if ($t -notmatch '^[0-9A-Fa-f]{40}$' -or $sn -notmatch '^[A-Za-z0-9 _-]{1,64}$' -or $sn -eq 'My') { return }
  if (@($out.other).Count -ge 32) { return }
  try {
    $p = 'Cert:\LocalMachine\' + $sn + '\' + $t
    if (Test-Path -LiteralPath $p) { $f = Facts (Get-Item -LiteralPath $p); $f.store = $sn; $out.other += $f }
  } catch { }
}
if ($k -contains 'iis') {
  try {
    Import-Module WebAdministration
    foreach ($s in @(Get-Website)) {
      $bs = @()
      foreach ($b in @($s.bindings.Collection | Where-Object { $_.protocol -eq 'https' })) {
        $bs += @{ info = [string]$b.bindingInformation; thumb = [string]$b.certificateHash;
                  store = [string]$b.certificateStoreName; sni = [int]$b.sslFlags }
        Other-Cert ([string]$b.certificateHash) ([string]$b.certificateStoreName)
      }
      $out.iis += @{ site = [string]$s.Name; state = [string]$s.State; bindings = $bs }
    }
  } catch { $out.iis_error = [string]$_.Exception.Message }
}
if ($k -contains 'rdp') {
  try { $out.rdp = [string](Rdp-Setting).SSLCertificateSHA1Hash } catch { }
  Other-Cert $out.rdp 'Remote Desktop'
}
if ($k -contains 'sql') {
  try {
    $names = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
    $is = @()
    if ($names) {
      foreach ($p in @($names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        $t = ''
        try { $t = [string](Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\' + [string]$p.Value + '\MSSQLServer\SuperSocketNetLib')).Certificate } catch { }
        $is += @{ name = [string]$p.Name; thumb = $t }
      }
    }
    $out.roles.sql = @{ instances = $is }
  } catch { }
}
if ($k -contains 'winrm') {
  try {
    $ls = @()
    foreach ($l in @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | Where-Object { $_.Keys -contains 'Transport=HTTPS' })) {
      $h = ''; $t = ''; $p = ''
      foreach ($i in @(Get-ChildItem -LiteralPath $l.PSPath)) {
        if ($i.Name -eq 'Hostname') { $h = [string]$i.Value }
        if ($i.Name -eq 'CertificateThumbprint') { $t = [string]$i.Value }
        if ($i.Name -eq 'Port') { $p = [string]$i.Value }
      }
      $ls += @{ host = $h; thumb = $t; port = $p }
    }
    $out.roles.winrm = @{ listeners = $ls }
  } catch { }
}
if ($k -contains 'ldaps') {
  try {
    $t = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates' -ErrorAction Stop | ForEach-Object { [string]$_.PSChildName })
    $out.roles.ldaps = @{ thumbs = $t }
  } catch { }
}
if ($k -contains 'ftp') {
  try {
    Import-Module WebAdministration
    $t = [string](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -Name serverCertHash).Value
    $out.roles.ftp = @{ thumb = $t }
  } catch { }
}
if ($k -contains 'adfs') {
  try { $out.roles.adfs = @{ thumb = [string](@(Get-AdfsSslCertificate)[0].CertificateHash) } } catch { }
}
if ($k -contains 'rdgw') {
  try {
    Import-Module RemoteDesktopServices
    $out.roles.rdgw = @{ thumb = [string](Get-Item -Path 'RDS:\GatewayServer\SSLCertificate\Thumbprint').CurrentValue }
  } catch { }
}
Say $out
"""
DISCOVER_ROLE_PORT = {'sql': 1433, 'winrm': 5986, 'ldaps': 636, 'ftp': 21, 'adfs': 443,
                      'wap': 443, 'exchange': 443, 'sstp': 443, 'rdgw': 443, 'rds': 443,
                      'sharepoint': 443, 'wac': 443, 'lync': 443, 'ccs': 443}


def _epoch(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0 < f < 2 ** 40 else None


def _thumb(v):
    t = re.sub(r'[^0-9A-Fa-f]', '', str(v or '')).upper()
    return t if THUMB_RE.match(t) else ''


def _cn(subject):
    m = re.search(r'(?:^|,\s*)CN=([^,]+)', str(subject or ''))
    return m.group(1).strip() if m else ''


def _store_facts(c, acme_thumbs):
    t = _thumb(c.get('thumb'))
    if not t:
        return None
    sans = c.get('sans') if isinstance(c.get('sans'), list) else []
    return {'thumbprint': t, 'subject': _clean(c.get('subject'), 300),
            'issuer': _clean(c.get('issuer'), 300), 'not_after': _epoch(c.get('not_after')),
            'serial': _clean(c.get('serial'), 80).upper(), 'cn': _cn(c.get('subject')),
            'sans': [_clean(x, 253) for x in sans[:40] if x],
            'friendly': _clean(c.get('friendly'), 120), 'has_key': bool(c.get('has_key')),
            'acme': t in acme_thumbs, 'where': []}


def _binding(info):
    """'IP:PORT:HOST' (IIS' bindingInformation) -> (ip, port, host)."""
    s = str(info or '')
    m = re.match(r'^(\[[^\]]*\]|[^:]*):(\d{1,5}):(.*)$', s)
    if not m:
        return '*', 443, ''
    ip = m.group(1) or '*'
    return ip, int(m.group(2)), m.group(3)


def discover(A, pol, kinds):
    """The job of op `discover` on Windows (the root side, LocalSystem) -> {found, certs,
    skipped}. `kinds`: what the policy allows and acme asked."""
    kinds = list(kinds)
    t0 = time.time()
    ok, objs, err = run(A, DISCOVER_PS, {'kinds': kinds}, timeout=DISCOVER_PS_S)
    got = objs[-1] if objs and isinstance(objs[-1], dict) else {}
    if not ok and not got:
        raise A.Refused('the server could not be looked at: %s' % (err or 'PowerShell failed'))
    acme = set()
    for recs in records_load(A).values():
        for x in recs if isinstance(recs, list) else []:
            if isinstance(x, dict) and THUMB_RE.match(str(x.get('thumb') or '')):
                acme.add(x['thumb'])
    store = {}
    for c in (got.get('store') or [])[:DISCOVER_STORE_MOST]:
        if isinstance(c, dict):
            f = _store_facts(c, acme)
            if f:
                store[f['thumbprint']] = f
    # bound from another store of the machine (Web Hosting, Remote Desktop): not missing
    for c in (got.get('other') or [])[:32]:
        if isinstance(c, dict):
            f = _store_facts(c, acme)
            if f and f['thumbprint'] not in store:
                f['store'] = _clean(c.get('store'), 64)
                store[f['thumbprint']] = f
    found, skipped = [], []

    def cert_of(t, where):
        t = _thumb(t)
        f = store.get(t)
        if f is None:
            return {'thumbprint': t, 'missing': True} if t else None
        if where not in f['where'] and len(f['where']) < 12:
            f['where'].append(where)
        return {k: v for k, v in f.items() if k != 'where'}

    if 'iis' in kinds:
        if got.get('iis_error'):
            skipped.append({'kind': 'iis', 'why': _clean(got['iis_error'], 200)})
        for s in (got.get('iis') or [])[:100]:
            if not isinstance(s, dict) or not s.get('bindings'):
                continue
            site = _clean(s.get('site'), 256)
            bs, names, cert = [], [], None
            for b in (s.get('bindings') or [])[:IIS_MOST]:
                if not isinstance(b, dict):
                    continue
                ip, port, host = _binding(b.get('info'))
                t = _thumb(b.get('thumb'))
                bs.append({'site': site, 'host': _clean(host, 253), 'port': port,
                           'ip': _clean(ip, 60), 'thumb': t, 'sni': bool(int(b.get('sni') or 0)
                                                                        & 1)})
                if host and host not in names:
                    names.append(_clean(host, 253))
                c = cert_of(t, 'IIS %s %s:%d' % (site, host or ip, port))
                cert = cert or c
            found.append({'kind': 'iis', 'title': 'IIS site', 'site': site, 'names': names,
                          'state': _clean(s.get('state'), 20), 'bindings': bs, 'cert': cert,
                          'listen': ['%s:%d' % (b['ip'], b['port']) for b in bs],
                          'unit': 'W3SVC', 'port': bs[0]['port'] if bs else 443,
                          'files': [], 'preset': '', 'config': 'IIS'})
    if 'rdp' in kinds:
        t = _thumb(got.get('rdp'))
        found.append({'kind': 'rdp', 'title': 'Remote Desktop listener', 'names': [],
                      'cert': cert_of(t, 'Remote Desktop listener'), 'listen': ['3389'],
                      'unit': 'TermService', 'port': 3389, 'files': [], 'preset': '',
                      'config': 'RDP-tcp'})
    R = _roles()
    asked_roles = [r[0] for r in R.ROLES if r[0] in kinds]
    if asked_roles:
        # what is left of the whole discovery's time (acme waits 180 s for its
        # answer): the roles' detection alone may take 300 s, an answer nobody waits for
        det, derr = detect(A, timeout=max(15, int(DISCOVER_ALL_S - (time.time() - t0))))
        if derr and not det:
            skipped.append({'kind': 'roles', 'why': _clean(derr, 200)})
        roles = got.get('roles') if isinstance(got.get('roles'), dict) else {}
        titles = {r[0]: r[2] for r in R.ROLES}
        for key in asked_roles:
            yes, detail = det.get(key, (False, ''))
            if not yes:
                continue
            one = {'kind': key, 'title': titles.get(key, key), 'detail': _clean(detail, 200),
                   'names': [], 'listen': [], 'files': [], 'preset': '', 'config': key,
                   'port': DISCOVER_ROLE_PORT.get(key, 443), 'cert': None}
            r = roles.get(key) if isinstance(roles.get(key), dict) else {}
            if key == 'sql':
                one['instances'] = []
                for i in (r.get('instances') or [])[:16]:
                    if isinstance(i, dict):
                        t = _thumb(i.get('thumb'))
                        one['instances'].append({'name': _clean(i.get('name'), 120),
                                                 'thumb': t})
                        one['cert'] = one['cert'] or cert_of(t, 'SQL Server %s' % _clean(
                            i.get('name'), 120))
            elif key == 'winrm':
                one['listeners'] = []
                for x in (r.get('listeners') or [])[:8]:
                    if isinstance(x, dict):
                        t = _thumb(x.get('thumb'))
                        one['listeners'].append({'host': _clean(x.get('host'), 253),
                                                 'port': _clean(x.get('port'), 8), 'thumb': t})
                        if x.get('host'):
                            one['names'].append(_clean(x.get('host'), 253))
                        one['cert'] = one['cert'] or cert_of(t, 'WinRM HTTPS listener')
            elif key == 'ldaps':
                for t in (r.get('thumbs') or [])[:4]:
                    one['cert'] = one['cert'] or cert_of(t, 'LDAPS (NTDS)')
            elif r.get('thumb'):
                one['cert'] = cert_of(r.get('thumb'), titles.get(key, key))
            if key == 'ccs' and detail and detail != 'not set up':
                one['ccs_path'] = _clean(detail, 260)
            found.append(one)
    certs = sorted(store.values(), key=lambda c: (c.get('not_after') or 0))
    if 'store' not in kinds:
        certs = [c for c in certs if c['where']]       # only those the services use
    return {'found': found, 'certs': certs, 'skipped': skipped}
