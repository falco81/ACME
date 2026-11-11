# -*- coding: utf-8 -*-
"""
Files and the script after them, for the targets that write the certificate
as files (ssh, windows_ssh, local) - not a module: the registry skips "_" files.

    FORMATS                     every format of an output line, in words
    password_fields()           pfx_password_mode / pfx_password / jks_alias
    script_fields(...)          script_mode / _path / _args / _body / _interp
    password_of(options)        the password the files are locked with, or None
    script_of(t, options, vars) what is run after the files: {mode, path, args,
                                body, interp, from} or None (a deployment's own,
                                else the target's default)
    env_for(...)                the ACME_* variables the script gets
    preview(...)                what a deployment would write, in words, for the
                                page (POST /api/deploys/preview) - no network
    run_posix(t, s, sc, env)    the script uploaded, run (through sudo when the
                                target says so), deleted -> (rc, out, err)
    run_windows(t, s, sc, env)  the same in PowerShell

The script never gets its variables on a command line (a password would be in
the process list): they are uploaded beside it in a file of mode 0600 that
the wrapper reads and deletes before the script starts.
"""
from __future__ import annotations

import json
import re
import secrets
import shlex
import time

from acmelib.plugins.targets._common import (
    PluginError, field, quote, text, subst, alt_of, family_of, variants_of,
    PFX_FORMATS, fp_of, put_scp)

SCRIPT_MAX = 64 * 1024          # bytes of a script written in the application
OUTPUT_MOST = 3500              # characters of what a script said kept in the job

# format: (title, what is inside, holds the key, binary)
FORMATS = {
    'fullchain-pem': ('Certificate + chain (PEM)', 'the certificate, then the intermediates - '
                      'what nginx, Postfix, Dovecot want', False, False),
    'cert-pem': ('Certificate only (PEM)', 'the certificate alone, no chain', False, False),
    'chain-pem': ('Chain only (PEM)', 'the intermediates, without the certificate', False, False),
    'key-pem': ('Private key (PEM, PKCS#8)', 'the key alone, "BEGIN PRIVATE KEY"', True, False),
    'key-rsa': ('Private key (PEM, PKCS#1)', '"BEGIN RSA PRIVATE KEY" for old programs - '
                'RSA keys only', True, False),
    'combined-pem': ('Key + certificate + chain (one PEM)', 'everything in one file - HAProxy, '
                     'Webmin, vsftpd', True, False),
    'cert-der': ('Certificate (DER, binary)', 'the certificate alone, binary', False, True),
    'key-der': ('Private key (DER, binary)', 'the key alone, binary', True, True),
    'p7b': ('Certificate + chain (PKCS#7, .p7b)', 'for imports into Windows or Java - no key',
            False, True),
    'pfx': ('PKCS#12 / PFX (AES-256)', 'key + certificate + chain, locked with a password',
            True, True),
    'p12': ('PKCS#12 (.p12, AES-256)', 'the same as PFX', True, True),
    'p12-legacy': ('PKCS#12, old (3DES)', 'for Windows Server 2016 and older, old Java and '
                   'devices', True, True),
    'jks': ('Java keystore (JKS)', 'key + certificate + chain, for Tomcat and other Java - '
            'needs a password', True, True),
}

# interpreter: (title, how a file is run on Linux / Unix, extension)
INTERPS = {
    'bash': ('bash', 'bash', '.sh'),
    'sh': ('sh (POSIX)', 'sh', '.sh'),
    'python3': ('Python 3', 'python3', '.py'),
    'powershell': ('PowerShell', 'powershell', '.ps1'),
}

# What the script is told, in this order: (name, what it is).
ENV_DOC = [
    ('ACME_CERT_NAME', 'the certificate\'s name in acme'),
    ('ACME_CN', 'its first name (the common name)'),
    ('ACME_NAMES', 'every name, separated by spaces'),
    ('ACME_NOT_AFTER', 'when it ends (UTC, ISO 8601)'),
    ('ACME_FINGERPRINT', 'its SHA-256 fingerprint (hex)'),
    ('ACME_SERIAL', 'its serial number (hex)'),
    ('ACME_VERSION', 'its version in acme (1, 2, ...)'),
    ('ACME_KEY_TYPE', 'the kind of its key (ec-256, rsa-2048, ...)'),
    ('ACME_FILES', 'the files written, one a line'),
    ('ACME_FILE_<FORMAT>', 'the path of the file of that format - ACME_FILE_KEY_PEM, '
     'ACME_FILE_FULLCHAIN_PEM...; _2 for a second one of the same format, _ALT / _RSA / '
     '_EC for a dual certificate\'s'),
    ('ACME_PASSWORD', 'the password of the PKCS#12 / keystore files (only when they have one)'),
    ('ACME_SERVICE', 'the service / container name of the deployment'),
    ('ACME_TARGET', 'the name of the target in acme'),
    ('ACME_HOST', 'the address acme reached'),
    ('ACME_DRY_RUN', '1 on a test (the files are in a temporary folder - change nothing), '
     'else 0'),
]

SNIPPETS = {
    'posix': [
        {'key': 'copy', 'title': 'Copy the key and certificate to more places',
         'interp': 'bash', 'body': '''#!/bin/bash
# The new certificate and key copied to more places.
set -euo pipefail
for dir in /opt/app1/tls /opt/app2/tls; do
  if [ "$ACME_DRY_RUN" = 1 ]; then
    echo "test: would copy to $dir"
    continue
  fi
  install -D -m 0644 "$ACME_FILE_FULLCHAIN_PEM" "$dir/cert.pem"
  install -D -m 0600 "$ACME_FILE_KEY_PEM" "$dir/key.pem"
  echo "copied to $dir"
done
'''},
        {'key': 'systemd', 'title': 'Reload a systemd service',
         'interp': 'bash', 'body': '''#!/bin/bash
# A systemd service reloaded (restarted when it cannot reload), then checked.
set -euo pipefail
UNIT="${ACME_SERVICE:-nginx}"
if [ "$ACME_DRY_RUN" = 1 ]; then
  systemctl is-active "$UNIT"
  exit 0
fi
systemctl reload-or-restart "$UNIT"
sleep 1
systemctl is-active --quiet "$UNIT" && echo "$UNIT is running with $ACME_CN"
'''},
        {'key': 'docker', 'title': 'Restart a Docker container',
         'interp': 'bash', 'body': '''#!/bin/bash
# A container restarted to read the new files (its name: "Service" of the deployment).
set -euo pipefail
C="${ACME_SERVICE:-web}"
if [ "$ACME_DRY_RUN" = 1 ]; then
  docker inspect -f '{{.State.Status}}' "$C"
  exit 0
fi
docker restart "$C"
'''},
    ],
    'windows': [
        {'key': 'copy', 'title': 'Copy the PFX to more places',
         'interp': 'powershell', 'body': '''# The new PFX copied to more places.
$ErrorActionPreference = 'Stop'
foreach ($dir in @('C:\\App1\\tls', 'D:\\App2\\tls')) {
  if ($env:ACME_DRY_RUN -eq '1') { Write-Output "test: would copy to $dir"; continue }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item -Force $env:ACME_FILE_PFX (Join-Path $dir 'site.pfx')
  Write-Output "copied to $dir"
}
'''},
        {'key': 'service', 'title': 'Restart a Windows service',
         'interp': 'powershell', 'body': '''# A Windows service restarted (its name: "Service" of the deployment).
$ErrorActionPreference = 'Stop'
$name = if ($env:ACME_SERVICE) { $env:ACME_SERVICE } else { 'W3SVC' }
if ($env:ACME_DRY_RUN -eq '1') { (Get-Service -Name $name).Status; exit 0 }
Restart-Service -Name $name -Force
(Get-Service -Name $name).Status
'''},
        {'key': 'thumb', 'title': 'Use the thumbprint (IIS, RDP, SQL Server...)',
         'interp': 'powershell', 'body': '''# $env:ACME_THUMBPRINT: the certificate imported into LocalMachine\\My.
$ErrorActionPreference = 'Stop'
$cert = Get-Item ("Cert:\\LocalMachine\\My\\" + $env:ACME_THUMBPRINT)
Write-Output ("imported: " + $cert.Subject + " until " + $cert.NotAfter)
if ($env:ACME_DRY_RUN -eq '1') { exit 0 }
# e.g. SQL Server:
# Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQLServer\\SuperSocketNetLib' -Name Certificate -Value $env:ACME_THUMBPRINT.ToLower()
'''},
    ],
}


# ---------------------------------------------------------------------------
# Fields
# ---------------------------------------------------------------------------
def password_fields(jks=True):
    out = [
        field('pfx_password_mode', 'Password of PKCS#12 / keystore files', 'select',
              default='fixed', advanced=True,
              options=[['fixed', 'the one set here (none when empty)'], ['none', 'none'],
                       ['generate', 'made by acme (random, kept sealed)']],
              help='for pfx, p12, p12-legacy and jks files. Made by acme: a random one, kept '
                   'with the deployment (a full administrator sees it), given to the script '
                   'as ACME_PASSWORD'),
        field('pfx_password', 'PKCS#12 / keystore password', 'secret',
              help='for pfx, p12, p12-legacy and jks files (jks needs one)'),
    ]
    if jks:
        out.append(field('jks_alias', 'Keystore alias', 'text', advanced=True,
                         help='the alias in a jks or pfx; empty: the certificate\'s name'))
    return out


def script_fields(interps, deploy=True, default='bash'):
    """The script after the files: of a deployment (deploy=True: '' = the target's
    default) or the target's default for its deployments."""
    modes = [['none', 'nothing'], ['path', 'a command or script already on the machine'],
             ['inline', 'a script written here (uploaded each time)']]
    if deploy:
        modes = [['', 'as the target says']] + modes
    k = {} if deploy else {'advanced': True}
    show = {'script_mode': ['inline']}
    return [
        field('script_mode', 'After the files' if deploy else 'Script after the files (default)',
              'select', default='' if deploy else 'none', options=modes, ui='script', **k,
              help='run after the files are written and the test passed; a failure puts '
                   'the previous files back' + ('' if deploy else
                                                 ' - the default of every deployment here')),
        field('script_path', 'Command or script on the machine', 'text', ui='script',
              placeholder='/usr/local/bin/reload-certs.sh', show_if={'script_mode': ['path']},
              help='its absolute path; the ACME_* variables are set for it', **k),
        field('script_args', 'Its arguments', 'text', ui='script', placeholder='{name}',
              show_if={'script_mode': ['path', 'inline']},
              help='{name} {cn} {service} {date} are filled in', **k),
        field('script_interp', 'Interpreter', 'select', default=default, ui='script',
              options=[[i, INTERPS[i][0]] for i in interps], show_if=show, **k),
        field('script_body', 'The script', 'textarea', ui='script', rows=12, show_if=show,
              help='uploaded on every deployment, run with the ACME_* variables, then '
                   'deleted; only a full administrator may change it (64 KiB at most)', **k),
    ]


def files_ui(kind, interps, layouts, presets=None, owners=True, base=None, script=True,
             dry_run=True):
    """What the page's files designer needs of a target (Target.describe -> files_ui)."""
    return {
        'kind': kind, 'owners': owners, 'modes': owners, 'base': base,
        'formats': [[k, v[0], v[1], v[2]] for k, v in FORMATS.items()],
        'vars': [['{name}', 'the certificate\'s name made safe'],
                 ['{cn}', 'its first name made safe'],
                 ['{service}', 'the service / container name'],
                 ['{date}', 'the day it starts: YYYYMMDD'],
                 ['{alt}', 'a dual certificate\'s twin: rsa or ec']],
        'layouts': layouts, 'presets': presets or [],
        'interps': [[i, INTERPS[i][0]] for i in interps],
        'script': script, 'dry_run': dry_run,
        'env': [list(x) for x in ENV_DOC] + ([['ACME_THUMBPRINT', 'the SHA-1 thumbprint '
                                               'of the certificate imported']]
                                             if kind == 'windows' else []),
        'snippets': SNIPPETS['windows' if kind == 'windows' else 'posix'],
        'script_max': SCRIPT_MAX,
    }


def layouts(folder, kind='posix'):
    """The quick layouts: one click fills the rows ({dir}: the folder chosen)."""
    d = '{dir}'
    key, cert = ('0600', '0644') if kind == 'posix' else ('', '')

    def ln(fmt, path, mode=''):
        return ' '.join(x for x in (fmt, path, mode) if x)
    out = [
        {'key': 'one', 'title': 'One PEM with everything', 'what': 'key + certificate + chain',
         'outputs': [ln('combined-pem', d + '/{name}.pem', key)]},
        {'key': 'separate', 'title': 'Separate files', 'what': 'certificate, chain, key',
         'outputs': [ln('cert-pem', d + '/{name}.crt', cert),
                     ln('chain-pem', d + '/{name}.chain.crt', cert),
                     ln('key-pem', d + '/{name}.key', key)]},
        {'key': 'fullchain', 'title': 'Full chain + key', 'what': 'as nginx wants it',
         'outputs': [ln('fullchain-pem', d + '/{name}.fullchain.crt', cert),
                     ln('key-pem', d + '/{name}.key', key)]},
        # The full chain where the server sends it from, the chain alone beside it for what checks
        # it (nginx's ssl_trusted_certificate for OCSP stapling, Apache's SSLCACertificateFile),
        # and the key (1.0.64).
        {'key': 'fullchain_chain', 'title': 'Full chain, chain, key',
         'what': 'nginx with OCSP stapling, Apache 2.4.8+',
         'outputs': [ln('fullchain-pem', d + '/{name}.crt', cert),
                     ln('chain-pem', d + '/{name}.ca', cert),
                     ln('key-pem', d + '/{name}.key', key)]},
        {'key': 'pfx', 'title': 'PKCS#12 with a password', 'what': 'one .pfx file',
         'outputs': [ln('pfx', d + '/{name}.pfx', key)], 'password': 'generate'},
        {'key': 'jks', 'title': 'Java keystore', 'what': 'one .jks file',
         'outputs': [ln('jks', d + '/{name}.jks', '0640' if kind == 'posix' else '')],
         'password': 'generate'},
        {'key': 'der', 'title': 'DER files', 'what': 'binary certificate and key',
         'outputs': [ln('cert-der', d + '/{name}.der', cert),
                     ln('key-der', d + '/{name}.key.der', key)]},
        {'key': 'windows', 'title': 'For Windows', 'what': 'PKCS#12 (3DES) any Windows imports',
         'outputs': [ln('p12-legacy', d + '/{name}.pfx', key)], 'password': 'generate'},
    ]
    for x in out:
        x['folder'] = folder
    return out


# ---------------------------------------------------------------------------
# The password, the script
# ---------------------------------------------------------------------------
def password_mode(options):
    m = text((options or {}).get('pfx_password_mode') or 'fixed').strip().lower()
    return m if m in ('fixed', 'none', 'generate') else 'fixed'


def password_of(options):
    """The password the PKCS#12 / keystore files are locked with, or None."""
    o = options or {}
    if password_mode(o) == 'none':
        return None
    return o.get('pfx_password') or None


def script_of(t, options, vars=None, interps=('bash', 'sh', 'python3')):
    """What runs after the files, or None. The deployment's own; where it says
    nothing (script_mode ''), the target's default."""
    o = options or {}
    mode = text(o.get('script_mode')).strip().lower()
    src, where = o, 'deployment'
    if mode in ('', 'inherit', 'default'):
        src, where = {k: t.config.get(k) for k in ('script_mode', 'script_path', 'script_args',
                                                    'script_body', 'script_interp')}, 'target'
        mode = text(src.get('script_mode')).strip().lower()
    if mode in ('', 'none', 'off'):
        return None
    if mode not in ('path', 'inline'):
        raise PluginError('"After the files" is nothing, a command on the machine or a '
                          'script written here - not "%s"' % mode, retry=False)
    vars = vars or {}
    sc = {'mode': mode, 'from': where, 'args': subst(text(src.get('script_args')).strip(), vars),
          'path': '', 'body': '', 'interp': ''}
    if re.search(r'[\x00-\x08\x0a-\x1f]', sc['args']):
        raise PluginError('the arguments of the script are one line', retry=False)
    if mode == 'path':
        p = subst(text(src.get('script_path')).strip(), vars)
        if not p:
            raise PluginError('"Command or script on the machine" is empty', retry=False)
        if not (p.startswith('/') or re.match(r'^[A-Za-z]:[\\/]', p)):
            raise PluginError('the script on the machine is named by its absolute path: %s' % p,
                              retry=False)
        if re.search(r'[\x00-\x1f\'"`$;&|<>]', p):
            raise PluginError('that path of a script is not allowed: %s' % p, retry=False)
        sc['path'] = p
    else:
        body = text(src.get('script_body'))
        if not body.strip():
            raise PluginError('the script written here is empty', retry=False)
        if len(body.encode('utf-8')) > SCRIPT_MAX:
            raise PluginError('the script is bigger than %d KiB' % (SCRIPT_MAX // 1024),
                              retry=False)
        interp = text(src.get('script_interp')).strip().lower() or interps[0]
        if interp not in interps:
            raise PluginError('the interpreter is one of %s' % ', '.join(interps), retry=False)
        sc['body'] = body.replace('\r\n', '\n')
        sc['interp'] = interp
    return sc


def check_body(v):
    """A script body as it may be saved (64 KiB at most) - ValueError otherwise."""
    if v in (None, ''):
        return
    if not isinstance(v, str):
        raise ValueError('the script is a piece of text')
    if len(v.encode('utf-8')) > SCRIPT_MAX:
        raise ValueError('the script is bigger than %d KiB' % (SCRIPT_MAX // 1024))
    if '\x00' in v:
        raise ValueError('the script holds a NUL character')


# ---------------------------------------------------------------------------
# The variables the script gets
# ---------------------------------------------------------------------------
def _iso(t):
    try:
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(t)))
    except (TypeError, ValueError):
        return ''


def file_vars(pairs, bundle):
    """{ACME_FILE_<FORMAT>[_ALT|_RSA|_EC][_2]: path} of [(output, bundle)]."""
    out = {}
    dual = alt_of(bundle) is not None

    def put(k, v):
        n, key = 1, k
        while key in out:
            n += 1
            key = '%s_%d' % (k, n)
        out[key] = v
    for o, b in pairs:
        base = 'ACME_FILE_' + o['format'].upper().replace('-', '_')
        v = o.get('variant') or ''
        if v:
            put(base + '_' + {'ec': 'EC', 'rsa': 'RSA', 'ed': 'ED'}.get(v, v.upper()), o['path'])
        else:
            put(base, o['path'])
        if dual:
            fam = family_of(b).upper()
            alias = base + '_' + fam
            if fam and alias not in out and (not v or v == 'alt'):
                out[alias] = o['path']
    return out


def env_for(t, bundle, pairs, vars, password=None, dry_run=False, extra=None):
    """The ACME_* variables, in the order ENV_DOC says them."""
    names = [text(n) for n in (getattr(bundle, 'names', None) or [])]
    alt = alt_of(bundle)
    env = {
        'ACME_CERT_NAME': text(getattr(bundle, 'name', '') or vars.get('name')),
        'ACME_CN': names[0] if names else text(getattr(bundle, 'name', '')),
        'ACME_NAMES': ' '.join(names),
        'ACME_NOT_AFTER': _iso(getattr(bundle, 'not_after', None)),
        'ACME_FINGERPRINT': _fp(bundle),
        'ACME_SERIAL': text(getattr(bundle, 'serial', '')).lower().replace(':', ''),
        'ACME_VERSION': text(getattr(bundle, 'version', '') or ''),
        'ACME_KEY_TYPE': text(getattr(bundle, 'key_type', '') or family_of(bundle)),
        'ACME_FILES': '\n'.join(o['path'] for o, _b in pairs),
    }
    if alt is not None:
        env['ACME_ALT_FINGERPRINT'] = _fp(alt)
        env['ACME_ALT_KEY_TYPE'] = text(getattr(alt, 'key_type', '') or family_of(alt))
    env.update(file_vars(pairs, bundle))
    if password and any(o['format'] in PFX_FORMATS for o, _b in pairs):
        env['ACME_PASSWORD'] = password
    env['ACME_SERVICE'] = text(vars.get('service') or '')
    ctx = getattr(t, 'ctx', None)
    env['ACME_TARGET'] = text(getattr(ctx, 'target_name', '') or t.c('host') or t.kind)
    env['ACME_HOST'] = text(t.c('host') or '')
    env['ACME_DRY_RUN'] = '1' if dry_run else '0'
    if getattr(ctx, 'deploy_id', None) not in (None, ''):
        env['ACME_DEPLOY_ID'] = text(ctx.deploy_id)
    env.update(extra or {})
    return env


def _fp(b):
    try:
        return fp_of(b) if (getattr(b, 'cert_pem', '') or getattr(b, 'fingerprint', '')) else ''
    except Exception:                                   # noqa: BLE001
        return text(getattr(b, 'fingerprint', '') or '')


def env_file(env):
    """The variables as sh reads them (". file"), each quoted."""
    return ''.join('export %s=%s\n' % (k, quote(text(v))) for k, v in env.items()
                   if re.match(r'^[A-Z][A-Z0-9_]*\Z', k)).encode('utf-8')


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------
def said_of(out, err):
    words = (text(out).rstrip() + ('\n' + text(err).rstrip() if text(err).strip() else '')).strip()
    if len(words) > OUTPUT_MOST:
        words = '…' + words[-OUTPUT_MOST:]
    return words


def tell(t, sc, rc, out, err, dry_run=False):
    """What the script said, into the job; -> its words."""
    what = _what(sc)
    words = said_of(out, err)
    if words:
        # what it printed, a step of its own (shown as it was said, never translated)
        t.ctx.step('%s said:' % what, 'info' if rc == 0 else 'bad')
        t.ctx.step(words if '\n' in words else words + '\n', 'info' if rc == 0 else 'bad')
    t.ctx.step('%s: %s' % (what, 'done' if rc == 0 else 'failed (exit %s)' % rc),
               'ok' if rc == 0 else 'bad')
    return words


def _what(sc):
    if sc['mode'] == 'path':
        return 'the script %s' % sc['path']
    return 'the script written here (%s%s)' % (sc['interp'], ', the target\'s default'
                                               if sc.get('from') == 'target' else '')


def run_posix(t, s, sc, env, tmp_dir='/tmp', timeout=600):
    """The script uploaded beside its variables, run through t.sh (sudo when the
    target says so), both deleted -> (rc, out, err)."""
    tmp_dir = (tmp_dir or '/tmp').rstrip('/') or '/tmp'
    token = secrets.token_hex(6)
    envf = '%s/.acme-env-%s' % (tmp_dir, token)
    body = None
    s.put(env_file(env), envf, 0o600)
    try:
        if sc['mode'] == 'inline':
            body = '%s/.acme-script-%s%s' % (tmp_dir, token, INTERPS[sc['interp']][2])
            s.put(sc['body'].encode('utf-8'), body, 0o600)
            cmd = '%s %s' % (INTERPS[sc['interp']][1], quote(body))
        else:
            cmd = quote(sc['path'])
        if sc['args']:
            cmd += ' ' + sc['args']
        script = ['set -a; . %s; set +a; rm -f %s' % (quote(envf), quote(envf))]
        if body:
            script.append('chmod 700 %s' % quote(body))
        script += ['cd %s 2>/dev/null || cd /' % quote(tmp_dir), cmd]
        return t.sh(s, '\n'.join(script), check=False, timeout=timeout)
    finally:
        try:
            t.sh(s, 'rm -f %s' % ' '.join(quote(x) for x in (envf, body) if x), check=False)
        except Exception:                               # noqa: BLE001
            pass


def ps_str(s):
    # PowerShell ends a quoted string at the curly quotes too (1.0.45): each doubled.
    t = text(s)
    for q in ("'", '\u2018', '\u2019', '\u201a', '\u201b'):
        t = t.replace(q, q + q)
    return "'" + t + "'"


def run_windows(t, s, sc, env, tmp_dir='C:/Windows/Temp', timeout=600):
    """The same on Windows: a .ps1 (or the script named) run by a child
    powershell with the variables set from a JSON file deleted first."""
    tmp_dir = (tmp_dir or 'C:/Windows/Temp').rstrip('/\\')
    token = secrets.token_hex(6)
    envf = '%s/acme-env-%s.json' % (tmp_dir, token)
    put_scp(s, json.dumps(env).encode('utf-8'), envf)
    body = None
    try:
        args = ' '.join(ps_str(a) for a in shlex.split(sc['args'])) if sc['args'] else ''
        if sc['mode'] == 'inline':
            body = '%s/acme-script-%s.ps1' % (tmp_dir, token)
            put_scp(s, b'\xef\xbb\xbf' + sc['body'].encode('utf-8'), body)
            run = ('& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %s %s'
                   % (ps_str(body), args))
        elif sc['path'].lower().endswith('.ps1'):
            run = ('& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %s %s'
                   % (ps_str(sc['path']), args))
        else:
            run = '& %s %s' % (ps_str(sc['path']), args)
        script = '\n'.join([
            '$e = Get-Content -Raw -LiteralPath %s | ConvertFrom-Json' % ps_str(envf),
            'Remove-Item -LiteralPath %s -Force' % ps_str(envf),
            'foreach ($p in $e.PSObject.Properties) { Set-Item -LiteralPath ("env:" + $p.Name) '
            '-Value ([string]$p.Value) }',
            'Set-Location -LiteralPath %s' % ps_str(tmp_dir),
            '$global:LASTEXITCODE = 0',
            run.strip(),
            'exit $LASTEXITCODE',
        ])
        return t.run_ps(s, script, 'the script', check=False, timeout=timeout)
    finally:
        try:
            t.run_ps(s, '; '.join('Remove-Item -LiteralPath %s -Force -ErrorAction '
                                  'SilentlyContinue' % ps_str(x) for x in (envf, body) if x),
                     'cleaning up', check=False)
        except Exception:                               # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# What a deployment would do, in words (the page's live preview)
# ---------------------------------------------------------------------------
_EST = {'ec': (800, 240), 'rsa': (1500, 1700), 'ed': (700, 120)}


def size_of(b, fmt, password=None):
    """The size of a file of this format, in bytes - made where that is cheap,
    else guessed from the PEM ones."""
    try:
        if fmt in ('cert-pem', 'fullchain-pem', 'chain-pem', 'key-pem', 'combined-pem',
                   'cert-der', 'key-der', 'key-rsa'):
            data = b.as_format(fmt)
            return len(data if isinstance(data, (bytes, bytearray)) else text(data).encode()), True
    except Exception:                                   # noqa: BLE001
        pass
    cert = len(text(getattr(b, 'cert_pem', '')))
    chain = sum(len(text(c)) for c in (getattr(b, 'chain_pems', None) or []))
    key = len(text(getattr(b, 'key_pem', '') or ''))
    if not cert:
        c, k = _EST.get(family_of(b), _EST['ec'])
        cert, chain, key = int(c * 1.37), int(c * 1.37) * 1, int(k * 1.37) + 60
    der = lambda n: int(n * 0.73)                       # noqa: E731
    guess = {'cert-pem': cert, 'fullchain-pem': cert + chain, 'chain-pem': chain,
             'key-pem': key, 'key-rsa': key, 'combined-pem': key + cert + chain,
             'cert-der': der(cert), 'key-der': der(key), 'p7b': der(cert + chain) + 60,
             'pfx': der(cert + chain + key) + 380, 'p12': der(cert + chain + key) + 380,
             'p12-legacy': der(cert + chain + key) + 300,
             'jks': der(cert + chain + key) + 120}.get(fmt, cert)
    return guess, False


def preview(t, bundle, options, pairs, vars, problems, base=None, owners=True,
            interps=('bash', 'sh', 'python3'), script_ok=None, windows=False):
    """{files, env, problems, script, password, vars} for the page."""
    o = options or {}
    files = []
    pw_mode = password_mode(o)
    pw_set = bool(o.get('pfx_password'))
    any_pfx = False
    for out, b in pairs:
        fmt = out['format']
        title, what, has_key, binary = FORMATS.get(fmt, (fmt, '', False, False))
        size, exact = size_of(b, fmt)
        one = {'path': out['path'], 'format': fmt, 'title': title, 'what': what,
               'variant': out.get('variant') or '', 'family': family_of(b),
               'mode': ('%04o' % out['mode']) if not windows else '',
               'owner': (out.get('owner') or '') if owners and not windows else '',
               'size': size, 'exact': exact, 'key': has_key, 'binary': binary}
        if base:
            one['full'] = base.rstrip('/') + '/' + out['path'].lstrip('/')
        if has_key and not windows and out['mode'] & 0o004:
            problems.append({'level': 'warn', 'words': '%s holds the private key and anybody on '
                             'the machine may read it (%04o) - 0600 or 0640'
                             % (out['path'], out['mode'])})
        if fmt in PFX_FORMATS:
            any_pfx = True
            if fmt == 'jks' and (pw_mode == 'none' or (pw_mode == 'fixed' and not pw_set)):
                problems.append({'level': 'bad', 'words': '%s: a Java keystore needs a password '
                                 '(6 characters or more)' % out['path']})
            elif pw_mode == 'none' or (pw_mode == 'fixed' and not pw_set):
                problems.append({'level': 'warn', 'words': '%s has no password: whoever can read '
                                 'the file has the key' % out['path']})
        if re.search(r'\{[a-z_]+\}', out['path']):
            problems.append({'level': 'bad', 'words': '%s: %s is not a placeholder there is' % (
                out['path'], re.search(r'\{[a-z_]+\}', out['path']).group(0))})
        if out['path'].endswith(('/', '\\')):
            problems.append({'level': 'bad', 'words': '%s is a folder: give the file a name'
                             % out['path']})
        files.append(one)
    if not files and not any(p['level'] == 'bad' for p in problems):
        problems.append({'level': 'info', 'words': 'no files are written'})
    try:
        sc = script_of(t, o, vars, interps)
    except PluginError as e:
        sc = None
        problems.append({'level': 'bad', 'words': str(e)})
    if sc is not None and script_ok is not None:
        why = script_ok(sc)
        if why:
            problems.append({'level': 'bad', 'words': why})
    pw = password_of(o) if any_pfx else None
    env = env_for(t, bundle, pairs, vars, password=pw or ('x' if any_pfx and pw_mode == 'generate'
                                                          else None))
    if 'ACME_PASSWORD' in env:
        env['ACME_PASSWORD'] = '\u2022' * 8
    script = None
    if sc is not None:
        script = {'mode': sc['mode'], 'from': sc['from'], 'path': sc['path'],
                  'args': sc['args'], 'interp': sc['interp'],
                  'lines': sc['body'].count('\n') + 1 if sc['body'] else 0,
                  'bytes': len(sc['body'].encode('utf-8')) if sc['body'] else 0}
    return {'files': files, 'env': env, 'problems': problems, 'script': script,
            'password': {'mode': pw_mode, 'set': pw_set, 'needed': any_pfx},
            'vars': {k: text(v) for k, v in vars.items() if k != 'host'},
            'dual': alt_of(bundle) is not None,
            'variants': [family_of(b) for b in variants_of(bundle)]}

