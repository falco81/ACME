# -*- coding: utf-8 -*-
"""
Discovery through a target's agent (1.0.125, docs/target-agent.md "Discovery"): what services of
the server use certificates, where their files are, which certificate each serves now - read by
the agent (op `discover`), only where its policy says `allow discover` (every kind) or
`allow discover KIND,KIND`. Read-only on the server, bounded, never a secret: of a certificate
found only its subject, names, issuer, the end, thumbprint and serial; of a key file only that it
is there, its owner and mode.

acme makes of it what its pages offer (agents.js "Found on this server", the policy designer's
"From discovery"): for each service found the deployment that would put a certificate of acme
there (the deployment dialog prefilled: the preset, the files with their paths, owners and modes,
the reload; on Windows the machine store, the IIS bindings, the listener, the role), the lines of
the policy that deployment needs, a test of what it serves - and which of the certificates found
acme manages.

The functions others call (the API, the command line, the console, the teams portal):

    run(store, row, kinds=None, by='')  a signed `discover` job to the agent of target `row`;
                                        its answer kept (meta agents:discover:<target id>) ->
                                        view
    cached(store, row)                  the last answer kept, as a view (None: never asked)
    view(store, row, got)               an answer (or a kept one) as the pages take it: each
                                        service with `prefill`, `items`, `watch`, `managed`
    allowed_kinds(policy, platform)     the kinds the agent's policy (as it last said it)
                                        allows; [] - none
    allow_line(kinds)                   the policy line that allows those kinds
    prefill(finding, platform)          the options of a deployment of that service
    items(finding, platform)            what that deployment needs of the policy (the builder's
                                        items, each with its line)
    forget(store, row)                  the kept answer taken away (the target deleted)

A team's portal (docs/teams.md) calls run() / cached() for a target of the team and keeps of the
view only the kinds its caps allow (`kinds=`).
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import ssl
import time

from acmelib.plugins.base import PluginError

KINDS_LINUX = ('nginx', 'apache', 'haproxy', 'postfix', 'dovecot', 'exim', 'tomcat', 'proxmox',
               'pbs', 'openldap', 'grafana', 'cockpit', 'webmin', 'vsftpd', 'mariadb', 'files')
KINDS_WINDOWS = ('store', 'iis', 'rdp', 'sql', 'exchange', 'adfs', 'wap', 'winrm', 'ldaps',
                 'sstp', 'ftp', 'ccs', 'rdgw', 'rds', 'sharepoint', 'wac', 'lync')
KIND_TITLES = {
    'nginx': 'nginx', 'apache': 'Apache httpd', 'haproxy': 'HAProxy', 'postfix': 'Postfix',
    'dovecot': 'Dovecot', 'exim': 'Exim', 'tomcat': 'Tomcat', 'proxmox': 'Proxmox VE',
    'pbs': 'Proxmox Backup Server', 'openldap': 'OpenLDAP', 'grafana': 'Grafana',
    'cockpit': 'Cockpit', 'webmin': 'Webmin', 'vsftpd': 'vsftpd', 'mariadb': 'MySQL / MariaDB',
    'files': 'Certificate files', 'store': 'Machine store', 'iis': 'IIS sites',
    'rdp': 'Remote Desktop', 'sql': 'SQL Server', 'exchange': 'Exchange', 'adfs': 'AD FS',
    'wap': 'Web Application Proxy', 'winrm': 'WinRM HTTPS', 'ldaps': 'LDAPS', 'sstp': 'SSTP VPN',
    'ftp': 'IIS FTP', 'ccs': 'IIS Central Certificate Store', 'rdgw': 'RD Gateway',
    'rds': 'Remote Desktop Services', 'sharepoint': 'SharePoint', 'wac': 'Windows Admin Center',
    'lync': 'Skype for Business'}
ROLES_WIN = ('sql', 'exchange', 'adfs', 'wap', 'winrm', 'ldaps', 'sstp', 'ftp', 'ccs', 'rdgw',
             'rds', 'sharepoint', 'wac', 'lync')
FORMATS = ('cert-pem', 'fullchain-pem', 'chain-pem', 'key-pem', 'combined-pem', 'jks', 'pfx')
ROLES = ('cert', 'key', 'chain', 'combined', 'keystore')
# the test of what a service serves (the check modules, family 'check'): kind -> (check, port)
WATCH = {'postfix': ('smtp', 25), 'exim': ('smtp', 25), 'mariadb': ('mysql', 3306),
         'vsftpd': ('ftp', 21), 'ftp': ('ftp', 21), 'rdp': ('rdp', 3389), 'sql': ('mssql', 1433)}
KEPT_MOST = 1024 * 1024
TIMEOUT = 180


def M_DISC(tid):
    return 'agents:discover:%d' % int(tid)


def _G():
    from acmelib.certs import agents
    return agents


def _txt(v, most=300):
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]', '', str(v if v is not None else ''))[:most]


def _num(v, lo=0, hi=2 ** 40):
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if f == f and lo <= f <= hi else None


def known_kinds(platform):
    return KINDS_WINDOWS if platform == 'windows' else KINDS_LINUX


def allowed_kinds(policy, platform):
    """The kinds the policy (as the agent last said it) lets acme discover - [] none."""
    have = (policy or {}).get('discover') or []
    k = known_kinds(platform)
    return list(k) if '*' in have else [x for x in k if x in have]


def allow_line(kinds=None):
    """`acme-agent allow discover[ KIND,KIND]` - the line the agent takes (its own order)."""
    kinds = [k for k in (kinds or []) if k != '*']
    return 'acme-agent allow discover' + (' %s' % ','.join(kinds) if kinds else '')


# ---- the agent's answer, its shape checked -------------------------------------------------
def _clean_cert(c):
    if not isinstance(c, dict):
        return None
    t = re.sub(r'[^0-9A-Fa-f]', '', str(c.get('thumbprint') or '')).upper()
    out = {'thumbprint': t if len(t) == 40 else '', 'subject': _txt(c.get('subject')),
           'issuer': _txt(c.get('issuer')), 'cn': _txt(c.get('cn'), 253),
           'serial': re.sub(r'[^0-9A-Fa-f]', '', str(c.get('serial') or '')).upper()[:80],
           'not_after': _num(c.get('not_after')),
           'sans': [_txt(x, 253) for x in (c.get('sans') or [])[:40] if isinstance(x, str)]
           if isinstance(c.get('sans'), list) else []}
    for k in ('has_key', 'acme', 'missing'):
        if c.get(k):
            out[k] = True
    if c.get('friendly'):
        out['friendly'] = _txt(c.get('friendly'), 120)
    if isinstance(c.get('where'), list):
        out['where'] = [_txt(x, 300) for x in c['where'][:12] if isinstance(x, str)]
    if not out['thumbprint'] and not out['subject']:
        return None
    return out


def _words(v, most=40, n=253):
    return [_txt(x, n) for x in v[:most] if isinstance(x, (str, int))] \
        if isinstance(v, list) else []


def clean(d):
    """What an agent says of its discovery (op discover) - every value of its shape, cut to size;
    a text that holds a private key is never kept (no agent of acme sends one)."""
    if not isinstance(d, dict):
        return {}
    kinds = set(KINDS_LINUX) | set(KINDS_WINDOWS)
    out = {'platform': 'windows' if d.get('platform') == 'windows' else 'linux',
           'kinds': [k for k in _words(d.get('kinds')) if k in kinds],
           'at': _num(d.get('at')), 'ms': _num(d.get('ms'), 0, 86400000),
           'found': [], 'certs': [], 'skipped': [], 'truncated': bool(d.get('truncated'))}
    for f in (d.get('found') or [])[:200] if isinstance(d.get('found'), list) else []:
        if not isinstance(f, dict) or f.get('kind') not in kinds:
            continue
        one = {'kind': f['kind'], 'title': _txt(f.get('title'), 120),
               'preset': _txt(f.get('preset'), 40), 'config': _txt(f.get('config'), 1024),
               'unit': _txt(f.get('unit'), 128), 'names': _words(f.get('names')),
               'listen': _words(f.get('listen'), 20, 80), 'cert': _clean_cert(f.get('cert')),
               'port': int(_num(f.get('port'), 0, 65535) or 0), 'files': []}
        for k, n in (('reload', 600), ('test', 600), ('note', 400), ('section', 120),
                     ('site', 256), ('state', 20), ('detail', 200), ('ccs_path', 260),
                     ('dir', 1024)):
            if f.get(k):
                one[k] = _txt(f[k], n)
        for x in (f.get('files') or [])[:12] if isinstance(f.get('files'), list) else []:
            if not isinstance(x, dict) or x.get('role') not in ROLES or \
                    x.get('format') not in FORMATS:
                continue
            fx = {'role': x['role'], 'format': x['format'], 'path': _txt(x.get('path'), 1024),
                  'there': bool(x.get('there'))}
            if x.get('dynamic'):
                fx['dynamic'] = True
            if re.fullmatch(r'0[0-7]{3}', str(x.get('mode') or '')):
                fx['mode'] = x['mode']
            for k in ('owner', 'group'):
                if x.get(k):
                    fx[k] = _txt(x[k], 32)
            if fx['path']:
                one['files'].append(fx)
        if isinstance(f.get('bindings'), list):
            one['bindings'] = []
            for b in f['bindings'][:16]:
                if isinstance(b, dict):
                    t = re.sub(r'[^0-9A-F]', '', str(b.get('thumb') or '').upper())
                    one['bindings'].append({'site': _txt(b.get('site'), 256),
                                            'host': _txt(b.get('host'), 253),
                                            'port': int(_num(b.get('port'), 0, 65535) or 0),
                                            'ip': _txt(b.get('ip'), 60),
                                            'thumb': t if len(t) == 40 else '',
                                            'sni': bool(b.get('sni'))})
        if isinstance(f.get('instances'), list):
            one['instances'] = [{'name': _txt(i.get('name'), 120),
                                 'thumb': _txt(i.get('thumb'), 40)}
                                for i in f['instances'][:16] if isinstance(i, dict)]
        if isinstance(f.get('listeners'), list):
            one['listeners'] = [{'host': _txt(i.get('host'), 253), 'port': _txt(i.get('port'), 8),
                                 'thumb': _txt(i.get('thumb'), 40)}
                                for i in f['listeners'][:8] if isinstance(i, dict)]
        if f.get('default_cert'):
            one['default_cert'] = _clean_cert(f.get('default_cert'))
        out['found'].append(one)
    for c in (d.get('certs') or [])[:300] if isinstance(d.get('certs'), list) else []:
        c = _clean_cert(c)
        if c:
            out['certs'].append(c)
    for s in (d.get('skipped') or [])[:40] if isinstance(d.get('skipped'), list) else []:
        if isinstance(s, dict):
            out['skipped'].append({'kind': _txt(s.get('kind'), 40), 'why': _txt(s.get('why'))})
    raw = json.dumps(out)
    if 'PRIVATE KEY' in raw:
        raise PluginError('the agent\'s answer holds a private key - not taken', retry=False)
    return out


# ---- what acme makes of it -----------------------------------------------------------------------
def _thumb_of_pem(pem):
    try:
        text = pem.decode('utf-8', 'replace') if isinstance(pem, bytes) else str(pem or '')
        m = re.search(r'-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----', text)
        if not m:
            return ''
        return hashlib.sha1(ssl.PEM_cert_to_DER_cert(m.group(0))).hexdigest().upper()
    except (ValueError, TypeError):
        return ''


def managed_map(store):
    """thumbprint -> {id, name, current} of every certificate acme holds (each version)."""
    out = {}
    try:
        rows = store.db.rows('SELECT id, name, cert_pem, alt_cert_pem FROM certs')[:5000]
        names = {}
        for r in rows:
            names[r['id']] = r['name']
            for k in ('cert_pem', 'alt_cert_pem'):
                t = _thumb_of_pem(r.get(k))
                if t:
                    out[t] = {'id': r['id'], 'name': r['name'], 'current': True}
        for v in store.db.rows('SELECT cert_id, cert_pem FROM cert_versions ORDER BY id DESC')[
                :20000]:
            t = _thumb_of_pem(v.get('cert_pem'))
            if t and t not in out and v.get('cert_id') in names:
                out[t] = {'id': v['cert_id'], 'name': names[v['cert_id']], 'current': False}
    except Exception:                                   # noqa: BLE001
        pass
    return out


def _preset(key):
    from acmelib.plugins.targets import ssh as SSH
    return SSH.PRESETS.get(key) or {}


def _preset_defaults(key):
    """format -> (mode, owner) of the preset's files."""
    out = {}
    for line in _preset(key).get('outputs') or []:
        w = line.split()
        if len(w) >= 3:
            out.setdefault(w[0], (w[2], w[3] if len(w) > 3 else 'root:root'))
    return out


def _unit_base(f):
    u = str(f.get('unit') or '')
    return u[:-len('.service')] if u.endswith('.service') else u


def prefill(f, platform):
    """The options of a deployment that puts a certificate of acme where the service found takes
    it (the deployment dialog's fields) - {} when there is nothing to fill."""
    if platform == 'windows':
        k = f.get('kind')
        if k == 'iis':
            lines = []
            for b in f.get('bindings') or []:
                ip = b.get('ip') or ''
                more = (' | %s' % ip) if ip and ip not in ('*', '') else ''
                lines.append('%s | %s | %d%s' % (b.get('site') or f.get('site'),
                                                 b.get('host') or '', int(b.get('port') or 443),
                                                 more))
            return {'store': True, 'iis': lines, 'rdp': False}
        if k == 'rdp':
            return {'store': True, 'rdp': True}
        if k in ROLES_WIN:
            o = {'store': True, 'role_%s' % k: True}
            if k == 'sql' and f.get('instances'):
                o['sql_instance'] = f['instances'][0]['name'] or 'MSSQLSERVER'
            if k == 'ccs' and f.get('ccs_path'):
                o['ccs_path'] = f['ccs_path']
            return o
        return {}
    files = [x for x in f.get('files') or [] if x.get('path') and not x.get('dynamic')]
    if not files:
        return {}
    preset = f.get('preset') if _preset(f.get('preset') or '') else 'custom'
    dflt = _preset_defaults(preset)
    outs = []
    for x in files:
        fmt = x['format']
        mode, owner = dflt.get(fmt, ('0600' if fmt in ('key-pem', 'combined-pem', 'jks', 'pfx')
                                     else '0644', 'root:root'))
        if x.get('there') and x.get('mode'):
            mode = '%04o' % (int(x['mode'], 8) & 0o666)
            owner = '%s:%s' % (x.get('owner') or 'root', x.get('group') or x.get('owner') or
                               'root')
        outs.append('%s %s %s %s' % (fmt, x['path'], mode, owner))
    o = {'preset': preset, 'outputs': outs}
    if f.get('test'):
        o['test_cmd'] = [f['test']]
    if f.get('reload'):
        o['reload_cmd'] = [f['reload']]
    if _unit_base(f):
        o['service'] = _unit_base(f)
    return o


def items(f, platform):
    """What a deployment of that service needs of the agent's policy - the builder's items
    ({kind, ...}), each with the line that allows it."""
    out = []
    if platform == 'windows':
        wc = _G().wincert_mod()
        k = f.get('kind')
        if k in ('iis', 'rdp') or k in ROLES_WIN:
            out.append({'kind': 'store', 'allow': 'acme-agent allow store'})
        if k == 'iis' and f.get('site'):
            out.append({'kind': 'iis', 'site': f['site'], 'allow': wc.allow_iis_words(f['site'])})
        elif k == 'rdp':
            out.append({'kind': 'rdp', 'allow': 'acme-agent allow rdp'})
        elif k in ROLES_WIN:
            extra = f.get('ccs_path') if k == 'ccs' else None
            if k != 'ccs' or extra:
                out.append({'kind': 'role', 'role': k, 'extra': extra or '',
                            'allow': wc.allow_role_words(k, extra)})
        return out
    from acmelib.plugins.targets import agent as AT
    o = prefill(f, platform)
    for line in o.get('outputs') or []:
        fmt, path, mode, owner = line.split(' ', 3)
        u, _, g = owner.partition(':')
        d = path.rsplit('/', 1)[0] or '/'
        out.append({'kind': 'file', 'path': path, 'mode': int(mode, 8), 'owner': u,
                    'group': g or u, 'allow': 'acme-agent allow file %s --owner %s --mode %s'
                    % (shlex.quote(d), owner, mode)})
    for key, step in (('test_cmd', 'test'), ('reload_cmd', 'reload')):
        for line in o.get(key) or []:
            try:
                ops = AT.cmd_ops(line)
            except PluginError:
                continue
            for op in ops:
                a = op['any'][0] if 'any' in op and op['any'] else op
                if 'unit' in a:
                    u = a['unit'] if '.' in a['unit'] else a['unit'] + '.service'
                    out.append({'kind': 'unit', 'unit': u, 'verb': a['verb'], 'step': step,
                                'allow': AT._allow_of(a)})
                elif 'argv' in a:
                    out.append({'kind': 'test', 'argv': a['argv'], 'step': step,
                                'allow': AT._allow_of(a)})
    return out


def watch_of(f, host):
    """A test of what the service serves: {kind (a check module), host, port, sni}."""
    k = f.get('kind')
    if k in ('files', 'store'):
        return None
    check, port = WATCH.get(k, ('tls', int(f.get('port') or 0) or 443))
    if k == 'iis' and f.get('bindings'):
        port = int(f['bindings'][0].get('port') or 443)
    for x in f.get('listen') or []:
        m = re.search(r'(?:^|:)(\d{2,5})(?:\s|$)', str(x))
        if m and k in ('nginx', 'apache', 'haproxy', 'webmin', 'tomcat'):
            port = int(m.group(1))
            break
    names = list(f.get('names') or []) or list((f.get('cert') or {}).get('sans') or [])
    sni = next((n for n in names if n and '*' not in n and '$' not in n), '')
    return {'kind': check, 'host': host or '', 'port': port, 'sni': sni}


def view(store, row, got, by=''):
    """A discovery (as kept) for the pages: each service with what acme makes of it."""
    G = _G()
    platform = got.get('platform') or G.platform_of(store, row)
    conf = G.target_conf(row)
    st = G.state(store, row['id'])
    host = str(conf.get('host') or st.get('host') or '')
    mm = managed_map(store)
    now = time.time()
    out = {'target': row['name'], 'platform': platform, 'at': got.get('at'),
           'by': got.get('by') or by, 'kinds': got.get('kinds') or [],
           'skipped': got.get('skipped') or [], 'truncated': bool(got.get('truncated')),
           'found': [], 'certs': [], 'host': host}

    def mark(c):
        if not c:
            return c
        c = dict(c)
        m = mm.get(c.get('thumbprint') or '')
        if m:
            c['managed'] = m
        if c.get('not_after'):
            c['days'] = int((c['not_after'] - now) // 86400)
        return c
    for i, f in enumerate(got.get('found') or []):
        f = dict(f)
        f['id'] = '%s-%d' % (f['kind'], i)
        f['cert'] = mark(f.get('cert'))
        f['prefill'] = prefill(f, platform)
        f['items'] = items(f, platform)
        f['watch'] = watch_of(f, host)
        f['kind_title'] = KIND_TITLES.get(f['kind'], f['kind'])
        out['found'].append(f)
    for c in got.get('certs') or []:
        c = mark(c)
        if not c.get('managed') and not c.get('acme'):
            # where it is served: the test of the first service that uses it
            for f in out['found']:
                if (f.get('cert') or {}).get('thumbprint') == c.get('thumbprint') and f['watch']:
                    c['watch'] = f['watch']
                    break
        out['certs'].append(c)
    out['unmanaged'] = len([c for c in out['certs'] if not c.get('managed') and
                            not c.get('acme')])
    return out


def _keep(store, row, got, by):
    k = dict(got, by=_txt(by, 120))
    raw = json.dumps(k, sort_keys=True)
    if len(raw) <= KEPT_MOST:
        store.set_meta(M_DISC(row['id']), raw)


def cached(store, row):
    """The last discovery kept for the target, as a view - None when it was never asked."""
    try:
        got = json.loads(store.get_meta(M_DISC(row['id'])) or 'null')
    except (TypeError, ValueError):
        got = None
    if not isinstance(got, dict):
        return None
    return view(store, row, got)


def forget(store, row):
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', (M_DISC(row['id']),))
    except Exception:                                   # noqa: BLE001
        pass


def run(store, row, kinds=None, by=''):
    """A discovery through the agent of `row` (a signed job, read-only on the server) -> the
    view; the agent's refusal (its policy) -> {refused, said, needs, allow} with the line that
    allows it. Kept for the target with its time."""
    G = _G()
    platform = G.platform_of(store, row)
    known = known_kinds(platform)
    if isinstance(kinds, str):
        kinds = [k.strip() for k in kinds.split(',') if k.strip()]
    kinds = list(kinds or [])
    bad = [k for k in kinds if k not in known]
    if bad:
        raise ValueError('%s is not a kind discovered on %s (%s)' % (
            bad[0], 'Windows' if platform == 'windows' else 'Linux', ', '.join(known)))
    got = G.call(store, row, 'discover', {'kinds': kinds} if kinds else {}, timeout=TIMEOUT)
    if not got.get('ok'):
        said = got.get('said') or 'the agent refused'
        needs = got.get('needs') or []
        if 'not an operation of this agent' in said:
            said = 'the agent on %s is older than discovery (acme 1.0.125) - update it' % (
                row['name'])
        out = {'target': row['name'], 'platform': platform, 'refused': True, 'said': said,
               'needs': needs, 'found': [], 'certs': []}
        out['allow'] = next((n.get('allow') for n in needs if n.get('kind') == 'discover'), '') \
            or (allow_line(kinds) if 'policy' in said else '')
        return out
    d = got.get('discover') or {}
    if not d:
        raise PluginError('the agent answered no discovery', retry=False)
    d['at'] = d.get('at') or time.time()
    _keep(store, row, d, by)
    store.add_event('certificates', 'a discovery on the server of target %s by %s: %s' % (
        row['name'], by or 'acme', got.get('said') or ''), who=by or None)
    out = view(store, row, dict(d, by=by), by)
    out['said'] = got.get('said') or ''
    return out


def lines(v):
    """A view as the command line prints it."""
    out = []
    for f in v.get('found') or []:
        c = f.get('cert') or {}
        head = '%-10s %s' % (f['kind'], f.get('site') or f.get('config') or '')
        if f.get('unit'):
            head += '  (%s)' % f['unit']
        out.append(head)
        if f.get('names'):
            out.append('    names     %s' % ', '.join(f['names'][:8]))
        for x in f.get('files') or []:
            out.append('    %-9s %s %s%s' % (x['role'], x['path'], x.get('mode') or '',
                                             '' if x.get('there') else '  (not there)'))
        for b in f.get('bindings') or []:
            out.append('    binding   %s:%s %s' % (b.get('ip') or '*', b.get('port'),
                                                   b.get('host') or ''))
        if c:
            out.append('    serves    %s - %s%s%s' % (
                c.get('cn') or c.get('subject') or c.get('thumbprint'), c.get('issuer') or '?',
                (', %d days left' % c['days']) if c.get('days') is not None else '',
                (', acme: %s' % c['managed']['name']) if c.get('managed') else ''))
        if f.get('reload'):
            out.append('    reload    %s' % f['reload'])
        for it in f.get('items') or []:
            out.append('    -> %s' % it['allow'])
    for s in v.get('skipped') or []:
        out.append('! %s: %s' % (s.get('kind'), s.get('why')))
    return out
