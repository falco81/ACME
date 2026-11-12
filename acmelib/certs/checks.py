# -*- coding: utf-8 -*-
"""
Tests of what the servers really serve (1.0.32). A test is defined as a target is
(Certificates → Tests, table cert_tests: a module of acmelib/plugins/checks and its
settings) and attached to certificates (cert_checks: certificate × test, with how it
went last). Run, it connects as a client of its protocol would - HTTPS, SMTP with
STARTTLS, RDP... - to the address set (empty: the certificate's first name) and gives
back the chain the server sent; here it is compared with the certificate:

    ok           the current version (main or its twin), its names hold the name
                 checked, the chain sent with it
    old          an older version of the same certificate - the renewal did not
                 reach the server (a service not restarted, another node)
    other        a certificate acme did not issue for it
    answer       HTTPS asked over HTTP: the status or the words not as set
    unreachable  no connection, no STARTTLS, no TLS
    warn         the right one, but: it ends within certs_checks_warn_days, the
                 name checked is not in it, the intermediates are missing, or it is
                 not trusted here (failing only with require_trusted)

A connector (checks/ssh_relay.py) signs in over SSH to a Linux server and runs the
tests it carries from there. Run after the certificate's deployments
(certs_checks_after_deploy - a few tries, the services may still be restarting), by
themselves every certs_checks_every_min on the node that leads (certs_checks_auto),
or asked. A test that starts failing is an event and a notification
(cert_check_failed, certs_checks_alert); one that works again too (cert_check_ok).
"""
from __future__ import annotations

import json
import ssl
import re
import time
import urllib.parse

from acmelib import engine as E
from acmelib.certs import pki
from acmelib.certs import store as S
from acmelib.plugins.base import PluginError

STATES = ('ok', 'warn', 'old', 'other', 'answer', 'unreachable')
BAD = ('old', 'other', 'answer', 'unreachable')
AFTER_DEPLOY_TRIES = (3, 10, 20)        # seconds waited before each try after a deployment
NOTIFY_EVERY = 6 * 3600


# ---------------------------------------------------------------------------
# The rows: a test attached to a certificate
# ---------------------------------------------------------------------------
def row_public(store, r):
    d = dict(r)
    d['last_detail'] = S.jload(r.get('last_detail'), {}) or {}
    # its names too (1.0.78): a test without "Connect to" said "its first name:443"
    cert = store.db.row('SELECT id, name, names FROM certs WHERE id = ?', (r['cert_id'],))
    d['cert'] = cert['name'] if cert else '?'
    trow = S.plugin_row(store, 'check', r['test'])
    cls = S.row_class('check', trow) if trow else None
    d['kind'] = trow['kind'] if trow else ''
    d['title'] = (cls.title or cls.kind) if cls else (trow or {}).get('kind') or '?'
    d['protocol'] = getattr(cls, 'protocol', '') if cls else ''
    d['test_missing'] = trow is None
    d['test_enabled'] = bool(trow.get('enabled', 1)) if trow else False
    d['where'] = label(trow, cert) if trow else r['test']
    return d


def runnable(store, ids):
    """Of these tests of certificates, those that may run: switched on here, as a test, and
    their certificate on (1.0.77: Run the tests ran every one, as the tests by themselves
    never did)."""
    if not ids:
        return []
    ok = set()
    for at in range(0, len(ids), 500):
        part = list(ids)[at:at + 500]
        ok |= {r['id'] for r in store.db.rows(
            'SELECT c.id FROM cert_checks c LEFT JOIN cert_tests t ON t.name = c.test JOIN certs x '
            'ON x.id = c.cert_id WHERE COALESCE(c.enabled, 1) <> 0 AND COALESCE(t.enabled, 1) <> 0 '
            'AND COALESCE(x.enabled, 1) <> 0 AND c.id IN (%s)' % ','.join('?' for _ in part),
            tuple(part))}
    return [i for i in ids if i in ok]


def rows(store, cert_id=None, test=None):
    where, args = [], []
    if cert_id is not None:
        where.append('cert_id = ?')
        args.append(int(cert_id))
    if test:
        where.append('test = ?')
        args.append(str(test))
    q = 'SELECT * FROM cert_checks' + (' WHERE ' + ' AND '.join(where) if where else '') + \
        ' ORDER BY cert_id, position, id'
    return [row_public(store, r) for r in store.db.rows(q, tuple(args))]


def attach(store, cert_id, names, by, after_target=''):
    """Tests attached to a certificate (those attached already stay) -> the ids made; with
    after_target (1.0.65) they run after a deployment on that target only."""
    t = time.time()
    if not store.db.row('SELECT id FROM certs WHERE id = ?', (int(cert_id),)):
        raise LookupError('there is no such certificate')
    after_target = _after_checked(store, cert_id, after_list(after_target))
    have = {r['test'] for r in store.db.rows('SELECT test FROM cert_checks WHERE cert_id = ?',
                                             (int(cert_id),))}
    made = []
    pos = len(have)
    for n in names or []:
        n = str(n).strip()
        if not n or n in have:
            continue
        if not S.plugin_row(store, 'check', n):
            raise LookupError('there is no test %s (Certificates → Tests)' % n)
        made.append(store.db.insert('cert_checks', {
            'cert_id': int(cert_id), 'test': n, 'enabled': 1, 'position': pos, 'fails': 0,
            'created': t, 'created_by': str(by)[:190], 'updated': t,
            'updated_by': str(by)[:190], 'after_target': after_target}))
        have.add(n)
        pos += 1
    return made


def for_target(store, cert_id, target, by, kind='tls', host='', port=None, sni='', via=None):
    """A test of what a target serves (1.0.77, in place of the deployment's "Check what is
    served"): made - or the same one found - attached to the certificate, run after a
    deployment on that target, and through the target's connector when it has one. A
    failing one fails the deployment there (deployer.run_deploys). -> the test's name."""
    from acmelib.certs import api
    trow = S.plugin_row(store, 'target', target)
    if not trow:
        raise LookupError('there is no target %s' % target)
    cls = S.plugin_class('check', kind)
    if cls is None or getattr(cls, 'connector', False) or kind == 'ssh_relay':
        raise ValueError('there is no test module "%s"' % kind)
    tcfg = S.plugin_config('target', trow) or {}
    if via is None:
        via = str(tcfg.get('via') or '').strip()
    host = str(host or '').strip()
    port = int(port or getattr(cls, 'default_port', 443) or 443)
    if not 0 < port < 65536:
        raise ValueError('the port %s is not one' % port)
    cfg = {'port': port}
    for k, v in (('host', host), ('sni', str(sni or '').strip()), ('via', str(via or '').strip())):
        if v:
            cfg[k] = v
    # the certificate must be deployed there - checked before a test is made (1.0.78: a test
    # was left behind, attached to nothing)
    _after_checked(store, cert_id, [target])
    # the same test already there (the same kind, place and way): taken as it is
    name = None
    for r in store.db.rows('SELECT name, config FROM cert_tests WHERE kind = ?', (kind,)):
        c = S.jload(r.get('config'), {}) or {}
        if all(str(c.get(k) or '') == str(cfg.get(k) or '') for k in ('host', 'port', 'sni', 'via')):
            name = r['name']
            break
    if name is None:
        base = re.sub(r'[^A-Za-z0-9_.-]+', '-', '%s-%s-%d' % (target, host or 'name', port)).strip('-')
        base = base[:60] or 'test'
        name, n = base, 2
        while S.plugin_row(store, 'check', name):
            name = '%s-%d' % (base, n)
            n += 1
        api.family_save(store, 'check', {'name': name, 'kind': kind, 'config': cfg,
                                         'note': 'what %s serves (made from its deployment)' % target},
                        by)
    have = store.db.row('SELECT * FROM cert_checks WHERE cert_id = ? AND test = ?',
                        (int(cert_id), name))
    if have is None:
        attach(store, cert_id, [name], by, after_target=target)
    else:
        now = after_list(have.get('after_target'))
        if now and AFTER_NONE not in now and target not in now:
            after(store, have['id'], '\n'.join(now + [target]), by)
        elif AFTER_NONE in now:
            after(store, have['id'], target, by)
    return name


def verify_to_tests(store, dep, opts, by):
    """A deployment's "Check what is served" (verify, verify_sni) made into tests of its
    target (for_target) and taken out of its options (1.0.77). -> the names; `opts` changed."""
    lines = [x.strip() for x in str(opts.get('verify') or '').replace(',', '\n').split('\n')
             if x.strip()] if not isinstance(opts.get('verify'), list) else \
        [str(x).strip() for x in opts['verify'] if str(x).strip()]
    sni = str(opts.get('verify_sni') or '').strip()
    made = []
    from acmelib.plugins.targets._common import split_hostport
    trow = S.plugin_row(store, 'target', dep['target'])
    tcls = S.row_class('target', trow) if trow else None
    dport = int(getattr(tcls, 'default_verify_port', 443) or 443)
    left = []
    for hp in lines[:10]:
        # as the old check read it (1.0.78): [v6]:port, a bare IPv6 address, the target's own
        # default port (Proxmox 8006, Synology 5001...) - not "2001:db8::1" as host "2001:db8:"
        try:
            host, port = split_hostport(hp, dport)
            made.append(for_target(store, dep['cert_id'], dep['target'], by, 'tls', host,
                                   int(port), sni))
        except (LookupError, ValueError) as e:
            left.append(hp)
            E.log('the check of what %s serves (%s) was not made a test: %s' % (
                dep['target'], hp, e), 'warn')
    for k in ('verify', 'verify_sni', 'verify_tries', 'verify_wait'):
        opts.pop(k, None)
    if left:                                    # kept, not lost: made the next time (1.0.78)
        opts['verify'] = '\n'.join(left)
        if sni:
            opts['verify_sni'] = sni
    return made


def served_tests(store, dep, by):
    """Tests of where the target serves the certificate (its module's served_places), made
    with a new deployment (1.0.93): the module checked them itself after a deployment until
    1.0.92 - what is served is checked by the tests attached only. -> the names."""
    trow = S.plugin_row(store, 'target', dep['target'])
    if not trow:
        return []
    made = []
    try:
        from acmelib.certs import runtime
        ctx = runtime.RunContext(store, None, scope='target:%s' % trow['name'], on_hostkey=False)
        inst = S.plugin_instance(store, 'target', trow, ctx)
        places = list(inst.served_places(S.jload(dep.get('options'), {}) or {}) or [])
    except Exception as e:                              # noqa: BLE001
        E.log('where %s serves could not be read: %s' % (dep['target'], e), 'warn')
        return []
    for host, port in places[:5]:
        try:
            made.append(for_target(store, dep['cert_id'], dep['target'], by, 'tls', host,
                                   int(port)))
        except (LookupError, ValueError) as e:
            E.log('the test of what %s serves (%s:%s) was not made: %s' % (
                dep['target'], host, port, e), 'warn')
    return made


def served_migrate(store, by='acme 1.0.93'):
    """Once (1.0.93): every deployment on a target whose module checked what it serves
    itself gets that as a test - none left without the check it had."""
    n = 0
    for dep in store.db.rows('SELECT * FROM cert_deploys'):
        n += len(served_tests(store, dep, by))
    return n


def _tries_for(store, chk, targets):
    """The waits of a test run after a deployment: longer where a target restarts for long
    (its module's served_wait, 1.0.93 - vCenter, a BMC)."""
    longest = None
    for tg in (after_list(chk.get('after_target')) or sorted(targets or [])):
        if targets is not None and tg not in targets:
            continue
        trow = S.plugin_row(store, 'target', tg)
        cls = S.row_class('target', trow) if trow else None
        w = getattr(cls, 'served_wait', None) if cls else None
        if w and (longest is None or w[0] * w[1] > longest[0] * longest[1]):
            longest = w
    if not longest:
        return AFTER_DEPLOY_TRIES
    tries, wait = max(1, int(longest[0])), max(1, int(longest[1]))
    return (3,) + (wait,) * (tries - 1)


def verify_migrate(store, by='acme 1.0.77'):
    """Every deployment's "Check what is served" made into tests, once (1.0.77)."""
    n = 0
    for dep in store.db.rows("SELECT * FROM cert_deploys WHERE options LIKE '%verify%'"):
        opts = S.jload(dep.get('options'), {}) or {}
        if not opts.get('verify') and 'verify_sni' not in opts:
            continue
        made = verify_to_tests(store, dep, opts, by)
        store.db.update('cert_deploys', dep['id'], {'options': json.dumps(opts)})
        n += len(made)
    return n


def target_gone(store, cert_id, target):
    """The certificate no longer goes to `target` (its deployment taken away or moved, 1.0.78):
    its tests that ran after a deployment there name it no more - they named it and never ran
    again, and changing them said "not deployed on ...". One left with no target runs on its
    schedule only (not after every deployment: it was tied to that one)."""
    if store.db.row('SELECT 1 AS x FROM cert_deploys WHERE cert_id = ? AND target = ?',
                    (int(cert_id), target)):
        return
    for r in store.db.rows('SELECT id, after_target FROM cert_checks WHERE cert_id = ?',
                           (int(cert_id),)):
        have = after_list(r.get('after_target'))
        if target in have:
            rest = [x for x in have if x != target]
            store.db.update('cert_checks', r['id'], {'after_target': '\n'.join(rest) or AFTER_NONE})


def detach(store, ident):
    if not store.db.row('SELECT id FROM cert_checks WHERE id = ?', (int(ident),)):
        raise LookupError('there is no such test of a certificate')
    store.db.run('DELETE FROM cert_checks WHERE id = ?', (int(ident),))


AFTER_NONE = '-'      # after_target: no deployment runs the test - only its schedule (1.0.66)


def after_list(v):
    """The targets a test runs after (1.0.65): '' - any; one name, or several, one a line;
    '-' (AFTER_NONE, 1.0.66) - none."""
    if isinstance(v, (list, tuple)):
        items = v
    else:
        items = str(v or '').replace(',', '\n').split('\n')
    out = []
    for x in items:
        x = str(x or '').strip()
        if x and x not in out:
            out.append(x[:190])
    return out[:50]


def _after_checked(store, cert_id, targets):
    if AFTER_NONE in targets:
        return AFTER_NONE
    have = {r['target'] for r in store.db.rows('SELECT target FROM cert_deploys WHERE cert_id = ?',
                                               (int(cert_id),))}
    for t in targets:
        if t not in have:
            raise ValueError('the certificate is not deployed on %s' % t)
    joined = '\n'.join(targets)
    if len(joined) > 190:
        # the column holds 190 characters on MariaDB (1.0.77): a vague "too big" came back
        raise ValueError('too many targets for one test (%d characters of names, 190 at most) - '
                         'choose "every deployment" instead' % len(joined))
    return joined


def after(store, ident, target, by):
    """The targets after whose deployment the test runs ('' - after any) (1.0.65)."""
    chk = store.db.row('SELECT * FROM cert_checks WHERE id = ?', (int(ident),))
    if not chk:
        raise LookupError('there is no such test of a certificate')
    target = _after_checked(store, chk['cert_id'], after_list(target))
    store.db.update('cert_checks', int(ident), {'after_target': target, 'updated': time.time(),
                                                 'updated_by': str(by)[:190]})
    return chk


def switch(store, ident, on, by):
    store.db.update('cert_checks', int(ident), {'enabled': 1 if on else 0,
                                                 'updated': time.time(),
                                                 'updated_by': str(by)[:190]})


# ---------------------------------------------------------------------------
# What is expected, where to connect
# ---------------------------------------------------------------------------
def expected(store, cert):
    """{current: {fp: (variant, version)}, old: {fp: version}, names, chain: [fp],
    not_after}."""
    cur = {}
    # A revoked one is not the current one (1.0.79: a server serving it was "ok") - also when a
    # new one could not be issued after it and it says "failed" (1.0.80)
    gone = S.revoked_fps(store, cert['id']) if cert.get('id') else set()
    if cert.get('fingerprint') and cert.get('state') != 'revoked' and \
            str(cert['fingerprint']).upper() not in gone:
        cur[str(cert['fingerprint']).upper()] = ('main', cert.get('version'))
    if cert.get('alt_fingerprint') and cert.get('alt_state') != 'revoked' and \
            str(cert['alt_fingerprint']).upper() not in gone:
        cur[str(cert['alt_fingerprint']).upper()] = ('alt', cert.get('alt_version'))
    old = {}
    for r in store.db.rows('SELECT version, fingerprint FROM cert_versions WHERE cert_id = ?',
                           (cert['id'],)):
        fp = str(r.get('fingerprint') or '').upper()
        if fp and fp not in cur:
            old[fp] = r.get('version')
    chain = []
    for _label, pem in pki.split_pem(cert.get('chain_pem') or ''):
        try:
            chain.append(pki.cert_info(pem)['sha256'])
        except Exception:                               # noqa: BLE001
            pass
    names = S.jload(cert.get('names'), []) or []
    if isinstance(names, str):
        names = [n for n in names.replace(',', ' ').split() if n]
    # what acme keeps, described - drawn beside what the server sends (1.0.34)
    infos = []
    for variant, pem_col, ver_col in (('main', 'cert_pem', 'version'), ('alt', 'alt_cert_pem', 'alt_version')):
        if not cert.get(pem_col):
            continue
        try:
            i = pki.cert_info(cert[pem_col])
        except Exception:                               # noqa: BLE001
            continue
        infos.append({'variant': variant, 'version': cert.get(ver_col),
                      'fingerprint': str(i.get('sha256') or '').upper(),
                      'subject': i.get('subject_dn'), 'issuer': i.get('issuer_dn'),
                      'not_before': i.get('not_before'), 'not_after': i.get('not_after'),
                      'names': [str(n).lower() for n in (i.get('names') or [])][:50],
                      'key': _key_words(i)})
    return {'current': cur, 'old': old, 'names': [str(n).lower() for n in names],
            'chain': chain, 'not_after': cert.get('not_after'), 'cert': cert.get('name'),
            'infos': infos,
            'key_type': _key_type_of(cert),
            'twin': bool(cert.get('alt_fingerprint'))}


def _key_words(info):
    """RSA 4096, EC 384 - a key said once (cert_info gives ec-256 and 256)."""
    kt, bits = str(info.get('key_type') or ''), str(info.get('key_bits') or '')
    fam = 'EC' if kt.lower().startswith('ec') else ('RSA' if 'rsa' in kt.lower() else kt.upper())
    return ('%s %s' % (fam, bits)).strip() if bits else (fam or kt)


def _cn(dn):
    m = re.search(r'CN=([^,/]+)', str(dn or ''))
    return m.group(1) if m else str(dn or '')


def compare(detail):
    """What acme keeps against what the server sent, line by line (1.0.34) - for the
    job's log, the event and the mail: [(what, in acme, sent, the same)]. The half of
    a dual certificate nearest to what was sent is the one set against."""
    d = detail or {}
    sv = d.get('served') or {}
    exps = d.get('expected') or []
    if not sv.get('fingerprint') or not exps:
        return []
    fp = str(sv['fingerprint']).upper()
    fam = _key_family(sv.get('key'))
    near = next((e for e in exps if e.get('fingerprint') == fp), None) or \
        next((e for e in exps if _key_family(e.get('key')) == fam), None) or exps[0]
    day = lambda t: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(t))) if t else '-'  # noqa: E731
    rows = [
        ('names', ', '.join(near.get('names') or []) or '-', ', '.join(sv.get('names') or []) or '-',
         sorted(near.get('names') or []) == sorted(sv.get('names') or [])),
        ('issued by', _cn(near.get('issuer')) or '-', _cn(sv.get('issuer')) or '-',
         _cn(near.get('issuer')) == _cn(sv.get('issuer'))),
        ('valid until', day(near.get('not_after')), day(sv.get('not_after')),
         int(float(near.get('not_after') or 0)) == int(float(sv.get('not_after') or 0))),
        ('key', near.get('key') or '-', sv.get('key') or '-',
         str(near.get('key') or '').strip() == str(sv.get('key') or '').strip()),
        ('SHA-256', _short_fp(near.get('fingerprint')), _short_fp(fp), near.get('fingerprint') == fp)]
    if len(exps) > 1:
        rows.insert(0, ('set against', 'the %s (%s)' % ('twin' if near.get('variant') == 'alt'
                                                        else 'certificate', near.get('key')),
                        '', True))
    return rows


def _short_fp(fp):
    f = re.sub(r'[^0-9A-F]', '', str(fp or '').upper())
    f = ':'.join(f[i:i + 2] for i in range(0, len(f), 2))
    return f[:23] + '…' + f[-8:] if len(f) > 32 else f


def compare_lines(detail):
    """compare() as lines of text: the ones that differ first, marked - for each half of a
    test asked for both keys, the one that failed."""
    halves = (detail or {}).get('halves')
    if halves:
        out = []
        for h in halves:
            if h.get('ok'):
                out.append('  %s: %s' % (h.get('half'), h.get('said')))
                continue
            out.append('  %s: %s' % (h.get('half'), h.get('said')))
            out += ['  ' + x for x in _compare_lines(h.get('detail'))]
        return out
    return _compare_lines(detail)


def _compare_lines(detail):
    rows = compare(detail)
    out = []
    for what, mine, sent, same in sorted(rows, key=lambda r: r[3]):
        if what == 'set against':
            out.append('  set against: %s' % mine)
        elif same:
            out.append('  = %s: %s' % (what, mine))
        else:
            out.append('  ✗ %s: acme %s | sent %s' % (what, mine, sent))
    return out


def _key_type_of(cert):
    """The key type of the certificate in use: read from it, else as the row says."""
    try:
        if cert.get('cert_pem'):
            return str(pki.cert_info(cert['cert_pem']).get('key_type') or '')
    except Exception:                                   # noqa: BLE001
        pass
    return str(cert.get('key_type') or '')


def _key_family(words):
    """RSA, ECDSA or '' of a key type as acme writes it (RSA 4096, EC P-256, ec-256)."""
    w = str(words or '').strip().lower()
    if w.startswith('ec') or 'ecdsa' in w:
        return 'ECDSA'
    return 'RSA' if 'rsa' in w else ''


def target_host(trow):
    """The address of a target, as its settings say it (host, address, url...)."""
    if not trow:
        return ''
    cfg = S.plugin_config('target', trow) if trow.get('config') is not None else {}
    for k in ('host', 'address', 'hostport', 'server', 'ip', 'hostname', 'url', 'api_url',
              'base_url', 'endpoint'):
        v = str(cfg.get(k) or '').strip()
        if not v:
            continue
        if '://' in v:
            return urllib.parse.urlsplit(v).hostname or ''
        if v.startswith('['):
            return v[1:].split(']')[0]
        if v.count(':') == 1:
            return v.split(':')[0]
        return v
    return ''


def _covers(names, host):
    host = str(host or '').lower().rstrip('.')
    if any(ord(c) > 127 for c in host):
        # the names of a certificate are A-labels (1.0.52): bücher.de as typed matched none
        try:
            host = '.'.join(x.encode('idna').decode('ascii') if any(ord(c) > 127 for c in x)
                            else x for x in host.split('.'))
        except UnicodeError:
            pass
    for n in names or []:
        n = str(n).lower().rstrip('.')
        if n == host:
            return True
        if n.startswith('*.') and host.count('.') >= 1 and host.split('.', 1)[1] == n[2:]:
            return True
    return False


def judge(exp, served, host, sni, require_trusted=False, trusted=None, why_untrusted='',
          check_name='', expect='current', check_chain=True):
    """What the chain served means, against what acme expects -> the result.
    `expect`: current (the version now, or its twin) | main | alt | any (any version)."""
    t = time.time()
    cur = dict(exp['current'])
    old = dict(exp['old'])
    if expect in ('main', 'alt'):
        for fp, (variant, version) in list(cur.items()):
            if variant != expect:
                old[fp] = version
                cur.pop(fp)
    elif expect == 'any':
        for fp, version in old.items():
            cur[fp] = ('main', version)
        old = {}
    chain = served.get('chain') or []
    leaf = pki.cert_info(chain[0])
    fp = leaf['sha256'].upper()
    said_names = [str(n).lower() for n in leaf.get('names') or []]
    detail = {'served': {'fingerprint': fp, 'subject': leaf.get('subject_dn'),
                         'issuer': leaf.get('issuer_dn'), 'serial': leaf.get('serial'),
                         'not_before': leaf.get('not_before'), 'not_after': leaf.get('not_after'),
                         'names': said_names[:50], 'key': _key_words(leaf)},
              'chain_len': len(chain), 'whole_chain': bool(served.get('whole_chain')),
              'tls': served.get('tls') or '', 'cipher': served.get('cipher') or '',
              'said': str(served.get('said') or '')[:300], 'host': host, 'sni': sni,
              'trusted': trusted, 'why_untrusted': why_untrusted[:300],
              'expected': exp.get('infos') or [], 'cert': exp.get('cert') or ''}
    warns = []
    if fp in cur:
        variant, version = cur[fp]
        state = 'ok'
        words = 'serves the current certificate (version %s%s)' % (
            version, ', its twin' if variant == 'alt' else '')
        detail['version'] = version
        detail['variant'] = variant
    elif fp in old:
        state = 'old'
        words = 'serves %s (%s) of %s - not the one expected' % (
            'an old version' if fp in exp['old'] else 'the other key type', old[fp],
            exp.get('cert') or 'the certificate') if expect != 'current' else \
            'serves an old version (%s) of %s - the new one did not reach the server' % (
                old[fp], exp.get('cert') or 'the certificate')
        detail['version'] = old[fp]
    else:
        state = 'other'
        words = 'serves another certificate: %s, issued by %s, until %s' % (
            leaf.get('cn') or leaf.get('subject_dn') or '?', (leaf.get('issuer') or {}).get(
                'CN') or leaf.get('issuer_dn') or '?',
            time.strftime('%Y-%m-%d', time.gmtime(leaf.get('not_after') or 0)))
        # the other half of a dual certificate acme does not keep (1.0.34): said as that
        mine, theirs = _key_family(exp.get('key_type')), _key_family(leaf.get('key_type'))
        names = set(exp.get('names') or [])
        if mine and theirs and mine != theirs and names and set(said_names) == names \
                and not exp.get('twin'):
            detail['twin_missing'] = theirs
            words = ('serves the %s twin of this certificate (the same names, issued by %s) - '
                     'acme keeps only its %s one: import the %s one into it as its twin, or '
                     'set "Key asked for" to %s' % (
                         theirs, (leaf.get('issuer') or {}).get('CN') or '?', mine, theirs, mine))
    if state == 'ok':
        name = check_name or (sni if sni != '-' else '') or host
        if name and not _covers(said_names, name):
            warns.append('%s is not one of its names' % name)
        days = int(E.CONFIG.get('certs_checks_warn_days') or 0)
        left = (leaf.get('not_after') or 0) - t
        if left <= 0 or float(leaf.get('not_before') or 0) > t:
            # not good now (1.0.52): an expired one served passed with a warning - and its
            # test alerted nobody while renewals failed
            state = 'other'
            words = ('serves the current certificate, but it has run out' if left <= 0 else
                     'serves the current certificate, but it is not valid yet')
        elif days and left < days * 86400:
            warns.append('it ends in %s' % E.human_span(max(0, left)))
        # The intermediates looked for unless switched off for the test (1.0.65: a server whose
        # clients have them already, say).
        if check_chain and served.get('whole_chain') and exp['chain'] and len(chain) < 2 and \
                not leaf.get('self_signed'):
            warns.append('the server sends no intermediate certificate')
        if trusted is False:
            if require_trusted:
                state = 'other'
                words = 'serves the current certificate, but it is not trusted here: %s' % (
                    why_untrusted or 'not verified')
            else:
                detail['note'] = 'not trusted by this machine\'s CAs: %s' % why_untrusted
        if warns and state == 'ok':
            state = 'warn'
            words += ' - but ' + '; '.join(warns)
    http = served.get('http')
    if http:
        detail['http'] = http
        if http.get('fault') and state in ('ok', 'warn'):
            state = 'answer'
            words += ' - but over HTTP %s' % http['fault']
        elif state in ('ok', 'warn'):
            words += ' - HTTP %s' % http.get('status')
    if served.get('alpn'):
        detail['alpn'] = served['alpn']
    detail['warnings'] = warns
    return {'state': state, 'ok': state in ('ok', 'warn'), 'said': words, 'detail': detail}


def _first_name(exp):
    return next((n for n in exp['names'] if not n.startswith('*.')), '')


def probe(store, chk, cert=None):
    """One run of a test attached to a certificate (chk: {cert_id, test}, or a test's
    settings tried before they are kept: {cert_id, kind, config}) -> {state, ok, said,
    detail, ms}. Never raises."""
    t0 = time.time()
    try:
        cert = cert or S.cert_get(store, chk['cert_id'])
        if not cert or not cert.get('cert_pem'):
            raise PluginError('the certificate has not been issued yet')
        if chk.get('config') is not None:
            cfg = dict(chk['config'])
            cls = S.plugin_class('check', chk['kind'], cfg.get(S.VERSION_KEY))
            name = 'unsaved'
        else:
            trow = S.plugin_row(store, 'check', chk['test'])
            if not trow:
                raise PluginError('there is no test %s any more' % chk['test'], retry=False)
            cls = S.row_class('check', trow)
            cfg = S.plugin_config('check', trow)
            name = trow['name']
        if cls is None:
            raise PluginError('there is no test module "%s"' % (chk.get('kind') or '?'))
        exp = expected(store, cert)
        if getattr(cls, 'composite', False):
            got = probe_relay(store, name, cls, cfg, cert, exp)
        else:
            mod = cls(cfg, None)
            host = str(cfg.get('host') or '').strip() or _first_name(exp)
            port = int(cfg.get('port') or cls.default_port)
            sni = str(cfg.get('sni') or '').strip() or _first_name(exp) or host
            via = str(cfg.get('via') or '').strip()
            got = _through(store, via, mod, host, port, sni, exp) if via else \
                _one_served(mod, host, port, sni, exp)
    except PluginError as e:
        got = {'state': 'unreachable', 'ok': False, 'said': str(e), 'detail': {}}
    except Exception as e:                              # noqa: BLE001
        got = {'state': 'unreachable', 'ok': False,
               'said': '%s: %s' % (type(e).__name__, e), 'detail': {}}
    got['ms'] = int((time.time() - t0) * 1000)
    return got


ORDER = {'ok': 0, 'warn': 1, 'old': 2, 'other': 3, 'answer': 3, 'unreachable': 4}


def _through(store, via, mod, host, port, sni, exp):
    """One test through a connector of the tests (1.0.76): signed in to its server over SSH,
    the test connected from there (ssh -W), as a target is reached through one."""
    from acmelib.certs import runtime
    from acmelib.plugins.checks import _tls
    crow = store.db.row("SELECT * FROM cert_tests WHERE name = ? AND kind = 'ssh_relay'", (via,))
    fam = 'check'
    if not crow:
        # a connector of the targets (1.0.77): the test of a target goes the way its
        # deployment goes
        crow = store.db.row("SELECT * FROM cert_targets WHERE name = ? AND kind = 'ssh_connector'",
                            (via,))
        fam = 'target'
    if not crow:
        raise PluginError('there is no connector called %s (Tests or Targets → Connector over '
                          'SSH)' % via, retry=False)
    if crow.get('enabled') == 0:
        raise PluginError('the connector %s is switched off' % via, retry=False)
    ctx = runtime.RunContext(store, None, scope='check:%s' % via)
    try:
        conn = S.plugin_instance(store, fam, crow, ctx)
        try:
            session = conn.ssh()
        except PluginError as e:
            raise PluginError('signing in to the connector %s (%s): %s' % (
                via, conn.c('host') or '?', e))
        try:
            _tls.RELAY.fn = lambda h, p, t: session.tunnel(h, p, t)
            try:
                got = _one_served(mod, host, port, sni, exp)
            except PluginError as e:
                why = session.tunnel_said() if hasattr(session, 'tunnel_said') else ''
                raise PluginError('%s (through %s)%s' % (e, via, (' - ssh said: ' + why) if why else ''))
            finally:
                _tls.RELAY.fn = None
        finally:
            session.close()
    finally:
        ctx.tidy()
    got.setdefault('detail', {})['via'] = via
    return got


def _one_served(mod, host, port, sni, exp):
    """The test once - or, with "Key asked for: both" (1.0.36), once for RSA and once
    for ECDSA: the worse of the two is the result, each said in detail['halves']."""
    if str(mod.config.get('key_want') or '').lower() != 'both':
        return _served_judged(mod, host, port, sni, exp)
    halves = []
    for want, words in (('rsa', 'RSA'), ('ecdsa', 'ECDSA')):
        half = type(mod)(dict(mod.config, key_want=want), mod.ctx)
        try:
            got = _served_judged(half, host, port, sni, exp)
        except PluginError as e:
            got = {'state': 'unreachable', 'ok': False, 'said': str(e), 'detail': {}}
        got['half'] = words
        halves.append(got)
    worst = max(halves, key=lambda g: ORDER.get(g['state'], 4))
    said = '; '.join('%s: %s' % (g['half'], g['said']) for g in halves)
    detail = dict(worst.get('detail') or {})
    detail['expect'] = str(mod.config.get('expect') or 'current')
    detail['key_want'] = 'both'
    detail['halves'] = [{'half': g['half'], 'state': g['state'], 'ok': g['ok'], 'said': g['said'],
                         'detail': g.get('detail') or {}} for g in halves]
    return {'state': worst['state'], 'ok': all(g['ok'] for g in halves), 'said': said,
            'detail': detail}


def _served_judged(mod, host, port, sni, exp):
    from acmelib.plugins.checks import _tls
    trusted, why = None, ''
    _tls.CURRENT.cfg = dict(mod.config)
    try:
        try:
            served = mod.served(host, port, sni, verify=True)
            trusted = True
        except ssl.SSLCertVerificationError as e:
            trusted, why = False, str(getattr(e, 'verify_message', '') or e)
            served = mod.served(host, port, sni, verify=False)
    finally:
        _tls.CURRENT.cfg = None
    req = str(mod.config.get('require_trusted', '')).lower() in ('1', 'true', 'yes', 'on')
    expect = str(mod.config.get('expect') or 'current')
    chain_on = str(mod.config.get('check_chain', True)).lower() not in ('0', 'false', 'no', 'off')
    got = judge(exp, served, host, sni, req, trusted, why,
                str(mod.config.get('check_name') or '').strip(), expect, chain_on)
    got['detail']['port'] = port
    got['detail']['expect'] = expect            # what counted as right - said under it
    got['detail']['key_want'] = str(mod.config.get('key_want') or '')
    return got


def probe_relay(store, name, cls, cfg, cert, exp):
    """A connector (checks/ssh_relay.py): signed in over SSH with its own settings, each
    test it carries run from there through `ssh -W`, each judged; the worst is the
    result, each said in detail['subs']."""
    from acmelib.certs import runtime
    from acmelib.plugins.checks import _tls
    ctx = runtime.RunContext(store, None, scope='check:%s' % name)
    subs = []
    try:
        mod = cls(cfg, ctx)
        plan = mod.plan()
        try:
            session = mod.ssh()
        except PluginError as e:
            raise PluginError('signing in to %s over SSH: %s' % (cfg.get('host') or '?', e))
        try:
            for tname in plan:
                trow = S.plugin_row(store, 'check', tname)
                sub_cls = S.row_class('check', trow) if trow else None
                if sub_cls is None or getattr(sub_cls, 'composite', False):
                    subs.append({'line': tname, 'state': 'unreachable', 'ok': False,
                                 'said': 'there is no test %s (or it is a connector too)' % tname,
                                 'detail': {}})
                    continue
                scfg = S.plugin_config('check', trow)
                sub = sub_cls(scfg, None)
                host = str(scfg.get('host') or '').strip() or _first_name(exp)
                port = int(scfg.get('port') or sub_cls.default_port)
                sni = str(scfg.get('sni') or '').strip() or _first_name(exp) or host
                _tls.RELAY.fn = lambda h, p, t: session.tunnel(h, p, t)
                try:
                    got = _one_served(sub, host, port, sni, exp)
                except PluginError as e:
                    why = session.tunnel_said() if hasattr(session, 'tunnel_said') else ''
                    got = {'state': 'unreachable', 'ok': False,
                           'said': str(e) + ((' - ssh said: ' + why) if why else ''),
                           'detail': {}}
                except Exception as e:                  # noqa: BLE001
                    got = {'state': 'unreachable', 'ok': False,
                           'said': '%s: %s' % (type(e).__name__, e), 'detail': {}}
                finally:
                    _tls.RELAY.fn = None
                got['line'] = tname
                got['label'] = '%s %s:%s' % (getattr(sub_cls, 'protocol', '') or sub_cls.kind,
                                             host, port)
                subs.append(got)
        finally:
            session.close()
    finally:
        ctx.tidy()
    worst = max(subs, key=lambda g: ORDER.get(g['state'], 4))
    bad = [g for g in subs if not g['ok']]
    via = cfg.get('host') or name
    if bad:
        said = '%d of %d from %s failed - %s' % (len(bad), len(subs), via, '; '.join(
            '%s: %s' % (g['line'], g['said']) for g in bad[:4]))
    else:
        said = 'all %d from %s serve the current certificate%s' % (
            len(subs), via, ' (with warnings)' if worst['state'] == 'warn' else '')
    return {'state': worst['state'], 'ok': not bad, 'said': said,
            'detail': {'relay': via, 'subs': [
                {'line': g['line'], 'label': g.get('label'), 'state': g['state'],
                 'said': g['said'], 'served': (g.get('detail') or {}).get('served'),
                 'tls': (g.get('detail') or {}).get('tls')} for g in subs]}}


def label(trow, cert=None):
    """A test in words: HTTPS www.example.cz:443, SSH connector backup1 (3 tests)."""
    if not trow:
        return '?'
    cfg = S.jload(trow.get('config'), {}) if not isinstance(trow.get('config'), dict) \
        else trow['config']
    cfg = cfg or {}
    cls = S.row_class('check', trow)
    proto = (getattr(cls, 'protocol', '') or trow['kind']) if cls else trow['kind']
    if cls is not None and getattr(cls, 'composite', False):
        return '%s %s (%d)' % (proto, cfg.get('host') or '?', len(cfg.get('tests') or []))
    names = S.jload((cert or {}).get('names'), []) if cert and 'names' in cert else []
    host = str(cfg.get('host') or '').strip() or next(
        (n for n in names or [] if not str(n).startswith('*.')), '') or 'its first name'
    port = cfg.get('port') or (cls.default_port if cls else '')
    return '%s %s:%s' % (proto, host, port)


def record(store, chk, got, step=None):
    """The result kept; a test that starts failing (or works again) said and told."""
    t = time.time()
    before = chk.get('last_state') or ''
    fails = int(chk.get('fails') or 0)
    fields = {'last_at': t, 'last_state': got['state'], 'last_said': got['said'][:2000],
              'last_detail': json.dumps(dict(got.get('detail') or {}, ms=got.get('ms')),
                                        default=str)}
    if got['ok']:
        fields['last_ok'] = t
        fields['fails'] = 0
    else:
        fields['fails'] = fails + 1
    store.db.update('cert_checks', chk['id'], fields)
    cert = S.cert_get(store, chk['cert_id'])
    trow = S.plugin_row(store, 'check', chk['test'])
    what = '%s (%s)' % (chk['test'], label(trow, cert)) if trow else chk['test']
    if trow:
        store.db.update('cert_tests', trow['id'], {'last_ok': t, 'last_error': ''} if got['ok']
                        else {'last_error': got['said'][:2000]})
    diff = compare_lines(got.get('detail')) if got['state'] not in ('ok', 'warn') else []
    if step:
        step('test %s: %s' % (what, got['said']), {'ok': 'ok', 'warn': 'warn'}.get(
            got['state'], 'bad'))
        for line in diff:
            step(line)
    went_bad = not got['ok'] and (before in ('', 'ok', 'warn') or fails == 0)
    came_back = got['ok'] and before in BAD
    ship_result(store, chk, got, cert, trow, fields['fails'], before,
                'bad' if went_bad else ('back' if came_back else ''))
    if went_bad or came_back:
        store.add_event('certificates', 'test %s of %s: %s%s' % (
            what, (cert or {}).get('name', '?'), got['said'],
            ('\n' + '\n'.join(diff)) if diff else ''), 'bad' if went_bad else 'info')
        if E.CONFIG.get('certs_checks_alert', 1) and cert:
            try:
                from acmelib.certs import notices
                vals = notices.cert_values(store, cert, target=chk['test'], check=what,
                                           error=got['said'][:500])
                if went_bad and diff:
                    vals['_compare'] = compare(got.get('detail'))     # drawn as a table
                notices.send(store, 'cert_check_failed' if went_bad else 'cert_check_ok',
                             'check:%s:%s' % (chk['id'], 'bad' if went_bad else 'ok'), vals,
                             mail_to=notices.recipients(store, cert))
            except Exception as e:                      # noqa: BLE001
                E.log('telling about test %s: %s' % (what, e), 'warn')
    return got


def ship_result(store, chk, got, cert, trow, fails, before, went):
    """A test's result to isemon (isemon_detail, 1.0.44): every run, with what it found -
    the values of its detail one by one (what was served, what was expected, days left...)."""
    try:
        if not E.detail_on():
            return
        f = {'event': 'result', 'check_id': chk.get('id'), 'test': chk.get('test'),
             'test_kind': (trow or {}).get('kind'), 'cert': (cert or {}).get('name'),
             'cert_id': chk.get('cert_id'), 'names': S.jload((cert or {}).get('names'), []) or None,
             'state': got.get('state'), 'ok': bool(got.get('ok')), 'ms': got.get('ms'),
             'fails': fails, 'before': before or None, 'went': went or None,
             'endpoint': label(trow, cert) if trow else None}
        for k, v in sorted((got.get('detail') or {}).items()):
            if isinstance(v, (str, int, float, bool)) and v not in ('', None):
                f['d_' + re.sub(r'[^a-z0-9_]', '_', str(k).lower())[:28]] = v
            elif isinstance(v, (list, tuple)) and all(isinstance(x, (str, int, float)) for x in v):
                f['d_' + re.sub(r'[^a-z0-9_]', '_', str(k).lower())[:28]] = ','.join(
                    str(x) for x in v[:20])
        E.ship_detail('check', {'ok': 'ok', 'warn': 'warn'}.get(got.get('state'), 'bad'),
                      'acme', f, got.get('said') or got.get('state') or '')
    except Exception:                                   # noqa: BLE001
        pass


def run(store, chk, step=None):
    chk = chk if isinstance(chk, dict) and 'cert_id' in chk else store.db.row(
        'SELECT * FROM cert_checks WHERE id = ?', (int(chk),))
    if not chk:
        raise LookupError('there is no such test of a certificate')
    return record(store, chk, probe(store, chk), step)


def after_deploy(store, job, cert_id, targets=None, failed=None):
    """The tests of a certificate just deployed, a few times while the services restart - those
    tied to a target (after_target, 1.0.65) only after a deployment on that target, those tied
    to none ('-', 1.0.66) never; `targets`:
    the targets just deployed on (None: every test, as before). `failed` (a dict, 1.0.77): a
    test tied to targets that fails says so of each of them - {target: words} - and the
    deployment there is failed by it (the place of "Check what is served" of before)."""
    if not E.CONFIG.get('certs_checks_after_deploy', 1):
        return None
    # switched off for this certificate (cert_checks) or as a test (cert_tests, 1.0.76: it ran
    # after a deployment all the same; the tests by themselves never did)
    tests = store.db.rows('SELECT c.* FROM cert_checks c LEFT JOIN cert_tests t ON t.name = c.test '
                          'WHERE c.cert_id = ? AND COALESCE(c.enabled, 1) <> 0 AND '
                          'COALESCE(t.enabled, 1) <> 0 ORDER BY c.position, c.id', (int(cert_id),))
    tests = [t for t in tests if AFTER_NONE not in after_list(t.get('after_target'))]
    if targets is not None:
        tests = [t for t in tests if not after_list(t.get('after_target')) or
                 set(after_list(t.get('after_target'))) & set(targets)]
    if not tests:
        return None
    worst = True
    for chk in tests:
        got = None
        waits = _tries_for(store, chk, targets)
        for i, wait in enumerate(waits):
            job.check()
            # a Stop heard while it waits (1.0.80: it ran to its end, the window said "running")
            pause = wait if i else min(wait, 3)
            stop = getattr(job, 'stop', None)
            if stop is not None and hasattr(stop, 'wait'):
                stop.wait(pause)
            else:
                time.sleep(pause)
            job.check()
            got = probe(store, chk)
            if got['state'] in ('ok', 'warn'):
                break
            if i + 1 < len(waits):
                job.step('test %s: %s - asked again in %d s' % (
                    chk['test'], got['said'], waits[i + 1]), 'debug')
        record(store, chk, got, job.step)
        worst = worst and got['ok']
        if not got['ok'] and failed is not None:
            # tied to targets, or (1.0.78) to every deployment: each target deployed on now
            for tg in (after_list(chk.get('after_target')) or sorted(targets or [])):
                if targets is None or tg in targets:
                    failed.setdefault(tg, 'the test %s after deploying here: %s' % (
                        chk['test'], got['said']))
    return worst


def due(store, t=None):
    """The tests to run by themselves now (certs_checks_auto)."""
    if not E.CONFIG.get('certs_checks_auto'):
        return []
    t = t or time.time()
    every = max(5, int(E.CONFIG.get('certs_checks_every_min') or 360)) * 60
    out = []
    for r in store.db.rows(
            'SELECT c.* FROM cert_checks c JOIN cert_tests t ON t.name = c.test JOIN certs x '
            'ON x.id = c.cert_id WHERE COALESCE(c.enabled, 1) <> 0 AND COALESCE(t.enabled, 1) '
            '<> 0 AND COALESCE(x.enabled, 1) <> 0'):
        if not r.get('last_at') or t - float(r['last_at']) >= every:
            out.append(r)
    return out


def scan(store, by='the renewer'):
    """The leader's look (renewer.scan): the tests due run in one job."""
    tests = due(store)
    if not tests:
        return 0
    from acmelib.certs import jobs
    ids = [r['id'] for r in tests]
    now = time.time()
    for at in range(0, len(ids), 500):                 # in chunks (1.0.77): the database's limit
        part = ids[at:at + 500]                        # of parameters cut tens of thousands off
        store.db.run('UPDATE cert_checks SET last_at = ? WHERE id IN (%s)' % ','.join(
            '?' for _ in part), tuple([now] + part))   # not started twice meanwhile

    def fn(job):
        return run_many(store, ids, job)
    jobs.submit(store, 'check', fn, by=by, said='%d test(s) of the servers' % len(ids))
    return 1


def run_many(store, ids, job):
    good = bad = 0
    for i in ids:
        job.check()
        try:
            got = run(store, i, job.step)
        except LookupError:
            continue
        if got['ok']:
            good += 1
        else:
            bad += 1
    if bad:
        return False, '%d of %d test(s) failed' % (bad, good + bad)
    return True, '%d test(s) passed' % good
