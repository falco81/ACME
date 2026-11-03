# -*- coding: utf-8 -*-
"""
Tests of what the servers really serve (1.0.32). A test belongs to a deployment
(one certificate on one target, cert_checks.deploy_id): a module of
acmelib/plugins/checks (kind) connects as a client of its protocol would -
HTTPS, SMTP with STARTTLS, RDP... - and gives back the chain the server sent.
Here it is compared with the certificate acme keeps:

    ok           the current version (main or its twin), its names cover the
                 address asked, the chain sent with it
    old          an older version of the same certificate - the renewal did not
                 reach the server (a service not restarted, another node)
    other        a certificate acme did not deploy there
    unreachable  no connection, no TLS
    warn         the right one, but: it ends within certs_checks_warn_days, the
                 name asked is not in it, the intermediates are missing, or it is
                 not trusted here (failing only with require_trusted)

Run after each deployment (certs_checks_after_deploy - a few tries, the service
may still be restarting), by themselves every certs_checks_every_min on the node
that leads (certs_checks_auto), or asked (the target's card Tests, the command
line). A test that starts failing is an event and a notification (cert_check_failed,
certs_checks_alert); one that works again too (cert_check_ok).
"""
from __future__ import annotations

import json
import ssl
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
# The rows
# ---------------------------------------------------------------------------
def row_public(store, r, deps=None):
    d = dict(r)
    d['config'] = S.jload(r.get('config'), {}) or {}
    d['last_detail'] = S.jload(r.get('last_detail'), {}) or {}
    dep = (deps or {}).get(r['deploy_id']) or store.db.row(
        'SELECT id, cert_id, target FROM cert_deploys WHERE id = ?', (r['deploy_id'],))
    if dep:
        d['target'] = dep['target']
        cert = store.db.row('SELECT id, name FROM certs WHERE id = ?', (dep['cert_id'],))
        d['cert_id'] = dep['cert_id']
        d['cert'] = cert['name'] if cert else '?'
    cls = S.plugin_class('check', r['kind'])
    d['title'] = (cls.title or cls.kind) if cls else r['kind']
    d['protocol'] = getattr(cls, 'protocol', '') if cls else ''
    d['module_missing'] = cls is None
    return d


def rows(store, target=None, cert_id=None, deploy_id=None):
    where, args = [], []
    if deploy_id is not None:
        where.append('c.deploy_id = ?')
        args.append(int(deploy_id))
    if target:
        where.append('d.target = ?')
        args.append(str(target))
    if cert_id is not None:
        where.append('d.cert_id = ?')
        args.append(int(cert_id))
    q = ('SELECT c.* FROM cert_checks c JOIN cert_deploys d ON d.id = c.deploy_id' +
         (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY c.deploy_id, c.position, c.id')
    return [row_public(store, r) for r in store.db.rows(q, tuple(args))]


def save(store, b, by):
    """{id?, deploy_id, kind, config, enabled, note} -> the id."""
    t = time.time()
    ident = b.get('id')
    row = store.db.row('SELECT * FROM cert_checks WHERE id = ?', (int(ident),)) \
        if ident not in (None, '', 0) else None
    if ident not in (None, '', 0) and not row:
        raise LookupError('there is no such test')
    deploy_id = int(b.get('deploy_id') or (row or {}).get('deploy_id') or 0)
    if not store.db.row('SELECT id FROM cert_deploys WHERE id = ?', (deploy_id,)):
        raise ValueError('a test belongs to a deployment (a certificate on a target) - choose one')
    kind = str(b.get('kind') or (row or {}).get('kind') or '').strip()
    cls = S.plugin_class('check', kind)
    if cls is None:
        raise ValueError('there is no test module "%s"' % kind)
    cfg = b.get('config') if isinstance(b.get('config'), dict) else \
        (S.jload((row or {}).get('config'), {}) or {})
    keys = {f['key']: f for f in cls.fields or []}
    clean = {}
    for k, v in cfg.items():
        if k not in keys and k != S.VERSION_KEY:
            continue
        clean[k] = v
    if clean.get('port') not in (None, ''):
        try:
            p = int(clean['port'])
        except (TypeError, ValueError):
            raise ValueError('the port is a number')
        if not 1 <= p <= 65535:
            raise ValueError('the port is 1 to 65535')
        clean['port'] = p
    fields = {'deploy_id': deploy_id, 'kind': kind, 'config': json.dumps(clean),
              'enabled': 0 if b.get('enabled') in (False, 0, '0') else 1,
              'note': str(b.get('note') or '')[:500], 'updated': t, 'updated_by': str(by)[:190]}
    if row:
        store.db.update('cert_checks', row['id'], fields)
        ident = row['id']
    else:
        fields.update({'created': t, 'created_by': str(by)[:190], 'fails': 0,
                       'position': int(store.db.value(
                           'SELECT COUNT(*) FROM cert_checks WHERE deploy_id = ?',
                           (deploy_id,), 0) or 0)})
        ident = store.db.insert('cert_checks', fields)
    return ident


def delete(store, ident):
    if not store.db.row('SELECT id FROM cert_checks WHERE id = ?', (int(ident),)):
        raise LookupError('there is no such test')
    store.db.run('DELETE FROM cert_checks WHERE id = ?', (int(ident),))


def forget_deploy(store, deploy_id):
    """A deployment taken away takes its tests with it."""
    store.db.run('DELETE FROM cert_checks WHERE deploy_id = ?', (int(deploy_id),))


# ---------------------------------------------------------------------------
# What is expected, where to connect
# ---------------------------------------------------------------------------
def expected(store, cert):
    """{current: {fp: (variant, version)}, old: {fp: version}, names, chain: [fp],
    not_after}."""
    cur = {}
    if cert.get('fingerprint'):
        cur[str(cert['fingerprint']).upper()] = ('main', cert.get('version'))
    if cert.get('alt_fingerprint'):
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
    return {'current': cur, 'old': old, 'names': [str(n).lower() for n in names],
            'chain': chain, 'not_after': cert.get('not_after'), 'cert': cert.get('name')}


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
    for n in names or []:
        n = str(n).lower().rstrip('.')
        if n == host:
            return True
        if n.startswith('*.') and host.count('.') >= 1 and host.split('.', 1)[1] == n[2:]:
            return True
    return False


def judge(exp, served, host, sni, require_trusted=False, trusted=None, why_untrusted='',
          check_name='', expect='current'):
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
                         'names': said_names[:50], 'key': '%s %s' % (leaf.get('key_type') or '',
                                                                   leaf.get('key_bits') or '')},
              'chain_len': len(chain), 'whole_chain': bool(served.get('whole_chain')),
              'tls': served.get('tls') or '', 'cipher': served.get('cipher') or '',
              'said': str(served.get('said') or '')[:300], 'host': host, 'sni': sni,
              'trusted': trusted, 'why_untrusted': why_untrusted[:300]}
    warns = []
    if fp in cur:
        variant, version = cur[fp]
        state = 'ok'
        words = 'serves the current certificate (version %s%s)' % (
            version, ', its twin' if variant == 'alt' else '')
        detail['version'] = version
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
    if state == 'ok':
        name = check_name or (sni if sni != '-' else '') or host
        if name and not _covers(said_names, name):
            warns.append('%s is not one of its names' % name)
        days = int(E.CONFIG.get('certs_checks_warn_days') or 0)
        left = (leaf.get('not_after') or 0) - t
        if days and left < days * 86400:
            warns.append('it ends in %s' % E.human_span(max(0, left)))
        if served.get('whole_chain') and exp['chain'] and len(chain) < 2 and \
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


def probe(store, chk, cert=None, trow=None):
    """One test run -> {state, ok, said, detail, ms}. Never raises."""
    t0 = time.time()
    try:
        dep = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (chk['deploy_id'],))
        if not dep:
            raise PluginError('its deployment is gone')
        cert = cert or S.cert_get(store, dep['cert_id'])
        if not cert or not cert.get('cert_pem'):
            raise PluginError('the certificate has not been issued yet')
        trow = trow or S.plugin_row(store, 'target', dep['target'])
        cfg = chk['config'] if isinstance(chk.get('config'), dict) else \
            (S.jload(chk.get('config'), {}) or {})
        cls = S.plugin_class('check', chk['kind'], cfg.get(S.VERSION_KEY))
        if cls is None:
            raise PluginError('there is no test module "%s"' % chk['kind'])
        if getattr(cls, 'composite', False):
            got = probe_relay(store, chk, cls, cfg, cert)
            got['ms'] = int((time.time() - t0) * 1000)
            return got
        mod = cls(cfg, None)
        host = str(cfg.get('host') or '').strip() or target_host(trow)
        port = int(cfg.get('port') or cls.default_port)
        exp = expected(store, cert)
        sni = str(cfg.get('sni') or '').strip() or next(
            (n for n in exp['names'] if not n.startswith('*.')), '') or host
        got = _one_served(mod, host, port, sni, exp)
    except PluginError as e:
        got = {'state': 'unreachable', 'ok': False, 'said': str(e), 'detail': {}}
    except Exception as e:                              # noqa: BLE001
        got = {'state': 'unreachable', 'ok': False,
               'said': '%s: %s' % (type(e).__name__, e), 'detail': {}}
    got['ms'] = int((time.time() - t0) * 1000)
    return got


def _one_served(mod, host, port, sni, exp):
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
    got = judge(exp, served, host, sni, req, trusted, why,
                str(mod.config.get('check_name') or '').strip(),
                str(mod.config.get('expect') or 'current'))
    got['detail']['port'] = port
    return got


def probe_relay(store, chk, cls, cfg, cert):
    """A set of tests run from an SSH server (checks/ssh_relay.py): each through
    `ssh -W`, each judged; the worst is the result, each said in detail['subs']."""
    from acmelib.certs import runtime
    from acmelib.plugins.checks import _tls
    relay = S.plugin_row(store, 'target', str(cfg.get('relay') or ''))
    if not relay:
        raise PluginError('the server to go through (%s) is not a target of acme' % (
            cfg.get('relay') or 'none chosen'), retry=False)
    mod = cls(cfg, None)
    plan = mod.plan()
    exp = expected(store, cert)
    first = next((n for n in exp['names'] if not n.startswith('*.')), '')
    ctx = runtime.RunContext(store, None, scope='target:%s' % relay['name'])
    subs = []
    try:
        tgt = S.plugin_instance(store, 'target', relay, ctx)
        if not hasattr(tgt, 'ssh'):
            raise PluginError('%s does not sign in over SSH' % relay['name'], retry=False)
        try:
            session = tgt.ssh()
        except PluginError as e:
            raise PluginError('signing in to %s over SSH: %s' % (relay['name'], e))
        try:
            timeout = float(cfg.get('timeout') or 15)
            for one in plan:
                sub_cls = S.plugin_class('check', one['kind'])
                if sub_cls is None or getattr(sub_cls, 'composite', False):
                    subs.append({'line': one['line'], 'state': 'unreachable', 'ok': False,
                                 'said': 'there is no test module "%s"' % one['kind'],
                                 'detail': {}})
                    continue
                known = {f['key'] for f in sub_cls.fields or []}
                bad = [k for k in one.get('options') or {} if k not in known]
                if bad:
                    subs.append({'line': one['line'], 'state': 'unreachable', 'ok': False,
                                 'said': '%s has no setting %s' % (one['kind'], ', '.join(bad)),
                                 'detail': {}})
                    continue
                sc = {'timeout': timeout, 'require_trusted': cfg.get('require_trusted')}
                sc.update(one.get('options') or {})
                sub = sub_cls(sc, None)
                port = int(one['port'] or sub_cls.default_port)
                sni = one['sni'] or first or one['host']
                _tls.RELAY.fn = lambda h, p, t: session.tunnel(h, p, t)
                try:
                    got = _one_served(sub, one['host'], port, sni, exp)
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
                got['line'] = one['line']
                got['label'] = '%s %s:%s' % (getattr(sub_cls, 'protocol', '') or one['kind'],
                                             one['host'], port)
                subs.append(got)
        finally:
            session.close()
    finally:
        ctx.tidy()
    order = {'ok': 0, 'warn': 1, 'old': 2, 'other': 3, 'unreachable': 4}
    worst = max(subs, key=lambda g: order.get(g['state'], 4))
    bad = [g for g in subs if not g['ok']]
    if bad:
        said = '%d of %d from %s failed - %s' % (len(bad), len(subs), relay['name'], '; '.join(
            '%s: %s' % (g.get('label') or g['line'], g['said']) for g in bad[:4]))
    else:
        said = 'all %d from %s serve the current certificate%s' % (
            len(subs), relay['name'], ' (with warnings)' if worst['state'] == 'warn' else '')
    return {'state': worst['state'], 'ok': not bad, 'said': said,
            'detail': {'relay': relay['name'], 'subs': [
                {'line': g['line'], 'label': g.get('label'), 'state': g['state'],
                 'said': g['said'], 'served': (g.get('detail') or {}).get('served'),
                 'tls': (g.get('detail') or {}).get('tls')} for g in subs]}}


def label(chk, trow=None):
    cfg = chk['config'] if isinstance(chk.get('config'), dict) else \
        (S.jload(chk.get('config'), {}) or {})
    cls = S.plugin_class('check', chk['kind'])
    proto = (getattr(cls, 'protocol', '') or chk['kind']) if cls else chk['kind']
    if cls is not None and getattr(cls, 'composite', False):
        return '%s %s' % (proto, cfg.get('relay') or '?')
    host = str(cfg.get('host') or '').strip() or target_host(trow) or '?'
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
    dep = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (chk['deploy_id'],)) or {}
    cert = S.cert_get(store, dep.get('cert_id')) if dep else None
    trow = S.plugin_row(store, 'target', dep.get('target')) if dep else None
    what = label(chk, trow)
    if step:
        step('test %s: %s' % (what, got['said']), {'ok': 'ok', 'warn': 'warn'}.get(
            got['state'], 'bad'))
    went_bad = not got['ok'] and (before in ('', 'ok', 'warn') or fails == 0)
    came_back = got['ok'] and before in BAD
    if went_bad or came_back:
        store.add_event('certificates', 'test %s of %s on %s: %s' % (
            what, (cert or {}).get('name', '?'), dep.get('target', '?'), got['said']),
            'bad' if went_bad else 'info')
        if E.CONFIG.get('certs_checks_alert', 1) and cert:
            try:
                from acmelib.certs import notices
                vals = notices.cert_values(store, cert, target=dep.get('target') or '',
                                           check=what, error=got['said'][:500])
                notices.send(store, 'cert_check_failed' if went_bad else 'cert_check_ok',
                             'check:%s:%s' % (chk['id'], 'bad' if went_bad else 'ok'), vals,
                             mail_to=notices.recipients(store, cert))
            except Exception as e:                      # noqa: BLE001
                E.log('telling about test %s: %s' % (what, e), 'warn')
    return got


def run(store, chk, step=None):
    chk = chk if isinstance(chk, dict) and 'deploy_id' in chk else store.db.row(
        'SELECT * FROM cert_checks WHERE id = ?', (int(chk),))
    if not chk:
        raise LookupError('there is no such test')
    return record(store, chk, probe(store, chk), step)


def after_deploy(store, job, dep_id):
    """The tests of a deployment just made, a few times while the service restarts."""
    if not E.CONFIG.get('certs_checks_after_deploy', 1):
        return None
    tests = [r for r in store.db.rows(
        'SELECT * FROM cert_checks WHERE deploy_id = ? AND COALESCE(enabled, 1) <> 0 '
        'ORDER BY position, id', (int(dep_id),))]
    if not tests:
        return None
    worst = True
    for chk in tests:
        got = None
        for i, wait in enumerate(AFTER_DEPLOY_TRIES):
            job.check()
            time.sleep(wait if i else min(wait, 3))
            got = probe(store, chk)
            if got['state'] in ('ok', 'warn'):
                break
            if i + 1 < len(AFTER_DEPLOY_TRIES):
                job.step('test %s: %s - asked again in %d s' % (
                    label(chk), got['said'], AFTER_DEPLOY_TRIES[i + 1]), 'debug')
        record(store, chk, got, job.step)
        worst = worst and got['ok']
    return worst


def due(store, t=None):
    """The tests to run by themselves now (certs_checks_auto)."""
    if not E.CONFIG.get('certs_checks_auto'):
        return []
    t = t or time.time()
    every = max(5, int(E.CONFIG.get('certs_checks_every_min') or 360)) * 60
    out = []
    for r in store.db.rows(
            'SELECT c.* FROM cert_checks c JOIN cert_deploys d ON d.id = c.deploy_id '
            'WHERE COALESCE(c.enabled, 1) <> 0 AND COALESCE(d.enabled, 1) <> 0'):
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
    store.db.run('UPDATE cert_checks SET last_at = ? WHERE id IN (%s)' % ','.join(
        '?' for _ in ids), tuple([time.time()] + ids))      # not started twice meanwhile

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
