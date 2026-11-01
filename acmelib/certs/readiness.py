# -*- coding: utf-8 -*-
"""
Before a certificate is asked for: what its names need, where, and whether it
is in place - acme tells the person, and tries it itself.

    plan(store, names, issuer=None, challenge=None, challenge_map=None, cert=None)
        -> {'groups': [{'domain', 'names', 'validation', 'kind', 'suggested',
                        'guide': {'steps', 'ok'}}],
            'issuer', 'issuer_needs_validation', 'ok', 'blocking': [...], 'took_ms',
            'complete'}
        The names grouped by the DNS zone they are in (found by SOA, else the
        registrable domain), the validation of each name chosen exactly as the
        renewer chooses it (store.challenge_for: challenge_map by the exact
        name, '*.parent', the longest suffix, then the certificate's own),
        the validation's guide() for each name (what to set up where, checked
        live and read-only) and, for each group, the validations acme would
        suggest: a DNS provider that holds the zone, acme's own DNS server,
        HTTP-01 here or on the web servers the names point at.
    check(store, names, ...)       the same, quicker: suggestions only where
                                   something blocks (the renewer's precheck)
    dry_run(store, names, ..., by='')  -> job id: each group's dry_run() in a
                                   job (Certificates → Jobs, live steps): a test
                                   value put in place, looked for from outside,
                                   taken away - no CA asked
    dry_run_result(store, job_id)  -> what that job found (the same shape as plan)
    job_steps(job, result)         a plan written into a job's steps

Everything is bounded in time: every DNS question has its own timeout, and a
plan gives up after `timeout` seconds (what did not finish is said so,
'complete': False). Lookups of a provider's zones are kept for a little while.
"""
from __future__ import annotations

import concurrent.futures
import json
import threading
import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.plugins.challenges import _dns as D
from acmelib.certs import store as S

CACHE_S = 120                   # how long a zone found (by SOA, at a provider) is kept
LOOKUP_S = 2.0                  # one DNS question
PLAN_S = 60                     # a whole plan at most
CHECK_S = 45                    # the renewer's precheck at most
_CACHE = {}
_CACHE_LOCK = threading.Lock()
DRY_KEEP = 30                   # dry-run results kept


class NotReady(base.PluginError):
    """The precheck found something missing: the CA was not asked."""


def _cached(key, fn, ttl=CACHE_S):
    t = time.time()
    with _CACHE_LOCK:
        got = _CACHE.get(key)
        if got and got[0] > t:
            return got[1]
    val = fn()
    with _CACHE_LOCK:
        if len(_CACHE) > 2000:
            for k in [k for k, v in _CACHE.items() if v[0] <= t]:
                _CACHE.pop(k, None)
        _CACHE[key] = (t + ttl, val)
    return val


def forget():
    """The cache emptied (a test, or after a validation was changed)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def resolvers():
    """The resolvers of the validation checks: Settings → DNS (acmelib/certs/dnssets.py)."""
    return D.resolver('validation')


def is_ip(name):
    import ipaddress
    try:
        ipaddress.ip_address(str(name).strip('[]'))
        return True
    except ValueError:
        return False


def bare(name):
    n = D.norm(name)
    while n.startswith('*.'):
        n = n[2:]
    return n


def zone_of(name):
    """The DNS zone a name is in: its SOA (asked of acme's resolvers), else
    the registrable domain (a small list of public suffixes)."""
    n = bare(name)
    if is_ip(n):
        return n

    def look():
        fallback = D.registrable(n)
        try:
            z = D.find_zone(n, resolvers(), timeout=LOOKUP_S)
        except (D.DnsError, D.FormErr, OSError):
            return fallback
        # A zone above the registrable domain (the name is not there at all,
        # the TLD answered): the domain is said instead.
        if not z or len(z.split('.')) < len(fallback.split('.')):
            return fallback
        return z
    return _cached(('zone', n), look)


# ---------------------------------------------------------------------------
# The rows and the modules
# ---------------------------------------------------------------------------
def _ctx(store, job, scope):
    from acmelib.certs import runtime
    return runtime.RunContext(store, job, scope=scope)


def module(store, ref, job=None):
    """(row, instance, words): a validation by name; words say why not."""
    row = S.plugin_row(store, 'challenge', ref)
    if not row:
        return None, None, 'there is no validation %s' % ref
    if not row.get('enabled', 1):
        return row, None, 'the validation %s is switched off' % row['name']
    try:
        inst = S.plugin_instance(store, 'challenge', row, _ctx(store, job,
                                                              'challenge:%s' % row['name']))
    except base.PluginError as e:
        return row, None, str(e)
    return row, inst, ''


def validations(store):
    return [r for r in store.db.rows('SELECT * FROM cert_challenges ORDER BY name')
            if r.get('enabled', 1) not in (0, '0')]


def resolve(store, names, challenge=None, challenge_map=None, cert=None):
    """{name: validation name or None}, exactly as the renewer chooses."""
    if cert is None:
        if not challenge and not challenge_map:
            from acmelib.certs import defaults as DF
            challenge = DF.default_name(store, 'challenge') or None
        cert = {'challenge': challenge, 'challenge_map': json.dumps(challenge_map or {})}
    return {n: S.challenge_for(cert, n) for n in names}


def issuer_of(store, issuer=None):
    """(row or None, class or None, explicitly named)."""
    named = bool(issuer)
    if not issuer:
        from acmelib.certs import defaults as DF
        issuer = DF.default_name(store, 'issuer')
    row = S.plugin_row(store, 'issuer', issuer) if issuer else None
    cls = S.plugin_class('issuer', row.get('kind')) if row else None
    return row, cls, named


# ---------------------------------------------------------------------------
# What is suggested for a group
# ---------------------------------------------------------------------------
def _provider_zone(store, row, fqdn):
    def look():
        r, inst, _w = module(store, row['name'])
        if inst is None or not getattr(inst, 'api_provider', False):
            return None
        return inst.provider_zone(fqdn)
    return _cached(('pz', row['id'], str(row.get('updated') or ''), D.norm(fqdn)), look)


def suggest(store, domain, names):
    """[{'validation', 'kind', 'why'}] - the validations that would do for these
    names, the best first. Read-only (DNS, a provider's list of zones)."""
    from acmelib.plugins.challenges._common import DnsChallenge, HttpChallenge, as_list
    out = []
    wild = any(D.norm(n).startswith('*.') for n in names)
    ips = any(is_ip(n) for n in names)
    rows = validations(store)
    probe = '_acme-challenge.' + bare(names[0]) if names else '_acme-challenge.' + domain
    for row in rows:
        cls = S.plugin_class('challenge', row.get('kind'))
        if cls is None or ips or not issubclass(cls, DnsChallenge) or \
                not getattr(cls, 'api_provider', False):
            continue
        try:
            z = _provider_zone(store, row, probe)
        except Exception:                               # noqa: BLE001
            z = None
        if z:
            out.append({'validation': row['name'], 'kind': row['kind'],
                        'why': 'the zone %s is at %s' % (z, getattr(cls, 'who', '') or
                                                         cls.title or cls.kind)})
    for row in rows:
        if row.get('kind') == 'rfc2136' and not ips:
            r, inst, _w = module(store, row['name'])
            if inst is None:
                continue
            try:
                z = _cached(('rfc', row['id'], str(row.get('updated') or ''), domain),
                            lambda: inst.zone_hint(probe))
            except Exception:                           # noqa: BLE001
                z = None
            if z:
                out.append({'validation': row['name'], 'kind': 'rfc2136',
                            'why': 'its server holds the zone %s' % z})
    dns_on = bool(str(E.CONFIG.get('dns_zone') or '').strip()) and \
        str(E.CONFIG.get('dns_server') or '0') not in ('0', '', 'False')
    for row in rows:
        if row.get('kind') == 'dns_builtin' and dns_on and not ips:
            out.append({'validation': row['name'], 'kind': 'dns_builtin',
                        'why': 'acme\'s own DNS server: one CNAME per name in %s, no DNS '
                               'credentials' % domain})
    if not wild:
        for row in rows:
            kind = row.get('kind')
            if kind not in ('http_local', 'http_ssh'):
                continue
            r, inst, _w = module(store, row['name'])
            if inst is None or not isinstance(inst, HttpChallenge):
                continue
            try:
                want = set(inst.answering(names[0]) or []) | set(as_list(inst.c(
                    'public_addresses' if kind == 'http_local' else 'balancer', '')))
                hits = bool(want) and all(
                    set(inst.lookup(n) if not is_ip(n) else [n]) & want for n in names)
            except Exception:                           # noqa: BLE001
                hits = False
            if hits:
                out.append({'validation': row['name'], 'kind': kind,
                            'why': ('the names point at acme: HTTP-01 answered here'
                                    if kind == 'http_local' else
                                    'the names point at its web servers: HTTP-01 written there')})
    if not any(s['kind'] in ('dns_builtin',) for s in out) and not ips and \
            not any(r.get('kind') == 'dns_builtin' for r in rows):
        out.append({'validation': None, 'kind': 'dns_builtin',
                    'why': 'set up acme\'s own DNS server (Settings → DNS server): then one '
                           'CNAME per name in %s, no DNS credentials' % domain})
    seen, uniq = set(), []
    for s in out:
        k = (s['validation'], s['kind'])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------
def _step(key, what, done, said='', fix='', where='acme', blocking=None):
    return base.guide_step(key, what, where=where, done=done, said=said, fix=fix,
                           blocking=blocking)


def _merge(parts):
    """One guide of several names' guides: each step once, its name with it."""
    steps, seen = [], set()
    for name, g in parts:
        for st in (g or {}).get('steps') or []:
            k = (st.get('key'), st.get('what'), st.get('where'),
                 json.dumps(st.get('record'), sort_keys=True), st.get('done'))
            if k in seen:
                continue
            seen.add(k)
            st = dict(st)
            st.setdefault('name', name)
            steps.append(st)
    return base.guide_of(steps)


def _group_guide(store, group):
    """The guide of one group (run in a worker)."""
    names, which = group['names'], group['validation']
    if not which:
        return base.guide_of([_step(
            'validation', 'A validation proves the names', False,
            said='no validation is chosen for %s' % ', '.join(names),
            fix='Choose a validation for them (or one for each name)')])
    row, inst, words = module(store, which)
    if inst is None:
        return base.guide_of([_step('validation', 'The validation %s can be used' % which,
                                    False, said=words,
                                    fix='Choose another validation, or switch it on')])
    group['kind'] = row.get('kind')
    pre = []
    types = tuple(getattr(inst, 'types', ()) or ())
    for n in names:
        if is_ip(n) and 'dns-01' in types and 'http-01' not in types:
            pre.append(_step('ip', 'The name can be proved this way', False,
                             said='%s is an IP address: DNS-01 cannot prove it' % n,
                             fix='Choose an HTTP-01 validation for %s' % n))
    if pre:
        return base.guide_of(pre)
    parts = []
    for n in names:
        try:
            parts.append((n, inst.guide(n)))
        except Exception as e:                          # noqa: BLE001
            parts.append((n, base.guide_of([_step(
                'guide', 'The validation can say what it needs', None,
                said='%s: %s' % (type(e).__name__, e), blocking=False)])))
    from acmelib.certs import dnssets      # which sets were asked (Settings → DNS)
    return _merge(parts + [('', base.guide_of([dnssets.guide_step(store)]))])


def plan(store, names, issuer=None, challenge=None, challenge_map=None, cert=None,
         timeout=None, suggestions='all'):
    """See the top of this file. `suggestions`: 'all', 'blocking' (only for a
    group that blocks) or 'none'."""
    t0 = time.time()
    timeout = PLAN_S if timeout is None else float(timeout)
    names = S.clean_names(names) if names else []
    irow, icls, named = issuer_of(store, issuer)
    out = {'groups': [], 'issuer': irow['name'] if irow else None,
           'issuer_needs_validation': bool(icls.needs_challenge) if icls else True,
           'ok': True, 'blocking': [], 'complete': True}
    head = []
    if named and not irow:
        head.append(_step('issuer', 'The source is there', False,
                          said='there is no source %s' % issuer,
                          fix='Choose a source (Certificates → Sources)'))
    elif irow and icls is None:
        head.append(_step('issuer', 'The source is there', False,
                          said='the module %s of %s is missing' % (irow.get('kind'), irow['name']),
                          fix='Choose another source'))
    if icls is not None:
        if any(n.startswith('*.') for n in names) and not getattr(icls, 'wildcards', True):
            head.append(_step('issuer', 'The source gives wildcard certificates', False,
                              said='%s gives none' % irow['name'],
                              fix='Choose a source that does, e.g. Let\'s Encrypt'))
        if any(is_ip(n) for n in names) and not getattr(icls, 'ip_names', False):
            head.append(_step('issuer', 'The source gives certificates for addresses', False,
                              said='%s gives none for IP addresses' % irow['name'],
                              fix='Take the addresses out, or choose a source that does'))
    if not names:
        head.append(_step('names', 'The certificate has names', False, said='no names',
                          fix='Give it its names'))
    if head:
        out['head'] = base.guide_of(head)
    if not out['issuer_needs_validation']:
        domains = {}
        for n in names:
            domains.setdefault(zone_of(n) if not is_ip(n) else n, []).append(n)
        out['groups'] = [{'domain': d, 'names': ns, 'validation': None, 'kind': None,
                          'suggested': [], 'guide': {'steps': [], 'ok': True}}
                         for d, ns in domains.items()]
    else:
        which = resolve(store, names, challenge, challenge_map, cert)
        groups, index = [], {}
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=8,
                                                   thread_name_prefix='certs-readiness')
        try:
            zones = dict(zip(names, ex.map(lambda n: zone_of(n), names, timeout=max(
                1.0, timeout - (time.time() - t0)))))
        except concurrent.futures.TimeoutError:
            zones = {n: D.registrable(bare(n)) for n in names}
            out['complete'] = False
        for n in names:
            k = (zones.get(n) or D.registrable(bare(n)), which.get(n))
            if k not in index:
                index[k] = {'domain': k[0], 'names': [], 'validation': k[1], 'kind': None,
                            'suggested': [], 'guide': None}
                groups.append(index[k])
            index[k]['names'].append(n)
        for g in groups:
            if g['validation']:
                r = S.plugin_row(store, 'challenge', g['validation'])
                g['kind'] = r.get('kind') if r else None

        def work(g):
            g['guide'] = _group_guide(store, g)
            if suggestions == 'all' or (suggestions == 'blocking' and g['guide']['ok'] is False):
                g['suggested'] = [s for s in suggest(store, g['domain'], g['names'])
                                  if s['validation'] != g['validation'] and not (
                                      s['kind'] == g.get('kind') and
                                      s['kind'] in ('dns_builtin', 'http_local'))]
            return g
        futs = {ex.submit(work, g): g for g in groups}
        left = max(1.0, timeout - (time.time() - t0))
        done, notyet = concurrent.futures.wait(futs, timeout=left)
        for f in done:
            try:
                f.result()
            except Exception as e:                      # noqa: BLE001
                futs[f]['guide'] = base.guide_of([_step(
                    'guide', 'The validation can say what it needs', None,
                    said='%s: %s' % (type(e).__name__, e), blocking=False)])
        for f in notyet:
            out['complete'] = False
            g = futs[f]
            if not g.get('guide'):
                g['guide'] = base.guide_of([_step(
                    'time', 'Every check finished in time', None,
                    said='not every check finished within %d s - a DNS server or an API '
                         'answers slowly' % int(timeout), blocking=False)])
        ex.shutdown(wait=False, cancel_futures=True)
        out['groups'] = groups
    for st in (out.get('head') or {}).get('steps') or []:
        if st.get('blocking'):
            out['blocking'].append({'domain': None, 'name': None, 'validation': None,
                                    'key': st['key'], 'what': st['what'], 'said': st['said'],
                                    'fix': st['fix'], 'record': st['record']})
    for g in out['groups']:
        for st in (g.get('guide') or {}).get('steps') or []:
            if st.get('blocking'):
                out['blocking'].append({'domain': g['domain'], 'name': st.get('name'),
                                        'validation': g['validation'], 'key': st['key'],
                                        'what': st['what'], 'said': st['said'],
                                        'fix': st['fix'], 'record': st['record']})
    out['ok'] = not out['blocking']
    out['took_ms'] = int((time.time() - t0) * 1000)
    return out


def check(store, names, issuer=None, challenge=None, challenge_map=None, cert=None,
          timeout=None):
    """plan(), guides only, quick: suggestions only for a group that blocks.
    Nothing is changed anywhere."""
    return plan(store, names, issuer, challenge, challenge_map, cert,
                timeout=CHECK_S if timeout is None else timeout, suggestions='blocking')


def cert_args(cert):
    """(names, issuer, challenge, challenge_map) of a certificate row."""
    return (S.jload(cert.get('names'), []) or [], cert.get('issuer') or None,
            cert.get('challenge') or None, S.jload(cert.get('challenge_map'), {}) or {})


# ---------------------------------------------------------------------------
# Words
# ---------------------------------------------------------------------------
def record_text(rec):
    """'_acme-challenge.www.firma.cz. CNAME www.firma.cz.acme.example.net.'"""
    if not rec:
        return ''
    name = rec.get('name') or ''
    val = rec.get('value') or ''
    if rec.get('type') == 'TXT' and not val.startswith('('):
        val = '"%s"' % val
    return '%s. %s%s %s' % (name.rstrip('.'), ('%s ' % rec['ttl']) if rec.get('ttl') else '',
                           rec.get('type') or '', val)


def step_line(st):
    words = st.get('what') or ''
    if st.get('said'):
        words += ': ' + st['said']
    if st.get('fix') and st.get('done') is not True:
        words += ' - ' + st['fix']
    return words


def fixes(result, most=3):
    """The words of what to do first, for last_error."""
    out = []
    for b in result.get('blocking') or []:
        w = b.get('fix') or b.get('what') or ''
        if b.get('name') and b['name'] not in w:
            w = '%s: %s' % (b['name'], w)
        if w and w not in out:
            out.append(w)
    more = len(out) - most
    return '; '.join(out[:most]) + (' (and %d more)' % more if more > 0 else '')


def group_line(g):
    if g.get('validation'):
        return 'Names %s in %s, proved by %s' % (', '.join(g['names']), g['domain'],
                                                 g['validation'])
    return 'Names %s in %s: no validation is chosen' % (', '.join(g['names']), g['domain'])


def _step_lines(job, st):
    """One guide step as job lines: what, what was found, what to do, the record -
    each a line of its own (the pages translate each by itself)."""
    lvl = 'ok' if st['done'] is True else 'bad' if st['blocking'] else \
        'warn' if st['done'] is False else 'info'
    job.step(st['what'], lvl)
    if st.get('said'):
        job.step(st['said'], 'info')
    if st.get('fix') and st['done'] is False:
        job.step(st['fix'], lvl)
    rec = st.get('record') or {}
    if rec.get('type') and st['done'] is False and not str(rec.get('value') or '').startswith('('):
        job.step(record_text(rec), lvl)


def job_steps(job, result):
    """A plan written into a job's steps."""
    for st in (result.get('head') or {}).get('steps') or []:
        _step_lines(job, st)
    for g in result.get('groups') or []:
        job.step(group_line(g))
        for st in (g.get('guide') or {}).get('steps') or []:
            _step_lines(job, st)
        for s in g.get('suggested') or []:
            job.step('Could also be: %s (%s)' % (s['validation'] or s['kind'], s['why']))


# ---------------------------------------------------------------------------
# The dry run
# ---------------------------------------------------------------------------
DRY_PREFIX = 'certs:dryrun:'


def dry_run(store, names, issuer=None, challenge=None, challenge_map=None, cert=None, by='',
            wait=None, cert_id=None):
    """A job (its id) that tries each group's validation for real, without a
    CA; what it found then by dry_run_result()."""
    names = S.clean_names(names)
    which = resolve(store, names, challenge, challenge_map, cert)
    said = 'dry run of %s' % ', '.join(names)

    def fn(job):
        return _dry(store, job, names, which, wait)
    from acmelib.certs import jobs
    return jobs.submit(store, 'dry-run', fn, cert_id=cert_id, by=by, said=said[:500])


def _dry(store, job, names, which, wait):
    groups, index = [], {}
    for n in names:
        k = (zone_of(n), which.get(n))
        if k not in index:
            index[k] = {'domain': k[0], 'names': [], 'validation': k[1], 'kind': None,
                        'suggested': [], 'guide': None}
            groups.append(index[k])
        index[k]['names'].append(n)
    for g in groups:
        job.check()
        job.step(group_line(g))
        if not g['validation']:
            g['guide'] = base.guide_of([_step(
                'validation', 'A validation proves the names', False,
                said='no validation is chosen', fix='Choose a validation for them')])
            _step_lines(job, g['guide']['steps'][0])
            continue
        row, inst, words = module(store, g['validation'], job)
        if inst is None:
            g['guide'] = base.guide_of([_step('validation', 'The validation can be used', False,
                                              said=words, fix='Choose another validation')])
            _step_lines(job, g['guide']['steps'][0])
            continue
        g['kind'] = row.get('kind')
        parts = []
        try:
            for n in g['names']:
                job.check()
                parts.append((n, inst.dry_run(n, wait)))
        finally:
            try:
                inst.ctx.tidy()
            except Exception:                           # noqa: BLE001
                pass
        g['guide'] = _merge(parts)
    blocking = [dict(st, domain=g['domain'], validation=g['validation'])
                for g in groups for st in g['guide']['steps'] if st.get('blocking')]
    result = {'groups': groups, 'ok': not blocking, 'blocking': blocking,
              'at': time.time(), 'job': job.id}
    _keep(store, job.id, result)
    if blocking:
        return False, 'the dry run found what is missing: %s' % fixes(result)
    return True, 'the dry run worked for %s' % ', '.join(names)


def _keep(store, job_id, result):
    try:
        store.set_meta(DRY_PREFIX + str(job_id), json.dumps(result, default=str))
        keys = S.jload(store.get_meta(DRY_PREFIX + 'list'), []) or []
        keys = [k for k in keys if k != job_id] + [job_id]
        for old in keys[:-DRY_KEEP]:
            store.db.run('DELETE FROM meta WHERE k = ?', (DRY_PREFIX + str(old),))
        store.set_meta(DRY_PREFIX + 'list', json.dumps(keys[-DRY_KEEP:]))
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-dryrun', 'a dry run\'s result could not be kept: %s' % e, 'warn',
                      every=3600)


def dry_run_result(store, job_id):
    """What the dry run job `job_id` found, or None (not finished, or long gone)."""
    return S.jload(store.get_meta(DRY_PREFIX + str(int(job_id))), None)


# ---------------------------------------------------------------------------
# The renewer's precheck
# ---------------------------------------------------------------------------
VALIDATION_WORDS = ('did not accept', 'not visible after', 'authorization of the order',
                    'unauthorized', 'incorrectresponse', 'nxdomain', 'dnssec', 'caa',
                    'no valid ip', 'timeout during connect', 'the proof for', 'the ca offers',
                    'no challenge is chosen', 'there is no way of proving', 'challenge')
FAILED_KEY = 'certs:validation_failed:'


def failed_on_validation(e):
    """Did this renewal fail on proving the names (not the CA, the network...)?"""
    if isinstance(e, NotReady):
        return True
    if str(getattr(e, 'acme_type', '') or '').lower() in (
            'unauthorized', 'dns', 'connection', 'incorrectresponse', 'caa', 'tls'):
        return True
    words = str(e).lower()
    return any(w in words for w in VALIDATION_WORDS)


def precheck_due(store, cert):
    """Before the first certificate (no version yet), and after a renewal that
    failed on validation - unless certs_precheck is off."""
    try:
        if not int(E.CONFIG.get('certs_precheck', 1) or 0):
            return False
    except (TypeError, ValueError):
        pass
    if not cert.get('cert_pem') or not cert.get('version'):
        return True
    try:
        return bool(store.get_meta(FAILED_KEY + str(cert['id'])))
    except Exception:                                   # noqa: BLE001
        return False


def mark(store, cert_id, failed):
    """Whether the last renewal of cert_id failed on validation, kept."""
    try:
        if failed:
            store.set_meta(FAILED_KEY + str(cert_id), str(int(time.time())))
        else:
            store.db.run('DELETE FROM meta WHERE k = ?', (FAILED_KEY + str(cert_id),))
    except Exception:                                   # noqa: BLE001
        pass


def precheck(store, job, cert, names):
    """The renewer's check before the CA is asked: raises NotReady (the CA is
    not asked) when something that blocks is found. The steps go into the job."""
    job.step('before the CA is asked, what the validation needs is checked (certs_precheck; '
             'Let\'s Encrypt counts failed validations)')
    result = check(store, names, cert.get('issuer') or None, cert=cert)
    job_steps(job, result)
    if result['blocking']:
        raise NotReady('the CA was not asked - the validation is not ready: %s' % fixes(result),
                       detail=json.dumps(result.get('blocking'), default=str)[:4000],
                       retry=True)
    if not result.get('complete'):
        job.step('not every check finished in time: the CA is asked anyway', 'warn')
    else:
        job.step('the validation looks ready: the CA is asked', 'ok')
    return result
