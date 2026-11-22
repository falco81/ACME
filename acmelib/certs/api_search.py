# -*- coding: utf-8 -*-
"""
The global search of the administration (1.0.140, docs/context-menu.md "The command
palette"): what Ctrl+K - and the search box in the header - finds beyond the page's own
commands. One route, every kind of object, each kept to what the person asking may see:

    certificates   by name, its names (SANs), common name, serial (with or without colons),
                   SHA-256 fingerprint - only those of the teams the session sees (teams.where)
    deployments    a certificate's deployment by the certificate's or the target's name -
                   only of the certificates the session sees
    targets        by name, module, host, tags (an agent's target is an "agent") - a target
                   of a team (owner) only for a session that sees that team
    sources        the sources and acme's own authorities, the validations, the tests
    profiles       the request profiles
    teams          the owners and teams the session sees
    accounts       the accounts of the administration - a full administrator only (never a
                   mail, a phone or a group)
    events         of the last 30 days, the newest first - only those the Events page would
                   show this session (events_hidden_of)

Bounded: at most 100 characters asked, every kind LIMIT-ed in SQL (8 by default, 20 at most),
events only within 30 days, and 30 questions in 10 seconds of one session (then 429).

    GET /api/search?q=TEXT&kinds=cert,target,...&limit=N
"""
from __future__ import annotations

import json
import re
import threading
import time

from acmelib import engine as E
from acmelib.certs import api as A

KINDS = ('cert', 'deploy', 'target', 'agent', 'source', 'ca', 'validation', 'test', 'profile',
         'team', 'account', 'event')
MAX_Q = 100
PER_KIND = 8
MOST_PER_KIND = 20
EVENT_DAYS = 30
RATE = {'lock': threading.Lock(), 'seen': {}}
RATE_N, RATE_S = 30, 10.0


def _like(q):
    return '%' + E.like_pattern(q.lower()) + '%'


def _limited(who):
    """True when this session asked too often (30 in 10 s)."""
    now = time.time()
    with RATE['lock']:
        if len(RATE['seen']) > 2000:
            RATE['seen'].clear()
        got = [t for t in RATE['seen'].get(who, []) if now - t < RATE_S]
        got.append(now)
        RATE['seen'][who] = got
        return len(got) > RATE_N


def _names(v):
    if isinstance(v, list):
        return v
    try:
        got = json.loads(v or '[]')
        return got if isinstance(got, list) else []
    except ValueError:
        return []


def _hit_names(names, ql, most=3):
    """The names that hold the words first, then the rest (what is shown under a certificate)."""
    names = [str(n) for n in names]
    hit = [n for n in names if ql in n.lower()]
    return (hit + [n for n in names if n not in hit])[:most]


def certs(store, s, q, n):
    from acmelib.certs import teams as T
    ql = q.lower()
    like = _like(q)
    serial = re.sub(r'[\s:]', '', ql)
    cond = ["LOWER(name) LIKE ? ESCAPE '!'", "LOWER(COALESCE(names, '')) LIKE ? ESCAPE '!'",
            "LOWER(COALESCE(cn, '')) LIKE ? ESCAPE '!'"]
    args = [like, like, like]
    if re.fullmatch(r'[0-9a-f]{4,}', serial):
        cond += ["LOWER(COALESCE(serial, '')) LIKE ? ESCAPE '!'",
                 "LOWER(COALESCE(fingerprint, '')) LIKE ? ESCAPE '!'"]
        args += [E.like_pattern(serial) + '%', E.like_pattern(serial) + '%']
    sw, sa = T.where(store, s, 'view')
    rows = store.db.rows('SELECT id, name, cn, names, serial, owner, issuer, state, not_after FROM '
                         'certs WHERE (%s)%s ORDER BY %s LIMIT %d' % (
                             ' OR '.join(cond), sw, store.db.name_order(), n * 3),
                         tuple(args) + tuple(sa))

    def rank(r):
        nm = str(r['name'] or '').lower()
        return (0 if nm == ql else 1 if nm.startswith(ql) else 2 if ql in nm else 3, nm)
    out = []
    for r in sorted(rows, key=rank)[:n]:
        names = _names(r.get('names'))
        dl = None
        if r.get('not_after'):
            dl = int((float(r['not_after']) - time.time()) // 86400)
        out.append({'kind': 'cert', 'id': r['id'], 'name': r['name'],
                    'sub': ', '.join(_hit_names(names, ql)), 'state': r.get('state') or '',
                    'days_left': dl, 'owner': r.get('owner') or '', 'issuer': r.get('issuer') or '',
                    'serial': (r.get('serial') or '') if serial and serial in str(
                        r.get('serial') or '').lower() else ''})
    return out


def deploys(store, s, q, n):
    from acmelib.certs import teams as T
    like = _like(q)
    sw, sa = T.where(store, s, 'view', 'c.owner')
    rows = store.db.rows('SELECT d.id, d.target, d.cert_id, d.state, c.name AS cert FROM '
                         'cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE '
                         "(LOWER(d.target) LIKE ? ESCAPE '!' OR LOWER(c.name) LIKE ? ESCAPE '!')"
                         '%s ORDER BY c.name, d.target LIMIT %d' % (sw, n),
                         (like, like) + tuple(sa))
    return [{'kind': 'deploy', 'id': r['id'], 'cert_id': r['cert_id'],
             'name': '%s → %s' % (r['cert'], r['target']), 'cert': r['cert'],
             'target': r['target'], 'sub': r.get('state') or ''} for r in rows]


def targets(store, s, q, n):
    from acmelib.certs import teams as T
    like = _like(q)
    sc = T.scope(store, s, 'view')
    rows = store.db.rows("SELECT id, name, kind, config, tags, owner, enabled FROM cert_targets "
                         "WHERE LOWER(name) LIKE ? ESCAPE '!' OR LOWER(COALESCE(kind, '')) LIKE ? "
                         "ESCAPE '!' OR LOWER(COALESCE(tags, '')) LIKE ? ESCAPE '!' OR "
                         "LOWER(COALESCE(config, '')) LIKE ? ESCAPE '!' ORDER BY name LIMIT %d"
                         % (n * 6), (like, like, like, like))
    out = {'target': [], 'agent': []}
    ql = q.lower()
    for r in rows:
        if sc is not None and r.get('owner') and str(r['owner']).strip().lower() not in sc:
            continue
        try:
            cfg = json.loads(r.get('config') or '{}') or {}
        except ValueError:
            cfg = {}
        host = ''
        for k in ('host', 'hostname', 'address', 'url', 'server'):
            v = cfg.get(k) if isinstance(cfg, dict) else None
            if isinstance(v, str) and v:
                host = v[:120]
                break
        hay = ' '.join([str(r['name']), str(r.get('kind') or ''), host,
                        ' '.join(_names(r.get('tags')))]).lower()
        if ql not in hay:
            continue            # only a secret's words matched: never said
        kind = 'agent' if str(r.get('kind') or '').startswith('agent') else 'target'
        if len(out[kind]) >= n:
            continue
        out[kind].append({'kind': kind, 'id': r['id'], 'name': r['name'],
                          'sub': ' · '.join(x for x in (r.get('kind') or '', host) if x),
                          'off': not r.get('enabled', 1)})
    return out


def plugins(store, q, n, table, kind):
    like = _like(q)
    rows = store.db.rows("SELECT id, name, kind, enabled FROM %s WHERE LOWER(name) LIKE ? "
                         "ESCAPE '!' OR LOWER(COALESCE(kind, '')) LIKE ? ESCAPE '!' ORDER BY name "
                         "LIMIT %d" % (table, n), (like, like))
    return [{'kind': kind, 'id': r['id'], 'name': r['name'], 'sub': r.get('kind') or '',
             'off': not r.get('enabled', 1)} for r in rows]


def cas(store, q, n):
    like = _like(q)
    rows = store.db.rows("SELECT id, name, subject_dn, not_after FROM cert_cas WHERE LOWER(name) "
                         "LIKE ? ESCAPE '!' OR LOWER(COALESCE(subject_dn, '')) LIKE ? ESCAPE '!' "
                         "ORDER BY name LIMIT %d" % n, (like, like))
    return [{'kind': 'ca', 'id': r['id'], 'name': r['name'], 'sub': r.get('subject_dn') or ''}
            for r in rows]


def profiles(store, q, n):
    like = _like(q)
    rows = store.db.rows("SELECT id, name, description FROM cert_req_profiles WHERE LOWER(name) "
                         "LIKE ? ESCAPE '!' OR LOWER(COALESCE(description, '')) LIKE ? ESCAPE '!' "
                         "ORDER BY name LIMIT %d" % n, (like, like))
    return [{'kind': 'profile', 'id': r['id'], 'name': r['name'],
             'sub': str(r.get('description') or '')[:120]} for r in rows]


def teams(store, s, q, n):
    from acmelib.certs import teams as T
    sc = T.scope(store, s, 'view')
    ql = q.lower()
    out = []
    for t in T.team_rows(store):
        if sc is not None and t['name'].lower() not in sc:
            continue
        if ql in t['name'].lower() or ql in str(t.get('description') or '').lower():
            out.append({'kind': 'team', 'id': t.get('id'), 'name': t['name'],
                        'sub': str(t.get('description') or t.get('kind') or '')[:120]})
        if len(out) >= n:
            break
    return out


def accounts(store, s, q, n):
    if s.get('role') != 'fulladmin':
        return []
    like = _like(q)
    rows = store.db.rows("SELECT name, role, source, disabled FROM accounts WHERE LOWER(name) "
                         "LIKE ? ESCAPE '!' ORDER BY name LIMIT %d" % n, (like,))
    return [{'kind': 'account', 'id': r['name'], 'name': r['name'],
             'sub': ' · '.join(x for x in (r.get('role') or '', r.get('source') or 'local') if x),
             'off': bool(r.get('disabled'))} for r in rows]


def events(h, s, q, n):
    since = time.time() - EVENT_DAYS * 86400
    hidden = E.events_hidden_of(h.store, s)
    out = []
    at = 0
    # read in chunks, kept to what this session sees, until enough (bounded: 600 rows)
    while len(out) < n and at < 600:
        rows, _total = h.reader.events(200, at, q, '', extra=('ts >= ?', [since]))
        if not rows:
            break
        at += len(rows)
        for r in rows:
            if hidden is not None and hidden(r):
                continue
            out.append({'kind': 'event', 'id': r.get('id'), 'name': str(r.get('words') or '')[:200],
                        'sub': ' · '.join(x for x in (str(r.get('kind') or ''),
                                                      str(r.get('who') or '')) if x),
                        'at': r.get('ts'), 'level': r.get('level') or ''})
            if len(out) >= n:
                break
        if len(rows) < 200:
            break
    return out


def search(h, s, q, kinds=None, n=PER_KIND):
    """{kind: [rows]} of every kind asked for."""
    store = h.store
    kinds = [k for k in (kinds or KINDS) if k in KINDS]
    got = {}
    if 'cert' in kinds:
        got['cert'] = certs(store, s, q, n)
    if 'deploy' in kinds:
        got['deploy'] = deploys(store, s, q, n)
    if 'target' in kinds or 'agent' in kinds:
        tg = targets(store, s, q, n)
        for k in ('target', 'agent'):
            if k in kinds:
                got[k] = tg[k]
    if 'source' in kinds:
        got['source'] = plugins(store, q, n, 'cert_issuers', 'source')
    if 'ca' in kinds:
        got['ca'] = cas(store, q, n)
    if 'validation' in kinds:
        got['validation'] = plugins(store, q, n, 'cert_challenges', 'validation')
    if 'test' in kinds:
        got['test'] = plugins(store, q, n, 'cert_tests', 'test')
    if 'profile' in kinds:
        got['profile'] = profiles(store, q, n)
    if 'team' in kinds:
        got['team'] = teams(store, s, q, n)
    if 'account' in kinds:
        got['account'] = accounts(store, s, q, n)
    if 'event' in kinds:
        got['event'] = events(h, s, q, n)
    return {k: v for k, v in got.items() if v}


@A.api('GET', '/api/search')
def _search(h, s):
    q = re.sub(r'\s+', ' ', str(h.arg('q') or '')).strip()
    if len(q) > MAX_Q:
        raise E.ApiError(400, 'at most %d characters are searched for' % MAX_Q)
    if not s.get('cli') and _limited(str(s.get('name') or '?')):
        raise E.ApiError(429, 'too many searches at once - wait a moment')
    t0 = time.time()
    if not q:
        return {'q': q, 'groups': {}, 'count': 0, 'took_ms': 0}
    kinds = [k for k in re.split(r'[\s,]+', str(h.arg('kinds') or '')) if k] or None
    n = h.num('limit', PER_KIND, 1, MOST_PER_KIND)
    got = search(h, s, q, kinds, n)
    return {'q': q, 'groups': got, 'count': sum(len(v) for v in got.values()),
            'took_ms': int((time.time() - t0) * 1000)}
