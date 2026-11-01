# -*- coding: utf-8 -*-
"""
What the certificate manager tells the monitoring (docs/monitoring.md):

    metrics(store)      Prometheus (HOOKS['metrics'], https://NODE/metrics) -
                        and so the acmeMetricTable of SNMP, which carries every sample
    snmp_rows(store)    SNMP (HOOKS['snmp']): acmeManagedCertTable and the counts
                        under acmeCertificates (deploy/ACME-MIB.txt)
    event_fields(kind, words, level)
                        HOOKS['event_fields']: the fields of an event of the
                        renewer's (cert, names, serial, not_after, issuer, action,
                        result), read out of its words, for isemon and the SIEM

The alerts are the renewer's (HOOKS['alerts']).
"""
from __future__ import annotations

import re
import time

from acmelib import engine as E
from acmelib.certs import store as S

STATES = ('new', 'ok', 'due', 'renewing', 'failed', 'expired', 'pending', 'revoked', 'disabled')
DEPLOY_STATES = ('new', 'ok', 'changed', 'deploying', 'failed')
STATE_NUM = {s: i for i, s in enumerate(STATES)}


def _leader(store):
    try:
        from acmelib.certs import renewer
        return renewer.leader(store) or {}
    except Exception:                                   # noqa: BLE001
        return {}


def _dns_state():
    try:
        import sys
        r = sys.modules.get('acmelib.certs.renewer')
        rr = r.RENEWER[0] if r is not None else None
        if rr is None or not E.CONFIG.get('dns_server'):
            return None
        return rr.dns_state()
    except Exception:                                   # noqa: BLE001
        return None


def counts(store):
    out = {s: 0 for s in STATES}
    for r in store.db.rows('SELECT state, COUNT(*) AS n FROM certs GROUP BY state'):
        out[r['state'] or 'new'] = int(r['n'])
    return out


def metrics(store):
    """[(name, help, type, [(labels, value)])] - HOOKS['metrics']."""
    t = time.time()
    c = counts(store)
    rows = store.db.rows("SELECT id, name, cn, issuer, state, not_after, auto_renew FROM certs "
                         "WHERE COALESCE(enabled, 1) <> 0 ORDER BY name")
    dated = [r for r in rows if r.get('not_after')]
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    deps = {s: 0 for s in DEPLOY_STATES}
    for r in store.db.rows('SELECT state, COUNT(*) AS n FROM cert_deploys WHERE '
                           'COALESCE(enabled, 1) <> 0 GROUP BY state'):
        deps[r['state'] or 'new'] = int(r['n'])
    jobs_ok = {}
    for r in store.db.rows('SELECT kind, ok, COUNT(*) AS n FROM cert_jobs WHERE finished IS NOT '
                           'NULL GROUP BY kind, ok'):
        jobs_ok[(r['kind'], 'ok' if r['ok'] else 'failed')] = int(r['n'])
    day = {}
    for r in store.db.rows('SELECT kind, ok, COUNT(*) AS n FROM cert_jobs WHERE ts > ? AND '
                           'finished IS NOT NULL GROUP BY kind, ok', (t - 86400,)):
        day[(r['kind'], 'ok' if r['ok'] else 'failed')] = int(r['n'])
    last = store.db.rows('SELECT kind, ok, MAX(finished) AS at FROM cert_jobs WHERE finished IS '
                         'NOT NULL GROUP BY kind, ok')
    lead = _leader(store)
    scan = S.jload(store.get_meta('certs:last_scan'), None) or {}
    me = E.node_name()
    out = [
        ('acme_certs', 'Certificates kept, by state', 'gauge',
         [({'state': s}, n) for s, n in sorted(c.items())]),
        ('acme_cert_expiry_seconds', 'Seconds until each certificate ends', 'gauge',
         [({'name': r['name']}, round(float(r['not_after']) - t)) for r in dated]),
        ('acme_cert_not_after_timestamp_seconds', 'When each certificate ends (unix time)',
         'gauge', [({'name': r['name'], 'cn': r.get('cn') or '', 'issuer': r.get('issuer') or
                     'imported'}, int(float(r['not_after']))) for r in dated]),
        ('acme_cert_state', 'Each certificate\'s state (1 for the state it is in)', 'gauge',
         [({'name': r['name'], 'state': r.get('state') or 'new'}, 1) for r in rows]),
        ('acme_cert_expiring', 'Certificates that end within certs_notify_days', 'gauge',
         [({}, sum(1 for r in dated if t < float(r['not_after']) < t + days * 86400))]),
        ('acme_cert_renewals_total', 'Renewals (and first issues) in the jobs kept, by result',
         'counter', [({'result': res}, jobs_ok.get(('renew', res), 0))
                     for res in ('ok', 'failed')]),
        ('acme_cert_deployments_total', 'Deployment jobs in the jobs kept, by result', 'counter',
         [({'result': res}, jobs_ok.get(('deploy', res), 0)) for res in ('ok', 'failed')]),
        ('acme_cert_jobs_24h', 'Certificate jobs of the last 24 hours, by kind and result',
         'gauge', [({'kind': k, 'result': res}, n) for (k, res), n in sorted(day.items())]),
        ('acme_cert_deploys', 'Deployments, by state', 'gauge',
         [({'state': s}, n) for s, n in sorted(deps.items())]),
        ('acme_cert_deploys_failed', 'Deployments whose last try failed', 'gauge',
         [({}, deps.get('failed', 0))]),
        ('acme_cert_jobs_failed_24h', 'Certificate jobs that failed in the last 24 hours',
         'gauge', [({}, sum(n for (k, res), n in day.items() if res == 'failed'))]),
        ('acme_cert_last_job_timestamp_seconds', 'When the last job of each kind ended, by '
         'result (unix time)', 'gauge',
         [({'kind': r['kind'], 'result': 'ok' if r['ok'] else 'failed'}, float(r['at']))
          for r in last if r.get('at')]),
        ('acme_cert_last_scan_timestamp_seconds', 'When the leader last looked for what is due '
         '(unix time)', 'gauge',
         [({'node': scan.get('node') or ''}, float(scan['at']))] if scan.get('at') else []),
        ('acme_cert_leader', 'Whether this node renews and deploys (1) or not (0)', 'gauge',
         [({'node': me}, 1 if lead.get('me') else 0)]),
        ('acme_cert_leader_info', 'The node that renews and deploys now', 'gauge',
         [({'node': lead.get('node')}, 1)] if lead.get('node') else []),
    ]
    st = _dns_state()
    if st is not None:
        stats = st.get('stats') or {}
        out += [
            ('acme_dns_up', 'Whether acme\'s own DNS server answers on this node', 'gauge',
             [({}, 1 if st.get('ok') or (st.get('running') and st.get('listening')) else 0)]),
            ('acme_dns_queries_total', 'Queries acme\'s own DNS server was asked on this node, '
             'by protocol', 'counter',
             [({'proto': p}, int(stats.get(p) or 0)) for p in ('udp', 'tcp')]),
            ('acme_dns_answers_total', 'Its answers, by kind', 'counter',
             [({'rcode': k}, int(stats.get(k) or 0)) for k in
              ('answered', 'nxdomain', 'refused', 'servfail', 'formerr', 'notimp',
               'rate_limited', 'dropped') if k in stats]),
            ('acme_dns_records', 'Records it answers with', 'gauge',
             [({}, int(st.get('records') or 0))]),
        ]
    return out


# ---------------------------------------------------------------------------
# SNMP: under acmeCertificates (acme 6) - 6.1 is the engine's, of the pages
# ---------------------------------------------------------------------------
#   6.2.1.C.<id>  acmeManagedCertEntry: 1 index (the certificate's id), 2 name, 3 cn,
#                 4 notAfter (unix time), 5 daysLeft, 6 state, 7 issuer, 8 stateNum,
#                 9 autoRenew, 10 deploysFailed
#   6.3.N.0       counts: 1 total, 2 ok, 3 failed, 4 expired, 5 expiring soon,
#                 6 deployments failed, 7 this node leads, 8 jobs failed (24 h),
#                 9 DNS queries (this node), 10 renewing / due / new
SNMP_TABLE = (6, 2, 1)
SNMP_COUNTS = (6, 3)


def snmp_rows(store):
    t = time.time()
    rows = store.db.rows("SELECT id, name, cn, issuer, state, not_after, auto_renew FROM certs "
                         "WHERE COALESCE(enabled, 1) <> 0 ORDER BY id")
    failed_by = {}
    for r in store.db.rows("SELECT cert_id, COUNT(*) AS n FROM cert_deploys WHERE state = "
                           "'failed' AND COALESCE(enabled, 1) <> 0 GROUP BY cert_id"):
        failed_by[int(r['cert_id'])] = int(r['n'])
    out = []
    for r in rows:
        i = int(r['id'])
        na = int(float(r['not_after'])) if r.get('not_after') else 0
        st = r.get('state') or 'new'
        T = SNMP_TABLE
        out += [(T + (1, i), 'int', i), (T + (2, i), 'str', str(r['name'])[:255]),
                (T + (3, i), 'str', str(r.get('cn') or '')[:255]),
                (T + (4, i), 'int', na),
                (T + (5, i), 'int', int((na - t) // 86400) if na else 0),
                (T + (6, i), 'str', st), (T + (7, i), 'str', str(r.get('issuer') or '')[:255]),
                (T + (8, i), 'int', STATE_NUM.get(st, 0)),
                (T + (9, i), 'int', 1 if r.get('auto_renew') else 0),
                (T + (10, i), 'gauge', failed_by.get(i, 0))]
    c = counts(store)
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    soon = sum(1 for r in rows if r.get('not_after') and
               t < float(r['not_after']) < t + days * 86400)
    dfail = int(store.db.value("SELECT COUNT(*) FROM cert_deploys WHERE state = 'failed' AND "
                               "COALESCE(enabled, 1) <> 0", (), 0) or 0)
    jfail = int(store.db.value('SELECT COUNT(*) FROM cert_jobs WHERE ok = 0 AND ts > ?',
                               (t - 86400,), 0) or 0)
    st = _dns_state() or {}
    C = SNMP_COUNTS
    out += [(C + (1, 0), 'gauge', sum(c.values())), (C + (2, 0), 'gauge', c.get('ok', 0)),
            (C + (3, 0), 'gauge', c.get('failed', 0)), (C + (4, 0), 'gauge', c.get('expired', 0)),
            (C + (5, 0), 'gauge', soon), (C + (6, 0), 'gauge', dfail),
            (C + (7, 0), 'int', 1 if _leader(store).get('me') else 0),
            (C + (8, 0), 'gauge', jfail),
            (C + (9, 0), 'counter', int((st.get('stats') or {}).get('queries') or 0)),
            (C + (10, 0), 'gauge', c.get('renewing', 0) + c.get('due', 0) + c.get('new', 0))]
    return out


# ---------------------------------------------------------------------------
# The fields of the renewer's events, for isemon and the SIEM
# ---------------------------------------------------------------------------
PATTERNS = [
    (re.compile(r'^(?P<cert>\S.*?) (?P<a>renewed|issued) \(version (?P<version>\d+), until '
                r'(?P<until>[^)]*)\)\Z'), {'result': 'ok'}),
    (re.compile(r'^renewing (?P<cert>\S.*?) failed: (?P<error>.*)\Z', re.S),
     {'action': 'renew', 'result': 'failed'}),
    (re.compile(r'^(?P<cert>\S.*?) has expired\Z'), {'action': 'expired', 'result': 'expired'}),
    (re.compile(r'^(?P<cert>\S.*?) ends in (?P<left>.+?)( and is not renewed by itself)?\Z'),
     {'action': 'expiring', 'result': 'warn'}),
    (re.compile(r'^(?P<cert>\S.*?) revoked \((?P<reason>[^)]*)\) by'),
     {'action': 'revoked', 'result': 'ok'}),
    (re.compile(r'^(?P<cert>\S.*?) \(version (?P<version>\d+)\) deployed to (?P<target>.+)\Z'),
     {'action': 'deployed', 'result': 'ok'}),
    (re.compile(r'^deploying (?P<cert>\S.*?) to (?P<target>.+?) failed: (?P<error>.*)\Z', re.S),
     {'action': 'deploy', 'result': 'failed'}),
    (re.compile(r'^certificate (?P<cert>\S.*?) (?P<a>added|changed|deleted|imported) by'),
     {'result': 'ok'}),
]


def fields_of(store, cert, **more):
    """The fields of an event about one certificate (a row or a name)."""
    row = cert if isinstance(cert, dict) else (S.cert_get(store, cert) if cert else None)
    out = {}
    if row:
        out = {'cert': row.get('name'), 'serial': row.get('serial'),
               'names': ','.join(S.jload(row.get('names'), []) or [])
               if not isinstance(row.get('names'), list) else ','.join(row['names']),
               'issuer': row.get('issuer') or '',
               'not_after': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(
                   float(row['not_after']))) if row.get('not_after') else ''}
    elif cert:
        out['cert'] = str(cert)
    out.update({k: v for k, v in more.items() if v not in (None, '')})
    return out


def event_fields(kind, words, level):
    if kind != 'certificates':
        return {}
    w = str(words or '')
    for rx, extra in PATTERNS:
        m = rx.match(w)
        if not m:
            continue
        g = m.groupdict()
        more = dict(extra)
        if g.get('a'):
            more['action'] = g['a']
        for k in ('version', 'target', 'reason'):
            if g.get(k):
                more[k] = g[k]
        store = E.HA_STORE.get('store')
        try:
            return fields_of(store, g['cert'], **more) if store is not None else \
                dict(more, cert=g['cert'])
        except Exception:                               # noqa: BLE001
            return dict(more, cert=g['cert'])
    return {}
