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

STATES = ('new', 'ok', 'due', 'renewing', 'failed', 'expired', 'pending', 'revoked', 'disabled',
          # 1.0.78: these were 0 ("new") in acmeManagedCertStateNum
          'revoke-failed', 'deleting', 'pending-approval', 'declined', 'held')
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


BAD_TESTS = ('old', 'other', 'answer', 'unreachable')
MODULE_TABLES = (('issuer', 'cert_issuers', 1), ('challenge', 'cert_challenges', 2),
                 ('target', 'cert_targets', 3), ('check', 'cert_tests', 4))


def _n(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _i32(v):
    return max(-2147483648, min(2147483647, _n(v)))


def deploy_rows(store):
    """Every deployment, with its certificate's name (1.0.78: monitored one by one)."""
    return store.db.rows(
        'SELECT d.id, d.cert_id, d.target, d.state, d.enabled, d.deployed_version, d.last_ok, '
        'd.last_try, d.fails, d.last_error, c.name AS cert_name FROM cert_deploys d JOIN certs c '
        'ON c.id = d.cert_id ORDER BY d.id')


def test_rows(store):
    """Every test of a certificate, with what it is and how it went last (1.0.78)."""
    return store.db.rows(
        'SELECT k.id, k.cert_id, k.test, k.enabled, k.after_target, k.last_at, k.last_ok, '
        'k.last_state, k.last_said, k.fails, c.name AS cert_name, t.kind AS kind, '
        't.enabled AS test_enabled FROM cert_checks k JOIN certs c ON c.id = k.cert_id '
        'LEFT JOIN cert_tests t ON t.name = k.test ORDER BY k.id')


def test_failing(r):
    return (r.get('last_state') or '') in BAD_TESTS and r.get('enabled', 1) != 0 and \
        r.get('test_enabled') != 0


def module_rows(store):
    out = []
    for fam, table, code in MODULE_TABLES:
        for r in store.db.rows('SELECT id, name, kind, enabled, last_ok, last_error FROM %s '
                               'ORDER BY id' % table):
            out.append(dict(r, family=fam, code=code))
    return out


def ca_rows(store):
    return store.db.rows('SELECT id, name, subject_dn, not_after, disabled, key_sealed, crl_at, '
                         'crl_days, external FROM cert_cas ORDER BY id')


def crl_next(r):
    """When the CA's CRL is to be made again (its last + its days), 0: never made."""
    if not r.get('crl_at') or r.get('external'):
        return 0
    return int(float(r['crl_at']) + 86400 * _n(r.get('crl_days'), 7))


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
    alts = store.db.rows("SELECT name, alt_not_after FROM certs WHERE alt_not_after IS NOT NULL "
                         "AND COALESCE(enabled, 1) <> 0 AND key_type_alt IS NOT NULL AND "
                         "key_type_alt <> '' ORDER BY name")
    deps_all = deploy_rows(store)
    tests_all = test_rows(store)
    mods = module_rows(store)
    cas = ca_rows(store)
    running = int(store.db.value("SELECT COUNT(*) FROM cert_jobs WHERE finished IS NULL", (), 0)
                  or 0)
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
        # gauges (1.0.88): counted from the jobs kept, which are pruned - as counters they went
        # down, and Prometheus took each drop for a restart; the first issues are jobs of their own
        ('acme_cert_renewals_total', 'Renewals (and first issues) in the jobs kept, by result',
         'gauge', [({'result': res}, jobs_ok.get(('renew', res), 0) + jobs_ok.get(('issue', res), 0))
                   for res in ('ok', 'failed')]),
        ('acme_cert_deployments_total', 'Deployment jobs in the jobs kept, by result', 'gauge',
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
        # 1.0.78: the twin of a dual certificate, each deployment, each test, each module,
        # each authority of acme's own - what the pages show, one by one
        ('acme_cert_alt_not_after_timestamp_seconds', 'When the twin of each dual certificate '
         '(the other key type) ends (unix time)', 'gauge',
         [({'name': r['name']}, int(float(r['alt_not_after']))) for r in alts]),
        ('acme_cert_deploy_state', 'Each deployment\'s state (1 for the state it is in)', 'gauge',
         [({'cert': r['cert_name'], 'target': r['target'], 'state': r.get('state') or 'new',
            'enabled': '0' if r.get('enabled') == 0 else '1'}, 1) for r in deps_all]),
        ('acme_cert_deploy_last_ok_timestamp_seconds', 'When each deployment last went through '
         '(unix time)', 'gauge',
         [({'cert': r['cert_name'], 'target': r['target']}, float(r['last_ok']))
          for r in deps_all if r.get('last_ok')]),
        ('acme_cert_test_state', 'Each test of a certificate: how it went last (1 for that state; '
         '"none": not run yet)', 'gauge',
         [({'cert': r['cert_name'], 'test': r['test'], 'kind': r.get('kind') or '',
            'state': r.get('last_state') or 'none',
            'enabled': '0' if r.get('enabled') == 0 or r.get('test_enabled') == 0 else '1'}, 1)
          for r in tests_all]),
        ('acme_cert_test_last_timestamp_seconds', 'When each test last ran (unix time)', 'gauge',
         [({'cert': r['cert_name'], 'test': r['test']}, float(r['last_at']))
          for r in tests_all if r.get('last_at')]),
        ('acme_cert_tests_failing', 'Tests (switched on) whose last run failed', 'gauge',
         [({}, sum(1 for r in tests_all if test_failing(r)))]),
        ('acme_module_failing', 'Each source, validation, target and test module: 1 when its last '
         'use failed', 'gauge',
         [({'family': r['family'], 'name': r['name'], 'kind': r.get('kind') or '',
            'enabled': '0' if r.get('enabled') == 0 else '1'}, 1 if r.get('last_error') else 0)
          for r in mods]),
        ('acme_ca_not_after_timestamp_seconds', 'When each authority of acme\'s own ends (unix '
         'time)', 'gauge',
         [({'name': r['name']}, int(float(r['not_after']))) for r in cas if r.get('not_after')]),
        ('acme_ca_crl_next_timestamp_seconds', 'When each authority\'s CRL is due again (unix '
         'time)', 'gauge',
         [({'name': r['name']}, crl_next(r)) for r in cas if crl_next(r)]),
        ('acme_cert_jobs_running', 'Certificate jobs queued or running now', 'gauge',
         [({}, running)]),
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
    # the targets with acme-agent (1.0.116) - only where there is one
    ags = agent_rows(store)
    if ags:
        out += [
            ('acme_agent_up', 'Each target\'s acme-agent: 1 when heard from lately', 'gauge',
             [({'target': a['name'], 'mode': a.get('mode') or ''},
               1 if a.get('state') == 'answers' else 0) for a in ags]),
            ('acme_agent_state', 'Each target\'s acme-agent: 1 for the state it is in', 'gauge',
             [({'target': a['name'], 'state': a.get('state') or 'new'}, 1) for a in ags]),
            ('acme_agent_last_seen_timestamp_seconds', 'When each agent was last heard from '
             '(unix time)', 'gauge',
             [({'target': a['name']}, float(a['last_seen'])) for a in ags if a.get('last_seen')]),
            ('acme_agent_cert_not_after_timestamp_seconds', 'When each agent\'s certificate of '
             'acme\'s agent authority ends (unix time)', 'gauge',
             [({'target': a['name']}, int(float(a['cert_end']))) for a in ags
              if a.get('cert_end')]),
            ('acme_agent_info', 'Each agent\'s version (1)', 'gauge',
             [({'target': a['name'], 'version': a.get('version') or ''}, 1) for a in ags
              if a.get('version')]),
            ('acme_agent_update_available', 'Whether this acme offers a newer agent', 'gauge',
             [({'target': a['name']}, 1 if (a.get('update') or {}).get('newer') else 0)
              for a in ags if a.get('joined')]),
            ('acme_agent_policy_blocks', 'Whether the agent\'s policy refused the last '
             'deployment', 'gauge',
             [({'target': a['name']}, 1 if a.get('blocked') else 0) for a in ags
              if a.get('joined')]),
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
#                 11 keyType, 12 keyTypeAlt, 13 altNotAfter, 14 altDaysLeft, 15 testsFailed (1.0.78)
#   6.3.N.0       ... 11 tests, 12 tests failing, 13 jobs running, 14 modules failing,
#                 15 authorities ending within 90 days, 16 deployments (1.0.78)
#   6.4.1.C.<id>  acmeDeployEntry: 1 index (the deployment's id), 2 certId, 3 cert, 4 target,
#                 5 state, 6 enabled, 7 deployedVersion, 8 lastOk, 9 lastTry, 10 fails, 11 lastError
#   6.5.1.C.<id>  acmeTestEntry: 1 index (the test of a certificate's id), 2 certId, 3 cert,
#                 4 test, 5 kind, 6 state, 7 enabled, 8 after, 9 lastAt, 10 lastOk, 11 fails, 12 said
#   6.6.1.C.<n>   acmeModuleEntry: 1 index (family * 1000000 + id: 1 source, 2 validation,
#                 3 target, 4 test), 2 family, 3 name, 4 kind, 5 enabled, 6 lastOk, 7 lastError
#   6.7.1.C.<id>  acmeCaEntry: 1 index, 2 name, 3 subject, 4 notAfter, 5 daysLeft, 6 enabled,
#                 7 signs (has its key), 8 crlNext
# 1.0.108: 6.2 16 owner, 17 source, 18 lastOk, 19 lastTry, 20 fails, 21 lastError, 22 nextTry,
#          23 version, 24 serial, 25 deploys, 26 tests, 27 notBefore, 28 names, 29 state (enum);
#          6.3 17 jobs ok (24 h), 18 last scan, 19 revoked, 20 pending approval, 21 renewals
#          failed (24 h), 22 renewals ok (24 h), 23 deployments ok (24 h), 24 deployments
#          failed (24 h); 6.4 12 state as a number; 6.5 13 state as a number; 6.6 8 failing;
#          6.7 9 external, 10 hours until the CRL is due; 6.8 acme's own DNS server
# 1.0.116: 6.9.1.C.<id> acmeAgentEntry: 1 index (the target's id), 2 name, 3 mode, 4 state,
#          5 lastSeen, 6 certDaysLeft, 7 version, 8 stateNum, 9 newer, 10 blocked
SNMP_TABLE = (6, 2, 1)
SNMP_COUNTS = (6, 3)
SNMP_DEPLOYS = (6, 4, 1)
SNMP_TESTS = (6, 5, 1)
SNMP_MODULES = (6, 6, 1)
SNMP_CAS = (6, 7, 1)
SNMP_DNS = (6, 8)
SNMP_AGENTS = (6, 9, 1)         # 1.0.116: acmeAgentEntry - the targets with acme-agent
AGENT_STATES = ('new', 'answers', 'quiet', 'refused', 'joining', 'off')
TEST_STATES = ('', 'ok', 'warn', 'old', 'other', 'answer', 'unreachable')


def snmp_rows(store):
    t = time.time()
    rows = store.db.rows("SELECT id, name, cn, issuer, state, not_after, auto_renew, key_type, "
                         "key_type_alt, alt_not_after, owner, source, last_ok, last_try, fails, "
                         "last_error, next_try, version, serial, not_before, names FROM certs "
                         "WHERE COALESCE(enabled, 1) <> 0 ORDER BY id")
    tests_all = test_rows(store)
    tfail = {}
    tests_on = {}
    for r in tests_all:
        if test_failing(r):
            tfail[int(r['cert_id'])] = tfail.get(int(r['cert_id']), 0) + 1
        if r.get('enabled') != 0 and r.get('test_enabled') != 0:
            tests_on[int(r['cert_id'])] = tests_on.get(int(r['cert_id']), 0) + 1
    deps_on = {}
    for r in store.db.rows("SELECT cert_id, COUNT(*) AS n FROM cert_deploys WHERE "
                           "COALESCE(enabled, 1) <> 0 GROUP BY cert_id"):
        deps_on[int(r['cert_id'])] = int(r['n'])
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
                (T + (4, i), 'int', min(int(na or 0), 2147483647)),   # Integer32 (1.0.52)
                (T + (5, i), 'int', int((na - t) // 86400) if na else 0),
                (T + (6, i), 'str', st), (T + (7, i), 'str', str(r.get('issuer') or '')[:255]),
                (T + (8, i), 'int', STATE_NUM.get(st, 0)),
                (T + (9, i), 'int', 1 if r.get('auto_renew') else 0),
                (T + (10, i), 'gauge', failed_by.get(i, 0)),
                # 1.0.78: its key, the twin of a dual one, its tests failing
                (T + (11, i), 'str', str(r.get('key_type') or '')),
                (T + (12, i), 'str', str(r.get('key_type_alt') or '')),
                (T + (13, i), 'int', _i32(r.get('alt_not_after') or 0)),
                (T + (14, i), 'int', int((float(r['alt_not_after']) - t) // 86400)
                 if r.get('alt_not_after') else 0),
                (T + (15, i), 'gauge', tfail.get(i, 0)),
                # 1.0.108: whose it is, how it came, its last renewal and failures, its serial
                (T + (16, i), 'str', str(r.get('owner') or '')[:255]),
                (T + (17, i), 'str', str(r.get('source') or '')[:255]),
                (T + (18, i), 'int', _i32(r.get('last_ok') or 0)),
                (T + (19, i), 'int', _i32(r.get('last_try') or 0)),
                (T + (20, i), 'gauge', max(0, _n(r.get('fails')))),
                (T + (21, i), 'str', E.detail_redact(str(r.get('last_error') or ''))[:255]),
                (T + (22, i), 'int', _i32(r.get('next_try') or 0)),
                (T + (23, i), 'int', _i32(r.get('version') or 0)),
                (T + (24, i), 'str', str(r.get('serial') or '')[:255]),
                (T + (25, i), 'gauge', deps_on.get(i, 0)),
                (T + (26, i), 'gauge', tests_on.get(i, 0)),
                (T + (27, i), 'int', _i32(r.get('not_before') or 0)),
                (T + (28, i), 'gauge', len(S.jload(r.get('names'), []) or [])),
                (T + (29, i), 'int', STATE_NUM.get(st, 0))]
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
    deps_all = deploy_rows(store)
    mods = module_rows(store)
    cas = ca_rows(store)
    ends = 90 * 86400
    out += [(C + (11, 0), 'gauge', len(tests_all)),
            (C + (12, 0), 'gauge', sum(tfail.values())),
            (C + (13, 0), 'gauge', int(store.db.value(
                "SELECT COUNT(*) FROM cert_jobs WHERE finished IS NULL", (), 0) or 0)),
            (C + (14, 0), 'gauge', sum(1 for r in mods if r.get('last_error') and
                                        r.get('enabled') != 0)),
            (C + (15, 0), 'gauge', sum(1 for r in cas if r.get('not_after') and not r.get('disabled')
                                        and float(r['not_after']) < t + ends)),
            (C + (16, 0), 'gauge', len(deps_all))]
    # 1.0.108: the jobs of the last 24 hours by what and how, the last scan, the revoked and
    # those waiting for an approval
    day = {}
    for r in store.db.rows('SELECT kind, ok, COUNT(*) AS n FROM cert_jobs WHERE ts > ? AND '
                           'finished IS NOT NULL GROUP BY kind, ok', (t - 86400,)):
        day[(r['kind'], bool(r['ok']))] = day.get((r['kind'], bool(r['ok'])), 0) + int(r['n'])
    scan = S.jload(store.get_meta('certs:last_scan'), None) or {}
    out += [(C + (17, 0), 'gauge', sum(n for (k, ok), n in day.items() if ok)),
            (C + (18, 0), 'int', _i32(scan.get('at') or 0)),
            (C + (19, 0), 'gauge', c.get('revoked', 0)),
            (C + (20, 0), 'gauge', c.get('pending-approval', 0)),
            (C + (21, 0), 'gauge', day.get(('renew', False), 0) + day.get(('issue', False), 0)),
            (C + (22, 0), 'gauge', day.get(('renew', True), 0) + day.get(('issue', True), 0)),
            (C + (23, 0), 'gauge', day.get(('deploy', True), 0)),
            (C + (24, 0), 'gauge', day.get(('deploy', False), 0))]
    # 6.8 acme's own DNS server, this node's
    D8 = SNMP_DNS
    stats = st.get('stats') or {}
    on = bool(E.CONFIG.get('dns_server'))
    out += [(D8 + (1, 0), 'int', 1 if on else 0),
            (D8 + (2, 0), 'int', 1 if on and (st.get('ok') or (st.get('running') and
                                                              st.get('listening'))) else 0),
            (D8 + (3, 0), 'gauge', _n(st.get('records'))),
            (D8 + (4, 0), 'counter', _n(stats.get('answered'))),
            (D8 + (5, 0), 'counter', _n(stats.get('refused'))),
            (D8 + (6, 0), 'counter', sum(_n(stats.get(k)) for k in ('servfail', 'formerr', 'notimp'))),
            (D8 + (7, 0), 'counter', sum(_n(stats.get(k)) for k in ('rate_limited', 'dropped')))]
    # 6.4 deployments, 6.5 tests, 6.6 modules, 6.7 authorities (1.0.78)
    for r in deps_all:
        i = int(r['id'])
        D = SNMP_DEPLOYS
        out += [(D + (1, i), 'int', i), (D + (2, i), 'int', int(r['cert_id'])),
                (D + (3, i), 'str', str(r['cert_name'])[:255]),
                (D + (4, i), 'str', str(r.get('target') or '')[:255]),
                (D + (5, i), 'str', str(r.get('state') or 'new')),
                (D + (6, i), 'int', 0 if r.get('enabled') == 0 else 1),
                (D + (7, i), 'int', _i32(r.get('deployed_version') or 0)),
                (D + (8, i), 'int', _i32(r.get('last_ok') or 0)),
                (D + (9, i), 'int', _i32(r.get('last_try') or 0)),
                (D + (10, i), 'gauge', max(0, _n(r.get('fails')))),
                (D + (11, i), 'str', E.detail_redact(str(r.get('last_error') or ''))[:255]),
                (D + (12, i), 'int', DEPLOY_STATES.index(r.get('state')) if r.get('state') in
                 DEPLOY_STATES else 0)]
    for r in tests_all:
        i = int(r['id'])
        K = SNMP_TESTS
        after = [x for x in str(r.get('after_target') or '').split('\n') if x.strip()]
        out += [(K + (1, i), 'int', i), (K + (2, i), 'int', int(r['cert_id'])),
                (K + (3, i), 'str', str(r['cert_name'])[:255]),
                (K + (4, i), 'str', str(r.get('test') or '')[:255]),
                (K + (5, i), 'str', str(r.get('kind') or '')),
                (K + (6, i), 'str', str(r.get('last_state') or '')),
                (K + (7, i), 'int', 0 if r.get('enabled') == 0 or r.get('test_enabled') == 0 else 1),
                (K + (8, i), 'str', ('any' if not after else ','.join(after))[:255]),
                (K + (9, i), 'int', _i32(r.get('last_at') or 0)),
                (K + (10, i), 'int', _i32(r.get('last_ok') or 0)),
                (K + (11, i), 'gauge', max(0, _n(r.get('fails')))),
                (K + (12, i), 'str', E.detail_redact(str(r.get('last_said') or ''))[:255]),
                (K + (13, i), 'int', TEST_STATES.index(r.get('last_state') or '') if
                 (r.get('last_state') or '') in TEST_STATES else 0)]
    for r in mods:
        i = r['code'] * 1000000 + int(r['id'])
        M = SNMP_MODULES
        out += [(M + (1, i), 'int', i), (M + (2, i), 'str', r['family']),
                (M + (3, i), 'str', str(r['name'])[:255]), (M + (4, i), 'str', str(r.get('kind') or '')),
                (M + (5, i), 'int', 0 if r.get('enabled') == 0 else 1),
                (M + (6, i), 'int', _i32(r.get('last_ok') or 0)),
                (M + (7, i), 'str', E.detail_redact(str(r.get('last_error') or ''))[:255]),
                (M + (8, i), 'int', 1 if r.get('last_error') else 0)]
    for r in cas:
        i = int(r['id'])
        A = SNMP_CAS
        na = _i32(r.get('not_after') or 0)
        out += [(A + (1, i), 'int', i), (A + (2, i), 'str', str(r['name'])[:255]),
                (A + (3, i), 'str', str(r.get('subject_dn') or '')[:255]),
                (A + (4, i), 'int', na),
                (A + (5, i), 'int', int((float(r['not_after']) - t) // 86400) if r.get('not_after') else 0),
                (A + (6, i), 'int', 0 if r.get('disabled') else 1),
                (A + (7, i), 'int', 1 if r.get('key_sealed') else 0),
                (A + (8, i), 'int', _i32(crl_next(r))),
                (A + (9, i), 'int', 1 if r.get('external') else 0),
                (A + (10, i), 'int', _i32((crl_next(r) - t) // 3600) if crl_next(r) else 0)]
    # 6.9 the targets with acme-agent (1.0.116) - none: nothing here
    for a in agent_rows(store):
        i = int(a['id'])
        G = SNMP_AGENTS
        end = float(a.get('cert_end') or 0)
        out += [(G + (1, i), 'int', i), (G + (2, i), 'str', str(a['name'])[:255]),
                (G + (3, i), 'str', str(a.get('mode') or '')),
                (G + (4, i), 'str', str(a.get('state') or 'new')),
                (G + (5, i), 'int', _i32(a.get('last_seen') or 0)),
                (G + (6, i), 'int', int((end - t) // 86400) if end else 0),
                (G + (7, i), 'str', str(a.get('version') or '')[:64]),
                (G + (8, i), 'int', AGENT_STATES.index(a['state']) if a.get('state') in
                 AGENT_STATES else 0),
                (G + (9, i), 'int', 1 if (a.get('update') or {}).get('newer') else 0),
                (G + (10, i), 'int', 1 if a.get('blocked') else 0)]
    return out


def agent_rows(store):
    """Each target with acme-agent as the pages show it (agents.info) - [] without one."""
    if not store.db.value("SELECT COUNT(*) FROM cert_targets WHERE kind IN ('agent', "
                          "'agent_windows')", (), 0):
        return []
    from acmelib.certs import agents
    out = []
    for r in agents.rows(store):
        try:
            out.append(agents.info(store, r))
        except Exception:                               # noqa: BLE001
            out.append({'id': r['id'], 'name': r['name'], 'state': 'new'})
    return out


# ---------------------------------------------------------------------------
# The fields of the renewer's events, for isemon and the SIEM
# ---------------------------------------------------------------------------
PATTERNS = [
    (re.compile(r'^(?P<cert>\S.*?) (?P<a>renewed|issued) \(version (?P<version>\d+), until '
                r'(?P<until>[^)]*)\)\Z'), {'result': 'ok'}),
    (re.compile(r'^renewing (?P<cert>\S.*?) failed: (?P<error>.*)\Z', re.S),
     {'action': 'renew', 'result': 'failed'}),
    (re.compile(r'^issuing (?P<cert>\S.*?) failed: (?P<error>.*)\Z', re.S),
     {'action': 'issue', 'result': 'failed'}),
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
# the targets with acme-agent (1.0.116): action=agent_... target=NAME (isemon, the SIEM) - a
# target's name may hold spaces ("web two"): it is matched up to the words after it
AGENT_PATTERNS = [
    (re.compile(r'^the policy of the agent of target (?P<target>.+?) blocks a deployment: '
                r'(?P<what>.*?) - allow it', re.S),
     {'action': 'agent_policy_blocks', 'result': 'failed'}),
    (re.compile(r'^the policy of the agent of target (?P<target>.+?) changed on the target'),
     {'action': 'agent_policy_changed', 'result': 'ok'}),
    (re.compile(r'^the agent of target (?P<target>.+?) has not been heard from'),
     {'action': 'agent_quiet', 'result': 'warn'}),
    (re.compile(r'^the agent of target (?P<target>.+?) is heard from again'),
     {'action': 'agent_back', 'result': 'ok'}),
    (re.compile(r'^the agent of target (?P<target>.+?) was updated to (?P<version>[0-9.]+)'),
     {'action': 'agent_updated', 'result': 'ok'}),
    (re.compile(r'^the agent of target (?P<target>.+?) was not updated to (?P<version>[0-9.]+)'),
     {'action': 'agent_update', 'result': 'failed'}),
    (re.compile(r'^the certificate of the agent of target (?P<target>.+?) was renewed'),
     {'action': 'agent_cert_renewed', 'result': 'ok'}),
    (re.compile(r'^the agent of target (?P<target>.+?) joined acme'),
     {'action': 'agent_joined', 'result': 'ok'}),
    (re.compile(r'^the agent of target (?P<target>.+?) was forgotten'),
     {'action': 'agent_forgotten', 'result': 'ok'}),
    # 1.0.118: the policy designed in acme (documentation only)
    (re.compile(r'^the policy design of the agent of target (?P<target>.+?) was saved by'),
     {'action': 'agent_design_saved', 'result': 'ok'}),
    (re.compile(r'^the policy design of the agent of target (?P<target>.+?) was deleted by'),
     {'action': 'agent_design_deleted', 'result': 'ok'}),
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
    for rx, extra in AGENT_PATTERNS:
        m = rx.match(w)
        if m:
            g = m.groupdict()
            out = dict(extra, target=g['target'], target_kind='agent')
            if g.get('version'):
                out['version'] = g['version']
            if g.get('what'):
                out['blocked'] = g['what'][:300]
            return out
    return {}
