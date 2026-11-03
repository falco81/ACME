# -*- coding: utf-8 -*-
"""
Tests of what the servers serve (acmelib/certs/checks.py, 1.0.32) - the card
Tests of a target, and a deployment's own tests.

    GET  /api/checks?target=&cert_id=&deploy_id=     {checks, modules, settings}
    POST /api/checks/save    {id?, deploy_id, kind, config, enabled, note}
    POST /api/checks/delete  {id}
    POST /api/checks/run     {id} -> the result at once | {target | cert_id} -> a job
    POST /api/checks/try     {deploy_id, kind, config} - run without keeping anything
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import checks as C
from acmelib.certs import store as S


def _int(v, what):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError('%s: a number' % what)


@A.api('GET', '/api/checks')
def _list(h, s):
    target = h.arg('target').strip() or None
    cert = h.arg('cert_id').strip()
    dep = h.arg('deploy_id').strip()
    rows = C.rows(h.store, target=target, cert_id=_int(cert, 'cert_id') if cert else None,
                  deploy_id=_int(dep, 'deploy_id') if dep else None)
    deps = []
    if target:
        for d in h.store.db.rows('SELECT d.id, d.cert_id, c.name FROM cert_deploys d JOIN certs c '
                                 'ON c.id = d.cert_id WHERE d.target = ? ORDER BY c.name',
                                 (target,)):
            deps.append({'id': d['id'], 'cert_id': d['cert_id'], 'cert': d['name']})
        trow = S.plugin_row(h.store, 'target', target)
        host = C.target_host(trow) if trow else ''
    else:
        host = ''
    mods = A.plugins_view(h.store).get('check', [])
    return {'checks': rows, 'deploys': deps, 'host': host, 'modules': mods,
            'settings': {k: E.CONFIG.get(k) for k in (
                'certs_checks_after_deploy', 'certs_checks_auto', 'certs_checks_every_min',
                'certs_checks_alert', 'certs_checks_warn_days')}}


@A.api('POST', '/api/checks/save', 'certadmin')
def _save(h, s):
    by = A.who(s)
    ident = C.save(h.store, h.body(), by)
    r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (ident,))
    h.store.add_event('certificates', 'test %s saved by %s' % (C.label(r), by), who=by)
    return {'ok': True, 'id': ident, 'check': C.row_public(h.store, r), 'message': 'saved'}


@A.api('POST', '/api/checks/delete', 'certadmin')
def _delete(h, s):
    b = h.body()
    ident = _int(b.get('id'), 'id')
    r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (ident,))
    C.delete(h.store, ident)
    by = A.who(s)
    if r:
        h.store.add_event('certificates', 'test %s taken away by %s' % (C.label(r), by), who=by)
    return {'ok': True, 'message': 'taken away'}


@A.api('POST', '/api/checks/run', 'certadmin')
def _run(h, s):
    from acmelib.certs import jobs
    b = h.body()
    by = A.who(s)
    if b.get('id') not in (None, '', 0):
        got = C.run(h.store, _int(b['id'], 'id'))
        r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (_int(b['id'], 'id'),))
        return {'ok': True, 'result': got, 'check': C.row_public(h.store, r)}
    if b.get('target'):
        ids = [r['id'] for r in C.rows(h.store, target=str(b['target']))
               if r.get('enabled', 1)]
        what = 'the tests of target %s' % b['target']
    elif b.get('cert_id') not in (None, '', 0):
        ids = [r['id'] for r in C.rows(h.store, cert_id=_int(b['cert_id'], 'cert_id'))
               if r.get('enabled', 1)]
        what = 'the tests of a certificate'
    else:
        ids = [r['id'] for r in C.rows(h.store) if r.get('enabled', 1)]
        what = 'every test'
    if not ids:
        raise ValueError('there is no test to run')

    def fn(job):
        return C.run_many(h.store, ids, job)
    jid = jobs.submit(h.store, 'check', fn, by=by, said='%s (%d)' % (what, len(ids)))
    return {'ok': True, 'job_id': jid, 'message': '%d test(s) started' % len(ids)}


@A.api('POST', '/api/checks/try', 'certadmin')
def _try(h, s):
    """A test as the form has it, run once and kept nowhere."""
    b = h.body()
    dep = _int(b.get('deploy_id'), 'deploy_id')
    if not h.store.db.row('SELECT id FROM cert_deploys WHERE id = ?', (dep,)):
        raise LookupError('there is no such deployment')
    kind = str(b.get('kind') or '')
    if S.plugin_class('check', kind) is None:
        raise ValueError('there is no test module "%s"' % kind)
    cfg = b.get('config') if isinstance(b.get('config'), dict) else {}
    got = C.probe(h.store, {'id': 0, 'deploy_id': dep, 'kind': kind, 'config': cfg})
    return {'ok': True, 'result': got}
