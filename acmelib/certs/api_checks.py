# -*- coding: utf-8 -*-
"""
Tests attached to certificates (acmelib/certs/checks.py, 1.0.32). The tests
themselves are defined as targets are: /api/tests (api.py's family routes,
family 'check', table cert_tests).

    GET  /api/checks?cert_id=&test=        {checks, settings}
    POST /api/checks/attach   {cert_id, tests: [name...]}
    POST /api/checks/detach   {id}
    POST /api/checks/switch   {id, enabled}
    POST /api/checks/run      {id} -> the result at once | {cert_id | test | all} -> a job
    POST /api/checks/try      {cert_id, kind, config} - a test as its form has it, kept nowhere
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


SETTINGS = ('certs_checks_after_deploy', 'certs_checks_auto', 'certs_checks_every_min',
            'certs_checks_alert', 'certs_checks_warn_days')


@A.api('GET', '/api/checks')
def _list(h, s):
    cert = h.arg('cert_id').strip()
    rows = C.rows(h.store, cert_id=_int(cert, 'cert_id') if cert else None,
                  test=h.arg('test').strip() or None)
    return {'checks': rows, 'settings': {k: E.CONFIG.get(k) for k in SETTINGS}}


@A.api('POST', '/api/checks/attach', 'certadmin')
def _attach(h, s):
    b = h.body()
    by = A.who(s)
    names = b.get('tests') if isinstance(b.get('tests'), list) else [b.get('test')]
    cid = _int(b.get('cert_id'), 'cert_id')
    made = C.attach(h.store, cid, [n for n in names if n], by)
    cert = S.cert_get(h.store, cid) or {}
    if made:
        h.store.add_event('certificates', 'test(s) %s attached to %s by %s' % (
            ', '.join(str(n) for n in names if n), cert.get('name', '?'), by), who=by)
    return {'ok': True, 'ids': made, 'message': '%d test(s) attached' % len(made)}


@A.api('POST', '/api/checks/detach', 'certadmin')
def _detach(h, s):
    b = h.body()
    ident = _int(b.get('id'), 'id')
    r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (ident,))
    C.detach(h.store, ident)
    by = A.who(s)
    if r:
        cert = S.cert_get(h.store, r['cert_id']) or {}
        h.store.add_event('certificates', 'test %s taken off %s by %s' % (
            r['test'], cert.get('name', '?'), by), who=by)
    return {'ok': True, 'message': 'taken off'}


@A.api('POST', '/api/checks/switch', 'certadmin')
def _switch(h, s):
    b = h.body()
    C.switch(h.store, _int(b.get('id'), 'id'), b.get('enabled') not in (False, 0, '0'),
             A.who(s))
    return {'ok': True}


@A.api('POST', '/api/checks/run', 'certadmin')
def _run(h, s):
    from acmelib.certs import jobs
    b = h.body()
    by = A.who(s)
    if b.get('id') not in (None, '', 0):
        ident = _int(b['id'], 'id')
        got = C.run(h.store, ident)
        r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (ident,))
        return {'ok': True, 'result': got, 'check': C.row_public(h.store, r)}
    if b.get('cert_id') not in (None, '', 0):
        ids = [r['id'] for r in C.rows(h.store, cert_id=_int(b['cert_id'], 'cert_id'))
               if r.get('enabled', 1)]
        cert = S.cert_get(h.store, _int(b['cert_id'], 'cert_id')) or {}
        what, cert_id = 'the tests of %s' % cert.get('name', '?'), cert.get('id')
    elif b.get('test'):
        ids = [r['id'] for r in C.rows(h.store, test=str(b['test'])) if r.get('enabled', 1)]
        what, cert_id = 'the test %s on its certificates' % b['test'], None
    else:
        ids = [r['id'] for r in C.rows(h.store) if r.get('enabled', 1)]
        what, cert_id = 'every test', None
    if not ids:
        raise ValueError('there is no test to run')

    def fn(job):
        return C.run_many(h.store, ids, job)
    jid = jobs.submit(h.store, 'check', fn, cert_id=None, by=by,
                      said='%s (%d)' % (what, len(ids)))
    return {'ok': True, 'job_id': jid, 'message': '%d test(s) started' % len(ids)}


@A.api('POST', '/api/checks/try', 'certadmin')
def _try(h, s):
    """A test as its form has it (Certificates → Tests → the test → Try it on a
    certificate), run once against that certificate, kept nowhere."""
    b = h.body()
    cid = _int(b.get('cert_id'), 'cert_id')
    if not S.cert_get(h.store, cid):
        raise LookupError('there is no such certificate')
    kind = str(b.get('kind') or '')
    cls = S.plugin_class('check', kind)
    if cls is None:
        raise ValueError('there is no test module "%s"' % kind)
    cfg = dict(b.get('config') if isinstance(b.get('config'), dict) else {})
    row = S.plugin_row(h.store, 'check', A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    if row:
        A.kept_secrets_guard(h.store, 'check', b, s)
        kept = S.plugin_config('check', row)
        for k in S.secret_fields(cls):
            if cfg.get(k) in (None, '') or E.is_masked(cfg.get(k)):
                if kept.get(k):
                    cfg[k] = kept[k]
    got = C.probe(h.store, {'id': 0, 'cert_id': cid, 'kind': kind, 'config': cfg})
    return {'ok': True, 'result': got}
