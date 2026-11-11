# -*- coding: utf-8 -*-
"""
Tests attached to certificates (acmelib/certs/checks.py, 1.0.32). The tests
themselves are defined as targets are: /api/tests (api.py's family routes,
family 'check', table cert_tests).

    GET  /api/checks?cert_id=&test=        {checks, settings}
    POST /api/checks/attach   {cert_id, tests: [name...], after_target}
    POST /api/checks/detach   {id}
    POST /api/checks/switch   {id, enabled}
    POST /api/checks/after    {id, target}   (1.0.65: '' - after any deployment; 1.0.66: '-' none)
    POST /api/checks/run      {id} -> the result at once | {cert_id | test | all} -> a job;
                              report: {mail, to, sms, sms_to} sent when they are done (1.0.73)
    POST /api/checks/try      {cert_id, kind, config} - a test as its form has it, kept nowhere
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import checks as C
from acmelib.certs import store as S
from acmelib.certs import teams as T


def _int(v, what):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError('%s: a number' % what)


def _scoped(s):
    return not (T.unscoped(s, 'view') and T.unscoped(s, 'manage'))


def _cert_need(h, s, cert_id, right, what):
    """Teams (1.0.44): the tests of a certificate only of a team the session is in - a
    scoped certificate administrator took another team's expiry tests off, and silenced
    its alerts; a scoped reader listed every team's hosts."""
    if _scoped(s):
        T.need_cert(h.store, s, cert_id, right, what)


def _check_need(h, s, ident, right, what):
    r = h.store.db.row('SELECT cert_id FROM cert_checks WHERE id = ?', (ident,))
    if r:
        _cert_need(h, s, r['cert_id'], right, what)


def _seen(h, s, rows, right='view'):
    if not _scoped(s):
        return rows
    keep, owners = [], {}
    for r in rows:
        cid = r.get('cert_id')
        if cid not in owners:
            owners[cid] = T.cert_may(h.store, s, S.cert_get(h.store, cid) or {}, right) \
                if cid is not None else False
        if owners[cid]:
            keep.append(r)
    return keep


SETTINGS = ('certs_checks_after_deploy', 'certs_checks_auto', 'certs_checks_every_min',
            'certs_checks_alert', 'certs_checks_warn_days')


@A.api('GET', '/api/checks')
def _list(h, s):
    cert = h.arg('cert_id').strip()
    if cert:
        _cert_need(h, s, _int(cert, 'cert_id'), 'view', 'look at the tests of')
    rows = _seen(h, s, C.rows(h.store, cert_id=_int(cert, 'cert_id') if cert else None,
                  test=h.arg('test').strip() or None))
    return {'checks': rows, 'settings': {k: E.CONFIG.get(k) for k in SETTINGS},
            # who a report of the tests goes to by default, and whether SMS can go (1.0.73)
            # the addresses only to whom may send a report (1.0.77): not to the read-only role
            'report': {'to': E._alerts_to('report_to') if A.may(s, 'certadmin') else [],
                       'sms': (E.CONFIG.get('sms_mode') or 'off') != 'off',
                       'mail': (E.CONFIG.get('mail_mode') or 'off') != 'off'}}


@A.api('POST', '/api/checks/for_target', 'certadmin')
def _for_target(h, s):
    """A test of what a target serves, for a deployment (1.0.77, in place of its "Check what
    is served"): made or found, attached, run after a deployment there - a failing one fails
    that deployment."""
    b = h.body()
    by = A.who(s)
    cid = _int(b.get('cert_id'), 'cert_id')
    _cert_need(h, s, cid, 'manage', 'add a test to')
    target = str(b.get('target') or '').strip()
    port = b.get('port')
    try:
        port = int(port) if port not in (None, '') else None
        name = C.for_target(h.store, cid, target, by, str(b.get('kind') or 'tls'),
                            str(b.get('host') or ''), port, str(b.get('sni') or ''),
                            None if b.get('via') is None else str(b.get('via') or ''))
    except (ValueError, TypeError) as e:
        raise E.ApiError(400, str(e))
    cert = S.cert_get(h.store, cid) or {}
    h.store.add_event('certificates', 'test %s of %s runs after a deployment on %s by %s' % (
        name, cert.get('name', '?'), target, by), who=by)
    return {'ok': True, 'test': name}


@A.api('POST', '/api/checks/attach', 'certadmin')
def _attach(h, s):
    b = h.body()
    by = A.who(s)
    names = b.get('tests') if isinstance(b.get('tests'), list) else [b.get('test')]
    cid = _int(b.get('cert_id'), 'cert_id')
    _cert_need(h, s, cid, 'manage', 'attach tests to')
    try:
        made = C.attach(h.store, cid, [n for n in names if n], by, b.get('after_target') or '')
    except ValueError as e:
        raise E.ApiError(400, str(e))
    cert = S.cert_get(h.store, cid) or {}
    if made:
        h.store.add_event('certificates', 'test(s) %s attached to %s by %s' % (
            ', '.join(str(n) for n in names if n), cert.get('name', '?'), by), who=by)
    return {'ok': True, 'ids': made, 'message': '%d test(s) attached' % len(made)}


@A.api('POST', '/api/checks/detach', 'certadmin')
def _detach(h, s):
    b = h.body()
    ident = _int(b.get('id'), 'id')
    _check_need(h, s, ident, 'manage', 'take a test off')
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
    _check_need(h, s, _int(b.get('id'), 'id'), 'manage', 'switch a test of')
    C.switch(h.store, _int(b.get('id'), 'id'), b.get('enabled') not in (False, 0, '0'),
             A.who(s))
    return {'ok': True}


@A.api('POST', '/api/checks/after', 'certadmin')
def _after(h, s):
    """After which deployment the test runs: a target of the certificate, or '' - any (1.0.65)."""
    b = h.body()
    ident = _int(b.get('id'), 'id')
    _check_need(h, s, ident, 'manage', 'change a test of')
    try:
        chk = C.after(h.store, ident, b.get('target'), A.who(s))
    except ValueError as e:
        raise E.ApiError(400, str(e))
    cert = S.cert_get(h.store, chk['cert_id']) or {}
    got = C.after_list(b.get('target'))
    t = ', '.join(got)
    if C.AFTER_NONE in got:
        how = 'no deployment (by its schedule only)'
    else:
        how = ('a deployment on %s' % t) if t else 'any deployment'
    h.store.add_event('certificates', 'test %s of %s runs after %s by %s' % (
        chk['test'], cert.get('name', '?'), how, A.who(s)), who=A.who(s))
    return {'ok': True}


@A.api('POST', '/api/checks/run', 'certadmin')
def _run(h, s):
    from acmelib.certs import jobs
    b = h.body()
    by = A.who(s)
    if b.get('id') not in (None, '', 0):
        ident = _int(b['id'], 'id')
        _check_need(h, s, ident, 'manage', 'run a test of')
        got = C.run(h.store, ident)
        r = h.store.db.row('SELECT * FROM cert_checks WHERE id = ?', (ident,))
        return {'ok': True, 'result': got, 'check': C.row_public(h.store, r)}
    if b.get('cert_id') not in (None, '', 0):
        _cert_need(h, s, _int(b['cert_id'], 'cert_id'), 'manage', 'run the tests of')
        ids = C.runnable(h.store, [r['id'] for r in C.rows(h.store, cert_id=_int(b['cert_id'], 'cert_id'))])
        cert = S.cert_get(h.store, _int(b['cert_id'], 'cert_id')) or {}
        what, cert_id = 'the tests of %s' % cert.get('name', '?'), cert.get('id')
    elif b.get('test'):
        ids = C.runnable(h.store, [r['id'] for r in _seen(h, s, C.rows(h.store, test=str(b['test'])), 'manage')])
        what, cert_id = 'the test %s on its certificates' % b['test'], None
    else:
        ids = C.runnable(h.store, [r['id'] for r in _seen(h, s, C.rows(h.store), 'manage')])
        what, cert_id = 'every test', None
    if not ids:
        raise ValueError('there is no test to run')
    # A report of them when they are done (1.0.73): by mail and/or SMS, to whom it says.
    from acmelib.certs import checkreport as R
    rep = b.get('report') if isinstance(b.get('report'), dict) else {}
    want_mail, want_sms = A._flag(rep.get('mail'), 0), A._flag(rep.get('sms'), 0)   # "false" is off
    to = R.addresses(rep.get('to')) if want_mail else []
    sms_to = R.phones(rep.get('sms_to')) if want_sms else []
    if want_mail and not to:
        raise ValueError('no address to send the report to')
    if want_sms and not sms_to:
        raise ValueError('no number to send the SMS to')
    if sms_to and (E.CONFIG.get('sms_mode') or 'off') == 'off':
        raise ValueError('sending SMS is switched off - Settings → Codes by mail and SMS')

    def fn(job):
        got = C.run_many(h.store, ids, job)
        if to or sms_to:
            R.send(h.store, ids, what, to, sms_to, by, job.step)
        return got
    jid = jobs.submit(h.store, 'check', fn, cert_id=None, by=by,
                      said='%s (%d)%s' % (what, len(ids), ', with a report' if to or sms_to else ''))
    return {'ok': True, 'job_id': jid, 'message': '%d test(s) started' % len(ids)}


@A.api('POST', '/api/checks/try', 'certadmin')
def _try(h, s):
    """A test as its form has it (Certificates → Tests → the test → Try it on a
    certificate), run once against that certificate, kept nowhere."""
    b = h.body()
    cid = _int(b.get('cert_id'), 'cert_id')
    if not S.cert_get(h.store, cid):
        raise LookupError('there is no such certificate')
    _cert_need(h, s, cid, 'manage', 'try a test on')
    kind = str(b.get('kind') or '')
    cls = S.plugin_class('check', kind)
    if cls is None:
        raise ValueError('there is no test module "%s"' % kind)
    cfg = dict(b.get('config') if isinstance(b.get('config'), dict) else {})
    row = S.plugin_row(h.store, 'check', A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    # A test as nobody saved it is a full administrator's (1.0.48): any kind, any host - acme
    # connected anywhere for a certificate administrator. Theirs: a saved one, as it is saved.
    if str(s.get('role') or '') != 'fulladmin' and not s.get('cli'):
        if row is None:
            raise E.ApiError(403, 'only a full administrator may try a test that is not saved')
        kind = str(row.get('kind') or kind)
        cls = S.plugin_class('check', kind) or cls
        cfg = dict(S.plugin_config('check', row))
    if row:
        A.kept_secrets_guard(h.store, 'check', b, s)
        kept = S.plugin_config('check', row)
        for k in S.secret_fields(cls):
            if cfg.get(k) in (None, '') or E.is_masked(cfg.get(k)):
                if kept.get(k):
                    cfg[k] = kept[k]
    got = C.probe(h.store, {'id': 0, 'cert_id': cid, 'kind': kind, 'config': cfg})
    return {'ok': True, 'result': got}
