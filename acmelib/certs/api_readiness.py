# -*- coding: utf-8 -*-
"""
Before a certificate: what its validation needs, where, and whether it is
in place (acmelib/certs/readiness.py) - the routes the pages ask.

    POST /api/certs/plan      {names, issuer, challenge, challenge_map}   the plan,
                              grouped by domain, with suggestions (read-only)
    POST /api/certs/check     {id}   the same for a certificate acme keeps
    POST /api/certs/dry_run   {names, issuer, challenge, challenge_map} | {id}
                              -> {job_id}: the validation tried for real, no CA
    GET  /api/certs/dry_run_result?job=   what that dry run found (null while it runs)
    GET  /api/validations/setup?id=|name=  for each certificate that uses the
                              validation: its names, the records to create, their state

All of them for a certificate administrator (or a full one). A plan here
gives up after PLAN_S seconds (what did not finish is said so).
"""
from __future__ import annotations

import json

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import readiness as R
from acmelib.certs import store as S

PLAN_S = 25
SETUP_MOST = 30                 # certificates looked at by /api/validations/setup


def _names(b):
    v = b.get('names')
    if isinstance(v, str):
        v = [x for x in v.replace(';', ',').replace('\n', ',').split(',')]
    names = [str(x).strip() for x in (v or []) if str(x).strip()]
    if not names:
        raise ValueError('which names?')
    if len(names) > 100:
        raise ValueError('at most 100 names')
    return S.clean_names(names)


def _ref(store, family, v):
    if v in (None, ''):
        return None
    if not S.plugin_row(store, family, v):
        raise LookupError('there is no %s %s' % ({'issuer': 'source',
                                                  'challenge': 'validation'}[family], v))
    return str(v)


def _cmap(store, v):
    if v in (None, ''):
        return {}
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise ValueError('challenge_map is {name: validation}')
    if not isinstance(v, dict):
        raise ValueError('challenge_map is {name: validation}')
    out = {}
    for k, w in v.items():
        if w in (None, ''):
            continue
        out[str(k).strip().lower()] = _ref(store, 'challenge', w)
    return out


def _args(store, b):
    return dict(issuer=_ref(store, 'issuer', b.get('issuer')),
                challenge=_ref(store, 'challenge', b.get('challenge')),
                challenge_map=_cmap(store, b.get('challenge_map')))


@A.api('POST', '/api/certs/plan', 'certadmin')
def _plan(h, s):
    b = h.body()
    return {'plan': R.plan(h.store, _names(b), timeout=PLAN_S, **_args(h.store, b))}


@A.api('POST', '/api/certs/check', 'certadmin')
def _check(h, s):
    row = S.cert_need(h.store, A._id(h.body().get('id')))
    names, issuer, _c, _m = R.cert_args(row)
    got = R.plan(h.store, names, issuer=issuer, cert=row, timeout=PLAN_S)
    got['cert'] = {'id': row['id'], 'name': row['name'],
                   'precheck_blocked': str(row.get('last_error') or '').startswith(
                       'the CA was not asked')}
    return {'plan': got}


@A.api('POST', '/api/certs/dry_run', 'certadmin')
def _dry_run(h, s):
    b = h.body()
    try:
        if b.get('id') not in (None, '', 0):
            row = S.cert_need(h.store, A._id(b.get('id')))
            jid = R.dry_run(h.store, R.cert_args(row)[0], cert=row, by=A.who(s),
                            cert_id=row['id'])
        else:
            jid = R.dry_run(h.store, _names(b), by=A.who(s), **_args(h.store, b))
    except ValueError as e:
        if 'already working' in str(e):
            raise E.ApiError(409, str(e))
        raise
    return {'job_id': jid}


@A.api('GET', '/api/certs/dry_run_result', 'certadmin')
def _dry_run_result(h, s):
    return {'result': R.dry_run_result(h.store, A._id(h.arg('job'), 'job'))}


@A.api('GET', '/api/validations/setup', 'certadmin')
def _setup(h, s):
    """What the certificates using a validation need set up, each record with its state."""
    row = S.plugin_row(h.store, 'challenge', h.arg('id') or h.arg('name'))
    if not row:
        raise LookupError('there is no such validation')
    certs = [c for c in h.store.db.rows('SELECT * FROM certs ORDER BY name')
             if row['name'] in set(R.resolve(h.store, S.jload(c.get('names'), []) or [],
                                             cert=c).values())]
    out = []
    for c in certs[:SETUP_MOST]:
        names = [n for n in S.jload(c.get('names'), []) or []
                 if S.challenge_for(c, n) == row['name']]
        got = R.plan(h.store, names, issuer=c.get('issuer') or None, cert=c,
                     timeout=PLAN_S, suggestions='none')
        steps = [st for g in got['groups'] for st in (g.get('guide') or {}).get('steps') or []]
        out.append({'id': c['id'], 'name': c['name'], 'names': names, 'ok': got['ok'],
                    'steps': steps})
    return {'validation': {'id': row['id'], 'name': row['name'], 'kind': row.get('kind')},
            'certs': out, 'more': max(0, len(certs) - SETUP_MOST)}
