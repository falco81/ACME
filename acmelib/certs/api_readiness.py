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
    POST /api/validations/persist {id|name, register}   a dns-persist-01 validation:
                              the record for each ACME source (its account made at the
                              CA with register), whether it is there, whether each CA
                              offers dns-persist-01 yet

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
                challenge_map=_cmap(store, b.get('challenge_map')),
                key_type=str(b.get('key_type') or '') or None,
                key_type_alt=str(b.get('key_type_alt') or '') or None)


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
            a = _args(h.store, b)
            a.pop('key_type', None)
            a.pop('key_type_alt', None)
            jid = R.dry_run(h.store, _names(b), by=A.who(s), **a)
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


@A.api('POST', '/api/validations/persist', 'certadmin')
def _persist(h, s):
    """The records a dns-persist-01 validation needs (challenges/dns_persist.py)."""
    b = h.body()
    ref = b.get('id') if b.get('id') not in (None, '', 0) else b.get('name')
    row, inst, words = R.module(h.store, ref)
    if not row:
        raise LookupError('there is no such validation')
    if inst is None:
        raise ValueError(words)
    if not callable(getattr(inst, 'overview', None)) or row.get('kind') != 'dns_persist':
        raise ValueError('%s is not a dns-persist-01 validation' % row['name'])
    register = bool(b.get('register'))
    got = inst.overview(register=register, check=True)
    for r in got['records']:
        r.pop('issuer', None)
    if register:
        h.store.add_event('certificates', '%s: the ACME accounts its record names made where '
                          'there were none, by %s' % (row['name'], A.who(s)), who=A.who(s))
    return {'validation': {'id': row['id'], 'name': row['name']}, 'persist': got}


@A.api('POST', '/api/validations/acme_dns_register', 'fulladmin')
def _acme_dns_register(h, s):
    """Accounts made at an acme-dns server for the form of an acme-dns validation:
    {url, names[], verify_tls, allow_from[]} -> {account} (no names) or
    {accounts: {name: account}} - nothing saved; the form keeps them on Save."""
    from acmelib.certs import runtime
    from acmelib.plugins.challenges import acme_dns, _dns as D
    b = h.body()
    names = []
    for n in (b.get('names') or []):
        n = D.norm(str(n).strip().lstrip('*.'))
        if n and n not in names:
            names.append(n)
    if len(names) > 50:
        raise ValueError('50 names at most at once')
    ctx = runtime.RunContext(h.store, None, scope='challenge:acme-dns-register')
    verify = b.get('verify_tls') not in (False, 0, '0', 'false', 'off')
    allow = [str(x).strip() for x in (b.get('allow_from') or []) if str(x).strip()]
    try:
        if not names:
            got = acme_dns.register(ctx, b.get('url'), verify, allow)
            h.store.add_event('certificates', 'an acme-dns account made at %s (%s) by %s' % (
                got['server_url'], got['fulldomain'], A.who(s)), who=A.who(s))
            return {'account': got}
        accounts = {}
        for n in names:
            accounts[n] = acme_dns.register(ctx, b.get('url'), verify, allow)
        h.store.add_event('certificates', '%d acme-dns accounts made at %s by %s (%s)' % (
            len(accounts), str(b.get('url') or '').rstrip('/'), A.who(s), ', '.join(names)),
            who=A.who(s))
        return {'accounts': accounts,
                'records': [{'name': '_acme-challenge.' + n, 'type': 'CNAME',
                             'value': a['fulldomain'] + '.'} for n, a in accounts.items()]}
    finally:
        ctx.tidy()

