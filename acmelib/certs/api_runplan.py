# -*- coding: utf-8 -*-
"""
What happens - the run plan of a certificate (acmelib/certs/runplan.py):

    GET  /api/certs/run_plan?id=        a certificate as it is saved, its deployments
    POST /api/certs/run_plan  {id?, draft: {names, issuer, challenge, challenge_map,
                               key_type, key_type_alt, reuse_key, auto_renew, renew_days,
                               profile, deploys: {target: options}}}
                              the wizard's values, nothing saved (with id: laid over
                              the certificate saved, its deployments kept)

Anybody signed in may look (readonly too); a team member only at a certificate
of the team's (teams.guard). Nothing is changed and nothing is contacted: the
modules are recorded in a process that can reach nothing. At most two plans
are worked out at a time.
"""
from __future__ import annotations

import json
import threading

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import runplan

BUSY = threading.BoundedSemaphore(2)
DRAFT_KEYS = ('name', 'issuer', 'challenge', 'key_type', 'key_type_alt', 'reuse_key', 'csr_from',
              'auto_renew', 'renew_days')


def _saved_deploys(store, cert_id):
    return store.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ? ORDER BY position, id',
                         (cert_id,))


def _draft(store, b):
    d = b.get('draft')
    if not isinstance(d, dict):
        raise ValueError('draft is the certificate as the wizard has it')
    row = None
    if b.get('id') not in (None, '', 0):
        row = S.cert_need(store, A._id(b.get('id')))
    cert = dict(row or {})
    if 'names' in d or not row:
        names = S.clean_names(d.get('names'))
        if not names:
            raise ValueError('a certificate needs at least one name')
        cert['names'] = json.dumps(names)
    for k in DRAFT_KEYS:
        if k in d:
            cert[k] = d[k]
    if 'challenge_map' in d:
        m = d.get('challenge_map') or {}
        if not isinstance(m, dict):
            raise ValueError('challenge_map is {name: validation}')
        # checked and written as a save does (1.0.101: taken unchecked, the plan and the save
        # disagreed)
        cm = {}
        for k, v in m.items():
            k, v = S.map_key(k), str(v or '').strip()
            if k and v:
                no = S.map_ip_refused(store, k, v)       # as a save refuses it (1.0.101)
                if no:
                    raise ValueError(no)
                cm[k] = v
        cert['challenge_map'] = json.dumps(cm)
    if 'profile' in d:
        p = d.get('profile') or {}
        if not isinstance(p, dict):
            raise ValueError('profile is an object')
        if p.get('subject'):
            # checked as a save checks it: What happens drew a CSR the save refuses (hunt M)
            from acmelib.certs import reqprofiles as RP
            p = dict(p, subject=RP.check_subject(p.get('subject')))
        cert['profile'] = json.dumps(p)
    if row and S.jload(cert.get('names'), []) != S.jload(row.get('names'), []):
        cert['csr_given'] = row.get('csr_given')
    if not row:
        cert['name'] = cert.get('name') or S.jload(cert['names'], ['?'])[0]
        cert['state'] = 'new'
    deploys = _saved_deploys(store, row['id']) if row else []
    have = {x['target'] for x in deploys}
    extra = d.get('deploys') or {}
    if isinstance(extra, dict):
        extra = [{'target': k, 'options': v} for k, v in extra.items()]
    if not isinstance(extra, list):
        raise ValueError('deploys is {target: options}')
    for x in extra[:50]:
        if not isinstance(x, dict) or not x.get('target') or x['target'] in have:
            continue
        opts = x.get('options') if isinstance(x.get('options'), dict) else {}
        deploys.append({'target': str(x['target']), 'options': json.dumps(opts),
                        '_options': opts, 'enabled': 1})
    return cert, deploys


def _go(store, cert, deploys, s):
    if not BUSY.acquire(timeout=30):
        raise E.ApiError(503, 'two plans are being worked out already - try again in a moment')
    try:
        return {'plan': runplan.plan(store, cert, deploys, A.may(s, 'fulladmin'))}
    finally:
        BUSY.release()


@A.api('GET', '/api/certs/run_plan')
def _run_plan(h, s):
    row = S.cert_need(h.store, h.arg('id') or h.arg('name'))
    return _go(h.store, row, _saved_deploys(h.store, row['id']), s)


@A.api('POST', '/api/certs/run_plan')
def _run_plan_draft(h, s):
    cert, deploys = _draft(h.store, h.body())
    return _go(h.store, cert, deploys, s)
