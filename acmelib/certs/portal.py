# -*- coding: utf-8 -*-
"""
The certificate portal: what people signed in on the enrolment pages (a
`portal` session) may do with certificates - kept modest.

    GET  /api/portal/certs             their certificates (owner = their name) and
                                       what they may ask for
    POST /api/portal/cert_download     {id, format}  cert-pem, cert-der, chain-pem,
                                       fullchain-pem, p7b - never a key
    POST /api/portal/cert_request      {names[], issuer, key_type?, note?}  a certificate
                                       for names under portal_cert_suffixes from one of
                                       portal_cert_issuers, owned by them; issued by a job

Settings: portal_cert (on/off), portal_cert_suffixes, portal_cert_issuers,
portal_cert_max (certificates one person may have).
"""
from __future__ import annotations

import re
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import jobs, renewer, schema

PORTAL_FORMATS = ('cert-pem', 'cert-der', 'chain-pem', 'fullchain-pem', 'p7b')


def words_list(key):
    return [w.strip().lower().lstrip('.').lstrip('*.') if key.endswith('suffixes') else w.strip()
            for w in re.split(r'[\s,;]+', str(E.CONFIG.get(key) or '')) if w.strip()]


def portal_session(h):
    s = E.portal_me(h)
    if not E.CONFIG.get('portal_cert'):
        raise E.ApiError(403, 'certificates are not offered on these pages')
    return s


def name_allowed(name, suffixes):
    n = name[2:] if name.startswith('*.') else name
    return any(n == suf or n.endswith('.' + suf) for suf in suffixes)


def mine(store, s):
    rows = store.db.rows('SELECT * FROM certs WHERE LOWER(owner) = ? ORDER BY name',
                         (str(s['name']).lower(),))
    out = []
    for r in rows:
        one = S.cert_public(r)
        for k in ('last_error', 'challenge_map', 'profile', 'ari', 'created_by', 'updated_by',
                  'csr_waiting', 'has_key'):
            one.pop(k, None)
        out.append(one)
    return out


@E.route('GET', '/api/portal/certs')
def _portal_certs(h):
    s = portal_session(h)
    sufs = words_list('portal_cert_suffixes')
    iss = [i for i in words_list('portal_cert_issuers') if S.plugin_row(h.store, 'issuer', i)]
    have = mine(h.store, s)
    most = int(E.CONFIG.get('portal_cert_max') or 10)
    return {'rows': have, 'suffixes': sufs, 'issuers': iss, 'formats': list(PORTAL_FORMATS),
            'key_types': list(schema.KEY_TYPES), 'most': most,
            'may_request': bool(sufs and iss) and len(have) < most}


@E.route('POST', '/api/portal/cert_download')
def _portal_download(h):
    s = portal_session(h)
    b = h.body()
    from acmelib.certs import api
    row = S.cert_get(h.store, api._id(b.get('id')))
    if not row or str(row.get('owner') or '').lower() != str(s['name']).lower():
        raise E.ApiError(404, 'there is no such certificate of yours')
    fmt = str(b.get('format') or 'fullchain-pem')
    if fmt not in PORTAL_FORMATS:
        raise E.ApiError(400, 'the format is one of %s' % ', '.join(PORTAL_FORMATS))
    got = api.cert_export(h.store, {'id': row['id'], 'format': fmt},
                          {'name': s['name'], 'role': 'readonly'}, allowed=PORTAL_FORMATS)
    h.store.add_event('certificates', '%s took %s (%s) from the enrolment pages' % (
        s['name'], row['name'], fmt), who=s['name'])
    return got


@E.route('POST', '/api/portal/cert_request')
def _portal_request(h):
    s = portal_session(h)
    b = h.body()
    store = h.store
    sufs = words_list('portal_cert_suffixes')
    allowed = words_list('portal_cert_issuers')
    if not sufs or not allowed:
        raise E.ApiError(403, 'asking for certificates here is not set up')
    if len(mine(store, s)) >= int(E.CONFIG.get('portal_cert_max') or 10):
        raise E.ApiError(403, 'you have as many certificates as one person may')
    try:
        names = S.clean_names(b.get('names'))
    except ValueError as e:
        raise E.ApiError(400, str(e))
    if not names:
        raise E.ApiError(400, 'which names?')
    bad = [n for n in names if not name_allowed(n, sufs)]
    if bad:
        raise E.ApiError(403, 'not under the names you may ask for (%s): %s' % (
            ', '.join(sufs), ', '.join(bad)))
    issuer = str(b.get('issuer') or (allowed[0] if len(allowed) == 1 else '')).strip()
    if issuer not in allowed or not S.plugin_row(store, 'issuer', issuer):
        raise E.ApiError(400, 'the issuer is one of %s' % ', '.join(allowed))
    kt = str(b.get('key_type') or 'ec-256')
    if kt not in schema.KEY_TYPES:
        raise E.ApiError(400, 'the key type is one of %s' % ', '.join(schema.KEY_TYPES))
    who = str(s['name'])
    base_name = re.sub(r'[^A-Za-z0-9._@+-]+', '-', names[0].replace('*.', 'wildcard.'))[:80]
    name = base_name
    n = 1
    while store.db.row('SELECT id FROM certs WHERE name = ?', (name,)):
        n += 1
        name = '%s-%d' % (base_name, n)
    t = time.time()
    import json
    cid = store.db.insert('certs', {
        'name': name, 'cn': names[0], 'names': json.dumps(names), 'key_type': kt,
        'issuer': S.plugin_row(store, 'issuer', issuer)['name'], 'challenge': '',
        'challenge_map': '{}', 'auto_renew': 1, 'renew_days': None, 'reuse_key': 0,
        'profile': '{}', 'source': 'portal', 'state': 'new', 'state_at': t, 'version': 0,
        'fails': 0, 'tags': json.dumps(['portal']),
        'note': ('asked for on the enrolment pages by %s. %s' % (
            who, str(b.get('note') or '')[:500])).strip(), 'owner': who[:190],
        'created': t, 'created_by': 'portal:' + who[:180], 'enabled': 1, 'ari': '{}'})
    store.add_event('certificates', '%s asked on the enrolment pages for %s (%s) from %s' % (
        who, name, ', '.join(names), issuer), who=who)
    job_id = None
    try:
        job_id = jobs.submit(store, 'renew', renewer.renew_job(cid, by='portal:' + who),
                             cert_id=cid, by='portal:' + who, said='asked on the enrolment pages')
    except ValueError:
        pass
    return {'id': cid, 'name': name, 'job_id': job_id}
