# -*- coding: utf-8 -*-
"""
Settings → Request profiles (acmelib/certs/reqprofiles.py, docs/request-profiles.md):
the routes of the administration and the two of the portal that go with them.

    GET  /api/reqprofiles           the profiles (with what is wrong with each, and how many
                                    certificates were asked for from it) and what a profile
                                    picks from (read-only)
    POST /api/reqprofiles/save      {name, old_name?, description, enabled, issuer, challenge,
                                    suffixes[], wildcards, max_names, make_key, csr,
                                    key_types[], key_default, subject{F: {mode, value}},
                                    auto_renew, renew_days, days, eku[], approval, owner,
                                    owner_team, tags[], teams[], pfx} (full)
    POST /api/reqprofiles/delete    {name} (full) - what was asked for from it stays

    POST /api/portal/csr_decode     {profile, csr | csr_b64}: the CSR decoded, and checked
                                    against the profile item by item - nothing kept
    POST /api/portal/cert_csr       {id, csr | csr_b64}: a new CSR for one of theirs
                                    (the right manage) - checked, kept, issued again
"""
from __future__ import annotations

import json
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import reqprofiles as R


@A.api('GET', '/api/reqprofiles')
def _list(h, s):
    return {'profiles': R.profiles(h.store), 'options': R.options(h.store),
            'can_change': s.get('role') == 'fulladmin',
            'portal': {'on': bool(E.CONFIG.get('portal')),
                       'certs': bool(E.CONFIG.get('portal_cert'))}}


@A.api('POST', '/api/reqprofiles/save', 'fulladmin')
def _save(h, s):
    got = R.save_profile(h.store, h.body(), A.who(s))
    return {'profile': got, 'message': 'the request profile %s was saved' % got['name']}


@A.api('POST', '/api/reqprofiles/delete', 'fulladmin')
def _delete(h, s):
    got = R.delete_profile(h.store, h.body().get('name'), A.who(s))
    got['message'] = 'the request profile %s was deleted' % got['deleted']
    return got


@E.route('POST', '/api/portal/csr_decode')
def _csr_decode(h):
    from acmelib.certs import portal as P
    s = P.portal_session(h)
    b = h.body()
    r = R.need_usable(h, s, b.get('profile'))
    try:
        info = R.read_csr(b)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    return R.csr_review(h.store, r, info)


@E.route('POST', '/api/portal/cert_csr')
def _cert_csr(h):
    """A new CSR for a certificate issued for one (a new key): checked against its profile
    when that is still there (else the names must stay the same), then issued again."""
    from acmelib.certs import portal as P
    s = P.portal_session(h)
    b = h.body()
    row = P.need_right(h, s, b.get('id'), 'manage', 'sending a new CSR for')
    if not row.get('csr_given'):
        raise E.ApiError(409, '%s was not issued for a CSR - acme makes its key' % row['name'])
    if row.get('state') in (P.WAITING, P.DECLINED):
        raise E.ApiError(409, '%s has not been approved' % row['name'])
    try:
        info = R.read_csr(b)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    prof = R.profile_get(h.store, P.asker(h.store, row['id']).get('profile'))
    if prof:
        rv = R.csr_review(h.store, prof, info)
        if not rv['fits']:
            raise E.ApiError(400, 'the CSR does not fit the profile: %s' % '; '.join(
                c['said'] for c in rv['checks'] if c['ok'] is False))
        names, kt, cn = rv['names'], rv['key_type'], rv['cn']
        subject = dict(rv['will'])
    else:
        if not S.pki().csr_verify(info['pem']):
            raise E.ApiError(400, 'the CSR is not signed by the key in it')
        dns = [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')] or \
            ([info['cn']] if info.get('cn') else [])
        names = S.clean_names(dns)
        if sorted(names) != sorted(S.jload(row.get('names'), []) or []):
            raise E.ApiError(400, 'the new CSR has to name the same names: %s' % ', '.join(
                S.jload(row.get('names'), []) or []))
        kt, cn = info.get('key_type') or row.get('key_type'), row.get('cn') or names[0]
        subject = (S.jload(row.get('profile'), {}) or {}).get('subject') or {}
    pf = S.jload(row.get('profile'), {}) or {}
    if subject:
        pf['subject'] = subject
    t = time.time()
    fields = {'csr_given': info['pem'], 'names': json.dumps(names), 'cn': str(cn)[:190],
              'key_type': kt, 'profile': json.dumps(pf), 'updated': t,
              'updated_by': P.portal_by(s)[:190]}
    if row.get('state') == 'revoked':
        fields.update(state='due', state_at=t)      # a new key: it may be issued again
    h.store.db.update('certs', row['id'], fields)
    h.store.add_event('certificates', '%s sent a new CSR for %s from the portal (%s) - it is '
                      'issued again' % (s['name'], row['name'], kt), 'warn', who=s['name'])
    try:
        job_id = A.start_renew(h.store, row['id'], True, P.portal_by(s))
    except (ValueError, LookupError) as e:
        raise E.ApiError(409, str(e))
    return {'job_id': job_id, 'message': 'the new CSR was taken - %s is being issued again'
            % row['name']}
