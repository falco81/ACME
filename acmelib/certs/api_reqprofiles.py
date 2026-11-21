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
    POST /api/reqprofiles/delete    {name, detach?} (full) - what was asked for from it stays;
                                    the base of others: refused, unless detach (they stand alone)
    GET  /api/reqprofiles/versions  ?name= its versions (1.0.138)
    GET  /api/reqprofiles/diff      ?name=&a=&b= two versions field by field ('now': as it is)
    POST /api/reqprofiles/restore   {name, version} (full) - as a new version
    GET  /api/reqprofiles/compliance ?at=YYYY-MM-DD the CA/B Forum's schedule and the rules
    POST /api/reqprofiles/rules     the company's rules (full)
    POST /api/reqprofiles/dryrun    {profile, names[] | csr, key_type, subject, team, who}
    GET  /api/reqprofiles/impact    ?name=&successor= what ending it moves
    POST /api/reqprofiles/ends      {name, successor, note} | {name, undo: true} (full)

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
from acmelib.certs import reqprofiles_more as RM


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
    b = h.body()
    got = R.delete_profile(h.store, b.get('name'), A.who(s), detach=bool(b.get('detach')))
    got['message'] = 'the request profile %s was deleted' % got['deleted']
    return got


# ---- 1.0.138 (reqprofiles_more.py): versions, compliance, a dry run, a profile that ends ----
@A.api('GET', '/api/reqprofiles/versions')
def _versions(h, s):
    return RM.versions(h.store, h.arg('name'))


@A.api('GET', '/api/reqprofiles/diff')
def _diff(h, s):
    return RM.diff(h.store, h.arg('name'), h.arg('a'), h.arg('b'))


@A.api('POST', '/api/reqprofiles/restore', 'fulladmin')
def _restore(h, s):
    b = h.body()
    try:
        n = int(b.get('version'))
    except (TypeError, ValueError):
        raise E.ApiError(400, 'which version?')
    got = RM.restore(h.store, b.get('name'), n, A.who(s))
    return {'profile': got, 'message': 'the request profile %s is as version %d said - as a new '
                                       'version' % (got['name'], n)}


@A.api('GET', '/api/reqprofiles/compliance')
def _compliance(h, s):
    try:
        got = RM.report(h.store, h.arg('at') or None)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    if not _sees_all(s):
        # an account that sees only some certificates (its teams): the profiles, not theirs
        got['certs'] = []
        got['cert_count'] = {'ok': 0, 'bad': 0, 'ends': 0}
        got['certs_hidden'] = True
    return got


def _sees_all(s):
    from acmelib.certs import teams as T
    return T.unscoped(s, 'view')


@A.api('POST', '/api/reqprofiles/rules', 'fulladmin')
def _rules(h, s):
    return {'rules': RM.save_rules(h.store, h.body(), A.who(s)),
            'message': 'the rules of the request profiles are saved'}


@A.api('POST', '/api/reqprofiles/dryrun')
def _dryrun(h, s):
    try:
        return RM.dryrun(h.store, h.body(), owners=_sees_all(s))
    except ValueError as e:
        raise E.ApiError(400, str(e))


@A.api('GET', '/api/reqprofiles/impact')
def _impact(h, s):
    if not _sees_all(s):
        raise E.ApiError(403, 'only an account that sees every certificate sees what ending a '
                              'profile moves')
    return RM.impact(h.store, h.arg('name'), h.arg('successor') or None)


@A.api('POST', '/api/reqprofiles/ends', 'fulladmin')
def _ends(h, s):
    b = h.body()
    if b.get('undo'):
        got = RM.set_ends(h.store, b.get('name'), None, '', A.who(s))
        return {'profile': got, 'message': 'the request profile %s no longer ends' % got['name']}
    if not str(b.get('successor') or '').strip():
        raise E.ApiError(400, 'choose its successor among the request profiles')
    got = RM.set_ends(h.store, b.get('name'), b.get('successor'), b.get('note'), A.who(s))
    return {'profile': got, 'message': 'the request profile %s ends' % got['name']}


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
    """A new CSR for a certificate issued for one (a new key): checked against its profile,
    then issued again - refused when the profile is gone (1.0.106)."""
    from acmelib.certs import portal as P
    s = P.portal_session(h)
    b = h.body()
    row = P.need_right(h, s, b.get('id'), 'manage', 'sending a new CSR for')
    if not row.get('csr_given'):
        raise E.ApiError(409, '%s was not issued for a CSR - acme makes its key' % row['name'])
    if S.unapproved_why(h.store, row):
        raise E.ApiError(409, '%s has not been approved' % row['name'])
    # Nothing written while a job works on it (1.0.102: the CSR and names were kept, and the
    # call answered 409 - or the job running then issued the old one)
    from acmelib.certs import jobs
    if jobs.cert_busy(h.store, row['id']):
        raise E.ApiError(409, 'a job is working on %s now - send the CSR again when it is done'
                         % row['name'])
    try:
        info = R.read_csr(b)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    prof = R.profile_get(h.store, P.asker(h.store, row['id']).get('profile'))
    if not prof:
        # Its request profile deleted (1.0.106): only the DNS names were compared - an e-mail or
        # URI name, any extended key usage and any subject went to the source unchecked.
        raise E.ApiError(409, 'its request profile is gone - ask again with another one')
    rv = R.csr_review(h.store, prof, info)
    if not rv['fits']:
        raise E.ApiError(400, 'the CSR does not fit the profile: %s' % '; '.join(
            c['said'] for c in rv['checks'] if c['ok'] is False))
    names, kt, cn = rv['names'], rv['key_type'], rv['cn']
    subject = dict(rv['will'])
    pf = S.jload(row.get('profile'), {}) or {}
    if subject:
        pf['subject'] = subject
    t = time.time()
    fields = {'csr_given': info['pem'], 'names': json.dumps(names), 'cn': str(cn)[:190],
              'key_type': kt, 'profile': json.dumps(pf), 'updated': t,
              'updated_by': P.portal_by(s)[:190]}
    if row.get('state') == 'revoked':
        fields.update(state='due', state_at=t)      # a new key: it may be issued again
    # The one who sends it is one of those who asked for it from now (1.0.102): never approves
    # what follows from it.
    sender = P.owner_word(s)
    # Other names as a new request (1.0.52): the profile's approval, a name another owner's
    # certificate holds - issued at once before, past both.
    changed = sorted(names) != sorted(S.jload(row.get('names'), []) or [])
    if changed:
        if not prof.get('enabled', 1):
            raise E.ApiError(403, 'its request profile is switched off - other names are not taken')
        pcfg = R.config_of(prof)
        waits = bool(pcfg.get('approval')) or P.held_by_others(h.store, names, row.get('owner'),
                                                                 row['id'])
        # Other names of a team's certificate: within the team's limits and its approval rule,
        # as a new request (hunt Rt2: a team whose every request waits, and whose names are
        # under its suffixes, had other names issued at once, outside them)
        from acmelib.certs import teampolicy as TP
        TP.need_request(h.store, row.get('owner'), sender, profile=prof['name'],
                        issuer=pcfg.get('issuer'), validation=pcfg.get('challenge') or None,
                        names=names, days=pcfg.get('days'), key_type=kt, count=False)
        rule_waits = TP.request_waits(h.store, row.get('owner'), waits, prof['name'], names,
                                      pcfg.get('days'), kt)
        if rule_waits is not None:
            waits = rule_waits or P.held_by_others(h.store, names, row.get('owner'), row['id'])
        if waits and row.get('cert_pem'):
            # one issued already is not put to approval (it would stop renewing, and declined it
            # would run out): other names are a new request
            raise E.ApiError(409, 'other names need approval: ask for a new certificate with them '
                                  '- this one is renewed as it is')
        if waits:
            held_now = P.holders(h.store, names, row.get('owner'), row['id'], waiting=False)
            fields.update(state=P.WAITING, state_at=t, auto_renew=0)
            # The state, who sent it and `approved` taken back in one transaction (1.0.106):
            # three writes, a stop between them left it waiting still marked approved - or
            # 'pending' with the new names and never approved.
            with h.store.db.transaction():
                h.store.db.update('certs', row['id'], fields)
                P.note_asker(h.store, row['id'], sender, held_now, P.asker_ids(s), waits=True)
            h.store.add_event('certificates', '%s sent a new CSR for %s from the portal with other '
                              'names (%s) - it waits for approval' % (s['name'], row['name'],
                                                                     ', '.join(names)),
                              'warn', who=s['name'])
            if held_now:
                P.tell_holders(h.store, row['id'], held_now, sender)
            # its team's approvers told, as of a new request (hunt Rt2: it waited for them
            # unannounced)
            from acmelib.certs import teampolicy as TP
            TP.request_started_waiting(h.store, row['id'], row.get('owner'))
            return {'waits': True, 'message': 'the new CSR was taken - with other names it waits '
                                              'for approval'}
    old = {k: row.get(k) for k in fields}
    h.store.db.update('certs', row['id'], fields)
    try:
        job_id = A.start_renew(h.store, row['id'], True, P.portal_by(s))
    except (ValueError, LookupError, E.ApiError) as e:
        # refused: nothing of it kept (1.0.102)
        h.store.db.update('certs', row['id'], old)
        raise E.ApiError(409, str(e))
    P.note_asker(h.store, row['id'], sender, ids=P.asker_ids(s))
    h.store.add_event('certificates', '%s sent a new CSR for %s from the portal (%s) - it is '
                      'issued again' % (s['name'], row['name'], kt), 'warn', who=s['name'])
    return {'job_id': job_id, 'message': 'the new CSR was taken - %s is being issued again'
            % row['name']}
