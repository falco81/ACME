# -*- coding: utf-8 -*-
"""
Periodic reports (Settings → Reports) and the teams' digests (a team's page → Digest) in the
administration (1.0.140, docs/reports.md, docs/teams.md "The digest"):

    GET  /api/reports                        the reports one may see, their last runs, the kinds
                                             (a full administrator every one; a certificate
                                             administrator those of the teams they manage)
    GET  /api/reports/one?id=                one, with its runs
    POST /api/reports/save {id?, name, kind, teams[], formats[], schedule{every, day, hour},
                            recipients, lang, keep, options{days}, enabled, note}     (full)
    POST /api/reports/delete {id}            (full)
    POST /api/reports/preview {id} | {draft} what it says now - nothing kept (a draft: full)
    POST /api/reports/run {id, send, to?}    made now, kept, mailed when `send` (full)
    GET  /api/reports/runs?id=               its runs kept
    GET  /api/reports/download?run=&format=  a run's file: {filename, mime, data_b64}

    GET  /api/teams/digest?team=             the team's digest: settings, when, last (who sees
                                             the team)
    POST /api/teams/digest_save {team, digest{on, every, day, hour, contact, members[], days,
                                skip_empty, below, lang}}                               (full)
    POST /api/teams/digest_preview {team, digest?, lang?}   the mail as it would go (HTML and
                                             text) - nothing sent (who sees the team)
    POST /api/teams/digest_send_me {team, digest?}  a preview to one's own address
    POST /api/teams/digest_send {team}       to its recipients now (full)
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import digest as D
from acmelib.certs import reports as RP
from acmelib.certs import teams as T


def _full(s):
    return s.get('role') == 'fulladmin' or bool(s.get('cli'))


def _mail_on():
    return (E.CONFIG.get('mail_mode') or 'off') != 'off'


def _lang_of(h, s, b=None):
    got = str((b or {}).get('lang') or h.arg('lang') or '')
    if got in ('cs', 'en'):
        return got
    try:
        import json
        acc = s.get('account') or {}
        pl = (json.loads(acc.get('prefs') or '{}') or {}).get('lang')
        if pl in ('cs', 'en'):
            return pl
    except Exception:                                   # noqa: BLE001
        pass
    return str(E.CONFIG.get('ui_lang') or 'en')


# ---- the reports ---------------------------------------------------------------------------
@A.api('GET', '/api/reports', 'certadmin')
def _reports(h, s):
    out = []
    for r in RP.rows(h.store):
        if not RP.may_see(h.store, s, r):
            continue
        one = RP.public(r)
        last = RP.runs(h.store, r, 1)
        one['last'] = last[0] if last else None
        one['next_at'] = _next(r)
        if not _full(s):
            one['recipients'] = [] if not one['recipients'] else ['…'] * len(one['recipients'])
        out.append(one)
    return {'reports': out, 'may_change': _full(s), 'mail_on': _mail_on(),
            'kinds': [{'kind': k, 'words': RP.KIND_WORDS[k], 'says': RP.KIND_SAYS[k]}
                      for k in RP.KINDS],
            'formats': list(RP.FORMATS)}


def _next(r):
    """When the schedule makes it next (epoch) - None: only by hand."""
    import datetime
    import time
    sch = RP._sched(r.get('schedule'))
    if sch['every'] == 'off' or not RP.public(r)['enabled']:
        return None
    now = time.time()
    n = datetime.datetime.fromtimestamp(now)
    for add in range(0, 400):
        d = (n + datetime.timedelta(days=add)).replace(hour=sch['hour'], minute=0, second=0,
                                                       microsecond=0)
        if sch['every'] == 'weekly' and d.isoweekday() != sch['day']:
            continue
        if sch['every'] == 'monthly' and d.day != sch['day']:
            continue
        ts = time.mktime(d.timetuple())
        if ts > now:
            return ts
    return None


def _id(h, s, method='GET'):
    ref = h.arg('id') if method == 'GET' else (h.body().get('id') or h.body().get('name'))
    if ref in (None, ''):
        raise ValueError('which report? (id)')
    return RP.need_see(h.store, s, ref)


@A.api('GET', '/api/reports/one', 'certadmin')
def _report_one(h, s):
    r = _id(h, s)
    one = RP.public(r)
    one['next_at'] = _next(r)
    if not _full(s):
        one['recipients'] = []
    return {'report': one, 'runs': RP.runs(h.store, r), 'may_change': _full(s)}


@A.api('POST', '/api/reports/save', 'fulladmin')
def _report_save(h, s):
    got = RP.save(h.store, h.body(), A.who(s))
    return {'report': got, 'message': 'the report %s was saved' % got['name']}


@A.api('POST', '/api/reports/delete', 'fulladmin')
def _report_delete(h, s):
    b = h.body()
    got = RP.delete(h.store, b.get('id') or b.get('name'), A.who(s))
    return dict(got, message='the report %s was deleted' % got['deleted'])


@A.api('POST', '/api/reports/preview', 'certadmin')
def _report_preview(h, s):
    b = h.body()
    lang = b.get('lang') if b.get('lang') in ('cs', 'en') else None
    if isinstance(b.get('draft'), dict):
        if not _full(s):
            raise E.ApiError(403, 'only a full administrator defines reports')
        d = b['draft']
        row = dict(RP.clean(h.store, d, RP.get_row(h.store, d.get('id')) if d.get('id') else None),
                   id=0)
    else:
        row = _id(h, s, 'POST')
    data = RP.build(h.store, row, lang=lang)
    return {'preview': RP.preview(data)}


@A.api('POST', '/api/reports/run', 'fulladmin')
def _report_run(h, s):
    b = h.body()
    r = _id(h, s, 'POST')
    to = None
    if b.get('to') not in (None, '', []):
        raw = b['to']
        to = [m for m in T.clean_mails(', '.join(raw) if isinstance(raw, list) else raw).split(
            ', ') if m]
    got = RP.run(h.store, r, A.who(s), send=bool(b.get('send')), to=to)
    words = 'the report %s was made' % r['name']
    if b.get('send'):
        words += ' and sent' if got['ok'] else ' - it was not sent: %s' % got['said']
    return {'run': got, 'message': words, 'mail_on': _mail_on()}


@A.api('GET', '/api/reports/runs', 'certadmin')
def _report_runs(h, s):
    r = _id(h, s)
    return {'report': r['name'], 'runs': RP.runs(h.store, r)}


@A.api('GET', '/api/reports/download', 'certadmin')
def _report_download(h, s):
    fmt = str(h.arg('format') or 'pdf')
    if fmt not in RP.FORMATS:
        raise ValueError('a report is downloaded as csv or pdf')
    run = RP.run_get(h.store, h.arg('run'))
    rep = RP.get_row(h.store, run.get('report_id'))
    if not rep or not RP.may_see(h.store, s, rep):
        raise E.ApiError(403, 'you may not see that report')
    got = RP.run_file(h.store, run['id'], fmt)
    got.pop('report_id', None)
    h.store.add_event('certificates', '%s downloaded the report %s (%s, run %s)' % (
        A.who(s), rep['name'], fmt.upper(), run['id']), who=A.who(s))
    return got


# ---- the teams' digests -------------------------------------------------------------------
def _seen_team(h, s, team):
    t = T.team_get(h.store, team)
    if not t:
        raise LookupError('there is no team %s' % str(team or '')[:120])
    seen = T.scope(h.store, s, 'view')
    if seen is not None and not T.owner_in(seen, t['name']):
        raise E.ApiError(403, 'you may not see the team %s' % t['name'])
    return t


@A.api('GET', '/api/teams/digest')
def _digest(h, s):
    t = _seen_team(h, s, h.arg('team'))
    full = _full(s)
    got = D.public(h.store, t, full=full)
    members = []
    if full:
        for m in D.S.jload(t.get('members'), []) or []:
            if isinstance(m, dict) and m.get('who'):
                who = str(m['who'])
                mails = [r['mail'] for r in D.recipients(h.store, t, dict(
                    D.config(t), contact=False, members=[who]))]
                members.append({'who': who, 'kind': T.member_kind(who), 'mails': len(mails),
                                'expired': bool(m.get('until') and T.member_expired(m))})
    return {'team': t['name'], 'digest': got, 'may_change': full, 'mail_on': _mail_on(),
            'members': members}


@A.api('POST', '/api/teams/digest_save', 'fulladmin')
def _digest_save(h, s):
    b = h.body()
    got = D.save(h.store, b.get('team'), b.get('digest') or {}, A.who(s))
    return {'digest': got, 'message': 'the digest of the team %s was saved' % b.get('team')}


@A.api('POST', '/api/teams/digest_preview')
def _digest_preview(h, s):
    b = h.body()
    t = _seen_team(h, s, b.get('team'))
    draft = b.get('digest') if isinstance(b.get('digest'), dict) else None
    return {'preview': D.preview(h.store, t['name'], draft, _lang_of(h, s, b), full=_full(s))}


@A.api('POST', '/api/teams/digest_send_me')
def _digest_send_me(h, s):
    b = h.body()
    t = _seen_team(h, s, b.get('team'))
    draft = b.get('digest') if isinstance(b.get('digest'), dict) else None
    got = D.send_me(h.store, t['name'], s, draft,
                    b.get('lang') if b.get('lang') in ('cs', 'en') else None)
    return dict(got, message='a preview of the digest went to %s' % got['to'])


@A.api('POST', '/api/teams/digest_send', 'fulladmin')
def _digest_send(h, s):
    b = h.body()
    t = _seen_team(h, s, b.get('team'))
    got = D.send_now(h.store, t['name'], A.who(s))
    return {'result': got, 'message': got.get('said') or 'done'}
