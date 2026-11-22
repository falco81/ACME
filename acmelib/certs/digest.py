# -*- coding: utf-8 -*-
"""
A team's digest by mail (1.0.140, docs/teams.md "The digest") - off for every team until it is
switched on (a team's page → Digest, or acme --team-digest-set).

On the chosen day and hour (weekly, or every day) the team's contact address and/or the members
chosen get one mail - HTML with a plain-text copy, in each recipient's language where acme knows
it (their account's choice, else the digest's, else the mails') - of what needs the team:

    the certificates ending within N days (30) - and those already ended
    the renewals and deployments that failed since the last digest
    what waits: certificates waiting for approval, requests for a temporary role, access reviews
    the temporary roles granted, ending soon, ended
    the team's target agents that need a look

The team's own and those of the teams below it (unless `below` is off). Nothing secret: names,
dates, states and what the jobs said. A digest with nothing in it is not sent (unless
`skip_empty` is off). Each sending is an event naming the team (its Activity shows it).

    config(t) / clean(store, t, v) / save(store, team, v, by)
    collect(store, team, cfg, since)      what goes in
    build(store, team, cfg, lang, since)  (subject, html, text, counts)
    preview / send_me / send_now          the pages' buttons
    tick(store)                           the schedule (reports.tick, on the node that leads)
"""
from __future__ import annotations

import datetime
import json
import re
import time

from acmelib import engine as E
from acmelib.certs import reports as RP
from acmelib.certs import store as S
from acmelib.certs import teams as T

EVERY = ('weekly', 'daily')
DEFAULTS = {'on': False, 'every': 'weekly', 'day': 1, 'hour': 7, 'contact': True,
            'members': [], 'days': 30, 'skip_empty': True, 'below': True, 'lang': ''}
META_LAST = 'digest:last:%s'
META_PERIOD = 'digest:period:%s'
MOST_ITEMS = 40
_ME = {}                    # (who) -> when a preview went to them last (one a minute)


def _low(v):
    return str(v or '').strip().lower()


def _now():
    return time.time()


def L(lang, words):
    return RP.L(lang, words)


def Lf(lang, words, *args):
    return RP.Lf(lang, words, *args)


# ---------------------------------------------------------------------------
# The settings (the team's extras: 'digest')
# ---------------------------------------------------------------------------
def _extras(t):
    got = S.jload((t or {}).get('extras'), {}) if t else {}
    return got if isinstance(got, dict) else {}


def config(t):
    """The digest of a team as set - the defaults (off) where nothing is."""
    got = _extras(t).get('digest')
    out = dict(DEFAULTS)
    if isinstance(got, dict):
        out.update({k: got[k] for k in DEFAULTS if k in got})
        out['since'] = got.get('since') or 0
    out['members'] = [str(m) for m in out.get('members') or []]
    return out


def _team(store, team):
    t = T.team_get(store, team)
    if not t:
        raise LookupError('there is no team %s' % str(team)[:120])
    return t


def _int(v, what, lo, hi, default):
    return RP._int(v, what, lo, hi, default)


def _flag(v, default):
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(v)


def clean(store, t, v):
    """The digest's settings checked against the team (its members)."""
    v = v if isinstance(v, dict) else {}
    cur = config(t)
    every = str(v.get('every', cur['every']) or 'weekly')
    if every not in EVERY:
        raise ValueError('a digest goes weekly or daily')
    out = {'on': _flag(v.get('on'), cur['on']), 'every': every,
           'day': _int(v.get('day', cur['day']), 'the day of the week', 1, 7, 1),
           'hour': _int(v.get('hour', cur['hour']), 'the hour', 0, 23, 7),
           'contact': _flag(v.get('contact'), cur['contact']),
           'days': _int(v.get('days', cur['days']), 'the days ahead', 1, 365, 30),
           'skip_empty': _flag(v.get('skip_empty'), cur['skip_empty']),
           'below': _flag(v.get('below'), cur['below']),
           'lang': str(v.get('lang', cur['lang']) or '')}
    if out['lang'] not in ('', 'cs', 'en'):
        raise ValueError('the language is cs, en or empty (each recipient\'s own)')
    mem = v.get('members', cur['members'])
    if isinstance(mem, str):
        mem = [m for m in re.split(r'\s*[,\n]\s*', mem) if m.strip()]
    have = {_low(m.get('who')): m.get('who') for m in (S.jload(t.get('members'), []) or [])
            if isinstance(m, dict) and m.get('who')}
    got = []
    for m in mem or []:
        k = _low(m)
        if k not in have:
            raise ValueError('%s is not a member of the team %s' % (str(m)[:120], t['name']))
        if have[k] not in got:
            got.append(have[k])
    out['members'] = got[:200]
    if out['on'] and not got and not (out['contact'] and _contact(t)):
        raise ValueError('the digest goes nowhere: the team has no contact address - choose '
                         'members, or give the team its address first')
    return out


def _contact(t):
    return [m for m in re.split(r'[\s,;]+', str((t or {}).get('contact_mail') or '')) if m]


def save(store, team, v, by):
    t = _team(store, team)
    clean_v = clean(store, t, v)
    ex = _extras(t)
    before = config(t)
    when = (clean_v['every'], clean_v['day'], clean_v['hour'], clean_v['on'])
    if before.get('since') and (before['every'], before['day'], before['hour'], before['on']) \
            == when:
        clean_v['since'] = before['since']
    else:
        clean_v['since'] = _now()          # the first one at the next moment chosen, not at once
    ex['digest'] = clean_v
    store.db.update('cert_teams', t['id'], {'extras': json.dumps(ex, sort_keys=True),
                                            'updated': _now(), 'updated_by': str(by)[:190]})
    T.changed()
    store.add_event('certificates', 'the team %s: the digest %s by %s (%s, %s)' % (
        t['name'], 'switched on' if clean_v['on'] else 'set (off)', by,
        clean_v['every'] if clean_v['every'] == 'daily' else 'weekly, day %d' % clean_v['day'],
        '%02d:00' % clean_v['hour']), who=str(by)[:190])
    return public(store, _team(store, t['name']))


def last(store, t):
    try:
        got = json.loads(store.get_meta(META_LAST % t['id']) or '{}')
    except (TypeError, ValueError):
        got = {}
    return got if isinstance(got, dict) else {}


def next_at(cfg, now=None):
    """When the next digest goes (epoch), or None while it is off."""
    if not cfg.get('on'):
        return None
    now = now or _now()
    n = datetime.datetime.fromtimestamp(now)
    for add in range(0, 9):
        d = (n + datetime.timedelta(days=add)).replace(hour=int(cfg['hour']), minute=0, second=0,
                                                       microsecond=0)
        if cfg['every'] == 'weekly' and d.isoweekday() != int(cfg['day']):
            continue
        ts = time.mktime(d.timetuple())
        if ts > now:
            return ts
    return None


def public(store, t, full=False):
    cfg = config(t)
    out = {k: cfg[k] for k in DEFAULTS}
    out['next_at'] = next_at(cfg)
    lt = last(store, t)
    out['last'] = {k: lt.get(k) for k in ('at', 'ok', 'said', 'items', 'to_count', 'skipped')} \
        if lt else None
    out['contact_mail'] = _contact(t) if full else bool(_contact(t))
    return out


# ---------------------------------------------------------------------------
# To whom: the contact address, the members chosen (their accounts' addresses and languages)
# ---------------------------------------------------------------------------
def default_lang(cfg=None):
    got = str((cfg or {}).get('lang') or '')
    return got if got in ('cs', 'en') else str(E.CONFIG.get('mail_lang') or 'cs')


def _acc_lang(acc):
    try:
        got = (json.loads(acc.get('prefs') or '{}') or {}).get('lang')
    except (TypeError, ValueError):
        got = None
    return got if got in ('cs', 'en') else None


def _principal(acc):
    if acc.get('source') == 'directory':
        names = {_low(acc['name'])}
        if acc.get('dn'):
            names.add(_low(acc['dn']))
        return names, T.groups_of_text(acc.get('group_list'))
    return {'local:' + _low(acc['name'])}, []


def recipients(store, t, cfg):
    """[{mail, lang, who}] - each address once."""
    out, seen = [], set()
    dl = default_lang(cfg)
    if cfg.get('contact'):
        for m in _contact(t):
            if _low(m) not in seen:
                seen.add(_low(m))
                out.append({'mail': m, 'lang': dl, 'who': 'contact'})
    if cfg.get('members'):
        now = _now()
        live = {_low(m.get('who')) for m in (S.jload(t.get('members'), []) or [])
                if isinstance(m, dict) and not T.member_expired(m, now)}
        accs = [a for a in store.accounts() if not a.get('disabled') and
                T.MAIL_RE.match(str(a.get('mail') or '').strip())]
        for who in cfg['members']:
            if _low(who) not in live:
                continue                    # a membership that ended gets nothing
            for a in accs:
                names, groups = _principal(a)
                if T.member_matches(who, names, groups):
                    m = str(a['mail']).strip()
                    if _low(m) not in seen:
                        seen.add(_low(m))
                        out.append({'mail': m, 'lang': (cfg.get('lang') or _acc_lang(a) or dl),
                                    'who': a['name']})
    return out


# ---------------------------------------------------------------------------
# What goes in
# ---------------------------------------------------------------------------
def _teams_of(store, t, cfg):
    k = _low(t['name'])
    out = {k}
    if cfg.get('below', True):
        out.update(T.tree(store).descendants(k))
    return out


def _marks(part):
    return ', '.join('?' * len(part))


def collect(store, team, cfg, since, now=None):
    """{expiring, expired, failed, deploys, approvals, elevations, reviews, roles_now,
    roles_ended, agents, counts} of the team (and those below it) - nothing secret."""
    t = _team(store, team) if not isinstance(team, dict) else team
    now = now or _now()
    tr = T.tree(store)
    part = sorted(_teams_of(store, t, cfg))
    marks = _marks(part)
    days = int(cfg.get('days') or 30)
    out = {'expiring': [], 'expired': [], 'failed': [], 'deploys': [], 'approvals': [],
           'elevations': [], 'reviews': [], 'roles_now': [], 'roles_ended': [], 'agents': []}
    certs = store.db.rows('SELECT id, name, names, owner, not_after, state, auto_renew, enabled, '
                          'created_by, created FROM certs WHERE LOWER(TRIM(owner)) IN (%s) '
                          'ORDER BY not_after' % marks, tuple(part))
    by_id = {c['id']: c for c in certs}
    for c in certs:
        st = c.get('state') or ''
        if st in ('revoked', 'disabled'):
            continue
        na = float(c.get('not_after') or 0)
        one = {'id': c['id'], 'name': c['name'], 'team': RP._team_name(tr, c['owner']),
               'names': RP._names(c, 3), 'ends': na, 'left': int((na - now) / 86400) if na
               else None, 'auto': bool(int(c.get('auto_renew') or 0)), 'state': st}
        if na and na < now:
            out['expired'].append(one)
        elif na and na <= now + days * 86400:
            out['expiring'].append(one)
        if st == 'pending-approval':
            out['approvals'].append({'name': c['name'], 'team': one['team'],
                                     'by': c.get('created_by') or '', 'at': c.get('created')})
    if by_id:
        ids = sorted(by_id)
        jobs = store.db.rows("SELECT cert_id, kind, target, ts, said FROM cert_jobs WHERE "
                             "state = 'failed' AND ts >= ? AND kind IN ('renew', 'issue', "
                             "'deploy') AND cert_id IN (%s) ORDER BY ts" % _marks(ids),
                             (since,) + tuple(ids))
        grouped = {}
        for j in jobs:
            key = (j['cert_id'], j['kind'], j.get('target') or '')
            g = grouped.setdefault(key, {'cert': by_id[j['cert_id']]['name'],
                                         'team': RP._team_name(tr, by_id[j['cert_id']]['owner']),
                                         'kind': j['kind'], 'target': j.get('target') or '',
                                         'times': 0, 'last': 0, 'said': ''})
            g['times'] += 1
            g['last'] = float(j['ts'] or 0)
            g['said'] = ' '.join(str(j.get('said') or '').split())[:200]
        out['failed'] = sorted(grouped.values(), key=lambda g: -g['last'])
        for d in store.db.rows("SELECT cert_id, target, last_try, last_error FROM cert_deploys "
                               "WHERE state = 'failed' AND cert_id IN (%s) ORDER BY last_try"
                               % _marks(ids), tuple(ids)):
            out['deploys'].append({'cert': by_id[d['cert_id']]['name'], 'target': d['target'],
                                   'since': d.get('last_try'),
                                   'error': ' '.join(str(d.get('last_error') or '').split())[:200]})
    try:
        for e in store.db.rows("SELECT * FROM cert_team_elevations WHERE LOWER(TRIM(team)) IN "
                               "(%s) ORDER BY asked" % marks, tuple(part)):
            st = e.get('state')
            row = {'team': tr.name(_low(e['team'])) if _low(e['team']) in tr.rows else e['team'],
                   'who': e.get('who') or '', 'role': e.get('role') or '',
                   'hours': e.get('hours'), 'asked': e.get('asked'), 'until': e.get('until'),
                   'decided': e.get('decided'), 'ended': e.get('ended'),
                   'reason': ' '.join(str(e.get('reason') or '').split())[:160]}
            if st == 'waiting':
                out['elevations'].append(row)
            elif st == 'granted' and float(e.get('until') or 0) > now:
                row['new'] = float(e.get('decided') or 0) >= since
                row['ends_soon'] = float(e.get('until') or 0) <= now + 2 * 86400
                out['roles_now'].append(row)
            elif st == 'ended' and float(e.get('ended') or e.get('until') or 0) >= since:
                out['roles_ended'].append(row)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('digest-elev', 'the digest: the temporary roles: %s' % e, 'warn',
                      every=3600)
    try:
        for r in store.db.rows("SELECT * FROM cert_team_reviews WHERE LOWER(TRIM(team)) IN (%s) "
                               "AND state IN ('open', 'overdue') ORDER BY started" % marks,
                               tuple(part)):
            items = S.jload(r.get('items'), []) or []
            pending = len([i for i in items if isinstance(i, dict) and
                           i.get('state') in (None, '', 'pending')])
            out['reviews'].append({'team': tr.name(_low(r['team'])) if _low(r['team']) in tr.rows
                                   else r['team'], 'due': r.get('due'), 'pending': pending,
                                   'late': r.get('state') == 'overdue' or
                                   float(r.get('due') or 0) < now})
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('digest-review', 'the digest: the access reviews: %s' % e, 'warn',
                      every=3600)
    try:
        for r in RP.agent_rows(store, set(part)):
            state, probs, f = RP.agent_look(store, r, now)
            if probs:
                out['agents'].append({'name': r['name'], 'team': RP._team_name(tr, r['owner']),
                                      'state': state, 'look': probs, 'version': f['version']})
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('digest-agents', 'the digest: the agents: %s' % e, 'warn', every=3600)
    for k in out:
        out[k] = out[k][:MOST_ITEMS] if k not in ('expiring',) else out[k][:MOST_ITEMS * 3]
    out['counts'] = {
        'ending': len(out['expiring']) + len(out['expired']),
        'failed': len(out['failed']) + len([d for d in out['deploys']
                                            if float(d.get('since') or 0) < since]),
        'waiting': len(out['approvals']) + len(out['elevations']) + len(out['reviews']),
        'roles': len(out['roles_now']) + len(out['roles_ended']),
        'agents': len(out['agents'])}
    out['empty'] = not any(out['counts'].values())
    return out


# ---------------------------------------------------------------------------
# The mail
# ---------------------------------------------------------------------------
def _btn(href, words):
    return ('<table role="presentation" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:10px 0 4px"><tr><td bgcolor="#1d4ed8" style="background:#1d4ed8;'
            'border-radius:8px;padding:9px 16px;%s"><a href="%s" style="color:#ffffff;'
            'text-decoration:none;font-weight:600;font-size:13.5px">%s</a></td></tr></table>'
            % (E.AL_FONT, E._h(href), E._h(words)))


def _pill(words, tone):
    edge, back, ink = E.AL_COLORS.get(tone, E.AL_COLORS['info'])
    return ('<span style="display:inline-block;padding:1px 8px;border-radius:10px;'
            'background:%s;color:%s;font-size:12px;font-weight:600;white-space:nowrap">%s</span>'
            % (back, ink, E._h(words)))


def _section(body, text, title, head, rows, plain):
    body.append(E._al_h(title))
    body.append(E._rep_table(head, rows))
    text.append(title.upper())
    text.extend('- ' + p for p in plain)
    text.append('')


def build(store, team, cfg, lang, since, now=None, preview=False):
    """(subject, html, text, data) of the team's digest in `lang`."""
    t = _team(store, team) if not isinstance(team, dict) else team
    now = now or _now()
    data = collect(store, t, cfg, since, now)
    c = data['counts']
    site = RP.site()
    link = E.alerts_link()
    day = lambda ts: RP.day(ts, lang)          # noqa: E731
    daily = cfg.get('every') == 'daily'
    title = L(lang, 'Daily digest') if daily else L(lang, 'Weekly digest')
    body, text = [], []
    body.append('<p style="margin:0 0 6px;font-size:15px;color:#111827"><b>%s</b></p>' % E._h(
        Lf(lang, 'What needs the team {0}', t['name'])))
    body.append('<p style="margin:0 0 14px;font-size:13.5px;color:#4b5563">%s</p>' % E._h(
        Lf(lang, 'Since {0}, as of {1}.', RP.stamp(since, lang), RP.stamp(now, lang))))
    text += [Lf(lang, 'What needs the team {0}', t['name']),
             Lf(lang, 'Since {0}, as of {1}.', RP.stamp(since, lang), RP.stamp(now, lang)), '']
    days = int(cfg.get('days') or 30)
    tiles = [(Lf(lang, 'ending within {0} days', days), str(c['ending']),
              'bad' if data['expired'] else 'warn' if c['ending'] else 'good'),
             (L(lang, 'failed'), str(c['failed']), 'bad' if c['failed'] else 'good'),
             (L(lang, 'waiting'), str(c['waiting']), 'warn' if c['waiting'] else 'good'),
             (L(lang, 'agents to look at'), str(c['agents']), 'warn' if c['agents'] else 'good')]
    body.append(E._rep_tiles(tiles))
    text += ['%s: %s' % (a, b) for a, b, _c in tiles] + ['']
    if data['empty']:
        body.append(E._al_card('good', L(lang, 'Nothing needs the team now'), [E._h(L(
            lang, 'No certificate ends soon, nothing failed, nothing waits and every agent '
                  'answers.'))]))
        text += [L(lang, 'Nothing needs the team now'), '']
    ending = data['expired'] + data['expiring']
    if ending:
        rows, plain = [], []
        for e in ending:
            gone = e['left'] is not None and e['left'] < 0
            left = L(lang, 'ended') if gone else Lf(lang, '{0} days', e['left'])
            tone = 'bad' if gone or (e['left'] is not None and e['left'] < 7) else 'warn'
            rows.append(['<b>%s</b><div style="font-size:11.5px;color:#6b7280">%s</div>' % (
                E._h(e['name']), E._h(e['names'])), E._h(e['team']), E._h(day(e['ends'])),
                _pill(left, tone), E._h(L(lang, 'by itself') if e['auto'] else
                                         L(lang, 'by hand'))])
            plain.append('%s (%s) - %s, %s' % (e['name'], e['team'], day(e['ends']), left))
        _section(body, text, Lf(lang, 'Certificates ending within {0} days', days),
                 [L(lang, 'Certificate'), L(lang, 'Team'), L(lang, 'Ends'), L(lang, 'Left'),
                  L(lang, 'Renewal')], rows, plain)
        body.append(_btn(link + '#certs', L(lang, 'Open the certificates in acme')))
    if data['failed'] or data['deploys']:
        rows, plain = [], []
        kinds = {'renew': L(lang, 'renewal'), 'issue': L(lang, 'issue'),
                 'deploy': L(lang, 'deployment')}
        for f in data['failed']:
            rows.append(['<b>%s</b>' % E._h(f['cert']), E._h(kinds.get(f['kind'], f['kind'])),
                         E._h(f['target'] or '-'), E._h(str(f['times'])),
                         '<span style="color:#991b1b">%s</span>' % E._h(L(lang, f['said'])[:160])])
            plain.append('%s: %s%s, %dx - %s' % (f['cert'], kinds.get(f['kind'], f['kind']),
                                                 (' → ' + f['target']) if f['target'] else '',
                                                 f['times'], f['said'][:160]))
        _section(body, text, L(lang, 'What failed since the last digest'),
                 [L(lang, 'Certificate'), L(lang, 'What'), L(lang, 'Where'), '#' + L(lang, 'Times'),
                  L(lang, 'Last said')], rows, plain)
        if data['deploys']:
            rows, plain = [], []
            for d in data['deploys']:
                rows.append(['<b>%s</b>' % E._h(d['cert']), E._h(d['target']),
                             E._h(day(d['since'])), '<span style="color:#991b1b">%s</span>'
                             % E._h(L(lang, d['error'])[:160])])
                plain.append('%s → %s: %s' % (d['cert'], d['target'], d['error'][:160]))
            _section(body, text, L(lang, 'Deployments failing now'),
                     [L(lang, 'Certificate'), L(lang, 'Target'), L(lang, 'Last tried'),
                      L(lang, 'Last said')], rows, plain)
        body.append(_btn(link + '#jobs', L(lang, 'Open the jobs in acme')))
    if data['approvals'] or data['elevations'] or data['reviews']:
        body.append(E._al_h(L(lang, 'Waiting')))
        text.append(L(lang, 'Waiting').upper())
        for a in data['approvals']:
            body.append(E._al_card('warn', Lf(lang, 'The certificate {0} waits for approval',
                                              a['name']),
                                   [E._h(Lf(lang, 'Asked for by {0} on {1}', a['by'] or '?',
                                            day(a['at'])))]))
            text.append('- ' + Lf(lang, 'The certificate {0} waits for approval', a['name']))
        for e in data['elevations']:
            body.append(E._al_card('warn', Lf(lang, '{0} asks for the role {1}', e['who'],
                                              e['role']),
                                   [E._h(Lf(lang, 'For {0} h in the team {1}', e['hours'],
                                            e['team'])), E._h(e['reason'])]))
            text.append('- ' + Lf(lang, '{0} asks for the role {1}', e['who'], e['role']))
        for r in data['reviews']:
            body.append(E._al_card('bad' if r['late'] else 'warn',
                                   Lf(lang, 'An access review of the team {0}', r['team']),
                                   [E._h(Lf(lang, '{0} members to confirm by {1}', r['pending'],
                                            day(r['due'])))]))
            text.append('- ' + Lf(lang, 'An access review of the team {0}', r['team']))
        text.append('')
        body.append(_btn(link + '#settings/teams', L(lang, 'Open the team in acme')))
    if data['roles_now'] or data['roles_ended']:
        rows, plain = [], []
        for e in data['roles_now']:
            st = _pill(L(lang, 'ends soon'), 'warn') if e.get('ends_soon') else \
                _pill(L(lang, 'new'), 'info') if e.get('new') else _pill(L(lang, 'granted'),
                                                                         'good')
            rows.append([E._h(e['who']), E._h(e['role']), E._h(e['team']),
                         E._h(RP.stamp(e['until'], lang)), st])
            plain.append('%s: %s (%s) %s %s' % (e['who'], e['role'], e['team'], L(lang, 'until'),
                                                RP.stamp(e['until'], lang)))
        for e in data['roles_ended']:
            rows.append([E._h(e['who']), E._h(e['role']), E._h(e['team']),
                         E._h(RP.stamp(e.get('ended') or e.get('until'), lang)),
                         _pill(L(lang, 'ended'), 'info')])
            plain.append('%s: %s (%s) - %s' % (e['who'], e['role'], e['team'], L(lang, 'ended')))
        _section(body, text, L(lang, 'Temporary roles'),
                 [L(lang, 'Who'), L(lang, 'Role'), L(lang, 'Team'), L(lang, 'Until'),
                  L(lang, 'State')], rows, plain)
    if data['agents']:
        rows, plain = [], []
        for a in data['agents']:
            rows.append(['<b>%s</b>' % E._h(a['name']), E._h(a['team']),
                         _pill(L(lang, RP.AGENT_WORDS.get(a['state'], a['state'])),
                               {'good': 'good', 'bad': 'bad', 'warn': 'warn'}.get(
                                   RP.AGENT_TONE.get(a['state']), 'info')),
                         E._h('; '.join(L(lang, p) for p in a['look']))])
            plain.append('%s (%s): %s' % (a['name'], a['team'],
                                          '; '.join(L(lang, p) for p in a['look'])))
        _section(body, text, L(lang, 'Agents that need a look'),
                 [L(lang, 'Agent'), L(lang, 'Team'), L(lang, 'State'), L(lang, 'What')],
                 rows, plain)
        body.append(_btn(link + '#settings/agents', L(lang, 'Open the agents in acme')))
    foot = E._h(Lf(lang, 'Sent by acme from {0} to the team {1}. Owners and teams → {1} → '
                         'Digest says who gets it and when.', site, t['name']))
    if preview:
        foot = E._h(L(lang, 'A preview - nothing was sent.')) + ' ' + foot
    kicker = 'acme · %s' % t['name']
    page = E._al_page(lang, title, kicker, E.AL_COLORS['info'][2], ''.join(body), foot)
    text += ['-- ', re.sub(r'<[^>]+>', '', __import__('html').unescape(foot)), link]
    if data['empty']:
        said = L(lang, 'nothing needs attention')
    else:
        bits = []
        if c['ending']:
            bits.append(Lf(lang, '{0} ending', c['ending']))
        if c['failed']:
            bits.append(Lf(lang, '{0} failed', c['failed']))
        if c['waiting']:
            bits.append(Lf(lang, '{0} waiting', c['waiting']))
        if c['agents']:
            bits.append(Lf(lang, '{0} agents', c['agents']))
        if c['roles'] and not bits:
            bits.append(Lf(lang, '{0} temporary roles', c['roles']))
        said = ', '.join(bits)
    subject = '[acme] %s: %s - %s' % (t['name'], title.lower() if lang == 'en' else title, said)
    if preview:
        subject = '[%s] %s' % (L(lang, 'preview'), subject)
    return subject, page, '\n'.join(text), data


def _since(store, t, cfg, now=None):
    now = now or _now()
    lt = last(store, t)
    if lt.get('at'):
        return float(lt['at'])
    return now - (86400 if cfg.get('every') == 'daily' else 7 * 86400)


def preview(store, team, cfg=None, lang='en', full=False):
    t = _team(store, team)
    cfg = clean(store, t, cfg) if cfg is not None else config(t)
    since = _since(store, t, cfg)
    subject, page, text, data = build(store, t, cfg, lang, since, preview=True)
    to = recipients(store, t, cfg)
    return {'team': t['name'], 'subject': subject, 'html': page, 'text': text,
            'counts': data['counts'], 'empty': data['empty'], 'since': since,
            'mail_on': (E.CONFIG.get('mail_mode') or 'off') != 'off',
            'recipients': [dict(r) for r in to] if full else
            [{'who': r['who'] if r['who'] != 'contact' else 'contact', 'lang': r['lang']}
             for r in to],
            'would_skip': bool(data['empty'] and cfg.get('skip_empty', True))}


def _deliver(store, t, subject, page, text, to, purpose, by=''):
    msg = E._al_msg(subject, page, text, to)
    E.mail_deliver(store, msg, to, kind='report', name=t['name'], by=by, purpose=purpose)


def send_me(store, team, s, cfg=None, lang=None):
    """A preview mailed to the one asking (their account's address) - nothing else."""
    if (E.CONFIG.get('mail_mode') or 'off') == 'off':
        raise E.ApiError(409, 'mail is switched off (Settings → Mail) - nothing can be sent')
    who = str(s.get('name') or '')
    acc = store.account(who) if who else None
    mail = str((acc or {}).get('mail') or '').strip()
    if not T.MAIL_RE.match(mail):
        raise E.ApiError(409, 'your account has no mail address (Accounts, or your directory) '
                              '- nowhere to send the preview')
    if _now() - _ME.get(_low(who), 0) < 20:
        raise E.ApiError(429, 'a preview went to you a moment ago - wait a little')
    _ME[_low(who)] = _now()
    t = _team(store, team)
    cfg = clean(store, t, cfg) if cfg is not None else config(t)
    lang = lang or _acc_lang(acc or {}) or default_lang(cfg)
    subject, page, text, data = build(store, t, cfg, lang, _since(store, t, cfg), preview=True)
    try:
        _deliver(store, t, subject, page, text, [mail], 'team digest preview', who)
        said = 'sent'
    except E.MailError as e:
        if getattr(e, 'queued', None) != 'waiting':
            store.add_event('certificates', 'a preview of the digest of the team %s did not go '
                            'to %s: %s' % (t['name'], who, str(e)[:200]), 'warn', who=who)
            raise E.ApiError(502, 'the mail did not go: %s' % str(e)[:300])
        said = 'waiting in the outgoing mail for another try'
    store.add_event('certificates', 'a preview of the digest of the team %s was sent to %s (%s)'
                    % (t['name'], who, mail), who=who)
    return {'to': mail, 'said': said, 'counts': data['counts']}


def send(store, team, by, cfg=None, since=None, period='', force=False):
    """The digest to its recipients now - one mail per language. -> what happened (also kept as
    the team's last digest, and an event)."""
    t = _team(store, team) if not isinstance(team, dict) else team
    cfg = cfg or config(t)
    now = _now()
    since = since if since is not None else _since(store, t, cfg, now)
    to = recipients(store, t, cfg)
    rec = {'at': now, 'period': period, 'since': since, 'ok': False, 'said': '', 'items': 0,
           'to_count': len(to), 'skipped': False}
    probe = collect(store, t, cfg, since, now)
    rec['items'] = sum(probe['counts'].values())
    if probe['empty'] and cfg.get('skip_empty', True) and not force:
        rec.update(ok=True, skipped=True, said='nothing to tell - not sent')
        store.add_event('certificates', 'the digest of the team %s was not sent: nothing to '
                        'tell' % t['name'], who=str(by)[:190])
    elif (E.CONFIG.get('mail_mode') or 'off') == 'off':
        rec['said'] = 'mail is switched off (Settings → Mail) - nothing was sent'
        store.add_event('certificates', 'the digest of the team %s was not sent: mail is '
                        'switched off' % t['name'], 'warn', who=str(by)[:190])
    elif not to:
        rec['said'] = 'nobody to send it to'
        store.add_event('certificates', 'the digest of the team %s was not sent: nobody to send '
                        'it to (no contact address, no member with an address)' % t['name'],
                        'warn', who=str(by)[:190])
    else:
        by_lang = {}
        for r in to:
            by_lang.setdefault(r['lang'], []).append(r['mail'])
        went, fails = [], []
        for lang, mails in sorted(by_lang.items()):
            subject, page, text, _d = build(store, t, cfg, lang, since, now)
            try:
                _deliver(store, t, subject, page, text, mails, 'team digest', str(by))
                went += mails
            except E.MailError as e:
                if getattr(e, 'queued', None) == 'waiting':
                    went += mails
                else:
                    fails.append('%s: %s' % (', '.join(mails), str(e)[:200]))
            except Exception as e:                      # noqa: BLE001
                fails.append('%s: %s' % (', '.join(mails), str(e)[:200]))
        rec['ok'] = not fails
        rec['said'] = 'sent to %s' % ', '.join(went) if went else ''
        if fails:
            rec['said'] = (rec['said'] + '; ' if rec['said'] else '') + 'not sent to ' + \
                '; '.join(fails)
        store.add_event('certificates', 'the digest of the team %s was %s (%d item(s))' % (
            t['name'], rec['said'], rec['items']), 'info' if rec['ok'] else 'warn',
            who=str(by)[:190])
    store.set_meta(META_LAST % t['id'], json.dumps(rec))
    return rec


def send_now(store, team, by):
    """Settings → the team → Digest → Send now (and acme --team-digest-send): to its recipients
    at once, an empty one too - the next one covers what came after."""
    t = _team(store, team)
    cfg = config(t)
    if not recipients(store, t, cfg):
        raise E.ApiError(409, 'the digest of the team %s goes to nobody: its contact address or '
                              'members with an address' % t['name'])
    return send(store, t, by, cfg, force=True)


# ---------------------------------------------------------------------------
# The schedule
# ---------------------------------------------------------------------------
def due_period(cfg, now=None):
    if not cfg.get('on'):
        return None
    now = now or _now()
    n = datetime.datetime.fromtimestamp(now)
    if cfg.get('every') == 'daily':
        at = n.replace(hour=int(cfg['hour']), minute=0, second=0, microsecond=0)
        key = 'd:%s' % n.strftime('%Y-%m-%d')
    else:
        start = (n - datetime.timedelta(days=n.isoweekday() - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0)
        at = start + datetime.timedelta(days=int(cfg['day']) - 1, hours=int(cfg['hour']))
        key = 'w:%04d-%02d' % tuple(n.isocalendar()[:2])
    ts = time.mktime(at.timetuple())
    if now < ts or ts < float(cfg.get('since') or 0):
        return None
    return key


def tick(store, now=None):
    for t in T.team_rows(store):
        cfg = config(t)
        if not cfg['on']:
            continue
        key = due_period(cfg, now)
        if not key:
            continue
        mk = META_PERIOD % t['id']
        if store.get_meta(mk) == key or not E.claim_once(store, mk, key):
            continue
        try:
            send(store, t, 'the schedule', cfg, period=key)
        except Exception as e:                          # noqa: BLE001
            store.add_event('certificates', 'the digest of the team %s could not be made: %s'
                            % (t['name'], str(e)[:300]), 'warn')
