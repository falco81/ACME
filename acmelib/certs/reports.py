# -*- coding: utf-8 -*-
"""
Periodic reports for management and audit (1.0.140, docs/reports.md - Settings → Reports).

A report is defined once (cert_reports): its kind, its scope (every team, or chosen teams and
the teams below them), its formats (CSV, PDF), its language, when it is made by itself (weekly
or monthly, a day and an hour - or only by hand) and to whom it is mailed. Each run is kept
(cert_report_runs, the newest `keep` of each report) with its files, to download again.
Nothing is made until a report is defined.

    KINDS                                   inventory, expiry, compliance, agents, access
    definitions(store) / get / save / delete
    build(store, rep)                       the data: tiles, columns, rows, sections
    render_csv / render_pdf / preview       the files and the page's preview
    run(store, rep, by, send, to)           made, kept, mailed - an event each time
    runs(store, rep) / run_file(store, id, fmt)
    may_see(store, s, rep)                  a full administrator every one; a certificate
                                            administrator those of the teams they manage
    tick(store)                             the schedule, on the node that leads (the renewer's
                                            scan) - and the teams' digests (digest.tick)
"""
from __future__ import annotations

import base64
import csv
import datetime
import io
import json
import re
import threading
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import teams as T

KINDS = ('inventory', 'expiry', 'compliance', 'agents', 'access')
KIND_WORDS = {'inventory': 'Certificate inventory', 'expiry': 'Expiry outlook',
              'compliance': 'Compliance with the CA/B rules', 'agents': 'Agents and their health',
              'access': 'Teams and access'}
KIND_SAYS = {
    'inventory': 'Every certificate in scope: its team, names, source, key, state and end.',
    'expiry': 'What ends within the days chosen - soonest first, with how each is renewed.',
    'compliance': 'Each certificate checked against the CA/Browser Forum\'s rules and the '
                  'company\'s own, as the request profiles\' compliance check does.',
    'agents': 'The target agents of the teams: whether each answers, its version and what '
              'needs a look.',
    'access': 'The members of each team with their roles and ends, and the last access review.'}
FORMATS = ('csv', 'pdf')
EVERY = ('off', 'weekly', 'monthly')
LANGS = ('', 'cs', 'en')
KEEP_DEFAULT = 12
NAME_RE = re.compile(r'^[^\x00-\x1f<>]{1,80}\Z')
MOST_ROWS = 50000
PDF_ROWS = 5000
PREVIEW_ROWS = 200
TICK_EVERY_S = 60
_TICK = {'at': 0.0, 'busy': False}


def _low(v):
    return str(v or '').strip().lower()


def _now():
    return time.time()


# ---------------------------------------------------------------------------
# Words in the report's language - the pages' translation (web/lang/<code>.json), as the
# alerts and the engine's report have them (i18n_mail)
# ---------------------------------------------------------------------------
def L(lang, words):
    return E.mail_tr(words, lang) if lang and lang != 'en' else words


def Lf(lang, words, *args):
    """A pattern filled, then said in the language ({0} {1} as the pages write them)."""
    out = str(words)
    for i, a in enumerate(args):
        out = out.replace('{%d}' % i, str(a))
    return L(lang, out)


def day(ts, lang):
    if not ts:
        return '-'
    try:
        return time.strftime('%d.%m.%Y' if lang == 'cs' else '%Y-%m-%d', time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return '-'


def stamp(ts, lang):
    if not ts:
        return '-'
    try:
        return time.strftime('%d.%m.%Y %H:%M' if lang == 'cs' else '%Y-%m-%d %H:%M',
                             time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return '-'


def lang_of(rep=None):
    got = str((rep or {}).get('lang') or '')
    if got in ('cs', 'en'):
        return got
    return str(E.CONFIG.get('report_lang') or E.CONFIG.get('mail_lang') or 'cs')


def site():
    import socket
    return str(E.CONFIG.get('site_name') or socket.gethostname())


# ---------------------------------------------------------------------------
# The definitions
# ---------------------------------------------------------------------------
def _sched(raw):
    s = S.jload(raw, {}) if not isinstance(raw, dict) else raw
    s = s if isinstance(s, dict) else {}
    every = s.get('every') if s.get('every') in EVERY else 'off'
    # hour 0 (midnight) is an hour: `or 7` made a report set for 00:00 come at 07:00
    hour = s.get('hour')
    return {'every': every, 'day': int(s.get('day') or 1),
            'hour': 7 if hour in (None, '') else int(hour), 'since': float(s.get('since') or 0)}


def public(r):
    """A definition as the pages, the API and the command line see it."""
    opts = S.jload(r.get('options'), {}) or {}
    return {'id': r['id'], 'name': r['name'], 'kind': r.get('kind') or 'inventory',
            'kind_words': KIND_WORDS.get(r.get('kind'), r.get('kind')),
            'teams': [t for t in (S.jload(r.get('teams'), []) or []) if t],
            'formats': [f for f in (S.jload(r.get('formats'), []) or []) if f in FORMATS] or ['pdf'],
            'schedule': {k: v for k, v in _sched(r.get('schedule')).items() if k != 'since'},
            'recipients': [m for m in re.split(r'[\s,;]+', str(r.get('recipients') or '')) if m],
            'lang': r.get('lang') or '', 'keep': int(r.get('keep') or KEEP_DEFAULT),
            'enabled': r.get('enabled') is None or bool(int(r.get('enabled') or 0)),
            'options': opts if isinstance(opts, dict) else {}, 'note': r.get('note') or '',
            'created': r.get('created'), 'created_by': r.get('created_by') or '',
            'updated': r.get('updated'), 'updated_by': r.get('updated_by') or '',
            'last_run': r.get('last_run'), 'last_ok': r.get('last_ok'),
            'last_said': r.get('last_said') or ''}


def rows(store):
    try:
        return store.db.rows('SELECT * FROM cert_reports ORDER BY %s' % store.db.name_order())
    except Exception:                                   # noqa: BLE001
        return store.db.rows('SELECT * FROM cert_reports ORDER BY name')


def definitions(store):
    return [public(r) for r in rows(store)]


def get_row(store, ref):
    """A definition by its number or its name - or None."""
    if ref in (None, ''):
        return None
    if isinstance(ref, int) or str(ref).isdigit():
        got = store.db.row('SELECT * FROM cert_reports WHERE id = ?', (int(ref),))
        if got:
            return got
    n = _low(ref)
    for r in rows(store):
        if _low(r['name']) == n:
            return r
    return None


def need(store, ref):
    r = get_row(store, ref)
    if not r:
        raise LookupError('there is no report %s' % str(ref)[:80])
    return r


def _int(v, what, lo, hi, default):
    if v in (None, ''):
        return default
    if isinstance(v, bool):
        raise ValueError('%s is a number' % what)
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a number' % what)
    if not lo <= n <= hi:
        raise ValueError('%s is %d to %d' % (what, lo, hi))
    return n


def clean(store, b, old=None):
    """A definition sent by the pages or the command line, checked: {column: value}."""
    b = b if isinstance(b, dict) else {}
    cur = public(old) if old else {}
    name = str(b.get('name', cur.get('name', '')) or '').strip()
    if not name or not NAME_RE.match(name):
        raise ValueError('a report needs a name (at most 80 characters, no < >)')
    kind = str(b.get('kind', cur.get('kind', 'inventory')) or 'inventory')
    if kind not in KINDS:
        raise ValueError('the kind of a report is one of %s' % ', '.join(KINDS))
    teams = b.get('teams', cur.get('teams', []))
    if isinstance(teams, str):
        teams = [t for t in re.split(r'\s*,\s*', teams) if t.strip()]
    tr = T.tree(store)
    got_teams = []
    for t in teams or []:
        k = _low(t)
        if k not in tr.rows:
            raise ValueError('there is no team %s' % str(t)[:80])
        if tr.rows[k]['name'] not in got_teams:
            got_teams.append(tr.rows[k]['name'])
    formats = b.get('formats', cur.get('formats', ['pdf']))
    if isinstance(formats, str):
        formats = [f for f in re.split(r'[\s,]+', formats) if f]
    formats = [f for f in FORMATS if f in [str(x).lower() for x in formats or []]]
    if not formats:
        raise ValueError('a report is made as CSV, PDF or both')
    sch = b.get('schedule', cur.get('schedule', {})) or {}
    if not isinstance(sch, dict):
        raise ValueError('the schedule is {every, day, hour}')
    every = str(sch.get('every') or 'off')
    if every not in EVERY:
        raise ValueError('a report is made weekly, monthly or only by hand (off)')
    dd = _int(sch.get('day'), 'the day', 1, 7 if every == 'weekly' else 28, 1)
    hh = _int(sch.get('hour'), 'the hour', 0, 23, 7)
    was = _sched(old.get('schedule')) if old else {}
    since = was.get('since') if was and (was.get('every'), was.get('day'), was.get('hour')) == (
        every, dd, hh) else _now()
    rec = b.get('recipients', cur.get('recipients', []))
    if isinstance(rec, (list, tuple)):
        rec = ', '.join(str(x) for x in rec)
    rec = T.clean_mails(rec) if str(rec or '').strip() else ''
    if len([m for m in re.split(r'[\s,;]+', rec) if m]) > 50:
        raise ValueError('at most 50 addresses')
    lang = str(b.get('lang', cur.get('lang', '')) or '')
    if lang not in LANGS:
        raise ValueError('the language is cs, en or empty (the mails\' own)')
    keep = _int(b.get('keep', cur.get('keep')), 'the runs kept', 1, 100, KEEP_DEFAULT)
    opts = b.get('options', cur.get('options', {})) or {}
    if not isinstance(opts, dict):
        raise ValueError('the options are an object')
    o = {}
    if kind == 'expiry':
        o['days'] = _int(opts.get('days'), 'the days ahead', 1, 3650, 90)
    if kind == 'inventory':
        o['expired'] = bool(opts.get('expired', True))
    enabled = b.get('enabled', cur.get('enabled', True))
    note = str(b.get('note', cur.get('note', '')) or '')[:1000]
    return {'name': name, 'kind': kind, 'teams': json.dumps(got_teams),
            'formats': json.dumps(formats),
            'schedule': json.dumps({'every': every, 'day': dd, 'hour': hh, 'since': since}),
            'recipients': rec, 'lang': lang, 'keep': keep, 'options': json.dumps(o),
            'enabled': 1 if enabled not in (False, 0, '0', 'false', 'off') else 0, 'note': note}


def save(store, b, by):
    """A new report, or one changed ({id} or {old_name}): its public form."""
    old = None
    ref = (b or {}).get('id') or (b or {}).get('old_name')
    if ref not in (None, '', 0):
        old = need(store, ref)
    row = clean(store, b, old)
    clash = get_row(store, row['name'])
    if clash and (not old or clash['id'] != old['id']):
        raise ValueError('there is a report %s already' % clash['name'])
    now = _now()
    row.update(updated=now, updated_by=str(by)[:190])
    if old:
        store.db.update('cert_reports', old['id'], row)
        rid = old['id']
        if _low(old['name']) != _low(row['name']):
            store.db.run('UPDATE cert_report_runs SET report = ? WHERE report_id = ?',
                         (row['name'], rid))
        words = 'changed'
    else:
        row.update(created=now, created_by=str(by)[:190])
        rid = store.db.insert('cert_reports', row)
        words = 'added'
    got = public(need(store, rid))
    store.add_event('certificates', 'the report %s (%s) was %s by %s' % (
        got['name'], got['kind'], words, by), who=str(by)[:190])
    return got


def delete(store, ref, by):
    r = need(store, ref)
    store.db.run('DELETE FROM cert_report_runs WHERE report_id = ?', (r['id'],))
    store.db.run('DELETE FROM cert_reports WHERE id = ?', (r['id'],))
    store.add_event('certificates', 'the report %s was deleted by %s' % (r['name'], by),
                    who=str(by)[:190])
    return {'deleted': r['name']}


# ---------------------------------------------------------------------------
# Who may see one
# ---------------------------------------------------------------------------
def _full(s):
    return (s or {}).get('role') == 'fulladmin' or bool((s or {}).get('cli'))


def may_see(store, s, rep):
    """A full administrator every report; a certificate administrator one whose teams are all
    teams they manage (those below them too) - one of every team only when they manage every
    certificate; nobody else."""
    if _full(s):
        return True
    if (s or {}).get('role') not in ('certadmin', 'tokenadmin'):
        return False
    sc = T.scope(store, s, 'manage')
    if sc is None:
        return True
    teams = [_low(t) for t in public(rep)['teams']]
    return bool(teams) and all(t in sc for t in teams)


def may_see_run(store, s, rep, run):
    """A run is seen by whom its report is - and, by a certificate administrator, only when the
    teams it was made of are theirs too: a report whose teams were narrowed (every team -> Web)
    kept the runs made of every team, downloadable by the Web's administrator."""
    if _full(s):
        return True
    if not may_see(store, s, rep):
        return False
    sc = T.scope(store, s, 'manage')
    if sc is None:
        return True
    raw = run.get('teams')
    teams = S.jload(raw, None) if raw not in (None, '') else None
    if not isinstance(teams, list):
        teams = public(rep)['teams']
    teams = [_low(t) for t in teams if t]
    return bool(teams) and all(t in sc for t in teams)


_ADDR = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)*")


def said_for(s, words):
    """What a run (a report's last run) said as the session may see it: a mail server's answer
    names the recipients ("<x@y>: mailbox unavailable") - a certificate administrator never
    sees recipients, so the addresses are masked for them (1.0.141)."""
    words = str(words or '')
    return words if _full(s) else _ADDR.sub('…', words)


def runs_for(store, s, rep, limit=100):
    """The runs as the session may see them: a certificate administrator's without the
    addresses they went to (the recipients are a full administrator's) nor the runs made of
    teams that are not theirs."""
    if _full(s):
        return runs(store, rep, limit)
    got = store.db.rows('SELECT id, teams FROM cert_report_runs WHERE report_id = ?',
                        (rep['id'],))
    ok = {r['id'] for r in got if may_see_run(store, s, rep, r)}
    out = []
    for r in runs(store, rep, max(int(limit), 100)):
        if r['id'] in ok:
            r['sent_to'] = ['…'] * len(r['sent_to'])
            r['said'] = said_for(s, r.get('said'))
            out.append(r)
    return out[:int(limit)]


def need_see(store, s, ref):
    r = need(store, ref)
    if not may_see(store, s, r):
        raise E.ApiError(403, 'you may not see the report %s' % r['name'])
    return r


# ---------------------------------------------------------------------------
# The data of each kind
# ---------------------------------------------------------------------------
def scope_teams(store, p):
    """None: everything (the certificates of no team too); else {team lower} - the teams chosen
    (`p` a definition's public form) and every team below them."""
    teams = p['teams']
    if not teams:
        return None
    tr = T.tree(store)
    out = set()
    for t in teams:
        k = _low(t)
        if k in tr.rows:
            out.add(k)
            out.update(tr.descendants(k))
    return out


def _in(sc, owner):
    return sc is None or _low(owner) in sc


def _team_name(tr, owner):
    k = _low(owner)
    return tr.rows[k]['name'] if k in tr.rows else str(owner or '')


def _certs(store, sc):
    got = store.db.rows('SELECT id, name, cn, names, owner, issuer, key_type, key_type_alt, '
                        'state, not_before, not_after, auto_renew, renew_days, tags, '
                        'last_error, issuer_dn, serial, cert_pem, enabled, created FROM certs '
                        'ORDER BY not_after')
    return [r for r in got if _in(sc, r.get('owner'))][:MOST_ROWS]


def _names(r, most=4):
    n = [x for x in (S.jload(r.get('names'), []) or []) if x]
    more = len(n) - most
    return ', '.join(n[:most]) + ((' +%d' % more) if more > 0 else '')


def _left(r, now):
    na = float(r.get('not_after') or 0)
    return int((na - now) / 86400) if na else None


STATE_WORDS = {'ok': 'valid', 'new': 'not issued yet', 'held': 'held', 'due': 'due for renewal',
               'renewing': 'being renewed', 'failed': 'renewal failed', 'expired': 'expired',
               'pending': 'waiting for a certificate', 'revoked': 'revoked',
               'disabled': 'switched off', 'pending-approval': 'waiting for approval'}
STATE_TONE = {'ok': 'good', 'failed': 'bad', 'expired': 'bad', 'due': 'warn',
              'renewing': 'info', 'pending-approval': 'warn', 'pending': 'warn', 'new': 'warn',
              'revoked': 'dim', 'disabled': 'dim', 'held': 'dim'}


def _state(r, now):
    st = r.get('state') or 'new'
    na = float(r.get('not_after') or 0)
    if na and na < now and st not in ('revoked', 'disabled'):
        st = 'expired'
    return st


def _yes(lang, v):
    return L(lang, 'yes') if v else L(lang, 'no')


def _deploy_counts(store):
    out = {}
    for d in store.db.rows('SELECT cert_id, COUNT(*) AS n, SUM(CASE WHEN state = \'failed\' '
                           'THEN 1 ELSE 0 END) AS bad FROM cert_deploys GROUP BY cert_id'):
        out[d['cert_id']] = (int(d['n'] or 0), int(d['bad'] or 0))
    return out


def _inventory(store, p, lang, sc, tr, now):
    opts = p['options']
    deps = _deploy_counts(store)
    out_rows, tones = [], {}
    n_ok = n_soon = n_bad = 0
    for r in _certs(store, sc):
        st = _state(r, now)
        if st == 'expired' and opts.get('expired') is False:
            continue
        left = _left(r, now)
        if st == 'ok':
            n_ok += 1
        if left is not None and 0 <= left <= 30 and st not in ('revoked', 'disabled'):
            n_soon += 1
        if st in ('failed', 'expired'):
            n_bad += 1
        d = deps.get(r['id'], (0, 0))
        i = len(out_rows)
        out_rows.append({'name': r['name'], 'team': _team_name(tr, r.get('owner')) or '-',
                         'names': _names(r), 'source': r.get('issuer') or '-',
                         'key': r.get('key_type') + (' + ' + r['key_type_alt']
                                                     if r.get('key_type_alt') else '')
                         if r.get('key_type') else '-',
                         'state': L(lang, STATE_WORDS.get(st, st)),
                         'ends': day(r.get('not_after'), lang),
                         'left': '' if left is None else str(left),
                         'auto': _yes(lang, int(r.get('auto_renew') or 0)),
                         'deploys': '%d' % d[0] + (' (%s)' % Lf(lang, '{0} failed', d[1])
                                                   if d[1] else ''),
                         'tags': ', '.join(S.jload(r.get('tags'), []) or [])})
        tones[(i, 6)] = STATE_TONE.get(st)
        if left is not None and left <= 14 and st not in ('revoked', 'disabled'):
            tones[(i, 8)] = 'bad' if left < 7 else 'warn'
    cols = [('name', 'Certificate'), ('team', 'Team'), ('names', 'Names'), ('source', 'Source'),
            ('key', 'Key'), ('tags', 'Tags'), ('state', 'State'), ('ends', 'Ends'),
            ('left', '#Days left'), ('auto', 'Renews itself'), ('deploys', '#Deployments')]
    # the tones by the columns' order above (state 6, days left 8)
    tiles = [(L(lang, 'certificates'), len(out_rows), 'info'),
             (L(lang, 'valid'), n_ok, 'good'),
             (L(lang, 'ending within 30 days'), n_soon, 'warn' if n_soon else 'good'),
             (L(lang, 'failed or expired'), n_bad, 'bad' if n_bad else 'good')]
    return {'tiles': tiles, 'columns': cols, 'rows': out_rows, 'tones': tones, 'sections': []}


def _expiry(store, p, lang, sc, tr, now):
    days = int(p['options'].get('days') or 90)
    out_rows, tones = [], {}
    by_month = {}
    c7 = c30 = gone = 0
    for r in _certs(store, sc):
        st = _state(r, now)
        if st in ('revoked', 'disabled'):
            continue
        left = _left(r, now)
        if left is None or left > days:
            continue
        if left < 0:
            gone += 1
        elif left <= 7:
            c7 += 1
        elif left <= 30:
            c30 += 1
        m = time.strftime('%Y-%m', time.localtime(float(r['not_after'])))
        by_month[m] = by_month.get(m, 0) + 1
        i = len(out_rows)
        auto = int(r.get('auto_renew') or 0)
        out_rows.append({'name': r['name'], 'team': _team_name(tr, r.get('owner')) or '-',
                         'names': _names(r, 3), 'ends': day(r.get('not_after'), lang),
                         'left': str(left), 'renewal': L(lang, 'by itself') if auto else
                         L(lang, 'by hand'), 'state': L(lang, STATE_WORDS.get(st, st)),
                         'error': ' '.join(str(r.get('last_error') or '').split())[:200]
                         if st == 'failed' else ''})
        tones[(i, 4)] = 'bad' if left < 7 else 'warn' if left <= 30 else None
        tones[(i, 6)] = STATE_TONE.get(st)
        if not auto:
            tones[(i, 5)] = 'warn'
    cols = [('name', 'Certificate'), ('team', 'Team'), ('names', 'Names'), ('ends', 'Ends'),
            ('left', '#Days left'), ('renewal', 'Renewal'), ('state', 'State'),
            ('error', 'Last error')]
    tiles = [(L(lang, 'expired'), gone, 'bad' if gone else 'good'),
             (L(lang, 'within 7 days'), c7, 'bad' if c7 else 'good'),
             (L(lang, 'within 30 days'), c30, 'warn' if c30 else 'good'),
             (Lf(lang, 'within {0} days', days), len(out_rows), 'info')]
    months = [{'month': k, 'count': str(v)} for k, v in sorted(by_month.items())]
    return {'tiles': tiles, 'columns': cols, 'rows': out_rows, 'tones': tones,
            'note': Lf(lang, 'Certificates that end within {0} days, soonest first.', days),
            'sections': [{'heading': L(lang, 'By month'),
                          'columns': [('month', 'Month'), ('count', '#Certificates')],
                          'rows': months}]}


def _compliance(store, p, lang, sc, tr, now):
    from acmelib.certs import reqprofiles_more as RM
    today = datetime.date.today()
    rl = RM.rules(store)
    prof_of = {}
    cfgs = {}
    try:
        from acmelib.certs import reqprofiles as R
        for p in R.rows(store):
            cfgs[_low(p['name'])] = (p['name'], R.config_of(p))
        for pk, pairs in RM.issued_from(store).items():
            for c, _a in pairs:
                prof_of[c['id']] = pk
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('reports-profiles', 'the reports: the request profiles: %s' % e, 'warn',
                      every=3600)
    publics = {}

    def is_public(issuer):
        if issuer not in publics:
            try:
                publics[issuer] = RM._is_public(store, issuer) if issuer else False
            except Exception:                           # noqa: BLE001
                publics[issuer] = False
        return publics[issuer]
    out_rows, tones = [], {}
    count = {'ok': 0, 'bad': 0, 'ends': 0}
    for r in _certs(store, sc):
        if _state(r, now) in ('revoked', 'disabled') or not r.get('cert_pem'):
            continue
        pk = prof_of.get(r['id'])
        pname, cfg = cfgs.get(pk, ('', {})) if pk else ('', {})
        pub = is_public(r.get('issuer'))
        try:
            fs = RM.lint_cert(store, r, cfg, pub, today, rl)
        except Exception as e:                          # noqa: BLE001
            fs = [{'rule': 'read', 'level': 'warn', 'said': str(e)[:200], 'from': ''}]
        st = RM._status(fs, today, today + datetime.timedelta(days=400))
        count[st] = count.get(st, 0) + 1
        i = len(out_rows)
        words = [L(lang, f['said']) + ((' (' + Lf(lang, 'from {0}', f['from']) + ')')
                                       if f.get('from') else '')
                 for f in fs if f.get('level') in ('bad', 'warn', 'info')]
        out_rows.append({'name': r['name'], 'team': _team_name(tr, r.get('owner')) or '-',
                         'profile': pname or '-', 'source': r.get('issuer') or '-',
                         'public': _yes(lang, pub), 'ends': day(r.get('not_after'), lang),
                         'status': L(lang, {'ok': 'complies', 'bad': 'does not comply',
                                            'ends': 'complies until a rule changes'}[st]),
                         'findings': '; '.join(words)[:600]})
        tones[(i, 6)] = {'ok': 'good', 'bad': 'bad', 'ends': 'warn'}[st]
    cols = [('name', 'Certificate'), ('team', 'Team'), ('profile', 'Profile'),
            ('source', 'Source'), ('public', 'Public CA'), ('ends', 'Ends'), ('status', 'Status'),
            ('findings', 'Findings')]
    sched = [{'from': day(time.mktime(RM._day(a).timetuple()), lang),
              'days': str(b)} for a, b in RM.CABF_SCHEDULE]
    tiles = [(L(lang, 'comply'), count['ok'], 'good'),
             (L(lang, 'do not comply'), count['bad'], 'bad' if count['bad'] else 'good'),
             (L(lang, 'until a rule changes'), count['ends'], 'warn' if count['ends'] else 'good'),
             (L(lang, 'longest validity now (days)'), RM.limit_on(today), 'info')]
    return {'tiles': tiles, 'columns': cols, 'rows': out_rows, 'tones': tones,
            'note': L(lang, 'The CA/Browser Forum\'s longest validity of a public TLS '
                            'certificate and the company\'s own rules (Settings → Request '
                            'profiles), checked on each certificate.'),
            'sections': [{'heading': L(lang, 'The CA/Browser Forum\'s schedule'),
                          'columns': [('from', 'Issued from'), ('days', '#Longest validity (days)')],
                          'rows': sched}]}


def agent_look(store, row, now=None):
    """(state, [what needs a look]) of one target agent - nothing secret."""
    from acmelib.certs import agents as G
    now = now or _now()
    st = G.state(store, row['id'])
    seen = float(st.get('last_seen') or 0)
    joined = bool(st.get('cert_fp'))
    pend = st.get('pending') if isinstance(st.get('pending'), dict) else None
    enabled = row.get('enabled') is None or bool(int(row.get('enabled') or 0))
    probs = []
    if not joined:
        state = 'joining' if pend else 'new'
    elif not enabled:
        state = 'off'
    elif st.get('refused'):
        state = 'refused'
    elif seen and now - seen < G.QUIET_S:
        state = 'answers'
    else:
        state = 'quiet'
    if pend and pend.get('fp') and not pend.get('cert'):
        probs.append('waits for confirmation')
    if state == 'quiet':
        probs.append('not heard from since %s' % (time.strftime('%Y-%m-%d %H:%M',
                                                                time.localtime(seen))
                                                  if seen else 'it joined'))
    if state == 'refused':
        probs.append('refused by acme')
    if isinstance(st.get('blocked'), dict):
        probs.append('its policy blocked a job')
    try:
        ce = float(st.get('cert_end') or 0)
    except (TypeError, ValueError):
        ce = 0
    if joined and ce and ce - now < 7 * 86400:
        probs.append('its own certificate ends soon')
    if st.get('last_error') and state != 'answers':
        probs.append('last error: %s' % ' '.join(str(st['last_error']).split())[:160])
    return state, probs, {'version': st.get('version') or '', 'os': st.get('os') or '',
                          'platform': st.get('platform') or ('windows' if row.get('kind') ==
                                                             'agent_windows' else 'linux'),
                          'last_seen': seen or None, 'cert_end': ce or None,
                          'mode': 'active' if str((S.jload(row.get('config'), {}) or {}).get(
                              'mode') or '') == 'active' else 'passive'}


AGENT_TONE = {'answers': 'good', 'quiet': 'bad', 'refused': 'bad', 'joining': 'warn',
              'new': 'dim', 'off': 'dim'}
AGENT_WORDS = {'answers': 'answers', 'quiet': 'quiet', 'refused': 'refused',
               'joining': 'joining', 'new': 'not joined yet', 'off': 'switched off'}


def agent_rows(store, sc):
    got = store.db.rows("SELECT id, name, kind, owner, config, enabled FROM cert_targets WHERE "
                        "kind IN ('agent', 'agent_windows') ORDER BY name")
    return [r for r in got if _in(sc, r.get('owner'))]


def _agents(store, p, lang, sc, tr, now):
    out_rows, tones = [], {}
    n_ok = n_look = n_wait = 0
    for r in agent_rows(store, sc):
        state, probs, f = agent_look(store, r, now)
        n_ok += state == 'answers'
        n_look += bool(probs)
        n_wait += any(p == 'waits for confirmation' for p in probs)
        i = len(out_rows)
        out_rows.append({'name': r['name'], 'team': _team_name(tr, r.get('owner')) or '-',
                         'platform': f['platform'], 'mode': L(lang, f['mode']),
                         'state': L(lang, AGENT_WORDS.get(state, state)),
                         'version': f['version'] or '-',
                         'seen': stamp(f['last_seen'], lang) if f['last_seen'] else '-',
                         'cert': day(f['cert_end'], lang) if f['cert_end'] else '-',
                         'look': '; '.join(L(lang, p) for p in probs)})
        tones[(i, 4)] = AGENT_TONE.get(state)
        if probs:
            tones[(i, 8)] = 'warn'
    cols = [('name', 'Agent (target)'), ('team', 'Team'), ('platform', 'Platform'),
            ('mode', 'Mode'), ('state', 'State'), ('version', 'Version'),
            ('seen', 'Last heard from'), ('cert', 'Its certificate ends'),
            ('look', 'Needs a look')]
    tiles = [(L(lang, 'agents'), len(out_rows), 'info'), (L(lang, 'answer'), n_ok, 'good'),
             (L(lang, 'need a look'), n_look, 'warn' if n_look else 'good'),
             (L(lang, 'wait for confirmation'), n_wait, 'warn' if n_wait else 'good')]
    return {'tiles': tiles, 'columns': cols, 'rows': out_rows, 'tones': tones, 'sections': []}


def _access(store, p, lang, sc, tr, now):
    reviews = {}
    try:
        for rv in store.db.rows('SELECT team, started, state, done, done_by, due FROM '
                                'cert_team_reviews ORDER BY started'):
            reviews[_low(rv['team'])] = rv
    except Exception:                                   # noqa: BLE001
        pass
    grants = []
    try:
        grants = store.db.rows("SELECT team, who, role, until FROM cert_team_elevations WHERE "
                               "state = 'granted' AND until > ?", (now,))
    except Exception:                                   # noqa: BLE001
        pass
    out_rows, tones = [], {}
    n_teams = n_members = n_late = 0
    teams_rows = []
    for k in tr.order:
        if sc is not None and k not in sc:
            continue
        t = tr.rows[k]
        n_teams += 1
        rv = reviews.get(k)
        late = bool(rv and (rv.get('state') == 'overdue' or (
            rv.get('state') == 'open' and float(rv.get('due') or 0) < now)))
        n_late += late
        rv_words = '-'
        if rv:
            rv_words = '%s, %s' % (L(lang, {'open': 'open', 'overdue': 'overdue',
                                            'done': 'done', 'closed': 'closed'}.get(
                rv.get('state'), rv.get('state') or '')), day(rv.get('done') or rv.get('started'),
                                                              lang))
            if rv.get('done_by') and rv.get('state') == 'done':
                rv_words += ' (%s)' % rv['done_by']
        members = [m for m in (S.jload(t.get('members'), []) or []) if isinstance(m, dict)]
        parent = tr.name(tr.parent[k]) if tr.parent.get(k) else ''
        teams_rows.append({'team': t['name'], 'parent': parent or '-',
                           'kind': L(lang, t.get('kind') or 'team'),
                           'members': str(len(members)), 'review': rv_words})
        for m in members:
            n_members += 1
            i = len(out_rows)
            roles = list(m.get('roles') or []) or list(m.get('rights') or [])
            until = m.get('until')
            out_rows.append({'team': t['name'], 'parent': parent or '-',
                             'member': str(m.get('who') or ''),
                             'kind': L(lang, T.member_kind(m.get('who'))),
                             'roles': ', '.join(str(x) for x in roles) or '-',
                             'until': day(until, lang) if until else '-',
                             'review': rv_words})
            if until and T.member_expired(m, now):
                tones[(i, 5)] = 'bad'
            if late:
                tones[(i, 6)] = 'warn'
        for g in grants:
            if _low(g.get('team')) != k:
                continue
            i = len(out_rows)
            out_rows.append({'team': t['name'], 'parent': parent or '-',
                             'member': str(g.get('who') or ''),
                             'kind': L(lang, 'temporary role'), 'roles': str(g.get('role') or ''),
                             'until': stamp(g.get('until'), lang), 'review': rv_words})
            tones[(i, 3)] = 'warn'
    cols = [('team', 'Team'), ('parent', 'Under'), ('member', 'Member'), ('kind', 'Kind'),
            ('roles', 'Roles or rights'), ('until', 'Until'), ('review', 'Last access review')]
    tiles = [(L(lang, 'teams'), n_teams, 'info'), (L(lang, 'memberships'), n_members, 'info'),
             (L(lang, 'temporary roles now'), len([g for g in grants
                                                    if sc is None or _low(g.get('team')) in sc]),
              'warn' if [g for g in grants if sc is None or _low(g.get('team')) in sc]
              else 'good'),
             (L(lang, 'reviews overdue'), n_late, 'bad' if n_late else 'good')]
    return {'tiles': tiles, 'columns': cols, 'rows': out_rows, 'tones': tones,
            'sections': [{'heading': L(lang, 'The teams'),
                          'columns': [('team', 'Team'), ('parent', 'Under'), ('kind', 'Kind'),
                                      ('members', '#Members'), ('review', 'Last access review')],
                          'rows': teams_rows}]}


BUILDERS = {'inventory': _inventory, 'expiry': _expiry, 'compliance': _compliance,
            'agents': _agents, 'access': _access}


def build(store, rep, lang=None, now=None):
    """The report's data now: {title, kind, lang, scope, made, tiles, columns, rows, tones,
    note, sections}. Column heads in the report's language ('#' first: a number)."""
    p = public(rep)
    lang = lang or lang_of(p)
    now = now or _now()
    sc = scope_teams(store, p)
    tr = T.tree(store)
    got = BUILDERS[p['kind']](store, p, lang, sc, tr, now)
    got['columns'] = [(k, ('#' if h.startswith('#') else '') + L(lang, h.lstrip('#')))
                      for k, h in got['columns']]
    for sec in got.get('sections') or []:
        sec['columns'] = [(k, ('#' if h.startswith('#') else '') + L(lang, h.lstrip('#')))
                          for k, h in sec['columns']]
    got.update(title=p['name'], kind=p['kind'], kind_words=L(lang, KIND_WORDS[p['kind']]),
               lang=lang, made=now,
               scope=(', '.join(p['teams']) if p['teams'] else L(lang, 'every team')),
               note=got.get('note') or L(lang, KIND_SAYS[p['kind']]))
    return got


# ---------------------------------------------------------------------------
# The files
# ---------------------------------------------------------------------------
def render_csv(data):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\r\n')
    w.writerow([h.lstrip('#') for _k, h in data['columns']])
    for r in data['rows']:
        w.writerow([_csv_cell(r.get(k, '')) for k, _h in data['columns']])
    # UTF-8 with its mark: a spreadsheet opens the Czech letters as they are
    return b'\xef\xbb\xbf' + buf.getvalue().encode('utf-8')


def _csv_cell(v):
    v = '' if v is None else str(v)
    # a cell a spreadsheet would take for a formula is written as words (CSV injection)
    if v[:1] in ('=', '+', '-', '@', '\t', '\r') and v != '-' and \
            not re.match(r'^-?\d+(\.\d+)?\Z', v):
        return "'" + v
    return v


def render_pdf(data):
    from acmelib.certs import pdfwriter as P
    lang = data['lang']
    doc = P.Doc(data['title'], '%s · %s · %s' % (data['kind_words'], site(), data['scope']),
                stamp(data['made'], lang), author='acme')
    doc.tiles([(lab, str(val), tone) for lab, val, tone in data['tiles']])
    if data.get('note'):
        doc.para(data['note'])
    heads = [h for _k, h in data['columns']]
    rows = data['rows']
    shown = rows[:PDF_ROWS]
    doc.heading(L(lang, 'The report') if len(rows) <= PDF_ROWS else
                Lf(lang, 'The first {0} rows of {1} (the CSV file has every one)', PDF_ROWS,
                   len(rows)))
    doc.table(heads, [[r.get(k, '') for k, _h in data['columns']] for r in shown],
              {k: v for k, v in (data.get('tones') or {}).items() if v and k[0] < PDF_ROWS},
              empty=L(lang, 'Nothing to report.'))
    for sec in data.get('sections') or []:
        doc.heading(sec['heading'])
        doc.table([h for _k, h in sec['columns']],
                  [[r.get(k, '') for k, _h in sec['columns']] for r in sec['rows']],
                  empty=L(lang, 'Nothing to report.'))
    return doc.output(lambda i, n: Lf(lang, 'Page {0} of {1}', i, n),
                      Lf(lang, 'Made by acme on {0}, {1}.', site(), stamp(data['made'], lang)))


def filename(rep_name, made, fmt):
    base = re.sub(r'[^A-Za-z0-9._-]+', '-', str(rep_name)).strip('-') or 'report'
    return '%s-%s.%s' % (base[:60], time.strftime('%Y-%m-%d', time.localtime(made)), fmt)


MIMES = {'csv': 'text/csv', 'pdf': 'application/pdf'}


def preview(data):
    """What the page draws of a report: its tiles, the first rows, the sections."""
    tones = data.get('tones') or {}
    keys = [k for k, _h in data['columns']]
    return {'title': data['title'], 'kind': data['kind'], 'kind_words': data['kind_words'],
            'lang': data['lang'], 'made': data['made'], 'scope': data['scope'],
            'note': data.get('note') or '',
            'tiles': [{'label': a, 'value': b, 'tone': c} for a, b, c in data['tiles']],
            'columns': [{'key': k, 'head': h.lstrip('#'), 'num': h.startswith('#')}
                        for k, h in data['columns']],
            'rows': [[r.get(k, '') for k in keys] for r in data['rows'][:PREVIEW_ROWS]],
            'tones': [[tones.get((i, j)) or '' for j in range(len(keys))]
                      for i in range(min(len(data['rows']), PREVIEW_ROWS))],
            'total': len(data['rows']),
            'sections': [{'heading': s['heading'],
                          'columns': [{'key': k, 'head': h.lstrip('#'), 'num': h.startswith('#')}
                                      for k, h in s['columns']],
                          'rows': [[r.get(k, '') for k, _h in s['columns']]
                                   for r in s['rows'][:PREVIEW_ROWS]]}
                         for s in data.get('sections') or []]}


# ---------------------------------------------------------------------------
# A run: made, kept, mailed
# ---------------------------------------------------------------------------
def _run_public(r, with_files=False):
    files = S.jload(r.get('files'), []) or []
    out = {'id': r['id'], 'report': r.get('report') or '', 'report_id': r.get('report_id'),
           'ts': r.get('ts'), 'by': r.get('by_who') or '', 'kind': r.get('kind') or '',
           'rows': int(r.get('row_count') or 0), 'ok': bool(int(r.get('ok') or 0)),
           'said': r.get('said') or '', 'sent_to': [m for m in str(r.get('sent_to') or '').split(
               ', ') if m], 'took_ms': int(r.get('took_ms') or 0), 'scope': r.get('scope') or '',
           'files': [{'format': f.get('format'), 'filename': f.get('filename'),
                      'size': f.get('size'), 'mime': f.get('mime')} for f in files
                     if isinstance(f, dict)]}
    if with_files:
        out['_files'] = files
    return out


def runs(store, rep, limit=100):
    return [_run_public(r) for r in store.db.rows(
        'SELECT id, report, report_id, ts, by_who, kind, row_count, ok, said, sent_to, '
        'took_ms, scope, files FROM cert_report_runs WHERE report_id = ? ORDER BY ts DESC, id DESC '
        'LIMIT ?', (rep['id'], int(limit)))]


def run_get(store, rid):
    try:
        rid = int(rid)
    except (TypeError, ValueError):
        raise ValueError('a run is a number')
    r = store.db.row('SELECT * FROM cert_report_runs WHERE id = ?', (rid,))
    if not r:
        raise LookupError('there is no run %s' % rid)
    return r


def run_file(store, rid, fmt):
    """{filename, mime, data_b64} of a run's file."""
    r = run_get(store, rid)
    for f in S.jload(r.get('files'), []) or []:
        if isinstance(f, dict) and f.get('format') == fmt:
            return {'filename': f['filename'], 'mime': f['mime'], 'data_b64': f['data_b64'],
                    'report_id': r.get('report_id')}
    raise LookupError('that run has no %s file' % str(fmt)[:10])


def _prune(store, rep):
    keep = int(public(rep)['keep'])
    old = store.db.rows('SELECT id FROM cert_report_runs WHERE report_id = ? ORDER BY ts DESC, '
                        'id DESC', (rep['id'],))[keep:]
    for r in old:
        store.db.run('DELETE FROM cert_report_runs WHERE id = ?', (r['id'],))


def make_files(store, rep, data=None):
    p = public(rep)
    data = data or build(store, rep)
    out = []
    for fmt in p['formats']:
        raw = render_csv(data) if fmt == 'csv' else render_pdf(data)
        out.append({'format': fmt, 'filename': filename(p['name'], data['made'], fmt),
                    'mime': MIMES[fmt], 'size': len(raw),
                    'data_b64': base64.b64encode(raw).decode('ascii')})
    return data, out


def mail_of(data, files, to, lang):
    """The mail of a run: a summary (its tiles and first rows) and the files attached."""
    p_title = data['title']
    link = E.alerts_link()
    body = []
    body.append('<p style="margin:0 0 12px;font-size:14px;color:#374151">%s</p>' % E._h(
        data.get('note') or ''))
    body.append(E._rep_tiles([(a, str(b), c if c in E.AL_COLORS else 'info')
                              for a, b, c in data['tiles']]))
    cols = data['columns'][:5]
    body.append(E._al_h(Lf(lang, 'The first {0} rows', min(15, len(data['rows'])))
                        if data['rows'] else L(lang, 'Nothing to report.')))
    if data['rows']:
        body.append(E._rep_table([h for _k, h in cols],
                                 [[E._h(str(r.get(k, ''))[:80]) for k, _h in cols]
                                  for r in data['rows'][:15]]))
    body.append('<p style="margin:14px 0 0;font-size:13.5px;color:#374151">%s</p>' % E._h(
        Lf(lang, 'Attached: {0}. The report is also kept in acme: Settings → Reports.',
           ', '.join(f['filename'] for f in files) or '-')))
    body.append('<table role="presentation" cellspacing="0" cellpadding="0" border="0" '
                'style="margin:14px 0 0"><tr><td bgcolor="#1d4ed8" style="background:#1d4ed8;'
                'border-radius:8px;padding:10px 18px"><a href="%s" style="color:#ffffff;'
                'text-decoration:none;font-weight:600;font-size:14px;%s">%s</a></td></tr>'
                '</table>' % (E._h(link + '#settings/reports'), E.AL_FONT,
                              E._h(L(lang, 'Open the reports in acme'))))
    foot = E._h(Lf(lang, 'Made by acme on {0}, {1}.', site(), stamp(data['made'], lang)))
    page = E._al_page(lang, p_title, 'acme · ' + data['kind_words'], E.AL_COLORS['info'][2],
                      ''.join(body), foot)
    text = [p_title, data['kind_words'] + ' · ' + data['scope'], '']
    text += ['%s: %s' % (a, b) for a, b, _c in data['tiles']]
    text += ['', Lf(lang, 'Attached: {0}. The report is also kept in acme: Settings → Reports.',
                    ', '.join(f['filename'] for f in files) or '-'), link + '#settings/reports']
    subject = '[acme] %s - %s' % (p_title, day(data['made'], lang))
    msg = E._al_msg(subject, page, '\n'.join(text), to)
    for f in files:
        main, sub = f['mime'].split('/', 1)
        msg.add_attachment(base64.b64decode(f['data_b64']), maintype=main, subtype=sub,
                           filename=f['filename'])
    return msg


def send_files(store, rep, data, files, to, by):
    """Mailed now - 'sent', or why not (mail off: nothing is sent and it says so)."""
    if (E.CONFIG.get('mail_mode') or 'off') == 'off':
        return False, 'mail is switched off (Settings → Mail) - nothing was sent'
    if not to:
        return False, 'no recipients'
    try:
        msg = mail_of(data, files, to, data['lang'])
        E.mail_deliver(store, msg, to, kind='report', name=public(rep)['name'], by=by,
                       purpose='periodic report')
        return True, 'sent'
    except E.MailError as e:
        if getattr(e, 'queued', None) == 'waiting':
            return True, 'waiting in the outgoing mail for another try'
        return False, str(e)[:300]
    except Exception as e:                              # noqa: BLE001
        return False, str(e)[:300]


def run(store, ref, by, send=False, to=None):
    """Made now and kept; mailed to its recipients (or `to`) when `send`. -> the run."""
    rep = need(store, ref) if not isinstance(ref, dict) else ref
    p = public(rep)
    t0 = time.monotonic()
    data, files = make_files(store, rep)
    to = [m for m in (to if to is not None else p['recipients']) if m]
    sent, said = (None, '')
    if send:
        sent, said = send_files(store, rep, data, files, to, by)
    took = int((time.monotonic() - t0) * 1000)
    rid = store.db.insert('cert_report_runs', {
        'report': p['name'], 'report_id': rep['id'], 'ts': data['made'], 'by_who': str(by)[:190],
        'kind': p['kind'], 'row_count': len(data['rows']), 'ok': 0 if sent is False else 1,
        'said': said or 'made', 'sent_to': ', '.join(to) if sent else '', 'took_ms': took,
        'scope': data['scope'][:500], 'files': json.dumps(files),
        'teams': json.dumps(p['teams'])})
    store.db.update('cert_reports', rep['id'], {'last_run': data['made'],
                                                'last_ok': data['made'] if sent is not False
                                                else (rep.get('last_ok') or None),
                                                'last_said': said or 'made'})
    _prune(store, rep)
    words = 'the report %s was made by %s (%d row(s), %s)' % (
        p['name'], by, len(data['rows']), ', '.join(f['format'].upper() for f in files))
    level = 'info'
    if send:
        if sent:
            words += ' and sent to %s' % ', '.join(to)
        else:
            words += ' - it was not sent: %s' % said
            level = 'warn'
    store.add_event('certificates', words, level, who=str(by)[:190])
    return _run_public(store.db.row('SELECT * FROM cert_report_runs WHERE id = ?', (rid,)))


# ---------------------------------------------------------------------------
# The schedule
# ---------------------------------------------------------------------------
def due_period(sched, now=None):
    """(the key of the period due now, its moment) - or (None, None) when nothing is due: the
    moment of this week's (month's) report has come, and came after the schedule was set."""
    sched = _sched(sched)
    if sched['every'] == 'off':
        return None, None
    n = datetime.datetime.fromtimestamp(now or _now())
    if sched['every'] == 'weekly':
        start = (n - datetime.timedelta(days=n.isoweekday() - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0)
        at = start + datetime.timedelta(days=min(7, max(1, sched['day'])) - 1,
                                        hours=sched['hour'])
        key = 'w:%04d-%02d' % tuple(n.isocalendar()[:2])
    else:
        at = n.replace(day=min(28, max(1, sched['day'])), hour=sched['hour'], minute=0, second=0,
                       microsecond=0)
        key = 'm:%04d-%02d' % (n.year, n.month)
    ts = time.mktime(at.timetuple())
    if (now or _now()) < ts or ts < sched['since']:
        return None, None
    return key, ts


def missed_period(sched, now=None):
    """(the key of the period before this one, its moment) when its moment came after the schedule
    was set - or (None, None). A report whose moment fell while the daemon was down, and the daemon
    started again only in the next period, was never made (1.0.141): _reports_tick makes it once,
    when that period's key is not the one made last."""
    sched = _sched(sched)
    if sched['every'] == 'off':
        return None, None
    now = now or _now()
    n = datetime.datetime.fromtimestamp(now)
    if sched['every'] == 'weekly':
        start = (n - datetime.timedelta(days=n.isoweekday() - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0)
        prev = start - datetime.timedelta(days=7)
        at = prev + datetime.timedelta(days=min(7, max(1, sched['day'])) - 1,
                                       hours=sched['hour'])
        key = 'w:%04d-%02d' % tuple(prev.isocalendar()[:2])
    else:
        y, m = (n.year, n.month - 1) if n.month > 1 else (n.year - 1, 12)
        at = datetime.datetime(y, m, min(28, max(1, sched['day'])), sched['hour'])
        key = 'm:%04d-%02d' % (y, m)
    ts = time.mktime(at.timetuple())
    if now < ts or ts < sched['since']:
        return None, None
    return key, ts


def _made(got, key):
    """Whether the period `key` (or a later one of the same kind) was made already."""
    got = str(got or '')
    return got == key or (got[:2] == key[:2] and len(got) == len(key) and got > key)


def _reports_tick(store):
    for r in rows(store):
        p = public(r)
        if not p['enabled']:
            continue
        key, _at = due_period(r.get('schedule'))
        if not key:
            # this period's moment not come yet: the last one's, missed while the daemon was down
            key, _at = missed_period(r.get('schedule'))
        if not key:
            continue
        mk = 'reports:period:%d' % r['id']
        if _made(store.get_meta(mk), key) or not E.claim_once(store, mk, key):
            continue
        try:
            run(store, r, 'the schedule', send=bool(p['recipients']))
        except Exception as e:                          # noqa: BLE001
            store.add_event('certificates', 'the report %s could not be made: %s' % (
                p['name'], str(e)[:300]), 'warn')
            E.log('the report %s: %s' % (p['name'], e), 'warn')


def tick(store, force=False, wait=False):
    """The reports due and the teams' digests due - on the node that leads (the renewer's scan
    calls it), at most once a minute, in a thread of its own (a slow mail server holds nothing
    up). Never raises."""
    if _TICK['busy'] or (not force and _now() - _TICK['at'] < TICK_EVERY_S):
        return
    _TICK['at'] = _now()
    _TICK['busy'] = True

    def go():
        try:
            for name, fn in (('reports', _reports_tick), ('digests', _digest_tick)):
                try:
                    fn(store)
                except Exception as e:                  # noqa: BLE001
                    E.log_sparing('reports-' + name, 'the %s: %s' % (name, e), 'warn',
                                  every=3600)
        finally:
            _TICK['busy'] = False
    if wait:
        go()
    else:
        threading.Thread(target=go, name='acme-reports', daemon=True).start()


def _digest_tick(store):
    from acmelib.certs import digest
    digest.tick(store)


def follow_rename(store, old, new):
    """A team renamed (teams._follow_rename, 1.0.140): the reports and the runs made of it follow -
    a report scoped to it became empty, and could no longer be saved ("there is no team")."""
    lo = _low(old)
    for table in ('cert_reports', 'cert_report_runs'):
        try:
            rows = store.db.rows('SELECT id, teams FROM %s' % table)
        except Exception:                               # noqa: BLE001
            continue
        for r in rows:
            got = S.jload(r.get('teams'), None)
            if not isinstance(got, list) or not any(_low(x) == lo for x in got):
                continue
            moved = [new if _low(x) == lo else x for x in got]
            store.db.run('UPDATE %s SET teams = ? WHERE id = ?' % table,
                         (json.dumps(moved), r['id']))
