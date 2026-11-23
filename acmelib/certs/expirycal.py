# -*- coding: utf-8 -*-
"""
The expiry calendar (1.0.140, docs/expiry-calendar.md): when certificates run out and when
acme plans to renew them - for a month view and a year's heatmap of the pages, the command
line (acme --calendar, --calendar-ics) and an iCalendar file or subscription.

Only what the person may see: the administration's certificates through the teams' scope
(teams.where - the same as the Certificates list), the portal's through portal.mine (theirs,
their groups', their teams'). Nothing is kept for the calendar but the subscription links:
a secret per account, kept only as its SHA-256 in `meta` (certs:calfeed:<hash>, and
certs:calfeed-of:<account> pointing at it), made and taken back by the account itself; a full
administrator takes back anyone's. A feed is answered as the account is NOW - switched off or
gone, nothing; its role and teams as they are at that moment, never more than it may see.

    GET  /api/calendar                ?from=&to=&team=&issuer=&target=&mine= the certificates
                                      running out (and planned renewals) between two dates
    GET  /api/calendar/ics            the same as an .ics ({text, filename})
    GET  /api/calendar/feed           the subscription (X-Acme-Calfeed: the secret) - text
    POST /api/calendar/feed_link      {action: new|revoke, lang} one's own link
    GET  /api/calendar/feeds          the accounts with a link (full administrator)
    POST /api/calendar/feeds_revoke   {who | all} (full administrator)
    GET  /api/portal/calendar         the portal's: their certificates
    GET  /api/portal/calendar_ics     ...as an .ics
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S

MOST = 5000                 # certificates in one answer, at most (the earliest first)
SPAN_DAYS = 800             # the longest window asked for at once
SKIP_STATES = ('revoked', 'disabled', 'declined', 'deleting')
META_FEED = 'certs:calfeed:'
META_FEED_OF = 'certs:calfeed-of:'
COLS = ('id', 'name', 'cn', 'names', 'owner', 'issuer', 'state', 'not_before', 'not_after',
        'auto_renew', 'renew_days', 'enabled', 'ari', 'created_by', 'tags', 'key_type')
FEED_CACHE = {'lock': threading.Lock(), 'at': {}}


# ---------------------------------------------------------------------------
# When
# ---------------------------------------------------------------------------
def _ts_of_day(v, end=False):
    """A YYYY-MM-DD date as seconds (local midnight; `end`: the next one)."""
    d = datetime.date.fromisoformat(str(v)[:10])
    if end:
        d = d + datetime.timedelta(days=1)
    return time.mktime(d.timetuple())


def window(frm, to):
    """(from, to) as seconds out of two dates ('' : today - 7 days, from + 366 days)."""
    try:
        start = _ts_of_day(frm) if frm else time.mktime(
            (datetime.date.today() - datetime.timedelta(days=7)).timetuple())
        end = _ts_of_day(to, end=True) if to else start + 366 * 86400
    except ValueError:
        raise ValueError('a date is YYYY-MM-DD')
    if end <= start:
        raise ValueError('the end comes before the start')
    if end - start > SPAN_DAYS * 86400:
        raise ValueError('at most %d days at once' % SPAN_DAYS)
    return start, end


def renew_at(row):
    """When acme plans to renew it (seconds), or None: renewed by itself and switched on, as
    renewer.main_due decides - its window before the end, an ARI window sooner."""
    from acmelib.certs import renewer
    if not row.get('auto_renew') or row.get('enabled') == 0 or not row.get('issuer'):
        return None
    if row.get('state') in SKIP_STATES + ('pending-approval', 'held'):
        return None
    na = row.get('not_after')
    if not na:
        return None
    try:
        at = float(na) - renewer.renew_window(row, float(na), row.get('not_before'))
    except (TypeError, ValueError):
        return None
    ari = S.jload(row.get('ari'), {}) or {}
    try:
        if ari.get('at') and float(ari['at']) < at:
            at = float(ari['at'])
    except (TypeError, ValueError):
        pass
    return at


def urgency(days):
    """crit (run out, or in 7 days), warn (30), info (60), ok."""
    if days is None:
        return 'dim'
    if days < 8:
        return 'crit'
    if days <= 30:
        return 'warn'
    if days <= 60:
        return 'info'
    return 'ok'


def entry(row, now=None):
    now = now or time.time()
    na = float(row.get('not_after') or 0)
    names = S.jload(row.get('names'), []) if not isinstance(row.get('names'), list) else \
        row.get('names')
    days = int((na - now) // 86400) if na else None
    ra = renew_at(row)
    return {'id': row.get('id'), 'name': row.get('name') or '', 'names': list(names or [])[:6],
            'n_names': len(names or []), 'owner': row.get('owner') or '',
            'issuer': row.get('issuer') or '', 'state': row.get('state') or '',
            'not_after': na or None, 'renew_at': ra, 'days_left': days,
            'auto_renew': bool(row.get('auto_renew')), 'urgency': urgency(days)}


# ---------------------------------------------------------------------------
# Whose
# ---------------------------------------------------------------------------
def _mine_where(s):
    """(sql, args) of 'only mine' for a session of the administration: owned by the person
    themselves (local:NAME, their directory names) or added by them."""
    from acmelib.certs import teams as T
    names, _groups = T.admin_principal(s)
    who = str(s.get('name') or '').strip().lower()
    names = sorted(set(n for n in names if n) | ({who} if who else set()))
    part = 'LOWER(TRIM(COALESCE(owner, \'\'))) IN (%s)' % ', '.join('?' * len(names))
    return '(%s OR LOWER(COALESCE(created_by, \'\')) = ?)' % part, tuple(names) + (who,)


def admin_rows(store, s, start, end, team='', issuer='', target='', mine=False):
    """The certificates of the window this session may see, earliest end first ([rows], capped)."""
    from acmelib.certs import teams as T
    where, args = ['not_after IS NOT NULL', 'not_after < ?',
                   "COALESCE(state, '') NOT IN (%s)" % ', '.join('?' * len(SKIP_STATES))], \
        [end + 400 * 86400] + list(SKIP_STATES)
    # those run out before the window are not in it (a planned renewal comes before the end)
    where.append('not_after >= ?')
    args.append(start)
    sw, sa = T.where(store, s, 'view')
    if sw:
        where.append(sw[len(' AND '):])
        args += list(sa)
    if team:
        tr = T.tree(store)
        want = sorted({team.strip().lower()} | set(tr.descendants(team.strip())))
        where.append('LOWER(TRIM(COALESCE(owner, \'\'))) IN (%s)' % ', '.join('?' * len(want)))
        args += want
    if issuer:
        where.append('issuer = ?')
        args.append(issuer)
    if target:
        where.append('id IN (SELECT cert_id FROM cert_deploys WHERE target = ?)')
        args.append(target)
    if mine:
        mw, ma = _mine_where(s)
        where.append(mw)
        args += list(ma)
    rows = store.db.rows('SELECT %s FROM certs WHERE %s ORDER BY not_after LIMIT %d' % (
        ', '.join(COLS), ' AND '.join(where), MOST + 1), tuple(args))
    return rows[:MOST], len(rows) > MOST


def in_window(entries, start, end):
    return [e for e in entries if (e['not_after'] and start <= e['not_after'] < end) or
            (e['renew_at'] and start <= e['renew_at'] < end)]


def options(store, s):
    """What the filters offer this session: its teams, the sources and targets of the
    certificates it sees."""
    from acmelib.certs import teams as T
    sc = T.scope(store, s, 'view')
    teams = [t['name'] for t in T.team_rows(store) if sc is None or t['name'].lower() in sc]
    sw, sa = T.where(store, s, 'view')
    iss = [r['issuer'] for r in store.db.rows(
        'SELECT DISTINCT issuer FROM certs WHERE issuer IS NOT NULL' + sw + ' ORDER BY issuer',
        tuple(sa)) if r.get('issuer')]
    tg = [r['target'] for r in store.db.rows(
        'SELECT DISTINCT d.target FROM cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE 1 = 1'
        + (sw.replace('owner', 'c.owner') if sw else '') + ' ORDER BY d.target', tuple(sa))
        if r.get('target')]
    return {'teams': teams, 'issuers': iss, 'targets': tg}


def answer(store, s, frm='', to='', team='', issuer='', target='', mine=False):
    start, end = window(frm, to)
    rows, capped = admin_rows(store, s, start, end, team, issuer, target, mine)
    now = time.time()
    got = in_window([entry(r, now) for r in rows], start, end)
    return {'from': time.strftime('%Y-%m-%d', time.localtime(start)),
            'to': time.strftime('%Y-%m-%d', time.localtime(end - 1)),
            'certs': got, 'count': len(got), 'capped': capped, 'today': time.strftime('%Y-%m-%d'),
            'counts': day_counts(got), 'weeks': week_counts(got, start, end),
            'filters': {'team': team, 'issuer': issuer, 'target': target, 'mine': bool(mine)}}


def _day(ts):
    return time.strftime('%Y-%m-%d', time.localtime(float(ts)))


def day_counts(entries):
    """{YYYY-MM-DD: {ends, renews, worst}} (the server's time zone; the pages count again in
    the browser's)."""
    out = {}
    order = ['ok', 'info', 'warn', 'crit']
    for e in entries:
        for key, ts in (('ends', e['not_after']), ('renews', e['renew_at'])):
            if not ts:
                continue
            d = out.setdefault(_day(ts), {'ends': 0, 'renews': 0, 'worst': 'ok'})
            d[key] += 1
            if key == 'ends' and order.index(e['urgency'] if e['urgency'] in order else 'ok') > \
                    order.index(d['worst']):
                d['worst'] = e['urgency']
    return out


def week_counts(entries, start, end):
    """[{week: YYYY-MM-DD (its Monday), ends, renews}] of each week in the window."""
    first = datetime.date.fromtimestamp(start)
    first = first - datetime.timedelta(days=first.weekday())
    weeks = {}
    d = first
    while time.mktime(d.timetuple()) < end:
        weeks[d.isoformat()] = {'week': d.isoformat(), 'ends': 0, 'renews': 0}
        d += datetime.timedelta(days=7)
    for e in entries:
        for key, ts in (('ends', e['not_after']), ('renews', e['renew_at'])):
            if not ts:
                continue
            day = datetime.date.fromtimestamp(float(ts))
            mon = (day - datetime.timedelta(days=day.weekday())).isoformat()
            if mon in weeks:
                weeks[mon][key] += 1
    return [weeks[k] for k in sorted(weeks)]


# ---------------------------------------------------------------------------
# iCalendar (RFC 5545)
# ---------------------------------------------------------------------------
def _ics_text(v):
    return re.sub(r'([\\;,])', r'\\\1', str(v or '')).replace('\r', '').replace('\n', '\\n')


def _fold(line):
    """Lines of at most 75 octets, a longer one folded (CRLF and a space)."""
    raw = line.encode('utf-8')
    if len(raw) <= 75:
        return line
    out, cur = [], b''
    for ch in line:
        b = ch.encode('utf-8')
        if len(cur) + len(b) > (75 if not out else 74):
            out.append(cur.decode('utf-8'))
            cur = b''
        cur += b
    out.append(cur.decode('utf-8'))
    return '\r\n '.join(out)


def ics(entries, lang='en', title='acme'):
    """The expiries (and planned renewals) as an iCalendar text: all-day events, a reminder
    a week before an end."""
    from acmelib import i18n_mail

    def t(s):
        return i18n_mail.tr(s, lang) if lang and lang != 'en' else s
    node = re.sub(r'[^A-Za-z0-9.-]', '', str(E.CONFIG.get('node_name') or 'acme')) or 'acme'
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//acme//expiry calendar//EN',
             'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
             'X-WR-CALNAME:' + _ics_text('%s - %s' % (title, t('certificates running out'))),
             'X-PUBLISHED-TTL:PT6H', 'REFRESH-INTERVAL;VALUE=DURATION:PT6H']
    for e in entries:
        who = []
        if e.get('names'):
            who.append('%s: %s' % (t('Names'), ', '.join(e['names'])))
        if e.get('owner'):
            who.append('%s: %s' % (t('Owner'), e['owner']))
        if e.get('issuer'):
            who.append('%s: %s' % (t('Source'), e['issuer']))
        for key, ts in (('end', e.get('not_after')), ('renew', e.get('renew_at'))):
            if not ts:
                continue
            day = datetime.date.fromtimestamp(float(ts))
            nxt = day + datetime.timedelta(days=1)
            summary = (t('The certificate {0} runs out') if key == 'end'
                       else t('acme renews the certificate {0}')).replace('{0}', e['name'])
            lines += ['BEGIN:VEVENT', 'UID:cert-%s-%s-%s@%s' % (e['id'], key, int(float(ts)),
                                                                   node),
                      'DTSTAMP:' + stamp, 'DTSTART;VALUE=DATE:' + day.strftime('%Y%m%d'),
                      'DTEND;VALUE=DATE:' + nxt.strftime('%Y%m%d'),
                      'SUMMARY:' + _ics_text(summary),
                      'DESCRIPTION:' + _ics_text('\n'.join(who)),
                      'CATEGORIES:' + ('EXPIRY' if key == 'end' else 'RENEWAL'),
                      'TRANSP:TRANSPARENT']
            if key == 'end':
                lines += ['BEGIN:VALARM', 'ACTION:DISPLAY', 'TRIGGER:-P7D',
                          'DESCRIPTION:' + _ics_text(summary), 'END:VALARM']
            lines.append('END:VEVENT')
    lines.append('END:VCALENDAR')
    return '\r\n'.join(_fold(x) for x in lines) + '\r\n'


# ---------------------------------------------------------------------------
# The subscription: a secret per account
# ---------------------------------------------------------------------------
def _hash(token):
    return hashlib.sha256(str(token).encode('utf-8')).hexdigest()


def feed_of(store, who):
    """{made, lang, used} of an account's link, or None (never the secret)."""
    h = store.get_meta(META_FEED_OF + str(who).lower())
    if not h:
        return None
    try:
        got = json.loads(store.get_meta(META_FEED + h) or 'null')
    except ValueError:
        got = None
    if not isinstance(got, dict):
        return None
    return {'made': got.get('made'), 'lang': got.get('lang') or 'en', 'used': got.get('used'),
            'who': got.get('who')}


def feed_new(store, who, lang='en'):
    """A new secret link for `who` (the old one stops working): the secret, once."""
    feed_revoke(store, who, by=None)
    tok = secrets.token_urlsafe(32)
    h = _hash(tok)
    lang = lang if re.fullmatch(r'[a-z]{2}', str(lang or '')) else 'en'
    rec = {'who': str(who), 'made': time.time(), 'lang': lang}
    # which account it is (hunt v1): a new account of the same name - somebody else, made after
    # this one was deleted, or a directory name given to another person - gets nothing from it
    acc = store.account(who) or {}
    if acc.get('created'):
        rec['acc_created'] = acc['created']
    if acc.get('dn'):
        rec['acc_dn'] = str(acc['dn']).lower()
    store.set_meta(META_FEED + h, json.dumps(rec))
    store.set_meta(META_FEED_OF + str(who).lower(), h)
    store.add_event('accounts', '%s made a link to subscribe to the calendar of their '
                                'certificates' % who, who=str(who))
    return tok


def feed_revoke(store, who, by=None):
    h = store.get_meta(META_FEED_OF + str(who).lower())
    if not h:
        return False
    store.db.run('DELETE FROM meta WHERE k = ?', (META_FEED + h,))
    store.db.run('DELETE FROM meta WHERE k = ?', (META_FEED_OF + str(who).lower(),))
    if by:
        store.add_event('accounts', 'the calendar link of %s was taken back by %s' % (who, by),
                        'warn', who=str(by))
    return True


def feeds(store):
    out = []
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (META_FEED_OF + '%',)):
        who = r['k'][len(META_FEED_OF):]
        one = feed_of(store, who)
        if one:
            out.append({'who': one.get('who') or who, 'made': one['made'], 'used': one['used'],
                        'lang': one['lang']})
    return sorted(out, key=lambda x: str(x['who']).lower())


def feed_session(store, token):
    """The account a secret belongs to, as a session of the administration is made of it now
    - or None (no such link, the account gone, switched off, no longer of the administration)."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{30,100}', str(token or '')):
        return None, None
    h = _hash(token)
    try:
        got = json.loads(store.get_meta(META_FEED + h) or 'null')
    except ValueError:
        got = None
    if not isinstance(got, dict) or not got.get('who'):
        return None, None
    if not hmac.compare_digest(store.get_meta(META_FEED_OF + str(got['who']).lower()) or '', h):
        return None, None
    acc = store.account(got['who'], checked=True)
    if not acc or acc.get('disabled') or not E.ROLE_RANK.get(acc.get('role') or ''):
        return None, None
    if not same_account(got, acc):
        return None, None
    return {'id': 0, 'name': acc['name'], 'role': acc['role'], 'kind': 'admin', 'account': acc,
            'feed': True}, got


def same_account(got, acc):
    """Whether the account is the one the link was made for (a link from before 1.0.140's hunt
    v1, without the mark: as it was)."""
    if got.get('acc_created') is not None:
        try:
            if abs(float(acc.get('created') or 0) - float(got['acc_created'])) > 0.001:
                return False
        except (TypeError, ValueError):
            return False
    if got.get('acc_dn') and str(acc.get('dn') or '').lower() != got['acc_dn']:
        return False
    return True


def _directory_now(h, s):
    """A directory account asked about again, as a sign-in is (engine directory_recheck, every
    ten minutes): out of the directory, or of every group that gives it a role here - None."""
    acc = s.get('account') or {}
    check = getattr(h, 'directory_recheck', None)
    if acc.get('source') != 'directory' or check is None:
        return s
    try:
        acc = check(acc)
    except E.ApiError:
        return None
    if not acc or acc.get('disabled') or not E.ROLE_RANK.get(acc.get('role') or ''):
        return None
    return dict(s, role=acc['role'], account=acc)


def _view_as(s):
    return isinstance((s.get('data') or {}).get('view_as'), dict)


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------
def _args(h):
    return {'frm': h.arg('from').strip(), 'to': h.arg('to').strip(),
            'team': h.arg('team').strip()[:190], 'issuer': h.arg('issuer').strip()[:190],
            'target': h.arg('target').strip()[:190],
            'mine': str(h.arg('mine') or '') in ('1', 'true', 'yes')}


@A.api('GET', '/api/calendar')
def _calendar(h, s):
    try:
        out = answer(h.store, s, **_args(h))
    except ValueError as e:
        raise E.ApiError(400, str(e))
    out['options'] = options(h.store, s)
    link = feed_of(h.store, s.get('name')) if not s.get('cli') else None
    out['feed'] = {'on': bool(link), 'made': (link or {}).get('made'),
                   'used': (link or {}).get('used'), 'may': not _view_as(s)}
    return out


@A.api('GET', '/api/calendar/ics')
def _calendar_ics(h, s):
    a = _args(h)
    if not a['frm']:
        a['frm'] = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
    if not a['to']:
        a['to'] = (datetime.date.today() + datetime.timedelta(days=730)).isoformat()
    try:
        got = answer(h.store, s, **a)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    lang = h.arg('lang') if re.fullmatch(r'[a-z]{2}', h.arg('lang') or '') else 'en'
    return {'text': ics(got['certs'], lang, str(E.CONFIG.get('site_name') or 'acme')),
            'filename': 'acme-certificates.ics', 'count': got['count']}


@A.api('POST', '/api/calendar/feed_link')
def _feed_link(h, s):
    b = h.body()
    act = str(b.get('action') or '')
    if _view_as(s):
        raise E.ApiError(403, 'viewing as a member changes nothing')
    if act == 'new':
        tok = feed_new(h.store, s['name'], str(b.get('lang') or 'en'))
        return {'token': tok, 'path': '/calendar.ics?t=' + tok,
                'message': 'a new link to subscribe to - the one before no longer works'}
    if act == 'revoke':
        gone = feed_revoke(h.store, s['name'], by=s['name'])
        return {'revoked': gone, 'message': 'the link no longer works' if gone else
                'there was no link'}
    raise E.ApiError(400, 'new or revoke')


@A.api('GET', '/api/calendar/feeds', 'fulladmin')
def _feeds(h, s):
    return {'feeds': feeds(h.store)}


@A.api('POST', '/api/calendar/feeds_revoke', 'fulladmin')
def _feeds_revoke(h, s):
    b = h.body()
    if b.get('all'):
        n = 0
        for f in feeds(h.store):
            n += 1 if feed_revoke(h.store, f['who'], by=A.who(s)) else 0
        return {'revoked': n, 'message': '%d calendar link(s) no longer work' % n}
    who = str(b.get('who') or '').strip()
    if not who:
        raise E.ApiError(400, 'whose link?')
    if not feed_revoke(h.store, who, by=A.who(s)):
        raise LookupError('%s has no calendar link' % who)
    return {'revoked': 1, 'message': 'the calendar link of %s no longer works' % who}


@E.route('GET', '/api/calendar/feed')
def _feed(h):
    """What calendar.php asks with the secret of the link - not a session."""
    tok = str(h.headers.get('X-Acme-Calfeed') or '')
    s, got = feed_session(h.store, tok)
    if s:
        s = _directory_now(h, s)
    if not s:
        raise E.ApiError(404, 'no such calendar - the link was taken back, or its account '
                              'may no longer sign in')
    key = _hash(tok)
    with FEED_CACHE['lock']:
        hit = FEED_CACHE['at'].get(key)
        if hit and time.time() - hit[0] < 60:
            return {'text': hit[1]}
    today = datetime.date.today()
    rows, _capped = admin_rows(h.store, s, time.mktime((today - datetime.timedelta(days=30))
                                                       .timetuple()),
                               time.mktime((today + datetime.timedelta(days=730)).timetuple()))
    text = ics([entry(r) for r in rows], got.get('lang') or 'en',
               str(E.CONFIG.get('site_name') or 'acme'))
    with FEED_CACHE['lock']:
        if len(FEED_CACHE['at']) > 500:
            FEED_CACHE['at'].clear()
        FEED_CACHE['at'][key] = (time.time(), text)
    # when it was last fetched (once an hour at most: a calendar asks often)
    if time.time() - float(got.get('used') or 0) > 3600:
        got['used'] = time.time()
        h.store.set_meta(META_FEED + key, json.dumps(got))
    return {'text': text}


# ---- the portal: their own certificates ------------------------------------------------
def _portal_entries(h):
    from acmelib.certs import portal as P
    s = P.portal_session(h)
    me = P._Me(h, s)
    pairs = P.mine_sort(P.mine_rows(h, s, me))
    rows = P.mine_public(h, s, pairs, me)
    # when acme renews each, of the row as it is kept (hunt w2: the page's row has no renew
    # days, no ARI window and no switch - a certificate with renew days of its own showed the
    # default's day, and one switched off a renewal that never comes)
    raw = {r['id']: r for r, _v in pairs}
    now = time.time()
    out = []
    for r in rows:
        src = raw.get(r.get('id')) or r
        if not src.get('not_after') or src.get('state') in SKIP_STATES:
            continue
        one = entry(src, now)
        out.append(one)
    return s, rows, out


@E.route('GET', '/api/portal/calendar')
def _portal_calendar(h):
    _s, rows, got = _portal_entries(h)
    keep = {e['id'] for e in got}
    return {'certs': got, 'count': len(got), 'today': time.strftime('%Y-%m-%d'),
            'rows': [r for r in rows if r.get('id') in keep], 'counts': day_counts(got)}


@E.route('GET', '/api/portal/calendar_ics')
def _portal_calendar_ics(h):
    _s, _rows, got = _portal_entries(h)
    lang = h.arg('lang') if re.fullmatch(r'[a-z]{2}', h.arg('lang') or '') else 'en'
    return {'text': ics(got, lang, str(E.CONFIG.get('site_name') or 'acme')),
            'filename': 'my-certificates.ics', 'count': len(got)}
