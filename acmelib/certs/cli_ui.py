# -*- coding: utf-8 -*-
"""
The command line of 1.0.140's pieces of the pages (docs/command-line.md "Search, the expiry
calendar, profiles from a template"): each option runs the page's own route, as the rest of
acmelib/certs/cli.py does (as `command line`, a full administrator).

    --find TEXT                   what Ctrl+K finds: certificates (names, SANs, serial),
                                  deployments, targets, agents, sources, authorities,
                                  validations, tests, profiles, teams, accounts, events
    --calendar                    the certificates running out (and the planned renewals),
                                  week by week: --from DATE, --weeks N, --team, --issuer,
                                  --target
    --calendar-ics FILE|-         the same as an iCalendar file (--lang cs)
    --calendar-feeds              who has a link to subscribe to their calendar
    --calendar-feed-revoke WHO|all  take one back (all: every one; asks, --yes)
    --profile-templates           the templates of request profiles and the sources that fit
    --profile-from-template ID    a new request profile: --name, --names DOMAIN,DOMAIN,
                                  [--issuer SOURCE] [--challenge VALIDATION] [--note TEXT]
"""
from __future__ import annotations

import datetime
import os
import sys
import time

KEYS = ('find', 'calendar', 'calendar_ics', 'calendar_feeds', 'calendar_feed_revoke',
        'profile_templates', 'profile_from_template')


def add_args(p):
    g = p.add_argument_group('CERTIFICATES: SEARCH, THE EXPIRY CALENDAR, PROFILES FROM A '
                             'TEMPLATE', 'What Ctrl+K finds, when certificates run out, and '
                             'request profiles from a template (1.0.140).')
    g.add_argument('--find', metavar='TEXT', help='find anything: certificates by name, SAN or '
                   'serial, deployments, targets, agents, sources, authorities, profiles, '
                   'teams, accounts, events of the last 30 days (--limit N a kind)')
    g.add_argument('--calendar', action='store_true', help='the certificates running out and '
                   'the planned renewals, week by week (--from YYYY-MM-DD, --weeks N [13], '
                   '--team TEAM, --issuer SOURCE, --target TARGET)')
    g.add_argument('--calendar-ics', dest='calendar_ics', metavar='FILE|-', help='the same as an '
                   'iCalendar file for a calendar program (- prints it; --lang cs)')
    g.add_argument('--calendar-feeds', dest='calendar_feeds', action='store_true',
                   help='the accounts that have a link to subscribe to their calendar')
    g.add_argument('--calendar-feed-revoke', dest='calendar_feed_revoke', metavar='WHO|all',
                   help='the link of an account taken back (all: every one; asks, --yes)')
    g.add_argument('--profile-templates', dest='profile_templates', action='store_true',
                   help='the templates of request profiles: what each sets, the sources that fit')
    g.add_argument('--profile-from-template', dest='profile_from_template', metavar='TEMPLATE',
                   help='a new request profile from a template: --name NAME, --names '
                   'DOMAIN,DOMAIN, [--issuer SOURCE] [--challenge VALIDATION] [--note TEXT]')
    g.add_argument('--from', dest='from', metavar='YYYY-MM-DD', default=None,
                   help='with --calendar, --calendar-ics: from this day [today]')
    g.add_argument('--weeks', dest='weeks', type=int, metavar='N', default=None,
                   help='with --calendar, --calendar-ics: this many weeks [13; the file 104]')
    g.add_argument('--team', dest='team', metavar='TEAM', default=None,
                   help='with --calendar, --calendar-ics: only the certificates of this team '
                        '(and the teams below it)')
    g.add_argument('--target', dest='target', metavar='TARGET', default=None,
                   help='with --calendar, --calendar-ics: only those deployed to this target')
    g.add_argument('--lang', dest='lang', metavar='CODE', default=None,
                   help='with --calendar-ics: the language of its words (en, cs)')
    _with_only()


def _given(a, k):
    return getattr(a, k, None) not in (None, False, '')


def _with_only():
    """Our options that go only with ours, refused beside any other one by cli.run() as the
    rest are (WITH_ONLY: "--team goes with --calendar, --calendar-ics - not with --certs")."""
    from acmelib.certs import cli as C
    for k, goes in (('from', ('calendar', 'calendar_ics')), ('weeks', ('calendar', 'calendar_ics')),
                    ('team', ('calendar', 'calendar_ics')), ('target', ('calendar', 'calendar_ics')),
                    ('lang', ('calendar_ics',))):
        C.WITH_ONLY.setdefault(k, goes)


def cli(c):
    a = c.args
    if _given(a, 'find'):
        return find(c, a.find)
    if _given(a, 'calendar'):
        return calendar(c)
    if _given(a, 'calendar_ics'):
        return calendar_ics(c, a.calendar_ics)
    if _given(a, 'calendar_feeds'):
        return calendar_feeds(c)
    if _given(a, 'calendar_feed_revoke'):
        return calendar_feed_revoke(c, a.calendar_feed_revoke)
    if _given(a, 'profile_templates'):
        return profile_templates(c)
    if _given(a, 'profile_from_template'):
        return profile_from_template(c, a.profile_from_template)
    return None


# ---- search ------------------------------------------------------------------------------
KIND_WORDS = {'cert': 'certificate', 'deploy': 'deployment', 'target': 'target', 'agent': 'agent',
              'source': 'source', 'ca': 'authority', 'validation': 'validation', 'test': 'test',
              'profile': 'request profile', 'team': 'team', 'account': 'account',
              'event': 'event'}


def find(c, text):
    text = str(text or '').strip()
    if not text:
        raise SystemExit('acme: --find needs the words to find')
    lim = getattr(c.args, 'limit', None)
    args = {'q': text}
    if lim and lim != 40:
        args['limit'] = str(lim)
    got = c.api('GET', '/api/search', args=args)
    if c.json:
        c.out(got)
        return 0
    rows = []
    for kind, items in got['groups'].items():
        for r in items:
            extra = r.get('sub') or ''
            if kind == 'cert' and r.get('days_left') is not None:
                extra = ('%d d left · ' % r['days_left']) + extra
            if kind == 'event' and r.get('at'):
                extra = time.strftime('%Y-%m-%d %H:%M', time.localtime(float(r['at']))) + ' · ' + extra
            rows.append([KIND_WORDS.get(kind, kind), str(r.get('name') or '')[:70],
                         str(extra)[:70]])
    if not rows:
        print('nothing found for "%s"' % text)
        return 1
    c.table(rows, ['what', 'name', ''])
    return 0


# ---- the calendar ------------------------------------------------------------------------
def _window(c, weeks_default):
    a = c.args
    start = getattr(a, 'from') or datetime.date.today().isoformat()
    try:
        d0 = datetime.date.fromisoformat(start)
    except ValueError:
        raise SystemExit('acme: --from is a day, YYYY-MM-DD')
    # --weeks 0 refused as --weeks 200 is (hunt w9: taken as "none given", 13 weeks shown)
    weeks = a.weeks if a.weeks is not None else weeks_default
    if not 1 <= weeks <= 110:
        raise SystemExit('acme: --weeks is 1 to 110')
    end = d0 + datetime.timedelta(days=7 * weeks - 1)
    return {'from': d0.isoformat(), 'to': end.isoformat(), 'team': a.team or '',
            'issuer': (a.issuer or '').strip() if getattr(a, 'issuer', None) else '',
            'target': a.target or ''}


BAR = '█'


def calendar(c):
    got = c.api('GET', '/api/calendar', args=_window(c, 13))
    if c.json:
        got.pop('options', None)
        c.out(got)
        return 0
    pal = c.pal
    weeks = got['weeks']
    most = max([w['ends'] for w in weeks] + [1])
    print('Certificates running out from %s to %s: %d%s' % (
        got['from'], got['to'], sum(w['ends'] for w in weeks),
        ' (the first %d)' % len(got['certs']) if got.get('capped') else ''))
    rows = []
    for w in weeks:
        bar = BAR * max(1 if w['ends'] else 0, int(round(20.0 * w['ends'] / most)))
        rows.append([w['week'], str(w['ends']), str(w['renews']), bar])
    c.table(rows, ['week of', 'run out', 'renewed', ''])
    ends = sorted((e for e in got['certs'] if e.get('not_after') and
                   got['from'] <= time.strftime('%Y-%m-%d', time.localtime(e['not_after'])) <=
                   got['to']), key=lambda e: e['not_after'])
    if ends:
        print('')
        rows = []
        for e in ends:
            day = time.strftime('%Y-%m-%d', time.localtime(e['not_after']))
            ren = time.strftime('%Y-%m-%d', time.localtime(e['renew_at'])) if e.get('renew_at') \
                else 'by hand'
            left = '-' if e.get('days_left') is None else '%d d' % e['days_left']
            tone = {'crit': pal.bad, 'warn': getattr(pal, 'warn', pal.bad)}.get(e['urgency'])
            rows.append([day, tone(left) if tone else left, e['name'], ren, e.get('owner') or '-',
                         e.get('issuer') or '-', ', '.join(e.get('names') or [])[:50]])
        c.table(rows, ['runs out', 'left', 'certificate', 'renewed', 'owner', 'source', 'names'])
    return 0


def calendar_ics(c, where):
    args = _window(c, 104)
    if not getattr(c.args, 'from'):
        args['from'] = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
    if c.args.lang:
        args['lang'] = c.args.lang
    got = c.api('GET', '/api/calendar/ics', args=args)
    if where == '-':
        sys.stdout.write(got['text'])
        return 0
    with open(where, 'w', encoding='utf-8', newline='') as f:
        f.write(got['text'])
    return c.done('%d certificate(s) written to %s' % (got['count'], os.path.abspath(where)),
                  {'ok': True, 'file': os.path.abspath(where), 'count': got['count']})


def calendar_feeds(c):
    got = c.api('GET', '/api/calendar/feeds')
    if c.json:
        c.out(got)
        return 0
    if not got['feeds']:
        print('nobody has a link to subscribe to the calendar')
        return 0

    def when(v):
        return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(v))) if v else '-'
    c.table([[f['who'], when(f['made']), when(f['used']), f['lang']] for f in got['feeds']],
            ['account', 'made', 'last fetched', 'language'])
    return 0


def calendar_feed_revoke(c, who):
    who = str(who or '').strip()
    if who.lower() == 'all':
        c.sure('every link to subscribe to the calendar stops working')
        got = c.api('POST', '/api/calendar/feeds_revoke', body={'all': True})
    else:
        got = c.api('POST', '/api/calendar/feeds_revoke', body={'who': who})
    return c.done(got['message'], got)


# ---- request profiles from a template ---------------------------------------------------
def profile_templates(c):
    got = c.api('GET', '/api/reqprofiles/templates')
    if c.json:
        c.out(got)
        return 0
    rows = []
    for t in got['templates']:
        fit = [s['name'] for s in t['sources'] if s['fits']]
        said = {'ok': 'complies', 'warn': 'complies, with warnings', 'bad': 'does not comply',
                'none': 'no source fits'}.get(t.get('status'), '')
        rows.append([t['id'], t['title'], said, ', '.join(fit) or '-', '; '.join(t['sets'])[:90]])
    c.table(rows, ['template', 'for', 'compliance', 'sources that fit', 'what it sets'])
    return 0


def profile_from_template(c, tid):
    a = c.args
    name = (getattr(a, 'name', None) or '').strip()
    if not name:
        raise SystemExit('acme: --profile-from-template needs --name NAME (the new profile)')
    sufs = [w for w in str(getattr(a, 'names', None) or '').replace(',', ' ').split() if w]
    if not sufs:
        raise SystemExit('acme: --profile-from-template needs --names DOMAIN,DOMAIN (the domains '
                         'names may be asked for under)')
    body = {'template': tid, 'name': name, 'suffixes': sufs,
            'issuer': (getattr(a, 'issuer', None) or '').strip(),
            'challenge': (getattr(a, 'challenge', None) or '').strip()}
    if getattr(a, 'note', None):
        body['description'] = a.note
    got = c.api('POST', '/api/reqprofiles/from_template', body=body)
    if c.json:
        c.out(got)
        return 0
    p = got['profile']
    print(c.pal.ok_line(got['message']))
    c.kv([('source', p.get('issuer')), ('validation', p.get('challenge')),
          ('domains', ', '.join(p.get('suffixes') or [])),
          ('keys', ', '.join(p.get('key_types') or [])), ('used for', ', '.join(p.get('eku') or [])),
          ('validity', '%s days' % p['days'] if p.get('days') else 'the CA\'s'),
          ('approval', 'waits' if p.get('approval') else 'at once'),
          ('notes', '; '.join(got.get('notes') or []))])
    for f in got.get('findings') or []:
        if f['level'] in ('bad', 'warn'):
            print('  %s %s%s' % ('!' if f['level'] == 'bad' else '·', f['said'],
                                 (' (from %s)' % f['from']) if f.get('from') else ''))
    return 0
