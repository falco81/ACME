# -*- coding: utf-8 -*-
"""
The command line and the console of the periodic reports and the teams' digests (1.0.140,
docs/command-line.md "Reports and digests", docs/console.md). Each option runs the pages' own
API route here, as 'command line' (a full administrator) - the same checks, events and words.

    acme --reports [--json]                                   the reports defined, their last run
    acme --report-show NAME [--json]                          one, its runs, and what it says now
    acme --report-add NAME --report-kind KIND [--report-teams T1,T2] [--report-formats csv,pdf]
         [--report-every off|weekly|monthly --report-day N --report-hour H]
         [--report-recipients A,B] [--report-lang cs|en] [--report-keep N] [--report-days N]
    acme --report-edit NAME [the same] [--report-name NEW]
    acme --report-del NAME [--yes]
    acme --report-run NAME [--report-send] [--report-out DIR]    made now (and mailed, saved)
    acme --report-runs NAME [--json]
    acme --report-get RUN --report-format csv|pdf --report-out FILE|-
    acme --team-digest TEAM [--json]                          the team's digest: on, when, last
    acme --team-digest-set TEAM [--digest on|off] [--digest-every weekly|daily] [--digest-day N]
         [--digest-hour H] [--digest-days N] [--digest-contact yes|no] [--digest-members W1,W2]
         [--digest-skip-empty yes|no] [--digest-below yes|no] [--digest-lang cs|en|-]
    acme --team-digest-preview TEAM [--digest-lang cs|en] [--report-out FILE.html]
         [--digest-mail ADDR]                                 shown (and mailed to ADDR) - a
                                                              preview, nothing else sent
    acme --team-digest-send TEAM [--yes]                      to its recipients now
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time

KEYS = ('reports', 'report_show', 'report_add', 'report_edit', 'report_del', 'report_run',
        'report_runs', 'report_get', 'team_digest', 'team_digest_set', 'team_digest_preview',
        'team_digest_send')
# options that go only with some of them
WITH = {
    'report_kind': ('report_add', 'report_edit'), 'report_teams': ('report_add', 'report_edit'),
    'report_formats': ('report_add', 'report_edit'), 'report_every': ('report_add', 'report_edit'),
    'report_day': ('report_add', 'report_edit'), 'report_hour': ('report_add', 'report_edit'),
    'report_recipients': ('report_add', 'report_edit'),
    'report_lang': ('report_add', 'report_edit', 'report_show'),
    'report_keep': ('report_add', 'report_edit'), 'report_days': ('report_add', 'report_edit'),
    'report_name': ('report_edit',), 'report_off': ('report_add', 'report_edit'),
    'report_send': ('report_run',), 'report_out': ('report_run', 'report_get',
                                                   'team_digest_preview'),
    'report_format': ('report_get',),
    'digest': ('team_digest_set',), 'digest_every': ('team_digest_set',),
    'digest_day': ('team_digest_set',), 'digest_hour': ('team_digest_set',),
    'digest_days': ('team_digest_set',), 'digest_contact': ('team_digest_set',),
    'digest_members': ('team_digest_set',), 'digest_skip_empty': ('team_digest_set',),
    'digest_below': ('team_digest_set',),
    'digest_lang': ('team_digest_set', 'team_digest_preview'),
    'digest_mail': ('team_digest_preview',)}
YESNO = ('yes', 'no')


def add_args(p):
    g = p.add_argument_group('REPORTS AND DIGESTS', 'Periodic reports for management and audit '
                             '(Settings → Reports, docs/reports.md) and the teams\' digests by '
                             'mail (docs/teams.md "The digest"). With --json each answers JSON.')
    g.add_argument('--reports', action='store_true', help='the reports defined: kind, scope, '
                   'formats, schedule, the last run')
    g.add_argument('--report-show', dest='report_show', metavar='NAME', help='one report: its '
                   'settings, its runs kept and what it says now (--report-lang cs|en)')
    g.add_argument('--report-add', dest='report_add', metavar='NAME', help='a new report: '
                   '--report-kind inventory|expiry|compliance|agents|access, --report-teams, '
                   '--report-formats, --report-every, --report-day, --report-hour, '
                   '--report-recipients, --report-lang, --report-keep, --report-days')
    g.add_argument('--report-edit', dest='report_edit', metavar='NAME', help='change one: the '
                   'same, --report-name NEW')
    g.add_argument('--report-del', dest='report_del', metavar='NAME', help='delete one and its '
                   'runs (--yes)')
    g.add_argument('--report-run', dest='report_run', metavar='NAME', help='make it now and keep '
                   'it; --report-send mails it to its recipients, --report-out DIR saves its files')
    g.add_argument('--report-runs', dest='report_runs', metavar='NAME', help='its runs kept')
    g.add_argument('--report-get', dest='report_get', metavar='RUN', help='a run\'s file: '
                   '--report-format csv|pdf --report-out FILE (- : standard output)')
    g.add_argument('--report-kind', dest='report_kind', metavar='KIND',
                   choices=('inventory', 'expiry', 'compliance', 'agents', 'access'),
                   help='with --report-add/-edit')
    g.add_argument('--report-teams', dest='report_teams', metavar='T1,T2', help='with '
                   '--report-add/-edit: only these teams and those below them (- : every team)')
    g.add_argument('--report-formats', dest='report_formats', metavar='csv,pdf', help='with '
                   '--report-add/-edit [pdf]')
    g.add_argument('--report-every', dest='report_every', choices=('off', 'weekly', 'monthly'),
                   help='with --report-add/-edit: made by itself (off: only by hand) [off]')
    g.add_argument('--report-day', dest='report_day', type=int, metavar='N', help='with '
                   '--report-every: the day of the week (1 Monday - 7) or of the month (1-28)')
    g.add_argument('--report-hour', dest='report_hour', type=int, metavar='H', help='with '
                   '--report-every: the hour (0-23) [7]')
    g.add_argument('--report-recipients', dest='report_recipients', metavar='A,B', help='with '
                   '--report-add/-edit: whom it is mailed to (- : nobody)')
    g.add_argument('--report-lang', dest='report_lang', choices=('cs', 'en', '-'), help='with '
                   '--report-add/-edit, --report-show: its language (- : the mails\')')
    g.add_argument('--report-keep', dest='report_keep', type=int, metavar='N', help='with '
                   '--report-add/-edit: the runs kept [12]')
    g.add_argument('--report-days', dest='report_days', type=int, metavar='N', help='with '
                   '--report-kind expiry: how many days ahead [90]')
    g.add_argument('--report-name', dest='report_name', metavar='NEW', help='with --report-edit')
    g.add_argument('--report-off', dest='report_off', choices=YESNO, help='with '
                   '--report-add/-edit: yes - its schedule paused')
    g.add_argument('--report-send', dest='report_send', action='store_true', help='with '
                   '--report-run')
    g.add_argument('--report-out', dest='report_out', metavar='PATH', help='with --report-run '
                   '(a folder), --report-get (a file, - standard output), --team-digest-preview '
                   '(the HTML into a file)')
    g.add_argument('--report-format', dest='report_format', choices=('csv', 'pdf'),
                   help='with --report-get')
    g.add_argument('--team-digest', dest='team_digest', metavar='TEAM', help='the team\'s '
                   'digest by mail: on or off, when, to whom, the last one')
    g.add_argument('--team-digest-set', dest='team_digest_set', metavar='TEAM', help='set it: '
                   '--digest on|off, --digest-every, --digest-day, --digest-hour, --digest-days, '
                   '--digest-contact, --digest-members, --digest-skip-empty, --digest-below, '
                   '--digest-lang')
    g.add_argument('--team-digest-preview', dest='team_digest_preview', metavar='TEAM',
                   help='what it says now (its plain text; --report-out FILE.html its HTML; '
                   '--digest-mail ADDR a preview mailed there)')
    g.add_argument('--team-digest-send', dest='team_digest_send', metavar='TEAM', help='send it '
                   'to its recipients now (--yes)')
    g.add_argument('--digest', dest='digest', choices=('on', 'off'), help='with '
                   '--team-digest-set')
    g.add_argument('--digest-every', dest='digest_every', choices=('weekly', 'daily'),
                   help='with --team-digest-set [weekly]')
    g.add_argument('--digest-day', dest='digest_day', type=int, metavar='N', help='with '
                   '--team-digest-set: the day of the week, 1 Monday - 7 Sunday [1]')
    g.add_argument('--digest-hour', dest='digest_hour', type=int, metavar='H', help='with '
                   '--team-digest-set: the hour, 0-23 [7]')
    g.add_argument('--digest-days', dest='digest_days', type=int, metavar='N', help='with '
                   '--team-digest-set: certificates ending within N days [30]')
    g.add_argument('--digest-contact', dest='digest_contact', choices=YESNO, help='with '
                   '--team-digest-set: to the team\'s contact address [yes]')
    g.add_argument('--digest-members', dest='digest_members', metavar='W1,W2', help='with '
                   '--team-digest-set: members of the team it goes to (- : none)')
    g.add_argument('--digest-skip-empty', dest='digest_skip_empty', choices=YESNO, help='with '
                   '--team-digest-set: not sent when nothing needs the team [yes]')
    g.add_argument('--digest-below', dest='digest_below', choices=YESNO, help='with '
                   '--team-digest-set: the teams below it too [yes]')
    g.add_argument('--digest-lang', dest='digest_lang', choices=('cs', 'en', '-'), help='with '
                   '--team-digest-set (- : each recipient\'s own), --team-digest-preview')
    g.add_argument('--digest-mail', dest='digest_mail', metavar='ADDR', help='with '
                   '--team-digest-preview: the preview mailed to this address')


def _opt(k):
    return '--' + k.replace('_', '-')


def run(args):
    given = [k for k in KEYS if getattr(args, k, None) not in (None, False, '')]
    if not given:
        return None
    if len(given) > 1:
        raise SystemExit('acme: %s - one of them at a time' % ', '.join(_opt(k) for k in given))
    main = given[0]
    for k, goes in WITH.items():
        if getattr(args, k, None) not in (None, False) and main not in goes:
            raise SystemExit('acme: %s goes with %s - not with %s (nothing was done)' % (
                _opt(k), ', '.join(_opt(g) for g in goes), _opt(main)))
    from acmelib.certs.cli import Cli
    c = Cli(args)
    c.open()
    return globals()['_' + main](c, getattr(args, main))


# ---- the reports ---------------------------------------------------------------------------
def _when(ts):
    if not ts:
        return '-'
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(ts)))


def _sched_words(p):
    s = p.get('schedule') or {}
    if s.get('every') == 'weekly':
        return 'weekly, %s %02d:00' % (('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')[
            max(1, min(7, int(s.get('day') or 1))) - 1], int(s.get('hour') or 0))
    if s.get('every') == 'monthly':
        return 'monthly, day %d %02d:00' % (int(s.get('day') or 1), int(s.get('hour') or 0))
    return 'by hand'


def _reports(c, _v):
    got = c.api('GET', '/api/reports')
    if c.json:
        c.out(got)
        return 0
    rows = []
    for p in got['reports']:
        last = p.get('last') or {}
        rows.append([p['name'], p['kind'], ', '.join(p['teams']) or 'every team',
                     ','.join(p['formats']), _sched_words(p) + ('' if p['enabled'] else
                                                              ' (paused)'),
                     ', '.join(p['recipients']) or '-',
                     ('%s, %d rows%s' % (_when(last.get('ts')), last.get('rows') or 0,
                                         '' if last.get('ok', True) else ', not sent'))
                     if last else '-'])
    if not rows:
        print('no report defined yet - acme --report-add NAME --report-kind KIND')
        return 0
    c.table(rows, ['report', 'kind', 'scope', 'formats', 'made', 'to', 'last run'])
    return 0


def _ref(c, name):
    from acmelib.certs import reports as RP
    r = RP.get_row(c.store, name)
    if not r:
        raise SystemExit('acme: there is no report %s (acme --reports)' % name)
    return r


def _report_show(c, name):
    r = _ref(c, name)
    one = c.api('GET', '/api/reports/one', args={'id': str(r['id'])})
    lang = getattr(c.args, 'report_lang', None)
    pv = c.api('POST', '/api/reports/preview', {'id': r['id'], 'lang': lang
                                                if lang in ('cs', 'en') else None})['preview']
    if c.json:
        c.out(dict(one, preview=pv))
        return 0
    p = one['report']
    c.kv([('report', p['name']), ('kind', p['kind_words']),
          ('scope', ', '.join(p['teams']) or 'every team'), ('formats', ', '.join(p['formats'])),
          ('made', _sched_words(p) + ('' if p['enabled'] else ' (paused)')),
          ('next', _when(p.get('next_at')) if p.get('next_at') else '-'),
          ('to', ', '.join(p['recipients']) or '-'), ('language', p['lang'] or 'the mails\''),
          ('runs kept', p['keep']), ('options', p['options'] or '-')])
    print()
    print('  ' + '   '.join('%s %s' % (t['value'], t['label']) for t in pv['tiles']))
    print()
    heads = [x['head'] for x in pv['columns']]
    if pv['rows']:
        c.table([[str(v)[:48] for v in r_] for r_ in pv['rows'][:30]], heads)
        if pv['total'] > 30:
            print('  … %d rows in all (acme --report-run %s --report-out DIR)' % (pv['total'],
                                                                                  p['name']))
    else:
        print('  nothing to report')
    if one['runs']:
        print()
        _print_runs(c, one['runs'])
    return 0


def _print_runs(c, runs):
    c.table([[str(x['id']), _when(x['ts']), x['by'], str(x['rows']),
              ', '.join(f['format'] for f in x['files']),
              ', '.join(x['sent_to']) or ('-' if x['ok'] else 'not sent: ' + x['said'][:60])]
             for x in runs], ['run', 'made', 'by', 'rows', 'files', 'sent to'])


def _body(c, name, old=None):
    a = c.args
    b = {'name': a.report_name or name}
    if old:
        b['id'] = old['id']
    if a.report_kind:
        b['kind'] = a.report_kind
    if a.report_teams is not None:
        b['teams'] = [] if a.report_teams.strip() in ('', '-') else \
            [t.strip() for t in a.report_teams.split(',') if t.strip()]
    if a.report_formats:
        b['formats'] = [f.strip().lower() for f in a.report_formats.split(',') if f.strip()]
    if any(getattr(a, k) is not None for k in ('report_every', 'report_day', 'report_hour')):
        from acmelib.certs import reports as RP
        cur = RP.public(old)['schedule'] if old else {'every': 'off', 'day': 1, 'hour': 7}
        b['schedule'] = {'every': a.report_every or cur['every'],
                         'day': a.report_day if a.report_day is not None else cur['day'],
                         'hour': a.report_hour if a.report_hour is not None else cur['hour']}
    if a.report_recipients is not None:
        b['recipients'] = '' if a.report_recipients.strip() == '-' else a.report_recipients
    if a.report_lang is not None:
        b['lang'] = '' if a.report_lang == '-' else a.report_lang
    if a.report_keep is not None:
        b['keep'] = a.report_keep
    if a.report_days is not None:
        b['options'] = {'days': a.report_days}
    if a.report_off is not None:
        b['enabled'] = a.report_off != 'yes'
    return b


def _report_add(c, name):
    from acmelib.certs import reports as RP
    if RP.get_row(c.store, name):
        raise SystemExit('acme: there is a report %s already (--report-edit)' % name)
    if not c.args.report_kind:
        raise SystemExit('acme: --report-add needs --report-kind inventory|expiry|compliance|'
                         'agents|access')
    got = c.api('POST', '/api/reports/save', _body(c, name))
    return c.done('the report %s was added (%s)' % (got['report']['name'],
                                                   _sched_words(got['report'])), got)


def _report_edit(c, name):
    old = _ref(c, name)
    got = c.api('POST', '/api/reports/save', _body(c, old['name'], old))
    return c.done('the report %s was changed' % got['report']['name'], got)


def _report_del(c, name):
    r = _ref(c, name)
    c.sure('delete the report %s and its runs' % r['name'])
    got = c.api('POST', '/api/reports/delete', {'id': r['id']})
    return c.done(got['message'], got)


def _save_files(c, run, folder):
    os.makedirs(folder, exist_ok=True)
    out = []
    for f in run['files']:
        got = c.api('GET', '/api/reports/download', args={'run': str(run['id']),
                                                          'format': f['format']})
        path = os.path.join(folder, got['filename'])
        with open(path, 'wb') as fh:
            fh.write(base64.b64decode(got['data_b64']))
        out.append(path)
    return out


def _report_run(c, name):
    r = _ref(c, name)
    got = c.api('POST', '/api/reports/run', {'id': r['id'], 'send': bool(c.args.report_send)})
    run = got['run']
    paths = _save_files(c, run, c.args.report_out) if c.args.report_out else []
    if c.json:
        c.out(dict(got, saved=paths))
        return 0 if run['ok'] else 1
    print(c.pal.ok_line(got['message']) if run['ok'] else c.pal.bad_line(got['message']))
    c.kv([('run', run['id']), ('rows', run['rows']),
          ('files', ', '.join('%s (%d B)' % (f['filename'], f['size']) for f in run['files'])),
          ('sent to', ', '.join(run['sent_to']) or '-'), ('saved', ', '.join(paths) or '-')])
    if c.args.report_send and not got.get('mail_on'):
        print('  mail is switched off (Settings → Mail): nothing was sent')
    return 0 if run['ok'] else 1


def _report_runs(c, name):
    r = _ref(c, name)
    got = c.api('GET', '/api/reports/runs', args={'id': str(r['id'])})
    if c.json:
        c.out(got)
        return 0
    if not got['runs']:
        print('no run kept yet - acme --report-run %s' % r['name'])
        return 0
    _print_runs(c, got['runs'])
    return 0


def _report_get(c, run_id):
    fmt = c.args.report_format or 'pdf'
    if not c.args.report_out:
        raise SystemExit('acme: --report-get needs --report-out FILE (- : standard output)')
    got = c.api('GET', '/api/reports/download', args={'run': str(run_id), 'format': fmt})
    data = base64.b64decode(got['data_b64'])
    if c.args.report_out == '-':
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
        return 0
    with open(c.args.report_out, 'wb') as fh:
        fh.write(data)
    return c.done('%s written to %s (%d B)' % (got['filename'], c.args.report_out, len(data)),
                  {'ok': True, 'filename': got['filename'], 'path': c.args.report_out,
                   'size': len(data)})


# ---- the teams' digests --------------------------------------------------------------------
DAYS = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')


def _digest_words(d):
    if not d.get('on'):
        return 'off'
    when = 'every day' if d['every'] == 'daily' else 'every %s' % DAYS[int(d['day']) - 1]
    return 'on, %s at %02d:00' % (when, int(d['hour']))


def _team_digest(c, team):
    got = c.api('GET', '/api/teams/digest', args={'team': team})
    if c.json:
        c.out(got)
        return 0
    d = got['digest']
    last = d.get('last') or {}
    c.kv([('team', got['team']), ('digest', _digest_words(d)),
          ('next', _when(d.get('next_at')) if d.get('next_at') else '-'),
          ('to', ', '.join(filter(None, [', '.join(d['contact_mail']) if d.get('contact') and
                                         isinstance(d.get('contact_mail'), list) else '',
                                         ', '.join(d.get('members') or [])])) or '-'),
          ('ending within', '%d days' % int(d['days'])),
          ('teams below', 'yes' if d['below'] else 'no'),
          ('when empty', 'not sent' if d['skip_empty'] else 'sent all the same'),
          ('language', d.get('lang') or 'each recipient\'s own'),
          ('last', ('%s - %s' % (_when(last.get('at')), last.get('said') or '-')) if last
           else '-')])
    if not got.get('mail_on'):
        print('  mail is switched off (Settings → Mail): no digest goes out')
    return 0


def _yn(v):
    return None if v is None else v == 'yes'


def _team_digest_set(c, team):
    a = c.args
    b = {}
    if a.digest is not None:
        b['on'] = a.digest == 'on'
    for k, opt in (('every', 'digest_every'), ('day', 'digest_day'), ('hour', 'digest_hour'),
                   ('days', 'digest_days')):
        if getattr(a, opt) is not None:
            b[k] = getattr(a, opt)
    for k, opt in (('contact', 'digest_contact'), ('skip_empty', 'digest_skip_empty'),
                   ('below', 'digest_below')):
        if getattr(a, opt) is not None:
            b[k] = _yn(getattr(a, opt))
    if a.digest_members is not None:
        b['members'] = [] if a.digest_members.strip() == '-' else \
            [m.strip() for m in a.digest_members.split(',') if m.strip()]
    if a.digest_lang is not None:
        b['lang'] = '' if a.digest_lang == '-' else a.digest_lang
    got = c.api('POST', '/api/teams/digest_save', {'team': team, 'digest': b})
    return c.done('the digest of the team %s: %s' % (team, _digest_words(got['digest'])), got)


def _team_digest_preview(c, team):
    a = c.args
    lang = a.digest_lang if a.digest_lang in ('cs', 'en') else None
    got = c.api('POST', '/api/teams/digest_preview', {'team': team, 'lang': lang})['preview']
    sent = None
    if a.digest_mail:
        sent = _mail_preview(c, got['team'], a.digest_mail, lang)
    if a.report_out:
        with open(a.report_out, 'w', encoding='utf-8') as fh:
            fh.write(got['html'])
    if c.json:
        c.out(dict(got, html_saved=a.report_out or None, mailed=sent))
        return 0
    print(got['subject'])
    print()
    print(got['text'])
    if a.report_out:
        print(c.pal.ok_line('the HTML written to %s' % a.report_out))
    if sent:
        print(c.pal.ok_line('a preview went to %s' % sent))
    if got.get('would_skip'):
        print('  (nothing needs the team: the schedule would not send it)')
    return 0


def _mail_preview(c, team, addr, lang):
    """The command line's "send a preview to me": to the address given."""
    from acmelib import engine as E
    from acmelib.certs import digest as D
    from acmelib.certs import teams as T
    if (E.CONFIG.get('mail_mode') or 'off') == 'off':
        raise SystemExit('acme: mail is switched off (Settings → Mail) - nothing can be sent')
    if not T.MAIL_RE.match(addr.strip()):
        raise SystemExit('acme: %s is not a mail address' % addr)
    t = D._team(c.store, team)
    cfg = D.config(t)
    lang = lang or D.default_lang(cfg)
    subject, page, text, _d = D.build(c.store, t, cfg, lang, D._since(c.store, t, cfg),
                                      preview=True)
    try:
        D._deliver(c.store, t, subject, page, text, [addr.strip()], 'team digest preview',
                   c.WHO)
    except E.MailError as e:
        if getattr(e, 'queued', None) != 'waiting':
            raise SystemExit('acme: the mail did not go: %s' % e)
    c.store.add_event('certificates', 'a preview of the digest of the team %s was sent to %s '
                      '(the command line)' % (t['name'], addr.strip()), who=c.WHO)
    return addr.strip()


def _team_digest_send(c, team):
    c.sure('send the digest of the team %s to its recipients now' % team)
    got = c.api('POST', '/api/teams/digest_send', {'team': team})
    r = got['result']
    return c.done('the digest of the team %s: %s' % (team, r.get('said') or '-'), got,
                  ok=bool(r.get('ok')))


# ---------------------------------------------------------------------------
# The console (acme --console): Reports and digests
# ---------------------------------------------------------------------------
def console_menu(con):
    return con.sub('Reports and team digests', [
        ('1', 'The reports (Enter: show, run now, mail, runs, change, delete)',
         lambda: _con_reports(con)),
        ('2', 'Add a report', lambda: _con_report_form(con, None)),
        ('3', 'A team\'s digest by mail (Enter: show, set, preview, send now)',
         lambda: _con_teams(con)),
    ])


def _con_reports(con):
    def load():
        return [{'name': '+ add a report', '_add': True}] + con._rows(con.out('--reports'),
                                                                      'reports')

    cols = [('report', lambda r: r['name'], 28, lambda r: 'ok' if r.get('_add') else None),
            ('kind', lambda r: '' if r.get('_add') else r.get('kind'), 11, None),
            ('scope', lambda r: '' if r.get('_add') else (', '.join(r.get('teams') or [])
                                                          or 'every team'), 22, None),
            ('made', lambda r: '' if r.get('_add') else _sched_words(r), 24, None),
            ('last run', lambda r: '' if r.get('_add') or not r.get('last') else
             _when(r['last'].get('ts')), 16, lambda r: 'dim')]

    def do(r):
        if r.get('_add'):
            return _con_report_form(con, None)
        what = con.choose(r['name'], [
            ('show', 'Show it: its settings, what it says now, its runs'),
            ('run', 'Make it now (kept, to download)'),
            ('send', 'Make it now and mail it to its recipients'),
            ('runs', 'Its runs kept'),
            ('edit', 'Change it'),
            ('del', 'Delete it')], '%s · %s' % (r.get('kind_words') or r.get('kind'),
                                                _sched_words(r)))
        if what == 'show':
            con.act('--report-show', r['name'])
        elif what == 'run':
            con.act('--report-run', r['name'])
        elif what == 'send':
            if con.confirm('Mail it', 'Make %s now and mail it to %s?' % (
                    r['name'], ', '.join(r.get('recipients') or []) or 'nobody'), 'Mail it'):
                con.act('--report-run', r['name'], '--report-send')
        elif what == 'runs':
            con.act('--report-runs', r['name'])
        elif what == 'edit':
            _con_report_form(con, r)
        elif what == 'del':
            if con.confirm('Delete', 'Delete the report %s and its runs?' % r['name'],
                           'Delete it', danger=True):
                con.act('--report-del', r['name'], '--yes')
    return con.pick('Reports', load, cols, do, 'no report yet')


def _con_report_form(con, r):
    r = r or {}
    s = r.get('schedule') or {}
    got = con.form('A report' if not r else r['name'], [
        {'key': 'name', 'label': 'its name', 'need': True, 'value': r.get('name') or ''},
        {'key': 'kind', 'label': 'kind', 'kind': 'choice', 'value': r.get('kind') or 'inventory',
         'options': [('inventory', 'Certificate inventory'), ('expiry', 'Expiry outlook'),
                     ('compliance', 'Compliance with the CA/B rules'),
                     ('agents', 'Agents and their health'), ('access', 'Teams and access')]},
        {'key': 'teams', 'label': 'teams (comma; empty: every team)',
         'value': ', '.join(r.get('teams') or [])},
        {'key': 'formats', 'label': 'formats', 'kind': 'choice',
         'value': ','.join(r.get('formats') or ['csv', 'pdf']),
         'options': [('csv,pdf', 'CSV and PDF'), ('pdf', 'PDF'), ('csv', 'CSV')]},
        {'key': 'every', 'label': 'made by itself', 'kind': 'choice',
         'value': s.get('every') or 'off',
         'options': [('off', 'only by hand'), ('weekly', 'weekly'), ('monthly', 'monthly')]},
        {'key': 'day', 'label': 'day (week 1-7, month 1-28)', 'kind': 'number',
         'value': str(s.get('day') or 1), 'range': (1, 28)},
        {'key': 'hour', 'label': 'hour', 'kind': 'number', 'value': str(s.get('hour') if
                                                                         s.get('hour') is not None
                                                                         else 7),
         'range': (0, 23)},
        {'key': 'to', 'label': 'mailed to (comma)', 'value': ', '.join(
            r.get('recipients') or []) if r else ''},
        {'key': 'lang', 'label': 'language', 'kind': 'choice', 'value': r.get('lang') or '-',
         'options': [('-', 'the mails\' own'), ('cs', 'Czech'), ('en', 'English')]}])
    if not got:
        return
    args = ['--report-edit' if r else '--report-add', r.get('name') or got['name'].strip(),
            '--report-kind', got['kind'], '--report-teams', got['teams'].strip() or '-',
            '--report-formats', got['formats'], '--report-every', got['every'],
            '--report-day', got['day'] or '1', '--report-hour', got['hour'] or '7',
            '--report-recipients', got['to'].strip() or '-', '--report-lang', got['lang']]
    if r and got['name'].strip() != r['name']:
        args += ['--report-name', got['name'].strip()]
    con.act(*args)


def _con_teams(con):
    def load():
        got = con.out('--teams') or {}
        return [t for t in (got.get('teams') or []) if isinstance(t, dict)]

    cols = [('team', lambda r: '  ' * int(r.get('depth') or 0) + r['name'], 34, None),
            ('kind', lambda r: r.get('kind') or 'team', 7, None),
            ('told at', lambda r: r.get('contact_mail') or '-', 40, lambda r: 'dim')]

    def do(r):
        what = con.choose(r['name'], [
            ('show', 'Show its digest: on, when, to whom, the last one'),
            ('set', 'Set it (on / off, when, to whom)'),
            ('preview', 'Preview it (what it says now)'),
            ('send', 'Send it now to its recipients')], 'the team\'s digest by mail')
        if what == 'show':
            con.act('--team-digest', r['name'])
        elif what == 'set':
            _con_digest_form(con, r['name'])
        elif what == 'preview':
            con.act('--team-digest-preview', r['name'])
        elif what == 'send':
            if con.confirm('Send it', 'Send the digest of %s to its recipients now?' % r['name'],
                           'Send it'):
                con.act('--team-digest-send', r['name'], '--yes')
    return con.pick('A team\'s digest', load, cols, do, 'no team yet')


def _con_digest_form(con, team):
    cur = (con.out('--team-digest', team) or {}).get('digest') or {}
    got = con.form('The digest of %s' % team, [
        {'key': 'on', 'label': 'sent', 'kind': 'choice', 'value': 'on' if cur.get('on') else 'off',
         'options': [('off', 'off'), ('on', 'on')]},
        {'key': 'every', 'label': 'how often', 'kind': 'choice',
         'value': cur.get('every') or 'weekly', 'options': [('weekly', 'weekly'),
                                                            ('daily', 'every day')]},
        {'key': 'day', 'label': 'day of the week (1 Monday)', 'kind': 'number',
         'value': str(cur.get('day') or 1), 'range': (1, 7)},
        {'key': 'hour', 'label': 'hour', 'kind': 'number', 'value': str(cur.get('hour') if
                                                                         cur.get('hour') is not None
                                                                         else 7),
         'range': (0, 23)},
        {'key': 'days', 'label': 'ending within (days)', 'kind': 'number',
         'value': str(cur.get('days') or 30), 'range': (1, 365)},
        {'key': 'contact', 'label': 'to the team\'s address', 'kind': 'choice',
         'value': 'yes' if cur.get('contact', True) else 'no', 'options': [('yes', 'yes'),
                                                                           ('no', 'no')]},
        {'key': 'members', 'label': 'to members (comma)', 'value': ', '.join(
            cur.get('members') or [])},
        {'key': 'skip', 'label': 'when nothing needs the team', 'kind': 'choice',
         'value': 'yes' if cur.get('skip_empty', True) else 'no',
         'options': [('yes', 'not sent'), ('no', 'sent all the same')]}])
    if not got:
        return
    con.act('--team-digest-set', team, '--digest', got['on'], '--digest-every', got['every'],
            '--digest-day', got['day'] or '1', '--digest-hour', got['hour'] or '7',
            '--digest-days', got['days'] or '30', '--digest-contact', got['contact'],
            '--digest-members', got['members'].strip() or '-', '--digest-skip-empty', got['skip'])


if __name__ == '__main__':                              # pragma: no cover
    print(json.dumps(KEYS))
