# -*- coding: utf-8 -*-
"""
The console's part of 1.0.140 (acme --console → Certificates): find anything, the expiry
calendar, request profiles from a template. As every menu of the console, it only runs
`acme ...` commands (acmelib/certs/cli_ui.py) - nothing here does more than they do.

    f  Find anything (acme --find): certificates by name, SAN or serial, deployments,
       targets, agents, sources, profiles, teams, accounts, events
    y  The expiry calendar: the next weeks (acme --calendar), as a file for a calendar
       program (acme --calendar-ics), the subscription links (--calendar-feeds, take back)
    p  Request profiles from a template (acme --profile-templates, --profile-from-template)
"""
from __future__ import annotations

KIND_WORDS = {'cert': 'certificate', 'deploy': 'deployment', 'target': 'target', 'agent': 'agent',
              'source': 'source', 'ca': 'authority', 'validation': 'validation', 'test': 'test',
              'profile': 'request profile', 'team': 'team', 'account': 'account',
              'event': 'event'}


def items(con):
    """The lines added to the Certificates menu."""
    return [('f', 'Find anything: a certificate (name, SAN, serial), a target, an agent, a '
                  'team, an event…', lambda: find(con)),
            ('y', 'The expiry calendar: what runs out week by week, a file for a calendar '
                  'program', lambda: calendar(con)),
            ('p', 'Request profiles from a template: web, mail, VPN, internal, wildcard, code '
                  'signing', lambda: templates(con))]


def find(con):
    text = con.ask_one('Find anything', 'find', '', 'A part of a name, a SAN, a serial number, '
                       'a target, a team, an account or words of an event.')
    if not text or not text.strip():
        return
    text = text.strip()

    def load():
        got = con.out('--find', text) or {}
        rows = []
        for kind, items_ in (got.get('groups') or {}).items():
            for r in items_:
                rows.append(dict(r, _kind=kind))
        return rows

    cols = [('what', lambda r: KIND_WORDS.get(r['_kind'], r['_kind']), 16, lambda r: 'dim'),
            ('name', lambda r: r.get('name') or '', 44, None),
            ('', lambda r: r.get('sub') or '', 50, lambda r: 'dim')]

    def do(r):
        k = r['_kind']
        if k == 'cert':
            return con.act('--cert', r['name'])
        if k in ('target', 'agent'):
            return con.act('--target-show', r['name'])
        if k == 'source':
            return con.act('--source-show', r['name'])
        if k == 'validation':
            return con.act('--validation-show', r['name'])
        if k == 'test':
            return con.act('--check-show', r['name'])
        if k == 'ca':
            return con.act('--ca-show', r['name'])
        if k == 'deploy':
            return con.act('--deploys', r.get('cert') or '')
        if k == 'team':
            return con.act('--team-show', r['name'])
        return con.details(KIND_WORDS.get(k, k), {kk: v for kk, v in r.items()
                                                    if not kk.startswith('_')})
    return con.pick('Found: %s' % text, load, cols, do, 'nothing found')


def calendar(con):
    def week():
        got = con.form('The expiry calendar', [
            {'key': 'weeks', 'label': 'weeks', 'kind': 'number', 'value': '13', 'range': (1, 110),
             'help': 'How many weeks from today.'},
            {'key': 'team', 'label': 'only the team', 'value': '', 'need': False,
             'help': 'Its certificates and those of the teams below it; empty: every one.'}])
        if not got:
            return
        args = ['--calendar', '--weeks', got.get('weeks') or '13']
        if (got.get('team') or '').strip():
            args += ['--team', got['team'].strip()]
        con.act(*args)

    def file_():
        got = con.form('A file for a calendar program', [
            {'key': 'path', 'label': 'file', 'value': '/root/acme-certificates.ics'},
            {'key': 'lang', 'label': 'language', 'kind': 'choice',
             'options': [('en', 'English'), ('cs', 'Czech')]}])
        if got and (got.get('path') or '').strip():
            con.act('--calendar-ics', got['path'].strip(), '--lang', got.get('lang') or 'en')

    def revoke():
        who = con.ask_one('Take a calendar link back', 'account', '', 'The account whose link to '
                          'subscribe stops working (all: every one).')
        if who and who.strip():
            con.act('--calendar-feed-revoke', who.strip(), '--yes')
    return con.sub('The expiry calendar', [
        ('1', 'What runs out, week by week', week),
        ('2', 'Write it as a file for a calendar program (.ics)', file_),
        ('3', 'Who has a link to subscribe to their calendar', lambda: con.act('--calendar-feeds')),
        ('4', 'Take a link back', revoke),
    ])


def templates(con):
    def load():
        got = con.out('--profile-templates') or {}
        return got.get('templates') or []

    said = {'ok': 'complies', 'warn': 'warnings', 'bad': 'does not comply', 'none': 'no source'}
    cols = [('template', lambda r: r['title'], 26, None),
            ('compliance', lambda r: said.get(r.get('status'), ''), 16,
             lambda r: {'ok': 'ok', 'warn': 'warn', 'bad': 'bad', 'none': 'dim'}.get(r.get('status'))),
            ('what it sets', lambda r: '; '.join(r.get('sets') or []), 70, lambda r: 'dim')]

    def do(t):
        fit = [s['name'] for s in t.get('sources') or [] if s.get('fits')]
        if not fit:
            con.note(t['title'], 'No source here fits this template%s.' % (
                ' - it needs an authority of acme\'s own' if t.get('needs_own_ca') else ''),
                'warn')
            return
        got = con.form('A new request profile: %s' % t['title'], [
            {'key': 'name', 'label': 'name', 'value': t.get('name') or t['title']},
            {'key': 'names', 'label': 'domains', 'value': '',
             'help': 'The domains names may be asked for under, with commas: example.com'},
            {'key': 'issuer', 'label': 'source', 'kind': 'choice',
             'options': [(n, n) for n in fit], 'value': t.get('source') or fit[0]}],
            words=t.get('about') or '')
        if not got:
            return
        con.act('--profile-from-template', t['id'], '--name', got['name'], '--names',
                got['names'], '--issuer', got['issuer'])
    return con.pick('Request profiles from a template', load, cols, do, 'no template')
