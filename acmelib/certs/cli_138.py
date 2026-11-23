# -*- coding: utf-8 -*-
"""
The command line and the console of 1.0.138's pieces of the pages (docs/command-line.md
"History and trash, request profiles, the agent fleet, the governance of teams"): each option
runs the page's own route here, as `command line` (a full administrator) - the same checks,
events and words, as the rest of acmelib/certs/cli.py does. Nothing here does more than the
pages do.

    --history [TYPE NAME]          the latest changes (--limit N), or one object's history
    --history-restore ENTRY        that version saved again (what changes said first; --yes)
    --trash                        what was deleted and can be restored
    --trash-restore ID [--name NEW]   brought back, with what went with it
    --trash-purge ID|all           gone for good (--yes)
    --profiles                     the request profiles: base, version, ends, used, problems
    --profile-show NAME            one whole
    --profile-versions NAME        its versions: who, when, what changed, certificates of each
    --profile-diff NAME A [B]      two versions field by field (B: now)
    --profile-restore NAME N       as version N said - as a new version (--yes)
    --profile-compliance [DATE]    every profile and certificate against the CA/B schedule
    --profile-dry-run NAME --names D,D   what it would issue, or why it would refuse
    --profile-end NAME SUCCESSOR|-   ends, its certificates move at their renewal (- : undo)
    --profile-del NAME             deleted (to the trash; --yes)
    --fleet                        every agent at a glance: health, version, groups, template,
                                   drift; the groups, the rollout, what is not managed
    --fleet-unmanaged              certificates found on servers that acme does not manage
    --fleet-takeover TARGET SERVICE   taken over: the preview, then made (--yes) [--issuer]
    --fleet-templates              the policy templates
    --fleet-assign TEMPLATE|- AGENT...   the template these agents follow (- : none)
    --fleet-drift [AGENT...]       each agent's policy against its template
    --fleet-group-save NAME [--fleet-members A,B] [--fleet-template REF|-] [--fleet-canary yes|no]
    --fleet-group-del NAME
    --fleet-ask AGENT...|all       asked now (a job)
    --fleet-update AGENT...|all    updated (a job; full administrator)
    --fleet-rollout plan|start|continue|stop|forget [GROUP] [--rollout-wait MIN]
    --team-health [TEAM]           the teams' health and score
    --team-gov TEAM                its governance: reviews, temporary roles, SoD, channels
    --team-gov-set TEAM JSON       {"review": .., "jit": .., "sod": .., "notify": ..} (null: off)
    --team-notify-test TEAM        every channel of the team tried now
    --who-may WHO|team:NAME        who may do what and why (a person, or a team's people)
    --who-can CAP TEAM|cert:NAME   the reverse: who may CAP there, and why
    --elevations [TEAM]            requests for a temporary role
    --elevation-approve ID [--why] / --elevation-decline ID --why / --elevation-end ID
    --reviews [TEAM]               access reviews open now, or a team's
    --review-open TEAM / --review-answer ID WHO keep|out [--note]
    --team-templates / --team-template-save TEAM NAME / --team-from-template TEMPLATE NAME
                                   [--parent TEAM] / --teams-import-csv FILE|- (a preview first)
    --team-template-del NAME       a template of teams deleted

And beside --target-agent NAME (acmelib/certs/cli.py): watch, watch-set KEY=VALUE...,
audit-verify, ack audit|anomaly, rotate [command|seal|both], served; --target-agent all keys,
all keys-rotate.
"""
from __future__ import annotations

import json
import re
import sys
import time

KEYS = ('history', 'history_restore', 'trash', 'trash_restore', 'trash_purge',
        'profiles', 'profile_show', 'profile_versions', 'profile_diff', 'profile_restore',
        'profile_compliance', 'profile_dry_run', 'profile_end', 'profile_del',
        'fleet', 'fleet_unmanaged', 'fleet_takeover', 'fleet_templates', 'fleet_assign',
        'fleet_drift', 'fleet_group_save', 'fleet_group_del', 'fleet_ask', 'fleet_update',
        'fleet_rollout',
        'team_health', 'team_gov', 'team_gov_set', 'team_notify_test', 'who_may', 'who_can',
        'elevations', 'elevation_approve', 'elevation_decline', 'elevation_end', 'reviews',
        'review_open', 'review_answer', 'team_templates', 'team_template_save',
        'team_template_del', 'team_from_template', 'teams_import_csv')
# options of ours that go only with some of ours
WITH = {'fleet_members': ('fleet_group_save',), 'fleet_template': ('fleet_group_save',),
        'fleet_canary': ('fleet_group_save',), 'rollout_wait': ('fleet_rollout',)}
# options of other groups that some of ours read (refused beside the others of ours)
SHARED = {'names': ('profile_dry_run',), 'issuer': ('fleet_takeover',),
          'name': ('trash_restore',), 'parent': ('team_from_template',),
          'why': ('elevation_approve', 'elevation_decline'), 'note': ('review_answer',
                                                                    'profile_end')}
AGENT_VERBS = ('watch', 'watch-set', 'audit-verify', 'ack', 'rotate', 'served')
GOV_KEYS = ('review', 'jit', 'sod', 'notify')


def add_args(p):
    g = p.add_argument_group(
        'HISTORY AND TRASH, REQUEST PROFILES, THE AGENT FLEET, THE GOVERNANCE OF TEAMS',
        'What 1.0.138 added to the pages (docs/command-line.md); with --json each answers JSON.')
    a = g.add_argument
    a('--history', nargs='*', metavar='TYPE NAME', default=None,
      help='the latest changes of everything (--limit N); TYPE NAME: one object\'s history '
           '(cert, target, source, validation, test, deploy, check, profile, team, role, tag, '
           'dnsset, dnsrecord)')
    a('--history-restore', dest='history_restore', metavar='ENTRY', type=int,
      help='that version (an entry of --history) saved again; says what changes first (--yes)')
    a('--trash', action='store_true', help='what was deleted and can be restored (30 days)')
    a('--trash-restore', dest='trash_restore', metavar='ID', type=int,
      help='brought back from the trash, with what went with it (--name NEW: under another '
           'name)')
    a('--trash-purge', dest='trash_purge', metavar='ID|all',
      help='gone for good: one, or every one (a full administrator; --yes)')
    a('--profiles', action='store_true', help='the request profiles: base, version, whether it '
      'ends, how many certificates were asked for from it, what is wrong with it')
    a('--profile-show', dest='profile_show', metavar='NAME', help='one request profile whole')
    a('--profile-versions', dest='profile_versions', metavar='NAME',
      help='its versions: who, when, what changed and why, the certificates of each')
    a('--profile-diff', dest='profile_diff', nargs='+', metavar='ARG',
      help='NAME A [B]: two versions side by side, field by field (B left out: as it is now)')
    a('--profile-restore', dest='profile_restore', nargs=2, metavar=('NAME', 'VERSION'),
      help='as that version said - saved as a new version (--yes)')
    a('--profile-compliance', dest='profile_compliance', nargs='?', const='', default=None,
      metavar='YYYY-MM-DD', help='every profile and every certificate asked for from one '
      'against the CA/Browser Forum\'s schedule and the company\'s rules (on a day to come)')
    a('--profile-dry-run', dest='profile_dry_run', metavar='NAME',
      help='what the profile would issue for --names D,D - or each reason it would refuse; '
           'nothing is issued or kept')
    a('--profile-end', dest='profile_end', nargs=2, metavar=('NAME', 'SUCCESSOR'),
      help='the profile ends: the portal stops offering it, its certificates take the '
           'successor\'s settings at their next renewal (says which first; --yes; --note). '
           'SUCCESSOR -: it no longer ends')
    a('--profile-del', dest='profile_del', metavar='NAME',
      help='delete a request profile (to the trash); what was asked for from it stays (--yes)')
    a('--fleet', action='store_true', help='every target agent at a glance: health, version, '
      'groups, template and drift; the groups, the rollout, how many certificates found are '
      'not managed')
    a('--fleet-unmanaged', dest='fleet_unmanaged', action='store_true',
      help='the certificates found on the servers that acme does not manage, the most urgent '
           'first')
    a('--fleet-takeover', dest='fleet_takeover', nargs=2, metavar=('TARGET', 'SERVICE'),
      help='take over a certificate found there (--fleet-unmanaged): what is made said first, '
           'then made (--yes); --issuer SOURCE')
    a('--fleet-templates', dest='fleet_templates', action='store_true',
      help='the policy templates of the agents: built in and your own')
    a('--fleet-assign', dest='fleet_assign', nargs='+', metavar='ARG',
      help='TEMPLATE|- AGENT...: the template these agents follow (- : none of their own)')
    a('--fleet-drift', dest='fleet_drift', nargs='*', metavar='AGENT', default=None,
      help='each agent\'s policy against its template: the lines missing, the lines besides')
    a('--fleet-group-save', dest='fleet_group_save', metavar='NAME',
      help='a group of agents made or changed: --fleet-members A,B, --fleet-template REF|-, '
           '--fleet-canary yes|no')
    a('--fleet-group-del', dest='fleet_group_del', metavar='NAME', help='a group deleted')
    a('--fleet-members', dest='fleet_members', metavar='A,B',
      help='with --fleet-group-save: its agents (targets), - none')
    a('--fleet-template', dest='fleet_template', metavar='REF',
      help='with --fleet-group-save: the template its agents follow (- none)')
    a('--fleet-canary', dest='fleet_canary', choices=('yes', 'no'),
      help='with --fleet-group-save: the canary ring of an update in rings')
    a('--fleet-ask', dest='fleet_ask', nargs='+', metavar='AGENT',
      help='these agents (or all) asked now, a job')
    a('--fleet-update', dest='fleet_update', nargs='+', metavar='AGENT',
      help='these agents (or all) updated to the agent this acme ships, a job')
    a('--fleet-rollout', dest='fleet_rollout', nargs='+', metavar='ARG',
      help='plan [GROUP] | start [GROUP] [--rollout-wait MIN] | continue | stop | forget: an '
           'update in rings (GROUP, or the group marked the canary ring, or 5 %% - GROUP -: '
           '5 %% - first)')
    a('--rollout-wait', dest='rollout_wait', type=int, metavar='MIN',
      help='with --fleet-rollout start: the minutes before the rest [60]')
    a('--team-health', dest='team_health', nargs='?', const='', default=None, metavar='TEAM',
      help='the teams\' health and one score (TEAM: its lists)')
    a('--team-gov', dest='team_gov', metavar='TEAM', help='a team\'s governance: access '
      'reviews, temporary roles, separation of duties, its channels and escalation')
    a('--team-gov-set', dest='team_gov_set', nargs=2, metavar=('TEAM', 'JSON'),
      help='changed: {"review": {"every_days": 90, "answer_days": 14, "action": '
           '"report|expire"}, "jit": {"roles": [..], "max_hours": 8}, "sod": '
           '{"no_self_approval": true, "exclusive": [["A", "B"]]}, "notify": {"mail": .., '
           '"manager_mail": .., "oncall_mail": .., "expiry_days": 14, "manager_days": 3, '
           '"deploy_failed": "oncall"}} - a key null: off; - : the JSON from stdin')
    a('--team-notify-test', dest='team_notify_test', metavar='TEAM',
      help='every channel of the team tried now')
    a('--who-may', dest='who_may', metavar='WHO|team:NAME',
      help='who may do what and why: a person (local:jan, a user, a group) against every '
           'capability, or team:NAME - the team\'s people')
    a('--who-can', dest='who_can', nargs=2, metavar=('CAP', 'TEAM|cert:NAME'),
      help='the reverse: who may CAP (cert.key, cert.renew...) in a team or on a certificate')
    a('--elevations', nargs='?', const='', default=None, metavar='TEAM',
      help='the requests for a temporary role to decide (TEAM: the team\'s, and its rule)')
    a('--elevation-approve', dest='elevation_approve', metavar='ID', type=int,
      help='a temporary role granted until it ends by itself (--why)')
    a('--elevation-decline', dest='elevation_decline', metavar='ID', type=int,
      help='a request for a temporary role declined (--why)')
    a('--elevation-end', dest='elevation_end', metavar='ID', type=int,
      help='a temporary role ended now')
    a('--reviews', nargs='?', const='', default=None, metavar='TEAM',
      help='the access reviews open now (TEAM: the team\'s, its rule and history)')
    a('--review-open', dest='review_open', metavar='TEAM', help='an access review opened now')
    a('--review-answer', dest='review_answer', nargs=3, metavar=('ID', 'WHO', 'keep|out'),
      help='a member of a review confirmed or taken out (--note)')
    a('--team-templates', dest='team_templates', action='store_true',
      help='the templates of teams')
    a('--team-template-save', dest='team_template_save', nargs=2, metavar=('TEAM', 'NAME'),
      help='a team saved as a template (roles, limits, governance - never a secret)')
    a('--team-template-del', dest='team_template_del', metavar='NAME',
      help='a template of teams deleted (--yes); the teams made from it stay')
    a('--team-from-template', dest='team_from_template', nargs=2, metavar=('TEMPLATE', 'NAME'),
      help='a new team made from a template (--parent TEAM)')
    a('--teams-import-csv', dest='teams_import_csv', metavar='FILE|-',
      help='teams made from a CSV file (name, parent, kind, template, description, '
           'contact_mail, members): a preview first, then made (--yes)')


def _given(a, k):
    v = getattr(a, k, None)
    return v not in (None, False, '') or (k in ('history', 'fleet_drift', 'team_health',
                                                'elevations', 'reviews',
                                                'profile_compliance') and v is not None)


def _opt(k):
    return '--' + k.replace('_', '-')


def run(args):
    given = [k for k in KEYS if _given(args, k)]
    if not given:
        return None
    if len(given) > 1:
        raise SystemExit('acme: %s - one of them at a time' % ', '.join(_opt(k) for k in given))
    main = given[0]
    for k, goes in list(WITH.items()) + list(SHARED.items()):
        if getattr(args, k, None) not in (None, False) and main not in goes:
            if k in SHARED and k not in WITH and getattr(args, k) == '' and k == 'note':
                continue                                   # --note's default is ''
            raise SystemExit('acme: %s goes with %s - not with %s (nothing was done)' % (
                _opt(k), ', '.join(_opt(g) for g in goes), _opt(main)))
    from acmelib.certs.cli import Cli
    c = Cli(args)
    c.open()
    return globals()['_' + main](c, getattr(args, main))


# ---- little helpers ----------------------------------------------------------------------
def _when(ts, fmt='%Y-%m-%d %H:%M'):
    if not ts:
        return '-'
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)


def _short(v, most=60):
    if isinstance(v, (list, tuple)):
        v = ', '.join(str(x) for x in v)
    elif isinstance(v, dict):
        v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    v = str(v if v is not None else '').replace('\n', ' ')
    return v if len(v) <= most else v[:most - 1] + '…'


def _json(c, got):
    if c.json:
        c.out(got)
        return True
    return False


def _sure(c, what):
    c.sure(what)


# ---- history and trash -------------------------------------------------------------------
def _history(c, words):
    if not words:
        lim = getattr(c.args, 'limit', 40) or 40
        got = c.api('GET', '/api/history', args={'feed': '1', 'limit': str(min(500, lim))})
        if _json(c, got):
            return 0
        rows = [[e['id'], _when(e.get('ts')), e.get('type'), _short(e.get('name'), 30),
                 e.get('action'), _short(e.get('who'), 24), _short(e.get('fields'), 40)]
                for e in got.get('entries') or []]
        if not rows:
            print('nothing changed yet (kept %s days)' % got.get('keep_days'))
            return 0
        c.table(rows, ['entry', 'when', 'what', 'name', 'done', 'by', 'fields'])
        print('%d change(s) in all; acme --history TYPE NAME: one object, acme --history-restore '
              'ENTRY: that version again' % got.get('total', len(rows)))
        return 0
    if len(words) != 2:
        raise SystemExit('acme: --history alone (the latest changes) or --history TYPE NAME')
    got = c.api('GET', '/api/history', args={'type': words[0], 'name': words[1]})
    if _json(c, got):
        return 0
    o = got['object']
    print('%s %s%s' % (o.get('words'), o.get('name'), '' if o.get('exists') else (
        ' - deleted%s' % ((' (in the trash: acme --trash-restore %s)' % o['trash_id'])
                          if o.get('trash_id') else ''))))
    for e in got.get('entries') or []:
        print('  %s  #%s  %s by %s%s' % (_when(e.get('ts')), e.get('id'), e.get('action'),
                                        e.get('who') or '?', (' - %s' % e['note'])
                                        if e.get('note') else ''))
        for ch in (e.get('changes') or e.get('made') or [])[:40]:
            print('      %s: %s → %s' % (ch.get('label') or ch.get('key'),
                                         _short(ch.get('before', ch.get('a')), 50),
                                         _short(ch.get('after', ch.get('b')), 50)))
    return 0


def _history_restore(c, entry):
    pre = c.api('POST', '/api/history/preview', body={'entry': entry})
    if not pre.get('exists'):
        raise SystemExit('acme: it is not here any more - restore it from the trash first '
                         '(acme --trash)')
    ch = pre.get('changes') or []
    if not ch:
        return c.done('it is as that version said already - nothing to restore', pre)
    if not c.json:
        print('restoring entry %s changes:' % entry)
        for x in ch[:60]:
            print('  %s: %s → %s' % (x.get('label') or x.get('key'),
                                     _short(x.get('before', x.get('a')), 50),
                                     _short(x.get('after', x.get('b')), 50)))
    _sure(c, '%d field(s) change back' % len(ch))
    got = c.api('POST', '/api/history/restore', body={'entry': entry})
    words = 'restored' + ((' - not restored: %s' % ', '.join(got['lost'])) if got.get('lost')
                          else '')
    return c.done(words, got)


def _trash(c, _v):
    got = c.api('GET', '/api/trash')
    if _json(c, got):
        return 0
    rows = [[r['id'], _when(r.get('ts')), r.get('words'), _short(r.get('name'), 34),
             _short(r.get('who'), 24), _short(', '.join('%s %s' % (k['words'], k['name'])
                                                     for k in r.get('children') or []), 40),
             _when(r.get('expires'), '%Y-%m-%d')] for r in got.get('items') or []]
    if not rows:
        print('the trash is empty (kept %s days)' % got.get('days'))
        return 0
    c.table(rows, ['id', 'deleted', 'what', 'name', 'by', 'with it', 'kept until'])
    return 0


def _trash_restore(c, ident):
    pre = c.api('POST', '/api/trash/preview', body={'id': ident})
    body = {'id': ident}
    if getattr(c.args, 'name', None):
        body['name'] = c.args.name
    got = c.api('POST', '/api/trash/restore', body=body)
    words = 'brought back: %s%s' % (got.get('name') or '', (' with %s' % ', '.join(
        '%s' % (w if isinstance(w, str) else w.get('name') or w) for w in got['with']))
        if got.get('with') else '')
    got['preview'] = pre
    return c.done(words, got)


def _trash_purge(c, which):
    which = str(which).strip()
    if which == 'all':
        _sure(c, 'everything in the trash is gone for good')
        got = c.api('POST', '/api/trash/purge', body={'all': True})
    else:
        try:
            n = int(which)
        except ValueError:
            raise SystemExit('acme: --trash-purge ID (acme --trash) or all')
        _sure(c, 'entry %d of the trash is gone for good' % n)
        got = c.api('POST', '/api/trash/purge', body={'ids': [n]})
    return c.done(got.get('message') or 'deleted for good', got)


# ---- request profiles --------------------------------------------------------------------
def _profile(c, name):
    for p in c.api('GET', '/api/reqprofiles').get('profiles') or []:
        if p['name'].lower() == str(name).strip().lower():
            return p
    raise SystemExit('acme: there is no request profile %s (acme --profiles)' % name)


def _profiles(c, _v):
    got = c.api('GET', '/api/reqprofiles')
    if _json(c, got):
        return 0
    rows = []
    for p in got.get('profiles') or []:
        ends = p.get('ends') or {}
        rows.append([p['name'], 'on' if p.get('enabled') else 'off', p.get('issuer') or '-',
                     p.get('base') or '', p.get('version') or 1,
                     ('→ %s' % ends.get('successor')) if ends else '', p.get('used', 0),
                     _short('; '.join(str(x.get('words') if isinstance(x, dict) else x)
                                      for x in p.get('problems') or []), 40)])
    if not rows:
        print('no request profile yet (acme --profile-templates, --profile-from-template)')
        return 0
    c.table(rows, ['profile', 'portal', 'source', 'based on', 'version', 'ends', 'certs',
                   'problems'])
    return 0


def _profile_show(c, name):
    p = _profile(c, name)
    if _json(c, p):
        return 0
    skip = ('id', 'children', 'problems')
    c.kv([(k, p[k]) for k in sorted(p) if k not in skip], 18)
    if p.get('children'):
        c.kv([('based on it', p['children'])], 18)
    for x in p.get('problems') or []:
        print('  ! %s' % (x.get('words') if isinstance(x, dict) else x))
    return 0


def _profile_versions(c, name):
    got = c.api('GET', '/api/reqprofiles/versions', args={'name': name})
    if _json(c, got):
        return 0
    rows = [[v['version'], _when(v.get('at')), _short(v.get('by'), 24), v.get('certs', 0),
             _short(', '.join(str(x.get('key') if isinstance(x, dict) else x)
                              for x in v.get('changes') or []), 40), _short(v.get('why'), 40)]
            for v in got.get('versions') or []]
    print('%s - version %s now' % (got.get('profile'), got.get('current')))
    c.table(rows, ['version', 'when', 'by', 'certs', 'changed', 'why'])
    return 0


def _profile_diff(c, words):
    if len(words) not in (2, 3):
        raise SystemExit('acme: --profile-diff NAME A [B] (B left out: as it is now)')
    got = c.api('GET', '/api/reqprofiles/diff', args={'name': words[0], 'a': words[1],
                                                      'b': words[2] if len(words) > 2 else 'now'})
    if _json(c, got):
        return 0
    rows = [[r['key'], _short(r.get('a'), 45), _short(r.get('b'), 45)]
            for r in got.get('rows') or [] if not r.get('same')]
    if not rows:
        print('%s: version %s and %s say the same' % (got.get('profile'), got.get('a'),
                                                       got.get('b')))
        return 0
    c.table(rows, ['field', 'version %s' % got.get('a'), str(got.get('b'))])
    return 0


def _profile_restore(c, pair):
    name, n = pair
    try:
        n = int(n)
    except ValueError:
        raise SystemExit('acme: --profile-restore NAME VERSION (a number: acme '
                         '--profile-versions NAME)')
    _sure(c, 'the request profile %s becomes as version %d said (a new version)' % (name, n))
    got = c.api('POST', '/api/reqprofiles/restore', body={'name': name, 'version': n})
    return c.done(got.get('message') or 'restored', got)


def _profile_compliance(c, day):
    got = c.api('GET', '/api/reqprofiles/compliance', args={'at': day} if day else None)
    if _json(c, got):
        return 0
    print('public TLS certificates: %s days at most today, %s on %s' % (
        got.get('limit_now'), got.get('limit_at'), got.get('at')))
    words = {'ok': 'complies', 'bad': 'does not comply', 'ends': 'not on %s' % got.get('at')}
    rows = [[p['name'], words.get(p['status'], p['status']), p.get('days') or '-',
             'yes' if p.get('public') else 'no',
             _short('; '.join(str(f.get('said') or f) if isinstance(f, dict) else str(f)
                              for f in p.get('findings') or []), 60)]
            for p in got.get('profiles') or []]
    if rows:
        c.table(rows, ['profile', 'status', 'days', 'public', 'findings'])
    rows = [[x['name'], x.get('profile'), words.get(x['status'], x['status']),
             _short('; '.join(str(f.get('said') or f) if isinstance(f, dict) else str(f)
                              for f in x.get('findings') or []), 60)]
            for x in got.get('certs') or [] if x.get('status') != 'ok']
    if rows:
        c.table(rows, ['certificate', 'profile', 'status', 'findings'])
    cc = got.get('count') or {}
    print('profiles: %d comply, %d do not, %d not on %s' % (cc.get('ok', 0), cc.get('bad', 0),
                                                          cc.get('ends', 0), got.get('at')))
    return 1 if cc.get('bad') else 0


def _profile_dry_run(c, name):
    names = [x.strip() for x in str(getattr(c.args, 'names', None) or '').split(',')
             if x.strip()]
    if not names:
        raise SystemExit('acme: --profile-dry-run NAME --names DOMAIN,DOMAIN')
    got = c.api('POST', '/api/reqprofiles/dryrun', body={'profile': name, 'names': names})
    if _json(c, got):
        return 0 if got.get('fits') else 1
    v = got.get('validity') or {}
    ap = got.get('approval') or {}
    c.kv([('profile', '%s (version %s)' % (got.get('profile'), got.get('version'))),
          ('subject', ', '.join('%s=%s' % (k, v_) for k, v_ in got.get('subject') or [])),
          ('names', got.get('sans')), ('key', (got.get('key') or {}).get('type')),
          ('usages', got.get('eku')), ('source', got.get('issuer')),
          ('validity', '%s days' % v.get('days') if v.get('days') else 'as the CA says'),
          ('waits', ('yes - %s' % ap.get('approver')) if ap.get('waits') else 'no'),
          ('owner', (got.get('owner') or {}).get('name')), ('tags', got.get('tags'))], 12)
    for r in got.get('refused') or []:
        print(c.pal.bad_line('refused: %s' % (r.get('words') if isinstance(r, dict) else r)))
    if got.get('fits'):
        print(c.pal.ok_line('it would be issued so - nothing was issued'))
        return 0
    return 1


def _profile_end(c, pair):
    name, succ = pair
    if succ == '-':
        got = c.api('POST', '/api/reqprofiles/ends', body={'name': name, 'undo': True})
        return c.done(got.get('message') or 'it no longer ends', got)
    imp = c.api('GET', '/api/reqprofiles/impact', args={'name': name, 'successor': succ})
    if not c.json:
        for x in imp.get('certs') or []:
            print('  %s: renewed %s, %s' % (x['name'], _when(x.get('renews'), '%Y-%m-%d'),
                                            'moves' if x.get('moves') else 'stays as it is (%s)'
                                            % (x.get('why') or '?')))
    _sure(c, 'the request profile %s ends, %s its successor: %d certificate(s) move at their '
          'renewal, %d stay' % (name, succ, imp.get('moves', 0), imp.get('stays', 0)))
    got = c.api('POST', '/api/reqprofiles/ends', body={'name': name, 'successor': succ,
                                                       'note': getattr(c.args, 'note', '') or ''})
    got['impact'] = imp
    return c.done(got.get('message') or 'it ends', got)


def _profile_del(c, name):
    p = _profile(c, name)
    _sure(c, 'the request profile %s is deleted (to the trash); %d certificate(s) asked for from '
          'it stay' % (p['name'], p.get('used', 0)))
    got = c.api('POST', '/api/reqprofiles/delete', body={'name': p['name']})
    return c.done(got.get('message') or 'deleted', got)


# ---- the agent fleet ---------------------------------------------------------------------
def _agent_ids(c, words, allow_all=True):
    from acmelib.certs import agents as G
    if allow_all and [w.lower() for w in words] == ['all']:
        return [r['id'] for r in G.rows(c.store)]
    out = []
    for w in words:
        for one in str(w).split(','):
            if not one.strip():
                continue
            try:
                out.append(int(G.target_row(c.store, one.strip())['id']))
            except LookupError as e:
                raise SystemExit('acme: %s' % e)
    if not out:
        raise SystemExit('acme: which agents? (their targets, or all)')
    return out


def _group(c, name):
    for g in c.api('GET', '/api/fleet').get('groups') or []:
        if g['name'].lower() == str(name).strip().lower() or g['id'] == name:
            return g
    raise SystemExit('acme: there is no group %s (acme --fleet)' % name)


def _template_ref(c, word):
    for t in c.api('GET', '/api/fleet/templates').get('templates') or []:
        if word in (t.get('ref'), t.get('title')) or str(t.get('title') or '').lower() == \
                str(word).lower():
            return t['ref']
    raise SystemExit('acme: there is no template %s (acme --fleet-templates)' % word)


def _fleet(c, _v):
    got = c.api('GET', '/api/fleet')
    if _json(c, got):
        return 0
    h = got.get('health') or {}
    print('%d agent(s): %d ok, %d to look at, %d bad, %d idle - acme ships acme-agent %s' % (
        len(got.get('agents') or []), h.get('ok', 0), h.get('warn', 0), h.get('bad', 0),
        h.get('idle', 0), got.get('offered')))
    gname = {g['id']: g['name'] for g in got.get('groups') or []}
    rows = [[a['name'], a.get('kind'), a.get('version') or '-', a.get('health'),
             _short(a.get('why'), 40), _short([gname.get(x, x) for x in a.get('groups') or []], 20),
             (a.get('template') or {}).get('title') or '',
             (a.get('drift') or {}).get('state') or ''] for a in got.get('agents') or []]
    if rows:
        c.table(rows, ['agent', 'kind', 'version', 'health', 'why', 'groups', 'template',
                       'drift'])
    rows = [[g['name'], len(g.get('members') or []), g.get('template_title') or '',
             g.get('drifted', 0), 'yes' if g.get('canary') else ''] for g in got.get('groups')
            or []]
    if rows:
        c.table(rows, ['group', 'agents', 'template', 'drifted', 'canary'])
    r = got.get('rollout')
    if r:
        print('an update in rings to %s: %s%s' % (r.get('version'), r.get('phase'),
                                                 (' - held: %s' % r['held']) if r.get('held')
                                                 else ''))
    if got.get('unmanaged'):
        print('%s certificate(s) found on the servers are not managed by acme (acme '
              '--fleet-unmanaged)' % got['unmanaged'])
    return 0


def _fleet_unmanaged(c, _v):
    got = c.api('GET', '/api/fleet/unmanaged')
    if _json(c, got):
        return 0
    rows = [[r['target'], r.get('service') or '-', _short(r.get('where'), 30),
             _short(r.get('names'), 34), '-' if r.get('days') is None else r['days'],
             r.get('risk'), 'yes' if r.get('can_take') else 'by hand']
            for r in got.get('rows') or []]
    if not rows:
        print('every certificate found on the servers is managed by acme (or nothing was '
              'discovered yet)')
        return 0
    c.table(rows, ['target', 'service', 'where', 'names', 'days', 'risk', 'take over'])
    print('acme --fleet-takeover TARGET SERVICE takes one over')
    return 0


def _fleet_takeover(c, pair):
    body = {'target': pair[0], 'service': pair[1]}
    if getattr(c.args, 'issuer', None):
        body['issuer'] = c.args.issuer
    pre = c.api('POST', '/api/fleet/takeover_preview', body=body)['preview']
    if not c.json:
        for kind, words in pre.get('steps') or []:
            print('  %s %s' % ({'ok': '✔', 'wait': '!'}.get(kind, '·'), words))
        if pre.get('block'):
            print('  on the server:\n    ' + pre['block'].replace('\n', '\n    '))
    _sure(c, 'the certificate %s and its deployment to %s are made' % (pre['cert']['name'],
                                                                       pre['target']))
    body.update(confirm=True, issue_now=False, auto_renew=True)
    got = c.api('POST', '/api/fleet/takeover', body=body)
    got['preview'] = pre
    return c.done('taken over: the certificate %s, its deployment to %s (acme --renew %s issues '
                  'it now)' % (got.get('name'), pre['target'], got.get('name')), got)


def _fleet_templates(c, _v):
    got = c.api('GET', '/api/fleet/templates')
    if _json(c, got):
        return 0
    c.table([[t['ref'], _short(t.get('title'), 34), t.get('platform') or '',
              'built in' if t.get('builtin') else (t.get('by') or ''),
              _short(t.get('note'), 40)] for t in got.get('templates') or []],
            ['ref', 'template', 'platform', 'by', 'note'])
    return 0


def _fleet_assign(c, words):
    if len(words) < 2:
        raise SystemExit('acme: --fleet-assign TEMPLATE|- AGENT [AGENT...]')
    ref = '' if words[0] == '-' else _template_ref(c, words[0])
    got = c.api('POST', '/api/fleet/assign', body={'ids': _agent_ids(c, words[1:]),
                                                  'template': ref})
    return c.done('%d agent(s) %s' % (len(got.get('done') or []), ('follow %s' % words[0])
                                       if ref else 'follow no template of their own'), got)


def _fleet_drift(c, words):
    ids = _agent_ids(c, words) if words else [a['id'] for a in c.api('GET', '/api/fleet').get(
        'agents') or [] if a.get('template')]
    got = c.api('GET', '/api/fleet/drift', args={'ids': ','.join(str(i) for i in ids)})
    if _json(c, got):
        return 0
    bad = 0
    for r in got.get('rows') or []:
        d = r.get('drift') or {}
        state = d.get('state') or 'no template'
        bad += state == 'differs'
        print('%s: %s%s%s' % (r.get('name') or r.get('id'), state, (' (%s%s)' % (
            (d.get('template') or {}).get('title') or '', (', of the group %s' % d['template'][
                'group']) if (d.get('template') or {}).get('group') else '')) if d.get('template')
            else '', (' - %s' % d['said']) if d.get('said') else ''))
        for x in d.get('missing') or []:
            print('   - missing on the server: %s' % x)
        for x in d.get('extra') or []:
            print('   + there besides: %s' % x)
    if not got.get('rows'):
        print('no agent follows a template (acme --fleet-assign)')
    return 1 if bad else 0


def _fleet_group_save(c, name):
    a = c.args
    body = {'name': name}
    try:
        body['id'] = _group(c, name)['id']
    except SystemExit:
        pass
    if a.fleet_members is not None:
        body['members'] = [] if a.fleet_members.strip() == '-' else _agent_ids(
            c, [a.fleet_members], allow_all=False)
    if a.fleet_template is not None:
        body['template'] = '' if a.fleet_template == '-' else _template_ref(c, a.fleet_template)
    if a.fleet_canary is not None:
        body['canary'] = a.fleet_canary == 'yes'
    got = c.api('POST', '/api/fleet/group_save', body=body)
    return c.done('the group %s is %s (%d agent(s))' % (name, 'changed' if 'id' in body else
                                                        'made', len(got['group']['members'])),
                  got)


def _fleet_group_del(c, name):
    g = _group(c, name)
    got = c.api('POST', '/api/fleet/group_delete', body={'id': g['id']})
    return c.done('the group %s is deleted' % g['name'], got)


def _fleet_job(c, action, words):
    got = c.api('POST', '/api/fleet/act', body={'action': action, 'ids': _agent_ids(c, words)})
    v = c._follow(got['job_id'])
    ok = bool(v.get('ok'))
    return c.done('job %s: %s' % (got['job_id'], v.get('said') or v.get('state')),
                  dict(got, ok=ok, said=v.get('said')), ok)


def _fleet_ask(c, words):
    return _fleet_job(c, 'ask', words)


def _fleet_update(c, words):
    return _fleet_job(c, 'update', words)


def _canary_of(c, rest):
    """The canary ring's group: the one named (- : none, 5 % of the agents), or - as the page
    has it - the group marked the canary ring (1.0.141: the command line took 5 % even then)."""
    if rest:
        return '' if rest[0] == '-' else _group(c, rest[0])['id']
    return next((g['id'] for g in c.api('GET', '/api/fleet').get('groups') or []
                 if g.get('canary')), '')


def _fleet_rollout(c, words):
    what, rest = words[0], words[1:]
    if what == 'plan':
        canary = _canary_of(c, rest)
        args = {'canary': canary} if canary else None
        got = c.api('GET', '/api/fleet/rollout_plan', args=args)
        if _json(c, got):
            return 0
        print('canary ring (%s): %s' % ('the group' if got.get('how') == 'group' else '5 %',
                                         ', '.join(x['name'] for x in got['canary']) or 'none'))
        print('then the rest: %s' % (', '.join(x['name'] for x in got['rest']) or 'none'))
        for x in got.get('skipped') or []:
            print('  not updated: %s - %s' % (x['name'], x['why']))
        return 0
    if what == 'start':
        body = {}
        canary = _canary_of(c, rest)
        if canary:
            body['canary'] = canary
        if c.args.rollout_wait is not None:
            body['wait'] = c.args.rollout_wait
        _sure(c, 'the agents are updated in rings')
        got = c.api('POST', '/api/fleet/rollout', body=body)
        r = got.get('rollout') or {}
        return c.done('an update in rings to %s: %d in the canary ring, %d after %s minute(s)' % (
            r.get('version'), len(r.get('canary') or []), len(r.get('rest') or []),
            r.get('wait')), got)
    if what in ('continue', 'stop', 'forget'):
        got = c.api('POST', '/api/fleet/rollout_step', body={'do': what})
        return c.done({'continue': 'the rollout goes on with the rest', 'stop': 'the rollout is '
                       'stopped', 'forget': 'the rollout is forgotten'}[what], got)
    raise SystemExit('acme: --fleet-rollout plan|start|continue|stop|forget [GROUP]')


# ---- the governance of teams -------------------------------------------------------------
def _team_health(c, team):
    got = c.api('GET', '/api/teams/health', args={'team': team} if team else None)
    if _json(c, got):
        return 0
    rows = []
    for r in got.get('teams') or []:
        b = r.get('below') or {}
        rows.append([r['team'], r.get('score'), r.get('grade'), b.get('certs', 0),
                     b.get('expiring', 0), b.get('expired', 0), b.get('failed_renewals', 0),
                     b.get('failed_deploys', 0), b.get('outside', 0), b.get('weak', 0)])
    c.table(rows, ['team', 'score', 'grade', 'certs', 'ending', 'expired', 'renewals failed',
                   'deploys failed', 'outside limits', 'weak'])
    if got.get('score') is not None:
        print('the score of every team together: %s (certificates ending within %s days)' % (
            got['score'], got.get('days')))
    return 0


def _team_row(c, name):
    for t in c.api('GET', '/api/teams').get('teams') or []:
        if t['name'].lower() == str(name).strip().lower():
            return t
    raise SystemExit('acme: there is no team %s (acme --teams)' % name)


def _team_gov(c, name):
    from acmelib.certs import teamgov as G
    from acmelib.certs import teams as T
    t = T.team_get(c.store, name)
    if not t:
        raise SystemExit('acme: there is no team %s (acme --teams)' % name)
    src, rule = G.jit_rule(c.store, t['name'])
    got = {'team': t['name'], 'gov': G.public_extras(t),
           'jit_in_force': {'rule': rule, 'from': src},
           'sod_in_force': G.sod_rules(c.store, t['name'])}
    if _json(c, got):
        return 0
    g = got['gov']
    sod = got['sod_in_force']
    print('the governance of %s' % t['name'])
    c.kv([('access reviews', g.get('review') or 'off'),
          ('temporary roles', g.get('jit') or (('from %s: %s' % (src, json.dumps(rule)))
                                               if rule else 'off')),
          ('separation', g.get('sod') or (('from above: %s' % json.dumps(sod))
                                          if sod.get('no_self_approval') or sod.get('exclusive')
                                          else 'off')),
          ('channels', g.get('notify') or 'as before (its contact)'),
          ('webhooks', ', '.join(k for k, v in (g.get('hooks') or {}).items() if v) or 'none')],
         16)
    return 0


def _team_gov_set(c, pair):
    name, raw = pair
    if raw == '-':
        raw = sys.stdin.read()
    try:
        b = json.loads(raw)
    except ValueError as e:
        raise SystemExit('acme: --team-gov-set TEAM JSON: %s' % e)
    if not isinstance(b, dict) or not b or any(k not in GOV_KEYS for k in b):
        raise SystemExit('acme: --team-gov-set TEAM JSON: an object of %s (the webhooks are '
                         'kept sealed: acme --api POST /api/teams/hooks - with the body on stdin)'
                         % ', '.join(GOV_KEYS))
    b['team'] = name
    got = c.api('POST', '/api/teams/governance', body=b)
    for x in got.get('clash') or []:
        if not c.json:
            print(c.pal.warn('  %s holds %s and %s in %s - said, not taken away' % (
                x['who'], x['pair'][0], x['pair'][1], x['team'])))
    return c.done(got.get('message') or 'saved', got)


def _team_notify_test(c, name):
    got = c.api('POST', '/api/teams/notify_test', body={'team': name})
    ch = got.get('channels') or {}
    bad = [k for k, v in ch.items() if not _sent(v.get('result'))]
    if _json(c, got):
        return 1 if bad else 0
    if got.get('from') and got['from'] != name:
        print('the channels of %s (the team above)' % got['from'])
    for k, v in ch.items():
        line = '%s%s: %s' % (k, (' (%s)' % ', '.join(v['to'])) if v.get('to') else '',
                             _short(v.get('result'), 120))
        print(c.pal.bad_line(line) if k in bad else c.pal.ok_line(line))
    if not ch:
        print('nothing to try')
    return 1 if bad else 0


def _sent(r):
    """A channel's result: True, {ok: ..}, "sent", or the words of what went wrong."""
    if isinstance(r, dict):
        return bool(r.get('ok', not r.get('error')))
    if isinstance(r, str):
        return r.lower() in ('ok', 'sent', 'queued') or r.lower().startswith('sent')
    return bool(r)


def _via_words(v):
    """Why: a right or a role, on which team, inherited, a temporary role and until when."""
    what = ', '.join(list(v.get('roles') or []) + list(v.get('rights') or [])) or '?'
    out = '%s on %s' % (what, v.get('team') or '?')
    if v.get('group'):
        out += ' (through the group %s)' % v['group']
    elif v.get('who'):
        out += ' (as %s)' % v['who']
    if v.get('inherited'):
        out += ', inherited'
    if v.get('jit'):
        out += ', a temporary role'
    if v.get('until'):
        out += ', until %s' % _when(v['until'])
    if v.get('expired'):
        out += ' - ended'
    return out


def _who_may(c, who):
    args = {'team': who[5:]} if who.lower().startswith('team:') else {'who': who}
    got = c.api('GET', '/api/teams/whomay', args=args)
    if _json(c, got):
        return 0
    if got.get('mode') == 'team':
        print('the people of %s (%s)' % (got.get('team'), ' → '.join(got.get('chain') or [])))
        for p in got.get('people') or []:
            print('  %s: %s' % (p.get('who'), ', '.join(p.get('caps') or []) or 'nothing'))
            for v in p.get('via') or []:
                print('      %s' % _via_words(v))
        if not got.get('people'):
            print('  nobody but those who see every certificate')
        return 0
    acc = got.get('account') or {}
    found = got.get('who')
    if isinstance(found, dict):
        found = found.get('name') or found.get('dn') or who
    print('%s%s%s' % (found or who, (' - an account of the administration: %s%s' % (
        acc.get('role'), ', switched off' if acc.get('disabled') else '')) if acc else '',
        (' - in %d group(s)' % got['groups_count']) if got.get('groups_count') else ''))
    for t in got.get('teams') or []:
        print('  %s%s: %s' % ('  ' * int(t.get('depth') or 0), t.get('team'),
                              ', '.join(t.get('caps') or []) or 'nothing'))
        for v in t.get('via') or []:
            print('      %s' % _via_words(v))
        if t.get('limits'):
            print('      its limits: %s' % _short(t['limits'], 100))
    if not got.get('teams'):
        print('  no team gives them anything')
    return 0


def _who_can(c, pair):
    cap, where = pair
    args = {'cap': cap}
    if where.lower().startswith('cert:'):
        args['cert'] = where[5:]
    else:
        args['team'] = where
    got = c.api('GET', '/api/teams/whocan', args=args)
    if _json(c, got):
        return 0
    print('who may %s (%s) in %s%s' % (got.get('cap'), got.get('words') or '',
                                       got.get('team') or 'no team',
                                       (' - the certificate %s' % got['cert'])
                                       if got.get('cert') else ''))
    for p in got.get('people') or []:
        why = p.get('why_here') or p.get('via') or []
        print('  %s%s' % (p.get('who') or p.get('name') or '', '' if why else
                          (' (%s)' % (p.get('role') or 'sees every certificate'))))
        for v in why:
            print('      %s' % _via_words(v))
    if not got.get('people'):
        print('  nobody but the full administrators')
    if got.get('limit'):
        print('  the team\'s limits: %s' % _short(got['limit'], 100))
    return 0


def _elev_rows(c, rows):
    c.table([[r['id'], r.get('team'), _short(r.get('who'), 24), r.get('role'), r.get('hours'),
              r.get('state'), _when(r.get('asked')), _short(r.get('reason'), 40)]
             for r in rows], ['id', 'team', 'who', 'role', 'hours', 'state', 'asked', 'why'])


def _elevations(c, team):
    got = c.api('GET', '/api/teams/elevations', args={'team': team} if team else None)
    if _json(c, got):
        return 0
    if team:
        print('temporary roles in %s: %s' % (got.get('team'), json.dumps(got.get('rule'))
                                             if got.get('rule') else 'not allowed'))
        _elev_rows(c, got.get('rows') or [])
        return 0
    todo = got.get('to_decide') or []
    if not todo:
        print('no request for a temporary role waits')
        return 0
    _elev_rows(c, todo)
    print('acme --elevation-approve ID, --elevation-decline ID --why TEXT')
    return 0


def _elevation_approve(c, ident):
    got = c.api('POST', '/api/teams/elevate_decide', body={
        'id': ident, 'ok': True, 'why': getattr(c.args, 'why', None) or ''})
    return c.done(got.get('message') or 'granted', got)


def _elevation_decline(c, ident):
    got = c.api('POST', '/api/teams/elevate_decide', body={
        'id': ident, 'ok': False, 'why': getattr(c.args, 'why', None) or ''})
    return c.done(got.get('message') or 'declined', got)


def _elevation_end(c, ident):
    got = c.api('POST', '/api/teams/elevate_end', body={'id': ident})
    return c.done(got.get('message') or 'ended', got)


def _rev_rows(c, rows):
    c.table([[r['id'], r.get('team'), r.get('state') + (' (late)' if r.get('late') else ''),
              _when(r.get('started'), '%Y-%m-%d'), _when(r.get('due'), '%Y-%m-%d'),
              r.get('pending', 0), len(r.get('items') or [])] for r in rows],
            ['id', 'team', 'state', 'opened', 'due', 'to answer', 'members'])


def _reviews(c, team):
    got = c.api('GET', '/api/teams/reviews', args={'team': team} if team else None)
    if _json(c, got):
        return 0
    if not team:
        if not got.get('open'):
            print('no access review is open')
            return 0
        _rev_rows(c, got['open'])
        return 0
    print('access reviews of %s: %s' % (got.get('team'), json.dumps(got.get('rule'))
                                         if got.get('rule') else 'not on a schedule'))
    if got.get('reviews'):
        _rev_rows(c, got['reviews'])
        cur = next((r for r in got['reviews'] if r.get('state') in ('open', 'overdue')), None)
        for i in (cur or {}).get('items') or []:
            print('  #%s %-28s %-10s %s' % (cur['id'], i.get('who'), i.get('state'),
                                            ', '.join(i.get('roles') or i.get('rights') or [])))
    return 0


def _review_open(c, team):
    got = c.api('POST', '/api/teams/review_open', body={'team': team})
    r = got.get('review') or {}
    return c.done('the access review of %s is open: %d member(s) to confirm by %s' % (
        r.get('team'), r.get('pending', 0), _when(r.get('due'), '%Y-%m-%d')), got)


def _review_answer(c, three):
    rid, who, keep = three
    if keep not in ('keep', 'out'):
        raise SystemExit('acme: --review-answer ID WHO keep|out')
    got = c.api('POST', '/api/teams/review_answer', body={
        'id': rid, 'who': who, 'keep': keep == 'keep', 'note': getattr(c.args, 'note', '') or ''})
    return c.done('%s %s' % (who, got.get('message')), got)


def _team_templates(c, _v):
    got = c.api('GET', '/api/teams/templates')
    if _json(c, got):
        return 0
    rows = [[t['name'], _short(t.get('description'), 40), (t.get('config') or {}).get('kind')
             or '', len((t.get('config') or {}).get('members') or []),
             ', '.join(k for k in GOV_KEYS if ((t.get('config') or {}).get('extras') or {}).get(k))]
            for t in got.get('templates') or []]
    if not rows:
        print('no team template yet (acme --team-template-save TEAM NAME)')
        return 0
    c.table(rows, ['template', 'description', 'kind', 'members', 'governance'])
    return 0


def _team_template_save(c, pair):
    team, name = pair
    got = c.api('POST', '/api/teams/template_save', body={'name': name, 'from_team': team})
    return c.done(got.get('message') or 'saved', got)


def _team_template_del(c, name):
    # the page deletes a template (Settings -> Owners and teams -> Templates); the command line
    # had no way to (hunt v4)
    _sure(c, 'the team template %s is deleted' % name)
    got = c.api('POST', '/api/teams/template_delete', body={'name': name})
    return c.done(got.get('message') or 'deleted', got)


def _team_from_template(c, pair):
    tpl, name = pair
    body = {'template': tpl, 'name': name}
    if getattr(c.args, 'parent', None):
        body['parent'] = c.args.parent
    got = c.api('POST', '/api/teams/from_template', body=body)
    return c.done(got.get('message') or 'made', got)


def _teams_import_csv(c, path):
    if path == '-':
        text = sys.stdin.read()
    else:
        text = c._read(path, 4 << 20).decode('utf-8-sig', 'replace')
    pre = c.api('POST', '/api/teams/import_csv', body={'csv': text, 'dry_run': True})
    if not c.json:
        for r in pre.get('rows') or []:
            mark = {'new': '+', 'exists': '=', 'error': '✘'}.get(r.get('state'), '?')
            print('  %s %s%s' % (mark, r.get('name') or '', (' - %s' % r['error'])
                                 if r.get('error') else (' - there already'
                                                         if r.get('state') == 'exists' else (
                                     (' under %s' % r['parent']) if r.get('parent') else ''))))
    if pre.get('errors'):
        if c.json:
            c.out(pre)
        raise SystemExit('acme: the file has errors - nothing was made')
    if not pre.get('new'):
        return c.done('every team of the file is there already - nothing to make', pre)
    _sure(c, 'the teams of the file are made')
    got = c.api('POST', '/api/teams/import_csv', body={'csv': text, 'dry_run': False})
    return c.done(got.get('message') or 'made', got)


# ---- beside --target-agent NAME (cli.py): what acme watches of an agent --------------------
def agent_all(c, what):
    """acme --target-agent all keys | keys-rotate."""
    if what == 'keys':
        got = c.api('GET', '/api/agents/keys')
        if _json(c, got):
            return 0
        k = got['keys']
        ca = k.get('ca') or {}
        c.kv([('agents\' CA', ('%s… (%s days old)' % (str(ca['fp'])[:16], ca.get('age')))
                if ca.get('fp') else 'not made yet (no agent has joined)'),
              ('acme\'s own', 'ends %s' % _when((k.get('ctl') or {}).get('end'), '%Y-%m-%d'))],
             14)
        c.table([[str(x['fp'])[:16], 'now' if x.get('current') else (
            'retired' if x.get('retired_at') else 'still taken'), x.get('age'),
            _short(x.get('agents'), 50)] for x in k.get('cmd') or []],
            ['command key', 'state', 'days old', 'pinned by'])
        c.table([[a['name'], a.get('cmd_age'), a.get('enc_age'),
                  ('every %s d' % a['rotate_days']) if a.get('rotate') else 'by hand',
                  ', '.join(a.get('due') or []) or '-', _short(a.get('said'), 40)]
                 for a in k.get('agents') or []],
                ['agent', 'command key (days)', 'secrets key (days)', 'changed', 'due', 'said'])
        return 0
    if what == 'keys-rotate':
        _sure(c, 'acme makes a new command key; the agents whose keys are changed on a schedule '
              'move to it (the old one is taken for three days)')
        got = c.api('POST', '/api/agents/keys/rotate')
        r = got.get('rotated') or {}
        for x in r.get('left') or []:
            print(c.pal.warn('  %s: %s' % (x['name'], x['said'])))
        return c.done('a new command key %s…; %d agent(s) moved to it' % (
            str(r.get('fp'))[:16], len(r.get('moved') or [])), got)
    return None


def agent_verb(c, row, what, rest):
    """acme --target-agent NAME watch | watch-set KEY=VALUE... | audit-verify | ack audit|anomaly
    | rotate [command|seal|both] | served - the card's "Watching this agent" (1.0.138)."""
    body = {'id': row['id']}
    if what == 'watch':
        got = c.api('GET', '/api/agents/guard', args={'id': str(row['id'])})
        if _json(c, got):
            return 0
        return _watch_print(c, got['guard'])
    if what == 'watch-set':
        if not rest:
            raise SystemExit('acme: --target-agent NAME watch-set audit=on|off anomaly=on|off '
                             'rotate=on|off rotate_days=N health=on|off')
        for one in rest:
            k, _, v = one.partition('=')
            if k in ('audit', 'anomaly', 'rotate'):
                if v not in ('on', 'off'):
                    raise SystemExit('acme: %s is on or off' % k)
                body[k] = v == 'on'
            elif k in ('health', 'served'):
                if v not in ('on', 'off'):
                    raise SystemExit('acme: %s is on or off' % k)
                body['health'] = v
            elif k == 'rotate_days':
                try:
                    body[k] = int(v)
                except ValueError:
                    raise SystemExit('acme: rotate_days is a number of days')
            else:
                raise SystemExit('acme: watch-set takes audit, anomaly, rotate, rotate_days, '
                                 'health - not %s' % k)
        got = c.api('POST', '/api/agents/guard', body=body)
        if _json(c, got):
            return 0
        return _watch_print(c, got['guard'])
    if what == 'audit-verify':
        got = c.api('POST', '/api/agents/guard/verify', body=body)
        a = got['guard']['audit']
        ok = a.get('state') in ('ok', 'waiting') and not a.get('problems')
        if _json(c, got):
            return 0 if ok else 1
        print('the audit chain of %s: %s - %s entries, %s checked%s' % (
            row['name'], a.get('state'), a.get('n') or 0, a.get('verified_n') or 0,
            (', %d not agreeing' % a['problems']) if a.get('problems') else ''))
        return 0 if ok else 1
    if what == 'ack':
        if rest[:1] not in (['audit'], ['anomaly']):
            raise SystemExit('acme: --target-agent NAME ack audit|anomaly')
        body['what'] = rest[0]
        got = c.api('POST', '/api/agents/guard/ack', body=body)
        return c.done('looked at: what is there now is the agent\'s usual', got)
    if what == 'rotate':
        body['what'] = rest[0] if rest else 'both'
        if body['what'] not in ('command', 'seal', 'both'):
            raise SystemExit('acme: --target-agent NAME rotate [command|seal|both]')
        c.sure('the keys of the agent of %s are changed now (%s)' % (row['name'], body['what']))
        got = c.api('POST', '/api/agents/guard/rotate', body=body)
        return c.done('changed: %s' % ', '.join(k for k in (got.get('rotated') or {})), got)
    if what == 'served':
        got = c.api('POST', '/api/agents/guard/served', body=body)
        sv = got['guard'].get('served') or {}
        if _json(c, got):
            return 0
        rows = sv.get('rows') or sv.get('items') or []
        old = 0
        for r in rows:
            old += r.get('state') == 'old'
            print('  %-24s %s' % (r.get('cert') or r.get('name') or r.get('id'),
                                  r.get('state') or ''))
        if not rows:
            print('asked: %s' % json.dumps(sv, ensure_ascii=False, default=str)[:600])
        return 1 if old else 0
    return None


def _watch_print(c, g):
    o = g.get('opts') or {}
    a = g.get('audit') or {}
    an = g.get('anomaly') or {}
    k = g.get('keys') or {}
    print('watching the agent of %s%s' % (g.get('name'), '' if g.get('joined') else
                                         ' (not joined yet)'))
    c.kv([('audit chain', 'off' if not o.get('audit') else '%s - %s entries, %s checked%s' % (
        a.get('state'), a.get('n') or 0, a.get('verified_n') or 0,
        (', %d not agreeing' % a['problems']) if a.get('problems') else '')),
          ('anomalies', 'off' if not an.get('on') else ('%d: %s' % (
              len(an.get('items') or []), '; '.join(i.get('words') or i.get('kind')
                                                    for i in an['items'])) if an.get('items')
              else 'none')),
          ('what it serves', o.get('health')),
          ('keys changed', ('every %s days' % o.get('rotate_days')) if o.get('rotate')
           else 'by hand'),
          ('command key', ('%s days old%s' % (k.get('cmd_age'), '' if k.get('cmd_current')
                                              else ' (not the current one)')) if k else '-'),
          ('secrets key', ('%s days old' % k.get('enc_age')) if k else '-'),
          ('due', ', '.join(k.get('due') or []) if k else '')], 16)
    return 0


# ---- the console ---------------------------------------------------------------------------
def console_menu(con):
    """History and trash, request profiles, the agent fleet (main menu h)."""
    return con.sub('History, trash, request profiles, agent fleet', [
        ('1', 'The latest changes (Enter: that version again)', lambda: _con_history(con)),
        ('2', 'The trash (Enter: bring it back, delete it for good)', lambda: _con_trash(con)),
        ('3', 'Request profiles (Enter: show, versions, compare, restore, dry run, end, delete)',
         lambda: _con_profiles(con)),
        ('4', 'Request profiles: the compliance check', lambda: con.act('--profile-compliance')),
        ('5', 'The agent fleet: every agent, the groups, the rollout', lambda: con.act('--fleet')),
        ('6', 'Certificates found on the servers that acme does not manage (Enter: take over)',
         lambda: _con_unmanaged(con)),
        ('7', 'Drift of the agents from their templates', lambda: con.act('--fleet-drift')),
        ('8', 'An update of the agents in rings', lambda: _con_rollout(con)),
        ('9', 'The keys of the agents and acme\'s command key',
         lambda: con.act('--target-agent', 'all', 'keys')),
        # 1.0.141: the group cards of Settings → Agent fleet (acme --fleet-group-save/-del)
        ('g', 'Groups of agents (Enter: change, delete; + add one)', lambda: _con_groups(con)),
    ])


def _con_history(con):
    def load():
        return con._rows(con.out('--history', '--limit', '200'), 'entries')
    cols = [('when', lambda r: _when(r.get('ts')), 16, lambda r: 'dim'),
            ('what', lambda r: r.get('type'), 10, None),
            ('name', lambda r: r.get('name'), 28, None),
            ('done', lambda r: r.get('action'), 8, None),
            ('by', lambda r: r.get('who'), 20, lambda r: 'dim'),
            ('fields', lambda r: ', '.join(r.get('fields') or []), 40, lambda r: 'dim')]

    def do(r):
        what = con.choose('%s %s' % (r.get('type'), r.get('name')), [
            ('show', 'Its whole history'), ('restore', 'This version again')])
        if what == 'show':
            con.act('--history', r.get('type'), r.get('name'))
        elif what == 'restore' and con.confirm('Restore', 'Save %s %s again as it was after this '
                                               'change?' % (r.get('type'), r.get('name')),
                                               'Restore'):
            con.act('--history-restore', str(r['id']), '--yes')
    return con.pick('The latest changes', load, cols, do, 'nothing changed yet')


def _con_trash(con):
    def load():
        return con._rows(con.out('--trash'), 'items')
    cols = [('deleted', lambda r: _when(r.get('ts')), 16, lambda r: 'dim'),
            ('what', lambda r: r.get('words'), 12, None),
            ('name', lambda r: r.get('name'), 30, None),
            ('by', lambda r: r.get('who'), 20, lambda r: 'dim'),
            ('with it', lambda r: ', '.join(k['name'] for k in r.get('children') or []), 40,
             lambda r: 'dim')]

    def do(r):
        what = con.choose('%s %s' % (r.get('words'), r.get('name')), [
            ('restore', 'Bring it back'), ('restore-as', 'Bring it back under another name'),
            ('purge', 'Delete it for good')])
        if what == 'restore':
            con.act('--trash-restore', str(r['id']))
        elif what == 'restore-as':
            name = con.ask_one('Bring it back', 'its name', r.get('name') or '')
            if name:
                con.act('--trash-restore', str(r['id']), '--name', name)
        elif what == 'purge' and con.confirm('Delete for good', '%s %s is gone for good?' % (
                r.get('words'), r.get('name')), 'Delete it', danger=True):
            con.act('--trash-purge', str(r['id']), '--yes')
    return con.pick('The trash', load, cols, do, 'the trash is empty')


def _con_profiles(con):
    def load():
        return con._rows(con.out('--profiles'), 'profiles')
    cols = [('profile', lambda r: r['name'], 26, None),
            ('source', lambda r: r.get('issuer') or '-', 18, None),
            ('version', lambda r: r.get('version') or 1, 7, None),
            ('based on', lambda r: r.get('base') or '', 16, lambda r: 'dim'),
            ('ends', lambda r: ('→ ' + (r.get('ends') or {}).get('successor', '')) if r.get('ends')
             else '', 16, lambda r: 'warn'),
            ('certs', lambda r: r.get('used', 0), 5, None)]

    def do(r):
        name = r['name']
        what = con.choose(name, [
            ('show', 'Show it'), ('versions', 'Its versions'),
            ('diff', 'Compare a version with now'), ('restore', 'Restore a version'),
            ('dry', 'Dry run: what it would issue for some names'),
            ('end', 'End it, with a successor') if not r.get('ends') else
            ('unend', 'It no longer ends'), ('del', 'Delete it')])
        if what == 'show':
            con.act('--profile-show', name)
        elif what == 'versions':
            con.act('--profile-versions', name)
        elif what in ('diff', 'restore'):
            n = con.ask_one(name, 'version', '', 'Its number (Its versions).', check=lambda v, _:
                            None if str(v).strip().isdigit() else 'a number')
            if n:
                if what == 'diff':
                    con.act('--profile-diff', name, n.strip())
                elif con.confirm('Restore', '%s becomes as version %s said?' % (name, n),
                                 'Restore'):
                    con.act('--profile-restore', name, n.strip(), '--yes')
        elif what == 'dry':
            names = con.ask_one('Dry run of %s' % name, 'names', '', 'The names, with commas: '
                                'www.example.com,example.com - nothing is issued.')
            if names:
                con.act('--profile-dry-run', name, '--names', names)
        elif what == 'end':
            succ = con.ask_one('End %s' % name, 'its successor', '', 'The request profile its '
                               'certificates take at their next renewal.')
            if succ and con.confirm('End it', '%s ends, %s its successor?' % (name, succ),
                                    'End it'):
                con.act('--profile-end', name, succ, '--yes')
        elif what == 'unend':
            con.act('--profile-end', name, '-')
        elif what == 'del' and con.confirm('Delete', 'Delete the request profile %s (to the '
                                           'trash)?' % name, 'Delete it', danger=True):
            con.act('--profile-del', name, '--yes')
    return con.pick('Request profiles', load, cols, do, 'no request profile yet')


def _con_unmanaged(con):
    def load():
        return con._rows(con.out('--fleet-unmanaged'), 'rows')
    cols = [('target', lambda r: r['target'], 18, None),
            ('where', lambda r: r.get('where') or '', 26, None),
            ('names', lambda r: ', '.join(r.get('names') or []), 30, None),
            ('days', lambda r: '-' if r.get('days') is None else r['days'], 5, None),
            ('risk', lambda r: r.get('risk'), 10, lambda r: 'bad' if r.get('risk_n', 0) >= 3
             else 'warn')]

    def do(r):
        if not r.get('can_take') or not r.get('service'):
            con.note('Take over', 'acme cannot make a deployment of that by itself - make it by '
                     'hand.', 'warn')
            return
        if con.confirm('Take over', 'Make the certificate of %s and its deployment there?' %
                       ', '.join(r.get('names') or [])[:200], 'Take it over'):
            con.act('--fleet-takeover', r['target'], r['service'], '--yes')
    return con.pick('Not managed', load, cols, do, 'every certificate found is managed')


def _con_groups(con):
    """The groups of agents: members, the template they follow, the canary ring."""
    def load():
        got = con.out('--fleet') or {}
        if not isinstance(got, dict):
            return []
        names = {a.get('id'): a.get('name') for a in got.get('agents') or []}
        return [{'name': '+ a new group', '_new': True}] + [
            dict(g, _names=[str(names.get(m, m)) for m in g.get('members') or []])
            for g in got.get('groups') or []]
    cols = [('group', lambda r: r['name'], 22, lambda r: 'ok' if r.get('_new') else None),
            ('agents', lambda r: '' if r.get('_new') else ', '.join(r.get('_names') or []) or
             '-', 36, None),
            ('template', lambda r: r.get('template_title') or r.get('template') or '', 22,
             lambda r: 'dim'),
            ('canary', lambda r: 'yes' if r.get('canary') else '', 6, lambda r: 'warn')]

    def do(r):
        if r.get('_new'):
            return _con_group_form(con, None)
        what = con.choose('The group %s' % r['name'], [
            ('edit', 'Change it: its agents, its template, the canary ring'),
            ('plan', 'An update in rings with it as the canary: who first, who after'),
            ('del', 'Delete it (its agents stay as they are)')])
        if what == 'edit':
            _con_group_form(con, r)
        elif what == 'plan':
            con.act('--fleet-rollout', 'plan', r['name'])
        elif what == 'del' and con.confirm('Delete the group', 'Delete the group %s? Its agents '
                                           'and their policies stay as they are.' % r['name'],
                                           'Delete it', danger=True):
            con.act('--fleet-group-del', r['name'])
    return con.pick('Groups of agents', load, cols, do, 'no group yet')


def _con_group_form(con, g):
    got = con.out('--fleet') or {}
    agents = [a.get('name') for a in (got.get('agents') if isinstance(got, dict) else None) or []]
    tpl = con.out('--fleet-templates') or {}
    tpls = [(t['ref'], t.get('title') or t['ref']) for t in (
        tpl.get('templates') if isinstance(tpl, dict) else None) or [] if t.get('ref')]
    cur = (g or {}).get('template') or ''
    opts = [('-', 'none: each agent its own policy')] + tpls
    if cur and cur not in [o[0] for o in opts]:
        opts.append((cur, cur))

    def check_members(v, _vals):
        bad = [x for x in re.split(r'[\s,]+', v or '') if x and x not in agents]
        return ('%s has no acme-agent (the agents: %s)' % (bad[0], ', '.join(agents) or 'none')
                if bad else None)
    fields = ([] if g else [{'key': 'name', 'label': 'its name', 'need': True, 'value': ''}]) + [
        {'key': 'members', 'label': 'its agents', 'value': ', '.join((g or {}).get('_names')
                                                                      or []),
         'need': False, 'check': check_members,
         'help': 'The targets with acme-agent, with commas: %s.' % (', '.join(agents[:12]) or
                                                                     'there is none yet')},
        {'key': 'template', 'label': 'its template', 'kind': 'choice', 'value': cur or '-',
         'options': opts, 'help': 'The policy template its agents follow (drift is measured '
                                  'against it).'},
        {'key': 'canary', 'label': 'the canary ring', 'kind': 'choice',
         'value': 'yes' if (g or {}).get('canary') else 'no',
         'options': [('no', 'no'), ('yes', 'yes - updated first in an update in rings')]}]
    got = con.form('The group %s' % g['name'] if g else 'A new group of agents', fields)
    if not got:
        return
    name = g['name'] if g else (got.get('name') or '').strip()
    if not name:
        return
    members = ','.join(x for x in re.split(r'[\s,]+', got.get('members') or '') if x) or '-'
    con.act('--fleet-group-save', name, '--fleet-members', members, '--fleet-template',
            got.get('template') or '-', '--fleet-canary', got.get('canary') or 'no')


def _con_rollout(con):
    what = con.choose('An update in rings', [
        ('plan', 'Who would be updated first, who after'),
        ('start', 'Start it (the canary ring first - its group, or 5 % - then the rest '
                  'after 60 minutes)'),
        ('continue', 'Go on with the rest now'), ('stop', 'Stop it'),
        ('forget', 'Forget the rollout that ended')])
    if what == 'start':
        if con.confirm('Update in rings', 'Update the agents in rings now?', 'Start'):
            con.act('--fleet-rollout', 'start', '--yes')
    elif what:
        con.act('--fleet-rollout', what)


def team_items(con, name):
    """The governance lines of a team's own menu (console.py teams)."""
    return [('health', 'Its health'),
            ('gov', 'Its governance (reviews, temporary roles, SoD)'),
            ('gov-set', 'Change its governance: access reviews, temporary roles, separation '
                        'of duties, channels'),
            ('reviews', 'Its access reviews (open one)'),
            ('elevations', 'Requests for a temporary role'),
            ('notify-test', 'Try its channels now'),
            # v5: the team templates' list pointed here ("save it as a template") - it was not
            ('template-save', 'Save it as a team template')]


def team_do(con, name, what):
    if what == 'health':
        con.act('--team-health', name)
    elif what == 'gov':
        con.act('--team-gov', name)
    elif what == 'gov-set':
        _con_gov(con, name)
    elif what == 'reviews':
        sub = con.choose('Access reviews of %s' % name, [
            ('show', 'Its reviews'), ('open', 'Open one now'),
            ('answer', 'Confirm or take out a member of the open one')])
        if sub == 'show':
            con.act('--reviews', name)
        elif sub == 'open':
            con.act('--review-open', name)
        elif sub == 'answer':
            got = con.form('An answer of the review', [
                {'key': 'id', 'label': 'review', 'need': True, 'help': 'Its number (Its reviews).'},
                {'key': 'who', 'label': 'member', 'need': True},
                {'key': 'keep', 'label': 'answer', 'kind': 'choice',
                 'options': [('keep', 'confirmed'), ('out', 'taken out')]},
                {'key': 'note', 'label': 'note', 'need': False}])
            if got:
                con.act('--review-answer', got['id'], got['who'], got['keep'], '--note',
                        got.get('note') or '')
    elif what == 'elevations':
        # Enter on one ends it (a request taken back, a role given ended early) - as the team's
        # page does; the console only listed them (hunt v4)
        def load():
            got = con.out('--elevations', name) or {}
            return got.get('rows') or [] if isinstance(got, dict) else []
        cols = [('id', lambda r: r.get('id'), 5, None),
                ('who', lambda r: r.get('asked_by') or r.get('who'), 22, None),
                ('role', lambda r: r.get('role'), 16, None),
                ('state', lambda r: r.get('state'), 9, None),
                ('until', lambda r: _when(r.get('until')) if r.get('until') else '', 16,
                 lambda r: 'dim'),
                ('why', lambda r: r.get('reason') or '', 30, lambda r: 'dim')]

        def end(r):
            if r.get('state') not in ('waiting', 'granted'):
                return
            if con.confirm('End it', 'The %s %s of %s on %s ends now?' % (
                    'request for' if r.get('state') == 'waiting' else 'temporary role',
                    r.get('role'), r.get('asked_by') or r.get('who'), name), 'End it',
                    danger=True):
                con.act('--elevation-end', str(r['id']))
        con.pick('Temporary roles in %s (Enter: end it)' % name, load, cols, end,
                 'no request for a temporary role')
    elif what == 'notify-test':
        con.act('--team-notify-test', name)
    elif what == 'template-save':
        tpl = con.ask_one('Save %s as a team template' % name, 'the template\'s name', name,
                          'Its kind, limits and governance are kept; the same name again '
                          'changes that template.')
        if tpl and tpl.strip():
            con.act('--team-template-save', name, tpl.strip())
    else:
        return False
    return True


def _gov_words(v):
    if isinstance(v, (list, tuple)):
        return ', '.join(str(x) for x in v)
    return '' if v is None else str(v)


def _con_gov(con, name):
    """A team's governance: shown, and each part set in a form of its own (acme --team-gov-set
    TEAM JSON - the console writes the JSON)."""
    what = con.choose('Change the governance of %s' % name, [
        ('review', 'Access reviews: how often, the days to answer, what happens then'),
        ('jit', 'Temporary roles: which may be asked for, for how long'),
        ('sod', 'Separation of duties: no self-approval, pairs no one may hold both of'),
        ('notify', 'Channels: who is told, when, and where a failed deployment goes')])
    if not what:
        return
    got = con.out('--team-gov', name) or {}
    gov = (got.get('gov') if isinstance(got, dict) else None) or {}
    cur = gov.get(what) or {}
    on = [('on', 'on'), ('off', 'off - none of its own')]

    def is_on(vals):
        return vals.get('on') == 'on'
    if what == 'review':
        fields = [
            {'key': 'on', 'label': 'access reviews', 'kind': 'choice', 'options': on,
             'value': 'on' if cur else 'off'},
            {'key': 'every_days', 'label': 'every (days)', 'kind': 'number', 'need': True,
             'range': (7, 3650),
             'value': str(cur.get('every_days') or 90), 'when': is_on},
            {'key': 'answer_days', 'label': 'days to answer', 'kind': 'number', 'need': True,
             'range': (1, 365),
             'value': str(cur.get('answer_days') or 14), 'when': is_on,
             'check': lambda v, vals: None if not is_on(vals) or not str(v).isdigit() or
             not str(vals.get('every_days') or '').isdigit() or int(v) <= int(
                 vals['every_days']) else 'at most the days between reviews'},
            {'key': 'action', 'label': 'not answered in time', 'kind': 'choice',
             'value': cur.get('action') or 'report', 'when': is_on,
             'options': [('report', 'reported'), ('expire', 'the member taken out')]}]
    elif what == 'jit':
        fields = [
            {'key': 'on', 'label': 'temporary roles', 'kind': 'choice', 'options': on,
             'value': 'on' if cur else 'off'},
            {'key': 'roles', 'label': 'roles that may be asked for', 'when': is_on,
             'value': _gov_words(cur.get('roles')),
             'check': lambda v, vals: None if not is_on(vals) or str(v).strip() else
             'say which roles (acme --roles)', 'help': 'Their names, with commas: Requester, '
                                                     'Deployer.'},
            {'key': 'max_hours', 'label': 'for at most (hours)', 'kind': 'number',
             'need': True, 'range': (1, 720), 'value': str(cur.get('max_hours') or 8), 'when': is_on}]
    elif what == 'sod':
        fields = [
            {'key': 'no_self_approval', 'label': 'no self-approval', 'kind': 'choice',
             'value': 'yes' if cur.get('no_self_approval') else 'no',
             'options': [('no', 'no'), ('yes', 'yes - nobody approves their own request')]},
            {'key': 'exclusive', 'label': 'pairs no one holds both', 'need': False,
             'value': '; '.join('%s + %s' % (p[0], p[1]) for p in cur.get('exclusive') or []
                                if isinstance(p, (list, tuple)) and len(p) == 2),
             'help': 'Roles or capabilities, a pair with + and pairs with ; - Requester + '
                     'Approver; cert.key + cert.revoke.'}]
    else:
        fields = [
            {'key': 'on', 'label': 'channels of its own', 'kind': 'choice', 'options': on,
             'value': 'on' if cur else 'off'},
            {'key': 'mail', 'label': 'the team (mail)', 'need': False, 'when': is_on,
             'value': _gov_words(cur.get('mail'))},
            {'key': 'manager_mail', 'label': 'its manager (mail)', 'need': False,
             'when': is_on, 'value': _gov_words(cur.get('manager_mail'))},
            {'key': 'oncall_mail', 'label': 'on call (mail)', 'need': False, 'when': is_on,
             'value': _gov_words(cur.get('oncall_mail'))},
            {'key': 'expiry_days', 'label': 'told days before the end', 'kind': 'number',
             'need': True, 'range': (0, 365), 'value': str(cur.get('expiry_days', 14)), 'when': is_on},
            {'key': 'manager_days', 'label': 'the manager, days before', 'kind': 'number',
             'need': True, 'range': (0, 365), 'value': str(cur.get('manager_days', 3)), 'when': is_on},
            {'key': 'deploy_failed', 'label': 'a failed deployment goes to', 'kind': 'choice',
             'value': cur.get('deploy_failed', 'oncall') or '-', 'when': is_on,
             'options': [('oncall', 'on call'), ('manager', 'the manager'), ('team', 'the team'),
                         ('-', 'nobody')]},
            {'key': 'elevations', 'label': 'requests for a temporary role', 'kind': 'choice',
             'value': 'no' if cur and not cur.get('elevations', True) else 'yes',
             'when': is_on, 'options': [('yes', 'told'), ('no', 'not told')]},
            {'key': 'reviews', 'label': 'access reviews', 'kind': 'choice',
             'value': 'no' if cur and not cur.get('reviews', True) else 'yes', 'when': is_on,
             'options': [('yes', 'told'), ('no', 'not told')]}]
    vals = con.form('The governance of %s' % name, fields,
                    'The webhooks of the team stay sealed: acme --api POST /api/teams/hooks - '
                    'with the body on stdin.' if what == 'notify' else '')
    if not vals:
        return
    if what == 'sod':
        pairs = [x.strip() for x in str(vals.get('exclusive') or '').split(';') if x.strip()]
        part = {'no_self_approval': vals.get('no_self_approval') == 'yes', 'exclusive': pairs}
        if not part['no_self_approval'] and not pairs:
            part = None
    elif vals.get('on') != 'on':
        part = None
    elif what == 'review':
        part = {'every_days': int(vals['every_days']), 'answer_days': int(vals['answer_days']),
                'action': vals['action']}
    elif what == 'jit':
        part = {'roles': [x.strip() for x in str(vals['roles']).split(',') if x.strip()],
                'max_hours': int(vals['max_hours'])}
    else:
        part = {k: vals.get(k) or '' for k in ('mail', 'manager_mail', 'oncall_mail')}
        part.update(expiry_days=int(vals['expiry_days']), manager_days=int(vals['manager_days']),
                    deploy_failed='' if vals.get('deploy_failed') == '-'
                    else vals.get('deploy_failed'),
                    elevations=vals.get('elevations') != 'no',
                    reviews=vals.get('reviews') != 'no')
    con.act('--team-gov-set', name, json.dumps({what: part}, ensure_ascii=False))


def gov_menu_items(con):
    """Lines of the Owners and teams menu (o)."""
    def decide():
        def load():
            got = con.out('--elevations') or {}
            return got.get('to_decide') or [] if isinstance(got, dict) else []
        cols = [('team', lambda r: r.get('team'), 18, None), ('who', lambda r: r.get('who'), 22,
                                                             None),
                ('role', lambda r: r.get('role'), 16, None),
                ('hours', lambda r: r.get('hours'), 5, None),
                ('why', lambda r: r.get('reason') or '', 40, lambda r: 'dim')]

        def do(r):
            what = con.choose('%s asks for %s in %s' % (r.get('who'), r.get('role'),
                                                        r.get('team')),
                              [('yes', 'Approve it'), ('no', 'Decline it')])
            if what:
                why = con.ask_one('Why', 'why', '', 'Said to who asked.', need=what == 'no')
                if what == 'yes':
                    con.act('--elevation-approve', str(r['id']), *(['--why', why] if why else []))
                elif why:
                    con.act('--elevation-decline', str(r['id']), '--why', why)
        return con.pick('Requests for a temporary role', load, cols, do, 'none waits')

    def who_may():
        who = con.ask_one('Who may', 'person or team:NAME', '', 'local:jan, a user, a group - or '
                          'team:Web for the people of a team.')
        if who:
            con.act('--who-may', who.strip())
    def templates():
        # the page's Templates: a team made from one, one deleted (hunt v4: only listed here)
        def load():
            return con._rows(con.out('--team-templates'), 'templates')
        cols = [('template', lambda r: r.get('name'), 24, None),
                ('description', lambda r: r.get('description') or '', 40, lambda r: 'dim'),
                ('kind', lambda r: (r.get('config') or {}).get('kind') or '', 8, None),
                ('members', lambda r: len((r.get('config') or {}).get('members') or []), 7,
                 None)]

        def do(r):
            what = con.choose('The template %s' % r.get('name'), [
                ('make', 'A new team from it'), ('del', 'Delete it')])
            if what == 'make':
                name = con.ask_one('A team from %s' % r.get('name'), 'its name', '')
                if name:
                    con.act('--team-from-template', r.get('name'), name.strip())
            elif what == 'del' and con.confirm('Delete', 'The template %s is deleted? The teams '
                                               'made from it stay.' % r.get('name'), 'Delete it',
                                               danger=True):
                con.act('--team-template-del', r.get('name'), '--yes')
        return con.pick('Team templates', load, cols, do,
                        'no team template yet (a team\'s menu: save it as a template)')
    def who_can():
        # acme --who-can CAP TEAM|cert:NAME (v5: the command line only)
        got = con.form('Who can', [
            {'key': 'cap', 'label': 'the capability', 'need': True, 'value': 'cert.renew',
             'help': 'cert.view, cert.renew, cert.key, cert.revoke ... (acme --roles).'},
            {'key': 'where', 'label': 'where', 'need': True,
             'help': 'A team, or cert:NAME for one certificate.'}])
        if got and got.get('cap', '').strip() and got.get('where', '').strip():
            con.act('--who-can', got['cap'].strip(), got['where'].strip())

    def import_csv():
        # acme --teams-import-csv FILE (v5: the command line only): each row said first
        path = con.ask_one('Teams from a CSV file', 'the file', '/root/teams.csv',
                           'Columns name, parent, kind, description, members ... - each row '
                           'is said first, nothing is made before Yes.')
        if not path or not path.strip():
            return
        path = path.strip()
        if con.act('--teams-import-csv', path) == 0:      # each row said; nothing new to make
            return
        pre = con.out('--teams-import-csv', path)          # errors in the file: JSON, nothing made
        if isinstance(pre, dict) and pre.get('errors'):
            return
        err = getattr(con, 'out_err', None)                 # not there, not readable: said
        if err is not None and 'again with --yes' not in err:
            return
        if con.confirm('Teams from a CSV file', 'Make the teams of %s that are not there yet?'
                       % path, 'Make them'):
            con.act('--teams-import-csv', path, '--yes')
    return [('7', 'The teams\' health', lambda: con.act('--team-health')),
            ('8', 'Requests for a temporary role to decide', decide),
            ('9', 'Access reviews open now', lambda: con.act('--reviews')),
            ('w', 'Who may do what, and why', who_may),
            ('m', 'Team templates (Enter: a team from it, delete it)', templates),
            ('n', 'Who can do one thing in a team or on a certificate, and why', who_can),
            ('i', 'Teams from a CSV file (each row said first)', import_csv)]
