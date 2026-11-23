# -*- coding: utf-8 -*-
"""
The governance of teams (1.0.138, docs/teams.md "Governance"): what an organisation of
thousands needs around the teams' memberships - every part off and empty by default; a team
that uses none of it works exactly as before.

    extras_of(t) / set_extras(store, team, key, value, by)  a team's settings (cert_teams.extras)
    Just-in-time elevation (T3)
        jit_rule(store, team)                       the rule in force (own, else the nearest
                                                    team above that has one)
        elevation_ask / elevation_decide / elevation_end   asked, approved or declined, ended
        active_grants(store)                        the roles given for now (teams.person_caps
                                                    folds them in, until their `until`)
    Access reviews (T4)
        review_open / review_answer / reviews(store, team)    a review, each member confirmed
                                                    or taken out; tick() opens and closes them
    Separation of duties (T5)
        sod_rules(store, team) / sod_conflicts(store, team, caps)   mutually exclusive roles
        no_self_approval(store, team)               the requester never approves their own
    Templates and bulk import (T6)
        templates / save_template / delete_template / team_from_template / import_csv
    Notification channels and escalation (T7)
        notify_rule(store, team) / set_hooks / hooks_public / tell(store, team, ...)
    Health (T8)
        health(store) / health_detail(store, team)

tick(store) - called by the renewer's scan on the node that leads (never twice in a cluster):
elevations ended by themselves, reviews opened and closed, the escalation chain.
Every change is an event (kind certificates) naming the team, so the team's Activity shows it.
"""
from __future__ import annotations

import csv
import io
import json
import re
import threading
import time
import urllib.parse
import urllib.request

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import teams as T

EXTRA_KEYS = ('review', 'jit', 'sod', 'notify')
HOOK_KINDS = ('teams', 'slack')
REVIEW_ACTIONS = ('report', 'expire')
ESCALATE_TO = ('oncall', 'manager', 'team', '')
JIT_WAIT_S = 7 * 86400          # a request nobody answered ends after a week
TICK_EVERY_S = 240
_TICK = {'at': 0.0}
_HEALTH = {}


def _low(v):
    return str(v or '').strip().lower()


def _now():
    return time.time()


def _who_by(by):
    return str(by or '?')[:190]


# ---------------------------------------------------------------------------
# A team's extras
# ---------------------------------------------------------------------------
def extras_of(t):
    got = S.jload((t or {}).get('extras'), {}) if t else {}
    return got if isinstance(got, dict) else {}


def _team_row(store, team):
    t = T.team_get(store, team)
    if not t:
        raise LookupError('there is no team %s' % str(team)[:120])
    return t


def set_extras(store, team, key, value, by):
    """One part of a team's extras saved (None or {} takes it away) - an event says what."""
    if key not in EXTRA_KEYS:
        raise ValueError('a part of the governance is one of %s' % ', '.join(EXTRA_KEYS))
    t = _team_row(store, team)
    ex = extras_of(t)
    clean = {'review': clean_review, 'jit': clean_jit, 'sod': lambda v: clean_sod(store, v),
             'notify': clean_notify}[key](value)
    before = ex.get(key)
    if clean:
        if key == 'notify' and not (before or {}).get('since'):
            clean['since'] = _now()
        elif key == 'notify':
            clean['since'] = before.get('since')
        ex[key] = clean
    else:
        ex.pop(key, None)
    store.db.update('cert_teams', t['id'], {'extras': json.dumps(ex, sort_keys=True) if ex else None,
                                            'updated': _now(), 'updated_by': _who_by(by)})
    T.changed()
    words = {'review': 'access reviews', 'jit': 'just-in-time elevation',
             'sod': 'separation of duties', 'notify': 'notification channels'}[key]
    store.add_event('certificates', 'the team %s: %s %s by %s%s' % (
        t['name'], words, 'set' if clean else 'switched off', by,
        (': ' + json.dumps({k: v for k, v in clean.items() if k != 'since'}, sort_keys=True)[:400])
        if clean else ''), who=_who_by(by))
    return clean


def _chain_rows(store, team):
    tr = T.tree(store)
    return [tr.rows[k] for k in reversed(tr.chain(team))]       # the team first, then up


def _nearest(store, team, key):
    """(the team's name, its part `key`) - its own, else the nearest team above that has it."""
    for t in _chain_rows(store, team):
        got = extras_of(t).get(key)
        if got:
            return t['name'], got
    return None, None


def public_extras(t):
    """What the pages show of a team's governance - never a webhook's address."""
    ex = extras_of(t)
    out = {k: ex[k] for k in EXTRA_KEYS if ex.get(k)}
    hooks = _hooks_of(t)
    out['hooks'] = {k: bool(hooks.get(k)) for k in HOOK_KINDS}
    return out


# ---------------------------------------------------------------------------
# Checks of the settings
# ---------------------------------------------------------------------------
def _int(v, what, lo, hi, default=None):
    if v in (None, ''):
        return default
    if isinstance(v, bool):
        raise ValueError('%s is a number' % what)
    try:
        n = int(float(v))
    except (TypeError, ValueError, OverflowError):
        raise ValueError('%s is a number' % what)
    if n < lo or n > hi:
        raise ValueError('%s is from %d to %d' % (what, lo, hi))
    return n


def _flag(v):
    return v in (True, 1, '1', 'true', 'yes', 'on')


def clean_review(v):
    if not v:
        return None
    if not isinstance(v, dict):
        raise ValueError('a review is {every_days, answer_days, action}')
    every = _int(v.get('every_days'), 'every_days', 7, 3650, 90)
    answer = _int(v.get('answer_days'), 'answer_days', 1, 365, 14)
    action = str(v.get('action') or 'report')
    if action not in REVIEW_ACTIONS:
        raise ValueError('what happens to a member not confirmed in time: report or expire')
    if answer > every:
        raise ValueError('the days to answer are at most the days between reviews')
    return {'every_days': every, 'answer_days': answer, 'action': action}


def clean_jit(v):
    if not v:
        return None
    if not isinstance(v, dict):
        raise ValueError('just-in-time elevation is {roles, max_hours}')
    roles = v.get('roles') or []
    if isinstance(roles, str):
        roles = [w.strip() for w in re.split(r'[,;\n]+', roles) if w.strip()]
    if not isinstance(roles, list) or not roles:
        raise ValueError('say which roles may be asked for')
    got = []
    for r in roles[:50]:
        r = str(r).strip()
        if not T.ROLE_NAME_RE.match(r):
            raise ValueError('%s is not a role' % r[:60])
        if _low(r) not in {_low(x) for x in got}:
            got.append(r)
    return {'roles': got, 'max_hours': _int(v.get('max_hours'), 'max_hours', 1, 720, 8)}


def _side(store, side, cat=None):
    """A side of an exclusive pair: a capability, an old right or a role (its name as in the
    catalog) - None when it is none of them."""
    s = str(side or '').strip()
    if not s:
        return None
    if s.lower() in T.CAPS:
        return s.lower()
    if s.lower() in T.RIGHTS:
        return s.lower()
    cat = cat if cat is not None else T.role_catalog(store)
    one = cat.get(s.lower())
    return one['name'] if one else None


def clean_sod(store, v):
    if not v:
        return None
    if not isinstance(v, dict):
        raise ValueError('separation of duties is {no_self_approval, exclusive}')
    cat = T.role_catalog(store)
    pairs = []
    raw = v.get('exclusive') or []
    if isinstance(raw, str):
        raw = [x for x in raw.splitlines() if x.strip()]
    if not isinstance(raw, list):
        raise ValueError('the exclusive pairs are a list')
    for p in raw[:50]:
        if isinstance(p, str):
            p = [x.strip() for x in re.split(r'\s*(?:\+|,|;| and | x )\s*', p) if x.strip()]
        if not isinstance(p, (list, tuple)) or len(p) != 2:
            raise ValueError('an exclusive pair is two roles or capabilities')
        a, b = _side(store, p[0], cat), _side(store, p[1], cat)
        if not a:
            raise ValueError('%s is not a role, an old right or a capability' % str(p[0])[:60])
        if not b:
            raise ValueError('%s is not a role, an old right or a capability' % str(p[1])[:60])
        if _low(a) == _low(b):
            raise ValueError('a pair is of two different roles or capabilities')
        if not any({_low(a), _low(b)} == {_low(x), _low(y)} for x, y in pairs):
            pairs.append([a, b])
    out = {}
    if _flag(v.get('no_self_approval')):
        out['no_self_approval'] = True
    if pairs:
        out['exclusive'] = pairs
    return out or None


def clean_notify(v):
    if not v:
        return None
    if not isinstance(v, dict):
        raise ValueError('the notifications are {mail, manager_mail, oncall_mail, ...}')
    out = {}
    for k in ('mail', 'manager_mail', 'oncall_mail'):
        got = T.clean_mails(v.get(k))
        if got:
            out[k] = got
    out['expiry_days'] = _int(v.get('expiry_days'), 'expiry_days', 0, 365, 14)
    out['manager_days'] = _int(v.get('manager_days'), 'manager_days', 0, 365, 3)
    if out['manager_days'] and out['expiry_days'] and out['manager_days'] > out['expiry_days']:
        raise ValueError('the manager is told later than the team: fewer days before the end')
    dep = str(v.get('deploy_failed') if v.get('deploy_failed') is not None else 'oncall')
    if dep not in ESCALATE_TO:
        raise ValueError('a failed deployment goes to oncall, manager, team or nobody')
    out['deploy_failed'] = dep
    for k in ('elevations', 'reviews'):
        out[k] = _flag(v.get(k, True))
    return out


# ---------------------------------------------------------------------------
# Separation of duties (T5)
# ---------------------------------------------------------------------------
def sod_rules(store, team):
    """{no_self_approval, exclusive: [[a, b, from team]]} in force for a team: its own and those
    of every team above it (a rule above holds below too)."""
    out = {'no_self_approval': False, 'exclusive': []}
    if not team or _low(team) not in T.tree(store).rows:
        return out
    seen = set()
    for t in _chain_rows(store, team):
        sod = extras_of(t).get('sod') or {}
        if sod.get('no_self_approval'):
            out['no_self_approval'] = True
            out.setdefault('self_from', t['name'])
        for a, b in sod.get('exclusive') or []:
            k = frozenset((_low(a), _low(b)))
            if k not in seen:
                seen.add(k)
                out['exclusive'].append([a, b, t['name']])
    return out


def no_self_approval(store, team):
    return bool(team) and sod_rules(store, team)['no_self_approval']


def _side_caps(store, side, cat):
    s = _low(side)
    if s in T.CAPS:
        return frozenset([s])
    if s in T.RIGHTS:
        caps = frozenset(T.RIGHT_CAPS[s]) - {T.LEGACY_MANAGE}
        if s == 'manage':
            caps = caps | {'cert.approve'}
    else:
        one = cat.get(s)
        caps = one['caps'] if one else frozenset()
    distinct = caps - T._R_VIEWER
    return distinct or caps


def _norm(caps):
    caps = frozenset(caps or ())
    if T.LEGACY_MANAGE in caps:
        caps = (caps - {T.LEGACY_MANAGE}) | {'cert.approve'}
    return caps


def sod_conflicts(store, team, caps):
    """[(a, b, from)] of the exclusive pairs whose both sides these capabilities hold."""
    rules = sod_rules(store, team)['exclusive']
    if not rules:
        return []
    cat = T.role_catalog(store)
    have = _norm(caps)
    out = []
    for a, b, src in rules:
        ca, cb = _side_caps(store, a, cat), _side_caps(store, b, cat)
        if ca and cb and ca <= have and cb <= have:
            out.append((a, b, src))
    return out


def sod_words(team, conflicts, who='the person'):
    a, b, src = conflicts[0]
    return ('separation of duties on the team %s: %s may not hold both %s and %s%s' % (
        team, who, a, b, (' (the rule of %s)' % src) if _low(src) != _low(team) else ''))


def check_members(store, team, members, only=None, parent=None):
    """A team's members saved: refused in words where one membership would hold both sides of an
    exclusive pair. `only`: the lower `who`s added or changed (the others are as they were);
    `parent`: the team above a team not made yet (its rules hold for it)."""
    rules_of = team if _low(team) in T.tree(store).rows else parent
    if not rules_of or not sod_rules(store, rules_of)['exclusive']:
        return
    cat = T.role_catalog(store)
    for m in members:
        if only is not None and _low(m.get('who')) not in only:
            continue
        c = T.member_caps(m, cat, now=0)
        bad = sod_conflicts(store, rules_of, c)
        if bad:
            raise ValueError(sod_words(team, bad, m.get('who')))


def approver_conflict(store, team, approver):
    """Words when the approver holds both sides of an exclusive pair on the team - None when
    not (a full administrator never)."""
    if not team or (approver or {}).get('all'):
        return None
    k = _low(team)
    caps = ((approver or {}).get('caps') or {}).get(k, {}).get('caps') or frozenset()
    bad = sod_conflicts(store, team, caps)
    if bad:
        return sod_words(team, bad, approver.get('by') or 'you') + ' - another person approves'
    return None


# ---------------------------------------------------------------------------
# Who is acting (admin pages and portal alike)
# ---------------------------------------------------------------------------
def actor_admin(store, s):
    from acmelib.certs import portal as P
    names, groups = T.admin_principal(s)
    acc = s.get('account') or {}
    who = 'local:%s' % _low(s.get('name')) if acc.get('source') != 'directory' else \
        _low(s.get('name'))
    return {'by': str(s.get('name') or '?'), 'who': who, 'ids': sorted(P.admin_names(s) | names),
            'names': names, 'groups': groups, 'caps': T.person_caps(store, names, groups),
            'all': s.get('role') == 'fulladmin' or bool(s.get('cli'))}


def actor_portal(h, s):
    from acmelib.certs import portal as P
    names, groups = P.my_names(s), P.my_groups(h, s)
    return {'by': P.portal_by(s), 'who': _low(P.owner_word(s)), 'ids': P.asker_ids(s),
            'names': set(names), 'groups': groups,
            'caps': T.person_caps(h.store, names, groups), 'all': bool(E.portal_sees_all(s))}


def _caps_on(actor, team):
    if actor.get('all'):
        return frozenset(T.CAPS)
    return ((actor.get('caps') or {}).get(_low(team)) or {}).get('caps') or frozenset()


def _same(actor, ids, who=''):
    mine = {_low(x) for x in actor.get('ids') or []} | {_low(actor.get('who'))}
    mine |= {_low(x) for x in actor.get('names') or []}
    mine.discard('')
    theirs = {_low(x) for x in ids or []} | {_low(who)}
    theirs.discard('')
    return bool(mine & theirs)


def _is_member_me(actor, who):
    names, gset = T._principal_key(actor.get('names') or (), actor.get('groups') or ())
    return T._matches_fast(who, names, gset)


# ---------------------------------------------------------------------------
# Just-in-time elevation (T3)
# ---------------------------------------------------------------------------
def jit_rule(store, team):
    """(the team whose rule it is, {roles, max_hours}) - (None, None) when none is in force."""
    if not team or _low(team) not in T.tree(store).rows:
        return None, None
    return _nearest(store, team, 'jit')


def _elev_public(r):
    out = {k: r.get(k) for k in ('id', 'team', 'who', 'role', 'hours', 'reason', 'state', 'asked',
                                 'asked_by', 'decided', 'decided_by', 'decided_why', 'until',
                                 'ended', 'ended_by')}
    now = _now()
    if out['state'] == 'granted' and out.get('until') and float(out['until']) <= now:
        out['state'] = 'expired'
    return out


def elevation_rows(store, team=None, state=None, below=True):
    try:
        rows = store.db.rows('SELECT * FROM cert_team_elevations ORDER BY asked DESC LIMIT 2000')
    except Exception:                                   # noqa: BLE001
        return []
    tr = T.tree(store)
    want = None
    if team:
        want = {_low(team)} | (set(tr.descendants(team)) if below else set())
    out = []
    for r in rows:
        if want is not None and _low(r.get('team')) not in want:
            continue
        p = _elev_public(r)
        if state and p['state'] != state:
            continue
        out.append(p)
    return out


def active_grants(store):
    """[{team, who, ids, role, until, id}] of the elevations in force now."""
    try:
        rows = store.db.rows("SELECT id, team, who, ids, role, until, reason FROM "
                             "cert_team_elevations WHERE state = 'granted' AND until > ?",
                             (_now(),))
    except Exception:                                   # noqa: BLE001
        return []
    out = []
    for r in rows:
        ids = S.jload(r.get('ids'), []) or []
        out.append({'id': r['id'], 'team': r.get('team'), 'who': r.get('who'),
                    'ids': [_low(x) for x in ids if x], 'role': r.get('role'),
                    'until': float(r.get('until') or 0), 'reason': r.get('reason') or ''})
    return out


def grant_matches(g, names, gset=None):
    if _low(g.get('who')) in names:
        return True
    return any(x in names for x in g.get('ids') or [])


def elevation_ask(store, actor, team, role, hours, reason):
    tr = T.tree(store)
    k = _low(team)
    if k not in tr.rows:
        raise LookupError('there is no team %s' % str(team)[:120])
    name = tr.rows[k]['name']
    src, rule = jit_rule(store, name)
    if not rule:
        raise E.ApiError(403, 'the team %s does not take requests for a temporary role (just-in-'
                              'time elevation is off)' % name)
    cat = T.role_catalog(store)
    one = cat.get(_low(role))
    if not one or _low(role) not in {_low(x) for x in rule['roles']}:
        raise E.ApiError(403, 'the team %s gives for a while only %s - not %s' % (
            name, ', '.join(rule['roles']), str(role)[:60]))
    hours = _int(hours, 'hours', 1, 720)
    if hours is None:
        raise ValueError('for how many hours?')
    if hours > int(rule.get('max_hours') or 8):
        raise E.ApiError(403, 'the team %s gives a role for %d hours at most' % (
            name, int(rule.get('max_hours') or 8)))
    reason = str(reason or '').strip()
    if len(reason) < 3:
        raise ValueError('say why you need it - the approver reads it')
    have = _caps_on(actor, name)
    if not actor.get('all') and not have:
        raise E.ApiError(403, 'you are not a member of the team %s - ask its manager to add you'
                              % name)
    if _norm(one['caps']) <= _norm(have) and not actor.get('all'):
        raise E.ApiError(409, 'you hold what %s gives on the team %s already' % (one['name'], name))
    for r in elevation_rows(store, name, below=False):
        if r['state'] in ('waiting', 'granted') and _low(r['role']) == _low(one['name']) and \
                _same(actor, [], r.get('who')):
            raise E.ApiError(409, 'you asked for %s on %s already (%s)' % (one['name'], name,
                                                                            r['state']))
    now = _now()
    row = {'team': name, 'who': actor.get('who') or _low(actor.get('by')),
           'ids': json.dumps(sorted({_low(x) for x in (actor.get('ids') or [])} |
                                    {_low(x) for x in (actor.get('names') or [])})[:40]),
           'role': one['name'], 'hours': hours, 'reason': reason[:500], 'state': 'waiting',
           'asked': now, 'asked_by': _who_by(actor.get('by')), 'updated': now}
    eid = store.db.insert('cert_team_elevations', row)
    T.changed()
    store.add_event('certificates', '%s asks for the role %s on the team %s for %d hour(s): %s'
                    % (row['asked_by'], one['name'], name, hours, reason[:200]),
                    who=row['asked_by'])
    tell(store, name, 'elevation_asked', {'who': row['asked_by'], 'role': one['name'],
                                          'hours': hours, 'reason': reason[:300]},
         key='elev-ask:%s' % eid)
    got = store.db.row('SELECT * FROM cert_team_elevations WHERE id = ?', (eid,)) if eid else None
    return _elev_public(got or dict(row, id=eid))


def _elev_get(store, eid):
    try:
        n = int(eid)
    except (TypeError, ValueError):
        raise ValueError('which request? (its number)')
    r = store.db.row('SELECT * FROM cert_team_elevations WHERE id = ?', (n,))
    if not r:
        raise LookupError('there is no such request')
    return r


_ALREADY = {'granted': 'it was granted already', 'declined': 'it was declined already',
            'cancelled': 'it was withdrawn already', 'ended': 'it has ended already',
            'expired': 'it has expired already'}
_REVIEW_ALREADY = {'done': 'the review is done already', 'closed': 'the review was closed already'}
_ITEM_ALREADY = {'kept': '%s was confirmed already', 'removed': '%s was taken out already',
                 'expired': '%s was not confirmed in time already'}


def _already(state):
    """A whole sentence for "it is <state> already" - translated as one (1.0.139)."""
    return _ALREADY.get(state) or 'it is %s already' % state


def may_decide(store, r, actor):
    """(whether this person may approve the request now, why not)."""
    if r.get('state') != 'waiting':
        return False, _already(r.get('state'))
    team = r.get('team')
    if _same(actor, S.jload(r.get('ids'), []), r.get('who')):
        return False, 'you asked for it yourself - someone else approves it'
    if not actor.get('all'):
        have = _caps_on(actor, team)
        if 'team.members' not in have:
            return False, 'approving needs "team.members" on the team %s' % team
        one = T.role_catalog(store).get(_low(r.get('role')))
        if one and not _norm(one['caps']) <= _norm(have):
            return False, 'you give only what you hold on the team %s yourself' % team
    bad = approver_conflict(store, team, actor)
    if bad:
        return False, bad
    return True, ''


def _requester_caps(store, r):
    names = {_low(x) for x in S.jload(r.get('ids'), []) or []} | {_low(r.get('who'))}
    names.discard('')
    got = T.person_caps(store, names, [])
    return ((got.get(_low(r.get('team'))) or {}).get('caps')) or frozenset()


def elevation_decide(store, eid, actor, ok, why=''):
    r = _elev_get(store, eid)
    may, words = may_decide(store, r, actor)
    if not may:
        store.add_event('certificates', '%s was refused: deciding the request of %s for %s on the '
                        'team %s (%s)' % (actor.get('by'), r.get('asked_by'), r.get('role'),
                                          r.get('team'), words), 'warn', who=_who_by(actor.get('by')))
        raise E.ApiError(409 if words.endswith(' already') else 403, words)
    why = str(why or '').strip()[:500]
    now = _now()
    team = r['team']
    if ok:
        one = T.role_catalog(store).get(_low(r.get('role')))
        if not one:
            raise E.ApiError(409, 'the role %s is not in the catalog any more' % r.get('role'))
        bad = sod_conflicts(store, team, _requester_caps(store, r) | one['caps'])
        if bad:
            raise E.ApiError(403, sod_words(team, bad, r.get('asked_by')))
        until = now + float(r.get('hours') or 1) * 3600
        ch = {'state': 'granted', 'decided': now, 'decided_by': _who_by(actor.get('by')),
              'decided_why': why, 'until': until, 'updated': now}
    else:
        if not why:
            raise ValueError('say why it is declined - the person who asked reads it')
        ch = {'state': 'declined', 'decided': now, 'decided_by': _who_by(actor.get('by')),
              'decided_why': why, 'updated': now}
    n = store.db.run("UPDATE cert_team_elevations SET state = ?, decided = ?, decided_by = ?, "
                     "decided_why = ?, until = ?, updated = ? WHERE id = ? AND state = 'waiting'",
                     (ch['state'], ch['decided'], ch['decided_by'], ch['decided_why'],
                      ch.get('until'), ch['updated'], r['id']))
    if not n:
        raise E.ApiError(409, 'it was decided meanwhile')
    T.changed()
    if ok:
        store.add_event('certificates', '%s gave %s the role %s on the team %s until %s (%s h, '
                        'asked: %s)%s' % (actor.get('by'), r.get('asked_by'), r.get('role'), team,
                                          time.strftime('%Y-%m-%d %H:%M', time.localtime(
                                              ch['until'])), r.get('hours'),
                                          (r.get('reason') or '')[:120],
                                          (' - ' + why) if why else ''), 'warn',
                        who=_who_by(actor.get('by')))
    else:
        store.add_event('certificates', '%s declined the request of %s for the role %s on the '
                        'team %s: %s' % (actor.get('by'), r.get('asked_by'), r.get('role'), team,
                                         why), who=_who_by(actor.get('by')))
    tell(store, team, 'elevation_granted' if ok else 'elevation_declined',
         {'who': r.get('asked_by'), 'role': r.get('role'), 'hours': r.get('hours'),
          'by': actor.get('by'), 'why': why,
          'until': time.strftime('%Y-%m-%d %H:%M', time.localtime(ch['until'])) if ok else ''},
         key='elev-%s:%s' % ('ok' if ok else 'no', r['id']))
    return _elev_public(store.db.row('SELECT * FROM cert_team_elevations WHERE id = ?', (r['id'],)))


def elevation_end(store, eid, actor):
    """A request taken back (waiting), or a role given ended early - by the one who asked, or by
    one who holds team.members on its team."""
    r = _elev_get(store, eid)
    mine = _same(actor, S.jload(r.get('ids'), []), r.get('who'))
    if not mine and not actor.get('all') and 'team.members' not in _caps_on(actor, r.get('team')):
        raise E.ApiError(403, 'only the one who asked, or a manager of the team %s, ends it'
                         % r.get('team'))
    p = _elev_public(r)
    if p['state'] not in ('waiting', 'granted'):
        raise E.ApiError(409, _already(p['state']))
    now = _now()
    state = 'cancelled' if p['state'] == 'waiting' else 'ended'
    # written only over the state as it was read (hunt v4): a request decided, or a role that
    # ran out, meanwhile was overwritten - a declined request became "cancelled", one granted
    # meanwhile became "cancelled" while the role stayed recorded as given
    n = store.db.run('UPDATE cert_team_elevations SET state = ?, ended = ?, ended_by = ?, '
                     'updated = ? WHERE id = ? AND state = ?' + (
                         ' AND (until IS NULL OR until > ?)' if r.get('state') == 'granted'
                         else ''),
                     (state, now, _who_by(actor.get('by')), now, r['id'], r.get('state'))
                     + ((now,) if r.get('state') == 'granted' else ()))
    if not n:
        cur = _elev_public(store.db.row('SELECT * FROM cert_team_elevations WHERE id = ?',
                                        (r['id'],)) or r)
        raise E.ApiError(409, _already(cur['state']) if cur['state'] not in
                         ('waiting', 'granted') else 'it was changed meanwhile - try again')
    T.changed()
    store.add_event('certificates', '%s %s the role %s of %s on the team %s' % (
        actor.get('by'), 'took back the request for' if state == 'cancelled' else 'ended',
        r.get('role'), r.get('asked_by'), r.get('team')), who=_who_by(actor.get('by')))
    return _elev_public(store.db.row('SELECT * FROM cert_team_elevations WHERE id = ?', (r['id'],)))


def elevations_for(store, actor, limit=200):
    """What a person sees: their own requests, and the requests they may decide now."""
    mine, todo = [], []
    try:
        rows = store.db.rows('SELECT * FROM cert_team_elevations ORDER BY asked DESC LIMIT 2000')
    except Exception:                                   # noqa: BLE001
        rows = []
    for r in rows:
        if _low(r.get('team')) not in T.tree(store).rows:
            continue
        ids = S.jload(r.get('ids'), []) or []
        if _same(actor, ids, r.get('who')):
            mine.append(_elev_public(r))
        elif r.get('state') == 'waiting':
            ok, _w = may_decide(store, r, actor)
            if ok:
                todo.append(_elev_public(r))
    return {'mine': mine[:limit], 'to_decide': todo[:limit]}


def _elev_tick(store):
    now = _now()
    try:
        ended = store.db.rows("SELECT * FROM cert_team_elevations WHERE state = 'granted' AND "
                              "until <= ?", (now,))
        stale = store.db.rows("SELECT * FROM cert_team_elevations WHERE state = 'waiting' AND "
                              "asked < ?", (now - JIT_WAIT_S,))
    except Exception:                                   # noqa: BLE001
        return
    for r in ended:
        if store.db.run("UPDATE cert_team_elevations SET state = 'expired', ended = ?, "
                        "ended_by = 'itself', updated = ? WHERE id = ? AND state = 'granted'",
                        (r.get('until') or now, now, r['id'])):
            store.add_event('certificates', 'the temporary role %s of %s on the team %s ended by '
                            'itself' % (r.get('role'), r.get('asked_by'), r.get('team')))
            tell(store, r.get('team'), 'elevation_ended', {'who': r.get('asked_by'),
                                                           'role': r.get('role')},
                 key='elev-end:%s' % r['id'])
    for r in stale:
        if store.db.run("UPDATE cert_team_elevations SET state = 'expired', ended = ?, "
                        "ended_by = 'nobody answered', updated = ? WHERE id = ? AND "
                        "state = 'waiting'", (now, now, r['id'])):
            store.add_event('certificates', 'the request of %s for the role %s on the team %s '
                            'ended: nobody answered it in a week' % (
                                r.get('asked_by'), r.get('role'), r.get('team')))
    if ended or stale:
        T.changed()


# ---------------------------------------------------------------------------
# Access reviews (T4)
# ---------------------------------------------------------------------------
def _review_public(r):
    out = {k: r.get(k) for k in ('id', 'team', 'started', 'started_by', 'due', 'state', 'done',
                                 'done_by', 'action')}
    out['items'] = S.jload(r.get('items'), []) or []
    out['pending'] = len([i for i in out['items'] if i.get('state') == 'pending'])
    if out['state'] == 'open' and out.get('due') and float(out['due']) < _now():
        out['late'] = True
    return out


def reviews(store, team, limit=50):
    try:
        rows = store.db.rows('SELECT * FROM cert_team_reviews WHERE LOWER(TRIM(team)) = ? ORDER BY '
                             'started DESC LIMIT %d' % int(limit), (_low(team),))
    except Exception:                                   # noqa: BLE001
        return []
    return [_review_public(r) for r in rows]


def review_open_rows(store):
    try:
        return [_review_public(r) for r in store.db.rows(
            "SELECT * FROM cert_team_reviews WHERE state IN ('open', 'overdue') ORDER BY due")]
    except Exception:                                   # noqa: BLE001
        return []


def review_open(store, team, by, rule=None):
    t = _team_row(store, team)
    if any(r['state'] in ('open', 'overdue') for r in reviews(store, t['name'], 5)):
        raise E.ApiError(409, 'a review of the team %s is open already' % t['name'])
    rule = rule or extras_of(t).get('review') or {'answer_days': 14, 'action': 'report'}
    now = _now()
    items = []
    for m in S.jload(t.get('members'), []) or []:
        if not isinstance(m, dict) or T.member_expired(m, now):
            continue
        items.append({'who': m.get('who'), 'roles': list(m.get('roles') or []),
                      'rights': list(m.get('rights') or []), 'until': m.get('until'),
                      'state': 'pending'})
    row = {'team': t['name'], 'started': now, 'started_by': _who_by(by),
           'due': now + int(rule.get('answer_days') or 14) * 86400,
           'state': 'open' if items else 'done', 'items': json.dumps(items),
           'action': rule.get('action') or 'report', 'updated': now}
    if not items:
        row.update(done=now, done_by='nothing to review')
    rid = store.db.insert('cert_team_reviews', row)
    store.add_event('certificates', 'an access review of the team %s was opened by %s: %d '
                    'member(s) to confirm by %s' % (t['name'], by, len(items), time.strftime(
                        '%Y-%m-%d', time.localtime(row['due']))), who=_who_by(by))
    if items:
        tell(store, t['name'], 'review_opened', {'count': len(items), 'due': time.strftime(
            '%Y-%m-%d', time.localtime(row['due']))}, key='review-open:%s' % rid)
    return _review_public(store.db.row('SELECT * FROM cert_team_reviews WHERE id = ?', (rid,))
                          or dict(row, id=rid))


def _review_item_back(store, rid, who):
    """An answer given back (its member pending again) - the removal it stood for failed."""
    for _i in range(8):
        r = store.db.row('SELECT items, state FROM cert_team_reviews WHERE id = ?', (rid,))
        if not r:
            return
        items = S.jload(r.get('items'), []) or []
        for i in items:
            if _low(i.get('who')) == _low(who):
                i['state'] = 'pending'
                for k in ('by', 'at', 'note'):
                    i.pop(k, None)
        state = 'open' if r.get('state') == 'done' else r.get('state')
        if store.db.run('UPDATE cert_team_reviews SET items = ?, state = ?, done = NULL, '
                        'done_by = NULL WHERE id = ? AND items = ?',
                        (json.dumps(items), state, rid, r.get('items'))):
            return


def review_answer(store, rid, who, keep, actor, note='', _round=0):
    try:
        r = store.db.row('SELECT * FROM cert_team_reviews WHERE id = ?', (int(rid),))
    except (TypeError, ValueError):
        raise ValueError('which review? (its number)')
    if not r:
        raise LookupError('there is no such review')
    if r.get('state') not in ('open', 'overdue'):
        raise E.ApiError(409, _REVIEW_ALREADY.get(r.get('state'))
                         or 'the review is %s already' % r.get('state'))
    team = r['team']
    if not actor.get('all') and 'team.members' not in _caps_on(actor, team):
        raise E.ApiError(403, 'confirming the members needs "team.members" on the team %s' % team)
    if _is_member_me(actor, who) and not actor.get('all'):
        raise E.ApiError(403, 'you do not confirm your own membership (or that of a group you are '
                              'in) - another manager of the team does')
    items = S.jload(r.get('items'), []) or []
    it = next((i for i in items if _low(i.get('who')) == _low(who)), None)
    if not it:
        raise LookupError('%s is not in this review' % str(who)[:120])
    if it.get('state') != 'pending':
        words = _ITEM_ALREADY.get(it['state'])
        raise E.ApiError(409, words % it['who'] if words else
                         '%s was answered already (%s)' % (it['who'], it['state']))
    if not keep and not actor.get('all'):
        # taken out only by one who holds no less than they do (as removing a member on the
        # portal): a manager of the members does not take out the team's owner
        t = T.team_get(store, team)
        cur = next((m for m in S.jload((t or {}).get('members'), []) or []
                    if isinstance(m, dict) and _low(m.get('who')) == _low(who)), None)
        more = _norm(T.member_caps(cur, T.role_catalog(store), now=0)) - \
            _norm(_caps_on(actor, team)) if cur else frozenset()
        if more:
            raise E.ApiError(403, '%s holds more on the team %s than you do (%s) - another '
                                  'manager of the team takes them out' % (
                                      it['who'], team, ', '.join(sorted(more))))
    now = _now()
    it.update(state='kept' if keep else 'removed', by=_who_by(actor.get('by')), at=now,
              note=str(note or '').strip()[:300])
    pending = [i for i in items if i.get('state') == 'pending']
    ch = {'items': json.dumps(items), 'updated': now}
    if not pending:
        ch.update(state='done', done=now, done_by=_who_by(actor.get('by')))
    # written only over the items as they were read (hunt v3): two managers answering at once
    # each wrote back the list they had read - one answer was lost (a member confirmed became
    # pending again, or one taken out of the team still pending), and the same member could be
    # taken out twice. The other answer is then read again and this one checked against it.
    keys = sorted(ch)
    n = store.db.run('UPDATE cert_team_reviews SET %s WHERE id = ? AND items = ? AND state IN '
                     "('open', 'overdue')" % ', '.join('%s = ?' % k for k in keys),
                     [ch[k] for k in keys] + [r['id'], r.get('items')])
    if not n:
        if _round < 7:
            return review_answer(store, rid, who, keep, actor, note, _round + 1)
        raise E.ApiError(409, 'the review was changed meanwhile - try again')
    if not keep:
        t = T.team_get(store, team)
        if t:
            ms = [m for m in S.jload(t.get('members'), []) or []
                  if isinstance(m, dict) and _low(m.get('who')) != _low(who)]
            try:
                T.save_team(store, {'old_name': t['name'], 'name': t['name'], 'members': ms},
                            '%s (access review)' % actor.get('by'))
            except Exception:
                # not taken out: the answer is given back (pending again), as it was
                _review_item_back(store, r['id'], who)
                raise
    store.add_event('certificates', '%s %s %s in the access review of the team %s%s' % (
        actor.get('by'), 'confirmed' if keep else 'took out', it['who'], team,
        ' - the review is done' if not pending else ''), 'info' if keep else 'warn',
        who=_who_by(actor.get('by')))
    return _review_public(store.db.row('SELECT * FROM cert_team_reviews WHERE id = ?', (r['id'],)))


def _review_tick(store):
    now = _now()
    tr = T.tree(store)
    for k in tr.order:
        t = tr.rows[k]
        rule = extras_of(t).get('review')
        if not rule:
            continue
        lst = reviews(store, t['name'], 3)
        cur = next((x for x in lst if x['state'] in ('open', 'overdue')), None)
        if cur and cur['state'] == 'open' and float(cur.get('due') or 0) < now:
            _review_late(store, t, cur, rule)
            continue
        if cur:
            continue
        last = lst[0] if lst else None
        if not last or float(last.get('started') or 0) + int(rule['every_days']) * 86400 <= now:
            try:
                review_open(store, t['name'], 'the schedule', rule)
            except E.ApiError:
                pass


def _review_late_write(store, cur, ch):
    """The deadline's change written only over the review as it was read (hunt v4): an answer
    given meanwhile (or the review closed, done) was overwritten - a member confirmed just before
    the deadline was expired all the same. False when it changed: the next tick looks again."""
    keys = sorted(ch)
    return bool(store.db.run(
        "UPDATE cert_team_reviews SET %s WHERE id = ? AND items = ? AND state = 'open'"
        % ', '.join('%s = ?' % k for k in keys),
        [ch[k] for k in keys] + [cur['id'], cur.get('_items_raw')]))


def _review_late(store, t, cur, rule):
    now = _now()
    raw = store.db.row('SELECT items, state FROM cert_team_reviews WHERE id = ?', (cur['id'],))
    if not raw or raw.get('state') != 'open':
        return
    cur = dict(cur, items=S.jload(raw.get('items'), []) or [], _items_raw=raw.get('items'))
    pending = [i for i in cur['items'] if i.get('state') == 'pending']
    if (cur.get('action') or rule.get('action')) == 'expire':
        whos = {_low(i['who']) for i in pending}
        for i in pending:
            i.update(state='expired', at=now, by='not confirmed in time')
        if not _review_late_write(store, cur, {
                'items': json.dumps(cur['items']), 'state': 'closed', 'done': now,
                'done_by': 'its deadline', 'updated': now}):
            return
        row = T.team_get(store, t['name'])
        ms = []
        for m in S.jload((row or {}).get('members'), []) or []:
            if isinstance(m, dict) and _low(m.get('who')) in whos and not T.member_expired(m, now):
                m = dict(m, until=now, note=(str(m.get('note') or '') + ' (not confirmed in the '
                                                                      'access review)').strip()[:300])
            ms.append(m)
        if row:
            T.save_team(store, {'old_name': row['name'], 'name': row['name'], 'members': ms},
                        'the access review')
        store.add_event('certificates', 'the access review of the team %s ended unanswered: %d '
                        'membership(s) expired (%s)' % (t['name'], len(pending), ', '.join(
                            i['who'] for i in pending[:20])), 'warn')
    else:
        for i in pending:
            i['late'] = True
        if not _review_late_write(store, cur, {
                'items': json.dumps(cur['items']), 'state': 'overdue', 'updated': now}):
            return
        store.add_event('certificates', 'the access review of the team %s is overdue: %d '
                        'member(s) not confirmed (%s)' % (t['name'], len(pending), ', '.join(
                            i['who'] for i in pending[:20])), 'warn')
    tell(store, t['name'], 'review_late', {'count': len(pending),
                                           'action': cur.get('action') or rule.get('action')},
         key='review-late:%s' % cur['id'], stage='manager')


# ---------------------------------------------------------------------------
# Templates and bulk import (T6)
# ---------------------------------------------------------------------------
TEMPLATE_KEYS = ('kind', 'description', 'members', 'policy', 'contact_mail', 'extras')


def _tpl_rows(store):
    try:
        return store.db.rows('SELECT * FROM cert_team_templates ORDER BY name')
    except Exception:                                   # noqa: BLE001
        return []


def _tpl_public(r):
    cfg = S.jload(r.get('config'), {}) or {}
    return {'id': r['id'], 'name': r['name'], 'description': r.get('description') or '',
            'config': cfg, 'updated': r.get('updated'), 'updated_by': r.get('updated_by')}


def templates(store):
    return [_tpl_public(r) for r in _tpl_rows(store)]


def template_get(store, name):
    r = next((x for x in _tpl_rows(store) if _low(x['name']) == _low(name)), None)
    return _tpl_public(r) if r else None


def _clean_tpl_config(store, cfg):
    if not isinstance(cfg, dict):
        raise ValueError('a template is {kind, description, members, policy, contact_mail, extras}')
    out = {}
    kind = str(cfg.get('kind') or 'team')
    if kind not in T.KINDS:
        raise ValueError('the kind is team, person or unit')
    out['kind'] = kind
    if str(cfg.get('description') or '').strip():
        out['description'] = str(cfg['description']).strip()[:1000]
    cat = T.role_catalog(store)
    ms = []
    for m in cfg.get('members') or []:
        one = T.clean_member(m, cat)
        if _low(one['who']) not in {_low(x['who']) for x in ms}:
            ms.append(one)
    if ms:
        out['members'] = ms[:T.MEMBER_MAX]
    pol = T.clean_policy(cfg.get('policy') or {})
    if pol:
        out['policy'] = pol
    if cfg.get('contact_mail'):
        out['contact_mail'] = T.clean_mails(cfg['contact_mail'])
    ex = {}
    for k, v in (cfg.get('extras') or {}).items():
        if k not in EXTRA_KEYS or not v:
            continue
        got = {'review': clean_review, 'jit': clean_jit, 'sod': lambda x: clean_sod(store, x),
               'notify': clean_notify}[k](v)
        if got:
            got.pop('since', None)
            ex[k] = got
    if ex:
        out['extras'] = ex
    return out


def save_template(store, b, by):
    """{name, old_name?, description, config} or {name, from_team, members?: bool} - a team's
    roles, limits, profiles and notifications copied; never a webhook's address."""
    old = None
    if b.get('old_name'):
        old = next((x for x in _tpl_rows(store) if _low(x['name']) == _low(b['old_name'])), None)
        if not old:
            raise LookupError('there is no template %s' % b['old_name'])
    name = S.clean_name(b.get('name'), 'the template\'s name')
    other = next((x for x in _tpl_rows(store) if _low(x['name']) == _low(name)), None)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is a template called %s already' % other['name'])
    if b.get('from_team'):
        t = _team_row(store, b['from_team'])
        cfg = {'kind': t.get('kind') or 'team', 'description': t.get('description') or '',
               'policy': T.policy_of(t), 'contact_mail': t.get('contact_mail') or '',
               'extras': {k: v for k, v in extras_of(t).items() if k in EXTRA_KEYS}}
        if _flag(b.get('members')):
            cfg['members'] = [m for m in S.jload(t.get('members'), []) or []
                              if isinstance(m, dict) and not T.member_expired(m)]
    else:
        cfg = b.get('config') if 'config' in b else S.jload((old or {}).get('config'), {})
    cfg = _clean_tpl_config(store, cfg or {})
    now = _now()
    row = {'name': name, 'description': str(b.get('description', (old or {}).get('description'))
                                            or '').strip()[:500],
           'config': json.dumps(cfg, sort_keys=True), 'updated': now, 'updated_by': _who_by(by)}
    if old:
        store.db.update('cert_team_templates', old['id'], row)
    else:
        row.update(created=now, created_by=_who_by(by))
        store.db.insert('cert_team_templates', row)
    store.add_event('certificates', 'the team template %s %s by %s%s' % (
        name, 'changed' if old else 'added', by,
        (' (from the team %s)' % b['from_team']) if b.get('from_team') else ''), who=_who_by(by))
    return template_get(store, name)


def delete_template(store, name, by):
    r = next((x for x in _tpl_rows(store) if _low(x['name']) == _low(name)), None)
    if not r:
        raise LookupError('there is no template %s' % str(name)[:120])
    store.db.run('DELETE FROM cert_team_templates WHERE id = ?', (r['id'],))
    store.add_event('certificates', 'the team template %s deleted by %s' % (r['name'], by),
                    who=_who_by(by))
    return {'deleted': r['name']}


def _fill(text, team):
    return str(text or '').replace('{team}', team).replace('{TEAM}', team)


def team_from_template(store, tpl_name, name, parent, by, description=None, contact_mail=None):
    tpl = template_get(store, tpl_name)
    if not tpl:
        raise LookupError('there is no template %s' % str(tpl_name)[:120])
    cfg = tpl['config']
    name = S.clean_name(name, 'the team\'s name')
    if T.team_get(store, name):
        raise ValueError('there is an owner called %s already' % name)
    body = {'name': name, 'kind': cfg.get('kind') or 'team', 'parent': parent or None,
            'description': description if description is not None else _fill(
                cfg.get('description'), name),
            'members': [dict(m, who=_fill(m['who'], name)) for m in cfg.get('members') or []],
            'policy': cfg.get('policy') or {},
            'contact_mail': contact_mail if contact_mail is not None else
            _fill(cfg.get('contact_mail'), name),
            'note': 'made from the template %s' % tpl['name']}
    got = T.save_team(store, body, by)
    for k, v in (cfg.get('extras') or {}).items():
        set_extras(store, got['name'], k, v, by)
    store.add_event('certificates', 'the team %s made from the template %s by %s' % (
        got['name'], tpl['name'], by), who=_who_by(by))
    return T.team_public(T.team_get(store, got['name']), T.used_counts(store))


CSV_COLS = ('name', 'parent', 'kind', 'template', 'description', 'contact_mail', 'members')
CSV_MOST = 2000


def _csv_members(text):
    """'local:jan=Requester+Deployer; group:Web=view' - as --members, a semicolon between."""
    out = []
    for part in re.split(r'\s*[;\n|]\s*', str(text or '').strip()):
        if part.strip():
            out.append(part.strip())
    return out


def import_csv(store, text, by, dry_run=True):
    """A team structure from CSV (a header line naming the columns of CSV_COLS; name required):
    -> {rows: [{line, name, parent, kind, template, state: new|exists|error, error}], made}.
    Parents may come later in the file; the teams are made top-down. Nothing is made while any
    line is wrong (the preview says which)."""
    text = str(text or '')
    if len(text) > 2 * 1024 * 1024:
        raise ValueError('the file is too big (2 MB at most)')
    if text.startswith('﻿'):
        text = text[1:]
    sample = text[:4096]
    delim = ';' if sample.count(';') > sample.count(',') else ','
    rd = csv.DictReader(io.StringIO(text), delimiter=delim)
    if not rd.fieldnames:
        raise ValueError('the file is empty - its first line names the columns: %s'
                         % ', '.join(CSV_COLS))
    cols = [_low(c) for c in rd.fieldnames]
    if 'name' not in cols:
        raise ValueError('the first line names the columns, "name" among them: %s'
                         % ', '.join(CSV_COLS))
    unknown = [c for c in cols if c and c not in CSV_COLS]
    if unknown:
        raise ValueError('%s is not a column (%s)' % (unknown[0][:30], ', '.join(CSV_COLS)))
    cat = T.role_catalog(store)
    rows = []
    for i, raw in enumerate(rd):
        if len(rows) >= CSV_MOST:
            raise ValueError('%d teams at most at once' % CSV_MOST)
        rec = {_low(k): str(v or '').strip() for k, v in raw.items() if k}
        if not any(rec.values()):
            continue
        one = {'line': i + 2, 'name': rec.get('name', ''), 'parent': rec.get('parent', ''),
               'kind': rec.get('kind') or '', 'template': rec.get('template', ''),
               'description': rec.get('description', ''),
               'contact_mail': rec.get('contact_mail', ''),
               'members': _csv_members(rec.get('members', ''))}
        try:
            one['name'] = S.clean_name(one['name'], 'the team\'s name')
            if one['kind'] and one['kind'] not in T.KINDS:
                raise ValueError('the kind is team, person or unit')
            if one['template'] and not template_get(store, one['template']):
                raise ValueError('there is no template %s' % one['template'][:60])
            if one['contact_mail']:
                one['contact_mail'] = T.clean_mails(one['contact_mail'])
            one['members'] = [T.clean_member(m, cat) for m in one['members']]
            one['state'] = 'exists' if T.team_get(store, one['name']) else 'new'
        except ValueError as e:
            one['state'] = 'error'
            one['error'] = str(e)
        rows.append(one)
    names = {}
    for r in rows:
        if r['state'] != 'error':
            if _low(r['name']) in names:
                r['state'], r['error'] = 'error', 'the team %s is twice in the file' % r['name']
            names[_low(r['name'])] = r
    for r in rows:
        if r['state'] == 'error' or not r['parent']:
            continue
        if _low(r['parent']) == _low(r['name']):
            r['state'], r['error'] = 'error', 'a team is not under itself'
        elif _low(r['parent']) not in names and not T.team_get(store, r['parent']):
            r['state'], r['error'] = 'error', 'there is no team %s to put it under' % r['parent']
    # a circle within the file
    for r in rows:
        if r['state'] == 'error':
            continue
        seen, at = {_low(r['name'])}, _low(r['parent'])
        while at and at in names:
            if at in seen:
                r['state'], r['error'] = 'error', 'the parents in the file make a circle'
                break
            seen.add(at)
            at = _low(names[at]['parent'])
    bad = [r for r in rows if r['state'] == 'error']
    made = []
    if not dry_run and not bad:
        done = set()

        def make(r):
            if _low(r['name']) in done:
                return
            p = names.get(_low(r['parent'])) if r['parent'] else None
            if p and p['state'] == 'new':
                make(p)
            done.add(_low(r['name']))
            if r['state'] != 'new':
                return
            if r['template']:
                team_from_template(store, r['template'], r['name'], r['parent'] or None, by,
                                   description=r['description'] or None,
                                   contact_mail=r['contact_mail'] or None)
                if r['members']:
                    t = T.team_get(store, r['name'])
                    ms = [m for m in S.jload(t.get('members'), []) or [] if isinstance(m, dict)]
                    have = {_low(m['who']) for m in ms}
                    ms += [m for m in r['members'] if _low(m['who']) not in have]
                    T.save_team(store, {'old_name': t['name'], 'name': t['name'], 'members': ms}, by)
            else:
                T.save_team(store, {'name': r['name'], 'kind': r['kind'] or 'team',
                                    'parent': r['parent'] or None,
                                    'description': r['description'],
                                    'contact_mail': r['contact_mail'], 'members': r['members'],
                                    'note': 'imported from CSV'}, by)
            made.append(r['name'])
        for r in rows:
            make(r)
        store.add_event('certificates', '%d team(s) imported from CSV by %s: %s' % (
            len(made), by, ', '.join(made[:30])), who=_who_by(by))
    for r in rows:
        r['members'] = [m['who'] if isinstance(m, dict) else m for m in r['members']]
    return {'rows': rows, 'made': made, 'dry_run': bool(dry_run or bad), 'errors': len(bad),
            'new': len([r for r in rows if r['state'] == 'new']),
            'exists': len([r for r in rows if r['state'] == 'exists'])}


# ---------------------------------------------------------------------------
# Notification channels and escalation (T7)
# ---------------------------------------------------------------------------
def _hooks_place(t):
    return 'cert_teams:%s:hooks_sealed' % t['id']


def _hooks_of(t):
    raw = (t or {}).get('hooks_sealed')
    if not raw:
        return {}
    try:
        got = E.unseal_secret(raw, _hooks_place(t)) if str(raw).startswith(E.SEALED2) else \
            E.unseal_secret(raw)
    except Exception:                                   # noqa: BLE001
        got = None
    got = S.jload(got, {}) if got else {}
    return got if isinstance(got, dict) else {}


def clean_hook(url):
    url = str(url or '').strip()
    if not url:
        return ''
    if len(url) > 2000 or any(ord(c) < 33 for c in url):
        raise ValueError('a webhook is one address (https://...)')
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ('https', 'http') or not p.hostname:
        raise ValueError('a webhook\'s address starts with https://')
    if p.username or p.password:
        raise ValueError('a webhook\'s address carries no user or password')
    return url


def set_hooks(store, team, b, by):
    """{teams?, slack?}: an address sets it, '' takes it away, a key not sent keeps it. The
    addresses are kept sealed; nothing gives them back."""
    t = _team_row(store, team)
    hooks = _hooks_of(t)
    changed = []
    for k in HOOK_KINDS:
        if k in b and b[k] is not None:
            v = clean_hook(b[k])
            if v:
                hooks[k] = v
            else:
                hooks.pop(k, None)
            changed.append('%s %s' % (k, 'set' if v else 'taken away'))
    if not changed:
        return {k: bool(hooks.get(k)) for k in HOOK_KINDS}
    sealed = E.seal_secret(json.dumps(hooks), _hooks_place(t)) if hooks else None
    store.db.update('cert_teams', t['id'], {'hooks_sealed': sealed, 'updated': _now(),
                                            'updated_by': _who_by(by)})
    T.changed()
    store.add_event('certificates', 'the team %s: its webhooks changed by %s (%s)' % (
        t['name'], by, ', '.join(changed)), who=_who_by(by))
    return {k: bool(hooks.get(k)) for k in HOOK_KINDS}


def notify_rule(store, team):
    """(the team whose channels these are, {mail, manager_mail, oncall_mail, expiry_days, ...},
    its webhooks) - its own, else the nearest team above with channels; (None, None, {})."""
    if not team or _low(team) not in T.tree(store).rows:
        return None, None, {}
    for t in _chain_rows(store, team):
        n = extras_of(t).get('notify')
        if n:
            return t['name'], n, _hooks_of(t)
    return None, None, {}


WORDS = {
    'elevation_asked': {
        'en': ('%(team)s: %(who)s asks for %(role)s for %(hours)s h',
               '%(who)s asks for the role %(role)s on the team %(team)s for %(hours)s hour(s).\n'
               'Why: %(reason)s\n\nApprove or decline it under Requests (a manager of the team, '
               'never the one who asked).'),
        'cs': ('%(team)s: %(who)s žádá o roli %(role)s na %(hours)s h',
               '%(who)s žádá o roli %(role)s v týmu %(team)s na %(hours)s h.\nDůvod: %(reason)s\n\n'
               'Schvalte ji nebo zamítněte v Žádostech (správce týmu, nikdy ten, kdo žádá).')},
    'elevation_granted': {
        'en': ('%(team)s: %(who)s has %(role)s until %(until)s',
               '%(by)s gave %(who)s the role %(role)s on the team %(team)s until %(until)s. It ends '
               'by itself.'),
        'cs': ('%(team)s: %(who)s má roli %(role)s do %(until)s',
               '%(by)s dal(a) uživateli %(who)s roli %(role)s v týmu %(team)s do %(until)s. '
               'Skončí sama.')},
    'elevation_declined': {
        'en': ('%(team)s: the request of %(who)s for %(role)s was declined',
               '%(by)s declined the request of %(who)s for the role %(role)s on the team %(team)s: '
               '%(why)s'),
        'cs': ('%(team)s: žádost %(who)s o roli %(role)s byla zamítnuta',
               '%(by)s zamítl(a) žádost %(who)s o roli %(role)s v týmu %(team)s: %(why)s')},
    'elevation_ended': {
        'en': ('%(team)s: the temporary role %(role)s of %(who)s ended',
               'The temporary role %(role)s of %(who)s on the team %(team)s ended by itself.'),
        'cs': ('%(team)s: dočasná role %(role)s uživatele %(who)s skončila',
               'Dočasná role %(role)s uživatele %(who)s v týmu %(team)s sama skončila.')},
    'review_opened': {
        'en': ('%(team)s: an access review is open (%(count)s members)',
               'Confirm the %(count)s member(s) of the team %(team)s and their roles by %(due)s '
               '(Owners and teams, the team, Governance - or the portal).'),
        'cs': ('%(team)s: otevřena revize přístupů (členů k potvrzení: %(count)s)',
               'Potvrďte členy týmu %(team)s a jejich role do %(due)s (členů: %(count)s; Vlastníci '
               'a týmy, tým, Správa - nebo na portálu).')},
    'review_late': {
        'en': ('%(team)s: the access review is overdue (%(count)s not confirmed)',
               'The access review of the team %(team)s was not finished in time: %(count)s '
               'member(s) not confirmed - %(action)s.'),
        'cs': ('%(team)s: revize přístupů je po termínu (nepotvrzených: %(count)s)',
               'Revize přístupů týmu %(team)s nebyla včas dokončena - nepotvrzených členů: '
               '%(count)s (%(action)s).')},
    'expiring': {
        'en': ('%(team)s: %(cert)s ends in %(days)s day(s)',
               'The certificate %(cert)s of the team %(team)s (%(names)s) ends on %(end)s - '
               'in %(days)s day(s).%(extra)s'),
        'cs': ('%(team)s: certifikát %(cert)s končí %(end)s',
               'Certifikát %(cert)s týmu %(team)s (%(names)s) končí %(end)s (zbývá dní: '
               '%(days)s).%(extra)s')},
    'deploy_failed': {
        'en': ('%(team)s: deploying %(cert)s to %(target)s failed',
               'Deploying the certificate %(cert)s of the team %(team)s to %(target)s failed: '
               '%(error)s'),
        'cs': ('%(team)s: nasazení %(cert)s na %(target)s selhalo',
               'Nasazení certifikátu %(cert)s týmu %(team)s na %(target)s selhalo: %(error)s')},
    'test': {
        'en': ('%(team)s: a test of the notification channels',
               'This is a test from acme: the team %(team)s is told here (%(stage)s).'),
        'cs': ('%(team)s: zkouška kanálů upozornění',
               'Toto je zkouška z acme: tým %(team)s dostává upozornění sem (%(stage)s).')},
}
STAGE_WORDS = {'en': {'team': 'the team', 'manager': 'the manager', 'oncall': 'on-call'},
               'cs': {'team': 'tým', 'manager': 'vedoucí', 'oncall': 'pohotovost'}}


def _lang():
    try:
        from acmelib.certs import notices
        return notices.lang()
    except Exception:                                   # noqa: BLE001
        return 'cs'


def _split(v):
    return [w for w in re.split(r'[\s,;]+', str(v or '')) if w]


def recipients(store, team, stage, rule=None, src_team=None):
    """The addresses of a stage (team, manager, oncall) - the team's mail (else its contact
    addresses) for the team."""
    rule = rule or {}
    if stage == 'manager':
        return _split(rule.get('manager_mail'))
    if stage == 'oncall':
        return _split(rule.get('oncall_mail'))
    got = _split(rule.get('mail'))
    if not got:
        t = T.team_get(store, src_team or team)
        got = _split((t or {}).get('contact_mail'))
    return got


def _post_hook(url, text, kind):
    body = json.dumps({'text': text}).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': 'acme-notify'})
    with E.url_open(req, timeout=10, purpose='acme') as r:
        return int(getattr(r, 'status', 200) or 200)


def _deliver(store, team, stage, subject, text, mails, hooks, wait=False):
    """Mail and webhooks - in a thread of their own unless `wait`. -> {channel: 'sent' | words}"""
    out = {}

    def go():
        if mails:
            if (E.CONFIG.get('mail_mode') or 'off') == 'off':
                out['mail'] = 'mail is switched off (Settings → Mail)'
            else:
                try:
                    from email.message import EmailMessage
                    msg = EmailMessage()
                    msg['Subject'] = subject
                    msg['From'] = E.mail_sender() or 'acme@%s' % E.node_name()
                    msg['To'] = ', '.join(mails)
                    msg.set_content(text + '\n\n-- acme, %s\n' % str(
                        E.CONFIG.get('site_name') or E.node_name()))
                    E.mail_deliver(store, msg, mails, kind='certs', name=team,
                                   purpose='team notification')
                    out['mail'] = 'sent'
                except Exception as e:                  # noqa: BLE001
                    if getattr(e, 'queued', None) == 'waiting':
                        out['mail'] = 'sent'
                    else:
                        out['mail'] = str(e)[:200]
                        E.log('the team %s could not be told by mail: %s' % (team, e), 'warn')
        for k in HOOK_KINDS:
            url = hooks.get(k)
            if not url:
                continue
            try:
                st = _post_hook(url, '%s\n%s' % (subject, text), k)
                out[k] = 'sent' if 200 <= st < 300 else 'answered %s' % st
            except Exception as e:                      # noqa: BLE001
                # the address itself never in the words (it is a secret)
                out[k] = 'not sent: %s' % (type(e).__name__ if 'http' in str(e).lower()
                                           else str(e)[:120])
                E.log('the %s webhook of the team %s: %s' % (k, team, out[k]), 'warn')
    if wait:
        go()
    else:
        threading.Thread(target=go, name='team-notify', daemon=True).start()
    return out


def tell(store, team, what, values, key=None, stage='team', wait=False):
    """A message of WORDS to the team's channels (its own or the nearest above) at `stage` -
    nothing where no team in the chain has channels (as before); each `key` once."""
    try:
        src, rule, hooks = notify_rule(store, team)
        if not rule:
            return {}
        if what.startswith('elevation') and not rule.get('elevations', True):
            return {}
        if what.startswith('review') and not rule.get('reviews', True):
            return {}
        if key:
            mk = 'teams:told:%s' % key
            if store.get_meta(mk):
                return {}
            store.set_meta(mk, str(_now()))
        lang = _lang()
        subj, body = WORDS[what].get(lang) or WORDS[what]['en']
        fill = dict(values or {})
        if what == 'review_late':
            fill['action'] = {'en': {'report': 'reported', 'expire': 'their memberships expired'},
                              'cs': {'report': 'nahlášeno', 'expire': 'jejich členství vypršela'}
                              }.get(lang, {}).get(fill.get('action'), fill.get('action'))
        fill.setdefault('team', team)
        fill.setdefault('stage', STAGE_WORDS.get(lang, STAGE_WORDS['en']).get(stage, stage))

        class _D(dict):
            def __missing__(self, k):
                return ''
        fill = _D({k: ('' if v is None else v) for k, v in fill.items()})
        subject = ' '.join((subj % fill).split())[:300]
        text = body % fill
        mails = recipients(store, team, stage, rule, src)
        # the webhooks are the team's channels: every stage is said there too
        return _deliver(store, team, stage, subject, text, mails, hooks, wait=wait)
    except Exception as e:                              # noqa: BLE001
        E.log('telling the team %s (%s): %s' % (team, what, e), 'warn')
        return {}


def notify_test(store, team):
    _team_row(store, team)
    src, rule, hooks = notify_rule(store, team)
    if not rule:
        raise E.ApiError(409, 'the team %s has no notification channels (nor a team above it)'
                         % team)
    out = {}
    for stage in ('team', 'manager', 'oncall'):
        mails = recipients(store, team, stage, rule, src)
        if mails:
            got = _deliver(store, team, stage, *_test_words(team, stage), mails=mails, hooks={},
                           wait=True)
            out[stage] = {'to': mails, 'result': got.get('mail')}
    if hooks:
        got = _deliver(store, team, 'team', *_test_words(team, 'team'), mails=[], hooks=hooks,
                       wait=True)
        for k in HOOK_KINDS:
            if k in got:
                out[k] = {'result': got[k]}
    store.add_event('certificates', 'the notification channels of the team %s were tried' % team)
    return {'from': src, 'channels': out}


def _test_words(team, stage):
    lang = _lang()
    subj, body = WORDS['test'].get(lang) or WORDS['test']['en']
    fill = {'team': team, 'stage': STAGE_WORDS.get(lang, STAGE_WORDS['en']).get(stage, stage)}
    return subj % fill, body % fill


def _escalate_tick(store):
    """Each certificate of a team with channels told at 14 days (the team) and 3 days (the
    manager) before its end, each failed deployment (on-call) - once each."""
    tr = T.tree(store)
    have = [k for k in tr.order if extras_of(tr.rows[k]).get('notify')]
    if not have:
        return
    now = _now()
    owners = set()
    for k in have:
        owners.add(k)
        owners.update(tr.descendants(k))
    part = sorted(owners)
    if not part:
        return
    marks = ', '.join('?' * len(part))
    rows = store.db.rows("SELECT id, name, names, owner, not_after, state, auto_renew FROM certs "
                         "WHERE LOWER(TRIM(owner)) IN (%s) AND not_after > ? AND COALESCE(state, "
                         "'') NOT IN ('revoked', 'disabled')" % marks, tuple(part) + (now,))
    for r in rows:
        team = tr.name(_low(r['owner']))
        src, rule, _h = notify_rule(store, team)
        if not rule:
            continue
        left = (float(r['not_after']) - now) / 86400.0
        stage = None
        if rule.get('manager_days') and left <= rule['manager_days']:
            stage = 'manager'
        elif rule.get('expiry_days') and left <= rule['expiry_days']:
            stage = 'team'
        if not stage:
            continue
        values = {'cert': r['name'], 'days': max(0, int(left)), 'names': ', '.join(
            (S.jload(r.get('names'), []) or [])[:5]),
                  'end': time.strftime('%Y-%m-%d', time.localtime(float(r['not_after']))),
                  'extra': ''}
        # the manager is told of what the team was told and did not settle - the team too
        tell(store, team, 'expiring', values, key='esc:%s:%s:%d' % (stage, r['id'],
                                                                    int(r['not_after'])),
             stage=stage)
    drows = store.db.rows("SELECT d.id, d.target, d.last_try, d.last_error, c.name, c.owner FROM "
                          "cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE d.state = "
                          "'failed' AND LOWER(TRIM(c.owner)) IN (%s)" % marks, tuple(part))
    for d in drows:
        team = tr.name(_low(d['owner']))
        src, rule, _h = notify_rule(store, team)
        if not rule or not rule.get('deploy_failed'):
            continue
        if float(d.get('last_try') or 0) < float(rule.get('since') or 0):
            continue            # failed before the channels were set: not a flood of the past
        tell(store, team, 'deploy_failed', {'cert': d['name'], 'target': d['target'],
                                            'error': str(d.get('last_error') or '')[:300]},
             key='esc:deploy:%s:%d' % (d['id'], int(float(d.get('last_try') or 0))),
             stage=rule['deploy_failed'])


# ---------------------------------------------------------------------------
# Health (T8)
# ---------------------------------------------------------------------------
WEAK_RSA = 2048
WEAK_EC = 256


def weak_key(key_type):
    k = _low(key_type)
    m = re.match(r'^(rsa|ec|ecdsa|dsa)[-_]?(\d+)$', k)
    if not m:
        return False
    bits = int(m.group(2))
    if m.group(1) == 'dsa':
        return True
    if m.group(1) == 'rsa':
        return bits < WEAK_RSA
    return bits < WEAK_EC


def outside_words(eff, r):
    """Why a certificate is outside its team's limits in force - [] when it is inside."""
    out = []
    if not eff:
        return out
    names = S.jload(r.get('names'), []) or []
    iss = r.get('issuer') or ''
    val = r.get('challenge') or ''
    if eff.get('issuers') is not None and iss and _low(iss) not in {_low(x) for x in eff['issuers']}:
        out.append('the source %s is not allowed' % iss)
    if eff.get('validations') is not None and val and \
            _low(val) not in {_low(x) for x in eff['validations']}:
        out.append('the validation %s is not allowed' % val)
    if eff.get('pairs') is not None and iss:
        try:
            if not T.pair_allowed(eff, iss, val or None):
                out.append('%s with %s is not a pair allowed' % (iss, val or 'no validation'))
        except Exception:                               # noqa: BLE001
            pass
    sufs = eff.get('suffixes')
    if sufs:
        from acmelib.certs import teampolicy as TP
        bad = [n for n in names if not TP.name_in_suffixes(n, sufs)]
        if bad:
            out.append('%s outside %s' % (', '.join(bad[:3]), ', '.join(sufs[:3])))
    if eff.get('wildcards') is False and any(str(n).startswith('*.') for n in names):
        out.append('a wildcard name')
    md = eff.get('max_days')
    if md and r.get('not_before') and r.get('not_after'):
        days = (float(r['not_after']) - float(r['not_before'])) / 86400.0
        if days > int(md) + 1:
            out.append('valid %d days, the limit is %d' % (int(days), int(md)))
    return out


def _score(m):
    pen = min(30, 10 * m['expired'] + 4 * m['expiring'])
    pen += min(25, 8 * m['failed_renewals'])
    pen += min(20, 6 * m['failed_deploys'])
    pen += min(15, 5 * m['outside'])
    pen += min(15, 5 * m['weak'])
    q = m.get('quota')
    if q and q.get('max'):
        used = q['used'] / float(q['max'])
        pen += 15 if used >= 1 else 8 if used >= 0.9 else 3 if used >= 0.8 else 0
    return max(0, 100 - pen)


def _grade(score):
    return 'good' if score >= 90 else 'fair' if score >= 70 else 'poor'


def _health_compute(store):
    tr = T.tree(store)
    now = _now()
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    own = {k: {'certs': 0, 'expiring': 0, 'expired': 0, 'failed_renewals': 0,
               'failed_deploys': 0, 'outside': 0, 'weak': 0, 'list': {}} for k in tr.rows}
    rows = store.db.rows("SELECT id, name, names, owner, issuer, challenge, key_type, "
                         "key_type_alt, not_before, not_after, state, alt_state FROM certs "
                         "WHERE COALESCE(owner, '') <> ''")
    fails = {}
    for d in store.db.rows("SELECT cert_id, COUNT(*) AS n FROM cert_deploys WHERE state = "
                           "'failed' GROUP BY cert_id"):
        fails[d['cert_id']] = int(d['n'] or 0)

    def note(o, cat, r, why=''):
        lst = o['list'].setdefault(cat, [])
        if len(lst) < 50:
            lst.append({'id': r['id'], 'name': r['name'], 'why': why})
    for r in rows:
        k = _low(r['owner'])
        o = own.get(k)
        if o is None:
            continue
        o['certs'] += 1
        st = r.get('state') or ''
        na = float(r.get('not_after') or 0)
        if st in ('revoked', 'disabled'):
            continue
        if na and na < now:
            o['expired'] += 1
            note(o, 'expired', r)
        elif na and na < now + days * 86400:
            o['expiring'] += 1
            note(o, 'expiring', r, time.strftime('%Y-%m-%d', time.localtime(na)))
        if st == 'failed' or r.get('alt_state') == 'failed':
            o['failed_renewals'] += 1
            note(o, 'failed_renewals', r)
        if fails.get(r['id']):
            o['failed_deploys'] += fails[r['id']]
            note(o, 'failed_deploys', r, str(fails[r['id']]))
        why = outside_words(tr.effective(k), r)
        if why:
            o['outside'] += 1
            note(o, 'outside', r, '; '.join(why))
        if weak_key(r.get('key_type')) or weak_key(r.get('key_type_alt')):
            o['weak'] += 1
            note(o, 'weak', r, r.get('key_type') or '')
    out = {}
    for k in reversed(tr.order):
        o = own[k]
        agg = {x: o[x] for x in ('certs', 'expiring', 'expired', 'failed_renewals',
                                 'failed_deploys', 'outside', 'weak')}
        for c in tr.children.get(k, []):
            for x in agg:
                agg[x] += out[c]['below'][x]
        out[k] = {'team': tr.rows[k]['name'], 'kind': tr.rows[k].get('kind') or 'team',
                  'parent': tr.name(tr.parent[k]) if tr.parent.get(k) else None,
                  'own': dict({x: o[x] for x in agg}, quota=None), 'below': dict(agg, quota=None),
                  'list': o['list']}
    # the quota: max_certs counts the certificates of the team that set it, with those below it
    for k in tr.order:
        eff = tr.effective(k)
        if eff.get('max_certs') is not None:
            src = _low((eff.get('from') or {}).get('max_certs') or tr.rows[k]['name'])
            src = src if src in out else k
            q = {'used': out[src]['below']['certs'], 'max': int(eff['max_certs']),
                 'from': tr.rows[src]['name']}
            out[k]['own']['quota'] = out[k]['below']['quota'] = q
        out[k]['score'] = _score(out[k]['below'])
        out[k]['grade'] = _grade(out[k]['score'])
    return out


def health(store):
    """{team lower: {team, kind, parent, own, below, score, grade, list}} - computed once per
    minute and version of the teams."""
    key = (T._version(store), int(_now() // 60))
    got = _HEALTH.get(key)
    if got is None:
        _HEALTH.clear()
        got = _health_compute(store)
        _HEALTH[key] = got
    return got


def health_public(store, seen=None, detail_team=None):
    """[...] of the teams `seen` (None every one) - the lists of certificates only for
    `detail_team`."""
    h = health(store)
    tr = T.tree(store)
    out = []
    for k in tr.order:
        one = h.get(k)
        if not one or (seen is not None and k not in seen):
            continue
        one = dict(one)
        if detail_team is None or _low(detail_team) != k:
            one.pop('list', None)
        out.append(one)
    return out


def summary_score(rows):
    """The score of many teams together - weighted by their certificates (top-level ones)."""
    tops = [r for r in rows if not r.get('parent') or r['parent'] not in {x['team'] for x in rows}]
    w = sum(max(1, r['below']['certs']) for r in tops)
    if not w:
        return None
    return int(round(sum(r['score'] * max(1, r['below']['certs']) for r in tops) / float(w)))


# ---------------------------------------------------------------------------
# Renamed, deleted
# ---------------------------------------------------------------------------
def follow_rename(store, old, new):
    for table in ('cert_team_elevations', 'cert_team_reviews'):
        try:
            store.db.run('UPDATE %s SET team = ? WHERE LOWER(TRIM(team)) = ?' % table,
                         (new, _low(old)))
        except Exception:                               # noqa: BLE001
            pass


def follow_delete(store, name):
    now = _now()
    try:
        store.db.run("UPDATE cert_team_elevations SET state = 'ended', ended = ?, ended_by = ?, "
                     "updated = ? WHERE LOWER(TRIM(team)) = ? AND state IN ('waiting', "
                     "'granted')", (now, 'the team was deleted', now, _low(name)))
        store.db.run("UPDATE cert_team_reviews SET state = 'closed', done = ?, done_by = ?, "
                     "updated = ? WHERE LOWER(TRIM(team)) = ? AND state IN ('open', 'overdue')",
                     (now, 'the team was deleted', now, _low(name)))
    except Exception:                                   # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# The tick
# ---------------------------------------------------------------------------
def tick(store, force=False):
    """Elevations ended, reviews opened and closed, the escalation chain - at most every
    TICK_EVERY_S. Never raises."""
    if not force and _now() - _TICK['at'] < TICK_EVERY_S:
        return
    _TICK['at'] = _now()
    for name, fn in (('elevations', _elev_tick), ('reviews', _review_tick),
                     ('escalation', _escalate_tick)):
        try:
            fn(store)
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('teams-gov-' + name, 'the teams\' %s: %s' % (name, e), 'warn',
                          every=3600)
