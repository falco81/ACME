# -*- coding: utf-8 -*-
"""
The limits of a team and its approvals (1.0.125, docs/teams.md "Enterprise teams").

A team's `policy` (teams.clean_policy) narrows what its members may do with its
certificates and devices; the policy in force is the intersection of the team's own and of
every team above it (teams.merge_policies). Each check here is one function that raises
E.ApiError (403, or 400 for a value that is not right) in words naming the team whose limit
refused it - and writes an event. A team without a policy: nothing here refuses anything,
nothing waits that did not wait before.

    need_request(store, team, ...)          a request for a team's certificate (the portal's
                                            free form or a request profile)
    need_max_certs(store, team, adding)     the most certificates a team (and below) may own
    request_waits(store, team, ...)         whether a request waits for approval (the rule)
    need_key_download(store, team, who)     a file with the private key
    need_target_kind(store, team, kind)     a device (target) of the team
    need_deploy(store, cert, target, who)   a deployment by the team
    need_admin_cert(store, s, b, row)       a certificate a scoped administrator makes/changes
    admin_create_waits(store, s, owner)     its approval forced (policy approval "always")

The approvals (section 8): who approves which request, each approval recorded (the request's
meta `approvals`), the request let through once the rule is met.

    rule_for(store, row)                    the rule in force for a request, or None
    approver_portal(h, s) / approver_admin(store, s)   who is approving
    approve_step(store, row, approver, ok, why)        one approval recorded
    approval_state(store, row)              what it has, what it still needs
    waiting_for(store, approver)            the requests this person may approve now
    timeline(store, cid)                    asked, each approval, approved/declined, issued
    action_* (approve_actions)              other actions waiting for an approval
"""
from __future__ import annotations

import fnmatch
import json
import secrets
import threading
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import teams as T

ACTION_META = 'teams:action:'           # + id: an action waiting for approval (approve_actions)
ACTION_KEEP_S = 30 * 86400


def _low(v):
    return str(v or '').strip().lower()


def team_name(store, owner):
    """The team (its name) a certificate's owner is - None when it is not a defined team."""
    if not _low(owner):
        return None
    tr = T.tree(store)
    return tr.name(owner) if _low(owner) in tr.rows else None


def _eff(store, team):
    return T.effective_policy(store, team) if team else {}


def _from(eff, key, team):
    return (eff.get('from') or {}).get(key) or team


def refuse(store, who, team, words, status=403):
    """An event, and the refusal in words naming the team."""
    store.add_event('certificates', '%s was refused by the limits of the team %s: %s' % (
        who or '?', team, words), 'warn', who=str(who or '')[:190])
    raise E.ApiError(status, 'the team %s does not allow it: %s' % (team, words))


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
def name_in_suffixes(name, sufs):
    n = _low(name)
    n = n[2:] if n.startswith('*.') else n
    return any(n == x or n.endswith('.' + x) for x in sufs)


def need_max_certs(store, team, adding=1, who=''):
    """The most certificates a team may own - each team of its chain that says `max_certs`
    counts its own and those of the teams below it."""
    if not team or adding <= 0:
        return
    tr = T.tree(store)
    used = T.used_counts(store)
    for k in tr.chain(team):
        most = (tr.policies.get(k) or {}).get('max_certs')
        if most is None:
            continue
        have = used.get(k, 0) + sum(used.get(d, 0) for d in tr.descendants(k))
        if have + adding > most:
            refuse(store, who, tr.rows[k]['name'],
                   'it may own %d certificate(s) with the teams below it, and owns %d'
                   % (most, have))


def need_request(store, team, who='', profile=None, issuer=None, validation=None, names=(),
                 days=None, key_type=None, count=True):
    """A request for a certificate owned by `team`: from a profile it allows (profile None:
    the portal's free form, where it allows that; '' an administrator's wizard - neither), a
    source and validation it allows, names under its suffixes, a validity no longer than its
    max_days, and room under max_certs (count)."""
    team = team_name(store, team)
    if not team:
        return
    eff = _eff(store, team)
    if profile is None:
        if not T.policy_value(eff, 'free_form'):
            refuse(store, who, _from(eff, 'free_form', team),
                   'its certificates are asked for from a request profile only')
    elif profile != '' and eff.get('profiles') is not None and \
            _low(profile) not in {_low(p) for p in eff['profiles']}:
        refuse(store, who, _from(eff, 'profiles', team),
               'the request profile %s is not one it may ask from (%s)' % (
                   profile, ', '.join(eff['profiles']) or 'none'))
    _check_eff(store, team, eff, who, issuer, validation, names, days, count)


def inside_envelope(eff, profile=None, names=(), days=None, key_type=None):
    """Whether a request stays inside the pre-approved envelope of approval.outside."""
    o = (eff.get('approval') or {}).get('outside') or {}
    if o.get('profiles') is not None and (profile is None or _low(profile) not in {
            _low(p) for p in o['profiles']}):
        return False
    if o.get('suffixes') is not None and any(not name_in_suffixes(n, o['suffixes'])
                                             for n in names or ()):
        return False
    if o.get('max_days') is not None and days and int(days) > int(o['max_days']):
        return False
    if o.get('key_types') is not None and key_type and _low(key_type) not in {
            _low(k) for k in o['key_types']}:
        return False
    return True


def request_waits(store, team, profile_waits, profile=None, names=(), days=None,
                  key_type=None):
    """Whether a request for `team` waits for approval: None - the team says nothing (as
    before: the profile, the portal's settings decide); True / False its rule's answer."""
    team = team_name(store, team)
    if not team:
        return None
    eff = _eff(store, team)
    if not eff.get('approval'):
        return None
    mode = T.approval_rule(eff)['mode']
    if mode == 'always':
        return True
    if mode == 'none':
        return False
    if mode == 'outside':
        return not inside_envelope(eff, profile, names, days, key_type)
    return bool(profile_waits)


def need_key_download(store, team, who=''):
    team = team_name(store, team)
    if not team:
        return
    eff = _eff(store, team)
    if not T.policy_value(eff, 'key_download'):
        refuse(store, who, _from(eff, 'key_download', team),
               'files with the private key of its certificates are not downloaded')


def kinds_allowed(eff):
    kinds = eff.get('target_kinds')
    if kinds is not None and not T.policy_value(eff, 'agents'):
        kinds = [k for k in kinds if k not in ('agent', 'agent_windows')]
    elif kinds is None and not T.policy_value(eff, 'agents'):
        return ('!agents',)
    return kinds


def need_target_kind(store, team, kind, who=''):
    """A device of the team (a target it owns) of this module: one its target_kinds (and
    `agents`) allow."""
    team = team_name(store, team)
    if not team:
        return
    eff = _eff(store, team)
    agent = kind in ('agent', 'agent_windows')
    if agent and not T.policy_value(eff, 'agents'):
        refuse(store, who, _from(eff, 'agents', team), 'it has no target agents')
    kinds = eff.get('target_kinds')
    if kinds is not None and _low(kind) not in {_low(k) for k in kinds}:
        refuse(store, who, _from(eff, 'target_kinds', team),
               'its devices are of the modules %s - not %s' % (', '.join(kinds) or 'none', kind))


def need_deploy(store, cert, target, who=''):
    """A deployment of a team's certificate (made by the team): to a device of the team (or of
    a team above or below it) or of acme's own, of a module its limits allow."""
    team = team_name(store, (cert or {}).get('owner'))
    if not team or not target:
        return
    tr = T.tree(store)
    own = _low(target.get('owner'))
    if own and own not in set(tr.chain(team)) | set(tr.descendants(team)):
        refuse(store, who, team, 'the device %s is another team\'s' % target.get('name'))
    eff = _eff(store, team)
    if eff:
        need_target_kind(store, team, target.get('kind'), who)


def need_admin_cert(store, s, b, row):
    """A certificate made (row None) or changed by a scoped certificate administrator: within
    its owner team's limits (its source, validation, names, validity, how many)."""
    owner = b.get('owner') if 'owner' in b or row is None else (row or {}).get('owner')
    team = team_name(store, owner)
    if not team:
        return
    if not _eff(store, team) and row is not None:
        return
    who = str(s.get('name') or '?')
    names = b.get('names') if 'names' in b else None
    if isinstance(names, str):
        names = [w for w in names.replace(',', ' ').split() if w]
    prof = b.get('profile') if isinstance(b.get('profile'), dict) else {}
    days = prof.get('days') if prof else None
    try:
        days = int(days) if days not in (None, '') else None
    except (TypeError, ValueError):
        days = None
    moving = row is not None and _low(owner) != _low(row.get('owner'))
    need_request(store, team, who, profile='', issuer=b.get('issuer') if 'issuer' in b else (
        None if row else None), validation=b.get('challenge') if 'challenge' in b else None,
        names=[str(n) for n in names or [] if isinstance(n, str)], days=days,
        count=row is None or moving)


def admin_create_waits(store, s, owner):
    """Whether a certificate a scoped administrator makes for `owner` waits for approval: its
    team's rule says always."""
    if T.unscoped(s, 'request'):
        return False
    team = team_name(store, owner)
    if not team:
        return False
    eff = _eff(store, team)
    return bool(eff.get('approval')) and T.approval_rule(eff)['mode'] == 'always'


def _check_eff(store, team, eff, who, issuer, validation, names, days, count):
    if issuer and eff.get('issuers') is not None and _low(issuer) not in {
            _low(x) for x in eff['issuers']}:
        refuse(store, who, _from(eff, 'issuers', team),
               'the source %s is not one it may use (%s)' % (issuer, ', '.join(eff['issuers'])
                                                            or 'none'))
    if validation and eff.get('validations') is not None and _low(validation) not in {
            _low(x) for x in eff['validations']}:
        refuse(store, who, _from(eff, 'validations', team),
               'the validation %s is not one it may use (%s)' % (
                   validation, ', '.join(eff['validations']) or 'none'))
    if eff.get('suffixes') is not None:
        bad = [n for n in names or () if not name_in_suffixes(n, eff['suffixes'])]
        if bad:
            refuse(store, who, _from(eff, 'suffixes', team),
                   'its certificates are for names under %s - not %s' % (
                       ', '.join(eff['suffixes']) or 'none', ', '.join(bad[:10])))
    if days and eff.get('max_days') is not None and int(days) > int(eff['max_days']):
        refuse(store, who, _from(eff, 'max_days', team),
               'its certificates are valid for %d days at most, not %d' % (eff['max_days'],
                                                                         int(days)))
    if count:
        need_max_certs(store, team, 1, who)


# ---------------------------------------------------------------------------
# Approvals (section 8)
# ---------------------------------------------------------------------------
def rule_for(store, row):
    """The approval rule in force for a request ({mode, approvers, count, self, outside}) -
    None when its owner is not a team, or its team (and those above) says nothing (as
    before)."""
    team = team_name(store, (row or {}).get('owner'))
    if not team:
        return None
    eff = _eff(store, team)
    if not eff.get('approval'):
        return None
    out = T.approval_rule(eff)
    out['team'] = team
    return out


def approver_admin(store, s):
    """Who approves, from the administration: {by, ids, caps, all}."""
    from acmelib.certs import portal as P
    return {'by': str(s.get('name') or '?'), 'ids': sorted(P.admin_names(s)),
            'caps': T.session_caps(store, s), 'all': T.unscoped(s, 'cert.approve')}


def approver_portal(h, s):
    """Who approves, on the portal: {by, ids, caps, all}."""
    from acmelib.certs import portal as P
    return {'by': P.portal_by(s), 'ids': P.asker_ids(s),
            'caps': T.person_caps(h.store, P.my_names(s), P.my_groups(h, s)),
            'all': bool(E.portal_sees_all(s))}


def _may_on(approver, k, direct=False):
    """Whether the approver may approve for the team k (lower name): cert.approve there - or
    the old right manage, as /api/certs/approve took it. `direct`: by a membership of that
    very team (its own leads), not one inherited from a team above."""
    if approver.get('all'):
        return True
    one = (approver.get('caps') or {}).get(k) or {}
    c = one.get('direct' if direct else 'caps') or frozenset()
    return 'cert.approve' in c or T.LEGACY_MANAGE in c


def levels_of(store, team, approver):
    """The levels this approver serves for a request of `team`: 'team' (a member of the team
    itself), 'parent' (holding it on the team above, there or from higher up)."""
    tr = T.tree(store)
    k = _low(team)
    out = set()
    if _may_on(approver, k, direct=True):
        out.add('team')
    p = tr.parent.get(k)
    if (p and _may_on(approver, p)) or (not p and approver.get('all')):
        out.add('parent')
    return out


def _key(approver):
    ids = [str(x).lower() for x in approver.get('ids') or [] if x]
    return ids[0] if ids else _low(approver.get('by'))


def _same_person(entry, approver):
    mine = {str(x).lower() for x in approver.get('ids') or []} | {_low(approver.get('by'))}
    theirs = {str(x).lower() for x in entry.get('ids') or []} | {_low(entry.get('by'))}
    mine.discard('')
    return bool(mine & theirs)


def _evaluate(rule, approvals):
    """(complete, needed: [levels still wanted], counted: [entries counted])."""
    ok = [a for a in approvals if a.get('ok')]
    need = max(int(rule.get('count') or 1), 2 if rule.get('approvers') == 'both' else 1)
    who = rule.get('approvers') or 'team'
    people = []
    for a in ok:
        if not any(_same_person(p, {'ids': a.get('ids'), 'by': a.get('by')}) for p in people):
            people.append(a)
    if who == 'both':
        team_ = [a for a in people if 'team' in (a.get('levels') or [])]
        first = team_[0] if team_ else None
        parent_ = [a for a in people if 'parent' in (a.get('levels') or []) and a is not first]
        needed = []
        if not first:
            needed.append('team')
        if not parent_:
            needed.append('parent')
        done = not needed and len(people) >= need
        if not done and not needed:
            needed.append('team_or_parent')
        return done, needed, people
    lv = {'team': ('team',), 'parent': ('parent',),
          'team_or_parent': ('team', 'parent')}.get(who, ('team',))
    good = [a for a in people if set(a.get('levels') or []) & set(lv)]
    done = len(good) >= need
    return done, ([] if done else [who] * (need - len(good))), good


def approval_state(store, row):
    """{rule, approvals: [...], complete, needed: [...]} of a request (its meta)."""
    from acmelib.certs import portal as P
    rule = rule_for(store, row)
    a = P.asker(store, row['id'])
    approvals = [x for x in a.get('approvals') or [] if isinstance(x, dict)]
    if not rule:
        return {'rule': None, 'approvals': approvals, 'complete': None, 'needed': []}
    done, needed, _c = _evaluate(rule, approvals)
    return {'rule': rule, 'approvals': approvals, 'complete': done, 'needed': needed}


def self_allowed(store, row):
    """Whether the rule of the request's team lets the one who asked approve it (self: true);
    never by default."""
    rule = rule_for(store, row)
    return bool(rule and rule.get('self'))


def _record(store, cid, entry):
    from acmelib.certs import portal as P

    def change(a):
        lst = [x for x in a.get('approvals') or [] if isinstance(x, dict)]
        lst.append(entry)
        a['approvals'] = lst[-50:]
    return P.asker_change(store, cid, change)


def approve_step(store, row, approver, ok, why):
    """One approval (or decline) of a request that waits: recorded; checked against its team's
    rule. -> {'complete': bool, 'needed': [...], 'rule': ...} - complete True when the request
    may now be let through (as before for a team without a rule: one approval does). Refused in
    words (403/409) where this person may not approve it (yet)."""
    rule = rule_for(store, row)
    approver = approver or {'by': '?', 'all': True}
    entry = {'by': str(approver.get('by') or '?')[:190], 'at': time.time(), 'ok': bool(ok),
             'why': str(why or '')[:500],
             'ids': [str(x)[:400] for x in (approver.get('ids') or [])][:20]}
    if not rule:
        entry['levels'] = ['team']
        _record(store, row['id'], entry)
        return {'complete': True, 'needed': [], 'rule': None}
    team = rule['team']
    levels = levels_of(store, team, approver)
    from acmelib.certs import portal as P
    approvals = [x for x in P.asker(store, row['id']).get('approvals') or []
                 if isinstance(x, dict)]
    who = rule.get('approvers') or 'team'
    want = {'team': {'team'}, 'parent': {'parent'}, 'team_or_parent': {'team', 'parent'},
            'both': {'team', 'parent'}}.get(who, {'team'})
    if not levels & want:
        parent = T.tree(store).parent.get(_low(team))
        where = {'team': 'the team %s' % team,
                 'parent': 'the team above %s (%s)' % (team, T.tree(store).name(parent)
                                                       if parent else 'none'),
                 'team_or_parent': 'the team %s or the team above it' % team,
                 'both': 'the team %s or the team above it' % team}[who]
        store.add_event('certificates', '%s was refused: approving %s (needs cert.approve on %s)'
                        % (entry['by'], row['name'], where), 'warn', who=entry['by'])
        raise E.ApiError(403, 'you may not approve requests of the team %s: its approvers are '
                              'on %s' % (team, where))
    if ok:
        if any(a.get('ok') and _same_person(a, approver) for a in approvals):
            raise E.ApiError(409, 'you approved %s already - the team %s wants another approver'
                             % (row['name'], team))
        done, needed, _c = _evaluate(rule, approvals)
        if who == 'both' and 'team' in needed and 'team' not in levels:
            raise E.ApiError(403, 'an approver of the team %s approves %s first, then one of the '
                                  'team above it' % (team, row['name']))
        if who == 'both' and 'team' not in needed and 'parent' in needed:
            if 'parent' not in levels:
                raise E.ApiError(403, 'the approver of the team %s approved %s - now one of the '
                                      'team above it approves it' % (team, row['name']))
            levels = {'parent'}
        entry['levels'] = sorted(levels & want)
    else:
        entry['levels'] = sorted(levels & want)
    _record(store, row['id'], entry)
    if not ok:
        return {'complete': True, 'needed': [], 'rule': rule}
    approvals.append(entry)
    done, needed, _c = _evaluate(rule, approvals)
    if not done:
        store.add_event('certificates', '%s approved %s for the team %s - it waits for %s more '
                        'approval(s) (%s)' % (entry['by'], row['name'], team, len(needed) or 1,
                                              ', '.join(needed)), who=entry['by'])
        notify_approvers(store, row['id'], team, needed)
    return {'complete': done, 'needed': needed, 'rule': rule}


def may_approve_now(store, row, approver):
    """(whether this person may approve the request now, why not) - said before, as the
    lists offer it."""
    rule = rule_for(store, row)
    if not rule:
        return True, ''
    try:
        levels = levels_of(store, rule['team'], approver)
        who = rule.get('approvers') or 'team'
        want = {'team': {'team'}, 'parent': {'parent'}}.get(who, {'team', 'parent'})
        if not levels & want:
            return False, 'its approvers are on another team'
        st = approval_state(store, row)
        if any(a.get('ok') and _same_person(a, approver) for a in st['approvals']):
            return False, 'you approved it already - another approver is wanted'
        if who == 'both' and 'team' in st['needed'] and 'team' not in levels:
            return False, 'an approver of the team approves it first'
        if who == 'both' and 'team' not in st['needed'] and 'parent' in st['needed'] and \
                'parent' not in levels:
            return False, 'the team approved it - now an approver of the team above it'
    except E.ApiError as e:
        return False, str(e)
    return True, ''


def waiting_for(store, approver, limit=500):
    """The requests waiting that this person may approve now ("Waiting for you"):
    [{id, name, owner, names, asked_by, at, needed, approvals}]."""
    from acmelib.certs import portal as P
    out = []
    ids = {str(x).lower() for x in approver.get('ids') or []}
    caps = approver.get('caps') or {}
    for r in store.db.rows('SELECT * FROM certs WHERE state = ? ORDER BY state_at', (P.WAITING,)):
        k = _low(r.get('owner'))
        if not approver.get('all'):
            tr = T.tree(store)
            near = {k} | ({tr.parent.get(k)} if tr.parent.get(k) else set())
            if not any(_may_on(approver, x) for x in near if x):
                continue
            if k not in caps and not any(x in caps for x in near if x):
                continue
        if P.askers_of(store, r['id']) & ids and not self_allowed(store, r):
            continue
        ok, _why = may_approve_now(store, r, approver)
        if not ok:
            continue
        a = P.asker(store, r['id'])
        st = approval_state(store, r)
        out.append({'id': r['id'], 'name': r['name'], 'owner': r.get('owner') or '',
                    'names': S.jload(r.get('names'), []) or [], 'asked_by': a.get('who') or '',
                    'at': a.get('at') or r.get('created'), 'profile': a.get('profile') or '',
                    'needed': st['needed'], 'approvals': st['approvals']})
        if len(out) >= limit:
            break
    return out


def timeline(store, cid):
    """What happened to a request, in order: [{at, what, by, why}] - asked, each approval or
    decline, approved, issued."""
    from acmelib.certs import portal as P
    row = S.cert_get(store, cid)
    if not row:
        return []
    a = P.asker(store, cid)
    out = []
    if a.get('who') or str(row.get('created_by') or '').startswith('portal:'):
        out.append({'at': a.get('at') or row.get('created'), 'what': 'asked',
                    'by': a.get('who') or row.get('created_by') or '', 'why': a.get('note') or '',
                    'profile': a.get('profile') or ''})
    for x in a.get('approvals') or []:
        if isinstance(x, dict):
            out.append({'at': x.get('at'), 'what': 'approved' if x.get('ok') else 'declined',
                        'by': x.get('by') or '', 'why': x.get('why') or '',
                        'levels': x.get('levels') or []})
    ap = a.get('approved')
    if isinstance(ap, dict):
        out.append({'at': ap.get('at'), 'what': 'let through', 'by': ap.get('by') or '',
                    'why': ''})
    for v in store.db.rows('SELECT version, created, why, by_who FROM cert_versions WHERE '
                           'cert_id = ? ORDER BY version', (cid,)):
        out.append({'at': v.get('created'), 'what': 'issued', 'by': v.get('by_who') or '',
                    'why': v.get('why') or '', 'version': v.get('version')})
    out.sort(key=lambda e: float(e.get('at') or 0))
    return out


# ---------------------------------------------------------------------------
# Telling the approvers
# ---------------------------------------------------------------------------
ASK_WORDS = {
    'en': ('A request of the team %(team)s waits for your approval',
           '%(what)s waits for an approval by %(level)s.\n\n  %(names)s\n\nApprove or decline '
           'it on the portal (%(url)s), "Waiting for you".'),
    'cs': ('Žádost týmu %(team)s čeká na vaše schválení',
           '%(what)s čeká na schválení: %(level)s.\n\n  %(names)s\n\nSchvalte ji nebo zamítněte '
           'na portálu (%(url)s), "Čeká na vás".'),
}


def notify_approvers(store, cid, team, needed):
    """A mail to the contact addresses of the teams whose approvers are wanted (the team, the
    team above it), and an event. Never raises; a thread of its own."""
    tr = T.tree(store)
    k = _low(team)
    targets = []
    for lv in needed or ['team']:
        if lv in ('team', 'team_or_parent') and k in tr.rows:
            targets.append((tr.rows[k]['name'], 'an approver of the team %s' % tr.rows[k]['name']))
        if lv in ('parent', 'team_or_parent') and tr.parent.get(k):
            p = tr.rows[tr.parent[k]]['name']
            targets.append((p, 'an approver of the team %s (above %s)' % (p, team)))
    seen, todo = set(), []
    for t, lvl in targets:
        if t.lower() not in seen:
            seen.add(t.lower())
            todo.append((t, lvl))
    if not todo:
        return

    def go():
        from acmelib.certs import portal as P
        try:
            row = S.cert_get(store, cid)
            if not row:
                return
            for t, lvl in todo:
                store.add_event('certificates', '%s waits for %s' % (row['name'], lvl), 'info')
                to = T.contact_mails(store, {'owner': t})
                if not to:
                    continue
                if (E.CONFIG.get('mail_mode') or 'off') == 'off':
                    E.log('the teams would have mailed %s (%s waits): mail is switched off'
                          % (', '.join(to), row['name']))
                    continue
                subject, body = ASK_WORDS.get(str(E.CONFIG.get('ui_lang') or 'cs'),
                                              ASK_WORDS['en'])
                site = str(E.CONFIG.get('portal_title') or E.CONFIG.get('site_name') or 'acme')
                fill = {'team': team, 'what': row['name'], 'level': lvl, 'url': P.portal_url(),
                        'names': ', '.join(S.jload(row.get('names'), []) or [])}
                from email.message import EmailMessage
                msg = EmailMessage()
                msg['Subject'] = subject % fill
                msg['From'] = E.mail_sender() or 'acme@%s' % E.node_name()
                msg['To'] = ', '.join(to)
                msg.set_content((body % fill) + '\n\n-- acme, %s\n' % site)
                try:
                    E.mail_deliver(store, msg, to, kind='certs', name=t,
                                   purpose='team approval wanted')
                except E.MailError as e:
                    if getattr(e, 'queued', None) != 'waiting':
                        raise
        except Exception as e:                          # noqa: BLE001
            E.log('the teams could not tell the approvers of %s: %s' % (cid, e), 'warn')
    threading.Thread(target=go, name='team-approvers-mail', daemon=True).start()


def request_started_waiting(store, cid, owner):
    """A request of a team with an approval rule began to wait: its approvers are told."""
    row = S.cert_get(store, cid)
    rule = rule_for(store, row) if row else None
    if not rule:
        return
    first = 'team' if rule['approvers'] in ('team', 'both') else rule['approvers']
    notify_approvers(store, cid, rule['team'], [first])


# ---------------------------------------------------------------------------
# Other actions waiting for an approval (policy approve_actions)
# ---------------------------------------------------------------------------
def action_needs_approval(store, team, action):
    """Whether `action` (revoke, delete, key, device) of the team waits for an approval."""
    team = team_name(store, team)
    if not team:
        return False
    return action in (_eff(store, team).get('approve_actions') or [])


def _action_get(store, aid):
    if not isinstance(aid, str) or not aid.isalnum() or len(aid) > 24:
        return None
    got = S.jload(store.get_meta(ACTION_META + aid), None)
    return got if isinstance(got, dict) else None


def action_ask(store, team, action, ref, asker, words=''):
    """An action waiting for an approval -> its record {id, team, action, ref, by, ids, at,
    state 'waiting', approvals}. `asker` as approver_*() gives."""
    if action not in T.APPROVE_ACTIONS:
        raise E.ApiError(400, 'the action is one of %s' % ', '.join(T.APPROVE_ACTIONS))
    team = team_name(store, team)
    if not team:
        raise E.ApiError(404, 'there is no team %s' % team)
    aid = secrets.token_hex(8)
    rec = {'id': aid, 'team': team, 'action': action, 'ref': ref, 'words': str(words)[:500],
           'by': str(asker.get('by') or '?')[:190],
           'ids': [str(x)[:400] for x in (asker.get('ids') or [])][:20], 'at': time.time(),
           'state': 'waiting', 'approvals': []}
    store.set_meta(ACTION_META + aid, json.dumps(rec, sort_keys=True))
    store.add_event('certificates', '%s asks to %s %s of the team %s - it waits for approval' % (
        rec['by'], action, ref, team), 'warn', who=rec['by'])
    rule = T.approval_rule(_eff(store, team))
    notify_approvers_action(store, rec, rule)
    return rec


def notify_approvers_action(store, rec, rule):
    try:
        store.add_event('certificates', 'the team %s: "%s %s" waits for %s' % (
            rec['team'], rec['action'], rec['ref'], rule.get('approvers') or 'team'), 'info')
    except Exception:                                   # noqa: BLE001
        pass


def action_approve(store, aid, approver, ok, why=''):
    """One approval (or decline) of a waiting action -> the record, `state` 'approved' once its
    team's rule is met (the caller then does it), 'declined', or still 'waiting'."""
    rec = _action_get(store, aid)
    if not rec:
        raise E.ApiError(404, 'there is no such action waiting')
    if rec.get('state') != 'waiting':
        raise E.ApiError(409, 'it is %s already' % rec.get('state'))
    rule = T.approval_rule(_eff(store, rec['team']))
    rule['team'] = rec['team']
    if _same_person({'ids': rec.get('ids'), 'by': rec.get('by')}, approver) and \
            not rule.get('self'):
        raise E.ApiError(403, 'you asked for it yourself - someone else approves it')
    levels = levels_of(store, rec['team'], approver)
    who = rule.get('approvers') or 'team'
    want = {'team': {'team'}, 'parent': {'parent'}}.get(who, {'team', 'parent'})
    # only at the level its rule names (hunt C1: a lead of the team declined - or approved, and
    # was counted - an action whose rule wants the team above)
    levels = levels & want
    if not levels:
        raise E.ApiError(403, 'you may not approve for the team %s: its approvers are on %s' % (
            rec['team'], {'team': 'the team itself', 'parent': 'the team above it'}.get(
                who, 'the team or the team above it')))
    if ok and who == 'both':
        done, needed, _c = _evaluate(rule, [a for a in rec.get('approvals') or []
                                            if isinstance(a, dict)])
        if 'team' in needed and 'team' not in levels:
            raise E.ApiError(403, 'an approver of the team %s approves it first, then one of the '
                                  'team above it' % rec['team'])
        if 'team' not in needed and 'parent' in needed:
            if 'parent' not in levels:
                raise E.ApiError(403, 'the approver of the team %s approved it - now one of the '
                                      'team above it approves it' % rec['team'])
            levels = {'parent'}
    if ok and any(a.get('ok') and _same_person(a, approver) for a in rec['approvals']):
        raise E.ApiError(409, 'you approved it already - another approver is wanted')
    rec['approvals'].append({'by': str(approver.get('by') or '?')[:190], 'at': time.time(),
                             'ok': bool(ok), 'why': str(why or '')[:500],
                             'ids': [str(x)[:400] for x in (approver.get('ids') or [])][:20],
                             'levels': sorted(levels)})
    if not ok:
        rec['state'] = 'declined'
    else:
        done, needed, _c = _evaluate(rule, rec['approvals'])
        rec['needed'] = needed
        if done:
            rec['state'] = 'approved'
    store.set_meta(ACTION_META + aid, json.dumps(rec, sort_keys=True))
    store.add_event('certificates', '%s %s "%s %s" of the team %s%s' % (
        approver.get('by'), 'approved' if ok else 'declined', rec['action'], rec['ref'],
        rec['team'], '' if rec['state'] != 'waiting' else ' - it waits for more'),
        who=str(approver.get('by') or ''))
    return rec


def may_approve_action_now(store, rec, approver):
    """Whether this person may approve the waiting action now - as action_approve would take
    it: the level its rule names, the team's lead first where both approve, never twice, never
    one's own unless the rule lets the asker."""
    rule = T.approval_rule(_eff(store, rec.get('team')))
    if _same_person({'ids': rec.get('ids'), 'by': rec.get('by')}, approver) and \
            not rule.get('self'):
        return False
    who = rule.get('approvers') or 'team'
    want = {'team': {'team'}, 'parent': {'parent'}}.get(who, {'team', 'parent'})
    levels = levels_of(store, rec.get('team'), approver) & want
    if not levels:
        return False
    approvals = [a for a in rec.get('approvals') or [] if isinstance(a, dict)]
    if any(a.get('ok') and _same_person(a, approver) for a in approvals):
        return False
    if who == 'both':
        _done, needed, _c = _evaluate(rule, approvals)
        if 'team' in needed and 'team' not in levels:
            return False
        if 'team' not in needed and 'parent' in needed and 'parent' not in levels:
            return False
    return True


def action_take(store, aid, said=''):
    """An approved action taken by its asker once (the key): kept as done in one compare-and-swap
    -> the record as it was, or None when it was not approved (any more) - two downloads at once
    with the same approval took the key twice (hunt C1)."""
    k = ACTION_META + str(aid)
    raw = store.get_meta(k)
    rec = S.jload(raw, None)
    if not isinstance(rec, dict) or rec.get('state') != 'approved':
        return None
    new = dict(rec, state='done', done={'at': time.time(), 'said': str(said)[:300]})
    with store.db.transaction():
        n = store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                         (json.dumps(new, sort_keys=True), k, raw))
        if n and E.dbguard_meta_signed(k):
            E.dbguard_sign(store.db, 'm', k, json.dumps(new, sort_keys=True))
    return rec if n else None


def action_untake(store, aid, rec):
    """The key could not be made after all: the approval stands again."""
    if isinstance(rec, dict):
        store.set_meta(ACTION_META + str(aid), json.dumps(dict(rec, state='approved'),
                                                          sort_keys=True))


def actions_follow(store, old, new):
    """The actions of a team renamed (new) follow it; of a team deleted (None) those waiting are
    declined - nobody may approve them any more (hunt C1: they stayed waiting, for nobody)."""
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'teams:action:%'"):
        rec = S.jload(r['v'], None)
        if not isinstance(rec, dict) or _low(rec.get('team')) != _low(old):
            continue
        if new:
            rec['team'] = new
        elif rec.get('state') == 'waiting':
            rec['state'] = 'declined'
            rec['done'] = {'at': time.time(), 'said': 'the team %s was deleted' % old}
        else:
            continue
        store.set_meta(r['k'], json.dumps(rec, sort_keys=True))


def action_done(store, aid, said=''):
    """The caller did an approved action: kept as done."""
    rec = _action_get(store, aid)
    if rec and rec.get('state') == 'approved':
        rec['state'] = 'done'
        rec['done'] = {'at': time.time(), 'said': str(said)[:300]}
        store.set_meta(ACTION_META + aid, json.dumps(rec, sort_keys=True))
    return rec


def actions(store, team=None, state=None):
    """The actions waiting (or done) - of a team and the teams below it, newest first; those
    older than ACTION_KEEP_S that are no longer waiting forgotten."""
    tr = T.tree(store)
    want = None
    if team:
        want = {_low(team)} | set(tr.descendants(team))
    out = []
    now = time.time()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'teams:action:%'"):
        rec = S.jload(r['v'], None)
        if not isinstance(rec, dict):
            continue
        if rec.get('state') != 'waiting' and now - float(rec.get('at') or 0) > ACTION_KEEP_S:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            continue
        if want is not None and _low(rec.get('team')) not in want:
            continue
        if state and rec.get('state') != state:
            continue
        out.append(rec)
    out.sort(key=lambda x: -float(x.get('at') or 0))
    return out


# ---------------------------------------------------------------------------
# Directory groups matched by a pattern (Teams from directory groups)
# ---------------------------------------------------------------------------
def group_pattern(text):
    """'CN=PKI-*' or 'PKI-*' -> the cn pattern (fnmatch, case-insensitive)."""
    t = str(text or '').strip()
    if t.lower().startswith('cn='):
        t = t[3:]
    t = t.split(',', 1)[0].strip()
    if not t or len(t) > 200 or any(ord(c) < 32 for c in t):
        raise E.ApiError(400, 'the filter is a group\'s name, * for any letters: PKI-*')
    return t


def matches_pattern(cn, pattern):
    return fnmatch.fnmatchcase(_low(cn), _low(pattern))
