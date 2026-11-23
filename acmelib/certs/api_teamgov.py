# -*- coding: utf-8 -*-
"""
The governance of teams in the administration (1.0.138, docs/teams.md "Governance") - the routes
(all under /api/teams/, relayed by admin/index.php as the other routes of the teams are):

    GET  /api/teams/whomay?who=|team=        who may do what and why: a person's matrix, or a
                                             team's people (certificate administrator)
    GET  /api/teams/whocan?cap=&team=|cert=  the reverse: who may `cap` there, and why
    GET  /api/teams/view_as                  whether this sign-in views as somebody (the banner)
    POST /api/teams/view_as {who}            view the administration as `who`, read-only (full)
    POST /api/teams/view_as_stop             stop it
    POST /api/teams/view_as_portal {who}     a one-time link that opens the portal as `who` (full)
    GET  /api/teams/elevations[?team=]       requests for a temporary role: mine, mine to decide,
                                             the team's
    POST /api/teams/elevate {team, role, hours, reason}
    POST /api/teams/elevate_decide {id, ok, why}       never one's own; team.members
    POST /api/teams/elevate_end {id}
    GET  /api/teams/reviews?team=            the access reviews of a team (its history)
    POST /api/teams/review_open {team}       (full, or team.members on it)
    POST /api/teams/review_answer {id, who, keep, note}
    POST /api/teams/governance {team, review?, jit?, sod?, notify?}   (full)
    POST /api/teams/hooks {team, teams?, slack?}   webhooks, kept sealed, never shown (full)
    POST /api/teams/notify_test {team}       every channel tried now (full)
    GET  /api/teams/health[?team=]           the teams' health (the lists of one team)
    GET  /api/teams/templates                the templates of teams
    POST /api/teams/template_save {name, old_name?, description, config | from_team, members}
    POST /api/teams/template_delete {name}
    POST /api/teams/from_template {template, name, parent}
    POST /api/teams/import_csv {csv, dry_run}
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import teams as T
from acmelib.certs import teamaccess as TA
from acmelib.certs import teamgov as G
from acmelib.certs import viewas as VA


def _seen(h, s):
    return T.scope(h.store, s, 'view')


def _need_seen(h, s, team):
    t = T.team_get(h.store, team)
    if not t:
        raise LookupError('there is no team %s' % str(team)[:120])
    seen = _seen(h, s)
    if seen is not None and not T.owner_in(seen, t['name']):
        raise E.ApiError(403, 'you may not see the team %s' % t['name'])
    return t['name']


def _full(s):
    return s.get('role') == 'fulladmin' or bool(s.get('cli'))


# ---- who may do what ----------------------------------------------------------------------
@A.api('GET', '/api/teams/whomay', 'certadmin')
def _whomay(h, s):
    seen = _seen(h, s)
    if h.arg('team'):
        team = _need_seen(h, s, h.arg('team'))
        got = TA.team_matrix(h.store, team)
        got['mode'] = 'team'
        return got
    from acmelib.certs import api_teams as AT
    names, groups, found = AT.principal_of(h, h.arg('who'), h.arg('directory') or None)
    got = TA.person_matrix(h.store, names, groups, seen)
    acc = None
    try:
        w = str(h.arg('who') or '')
        acc = h.store.account(w[6:] if w.lower().startswith('local:') else w)
    except Exception:                                   # noqa: BLE001
        acc = None
    got.update(mode='person', who=found, groups_count=len(groups),
               groups=sorted({cn for _dn, cn in groups}, key=str.lower)[:200],
               account={'name': acc['name'], 'role': acc.get('role'),
                        'disabled': bool(acc.get('disabled'))} if acc else None,
               settings=TA.certadmin_note())
    return got


@A.api('GET', '/api/teams/whocan', 'certadmin')
def _whocan(h, s):
    limited = _seen(h, s) is not None
    try:
        got = TA.who_can(h.store, h.arg('cap'), team=h.arg('team') or None,
                         cert=h.arg('cert') or None)
    except LookupError:
        if h.arg('cert') and limited:
            # the same answer for "there is no such certificate" as for "you may not see it" -
            # a 404 told one who sees a part which names exist (1.0.141)
            raise E.ApiError(403, 'not a certificate you may see') from None
        raise
    if got.get('team'):
        try:
            _need_seen(h, s, got['team'])
        except (E.ApiError, LookupError):
            if h.arg('cert') and limited:
                # not the owner's name of a certificate one cannot see (1.0.138) - nor whether
                # its owner is a team defined (1.0.141)
                raise E.ApiError(403, 'not a certificate you may see') from None
            raise
    elif limited:
        if h.arg('cert'):
            raise E.ApiError(403, 'not a certificate you may see')
        raise E.ApiError(403, 'a certificate without a team is seen only by those who see every '
                              'certificate')
    return got


# ---- view as ------------------------------------------------------------------------------
@A.api('GET', '/api/teams/view_as')
def _view_as_state(h, s):
    got = VA.public(s)
    return {'active': bool(got), 'view_as': got, 'may': s.get('role') == 'fulladmin'}


@A.api('POST', '/api/teams/view_as', 'fulladmin')
def _view_as(h, s):
    got = VA.start(h, s, h.body().get('who'))
    return {'view_as': got, 'message': 'you see the pages as %s now - read-only' % got['who']}


@A.api('POST', '/api/teams/view_as_stop')
def _view_as_stop(h, s):
    done = VA.stop(h.store, s)
    return {'stopped': done, 'message': 'you see the pages as yourself again' if done else
            'you were not viewing as anybody'}


@A.api('POST', '/api/teams/view_as_portal', 'fulladmin')
def _view_as_portal(h, s):
    got = VA.portal_code(h, s, h.body().get('who'))
    return {'url': got['url'], 'who': got['who']}


# ---- just-in-time elevation -----------------------------------------------------------------
@A.api('GET', '/api/teams/elevations')
def _elevations(h, s):
    actor = G.actor_admin(h.store, s)
    got = G.elevations_for(h.store, actor)
    if h.arg('team'):
        team = _need_seen(h, s, h.arg('team'))
        got['team'] = team
        got['rows'] = G.elevation_rows(h.store, team, below=False)[:200]
        src, rule = G.jit_rule(h.store, team)
        got['rule'] = rule
        got['rule_from'] = src
    # where this person may ask, and for what
    may = []
    for k, v in sorted((actor.get('caps') or {}).items() if not actor['all'] else ()):
        src, rule = G.jit_rule(h.store, v['name'])
        if rule:
            may.append({'team': v['name'], 'roles': rule['roles'],
                        'max_hours': rule['max_hours'], 'from': src})
    got['may_ask'] = may[:500]
    return got


@A.api('POST', '/api/teams/elevate')
def _elevate(h, s):
    b = h.body()
    got = G.elevation_ask(h.store, G.actor_admin(h.store, s), b.get('team'), b.get('role'),
                          b.get('hours'), b.get('reason'))
    return {'elevation': got, 'message': 'asked - a manager of the team %s approves it'
            % got['team']}


@A.api('POST', '/api/teams/elevate_decide')
def _elevate_decide(h, s):
    b = h.body()
    got = G.elevation_decide(h.store, b.get('id'), G.actor_admin(h.store, s),
                             A._flag(b.get('ok')), b.get('why'))
    return {'elevation': got, 'message': 'granted until the time it ends by itself'
            if got['state'] == 'granted' else 'declined'}


@A.api('POST', '/api/teams/elevate_end')
def _elevate_end(h, s):
    got = G.elevation_end(h.store, h.body().get('id'), G.actor_admin(h.store, s))
    return {'elevation': got, 'message': 'ended'}


# ---- access reviews -----------------------------------------------------------------------
@A.api('GET', '/api/teams/reviews')
def _reviews(h, s):
    if not h.arg('team'):
        # the reviews open now in the teams this account sees
        seen = _seen(h, s)
        actor = G.actor_admin(h.store, s)
        rows = [dict(r, may_answer=actor['all'] or 'team.members' in G._caps_on(actor, r['team']))
                for r in G.review_open_rows(h.store) if seen is None or T.owner_in(seen, r['team'])]
        return {'open': rows[:300]}
    team = _need_seen(h, s, h.arg('team'))
    t = T.team_get(h.store, team)
    actor = G.actor_admin(h.store, s)
    return {'team': team, 'rule': G.extras_of(t).get('review'), 'reviews': G.reviews(h.store, team),
            'may_answer': actor['all'] or 'team.members' in G._caps_on(actor, team)}


@A.api('POST', '/api/teams/review_open')
def _review_open(h, s):
    team = h.body().get('team')
    actor = G.actor_admin(h.store, s)
    if not actor['all'] and 'team.members' not in G._caps_on(actor, team):
        raise E.ApiError(403, 'opening a review needs "team.members" on the team')
    got = G.review_open(h.store, team, A.who(s))
    return {'review': got, 'message': 'the review is open'}


@A.api('POST', '/api/teams/review_answer')
def _review_answer(h, s):
    b = h.body()
    got = G.review_answer(h.store, b.get('id'), b.get('who'), A._flag(b.get('keep')),
                          G.actor_admin(h.store, s), b.get('note'))
    return {'review': got, 'message': 'confirmed' if A._flag(b.get('keep')) else 'taken out'}


# ---- the settings of a team's governance ------------------------------------------------------
@A.api('POST', '/api/teams/governance', 'fulladmin')
def _governance(h, s):
    b = h.body()
    t = T.team_get(h.store, b.get('team'))
    if not t:
        raise LookupError('there is no team %s' % str(b.get('team'))[:120])
    for k in G.EXTRA_KEYS:
        if k in b:
            G.set_extras(h.store, t['name'], k, b.get(k), A.who(s))
    t = T.team_get(h.store, t['name'])
    # the memberships that hold both sides of a pair now (the rule holds for what is changed
    # from now on; these are said, not taken away)
    clash = []
    cat = T.role_catalog(h.store)
    for name in [t['name']] + T.descendants(h.store, t['name']):
        row = T.team_get(h.store, name)
        for m in G.S.jload((row or {}).get('members'), []) or []:
            if isinstance(m, dict):
                bad = G.sod_conflicts(h.store, name, T.member_caps(m, cat))
                if bad:
                    clash.append({'team': name, 'who': m.get('who'), 'pair': list(bad[0][:2])})
    return {'gov': G.public_extras(t), 'clash': clash[:200],
            'message': 'the governance of %s is saved' % t['name']}


@A.api('POST', '/api/teams/hooks', 'fulladmin')
def _hooks(h, s):
    b = h.body()
    got = G.set_hooks(h.store, b.get('team'), b, A.who(s))
    return {'hooks': got, 'message': 'the webhooks are saved'}


@A.api('POST', '/api/teams/notify_test', 'fulladmin')
def _notify_test(h, s):
    return G.notify_test(h.store, h.body().get('team'))


# ---- health ----------------------------------------------------------------------------
@A.api('GET', '/api/teams/health')
def _health(h, s):
    seen = _seen(h, s)
    team = _need_seen(h, s, h.arg('team')) if h.arg('team') else None
    rows = G.health_public(h.store, seen, detail_team=team)
    return {'teams': rows, 'score': G.summary_score(rows), 'team': team,
            'days': int(E.CONFIG.get('certs_notify_days') or 14)}


# ---- templates and bulk import ----------------------------------------------------------------
@A.api('GET', '/api/teams/templates', 'fulladmin')   # members may be in them
def _templates(h, s):
    return {'templates': G.templates(h.store), 'columns': list(G.CSV_COLS)}


@A.api('POST', '/api/teams/template_save', 'fulladmin')
def _template_save(h, s):
    got = G.save_template(h.store, h.body(), A.who(s))
    return {'template': got, 'message': 'the template %s is saved' % got['name']}


@A.api('POST', '/api/teams/template_delete', 'fulladmin')
def _template_delete(h, s):
    got = G.delete_template(h.store, h.body().get('name'), A.who(s))
    got['message'] = 'the template %s is deleted' % got['deleted']
    return got


@A.api('POST', '/api/teams/from_template', 'fulladmin')
def _from_template(h, s):
    b = h.body()
    got = G.team_from_template(h.store, b.get('template'), b.get('name'), b.get('parent') or None,
                               A.who(s))
    return {'team': got, 'message': 'the team %s is made' % got['name']}


@A.api('POST', '/api/teams/import_csv', 'fulladmin')
def _import_csv(h, s):
    b = h.body()
    got = G.import_csv(h.store, b.get('csv'), A.who(s),
                       dry_run=b.get('dry_run') in (True, 1, '1', 'true'))
    got['message'] = ('%d team(s) made' % len(got['made'])) if got['made'] else \
        'nothing made (a preview)'
    return got
