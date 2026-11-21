# -*- coding: utf-8 -*-
"""
The team workspace of the certificate portal (1.0.125, docs/certificate-portal.md "Teams",
docs/teams.md "Enterprise teams"): what a person signed in on the portal does for the teams
they are a member of - and the teams below them. Every route checks the person's capability
on the team (teams.person_caps: their memberships, by name or a directory group, inherited
downwards) and the team's limits (teampolicy); a refusal is 403 in words and an event.

    GET  /api/portal/teams                  their teams: caps, limits, counts, children
    GET  /api/portal/inbox                  what waits for them: requests, actions (timelines)
    GET  /api/portal/timeline?id=           one request of theirs: what happened to it
    POST /api/portal/action_approve         {id, ok, why}  an action that waits (approve_actions)
    GET  /api/portal/devices?team=[&below=1]   the team's devices (targets it owns)
    GET  /api/portal/device?id=             one device: its settings, secrets set / not set
    POST /api/portal/device_save            {id?, team, name, kind, config, note, enabled, tags}
    POST /api/portal/device_delete          {id}
    POST /api/portal/device_test            {id}
    GET  /api/portal/kinds?team=            the modules the team may use, with their fields
    GET  /api/portal/tests?team=[&below=1]  the team's tests (1.0.128) - test.view
    GET  /api/portal/test?id=               one test: its settings, secrets set / not set
    GET  /api/portal/test_kinds?team=       the test modules the team may use (test_kinds)
    POST /api/portal/test_save              {id?, team, name, kind, config, note, enabled}
    POST /api/portal/test_delete            {id}                      - test.manage
    POST /api/portal/test_run               {id}
    GET  /api/portal/policy_catalog?team=   the sources and validations to pair (team.policy)
    POST /api/portal/agent_code             {id}   a one-time join code of a team's agent target
    POST /api/portal/enroll_code            {team, title, mode, port, days, most, auto}
    POST /api/portal/enroll_revoke          {id}
    GET  /api/portal/agents_waiting?team=   agents asking to join, the team's enrollment codes
    POST /api/portal/agent_confirm          {id, fp}
    POST /api/portal/agent_refuse           {id}
    GET  /api/portal/agent?id=              the agent: its state, the server's facts
    GET  /api/portal/agent_builder?id=      the policy builder's data
    POST /api/portal/agent_design           {id, text, design_state, title, note}
    POST /api/portal/agent_update           {id}
    GET  /api/portal/deploys?team=          the deployments of the team's certificates
    POST /api/portal/deploy_save            {id?, cert_id, target, options, enabled, note}
    POST /api/portal/deploy_delete          {id}
    POST /api/portal/deploy_run             {id}
    POST /api/portal/deploy_dry_run         {id, test?}  What happens (or the module's test)
    GET  /api/portal/members?team=          the team's members, what may be given
    POST /api/portal/member_save            {team, who, roles, rights, until, note}
    POST /api/portal/member_delete          {team, who}
    GET  /api/portal/dir_search?q=&kind=    the directory, for the member picker (20 at most)
    POST /api/portal/team_save              {name, old_name?, parent, kind, description, policy}
    POST /api/portal/team_delete            {name, reparent?, reassign?}
    GET  /api/portal/activity?team=&page=   what happened in the team

The administration's own functions do the work (api.family_save / family_delete /
family_test, api.deploy_save, the agents' and teams' functions) - their checks are the
same; only who may is decided here. A person in no team: every route here answers as for
nobody (no teams, 403), the rest of the portal is as before.
"""
from __future__ import annotations

import json
import re
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import api as A
from acmelib.certs import portal as P
from acmelib.certs import teams as T
from acmelib.certs import teampolicy as TP
from acmelib.plugins.base import PluginError

PREFIX = '/api/portal/'
# modules never made by a team on the portal, whatever its limits say: `local` writes files
# on acme's own server
NEVER_KINDS = ('local',)
AGENT_KINDS = ('agent', 'agent_windows')
DIR_MOST = 20
ACTIVITY_PER = 50


def _low(v):
    return str(v or '').strip().lower()


class _H(object):
    """The request with another body - for the administration's own route functions."""
    def __init__(self, h, body):
        self._h = h
        self._b = body

    def body(self):
        return self._b

    def __getattr__(self, n):
        return getattr(self._h, n)


def route(method, name):
    """A route of the team workspace: errors of the functions it calls in words (404, 400)."""
    def wrap(fn):
        def run(h):
            try:
                return fn(h)
            except E.ApiError:
                raise
            except LookupError as e:
                raise E.ApiError(404, str(e).strip('\'"'))
            except PluginError as e:
                raise E.ApiError(400, str(e), detail=e.detail or '')
            except ValueError as e:
                raise E.ApiError(400, str(e))
        run.__name__ = 'portal_' + name
        E.route(method, PREFIX + name)(run)
        return fn
    return wrap


class Me(object):
    """A portal sign-in and what it holds on which team - read once per request."""
    def __init__(self, h):
        self.h = h
        self.store = h.store
        self.s = P.portal_session(h)
        self.name = str(self.s['name'])
        self.by = P.portal_by(self.s)
        self.names = P.my_names(self.s)
        self.groups = P.my_groups(h, self.s)
        self.all = bool(E.portal_sees_all(self.s))
        self.pc = T.person_caps(self.store, self.names, self.groups)
        self.tr = T.tree(self.store)

    def admin(self):
        """A session of the administration for its route functions: a certificate
        administrator (never a full one - the scripts, commands and key places stay theirs)."""
        return {'name': self.by, 'role': 'certadmin', 'portal': True}

    def caps(self, team):
        k = _low(team)
        if k not in self.tr.rows:
            return frozenset()
        if self.all:
            return frozenset(T.CAPS)
        return (self.pc.get(k) or {}).get('caps') or frozenset()

    def reach(self, cap=None):
        """[lower] of the teams they hold anything (or `cap`) on, top-down."""
        if self.all:
            return list(self.tr.order)
        return [k for k in self.tr.order if k in self.pc and (cap is None or
                                                              cap in self.pc[k]['caps'])]

    def team(self, team):
        """The team's name - 404 for one that is not there or none of theirs."""
        k = _low(team)
        if not k:
            raise E.ApiError(400, 'which team?')
        if k not in self.tr.rows or (not self.all and k not in self.pc):
            raise E.ApiError(404, 'there is no team %s of yours' % str(team)[:120])
        return self.tr.rows[k]['name']

    def need(self, team, cap, doing):
        """The team's name when they hold `cap` there - else 403 in words and an event."""
        name = self.team(team)
        if cap not in self.caps(name):
            self.refused('%s in the team %s (needs %s)' % (doing, name, cap))
            raise E.ApiError(403, 'you may not %s in the team %s - it does not give you "%s" '
                                  '(%s)' % (doing, name, cap, T.CAP_WORDS[cap]))
        return name

    def need_above(self, team, cap, doing):
        """`cap` on a team that may be above all of theirs (the parent of the team acted on):
        refused 403 in words when they do not hold it there - never 404."""
        k = _low(team)
        if k not in self.tr.rows or cap not in self.caps(k):
            name = self.tr.name(k) or str(team)[:120]
            self.refused('%s (needs %s on the team %s)' % (doing, cap, name))
            raise E.ApiError(403, 'you may not %s - that needs "%s" on the team %s above it'
                             % (doing, cap, name))
        return self.tr.rows[k]['name']

    def refused(self, words):
        self.store.add_event('certificates', '%s was refused on the portal: %s' % (
            self.name, words), 'warn', who=self.name)

    def deny(self, words, status=403):
        self.refused(words)
        raise E.ApiError(status, words)

    def below(self, team, cap, h_below=None):
        """{lower} of the team and (below) the teams under it where they hold `cap`."""
        k = _low(team)
        out = {k}
        if h_below:
            out |= {d for d in self.tr.descendants(k) if cap in self.caps(d)}
        return out

    def approver(self):
        return TP.approver_portal(self.h, self.s)


def _flag(h, name):
    return str(h.arg(name) or '') in ('1', 'true', 'yes')


def _page(h, default_per=50, most=200):
    try:
        per = max(1, min(most, int(h.arg('per') or default_per)))
    except (TypeError, ValueError):
        per = default_per
    try:
        page = max(0, min(100000, int(h.arg('page') or 0)))
    except (TypeError, ValueError):
        page = 0
    return page, per


def _ident(v, what='id'):
    return A._id(v, what)


def _clean_approvals(lst):
    """Approvals as a page shows them: who, when, what they said - never the names and DNs an
    approver is known by."""
    return [{k: a.get(k) for k in ('by', 'at', 'ok', 'why', 'levels')}
            for a in lst or [] if isinstance(a, dict)]


def _timeline(store, cid):
    return [{k: v for k, v in e.items() if k != 'ids'} for e in TP.timeline(store, cid)]


# ---------------------------------------------------------------------------
# The teams
# ---------------------------------------------------------------------------
def _grouped(store, sql, args=()):
    out = {}
    try:
        for r in store.db.rows(sql, args):
            out[r['o']] = int(r['n'] or 0)
    except Exception as e:                              # noqa: BLE001
        E.log('the portal\'s team counts: %s' % e, 'warn')
    return out


def counts(store, me, reach):
    """{team lower: {certs, expiring, failing, devices, agents_waiting, waiting_for_me}} - a
    few grouped statements for every team at once."""
    now = time.time()
    certs = T.used_counts(store)
    expiring = _grouped(store, "SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE "
                               "COALESCE(owner, '') <> '' AND not_after > ? AND not_after < ? "
                               "GROUP BY LOWER(TRIM(owner))", (now, now + P.EXPIRING_S))
    failing = _grouped(store, "SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE "
                              "COALESCE(owner, '') <> '' AND (state = 'failed' OR "
                              "COALESCE(alt_state, '') = 'failed') GROUP BY LOWER(TRIM(owner))")
    devices = _grouped(store, "SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM cert_targets "
                              "WHERE COALESCE(owner, '') <> '' GROUP BY LOWER(TRIM(owner))")
    waiting_agents = {}
    see_t = {k for k in reach if 'target.view' in me.caps(k)}
    if see_t:
        from acmelib.certs import agents as G
        try:
            for w in G.waiting(store, teams=see_t):
                o = _low(w.get('owner'))
                waiting_agents[o] = waiting_agents.get(o, 0) + 1
        except Exception as e:                          # noqa: BLE001
            E.log('the portal\'s waiting agents: %s' % e, 'warn')
    mine = {}
    for w in TP.waiting_for(store, me.approver(), limit=2000):
        o = _low(w.get('owner'))
        mine[o] = mine.get(o, 0) + 1
    for rec in inbox_actions(me):
        o = _low(rec.get('team'))
        mine[o] = mine.get(o, 0) + 1
    out = {}
    for k in reach:
        c = me.caps(k)
        one = {}
        if 'cert.view' in c:
            one.update(certs=certs.get(k, 0), expiring=expiring.get(k, 0),
                       failing=failing.get(k, 0))
        if 'target.view' in c:
            one.update(devices=devices.get(k, 0), agents_waiting=waiting_agents.get(k, 0))
        one['waiting_for_me'] = mine.get(k, 0)
        out[k] = one
    return out


@route('GET', 'teams')
def _teams(h):
    me = Me(h)
    reach = me.reach()
    cnt = counts(h.store, me, reach) if reach else {}
    out = []
    for k in reach:
        t = me.tr.rows[k]
        c = me.caps(k)
        one = {'name': t['name'], 'kind': t.get('kind') or 'team',
               'parent': me.tr.name(me.tr.parent[k]) if me.tr.parent.get(k) else None,
               'depth': me.tr.depth(k), 'description': t.get('description') or '',
               'caps': [x for x in T.CAPS if x in c],
               'direct': [x for x in T.CAPS if x in ((me.pc.get(k) or {}).get('direct') or ())],
               'policy': me.tr.effective(k),
               'children': [me.tr.rows[x]['name'] for x in me.tr.children.get(k, [])],
               'counts': cnt.get(k, {})}
        if 'team.view' in c:
            one['own_policy'] = me.tr.policies.get(k) or {}
            one['members'] = len([m for m in S.jload(t.get('members'), []) or []
                                  if isinstance(m, dict)])
            one['contact_mail'] = t.get('contact_mail') or ''
        out.append(one)
    return {'teams': out, 'sees_all': me.all, 'in_teams': bool(out),
            'caps': T.caps_catalog(),
            'kinds': list(T.KINDS[:1]) + ['unit'],
            'approval_modes': list(T.APPROVAL_MODES), 'approvers': list(T.APPROVERS),
            'approve_actions': list(T.APPROVE_ACTIONS), 'policy_keys': list(T.POLICY_KEYS)}


# ---------------------------------------------------------------------------
# What waits for them
# ---------------------------------------------------------------------------
def inbox_actions(me):
    """The actions waiting (approve_actions) this person may approve now."""
    ap = me.approver()
    out = []
    for rec in TP.actions(me.store, state='waiting'):
        team = rec.get('team')
        if _low(team) not in me.tr.rows:
            continue
        # as action_approve takes it (hunt C1: offered to a lead of the team where the rule
        # wants the team above - and refused)
        if not TP.may_approve_action_now(me.store, rec, ap):
            continue
        out.append(rec)
    return out


def _action_public(store, rec):
    out = {k: rec.get(k) for k in ('id', 'team', 'action', 'ref', 'words', 'by', 'at', 'state',
                                   'needed', 'reason', 'again', 'done')}
    out['approvals'] = _clean_approvals(rec.get('approvals'))
    if rec.get('action') in ('revoke', 'delete', 'key'):
        r = S.cert_get(store, rec.get('ref')) if str(rec.get('ref') or '').isdigit() else None
        out['what'] = r['name'] if r else '?'
    elif rec.get('action') == 'device':
        r = S.plugin_row(store, 'target', rec.get('ref')) if rec.get('ref') else None
        out['what'] = r['name'] if r else '?'
    return out


@route('GET', 'inbox')
def _inbox(h):
    me = Me(h)
    ap = me.approver()
    reqs = []
    for w in TP.waiting_for(h.store, ap, limit=500):
        w = dict(w)
        w['approvals'] = _clean_approvals(w.get('approvals'))
        w['timeline'] = _timeline(h.store, w['id'])
        # whether the one who asked is told by mail (its Decline says so - hunt U4)
        w['told_by_mail'] = P.told_by_mail(h.store, w['id'])
        reqs.append(w)
    acts = [_action_public(h.store, r) for r in inbox_actions(me)]
    # what they asked for that waits (or was answered): their requests and actions
    ids = set(P.asker_ids(me.s))
    asked = []
    for r in h.store.db.rows('SELECT id, name, owner, names, state FROM certs WHERE state = ? '
                             'ORDER BY state_at', (P.WAITING,)):
        if P.askers_of(h.store, r['id']) & ids:
            st = TP.approval_state(h.store, r)
            asked.append({'id': r['id'], 'name': r['name'], 'owner': r.get('owner') or '',
                          'names': S.jload(r.get('names'), []) or [], 'needed': st['needed'],
                          'approvals': _clean_approvals(st['approvals']),
                          'timeline': _timeline(h.store, r['id'])})
    mine_acts = [_action_public(h.store, r) for r in TP.actions(h.store)
                 if TP._same_person({'ids': r.get('ids'), 'by': r.get('by')}, ap)][:100]
    return {'requests': reqs, 'actions': acts, 'asked': asked, 'asked_actions': mine_acts,
            'count': len(reqs) + len(acts)}


@route('GET', 'timeline')
def _timeline_route(h):
    me = Me(h)
    row = P.need_mine(h, me.s, h.arg('id'))
    st = TP.approval_state(h.store, row)
    rule = st.get('rule')
    return {'id': row['id'], 'name': row['name'], 'state': row.get('state'),
            'timeline': _timeline(h.store, row['id']), 'rule': rule,
            'approvals': _clean_approvals(st['approvals']), 'needed': st['needed']}


def do_action(me, rec):
    """An action approved in full done as its asker asked -> words."""
    store = me.store
    act = rec.get('action')
    by = '%s (approved by %s)' % (rec.get('by') or '?', me.by)
    try:
        if act == 'key':
            # the person by name (hunt U4: "portal:jan may take the key now")
            return 'approved - %s may take the key now' % re.sub(
                r'^(local|portal):', '', str(rec.get('by') or '?'), flags=re.I)
        if act in ('revoke', 'delete'):
            row = S.cert_get(store, int(rec.get('ref') or 0))
            if not row:
                TP.action_done(store, rec['id'], 'the certificate is gone')
                return 'the certificate is gone - nothing to do'
            if act == 'revoke':
                reason = str(rec.get('reason') or 'unspecified')
                again = bool(rec.get('again'))
                P.revoke_checked(row, reason, again)
                job = P.start_revoke(store, row, reason, again, by)
                store.add_event('certificates', '%s revokes %s from the portal (%s), approved '
                                'by %s' % (rec.get('by'), row['name'], reason, me.name), 'warn',
                                who=me.name)
                TP.action_done(store, rec['id'], 'revoking: job %s' % job)
                return 'approved - %s is being revoked' % row['name']
            from acmelib.certs import jobs
            if jobs.cert_busy(store, row['id']):
                raise E.ApiError(409, 'a job is working on %s - approve it again when it ends'
                                 % row['name'])
            A.cert_drop(store, row, by)
            TP.action_done(store, rec['id'], 'deleted')
            return 'approved - %s is deleted' % row['name']
        if act == 'device':
            row = S.plugin_row(store, 'target', int(rec.get('ref') or 0))
            if not row:
                TP.action_done(store, rec['id'], 'the device is gone')
                return 'the device is gone - nothing to do'
            A.family_delete(store, 'target', {'id': row['id']}, by)
            TP.action_done(store, rec['id'], 'deleted')
            return 'approved - the device %s is deleted' % row['name']
    except (ValueError, LookupError) as e:
        TP.action_done(store, rec['id'], 'not done: %s' % e)
        return 'approved, but it could not be done: %s' % e
    return 'approved'


@route('POST', 'action_approve')
def _action_approve(h):
    me = Me(h)
    b = h.body()
    rec = TP._action_get(h.store, str(b.get('id') or ''))
    if not rec:
        raise E.ApiError(404, 'there is no such action waiting')
    me.team(rec.get('team'))
    ok = A._flag(b.get('ok'))
    why = str(b.get('why') or '').strip()[:500]
    if not ok and not why:
        raise E.ApiError(400, 'say why it is declined - the person who asked is told')
    before = dict(rec)
    rec = TP.action_approve(h.store, rec['id'], me.approver(), ok, why)
    said = ''
    if rec.get('state') == 'approved':
        try:
            said = do_action(me, rec)
        except E.ApiError:
            # not done (a job working on the certificate, a revocation refused): it waits as
            # before this approval, to be approved again - kept 'approved', it was never done
            # and every approval after was refused ("it is approved already")
            h.store.set_meta(TP.ACTION_META + before['id'], json.dumps(before, sort_keys=True))
            raise
        rec = TP._action_get(h.store, rec['id']) or rec
    elif rec.get('state') == 'declined':
        # no mail is sent for a team's action: the person who asked sees it, with the reason,
        # in the team's actions
        said = 'declined - %s sees why in the team\'s actions' % (
            str(rec.get('by') or '?').split('portal:', 1)[-1])
    else:
        said = 'your approval is recorded - it waits for %d more' % (len(rec.get('needed') or [])
                                                                   or 1)
    return {'action': _action_public(h.store, rec), 'message': said}


# ---------------------------------------------------------------------------
# Devices: the targets a team owns
# ---------------------------------------------------------------------------
def device_public(store, row, agent=False):
    """A device as the portal shows it: its settings, every secret '' with `secrets` saying
    whether it is set - never a secret, nor its dots."""
    pub = S.plugin_public(store, 'target', row, full=False)
    cls = S.row_class('target', row)
    secrets = S.secret_fields(cls) if cls else set()
    cfg = pub.get('config') or {}
    for k in list(cfg):
        v = cfg[k]
        if k in secrets or (isinstance(v, str) and (v.startswith('sealed:') or E.is_masked(v))):
            cfg[k] = ''
    pub['config'] = cfg
    is_set = set(pub.get('secret_set') or [])
    pub['secrets'] = {k: k in is_set for k in sorted(secrets | is_set)}
    pub['owner'] = row.get('owner') or None
    pub.pop('state', None)
    if row.get('kind') in AGENT_KINDS:
        from acmelib.certs import agents as G
        try:
            a = G.info(store, row)
            pub['agent'] = {k: a.get(k) for k in ('state', 'joined', 'mode', 'platform',
                                                  'version', 'last_seen', 'host', 'os')}
            pub['agent']['waiting'] = bool(a.get('pending') and not a['pending'].get(
                'confirmed'))
            if agent:
                pub['agent'] = a
        except Exception as e:                          # noqa: BLE001
            pub['agent'] = {'state': 'new', 'error': str(e)[:200]}
    return pub


def device_of(me, ref, cap, doing):
    """(row, team) of a team's device where they hold `cap` on its team."""
    try:
        ident = _ident(ref)
    except ValueError:
        raise E.ApiError(400, 'which device? (its id)')
    row = S.plugin_row(me.store, 'target', ident)
    if not row or not _low(row.get('owner')) or _low(row.get('owner')) not in me.tr.rows or \
            (not me.all and _low(row.get('owner')) not in me.pc):
        raise E.ApiError(404, 'there is no such device of your teams')
    team = me.need(row['owner'], cap, '%s the device %s' % (doing, row['name']))
    return row, team


@route('GET', 'devices')
def _devices(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'target.view', 'see the devices')
    want = me.below(team, 'target.view', _flag(h, 'below'))
    q = _low(h.arg('q'))[:200]
    rows = []
    for r in h.store.db.rows('SELECT * FROM cert_targets WHERE COALESCE(owner, \'\') <> \'\' '
                             'ORDER BY name'):
        if _low(r.get('owner')) not in want:
            continue
        if q and q not in ('%s %s %s' % (r['name'], r.get('kind'), r.get('note') or '')).lower():
            continue
        rows.append(device_public(h.store, r))
    c = me.caps(team)
    return {'team': team, 'rows': rows, 'total': len(rows),
            'may': {'manage': 'target.manage' in c, 'test': 'target.test' in c}}


@route('GET', 'device')
def _device(h):
    me = Me(h)
    row, team = device_of(me, h.arg('id'), 'target.view', 'look at')
    out = _others_hidden(me, device_public(h.store, row, agent=True))
    deps =h.store.db.rows('SELECT d.id, d.cert_id, d.state, d.last_error, c.name AS cert_name, '
                           'c.owner AS cert_owner FROM cert_deploys d JOIN certs c ON c.id = '
                           'd.cert_id WHERE d.target = ? ORDER BY c.name', (row['name'],))
    out['deploys'] = [{'id': d['id'], 'cert_id': d['cert_id'], 'state': d.get('state'),
                       'cert_name': d['cert_name'] if _low(d.get('cert_owner')) in
                       set(me.reach('cert.view')) else 'another owner\'s certificate'}
                      for d in deps]
    c = me.caps(team)
    out['may'] = {'manage': 'target.manage' in c, 'test': 'target.test' in c}
    return {'device': out, 'team': team}


def _kinds_of(me, team):
    """The target modules a team may use on the portal (its limits; never NEVER_KINDS)."""
    eff = T.effective_policy(me.store, team)
    allowed = TP.kinds_allowed(eff)
    view = A.plugins_view(me.store)
    out = []
    for one in view.get('target') or []:
        k = one.get('kind')
        if k in NEVER_KINDS:
            continue
        if allowed == ('!agents',):
            if k in AGENT_KINDS:
                continue
        elif allowed is not None and _low(k) not in {_low(x) for x in allowed}:
            continue
        out.append(_choices_of_team(me, team, one))
    return out


def _choices_of_team(me, team, one, tests=False):
    """A module's form with the choices its fields read from acme (options_from) cut to what
    the team may choose (hunt C1: every connector of acme and of the other teams was listed,
    by name, to any member who may see devices): the connectors among the team's devices (its
    own, above or below it, where they see devices) - of any other list only the empty choice."""
    import copy
    one = copy.deepcopy(one)
    near = set(me.tr.chain(team)) | set(me.tr.descendants(team))
    mine = None

    def own():
        got = set()
        for r in me.store.db.rows("SELECT name, owner FROM cert_targets WHERE COALESCE(owner, "
                                  "'') <> '' AND kind IN ('ssh_connector', 'agent', "
                                  "'agent_windows')"):
            o = _low(r.get('owner'))
            if o in near and 'target.view' in me.caps(o):
                got.add(r['name'])
        if tests:
            # a test's connector may also be one of the team's tests (1.0.128)
            for r in me.store.db.rows("SELECT name, owner FROM cert_tests WHERE COALESCE("
                                      "owner, '') <> '' AND kind = 'ssh_relay'"):
                o = _low(r.get('owner'))
                if o in near and 'test.view' in me.caps(o):
                    got.add(r['name'])
        return got

    def cut(fields):
        nonlocal mine
        out = []
        for f in fields or []:
            if isinstance(f, dict) and f.get('options_from'):
                f = dict(f)
                if f['options_from'] in CONNECTOR_SOURCES:
                    if mine is None:
                        mine = own()
                    keep = mine
                else:
                    keep = set()
                f['options'] = [o for o in f.get('options') or [] if isinstance(
                    o, (list, tuple)) and o and (o[0] == '' or o[0] in keep)]
                if f.get('default') not in (None, '') and f['default'] not in {
                        o[0] for o in f['options']}:
                    f['default'] = ''
            out.append(f)
        return out
    for key in ('fields', 'deploy_fields'):
        if key in one:
            one[key] = cut(one.get(key))
    for v in one.get('versions') or []:
        if isinstance(v, dict):
            for key in ('fields', 'deploy_fields'):
                if key in v:
                    v[key] = cut(v.get(key))
    return one


def need_kind(me, team, kind):
    if not kind:
        raise E.ApiError(400, 'which module (kind)?')
    if kind in NEVER_KINDS:
        me.deny('the module %s is not made on the portal - it works on acme\'s own server (an '
                'administrator adds it)' % kind)
    TP.need_target_kind(me.store, team, kind, me.name)


@route('GET', 'kinds')
def _kinds(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'target.view', 'see the device modules')
    eff = T.effective_policy(h.store, team)
    allowed = TP.kinds_allowed(eff)
    return {'team': team, 'kinds': _kinds_of(me, team),
            'limit': None if allowed in (None, ('!agents',)) else list(allowed),
            'agents': bool(T.policy_value(eff, 'agents')),
            'from': (eff.get('from') or {}).get('target_kinds')}


CONNECTOR_SOURCES = ('connectors', 'agent_hops', 'test_connectors', 'ssh_targets',
                     'targets', 'agent_windows_targets')


def _via_keys(kind, cfg):
    """The settings of a module that name another device to go through (`via`, `ssh_via`,
    `stage_via` ... - a field choosing among the connectors or the targets)."""
    keys = {k for k in (cfg or {}) if k == 'via' or str(k).endswith('_via')}
    cls = S.given_class('target', kind, cfg) if kind else None
    for f in (getattr(cls, 'fields', None) or []) if cls else []:
        if isinstance(f, dict) and f.get('options_from') in CONNECTOR_SOURCES:
            keys.add(f['key'])
    for v in (getattr(cls, 'versions', None) or {}).values() if cls and isinstance(
            getattr(cls, 'versions', None), dict) else []:
        for f in getattr(v, 'fields', None) or []:
            if isinstance(f, dict) and f.get('options_from') in CONNECTOR_SOURCES:
                keys.add(f['key'])
    return keys


def _via_ok(me, team, cfg, kind=None, row=None):
    """A device reached through a connector (`via` - and every other setting naming a device
    to go through, `ssh_via`, `stage_via`, hunt C1): a connector of a team they see (their
    team, above or below it) - never acme's own, nor another team's. A value the device has
    already (set by an administrator) is kept as it is."""
    had = S.jload((row or {}).get('config'), {}) or {} if row else {}
    for key in sorted(_via_keys(kind, cfg)):
        if key not in (cfg or {}):
            continue
        via = str((cfg or {}).get(key) or '').strip()
        if not via or (row is not None and via == str(had.get(key) or '').strip()):
            continue
        # by its name alone, as the run finds it (runtime._jump): a connector of the targets,
        # else a test's, else a target's agent - never an id ("7" was the team's device of id
        # 7, and the run went through acme's test connector called 7)
        vrow = me.store.db.row('SELECT * FROM cert_targets WHERE name = ?', (via,))
        if vrow is not None and vrow.get('kind') != 'ssh_connector' and (
                vrow.get('kind') not in AGENT_KINDS or me.store.db.value(
                    "SELECT COUNT(*) FROM cert_tests WHERE name = ? AND kind = 'ssh_relay'",
                    (via,), 0)):
            vrow = None
        near = set(me.tr.chain(team)) | set(me.tr.descendants(team))
        if not vrow or _low(vrow.get('owner')) not in near or 'target.view' not in me.caps(
                vrow.get('owner')):
            me.deny('the device goes through %s, which is not a connector of the team %s' % (
                via[:120], team))


@route('POST', 'device_save')
def _device_save(h):
    me = Me(h)
    b = h.body()
    row = None
    if b.get('id') not in (None, '', 0):
        row, old_team = device_of(me, b.get('id'), 'target.manage', 'change')
    team = b.get('team') or (row or {}).get('owner')
    team = me.need(team, 'target.manage', 'add or change devices')
    kind = str(b.get('kind') or (row or {}).get('kind') or '').strip()
    need_kind(me, team, kind)
    cfg = b.get('config')
    if cfg is not None and not isinstance(cfg, dict):
        raise E.ApiError(400, 'config is the module\'s settings {key: value}')
    if isinstance(cfg, dict):
        _via_ok(me, team, cfg, kind, row if row is not None and row.get('kind') == kind
                else None)
    body = {'owner': team, 'kind': kind}
    for k in ('name', 'config', 'note', 'enabled', 'tags'):
        if k in b:
            body[k] = b[k]
    if row is not None:
        body['id'] = row['id']
        if isinstance(cfg, dict) and row.get('kind') == kind:
            # where it connects changed with a secret kept that was typed by someone else: the
            # secret would go to the new place - typed again, or the place kept (as the
            # administration's Test of a certificate administrator)
            try:
                A.kept_secrets_guard(h.store, 'target', {'id': row['id'], 'kind': kind,
                                                         'config': cfg}, me.admin())
            except E.ApiError:
                me.deny('%s keeps secrets: type them again when you change its other settings '
                        '(they would go to the new place)' % row['name'])
    elif not body.get('name'):
        raise E.ApiError(400, 'the device needs a name')
    rid = A.family_save(h.store, 'target', body, me.by)
    got = S.plugin_row(h.store, 'target', rid)
    return {'id': rid, 'device': device_public(h.store, got),
            'message': '%s saved' % got['name']}


@route('POST', 'device_delete')
def _device_delete(h):
    me = Me(h)
    row, team = device_of(me, h.body().get('id'), 'target.manage', 'delete')
    uses = A.family_uses(h.store, 'target', row)
    if uses:
        # refused while deployments use it, as the administration refuses it
        raise E.ApiError(409, A._uses_said(row, uses))
    if not me.all and TP.action_needs_approval(h.store, team, 'device'):
        rec = TP.action_ask(h.store, team, 'device', row['id'], me.approver(),
                            'delete the device %s' % row['name'])
        return {'waits': True, 'action': _action_public(h.store, rec),
                'message': 'deleting %s waits for an approval of the team %s first' % (
                    row['name'], team)}
    name = A.family_delete(h.store, 'target', {'id': row['id']}, me.by)
    return {'message': '%s deleted' % name}


@route('POST', 'device_test')
def _device_test(h):
    me = Me(h)
    row, _team = device_of(me, h.body().get('id'), 'target.test', 'test')
    # as it is saved - settings not saved are tried by saving them (as a certificate
    # administrator's Test in the administration)
    return A.family_test(h.store, 'target', {'id': row['id']}, me.by)


# ---------------------------------------------------------------------------
# Tests: the tests a team owns (1.0.128, docs/teams.md "Tests of a team")
# ---------------------------------------------------------------------------
def test_public(store, row):
    """A test as the portal shows it: as a device is (device_public) - every secret '' with
    `secrets` saying whether it is set, never a secret nor its dots."""
    pub = S.plugin_public(store, 'check', row, full=False)
    cls = S.row_class('check', row)
    secrets = S.secret_fields(cls) if cls else set()
    cfg = pub.get('config') or {}
    for k in list(cfg):
        v = cfg[k]
        if k in secrets or (isinstance(v, str) and (v.startswith('sealed:') or E.is_masked(v))):
            cfg[k] = ''
    pub['config'] = cfg
    is_set = set(pub.get('secret_set') or [])
    pub['secrets'] = {k: k in is_set for k in sorted(secrets | is_set)}
    pub['owner'] = row.get('owner') or None
    pub.pop('state', None)
    pub.pop('secret_set', None)
    return pub


def test_of(me, ref, cap, doing):
    """(row, team) of a team's test where they hold `cap` on its team - 404 for acme's own
    tests and another team's."""
    try:
        ident = _ident(ref)
    except ValueError:
        raise E.ApiError(400, 'which test? (its id)')
    row = me.store.db.row('SELECT * FROM cert_tests WHERE id = ?', (ident,))
    if not row or not _low(row.get('owner')) or _low(row.get('owner')) not in me.tr.rows or \
            (not me.all and _low(row.get('owner')) not in me.pc):
        raise E.ApiError(404, 'there is no such test of your teams')
    team = me.need(row['owner'], cap, '%s the test %s' % (doing, row['name']))
    return row, team


def _test_kinds_of(me, team):
    """The test modules a team may use on the portal (its test_kinds), their choices cut to
    the team's connectors."""
    allowed = TP.test_kinds_allowed(T.effective_policy(me.store, team))
    view = A.plugins_view(me.store)
    out = []
    for one in view.get('check') or []:
        k = one.get('kind')
        if allowed is not None and _low(k) not in {_low(x) for x in allowed}:
            continue
        out.append(_choices_of_team(me, team, one, tests=True))
    return out


def _test_refs_ok(me, team, cfg, row=None):
    """A test going through a connector (`via`) - a connector of a team they see (a target
    connector, a server with acme-agent, or a connector of the tests), never acme's own nor
    another team's; a connector of the tests runs only the team's own tests (`tests`). A
    value the test has already (set by an administrator) is kept as it is."""
    had = (S.jload((row or {}).get('config'), {}) or {}) if row else {}
    near = set(me.tr.chain(team)) | set(me.tr.descendants(team))
    for key in sorted(k for k in (cfg or {}) if k == 'via' or str(k).endswith('_via')):
        via = str(cfg.get(key) or '').strip()
        if not via or (row is not None and via == str(had.get(key) or '').strip()):
            continue
        # as a test's run finds it (checks._through): a connector of the tests, else a
        # server's agent, else a connector of the targets (hunt R u1: looked up in the order
        # of the targets' runtime._jump - a device of the team named as acme's own connector
        # of the tests passed here, and the test ran through acme's own)
        got = me.store.db.row("SELECT owner FROM cert_tests WHERE name = ? AND kind = "
                              "'ssh_relay'", (via,))
        cap = 'test.view'
        if not got:
            got = me.store.db.row("SELECT owner FROM cert_targets WHERE name = ? AND kind IN "
                                  "('agent', 'agent_windows')", (via,))
            cap = 'target.view'
        if not got:
            got = me.store.db.row("SELECT owner FROM cert_targets WHERE name = ? AND kind = "
                                  "'ssh_connector'", (via,))
            cap = 'target.view'
        if not got or _low(got.get('owner')) not in near or cap not in me.caps(got.get('owner')):
            me.deny('the test goes through %s, which is not a connector of the team %s' % (
                via[:120], team))
    names = (cfg or {}).get('tests')
    if names is not None:
        if isinstance(names, str):
            names = [x.strip() for x in names.splitlines()]
        before = set(had.get('tests') or []) if row is not None else set()
        for n in [str(x).strip() for x in names or [] if str(x).strip()]:
            if n in before:
                continue
            got = me.store.db.row('SELECT owner FROM cert_tests WHERE name = ?', (n,))
            if not got or _low(got.get('owner')) not in near or \
                    'test.view' not in me.caps(got.get('owner')):
                me.deny('the test %s is not one of the team %s' % (n[:120], team))


@route('GET', 'tests')
def _tests(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'test.view', 'see the tests')
    want = me.below(team, 'test.view', _flag(h, 'below'))
    q = _low(h.arg('q'))[:200]
    rows = []
    for r in h.store.db.rows("SELECT * FROM cert_tests WHERE COALESCE(owner, '') <> '' "
                             "ORDER BY name"):
        if _low(r.get('owner')) not in want:
            continue
        if q and q not in ('%s %s %s' % (r['name'], r.get('kind'), r.get('note') or '')).lower():
            continue
        rows.append(test_public(h.store, r))
    c = me.caps(team)
    return {'team': team, 'rows': rows, 'total': len(rows),
            'may': {'manage': 'test.manage' in c}}


@route('GET', 'test')
def _test(h):
    me = Me(h)
    row, team = test_of(me, h.arg('id'), 'test.view', 'look at')
    out = test_public(h.store, row)
    out['may'] = {'manage': 'test.manage' in me.caps(team)}
    return {'test': out, 'team': team}


@route('GET', 'test_kinds')
def _test_kinds(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'test.view', 'see the test modules')
    eff = T.effective_policy(h.store, team)
    allowed = TP.test_kinds_allowed(eff)
    return {'team': team, 'kinds': _test_kinds_of(me, team),
            'limit': None if allowed is None else list(allowed),
            'from': (eff.get('from') or {}).get('test_kinds')}


@route('POST', 'test_save')
def _test_save(h):
    me = Me(h)
    b = h.body()
    row = None
    if b.get('id') not in (None, '', 0):
        row, _old = test_of(me, b.get('id'), 'test.manage', 'change')
    team = me.need(b.get('team') or (row or {}).get('owner'), 'test.manage',
                   'add or change tests')
    kind = str(b.get('kind') or (row or {}).get('kind') or '').strip()
    if not kind:
        raise E.ApiError(400, 'which module (kind)?')
    TP.need_test_kind(h.store, team, kind, me.name)
    cfg = b.get('config')
    if cfg is not None and not isinstance(cfg, dict):
        raise E.ApiError(400, 'config is the module\'s settings {key: value}')
    if isinstance(cfg, dict):
        _test_refs_ok(me, team, cfg, row if row is not None and row.get('kind') == kind
                      else None)
    body = {'owner': team, 'kind': kind}
    for k in ('name', 'config', 'note', 'enabled'):
        if k in b:
            body[k] = b[k]
    if row is not None:
        body['id'] = row['id']
        if isinstance(cfg, dict) and row.get('kind') == kind:
            try:
                A.kept_secrets_guard(h.store, 'check', {'id': row['id'], 'kind': kind,
                                                        'config': cfg}, me.admin())
            except E.ApiError:
                me.deny('%s keeps secrets: type them again when you change its other settings '
                        '(they would go to the new place)' % row['name'])
    elif not body.get('name'):
        raise E.ApiError(400, 'the test needs a name')
    rid = A.family_save(h.store, 'check', body, me.by)
    got = h.store.db.row('SELECT * FROM cert_tests WHERE id = ?', (rid,))
    h.store.add_event('certificates', 'the test %s of the team %s saved on the portal by %s' % (
        got['name'], team, me.name), who=me.name)
    return {'id': rid, 'test': test_public(h.store, got), 'message': '%s saved' % got['name']}


@route('POST', 'test_delete')
def _test_delete(h):
    me = Me(h)
    row, team = test_of(me, h.body().get('id'), 'test.manage', 'delete')
    uses = A.family_uses(h.store, 'check', row)
    if uses:
        raise E.ApiError(409, A._uses_said(row, uses))
    name = A.family_delete(h.store, 'check', {'id': row['id']}, me.by)
    return {'message': '%s deleted' % name}


@route('POST', 'test_run')
def _test_run(h):
    me = Me(h)
    row, _team = test_of(me, h.body().get('id'), 'test.manage', 'run')
    # as it is saved (as a certificate administrator's Test in the administration)
    return A.family_test(h.store, 'check', {'id': row['id']}, me.by)


@route('GET', 'policy_catalog')
def _policy_catalog(h):
    """The names of the sources and validations (never their settings) a team's limits may
    pair (1.0.128) - for a holder of team.policy, cut to what is in force above the team."""
    me = Me(h)
    # the team whose limits are in force above the one designed (its parent)
    team = me.need(h.arg('team'), 'team.policy', 'see the sources and validations for limits')
    eff = T.effective_policy(h.store, team)

    def rows(table, key):
        allowed = eff.get(key)
        keep = None if allowed is None else {_low(x) for x in allowed}
        return [{'name': r['name'], 'kind': r.get('kind') or ''}
                for r in h.store.db.rows('SELECT name, kind FROM %s ORDER BY name' % table)
                if keep is None or _low(r['name']) in keep]
    src = rows('cert_issuers', 'issuers')
    if eff.get('pairs') is not None:
        paired = {_low(k) for k in eff['pairs']}
        src = [r for r in src if _low(r['name']) in paired]
    return {'team': team, 'sources': src, 'validations': rows('cert_challenges', 'validations'),
            'pairs': eff.get('pairs')}


# ---------------------------------------------------------------------------
# Agents of the team's devices
# ---------------------------------------------------------------------------
def agent_of(me, ref, cap, doing):
    row, team = device_of(me, ref, cap, doing)
    if row.get('kind') not in AGENT_KINDS:
        raise E.ApiError(404, '%s is not a device with acme-agent' % row['name'])
    return row, team


@route('POST', 'agent_code')
def _agent_code(h):
    me = Me(h)
    from acmelib.certs import agents as G
    row, team = agent_of(me, h.body().get('id'), 'target.manage', 'make a join code for')
    # a server let in only while the team's limits still allow its agents (as its enrollment
    # code is refused then): a join code was made after the administrators took them away
    TP.need_target_kind(h.store, team, row.get('kind'), me.name)
    got = G.code_new(h.store, row, me.by)
    got['agent'] = G.info(h.store, row)
    return got


@route('POST', 'enroll_code')
def _enroll_code(h):
    me = Me(h)
    from acmelib.certs import agents as G
    b = h.body()
    team = me.need(b.get('team'), 'target.manage', 'make an enrollment code')
    # its limits first, refused in words naming the team (403): agents at all, auto-confirm
    TP.need_target_kind(h.store, team, G.enroll_kind(T.effective_policy(h.store, team)),
                        me.name)
    auto = bool(A._flag(b.get('auto')))
    if auto and not T.policy_value(T.effective_policy(h.store, team), 'agents_auto_confirm'):
        TP.refuse(h.store, me.name, team, 'its agents are confirmed by a person - only the '
                                          'administrators allow them to be confirmed by '
                                          'themselves (agents_auto_confirm)')
    # auto-confirm only where the administrators' limits allow it (agents_auto_confirm) -
    # enroll_new refuses it otherwise, naming the team
    return G.enroll_new(h.store, me.by, title=A._text(b, 'title', 200),
                        mode=b.get('mode') or 'passive', port=b.get('port'), days=b.get('days'),
                        most=b.get('most'), auto=auto, team=team)


@route('POST', 'enroll_revoke')
def _enroll_revoke(h):
    me = Me(h)
    from acmelib.certs import agents as G
    ec = G.enroll_get(h.store, str(h.body().get('id') or ''))
    if not ec or not ec.get('team'):
        raise E.ApiError(404, 'there is no such enrollment code of your teams')
    me.need(ec['team'], 'target.manage', 'revoke an enrollment code')
    return {'code': G.enroll_revoke(h.store, ec['id'], me.by)}


@route('GET', 'agents_waiting')
def _agents_waiting(h):
    me = Me(h)
    from acmelib.certs import agents as G
    team = me.need(h.arg('team'), 'target.view', 'see the agents')
    want = me.below(team, 'target.view', _flag(h, 'below'))
    c = me.caps(team)
    return {'team': team, 'rows': G.waiting(h.store, teams=want),
            'codes': G.enroll_list(h.store, teams=want), 'active': G.active_on(),
            'auto_ok': bool(T.policy_value(T.effective_policy(h.store, team),
                                           'agents_auto_confirm')),
            'may': {'manage': 'target.manage' in c}}


@route('POST', 'agent_confirm')
def _agent_confirm(h):
    me = Me(h)
    from acmelib.certs import api_agents
    row, team = agent_of(me, h.body().get('id'), 'target.manage', 'confirm the agent of')
    # ...and confirmed only while they allow it (refusing it stays possible)
    TP.need_target_kind(h.store, team, row.get('kind'), me.name)
    # the administration's own confirmation (the fingerprint compared; a passive one looked at)
    return api_agents._confirm(_H(h, {'id': row['id'], 'fp': h.body().get('fp')}), me.admin())


@route('POST', 'agent_refuse')
def _agent_refuse(h):
    """The agent asking to join is not let in: what it asked with is forgotten (its join code
    too) - a device an enrollment code made for it, never joined and used by nothing, goes."""
    me = Me(h)
    from acmelib.certs import agents as G
    row, _t = agent_of(me, h.body().get('id'), 'target.manage', 'refuse the agent of')
    st = G.state(h.store, row['id'])
    pend = st.get('pending') if isinstance(st.get('pending'), dict) else None
    if not pend or pend.get('cert'):
        raise E.ApiError(409, 'no agent waits to be confirmed on %s' % row['name'])
    st.pop('pending', None)
    st.pop('code', None)
    G.state_put(h.store, row['id'], st)
    h.store.add_event('certificates', 'the agent asking to join as target %s was refused by %s '
                      '(key %s…)' % (row['name'], me.by, str(pend.get('fp') or '')[:16]), 'warn',
                      who=me.name)
    gone = False
    if isinstance(st.get('enroll'), dict) and not st.get('cert_fp') and \
            not A.family_uses(h.store, 'target', row):
        A.family_delete(h.store, 'target', {'id': row['id']}, me.by)
        gone = True
    return {'message': 'refused%s' % (' - the device is deleted' if gone else ''),
            'deleted': gone}


@route('GET', 'agent')
def _agent(h):
    me = Me(h)
    from acmelib.certs import agents as G, agent_policy as AP
    row, team = agent_of(me, h.arg('id'), 'target.view', 'look at the agent of')
    out = _others_hidden(me, G.info(h.store, row))
    out['design'] = AP.design_view(h.store, row, out.get('policy'))
    c = me.caps(team)
    return {'agent': out, 'team': team,
            'may': {'manage': 'target.manage' in c, 'test': 'target.test' in c}}


def _others_hidden(me, out):
    """What a device's agent says, the certificates of other owners not named (hunt R t2): the
    deployments' needs of the policy builder and the certificates whose key the agent makes
    named every certificate deployed to the team's device - acme's own and other teams' - to a
    member who may only see devices, where the device itself says "another owner's
    certificate"."""
    if me.all or not isinstance(out, dict):
        return out
    seen = set(me.reach('cert.view'))

    def visible(name):
        r = me.store.db.row('SELECT owner FROM certs WHERE name = ?', (name,))
        return r is not None and _low(r.get('owner')) in seen
    for a in (out, out.get('agent')):
        if isinstance(a, dict) and isinstance(a.get('keys_of'), list):
            a['keys_of'] = [n for n in a['keys_of'] if visible(n)]
    for one in out.get('needs') or []:
        if isinstance(one, dict) and not str(one.get('id') or '').startswith('source:'):
            dep = me.store.db.row('SELECT c.owner FROM cert_deploys d LEFT JOIN certs c ON '
                                  'c.id = d.cert_id WHERE d.id = ?', (one.get('id'),))
            if dep is None or _low(dep.get('owner')) not in seen:
                one['cert'] = A.OTHERS_CERT
    if isinstance(out.get('discovered'), dict):
        _disc_hidden(me, out['discovered'])
    return out


def _disc_hidden(me, v):
    """A discovery (agent_discover.view) as a member sees it (hunt R t3, as _others_hidden): a
    certificate found on the server that acme holds was named ("acme: NAME", its id) though it
    is acme's own or another team's - "another owner's certificate", no id."""
    if me.all or not isinstance(v, dict):
        return v
    seen = set(me.reach('cert.view'))
    owners = {}
    certs = [f.get('cert') for f in v.get('found') or [] if isinstance(f, dict)]
    certs += list(v.get('certs') or [])
    for c in certs:
        m = c.get('managed') if isinstance(c, dict) else None
        if not isinstance(m, dict):
            continue
        if m.get('id') not in owners:
            r = me.store.db.row('SELECT owner FROM certs WHERE id = ?', (m.get('id'),))
            owners[m.get('id')] = None if r is None else _low(r.get('owner'))
        if owners[m.get('id')] is None or owners[m.get('id')] not in seen:
            c['managed'] = dict(m, id=None, name=A.OTHERS_CERT)
    return v


@route('GET', 'agent_builder')
def _agent_builder(h):
    me = Me(h)
    from acmelib.certs import agent_policy as AP
    row, _t = agent_of(me, h.arg('id'), 'target.view', 'look at the policy of')
    return _others_hidden(me, AP.builder(h.store, row))


@route('POST', 'agent_design')
def _agent_design(h):
    me = Me(h)
    from acmelib.certs import api_agents
    b = h.body()
    row, _t = agent_of(me, b.get('id'), 'target.manage', 'design the policy of')
    return api_agents._design_save(_H(h, dict(b, id=row['id'])), me.admin())


@route('POST', 'agent_update')
def _agent_update(h):
    me = Me(h)
    from acmelib.certs import api_agents
    row, _t = agent_of(me, h.body().get('id'), 'target.manage', 'update the agent of')
    return api_agents._update(_H(h, {'id': row['id']}), me.admin())


@route('GET', 'agent_discover')
def _agent_discover(h):
    """What the server of a team's agent runs that takes certificates (1.0.125,
    agent_discover.py): the last look kept (target.view, `cached=1`) or a new one
    (target.manage) - read-only on the server, and only the kinds the agent's policy (as it last
    said it) allows; the agent checks its policy again itself."""
    me = Me(h)
    from acmelib.certs import agent_discover as AD, agents as G
    live = not _flag(h, 'cached')
    row, _t = agent_of(me, h.arg('id'), 'target.manage' if live else 'target.view',
                       'look at what runs on the server of' if not live else 'run a discovery on')
    if not live:
        return {'discovery': _disc_hidden(me, AD.cached(h.store, row)), 'target': row['name']}
    platform = G.platform_of(h.store, row)
    policy = G.info(h.store, row).get('policy')
    allowed = AD.allowed_kinds(policy, platform)
    want = [k.strip() for k in str(h.arg('kind') or '').split(',') if k.strip()]
    if policy is not None and not allowed:
        me.deny('the policy of the agent of %s does not allow discovery - its server\'s root '
                'allows it: %s' % (row['name'], AD.allow_line(want)))
    bad = [k for k in want if allowed and k not in allowed]
    if bad:
        me.deny('the policy of the agent of %s does not allow discovering %s - only %s' % (
            row['name'], ', '.join(bad), ', '.join(allowed)))
    try:
        got = AD.run(h.store, row, want or None, me.by)
    except ValueError as e:
        raise E.ApiError(400, str(e))
    return {'discovery': _disc_hidden(me, got), 'target': row['name']}


# ---------------------------------------------------------------------------
# Deployments of the team's certificates to the team's devices
# ---------------------------------------------------------------------------
def cert_team(me, cert, cap, doing):
    """The team of a certificate where they hold `cap` - personal ones are not deployed
    from here."""
    owner = _low((cert or {}).get('owner'))
    if not owner or owner not in me.tr.rows or (not me.all and owner not in me.pc):
        raise E.ApiError(404, 'there is no such certificate of your teams')
    return me.need(owner, cap, '%s %s' % (doing, cert['name']))


def deploy_of(me, ref, cap, doing):
    try:
        ident = _ident(ref)
    except ValueError:
        raise E.ApiError(400, 'which deployment? (its id)')
    dep = me.store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (ident,))
    if not dep:
        raise E.ApiError(404, 'there is no such deployment of your teams')
    cert = S.cert_get(me.store, dep['cert_id'])
    if not cert:
        raise E.ApiError(404, 'there is no such deployment of your teams')
    cert_team(me, cert, cap, doing)
    return dep, cert


def deploy_clean(one):
    """A deployment as the portal shows it: secrets '' (set or not said)."""
    opts = one.get('options') or {}
    for k in list(opts):
        v = opts[k]
        if k in (one.get('secret_set') or []) or (isinstance(v, str) and (
                v.startswith('sealed:') or E.is_masked(v))):
            opts[k] = ''
    one['options'] = opts
    one['secrets'] = {k: True for k in one.get('secret_set') or []}
    return one


@route('GET', 'deploys')
def _deploys(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'deploy.view', 'see the deployments')
    want = me.below(team, 'deploy.view', _flag(h, 'below'))
    ids = set()
    part = sorted(want)
    for r in h.store.db.rows('SELECT id FROM certs WHERE LOWER(TRIM(owner)) IN (%s)' % ', '.join(
            '?' * len(part)), tuple(part)):
        ids.add(r['id'])
    rows = [deploy_clean(d) for d in A.deploy_rows(h.store) if d['cert_id'] in ids] if ids \
        else []
    c = me.caps(team)
    return {'team': team, 'rows': rows, 'total': len(rows),
            'may': {'manage': 'deploy.manage' in c, 'run': 'deploy.run' in c}}


@route('POST', 'deploy_save')
def _deploy_save(h):
    me = Me(h)
    b = h.body()
    dep = None
    if b.get('id') not in (None, '', 0):
        dep, _c = deploy_of(me, b.get('id'), 'deploy.manage', 'change a deployment of')
    cert = S.cert_get(me.store, b.get('cert_id') or (dep or {}).get('cert_id'))
    if not cert:
        raise E.ApiError(404, 'there is no such certificate of your teams')
    team = cert_team(me, cert, 'deploy.manage', 'deploy')
    tname = str(b.get('target') or (dep or {}).get('target') or '').strip()
    trow = S.plugin_row(h.store, 'target', tname) if tname else None
    if not trow:
        raise E.ApiError(404, 'there is no device %s of your teams' % tname[:120])
    tteam = _low(trow.get('owner'))
    if not tteam or tteam not in me.tr.rows or 'target.view' not in me.caps(tteam):
        me.deny('%s is not a device of your teams - a team deploys to its own devices'
                % trow['name'])
    # the device of the team (above or below it) and a module its limits allow
    TP.need_deploy(h.store, cert, trow, me.name)
    body = {'cert_id': cert['id'], 'target': trow['name']}
    if dep:
        body['id'] = dep['id']
    for k in ('options', 'enabled', 'note', 'position'):
        if k in b:
            body[k] = b[k]
    if not dep and 'options' not in body:
        body['options'] = {}
    # checked as the administration checks a certificate administrator's: the commands, the
    # script and where the key goes stay a full administrator's
    rid = A.deploy_save(h.store, body, me.by, full=False)
    one = [d for d in A.deploy_rows(h.store, cert=str(cert['id'])) if d['id'] == rid]
    return {'id': rid, 'deploy': deploy_clean(one[0]) if one else None, 'team': team,
            'message': 'the deployment of %s to %s is saved' % (cert['name'], trow['name'])}


@route('POST', 'deploy_delete')
def _deploy_delete(h):
    me = Me(h)
    dep, _c = deploy_of(me, h.body().get('id'), 'deploy.manage', 'delete a deployment of')
    from acmelib.certs import api as AA
    return AA._deploy_delete(_H(h, {'id': dep['id']}), me.admin())


@route('POST', 'deploy_run')
def _deploy_run(h):
    me = Me(h)
    dep, cert = deploy_of(me, h.body().get('id'), 'deploy.run', 'run a deployment of')
    got = A._deploy_run(_H(h, {'id': dep['id']}), me.admin())
    h.store.add_event('certificates', '%s runs the deployment of %s to %s from the portal' % (
        me.name, cert['name'], dep['target']), who=me.name)
    return got


@route('POST', 'deploy_dry_run')
def _deploy_dry_run(h):
    """What happens (the run plan) of one deployment, nothing contacted - or, `test`, the
    module's own test of it on the device (nothing put in place; deploy.run)."""
    me = Me(h)
    b = h.body()
    test = A._flag(b.get('test'))
    dep, cert = deploy_of(me, b.get('id'), 'deploy.run' if test else 'deploy.view',
                          'test a deployment of' if test else 'look at a deployment of')
    if test:
        from acmelib.certs import api_deploys
        return api_deploys._deploys_dry_run(_H(h, {'id': dep['id']}), me.admin())
    from acmelib.certs import api_runplan
    return api_runplan._go(h.store, cert, [dep], me.admin())


# ---------------------------------------------------------------------------
# Members - never more than the one giving holds
# ---------------------------------------------------------------------------
def _caps_list(c):
    return [x for x in T.CAPS if x in c]


def _is_me(me, who):
    names, gset = T._principal_key(me.names, me.groups)
    return T._matches_fast(who, names, gset)


@route('GET', 'members')
def _members(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'team.members', 'see the members')
    t = T.team_get(h.store, team)
    cat = T.role_catalog(h.store)
    mine = _norm(me.caps(team))
    now = time.time()
    rows = []
    for m in S.jload(t.get('members'), []) or []:
        if not isinstance(m, dict):
            continue
        one = dict(m)
        c = T.member_caps(m, cat, now=0)
        one['kind'] = T.member_kind(m.get('who'))
        one['caps'] = _caps_list(c)
        one['expired'] = T.member_expired(m, now)
        one['me'] = _is_me(me, m.get('who'))
        one['may_change'] = me.all or _norm(c) <= mine
        rows.append(one)
    above = []
    for k in me.tr.ancestors(team):
        for m in S.jload(me.tr.rows[k].get('members'), []) or []:
            if isinstance(m, dict):
                above.append({'team': me.tr.rows[k]['name'], 'who': m.get('who'),
                              'roles': m.get('roles') or [], 'rights': m.get('rights') or [],
                              'kind': T.member_kind(m.get('who'))})
    roles = [{'name': r['name'], 'builtin': r['builtin'], 'description': r['description'],
              'caps': _caps_list(r['caps']), 'givable': me.all or _norm(r['caps']) <= mine}
             for r in T.role_catalog(h.store).values()]
    return {'team': team, 'members': rows, 'above': above[:500], 'roles': roles,
            'rights': [{'name': r, 'caps': _caps_list(T.RIGHT_CAPS[r]),
                        'givable': me.all or _norm(T.RIGHT_CAPS[r]) <= mine} for r in T.RIGHTS],
            'my_caps': _caps_list(mine)}


def _member_list(t):
    return [m for m in S.jload(t.get('members'), []) or [] if isinstance(m, dict)]


def _norm(caps):
    """Capabilities compared for escalation: the old right manage's marker is what it gives -
    approving (cert.approve) - so a Team owner gives manage, and a member with manage an
    Approver, and nobody gives approving they do not hold under another name."""
    caps = frozenset(caps or ())
    if T.LEGACY_MANAGE in caps:
        caps = (caps - {T.LEGACY_MANAGE}) | {'cert.approve'}
    return caps


def _no_escalation(me, team, new, old):
    """Refused in words: a member given a capability the giver does not hold on the team, a
    member holding more than the giver changed, their own membership raised."""
    if me.all:
        return
    cat = T.role_catalog(me.store)
    mine = _norm(me.caps(team))
    new_c = _norm(T.member_caps(new, cat, now=0)) if new else frozenset()
    old_c = _norm(T.member_caps(old, cat, now=0)) if old else frozenset()
    who = (new or old)['who']
    if old and not old_c <= mine:
        me.deny('%s holds more on the team %s than you do (%s) - you do not change their '
                'membership' % (who, team, ', '.join(_caps_list(old_c - mine))))
    if new and not new_c <= mine:
        me.deny('you give only what you hold on the team %s yourself - not %s'
                % (team, ', '.join(_caps_list(new_c - mine))))
    if new and _is_me(me, who):
        if not old:
            me.deny('you do not add yourself (or a group of yours) to the team %s - ask '
                    'another manager' % team)
        if not new_c <= old_c:
            me.deny('you do not raise your own membership (%s) on the team %s' % (
                ', '.join(_caps_list(new_c - old_c)), team))
        ou, nu = old.get('until'), new.get('until')
        if ou and (not nu or float(nu) > float(ou)):
            me.deny('you do not lengthen your own membership of the team %s' % team)


@route('POST', 'member_save')
def _member_save(h):
    me = Me(h)
    b = h.body()
    team = me.need(b.get('team'), 'team.members', 'change the members')
    t = T.team_get(h.store, team)
    cat = T.role_catalog(h.store)
    raw = {k: b.get(k) for k in ('who', 'roles', 'rights', 'until', 'note') if k in b}
    if 'rights' not in raw and raw.get('roles'):
        raw['rights'] = []
    new = T.clean_member(raw, cat)
    ms = _member_list(t)
    old_who = _low(b.get('old_who') or new['who'])
    at = next((i for i, m in enumerate(ms) if _low(m.get('who')) == old_who), None)
    old = ms[at] if at is not None else None
    if old is not None and _low(new['who']) != old_who and \
            any(_low(m.get('who')) == _low(new['who']) for m in ms):
        raise E.ApiError(409, '%s is a member already' % new['who'])
    if old is None and any(_low(m.get('who')) == _low(new['who']) for m in ms):
        at = next(i for i, m in enumerate(ms) if _low(m.get('who')) == _low(new['who']))
        old = ms[at]
    _no_escalation(me, team, new, old)
    if old is not None and _is_me(me, old['who']) and _low(new['who']) != _low(old['who']):
        me.deny('you do not give your own membership of the team %s to another' % team)
    if old is not None and _is_me(me, new['who']) and not _is_me(me, old['who']) and \
            not me.all:
        # another's membership made one's own (hunt C1): adding oneself by another way
        me.deny('you do not add yourself (or a group of yours) to the team %s - ask another '
                'manager' % team)
    if at is None:
        ms.append(new)
    else:
        ms[at] = new
    got = T.save_team(h.store, {'old_name': team, 'name': team, 'members': ms}, me.by)
    return {'team': team, 'member': new, 'members': got['members'],
            'message': 'the members of %s are saved' % team}


@route('POST', 'member_delete')
def _member_delete(h):
    me = Me(h)
    b = h.body()
    team = me.need(b.get('team'), 'team.members', 'remove members')
    t = T.team_get(h.store, team)
    ms = _member_list(t)
    who = _low(b.get('who'))
    old = next((m for m in ms if _low(m.get('who')) == who), None)
    if not old:
        raise E.ApiError(404, '%s is not a member of %s' % (str(b.get('who'))[:120], team))
    if not _is_me(me, old['who']):
        # their own taken off is always theirs to do (downwards); another's only when they hold
        # no more than the one removing them
        _no_escalation(me, team, None, old)
    ms = [m for m in ms if m is not old]
    got = T.save_team(h.store, {'old_name': team, 'name': team, 'members': ms}, me.by)
    return {'team': team, 'members': got['members'],
            'message': '%s is no longer a member of %s' % (old['who'], team)}


@route('GET', 'dir_search')
def _dir_search(h):
    """Users and groups of the directory for the member picker - for those who manage members
    somewhere; 20 at most, the text never an LDAP filter."""
    me = Me(h)
    if not me.reach('team.members'):
        me.deny('looking people up in the directory is for those who manage a team\'s members')
    from acmelib.certs import api_teams as AT
    q = str(h.arg('q') or '').strip()[:100]
    kind = str(h.arg('kind') or 'user')
    if kind not in ('user', 'group'):
        raise E.ApiError(400, 'kind is user or group')
    ad = AT.directory(h)
    if ad is None:
        raise E.ApiError(404, 'no directory is set up - type local:NAME, a user\'s name or '
                              'group:NAME')
    if len(q) < 2:
        return {'rows': [], 'more': False}
    if kind == 'user':
        found = AT._dir_call(lambda: ad.find_users(q, DIR_MOST + 1))
        rows = [{'who': (u.get('upn') or u.get('sam') or '').lower() or u['dn'],
                 'display': u.get('display') or '', 'sam': u.get('sam') or '',
                 'upn': u.get('upn') or '', 'mail': u.get('mail') or '',
                 'disabled': bool(u.get('disabled'))} for u in found]
    else:
        found = AT._dir_call(lambda: ad.find_groups(q, limit=DIR_MOST + 1))
        rows = [{'who': 'group:' + g['cn'], 'cn': g['cn'],
                 'description': g.get('description') or ''} for g in found]
    return {'rows': rows[:DIR_MOST], 'more': len(rows) > DIR_MOST}


# ---------------------------------------------------------------------------
# Teams below: created, renamed, moved, their limits, deleted
# ---------------------------------------------------------------------------
def widened(eff_parent, new):
    """The keys of `new` (a team's own limits) wider than those in force above it
    ([(key, words)]): the intersection would make them meaningless - refused in words."""
    base = {k: v for k, v in (eff_parent or {}).items() if k != 'from'}
    if not base:
        out = []
    else:
        merged = T.merge_policies([('above', base), ('it', new)])
        out = []
        for k, v in new.items():
            m = merged.get(k)
            if k in T.POLICY_LISTS and k in base:
                got = {_low(x) for x in m or []}
                extra = [x for x in v if _low(x) not in got]
                if extra:
                    out.append((k, '%s not in %s' % (', '.join(extra[:10]),
                                                     ', '.join(base[k]) or 'none')))
            elif k in T.POLICY_INTS and k in base and m != v:
                out.append((k, '%s is more than %s' % (v, base[k])))
            elif k in T.POLICY_BOOLS and k in base and bool(m) != bool(v):
                out.append((k, '%s, where above it is %s' % (str(v).lower(),
                                                             str(base[k]).lower())))
            elif k == 'approval' and base.get('approval'):
                a, have = m or {}, T.approval_rule({'approval': base['approval']})
                vv = T.approval_rule({'approval': v})
                if a.get('mode') != vv['mode'] or int(a.get('count') or 1) != vv['count'] or \
                        bool(a.get('self')) != bool(vv['self']):
                    out.append((k, 'mode %s, %d approver(s)%s - above it: %s, %d%s' % (
                        vv['mode'], vv['count'], ', self' if vv['self'] else '', have['mode'],
                        have['count'], ', self' if have['self'] else '')))
                elif v.get('approvers') and (a.get('approvers') or 'team') != v['approvers']:
                    # fewer levels approving than above it (hunt C1)
                    out.append((k, 'approved by %s - above it by %s' % (
                        v['approvers'], have['approvers'])))
                elif vv['mode'] == 'outside' and not _same_envelope(v.get('outside'),
                                                                     a.get('outside')):
                    # a wider envelope let through without an approval (hunt C1)
                    out.append((k, 'what goes without an approval would be wider than above '
                                   'it'))
    if base.get('pairs') is not None and (new.get('pairs') is not None or 'issuers' in new):
        # the sources with their validations (1.0.128): every pair said here allowed above
        mine = T.level_pairs(new) or {}
        have = {_low(k): v for k, v in base['pairs'].items()}
        extra = []
        for k, (nm, vals) in sorted(mine.items()):
            if k not in have:
                extra.append(nm)
            elif have[k] is not None and (vals is None or any(
                    _low(v) not in {_low(x) for x in have[k]} for v in vals)):
                extra.append('%s with %s' % (nm, ', '.join(
                    v for v in (vals or ['any validation'])
                    if vals is None or _low(v) not in {_low(x) for x in have[k]})))
        if extra:
            out.append(('pairs', '%s not allowed above it' % ', '.join(extra[:10])))
    if new.get('agents_auto_confirm') and not T.policy_value(base, 'agents_auto_confirm'):
        out.append(('agents_auto_confirm', 'agents confirmed by themselves are allowed by the '
                                           'administrators only'))
    return out


def _same_envelope(a, b):
    """Whether two envelopes (approval.outside) let the same through - lists as sets."""
    a, b = a or {}, b or {}
    for k in ('profiles', 'suffixes', 'key_types'):
        x, y = a.get(k), b.get(k)
        if (x is None) != (y is None) or (x is not None and {_low(i) for i in x} !=
                                          {_low(i) for i in y}):
            return False
    return a.get('max_days') == b.get('max_days') and \
        (a.get('wildcards') is False) == (b.get('wildcards') is False)


def need_policy(me, parent, policy, team):
    eff = me.tr.effective(parent) if _low(parent) in me.tr.rows else {}
    bad = widened(eff, policy)
    if bad:
        me.deny('the limits of %s would be wider than those of %s: %s' % (
            team, parent, '; '.join('%s - %s' % kv for kv in bad)))


def name_free(me, name):
    """A name a team made (or renamed) on the portal may take (hunt C1): never one that
    certificates or devices already carry as their owner - the team made would own them (a
    person's own certificates, a free-text owner's), nor a name of a person (a mail or UPN, a
    user of the directory) - what that person asks for on the portal would be the team's."""
    low = _low(name)
    if not low:
        return
    if '@' in low or '\\' in low or low.startswith(('local:', 'group:')):
        me.deny('a team is not called as a person is (%s) - choose another name' % name[:120])
    if low in me.tr.rows:
        return                  # taken: save_team says so in its own words
    for table in ('certs', 'cert_targets', 'cert_tests'):
        if me.store.db.value('SELECT COUNT(*) FROM %s WHERE LOWER(TRIM(owner)) = ?' % table,
                             (low,), 0):
            me.deny('%s is the owner of certificates or devices already - a team made here '
                    'is not given them; choose another name (or ask an administrator)'
                    % name[:120])
    from acmelib.certs import api_teams as AT
    ad = AT.directory(me.h)
    if ad is not None:
        if AT._dir_call(lambda: ad.find_user(name, 'sam')):
            me.deny('%s is a user of the directory - a team is not called as a person is; '
                    'choose another name' % name[:120])


@route('POST', 'team_save')
def _team_save(h):
    me = Me(h)
    b = h.body()
    if 'members' in b:
        raise E.ApiError(400, 'members are changed one by one (member_save)')
    kind = str(b.get('kind') or '').strip() or None
    if kind and kind not in ('team', 'unit'):
        raise E.ApiError(400, 'the kind is team or unit')
    policy = T.clean_policy(b.get('policy')) if 'policy' in b else None
    old = None
    if b.get('old_name'):
        name = me.team(b['old_name'])
        old = T.team_get(h.store, name)
        k = _low(name)
        parent = me.tr.name(me.tr.parent[k]) if me.tr.parent.get(k) else None
        if not parent:
            me.deny('the team %s is at the top - the administrators change it' % name)
        body = {'old_name': name, 'name': b.get('name') or name}
        changes = []
        if _low(body['name']) != k or ('description' in b and str(b.get('description') or '')
                                         .strip() != str(old.get('description') or '')) or \
                (kind and kind != (old.get('kind') or 'team')):
            changes.append('rename')
        new_parent = parent
        if 'parent' in b and _low(b.get('parent')) != _low(parent):
            new_parent = b.get('parent')
            if not _low(new_parent):
                me.deny('only the administrators put a team at the top')
            new_parent = me.need(new_parent, 'team.create', 'move teams under')
            body['parent'] = new_parent
            changes.append('move')
        if changes:
            me.need_above(parent, 'team.create', 'rename or move the team %s' % name)
        if _low(body['name']) != k:
            name_free(me, body['name'])
        if policy is not None and policy != (me.tr.policies.get(k) or {}):
            me.need_above(parent, 'team.policy', 'change the limits of the team %s' % name)
            if _low(new_parent) != _low(parent):
                # its limits set under its new place too (hunt C1: team.create there sufficed)
                me.need_above(new_parent, 'team.policy', 'set the limits of the team %s' % name)
            need_policy(me, new_parent, policy, name)
            body['policy'] = policy
        elif new_parent != parent and me.tr.policies.get(k):
            need_policy(me, new_parent, me.tr.policies.get(k), name)
        if 'description' in b:
            body['description'] = b.get('description')
        if kind:
            body['kind'] = kind
        if not changes and 'policy' not in body:
            return {'team': T.team_public(old, T.used_counts(h.store)),
                    'message': 'nothing changed'}
    else:
        parent = b.get('parent')
        if not _low(parent):
            me.deny('a team made on the portal is under one of your teams - say which (parent)')
        parent = me.need(parent, 'team.create', 'create teams below')
        name = str(b.get('name') or '').strip()
        name_free(me, name)
        body = {'name': name, 'parent': parent, 'kind': kind or 'team',
                'description': b.get('description') or ''}
        if policy:
            me.need(parent, 'team.policy', 'set the limits of the teams below')
            need_policy(me, parent, policy, name)
            body['policy'] = policy
    got = T.save_team(h.store, body, me.by)
    return {'team': got, 'message': 'the team %s is saved' % got['name']}


@route('POST', 'team_delete')
def _team_delete(h):
    me = Me(h)
    b = h.body()
    name = me.team(b.get('name'))
    k = _low(name)
    parent = me.tr.name(me.tr.parent[k]) if me.tr.parent.get(k) else None
    if not parent:
        me.deny('the team %s is at the top - the administrators delete it' % name)
    me.need_above(parent, 'team.create', 'delete the team %s' % name)
    reparent = b.get('reparent')
    if reparent in (None, ''):
        reparent = parent
    reparent = me.need(reparent, 'team.create', 'move the teams below to')
    reassign = b.get('reassign')
    if reassign in (None, ''):
        reassign = parent
    reassign = me.need(reassign, 'team.create', 'give the certificates and devices to')
    if _low(reassign) == k or _low(reassign) in set(me.tr.descendants(k)):
        raise E.ApiError(400, 'the certificates and devices go to a team that stays')
    got = T.delete_team(h.store, name, me.by, reassign=reassign,
                        reparent=reparent if me.tr.children.get(k) else None)
    got['message'] = 'the team %s is deleted' % name
    return got


@route('GET', 'activity')
def _activity(h):
    me = Me(h)
    team = me.need(h.arg('team'), 'team.activity', 'see what happened')
    page, per = _page(h, ACTIVITY_PER, 200)
    rows, total = T.team_activity(h.store, team, per, page * per, below=_flag(h, 'below'))
    return {'team': team, 'rows': rows, 'total': total, 'page': page, 'per': per,
            'pages': (total + per - 1) // per}


# ---------------------------------------------------------------------------
# Governance (1.0.138, docs/teams.md "Governance"): health, temporary roles, access reviews,
# who may do what in a team, viewing as (the banner)
# ---------------------------------------------------------------------------
@route('GET', 'health')
def _health(h):
    """The health of the teams they see the certificates of (cert.view)."""
    from acmelib.certs import teamgov as G
    me = Me(h)
    seen = set(me.reach('cert.view'))
    team = None
    if h.arg('team'):
        team = me.need(h.arg('team'), 'cert.view', 'see the health')
    rows = G.health_public(h.store, seen, detail_team=team)
    return {'teams': rows, 'score': G.summary_score(rows), 'team': team,
            'days': int(E.CONFIG.get('certs_notify_days') or 14)}


@route('GET', 'elevations')
def _elevations(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    actor = G.actor_portal(h, me.s)
    got = G.elevations_for(h.store, actor)
    may = []
    for k in me.reach():
        src, rule = G.jit_rule(h.store, me.tr.rows[k]['name'])
        if rule:
            cat = T.role_catalog(h.store)
            have = _norm(me.caps(k))
            roles = [r for r in rule['roles'] if cat.get(_low(r)) and
                     not _norm(cat[_low(r)]['caps']) <= have]
            if roles:
                may.append({'team': me.tr.rows[k]['name'], 'roles': roles,
                            'max_hours': rule['max_hours'], 'from': src})
    got['may_ask'] = may[:500]
    return got


@route('POST', 'elevate')
def _elevate(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    b = h.body()
    team = me.team(b.get('team'))
    got = G.elevation_ask(h.store, G.actor_portal(h, me.s), team, b.get('role'), b.get('hours'),
                          b.get('reason'))
    return {'elevation': got, 'message': 'asked - a manager of the team %s approves it' % team}


@route('POST', 'elevate_decide')
def _elevate_decide(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    b = h.body()
    got = G.elevation_decide(h.store, b.get('id'), G.actor_portal(h, me.s), A._flag(b.get('ok')),
                             b.get('why'))
    return {'elevation': got, 'message': 'granted until the time it ends by itself'
            if got['state'] == 'granted' else 'declined'}


@route('POST', 'elevate_end')
def _elevate_end(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    got = G.elevation_end(h.store, h.body().get('id'), G.actor_portal(h, me.s))
    return {'elevation': got, 'message': 'ended'}


@route('GET', 'reviews')
def _reviews(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    if h.arg('team'):
        team = me.need(h.arg('team'), 'team.members', 'see the access reviews')
        t = T.team_get(h.store, team)
        return {'team': team, 'rule': G.extras_of(t).get('review'),
                'reviews': G.reviews(h.store, team)}
    # the reviews open where they confirm members
    teams = {k for k in me.reach('team.members')}
    rows = [r for r in G.review_open_rows(h.store) if _low(r['team']) in teams]
    return {'open': rows[:200]}


@route('POST', 'review_open')
def _review_open(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    team = me.need(h.body().get('team'), 'team.members', 'open an access review')
    return {'review': G.review_open(h.store, team, me.by), 'message': 'the review is open'}


@route('POST', 'review_answer')
def _review_answer(h):
    from acmelib.certs import teamgov as G
    me = Me(h)
    b = h.body()
    got = G.review_answer(h.store, b.get('id'), b.get('who'), A._flag(b.get('keep')),
                          G.actor_portal(h, me.s), b.get('note'))
    return {'review': got, 'message': 'confirmed' if A._flag(b.get('keep')) else 'taken out'}


@route('GET', 'whomay')
def _whomay(h):
    """Who may do what in a team, and why - for those who manage its members."""
    from acmelib.certs import teamaccess as TA
    me = Me(h)
    team = me.need(h.arg('team'), 'team.members', 'see who may do what')
    got = TA.team_matrix(h.store, team, admins=False)
    got['mode'] = 'team'
    return got


@route('GET', 'view_as')
def _view_as(h):
    from acmelib.certs import viewas as VA
    P.portal_session(h)
    return VA.portal_public(h)


@E.route('POST', '/api/portal/view_as_enter')
def _view_as_enter(h):
    """{code}: the one-time code of "Open the portal as" - a portal sign-in viewing as the member
    (its token set as the portal's cookie by index.php, never shown to the page)."""
    from acmelib.certs import viewas as VA
    if not E.CONFIG.get('portal'):
        raise E.ApiError(403, 'these pages are switched off')
    return VA.portal_enter(h, h.body().get('code'))
