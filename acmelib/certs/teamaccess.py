# -*- coding: utf-8 -*-
"""
Who may do what - and why (1.0.138, docs/teams.md "Who may do what and why").

    person_matrix(store, names, groups, seen=None)   a person's teams x the capabilities, each
                                                     cell with the memberships that give it
    team_matrix(store, team, seen=None)              a team's people (its own members, those of
                                                     the teams above, roles given for a while,
                                                     the administrators) x the capabilities
    who_can(store, cap, team)                        the reverse: everybody who may `cap` on the
                                                     team (a certificate's: its owner) and why

Built on what the guard itself uses (teams.explain / person_caps / the tree, cached per version
of the teams and the roles) - what is said here is what is enforced. A limit of the team that
still refuses (no key downloads, an action that waits for an approval) is said beside the cell.
"""
from __future__ import annotations

import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import teams as T


def _low(v):
    return str(v or '').strip().lower()


# A capability the team's limits narrow, and how (the cell says it)
APPROVE_CAP = {'revoke': 'cert.revoke', 'delete': 'cert.delete', 'key': 'cert.key',
               'device': 'target.manage'}


def limits_of(eff):
    """{cap: words} of what the limits in force still say about a capability held."""
    out = {}
    if T.policy_value(eff, 'key_download') is False:
        out['cert.key'] = 'the limits forbid downloading keys (%s)' % (
            (eff.get('from') or {}).get('key_download') or 'the team')
    for a in eff.get('approve_actions') or []:
        c = APPROVE_CAP.get(a)
        if c and c not in out:
            out[c] = 'waits for an approval (%s)' % ((eff.get('from') or {}).get(
                'approve_actions') or 'the team')
    if eff.get('free_form') is False and not eff.get('profiles'):
        out.setdefault('cert.request', 'only from a request profile')
    return out


def _via_public(v):
    return {k: v.get(k) for k in ('team', 'who', 'kind', 'rights', 'roles', 'group', 'until',
                                  'expired', 'inherited', 'jit', 'reason', 'caps')
            if v.get(k) not in (None, '', [])}


def person_matrix(store, names, groups, seen=None):
    """{'teams': [{team, kind, parent, depth, caps, via, cells: {cap: [via index]}, limits}]}."""
    tr = T.tree(store)
    rows = []
    for t in T.explain(store, names, groups):
        k = _low(t['team'])
        if seen is not None and k not in seen:
            continue
        via = [_via_public(v) for v in t.get('via') or []]
        cells = {}
        for c in t.get('caps') or []:
            cells[c] = [i for i, v in enumerate(via) if c in (v.get('caps') or [])
                        and not v.get('expired')]
        rows.append({'team': t['team'], 'kind': t.get('kind') or 'team', 'parent': t.get('parent'),
                     'depth': tr.depth(k) if k in tr.rows else 0, 'caps': t.get('caps') or [],
                     'via': via, 'cells': cells, 'limits': limits_of(t.get('policy') or {})})
    return {'teams': rows, 'caps': T.caps_catalog()}


def _admins(store):
    """[{who, role, caps, why}] of the accounts that hold capabilities on every team by their
    role - as teams.unscoped decides."""
    out = []
    try:
        accs = store.accounts()
    except Exception:                                   # noqa: BLE001
        accs = []
    certadmin_all = T._setting('certs_certadmin_all')
    readonly_all = T._setting('certs_readonly_all')
    for a in accs:
        if a.get('disabled'):
            continue
        role = str(a.get('role') or '')
        who = 'local:%s' % a['name'] if a.get('source') != 'directory' else a['name']
        if role == 'fulladmin':
            out.append({'who': who, 'role': role, 'caps': list(T.CAPS),
                        'why': 'a full administrator - every capability on every team, '
                               'whatever is set'})
        elif role in ('certadmin', 'tokenadmin') and certadmin_all:
            out.append({'who': who, 'role': 'certadmin',
                        'caps': [c for c in T.CAPS if not c.startswith('team.')],
                        'why': 'a certificate administrator, with "Certificate administrators '
                               'manage every certificate" on'})
        elif role == 'readonly' and readonly_all:
            out.append({'who': who, 'role': role, 'caps': sorted(T.VIEW_CAPS),
                        'why': 'a read-only account, with "Read-only accounts see every '
                               'certificate" on'})
    return out


def team_matrix(store, team, seen=None, admins=True):
    """{'team', 'people': [{who, kind, caps, cells: {cap: [via index]}, via, admin}], limits}."""
    tr = T.tree(store)
    k = _low(team)
    if k not in tr.rows:
        raise LookupError('there is no team %s' % str(team)[:120])
    cat = T.role_catalog(store)
    now = time.time()
    people = {}
    order = []
    for x in tr.chain(k):
        t = tr.rows[x]
        for m in S.jload(t.get('members'), []) or []:
            if not isinstance(m, dict) or not m.get('who'):
                continue
            c = T.member_caps(m, cat, now)
            w = _low(m['who'])
            if w not in people:
                people[w] = {'who': m['who'], 'kind': T.member_kind(m['who']), 'via': [],
                             'caps': set()}
                order.append(w)
            people[w]['via'].append(_via_public({
                'team': t['name'], 'who': m['who'], 'kind': T.member_kind(m['who']),
                'rights': list(m.get('rights') or []), 'roles': list(m.get('roles') or []),
                'until': m.get('until'), 'expired': T.member_expired(m, now),
                'inherited': x != k, 'caps': [c2 for c2 in T.CAPS if c2 in c]}))
            people[w]['caps'] |= c
    for g in T._grants(store):
        gk = _low(g.get('team'))
        if gk not in tr.chain(k):
            continue
        one = cat.get(_low(g.get('role')))
        if not one:
            continue
        w = _low(g.get('who'))
        if w not in people:
            people[w] = {'who': g.get('who'), 'kind': T.member_kind(g.get('who')), 'via': [],
                         'caps': set()}
            order.append(w)
        people[w]['via'].append(_via_public({
            'team': tr.rows[gk]['name'], 'who': g.get('who'), 'kind': T.member_kind(g.get('who')),
            'roles': [one['name']], 'until': g['until'], 'inherited': gk != k, 'jit': g['id'],
            'reason': g.get('reason'), 'caps': [c2 for c2 in T.CAPS if c2 in one['caps']]}))
        people[w]['caps'] |= one['caps']
    out = []
    for w in order:
        p = people[w]
        caps = [c for c in T.CAPS if c in p['caps']]
        cells = {c: [i for i, v in enumerate(p['via']) if c in (v.get('caps') or [])
                     and not v.get('expired')] for c in caps}
        out.append({'who': p['who'], 'kind': p['kind'], 'caps': caps, 'cells': cells,
                    'via': p['via']})
    if admins:
        rows = {_low(p['who']): p for p in out}
        for a in _admins(store):
            p = rows.get(_low(a['who']))
            if p is not None:
                # a member who is also an administrator: what the role adds, said beside
                for c in a['caps']:
                    if c not in p['caps']:
                        p['caps'].append(c)
                        p['cells'][c] = []
                p['caps'] = [c for c in T.CAPS if c in p['caps']]
                p.update(admin=a['role'], why=a['why'])
                continue
            out.append({'who': a['who'], 'kind': 'local' if a['who'].startswith('local:')
                        else 'user', 'caps': a['caps'], 'admin': a['role'], 'why': a['why'],
                        'cells': {c: [] for c in a['caps']}, 'via': []})
    eff = tr.effective(k)
    return {'team': tr.rows[k]['name'], 'kind': tr.rows[k].get('kind') or 'team',
            'chain': [tr.rows[x]['name'] for x in tr.chain(k)], 'people': out,
            'limits': limits_of(eff), 'caps': T.caps_catalog()}


def who_can(store, cap, team=None, cert=None):
    """Everybody who may `cap` on a team (or a certificate's team) and why:
    {cap, team, cert, people: [...], admins_only, limit}."""
    cap = _low(cap)
    if cap not in T.CAPS:
        raise ValueError('a capability is one of %s' % ', '.join(T.CAPS))
    crow = None
    if cert not in (None, ''):
        crow = T.cert_of_ref(store, cert)
        if not crow:
            raise LookupError('there is no certificate %s' % str(cert)[:120])
        team = crow.get('owner') or ''
    tr = T.tree(store)
    if not _low(team) or _low(team) not in tr.rows:
        # no owner (or one not defined): only those who see every certificate
        return {'cap': cap, 'team': team or None, 'cert': crow['name'] if crow else None,
                'people': [dict(a, cells={cap: []}) for a in _admins(store) if cap in a['caps']],
                'admins_only': True, 'limit': None}
    m = team_matrix(store, team)
    people = [p for p in m['people'] if cap in p['caps']]
    for p in people:
        p['why_here'] = [p['via'][i] for i in p['cells'].get(cap, [])]
    return {'cap': cap, 'team': m['team'], 'cert': crow['name'] if crow else None,
            'chain': m['chain'], 'people': people, 'admins_only': False,
            'limit': m['limits'].get(cap), 'words': T.CAP_WORDS.get(cap)}


def certadmin_note():
    return {'certadmin_all': T._setting('certs_certadmin_all'),
            'readonly_all': T._setting('certs_readonly_all'),
            'site': str(E.CONFIG.get('site_name') or '')}
