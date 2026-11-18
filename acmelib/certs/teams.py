# -*- coding: utf-8 -*-
"""
Owners and teams, tags - and who may see and do what with which certificate
(docs/teams.md).

    teams(store) / team_get / save_team / delete_team       the owners (cert_teams)
    tags(store) / save_tag / delete_tag                     the tags (cert_tags)
    legacy(store) / adopt(store, by)                        what certificates say that
                                                            is not defined (yet)
    scope(store, s, right)                                  None (all) or {team names}
    scope_cap(store, s, cap)                                the same for a capability
    cert_may(store, s, row, right)                          one certificate, one right (or cap)
    guard(h, s, method, path)                               the API's check, per route
    person_teams(store, names, groups)                      {team: rights} of a person
    person_caps(store, names, groups)                       {team: {name, caps, direct}}
    roles(store) / save_role / delete_role                  the roles (built in + cert_roles)
    tree(store) / effective_policy(store, team)             the teams' tree, their limits
    contact_mails(store, cert)                              the owner team's addresses

Enterprise teams (1.0.125, docs/teams.md "Enterprise teams"): a tree of teams (parent),
capabilities given by the old rights and by roles, a member's capabilities applying to the
team and every team below it, limits (policy) narrowed downwards. A team without a parent,
policy or roles works exactly as before.

A full administrator is never scoped, whatever is set; the command line runs as one.
"""
from __future__ import annotations

import json
import re
import time

from acmelib import engine as E
from acmelib.certs import store as S

RIGHTS = ('view', 'request', 'manage', 'approve')
IMPLIES = {'view': {'view'}, 'request': {'view', 'request'},
           'manage': {'view', 'request', 'manage'}, 'approve': {'view', 'approve'}}
KINDS = ('team', 'person', 'unit')
DEFAULT_RIGHTS = ['view', 'request']
COLOURS = ('dim', 'info', 'ok', 'warn', 'crit', 'violet',
           # 1.0.24: more to tell tags apart (teams.css: .tag.tc-<colour>)
           'teal', 'cyan', 'indigo', 'pink', 'rose', 'orange', 'amber', 'lime', 'brown', 'slate')
TAG_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:+-]{0,59}\Z')
MAIL_RE = re.compile(r'^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+\Z')
MEMBER_MAX = 500


def _now():
    return time.time()


def _low(v):
    return str(v or '').strip().lower()


# ---------------------------------------------------------------------------
# Capabilities and roles (1.0.125)
# ---------------------------------------------------------------------------
CAPS = ('cert.view', 'cert.request', 'cert.renew', 'cert.auto', 'cert.edit', 'cert.revoke',
        'cert.delete', 'cert.key', 'cert.approve', 'deploy.view', 'deploy.run', 'deploy.manage',
        'target.view', 'target.manage', 'target.test', 'team.view', 'team.members',
        'team.policy', 'team.create', 'team.activity', 'test.view', 'test.manage')
CAP_WORDS = {
    'cert.view': 'see the team\'s certificates, their jobs and deployments',
    'cert.request': 'ask for new certificates owned by the team',
    'cert.renew': 'renew the team\'s certificates now',
    'cert.auto': 'switch renewing by itself on or off',
    'cert.edit': 'change the team\'s certificates (names, source, validation, details)',
    'cert.revoke': 'revoke the team\'s certificates',
    'cert.delete': 'delete the team\'s certificates',
    'cert.key': 'download a file with the private key',
    'cert.approve': 'approve or decline the team\'s requests',
    'deploy.view': 'see the deployments of the team\'s certificates',
    'deploy.run': 'run deployments now',
    'deploy.manage': 'add, change and delete deployments',
    'target.view': 'see the team\'s devices',
    'target.manage': 'add, change and delete the team\'s devices (and confirm its agents)',
    'target.test': 'test the team\'s devices',
    'team.view': 'see the team, its members and its limits',
    'team.members': 'add, change and remove members (never more than one holds oneself)',
    'team.policy': 'change the limits of the teams below',
    'team.create': 'create, rename and delete teams below',
    'team.activity': 'see what happened in the team',
    'test.view': 'see the team\'s tests',
    'test.manage': 'add, change, delete and run the team\'s tests',
}
CAP_GROUPS = (('Certificates', ('cert.view', 'cert.request', 'cert.renew', 'cert.auto',
                                'cert.edit', 'cert.revoke', 'cert.delete', 'cert.key',
                                'cert.approve')),
              ('Deployments', ('deploy.view', 'deploy.run', 'deploy.manage')),
              ('Devices', ('target.view', 'target.manage', 'target.test')),
              ('Tests', ('test.view', 'test.manage')),
              ('The team', ('team.view', 'team.members', 'team.policy', 'team.create',
                            'team.activity')))
VIEW_CAPS = frozenset(('cert.view', 'deploy.view', 'target.view', 'team.view'))
# The old rights, as capabilities - a member with an old right holds exactly what it gave.
RIGHT_CAPS = {'view': VIEW_CAPS}
RIGHT_CAPS['request'] = RIGHT_CAPS['view'] | {'cert.request'}
RIGHT_CAPS['manage'] = RIGHT_CAPS['request'] | {'cert.renew', 'cert.auto', 'cert.edit',
                                                'cert.revoke', 'cert.delete', 'cert.key',
                                                'deploy.run', 'deploy.manage'}
# The old right `manage` also approved its team's requests (1.0.16). A marker of its own keeps
# that for members with the old right, while the role "Certificate manager" (the same
# certificate caps) does not approve - approving is the Approver's (1.0.125).
LEGACY_MANAGE = 'legacy.manage'
RIGHT_CAPS['manage'] = RIGHT_CAPS['manage'] | {LEGACY_MANAGE}
RIGHT_CAPS['approve'] = RIGHT_CAPS['view'] | {'cert.approve'}
# test.view (1.0.128): a viewer sees the team's tests too - the old right `view` stays as it was
_R_VIEWER = VIEW_CAPS | {'test.view'}
_R_REQUESTER = _R_VIEWER | {'cert.request'}
_R_RENEWER = _R_VIEWER | {'cert.renew', 'cert.auto'}
# The built-in roles: in the code, never in the table, never changed or deleted.
BUILTIN_ROLES = (
    ('Viewer', _R_VIEWER, 'sees the team\'s certificates, deployments, devices and tests'),
    ('Requester', _R_REQUESTER, 'a viewer who asks for new certificates'),
    ('Renewer', _R_RENEWER, 'a viewer who renews certificates and switches renewing by itself'),
    ('Deployer', _R_VIEWER | {'deploy.run'}, 'a viewer who runs deployments'),
    ('Device manager', _R_VIEWER | {'target.manage', 'target.test', 'deploy.manage',
                                    'deploy.run', 'test.manage'},
     'looks after the team\'s devices and the deployments to them'),
    ('Certificate manager', _R_REQUESTER | _R_RENEWER | {
        'cert.edit', 'cert.revoke', 'cert.delete', 'cert.key', 'deploy.run', 'deploy.manage'},
     'everything with the team\'s certificates but approving'),
    ('Approver', _R_VIEWER | {'cert.approve'}, 'a viewer who approves or declines requests'),
    ('Team manager', _R_VIEWER | {'team.members', 'team.policy', 'team.create',
                                  'team.activity'},
     'runs the team: its members, the teams below and their limits'),
    ('Team owner', frozenset(CAPS), 'every capability'),
)
ROLE_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,59}\Z')
ROLES_MOST = 200


def _version(store):
    """What changes when a team or a role does: the tree and the people's capabilities are
    computed again (kept per store, a generation bumped by every save here, and 30 s at most
    for what another node or an import wrote)."""
    try:
        a = store.db.row('SELECT COUNT(*) AS n, MAX(updated) AS u, MAX(id) AS i FROM cert_teams')
        b = store.db.row('SELECT COUNT(*) AS n, MAX(updated) AS u, MAX(id) AS i FROM cert_roles')
    except Exception:                                   # noqa: BLE001
        return None
    return (id(store), _GEN[0], int(time.time() // 30),
            tuple((a or {}).values()), tuple((b or {}).values()))


_GEN = [0]
_CACHE = {}                 # ('tree', version) / ('caps', version, principal) -> value
_CACHE_MOST = 4096


def changed():
    """A team or a role saved: what was computed of them is computed again."""
    _GEN[0] += 1
    _CACHE.clear()


def _cached(key, make):
    if key[1] is None:
        return make()
    got = _CACHE.get(key)
    if got is not None:
        return got
    got = make()
    if len(_CACHE) >= _CACHE_MOST:
        _CACHE.clear()
    _CACHE[key] = got
    return got


def role_rows(store):
    try:
        return store.db.rows('SELECT * FROM cert_roles ORDER BY name')
    except Exception:                                   # noqa: BLE001
        return []


def clean_caps(v):
    if isinstance(v, str):
        v = [w for w in re.split(r'[\s,;+|]+', v) if w]
    got = set()
    for c in v or []:
        c = str(c).strip().lower()
        if c in ('*', 'all'):
            got |= set(CAPS)
            continue
        if c in RIGHTS:                     # an old right is what it gave
            got |= RIGHT_CAPS[c]
            continue
        if c not in CAPS:
            raise ValueError('a capability is one of %s, not %r' % (', '.join(CAPS), c))
        got.add(c)
    return [c for c in CAPS if c in got]


def role_catalog(store):
    """{name lower: {'name', 'caps' (frozenset), 'builtin', 'description'}}."""
    def make():
        out = {}
        for name, caps, words in BUILTIN_ROLES:
            out[name.lower()] = {'name': name, 'caps': frozenset(caps), 'builtin': True,
                                 'description': words}
        for r in role_rows(store):
            k = _low(r['name'])
            if k in out:
                continue
            try:
                caps = frozenset(clean_caps(S.jload(r.get('caps'), []) or []))
            except ValueError:
                caps = frozenset(c for c in (S.jload(r.get('caps'), []) or []) if c in CAPS)
            out[k] = {'name': r['name'], 'caps': caps, 'builtin': False,
                      'description': r.get('description') or '', 'id': r['id'],
                      'updated': r.get('updated'), 'updated_by': r.get('updated_by')}
        return out
    return _cached(('roles', _version(store)), make)


def roles(store):
    """The roles as the pages show them: built in first, then the custom ones, each with its
    capabilities and how many members carry it."""
    used = {}
    for t in team_rows(store):
        for m in S.jload(t.get('members'), []) or []:
            if isinstance(m, dict):
                for r in m.get('roles') or []:
                    used[_low(r)] = used.get(_low(r), 0) + 1
    out = []
    for k, r in role_catalog(store).items():
        out.append({'name': r['name'], 'builtin': r['builtin'], 'description': r['description'],
                    'caps': [c for c in CAPS if c in r['caps']], 'used': used.get(k, 0)})
    return out


def caps_catalog():
    return [{'id': c, 'words': CAP_WORDS[c], 'group': g} for g, cs in CAP_GROUPS for c in cs]


def _role_members_rename(store, old, new, by):
    """Every member carrying the role `old` given `new` (None: taken off) -> members changed."""
    n = 0
    for t in team_rows(store):
        ms = S.jload(t.get('members'), []) or []
        hit = False
        for m in ms:
            if isinstance(m, dict) and any(_low(r) == _low(old) for r in m.get('roles') or []):
                got = []
                for r in m.get('roles') or []:
                    r = new if _low(r) == _low(old) else r
                    if r and _low(r) not in {_low(x) for x in got}:
                        got.append(r)
                if got:
                    m['roles'] = got
                else:
                    m.pop('roles', None)
                hit = True
                n += 1
        if hit:
            ms = [m for m in ms if not isinstance(m, dict) or m.get('rights') or m.get('roles')]
            store.db.update('cert_teams', t['id'], {'members': json.dumps(ms),
                                                    'updated': _now(), 'updated_by': str(by)[:190]})
    return n


def save_role(store, b, by):
    """A custom role added or changed: {name, old_name?, description, caps}."""
    cat = role_catalog(store)
    old = None
    if b.get('old_name'):
        old = next((r for r in role_rows(store) if _low(r['name']) == _low(b['old_name'])), None)
        if not old:
            if _low(b['old_name']) in cat:
                raise ValueError('%s is a built-in role - it is not changed (copy it into a role '
                                 'of your own)' % cat[_low(b['old_name'])]['name'])
            raise LookupError('there is no role %s' % b['old_name'])
    name = str(b.get('name') or '').strip()
    if not ROLE_NAME_RE.match(name):
        raise ValueError('a role\'s name: letters, digits, spaces and . _ + - (60 at most), '
                         'starting with a letter or a digit')
    if name.lower() in {n.lower() for n, _c, _w in BUILTIN_ROLES}:
        raise ValueError('%s is a built-in role - choose another name' % name)
    if name.lower() in RIGHTS:
        raise ValueError('%s is an old right - choose another name' % name)
    other = next((r for r in role_rows(store) if _low(r['name']) == _low(name)), None)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is a role called %s already' % other['name'])
    if not old and len(role_rows(store)) >= ROLES_MOST:
        raise ValueError('%d roles at most' % ROLES_MOST)
    caps = clean_caps(b.get('caps') if 'caps' in b else S.jload((old or {}).get('caps'), []))
    if not caps:
        raise ValueError('a role gives at least one capability')
    row = {'name': name, 'caps': json.dumps(caps),
           'description': str(b.get('description', (old or {}).get('description')) or '')
           .strip()[:500], 'updated': _now(), 'updated_by': str(by)[:190]}
    if old:
        store.db.update('cert_roles', old['id'], row)
        if old['name'] != name:
            _role_members_rename(store, old['name'], name, by)
        store.add_event('certificates', 'the role %s changed by %s%s: %s' % (
            name, by, (' (was %s)' % old['name']) if old['name'] != name else '',
            ', '.join(caps)), who=by)
    else:
        row.update(created=_now(), created_by=str(by)[:190])
        store.db.insert('cert_roles', row)
        store.add_event('certificates', 'the role %s added by %s: %s' % (
            name, by, ', '.join(caps)), who=by)
    changed()
    return next(r for r in roles(store) if r['name'] == name)


def delete_role(store, name, by, strip=False):
    row = next((r for r in role_rows(store) if _low(r['name']) == _low(name)), None)
    if not row:
        if _low(name) in role_catalog(store):
            raise ValueError('%s is a built-in role - it is not deleted' % name)
        raise LookupError('there is no role %s' % name)
    used = next((r['used'] for r in roles(store) if _low(r['name']) == _low(row['name'])), 0)
    if used and not strip:
        raise ValueError('%s is given to %d member(s) - delete it with strip to take it off '
                         'them' % (row['name'], used))
    if used:
        _role_members_rename(store, row['name'], None, by)
    store.db.run('DELETE FROM cert_roles WHERE id = ?', (row['id'],))
    store.add_event('certificates', 'the role %s deleted by %s%s' % (
        row['name'], by, (' - taken off %d member(s)' % used) if used else ''),
        'warn' if used else 'info', who=by)
    changed()
    return {'deleted': row['name'], 'stripped': used}


def member_caps(m, cat, now=None):
    """The capabilities one member (a dict) gives: its rights and its roles - none once its
    `until` has passed."""
    if not isinstance(m, dict) or member_expired(m, now):
        return frozenset()
    got = set()
    for r in m.get('rights') or []:
        got |= RIGHT_CAPS.get(r, set())
    for r in m.get('roles') or []:
        one = cat.get(_low(r))
        if one:
            got |= one['caps']
    return frozenset(got)


def member_expired(m, now=None):
    u = m.get('until') if isinstance(m, dict) else None
    if u in (None, '', 0):
        return False
    try:
        return float(u) <= (time.time() if now is None else now)
    except (TypeError, ValueError):
        return False


def rights_of_caps(caps):
    """The old rights a set of capabilities holds in full (for the old callers)."""
    # the marker of the old right is not a capability of its own: a member whose roles hold
    # every capability of `manage` holds `manage`, as before the marker
    return {r for r in RIGHTS if (RIGHT_CAPS[r] - {LEGACY_MANAGE}) <= caps}


# ---------------------------------------------------------------------------
# The tree (1.0.125)
# ---------------------------------------------------------------------------
class Tree(object):
    """The teams as a tree, computed once per version: rows by lower name, parent, children,
    top-down order, policies."""
    def __init__(self, rows):
        self.rows = {}
        self.parent = {}
        self.children = {}
        for t in rows:
            k = _low(t['name'])
            self.rows[k] = t
        for k, t in self.rows.items():
            p = _low(t.get('parent'))
            self.parent[k] = p if p and p in self.rows and p != k else None
        # a cycle written by hand (never by save_team): broken where it closes - at a team of
        # the cycle itself; a team merely below a cycle keeps its parent (hunt Rt1: it was put
        # at the top level, its inherited capabilities and limits lost)
        for k in list(self.rows):
            seen, at = {k}, self.parent[k]
            while at:
                if at == k:
                    self.parent[k] = None
                    break
                if at in seen:
                    break
                seen.add(at)
                at = self.parent.get(at)
        for k, p in self.parent.items():
            self.children.setdefault(p, []).append(k)
        for v in self.children.values():
            v.sort(key=lambda x: self.rows[x]['name'].lower())
        self.order = []
        todo = list(self.children.get(None, []))
        while todo:
            k = todo.pop(0)
            self.order.append(k)
            todo[0:0] = self.children.get(k, [])
        self.policies = {k: policy_of(t) for k, t in self.rows.items()}
        self._eff = {}

    def name(self, k):
        t = self.rows.get(_low(k))
        return t['name'] if t else None

    def ancestors(self, k):
        """[parent, grandparent, ...] (lower names)."""
        out, at = [], self.parent.get(_low(k))
        while at:
            out.append(at)
            at = self.parent.get(at)
        return out

    def chain(self, k):
        """[top, ..., k] (lower names)."""
        k = _low(k)
        return list(reversed(self.ancestors(k))) + ([k] if k in self.rows else [])

    def descendants(self, k):
        out, todo = [], list(self.children.get(_low(k), []))
        while todo:
            x = todo.pop()
            out.append(x)
            todo.extend(self.children.get(x, []))
        return out

    def depth(self, k):
        return len(self.ancestors(k))

    def effective(self, k):
        k = _low(k)
        if k not in self._eff:
            self._eff[k] = merge_policies([(self.rows[x]['name'], self.policies.get(x) or {})
                                           for x in self.chain(k)])
        return self._eff[k]


def tree(store):
    return _cached(('tree', _version(store)), lambda: Tree(team_rows(store)))


def descendants(store, team):
    return [tree(store).rows[k]['name'] for k in tree(store).descendants(team)]


def tree_public(store, counts=None):
    """[{name, kind, parent, depth, children: [names], description, members, certs}] top-down."""
    tr = tree(store)
    counts = counts or {}
    out = []
    for k in tr.order:
        t = tr.rows[k]
        out.append({'name': t['name'], 'kind': t.get('kind') or 'team',
                    'parent': tr.name(tr.parent[k]) if tr.parent[k] else None,
                    'depth': tr.depth(k), 'children': [tr.rows[c]['name']
                                                       for c in tr.children.get(k, [])],
                    'description': t.get('description') or '',
                    'members': len([m for m in S.jload(t.get('members'), []) or []
                                    if isinstance(m, dict)]),
                    'certs': counts.get(k, 0)})
    return out


# ---------------------------------------------------------------------------
# Whose capabilities, where (1.0.125)
# ---------------------------------------------------------------------------
def _principal_key(names, groups):
    gset = set()
    for dn, cn in groups or ():
        gset.add(_low(dn))
        gset.add(_low(cn))
    gset.discard('')
    return frozenset(_low(n) for n in names or () if n), frozenset(gset)


def _matches_fast(who, names, gset):
    """member_matches with the groups as a set (a person in hundreds of groups, thousands of
    members): the same answer."""
    w = _low(who)
    if not w:
        return False
    if w in names:
        return True
    if w.startswith('local:'):
        return False
    bare = w[6:].strip() if w.startswith('group:') else w
    return bare in gset


def person_caps(store, names, groups):
    """{team lower: {'name', 'caps' (frozenset, inherited from the teams above too),
    'direct' (its own memberships only)}} of a person by their names and groups - computed once
    per version of the teams and the person (2000 teams, nested groups: one pass)."""
    names, gset = _principal_key(names, groups)
    ver = _version(store)

    def make():
        tr = tree(store)
        cat = role_catalog(store)
        now = time.time()
        direct = {}
        for k, t in tr.rows.items():
            got = set()
            for m in S.jload(t.get('members'), []) or []:
                if isinstance(m, dict) and _matches_fast(m.get('who'), names, gset):
                    got |= member_caps(m, cat, now)
            if got:
                direct[k] = frozenset(got)
        if not direct:
            return {}
        out = {}
        eff = {}
        for k in tr.order:
            c = direct.get(k, frozenset()) | eff.get(tr.parent[k], frozenset())
            if c:
                eff[k] = c
                out[k] = {'name': tr.rows[k]['name'], 'caps': c,
                          'direct': direct.get(k, frozenset())}
        return out
    return _cached(('caps', ver, names, gset), make)


def person_teams(store, names, groups):
    """{team name lower: (team name, {rights})} of a person, by their names and groups - the old
    rights their capabilities hold in full (inherited from the teams above too; a member whose
    `until` passed none)."""
    return {k: (v['name'], rights_of_caps(v['caps']))
            for k, v in person_caps(store, names, groups).items() if rights_of_caps(v['caps'])}


def explain(store, names, groups):
    """Why a person holds what, per team: [{team, caps, via: [{team, who, kind, rights, roles,
    group, inherited, until}]}] - the access check."""
    names, gset = _principal_key(names, groups)
    tr = tree(store)
    cat = role_catalog(store)
    now = time.time()
    hits = {}
    for k, t in tr.rows.items():
        for m in S.jload(t.get('members'), []) or []:
            if not isinstance(m, dict) or not _matches_fast(m.get('who'), names, gset):
                continue
            c = member_caps(m, cat, now)
            w = _low(m.get('who'))
            hits.setdefault(k, []).append({
                'team': t['name'], 'who': m.get('who'), 'kind': member_kind(m.get('who')),
                'rights': list(m.get('rights') or []), 'roles': list(m.get('roles') or []),
                'group': None if w in names else (w[6:] if w.startswith('group:') else w),
                'until': m.get('until'), 'expired': member_expired(m, now),
                'caps': [x for x in CAPS if x in c]})
    caps = person_caps(store, names, [(g, g) for g in gset])
    out = []
    for k in tr.order:
        if k not in caps:
            continue
        via = []
        for x in tr.chain(k):
            for one in hits.get(x, []):
                via.append(dict(one, inherited=x != k))
        out.append({'team': tr.rows[k]['name'], 'kind': tr.rows[k].get('kind') or 'team',
                    'parent': tr.name(tr.parent[k]) if tr.parent[k] else None,
                    'caps': [c for c in CAPS if c in caps[k]['caps']],
                    'rights': sorted(rights_of_caps(caps[k]['caps'])), 'via': via,
                    'policy': tr.effective(k)})
    # memberships that give nothing now (expired): said too
    for k, lst in hits.items():
        if k not in caps:
            out.append({'team': tr.rows[k]['name'], 'kind': tr.rows[k].get('kind') or 'team',
                        'parent': tr.name(tr.parent[k]) if tr.parent[k] else None,
                        'caps': [], 'rights': [], 'via': [dict(o, inherited=False) for o in lst],
                        'policy': tr.effective(k)})
    return out


def session_caps(store, s):
    """{team lower: {...}} of a session of the administration (person_caps)."""
    names, groups = admin_principal(s)
    return person_caps(store, names, groups)


# ---------------------------------------------------------------------------
# Policy: a team's limits (1.0.125)
# ---------------------------------------------------------------------------
POLICY_LISTS = ('profiles', 'issuers', 'validations', 'target_kinds', 'suffixes')
POLICY_BOOLS = {'free_form': True, 'key_download': True, 'agents': True,
                'agents_auto_confirm': False}
POLICY_INTS = ('max_certs', 'max_days')
APPROVAL_MODES = ('none', 'outside', 'profile', 'always')        # weakest first
APPROVERS = ('team', 'parent', 'team_or_parent', 'both')
APPROVE_ACTIONS = ('revoke', 'delete', 'key', 'device')
POLICY_KEYS = POLICY_LISTS + tuple(POLICY_BOOLS) + POLICY_INTS + ('approval',
                                                                  'approve_actions')


def policy_of(t):
    p = S.jload((t or {}).get('policy'), None)
    return p if isinstance(p, dict) else {}


def _words_list(v, what, most=500, low=True):
    if v is None:
        return None
    if isinstance(v, str):
        v = [w for w in re.split(r'[\s,;]+', v) if w]
    if not isinstance(v, (list, tuple)):
        raise ValueError('%s is a list (or null: no limit)' % what)
    out = []
    for w in v:
        if isinstance(w, (dict, list)) or w in (None, ''):
            raise ValueError('%s is a list of names' % what)
        w = str(w).strip()
        w = w.lower() if low else w
        if len(w) > 253 or any(ord(c) < 32 for c in w):
            raise ValueError('%s: %r is not a name' % (what, w[:60]))
        if w not in out:
            out.append(w)
    if len(out) > most:
        raise ValueError('%s: %d at most' % (what, most))
    return out


def clean_approval(v):
    """The approval rule: an object (or the old words "profile" / "always")."""
    if v in (None, '', {}):
        return None
    if isinstance(v, str):
        v = {'mode': v}
    if not isinstance(v, dict):
        raise ValueError('approval is {mode, approvers, count, self, outside}')
    bad = set(v) - {'mode', 'approvers', 'count', 'self', 'outside'}
    if bad:
        raise ValueError('approval knows no %s' % ', '.join(sorted(bad)))
    mode = str(v.get('mode') or 'profile')
    if mode not in APPROVAL_MODES:
        raise ValueError('approval.mode is one of %s' % ', '.join(APPROVAL_MODES))
    out = {'mode': mode}
    if v.get('approvers') not in (None, ''):
        if v['approvers'] not in APPROVERS:
            raise ValueError('approval.approvers is one of %s' % ', '.join(APPROVERS))
        out['approvers'] = v['approvers']
    if v.get('count') not in (None, ''):
        try:
            n = int(v['count'])
        except (TypeError, ValueError):
            n = 0
        if n not in (1, 2):
            raise ValueError('approval.count is 1 or 2')
        out['count'] = n
    if v.get('self') not in (None, ''):
        out['self'] = bool(v['self']) and str(v['self']).lower() not in ('0', 'false', 'no')
    if v.get('outside') not in (None, '', {}):
        o = v['outside']
        if not isinstance(o, dict):
            raise ValueError('approval.outside is {profiles, suffixes, max_days, key_types}')
        bad = set(o) - {'profiles', 'suffixes', 'max_days', 'key_types'}
        if bad:
            raise ValueError('approval.outside knows no %s' % ', '.join(sorted(bad)))
        oo = {}
        for k in ('profiles', 'suffixes', 'key_types'):
            if o.get(k) is not None:
                oo[k] = _words_list(o[k], 'approval.outside.' + k, low=k != 'profiles')
        if o.get('max_days') not in (None, ''):
            oo['max_days'] = _pos_int(o['max_days'], 'approval.outside.max_days')
        out['outside'] = oo
    return out


def _pos_int(v, what):
    if isinstance(v, bool):
        raise ValueError('%s is a whole number' % what)
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a whole number' % what)
    if n < 0 or n > 10 ** 6:
        raise ValueError('%s is 0 to 1000000' % what)
    return n


def clean_policy(v):
    """A team's own limits -> a dict of the keys set (an empty one: no limit of its own)."""
    if v in (None, '', {}):
        return {}
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise ValueError('the policy is JSON: {"profiles": [...], "max_days": 90, ...}')
    if not isinstance(v, dict):
        raise ValueError('the policy is an object of limits')
    bad = set(v) - set(POLICY_KEYS)
    if bad:
        raise ValueError('a policy knows no %s (it knows %s)' % (', '.join(sorted(bad)),
                                                                  ', '.join(POLICY_KEYS)))
    out = {}
    for k in POLICY_LISTS:
        if k in v and v[k] is not None:
            out[k] = _words_list(v[k], k, low=k not in ('profiles', 'issuers', 'validations'))
            if k == 'suffixes':
                out[k] = [w.lstrip('*').lstrip('.') for w in out[k]]
    for k, _d in POLICY_BOOLS.items():
        if k in v and v[k] is not None:
            if not isinstance(v[k], bool) and str(v[k]).lower() not in ('0', '1', 'true',
                                                                          'false'):
                raise ValueError('%s is true or false' % k)
            out[k] = v[k] if isinstance(v[k], bool) else str(v[k]).lower() in ('1', 'true')
    for k in POLICY_INTS:
        if k in v and v[k] not in (None, ''):
            out[k] = _pos_int(v[k], k)
    if 'approval' in v:
        a = clean_approval(v['approval'])
        if a:
            out['approval'] = a
    if v.get('approve_actions') is not None:
        acts = _words_list(v['approve_actions'], 'approve_actions')
        bad = [a for a in acts if a not in APPROVE_ACTIONS]
        if bad:
            raise ValueError('approve_actions are of %s' % ', '.join(APPROVE_ACTIONS))
        out['approve_actions'] = acts
    return out


def _under(name, suffix):
    name, suffix = _low(name).lstrip('*').lstrip('.'), _low(suffix).lstrip('*').lstrip('.')
    return name == suffix or name.endswith('.' + suffix)


def _meet_suffixes(a, b):
    out = []
    for x in a:
        for y in b:
            z = x if _under(x, y) else (y if _under(y, x) else None)
            if z and z not in out:
                out.append(z)
    return out


_APPROVER_LEVELS = {'team': frozenset(['team']), 'parent': frozenset(['parent']),
                    'both': frozenset(['team', 'parent']), 'team_or_parent': frozenset()}


def _meet_approvers(a, b):
    """The approvers of two rules in force at once: the levels both want (team_or_parent wants
    either, so the other's)."""
    if not a or not b or a == b:
        return b or a
    want = _APPROVER_LEVELS.get(a, frozenset()) | _APPROVER_LEVELS.get(b, frozenset())
    if want == {'team', 'parent'}:
        return 'both'
    if want:
        return next(iter(want))
    return 'team_or_parent'


def _meet_envelopes(a, b):
    """The pre-approved envelope (approval.outside) of two rules: what both let through."""
    if a is None or b is None:
        return b if a is None else a
    out = {}
    for k in ('profiles', 'key_types'):
        if a.get(k) is None or b.get(k) is None:
            v = a.get(k) if b.get(k) is None else b.get(k)
        else:
            mine = {_low(x) for x in b[k]}
            v = [x for x in a[k] if _low(x) in mine]
        if v is not None:
            out[k] = list(v)
    if a.get('suffixes') is None or b.get('suffixes') is None:
        v = a.get('suffixes') if b.get('suffixes') is None else b.get('suffixes')
    else:
        v = _meet_suffixes(a['suffixes'], b['suffixes'])
    if v is not None:
        out['suffixes'] = list(v)
    ds = [x.get('max_days') for x in (a, b) if x.get('max_days') is not None]
    if ds:
        out['max_days'] = min(int(d) for d in ds)
    return out


def merge_policies(chain):
    """The limits in force for the last team of `chain` ([(team, own policy)] top first): the
    intersection - a team below only narrows what those above allow. `from` says which team's
    limit each key is (the inner-most that narrowed it)."""
    eff, src = {}, {}
    for team, p in chain:
        for k in POLICY_LISTS:
            if p.get(k) is None:
                continue
            if k not in eff:
                eff[k] = list(p[k])
            elif k == 'suffixes':
                eff[k] = _meet_suffixes(eff[k], p[k])
            else:
                mine = {_low(x) for x in p[k]}
                eff[k] = [x for x in eff[k] if _low(x) in mine]
            src[k] = team
        for k, d in POLICY_BOOLS.items():
            if k not in p:
                continue
            if k == 'agents_auto_confirm':
                eff[k] = bool(p[k]) and eff.get(k, True) is not False
            else:
                eff[k] = bool(p[k]) and eff.get(k, True)
            src[k] = team
        for k in POLICY_INTS:
            if p.get(k) is not None and (eff.get(k) is None or p[k] < eff[k]):
                eff[k] = p[k]
                src[k] = team
        a = p.get('approval')
        if a:
            have = eff.get('approval') or {}
            m = a.get('mode', 'profile')
            if not have or APPROVAL_MODES.index(m) >= APPROVAL_MODES.index(have.get('mode',
                                                                                 'profile')):
                new = dict(a)
            else:
                new = dict(have)
            new['count'] = max(int(a.get('count') or 1), int(have.get('count') or 1))
            new['self'] = bool(a.get('self', False)) and bool(have.get('self', True))
            if have:
                # who approves: never fewer levels than above (hunt C1: a team below said
                # "team" in the same mode and its leads alone approved what the team above had
                # made wait for both)
                ap = _meet_approvers(have.get('approvers'), a.get('approvers'))
                if ap:
                    new['approvers'] = ap
                if new.get('mode') == 'outside':
                    # the envelope let through without an approval: never wider than above
                    env = _meet_envelopes(have.get('outside') if have.get('mode') == 'outside'
                                          else None,
                                          a.get('outside') if m == 'outside' else None)
                    if env is not None:
                        new['outside'] = env
            eff['approval'] = new
            src['approval'] = team
        if p.get('approve_actions'):
            eff['approve_actions'] = sorted(set(eff.get('approve_actions') or [])
                                            | set(p['approve_actions']))
            src['approve_actions'] = team
    if eff:
        eff['from'] = src
    return eff


def policy_rename(store, key, old, new):
    """A source (key 'issuers'), a validation ('validations') or a request profile ('profiles')
    renamed: the teams' limits naming it follow (hunt Rt1: they kept the old name, and the team
    was refused what it was allowed - "the source X is not one it may use (old)"). The
    pre-approved envelope (approval.outside.profiles) follows a profile too. -> teams changed."""
    if key not in ('issuers', 'validations', 'profiles') or not new or _low(old) == '' or \
            str(old) == str(new):
        return 0

    def swap(lst):
        if not isinstance(lst, list) or not any(_low(x) == _low(old) for x in lst):
            return lst, False
        out = []
        for x in lst:
            x = new if _low(x) == _low(old) else x
            if _low(x) not in {_low(y) for y in out}:
                out.append(x)
        return out, True

    n = 0
    for t in team_rows(store):
        p = policy_of(t)
        if not p:
            continue
        p[key], hit = swap(p.get(key))
        if p[key] is None:
            p.pop(key)
        a = p.get('approval')
        if key == 'profiles' and isinstance(a, dict) and isinstance(a.get('outside'), dict):
            a['outside']['profiles'], hit2 = swap(a['outside'].get('profiles'))
            if a['outside']['profiles'] is None:
                a['outside'].pop('profiles')
            hit = hit or hit2
        if hit:
            store.db.update('cert_teams', t['id'], {'policy': json.dumps(p),
                                                    'updated': _now()})
            n += 1
    if n:
        changed()
    return n


def effective_policy(store, team):
    """The limits in force for a team ({} none - as before)."""
    tr = tree(store)
    if _low(team) not in tr.rows:
        return {}
    return tr.effective(team)


def policy_value(eff, key):
    """A key of an effective policy, its default where no team said it."""
    if key in POLICY_BOOLS:
        return eff.get(key, POLICY_BOOLS[key])
    return eff.get(key)


def approval_rule(eff):
    """{mode, approvers, count, self, outside} in force ('profile' as before when none)."""
    a = dict(eff.get('approval') or {})
    a.setdefault('mode', 'profile')
    a.setdefault('approvers', 'team')
    a['count'] = int(a.get('count') or 1)
    a.setdefault('self', False)
    return a


# ---------------------------------------------------------------------------
# Members and their rights
# ---------------------------------------------------------------------------
def clean_rights(v):
    if isinstance(v, str):
        v = [w for w in re.split(r'[\s,;+|]+', v) if w]
    got = []
    for r in v or []:
        r = str(r).strip().lower()
        if r not in RIGHTS:
            raise ValueError('a right is one of %s, not %r' % (', '.join(RIGHTS), r))
        if r not in got:
            got.append(r)
    return [r for r in RIGHTS if r in got]


def clean_member(m, cat=None):
    """{'who', 'rights'} of one member: local:NAME, a directory user (its
    sAMAccountName, UPN or mail), group:NAME or a group's DN - and (1.0.125) its `roles`
    (names of the roles catalog, `cat`), `until` (epoch: the membership ends then) and a
    `note`, kept only where given."""
    if isinstance(m, str):
        who, _, rights = m.partition('=')
        words = [w.strip() for w in re.split(r'[,;+|]+', rights) if w.strip()]
        if words and any(w.lower() not in RIGHTS for w in words):
            # who=Requester+Deployer (1.0.125): roles, the old rights among them kept as rights
            m = {'who': who, 'rights': [w for w in words if w.lower() in RIGHTS],
                 'roles': [w for w in words if w.lower() not in RIGHTS]}
        else:
            m = {'who': who, 'rights': rights or list(DEFAULT_RIGHTS)}
    if not isinstance(m, dict):
        raise ValueError('a member is {who, rights}')
    who = str(m.get('who') or '').strip()
    if not who or len(who) > 500 or any(ord(c) < 32 for c in who):
        raise ValueError('a member is local:NAME, a user of the directory, group:NAME or a '
                         'group\'s DN (500 characters at most)')
    if who.lower().startswith('local:'):
        name = who[6:].strip()
        if not name:
            raise ValueError('local: needs the name of an account')
        who = 'local:' + name
    elif who.lower().startswith('group:'):
        if not who[6:].strip():
            raise ValueError('group: needs the name of a group')
        who = 'group:' + who[6:].strip()
    roles_ = m.get('roles')
    if isinstance(roles_, str):
        roles_ = [w for w in re.split(r'[,;+|]+', roles_) if w.strip()]
    if roles_ is not None and not isinstance(roles_, (list, tuple)):
        raise ValueError('the roles of a member are a list of names')
    got_roles = []
    for r in roles_ or []:
        r = str(r).strip()
        if not r:
            continue
        if cat is not None:
            one = cat.get(r.lower())
            if not one:
                raise ValueError('there is no role %s' % r[:60])
            r = one['name']
        if r.lower() not in {x.lower() for x in got_roles}:
            got_roles.append(r)
    given = m.get('rights')
    if given is None and got_roles:
        rights = []
    else:
        rights = clean_rights(given if given is not None else DEFAULT_RIGHTS)
    if not rights and not got_roles:
        raise ValueError('%s has no right - give it at least view' % who)
    out = {'who': who, 'rights': rights}
    if got_roles:
        out['roles'] = got_roles
    if m.get('until') not in (None, '', 0):
        try:
            u = float(m['until'])
        except (TypeError, ValueError):
            u = _date_epoch(m['until'])
        # before the year 10000 (253402300799 = 9999-12-31 23:59:59 UTC): a later one was kept,
        # and every page and command showing the member then failed on it (hunt t10)
        if u is None or u <= 0 or u != u or u > 253402300799:
            raise ValueError('until is the time the membership ends (epoch or YYYY-MM-DD)')
        out['until'] = u
    if str(m.get('note') or '').strip():
        out['note'] = str(m['note']).strip()[:300]
    return out


def _date_epoch(v):
    try:
        return time.mktime(time.strptime(str(v).strip()[:10], '%Y-%m-%d')) + 86399
    except (TypeError, ValueError):
        return None


def member_kind(who):
    w = _low(who)
    if w.startswith('local:'):
        return 'local'
    if w.startswith('group:') or ('=' in w and ',' in w) or w.startswith('cn='):
        return 'group'
    return 'user'


def member_matches(who, names, groups):
    """Whether one member is this person: one of their names (a local account
    only as local:NAME), or a group they are in (by its cn or DN)."""
    w = _low(who)
    if not w:
        return False
    if w in names:
        return True
    if w.startswith('local:'):
        return False
    bare = w[6:].strip() if w.startswith('group:') else w
    for dn, cn in groups or ():
        if bare in (_low(dn), _low(cn)):
            return True
    return False


def groups_of_text(text):
    """[(dn, cn)] of accounts.group_list ('; ' between them, each a DN or a name)."""
    out = []
    for g in re.split(r'\s*;\s*', str(text or '')):
        g = g.strip()
        if not g:
            continue
        m = re.match(r'^\s*cn=((?:\\.|[^,])+)', g, re.I)
        out.append((g, m.group(1).replace('\\', '') if m else g))
    return out


def admin_principal(s):
    """(names, groups) of a session of the administration pages."""
    acc = s.get('account') or {}
    name = str(s.get('name') or '')
    if acc.get('source') == 'directory':
        names = {_low(name)}
        if acc.get('dn'):
            names.add(_low(acc['dn']))
        return names, groups_of_text(acc.get('group_list'))
    return {'local:' + _low(name)}, []


# ---------------------------------------------------------------------------
# Scope: who sees what
# ---------------------------------------------------------------------------
def _setting(key):
    try:
        return bool(int(E.CONFIG.get(key, 1) if E.CONFIG.get(key, 1) not in (None, '') else 1))
    except (TypeError, ValueError):
        return True


def unscoped(s, right):
    """Whether this session holds `right` (an old right or a capability) on every
    certificate."""
    if right in CAPS:
        right = 'view' if right in VIEW_CAPS else 'manage'
    role = str(s.get('role') or '')
    if role == 'fulladmin' or s.get('cli'):
        return True
    if role in ('certadmin', 'tokenadmin') and _setting('certs_certadmin_all'):
        return True
    if right == 'view' and role not in ('certadmin', 'tokenadmin') \
            and _setting('certs_readonly_all'):
        return True
    return False


def scope(store, s, right='view'):
    """None: every certificate; else the names (lower case) of the teams whose
    certificates this session holds `right` on - a certificate without an
    owner is then in none. The teams below one where it holds it are in too (1.0.125).
    `right` may be a capability (scope_cap)."""
    if right in CAPS:
        return scope_cap(store, s, right)
    if right == LEGACY_MANAGE:
        # the teams where the session holds the OLD right manage itself (it approves too)
        if unscoped(s, 'manage'):
            return None
        if str(s.get('role') or '') not in ('certadmin', 'tokenadmin'):
            return set()
        return {k for k, v in session_caps(store, s).items() if LEGACY_MANAGE in v['caps']}
    if unscoped(s, right):
        return None
    role = str(s.get('role') or '')
    if right in ('manage', 'request', 'approve') and role not in ('certadmin', 'tokenadmin'):
        return set()
    names, groups = admin_principal(s)
    return {k for k, (_, r) in person_teams(store, names, groups).items() if right in r}


def scope_cap(store, s, cap):
    """scope() for one capability (1.0.125): None every team, else the teams (lower case,
    those below included) where this session holds `cap`."""
    if cap not in CAPS:
        raise ValueError('no capability %r' % cap)
    if unscoped(s, cap):
        return None
    role = str(s.get('role') or '')
    if cap not in VIEW_CAPS and role not in ('certadmin', 'tokenadmin'):
        return set()
    return {k for k, v in session_caps(store, s).items() if cap in v['caps']}


def owner_in(sc, owner):
    return sc is None or _low(owner) in sc


def cert_may(store, s, row, right):
    return owner_in(scope(store, s, right), (row or {}).get('owner'))


def cert_caps_of(store, s):
    """A function: certificate row -> the capabilities (in CAPS' order) this session holds on
    it, and 'manage' when it holds the old right manage there (the tests of a certificate ask
    for it) - for the page to offer only what the server would not refuse (hunt Rt5: a
    certificate administrator of some teams, a Viewer on one, was offered Renew, Delete...
    on its certificates). The scopes are read once, for a whole list."""
    wants = tuple(CAPS) + ('manage',)
    scopes = [(w, scope(store, s, w)) for w in wants]

    def caps(row):
        owner = (row or {}).get('owner')
        return [w for w, sc in scopes if owner_in(sc, owner)]
    return caps


def cert_caps(store, s, row):
    return cert_caps_of(store, s)(row)


def where(store, s, right='view', col='owner'):
    """(' AND ...', args) to keep a query of certs to the session's scope ('' when all)."""
    sc = scope(store, s, right)
    if sc is None:
        return '', ()
    if not sc:
        return ' AND 1 = 0', ()
    part = sorted(sc)
    return (' AND LOWER(TRIM(COALESCE(%s, \'\'))) IN (%s)' % (col, ', '.join('?' * len(part))),
            tuple(part))


def deny(store, s, what, right):
    who = str(s.get('name') or '?')
    store.add_event('certificates', '%s was refused: %s (needs the right %s on its team)' % (
        who, what, right), 'warn', who=who)
    if right in CAPS:
        raise E.ApiError(403, 'you may not do that with this certificate: its team does not '
                              'give you "%s" (%s)' % (right, CAP_WORDS[right]))
    raise E.ApiError(403, 'you may not do that with this certificate: its team does not give you '
                          'the right "%s"' % right)


def cert_of_ref(store, ref):
    """The certificate a route will act on: by its id or name - and by the number
    the route itself reads (api._id: int(' 5'), int(5.0)), which cert_get alone
    took for a name, found none, and let the route act unchecked (1.0.19)."""
    if ref in (None, '') or isinstance(ref, (dict, list)):
        return None
    # A number - 5, 5.0, " 5", "5.0"? - is an id, as the route reads it (1.0.79: 1.0 was looked
    # up by name first - a certificate of one's own team called "1.0" - and the route then acted
    # on the id 1 of another team's)
    if not isinstance(ref, bool):
        try:
            n = int(ref) if not isinstance(ref, str) else int(ref.strip())
        except (TypeError, ValueError, OverflowError):
            n = None
        if n is None and isinstance(ref, (int, float)):
            n = 0
        if n is not None:
            return S.cert_get(store, n) if n > 0 else None
    row = S.cert_get(store, ref)
    if row is None and not isinstance(ref, bool):
        try:
            n = int(ref)
        except (TypeError, ValueError, OverflowError):
            n = 0
        if n > 0:
            row = S.cert_get(store, n)
    return row


def need_cert(store, s, ref, right, what=''):
    row = cert_of_ref(store, ref)
    if row is None:
        return None
    if not cert_may(store, s, row, right):
        deny(store, s, '%s %s' % (what or right, row['name']), right)
    return row


def need_job(store, s, ident, right, what):
    """A job: as its certificate - and one of no certificate (a target's test, a module's
    action), or of a certificate deleted since, only for those who hold the right on every
    certificate and for the one who started it (1.0.46: looked at, stopped and its test read
    by any scoped session before; its steps say what another team's target did)."""
    row = need_cert(store, s, _cert_of_job(store, ident), right, what)
    if row is not None or unscoped(s, right):
        return
    try:
        by = store.db.value('SELECT by_who FROM cert_jobs WHERE id = ?', (int(ident),))
    except (TypeError, ValueError, OverflowError):
        by = None
    if not by or str(by).lower() != str(s.get('name') or '').lower():
        deny(store, s, '%s no certificate' % what, right)


def need_owner(store, s, owner, what):
    """A new certificate (or a new owner) given to `owner`: the session needs
    request (or manage) on that team; scoped, an empty owner is refused."""
    sc = scope(store, s, 'request')
    if sc is None:
        return
    if not _low(owner):
        deny(store, s, '%s without an owner' % what, 'request')
    if _low(owner) not in sc:
        deny(store, s, '%s for the team %s' % (what, owner), 'request')


def _ref(b, *keys):
    for k in keys:
        if b.get(k) not in (None, ''):
            return b.get(k)
    return None


def _cert_of_deploy(store, ident):
    try:
        r = store.db.row('SELECT cert_id FROM cert_deploys WHERE id = ?', (int(ident),))
    except (TypeError, ValueError):
        return None
    return r and r['cert_id']


def _cert_of_job(store, ident):
    try:
        r = store.db.row('SELECT cert_id FROM cert_jobs WHERE id = ?', (int(ident),))
    except (TypeError, ValueError):
        return None
    return r and r['cert_id']


MANAGE_ROUTES = {'/api/certs/auto', '/api/certs/delete', '/api/certs/renew', '/api/certs/deploy',
                 '/api/certs/revoke', '/api/certs/export', '/api/certs/csr_answer',
                 '/api/certs/plan', '/api/certs/check', '/api/certs/dry_run', '/api/certs/keep',
                 '/api/certs/add_key',
                 # held or let go for another team's certificate (1.0.88: not checked)
                 '/api/certs/hold'}
# The capability each of them needs (1.0.125) - the old right manage holds every one of them,
# so a member with it does what it did.
ROUTE_CAPS = {'/api/certs/auto': 'cert.auto', '/api/certs/delete': 'cert.delete',
              '/api/certs/renew': 'cert.renew', '/api/certs/deploy': 'deploy.run',
              '/api/certs/revoke': 'cert.revoke', '/api/certs/export': 'cert.edit',
              '/api/certs/csr_answer': 'cert.edit', '/api/certs/plan': 'cert.edit',
              '/api/certs/check': 'cert.edit', '/api/certs/dry_run': 'cert.renew',
              '/api/certs/keep': 'cert.edit', '/api/certs/add_key': 'cert.edit',
              '/api/certs/hold': 'cert.auto'}


def route_cap(path, b=None):
    """The capability a route of /api/certs or /api/deploys needs on the certificate's team."""
    if path == '/api/certs/export' and str((b or {}).get('format') or '') in S.KEY_FORMATS:
        return 'cert.key'
    return ROUTE_CAPS.get(path)


def guard(h, s, method, path):
    """The check of one route of the API before it runs (docs/teams.md "Who sees
    what"): nothing for a session that is not scoped."""
    if unscoped(s, 'view') and unscoped(s, 'manage'):
        return
    store = h.store
    if method == 'GET':
        if path == '/api/certs/one':
            need_cert(store, s, h.arg('id') or h.arg('name'), 'view', 'look at')
        elif path == '/api/certs/job':
            need_job(store, s, h.arg('id'), 'view', 'look at a job of')
        elif path == '/api/certs/dry_run_result':
            need_job(store, s, h.arg('job'), 'view', 'look at a test of')
        elif path == '/api/certs/jobs' and h.arg('cert_id'):
            need_cert(store, s, h.arg('cert_id'), 'view', 'look at the jobs of')
        elif path == '/api/certs/run_plan':
            need_cert(store, s, h.arg('id') or h.arg('name'), 'view', 'look at the plan of')
        return
    if not path.startswith('/api/certs') and not path.startswith('/api/deploys'):
        return
    b = h.body()
    if path == '/api/certs/run_plan':
        # The plan of a draft: of a certificate saved, only where it may be looked at.
        if b.get('id') not in (None, '', 0):
            need_cert(store, s, b.get('id'), 'view', 'look at the plan of')
        return
    if path in MANAGE_ROUTES:
        row = need_cert(store, s, _ref(b, 'id', 'cert_id', 'name'), route_cap(path, b),
                        path.rsplit('/', 1)[-1])
        if row is not None and route_cap(path, b) == 'cert.key' and not unscoped(s, 'manage'):
            # its team's limits on a file with the key (hunt C1: checked on the portal only)
            from acmelib.certs import teampolicy as TP
            TP.need_key_download(store, row.get('owner'), str(s.get('name') or '?'))
    elif path == '/api/certs/job_stop':
        need_job(store, s, b.get('id'), 'cert.renew', 'stop a job of')
    elif path in ('/api/certs/save', '/api/certs/import', '/api/certs/csr'):
        ref = _ref(b, 'id')
        # 0, false, an id of nothing (1.0.51): the route makes a new one of it - the owner
        # sent was taken unchecked (any team, or none)
        row = need_cert(store, s, ref, 'cert.edit', 'change') \
            if ref not in (None, 0, False, '0') else None
        if row is None:
            need_owner(store, s, b.get('owner'), 'a new certificate')
            if path == '/api/certs/save' and not unscoped(s, 'request'):
                # its team's limits (1.0.125): a scoped certificate administrator asks within them
                from acmelib.certs import teampolicy as TP
                TP.need_admin_cert(store, s, b, None)
        else:
            if 'owner' in b and _low(b.get('owner')) != _low(row.get('owner')):
                need_owner(store, s, b.get('owner'), 'the owner of %s' % row['name'])
            if path == '/api/certs/save' and not unscoped(s, 'request'):
                from acmelib.certs import teampolicy as TP
                TP.need_admin_cert(store, s, b, row)
    elif path == '/api/certs/online_import':
        # Import from a source: each certificate is a new one, for a team they may ask for.
        for it in (b.get('items') if isinstance(b.get('items'), list) else []):
            if isinstance(it, dict):
                need_owner(store, s, it.get('owner'), 'a certificate imported from a source')
    elif path == '/api/certs/approve':
        # As the route reads it (1.0.45): " 5" or 5.0 found nothing here, and went through.
        row = cert_of_ref(store, b.get('id')) if b.get('id') not in (None, '') else None
        if row is not None and not (cert_may(store, s, row, 'cert.approve')
                                    or cert_may(store, s, row, LEGACY_MANAGE)):
            deny(store, s, 'approve %s' % row['name'], 'approve')
    elif path in ('/api/deploys/save', '/api/deploys/dry_run', '/api/deploys/preview'):
        right = 'view' if path == '/api/deploys/preview' else 'deploy.manage'
        # Both: the certificate given, and the one of the deployment given - a
        # deployment of another team's certificate was taken over by giving it
        # a certificate of one's own (1.0.19).
        if b.get('id') not in (None, '', 0):
            need_cert(store, s, _cert_of_deploy(store, b['id']), right, 'deploy')
        crow = need_cert(store, s, _ref(b, 'cert_id'), right, 'deploy')
        sends = path in ('/api/deploys/save', '/api/deploys/dry_run')
        if sends and crow is None and not unscoped(s, 'manage') and \
                b.get('id') not in (None, '', 0) and b.get('target') not in (None, ''):
            # a deployment saved (or tried) without its certificate keeps the one it has (the
            # route takes it): its team's limits on the device all the same (hunt R t8 - one of
            # a team's certificates moved to another team's device by its id alone, unchecked)
            crow = cert_of_ref(store, _cert_of_deploy(store, b['id']))
        if sends and crow is not None and not unscoped(s, 'manage') and \
                b.get('target') not in (None, ''):
            # a team's certificate to a device of its own (or acme's), of a module its limits
            # allow (hunt C1: checked on the portal only) - and tried there (hunt R t8: the test
            # writes the files, the key too, into a folder on another team's device)
            from acmelib.certs import teampolicy as TP
            TP.need_deploy(store, crow, S.plugin_row(store, 'target', b.get('target')),
                           str(s.get('name') or '?'))
    elif path == '/api/deploys/delete':
        need_cert(store, s, _cert_of_deploy(store, b.get('id')), 'deploy.manage', 'deploy')
    elif path == '/api/deploys/run':
        need_cert(store, s, _cert_of_deploy(store, b.get('id')), 'deploy.run', 'deploy')


# ---------------------------------------------------------------------------
# The owners
# ---------------------------------------------------------------------------
def team_rows(store):
    try:
        return store.db.rows('SELECT * FROM cert_teams ORDER BY %s' % store.db.name_order())
    except Exception:                                   # noqa: BLE001
        return store.db.rows('SELECT * FROM cert_teams ORDER BY name')


def team_get(store, name):
    n = _low(name)
    if not n:
        return None
    for t in team_rows(store):
        if _low(t['name']) == n:
            return t
    return None


def used_counts(store):
    """{owner lower: certificates}."""
    out = {}
    for r in store.db.rows("SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE "
                           "COALESCE(owner, '') <> '' GROUP BY LOWER(TRIM(owner))"):
        out[r['o']] = int(r['n'] or 0)
    return out


def team_counts(store):
    """{team lower: {certs, certs_below, expiring, failing, waiting, devices, agents,
    agents_waiting}} of every team at once (1.0.125, hunt C1: the page asked four lists per
    team) - a few grouped statements; certs_below the team's and those of the teams below."""
    def grouped(sql, args=()):
        out = {}
        try:
            for r in store.db.rows(sql, args):
                out[_low(r['o'])] = out.get(_low(r['o']), 0) + int(r['n'] or 0)
        except Exception as e:                          # noqa: BLE001
            E.log('the teams\' counts: %s' % e, 'warn')
        return out
    now = time.time()
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    certs = used_counts(store)
    by_owner = "COALESCE(owner, '') <> '' GROUP BY LOWER(TRIM(owner))"
    expiring = grouped('SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE '
                       'not_after > ? AND not_after < ? AND ' + by_owner,
                       (now, now + days * 86400))
    failing = grouped("SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE "
                      "state = 'failed' AND " + by_owner)
    waiting = grouped("SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM certs WHERE "
                      "state = 'pending-approval' AND " + by_owner)
    devices = grouped('SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM cert_targets WHERE '
                      + by_owner)
    agents = grouped("SELECT LOWER(TRIM(owner)) AS o, COUNT(*) AS n FROM cert_targets WHERE "
                     "kind IN ('agent', 'agent_windows') AND " + by_owner)
    agents_waiting = {}
    if agents:
        try:
            from acmelib.certs import agents as G
            for w in G.waiting(store, teams=set(agents)):
                o = _low(w.get('owner'))
                agents_waiting[o] = agents_waiting.get(o, 0) + 1
        except Exception as e:                          # noqa: BLE001
            E.log('the teams\' waiting agents: %s' % e, 'warn')
    tr = tree(store)
    out = {}
    for k in reversed(tr.order):
        below = certs.get(k, 0) + sum(out[c]['certs_below'] for c in tr.children.get(k, [])
                                      if c in out)
        out[k] = {'certs': certs.get(k, 0), 'certs_below': below,
                  'expiring': expiring.get(k, 0), 'failing': failing.get(k, 0),
                  'waiting': waiting.get(k, 0), 'devices': devices.get(k, 0),
                  'agents': agents.get(k, 0), 'agents_waiting': agents_waiting.get(k, 0)}
    return out


def team_public(t, used=None):
    out = {k: t.get(k) for k in ('id', 'name', 'kind', 'contact_mail', 'contact_phone', 'note',
                                 'created', 'created_by', 'updated', 'updated_by')}
    out['kind'] = out['kind'] or 'team'
    out['members'] = [m for m in (S.jload(t.get('members'), []) or []) if isinstance(m, dict)]
    now = time.time()
    for m in out['members']:
        m['kind'] = member_kind(m.get('who'))
        if m.get('until'):
            m['expired'] = member_expired(m, now)
    if used is not None:
        out['used'] = used.get(_low(t['name']), 0)
    # 1.0.125: where it is in the tree, its own limits, its words
    out['parent'] = t.get('parent') or None
    out['policy'] = policy_of(t)
    out['description'] = t.get('description') or ''
    return out


def teams(store):
    used = used_counts(store)
    tr = tree(store)
    out = []
    for t in team_rows(store):
        one = team_public(t, used)
        if _low(t['name']) in tr.rows:
            one['effective'] = tr.effective(t['name'])
            one['depth'] = tr.depth(t['name'])
        out.append(one)
    return out


def clean_mails(v):
    got = [w for w in re.split(r'[\s,;]+', str(v or '')) if w]
    for w in got:
        if not MAIL_RE.match(w):
            raise ValueError('\u201c%s\u201d is not a mail address' % str(w)[:120])
    if len(got) > 20:
        raise ValueError('20 addresses at most')
    return ', '.join(got)


def _profiles_follow(store, kind, old, new):
    """The request profiles that name an owner or a tag renamed (or a tag deleted)."""
    from acmelib.certs import reqprofiles
    reqprofiles.rename_ref(store, kind, old, new)


def _clean_parent(store, b, old, name):
    """The parent a team is given: None top level; never itself nor a team below it."""
    raw = b.get('parent') if 'parent' in b else (old or {}).get('parent')
    if raw in (None, '', '-'):
        return None
    p = team_get(store, raw)
    if not p and ('parent' not in b or (old and _low(raw) == _low(old.get('parent')))):
        # the parent it had is gone (an import, another node): the tree puts it at the top
        # level, and a save that does not move it keeps it there (hunt Rt1: every save of it -
        # its members, its note - was refused "there is no team"; hunt R t3: the page sends
        # the parent it has, the one gone, with every save of its members)
        return None
    if not p:
        raise LookupError('there is no team %s to put it under' % raw)
    if old and p['id'] == old['id']:
        raise ValueError('a team is not under itself')
    if old:
        tr = tree(store)
        below = set(tr.descendants(old['name']))
        if _low(p['name']) in below:
            raise ValueError('%s is below %s - a team is not put under a team below it (that '
                             'would be a circle)' % (p['name'], name))
    return p['name']


def _follow_rename(store, old_name, name):
    """A team renamed: its children, the targets it owns and its enrollment codes follow."""
    store.db.run('UPDATE cert_teams SET parent = ? WHERE LOWER(TRIM(parent)) = ?',
                 (name, _low(old_name)))
    store.db.run('UPDATE cert_targets SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                 (name, _low(old_name)))
    _enroll_follow(store, old_name, name)
    from acmelib.certs import teampolicy as TP
    TP.actions_follow(store, old_name, name)


def _enroll_follow(store, old, new):
    """The enrollment codes of agents scoped to a team (agents.enroll_new team=) follow its
    renaming (new) or deletion (None: no longer of any team)."""
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agents:enroll:%'")
    except Exception:                                   # noqa: BLE001
        return
    for r in rows:
        ec = S.jload(r['v'], None)
        if isinstance(ec, dict) and _low(ec.get('team')) == _low(old):
            if new:
                ec['team'] = new
            else:
                ec.pop('team', None)
                ec['revoked'] = ec.get('revoked') or {'by': 'the team %s deleted' % old,
                                                      'at': _now()}
            store.set_meta(r['k'], json.dumps(ec, sort_keys=True))


def save_team(store, b, by):
    old = team_get(store, b.get('old_name')) if b.get('old_name') else None
    if b.get('old_name') and not old:
        raise LookupError('there is no owner %s' % b.get('old_name'))
    name = S.clean_name(b.get('name'), 'the owner\'s name')
    other = team_get(store, name)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is an owner called %s already' % other['name'])
    kind = str(b.get('kind') or (old or {}).get('kind') or 'team')
    if kind not in KINDS:
        raise ValueError('the kind is team, person or unit')
    raw = b.get('members') if 'members' in b else S.jload((old or {}).get('members'), [])
    if isinstance(raw, str):
        raw = [w for w in re.split(r'[\n;]+', raw) if w.strip()]
    members, seen = [], set()
    cat = role_catalog(store)
    for m in raw or []:
        m = clean_member(m, cat)
        if _low(m['who']) in seen:
            continue
        seen.add(_low(m['who']))
        members.append(m)
    if len(members) > MEMBER_MAX:
        raise ValueError('%d members at most' % MEMBER_MAX)
    parent = _clean_parent(store, b, old, name)
    if 'policy' in b:
        policy = clean_policy(b.get('policy'))
    else:
        policy = policy_of(old)
    row = {'name': name, 'kind': kind, 'members': json.dumps(members),
           'contact_mail': clean_mails(b.get('contact_mail', (old or {}).get('contact_mail'))),
           'contact_phone': str(b.get('contact_phone', (old or {}).get('contact_phone')) or '')
           .strip()[:60],
           'note': str(b.get('note', (old or {}).get('note')) or '').strip()[:2000],
           'updated': _now(), 'updated_by': str(by)[:190]}
    # The new columns written only where said or held (1.0.125): a team saved as before keeps
    # NULL - "as before".
    if parent or (old or {}).get('parent') or 'parent' in b:
        row['parent'] = parent
    if policy or (old or {}).get('policy') or 'policy' in b:
        row['policy'] = json.dumps(policy) if policy else None
    if 'description' in b or (old or {}).get('description'):
        row['description'] = str(b.get('description', (old or {}).get('description')) or '') \
            .strip()[:1000] or None
    what = []
    if old:
        if _low(parent) != _low(old.get('parent')):
            what.append('now under %s' % (parent or 'nothing (top level)'))
        if policy != policy_of(old):
            what.append('its limits %s' % (json.dumps(policy, sort_keys=True) if policy
                                           else 'taken off'))
        store.db.update('cert_teams', old['id'], row)
        if old['name'] != name:
            store.db.run('UPDATE certs SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                         (name, _low(old['name'])))
            _profiles_follow(store, 'team', old['name'], name)
            _follow_rename(store, old['name'], name)
        before = {_low(m.get('who')): m for m in S.jload(old.get('members'), []) or []
                  if isinstance(m, dict)}
        after = {_low(m['who']): m for m in members}
        gone = [before[k].get('who') for k in before if k not in after]
        came = [after[k]['who'] for k in after if k not in before]
        moved = [after[k]['who'] for k in after if k in before and
                 {x: before[k].get(x) for x in ('rights', 'roles', 'until')} !=
                 {x: after[k].get(x) for x in ('rights', 'roles', 'until')}]
        if came:
            what.append('members added: %s' % ', '.join(came[:20]))
        if gone:
            what.append('members removed: %s' % ', '.join(gone[:20]))
        if moved:
            what.append('members changed: %s' % ', '.join(moved[:20]))
        store.add_event('certificates', 'the owner %s changed by %s%s%s' % (
            name, by, (' (was %s)' % old['name']) if old['name'] != name else '',
            (' - the team %s: %s' % (name, '; '.join(what))) if what else ''), who=by)
    else:
        row.update(created=_now(), created_by=str(by)[:190])
        store.db.insert('cert_teams', row)
        store.add_event('certificates', 'the owner %s added by %s%s' % (
            name, by, (' - the team %s under %s' % (name, parent)) if parent else ''), who=by)
    changed()
    return team_public(team_get(store, name), used_counts(store))


def delete_team(store, name, by, reassign=None, reparent=None):
    """A team deleted. Owning certificates: refused unless `reassign` ('' nobody). With teams
    below it (1.0.125): refused unless `reparent` - the team they move under ('' or '-' the
    top level). The targets it owns go to `reassign` too (else they are acme's again)."""
    t = team_get(store, name)
    if not t:
        raise LookupError('there is no owner %s' % name)
    kids = [r for r in team_rows(store) if _low(r.get('parent')) == _low(t['name'])]
    to_parent = None
    if kids:
        if reparent is None:
            raise ValueError('%s has %d team(s) below it (%s) - move them first, or delete it '
                             'with reparent (another team, or \'\' for the top level)' % (
                                 t['name'], len(kids), ', '.join(k['name'] for k in kids[:10])))
        if reparent not in ('', '-'):
            p = team_get(store, reparent)
            if not p or p['id'] == t['id'] or _low(p['name']) in set(
                    tree(store).descendants(t['name'])):
                raise LookupError('there is no other team %s above it to move them under'
                                  % reparent)
            to_parent = p['name']
    n = used_counts(store).get(_low(t['name']), 0)
    moved = ''
    if n:
        if reassign is None:
            raise ValueError('%s owns %d certificate(s) - give them another owner first, or '
                             'delete it with reassign' % (t['name'], n))
    if reassign not in (None, '', '-'):
        to = team_get(store, reassign)
        if not to or to['id'] == t['id']:
            raise LookupError('there is no other owner %s' % reassign)
        moved = to['name']
    if n:
        store.db.run('UPDATE certs SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                     (moved, _low(t['name'])))
    store.db.run('UPDATE cert_targets SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                 (moved or None, _low(t['name'])))
    if kids:
        store.db.run('UPDATE cert_teams SET parent = ?, updated = ? WHERE LOWER(TRIM(parent)) = ?',
                     (to_parent, _now(), _low(t['name'])))
    store.db.run('DELETE FROM cert_teams WHERE id = ?', (t['id'],))
    _enroll_follow(store, t['name'], None)
    from acmelib.certs import teampolicy as TP
    TP.actions_follow(store, t['name'], None)
    # The profiles naming it follow (1.0.45): they named an owner no longer there, unusable.
    _profiles_follow(store, 'team', t['name'], moved or None)
    store.add_event('certificates', 'the owner %s deleted by %s%s%s' % (
        t['name'], by, (' - its %d certificate(s) now owned by %s' % (n, moved or 'nobody'))
        if n else '', (' - the team %s: its %d team(s) below now under %s' % (
            t['name'], len(kids), to_parent or 'nothing (top level)')) if kids else ''),
        'warn', who=by)
    changed()
    return {'deleted': t['name'], 'moved': n, 'to': moved,
            'children': [k['name'] for k in kids], 'reparented_to': to_parent}


# ---------------------------------------------------------------------------
# The tags
# ---------------------------------------------------------------------------
def _tag_uses(store):
    """{tag lower: {'certs': n, 'targets': n}} of every tag certificates and targets carry."""
    out = {}
    for table, key in (('certs', 'certs'), ('cert_targets', 'targets')):
        for r in store.db.rows("SELECT tags FROM %s WHERE COALESCE(tags, '') NOT IN ('', '[]')"
                               % table):
            for t in S.jload(r.get('tags'), []) or []:
                k = _low(t)
                if k:
                    d = out.setdefault(k, {'certs': 0, 'targets': 0, 'name': str(t)})
                    d[key] += 1
    return out


def tag_rows(store):
    return store.db.rows('SELECT * FROM cert_tags ORDER BY name')


def tag_get(store, name):
    n = _low(name)
    for t in tag_rows(store):
        if _low(t['name']) == n:
            return t
    return None


def tags(store):
    uses = _tag_uses(store)
    out = []
    for t in tag_rows(store):
        u = uses.get(_low(t['name']), {})
        out.append({'id': t['id'], 'name': t['name'], 'colour': t.get('colour') or 'dim',
                    'description': t.get('description') or '', 'certs': u.get('certs', 0),
                    'targets': u.get('targets', 0)})
    return out


def clean_tag(name):
    name = str(name or '').strip()
    if not TAG_RE.match(name):
        raise ValueError('a tag is one word: letters, digits and . _ : + - (60 at most), '
                         'starting with a letter or a digit')
    return name


def _retag(store, old, new):
    """Every certificate and target carrying `old` given `new` instead (None: taken off)."""
    n = 0
    for table in ('certs', 'cert_targets'):
        for r in store.db.rows("SELECT id, tags FROM %s WHERE COALESCE(tags, '') NOT IN "
                               "('', '[]')" % table):
            have = S.jload(r.get('tags'), []) or []
            if not any(_low(t) == _low(old) for t in have):
                continue
            got = []
            for t in have:
                t = (new if _low(t) == _low(old) else t)
                if t and _low(t) not in {_low(x) for x in got}:
                    got.append(t)
            store.db.update(table, r['id'], {'tags': json.dumps(got)})
            n += 1
    return n


def save_tag(store, b, by):
    old = tag_get(store, b.get('old_name')) if b.get('old_name') else None
    if b.get('old_name') and not old:
        raise LookupError('there is no tag %s' % b.get('old_name'))
    name = clean_tag(b.get('name'))
    other = tag_get(store, name)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is a tag %s already' % other['name'])
    colour = str(b.get('colour', (old or {}).get('colour')) or 'dim')
    if colour not in COLOURS:
        raise ValueError('the colour is one of %s' % ', '.join(COLOURS))
    row = {'name': name, 'colour': colour,
           'description': str(b.get('description', (old or {}).get('description')) or '')
           .strip()[:500], 'updated': _now(), 'updated_by': str(by)[:190]}
    if old:
        store.db.update('cert_tags', old['id'], row)
        if old['name'] != name:
            _retag(store, old['name'], name)
            _profiles_follow(store, 'tag', old['name'], name)
        store.add_event('certificates', 'the tag %s changed by %s' % (name, by), who=by)
    else:
        row.update(created=_now(), created_by=str(by)[:190])
        store.db.insert('cert_tags', row)
        store.add_event('certificates', 'the tag %s added by %s' % (name, by), who=by)
    return [t for t in tags(store) if t['name'] == name][0]


def delete_tag(store, name, by, strip=False):
    t = tag_get(store, name)
    if not t:
        raise LookupError('there is no tag %s' % name)
    u = _tag_uses(store).get(_low(t['name']), {})
    n = u.get('certs', 0) + u.get('targets', 0)
    if n and not strip:
        raise ValueError('%s is on %d certificate(s) and %d target(s) - delete it with strip to '
                         'take it off them' % (t['name'], u.get('certs', 0), u.get('targets', 0)))
    if n:
        _retag(store, t['name'], None)
    _profiles_follow(store, 'tag', t['name'], None)
    store.db.run('DELETE FROM cert_tags WHERE id = ?', (t['id'],))
    store.add_event('certificates', 'the tag %s deleted by %s%s' % (
        t['name'], by, (' - taken off %d' % n) if n else ''), 'warn' if n else 'info', who=by)
    return {'deleted': t['name'], 'stripped': n}


# ---------------------------------------------------------------------------
# What certificates say that is not defined
# ---------------------------------------------------------------------------
def legacy(store):
    have = {_low(t['name']) for t in team_rows(store)}
    owners = [{'owner': r['owner'], 'certs': int(r['n'] or 0)} for r in store.db.rows(
        "SELECT TRIM(owner) AS owner, COUNT(*) AS n FROM certs WHERE COALESCE(owner, '') <> '' "
        "GROUP BY TRIM(owner) ORDER BY TRIM(owner)") if _low(r['owner']) not in have]
    tagged = {_low(t['name']) for t in tag_rows(store)}
    tl = [{'tag': u['name'], 'certs': u['certs'], 'targets': u['targets']}
          for k, u in sorted(_tag_uses(store).items()) if k not in tagged]
    return {'owners': owners, 'tags': tl}


def adopt_owner(store, owner, by):
    """A free-text owner made a team: its one member is that text (so whoever saw
    the certificate on the portal still does), its certificates owned by it."""
    owner = str(owner or '').strip()
    if not owner:
        raise ValueError('which owner?')
    if team_get(store, owner):
        return team_get(store, owner)['name']
    try:
        name = S.clean_name(owner)
    except ValueError:
        bare = re.sub(r'^(group|local):', '', owner, flags=re.I)
        m = re.match(r'^\s*cn=((?:\\.|[^,])+)', bare, re.I)
        name = S.safe_name(m.group(1) if m else bare, [t['name'] for t in team_rows(store)])
    kind = 'team' if member_kind(owner) == 'group' else 'person'
    save_team(store, {'name': name, 'kind': kind,
                      'members': [{'who': owner, 'rights': list(DEFAULT_RIGHTS)}],
                      'note': 'made from what certificates said'}, by)
    name = team_get(store, name)['name']
    store.db.run('UPDATE certs SET owner = ? WHERE TRIM(owner) = ?', (name, owner))
    return name


def adopt(store, by, owners=True, tag_list=True):
    made = {'teams': [], 'tags': []}
    lg = legacy(store)
    if owners:
        for o in lg['owners']:
            made['teams'].append(adopt_owner(store, o['owner'], by))
    if tag_list:
        for t in lg['tags']:
            try:
                made['tags'].append(save_tag(store, {'name': clean_tag(t['tag'])}, by)['name'])
            except ValueError:
                pass
    return made


# ---------------------------------------------------------------------------
# Notices
# ---------------------------------------------------------------------------
def contact_mails(store, cert):
    try:
        t = team_get(store, (cert or {}).get('owner'))
    except Exception:                                   # noqa: BLE001
        return []
    if not t:
        return []
    return [w for w in re.split(r'[\s,;]+', str(t.get('contact_mail') or '')) if w]


# ---------------------------------------------------------------------------
# What happened in a team (1.0.125)
# ---------------------------------------------------------------------------
def _like(text):
    return '%' + str(text).lower().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'


_NAME_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789_@+-')
ACTIVITY_SCAN_MOST = 20000


def _mentions(text, term, longer=()):
    """Whether `text` (lower case) names `term` (lower case) as a whole name - not the start of
    a longer one (1.0.125, hunt C1: the activity of the team Web showed the events of WebDev and
    of Web2, and those of a certificate web1 the events of web10). `longer`: the other names
    that begin with `term` (a team "Web Ops" beside "Web") - an occurrence that is one of them
    is theirs."""
    n = len(term)
    at = text.find(term)
    while at >= 0:
        before = text[at - 1] if at else ' '
        after = text[at + n:at + n + 1]
        nxt = text[at + n + 1:at + n + 2]
        ok = before not in _NAME_CHARS and before != '.'
        if ok and after:
            if after in _NAME_CHARS or (after == '.' and nxt and nxt in _NAME_CHARS):
                ok = False
        if ok:
            for lo in longer:
                if text.startswith(lo, at) and not _continues(text, at + len(lo)):
                    ok = False
                    break
        if ok:
            return True
        at = text.find(term, at + 1)
    return False


def _continues(text, end):
    after = text[end:end + 1]
    nxt = text[end + 1:end + 2]
    return bool(after) and (after in _NAME_CHARS or (after == '.' and bool(nxt) and
                                                      nxt in _NAME_CHARS))


def team_activity(store, team, limit=50, offset=0, below=False):
    """The events about a team: its own changes (the owner / the team NAME), its certificates'
    and its devices' - (rows, total), newest first. `below`: the teams below it too.
    A name is matched as a whole (1.0.125, hunt C1): the LIKE of the database only narrows what
    is read; each event is then read for the names themselves - never an event of WebDev for
    Web, nor of web10 for web1."""
    tr = tree(store)
    k = _low(team)
    if k not in tr.rows:
        raise LookupError('there is no team %s' % team)
    teams_ = [k] + (tr.descendants(k) if below else [])
    terms = []
    team_names = [tr.rows[x]['name'] for x in tr.order]
    exact = {}
    for x in teams_:
        n = tr.rows[x]['name']
        longer = [o.lower() for o in team_names if o.lower() != n.lower() and
                  o.lower().startswith(n.lower())]
        # 'under NAME': a team made, moved or let go below it (save_team's, delete_team's words)
        for pre in ('the owner ', 'the team ', 'team ', 'under '):
            t = pre + n
            terms.append(t)
            exact[t.lower()] = [pre + o for o in longer]
    part = ', '.join('?' * len(teams_))
    for r in store.db.rows('SELECT name FROM certs WHERE LOWER(TRIM(owner)) IN (%s) ORDER BY '
                           'name LIMIT 300' % part, tuple(teams_)):
        terms.append(r['name'])
    for r in store.db.rows('SELECT name FROM cert_targets WHERE LOWER(TRIM(owner)) IN (%s) '
                           'ORDER BY name LIMIT 200' % part, tuple(teams_)):
        terms.append(r['name'])
    terms = list(dict.fromkeys(t for t in terms if t))[:600]
    sql = "kind = 'certificates' AND (%s)" % ' OR '.join(
        "LOWER(words) LIKE ? ESCAPE '!'" for _ in terms)
    low_terms = [(t.lower(), exact.get(t.lower(), ())) for t in terms]
    hits = []
    for r in store.db.rows('SELECT id, words FROM events WHERE %s ORDER BY ts DESC, id DESC '
                           'LIMIT %d' % (sql, ACTIVITY_SCAN_MOST), [_like(t) for t in terms]):
        w = str(r.get('words') or '').lower()
        if any(_mentions(w, t, lg) for t, lg in low_terms):
            hits.append(r['id'])
    total = len(hits)
    limit, offset = max(1, min(500, int(limit))), max(0, int(offset))
    page = hits[offset:offset + limit]
    rows = []
    if page:
        got = {r['id']: r for r in store.db.rows('SELECT * FROM events WHERE id IN (%s)' % ', '.join(
            '?' * len(page)), tuple(page))}
        rows = [got[i] for i in page if i in got]
    return [{'id': r.get('id'), 'ts': r.get('ts'), 'level': r.get('level'), 'who': r.get('who'),
             'words': r.get('words'), 'node': r.get('node')} for r in rows], total
