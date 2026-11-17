# -*- coding: utf-8 -*-
"""
Settings → Owners and teams (acmelib/certs/teams.py, docs/teams.md): the owners
of certificates, the tags, and what certificates say that is not defined yet -
the routes the pages ask, and the command line.

    GET  /api/teams              the owners (with how many certificates each), the tags,
                                 the legacy values, the two settings of scope, and which
                                 owners this account may give a new certificate (read-only)
    POST /api/teams/save         {name, old_name?, kind, members[], contact_mail,
                                 contact_phone, note}: an owner added or changed (full)
    POST /api/teams/delete       {name, reassign?}: an owner deleted - refused while it
                                 owns certificates unless reassign ('' nobody) (full)
    POST /api/teams/adopt        {owner?} | {tag?} | {}: free text made an owner / a tag
                                 (one, or all of them) (full)
    POST /api/tags/save          {name, old_name?, colour, description} (full)
    POST /api/tags/delete        {name, strip?} (full)

Enterprise teams (1.0.125, docs/teams.md "Enterprise teams"; the shapes: API_A1 of the work):
    GET  /api/teams              also: per team parent, policy, effective, description, depth
                                 (members with roles, until, expired); tree, roles, caps,
                                 policy_keys, approval_modes
    POST /api/teams/save         also {parent, policy, description, kind unit, members[].roles,
                                 members[].until} (full)
    POST /api/teams/delete       also {reparent} for a team with teams below it (full)
    POST /api/roles/save         {name, old_name?, description, caps[]} a custom role (full)
    POST /api/roles/delete       {name, strip?} (full)
    GET  /api/teams/access?who=  the access check: a person's teams, capabilities, why
                                 (certificate administrator)
    GET  /api/dir/search?q=&kind=user|group&page=   the directory's users / groups (50 at most)
    GET  /api/dir/group?name=    a group: how many are in it (nested), the first 20
    POST /api/teams/from_groups  {filter, role, parent, kind, dry_run} teams made from
                                 directory groups (full; dry_run: the preview, for a
                                 certificate administrator too)
    GET  /api/teams/activity?team=&below=&limit=&offset=   what happened in the team
"""
from __future__ import annotations

import json
import re
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import teams as T


def summary(store, s):
    sc = T.scope(store, s, 'request')
    teams = T.teams(store)
    # A scoped account (its settings off) sees the members and the addresses of
    # its own teams only (1.0.19) - of the others the name, which the owner lists need.
    seen = T.scope(store, s, 'view')
    if seen is not None:
        teams = [t if T.owner_in(seen, t['name']) else
                 dict(t, members=[], contact_mail='', contact_phone='', note='')
                 for t in teams]
    legacy = T.legacy(store)
    if seen is not None:
        # the free-text owners of the others' certificates not told (1.0.79); adopting them
        # is a full administrator's alone anyway
        legacy = {'owners': [], 'tags': legacy.get('tags') or []}
    return {'teams': teams, 'tags': T.tags(store), 'legacy': legacy,
            'rights': list(T.RIGHTS), 'kinds': list(T.KINDS), 'colours': list(T.COLOURS),
            'can_change': s.get('role') == 'fulladmin',
            # The owners a new certificate (or a new owner) may be given by this account.
            'choosable': [t['name'] for t in teams if T.owner_in(sc, t['name'])],
            'unowned_ok': sc is None,
            # Whether the members can see anything on the enrolment pages at all
            # (1.0.15): with either switch off, nothing is offered there.
            'portal': {'on': bool(E.CONFIG.get('portal')),
                       'certs': bool(E.CONFIG.get('portal_cert')),
                       'ask': bool(str(E.CONFIG.get('portal_cert_suffixes') or '').strip()
                                   and str(E.CONFIG.get('portal_cert_issuers') or '').strip())
                       # ...or a request profile says it (1.0.80: "not said yet" beside them)
                       or bool(store.db.value('SELECT COUNT(*) FROM cert_req_profiles WHERE '
                                             'COALESCE(enabled, 1) <> 0', (), 0))},
            'scoped': {'view': T.scope(store, s, 'view') is not None,
                       'manage': T.scope(store, s, 'manage') is not None},
            # 1.0.125: the tree, the roles, the capabilities in words, the policy's keys
            'tree': [n for n in T.tree_public(store, T.used_counts(store))
                     if seen is None or T.owner_in(seen, n['name'])],
            'roles': T.roles(store), 'caps': T.caps_catalog(),
            'policy_keys': list(T.POLICY_KEYS), 'approval_modes': list(T.APPROVAL_MODES),
            'approvers': list(T.APPROVERS), 'approve_actions': list(T.APPROVE_ACTIONS)}


@A.api('GET', '/api/teams')
def _list(h, s):
    return summary(h.store, s)


@A.api('POST', '/api/teams/save', 'fulladmin')
def _save(h, s):
    got = T.save_team(h.store, h.body(), A.who(s))
    return {'team': got, 'message': 'the owner %s was saved' % got['name']}


@A.api('POST', '/api/teams/delete', 'fulladmin')
def _delete(h, s):
    b = h.body()
    got = T.delete_team(h.store, b.get('name'), A.who(s),
                        reassign=b.get('reassign') if 'reassign' in b else None,
                        reparent=b.get('reparent') if 'reparent' in b else None)
    got['message'] = 'the owner %s was deleted' % got['deleted']
    return got


@A.api('POST', '/api/teams/adopt', 'fulladmin')
def _adopt(h, s):
    b = h.body()
    if b.get('owner'):
        name = T.adopt_owner(h.store, b['owner'], A.who(s))
        return {'team': name, 'message': 'the owner %s was made' % name}
    if b.get('tag'):
        got = T.save_tag(h.store, {'name': b['tag']}, A.who(s))
        return {'tag': got['name'], 'message': 'the tag %s was made' % got['name']}
    got = T.adopt(h.store, A.who(s))
    got['message'] = '%d owner(s) and %d tag(s) were made' % (len(got['teams']), len(got['tags']))
    return got


@A.api('POST', '/api/tags/save', 'fulladmin')
def _tag_save(h, s):
    got = T.save_tag(h.store, h.body(), A.who(s))
    return {'tag': got, 'message': 'the tag %s was saved' % got['name']}


@A.api('POST', '/api/tags/delete', 'fulladmin')
def _tag_delete(h, s):
    b = h.body()
    got = T.delete_tag(h.store, b.get('name'), A.who(s), strip=bool(b.get('strip')))
    got['message'] = 'the tag %s was deleted' % got['deleted']
    return got


# ---------------------------------------------------------------------------
# Enterprise teams (1.0.125): roles, the access check, the directory, activity
# ---------------------------------------------------------------------------
@A.api('POST', '/api/roles/save', 'fulladmin')
def _role_save(h, s):
    got = T.save_role(h.store, h.body(), A.who(s))
    return {'role': got, 'message': 'the role %s was saved' % got['name']}


@A.api('POST', '/api/roles/delete', 'fulladmin')
def _role_delete(h, s):
    b = h.body()
    got = T.delete_role(h.store, b.get('name'), A.who(s), strip=bool(b.get('strip')))
    got['message'] = 'the role %s was deleted' % got['deleted']
    return got


def directory(h, name=None):
    """The directory people are looked up in: the one named, else the portal's, else the
    administrators' - None when there is none (or it is switched off)."""
    d = getattr(h, 'd', None)
    dirs = getattr(d, 'dirs', None) or {}
    for n in (name, E.CONFIG.get('portal_directory'), E.CONFIG.get('admin_directory')):
        n = str(n or '').strip().lower()
        if n and n in dirs:
            return dirs[n]
        if name:
            break
    return None


def _need_dir(h, name=None):
    ad = directory(h, name)
    if ad is None:
        raise E.ApiError(404, 'no directory is set up for the teams - choose one for the portal '
                              '(Settings → Portal) or for the administrators')
    return ad


def _dir_call(fn):
    try:
        return fn()
    except E.LdapUnreachable as e:
        E.log('the directory could not be reached: %s' % e, 'warn')
        raise E.ApiError(503, 'the directory cannot be reached just now')
    except E.LdapError as e:
        raise E.ApiError(502, 'the directory refused it: %s' % str(e)[:200])


def principal_of(h, who, dname=None):
    """(names, groups, found) of a person as the teams match them: local:NAME an account of
    acme's own; otherwise the directory's user (by UPN, sAMAccountName or mail) - their names,
    DN and every group they are in (nested)."""
    who = str(who or '').strip()
    if not who or len(who) > 400 or any(ord(c) < 32 for c in who):
        raise E.ApiError(400, 'who? (local:NAME, a user of the directory: their UPN, account '
                              'or mail)')
    if who.lower().startswith('local:'):
        return {'local:' + who[6:].strip().lower()}, [], {'kind': 'local', 'name': who}
    ad = directory(h, dname)
    if ad is None:
        return {who.lower()}, [], {'kind': 'unknown', 'name': who,
                                   'said': 'no directory is set up - matched by the name alone'}
    entry = None
    tries = [('upn', who), ('mail', who)] if '@' in who else [('sam', who)]
    for how, v in tries:
        entry = _dir_call(lambda: ad.find_user(v, how))
        if entry:
            break
    if not entry:
        return {who.lower()}, [], {'kind': 'unknown', 'name': who, 'directory': ad.name,
                                   'said': 'the directory knows no such user - matched by the '
                                           'name alone'}
    names = {who.lower()}
    for k in ('sam', 'upn', 'mail', 'dn'):
        if entry.get(k):
            names.add(str(entry[k]).strip().lower())
    groups = _dir_call(lambda: ad.groups_of(entry, True))
    return names, groups, {'kind': 'user', 'name': who, 'directory': ad.name,
                           'dn': entry.get('dn'), 'sam': entry.get('sam'),
                           'upn': entry.get('upn'), 'display': entry.get('display'),
                           'mail': entry.get('mail'), 'disabled': bool(entry.get('disabled'))}


@A.api('GET', '/api/teams/access', 'certadmin')
def _access(h, s):
    names, groups, found = principal_of(h, h.arg('who'), h.arg('directory') or None)
    got = T.explain(h.store, names, groups)
    seen = T.scope(h.store, s, 'view')
    if seen is not None:
        got = [t for t in got if T.owner_in(seen, t['team'])]
    return {'who': found, 'groups': sorted({cn for _dn, cn in groups}, key=str.lower)[:500],
            'groups_count': len(groups), 'teams': got}


@A.api('GET', '/api/dir/search', 'certadmin')
def _dir_search(h, s):
    q = str(h.arg('q') or '').strip()[:100]
    kind = str(h.arg('kind') or 'user')
    if kind not in ('user', 'group'):
        raise E.ApiError(400, 'kind is user or group')
    per = h.num('limit', 50, 1, 50)
    page = h.num('page', 0, 0, 20)
    ad = _need_dir(h, h.arg('directory') or None)
    if len(q) < 2:
        return {'rows': [], 'page': page, 'more': False, 'directory': ad.name}
    want = per * (page + 1) + 1
    if kind == 'user':
        found = _dir_call(lambda: ad.find_users(q, min(want, 1050)))
        rows = [{'who': (u.get('upn') or u.get('sam') or '').lower() or u['dn'],
                 'sam': u.get('sam') or '', 'upn': u.get('upn') or '', 'dn': u['dn'],
                 'display': u.get('display') or '', 'mail': u.get('mail') or '',
                 'disabled': bool(u.get('disabled'))} for u in found]
    else:
        found = _dir_call(lambda: ad.find_groups(q, limit=min(want, 1050)))
        rows = [{'who': 'group:' + g['cn'], 'cn': g['cn'], 'dn': g['dn'],
                 'description': g.get('description') or ''} for g in found]
    part = rows[page * per:(page + 1) * per]
    return {'rows': part, 'page': page, 'more': len(rows) > (page + 1) * per,
            'directory': ad.name}


def group_entry(ad, name):
    """(dn, cn, description) of a group by its cn (group:CN too) or its DN - or None."""
    name = str(name or '').strip()
    if name.lower().startswith('group:'):
        name = name[6:].strip()
    if not name:
        return None
    if '=' in name and ',' in name:
        flt = E.ldap_and(E.ldap_equal('objectClass', 'group'),
                         E.ldap_equal('distinguishedName', name))
        rows = _dir_call(lambda: ad.asked(lambda link: link.search(
            name, E.ldap_equal('objectClass', 'group'), ('cn', 'description'), scope=0,
            limit=1)))
        if not rows:
            rows = _dir_call(lambda: ad.asked(lambda link: link.search(
                ad.base, flt, ('cn', 'description'), scope=2, limit=1)))
    else:
        rows = _dir_call(lambda: ad.asked(lambda link: link.search(
            ad.base, E.ldap_and(E.ldap_equal('objectClass', 'group'), E.ldap_equal('cn', name)),
            ('cn', 'description'), scope=2, limit=2)))
    if not rows:
        return None
    r = rows[0]
    a = {k.lower(): v for k, v in r['attrs'].items()}
    return r['dn'], (a.get('cn') or [name])[0], (a.get('description') or [''])[0]


def group_members(ad, dn, first=20, most=5000):
    """(count, [first names], capped) of the users in a group, groups inside it included."""
    def do(link):
        link.PAGES_MOST = 50
        return link.search(ad.base, E.ldap_and(E.ldap_equal('objectClass', 'user'),
                                               E.ldap_in_chain('memberOf', dn)),
                           ('sAMAccountName', 'userPrincipalName', 'displayName'), scope=2,
                           limit=most, paged=True)
    rows = _dir_call(lambda: ad.asked(do))
    out = []
    for r in rows:
        a = {k.lower(): v for k, v in r['attrs'].items()}
        sam = (a.get('samaccountname') or [''])[0]
        if str(sam).endswith('$'):
            continue
        out.append({'sam': sam, 'upn': (a.get('userprincipalname') or [''])[0],
                    'display': (a.get('displayname') or [''])[0], 'dn': r['dn']})
    out.sort(key=lambda u: (u['display'] or u['sam'] or '').lower())
    return len(out), out[:first], len(rows) >= most


@A.api('GET', '/api/dir/group', 'certadmin')
def _dir_group(h, s):
    ad = _need_dir(h, h.arg('directory') or None)
    got = group_entry(ad, h.arg('name'))
    if not got:
        raise E.ApiError(404, 'the directory has no group %s' % str(h.arg('name'))[:120])
    dn, cn, words = got
    n, first, capped = group_members(ad, dn)
    return {'dn': dn, 'cn': cn, 'description': words, 'count': n, 'first': first,
            'capped': capped, 'directory': ad.name}


FROM_GROUPS_MOST = 500


def from_groups(h, b, by, may_make=True):
    """Teams made from the directory's groups whose cn fits `filter` (PKI-*): each a team (or a
    unit) of that name, the group its member with `role`, under `parent`. dry_run: said, not
    made."""
    from acmelib.certs import teampolicy as TP
    store = h.store
    pattern = TP.group_pattern(b.get('filter'))
    role = str(b.get('role') or 'Viewer').strip()
    cat = T.role_catalog(store)
    if role.lower() not in cat and role.lower() not in T.RIGHTS:
        raise E.ApiError(400, 'there is no role %s' % role[:60])
    kind = str(b.get('kind') or 'team')
    if kind not in ('team', 'unit'):
        raise E.ApiError(400, 'the kind is team or unit')
    parent = None
    if b.get('parent') not in (None, '', '-'):
        p = T.team_get(store, b['parent'])
        if not p:
            raise E.ApiError(404, 'there is no team %s to put them under' % b['parent'])
        parent = p['name']
    dry = b.get('dry_run') in (True, 1, '1', 'true') or not may_make
    ad = _need_dir(h, b.get('directory') or None)
    literal = max(re.split(r'[*?\[\]]+', pattern), key=len)
    found = _dir_call(lambda: ad.find_groups(literal, limit=5000))
    groups = [g for g in found if TP.matches_pattern(g['cn'], pattern)]
    capped = len(groups) > FROM_GROUPS_MOST
    groups = sorted(groups, key=lambda g: g['cn'].lower())[:FROM_GROUPS_MOST]
    names = [t['name'] for t in T.team_rows(store)]
    out, made = [], []
    member_of = {}
    for t in T.team_rows(store):
        for m in S.jload(t.get('members'), []) or []:
            if isinstance(m, dict):
                member_of.setdefault(T._low(m.get('who')), []).append(t['name'])
    for g in groups:
        who = 'group:' + g['cn']
        have = member_of.get(who.lower()) or member_of.get(g['dn'].lower()) or []
        try:
            want = S.clean_name(g['cn'])
        except ValueError:
            want = S.safe_name(g['cn'], names)
        exists = T.team_get(store, want)
        one = {'cn': g['cn'], 'dn': g['dn'], 'team': want, 'exists': bool(exists),
               'member_of': have, 'description': g.get('description') or ''}
        if not exists and not dry:
            member = {'who': who}
            if role.lower() in T.RIGHTS:
                member['rights'] = [role.lower()]
            else:
                member['roles'] = [cat[role.lower()]['name']]
            got = T.save_team(store, {'name': want, 'kind': kind, 'parent': parent,
                                      'members': [member],
                                      'description': (g.get('description') or '')[:1000],
                                      'note': 'made from the directory group %s' % g['dn']}, by)
            names.append(got['name'])
            made.append(got['name'])
            one['made'] = True
        out.append(one)
    if made:
        store.add_event('certificates', '%d team(s) made from the directory groups %s by %s: %s'
                        % (len(made), pattern, by, ', '.join(made[:30])), who=by)
    return {'groups': out, 'made': made, 'dry_run': dry, 'capped': capped, 'filter': pattern,
            'role': role, 'parent': parent, 'directory': ad.name}


@A.api('POST', '/api/teams/from_groups', 'certadmin')
def _from_groups(h, s):
    b = h.body()
    full = s.get('role') == 'fulladmin' or bool(s.get('cli'))
    if not full and b.get('dry_run') not in (True, 1, '1', 'true'):
        raise E.ApiError(403, A.ROLE_WORDS['fulladmin'])
    return from_groups(h, b, A.who(s), may_make=full)


@A.api('GET', '/api/teams/activity')
def _activity(h, s):
    team = T.team_get(h.store, h.arg('team'))
    if not team:
        raise E.ApiError(404, 'there is no team %s' % str(h.arg('team'))[:120])
    seen = T.scope(h.store, s, 'view')
    if seen is not None and not T.owner_in(seen, team['name']):
        raise E.ApiError(403, 'you may not see what happened in the team %s' % team['name'])
    rows, total = T.team_activity(h.store, team['name'], h.num('limit', 50, 1, 500),
                                  h.num('offset', 0, 0, 10 ** 6),
                                  below=str(h.arg('below') or '') in ('1', 'true'))
    return {'team': team['name'], 'rows': rows, 'total': total}


# ---------------------------------------------------------------------------
# The command line: --teams, --team-add NAME, --team-edit NAME, --team-del NAME,
# --tag-add NAME, --tag-del NAME, --teams-adopt
# ---------------------------------------------------------------------------
CLI_KEYS = ('teams', 'team_add', 'team_edit', 'team_del', 'tag_add', 'tag_del', 'teams_adopt')


def add_args(p):
    g = p.add_argument_group('OWNERS AND TAGS', 'Who certificates belong to, what their members '
                             'may do, and the tags (Settings → Owners and teams, docs/teams.md).')
    g.add_argument('--teams', action='store_true', help='the owners and the tags, and how many '
                   'certificates each')
    g.add_argument('--team-add', metavar='NAME', help='a new owner: --team-kind team|person, '
                   '--members WHO=RIGHTS,WHO, --contact-mail, --note')
    g.add_argument('--team-edit', metavar='NAME', help='change one: the same, --name NEW')
    g.add_argument('--team-del', metavar='NAME', help='delete one; owning certificates, with '
                   '--reassign OTHER (- for nobody)')
    g.add_argument('--team-kind', choices=T.KINDS, help='with --team-add/-edit')
    g.add_argument('--members', metavar='LIST', help='with --team-add/-edit: local:NAME, a user, '
                   'group:NAME or a DN, each =view+request+manage+approve (default view+request), '
                   'comma between them')
    g.add_argument('--contact-mail', metavar='ADDR', help='with --team-add/-edit')
    g.add_argument('--reassign', metavar='OWNER', help='with --team-del')
    g.add_argument('--tag-add', metavar='TAG', help='a tag of the catalog: --colour, --note')
    g.add_argument('--tag-del', metavar='TAG', help='delete one; carried, with --strip')
    g.add_argument('--colour', choices=T.COLOURS, help='with --tag-add')
    g.add_argument('--strip', action='store_true', help='with --tag-del')
    g.add_argument('--teams-adopt', action='store_true', help='owners and tags made from what '
                   'certificates say now')


def _members(text):
    out = []
    for part in [w for w in str(text or '').split(',') if w.strip()]:
        who, _, rights = part.strip().partition('=')
        out.append({'who': who.strip(), 'rights': rights.replace('+', ',') if rights else None})
    return out


def _fields(a, base=None):
    b = dict(base or {})
    if a.team_kind:
        b['kind'] = a.team_kind
    if a.members is not None:
        b['members'] = _members(a.members)
    if a.contact_mail is not None:
        b['contact_mail'] = a.contact_mail
    if getattr(a, 'note', None):
        b['note'] = a.note
    return b


def cli(c):
    a, store, by = c.args, c.store, c.WHO
    try:
        if a.team_add:
            if T.team_get(store, a.team_add):
                raise SystemExit('acme: there is an owner %s already (--team-edit)' % a.team_add)
            got = T.save_team(store, _fields(a, {'name': a.team_add}), by)
            return c.done('the owner %s was added' % got['name'], {'ok': True, 'team': got})
        if a.team_edit:
            have = T.team_get(store, a.team_edit)
            if not have:
                raise SystemExit('acme: there is no owner %s' % a.team_edit)
            got = T.save_team(store, _fields(a, {'old_name': have['name'],
                                                 'name': a.name or have['name']}), by)
            return c.done('the owner %s was changed' % got['name'], {'ok': True, 'team': got})
        if a.team_del:
            if not T.team_get(store, a.team_del):      # said before it is asked (1.0.79)
                raise SystemExit('acme: there is no owner %s' % a.team_del)
            c.sure('delete the owner %s' % a.team_del)
            got = T.delete_team(store, a.team_del, by, reassign=a.reassign)
            return c.done('the owner %s was deleted%s' % (got['deleted'], (
                '; its %d certificate(s) now owned by %s' % (got['moved'], got['to'] or 'nobody'))
                if got['moved'] else ''), got)
        if a.tag_add:
            got = T.save_tag(store, {'name': a.tag_add, 'colour': a.colour or 'dim',
                                     'description': getattr(a, 'note', None) or ''}, by)
            return c.done('the tag %s was added' % got['name'], {'ok': True, 'tag': got})
        if a.tag_del:
            if not T.tag_get(store, a.tag_del):
                raise SystemExit('acme: there is no tag %s' % a.tag_del)
            c.sure('delete the tag %s' % a.tag_del)
            got = T.delete_tag(store, a.tag_del, by, strip=bool(a.strip))
            return c.done('the tag %s was deleted' % got['deleted'], got)
        if a.teams_adopt:
            got = T.adopt(store, by)
            return c.done('%d owner(s) and %d tag(s) were made' % (len(got['teams']),
                                                                  len(got['tags'])), got)
    except (ValueError, LookupError) as e:
        raise SystemExit('acme: %s' % e)
    got = {'teams': T.teams(store), 'tags': T.tags(store), 'legacy': T.legacy(store)}
    if c.json:
        c.out(got)
        return 0
    print('Owners and teams')
    c.table([[t['name'], t['kind'], ', '.join('%s=%s' % (m['who'], '+'.join(m['rights']))
                                               for m in t['members']) or '-',
              t['contact_mail'] or '-', str(t['used'])] for t in got['teams']],
            ['owner', 'kind', 'members', 'told', 'certs'])
    print('\nTags')
    c.table([[t['name'], t['colour'], t['description'] or '-', str(t['certs']),
              str(t['targets'])] for t in got['tags']],
            ['tag', 'colour', 'what', 'certs', 'targets'])
    lg = got['legacy']
    if lg['owners'] or lg['tags']:
        print('\nNot defined (acme --teams-adopt makes them): owners %s; tags %s' % (
            ', '.join(o['owner'] for o in lg['owners']) or '-',
            ', '.join(t['tag'] for t in lg['tags']) or '-'))
    return 0
