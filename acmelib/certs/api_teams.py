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
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import teams as T


def summary(store, s):
    sc = T.scope(store, s, 'request')
    teams = T.teams(store)
    return {'teams': teams, 'tags': T.tags(store), 'legacy': T.legacy(store),
            'rights': list(T.RIGHTS), 'kinds': list(T.KINDS), 'colours': list(T.COLOURS),
            'can_change': s.get('role') == 'fulladmin',
            # The owners a new certificate (or a new owner) may be given by this account.
            'choosable': [t['name'] for t in teams if T.owner_in(sc, t['name'])],
            'unowned_ok': sc is None,
            'scoped': {'view': T.scope(store, s, 'view') is not None,
                       'manage': T.scope(store, s, 'manage') is not None}}


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
                        reassign=b.get('reassign') if 'reassign' in b else None)
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
