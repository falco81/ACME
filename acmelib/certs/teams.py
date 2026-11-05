# -*- coding: utf-8 -*-
"""
Owners and teams, tags - and who may see and do what with which certificate
(docs/teams.md).

    teams(store) / team_get / save_team / delete_team       the owners (cert_teams)
    tags(store) / save_tag / delete_tag                     the tags (cert_tags)
    legacy(store) / adopt(store, by)                        what certificates say that
                                                            is not defined (yet)
    scope(store, s, right)                                  None (all) or {team names}
    cert_may(store, s, row, right)                          one certificate, one right
    guard(h, s, method, path)                               the API's check, per route
    person_teams(store, names, groups)                      {team: rights} of a person
    contact_mails(store, cert)                              the owner team's addresses

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
KINDS = ('team', 'person')
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


def clean_member(m):
    """{'who', 'rights'} of one member: local:NAME, a directory user (its
    sAMAccountName, UPN or mail), group:NAME or a group's DN."""
    if isinstance(m, str):
        who, _, rights = m.partition('=')
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
    rights = clean_rights(m.get('rights') if m.get('rights') is not None else DEFAULT_RIGHTS)
    if not rights:
        raise ValueError('%s has no right - give it at least view' % who)
    return {'who': who, 'rights': rights}


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


def person_teams(store, names, groups):
    """{team name lower: (team name, {rights})} of a person, by their names and groups."""
    names = {_low(n) for n in names or () if n}
    out = {}
    for t in team_rows(store):
        got = set()
        for m in S.jload(t.get('members'), []) or []:
            if isinstance(m, dict) and member_matches(m.get('who'), names, groups):
                for r in m.get('rights') or []:
                    got |= IMPLIES.get(r, set())
        if got:
            out[_low(t['name'])] = (t['name'], got)
    return out


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
    """Whether this session holds `right` on every certificate."""
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
    owner is then in none."""
    if unscoped(s, right):
        return None
    role = str(s.get('role') or '')
    if right in ('manage', 'request', 'approve') and role not in ('certadmin', 'tokenadmin'):
        return set()
    names, groups = admin_principal(s)
    return {k for k, (_, r) in person_teams(store, names, groups).items() if right in r}


def owner_in(sc, owner):
    return sc is None or _low(owner) in sc


def cert_may(store, s, row, right):
    return owner_in(scope(store, s, right), (row or {}).get('owner'))


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
    raise E.ApiError(403, 'you may not do that with this certificate: its team does not give you '
                          'the right "%s"' % right)


def cert_of_ref(store, ref):
    """The certificate a route will act on: by its id or name - and by the number
    the route itself reads (api._id: int(' 5'), int(5.0)), which cert_get alone
    took for a name, found none, and let the route act unchecked (1.0.19)."""
    if ref in (None, '') or isinstance(ref, (dict, list)):
        return None
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
                 '/api/certs/add_key'}


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
        need_cert(store, s, _ref(b, 'id', 'cert_id', 'name'), 'manage', path.rsplit('/', 1)[-1])
    elif path == '/api/certs/job_stop':
        need_job(store, s, b.get('id'), 'manage', 'stop a job of')
    elif path in ('/api/certs/save', '/api/certs/import', '/api/certs/csr'):
        ref = _ref(b, 'id')
        # 0, false, an id of nothing (1.0.51): the route makes a new one of it - the owner
        # sent was taken unchecked (any team, or none)
        row = need_cert(store, s, ref, 'manage', 'change') if ref not in (None, 0, False, '0') \
            else None
        if row is None:
            need_owner(store, s, b.get('owner'), 'a new certificate')
        else:
            if 'owner' in b and _low(b.get('owner')) != _low(row.get('owner')):
                need_owner(store, s, b.get('owner'), 'the owner of %s' % row['name'])
    elif path == '/api/certs/online_import':
        # Import from a source: each certificate is a new one, for a team they may ask for.
        for it in (b.get('items') if isinstance(b.get('items'), list) else []):
            if isinstance(it, dict):
                need_owner(store, s, it.get('owner'), 'a certificate imported from a source')
    elif path == '/api/certs/approve':
        # As the route reads it (1.0.45): " 5" or 5.0 found nothing here, and went through.
        row = cert_of_ref(store, b.get('id')) if b.get('id') not in (None, '') else None
        if row is not None and not (cert_may(store, s, row, 'approve')
                                    or cert_may(store, s, row, 'manage')):
            deny(store, s, 'approve %s' % row['name'], 'approve')
    elif path in ('/api/deploys/save', '/api/deploys/dry_run', '/api/deploys/preview'):
        right = 'view' if path == '/api/deploys/preview' else 'manage'
        # Both: the certificate given, and the one of the deployment given - a
        # deployment of another team's certificate was taken over by giving it
        # a certificate of one's own (1.0.19).
        if b.get('id') not in (None, '', 0):
            need_cert(store, s, _cert_of_deploy(store, b['id']), right, 'deploy')
        need_cert(store, s, _ref(b, 'cert_id'), right, 'deploy')
    elif path in ('/api/deploys/delete', '/api/deploys/run'):
        need_cert(store, s, _cert_of_deploy(store, b.get('id')), 'manage', 'deploy')


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


def team_public(t, used=None):
    out = {k: t.get(k) for k in ('id', 'name', 'kind', 'contact_mail', 'contact_phone', 'note',
                                 'created', 'created_by', 'updated', 'updated_by')}
    out['kind'] = out['kind'] or 'team'
    out['members'] = [m for m in (S.jload(t.get('members'), []) or []) if isinstance(m, dict)]
    for m in out['members']:
        m['kind'] = member_kind(m.get('who'))
    if used is not None:
        out['used'] = used.get(_low(t['name']), 0)
    return out


def teams(store):
    used = used_counts(store)
    return [team_public(t, used) for t in team_rows(store)]


def clean_mails(v):
    got = [w for w in re.split(r'[\s,;]+', str(v or '')) if w]
    for w in got:
        if not MAIL_RE.match(w):
            raise ValueError('%r is not a mail address' % w)
    if len(got) > 20:
        raise ValueError('20 addresses at most')
    return ', '.join(got)


def _profiles_follow(store, kind, old, new):
    """The request profiles that name an owner or a tag renamed (or a tag deleted)."""
    from acmelib.certs import reqprofiles
    reqprofiles.rename_ref(store, kind, old, new)


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
        raise ValueError('the kind is team or person')
    raw = b.get('members') if 'members' in b else S.jload((old or {}).get('members'), [])
    if isinstance(raw, str):
        raw = [w for w in re.split(r'[\n;]+', raw) if w.strip()]
    members, seen = [], set()
    for m in raw or []:
        m = clean_member(m)
        if _low(m['who']) in seen:
            continue
        seen.add(_low(m['who']))
        members.append(m)
    if len(members) > MEMBER_MAX:
        raise ValueError('%d members at most' % MEMBER_MAX)
    row = {'name': name, 'kind': kind, 'members': json.dumps(members),
           'contact_mail': clean_mails(b.get('contact_mail', (old or {}).get('contact_mail'))),
           'contact_phone': str(b.get('contact_phone', (old or {}).get('contact_phone')) or '')
           .strip()[:60],
           'note': str(b.get('note', (old or {}).get('note')) or '').strip()[:2000],
           'updated': _now(), 'updated_by': str(by)[:190]}
    if old:
        store.db.update('cert_teams', old['id'], row)
        if old['name'] != name:
            store.db.run('UPDATE certs SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                         (name, _low(old['name'])))
            _profiles_follow(store, 'team', old['name'], name)
        store.add_event('certificates', 'the owner %s changed by %s%s' % (
            name, by, (' (was %s)' % old['name']) if old['name'] != name else ''), who=by)
    else:
        row.update(created=_now(), created_by=str(by)[:190])
        store.db.insert('cert_teams', row)
        store.add_event('certificates', 'the owner %s added by %s' % (name, by), who=by)
    return team_public(team_get(store, name), used_counts(store))


def delete_team(store, name, by, reassign=None):
    t = team_get(store, name)
    if not t:
        raise LookupError('there is no owner %s' % name)
    n = used_counts(store).get(_low(t['name']), 0)
    moved = ''
    if n:
        if reassign is None:
            raise ValueError('%s owns %d certificate(s) - give them another owner first, or '
                             'delete it with reassign' % (t['name'], n))
        if reassign not in ('', '-'):
            to = team_get(store, reassign)
            if not to or to['id'] == t['id']:
                raise LookupError('there is no other owner %s' % reassign)
            moved = to['name']
        store.db.run('UPDATE certs SET owner = ? WHERE LOWER(TRIM(owner)) = ?',
                     (moved, _low(t['name'])))
    store.db.run('DELETE FROM cert_teams WHERE id = ?', (t['id'],))
    # The profiles naming it follow (1.0.45): they named an owner no longer there, unusable.
    _profiles_follow(store, 'team', t['name'], moved or None)
    store.add_event('certificates', 'the owner %s deleted by %s%s' % (
        t['name'], by, (' - its %d certificate(s) now owned by %s' % (n, moved or 'nobody'))
        if n else ''), 'warn', who=by)
    return {'deleted': t['name'], 'moved': n, 'to': moved}


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
