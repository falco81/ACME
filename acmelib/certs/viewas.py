# -*- coding: utf-8 -*-
"""
View as (1.0.138, docs/teams.md "View as"): a full administrator opens the administration - and
the portal - as a chosen member would see them, READ-ONLY.

The administration: the administrator's own sign-in carries `view_as` in its data; every route
but the few below then answers as the member's account would (its role, its name, its groups -
engine me() calls admin_session()); every write is refused (engine route() calls refused())
until "Stop viewing as". The portal: a sign-in of the portal of its own is made for the member,
marked `view_as`, entered by a one-time code from the administration (POST
/api/portal/view_as_enter) - every write of it refused the same way; Sign out ends it.

Started, stopped and every write refused meanwhile are events (kind certificates, naming the
member's teams, so each team's Activity shows them).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

from acmelib import engine as E
from acmelib.certs import teams as T

KEY = 'view_as'
# Answered as the administrator, never as the member (the banner, stopping, signing out).
OWN_PATHS = ('/api/teams/view_as', '/api/teams/view_as_stop', '/api/auth/logout')
# Writes that stay allowed while viewing as: stopping and signing out only.
FREE_POSTS = ('/api/teams/view_as_stop', '/api/auth/logout', '/api/portal/logout',
              '/api/portal/view_as_stop')
# Reads that hand out a file (a key, the database, a backup): refused too.
BLOCKED_GETS = ('/api/db/download', '/api/rbackup/download', '/api/export')
CODE_META = 'teams:viewas:'
CODE_S = 120
MOST_H = 2


def _low(v):
    return str(v or '').strip().lower()


def _hash(token):
    return hashlib.sha256(str(token or '').encode()).hexdigest()


def _session_row(h):
    token = str(h.headers.get('X-Acme-Session') or '')
    if not token:
        return None
    try:
        return h.store.db.row('SELECT id, kind, name, data FROM sessions WHERE token_hash = ?',
                              (_hash(token),))
    except Exception:                                   # noqa: BLE001
        return None


def _va_of(row):
    raw = (row or {}).get('data')
    if not raw or KEY not in str(raw):
        return None
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return None
    va = (data or {}).get(KEY)
    return va if isinstance(va, dict) else None


def _teams_words(store, names, groups):
    try:
        got = T.person_caps(store, names, groups)
    except Exception:                                   # noqa: BLE001
        return ''
    lst = sorted(v['name'] for v in got.values() if v.get('direct'))[:10]
    return (' - member of %s' % ', '.join('the team %s' % n for n in lst)) if lst else ''


def refused(h, method, path):
    """The words a request is refused with while its sign-in views as somebody - None when it
    may go (engine route(), before any route runs). One look at the sign-in's row."""
    if method == 'GET' and path not in BLOCKED_GETS:
        return None
    if method == 'POST' and path in FREE_POSTS:
        return None
    row = _session_row(h)
    va = _va_of(row)
    if not va:
        return None
    who = va.get('who') or va.get('name') or '?'
    by = va.get('by') or row.get('name') or '?'
    try:
        h.store.add_event('certificates', '%s, viewing the pages as %s (read-only), was refused: '
                          '%s %s' % (by, who, method, path), 'warn', who=str(by)[:190])
    except Exception:                                   # noqa: BLE001
        pass
    return ('read-only: you are viewing the pages as %s - nothing is changed while you do '
            '(Stop viewing as first)' % who)


def admin_session(h, s):
    """The session as the member's (engine me()): their name, role and account - the
    administrator's own for OWN_PATHS."""
    va = (s.get('data') or {}).get(KEY)
    if not isinstance(va, dict) or getattr(h, 'route_path', '') in OWN_PATHS:
        return s
    if time.time() - float(va.get('since') or 0) > MOST_H * 3600:
        stop(h.store, s, 'its time ran out')
        return s
    if s.get('role') != 'fulladmin':
        # no longer a full administrator (another role given meanwhile): seen as themselves
        stop(h.store, s, 'they are no longer a full administrator')
        return s
    acc = None
    if va.get('account'):
        try:
            acc = h.store.account(va['account'], checked=True)
        except Exception:                               # noqa: BLE001
            acc = None
    if acc is None:
        acc = dict(va.get('acc') or {})
    if not acc or acc.get('disabled') or acc.get('role') not in E.ROLE_RANK or \
            not E.ROLE_RANK.get(acc.get('role')):
        raise E.ApiError(403, '%s may not use the administration - stop viewing as them'
                         % (va.get('who') or '?'))
    out = dict(s)
    out.update(name=acc.get('name') or va.get('who'), role=acc['role'], account=acc,
               view_as_by=s.get('name'))
    return out


def whoami(h, s, got):
    """/api/auth/whoami of a sign-in viewing as somebody: the member's role and name, and
    `view_as` for the banner."""
    va = ((s or {}).get('data') or {}).get(KEY) if s else None
    if not isinstance(va, dict) or not isinstance((got or {}).get('who'), dict):
        return got
    if got['who'].get('role') != 'fulladmin':
        # their own role now: no longer a full administrator - not viewing as anybody
        stop(h.store, s, 'they are no longer a full administrator')
        return got
    acc = (va.get('acc') or {})
    if va.get('account'):
        try:
            acc = h.store.account(va['account'], checked=True) or acc
        except Exception:                               # noqa: BLE001
            pass
    who = dict(got['who'])
    who['role'] = acc.get('role') or 'readonly'
    who['view_as'] = public(s)
    return dict(got, who=who)


def public(s):
    va = ((s or {}).get('data') or {}).get(KEY)
    if not isinstance(va, dict):
        return None
    return {'who': va.get('who'), 'name': (va.get('acc') or {}).get('name') or va.get('who'),
            'role': (va.get('acc') or {}).get('role'), 'by': va.get('by') or s.get('name'),
            'since': va.get('since'), 'display': va.get('display') or ''}


# ---------------------------------------------------------------------------
# Whom: an account of the administration (local or of the directory)
# ---------------------------------------------------------------------------
def target_admin(h, who):
    """(account dict, words for the event) of the member to view the administration as -
    ApiError when they do not use the administration."""
    w = str(who or '').strip()
    if not w or len(w) > 400 or any(ord(c) < 32 for c in w):
        raise E.ApiError(400, 'whom? (local:NAME or a user of the directory)')
    bare = w[6:].strip() if w.lower().startswith('local:') else w
    acc = None
    try:
        acc = h.store.account(bare, checked=True)
    except Exception:                                   # noqa: BLE001
        acc = None
    if acc and w.lower().startswith('local:') and acc.get('source') == 'directory':
        acc = None
    if acc:
        if acc.get('disabled'):
            raise E.ApiError(409, '%s is switched off - they see nothing' % acc['name'])
        if not E.ROLE_RANK.get(acc.get('role') or ''):
            raise E.ApiError(409, '%s signs in on the portal only - open the portal as them'
                             % acc['name'])
        return {'name': acc['name'], 'role': acc['role'], 'source': acc.get('source') or 'local',
                'dn': acc.get('dn') or '', 'group_list': acc.get('group_list') or '',
                'display': acc.get('display') or ''}, acc['name']
    if w.lower().startswith('local:'):
        raise LookupError('there is no account %s' % bare[:120])
    # a person of the directory who has not signed in yet: the role their groups give
    from acmelib.certs import api_teams as AT
    ad = getattr(getattr(h, 'd', None), 'dirs', {}).get(str(E.CONFIG.get('admin_directory') or '')
                                                         .lower())
    if ad is None:
        raise E.ApiError(409, '%s has no account of the administration - open the portal as them'
                         % w[:120])
    entry = None
    for how, v in ([('upn', w), ('mail', w)] if '@' in w else [('sam', w)]):
        entry = AT._dir_call(lambda: ad.find_user(v, how))
        if entry:
            break
    if not entry:
        raise LookupError('the directory knows no %s' % w[:120])
    groups = AT._dir_call(lambda: ad.groups_of(entry, True))
    role = E.admin_role_for(groups, ad)
    if not role or role == 'portal':
        raise E.ApiError(409, '%s may not use the administration (none of their groups gives a '
                              'role there) - open the portal as them' % w[:120])
    name = entry.get('sam') or w
    return {'name': name, 'role': role, 'source': 'directory', 'dn': entry.get('dn') or '',
            'group_list': '; '.join(dn for dn, _cn in groups)[:20000],
            'display': entry.get('display') or ''}, name


def start(h, s, who):
    if s.get('role') != 'fulladmin':
        raise E.ApiError(403, 'only a full administrator views the pages as somebody else')
    if (s.get('data') or {}).get(KEY):
        raise E.ApiError(409, 'you are viewing as somebody already - stop that first')
    acc, name = target_admin(h, who)
    if _low(name) == _low(s.get('name')) and acc.get('source') == (s.get('account') or {}).get(
            'source'):
        raise E.ApiError(400, 'that is you')
    va = {'who': str(who).strip()[:200], 'account': acc['name'] if h.store.account(
        acc['name']) else None, 'acc': acc, 'by': s.get('name'), 'since': time.time(),
        'display': acc.get('display') or ''}
    h.store.session_merge(s['id'], {KEY: va})
    names, groups = T.admin_principal({'name': acc['name'], 'account': acc})
    h.store.add_event('certificates', '%s views the administration as %s (%s, read-only)%s' % (
        s.get('name'), va['who'], acc['role'], _teams_words(h.store, names, groups)), 'warn',
        who=str(s.get('name'))[:190])
    return public(dict(s, data={KEY: va}))


def stop(store, s, why=''):
    va = (s.get('data') or {}).get(KEY)
    if not va:
        return False
    store.session_merge(s['id'], {KEY: None})
    store.add_event('certificates', '%s stopped viewing the administration as %s%s' % (
        s.get('name'), va.get('who'), (' (%s)' % why) if why else ''), who=str(s.get('name'))[:190])
    return True


# ---------------------------------------------------------------------------
# The portal as the member
# ---------------------------------------------------------------------------
def portal_code(h, s, who):
    """A one-time code (2 min) that opens a read-only sign-in of the portal as `who`."""
    if s.get('role') != 'fulladmin' or (s.get('data') or {}).get(KEY):
        raise E.ApiError(403, 'only a full administrator (not viewing as somebody) opens the '
                              'portal as somebody else')
    if not E.CONFIG.get('portal') or not E.CONFIG.get('portal_cert'):
        raise E.ApiError(409, 'the portal (with certificates) is switched off - nobody sees it')
    data, name, words = portal_data(h, who)
    code = secrets.token_urlsafe(24)
    rec = {'name': name, 'data': data, 'by': s.get('name'), 'at': time.time(), 'who': words}
    h.store.set_meta(CODE_META + _hash(code), json.dumps(rec))
    return {'code': code, 'url': '/?viewas=' + code, 'who': words}


def portal_data(h, who):
    w = str(who or '').strip()
    if not w or len(w) > 400 or any(ord(c) < 32 for c in w):
        raise E.ApiError(400, 'whom? (local:NAME or a user of the directory)')
    if w.lower().startswith('local:'):
        bare = w[6:].strip()
        acc = h.store.account(bare, checked=True)
        if not acc or acc.get('source') == 'directory':
            raise LookupError('there is no account %s' % bare[:120])
        if acc.get('disabled') or not E.portal_local_may(acc):
            raise E.ApiError(409, '%s may not sign in on the portal' % acc['name'])
        return ({'kind': 'local', 'role': acc.get('role') or 'readonly', 'gate_ok': True,
                 'mfa_ok': True, 'display': acc.get('display') or ''}, acc['name'],
                'local:' + acc['name'])
    from acmelib.certs import api_teams as AT
    ad = AT.directory(h)
    if ad is None:
        raise E.ApiError(409, 'no directory is set up for the portal - its people cannot be '
                              'looked up')
    entry = None
    for how, v in ([('upn', w), ('mail', w)] if '@' in w else [('sam', w)]):
        entry = AT._dir_call(lambda: ad.find_user(v, how))
        if entry:
            break
    if not entry or not entry.get('dn'):
        raise LookupError('the directory knows no %s' % w[:120])
    name = str(entry.get('upn') or entry.get('sam') or w).strip().lower()
    return ({'kind': 'directory', 'dn': entry['dn'], 'role': '', 'dir_checked': time.time(),
             'gate_ok': True, 'login': w, 'mail': entry.get('mail') or '',
             'display': entry.get('display') or '',
             'about': {'sam': entry.get('sam') or '', 'upn': entry.get('upn') or ''}},
            name, name)


def portal_enter(h, code):
    """The one-time code taken (once) -> a portal sign-in viewing as the member: {token}."""
    code = str(code or '').strip()
    if not code or len(code) > 100:
        raise E.ApiError(400, 'the code is missing')
    k = CODE_META + _hash(code)
    raw = h.store.get_meta(k)
    if not raw:
        raise E.ApiError(403, 'the code is used or wrong - open the portal as them again')
    n = h.store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (k, raw))
    if not n:
        raise E.ApiError(403, 'the code is used already')
    rec = json.loads(raw)
    if time.time() - float(rec.get('at') or 0) > CODE_S:
        raise E.ApiError(403, 'the code ran out - open the portal as them again')
    data = dict(rec['data'])
    data[KEY] = {'who': rec.get('who'), 'by': rec.get('by'), 'since': time.time()}
    token = h.store.session_new('portal', rec['name'], 'portal', h.client_ip(), MOST_H, data)
    names = {_low(rec['name'])}
    if data.get('kind') == 'local':
        names = {'local:' + _low(rec['name'])}
    h.store.add_event('certificates', '%s views the portal as %s (read-only)%s' % (
        rec.get('by'), rec.get('who'), _teams_words(h.store, names, [])), 'warn',
        who=str(rec.get('by') or '')[:190])
    return {'token': token, 'who': rec.get('who'), 'by': rec.get('by')}


def portal_public(h):
    row = _session_row(h)
    va = _va_of(row) if row and row.get('kind') == 'portal' else None
    if not va:
        return {'active': False}
    return {'active': True, 'who': va.get('who'), 'by': va.get('by'), 'since': va.get('since')}
