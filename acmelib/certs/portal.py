# -*- coding: utf-8 -*-
"""
The certificate portal: what people signed in on the enrolment pages (a
`portal` session, against the directory) may do with certificates - kept
modest. Their certificates are those whose `owner` is them (their name,
account, UPN or mail) or a directory group they are in (its name or DN,
"group:" in front allowed). An account of acme's own signed in there
(portal_local) owns those whose owner is its name or "local:" and its name;
with portal_admins_all one with the role certadmin or fulladmin sees every
certificate (via '*'). What it asks for is owned by "local:NAME".

    GET  /api/portal/certs             their certificates, the job of each, and what
                                       they may ask for
    GET  /api/portal/cert_job?id=      one job of one of their certificates, every step
    POST /api/portal/cert_download     {id, format, password?}  cert-pem, cert-der,
                                       chain-pem, fullchain-pem, p7b - and pfx (with its
                                       key, a password needed) only with portal_cert_keys
    POST /api/portal/cert_request      {names[], issuer, key_type?, note?}  a certificate
                                       for names under portal_cert_suffixes from one of
                                       portal_cert_issuers, owned by them: issued at once
                                       (portal_cert_auto) or kept 'pending-approval'
    POST /api/certs/approve            {id, ok, why}  an administrator (certadmin) lets a
                                       request be issued, or declines it

Settings: portal_cert (on/off), portal_cert_suffixes, portal_cert_issuers,
portal_cert_challenge, portal_cert_max (requests one person may have),
portal_cert_auto (issued without approval), portal_cert_keys (PFX with the key).
The person is mailed (their directory mail) when their certificate is issued,
approved or declined. Every action is an event of kind `certificates`.
"""
from __future__ import annotations

import json
import re
import threading
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import jobs, renewer, schema
from acmelib.certs import api as A
from acmelib.certs import reqprofiles

PORTAL_FORMATS = ('cert-pem', 'cert-der', 'chain-pem', 'fullchain-pem', 'p7b')
KEY_FORMAT = 'pfx'
WAITING = 'pending-approval'
DECLINED = 'declined'
GROUPS_KEEP_S = 600             # the person's groups, asked of the directory at most this often
META = 'certs:portal:'          # + cert id: who asked, and where to mail them

# The two states of a request, beside the certificate manager's own. A row in
# either is never renewed by itself: auto_renew stays 0 until it is approved.
schema.STATES.setdefault(WAITING, 'asked for on the portal, waiting for an administrator')
schema.STATES.setdefault(DECLINED, 'asked for on the portal, declined')


def words_list(key):
    return [w.strip().lower().lstrip('.').lstrip('*.') if key.endswith('suffixes') else w.strip()
            for w in re.split(r'[\s,;]+', str(E.CONFIG.get(key) or '')) if w.strip()]


def portal_session(h):
    s = E.portal_me(h)
    if not E.CONFIG.get('portal_cert'):
        raise E.ApiError(403, 'certificates are not offered on these pages')
    return s


def name_allowed(name, suffixes):
    n = name[2:] if name.startswith('*.') else name
    return any(n == suf or n.endswith('.' + suf) for suf in suffixes)


# ---------------------------------------------------------------------------
# Whose certificates
# ---------------------------------------------------------------------------
def is_local(s):
    return (s.get('data') or {}).get('kind') == 'local'


def owner_word(s):
    """What a certificate asked for by this sign-in is owned by: the
    directory's name of the person, or local:NAME for an account here - so a
    person of the directory with the same name does not get it."""
    return ('local:%s' % s['name']) if is_local(s) else str(s['name'])


def my_names(s):
    data = s.get('data') or {}
    about = data.get('about') or {}
    if is_local(s):
        # local:NAME; NAME alone only where nobody of a directory signs in here (1.0.88: with a
        # directory, a local "novak" owned the directory novak's certificates and took their keys)
        mine = {'local:' + str(s['name']).lower()}
        if not str(E.CONFIG.get('portal_directory') or E.CONFIG.get('admin_directory') or '').strip():
            mine.add(str(s['name']).lower())
        return mine
    out = {str(s['name']).lower()}
    # What the directory said who it is (1.0.45) - never the name as typed: "B\\falco" typed by
    # falco of domain A owned what was B\\falco's.
    for v in (about.get('sam'), about.get('upn'), data.get('mail')):
        if v:
            out.add(str(v).strip().lower())
    return out


def asker_ids(s):
    """Every name a portal session's person is known by (lower case), kept with a request they
    ask for or give a CSR or names to (1.0.102): my_names and, of the directory, the DN - an
    administrator whose account is their sAMAccountName (jnovak) and whose portal sign-in is their
    UPN (jan.novak@corp) is found by either."""
    out = set(my_names(s))
    if not is_local(s):
        dn = str((s.get('data') or {}).get('dn') or '').strip().lower()
        if dn:
            out.add(dn)
    out.discard('')
    return sorted(out)


def my_groups(h, s):
    """[(dn, cn)] of every group the person is in (nested), asked of the
    directory at most every GROUPS_KEEP_S and kept in the session; what was
    kept when the directory cannot be reached."""
    data = s.get('data') or {}
    if is_local(s):
        return []
    kept = data.get('cert_groups')
    if isinstance(kept, list) and time.time() - float(data.get('cert_groups_at') or 0) < GROUPS_KEEP_S:
        return [tuple(g) for g in kept]
    got = None
    try:
        ad = E.portal_directory(h)
        if ad and data.get('dn'):
            got = [[str(dn), str(cn)] for dn, cn in ad.groups_of({'dn': data['dn']}, True)][:500]
    except Exception as e:                              # noqa: BLE001
        E.log('the certificate portal could not read the groups of %s: %s' % (s['name'], e),
              'warn')
    if got is None:
        return [tuple(g) for g in (kept or [])]
    try:
        E.portal_data_set(h, s, cert_groups=got, cert_groups_at=time.time())
    except Exception:                                   # noqa: BLE001
        pass
    return [tuple(g) for g in got]


def my_teams(h, s):
    """{team lower: (name, {rights})} of the person (Settings → Owners and teams):
    the teams with them - their name, local:NAME, a group they are in - as a member."""
    from acmelib.certs import teams
    return teams.person_teams(h.store, my_names(s), my_groups(h, s))


def defined_teams(store):
    """The names (lower case) of every team of Settings → Owners and teams."""
    from acmelib.certs import teams
    return {str(t['name']).strip().lower() for t in teams.team_rows(store)}


def owner_of(row, names, groups, teams=None, defined=()):
    """'' when the certificate is not theirs, 'me', the team's name (a team with
    them as a member that may see it), or the group's name. An owner that is a team
    (`defined`) is the team's only (1.0.19): a group of the directory or a person of
    the same name as the team saw its certificates - and got their keys - without
    being one of its members."""
    owner = str(row.get('owner') or '').strip().lower()
    if not owner:
        return ''
    if owner in names and owner not in defined:
        return 'me'
    if teams and owner in teams and 'view' in teams[owner][1]:
        return teams[owner][0]
    if owner in defined:
        return ''
    bare = owner[6:].strip() if owner.startswith('group:') else owner
    for dn, cn in groups:
        if bare in (dn.lower(), cn.lower()):
            return cn
    return ''


def last_job(store, cid):
    r = store.db.row('SELECT id, ts, kind, state, ok, finished, said FROM cert_jobs '
                     'WHERE cert_id = ? ORDER BY ts DESC, id DESC LIMIT 1', (cid,))
    if not r:
        return None
    with jobs._LOCK:
        live = jobs.RUNNING.get(r['id'])
    if live is not None:
        r['state'] = live.state
    r['live'] = r.get('state') in ('queued', 'running')
    return r


def public_row(store, r, via):
    one = S.cert_public(r)
    why = one.get('last_error') if one.get('state') in (DECLINED, 'failed') else ''
    # The twin's error too (1.0.19): what the CA or a module said, as last_error is.
    for k in ('last_error', 'challenge_map', 'profile', 'ari', 'updated_by', 'csr_waiting',
              'challenge', 'renew_days', 'reuse_key', 'fails', 'next_try', 'enabled',
              'alt_error'):
        one.pop(k, None)
    one['why'] = str(why or '')[:500]
    one['via'] = via                    # 'me', or the group it is theirs through
    one['mine'] = str(r.get('created_by') or '') == 'portal:' + str(one.get('owner') or '')
    one['job'] = last_job(store, r['id'])
    # What it may be downloaded as, and the request profile it was asked for from (1.0.18).
    one['formats'] = row_formats(store, r)
    one['req_profile'] = asker(store, r['id']).get('profile') or ''
    return one


def row_formats(store, row):
    """The formats of one certificate: those of the portal, and the PFX with its key where
    its request profile gives it (or, asked for without one, portal_cert_keys) - never for one
    issued for a CSR sent in, whose key acme does not hold."""
    a = asker(store, row['id'])
    if a.get('profile'):
        out = list(PORTAL_FORMATS) + ([KEY_FORMAT] if a.get('pfx') else [])
    else:
        out = formats()
    if row.get('csr_given') or row.get('csr_from'):
        out = [f for f in out if f != KEY_FORMAT]
    return out


ALL_RIGHTS = ('view', 'request', 'manage', 'approve')


def rights_of(s, row, names, groups, tms, defined=()):
    """What this sign-in may do with one certificate (1.0.16): an administrator
    of acme's own who sees all (portal_admins_all) everything; otherwise the
    rights of the team that owns it (Settings → Owners and teams), and seeing
    it when it is owned by them or a group of theirs - as before."""
    if E.portal_sees_all(s):
        return set(ALL_RIGHTS)
    owner = str(row.get('owner') or '').strip().lower()
    got = set()
    if owner and owner in tms:
        got |= set(tms[owner][1])
    if owner_of(row, names, groups, None, defined):
        got.add('view')
    return got


def mine(h, s, rows=None):
    """Their certificates: owned by them or by a group they are in - every
    one for an administrator of acme's own (portal_admins_all)."""
    store = h.store
    names = my_names(s)
    groups = my_groups(h, s)
    tms = my_teams(h, s)
    defined = defined_teams(store)
    ids = set(asker_ids(s))
    held_rows = []

    def public(st_, r, via):
        one = public_row(st_, r, via)
        one['may'] = [w for w in ALL_RIGHTS if w in rights_of(s, r, names, groups, tms, defined)]
        one['team'] = str(r.get('owner') or '').strip().lower() in tms
        # asked for by this very person (1.0.80): its Approve was offered, then refused
        one['asked_by_me'] = bool(askers_of(st_, r['id']) & ids)
        if r.get('state') == WAITING:
            # whose names it asks for (1.0.102) - the certificates read once for the list
            if not held_rows:
                held_rows.append(holder_rows(st_))
            held = held_of(st_, r, held_rows[0])
            one.update(held_public(st_, r, held_rows[0], defined, held))
            # whether its Approve would be refused, and why (said, not offered and then refused)
            if one['asked_by_me']:
                one['may_approve'], one['approve_why'] = False, (
                    'you asked for it yourself, or sent its CSR or names - someone else '
                    'approves it')
            elif E.portal_sees_all(s):
                one['may_approve'], one['approve_why'] = True, ''
            else:
                why = held_refused(st_, r, portal_may_owner(names, tms, defined), held, defined)
                one['may_approve'], one['approve_why'] = not why, why
        if not key_may(s, via, one['may'], asker(st_, r['id']).get('who')):
            one['formats'] = [f for f in one.get('formats') or [] if f != KEY_FORMAT]
        return one
    if E.portal_sees_all(s):
        out = [public(store, r, owner_of(r, names, groups, tms) or '*')
               for r in store.db.rows('SELECT * FROM certs ORDER BY name')]
        out.sort(key=lambda o: (o.get('via') != 'me', str(o.get('name') or '').lower()))
        return out
    want = sorted(names | {cn.lower() for _, cn in groups} | {dn.lower() for dn, _ in groups}
                  | {'group:' + cn.lower() for _, cn in groups}
                  | {k for k, (_, r) in tms.items() if 'view' in r})
    out = []
    # Asked in pieces: a person in hundreds of groups is not one statement of hundreds of '?'.
    for at in range(0, len(want), 100):
        part = want[at:at + 100]
        for r in store.db.rows('SELECT * FROM certs WHERE LOWER(TRIM(owner)) IN (%s)' % ', '.join(
                '?' * len(part)), tuple(part)):
            via = owner_of(r, names, groups, tms, defined)
            if via and r['id'] not in {o['id'] for o in out}:
                out.append(public(store, r, via))
    out.sort(key=lambda o: (o.get('via') != 'me', str(o.get('name') or '').lower()))
    return out


def used(store, who):
    """The requests a person has made that count: every one asked for here
    and still kept, but those declined."""
    return int(store.db.value("SELECT COUNT(*) FROM certs WHERE created_by = ? AND "
                              "COALESCE(state, '') <> ?", ('portal:' + who, DECLINED), 0) or 0)


def key_may(s, via, may, asked_by=''):
    """Whether this sign-in may take the key (a PFX) of a certificate it sees
    (1.0.19): its own (owned by them, or asked for by them for a team), one of
    a team where they may manage, or an administrator of acme's own who sees
    all - never a member who may only see it, nor through a directory group."""
    # Seeing all gives the key only to a full administrator (1.0.45), as the administration's
    # own export does: a certificate administrator took any certificate's key from here.
    sees_all_key = E.portal_sees_all(s) and (s.get('data') or {}).get('role') == 'fulladmin'
    if sees_all_key or via == 'me' or (asked_by and str(asked_by).lower() == owner_word(s).lower()):
        return True
    # 'manage' by a team's right - not the every-right a sees-all session gets.
    return bool('manage' in (may or ()) and not E.portal_sees_all(s))


def need_mine(h, s, ref):
    row = S.cert_get(h.store, A._id(ref))
    if row and E.portal_sees_all(s):
        return row
    if not row or not owner_of(row, my_names(s), my_groups(h, s), my_teams(h, s),
                               defined_teams(h.store)):
        raise E.ApiError(404, 'there is no such certificate of yours')
    return row


def need_right(h, s, ref, right, doing):
    """One of their certificates, and the right asked for on it - or a 403 in
    words and an event saying who was refused what."""
    row = need_mine(h, s, ref)
    have = rights_of(s, row, my_names(s), my_groups(h, s), my_teams(h, s),
                     defined_teams(h.store))
    ok = right in have or (right == 'approve' and 'manage' in have)
    if not ok:
        h.store.add_event('certificates', '%s was refused on the portal: %s %s (needs the right '
                          '%s)' % (s['name'], doing, row['name'], right), 'warn', who=s['name'])
        raise E.ApiError(403, {'manage': 'you may not change this certificate - its team gives '
                                         'you the right manage for that',
                               'approve': 'you may not approve this certificate - its team gives '
                                          'you the right approve for that'}.get(
            right, 'you may not do that'))
    return row


def most():
    return int(E.CONFIG.get('portal_cert_max') or 10)


def formats():
    return list(PORTAL_FORMATS) + ([KEY_FORMAT] if E.CONFIG.get('portal_cert_keys') else [])


# ---------------------------------------------------------------------------
# Telling the person
# ---------------------------------------------------------------------------
MAIL_WORDS = {
    'en': {
        'issued': ('Your certificate %(name)s is ready',
                   'The certificate you asked for on %(site)s has been issued.\n\n'
                   '  Names:      %(names)s\n  Valid until: %(until)s\n  Issuer:     %(issuer)s\n\n'
                   'Download it from %(url)s - it is renewed by itself before it runs out.'),
        'approved': ('Your request for %(name)s was approved',
                     'An administrator approved the certificate you asked for on %(site)s '
                     '(%(names)s). It is being issued now: you get another mail when it is '
                     'ready.%(why)s'),
        'declined': ('Your request for %(name)s was declined',
                     'An administrator declined the certificate you asked for on %(site)s '
                     '(%(names)s).%(why)s\n\nAsk them for more, or ask again at %(url)s.'),
        'why': '\n\nThey said: %s',
    },
    'cs': {
        'issued': ('Váš certifikát %(name)s je připraven',
                   'Certifikát, o který jste požádali na %(site)s, byl vydán.\n\n'
                   '  Jména:      %(names)s\n  Platí do:   %(until)s\n  Vydavatel:  %(issuer)s\n\n'
                   'Stáhnete si ho na %(url)s - před koncem platnosti se obnoví sám.'),
        'approved': ('Vaše žádost o %(name)s byla schválena',
                     'Správce schválil certifikát, o který jste požádali na %(site)s '
                     '(%(names)s). Právě se vydává: až bude připraven, přijde další e-mail.%(why)s'),
        'declined': ('Vaše žádost o %(name)s byla zamítnuta',
                     'Správce zamítl certifikát, o který jste požádali na %(site)s '
                     '(%(names)s).%(why)s\n\nZeptejte se ho na víc, nebo požádejte znovu na %(url)s.'),
        'why': '\n\nNapsal: %s',
    },
}


def _covers(pattern, host):
    """A name, or a wildcard of one label, holding the host."""
    pattern, host = str(pattern).lower().rstrip('.'), str(host).lower().rstrip('.')
    if pattern == host:
        return True
    if pattern.startswith('*.'):
        return '.' in host and host.split('.', 1)[1] == pattern[2:]
    return False


def holder_rows(store):
    """The certificates that may hold names (holders' `rows`): [(id, owner, state, [names])]
    - read once for a whole list (1.0.102), not once a row. Revoked and declined ones, and
    ones run out (not_after past), hold none."""
    now = time.time()
    out = []
    for r in store.db.rows("SELECT id, owner, names, state, not_after FROM certs WHERE "
                           "state NOT IN ('revoked', 'declined')"):
        try:
            na = float(r.get('not_after') or 0)
        except (TypeError, ValueError):
            na = 0
        if na and na < now:
            continue
        out.append((r.get('id'), str(r.get('owner') or '').strip(), r.get('state'),
                    [str(x).lower() for x in (S.jload(r.get('names'), []) or [])]))
    return out


def holders(store, names, who, exclude=None, waiting=True, rows=None, unowned=False):
    """{owner (as the certificate says it): [the names of these it holds]} of every
    certificate of another owner naming one of these (1.0.51) - under a wildcard of theirs,
    or a wildcard asked over a name of theirs, too (1.0.80). `exclude`: the id of the
    certificate asked about itself; `waiting`: requests that wait for approval count too;
    `rows`: holder_rows() read already. A certificate without an owner holds nothing (no team
    to ask - any approver approves), unless `unowned` (then under ''): a request for its names
    still waits for approval (1.0.51). One run out, revoked or declined holds nothing."""
    me = str(who or '').strip().lower()
    want = [str(n).lower() for n in names or [] if n]
    out = {}
    if not want:
        return out
    for rid, owner, state, theirs in (holder_rows(store) if rows is None else rows):
        if exclude is not None and rid == exclude:
            continue
        if not waiting and state == WAITING:
            continue
        if owner.lower() == me or (not owner and not unowned):
            continue
        for n in want:
            for t in theirs:
                if _covers(t, n) or _covers(n, t) or \
                        (n.startswith('*.') and t.startswith('*.') and n == t):
                    got = out.setdefault(owner, [])
                    if n not in got:
                        got.append(n)
    return out


def held_by_others(store, names, who, exclude=None):
    """Whether a certificate of another owner names one of these (1.0.51): asked for on the
    portal and issued at once, mail.corp.example of the IT team's - and its key taken. It waits
    for approval then - by the owner that holds the name (1.0.102), see may_approve_held."""
    return bool(holders(store, names, who, exclude, unowned=True))


def held_list(got):
    """holders() as it is kept in the request's meta and shown: [{owner, names}]."""
    return [{'owner': o, 'names': sorted(n)} for o, n in sorted(got.items())]


def held_of(store, row, rows=None):
    """[{owner, names}] of a request waiting for approval: who holds its names now (another
    owner's certificate issued since too). An owner kept when it began to wait counts only
    while a certificate of theirs still holds one of its names (1.0.106: one revoked, run out
    or deleted since kept its owner the approver for good). No owner holds nothing (holders).
    `rows`: holder_rows() read already."""
    kept = asker(store, row['id']).get('held')
    live = holders(store, S.jload(row.get('names'), []) or [], row.get('owner'), row['id'],
                   waiting=False, rows=rows)
    by_low = {o.lower(): o for o in live}
    out = {}
    for one in kept if isinstance(kept, list) else []:
        if isinstance(one, dict) and str(one.get('owner') or '').strip():
            o = by_low.get(str(one.get('owner') or '').strip().lower())
            if o is not None:
                out.setdefault(o, set()).update(live[o])
    if row.get('state') == WAITING:
        for o, ns in live.items():
            out.setdefault(o, set()).update(ns)
    return [{'owner': o, 'names': sorted(ns)} for o, ns in sorted(out.items())]


def held_words(held, defined=()):
    """The owners holding the names, in words: a team by its name; a person or no owner not
    named (1.0.102: another team's certificates are not named to a scoped session)."""
    out = []
    for one in held:
        o = str(one.get('owner') or '').strip()
        if o and o.lower() in defined:
            out.append('the team %s (%s)' % (o, ', '.join(one.get('names') or [])))
        elif o:
            out.append('a certificate of a person (%s)' % ', '.join(one.get('names') or []))
        else:
            out.append('a certificate without an owner (%s)' % ', '.join(one.get('names') or []))
    return out


def held_public(store, row, rows=None, defined=None, held=None):
    """What the approval dialogs show of a request held by others' names (1.0.102). `rows`
    (holder_rows), `defined` (defined_teams) and `held` (held_of) where read once already."""
    if defined is None:
        defined = defined_teams(store)
    if held is None:
        held = held_of(store, row, rows)
    return {'held': [{'team': o['owner'] if o['owner'].lower() in defined else '',
                      'names': o['names']} for o in held],
            'held_words': held_words(held, defined)}


def need_held_ok(store, row, may_owner, who):
    """A request whose names another owner's certificate holds is approved only by someone
    who may approve (or manage) for that owner, or a full administrator (1.0.102: any
    approver of the asker's own team approved mail.example of the Mail team's - and the asker
    took its key). `may_owner(owner)`: whether the one approving may for that owner."""
    why = held_refused(store, row, may_owner)
    if not why:
        return
    store.add_event('certificates', '%s was refused: approving %s, whose names are held by '
                    'another owner\'s certificates' % (who, row['name']), 'warn', who=who)
    raise E.ApiError(403, why)


def held_refused(store, row, may_owner, held=None, defined=None):
    """Why need_held_ok refuses this one approving it, in words - '' when it does not; nothing
    said or written (the lists offer Approve by it: may_approve). The owners are the list
    after the dash, one sentence each, so it reads (and is translated) for any number."""
    held = held_of(store, row) if held is None else held
    bad = [o for o in held if not may_owner(o['owner'])]
    if not bad:
        return ''
    return ('its names are held by certificates of another owner: only someone who may approve '
            '(or manage) for that owner, or a full administrator, approves it - %s'
            % '; '.join(held_words(bad, defined_teams(store) if defined is None else defined)))


def portal_may_owner(names, tms, defined):
    """Whether a portal sign-in (my_names, my_teams, defined_teams) may approve for an owner
    holding a request's names: an approver (or manager) of that team, or the person himself."""
    def may_owner(o):
        o = str(o or '').strip().lower()
        if o and o in tms and tms[o][1] & {'approve', 'manage'}:
            return True
        return bool(o) and o in names and o not in defined     # their own certificate
    return may_owner


def admin_may_approve(store, row, s, held=None, defined=None):
    """(whether this session of the administration may approve the request, why not) - the
    checks of /api/certs/approve, said beforehand (the list and the view: no Approve offered
    that is then refused)."""
    if asked_by_admin(store, row, s):
        return False, ('you asked for it yourself, or gave it its CSR or names - have another '
                       'administrator approve or decline it (a full administrator who needs a '
                       'certificate adds it here: Add a certificate)')
    if s.get('role') == 'fulladmin' or s.get('cli'):
        return True, ''
    from acmelib.certs import teams as T
    why = held_refused(store, row, lambda o: T.cert_may(store, s, {'owner': o}, 'approve')
                       or T.cert_may(store, s, {'owner': o}, 'manage'), held, defined)
    return (not why), why


def askers_of(store, cid):
    """Who asked for it, and everyone who sent a new CSR or names for it since (1.0.102: a
    member who may manage sent his own CSR with other names for another's request, and approved
    it himself) - lower case."""
    a = asker(store, cid)
    out = {str(a.get('who') or '').strip().lower()}
    out |= {str(x).strip().lower() for x in (a.get('askers') or []) if x}
    # every name each of them is known by (1.0.102): the DN, sAMAccountName, UPN
    out |= {str(x).strip().lower() for x in (a.get('ids') or []) if x}
    out.discard('')
    return out


def note_asker(store, cid, who, held=None, ids=(), waits=False):
    """`who` (owner_word) sent a CSR or names for it: one of its askers from now; `ids` every
    other name they are known by (asker_ids, admin_names); `held` (holders()) kept as why it
    waits, where given; `waits`: it needs an approval (again), as mark_waiting - in the same
    write (1.0.106)."""
    def change(a):
        if waits:
            a['waits'] = True
            a.pop('approved', None)
        lst = [str(x) for x in (a.get('askers') or []) if x]
        if who and str(who).lower() not in {x.lower() for x in lst}:
            lst.append(str(who)[:190])
        a['askers'] = lst[-50:]
        known = [str(x) for x in (a.get('ids') or []) if x]
        for x in ids or ():
            x = str(x).strip().lower()[:400]
            if x and x not in known:
                known.append(x)
        a['ids'] = known[-200:]
        if held is not None:
            a['held'] = held_list(held)
    asker_change(store, cid, change)


HELD_WORDS = {
    'en': ('A request for names of %(team)s waits for your approval',
           '%(who)s asked on %(site)s for a certificate with names that a certificate of the team '
           '%(team)s holds:\n\n  %(names)s\n\nIt is issued only when someone who may approve '
           'for %(team)s (or a full administrator) approves it - on the portal (%(url)s) or in '
           'the administration, Certificates, waiting for approval.'),
    'cs': ('Žádost o jména týmu %(team)s čeká na vaše schválení',
           '%(who)s požádal na %(site)s o certifikát se jmény, která má certifikát týmu '
           '%(team)s:\n\n  %(names)s\n\nVydá se, až ho schválí někdo, kdo smí schvalovat za '
           '%(team)s (nebo plný správce) - na portálu (%(url)s) nebo ve správě, Certifikáty, '
           'čeká na schválení.'),
}


def tell_holders(store, cid, held, who):
    """A mail to each team whose certificate holds a name of a request that waits (its
    contact mail, Settings → Owners and teams), and an event (1.0.102: the team holding the
    name was never asked nor told). Never raises; run in a thread of its own."""
    defined = defined_teams(store)
    teams_ = [(o, ns) for o, ns in sorted((held or {}).items()) if o and o.lower() in defined]
    if not teams_:
        return

    def go():
        from acmelib.certs import teams as T
        try:
            row = S.cert_get(store, cid)
            if not row:
                return
            for team, ns in teams_:
                store.add_event('certificates', '%s waits for approval by the team %s: its names '
                                '%s are held by a certificate of that team' % (
                                    row['name'], team, ', '.join(ns)), 'warn', who=who)
                to = T.contact_mails(store, {'owner': team})
                if not to:
                    continue
                if (E.CONFIG.get('mail_mode') or 'off') == 'off':
                    E.log('the certificate portal would have mailed %s (names of %s asked for): '
                          'mail is switched off' % (', '.join(to), team))
                    continue
                subject, body = HELD_WORDS.get(str(E.CONFIG.get('ui_lang') or 'cs'),
                                               HELD_WORDS['en'])
                site = str(E.CONFIG.get('portal_title') or E.CONFIG.get('site_name') or 'acme')
                fill = {'team': team, 'who': who, 'site': site, 'url': portal_url(),
                        'names': ', '.join(ns)}
                from email.message import EmailMessage
                msg = EmailMessage()
                msg['Subject'] = subject % fill
                msg['From'] = E.mail_sender() or 'acme@%s' % E.node_name()
                msg['To'] = ', '.join(to)
                msg.set_content((body % fill) + '\n\n-- acme, %s\n' % site)
                try:
                    E.mail_deliver(store, msg, to, kind='certs', name=team,
                                   purpose='portal certificate held names')
                except E.MailError as e:
                    if getattr(e, 'queued', None) != 'waiting':
                        raise
        except Exception as e:                          # noqa: BLE001
            E.log('the certificate portal could not tell the team holding the names of %s: %s'
                  % (cid, e), 'warn')
    threading.Thread(target=go, name='portal-mail-held', daemon=True).start()


def asker_change(store, cid, change):
    """The request's meta changed by `change(a)` (a dict, changed in place) as one compare-and-
    swap (1.0.106): read, changed and written only over what was read - an approval and a CSR
    sent at once each wrote the whole meta over the other's, and `approved` written by one was
    gone, the request "never approved" for good. Tried again over what the other wrote."""
    k = META + str(cid)
    # Inside a transaction on MariaDB, read with a lock (1.0.106): REPEATABLE READ read each try
    # again from the snapshot the transaction began with - approve_request's mark_approved saw
    # the row as it was, never what another wrote, and gave up after a second with a 409.
    # PostgreSQL (READ COMMITTED) and SQLite (BEGIN IMMEDIATE, one writer) see the new row.
    locked = store.db.engine == 'mariadb' and getattr(store.db, 'in_tx', False)
    for _ in range(50):
        if locked:
            raw = store.db.value('SELECT v FROM meta WHERE k = ? FOR UPDATE', (k,))
        else:
            raw = store.get_meta(k)
        try:
            a = json.loads(raw or 'null')
        except (TypeError, ValueError):
            a = None
        a = a if isinstance(a, dict) else {}
        change(a)
        new = json.dumps(a)
        if raw is None:
            # none yet: written as set_meta writes (an insert - nothing to compare with)
            store.set_meta(k, new)
            return a
        with store.db.transaction():
            n = store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?', (new, k, raw))
            if n and E.dbguard_meta_signed(k):
                E.dbguard_sign(store.db, 'm', k, new)
        if n:
            return a
        time.sleep(0.02)
    raise E.ApiError(409, 'the request %s changed while it was written - try again' % cid)


def asker(store, cid):
    try:
        got = json.loads(store.get_meta(META + str(cid)) or 'null')
    except Exception:                                   # noqa: BLE001
        got = None
    return got if isinstance(got, dict) else {}


def portal_url():
    """Where the portal is - this machine's name: the address people reach it
    by is the one nginx answers on."""
    import socket
    try:
        return 'https://%s/' % (socket.getfqdn() or E.short_host())
    except Exception:                                   # noqa: BLE001
        return 'the portal'


def tell(store, cid, what, why=''):
    """A mail to the person who asked for the certificate, if their directory
    entry has a mail - through the engine's mail queue (kept and tried again
    when it is not taken at once). Never raises; run in a thread of its own,
    as the queue sends at once."""
    def go():
        try:
            who = asker(store, cid)
            to = str(who.get('mail') or '').strip()
            row = S.cert_get(store, cid)
            if not to or '@' not in to or not row:
                return
            if (E.CONFIG.get('mail_mode') or 'off') == 'off':
                E.log('the certificate portal would have mailed %s (%s): mail is switched off'
                      % (to, what))
                return
            words = MAIL_WORDS.get(str(E.CONFIG.get('ui_lang') or 'cs'), MAIL_WORDS['en'])
            site = str(E.CONFIG.get('portal_title') or E.CONFIG.get('site_name') or 'acme')
            until = time.strftime('%Y-%m-%d', time.localtime(float(row['not_after']))) \
                if row.get('not_after') else '?'
            fill = {'name': row['name'], 'site': site, 'url': portal_url(), 'until': until,
                    'names': ', '.join(S.jload(row.get('names'), []) or []),
                    'issuer': row.get('issuer') or '',
                    'why': (words['why'] % why) if why else ''}
            msg = None
            if what in ('issued', 'declined'):
                # in the words of Settings → Message texts (1.0.88: they were never used - the
                # mail went in words of its own whatever an administrator wrote there)
                try:
                    from acmelib.certs import notices
                    mail, _sms = notices.drawn('cert_portal_' + what, notices.cert_values(
                        store, row, name=who.get('who') or '', reason=why or '', site=site))
                    if mail and (mail.get('text') or '').strip():
                        msg = notices._mail([to], mail)
                except Exception as e:                  # noqa: BLE001
                    E.log('the portal\'s mail in its own words: %s' % e, 'warn')
            if msg is None:
                subject, body = words[what]
                from email.message import EmailMessage
                msg = EmailMessage()
                msg['Subject'] = subject % fill
                msg['From'] = E.mail_sender() or 'acme@%s' % E.node_name()
                msg['To'] = to
                msg.set_content((body % fill) + '\n\n-- acme, %s\n' % site)
            said = 'told %s by mail' % to
            try:
                E.mail_deliver(store, msg, [to], kind='certs', name=who.get('who') or '',
                               purpose='portal certificate %s' % what)
            except E.MailError as e:
                if getattr(e, 'queued', None) != 'waiting':
                    raise
                said = 'a mail to %s waits in the outgoing mail (%s)' % (to, e)
            store.add_event('certificates', '%s was %s: %s' % (row['name'], what, said),
                            who=who.get('who') or '')
        except Exception as e:                          # noqa: BLE001
            E.log('the certificate portal could not mail about %s (%s): %s' % (cid, what, e),
                  'warn')
    threading.Thread(target=go, name='portal-mail', daemon=True).start()


def issue_job(cid, by):
    """renewer.renew_job, and the person told when it worked."""
    def fn(job):
        # the person is told by the renewal when the first one is issued (1.0.88: here only,
        # and a first try that failed was retried by the renewer - and nobody told)
        return renewer.renew_cert(job.store, job, cid, False, by)
    return fn


def start_issue(store, cid, by, said):
    try:
        return jobs.submit(store, 'issue', issue_job(cid, by), cert_id=cid, by=by, said=said)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# The routes of the portal
# ---------------------------------------------------------------------------
@E.route('GET', '/api/portal/certs')
def _portal_certs(h):
    s = portal_session(h)
    sufs = words_list('portal_cert_suffixes')
    iss = []
    for i in words_list('portal_cert_issuers'):
        row = S.plugin_row(h.store, 'issuer', i)
        if row and row.get('enabled', 1):
            iss.append({'name': row['name'], 'kind': row.get('kind') or ''})
    have = mine(h, s)
    n = used(h.store, owner_word(s))
    return {'rows': have, 'suffixes': sufs, 'issuers': [i['name'] for i in iss],
            'issuer_kinds': {i['name']: i['kind'] for i in iss}, 'formats': formats(),
            'key_types': list(schema.KEY_TYPES), 'most': most(), 'used': n,
            'auto': bool(E.CONFIG.get('portal_cert_auto')),
            'keys': bool(E.CONFIG.get('portal_cert_keys')),
            'groups': [cn for _, cn in my_groups(h, s)][:50],
            # The teams they may ask for a certificate for (Settings → Owners and teams).
            'teams': sorted(n for n, r in my_teams(h, s).values() if 'request' in r),
            'sees_all': E.portal_sees_all(s), 'kind': 'local' if is_local(s) else 'directory',
            'may_request': bool(sufs and iss) and n < most(),
            # The request profiles they may ask from (Settings → Request profiles, 1.0.18).
            'profiles': reqprofiles.usable(h, s), 'free_form': bool(sufs and iss),
            'may_ask': n < most()}


@E.route('GET', '/api/portal/cert_job')
def _portal_job(h):
    s = portal_session(h)
    try:
        job = jobs.job_view(h.store, A._id(h.arg('id')))
    except (LookupError, ValueError):
        raise E.ApiError(404, 'there is no such job')
    if not job.get('cert_id'):
        raise E.ApiError(404, 'there is no such job')
    need_mine(h, s, job['cert_id'])
    # The steps as they are, but never the debug lines (what a module said back in full).
    steps = [st for st in (job.get('steps') or []) if not (
        isinstance(st, (list, tuple)) and len(st) > 1 and st[1] == 'debug')]
    keep = ('id', 'ts', 'kind', 'cert_id', 'state', 'ok', 'finished', 'took_ms', 'said',
            'live', 'cert_name', 'version')
    out = {k: job.get(k) for k in keep}
    out['steps'] = steps[-300:]
    return {'job': out}


@E.route('POST', '/api/portal/cert_download')
def _portal_download(h):
    s = portal_session(h)
    b = h.body()
    row = need_mine(h, s, b.get('id'))
    fmt = str(b.get('format') or 'fullchain-pem')
    if fmt == KEY_FORMAT and row.get('csr_from'):
        raise E.ApiError(400, 'the key of %s was made by a device and stays there - acme never '
                              'had it' % row['name'])
    if fmt == KEY_FORMAT and row.get('csr_given'):
        raise E.ApiError(400, '%s was issued for the CSR you sent: acme never had its key - it '
                              'is where you made the CSR' % row['name'])
    if fmt not in row_formats(h.store, row):
        raise E.ApiError(400, 'the format is one of %s' % ', '.join(row_formats(h.store, row)))
    as_who = {'name': s['name'], 'role': 'readonly'}
    if fmt == KEY_FORMAT:
        pw = str(b.get('password') or '')
        if len(pw) < 8:
            raise E.ApiError(400, 'a PFX file with the key needs a password of at least 8 '
                                  'characters')
        if not row.get('key_sealed'):
            raise E.ApiError(400, 'acme does not hold the key of this certificate')
        names, groups, tms = my_names(s), my_groups(h, s), my_teams(h, s)
        defined = defined_teams(h.store)
        via = owner_of(row, names, groups, tms, defined)
        if not key_may(s, via, rights_of(s, row, names, groups, tms, defined),
                       asker(h.store, row['id']).get('who')):
            h.store.add_event('certificates', '%s was refused on the portal: the key of %s '
                              '(needs the right manage)' % (s['name'], row['name']), 'warn',
                              who=s['name'])
            raise E.ApiError(403, 'only its owner, or a member of its team who may manage '
                                  'it, may take its key')
        # The key, only through this route and only as a PFX with a password:
        # the setting portal_cert_keys says the people may have theirs.
        as_who = {'name': 'portal:%s' % s['name'], 'role': 'fulladmin'}
    try:
        got = A.cert_export(h.store, {'id': row['id'], 'format': fmt,
                                      'password': b.get('password') if fmt == KEY_FORMAT else None},
                            as_who, allowed=row_formats(h.store, row))
    except (ValueError, LookupError) as e:
        raise E.ApiError(400, str(e))
    h.store.add_event('certificates', '%s took %s (%s) from the portal' % (
        s['name'], row['name'], fmt), 'warn' if fmt == KEY_FORMAT else 'info', who=s['name'])
    return got


@E.route('POST', '/api/portal/cert_request')
def _portal_request(h):
    s = portal_session(h)
    b = h.body()
    if str(b.get('profile') or '').strip():
        # From a request profile (1.0.18): everything but the names given beforehand.
        return reqprofiles.request(h, s, b)
    store = h.store
    who = owner_word(s)
    sufs = words_list('portal_cert_suffixes')
    allowed = words_list('portal_cert_issuers')
    if not sufs or not allowed:
        raise E.ApiError(403, 'asking for certificates here is not set up')
    if used(store, who) >= most():
        raise E.ApiError(403, 'you have asked for as many certificates as one person may (%d)'
                         % most())
    try:
        names = S.clean_names(b.get('names'))
    except ValueError as e:
        raise E.ApiError(400, str(e))
    if not names:
        raise E.ApiError(400, 'which names?')
    if len(names) > 50:
        raise E.ApiError(400, 'at most 50 names in one certificate')
    bad = [n for n in names if not name_allowed(n, sufs)]
    if bad:
        raise E.ApiError(403, 'not under the names you may ask for (%s): %s' % (
            ', '.join(sufs), ', '.join(bad)))
    issuer = str(b.get('issuer') or (allowed[0] if len(allowed) == 1 else '')).strip()
    irow = S.plugin_row(store, 'issuer', issuer) if issuer in allowed else None
    if not irow or not irow.get('enabled', 1):
        raise E.ApiError(400, 'the issuer is one of %s' % ', '.join(allowed))
    kt = str(b.get('key_type') or 'ec-256')
    if kt not in schema.KEY_TYPES:
        raise E.ApiError(400, 'the key type is one of %s' % ', '.join(schema.KEY_TYPES))
    # What fits (acmelib/certs/compat.py): the names, the source, the validation, the key.
    from acmelib.certs import compat
    probs = compat.check(store, names, irow, str(E.CONFIG.get('portal_cert_challenge') or '')
                         or None, {}, kt, '')
    if probs:
        raise E.ApiError(400, compat.words(probs))
    # Owned by a team they may ask for (its right `request`), or by them as before.
    owner = who
    if str(b.get('team') or '').strip():
        tm = my_teams(h, s).get(str(b['team']).strip().lower())
        if not tm or 'request' not in tm[1]:
            store.add_event('certificates', '%s was refused on the portal: a certificate for '
                            'the team %s (needs the right request)' % (who, b['team']), 'warn',
                            who=who)
            raise E.ApiError(403, 'you may not ask for certificates of the team %s' % b['team'])
        owner = tm[0]
    # A wildcard waits for an administrator whatever portal_cert_auto says (1.0.45): issued at
    # once, with its key to take, it covered every host under the name.
    held = holders(store, names, owner, unowned=True)
    auto = bool(E.CONFIG.get('portal_cert_auto')) and not any(n.startswith('*.') for n in names) \
        and not held
    # a name the rules take (1.0.79: "_svc.example.test" stayed as it was, and every save of the
    # certificate by an administrator was refused until it was renamed)
    base_name = S.safe_name(names[0].replace('*.', 'wildcard.'), most=80)
    name = base_name
    n = 1
    while store.db.row('SELECT id FROM certs WHERE name = ?', (name,)):
        n += 1
        name = '%s-%d' % (base_name, n)
    t = time.time()
    note = str(b.get('note') or '').strip()[:500]
    row_new = {
        'name': name, 'cn': names[0], 'names': json.dumps(names), 'key_type': kt,
        'issuer': irow['name'], 'challenge': str(E.CONFIG.get('portal_cert_challenge') or '')[:190],
        'challenge_map': '{}', 'auto_renew': 1 if auto else 0, 'renew_days': None,
        'reuse_key': 0, 'profile': '{}', 'source': 'portal',
        'state': 'new' if auto else WAITING, 'state_at': t, 'version': 0,
        'fails': 0, 'tags': json.dumps(['portal']),
        'note': ('asked for on the portal by %s. %s' % (who, note)).strip(), 'owner': owner[:190],
        'created': t, 'created_by': 'portal:' + who[:180], 'enabled': 1, 'ari': '{}'}
    # Two asks at once (1.0.45): the name another took meanwhile is taken next (it was a 500),
    # and the person's limit counted again once the row is in (both had passed it).
    cid = None
    for _ in range(50):
        try:
            cid = store.db.insert('certs', dict(row_new, name=name))
            break
        except Exception as e:                          # noqa: BLE001
            if not re.search(r'unique|duplicate', str(e), re.I):
                raise
            n += 1
            name = '%s-%d' % (base_name, n)
    if cid is None:
        raise E.ApiError(409, 'no free name for the certificate - try again')
    if used(store, who) > most():
        store.db.run('DELETE FROM certs WHERE id = ?', (cid,))
        raise E.ApiError(403, 'you have asked for as many certificates as one person may (%d)'
                         % most())
    data = s.get('data') or {}
    # why it waits, kept with it (1.0.102): who holds which of its names - they approve it
    held_now = holders(store, names, owner, cid, waiting=False)
    store.set_meta(META + str(cid), json.dumps({
        'who': who, 'display': data.get('display') or '', 'mail': data.get('mail') or '',
        'at': t, 'note': note, 'held': held_list(held_now), 'ids': asker_ids(s),
        # it needs an approval (1.0.106): issued, imported into or given a CSR only once
        # approved (S.unapproved_why) - `approved` set by approve_request
        'waits': not auto}))
    job_id = None
    if not auto and held_now:
        tell_holders(store, cid, held_now, who)
    if auto:
        store.add_event('certificates', '%s asked on the portal for %s (%s) from %s - issued '
                        'without approval' % (who, name, ', '.join(names), irow['name']), who=who)
        job_id = start_issue(store, cid, 'portal:' + who, 'asked for on the portal')
    else:
        store.add_event('certificates', '%s asked on the portal for %s (%s) from %s - it waits '
                        'for an administrator\'s approval' % (who, name, ', '.join(names),
                                                              irow['name']), 'warn', who=who)
    return {'id': cid, 'name': name, 'job_id': job_id,
            'state': 'new' if auto else WAITING, 'waits': not auto}


# ---------------------------------------------------------------------------
# What a team's rights give on the portal (1.0.16): manage - renew, renewed by
# itself or not, revoke; approve - the team's requests approved or declined.
# ---------------------------------------------------------------------------
def portal_by(s):
    return 'portal:%s' % s['name']


@E.route('POST', '/api/portal/cert_renew')
def _portal_renew(h):
    s = portal_session(h)
    row = need_right(h, s, h.body().get('id'), 'manage', 'renewing')
    if row.get('state') in (WAITING, DECLINED):
        raise E.ApiError(409, '%s has not been approved' % row['name'])
    try:
        job_id = A.start_renew(h.store, row['id'], False, portal_by(s))
    except (ValueError, LookupError) as e:
        raise E.ApiError(400, str(e))
    h.store.add_event('certificates', '%s renews %s from the portal' % (s['name'], row['name']),
                      who=s['name'])
    return {'job_id': job_id}


@E.route('POST', '/api/portal/cert_auto')
def _portal_auto(h):
    s = portal_session(h)
    b = h.body()
    row = need_right(h, s, b.get('id'), 'manage', 'switching renewing for')
    try:
        return A.cert_auto(h.store, row['id'], A._flag(b.get('auto_renew'), 1), portal_by(s))
    except (ValueError, LookupError) as e:
        raise E.ApiError(400, str(e))


@E.route('POST', '/api/portal/cert_revoke')
def _portal_revoke(h):
    s = portal_session(h)
    b = h.body()
    row = need_right(h, s, b.get('id'), 'manage', 'revoking')
    if not row.get('cert_pem') or (row.get('state') == 'revoked' and
                                   row.get('alt_state') != 'revoke-failed'):
        raise E.ApiError(409, '%s is not a certificate that can be revoked' % row['name'])
    reason = str(b.get('reason') or 'unspecified')
    if reason not in A.REVOKE_REASONS:
        raise E.ApiError(400, 'the reason is one of %s' % ', '.join(A.REVOKE_REASONS))
    by = portal_by(s)
    again = A._flag(b.get('renew'), 0)
    if again and row.get('csr_given'):
        # Refused before anything is revoked (1.0.19): revoked, it then could not be issued
        # again with the same CSR - and was left renewed by itself, revoked.
        raise E.ApiError(400, '%s was issued for the CSR you sent: a new one needs a new CSR '
                              '(a new key) - revoke it without one, then send it'
                         % row['name'])

    def fn(job):
        got = renewer.revoke_cert(job.store, job, row['id'], reason, by)
        if not again:
            return got
        # Not renewed over a revocation not done in full (1.0.79: the twin not revoked was
        # replaced and forgotten - its compromised key still valid at the CA)
        if isinstance(got, tuple) and got and got[0] is False:
            return got
        job.step('issuing a new one in its place')
        job.store.db.update('certs', row['id'], {'auto_renew': 1})
        return renewer.renew_cert(job.store, job, row['id'], True, by)
    try:
        job_id = jobs.submit(h.store, 'revoke', fn, cert_id=row['id'], by=by,
                             said='reason: %s%s, from the portal' % (
                                 reason, ', a new one at once' if again else ''))
    except ValueError as e:
        raise E.ApiError(409, str(e))
    h.store.add_event('certificates', '%s revokes %s from the portal (%s)' % (
        s['name'], row['name'], reason), 'warn', who=s['name'])
    return {'job_id': job_id}


@E.route('POST', '/api/portal/cert_approve')
def _portal_approve(h):
    s = portal_session(h)
    b = h.body()
    row = need_right(h, s, b.get('id'), 'approve', 'approving')
    # Never one's own (1.0.51): a member with "manage" asked for a wildcard (which always waits
    # for approval) and approved it himself - and took its key. Declining one's own is fine.
    # ...nor one they sent a new CSR or names for (1.0.102): a member who may manage sent his
    # own CSR with other names for another's request, and approved it himself.
    ok = A._flag(b.get('ok'))
    if ok and askers_of(h.store, row['id']) & set(asker_ids(s)):
        raise E.ApiError(403, 'you asked for it yourself, or sent its CSR or names - someone else '
                              'approves it')
    if ok and (row.get('state') == WAITING or approval_missing(h.store, row)) and \
            not E.portal_sees_all(s):
        may_owner = portal_may_owner(my_names(s), my_teams(h, s), defined_teams(h.store))
        need_held_ok(h.store, row, may_owner, s['name'])
    return approve_request(h.store, row, portal_by(s), A._flag(b.get('ok')),
                           str(b.get('why') or '').strip()[:500])


# ---------------------------------------------------------------------------
# The administrators' side: approving or declining
# ---------------------------------------------------------------------------
@A.api('POST', '/api/certs/approve', 'certadmin')
def _cert_approve(h, s):
    b = h.body()
    row = S.cert_need(h.store, A._id(b.get('id')))
    ok = A._flag(b.get('ok'))
    if ok and (row.get('state') == WAITING or approval_missing(h.store, row)):
        # Never one's own here either (1.0.102: a certificate administrator who also signs in
        # to the portal asked, approved it here, and took its key there) - a full administrator
        # included: one who needs a certificate adds it in the administration.
        if asked_by_admin(h.store, row, s):
            h.store.add_event('certificates', '%s was refused: approving %s, asked for by '
                              'themselves' % (A.who(s), row['name']), 'warn', who=A.who(s))
            raise E.ApiError(403, 'you asked for it yourself, or gave it its CSR or names - have '
                                  'another administrator approve or decline it (a full '
                                  'administrator who needs a certificate adds it here: Add a '
                                  'certificate)')
        if not (s.get('role') == 'fulladmin' or s.get('cli')):
            from acmelib.certs import teams as T
            need_held_ok(h.store, row, lambda o: T.cert_may(h.store, s, {'owner': o}, 'approve')
                         or T.cert_may(h.store, s, {'owner': o}, 'manage'), A.who(s))
    return approve_request(h.store, row, A.who(s), ok, str(b.get('why') or '').strip()[:500])


def _bare(n):
    """A directory name without its domain: DOMAIN\\name -> name."""
    return str(n or '').strip().lower().split('\\')[-1]


def _sam_like(n):
    """Whether a name is a sAMAccountName (name or DOMAIN\\name): not a UPN or a mail
    (name@domain), not a DN, not an account of acme's own (local:)."""
    n = str(n or '')
    return bool(n) and '@' not in n and '=' not in n and not n.startswith('local:')


def admin_names(s):
    """The names a session of the administration asks for certificates under on the portal
    (lower case): local:NAME of an account of acme's own only; of the directory, its name, the
    name without its domain (a sAMAccountName's only), its DN and mail - matched against every
    name an asker is known by (asker_ids: the portal's UPN, sAMAccountName and DN)."""
    acc = s.get('account') or {}
    name = str(s.get('name') or '').strip().lower()
    if acc.get('source') != 'directory':
        return {'local:' + name} if name else set()
    out = {name}
    if _sam_like(name):
        out.add(_bare(name))
    for k in ('mail', 'dn'):
        if acc.get(k):
            out.add(str(acc[k]).strip().lower())
    out.discard('')
    return out


def asked_by_admin(store, row, s):
    """Whether this session of the administration asked for the request on the portal, or
    sent its CSR or names (1.0.102). An account of acme's own is matched by local:NAME only, one
    of the directory never by a local: name; a UPN, DN or mail only as it is - a name without
    its domain only for a sAMAccountName against a sAMAccountName (jan@corp is not
    jan@partner, nor CORP\\jan's mail jan@gmail)."""
    acc = s.get('account') or {}
    mine = admin_names(s)
    who = askers_of(store, row['id'])
    if acc.get('source') != 'directory':
        return bool({w for w in who if w.startswith('local:')} & mine)
    who = {w for w in who if not w.startswith('local:')}
    if who & mine:
        return True
    sams = {_bare(n) for n in mine if _sam_like(n)}
    if sams and {_bare(w) for w in who if _sam_like(w)} & sams:
        return True
    mail = str(acc.get('mail') or '').strip().lower()
    return bool(mail and str(asker(store, row['id']).get('mail') or '').strip().lower() == mail)


def mark_waiting(store, cid):
    """The request needs an approval (again): never issued, imported into or given a CSR
    until approve_request marks it approved (1.0.106, S.unapproved_why)."""
    def change(a):
        a['waits'] = True
        a.pop('approved', None)
    asker_change(store, cid, change)


def mark_approved(store, cid, by, t=None):
    def change(a):
        a['approved'] = {'by': str(by)[:190], 'at': t or time.time()}
    asker_change(store, cid, change)


def mark_declined(store, cid):
    """Declined: `approved` written false (1.0.106) - never taken for an approval, whatever
    reads the meta."""
    def change(a):
        a['waits'] = True
        a['approved'] = False
    asker_change(store, cid, change)


def approval_missing(store, row):
    """A request let out of the waiting state whose approval was never noted (1.0.106: the
    state changed and `approved` written in two steps - a stop between them, or a CSR sent at
    the same moment, left it 'new' or 'ok', "never approved", and Approve said it did not
    wait): Approve takes it as a repair, Decline declines it. One declined (`approved` false)
    is none, whatever its state became since."""
    if row.get('state') in (WAITING, DECLINED) or \
            not str(row.get('created_by') or '').startswith('portal:'):
        return False
    a = asker(store, row['id'])
    return bool(a.get('waits') and a.get('approved') is None)


def approve_request(store, row, by, ok, why):
    if ok and approval_missing(store, row):
        t = time.time()
        mark_approved(store, row['id'], by, t)
        store.add_event('certificates', '%s approved %s, asked for on the portal by %s - out of '
                        'the waiting state already, its approval had not been noted%s' % (
                            by, row['name'], row.get('owner') or '?',
                            (': ' + why) if why else ''), who=by)
        job_id = None
        if row.get('state') == 'new':
            job_id = start_issue(store, row['id'], by, 'approved by %s' % by)
        tell(store, row['id'], 'approved', why)
        out = {'message': '%s approved' % row['name']}
        if job_id:
            out.update(job_id=job_id, message='%s approved - it is being issued' % row['name'])
        return out
    # A stuck one declined as well (1.0.106): never approved and never issued, out of the
    # waiting state - Decline said it did not wait, and it could only be approved. One with
    # a certificate issued is revoked instead, not declined.
    stuck = not ok and not row.get('cert_pem') and approval_missing(store, row)
    from_state = row.get('state') if stuck else WAITING
    if row.get('state') != from_state:
        raise E.ApiError(409, '%s is not waiting for approval' % row['name'])
    t = time.time()
    if ok:
        # Renewed by itself after it is approved - unless its request profile says not.
        auto = 0 if asker(store, row['id']).get('auto') is False else 1
        # taken from the waiting state in one step (1.0.51): an approve and a decline at once
        # both passed the look above - issued while declined, both mails sent. Its approval
        # noted in the same transaction (1.0.106): written after it, a stop between the two
        # left a request 'new' that was "never approved" - never issued, never approved again.
        with store.db.transaction():
            n = store.db.run("UPDATE certs SET state = 'new', state_at = ?, auto_renew = ?, "
                             "last_error = '', updated = ?, updated_by = ? WHERE id = ? AND "
                             "state = ?", (t, auto, t, str(by)[:190], row['id'], WAITING))
            if n:
                mark_approved(store, row['id'], by, t)
        if not n:
            raise E.ApiError(409, '%s is not waiting for approval' % row['name'])
        store.add_event('certificates', '%s approved %s, asked for on the portal by %s%s' % (
            by, row['name'], row.get('owner') or '?', (': ' + why) if why else ''), who=by)
        job_id = start_issue(store, row['id'], by, 'approved by %s' % by)
        tell(store, row['id'], 'approved', why)
        return {'job_id': job_id, 'message': '%s approved - it is being issued' % row['name']}
    if not why:
        raise E.ApiError(400, 'say why it is declined - the person who asked is told')
    # Taken from the state it was read in, its meta noted declined (`approved` false) in the
    # same transaction (1.0.106).
    with store.db.transaction():
        n = store.db.run("UPDATE certs SET state = ?, state_at = ?, auto_renew = 0, "
                         "last_error = ?, updated = ?, updated_by = ? WHERE id = ? AND state = ?",
                         (DECLINED, t, why, t, str(by)[:190], row['id'], from_state))
        if n:
            mark_declined(store, row['id'])
    if not n:
        raise E.ApiError(409, '%s is not waiting for approval' % row['name'])
    store.add_event('certificates', '%s declined %s, asked for on the portal by %s: %s' % (
        by, row['name'], row.get('owner') or '?', why), 'warn', who=by)
    tell(store, row['id'], 'declined', why)
    who_ = str(row.get('owner') or '')
    who_ = who_[6:] if who_.startswith('local:') else who_      # a person's name (1.0.88)
    return {'message': '%s declined - %s is told' % (row['name'], who_ or 'nobody')}
