# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the enrolment pages: a sign-in of their own, for people who are no administrators -----
# What is here is the plumbing a page for people (a certificate portal: ask for
# one, fetch yours) stands on, and nothing of what such a page does:
#
#   POST /api/portal/login {name, password}   signed in against the directory
#        (Settings - The enrolment pages: which one, and who may), counted and
#        paused as the administrators' sign-in is → {token, name}
#        - with portal_local, an account of acme's own (Accounts) first: its
#        password, its second step (→ {mfa: 'check'|'enrol'}, given through
#        GET/POST /api/portal/mfa as the administration's /api/auth/mfa)
#   POST /api/portal/logout                   the sign-in ended
#   GET  /api/portal/me                       who is signed in: {me: {name, display, about,
#        ...}} - and whatever each function of PORTAL_ME adds
#   GET  /api/portal/info                     what the sign-in page shows (anybody)
#   GET  /api/portal/logo, /api/portal/art    the pictures of the two sign-ins
#
# A route of a module asks portal_me(h) for the session (401 without one, 403
# once the pages are switched off) and keeps what it needs between two
# requests with portal_data_set(h, s, key=value). The session is a row of
# `sessions` of kind 'portal': the same on both nodes of a cluster. Its data
# says {kind: 'directory'|'local', role}: the role of an account of acme's
# own, read again at every request ('' for the directory's people).
PORTAL_ME = []          # fn(h, s) -> {key: value} added to GET /api/portal/me


def portal_me(h):
    s = h.session('portal')
    if not s:
        raise ApiError(401, 'not signed in, or the sign-in has run out')
    # Switched off while somebody was signed in, it is off for them too (1.0.33).
    if not CONFIG.get('portal'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(403, 'these pages are switched off')
    if portal_mfa_pending(s):
        raise ApiError(401, 'the second step of signing in is not done yet')
    if not portal_local_ok(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'that account may no longer sign in here')
    if not portal_dir_still(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'that account may no longer sign in here')
    if portal_must_change(s):
        raise ApiError(403, 'change the password first')
    return s


PORTAL_DIR_CHECK_S = 600


def portal_dir_still(h, s):
    """A person of the directory, asked about again every ten minutes (1.0.19),
    as the administration asks about its own: switched off there, gone, or no
    longer in the groups that let them in here, and the sign-in ends - not when
    it runs out. A directory that cannot be reached leaves them as they are."""
    data = s.get('data') if isinstance(s.get('data'), dict) else {}
    if data.get('kind') == 'local' or not data.get('dn'):
        return True
    t = time.time()
    if t - float(data.get('dir_checked') or 0) < PORTAL_DIR_CHECK_S:
        return True
    ad = portal_directory(h)
    if not ad:
        return False
    try:
        who, how = admin_name_parts(str(data.get('login') or s['name']))
        entry = ad.find_user(who, how)
        ok = bool(entry and not entry.get('many') and not entry_unusable(entry, locked=False)
                  and str(entry.get('dn') or '').lower() == str(data['dn']).lower())
        if ok and (CONFIG.get('portal_who') or 'anyone') == 'groups':
            wanted = [{'group': g} for g in dn_list(CONFIG.get('portal_groups'))]
            if CONFIG.get('portal_enrolers', 1):
                wanted += [{'group': g} for g in dn_list(CONFIG.get('admin_group_portal'))]
            have = ad.groups_of(entry, True)
            ok = any(group_matches([w], have, ad) for w in wanted)
    except Exception as e:                              # noqa: BLE001
        log('the enrolment pages could not ask the directory about %s: %s' % (s['name'], e),
            'warn')
        try:
            portal_data_set(h, s, dir_checked=t - PORTAL_DIR_CHECK_S + 60)
        except Exception:                               # noqa: BLE001
            pass
        return True
    if not ok:
        h.store.add_event('portal', 'the directory no longer lets %s use the enrolment pages: '
                          'signed out' % s['name'], 'warn', who=s['name'])
        return False
    try:
        portal_data_set(h, s, dir_checked=t)
    except Exception:                                   # noqa: BLE001
        pass
    return True


def portal_mfa_pending(s):
    """The second step of an account of acme's own, still to be given."""
    data = s.get('data') or {}
    return str(data.get('mfa') or '') if data.get('kind') == 'local' and \
        CONFIG.get('admin_2fa') else ''


def portal_local_ok(h, s):
    """A sign-in of an account of acme's own still good: portal_local still on,
    the account there, not switched off - its role as it is now put in the
    session (taken away or changed in Accounts, it counts at once)."""
    data = s.get('data') if isinstance(s.get('data'), dict) else {}
    if data.get('kind') != 'local':
        return True
    acc = h.store.account(s['name'])
    if not acc or acc.get('disabled') or acc.get('source') == 'directory':
        return False
    if not portal_local_may(acc):
        return False
    data['role'] = acc.get('role') or 'readonly'
    s['data'] = data
    return True


def portal_local_may(acc):
    """Whether an account of acme's own may sign in on these pages: one of
    the role of the enrolment pages only with portal_enrolers (1.0.14), any
    other with portal_local."""
    if (acc.get('role') or '') == 'portal':
        return bool(CONFIG.get('portal_enrolers', 1))
    return bool(CONFIG.get('portal_local'))


def portal_must_change(s):
    """An account of acme's own whose password is to be changed first
    (1.0.14): until it is, the sign-in can do nothing else."""
    data = s.get('data') or {}
    return bool(data.get('kind') == 'local' and data.get('must_change'))


def portal_sees_all(s):
    """Whether this sign-in sees every certificate (portal_admins_all): an
    account of acme's own with the role of a certificate or full
    administrator."""
    data = s.get('data') or {}
    return bool(data.get('kind') == 'local' and CONFIG.get('portal_admins_all', 1)
                and data.get('role') in ('certadmin', 'fulladmin'))


# The pictures of the two sign-ins (1.0.71; each its own since 1.0.72):
# which one ({art, sha}) and a picture of the site's own (JSON with base64).
ART_SLOTS = {'portal': ('portal:art', 'portal:logo', 'cert'),
             'admin': ('admin:art', 'admin:logo', 'deploy')}
LOGO_META = 'portal:logo'
LOGO_MAX = 512 * 1024
# The drawings the pages have; a name saved by an older version (phone,
# and others no longer drawn) is shown as the slot's own drawing.
ART_NAMES = ('cert', 'chain', 'renew', 'deploy', 'none', 'custom')


def art_slot(slot):
    if slot not in ART_SLOTS:
        raise ApiError(400, 'portal or admin')
    return ART_SLOTS[slot]


def logo_kind(raw):
    """What sort of picture the bytes are, by their first bytes - never by
    the name they came with."""
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if raw.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if raw[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'image/webp'
    head = raw[:4096].lstrip(b'\xef\xbb\xbf \t\r\n').lower()
    if (head.startswith(b'<svg') or head.startswith(b'<?xml') or head.startswith(b'<!--')
            or head.startswith(b'<!doctype svg')) and b'<svg' in raw[:65536].lower():
        return 'image/svg+xml'
    return None


def logo_check(raw):
    if not raw:
        raise ValueError('the file is empty')
    if len(raw) > LOGO_MAX:
        raise ValueError('the picture is %s - at most 512 KB' % bytes_words(len(raw)))
    kind = logo_kind(raw)
    if not kind:
        raise ValueError('that is not a picture this takes: PNG, JPEG, GIF, WebP or SVG')
    if kind == 'image/svg+xml':
        # Shown only as an <img> and sent with a policy that runs nothing,
        # but an SVG with a script or a link out is turned away all the same.
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('the SVG is not UTF-8 text')
        low = text.lower()
        if (re.search(r'<\s*(script|foreignobject|iframe|embed|object)\b', low)
                or re.search(r'\son[a-z]+\s*=', low) or 'javascript:' in low
                or '<!entity' in low
                or re.search(r'(href|src)\s*=\s*["\']\s*(https?:|//|data:text)', low)):
            raise ValueError('the SVG holds a script, an event handler or a link out - '
                             'save it as a plain picture (or as PNG) and again')
    return kind


def _art_meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or 'null')
    except Exception:
        return None
    return got if isinstance(got, dict) else None


def logo_read(store, slot='portal'):
    _, lk, _ = art_slot(slot)
    got = _art_meta(store, lk)
    if not got and slot == 'admin' and _admin_as_1071(store):
        got = _art_meta(store, ART_SLOTS['portal'][1])
    return got if got and got.get('b64') else None


def _admin_as_1071(store):
    """1.0.71 had one picture, put on the administration's sign-in too with
    'admin': true - read so until the administration's own is picked."""
    return store.get_meta(ART_SLOTS['admin'][0]) is None and bool(
        (_art_meta(store, ART_SLOTS['portal'][0]) or {}).get('admin'))


def art_read(store, slot='portal'):
    """Which picture a sign-in shows - a few bytes, read by every page."""
    ak, _, default = art_slot(slot)
    got = _art_meta(store, ak)
    if got is None and slot == 'admin' and _admin_as_1071(store):
        got = _art_meta(store, ART_SLOTS['portal'][0])
    got = got or {}
    art = got.get('art') if got.get('art') in ART_NAMES else default
    return {'art': art, 'sha': str(got.get('sha') or '') if art == 'custom' else ''}


def art_set(store, slot, art):
    ak, _, _ = art_slot(slot)
    one = {'art': art, 'sha': ''}
    if art == 'custom':
        logo = logo_read(store, slot)
        if not logo:
            raise ValueError('there is no picture of your own yet - upload one first')
        one['sha'] = logo.get('sha') or ''
        if slot == 'admin' and not _art_meta(store, ART_SLOTS['admin'][1]):
            store.set_meta(ART_SLOTS['admin'][1], json.dumps(logo))  # 1.0.71's, its own now
    store.set_meta(ak, json.dumps(one))
    return one


def logo_set(store, slot, raw, by, name=''):
    """A picture of the site's own, kept in the database - so it is the same
    on both nodes of a cluster, in every backup and in the configuration
    file. b'' takes it away (and the drawing that page came with is shown)."""
    _, lk, default = art_slot(slot)
    if not raw:
        if slot == 'admin' and _admin_as_1071(store):
            store.set_meta(ART_SLOTS['admin'][0], json.dumps(art_read(store, 'admin')))
        store.set_meta(lk, '')
        if art_read(store, slot)['art'] == 'custom':
            art_set(store, slot, default)
        return None
    kind = logo_check(raw)
    one = {'type': kind, 'b64': base64.b64encode(raw).decode('ascii'),
           'sha': hashlib.sha256(raw).hexdigest()[:16], 'bytes': len(raw),
           'name': str(name or '')[:120], 'at': time.time(), 'by': by}
    store.set_meta(lk, json.dumps(one))
    return one


def art_state(store, slot):
    logo = logo_read(store, slot)
    return dict(art_read(store, slot), default=ART_SLOTS[slot][2],
                logo={k: logo.get(k) for k in ('type', 'sha', 'bytes', 'name', 'at', 'by')}
                if logo else None)


@route('GET', '/api/portal/logo')
def _portal_logo(h):
    # Anybody: it is the picture on a sign-in. Only the picture.
    one = logo_read(h.store, 'admin' if h.arg('slot') == 'admin' else 'portal')
    if not one:
        return {'logo': None}
    return {'logo': {'type': one.get('type'), 'b64': one.get('b64'), 'sha': one.get('sha')}}


@route('GET', '/api/portal/art')
def _portal_art(h):
    h.me()
    return {'names': list(ART_NAMES), 'portal': art_state(h.store, 'portal'),
            'admin': art_state(h.store, 'admin')}


@route('POST', '/api/portal/art')
def _portal_art_set(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    slot = str(b.get('slot') or 'portal')
    art_slot(slot)
    where = {'portal': 'the enrolment pages', 'admin': 'the administration'}[slot]
    who = s['name']
    try:
        if act == 'pick':
            art = str(b.get('art') or '')
            if art not in ART_NAMES:
                raise ApiError(400, 'no such picture: %s' % art)
            art_set(h.store, slot, art)
            h.store.add_event('settings', '%s picked the picture of the sign-in of %s: %s'
                              % (who, where, art), who=who)
        elif act == 'reset':
            art_set(h.store, slot, ART_SLOTS[slot][2])
            h.store.add_event('settings', '%s put the picture of the sign-in of %s back to '
                              'the one it came with' % (who, where), who=who)
        elif act == 'upload':
            data = str(b.get('data') or '')
            if data.startswith('data:'):
                data = data.split(',', 1)[-1]
            try:
                raw = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                raise ApiError(400, 'the picture did not arrive whole')
            if not raw:
                # Nothing is not a picture (1.0.94): it took the one there away.
                raise ApiError(400, 'no picture arrived')
            one = logo_set(h.store, slot, raw, who, str(b.get('name') or ''))
            art_set(h.store, slot, 'custom')
            h.store.add_event('settings', '%s put a picture of their own on the sign-in of %s '
                              '(%s, %s)' % (who, where,
                                           one['type'].split('/')[1].split('+')[0].upper(),
                                           bytes_words(one['bytes'])), who=who)
        elif act == 'save':
            # All of one sign-in's changes at once, as the save bar sends
            # them (1.0.73): a picture of your own taken away or uploaded,
            # then which picture is shown.
            art = str(b.get('art') or '')
            if art not in ART_NAMES:
                raise ApiError(400, 'no such picture: %s' % art)
            raw = None
            if b.get('data'):
                data = str(b.get('data'))
                if data.startswith('data:'):
                    data = data.split(',', 1)[-1]
                try:
                    raw = base64.b64decode(data, validate=True)
                except (binascii.Error, ValueError):
                    raise ApiError(400, 'the picture did not arrive whole')
                logo_check(raw)
            if b.get('forget') and not raw:
                logo_set(h.store, slot, b'', who)
                h.store.add_event('settings', '%s took away the picture of their own of the '
                                  'sign-in of %s' % (who, where), who=who)
            if raw:
                one = logo_set(h.store, slot, raw, who, str(b.get('name') or ''))
                h.store.add_event('settings', '%s put a picture of their own on the sign-in of '
                                  '%s (%s, %s)' % (who, where,
                                                  one['type'].split('/')[1].split('+')[0].upper(),
                                                  bytes_words(one['bytes'])), who=who)
            if art_read(h.store, slot)['art'] != art or raw:
                art_set(h.store, slot, art)
                h.store.add_event('settings', '%s picked the picture of the sign-in of %s: %s'
                                  % (who, where, art), who=who)
        elif act == 'forget':
            logo_set(h.store, slot, b'', who)
            h.store.add_event('settings', '%s took away the picture of their own of the '
                              'sign-in of %s' % (who, where), who=who)
        else:
            raise ApiError(400, 'save, pick, upload, forget or reset')
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'names': list(ART_NAMES), 'portal': art_state(h.store, 'portal'),
            'admin': art_state(h.store, 'admin'), 'message': 'saved - every node shows it'}


@route('GET', '/api/portal/info')
def _portal_info(h):
    return {'on': bool(CONFIG.get('portal')), 'title': CONFIG.get('portal_title') or '',
            'art': art_read(h.store, 'portal'), 'admin_art': art_read(h.store, 'admin'),
            'hint': CONFIG.get('portal_hint') or '', 'help': CONFIG.get('portal_help') or '',
            'lang': CONFIG.get('ui_lang') or 'cs',
            'site': CONFIG.get('site_name') or short_host()}


def portal_directory(h):
    """The directory people sign in against on these pages: the one named
    for them, else the one administrators sign in against - None when there
    is none (or it is switched off)."""
    name = str(CONFIG.get('portal_directory') or CONFIG.get('admin_directory') or '').strip()
    return h.d.dirs.get(name.lower()) if name else None


@route('POST', '/api/portal/login')
def _portal_login(h):
    if not CONFIG.get('portal'):
        raise ApiError(403, 'these pages are switched off')
    b = h.body()
    # No account has a longer name (1.0.19, as the administration's since 1.0.146):
    # megabytes typed went into the log and to the directory.
    name = str(b.get('name') or '').strip()[:190]
    password = str(b.get('password') or '')
    key = h.throttle('portal', split_limit('portal_tries', 5),
                     int(CONFIG.get('portal_wait_min') or 15), name=name)
    if name and name_letters_problem(name):
        # Letters with accents or of another language, switched off (1.0.154): said plainly -
        # it is no password that is wrong.
        h.failed(key)
        raise ApiError(400, 'that name has letters this server does not take (accents or '
                            'another language) - ask the administrator')
    local = bool(CONFIG.get('portal_local')) or bool(
        CONFIG.get('portal_enrolers', 1) and h.store.db.row(
            "SELECT 1 FROM accounts WHERE role = 'portal' AND source <> 'directory'"))
    local_wrong = False
    if local and name and password:
        # acme's own accounts first (portal_local; those of the enrolment pages
        # only with portal_enrolers): the name as it is written in Accounts,
        # its password as the administration checks it.
        acc = h.store.account(name)
        if acc and acc.get('source') != 'directory' and portal_local_may(acc):
            if acc.get('pw') and password_ok(password, acc['pw']):
                return portal_local_login(h, key, name, acc)
            local_wrong = True
            h.store.add_event('sign-ins', 'a wrong password for %s (an account here) on the '
                              'enrolment pages from %s' % (name, h.client_ip()), 'warn')
        else:
            # As long as for a name that is there: how long the answer took
            # told which names exist.
            password_ok(password, DUMMY_PW_HASH)
    ad = portal_directory(h)
    if not ad and not local:
        # Nobody can sign in yet - and the one trying is most likely the
        # administrator who has just installed this, at the wrong door.
        raise ApiError(503, 'nobody can sign in here yet: no directory is set up for these '
                            'pages. Administrators sign in at /admin/')
    if not name or not password or not ad:
        h.failed(key)
        raise ApiError(401, 'the name or the password is not right')
    bare, how = admin_name_parts(name)
    held = ''
    try:
        entry = ad.find_user(bare, how)
        if not entry or entry.get('many') or entry_unusable(entry):
            # Counted as a wrong password of a name that exists is (as otp 1.0.234): the
            # cap of wrong directory passwords per person holds back a name the directory
            # lacks the same way, so the answer does not tell which names exist.
            dir_pw_done(h, dir_pw_take(h, bare, ad.name, entry if entry and not entry.get('many')
                                       else None), True)
        if not entry:
            raise LdapError('there is no such account')
        if entry.get('many'):
            # More than one account answers to the name (1.0.205): which one
            # signed in could not be said.
            raise LdapError('more than one account answers to that name')
        if entry_unusable(entry):
            raise LdapError('the account may not sign in: %s' % entry_unusable(entry))
        held = dir_pw_take(h, bare, ad.name, entry)  # the cap per account (as otp 1.0.230)
        ad.password_ok(entry, password)
    except LdapUnreachable as e:
        dir_pw_done(h, held, False)
        log('the enrolment pages could not reach the directory: %s' % e, 'warn')
        if local_wrong:
            # The password of an account here was wrong, and counts as one (1.0.19):
            # with the directory down every guess was given back, without end.
            h.failed(key)
        raise ApiError(503, 'the directory cannot be reached just now')
    except LdapError as e:
        dir_pw_done(h, held, not isinstance(e, LdapNotAsked))   # never asked: not counted
        h.failed(key)
        h.store.add_event('portal', '%s could not sign in to the enrolment pages from %s: %s'
                          % (name, h.client_ip(), e), 'warn', who=name)
        raise ApiError(401, 'the name or the password is not right')
    dir_pw_done(h, held, False)
    let_in = []
    if (CONFIG.get('portal_who') or 'anyone') == 'groups':
        wanted = [{'group': g} for g in dn_list(CONFIG.get('portal_groups'))]
        if CONFIG.get('portal_enrolers', 1):
            # The directory's group of the enrolment pages only (1.0.14) lets
            # its members in too, whatever the groups above say.
            wanted += [{'group': g} for g in dn_list(CONFIG.get('admin_group_portal'))]
        have = ad.groups_of(entry, True)
        for w in wanted:
            try:
                if group_matches([w], have, ad):
                    let_in.append(cn_of(w['group']) or w['group'])
            except Exception:                           # noqa: BLE001
                pass
        if not let_in:
            h.store.add_event('portal', '%s may not use the enrolment pages: in none of the '
                              'groups (%s)' % (name, ', '.join(
                                  cn_of(w['group']) or w['group'] for w in wanted[:6])),
                              'warn', who=name)
            # Counted as a wrong password is (1.0.101): the answer tells that
            # the password was right, so guessing it this way meets the same
            # limit.
            h.failed(key)
            raise ApiError(403, 'this account may not use these pages - ask the administrator')
    who = str(entry.get('upn') or entry.get('sam') or name).strip().lower()
    token = h.store.session_new('portal', who, 'portal', h.client_ip(),
                                max(1, int(CONFIG.get('portal_session_min') or 15)) / 60.0 * 4,
                                {'display': entry.get('display') or '', 'dn': entry['dn'],
                                 'kind': 'directory', 'role': '', 'dir_checked': time.time(),
                                 'login': name, 'mail': entry.get('mail') or '',
                                 'mobile': entry.get('mobile') or '',
                                 # What the page shows under the name (1.0.113).
                                 'about': {'sam': entry.get('sam') or '',
                                           'upn': entry.get('upn') or '',
                                           'department': entry.get('department') or '',
                                           'title': entry.get('title') or '',
                                           'phone': entry.get('phone') or '',
                                           'expires': entry.get('expires') or None,
                                           'pw_set': entry.get('pw_set') or None,
                                           'groups': let_in[:20],
                                           'directory': ad.name}})
    h.store.add_event('portal', '%s signed in to the enrolment pages from %s'
                      % (who, h.client_ip()), who=who)
    split_note(h.store, 'signin', who, 'signin:portal:' + str(who).lower())
    return {'token': token, 'name': who}


def portal_local_login(h, key, name, acc):
    """An account of acme's own, its password right: switched off, it is
    said as a wrong password (and counted as one), as in the administration;
    with the second step on (admin_2fa) the sign-in can do nothing but give it."""
    if acc.get('disabled'):
        h.failed(key)
        h.store.add_event('sign-ins', '%s, switched off, tried to sign in to the enrolment '
                          'pages from %s' % (acc['name'], h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    who = acc['name']
    stage = mfa_stage(h.store, who) if CONFIG.get('admin_2fa') else ''
    rec = mfa_get(h.store, who) or {}
    mail = rec.get('dest') if rec.get('kind') == 'mail' else ''
    data = {'kind': 'local', 'role': acc.get('role') or 'readonly',
            'display': acc.get('display') or '', 'dn': '', 'login': name, 'mail': mail or '',
            'mobile': (rec.get('dest') if rec.get('kind') == 'sms' else '') or '',
            'about': {'local': True, 'role': acc.get('role') or 'readonly'}}
    if stage:
        data['mfa'] = stage
    if acc.get('must_change'):
        # Changed here (1.0.14): an account of the enrolment pages only has
        # no other place to change it. Until it is, nothing else.
        data['must_change'] = 1
    token = h.store.session_new('portal', who, 'portal', h.client_ip(),
                                max(1, int(CONFIG.get('portal_session_min') or 15)) / 60.0 * 4,
                                data)
    h.store.set_account(who, last_in=time.time(), last_from=h.client_ip())
    h.store.add_event('sign-ins', '%s signed in to the enrolment pages from %s (an account '
                      'here, %s)%s' % (who, h.client_ip(), acc.get('role') or 'readonly', {
                          'check': ' - the second step to give',
                          'enrol': ' - the second step to set up'}.get(stage, '')), who=who)
    split_note(h.store, 'signin', who, 'signin:portal:' + str(who).lower())
    return {'token': token, 'name': who, 'kind': 'local', 'mfa': stage}


@route('POST', '/api/portal/logout')
def _portal_logout(h):
    h.store.session_end(h.headers.get('X-Acme-Session'))
    return {}


@route('POST', '/api/portal/password')
def _portal_password(h):
    """An account of acme's own changes its password on these pages (1.0.14):
    the one it has now, and the new one - as in the administration."""
    s = h.session('portal')
    if not s or not CONFIG.get('portal'):
        raise ApiError(401, 'not signed in, or the sign-in has run out')
    if portal_mfa_pending(s):
        raise ApiError(401, 'the second step of signing in is not done yet')
    if not portal_local_ok(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'that account may no longer sign in here')
    if (s.get('data') or {}).get('kind') != 'local':
        raise ApiError(400, 'this account signs in with its directory password, which is '
                            'changed in the directory')
    acc = h.store.account(s['name'])
    b = h.body()
    key = h.throttle('password', split_limit('login_tries', 5), 5, name=acc['name'])
    if not password_ok(str(b.get('old') or ''), acc.get('pw')):
        h.failed(key)
        raise ApiError(400, 'the password you have now is not right')
    try:
        h.store.set_account(acc['name'], password=str(b.get('new') or ''), must_change=0)
    except ValueError as e:
        raise ApiError(400, str(e))
    # Every other sign-in with the old password ends, here and in the administration.
    mine = hashlib.sha256(str(h.headers.get('X-Acme-Session') or '').encode()).hexdigest()
    h.store.db.run('DELETE FROM sessions WHERE kind IN (?, ?) AND LOWER(name) = ? AND '
                   'token_hash <> ?', ('admin', 'portal', acc['name'].lower(), mine))
    portal_data_set(h, s, must_change=None)
    h.store.add_event('accounts', '%s changed their own password (on the enrolment pages)'
                      % acc['name'], who=acc['name'])
    return {}


def portal_state(h, s):
    """What GET /api/portal/me says of the person signed in - and what each
    of PORTAL_ME adds (a module's own part of the page)."""
    data = s.get('data') or {}
    about = dict(data.get('about') or {})
    about.update(login=data.get('login') or '', mail=data.get('mail') or '',
                 mobile=data.get('mobile') or '')
    out = {'name': s['name'], 'display': data.get('display') or '', 'about': about,
           'kind': data.get('kind') or 'directory', 'role': data.get('role') or '',
           'sees_all': portal_sees_all(s), 'must_change': portal_must_change(s),
           'title': CONFIG.get('portal_title') or '', 'help': CONFIG.get('portal_help') or ''}
    for fn in PORTAL_ME:
        try:
            out.update(fn(h, s) or {})
        except ApiError:
            raise
        except Exception as e:                          # noqa: BLE001
            log('the enrolment pages: %s failed: %s' % (getattr(fn, '__name__', fn), e), 'warn')
    return out


@route('GET', '/api/portal/me')
def _portal_whoami(h):
    s = h.session('portal')
    if not s:
        return {'me': None}
    if not CONFIG.get('portal'):
        # Switched off meanwhile: nothing more of it shown (1.0.44).
        h.store.session_end(h.headers.get('X-Acme-Session'))
        return {'me': None}
    if portal_mfa_pending(s):
        # The password given, the second step not yet: the sign-in page asks it.
        return {'me': None, 'mfa': portal_mfa_pending(s)}
    if not portal_local_ok(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        return {'me': None}
    return {'me': portal_state(h, s)}


def portal_data_set(h, s, **changes):
    """What the session remembers, changed (1.0.76) - only the keys given,
    over what the database holds now (1.0.101); None takes a key away."""
    data = h.store.session_merge(s['id'], changes)
    if data is None:
        data = dict(s.get('data') or {})
        for k, v in changes.items():
            if v is None:
                data.pop(k, None)
            else:
                data[k] = v
    s['data'] = data
    return data


class ApiHttpServer(ThreadingHTTPServer):
    """The API's HTTP server, with room for many connections waiting at once
    (1.0.33): the default queue of five dropped the sixth of twenty pages
    asking at the same moment."""
    request_queue_size = 256
    daemon_threads = True
    # At most this many at once (1.0.101); past it a connection is closed at
    # once rather than given a thread.
    MOST = 256

    def __init__(self, *a, **kw):
        self.slots = threading.BoundedSemaphore(self.MOST)
        ThreadingHTTPServer.__init__(self, *a, **kw)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            log_sparing('api-full', 'the API has %d connections open already: one more was '
                        'closed' % self.MOST, 'warn')
            self.shutdown_request(request)
            return
        try:
            ThreadingHTTPServer.process_request(self, request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            ThreadingHTTPServer.process_request_thread(self, request, client_address)
        finally:
            self.slots.release()


class ApiServer(object):
    def __init__(self, daemon):
        self.daemon = daemon
        self.httpd = None

    def start(self):
        port = int(CONFIG.get('api_port') or 9861)
        # The port first, the key after (1.0.61): somebody else's program on
        # the port would otherwise have been handed the new key by the pages.
        self.httpd = ApiHttpServer(('127.0.0.1', port), ApiHandler)
        api_token(make=True)
        self.httpd.daemon_threads = True
        self.httpd.daemon = self.daemon
        threading.Thread(target=self.httpd.serve_forever, name='api', daemon=True).start()
        # Said beside the key (1.0.59): the pages read the port from here, so
        # api_port changed in the settings no longer leaves them asking 9861.
        try:
            write_replacing(RUN_DIR / 'api-port', '%d\n' % port, 0o644)
        except OSError as e:
            log('the API port could not be written down for the pages: %s' % e, 'warn')
        log('the API is on 127.0.0.1:%d' % port)

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass


