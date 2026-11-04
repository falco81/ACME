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


def portal_me(h, gate_ok=False):
    s = h.session('portal')
    if not s:
        raise ApiError(401, 'not signed in, or the sign-in has run out')
    # Switched off while somebody was signed in, it is off for them too (1.0.33).
    if not CONFIG.get('portal'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(403, 'these pages are switched off')
    # Signed in by the balancer, and that switched off meanwhile (otp 1.0.239): it ends.
    if (s.get('data') or {}).get('sso') and not CONFIG.get('portal_sso'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'sign in again')
    if portal_mfa_pending(s):
        raise ApiError(401, 'the second step of signing in is not done yet')
    # The one-time code at every sign-in (1.0.40, as otp 1.0.228): until it is typed, the sign-in
    # may do that and nothing else.
    if portal_gated(s) and not gate_ok:
        raise ApiError(401, 'type the code that was sent to you first')
    # Asked again on every step (as otp 1.0.234): a sign-in kept open from before it was switched
    # on goes no further without the code.
    data = s.get('data') or {}
    # ...acme's own accounts too (1.0.44), by their own setting.
    needed = portal_local_ways() if data.get('kind') == 'local' else portal_gate_needed()
    if not gate_ok and not data.get('gate_ok') and needed:
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'sign in again: a code is sent to you first')
    if not portal_local_ok(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'that account may no longer sign in here')
    if not portal_dir_still(h, s):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(401, 'that account may no longer sign in here')
    if portal_must_change(s):
        raise ApiError(403, 'change the password first')
    return s


def portal_gated(s):
    """Whether this sign-in to the portal still waits for its one-time code (as otp 1.0.228)."""
    return bool((s.get('data') or {}).get('gate_wait'))


def portal_gate_needed():
    """Whether a sign-in of a person of the directory needs the one-time code (1.0.40): at
    every sign-in while it is switched on - otp asks it before the first token only."""
    return bool(PORTAL_CODE_WAYS.get(str(CONFIG.get('portal_code') or 'off')))


def portal_gate_where(entry, ways=None):
    """Where the code goes, as the directory has it: (kind, address, ''), or (None, None, why)
    with why 'nothing' (no way of sending set up) or what the directory lacks. `ways`: those
    of acme's own accounts (1.0.44), their address and number as Accounts has them."""
    if ways is None:
        ways = PORTAL_CODE_WAYS.get(str(CONFIG.get('portal_code') or 'off')) or ()
    have = code_channels()
    tried = []
    for kind in ways:
        if kind not in have:
            continue
        raw = str(entry.get('mail' if kind == 'mail' else 'mobile') or '').strip()
        if not raw:
            tried.append('no %s' % ('e-mail address' if kind == 'mail' else 'mobile number'))
            continue
        try:
            return kind, dest_checked(kind, raw), ''
        except ValueError as e:
            tried.append('%s %s: %s' % ('the e-mail address' if kind == 'mail' else 'the mobile number',
                                         raw, e))
    if not any(k in have for k in ways):
        return None, None, 'nothing'
    return None, None, '; '.join(tried) or 'nothing to send it to'


def portal_gate_send(h, name, kind, dest, display='', lang=''):
    """A one-time code sent for the sign-in to the portal: the gate to keep in the session."""
    key = h.throttle('portal-send', 10 * int(CONFIG.get('code_send_max') or 5),
                     int(CONFIG.get('code_send_window_min') or 15), name=name, what='codes sent')
    if not code_send_allowed(h.store, name) or \
            not code_send_allowed(h.store, 'to:%s:%s' % (kind, dest.lower())):
        raise ApiError(429, 'too many codes were sent - wait %d min and try again'
                       % code_send_wait_min(h.store, 'to:%s:%s' % (kind, dest.lower())))
    # A code that goes holds its place - and is no refused sign-in for the guard (1.0.44): five
    # people signing in rightly from one office blocked its address for everybody.
    h.failed(key, guard=False)
    code = code_new()
    lang = lang if lang in ('cs', 'en') else None
    try:
        code_send(h.store, kind, dest, code, 'portal', name=name, lang=lang, display=display or '')
    except (MailError, SmsError) as e:
        h.store.add_event('portal', 'the one-time code for %s to sign in to the portal '
                          'could not be sent to %s: %s' % (name, dest, e), 'warn', who=name)
        # The mail or SMS server's own words in Events only (as otp 1.0.234), not on the portal.
        raise ApiError(502, 'the code could not be sent - try again later, or ask the administrator')
    h.store.add_event('portal', '%s signed in to the portal with the password: a one-time code went '
                      'by %s to %s' % (name, 'mail' if kind == 'mail' else 'SMS', dest), who=name)
    return {'kind': kind, 'dest': dest, 'code': code_hash(name, code),
            'exp': time.time() + int(CONFIG.get('code_ttl_s') or 300), 'tries': 0,
            'lang': lang or ''}


def portal_gate_view(s):
    data = s.get('data') or {}
    g = data.get('gate') or {}
    w = data.get('gate_wait') or {}
    kind = g.get('kind') or w.get('kind')
    return {'kind': kind, 'dest': dest_masked(kind, g.get('dest') or w.get('dest')),
            'live': bool(g) and float(g.get('exp') or 0) > time.time(),
            'digits': int(CONFIG.get('code_digits') or 6),
            'minutes': max(1, int(CONFIG.get('code_ttl_s') or 300) // 60),
            'sso': bool(data.get('sso'))}           # signed in by the balancer (as otp 1.0.239)


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
    # Not while the portal sends acme's own accounts its code (1.0.44): that is their second
    # step here, not the administration's.
    return str(data.get('mfa') or '') if data.get('kind') == 'local' and \
        CONFIG.get('admin_2fa') and not portal_local_ways() else ''


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
ART_NAMES = ('cert', 'chain', 'renew', 'deploy', 'order', 'dns', 'keys', 'watch', 'revoke',
             'cycle', 'ask', 'get', 'mine', 'code', 'team', 'overview', 'cluster', 'sources',
             'jobs', 'alerts', 'none', 'custom')
# The pictures of one sign-in only (1.0.41), as web/acme-art.php's ACME_ART_ONLY: the
# people who ask for certificates see their side of it, the administrators theirs.
ART_ONLY = {'ask': 'portal', 'get': 'portal', 'mine': 'portal', 'code': 'portal',
            'team': 'portal', 'overview': 'admin', 'cluster': 'admin', 'sources': 'admin',
            'jobs': 'admin', 'alerts': 'admin'}


def art_for_slot(slot, art):
    """Whether a picture may be shown on that sign-in."""
    return ART_ONLY.get(art, slot) == slot


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
    if not art_for_slot(slot, art):
        art = default
    return {'art': art, 'sha': str(got.get('sha') or '') if art == 'custom' else ''}


def art_set(store, slot, art):
    ak, _, _ = art_slot(slot)
    if not art_for_slot(slot, art):
        raise ValueError('that picture is for the sign-in of the enrolment pages only'
                         if ART_ONLY[art] == 'portal' else
                         'that picture is for the sign-in of the administration only')
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
    return {'names': list(ART_NAMES), 'only': dict(ART_ONLY), 'portal': art_state(h.store, 'portal'),
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
    return {'names': list(ART_NAMES), 'only': dict(ART_ONLY), 'portal': art_state(h.store, 'portal'),
            'admin': art_state(h.store, 'admin'), 'message': 'saved - every node shows it'}


@route('GET', '/api/portal/info')
def _portal_info(h):
    return {'on': bool(CONFIG.get('portal')), 'title': CONFIG.get('portal_title') or '',
            'art': art_read(h.store, 'portal'), 'admin_art': art_read(h.store, 'admin'),
            'hint': CONFIG.get('portal_hint') or '', 'help': CONFIG.get('portal_help') or '',
            'lang': CONFIG.get('ui_lang') or 'cs',
            'site': CONFIG.get('site_name') or short_host(),
            # Signed in by the balancer in front (otp 1.0.239): which header the page reads the
            # name from - only while it is switched on.
            'sso': {'header': CONFIG.get('portal_sso_header') or 'X-Acme-User',
                    'logout': CONFIG.get('portal_sso_logout') or ''}
            if CONFIG.get('portal_sso') and CONFIG.get('portal') else None}


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
    return portal_open_dir(h, key, name, ad, entry)


def portal_open_dir(h, key, name, ad, entry, sso=False):
    """The directory has said who it is (the password right, or the balancer in front signed
    them in, otp 1.0.239): who may use these pages decides, and the sign-in is made."""
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
    # A one-time code at every sign-in (1.0.40, as otp's before the first token, 1.0.228): to the
    # address or the number the directory has - the password alone, or the balancer's word, no
    # longer opens anybody's certificates.
    gate = None
    if portal_gate_needed():
        kind, dest, why = portal_gate_where(entry)
        if not kind:
            if why == 'nothing':
                h.store.add_event('portal', '%s cannot sign in: a one-time code is needed, and '
                                  'neither the mail nor the SMS is set up' % who, 'bad', who=who)
                raise ApiError(503, 'the code cannot be sent just now - ask the administrator')
            h.store.add_event('portal', '%s cannot sign in here: a one-time code is needed, and the '
                              'directory has %s' % (who, why), 'warn', who=who)
            raise ApiError(403, 'the directory has no e-mail address or mobile number of yours to '
                                'send the code to - ask the administrator')
        try:
            lang = str((h.body() or {}).get('lang') or '')
        except Exception:                               # noqa: BLE001
            lang = ''
        gate = portal_gate_send(h, who, kind, dest, display=entry.get('display') or '', lang=lang)
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
                                           'directory': ad.name},
                                 'gate': gate,
                                 'gate_wait': {'kind': gate['kind'], 'dest': gate['dest']}
                                 if gate else None,
                                 'sso': 1 if sso else 0})
    if gate:
        return {'token': token, 'name': who,
                'gate': {'kind': gate['kind'], 'dest': dest_masked(gate['kind'], gate['dest']),
                         'live': True, 'digits': int(CONFIG.get('code_digits') or 6),
                         'minutes': max(1, int(CONFIG.get('code_ttl_s') or 300) // 60),
                         'sso': bool(sso)}}
    h.store.add_event('portal', '%s signed in to the enrolment pages from %s%s'
                      % (who, h.client_ip(), ' (signed in by the load balancer)' if sso else ''),
                      who=who)
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
    ways = portal_local_ways()
    stage = mfa_stage(h.store, who) if CONFIG.get('admin_2fa') and not ways else ''
    rec = mfa_get(h.store, who) or {}
    # The account's own address and number (Accounts, 1.0.44) - else the administration's
    # second step's, where it is one by mail or SMS.
    mail = acc.get('mail') or (rec.get('dest') if rec.get('kind') == 'mail' else '') or ''
    mobile = acc.get('mobile') or (rec.get('dest') if rec.get('kind') == 'sms' else '') or ''
    data = {'kind': 'local', 'role': acc.get('role') or 'readonly',
            'display': acc.get('display') or '', 'dn': '', 'login': name, 'mail': mail,
            'mobile': mobile,
            'about': {'local': True, 'role': acc.get('role') or 'readonly'}}
    if stage:
        data['mfa'] = stage
    # The portal's one-time code for acme's own accounts (1.0.44): the password alone let an
    # account of acme's own in where the directory's people needed the code.
    gate = None
    if ways:
        kind, dest, why = portal_gate_where({'mail': mail, 'mobile': mobile}, ways)
        if not kind:
            if why == 'nothing':
                h.store.add_event('portal', '%s cannot sign in: a one-time code is needed, and '
                                  'neither the mail nor the SMS is set up' % who, 'bad', who=who)
                raise ApiError(503, 'the code cannot be sent just now - ask the administrator')
            h.store.add_event('portal', '%s (an account here) cannot sign in to the portal: a '
                              'one-time code is needed, and the account has %s (Accounts)'
                              % (who, why), 'warn', who=who)
            raise ApiError(403, 'this account has no e-mail address or mobile number to send the '
                                'code to - ask the administrator')
        try:
            lang = str((h.body() or {}).get('lang') or '')
        except Exception:                               # noqa: BLE001
            lang = ''
        gate = portal_gate_send(h, who, kind, dest, display=acc.get('display') or '', lang=lang)
        data['gate'] = gate
        data['gate_wait'] = {'kind': gate['kind'], 'dest': gate['dest']}
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
                          'enrol': ' - the second step to set up'}.get(stage, '') or (
                          ' - the one-time code to type' if gate else '')), who=who)
    split_note(h.store, 'signin', who, 'signin:portal:' + str(who).lower())
    out = {'token': token, 'name': who, 'kind': 'local', 'mfa': stage}
    if gate:
        out['gate'] = {'kind': gate['kind'], 'dest': dest_masked(gate['kind'], gate['dest']),
                       'live': True, 'digits': int(CONFIG.get('code_digits') or 6),
                       'minutes': max(1, int(CONFIG.get('code_ttl_s') or 300) // 60),
                       'sso': False}
    return out


# ---- signed in by the load balancer or WAF in front (otp 1.0.239) ------------------------------
# A NetScaler (nFactor / LDAP), an F5 APM or another balancer signs people in against the
# directory before the enrolment pages are shown; who it signed in comes in a header of its own,
# with a key only the balancer has (X-Acme-Sso-Key), on a connection from the balancer's own
# address - nginx's $realip_remote_addr, which the page passes on as X-Acme-Peer, never the
# client's address from X-Forwarded-For. Everything after the password is as it was: the
# directory is asked who it is, and who may use these pages decides. Off by default; the
# administration pages are not concerned.

SSO_KEY_HEADER = 'X-Acme-Sso-Key'
SSO_NOTED = {'at': 0.0, 'what': None}


def sso_nets(conf=None):
    out = []
    for w in re.split(r'[\s,;]+', str((conf or CONFIG).get('portal_sso_from') or '')):
        if not w:
            continue
        try:
            out.append(ipaddress.ip_network(w, strict=False))
        except ValueError:
            continue
    return out


def sso_peer_ok(peer):
    try:
        a = ipaddress.ip_address(str(peer or '').strip().split('%')[0])
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return any(a in n for n in sso_nets() if n.version == a.version)


def sso_note(h, ok, why, peer, name):
    """The last sign-in by the balancer this node saw - for the card on the administration
    pages. A refusal always; one that went well at most once a minute (a write on every page)."""
    what = (bool(ok), str(why)[:200], str(peer)[:64], str(name)[:120])
    t = time.time()
    if ok and SSO_NOTED['what'] == what and t - SSO_NOTED['at'] < 60:
        return
    SSO_NOTED.update(at=t, what=what)
    rec = {'at': t, 'ok': bool(ok), 'why': what[1], 'peer': what[2], 'name': what[3],
           'client': h.client_ip(), 'node': node_name()}
    try:
        # The last that went well and the last refused, each its own (a refusal hid the sign-ins),
        # each node its own row (one writer a row: replication).
        h.store.set_meta('portal_sso:last:%s:%s' % (node_name(), 'ok' if ok else 'refused'),
                         json.dumps(rec))
    except Exception as e:                                  # noqa: BLE001
        log('the last sign-in by the load balancer could not be noted: %s' % e, 'warn')


def sso_refuse(h, peer, name, why, code=401, said=None):
    """Refused - in the events with the reason, to the page in general words."""
    sso_note(h, False, why, peer, name)
    log_sparing('sso-refused:' + why[:40], 'the enrolment pages refused a sign-in by the load '
                'balancer from %s (%s): %s' % (peer or '?', name or '?', why), 'warn', every=300)
    h.store.add_event('portal', 'a sign-in by the load balancer was refused (from %s, for %s): '
                      '%s' % (peer or '?', name or '?', why), 'warn', who=name or None)
    raise ApiError(code, said or 'the sign-in through the load balancer was not taken here - '
                                 'sign in with your password, or ask the administrator')


@route('POST', '/api/portal/sso')
def _portal_sso(h):
    if not CONFIG.get('portal'):
        raise ApiError(403, 'these pages are switched off')
    if not CONFIG.get('portal_sso'):
        raise ApiError(404, 'signing in through the load balancer is switched off')
    b = h.body()
    name = str(b.get('name') or '').strip()
    given = str(b.get('key') or '')
    peer = str(h.headers.get('X-Acme-Peer') or '').strip()
    # Counted per address and per name as the sign-in is - more loosely per address: without
    # "Behind a load balancer" every client is the balancer's address.
    tries = int(CONFIG.get('portal_tries') or 5)
    key = h.throttle('portal-sso', tries, int(CONFIG.get('portal_wait_min') or 15), name=name,
                     ip_tries=max(50, tries * 10), what='refused sign-ins by the load balancer')
    if not peer:
        h.failed(key)
        sso_refuse(h, peer, name, 'nginx does not say which machine the request came from '
                   '(ACME_PEER) - the node\'s nginx has not been set up for it yet', 503)
    if not sso_peer_ok(peer):
        h.failed(key)
        sso_refuse(h, peer, name, 'not from the balancers named (%s)'
                   % (CONFIG.get('portal_sso_from') or 'none'))
    want = unseal_secret(str(CONFIG.get('portal_sso_key') or '')) or ''
    if not want:
        sso_refuse(h, peer, name, 'no key is set (Make a key)', 503)
    if not hmac.compare_digest(given.encode('utf-8', 'replace'), want.encode('utf-8', 'replace')):
        h.failed(key)
        sso_refuse(h, peer, name, 'the key in %s is %s' % (SSO_KEY_HEADER,
                                                           'not the one set' if given else 'not there'))
    if not name or len(name) > 190 or re.search(r'[\x00-\x1f\x7f]', name):
        h.failed(key)
        sso_refuse(h, peer, name[:60], 'no name in %s' % (CONFIG.get('portal_sso_header') or
                                                         'X-Acme-User'))
    # Signed in already, as the same person by the balancer: the same session goes on.
    s = h.session('portal')
    if s:
        data = s.get('data') or {}
        if data.get('sso') and str(data.get('login') or '').lower() == name.lower():
            return {'same': True, 'name': s['name']}
        # Somebody else now (a shared machine), or signed in with a password before: that one ends.
        h.store.session_end(h.headers.get('X-Acme-Session'))
    if name_letters_problem(name):
        h.failed(key)
        sso_refuse(h, peer, name, 'the name has letters this server does not take', 400,
                   'that name has letters this server does not take (accents or another '
                   'language) - ask the administrator')
    ad = portal_directory(h)
    if not ad:
        h.failed(key)
        sso_refuse(h, peer, name, 'no directory is set up for these pages', 503)
    bare, how = admin_name_parts(name)
    try:
        entry = ad.find_user(bare, how)
        if not entry:
            raise LdapError('there is no such account')
        if entry.get('many'):
            raise LdapError('more than one account answers to that name')
        if entry_unusable(entry):
            raise LdapError('the account may not sign in: %s' % entry_unusable(entry))
    except LdapUnreachable as e:
        log('the enrolment pages could not reach the directory: %s' % e, 'warn')
        raise ApiError(503, 'the directory cannot be reached just now')
    except LdapError as e:
        h.failed(key)
        sso_refuse(h, peer, name, 'the directory: %s' % e)
    try:
        got = portal_open_dir(h, key, name, ad, entry, sso=True)
    except ApiError as e:
        sso_note(h, False, str(e), peer, name)
        raise
    sso_note(h, True, '', peer, name)
    return got


def sso_view(store):
    """What the card on the administration pages shows: set or not, and the last sign-in by the
    balancer each node saw."""
    last = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'portal_sso:last:%'"):
        try:
            rec = json.loads(r['v'])
        except (TypeError, ValueError):
            continue
        if isinstance(rec, dict):
            last.append({k: rec.get(k) for k in ('at', 'ok', 'why', 'peer', 'name', 'client',
                                                 'node')})
    last.sort(key=lambda x: -float(x.get('at') or 0))
    return {'on': bool(CONFIG.get('portal_sso')), 'portal': bool(CONFIG.get('portal')),
            'key_set': bool(unseal_secret(str(CONFIG.get('portal_sso_key') or ''))),
            'from': [str(n) for n in sso_nets()],
            'header': CONFIG.get('portal_sso_header') or 'X-Acme-User',
            'key_header': SSO_KEY_HEADER, 'logout': CONFIG.get('portal_sso_logout') or '',
            'web_proxy': bool(CONFIG.get('web_proxy')),
            'web_proxy_from': str(CONFIG.get('web_proxy_from') or ''),
            'web_proxy_header': CONFIG.get('web_proxy_header') or 'X-Forwarded-For',
            'site': CONFIG.get('site_name') or short_host(), 'last': last[:8]}


@route('GET', '/api/portal-sso')
def _portal_sso_view(h):
    h.me('readonly')
    return sso_view(h.store)


@route('POST', '/api/portal-sso')
def _portal_sso_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'key':
        tok = secrets.token_urlsafe(32)
        h.d.save_settings({'portal_sso_key': tok}, by=s['name'])
        h.store.add_event('settings', '%s made a new key for the sign-in by the load balancer - '
                          'the one before is no longer taken' % s['name'], 'warn', who=s['name'])
        return {'key': tok, 'view': sso_view(h.store)}
    if act == 'forget':
        h.store.db.run("DELETE FROM meta WHERE k LIKE 'portal_sso:last:%'")
        return {'view': sso_view(h.store)}
    raise ApiError(400, 'no such thing to do')


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
           'title': CONFIG.get('portal_title') or '', 'help': CONFIG.get('portal_help') or '',
           # Signed in by the balancer (otp 1.0.239): where signing out goes.
           'sso': bool(data.get('sso')),
           'sso_logout': (CONFIG.get('portal_sso_logout') or '') if data.get('sso') else ''}
    for fn in PORTAL_ME:
        try:
            out.update(fn(h, s) or {})
        except ApiError:
            raise
        except Exception as e:                          # noqa: BLE001
            log('the enrolment pages: %s failed: %s' % (getattr(fn, '__name__', fn), e), 'warn')
    return out


@route('POST', '/api/portal/gate')
def _portal_gate(h):
    """The one-time code of the sign-in, typed back (as otp 1.0.228)."""
    s = portal_me(h, gate_ok=True)
    data = s.get('data') or {}
    if not portal_gated(s):
        return {'me': portal_state(h, s)}
    g = data.get('gate') or {}
    if not g or float(g.get('exp') or 0) < time.time():
        portal_data_set(h, s, gate=None)
        raise ApiError(410, 'the code ran out - ask for a new one')
    key = h.throttle('portal-gate', int(CONFIG.get('code_tries') or 3) + 2,
                     int(CONFIG.get('portal_wait_min') or 15), name=s['name'], ip_tries=50,
                     name_tries=int(CONFIG.get('code_tries') or 3) * 3, what='wrong codes')
    code = code_typed(h.body().get('code') or '')
    if not hmac.compare_digest(code_hash(s['name'], code), str(g.get('code') or '')):
        h.failed(key)
        last = h.store.session_count_try(s['id'], 'gate', g.get('code'),
                                         int(CONFIG.get('code_tries') or 3))
        h.store.add_event('portal', '%s typed a wrong one-time code on the portal%s'
                          % (s['name'], ' - the last try' if last else ''), 'warn', who=s['name'])
        if last:
            raise ApiError(403, 'that was not the code - and it was the last try: ask for a '
                                'new one')
        raise ApiError(403, 'that is not the code that was sent')
    # Taken once: two requests with the right code at once both read it.
    if not h.store.session_take(s['id'], 'gate'):
        raise ApiError(409, 'that code was taken already')
    portal_data_set(h, s, gate_wait=None, gate_ok=time.time())
    h.store.add_event('portal', '%s signed in to the portal from %s, with the one-time '
                      'code by %s' % (s['name'], h.client_ip(),
                                      'mail' if g.get('kind') == 'mail' else 'SMS'), who=s['name'])
    return {'me': portal_state(h, s)}


@route('POST', '/api/portal/gate/again')
def _portal_gate_again(h):
    """The one-time code sent again, to where the first one went (as otp 1.0.228)."""
    s = portal_me(h, gate_ok=True)
    if not portal_gated(s):
        return {'me': portal_state(h, s)}
    w = (s.get('data') or {}).get('gate_wait') or {}
    if w.get('kind') not in code_channels():
        raise ApiError(503, 'the code cannot be sent just now - ask the administrator')
    lang = str(h.body().get('lang') or '') or ((s.get('data') or {}).get('gate') or {}).get('lang') or ''
    gate = portal_gate_send(h, s['name'], w['kind'], w['dest'],
                            display=(s.get('data') or {}).get('display') or '', lang=lang)
    portal_data_set(h, s, gate=gate)
    return {'gate': portal_gate_view(s)}


@route('GET', '/api/portal/me')
def _portal_whoami(h):
    s = h.session('portal')
    if not s:
        return {'me': None}
    if not CONFIG.get('portal'):
        # Switched off meanwhile: nothing more of it shown (1.0.44).
        h.store.session_end(h.headers.get('X-Acme-Session'))
        return {'me': None}
    if (s.get('data') or {}).get('sso') and not CONFIG.get('portal_sso'):
        # Signed in by the balancer, and that switched off meanwhile (otp 1.0.239): it ends.
        h.store.session_end(h.headers.get('X-Acme-Session'))
        return {'me': None}
    if portal_mfa_pending(s):
        # The password given, the second step not yet: the sign-in page asks it.
        return {'me': None, 'mfa': portal_mfa_pending(s)}
    if portal_gated(s):
        # Waiting for its one-time code (as otp 1.0.228): nothing of the person shown yet.
        return {'me': {'name': s['name'], 'gate': portal_gate_view(s)}}
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


