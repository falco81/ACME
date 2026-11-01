# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the enrolment pages -------------------------------------------------------------
def portal_me(h):
    s = h.session('portal')
    if not s:
        raise ApiError(401, 'not signed in, or the sign-in has run out')
    # Switched off while somebody was signed in, it is off for them too (1.0.33).
    if not CONFIG.get('portal'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
        raise ApiError(403, 'enrolling a token here is switched off')
    return s


# The pictures of the two sign-ins (1.0.71; each its own since 1.0.72):
# which one ({art, sha}) and a picture of the site's own (JSON with base64).
ART_SLOTS = {'portal': ('portal:art', 'portal:logo', 'phone'),
             'admin': ('admin:art', 'admin:logo', 'radius')}
LOGO_META = 'portal:logo'
LOGO_MAX = 512 * 1024
ART_NAMES = ('phone', 'radius', 'authapp', 'totp', 'acmecode', 'twostep', 'vpn', 'timeline',
             'recovery', 'clock', 'key', 'qr', 'lock', 'none', 'custom')


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
            'lang': CONFIG.get('ui_lang') or 'cs', 'issuer': CONFIG.get('totp_issuer') or '',
            'site': CONFIG.get('site_name') or short_host()}


@route('POST', '/api/portal/login')
def _portal_login(h):
    if not CONFIG.get('portal'):
        raise ApiError(403, 'enrolling a token here is switched off')
    b = h.body()
    name = str(b.get('name') or '').strip()
    password = str(b.get('password') or '')
    key = h.throttle('portal', int(CONFIG.get('portal_tries') or 5),
                     int(CONFIG.get('portal_wait_min') or 15), name=name)
    full = Authenticator.full_name(name, CONFIG.get('portal_realm') or
                                   CONFIG.get('default_realm') or '')
    if full and name_letters_problem(full):
        # Letters with accents or of another language, switched off (1.0.154): said plainly -
        # it is no password that is wrong.
        h.failed(key)
        raise ApiError(400, 'that name has letters this server does not take (accents or '
                            'another language) - ask the administrator')
    realm = h.store.realm_for(full) if full else None
    if not any(r.get('directory') for r in h.store.realms()):
        # Nobody can enrol yet - and the one trying is most likely the
        # administrator who has just installed this, at the wrong door.
        raise ApiError(503, 'nobody can enrol here yet: no realm with a directory is set up. '
                            'Administrators sign in at /admin/')
    if not realm or not realm.get('directory'):
        h.failed(key)
        raise ApiError(401, 'the name or the password is not right')
    ad = h.d.auth.directory(realm['directory'])
    if not ad:
        raise ApiError(503, 'the directory of this realm is not set up')
    how = realm.get('lookup') if realm.get('lookup') in ('upn', 'sam') else (
        'upn' if '@' in full else 'sam')
    try:
        entry = Authenticator.find_person(ad, full, how, realm)
        if not entry:
            raise LdapError('there is no such account')
        if entry.get('many'):
            # More than one account answers to the name (1.0.205): as RADIUS
            # refuses it - the token could be made for the wrong one.
            raise LdapError('more than one account answers to that name')
        if entry_unusable(entry):
            raise LdapError('the account may not sign in: %s' % entry_unusable(entry))
        ad.password_ok(entry, password)
    except LdapUnreachable as e:
        log('the enrolment pages could not reach the directory: %s' % e, 'warn')
        raise ApiError(503, 'the directory cannot be reached just now')
    except LdapError as e:
        h.failed(key)
        h.store.add_event('enrolment', '%s could not sign in to the enrolment pages from %s: %s'
                          % (full, h.client_ip(), e), 'warn', who=full)
        raise ApiError(401, 'the name or the password is not right')
    # The realm's groups always: nobody enrols a token the VPN would refuse.
    # "Who may enrol" can only narrow that further, never widen it.
    who = CONFIG.get('portal_who') or 'realm_groups'
    musts = []
    if realm.get('groups'):
        musts.append(realm['groups'])
    if who == 'groups' and dn_list(CONFIG.get('portal_groups')):
        musts.append([{'group': g} for g in dn_list(CONFIG.get('portal_groups'))])
    let_in = []
    if musts:
        have = ad.groups_of(entry, bool(realm.get('nested', 1)))
        # The groups of the realm that let this person in, for "About you"
        # on the page (1.0.113).
        for w in realm.get('groups') or []:
            try:
                if group_matches([w], have, ad):
                    g = str(w.get('group') if isinstance(w, dict) else w)
                    let_in.append(cn_of(g) or g)
            except Exception:                           # noqa: BLE001
                pass
        if not all(group_matches(w, have, ad) for w in musts):
            names = ', '.join(cn_of(w.get('group') or '') or w.get('group') or ''
                              for m in musts for w in m[:6])
            h.store.add_event('enrolment', '%s may not enrol a token: in none of the groups '
                              '(%s)' % (full, names), 'warn', who=full)
            h.d.tokens._said(Authenticator.token_name(full, realm), False,
                             'Not in the groups of the realm %s: may not enrol' % realm['name'],
                             'portal', h.client_ip(), '')
            # Counted as a wrong password is (1.0.101): the answer tells that
            # the password was right, so guessing it this way meets the same
            # limit.
            h.failed(key)
            raise ApiError(403, 'this account may not have a token here - ask the '
                           'administrator')
    tname, _how = Authenticator.token_for(h.store, full, realm)
    # The same person under another spelling (1.0.44): DOMAIN\\name, another
    # realm on the same directory, other letters' case. A token they have
    # already under any of them is the one this session is about, so that
    # the directory password alone never makes a second one.
    if not h.store.token(tname):
        same = portal_same_person(h.store, realm, entry)
        if same:
            h.store.add_event('enrolment', '%s signed in as %s: the token %s is theirs already'
                              % (full, tname, same), 'warn', who=same)
            tname = same
    token = h.store.session_new('portal', tname, 'portal', h.client_ip(),
                                max(1, int(CONFIG.get('portal_session_min') or 15)) / 60.0 * 4,
                                {'display': entry.get('display') or '', 'dn': entry['dn'],
                                 'realm': realm['name'], 'login': full,
                                 # What the page offers for a code by mail or SMS (1.0.76).
                                 'mail': entry.get('mail') or '',
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
                                           'directory': realm.get('directory') or ''}})
    h.store.add_event('enrolment', '%s signed in to the enrolment pages from %s'
                      % (tname, h.client_ip()), who=tname)
    return {'token': token, 'name': tname}


def portal_same_person(store, realm, entry):
    """The name of a token the directory entry already has under another
    spelling: its userPrincipalName, its account name with the suffix of
    any realm on the same directory, or bare - '' when none."""
    sam = str(entry.get('sam') or '').strip()
    upn = str(entry.get('upn') or '').strip()
    names = []                          # (name, what it is: 'upn' or 'sam')
    star = False
    if upn:
        names.append((upn, 'upn'))
    if sam:
        names.append((sam, 'sam'))
        for r in store.realms():
            if str(r.get('directory') or '').lower() != str(realm.get('directory') or '').lower():
                continue
            suf = str(r.get('suffix') or '')
            if suf == '*':
                star = True
            elif suf:
                names.append(('%s@%s' % (sam, suf), 'sam'))
                # And under its other suffixes (1.0.117), for a token made
                # before they were.
                for al in r.get('aliases') or []:
                    names.append(('%s@%s' % (sam, al), 'sam'))
    here = str(realm.get('directory') or '').lower()

    def same_directory(cand, what):
        # Only a name whose own realm reads the same directory is the same
        # person (1.0.59): a bare "novak" can be a different Novak in a realm
        # on another directory. And only as that realm reads its names
        # (1.0.205): in a realm that looks names up by the account name,
        # "jan.novak@corp.cz" is the account jan.novak - not whoever has
        # that userPrincipalName; another person's token was taken for his.
        r = store.realm_for(cand)
        if not r or str(r.get('directory') or '').lower() != here:
            return False
        how = r.get('lookup')
        return how not in ('upn', 'sam') or how == what
    names = [(n, w) for n, w in names if same_directory(n, w)]
    seen = set()
    for n, w in names:
        for cand in (n, n.lower()):
            if cand in seen:
                continue
            seen.add(cand)
            if store.token(cand):
                return norm_name(cand)
    want = {}
    for n, w in names:
        want.setdefault(n.lower(), w)
    if want:
        for row in store.db.rows('SELECT name FROM tokens WHERE LOWER(name) IN (%s)'
                                 % ','.join('?' * len(want)), tuple(sorted(want))):
            if same_directory(row['name'], want.get(row['name'].lower(), 'sam')):
                return row['name']
    if sam and star:
        # A realm of every suffix on this directory (1.0.205): the account's
        # token under any suffix is its own - typed with another one, a
        # second token was made with the password alone, and let in.
        like = re.sub(r'([!%_])', r'!\1', sam.lower()) + '@%'
        for row in store.db.rows("SELECT name FROM tokens WHERE LOWER(name) LIKE ? ESCAPE '!'",
                                 (like,)):
            if row['name'].lower().split('@', 1)[0] == sam.lower() and \
                    same_directory(row['name'], 'sam'):
                return row['name']
    return ''


def token_meta_forget(store, name):
    """What was kept beside a token that is gone (1.0.61)."""
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', ('disabled_from:' + norm_name(name),))
    except Exception:                                   # noqa: BLE001
        pass


def token_switch_state(store, name, on):
    """The state a token is switched to (1.0.59). Switched off, the state it
    had is kept aside; switched on, a token that was waiting for its first
    code waits again rather than coming into use with a key never proven
    scanned."""
    name = norm_name(name)
    if not on:
        cur = (store.token(name) or {}).get('state') or 'active'
        if cur != 'disabled':
            store.set_meta('disabled_from:' + name, cur)
        return 'disabled'
    was = store.get_meta('disabled_from:' + name, '') or 'active'
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', ('disabled_from:' + name,))
    except Exception:                                   # noqa: BLE001
        pass
    return 'pending' if was == 'pending' else 'active'


@route('POST', '/api/portal/logout')
def _portal_logout(h):
    h.store.session_end(h.headers.get('X-Acme-Session'))
    return {}


def portal_methods(h, s):
    """The kinds of token this person may choose (1.0.76): what their realm
    offers, less a way of sending that is not set up."""
    data = s.get('data') or {}
    realm = h.store.realm_for(data.get('login') or s['name'])
    chan = code_channels()
    return [k for k in realm_methods(realm) if k == 'totp' or k in chan]


PORTAL_TOKEN_KEYS = ('name', 'kind', 'state', 'dest', 'lang', 'mail_fmt', 'digits', 'period',
                     'scratch_left', 'scratch_kept', 'pending', 'locked_until', 'created',
                     'activated', 'last_used', 'key_lost')


def portal_state(h, s):
    tok = h.store.token(s['name'])
    shown = h.store.token_shown(tok)
    if shown:
        # What its owner needs and nothing else (1.0.208): the administrators'
        # note and who made it went to the enrolment page as they are.
        shown = {k: shown.get(k) for k in PORTAL_TOKEN_KEYS}
    data = s.get('data') or {}
    ver = data.get('verify') or {}
    if ver and float(ver.get('exp') or 0) < time.time():
        ver = {}
    about = dict(data.get('about') or {})
    about.update(login=data.get('login') or '', realm=data.get('realm') or '',
                 mail=data.get('mail') or '', mobile=data.get('mobile') or '')
    return {'name': s['name'], 'display': data.get('display') or '',
            'about': about,
            'methods': portal_methods(h, s),
            'suggest': {'mail': data.get('mail') or '', 'sms': data.get('mobile') or ''},
            'verify': {'kind': ver.get('kind'), 'dest': dest_masked(ver.get('kind'),
                                                                     ver.get('dest'))}
            if ver else None,
            'may_replace': bool(data.get('may_replace')),
            'code_digits': int(CONFIG.get('code_digits') or 6),
            'mail_fmt_default': 'text' if CONFIG.get('code_mail_fmt') == 'text' else 'html',
            'token': shown, 'confirm': bool(CONFIG.get('portal_confirm')),
            'reissue': bool(CONFIG.get('portal_reissue')),
            'show_secret': bool(CONFIG.get('portal_show_secret')),
            'show_scratch': bool(CONFIG.get('portal_scratch')),
            'codes_view': bool(CONFIG.get('portal_codes_view')) and bool(shown) and
            bool((shown or {}).get('scratch_kept')),
            'title': CONFIG.get('portal_title') or '', 'help': CONFIG.get('portal_help') or ''}


@route('GET', '/api/portal/me')
def _portal_whoami(h):
    s = h.session('portal')
    if not s:
        return {'me': None}
    if not CONFIG.get('portal'):
        # Switched off meanwhile: nothing more of it shown (1.0.44).
        h.store.session_end(h.headers.get('X-Acme-Session'))
        return {'me': None}
    return {'me': portal_state(h, s)}


def _picture_for_page(got):
    if not CONFIG.get('portal_show_secret'):
        got = dict(got)
        got.pop('secret', None)
        got.pop('secret_spaced', None)
    if not CONFIG.get('portal_scratch'):
        got = dict(got)
        got['scratch'] = []
    return got


def portal_data_set(h, s, **changes):
    """What the enrolment session remembers, changed (1.0.76) - only the keys
    given, over what the database holds now (1.0.101)."""
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


@route('POST', '/api/portal/enroll')
def _portal_enroll(h):
    s = portal_me(h)
    b = h.body()
    kind = str(b.get('kind') or 'totp')
    if kind not in portal_methods(h, s):
        raise ApiError(403, 'that way of getting codes is not offered here')
    may_replace = bool((s.get('data') or {}).get('may_replace'))
    if may_replace and h.d.tokens.blocked(s['name']):
        # Switched off or locked meanwhile (1.0.94).
        portal_data_set(h, s, may_replace=None)
        raise ApiError(403, 'the token cannot be replaced here: %s' % h.d.tokens.blocked(s['name']))
    if kind in ('mail', 'sms'):
        # A code sent by mail or SMS (1.0.76): the address or the number is
        # proven first - a code goes there, and is typed back here - and only
        # then is the token made.
        tok = h.store.token(s['name'])
        if tok and tok.get('state') != 'pending' and not may_replace:
            raise ApiError(409, 'there is a token already; it can be replaced with a code '
                                'from it')
        ver_was = (s.get('data') or {}).get('verify') or {}
        if b.get('again') and not b.get('dest') and ver_was.get('kind') == kind:
            # Sent again to where the check in this session goes (1.0.98):
            # the page reloaded meanwhile knows only that it is masked.
            # The language chosen for the check kept (1.0.103): the page
            # reloaded meanwhile sends its own, which is not that choice.
            b = dict(b, dest=ver_was.get('dest'), mail_fmt=ver_was.get('mail_fmt') or b.get('mail_fmt'),
                     lang=ver_was.get('lang') or b.get('lang'))
        try:
            dest = dest_checked(kind, b.get('dest'))
        except ValueError as e:
            raise ApiError(400, str(e))
        # Every code sent holds its place (1.0.101): a code sent "went well"
        # and gave it back, so only the count per name below bounded how
        # many SMS a signed-in person could have sent - to any number. Now
        # also per address of the page and per destination.
        # Per address ten times what one person may have sent - many people
        # sit behind one address - and the person's own count below.
        key = h.throttle('portal-send', 10 * int(CONFIG.get('code_send_max') or 5),
                         int(CONFIG.get('code_send_window_min') or 15), name=s['name'],
                         what='codes sent')
        if not code_send_allowed(h.store, s['name']) or \
                not code_send_allowed(h.store, 'to:%s:%s' % (kind, dest.lower())):
            # Nothing sent: the address's place given back (1.0.103).
            raise ApiError(429, 'too many codes were sent - wait %d min and try again'
                           % code_send_wait_min(h.store, 'to:%s:%s' % (kind, dest.lower())))
        h.failed(key)       # a code that goes holds its place
        code = code_new()
        page_lang = str(b.get('lang') or '')
        page_lang = page_lang if page_lang in ('cs', 'en') else ''
        # What the person chose (1.0.83): HTML or plain text, for a mail.
        fmt = str(b.get('mail_fmt') or '')
        fmt = fmt if (kind == 'mail' and fmt in ('html', 'text')) else ''
        try:
            code_send(h.store, kind, dest, code, 'verify', name=s['name'],
                      lang=page_lang or None, fmt=fmt or None)
        except (MailError, SmsError) as e:
            h.store.add_event('enrolment', 'the code to check %s for %s could not be sent: %s'
                              % (dest, s['name'], e), 'warn', who=s['name'])
            raise ApiError(502, 'the code could not be sent: %s' % e)
        portal_data_set(h, s, verify={'kind': kind, 'dest': dest, 'code': code_hash(s['name'], code),
                                      'exp': time.time() + int(CONFIG.get('code_ttl_s') or 300),
                                      'tries': 0, 'lang': page_lang, 'mail_fmt': fmt})
        h.store.add_event('enrolment', '%s asked for a code by %s to %s, to check it' % (
            s['name'], 'mail' if kind == 'mail' else 'SMS', dest), who=s['name'])
        return {'verify': {'kind': kind, 'dest': dest_masked(kind, dest)},
                'me': portal_state(h, s)}
    confirm = bool(CONFIG.get('portal_confirm'))
    if may_replace and h.store.token(s['name']):
        # The old one proven on this page (a recovery code, or a code sent
        # to it): a new app token beside it until a code confirms it.
        got = (h.d.tokens.stage_replacement(s['name'], 'self') if confirm
               else h.d.tokens.enroll(s['name'], 'self', pending=False))
        portal_data_set(h, s, may_replace=None)
        if str(b.get('lang') or '') in ('cs', 'en'):
            h.store.token_write(s['name'], {'lang': str(b.get('lang'))})
        h.store.add_event('enrolment', '%s is replacing their token with the app' % s['name'],
                          who=s['name'])
        return {'made': _picture_for_page(got), 'confirm': confirm}
    # Looked at and written under the name's lock (1.0.59): two tabs, or a
    # confirm in one, no longer slip between the look and the write.
    with h.d.tokens.lock_of(norm_name(s['name'])):
        tok = h.store.token(s['name'])
        if tok and tok.get('state') != 'pending':
            raise ApiError(409, 'there is a token already; it can be replaced with a code '
                                'from it')
        got = h.d.tokens.enroll(s['name'], 'self', pending=confirm,
                                display=(s.get('data') or {}).get('display') or '')
        if str(b.get('lang') or '') in ('cs', 'en'):       # its second window's language (1.0.82)
            h.store.token_write(s['name'], {'lang': str(b.get('lang'))})
    h.store.add_event('enrolment', '%s enrolled a token for themselves%s' % (
        s['name'], ', waiting for a code' if confirm else ''), who=s['name'])
    return {'made': _picture_for_page(got), 'confirm': confirm}


@route('POST', '/api/portal/verify')
def _portal_verify(h):
    """The code sent to an address or a number, typed back (1.0.76): the
    token is made."""
    s = portal_me(h)
    data = s.get('data') or {}
    ver = data.get('verify') or {}
    if not ver or float(ver.get('exp') or 0) < time.time():
        portal_data_set(h, s, verify=None)
        raise ApiError(410, 'the code ran out - ask for a new one')
    # Counted where many requests at once cannot each see "no tries yet"
    # (1.0.94) - the tries in the session are read at the start of each.
    key = h.throttle('portal-verify', int(CONFIG.get('code_tries') or 3) + 2,
                     int(CONFIG.get('portal_wait_min') or 15), name=s['name'], ip_tries=50,
                     name_tries=int(CONFIG.get('code_tries') or 3) * 3, what='wrong codes')
    code = re.sub(r'\s', '', str(h.body().get('code') or ''))
    if not hmac.compare_digest(code_hash(s['name'], code), str(ver.get('code') or '')):
        h.failed(key)
        # Counted on the code as it is now (1.0.101): a copy read at the
        # start and written back brought back a code another request had
        # taken, or lost another's count.
        last = h.store.session_count_try(s['id'], 'verify', ver.get('code'),
                                         int(CONFIG.get('code_tries') or 3))
        if last:
            raise ApiError(403, 'that was not the code - and it was the last try: ask for a '
                                'new one')
        raise ApiError(403, 'that is not the code that was sent')
    # Taken once (1.0.101): two requests with the right code at once both
    # read it before either cleared it.
    if not h.store.session_take(s['id'], 'verify'):
        raise ApiError(409, 'that code was taken already')
    # Looked at again now (1.0.136), as making the token is: switched off,
    # locked or confirmed by its owner while the code was on its way, it is
    # not replaced by one whose codes go where this session said.
    tok = h.store.token(s['name'])
    may_replace = bool(data.get('may_replace'))
    if tok and tok.get('state') != 'pending' and not may_replace:
        portal_data_set(h, s, verify=None)
        raise ApiError(409, 'there is a token already; it can be replaced with a code from it')
    if may_replace and h.d.tokens.blocked(s['name']):
        portal_data_set(h, s, verify=None, may_replace=None)
        raise ApiError(403, 'the token cannot be replaced here: %s'
                       % h.d.tokens.blocked(s['name']))
    got = h.d.tokens.enroll_sent(s['name'], 'self', ver['kind'], ver['dest'],
                                 display=data.get('display') or '', lang=ver.get('lang') or None,
                                 mail_fmt=ver.get('mail_fmt') or None)
    portal_data_set(h, s, verify=None, may_replace=None)
    h.store.add_event('enrolment', '%s set up their sign-in: codes by %s to %s' % (
        s['name'], 'mail' if ver['kind'] == 'mail' else 'SMS', ver['dest']), who=s['name'])
    made = {'kind': got['kind'], 'dest': got['dest'],
            'scratch': got['scratch'] if CONFIG.get('portal_scratch') else []}
    return {'made': made, 'me': portal_state(h, s)}


@route('POST', '/api/portal/sendold')
def _portal_sendold(h):
    """A code to where the codes go now (1.0.76): proof of the old token on
    the way to replacing it, as a code from the old phone is."""
    s = portal_me(h)
    if not CONFIG.get('portal_reissue') and not CONFIG.get('portal_codes_view'):
        raise ApiError(403, 'a token can only be replaced by an administrator here')
    tok = h.store.token(s['name'])
    kind = token_kind(tok)
    if not tok or kind == 'totp':
        raise ApiError(400, 'this token gets no codes sent')
    # A token switched off or locked out stays so (1.0.94): its owner does
    # not switch it on again by replacing it.
    stop = h.d.tokens.blocked(s['name'])
    if stop:
        raise ApiError(403, 'the token cannot be replaced here: %s' % stop)
    if not code_send_allowed(h.store, s['name']):
        raise ApiError(429, 'too many codes were sent - wait %d min and try again'
                       % code_send_wait_min(h.store, s['name']))
    code = code_new()
    page_lang = str(h.body().get('lang') or '')
    try:
        code_send(h.store, kind, tok.get('dest') or '', code, 'signin', name=s['name'],
                  lang=page_lang if page_lang in ('cs', 'en') else None)
    except (MailError, SmsError) as e:
        raise ApiError(502, 'the code could not be sent: %s' % e)
    portal_data_set(h, s, old={'code': code_hash(s['name'], code),
                               'exp': time.time() + int(CONFIG.get('code_ttl_s') or 300)})
    return {'sent_to': dest_masked(kind, tok.get('dest'))}


@route('POST', '/api/portal/codes')
def _portal_codes(h):
    """The person's own recovery codes, shown again (1.0.113) - only with a
    code from the token itself: the directory password alone must never
    hand over a second factor."""
    s = portal_me(h)
    if not CONFIG.get('portal_codes_view'):
        raise ApiError(403, 'the recovery codes are shown only when the token is made here')
    tok = h.store.token(s['name'])
    if not tok or tok.get('state') == 'pending':
        raise ApiError(400, 'there is no token in use yet')
    stop = h.d.tokens.blocked(s['name'])
    if stop:
        raise ApiError(403, 'not while the token is blocked: %s' % stop)
    key = h.throttle('portal-codes', int(CONFIG.get('portal_tries') or 5),
                     int(CONFIG.get('portal_wait_min') or 15), name=s['name'], ip_tries=30,
                     name_tries=2 * int(CONFIG.get('portal_tries') or 5), what='wrong codes')
    code = re.sub(r'\s', '', str(h.body().get('code') or ''))
    old = (s.get('data') or {}).get('old') or {}
    if old and float(old.get('exp') or 0) >= time.time() and \
            hmac.compare_digest(code_hash(s['name'], code), str(old.get('code') or '')):
        ok, said = True, 'Code sent accepted'
        if not h.store.session_take(s['id'], 'old'):
            ok, said = False, SAY_REUSED
    else:
        ok, said, _f = h.d.tokens.check(s['name'], code, how='portal', src=h.client_ip())
    if not ok:
        h.failed(key)
        raise ApiError(403, 'the code was not taken: %s' % said)
    shown = codes_open(h.store.token(s['name']))
    if shown is None:
        raise ApiError(409, 'the recovery codes of this token are kept only in a form that '
                            'cannot be shown - ask the administrator for new ones')
    h.store.add_event('enrolment', '%s looked at their recovery codes from %s'
                      % (s['name'], h.client_ip()), 'warn', who=s['name'])
    return {'codes': [{'code': c.get('c') if isinstance(c, dict) else str(c),
                       'used': (c.get('used') if isinstance(c, dict) else None)}
                      for c in shown]}


@route('POST', '/api/portal/confirm')
def _portal_confirm(h):
    s = portal_me(h)
    # Its own limit too (1.0.101), whatever the token's pause and lockout
    # are set to.
    key = h.throttle('portal-confirm', 10, int(CONFIG.get('portal_wait_min') or 15),
                     name=s['name'], ip_tries=50, name_tries=10, what='wrong codes')
    ok, said = h.d.tokens.confirm(s['name'], str(h.body().get('code') or ''), 'portal',
                                  h.client_ip())
    if ok:
        h.store.add_event('enrolment', '%s confirmed their token' % s['name'], who=s['name'])
    else:
        h.failed(key)
    return {'good': ok, 'said': said, 'me': portal_state(h, s)}


@route('POST', '/api/portal/reissue')
def _portal_reissue(h):
    s = portal_me(h)
    if not CONFIG.get('portal_reissue'):
        raise ApiError(403, 'a token can only be replaced by an administrator here')
    b = h.body()
    # Its own count (1.0.103), not the sign-in's: a wrong old code here no
    # longer locked the sign-in of everybody at the address.
    key = h.throttle('portal-reissue', int(CONFIG.get('portal_tries') or 5),
                     int(CONFIG.get('portal_wait_min') or 15), name=s['name'], ip_tries=30,
                     name_tries=2 * int(CONFIG.get('portal_tries') or 5),
                     what='wrong passwords or codes')
    realm = h.store.realm_for((s.get('data') or {}).get('login') or s['name'])
    ad = h.d.auth.directory(realm['directory']) if realm else None
    if not ad:
        raise ApiError(503, 'the directory of this realm is not set up')
    try:
        ad.password_ok({'dn': (s.get('data') or {}).get('dn')}, str(b.get('password') or ''))
    except LdapUnreachable as e:
        log('the enrolment pages could not reach the directory: %s' % e, 'warn')
        raise ApiError(503, 'the directory cannot be reached just now')
    except LdapError:
        h.failed(key)
        # 403, not 401 (1.0.33): a 401 signs the page out, and the person
        # lost the words saying what was wrong.
        raise ApiError(403, 'the password is not right')
    stop = h.d.tokens.blocked(s['name'])
    if stop:
        raise ApiError(403, 'the token cannot be replaced here: %s' % stop)
    code = re.sub(r'\s', '', str(b.get('code') or ''))
    old = (s.get('data') or {}).get('old') or {}
    if old and float(old.get('exp') or 0) >= time.time() and \
            hmac.compare_digest(code_hash(s['name'], code), str(old.get('code') or '')):
        ok, said = True, 'Code sent accepted'               # 1.0.76
        if not h.store.session_take(s['id'], 'old'):         # once (1.0.101)
            ok, said = False, SAY_REUSED
        s['data'] = dict(s.get('data') or {})
        s['data'].pop('old', None)
    else:
        ok, said, _f = h.d.tokens.check(s['name'], code, how='portal', src=h.client_ip())
    if not ok:
        h.failed(key)
        raise ApiError(403, 'the code from the old token was not taken: %s' % said)
    want = str(b.get('kind') or 'totp')
    if want != 'totp' or token_kind(h.store.token(s['name'])) != 'totp':
        # Another way, or away from one (1.0.76): the page asks which, and
        # the old token goes on working until the new one is made.
        portal_data_set(h, s, may_replace=True)
        h.store.add_event('enrolment', '%s proved their token and may set up another way'
                          % s['name'], who=s['name'])
        return {'choose': True, 'me': portal_state(h, s)}
    if CONFIG.get('portal_confirm'):
        got = h.d.tokens.stage_replacement(s['name'], 'self')
    else:
        got = h.d.tokens.enroll(s['name'], 'self', pending=False)
    h.store.add_event('enrolment', '%s is replacing their token' % s['name'], who=s['name'])
    return {'made': _picture_for_page(got), 'confirm': bool(CONFIG.get('portal_confirm'))}


@route('POST', '/api/portal/cancel')
def _portal_cancel(h):
    s = portal_me(h)
    if (s.get('data') or {}).get('verify') or (s.get('data') or {}).get('may_replace'):
        # An address being checked, or a new way being chosen (1.0.76): given
        # up, and the token there is (if any) stays as it is.
        portal_data_set(h, s, verify=None, may_replace=None, old=None)
        return {'me': portal_state(h, s)}
    with h.d.tokens.lock_of(norm_name(s['name'])):      # with confirm (1.0.59)
        tok = h.store.token(s['name'])
        if tok and tok.get('pending_secret'):
            h.d.tokens.drop_staged(s['name'])
            h.store.add_event('enrolment', '%s stopped replacing their token' % s['name'],
                              who=s['name'])
        elif tok and tok.get('state') == 'pending':
            h.store.token_drop(s['name'])
            token_meta_forget(h.store, s['name'])
            h.store.add_event('enrolment', '%s threw away the token they had not confirmed'
                              % s['name'], who=s['name'])
    return {'me': portal_state(h, s)}


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


