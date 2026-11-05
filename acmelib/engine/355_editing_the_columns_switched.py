# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- editing the columns, switched on for one sign-in --------------------------
# Held here in memory, as on isemon: signing out, a sign-in running out and a
# restart of the service all switch it off again. Off, a layout already kept
# is drawn just the same; nothing can be changed.
COLS_EDITING = {}
COLS_EDITING_LOCK = threading.Lock()


def _cols_key(token):
    return hashlib.sha256(str(token or '').encode('utf-8', 'replace')).hexdigest()


# Kept with the sign-in's own row since 1.0.13 - in memory it was this node's
# alone, and behind a load balancer the next request found it switched off.
def _session_row(token):
    store = HA_STORE.get('store')
    if not store or not token:
        return None, None
    row = store.db.row('SELECT id, data FROM sessions WHERE token_hash = ?',
                       (hashlib.sha256(str(token).encode()).hexdigest(),))
    if not row:
        return store, None
    try:
        row['data'] = json.loads(row.get('data') or '{}')
    except ValueError:
        row['data'] = {}
    return store, row


def cols_editing(token):
    _, row = _session_row(token)
    return bool(row and row['data'].get('cols_edit'))


def set_cols_editing(token, on):
    store, row = _session_row(token)
    if not row:
        return False
    data = row['data']
    if on:
        data['cols_edit'] = 1
    else:
        data.pop('cols_edit', None)
    store.session_set_data(row['id'], data)
    return bool(on)


SETTINGS_FILE_KIND = 'acme-user-settings'


@route('POST', '/api/auth/logout')
def _logout(h):
    token = h.headers.get('X-Acme-Session')
    h.store.session_end(token)
    set_cols_editing(token, False)
    return {}


@route('POST', '/api/auth/columns')
def _columns(h):
    """Anybody signed in, a read-only account as well: this is how the page
    looks to that one person and changes nothing anybody else sees."""
    s = h.me()
    b = h.body()
    token = h.headers.get('X-Acme-Session') or ''
    if 'edit' in b:
        set_cols_editing(token, bool(b.get('edit')))
        if 'cols' not in b:
            return {'edit': cols_editing(token)}
    reset = bool(b.get('reset'))
    # Putting them back is always allowed; changing them only with the switch
    # on, so a page that misbehaves cannot rearrange somebody's tables while
    # they are only reading them.
    if not reset and not cols_editing(token):
        raise ApiError(409, 'switch on "Edit the columns" under your name first: the columns '
                       'are not being edited from this sign-in')
    try:
        kept = h.store.put_user_cols(s['name'], {} if reset else (b.get('cols') or {}))
    except ValueError as e:
        raise ApiError(400, str(e))
    if reset:
        h.store.add_event('accounts', '%s put the columns of every table back as they come'
                          % s['name'], who=s['name'])
    return {'tables': len(kept), 'edit': cols_editing(token)}


@route('GET', '/api/auth/settings')
def _my_settings(h):
    """What a person has set for themselves on the page, as one object that
    can be saved to a file and read back - here or on another machine. Never
    the password, the role or anything else about the account."""
    s = h.me()
    return {'name': s['name'], 'version': __version__, 'kind': SETTINGS_FILE_KIND,
            'settings': {'columns': h.store.user_cols(s['name']),
                         'prefs': h.store.user_prefs(s['name'])}}


@route('POST', '/api/auth/settings')
def _my_settings_put(h):
    s = h.me()
    b = h.body()
    got = b.get('settings')
    if not isinstance(got, dict):
        raise ApiError(400, 'that is not a file of settings: there is no "settings" in it')
    known = ('columns', 'prefs')
    ignored = sorted(k for k in got if k not in known)
    # Every section checked before any of them is written.
    for section, check, words in (('columns', h.store.clean_cols, 'the columns'),
                                  ('prefs', h.store.clean_prefs, 'the choices')):
        if section in got:
            try:
                check(got[section] if got[section] is not None else {})
            except (ValueError, TypeError, AttributeError) as e:
                raise ApiError(400, '%s in that file: %s' % (words, e))
    took = {}
    if 'columns' in got:
        took['columns'] = len(h.store.put_user_cols(s['name'], got['columns'] or {}))
    if 'prefs' in got:
        took['prefs'] = len(h.store.put_user_prefs(s['name'], got['prefs'] or {}))
    if not took:
        raise ApiError(400, 'nothing in that file is a setting this version keeps'
                       + (' (it holds: %s)' % ', '.join(ignored) if ignored else ''))
    h.store.add_event('accounts', '%s read their own settings back from a file (%s)'
                      % (s['name'], ', '.join('%s: %d' % kv for kv in took.items())),
                      who=s['name'])
    return {'took': took, 'ignored': ignored}


@route('GET', '/api/auth/whoami')
def _whoami(h):
    s = h.session('admin')
    if not s:
        return {'who': None}
    acc = h.store.account(s['name'])
    if not acc or acc.get('disabled'):
        return {'who': None}
    if mfa_pending(s):
        # No role until the second step is given: the pages that ask who it
        # is (a database or a package sent) refuse it.
        return {'who': {'name': acc['name'], 'role': '', 'display': acc.get('display') or '',
                        'mfa': mfa_pending(s)}}
    try:
        prefs = json.loads(acc.get('prefs') or '{}')
    except ValueError:
        prefs = {}
    # The page is drawn with the person's own layout of the tables from the
    # first frame, rather than as it comes and then again.
    return {'idle_min': int(CONFIG.get('session_idle_min') or 120),
            'who': {'name': acc['name'], 'role': acc['role'], 'source': acc.get('source'),
                    'display': acc.get('display') or '', 'must_change': bool(
                        acc.get('must_change')), 'prefs': prefs,
                    'cols': h.store.user_cols(acc['name']),
                    'cols_edit': cols_editing(h.headers.get('X-Acme-Session') or '')}}


@route('POST', '/api/auth/password')
def _password(h):
    s = h.me()
    b = h.body()
    acc = s['account']
    if acc.get('source') == 'directory':
        raise ApiError(400, 'this account signs in with its directory password, which is '
                       'changed in the directory')
    # Counted as sign-ins are (1.0.57): a session left open was a way to
    # guess the password without end.
    key = h.throttle('password', split_limit('login_tries', 5), 5, name=acc['name'])
    if not password_ok(str(b.get('old') or ''), acc.get('pw')):
        h.failed(key)
        raise ApiError(400, 'the password you have now is not right')
    h.store.set_account(acc['name'], password=str(b.get('new') or ''), must_change=0)
    # Every other sign-in with the old password ends (1.0.33).
    h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ? AND token_hash <> ?',
                   ('admin', acc['name'].lower(), hashlib.sha256(
                       str(h.headers.get('X-Acme-Session') or '').encode()).hexdigest()))
    # And on the enrolment pages (1.0.44), as a password set by an administrator ends them.
    try:
        account_portal_end(h.store, acc['name'])
    except Exception:                                   # noqa: BLE001
        pass
    h.store.add_event('accounts', '%s changed their own password' % acc['name'],
                      who=acc['name'])
    # The first password, written down by the installer, is no use to anybody
    # now - and stays readable no longer (1.0.33).
    first = STATE_DIR / 'first-login.txt'
    try:
        if first.exists() and ('name: %s\n' % acc['name']) in first.read_text():
            first.unlink()
    except OSError:
        pass
    return {'message': 'the password is changed'}


@route('POST', '/api/auth/prefs')
def _prefs(h):
    s = h.me()
    acc = s['account']
    try:
        prefs = json.loads(acc.get('prefs') or '{}')
    except ValueError:
        prefs = {}
    b = h.body()
    if 'lang' in b:
        if str(b['lang']) not in ('cs', 'en'):
            raise ApiError(400, 'no such language here')
        prefs['lang'] = str(b['lang'])
    # ...and the performance meter's look and its details' style (1.0.48), as Storage keeps them
    try:
        prefs.update(h.store.clean_prefs({k: b[k] for k in ('hload', 'hpanel') if k in b}))
    except ValueError as e:
        raise ApiError(400, str(e))
    h.store.set_account(acc['name'], prefs=json.dumps(prefs))
    return {'prefs': prefs}


