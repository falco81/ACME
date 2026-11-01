# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- health and signing in -------------------------------------------------------
HEALTH_SEEN = {}


# ---- who is locked out (1.0.112) ---------------------------------------------------
# Each node counts the wrong passwords that reach it, in memory. Every node
# writes its list into meta when it changes, so the pages of either show both;
# a lockout is cleared by the node that holds it - asked through meta when it
# is the other one.
LOCKOUT_KINDS = {
    'admin': 'signing in to these pages',
    'portal': 'signing in to the enrolment pages',
    # Kept in the database for the whole cluster (1.0.116), not in a node's
    # memory: codes sent to a person.
    'codes-sent': 'codes sent by e-mail or SMS',
    'password': 'changing a password',
    'dirtry': 'trying a directory sign-in (Accounts)',
    'texts-test': 'a test message (Message texts)',
}
LOCKOUTS_SENT = {'sig': None, 'at': 0.0}
THROTTLE_GUARD = threading.Lock()


def lockouts_view(d):
    """What this node counts now: one line per address or name with a wrong
    attempt still counted, locked or not yet."""
    t = time.time()
    rows = []
    for key, fails in list(d.login_fails.items()):
        info = d.login_info.get(key) or {}
        span = float(info.get('span') or 0)
        if not span:
            continue
        fails = [x for x in fails if t - x < span]
        kind, who = key
        if not fails:
            continue
        by_name = kind.endswith('-name')
        base = kind[:-5] if by_name else kind
        limit = int(info.get('limit') or 0)
        locked = bool(limit) and len(fails) >= limit
        rows.append({
            'kind': kind, 'who': who, 'by': 'name' if by_name else 'address',
            'what': LOCKOUT_KINDS.get(base, base), 'base': base,
            'words': info.get('what') or 'wrong passwords',
            'fails': len(fails), 'limit': limit, 'locked': locked,
            'until': (fails[0] + span) if locked else None,
            'forgets': fails[-1] + span, 'first': fails[0], 'last': fails[-1],
            'others': list(info.get('others') or [])})
    rows.sort(key=lambda r: (not r['locked'], -r['last']))
    return rows


def lockouts_clear(d, which=None):
    """Forget counts: which is a list of (kind, who); None - every one."""
    n = 0
    with ApiHandler.THROTTLE_LOCK:
        keys = list(d.login_fails) if which is None else \
            [tuple(k) for k in which if tuple(k) in d.login_fails]
        for k in keys:
            if d.login_fails.pop(k, None):
                n += 1
            d.login_info.pop(k, None)
    LOCKOUTS_SENT['sig'] = None
    return n


LOCKOUTS_PUBLISHED_MOST = 500


def lockouts_publish(d, force=False):
    rows = lockouts_view(d)
    if len(rows) > LOCKOUTS_PUBLISHED_MOST:
        # The locked ones and the busiest (1.0.149), not every place.
        rows = sorted(rows, key=lambda r: (not r.get('locked'), -int(r.get('fails') or 0)))[
            :LOCKOUTS_PUBLISHED_MOST]
    sig = json.dumps([(r['kind'], r['who'], r['fails'], r['locked']) for r in rows])
    now = time.time()
    if not force and sig == LOCKOUTS_SENT['sig'] and now - LOCKOUTS_SENT['at'] < 60:
        return rows
    # On a server alone too (1.0.187): the command line reads it there
    # (acme --lockouts), the daemon's counts being in its memory only.
    d.store.set_meta('lockouts:' + node_name(), json.dumps({'at': now, 'rows': rows}))
    LOCKOUTS_SENT.update(sig=sig, at=now)
    return rows


def lockouts_tick(d):
    """Asked by the other node's pages to clear something here? Then the list."""
    key = 'lockouts:ask:' + node_name()
    raw = d.store.get_meta(key)
    if raw:
        d.store.db.run('DELETE FROM meta WHERE k = ?', (key,))
        try:
            asks = json.loads(raw)
        except ValueError:
            asks = []
        for a in asks if isinstance(asks, list) else []:
            if not isinstance(a, dict):
                continue
            n = lockouts_clear(d, None if a.get('all') else [a.get('key') or []])
            lockouts_said(d.store, a, n)
        lockouts_publish(d, force=True)
        return
    lockouts_publish(d)


def lockouts_said(store, a, n):
    by = str(a.get('by') or '?')
    if a.get('all'):
        words = '%s cleared every lockout and count of wrong attempts on %s (%d)' % (
            by, node_name(), n)
    else:
        k = a.get('key') or ['', '']
        base = str(k[0])[:-5] if str(k[0]).endswith('-name') else str(k[0])
        words = '%s cleared the count of wrong attempts of %s %s (%s) on %s' % (
            by, 'the name' if str(k[0]).endswith('-name') else 'the address', k[1],
            LOCKOUT_KINDS.get(base, base), node_name())
    store.add_event('sign-ins', words, 'warn', who=by)


def lockouts_shared(store):
    """What the database holds for every node (1.0.116): the codes sent to a
    person within the window."""
    t = time.time()
    rows = []
    span = 60 * int(CONFIG.get('code_send_window_min') or 15)
    limit = int(CONFIG.get('code_send_max') or 5)
    per = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'codesent:%'"):
        try:
            per.setdefault(node_key_name('codesent', r['k']), []).extend(
                float(x) for x in json.loads(r['v'] or '[]'))
        except (ValueError, TypeError):
            continue
    for who, times in per.items():          # every node's row of a person together (1.0.146)
        times = sorted(x for x in times if t - x < span)
        if not times:
            continue
        locked = len(times) >= limit
        rows.append({'kind': 'codes-sent', 'who': who, 'by': 'name',
                     'what': LOCKOUT_KINDS['codes-sent'], 'base': 'codes-sent',
                     'words': 'codes sent', 'fails': len(times), 'limit': limit,
                     'locked': locked,
                     'until': (times[len(times) - limit] + span) if locked else None,
                     'forgets': times[-1] + span, 'first': times[0], 'last': times[-1],
                     'others': []})
    rows.sort(key=lambda r: (not r['locked'], -r['last']))
    return rows


def lockouts_shared_clear(store, kind, who, by):
    if kind == 'codes-sent':
        n = node_key_drop(store, 'codesent', who)
        store.add_event('sign-ins', '%s cleared the count of codes sent to %s' % (by, who),
                        'warn', who=by)
        return n
    return 0


@route('GET', '/api/lockouts')
def _lockouts(h):
    h.me('fulladmin')
    me = node_name()
    out = [{'node': me, 'me': True, 'fresh': True, 'rows': lockouts_view(h.d)}]
    now = time.time()
    for n in h.d.cluster_nodes():
        if n == me:
            continue
        try:
            got = json.loads(h.store.get_meta('lockouts:' + n) or '{}')
        except ValueError:
            got = {}
        rows = [r for r in (got.get('rows') or []) if float(r.get('forgets') or 0) > now]
        for r in rows:
            if r.get('locked') and float(r.get('until') or 0) <= now:
                r['locked'] = False
        out.append({'node': n, 'me': False, 'fresh': now - float(got.get('at') or 0) < 120,
                    'at': got.get('at'), 'rows': rows})
    out.append({'node': '*', 'me': False, 'fresh': True, 'shared': True,
                'rows': lockouts_shared(h.store)})
    return {'nodes': out, 'now': now, 'cluster': len(out) > 2}


@route('POST', '/api/lockouts')
def _lockouts_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    nodes = [node_name()] + [n for n in h.d.cluster_nodes() if n != node_name()]
    if act == 'clear' and str(b.get('kind') or '') == 'codes-sent':
        n = lockouts_shared_clear(h.store, str(b.get('kind')), norm_name(b.get('who') or ''),
                                  s['name'])
        if not n:
            raise ApiError(404, 'that is not counted any more')
        return {'message': 'cleared', 'told': []}
    if act == 'clear_all':
        want = nodes
        ask = {'all': 1, 'by': s['name']}
        shared = lockouts_shared(h.store)
        for r in shared:
            lockouts_shared_clear(h.store, r['kind'], r['who'], s['name'])
    elif act == 'clear':
        kind, who = str(b.get('kind') or ''), str(b.get('who') or '')
        base = kind[:-5] if kind.endswith('-name') else kind
        if base not in LOCKOUT_KINDS or not who:
            raise ApiError(400, 'which lockout?')
        node = str(b.get('node') or node_name())
        if node not in nodes:
            raise ApiError(400, 'there is no node %s' % node)
        want = [node]
        ask = {'key': [kind, who], 'by': s['name']}
    else:
        raise ApiError(400, 'no such thing to do')
    told = []
    for n in want:
        if n == node_name():
            got = lockouts_clear(h.d, None if ask.get('all') else [ask['key']])
            lockouts_said(h.store, ask, got)
            lockouts_publish(h.d, force=True)
        else:
            # The other node clears it within five seconds.
            with THROTTLE_GUARD:
                try:
                    pending = json.loads(h.store.get_meta('lockouts:ask:' + n) or '[]')
                except ValueError:
                    pending = []
                pending = (pending if isinstance(pending, list) else [])[-50:] + [ask]
                h.store.set_meta('lockouts:ask:' + n, json.dumps(pending))
            told.append(n)
    return {'message': 'cleared', 'told': told}


@route('GET', '/api/health')
def _health(h):
    """Asked without the API token, so it says only what the pages need
    before anybody is signed in: that the database opens, whether any
    account exists at all (the sign-in page says how to make the first one
    otherwise), the language and this node's name. No version, no count."""
    # The database asked at most once a second (1.0.57): /healthz is public,
    # and every load balancer, monitor and the VIP address's own check ask it.
    got = HEALTH_SEEN.get('db')
    if got and time.time() - got[0] < 1.0:
        users, db_ok, maint = got[1]
    else:
        try:
            users = 1 if h.store.db.value('SELECT 1 FROM accounts LIMIT 1') else 0
            db_ok = True
        except Exception:
            users, db_ok = 0, False
        try:
            maint = bool(maintenance_now(h.store).get('on'))
        except Exception:                               # noqa: BLE001
            maint = False
        HEALTH_SEEN['db'] = (time.time(), (users, db_ok, maint))
    out = {'ok': True, 'users': users, 'database': {'ok': db_ok},
           'lang': CONFIG.get('ui_lang') or 'cs', 'node': node_name(),
           'maintenance': maint}
    # For monitoring (1.0.47) - asked for - whether replication runs.
    if h.arg('check') == 'all' and CONFIG.get('ha_mode') == 'replicated':
        try:
            rep = ha_repl_state(h.store)
            out['replication'] = {'ok': bool(rep.get('healthy')), 'lost': bool(rep.get('lost'))}
        except Exception:                               # noqa: BLE001
            out['replication'] = {'ok': False}
    # For a balancer in front of acme's own DNS server: is it listening here?
    if h.arg('check') == 'dns':
        try:
            from acmelib.certs import renewer as _ren
            r = _ren.RENEWER[0]
            st = r.dns_state() if r is not None else {'running': False}
            out['dns'] = {'ok': bool(st.get('running') and st.get('listening')),
                          'on': bool(int(CONFIG.get('dns_server') or 0))}
        except Exception:                               # noqa: BLE001
            out['dns'] = {'ok': False, 'on': bool(int(CONFIG.get('dns_server') or 0))}
    return out


DUMMY_PW_HASH = password_hash(secrets.token_urlsafe(18))

ROLE_GROUP_KEYS = (('admin_group_full', 'fulladmin'), ('admin_group_cert', 'certadmin'),
                   ('admin_group_readonly', 'readonly'))


def admin_role_for(have, ad=None):
    """Which role these groups earn - full administrator first - or None.
    Only a group named for a role lets anybody in (1.0.33): with none named,
    nobody from the directory gets in at all. Before, being anywhere in the
    directory was then enough to read every log and every certificate."""
    for key, role in ROLE_GROUP_KEYS:
        wanted = dn_list(CONFIG.get(key))
        if wanted and group_matches(wanted, have, ad):
            return role
    return None


def admin_name_parts(name):
    """`DOMAIN\\novak`, `novak@example.cz` or `novak`, as the directory is asked."""
    name = name.strip()
    if '\\' in name:
        name = name.split('\\', 1)[1]
    return name, ('upn' if '@' in name else 'sam')


def admin_ask_directory(h, name, password):
    """One sign-in, asked of the directory in `admin_directory`, and what it
    earns here. Nothing is made and no session is opened."""
    ad = h.d.dirs.get(str(CONFIG.get('admin_directory') or '').lower())
    if not ad:
        return None
    who, how = admin_name_parts(name)
    try:
        entry = ad.find_user(who, how)
    except LdapUnreachable as e:
        raise ApiError(503, 'the directory cannot be reached', str(e))
    if not entry:
        return {'ok': False, 'missing': True, 'said': 'the directory has nobody called %s' % who,
                'directory': ad.name}
    if entry.get('many'):
        # Two accounts answer to the name (1.0.208): the first one's password and
        # groups were taken - and with them the account of the one signed in
        # before under that name. Refused, as the enrolment pages do.
        return {'ok': False, 'said': 'more than one account answers to %s' % who,
                'directory': ad.name}
    if entry_unusable(entry):
        return {'ok': False, 'said': 'the account may not sign in: %s' % entry_unusable(entry),
                'dn': entry['dn'], 'directory': ad.name}
    try:
        ad.password_ok(entry, password)
    except LdapUnreachable as e:
        raise ApiError(503, 'the directory cannot be reached', str(e))
    except LdapError as e:
        return {'ok': False, 'said': str(e) or 'the password is not right', 'dn': entry['dn'],
                'directory': ad.name}
    have = ad.groups_of(entry, True)
    return {'ok': True, 'name': who, 'role': admin_role_for(have, ad), 'dn': entry['dn'],
            'display': entry.get('display') or '', 'directory': ad.name, 'entry': entry,
            'groups': sorted({cn for _, cn in have}, key=str.lower)}


def admin_from_directory(h, name, password):
    """An administrator signed in against the directory named in
    `admin_directory`: the role is that of the first group they are in."""
    said = admin_ask_directory(h, name, password)
    if said is None:
        return None
    if not said['ok']:
        # What the directory said goes into the log only: the answer must not
        # tell the caller whether the name exists there.
        h.store.add_event('sign-ins', 'the directory did not sign %s in from %s: %s'
                          % (name, h.client_ip(), said.get('said') or '?'), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    if not said['role']:
        # Said as a wrong password is (1.0.101): a 403 told anybody trying
        # names and passwords that this one was right.
        h.store.add_event('sign-ins', 'the directory knows %s, and none of the groups given a '
                          'role here holds them (from %s)' % (said['name'], h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    name, role, entry = said['name'], said['role'], said['entry']
    bad = name_letters_problem(name)
    if bad:
        # Said as a wrong password is, and written down (1.0.154).
        h.store.add_event('sign-ins', 'the directory signed %s in, refused here: %s'
                          % (name, bad), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    # One person, one account, whatever way the name was typed (1.0.101):
    # novak, novak@corp.cz and CORP\novak are the same entry in the
    # directory - found by its DN. Kept under their typed name, each
    # spelling was an account of its own, and switching one off left the
    # others to sign in with.
    same = [a for a in h.store.db.rows("SELECT * FROM accounts WHERE source = 'directory'")
            if str(a.get('dn') or '').lower() == str(entry['dn']).lower()]
    off = [a for a in same if a.get('disabled')]
    if off:
        return off[0]
    if same:
        name = same[0]['name']
    acc = h.store.account(name)
    groups = '; '.join(said['groups'])[:2000]
    if acc:
        if acc.get('source') != 'directory':
            return None
        if acc.get('dn') and str(acc['dn']).lower() != str(entry['dn']).lower():
            # Another entry of the directory under the name now (1.0.208): moved
            # to another OU, or the name given to somebody else - said, so that
            # it is seen.
            h.store.add_event('accounts', 'the directory account of %s is another one now: '
                              '%s (was %s)' % (name, entry['dn'], acc['dn']), 'warn')
        h.store.set_account(name, role=role, display=entry.get('display') or '',
                            dn=entry['dn'], group_list=groups)
    elif CONFIG.get('ha_mode') == 'replicated' and not ha_lead(h.store):
        # Made by one node of the two only (1.0.149): a first sign-in on both
        # at once - or while replication was stopped - put the name in twice,
        # and replication stopped on it for good. The other node's database
        # gets it; replication brings it here.
        dir_account_far(h.store, name, role, said, entry, groups)
    else:
        h.store.add_account(name, role, None, source='directory',
                            note='signed in from %s' % said['directory'],
                            display=entry.get('display') or '', dn=entry['dn'], groups=groups)
    return h.store.account(name)


def dir_account_far(store, name, role, said, entry, groups):
    if not ACCOUNT_NAME_RE.match(name) or role not in ROLES_ALL:
        raise ApiError(401, 'the name or the password is not right')
    row = {'name': name, 'role': role, 'pw': '', 'source': 'directory', 'disabled': 0,
           'must_change': 0, 'note': ('signed in from %s' % said['directory'])[:400],
           'created': time.time(), 'last_in': None, 'last_from': '', 'prefs': '{}',
           'display': entry.get('display') or '', 'dn': entry['dn'], 'group_list': groups}
    mode, ca = ha_link_tls()
    done = False
    for tls in [None] + ([('verify-ca', ca)] if mode == 'verify-full' else []):
        try:
            far = db_open(ha_peer_conf(timeout=5, tls=tls))
        except Exception:                               # noqa: BLE001
            continue
        try:
            if not far.row('SELECT id FROM accounts WHERE LOWER(name) = ?', (name.lower(),)):
                far.insert('accounts', row)
            done = True
            break
        except Exception:                               # noqa: BLE001
            continue
        finally:
            far.close()
    if done:
        for _ in range(40):
            if store.account(name):
                return
            time.sleep(0.25)
    raise ApiError(503, 'the first sign-in of %s is made on the other node of the cluster, '
                        'which could not be reached or has not passed it on yet - try again in '
                        'a minute, or sign in there' % name)


@route('POST', '/api/auth/login')
def _login(h):
    b = h.body()
    # No account has a longer name (1.0.146): megabytes typed went into the log.
    name = str(b.get('name') or '').strip()[:190]
    password = str(b.get('password') or '')
    key = h.throttle('admin', split_limit('login_tries', 5),
                     int(CONFIG.get('login_wait_min') or 15), name=name)
    acc = h.store.account(name) or (h.store.account(admin_name_parts(name)[0])
                                    if CONFIG.get('admin_directory') else None)
    ok = None
    if acc and acc.get('source') != 'directory':
        ok = acc if (acc.get('pw') and password_ok(password, acc['pw'])) else None
    elif not acc and not CONFIG.get('admin_directory'):
        # As long as for a name that is there (1.0.33): how long the answer
        # took told which names exist.
        password_ok(password, DUMMY_PW_HASH)
    elif CONFIG.get('admin_directory') and password:
        if not acc:
            # The time of a password hash spent here too (1.0.101): a wrong
            # password of a local account took a hash longer than a name that
            # is not there, which went straight to the directory.
            password_ok(password, DUMMY_PW_HASH)
        try:
            ok = admin_from_directory(h, name, password)
        except ApiError as e:
            h.failed(key)
            h.store.add_event('sign-ins', '%s could not sign in from %s: %s'
                              % (name, h.client_ip(), e), 'warn')
            raise
    if not ok:
        h.failed(key)
        h.store.add_event('sign-ins', 'a wrong password for %s from %s'
                          % (name or '(nobody)', h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    if ok.get('disabled'):
        # Said as a wrong password is, and counted as one (1.0.57): the
        # difference told that the password was right.
        h.failed(key)
        h.store.add_event('sign-ins', '%s, switched off, tried to sign in from %s'
                          % (ok['name'], h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    # The second step, when it is asked for (1.0.125): the sign-in is made,
    # and may do nothing but give it.
    stage = mfa_stage(h.store, ok['name']) if CONFIG.get('admin_2fa') else ''
    token = h.store.session_new('admin', ok['name'], ok['role'], h.client_ip(),
                                CONFIG.get('session_hours') or 12,
                                data={'mfa': stage} if stage else None)
    h.store.set_account(ok['name'], last_in=time.time(), last_from=h.client_ip())
    h.store.add_event('sign-ins', '%s signed in from %s%s' % (
        ok['name'], h.client_ip(), {'check': ' - the second step to give',
                                     'enrol': ' - the second step to set up'}.get(stage, '')),
                      who=ok['name'])
    split_note(h.store, 'signin', ok['name'], 'signin:admin:' + str(ok['name']).lower())
    return {'token': token, 'who': {'name': ok['name'], 'role': ok['role'] if not stage else ''},
            'must_change': bool(ok.get('must_change')), 'mfa': stage}


