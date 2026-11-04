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
    'guard-src': 'signing in to these pages or the portal, from one place',
    # Wrong directory passwords per person, for the whole cluster (as otp 1.0.230).
    'dir-passwords': 'directory passwords tried on the pages',
}
LOCKOUTS_SENT = {'sig': None, 'at': 0.0}
THROTTLE_GUARD = threading.Lock()


# ---- Block a place that keeps guessing (as otp 1.0.137 - its RADIUS guard - for the sign-ins
# to these pages and to the certificate portal) ------------------------------------------------
GUARD_KIND = 'guard-src'
# The sign-ins counted by the place they come from: these pages, the portal, the second step.
GUARD_KINDS = ('admin', 'portal', 'mfa', 'portal-sso')


def guard_on():
    return bool(CONFIG.get('login_guard'))


def guard_trusted(src):
    """A place never blocked: login_guard_trusted (an office behind one
    address, a monitor that signs in)."""
    raw = str(CONFIG.get('login_guard_trusted') or '')
    if not raw.strip() or not src:
        return False
    try:
        a = ipaddress.ip_network(src, strict=False)
    except ValueError:
        return src in [x.strip().lower() for x in re.split(r'[\s,;]+', raw) if x.strip()]
    for x in re.split(r'[\s,;]+', raw):
        if not x.strip():
            continue
        try:
            net = ipaddress.ip_network(x.strip(), strict=False)
        except ValueError:
            continue
        if net.version != a.version:
            continue
        if a.prefixlen >= net.prefixlen and a.subnet_of(net):
            return True
        # One IPv6 address (1.0.146): requests are told apart by their /64
        # only, so the /64 it is in is the one trusted.
        if a.version == 6 and a.prefixlen == 64 and net.overlaps(a):
            return True
    return False


def guard_blocked(daemon, src):
    """(until, why) while the place is blocked, else None."""
    if not src:
        return None
    info = daemon.login_info.get((GUARD_KIND, src))
    if not info:
        return None
    until = float(info.get('blocked_until') or 0)
    if until > time.time():
        return until, info.get('blocked_why') or 'too many wrong sign-ins'
    return None


def guard_count(daemon, src, name):
    """One refusal from `src` for `name`: counted; blocked at the limit."""
    t = time.time()
    tries = int(CONFIG.get('login_guard_tries') or 20)
    nlimit = int(CONFIG.get('login_guard_names') or 0)
    span = 60 * int(CONFIG.get('login_guard_window_min') or 15)
    block = 60 * int(CONFIG.get('login_guard_block_min') or 30)
    key = (GUARD_KIND, src)
    name = str(name or '').strip().lower()[:120]
    newly = None
    with ApiHandler.THROTTLE_LOCK:
        fails = [x for x in daemon.login_fails[key] if t - x < span] + [t]
        # Kept to the limits set (1.0.139): tries up to 10000, names up to 1000.
        daemon.login_fails[key] = fails[-max(1000, tries):]
        info = daemon.login_info.setdefault(key, {'others': []})
        names = {n: ts for n, ts in (info.get('names') or {}).items() if t - ts < span}
        if name:
            names[name] = t
            cap = max(500, nlimit)
            if len(names) > cap:
                names = dict(sorted(names.items(), key=lambda kv: kv[1])[-cap:])
            others = [x for x in info.get('others') or [] if x != name]
            info['others'] = (others + [name])[-6:]
        info.update(limit=tries, span=span, what='wrong sign-ins', at=t, names=names,
                    names_limit=nlimit, guard=True)
        if float(info.get('blocked_until') or 0) <= t:
            why = None
            if len(fails) >= tries:
                why = '%d wrong sign-ins in %d min' % (len(fails), span // 60)
            elif nlimit and len(names) >= nlimit:
                why = '%d different names refused in %d min' % (len(names), span // 60)
            if why:
                info['blocked_until'] = t + block
                info['blocked_why'] = why
                info['blocked_at'] = t
                newly = why
    if newly:
        try:
            daemon.store.add_event('sign-ins', '%s is blocked for %d min - %s; the names: %s'
                                   % (src, block // 60, newly, ', '.join(
                                       (daemon.login_info.get(key) or {}).get('others') or [])),
                                   'warn')
        except Exception:                               # noqa: BLE001
            pass
        LOCKOUTS_SENT['sig'] = None


def guard_left(until):
    left = max(0, int(until - time.time()))
    return '%d min' % ((left + 59) // 60) if left >= 60 else '%d s' % left


def lockouts_view(d):
    """What this node counts now: one line per address or name with a wrong
    attempt still counted, locked or not yet."""
    t = clock_now('locks')          # as the counts are written (clock_locks, 1.0.21)
    rows = []
    for key, fails in list(d.login_fails.items()):
        info = d.login_info.get(key) or {}
        span = float(info.get('span') or 0)
        if not span:
            continue
        fails = [x for x in fails if t - x < span]
        kind, who = key
        if info.get('guard'):
            # A place counted by the sign-in protection (as otp 1.0.137): blocked for its own
            # time, by its refusals or by its names.
            until = float(info.get('blocked_until') or 0)
            blocked = until > t
            if not fails and not blocked:
                # Forgotten once nothing of it counts (otp 1.0.149).
                if t - float(info.get('at') or 0) > span and t - until > span:
                    d.login_fails.pop(key, None)
                    d.login_info.pop(key, None)
                continue
            names = [n for n, ts in (info.get('names') or {}).items() if t - ts < span]
            last = max(fails[-1] if fails else 0, float(info.get('blocked_at') or 0))
            rows.append({
                'kind': kind, 'who': who, 'by': 'place', 'what': LOCKOUT_KINDS.get(kind, kind),
                'base': kind, 'words': info.get('what') or 'wrong sign-ins',
                'fails': len(fails), 'limit': int(info.get('limit') or 0),
                'names': len(names), 'names_limit': int(info.get('names_limit') or 0),
                'locked': blocked, 'until': until if blocked else None,
                'why': info.get('blocked_why') if blocked else '',
                'forgets': max(until, (fails[-1] + span) if fails else 0),
                'first': fails[0] if fails else last, 'last': last,
                'others': list(info.get('others') or [])})
            continue
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


# ---- the cap of wrong directory passwords per person (as otp 1.0.230) -------------------------------
def dir_pw_caps_list(store):
    """Each directory with its own cap of wrong passwords, and the setting's (otp 1.0.232)."""
    caps = dir_pw_caps(store)
    out = []
    for d in store.directories():
        own = caps.get(d['name'].lower()) or {}
        out.append({'name': d['name'], 'hosts': d.get('hosts') or '', 'tls': d.get('tls') or '',
                    'enabled': bool(d.get('enabled', 1)), 'base': d.get('base') or '',
                    'tries': own.get('tries'), 'window_min': own.get('window_min'),
                    'policy': own.get('policy')})
    return {'directories': out, 'setting': {'tries': int(CONFIG.get('dir_pw_tries') or 0),
                                            'window_min': int(CONFIG.get('dir_pw_window_min') or 30)},
            # One switch for the guessing guards (as otp 1.0.241).
            'in_use': guard_on()}


def dir_pw_caps_set(store, want, by):
    """Directories' own caps saved (the pages, acme --dir-cap): {name: {tries, window_min}} -
    tries None as the setting, 0 no cap. ValueError with the words when it may not be."""
    if not isinstance(want, dict):
        raise ValueError('the caps are an object of directories')
    names = {d['name'].lower(): d['name'] for d in store.directories()}
    caps = dir_pw_caps(store)
    said = []
    for name, c in want.items():
        key = str(name).lower()
        if key not in names:
            raise ValueError('there is no directory called %s' % name)
        c = c if isinstance(c, dict) else {}
        tries, window = c.get('tries'), c.get('window_min')
        try:
            tries = None if tries in (None, '') else int(tries)
            window = None if window in (None, '') else int(window)
        except (TypeError, ValueError):
            raise ValueError('%s: the cap and its time are whole numbers' % names[key])
        if tries is not None and not 0 <= tries <= 100:
            raise ValueError('%s: the cap is 0 to 100 wrong passwords' % names[key])
        if window is not None and not 1 <= window <= 1440:
            raise ValueError('%s: the time is 1 to 1440 min' % names[key])
        was = caps.get(key) or {}
        now = dict(was, tries=tries, window_min=window)
        if now != was:
            caps[key] = now
            said.append('%s: %s' % (names[key], 'as the setting' if tries is None else
                                    ('no cap' if tries == 0 else '%d in %s min' % (
                                        tries, window or CONFIG.get('dir_pw_window_min') or 30))))
    for key in list(caps):
        if key not in names:
            caps.pop(key, None)
    store.set_meta('dirpw:conf', json.dumps(caps))
    if said:
        store.add_event('settings', '%s set the cap of wrong directory passwords: %s'
                        % (by, '; '.join(said)), who=by)
    return said


def dir_policy_read(store, ad):
    """The domain's lockout and password policy read, its recommendation with it, and kept beside
    the directory's cap for the card (not a setting). LdapError as the directory says it."""
    pol = ad.policy()
    caps = dir_pw_caps(store)
    key = ad.name.lower()
    caps[key] = dict(caps.get(key) or {}, policy={k: pol[k] for k in ('lockout', 'password', 'at', 'name')})
    store.set_meta('dirpw:conf', json.dumps(caps))
    return pol


def dir_pw_who(name, entry=None):
    """A person as the cap counts them: their account in the directory (otp 1.0.234) - the name
    typed counted novakj (sAMAccountName) and jan.novak@corp.cz (UPN) apart, and both forms
    together got twice the cap through to the directory. Its first part and a short hash of
    the whole DN: readable among the counts, one per account. A name the directory does not
    have: as typed - DOMAIN\\novak, novak@anything and Novak are one."""
    dn = str((entry or {}).get('dn') or '').strip().lower()
    if dn:
        first = re.split(r'(?<!\\),', dn, maxsplit=1)[0].split('=', 1)[-1].strip()
        return '%s#%s' % (first[:60], hashlib.sha256(dn.encode('utf-8')).hexdigest()[:8])
    return str(name or '').strip().lower().split('\\', 1)[-1].rsplit('@', 1)[0].strip()[:190]


def dir_pw_caps(store):
    """Each directory's own cap (otp 1.0.232): {name in small letters: {'tries': n, 'window_min': m}}
    - a directory not in it, or with tries None, follows the setting."""
    try:
        got = json.loads(store.get_meta('dirpw:conf') or '{}')
    except (ValueError, TypeError):
        got = {}
    return got if isinstance(got, dict) else {}


def dir_pw_cap_of(store, directory):
    """(tries, window in seconds) for a directory: its own, else the setting's. None at all while
    "Block a place that keeps guessing" is off (as otp 1.0.241): one switch for the guessing guards."""
    own = dir_pw_caps(store).get(str(directory or '').lower()) or {}
    if not guard_on():
        return 0, 60 * int(own.get('window_min') or CONFIG.get('dir_pw_window_min') or 30)
    tries = own.get('tries') if own.get('tries') is not None else CONFIG.get('dir_pw_tries')
    window = own.get('window_min') if own.get('window_min') else CONFIG.get('dir_pw_window_min')
    return int(tries or 0), 60 * int(window or 30)


def dir_pw_take(h, name, directory='', entry=None):
    """A place for one directory password of `name`, held before the directory is asked; ''
    when there is no cap. Over it: 429 - the directory is not asked. Counted per directory
    (otp 1.0.232): novak of one domain is not novak of another, and each has its own lockout."""
    most, span = dir_pw_cap_of(h.store, directory)
    who = dir_pw_who(name, entry)
    if most <= 0 or not who:
        return ''
    if directory:
        who = '%s|%s' % (who, str(directory).lower())
    if not node_key_add(h.store, 'adpw', who, span, limit=most):
        times = sorted(x for x in node_key_times(h.store, 'adpw', who) if time.time() - x < span)
        wait = max(1, int(((times[-most] + span) - time.time()) // 60) + 1) if len(times) >= most else 1
        log_sparing('adpw:' + who, 'wrong directory passwords for %s: the cap of %d in %d min is '
                    'reached - the directory is not asked for that name meanwhile'
                    % (who, most, span // 60), 'warn', every=300)
        # The address's own count keeps its place too (otp 1.0.234): the tries spent on a capped
        # name no longer came back to it.
        h.failed(None)
        raise ApiError(429, 'too many wrong passwords for this name: try again in %d min' % wait)
    return who


def dir_pw_done(h, held, wrong):
    """The place given back when the password was right (or the directory not reached)."""
    if held and not wrong:
        try:
            node_key_give_back(h.store, 'adpw', held)
        except Exception:                               # noqa: BLE001
            pass


def adpw_tidy(store):
    """The counts of wrong directory passwords whose every time is past its window (as otp
    1.0.230 tidies them with the challenges): a row a person no longer has."""
    span = 60 * int(CONFIG.get('dir_pw_window_min') or 30)
    try:                                    # a directory's own window, the longest
        caps = dir_pw_caps(store)
        span = max([span] + [60 * int(c.get('window_min') or 0) for c in caps.values()
                             if isinstance(c, dict)])
    except (ValueError, TypeError, AttributeError):
        pass
    now = time.time()                       # the counts by the machine's clock
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'adpw:%'"):
        try:
            v = json.loads(r['v'] or 'null')
        except ValueError:
            v = None
        if not isinstance(v, list) or not any(abs(now - float(x)) < span for x in v):
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))


def lockouts_shared(store):
    """What the database holds for every node (1.0.116): the codes sent to a
    person within the window, and the wrong directory passwords per person."""
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
    # Wrong directory passwords per person (otp 1.0.230), when there is a cap.
    most = int(CONFIG.get('dir_pw_tries') or 0)
    pspan = 60 * int(CONFIG.get('dir_pw_window_min') or 30)
    per = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'adpw:%'"):
        try:
            per.setdefault(node_key_name('adpw', r['k']), []).extend(
                float(x) for x in json.loads(r['v'] or '[]'))
        except (ValueError, TypeError):
            continue
    for who, times in per.items():
        # Each directory's own cap (otp 1.0.232): the name counted is "novak|directory".
        name_, _s, dname = who.partition('|')
        most, pspan = dir_pw_cap_of(store, dname)
        times = sorted(x for x in times if t - x < pspan)
        if not times or most <= 0:
            continue
        locked = len(times) >= most
        rows.append({'kind': 'dir-passwords', 'who': who, 'by': 'name',
                     'what': LOCKOUT_KINDS['dir-passwords'] + (' (%s)' % dname if dname else ''),
                     'base': 'dir-passwords',
                     'words': 'wrong directory passwords', 'fails': len(times), 'limit': most,
                     'locked': locked,
                     'until': (times[len(times) - most] + pspan) if locked else None,
                     'forgets': times[-1] + pspan, 'first': times[0], 'last': times[-1],
                     'others': []})
    rows.sort(key=lambda r: (not r['locked'], -r['last']))
    return rows


def lockouts_shared_clear(store, kind, who, by):
    if kind == 'dir-passwords':
        n = node_key_drop(store, 'adpw', str(who or '').strip().lower()[:190])
        store.add_event('sign-ins', '%s cleared the count of wrong directory passwords for %s'
                        % (by, who), 'warn', who=by)
        return n
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
    now = clock_now('locks')
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
    if act == 'clear' and str(b.get('kind') or '') in ('codes-sent', 'dir-passwords'):
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
                   ('admin_group_readonly', 'readonly'), ('admin_group_portal', 'portal'))

PORTAL_ONLY_SAID = 'this account signs in on the enrolment pages only, not here'


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
    if not entry or entry.get('many') or entry_unusable(entry):
        # Counted as a wrong password of a name that exists is (as otp 1.0.234): only those
        # were held back, so a name the directory lacks answered 401 for ever - which said
        # who exists.
        dir_pw_done(h, dir_pw_take(h, who, ad.name, entry if entry and not entry.get('many')
                                   else None), True)
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
    if not dbguard_directory_ok(h.store.db, ad.name):
        # The directory's row not as acme wrote it (1.0.231): another server put in - asked
        # there, anybody would be an administrator here.
        return {'ok': False, 'said': 'the directory %s is not as acme wrote it - not asked' % ad.name,
                'directory': ad.name}
    # The cap per account (as otp 1.0.230, 1.0.232, 1.0.234).
    held = dir_pw_take(h, who, ad.name, entry)
    try:
        ad.password_ok(entry, password)
    except LdapUnreachable as e:
        dir_pw_done(h, held, False)
        raise ApiError(503, 'the directory cannot be reached', str(e))
    except LdapError as e:
        dir_pw_done(h, held, not isinstance(e, LdapNotAsked))   # never asked: not counted
        return {'ok': False, 'said': str(e) or 'the password is not right', 'dn': entry['dn'],
                'directory': ad.name}
    dir_pw_done(h, held, False)
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
    if said['role'] == 'portal':
        # Enrolment pages only (1.0.14): no account made here, no way in.
        h.store.add_event('sign-ins', 'the directory knows %s, a member of the group of '
                          'enrolment-only accounts - refused here (from %s)'
                          % (said['name'], h.client_ip()), 'warn')
        raise ApiError(403, PORTAL_ONLY_SAID)
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
    return h.store.account(name, checked=True)


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
                dbguard_account_sign(far, name)               # signed there too (1.0.231)
            done = True
            break
        except Exception:                               # noqa: BLE001
            continue
        finally:
            far.close()
    if done:
        for _ in range(40):
            # With its signature (1.0.234): the account came over before it, and the first
            # sign-in through the other node was refused with the guard on.
            if store.account(name, checked=True):
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
    acc = h.store.account(name, checked=True) or (h.store.account(admin_name_parts(name)[0], checked=True)
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
    if ok.get('role') == 'portal':
        # An account of the enrolment pages only (1.0.14): its password is
        # right, and it is said so - it is the wrong door, not a wrong
        # password - counted as a wrong one all the same.
        h.failed(key)
        h.store.add_event('sign-ins', '%s (enrolment pages only) tried to sign in to the '
                          'administration from %s' % (ok['name'], h.client_ip()), 'warn')
        raise ApiError(403, PORTAL_ONLY_SAID)
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


