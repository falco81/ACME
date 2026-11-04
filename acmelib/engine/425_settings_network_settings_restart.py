# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- Settings → Network, Settings → Restart and power off (1.0.119) -------------------
@route('GET', '/api/net')
def _net(h):
    h.me('fulladmin')
    return net_view(h.store)


@route('POST', '/api/net')
def _net_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    node = str(b.get('node') or node_name())
    known = [node_name()] + [n['name'] for n in ha_nodes(h.store)]
    if node not in known:
        raise ApiError(400, 'there is no node %s' % node)
    try:
        if act == 'read':
            # Said again by that node within seconds; this one at once.
            h.store.set_meta('net:read:' + node, repr(time.time()))
            if node == node_name():
                try:
                    net_publish(h.store)
                except ValueError as e:
                    raise ApiError(502, str(e))
            return net_view(h.store)
        if act == 'plan':
            got = net_check(h.store, node, b.get('want') or {})
            return {'plan': got['plan'], 'want': got}
        if act == 'hide':
            job = _meta_json(h.store, 'net:job:' + node) or {}
            if not job:
                raise ApiError(409, 'there is nothing on %s to hide' % node)
            if job.get('state') not in ('done', 'failed'):
                raise ApiError(409, 'the change on %s is not over yet' % node)
            h.store.set_meta('net:seen:' + node, str(job.get('id')))
            return net_view(h.store)
        if act == 'apply':
            ask = net_ask(h.store, node, b.get('want') or {}, s['name'])
            return {'message': 'asked: %s does it now' % node, 'id': ask['id']}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/power')
def _power(h):
    h.me('fulladmin')
    return power_view(h.store)


@route('POST', '/api/power')
def _power_do(h):
    s = h.me('fulladmin')
    b = h.body()
    if b.get('action') == 'hide':
        plan = power_plan(h.store)
        if plan.get('id'):
            h.store.set_meta('power:seen', str(plan['id']))
        return power_view(h.store)
    try:
        plan = power_ask(h.store, str(b.get('how') or ''), b.get('targets') or [],
                         str(b.get('order') or ''), s['name'])
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'message': 'asked', 'plan': plan}


@route('GET', '/api/ntp')
def _ntp(h):
    h.me('fulladmin')
    return ntp_view(h.store)


@route('POST', '/api/ntp')
def _ntp_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    node = str(b.get('node') or node_name())
    try:
        if act == 'save':
            ntp_save(h.store, b.get('conf') or {}, s['name'])
            return {'message': 'saved; each node sets its time servers within seconds'}
        if act in ('read', 'sync'):
            known = [node_name()] + [n['name'] for n in ha_nodes(h.store)]
            if node not in known:
                raise ApiError(400, 'there is no node %s' % node)
            h.store.set_meta('ntp:%s:%s' % (act, node), repr(time.time()))
            if act == 'sync':
                h.store.add_event('settings', '%s asked %s to step its clock to the time '
                                  'servers now' % (s['name'], node), 'warn', who=s['name'])
            return {'message': 'asked: %s does it within seconds' % node}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/console-login')
def _console_login(h):
    h.me('fulladmin')
    return console_login_view(h.store)


@route('POST', '/api/console-login')
def _console_login_do(h):
    s = h.me('fulladmin')
    b = h.body()
    on = b.get('on')
    if not isinstance(on, bool):
        raise ApiError(400, 'on is true or false')
    try:
        # The normal users it opens for too (1.0.240): '*', a list of names, or none - left out,
        # as they are.
        console_login_ask(h.store, str(b.get('node') or node_name()), on, s['name'],
                          users=b.get('users') if 'users' in b else None)
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'message': 'asked: the console at login is switched on within seconds' if on else
            'asked: the console at login is switched off within seconds'}


@route('GET', '/api/selinux')
def _selinux(h):
    h.me('fulladmin')
    return selinux_view(h.store)


@route('POST', '/api/selinux')
def _selinux_do(h):
    s = h.me('fulladmin')
    b = h.body()
    node = str(b.get('node') or node_name())
    action = str(b.get('action') or '')
    if action == 'download':
        # Every node's report in one archive, from the database - whichever node answers.
        data, missing = selinux_report_bundle(h.store)
        h.store.add_event('settings', '%s took the SELinux report%s' % (
            s['name'], (' - without %s' % ', '.join(m.split(':')[0] for m in missing)) if missing else ''),
            'info', who=s['name'])
        return {'name': 'acme-selinux-report-%s.tar.gz' % time.strftime('%Y%m%d-%H%M'),
                'file': base64.b64encode(data).decode('ascii'), 'mime': 'application/gzip',
                'missing': missing}
    try:
        if action == 'report' and node == '*':
            for n in [node_name()] + [x['name'] for x in ha_nodes(h.store) if x['name'] != node_name()]:
                selinux_ask(h.store, n, 'report', s['name'])
            return {'message': 'asked: every node makes its report within a minute'}
        selinux_ask(h.store, node, action, s['name'])
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'message': {'check': 'asked: %s looks within seconds',
                        'prepare': 'asked: %s makes SELinux ready and permissive within seconds',
                        'enforce': 'asked: %s switches SELinux to enforcing within seconds',
                        'permissive': 'asked: %s switches SELinux to permissive within seconds',
                        'report': 'asked: %s makes its report within a minute'
                        }[action] % node}


# ---- root's SSH keys and the updates of the system on the pages (1.0.158) ------------
@route('GET', '/api/sshkeys')
def _sshkeys(h):
    h.me('fulladmin')
    return sshkeys_view(h.store)


@route('POST', '/api/sshkeys')
def _sshkeys_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    nodes = b.get('nodes') or [node_name()]
    if not isinstance(nodes, list):
        raise ApiError(400, 'nodes is a list')
    # Whose keys (1.0.240): root's as until now, or a normal user's of the nodes.
    user = str(b.get('user') or 'root')
    try:
        if act == 'refresh':
            sshkeys_ask(h.store, nodes, 'list', s['name'], user=user)
            return {'message': 'asked again'}
        if act == 'add':
            # A public line, or a private key of which only the public half
            # is used and nothing else kept (1.0.161).
            line, was_private = rootkey_public(b.get('line'), str(b.get('passphrase') or ''))
            sshkeys_ask(h.store, nodes, 'add', s['name'], line=line, user=user)
            return {'message': 'the key goes onto %s within a few seconds%s' % (
                ', '.join(nodes), ' - the private half was not kept' if was_private else '')}
        if act == 'drop':
            sshkeys_ask(h.store, nodes, 'drop', s['name'], fp=str(b.get('fp') or ''),
                        last_ok=bool(b.get('last_ok')), user=user)
            return {'message': 'the key is taken away on %s within a few seconds'
                               % ', '.join(nodes)}
        if act == 'uk_make':
            # A key made for a normal user (1.0.240): its private half to the page once, its
            # public half onto the nodes asked - remembered nowhere.
            if user == 'root':
                raise ValueError('root\'s key is made with the card above')
            if b.get('kind', 'ed25519') not in ('ed25519', 'rsa4096'):
                raise ValueError('ed25519 or rsa4096')
            private, public, fp = sshkey_pair(str(b.get('kind') or 'ed25519'),
                                              '%s@%s %s' % (user, node_name(), time.strftime('%Y-%m-%d')))
            done = sshkeys_ask(h.store, nodes, 'add', s['name'], line=public, user=user)
            h.store.add_event('settings', '%s made a new SSH key for %s on %s (%s) - its private '
                              'half handed to the page once, kept nowhere' % (
                                  s['name'], user, ', '.join(done), fp), 'warn', who=s['name'])
            return {'private': private, 'pub': public, 'fp': fp, 'nodes': done,
                    'file': 'acme-%s-%s' % (re.sub(r'[^A-Za-z0-9-]', '', user), time.strftime('%Y%m%d')),
                    'message': 'made - keep the private half now, it is not shown again'}
        # Root's key made or given here (1.0.159): its private half kept nowhere.
        scope = str(b.get('scope') or 'all')
        if act == 'rk_make':
            if b.get('kind', 'ed25519') not in ('ed25519', 'rsa4096'):
                raise ValueError('ed25519 or rsa4096')
            private, public, _ = sshkey_pair(str(b.get('kind') or 'ed25519'),
                                             'root@%s %s' % (scope if scope != 'all' else node_name(),
                                                             time.strftime('%Y-%m-%d')))
            x = rootkey_put(h.store, scope, public, s['name'], 'made')
            h.store.add_event('settings', '%s made a new SSH key for root on %s (%s) - its private '
                              'half handed to the page once, kept nowhere' % (
                                  s['name'], ', '.join(x['nodes']), x['fp']), 'warn', who=s['name'])
            return dict(x, private=private,
                        file='acme-root-%s-%s' % (re.sub(r'[^A-Za-z0-9-]', '', scope),
                                                 time.strftime('%Y%m%d')),
                        message='made - keep the private half now, it is not shown again')
        if act == 'rk_given':
            public, was_private = rootkey_public(b.get('key'), str(b.get('passphrase') or ''))
            x = rootkey_put(h.store, scope, public, s['name'], 'given')
            return dict(x, message='the public half goes onto %s%s' % (
                ', '.join(x['nodes']), ' - the private half was not kept' if was_private else ''))
        if act == 'rk_again':
            nodes = rootkey_again(h.store, scope, s['name'])
            return {'message': 'the key goes onto %s again' % ', '.join(nodes)}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/osup')
def _osup(h):
    h.me('fulladmin')
    return osup_view(h.store)


@route('POST', '/api/osup')
def _osup_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'check':
            nodes = osup_check_ask(h.store, b.get('nodes') or host_nodes(h.store), s['name'])
            return {'message': 'looking for updates on %s' % ', '.join(nodes)}
        if act == 'start':
            plan = osup_start(h.store, b.get('nodes') or None, str(b.get('reboot') or 'ask'),
                              s['name'], security=bool(b.get('security')))
            return {'message': 'the update starts: %s, one at a time' % ', '.join(plan['order']),
                    'plan': plan}
        if act == 'cancel':
            osup_cancel(h.store, s['name'])
            return {'message': 'stopped - a node being updated finishes'}
        if act == 'clear':
            osup_clear(h.store, s['name'])
            return osup_view(h.store)
        if act == 'hide':
            plan = osup_plan(h.store)
            if plan.get('state') == 'running':
                raise ValueError('it is still going on')
            if plan.get('id'):
                h.store.set_meta('host:osup:seen', str(plan['id']))
            return osup_view(h.store)
        if act == 'reboot':
            nodes = [n for n in host_nodes(h.store) if n in (b.get('nodes') or [])]
            plan = power_ask(h.store, 'reboot', nodes, 'rolling' if len(nodes) > 1 else 'one',
                             s['name'])
            return {'message': 'restarting %s, one at a time' % ', '.join(nodes), 'plan': plan}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/sshd')
def _sshd(h):
    h.me('fulladmin')
    return sshd_view(h.store)


@route('POST', '/api/sshd')
def _sshd_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'save':
            c = sshd_save(h.store, b.get('conf') or {}, s['name'])
            return dict(sshd_view(h.store), message='put in on every node within a few seconds' +
                        (' - on trial: Keep it within %d min, or it goes back' % c['trial_min']
                         if c['manage'] and c['trial_min'] else ''))
        if act == 'keep':
            c = sshd_conf(h.store)
            h.store.set_meta('host:sshd:keep', json.dumps({'hash': c.get('hash'), 'at': time.time(),
                                                           'by': s['name']}))
            h.store.add_event('settings', '%s kept the change of the SSH server' % s['name'],
                              'info', who=s['name'])
            return dict(sshd_view(h.store), message='kept')
        if act == 'back':
            h.store.set_meta('host:sshd:back', json.dumps({'id': secrets.token_hex(6),
                                                           'at': time.time(), 'by': s['name']}))
            h.store.add_event('settings', '%s put the SSH server back as it was' % s['name'],
                              'warn', who=s['name'])
            return dict(sshd_view(h.store), message='it goes back within a few seconds')
        if act == 'refresh':
            HOST_WORK['sshd_read'] = 0.0
            return sshd_view(h.store)
        # SSH tokens of their own (as otp 1.0.181): the app's QR shown once, when made.
        if act == 'sshotp_add':
            # Only an account of the nodes (as otp 1.0.242): root, or a user who may sign in
            # there, as the nodes said - never a name typed that is nobody's.
            if not b.get('replace'):
                known = sshotp_accounts(h.store)
                if known is not None and str(b.get('name') or '').strip() not in known:
                    raise ValueError('%s is not an account of the nodes - pick one of the list '
                                     '(root, or a user who may sign in there)'
                                     % str(b.get('name') or '')[:40])
            got = sshotp_make(h.store, b.get('name'), s['name'], b.get('note') or '',
                              replace=bool(b.get('replace')), kind=str(b.get('kind') or 'app'),
                              dest=str(b.get('dest') or ''), lang=str(b.get('lang') or ''))
            return dict(sshd_view(h.store), made=got, message=(
                'the SSH token of %s is made - scan it now, it is not shown again' % got['name']
                if got['kind'] == 'app' else 'the SSH token of %s is made - its codes go to %s'
                % (got['name'], got['dest'])))
        if act == 'sshotp_remove':
            sshotp_remove(h.store, b.get('name'), s['name'])
            return dict(sshd_view(h.store), message='removed')
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')


# ---- the local users of the machines (1.0.243) -----------------------------------------
# Settings -> Local users: the users of each node (root and those of the normal range), made and
# looked after on every node of a cluster at once or on one - by each node's root helper
# (acme_web.py, users.ask), asked through the database as root's SSH keys are: what is asked of a
# node is in a row of the asking node's own ('host:users:want:NODE@@ASKER', signed when the guard
# of root's actions is on), and the node answers in a row of its own ('host:users:now:NODE').
# root is shown, never changed. A password is typed on one node and never leaves it as itself:
# its hash (SHA-512 crypt, made by openssl from standard input) is what is asked, sealed with
# the cluster's key, taken out of the asking row once the node said it is done.
OSU_WORK = {'busy': False, 'since': 0.0, 'seen': 0.0}
OSU_KEEP = ('root', 'acme', 'acme-web', 'postgres', 'mysql', 'nginx', 'apache', 'nobody',
            'keepalived', 'chrony', 'sshd', 'polkitd', 'dbus', 'systemd-network', 'tss')
OSU_DOS = ('list', 'add', 'password', 'lock', 'unlock', 'sudo', 'set', 'drop')
OSU_PW_MIN = 8


def osu_now(store, n):
    return _meta_json(store, 'host:users:now:' + n) or {}


def osu_asks(store, n):
    out = []
    for r in node_key_rows(store, 'host:users:want', n):
        try:
            asks = json.loads(r['v'] or '[]')
        except ValueError:
            continue
        for a in asks if isinstance(asks, list) else [asks]:
            if isinstance(a, dict) and a.get('id'):
                out.append(a)
    return out


def osu_view(store):
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        now = osu_now(store, n)
        done = set(now.get('done') or [])
        pending = late = 0
        for a in osu_asks(store, n):
            if a['id'] in done or a.get('do') == 'list':
                continue
            age = time.time() - float(a.get('at') or 0)
            if age < 300:
                pending += 1
            elif age < 3600:
                late += 1
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'users': now.get('users') or [], 'at': now.get('at'),
                      'admin_group': now.get('admin_group') or '', 'shells': now.get('shells') or [],
                      'uid_min': now.get('uid_min'), 'uid_max': now.get('uid_max'),
                      'today': now.get('today'), 'said': now.get('said') or [],
                      'error': now.get('error') or ('%d change(s) asked of it more than five minutes '
                                                    'ago are not done - is acme-web.path running '
                                                    'there?' % late if late else ''),
                      'pending': pending})
    pol = osu_policy()
    sig = osu_policy_ask(pol)['sig']
    for x in nodes:
        now = osu_now(store, x['name'])
        x['policy_ok'] = now.get('policy') == sig
        x['policy_said'] = now.get('policy_said') or ''
    return {'nodes': nodes, 'cluster': len(nodes) > 1, 'pw_min': pol['min'], 'policy': pol,
            'openssl': bool(shutil.which('openssl'))}


# ---- the password policy (1.0.42) ---------------------------------------------------------
def osu_policy():
    """What Settings -> Local users -> The password policy says."""
    def g(v, d):
        try:
            return int(v if v not in (None, '') else d)
        except (TypeError, ValueError):
            return d
    return {'min': max(OSU_PW_MIN, g(CONFIG.get('osu_pw_min'), 8)),
            'classes': min(4, max(1, g(CONFIG.get('osu_pw_classes'), 1))),
            'not_name': bool(g(CONFIG.get('osu_pw_not_name'), 1)),
            'max_days': g(CONFIG.get('osu_pw_max_days'), 0),
            'min_days': g(CONFIG.get('osu_pw_min_days'), 0),
            'warn_days': g(CONFIG.get('osu_pw_warn_days'), 7),
            'system': bool(g(CONFIG.get('osu_pw_system'), 0))}


def osu_aging(pol=None):
    pol = pol or osu_policy()
    return {'max_days': pol['max_days'], 'min_days': pol['min_days'], 'warn_days': pol['warn_days']}


def osu_policy_ask(pol=None):
    """What is asked of a node's root helper to put the policy on it, and its signature."""
    pol = pol or osu_policy()
    ask = {'do': 'policy', 'aging': osu_aging(pol),
           'rules': ({'min': pol['min'], 'classes': pol['classes'], 'not_name': pol['not_name']}
                     if pol['system'] else None)}
    ask['sig'] = hashlib.sha256(json.dumps(ask, sort_keys=True).encode()).hexdigest()[:16]
    return ask


def osu_pw_kinds(pw):
    return sum(1 for rx in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]') if re.search(rx, pw))


def osu_pw_problem(pw, name='', pol=None):
    """What is wrong with a password by the policy - '' when nothing."""
    pol = pol or osu_policy()
    if len(pw) < pol['min']:
        return 'the password is %d characters at least' % pol['min']
    if osu_pw_kinds(pw) < pol['classes']:
        return ('the password has %d of the four kinds of characters at least (small letters, '
                'capitals, digits, the others)' % pol['classes'])
    n = str(name or '').lower()
    if pol['not_name'] and len(n) >= 3 and (n in pw.lower() or n[::-1] in pw.lower()):
        return 'the password has the user\'s name in it'
    return ''


def osu_hash(password, name=''):
    """The SHA-512 crypt hash of a password, by openssl from its standard input."""
    pw = str(password or '')
    bad = osu_pw_problem(pw, name)
    if bad:
        raise ValueError(bad)
    if len(pw) > 256 or re.search(r'[\x00-\x1f\x7f]', pw):
        raise ValueError('the password is 256 characters at most, with no line breaks')
    exe = shutil.which('openssl')
    if not exe:
        raise ValueError('openssl is not on this node - it makes the password\'s hash')
    got = subprocess.run([exe, 'passwd', '-6', '-stdin'], input=pw + '\n', capture_output=True,
                         text=True, timeout=30)
    h = (got.stdout or '').strip()
    if got.returncode != 0 or not h.startswith('$6$'):
        raise ValueError('openssl did not make the password\'s hash: %s'
                         % ((got.stderr or '').strip()[:200] or 'no answer'))
    return h


def osu_free_uid(store, nodes, name):
    """One UID for the new user on every node: the one it has where it is there already, or the
    lowest of the normal range none of the nodes uses."""
    lo, hi, used = 1000, 60000, set()
    for n in nodes:
        now = osu_now(store, n)
        if not now.get('at'):
            raise ValueError('%s has not said who its users are yet - wait a few seconds' % n)
        lo = max(lo, int(now.get('uid_min') or 1000))
        hi = min(hi, int(now.get('uid_max') or 60000))
        used.update(int(u) for u in now.get('used') or [] if str(u).isdigit())
        for u in now.get('users') or []:
            if u.get('name') == name:
                return int(u['uid'])
    for uid in range(lo, hi + 1):
        if uid not in used:
            return uid
    raise ValueError('no UID of the normal range is free on %s' % ', '.join(nodes))


def osu_ask(store, nodes, do, by, **f):
    """One change asked of the nodes named - checked here, done by each node's root helper."""
    known = host_nodes(store)
    nodes = [n for n in known if n in (nodes or [])]
    if not nodes:
        raise ValueError('which node?')
    if do not in OSU_DOS:
        raise ValueError('no such thing to do with a user')
    name = str(f.get('name') or '')
    ask = {'do': do, 'by': by, 'at': time.time()}
    if do != 'list':
        if name == 'root':
            raise ValueError('root is shown here, never changed - on the machine itself only')
        if not SSH_USER_RE.match(name) or name in OSU_KEEP or name.lower() != name:
            raise ValueError('a user\'s name is small letters, digits, _ . and -, 32 at most, '
                             'starting with a letter - and not one of the system\'s')
        ask['name'] = name
        if do != 'add':
            # Only a user of the normal range the node said it has.
            for n in nodes:
                now = osu_now(store, n)
                if now.get('at') and not any(u.get('name') == name and not u.get('root')
                                             for u in now.get('users') or []):
                    if do != 'drop':
                        raise ValueError('%s has no user %s' % (n, name))
    if do in ('add', 'set'):
        if 'gecos' in f:
            g = str(f.get('gecos') or '').strip()
            if len(g) > 120 or re.search(r'[:\x00-\x1f\x7f]', g):
                raise ValueError('the full name is 120 characters at most, without a colon')
            ask['gecos'] = g
        if 'shell' in f:
            s = str(f.get('shell') or '')
            if not re.match(r'^/[A-Za-z0-9_./-]{1,80}\Z', s):
                raise ValueError('that is not a shell')
            ask['shell'] = s
    if do == 'add':
        ask['uid'] = osu_free_uid(store, nodes, name)
        ask['sudo'] = bool(f.get('sudo'))
        ask['must_change'] = bool(f.get('must_change'))
        if f.get('password'):
            ask['hash'] = seal_secret(osu_hash(f['password'], name), 'osuser:' + name)
        ask['aging'] = osu_aging()
    elif do == 'password':
        ask['hash'] = seal_secret(osu_hash(f.get('password'), name), 'osuser:' + name)
        ask['must_change'] = bool(f.get('must_change'))
        ask['aging'] = osu_aging()
    elif do == 'sudo':
        ask['on'] = bool(f.get('on'))
    elif do == 'drop':
        ask['home'] = bool(f.get('home'))
    for n in nodes:
        k = node_key('host:users:want', n)
        try:
            had = json.loads(store.get_meta(k) or '[]')
        except ValueError:
            had = []
        had = [x for x in (had if isinstance(had, list) else [had])
               if isinstance(x, dict) and time.time() - float(x.get('at') or 0) < 3600]
        had.append(dict(ask, id=secrets.token_hex(6)))
        store.set_meta(k, json.dumps(had[-20:]))
    if do != 'list':
        words = {'add': 'made the local user %s' % name,
                 'password': 'set a new password for the local user %s' % name,
                 'lock': 'locked the local user %s' % name,
                 'unlock': 'unlocked the local user %s' % name,
                 'sudo': '%s the local user %s sudo' % ('gave' if ask.get('on') else 'took from', name),
                 'set': 'changed the local user %s' % name,
                 'drop': 'took away the local user %s%s' % (name, ' and the home folder'
                                                             if ask.get('home') else '')}[do]
        if do == 'add':
            words += ' (UID %d%s%s)' % (ask['uid'], ', sudo' if ask['sudo'] else '',
                                        ', a password set' if ask.get('hash') else ', no password')
        store.add_event('settings', '%s %s on %s' % (by, words, ', '.join(nodes)), 'warn', who=by)
    return nodes


def osu_forget_hashes(store):
    """The hashes this node asked of the others, taken out of its own rows once done."""
    me = node_name()
    for n in host_nodes(store):
        k = node_key('host:users:want', n)
        try:
            had = json.loads(store.get_meta(k) or '[]')
        except ValueError:
            continue
        if not isinstance(had, list) or not any(isinstance(a, dict) and a.get('hash') for a in had):
            continue
        done = set(osu_now(store, n).get('done') or [])
        changed = False
        for a in had:
            if isinstance(a, dict) and a.get('hash') and (
                    a.get('id') in done or time.time() - float(a.get('at') or 0) > 900):
                a.pop('hash', None)
                a['hash_gone'] = True
                changed = True
        if changed:
            store.set_meta(k, json.dumps(had))


def osu_keep(row, got):
    row.update({k: got.get(k) for k in ('users', 'uid_min', 'uid_max', 'used', 'admin_group',
                                        'shells', 'today')})
    row['at'] = time.time()


def osu_one(a):
    """One change done by the root helper: its answer, or what went wrong (words)."""
    q = {k: v for k, v in a.items() if k in ('do', 'name', 'uid', 'gecos', 'shell', 'sudo',
                                              'must_change', 'on', 'home', 'aging', 'rules', 'sig')}
    if a.get('hash'):
        h = unseal_secret(a['hash'], 'osuser:' + str(a.get('name') or ''))
        if not str(a['hash']).startswith(SEALED2) or not h:
            return ('the password for %s could not be opened here - is the key that opens the '
                    'tokens the same on this node?' % a.get('name'))
        q['hash'] = h
    elif a.get('hash_gone'):
        return 'it came too late: the password for %s is no longer kept' % a.get('name')
    try:
        return root_ask('users.ask', 'users.json', q, 120)
    except Exception as e:                              # noqa: BLE001
        err = str(e)[:300] or e.__class__.__name__
        log('the local user %s: %s' % (a.get('name') or '?', err), 'warn')
        return err


def osu_tick(daemon):
    store = daemon.store
    me = node_name()
    try:
        osu_forget_hashes(store)
    except Exception as e:                              # noqa: BLE001
        log_sparing('osu-forget', 'the local users: %s' % e, 'warn', every=600)
    if OSU_WORK['busy'] and time.time() - OSU_WORK['since'] < 900:
        return
    now = osu_now(store, me)
    done = list(now.get('done') or [])
    todo = [a for a in osu_asks(store, me) if a['id'] not in done and
            time.time() - float(a.get('at') or 0) < 3600]
    todo.sort(key=lambda a: float(a.get('at') or 0))
    stale = time.time() - OSU_WORK['seen'] > 300 or not now
    # The password policy (1.0.42): put on this node whenever what it has is not what is asked -
    # once the users were read, and not again within ten minutes after it went wrong.
    pol_ask = osu_policy_ask()
    if (now.get('at') and not now.get('policy') and not now.get('policy_tried') and
            pol_ask['sig'] == osu_policy_ask(dict(osu_policy(), max_days=0, min_days=0,
                                                  warn_days=7, system=False))['sig']):
        # Never asked for, and nothing asked now: what the machine has is left as it is.
        now = dict(now, policy=pol_ask['sig'], policy_said='as the machine has it')
        store.set_meta('host:users:now:' + me, json.dumps(now))
    pol_due = (bool(now.get('at')) and now.get('policy') != pol_ask['sig'] and
               (now.get('policy_tried') != pol_ask['sig'] or
                time.time() - float(now.get('policy_tried_at') or 0) > 600))
    if not todo and not stale and not pol_due:
        return
    changes = [a for a in todo if a.get('do') != 'list']
    lists = [a for a in todo if a.get('do') == 'list']
    OSU_WORK.update(busy=True, since=time.time())

    def go():
        row = dict(now)
        said = list(row.get('said') or [])[-10:]
        try:
            for a in changes:
                err, got = osu_one(a), None
                if isinstance(err, dict):
                    got, err = err, ''
                done.append(a['id'])
                said.append({'at': time.time(), 'id': a['id'], 'do': a.get('do'),
                             'name': a.get('name') or '', 'by': a.get('by') or '',
                             'ok': not err, 'said': err or (got or {}).get('said') or ''})
                if got:
                    osu_keep(row, got)
                row.update(done=done[-300:], said=said[-10:])
                store.set_meta('host:users:now:' + me, json.dumps(row))
            if pol_due:
                row.update(policy_tried=pol_ask['sig'], policy_tried_at=time.time())
                got = osu_one(pol_ask)
                if isinstance(got, dict):
                    osu_keep(row, got)
                    row.update(policy=pol_ask['sig'], policy_said=got.get('said') or '')
                    log('the password policy of the local users put in: %s' % (got.get('said') or ''))
                else:
                    row['policy_said'] = 'not put in: %s' % got
                store.set_meta('host:users:now:' + me, json.dumps(row))
            try:
                osu_keep(row, root_ask('users.ask', 'users.json', {'do': 'list'}, 60))
                row['error'] = ''
            except Exception as e:                      # noqa: BLE001
                row['error'] = 'its users could not be read: %s' % (str(e)[:300] or
                                                                   e.__class__.__name__)
            done.extend(x['id'] for x in lists)
            row.update(done=done[-300:], said=said[-10:])
            store.set_meta('host:users:now:' + me, json.dumps(row))
            OSU_WORK['seen'] = time.time()
        except Exception as e:                          # noqa: BLE001
            log_sparing('osu', 'the local users: %s' % e)
        finally:
            OSU_WORK['busy'] = False
    threading.Thread(target=go, name='acme-osusers', daemon=True).start()


@route('GET', '/api/osusers')
def _osusers(h):
    h.me('fulladmin')
    return osu_view(h.store)


@route('POST', '/api/osusers')
def _osusers_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    nodes = b.get('nodes') or host_nodes(h.store)
    if not isinstance(nodes, list):
        raise ApiError(400, 'nodes is a list')
    if act == 'refresh':
        act = 'list'
    if act not in OSU_DOS:
        raise ApiError(400, 'no such thing to do with a user')
    f = {k: b[k] for k in ('name', 'gecos', 'shell', 'sudo', 'must_change', 'password', 'on', 'home')
         if k in b}
    try:
        done = osu_ask(h.store, nodes, act, s['name'], **f)
    except ValueError as e:
        raise ApiError(400, str(e))
    if act == 'list':
        return {'message': 'asked again', 'nodes': done}
    return {'message': 'done on %s within a few seconds' % ', '.join(done), 'nodes': done}
