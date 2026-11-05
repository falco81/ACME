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
            job = _meta_obj(h.store, 'net:job:' + node)
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
OSU_DOS = ('list', 'add', 'password', 'aging', 'lock', 'unlock', 'sudo', 'set', 'drop')
OSU_PW_MIN = 8


def osu_now(store, n):
    # Only an object (1.0.45): a row of another shape made every look fail - "'str' object has
    # no attribute 'get'" every few seconds - and was never written anew. Taken as none: the
    # node writes it again at its next look.
    got = _meta_json(store, 'host:users:now:' + n)
    return got if isinstance(got, dict) else {}


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
                      # Who its machine had before it was built again (1.0.43).
                      'before': (_meta_obj(store, 'host:users:before:' + n)).get('users') or [],
                      'admin_group': now.get('admin_group') or '', 'shells': now.get('shells') or [],
                      'uid_min': now.get('uid_min'), 'uid_max': now.get('uid_max'),
                      'today': now.get('today'), 'said': now.get('said') or [],
                      'error': now.get('error') or ('%d change(s) asked of it more than five minutes '
                                                    'ago are not done - is acme-web.path running '
                                                    'there?' % late if late else ''),
                      'pending': pending})
    pol = pwp_conf(store)
    want = pwp_want(store, pol)
    for x in nodes:
        now = osu_now(store, x['name'])
        # What each node has in effect, read from its files - and whether it put in this one.
        x['policy'] = now.get('policy') if isinstance(now.get('policy'), dict) else None
        x['policy_applied'] = now.get('policy_hash') == want
        x['policy_said'] = now.get('policy_said') or ''
        x['policy_error'] = now.get('policy_error') or ''
    return {'nodes': nodes, 'cluster': len(nodes) > 1,
            'pw_min': max(OSU_PW_MIN, pol['minlen'] if pol['managed'] else OSU_PW_MIN),
            'policy': pol, 'policy_refused': pwp_refused(store),
            'openssl': bool(shutil.which('openssl'))}


# ---- the password policy of the local users (1.0.43, as otp 1.0.245) --------------------------
PWP_DEFAULT = {'managed': False, 'minlen': 12, 'minclass': 3, 'maxrepeat': 3, 'dictcheck': 1,
               'usercheck': 1, 'difok': 5, 'remember': 5, 'max_days': 99999, 'min_days': 0,
               'warn_days': 7, 'deny': 0, 'unlock_time': 900, 'fail_interval': 900, 'existing': False}
PWP_RANGES = {'minlen': (6, 128), 'minclass': (0, 4), 'maxrepeat': (0, 20), 'difok': (0, 20),
              'remember': (0, 50), 'max_days': (0, 99999), 'min_days': (0, 365), 'warn_days': (0, 365),
              'deny': (0, 100), 'unlock_time': (0, 86400), 'fail_interval': (60, 86400)}


def osu_coded(store):
    """Who SSH asks a code of (1.0.44): left out of the policy's aging unless they may use sudo
    (the root helper knows who has sudo). {'all': True} while it is everybody but root."""
    try:
        c = sshd_conf(store)
    except Exception:                                   # noqa: BLE001
        c = {}
    if not (c.get('manage') and c.get('radius')):
        return {'all': False, 'names': []}
    names = sorted(str(n) for n in (c.get('radius_users') or []) if n != 'root')
    return {'all': not names, 'names': names}


def pwp_want(store, pol):
    """What a node must have put in: the policy - and, with it put on the users there now, who
    SSH asks a code of (1.0.44): a change there is put in again."""
    h = pwp_hash(pol)
    if pol.get('managed') and pol.get('existing'):
        sp = osu_coded(store)
        if sp['all'] or sp['names']:
            h += ':' + hashlib.sha256(json.dumps(sp, sort_keys=True).encode()).hexdigest()[:8]
    return h


def pwp_conf(store):
    """The password policy of the local users as set for the cluster; not managed - the system's
    own, untouched - until set."""
    c = dict(PWP_DEFAULT)
    c.update({k: v for k, v in (_meta_obj(store, 'host:pwpolicy:conf')).items() if k in PWP_DEFAULT})
    return c


def pwp_refused(store):
    """The policy's row there but not taken: the guard of root's actions refused it - not acme's
    word. A node then keeps the policy it has put in, and changes nothing - a row written
    straight into the database must not take the policy away either."""
    try:
        there = store.db.rows("SELECT k FROM meta WHERE k = 'host:pwpolicy:conf'")
    except Exception:                                   # noqa: BLE001
        return False
    return bool(there) and _meta_json(store, 'host:pwpolicy:conf') is None


def pwp_hash(c):
    return hashlib.sha256(json.dumps({k: c.get(k) for k in sorted(PWP_DEFAULT)},
                                     sort_keys=True).encode()).hexdigest()[:16]


def pwp_checked_api(b):
    c = dict(PWP_DEFAULT)
    if not isinstance(b, dict):
        raise ValueError('the policy is an object')
    for k in PWP_DEFAULT:
        if k not in b:
            continue
        if k in PWP_RANGES:
            try:
                v = int(b[k])
            except (TypeError, ValueError):
                raise ValueError('%s is a number' % k)
            lo, hi = PWP_RANGES[k]
            if not lo <= v <= hi:
                raise ValueError('%s is %d to %d' % (k, lo, hi))
            c[k] = v
        else:
            c[k] = bool(b[k]) if k in ('managed', 'existing') else (1 if b[k] else 0)
    if c['min_days'] and c['max_days'] < 99999 and c['min_days'] > c['max_days']:
        raise ValueError('the least days between two changes is more than the days a password is good')
    return c


def pwp_aging(c):
    """The policy's aging for a user given a password (made with one, or a new one)."""
    if not c.get('managed'):
        return None
    return {'max_days': c['max_days'], 'min_days': c['min_days'], 'warn_days': c['warn_days']}


def pwp_password_check(store, password, name):
    """A password set from these pages kept to the policy: by pwscore (the system's own rules and
    its dictionary) where it is there, by the rules set here where it is not."""
    c = pwp_conf(store)
    if pwp_refused(store):
        # Its row not acme's: checked by what this node has put in, as its files say.
        p = osu_now(store, node_name()).get('policy')     # a text in a row of 1.0.42
        q = (p if isinstance(p, dict) else {}).get('pwquality') or {}
        q = q if isinstance(q, dict) else {}
        c = dict(c, managed=True, minlen=int(q.get('minlen') or 8), minclass=int(q.get('minclass') or 0),
                 maxrepeat=int(q.get('maxrepeat') or 0), usercheck=int(q.get('usercheck') or 0))
    if not c['managed']:
        return
    exe = shutil.which('pwscore')
    if exe:
        got = subprocess.run([exe, name], input=password + '\n', capture_output=True, text=True,
                             timeout=30)
        if got.returncode != 0:
            why = ((got.stderr or got.stdout or '').strip().splitlines() or ['refused'])[-1]
            why = re.sub(r'^Password quality check failed:\s*', '', why)
            raise ValueError('the password policy does not take it: %s' % why[:200])
        return
    if len(password) < c['minlen']:
        raise ValueError('the password policy wants %d characters at least' % c['minlen'])
    kinds = sum(1 for rx in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]') if re.search(rx, password))
    if kinds < c['minclass']:
        raise ValueError('the password policy wants %d kinds of characters at least (small '
                         'letters, capitals, digits, others) - it has %d' % (c['minclass'], kinds))
    if c['maxrepeat'] and re.search(r'(.)\1{%d,}' % c['maxrepeat'], password):
        raise ValueError('the password policy takes no character more than %d times in a row'
                         % c['maxrepeat'])
    if c['usercheck'] and name and len(name) >= 3 and name.lower() in password.lower():
        raise ValueError('the password policy takes no password with the user\'s name in it')


def pwp_migrate(store):
    """acme 1.0.42's own password policy (settings osu_pw_*) taken into the policy of otp's shape
    once (1.0.43): set there, it is managed with the same rules."""
    # A mark of its own (1.0.44): 1.0.43 set 'pwpolicy:migrated' before its narrower look, and
    # a policy of only the days between changes was never taken over where it had run.
    if store.get_meta('host:pwpolicy:conf') is not None or store.get_meta('pwpolicy:migrated:2'):
        return False
    try:
        saved = store.settings_saved()
    except Exception:                                   # noqa: BLE001
        return False

    def g(k, d):
        try:
            return int(saved.get(k)) if saved.get(k) not in (None, '') else d
        except (TypeError, ValueError):
            return d
    mx, mn, cl = g('osu_pw_max_days', 0), g('osu_pw_min', 8), g('osu_pw_classes', 1)
    system = g('osu_pw_system', 0)
    store.set_meta('pwpolicy:migrated:2', '%.0f' % time.time())
    # Any rule of 1.0.42's set (1.0.44: the days between changes, or the warning, alone too).
    if not (mx > 0 or mn > 8 or cl > 1 or system or g('osu_pw_min_days', 0) > 0 or
            g('osu_pw_warn_days', 7) != 7 or not g('osu_pw_not_name', 1)):
        return False
    c = dict(PWP_DEFAULT, managed=True, minlen=max(6, min(128, mn)), minclass=max(0, min(4, cl)),
             usercheck=1 if g('osu_pw_not_name', 1) else 0, maxrepeat=0, difok=1, remember=0,
             dictcheck=0, max_days=mx if mx > 0 else 99999, min_days=max(0, min(365, g('osu_pw_min_days', 0))),
             warn_days=max(0, min(365, g('osu_pw_warn_days', 7))), existing=mx > 0)
    store.set_meta('host:pwpolicy:conf', json.dumps(dict(c, at=time.time(), by='acme 1.0.43')))
    store.add_event('settings', 'the password policy of the local users of acme 1.0.42 is set as '
                    'the policy of Settings -> Local users -> Password policy: at least %d characters, '
                    '%d kinds, %s' % (c['minlen'], c['minclass'], 'good for %d days' % c['max_days']
                                      if c['max_days'] < 99999 else 'no end'), 'warn')
    return True


def osu_hash(password, name='', store=None):
    """The SHA-512 crypt hash of a password, by openssl from its standard input - kept to the
    password policy of the local users first (1.0.43)."""
    pw = str(password or '')
    if len(pw) < OSU_PW_MIN:
        raise ValueError('the password is %d characters at least' % OSU_PW_MIN)
    if store is not None:
        pwp_password_check(store, pw, name)
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


def osu_free_uid(store, nodes, name, want=None):
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
    # The same UID as on the other nodes of the cluster, where the user is (1.0.44): made on one
    # node only (Make them again), it got the lowest free one there - another than its twin's.
    for n in host_nodes(store):
        for u in osu_now(store, n).get('users') or []:
            if u.get('name') == name and str(u.get('uid') or '').isdigit():
                if int(u['uid']) in used:
                    raise ValueError('%s has UID %s on %s, which is another user\'s on %s' % (
                        name, u['uid'], n, ', '.join(nodes)))
                return int(u['uid'])
    # The one asked for (the UID it had before its machine was built again), if it is free.
    if want not in (None, ''):
        try:
            want = int(want)
        except (TypeError, ValueError):
            raise ValueError('a UID is a number')
        if not lo <= want <= hi:
            raise ValueError('UID %d is not one of a normal user (%d to %d)' % (want, lo, hi))
        if want in used:
            raise ValueError('UID %d is another user\'s on %s' % (want, ', '.join(nodes)))
        return want
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
        ask['uid'] = osu_free_uid(store, nodes, name, want=f.get('uid'))
        ask['sudo'] = bool(f.get('sudo'))
        ask['must_change'] = bool(f.get('must_change'))
        if ask['sudo'] and not f.get('password'):
            # sudo asks for the user's own password (as otp 1.0.246).
            raise ValueError('sudo asks for the user\'s own password - give them one, or they '
                             'cannot use sudo')
        if f.get('password'):
            ask['hash'] = seal_secret(osu_hash(f['password'], name, store), 'osuser:' + name)
            pa = pwp_aging(pwp_conf(store))
            if pa:
                ask['policy_aging'] = pa
                ask['spare'] = osu_coded(store)
    elif do == 'password':
        ask['hash'] = seal_secret(osu_hash(f.get('password'), name, store), 'osuser:' + name)
        ask['must_change'] = bool(f.get('must_change'))
        pa = pwp_aging(pwp_conf(store))
        if pa:
            ask['policy_aging'] = pa
            ask['spare'] = osu_coded(store)
    elif do == 'aging':
        a = {}
        for k, lo, hi in (('max_days', 0, 99999), ('min_days', 0, 365), ('warn_days', 0, 365)):
            try:
                v = int(f.get(k))
            except (TypeError, ValueError):
                raise ValueError('%s is a number' % k)
            if not lo <= v <= hi:
                raise ValueError('%s is %d to %d' % (k, lo, hi))
            a[k] = v
        if a['min_days'] and a['max_days'] < 99999 and a['min_days'] > a['max_days']:
            raise ValueError('the least days between two changes is more than the days a password is good')
        ask['aging'] = a
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
                 'aging': 'set the password aging of the local user %s (%s days, %s before, %s '
                          'between)' % (name, ask.get('aging', {}).get('max_days'),
                                        ask.get('aging', {}).get('warn_days'),
                                        ask.get('aging', {}).get('min_days')),
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


def osu_remake(store, node, names, by, forget=False):
    """The users a node's machine had before it was built again (1.0.43), made again on it -
    the same name, UID, full name, shell and sudo, no password (none is kept anywhere: given
    one on Local users, or a key on SSH keys). Or that list forgotten."""
    if node not in host_nodes(store):
        raise ValueError('which node?')
    k = 'host:users:before:' + node
    had = _meta_obj(store, k)
    users = had.get('users') or []
    if forget:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
        return {'message': 'forgotten', 'made': []}
    want = set(names) if isinstance(names, list) and names else None
    there = {u.get('name') for u in osu_now(store, node).get('users') or []}
    made, said, sudo_later = [], [], []
    for u in users:
        n = u.get('name')
        if not n or (want is not None and n not in want) or n in there:
            continue
        try:
            # sudo asks for the user's own password, and none is kept (1.0.43): made without it,
            # given once they have a password again.
            osu_ask(store, [node], 'add', by, name=n, gecos=u.get('gecos') or '',
                    shell=u.get('shell') or '/bin/bash', sudo=False, uid=u.get('uid'))
            made.append(n)
            if u.get('sudo'):
                sudo_later.append(n)
        except ValueError as e:
            said.append('%s: %s' % (n, e))
    left = [u for u in users if u.get('name') not in set(made) | there]
    if left:
        store.set_meta(k, json.dumps(dict(had, users=left)))
    else:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
    msg = ('made again on %s: %s - each with no password' % (node, ', '.join(made))) if made \
        else 'nothing made'
    if sudo_later:
        msg += '; sudo again once they have a password: ' + ', '.join(sudo_later)
    if said:
        msg += '; not: ' + '; '.join(said)
    return {'message': msg, 'made': made}


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
    if not isinstance(got, dict):
        raise ValueError('the root helper said no list of users (%s)' % type(got).__name__)
    row.update({k: got.get(k) for k in ('users', 'uid_min', 'uid_max', 'used', 'admin_group',
                                        'shells', 'today', 'policy')})
    row['at'] = time.time()


def osu_one(a):
    """One change done by the root helper: its answer, or what went wrong (words)."""
    q = {k: v for k, v in a.items() if k in ('do', 'name', 'uid', 'gecos', 'shell', 'sudo',
                                              'must_change', 'on', 'home', 'aging', 'policy_aging',
                                              'spare',
                                              'conf')}
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
    # The password policy (1.0.43, as otp 1.0.245): put in when it is not what this node has done
    # last - tried again in ten minutes when the helper refused it; never on a row the guard
    # refused (pwp_refused). A row of this node forgotten (a new machine, MACHINE_ROWS) has no
    # policy_hash: put in again there.
    pol = pwp_conf(store)
    want = pwp_want(store, pol)
    policy_due = bool(now.get('at')) and now.get('policy_hash') != want and (
        now.get('policy_tried') != want or time.time() - float(now.get('policy_at') or 0) > 600) and \
        not pwp_refused(store)
    if not pol['managed'] and not now.get('policy_hash') and not now.get('policy_tried') and \
            not (now.get('policy') if isinstance(now.get('policy'), dict) else {}).get('managed'):
        # Never set, and nothing of acme's on the machine: nothing to put in or take out - in
        # effect as set (the system's own) without asking the helper.
        policy_due = False
        if now.get('at'):
            now = dict(now, policy_hash=want, policy_said='the system\'s own', policy_error='')
            store.set_meta('host:users:now:' + me, json.dumps(now))
    if not todo and not stale and not policy_due:
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
            if policy_due:
                row.update(policy_tried=want, policy_at=time.time())
                got = osu_one({'do': 'policy', 'conf': pol, 'spare': osu_coded(store)})
                if isinstance(got, dict):
                    osu_keep(row, got)
                    row.update(policy_hash=want, policy_said=got.get('said') or '', policy_error='')
                    log('the password policy of the local users put in: %s' % (got.get('said') or 'done'))
                else:
                    row['policy_error'] = str(got)[:300]
                    log('the password policy of the local users: %s' % row['policy_error'], 'warn')
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
    if act in ('remake', 'remake-forget'):
        try:
            return osu_remake(h.store, str(b.get('node') or ''), b.get('names'), s['name'],
                              forget=act == 'remake-forget')
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'policy':
        try:
            c = pwp_checked_api(b.get('policy') or {})
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.set_meta('host:pwpolicy:conf', json.dumps(dict(c, at=time.time(), by=s['name'])))
        h.store.add_event('settings', '%s %s the password policy of the local users%s' % (
            s['name'], 'set' if c['managed'] else 'gave back to the system',
            (': at least %d characters, %d kinds, %s, history %d, %s' % (
                c['minlen'], c['minclass'], 'good for %d days' % c['max_days'] if c['max_days'] < 99999
                else 'no end', c['remember'], 'locked after %d wrong' % c['deny'] if c['deny']
                else 'no lockout')) if c['managed'] else ''), 'warn', who=s['name'])
        return {'message': 'each node puts it in within a few seconds', 'policy': c}
    if act not in OSU_DOS:
        raise ApiError(400, 'no such thing to do with a user')
    f = {k: b[k] for k in ('name', 'gecos', 'shell', 'sudo', 'must_change', 'password', 'on', 'home',
                           'max_days', 'min_days', 'warn_days')
         if k in b}
    try:
        done = osu_ask(h.store, nodes, act, s['name'], **f)
    except ValueError as e:
        raise ApiError(400, str(e))
    if act == 'list':
        return {'message': 'asked again', 'nodes': done}
    return {'message': 'done on %s within a few seconds' % ', '.join(done), 'nodes': done}
