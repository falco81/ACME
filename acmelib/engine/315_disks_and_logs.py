# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- disks and logs (1.0.166) ------------------------------------------------------
# Settings → Disks and logs: how much systemd's journal may take and for how
# long, and how many of acme's own log files logrotate keeps - the same for
# every node, each node putting it in on its own machine through its root
# helper (logs.ask): journald.conf.d/00-acme.conf and /etc/logrotate.d/acme.
# Asked again when the settings change, and every 6 hours to read how much
# the journal and the logs take now. Done in the alerts' thread: never on
# the way of a sign-in.
LOGS_EVERY = 6 * 3600
LOGS_WORK = {'at': 0.0, 'hash': '', 'again': ''}
LOGS_LOCK = threading.Lock()


def logs_desired():
    return {'journal_mb': int(CONFIG.get('logs_journal_mb') or 0),
            'journal_days': int(CONFIG.get('logs_journal_days') or 0),
            'keep': int(CONFIG.get('logs_keep') or 30),
            'max_mb': int(CONFIG.get('logs_max_mb') or 200)}


def logs_hash(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]


def dir_size(path, most=200000):
    total, n = 0, 0
    for top, _dirs, files in os.walk(str(path)):
        for f in files:
            n += 1
            if n > most:
                return total
            try:
                total += os.lstat(os.path.join(top, f)).st_size
            except OSError:
                pass
    return total


def logs_start(daemon):
    """logs_tick in a thread of its own: the helper may take its time (90 s
    when it does not answer) and the alerts never wait for it."""
    if LOGS_WORK.get('busy'):
        return
    LOGS_WORK['busy'] = True

    def go():
        try:
            logs_tick(daemon)
        except Exception as e:                          # noqa: BLE001
            log_sparing('logs', 'the journal and the logs: %s' % e, 'warn', every=900)
        finally:
            LOGS_WORK['busy'] = False
    threading.Thread(target=go, name='acme-logs', daemon=True).start()


def logs_tick(daemon, force=False):
    """This node's journal and logrotate as the settings say; what they take."""
    with LOGS_LOCK:
        return _logs_tick(daemon, force)


def _logs_tick(daemon, force):
    store = daemon.store
    want = logs_desired()
    h = logs_hash(want)
    again = store.get_meta('host:logs:again') or ''
    k = 'host:logs:' + node_name()
    row = _meta_obj(store, k)
    age = time.time() - float(row.get('at') or 0)
    if force or again != LOGS_WORK['again'] or row.get('hash') != h:
        pass
    elif age < (LOGS_EVERY if row.get('ok') else 600):
        return row
    LOGS_WORK['again'] = again
    out = {'at': time.time(), 'hash': h, 'want': want, 'ok': False,
           'logdir': dir_size(LOG_DIR), 'state': dir_size(STATE_DIR)}
    try:
        got = root_ask('logs.ask', 'logs.ans', dict(want, do='apply'), wait=90)
        out.update(ok=True, **{x: got.get(x) for x in ('journal_use', 'journal_conf',
                                                       'rotate_conf', 'said')})
    except ValueError as e:
        out['said'] = str(e)[:300]
    store.set_meta(k, json.dumps(out))
    if row.get('hash') and row.get('hash') != h and out['ok']:
        log('the journal and the logs set as Settings say: %s' % json.dumps(want))
    return out


def logs_view(store):
    nodes = [n['name'] for n in ha_nodes(store)] if CONFIG.get('ha_mode') else [node_name()]
    want = logs_desired()
    h = logs_hash(want)
    out = []
    for n in nodes:
        row = _meta_obj(store, 'host:logs:' + n)
        health = _meta_obj(store, 'host:health:' + n)
        out.append({'node': n, 'me': n == node_name(), 'disks': health.get('disks') or [],
                    'health_at': health.get('at'), 'at': row.get('at'), 'ok': row.get('ok'),
                    'said': row.get('said') or '', 'current': row.get('hash') == h,
                    'journal_use': row.get('journal_use'), 'logdir': row.get('logdir'),
                    'state': row.get('state'), 'siem': health.get('siem') or {}})
    return {'nodes': out, 'want': want, 'disk_pct': int(CONFIG.get('alerts_disk_pct') or 0)}


# ---- root's SSH keys and the updates of the system (1.0.158) ------------------------
# Both done by each node's root helper (acme_web.py), asked through the
# database so a page on either node reaches both. One writer a row, as
# replication wants: what is asked of a node is in a row of the asking node's
# own ('host:sshkeys:want:NODE@@ASKER', node_key) and the node answers in rows
# of its own ('host:sshkeys:now:NODE', 'host:osup:node:NODE').
HOST_WORK = {'ssh': False, 'ssh_seen': 0.0, 'ssh_since': 0.0, 'osup': False, 'osup_read': 0.0}


def host_nodes(store):
    return [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]


def host_alive(store):
    """{node: whether it is heard from}."""
    out = {node_name(): True}
    for n in ha_nodes(store):
        if n['name'] != node_name():
            out[n['name']] = bool(n.get('alive'))
    return out


# -- the keys --------------------------------------------------------------------------
def sshkeys_view(store):
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        now = _meta_obj(store, 'host:sshkeys:now:' + n)
        done = set(now.get('done') or [])
        pending = late = 0
        for r in node_key_rows(store, 'host:sshkeys:want', n):
            try:
                asks = json.loads(r['v'] or '[]')
            except ValueError:
                continue
            for a in asks if isinstance(asks, list) else [asks]:
                # A change still to be written - a read again is no change,
                # and one not done in five minutes is not still coming (1.0.159).
                if isinstance(a, dict) and a.get('id') and a['id'] not in done and \
                        a.get('do') in ('add', 'drop') and time.time() - float(a.get('at') or 0) < 300:
                    pending += 1
                elif isinstance(a, dict) and a.get('id') and a['id'] not in done and \
                        a.get('do') in ('add', 'drop') and time.time() - float(a.get('at') or 0) < 3600:
                    late += 1
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'keys': now.get('keys') or [], 'sshd': now.get('sshd') or {},
                      # The normal users who may sign in there, and the keys of those read (1.0.240).
                      'users': now.get('users') or [], 'keys_of': now.get('keys_of') or {},
                      'file': now.get('file') or '', 'at': now.get('at'),
                      # The keys of root its machine had before it was built again (1.0.43).
                      'before': (_meta_obj(store, 'host:sshkeys:before:' + n)).get('keys') or [],
                      'error': now.get('error') or ('%d change(s) asked of it more than five minutes ago '
                                                    'are not written - is acme-web.path running there?' % late
                                                    if late else ''),
                      'pending': pending})
    return {'nodes': nodes, 'keygen': bool(shutil.which('ssh-keygen')),
            'cluster': len(nodes) > 1,
            'kept': rootkey_view(store, {n['name']: n['keys'] for n in nodes})}


SSH_USER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z')


def sshkeys_ask(store, nodes, do, by, line='', fp='', last_ok=False, user='root'):
    user = str(user or 'root')
    if not SSH_USER_RE.match(user):
        raise ValueError('that is not the name of a user')
    known = host_nodes(store)
    nodes = [n for n in known if n in (nodes or [])]
    if not nodes:
        raise ValueError('which node?')
    if do not in ('list', 'add', 'drop'):
        raise ValueError('list, add or drop')
    line = str(line or '').strip()
    if do == 'add' and (len(line) > 16500 or '\n' in line):
        raise ValueError('one public key line')
    for n in nodes:
        # One row per asked node and asking node, kept to the last few asks.
        k = node_key('host:sshkeys:want', n)
        try:
            had = json.loads(store.get_meta(k) or '[]')
        except ValueError:
            had = []
        if isinstance(had, dict):
            had = [had]
        had = [x for x in had if isinstance(x, dict) and time.time() - float(x.get('at') or 0) < 3600]
        had.append({'id': secrets.token_hex(6), 'do': do, 'line': line, 'fp': str(fp or '')[:80],
                    'last_ok': bool(last_ok), 'by': by, 'at': time.time(), 'user': user})
        store.set_meta(k, json.dumps(had[-10:]))
    if do != 'list':
        what = 'added the SSH key %s' % (line.split(' ', 2)[2] if line.count(' ') >= 2 else
                                         line[:40]) if do == 'add' else 'took away the SSH key %s' % fp
        store.add_event('settings', '%s %s for %s on %s' % (by, what, user, ', '.join(nodes)),
                        'warn', who=by)
    return nodes


def sshkeys_tick(daemon):
    store = daemon.store
    me = node_name()
    # Built again on another machine (1.0.43): the keys of root made on these pages put on again.
    if store.get_meta('host:rootkey:again:' + me):
        try:
            for sc in rootkey_scopes(store):
                r = rootkey_row(store, sc)
                if r.get('pub') and me in rootkey_nodes(store, sc):
                    sshkeys_ask(store, [me], 'add', 'acme (the machine built again)', line=r['pub'])
            meta_drop(store, 'host:rootkey:again:' + me)       # and its signatures (1.0.58)
        except Exception as e:                          # noqa: BLE001
            log_sparing('rootkey-again', 'the keys of root could not be put on again: %s' % e,
                        'warn', every=600)
    if HOST_WORK['ssh'] and time.time() - HOST_WORK.get('ssh_since', 0) < 900:
        return
    now = _meta_obj(store, 'host:sshkeys:now:' + me)
    done = list(now.get('done') or [])
    todo = []
    for r in node_key_rows(store, 'host:sshkeys:want', me):
        try:
            asks = json.loads(r['v'] or '[]')
        except ValueError:
            continue
        for a in asks if isinstance(asks, list) else [asks]:
            if isinstance(a, dict) and a.get('id') and a['id'] not in done and \
                    time.time() - float(a.get('at') or 0) < 3600:
                todo.append(a)
    todo.sort(key=lambda a: float(a.get('at') or 0))
    stale = time.time() - HOST_WORK['ssh_seen'] > 300 or not now
    if not todo and not stale:
        return
    HOST_WORK['ssh'] = True
    HOST_WORK['ssh_since'] = time.time()
    # Reads asked again and again are one read (1.0.159) - one for each user (1.0.240).
    lists = [a for a in todo if a.get('do') == 'list']
    last_list = {}
    for a in lists:
        last_list[str(a.get('user') or 'root')] = a
    todo = [a for a in todo if a.get('do') != 'list'] + sorted(
        last_list.values(), key=lambda a: float(a.get('at') or 0))

    def go():
        row = dict(now)
        changed_err = ''
        try:
            for a in todo or [{'id': '', 'do': 'list'}]:
                err, got = '', None
                user = str(a.get('user') or 'root')
                try:
                    got = root_ask('sshkeys.ask', 'sshkeys.json', {
                        'do': a.get('do'), 'line': a.get('line') or '', 'fp': a.get('fp') or '',
                        'last_ok': bool(a.get('last_ok')), 'user': user}, 60)
                except Exception as e:                  # noqa: BLE001
                    err = str(e)[:300] or e.__class__.__name__
                    log('the SSH keys of %s: %s' % (user, err), 'warn')
                if a.get('id'):
                    done.append(a['id'])
                done.extend(x['id'] for x in lists if x.get('id') and x['id'] not in done)
                if user != 'root':
                    # A normal user's (1.0.240): kept apart, root's as they are; the last 30 read.
                    of = row.get('keys_of')
                    of = dict(of) if isinstance(of, dict) else {}
                    mine = of.get(user)
                    mine = dict(mine) if isinstance(mine, dict) else {}
                    mine.update(at=time.time(), error=err)
                    if got:
                        mine.update(keys=got.get('keys') or [], file=got.get('file') or '')
                    of[user] = mine
                    if len(of) > 30:
                        for k in sorted(of, key=lambda k: float(of[k].get('at') or 0))[:len(of) - 30]:
                            of.pop(k, None)
                    row.update(keys_of=of, at=time.time(), done=done[-200:])
                    if got:
                        row.update(users=got.get('users') or [], sshd=got.get('sshd') or row.get('sshd') or {})
                    store.set_meta('host:sshkeys:now:' + me, json.dumps(row))
                    continue
                # Written after each, so what is done shows as it is done.
                # A change refused stays said over the read after it.
                if err or a.get('do') != 'list' or not changed_err:
                    row['error'] = err
                if a.get('do') != 'list':
                    changed_err = err
                row.update(at=time.time(), done=done[-200:])
                if got:
                    row.update(keys=got.get('keys') or [], sshd=got.get('sshd') or {},
                               file=got.get('file') or '', users=got.get('users') or [])
                store.set_meta('host:sshkeys:now:' + me, json.dumps(row))
            HOST_WORK['ssh_seen'] = time.time()
        except Exception as e:                          # noqa: BLE001
            log_sparing('sshkeys', 'root\'s SSH keys: %s' % e)
        finally:
            HOST_WORK['ssh'] = False
    threading.Thread(target=go, name='acme-sshkeys', daemon=True).start()


# -- root's key, made or given here (1.0.159) -------------------------------------------
# Drawn as isemon draws a router's key, but kept nowhere: acme never signs in
# as root itself, so a private half in the database would only be one more
# way to root on every node. A key made here is handed to the page once; one
# given has its public half worked out and its private half dropped. What is
# remembered of each - for every node ('all') or for one node - is its public
# half, to show it and put it on again where it is missing.


SSH_KEY_KINDS = {'ed25519': ['-t', 'ed25519'], 'rsa4096': ['-t', 'rsa', '-b', '4096']}


def sshkey_pair(kind, comment):
    """A new key pair made by ssh-keygen in a folder of its own, taken away
    after: (private, public, fingerprint)."""
    if kind not in SSH_KEY_KINDS:
        raise ValueError('ed25519 or rsa4096')
    if not shutil.which('ssh-keygen'):
        raise ValueError('ssh-keygen is not on this machine (dnf install openssh-clients)')
    comment = re.sub(r'[^A-Za-z0-9@._ -]', '', str(comment or ''))[:80].strip() or 'root'
    with tempfile.TemporaryDirectory(prefix='.acme-key-') as work:
        path = os.path.join(work, 'k')
        got = subprocess.run(['ssh-keygen', '-q'] + SSH_KEY_KINDS[kind] +
                             ['-a', '100', '-N', '', '-C', comment, '-f', path],
                             capture_output=True, text=True, timeout=120)
        if got.returncode != 0:
            raise ValueError('ssh-keygen: %s' % (got.stderr or got.stdout).strip()[:200])
        with open(path) as f:
            private = f.read()
        with open(path + '.pub') as f:
            public = f.read().strip()
    return private, public, ssh_fp_of(public)[0]


def rootkey_scopes(store):
    return ['all'] + (host_nodes(store) if CONFIG.get('ha_mode') or len(host_nodes(store)) > 1 else [])


def rootkey_nodes(store, scope):
    return host_nodes(store) if scope == 'all' else [scope]


def rootkey_row(store, scope):
    return _meta_obj(store, 'host:rootkey:' + scope)


def _rootkey_scope(store, scope):
    scope = str(scope or 'all')
    if scope not in rootkey_scopes(store):
        raise ValueError('for every node, or for one of them')
    return scope


def ssh_fp_of(public):
    got = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], input=public + '\n',
                         capture_output=True, text=True, timeout=20)
    bits = got.stdout.split()
    if got.returncode != 0 or len(bits) < 2:
        raise ValueError('ssh-keygen does not read that key')
    return bits[1], bits[-1].strip('()') if bits[-1].startswith('(') else ''


def rootkey_view(store, keys_on):
    out = []
    for sc in rootkey_scopes(store):
        r = rootkey_row(store, sc)
        on = {n: any(k.get('fp') == r.get('fp') for k in keys_on.get(n, [])) if r.get('fp') else False
              for n in rootkey_nodes(store, sc)}
        out.append({'scope': sc, 'has': bool(r.get('pub')), 'pub': r.get('pub') or '',
                    'fp': r.get('fp') or '', 'kind': r.get('kind') or '', 'how': r.get('how') or '',
                    'by': r.get('by') or '', 'at': r.get('at'), 'on': on})
    return out


def rootkey_put(store, scope, public, by, how):
    """A public half onto the nodes of a scope, remembered for it. The key put
    there before stays - it is taken away in the list, if it should go."""
    scope = _rootkey_scope(store, scope)
    fp, kind = ssh_fp_of(public)
    nodes = rootkey_nodes(store, scope)
    sshkeys_ask(store, nodes, 'add', by, line=public)
    store.set_meta('host:rootkey:' + scope, json.dumps({
        'scope': scope, 'pub': public, 'fp': fp, 'kind': kind, 'how': how, 'by': by,
        'at': time.time()}))
    return {'pub': public, 'fp': fp, 'nodes': nodes}


def rootkey_public(text, passphrase=''):
    """What the page was given: a public key line as it is, or a private key's
    public half - the private half dropped."""
    text = str(text or '').strip()
    if 'PRIVATE KEY-----' in text:
        _, public = ssh_public_of(text, passphrase)
        return public, True
    line = text.splitlines()[0].strip() if text else ''
    if not re.match(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|'
                    r'sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{20,}( [^\r\n]{0,200})?$', line):
        raise ValueError('that is not a public key line (ssh-ed25519 AAAA… comment) nor a private key')
    return line, False


def rootkey_again(store, scope, by):
    scope = _rootkey_scope(store, scope)
    r = rootkey_row(store, scope)
    if not r.get('pub'):
        raise ValueError('there is no key made or given for that')
    return sshkeys_ask(store, rootkey_nodes(store, scope), 'add', by, line=r['pub'])


# -- the updates -----------------------------------------------------------------------
OSUP_STATES = ('waiting', 'draining', 'updating', 'rebooting', 'done', 'failed', 'skipped')


def osup_plan(store):
    return _meta_obj(store, 'host:osup:plan')


def osup_row(store, name):
    return _meta_obj(store, 'host:osup:node:' + name)


def osup_put(store, row, **kw):
    row.update(kw, at=time.time())
    store.set_meta('host:osup:node:' + node_name(), json.dumps(row))
    return row


def osup_view(store):
    plan = osup_plan(store)
    seen = store.get_meta('host:osup:seen')
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        row = osup_row(store, n)
        chk = _meta_obj(store, 'host:osup:check:' + n)
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'row': row if row.get('plan') == plan.get('id') else {},
                      'check': chk, 'reboot': bool(row.get('reboot') and not row.get('rebooted')) or
                      bool(chk.get('reboot_now') and chk.get('state') == 'done'),
                      'started': (_meta_obj(store, 'node:' + n)).get('started')})
    _osup_cleared(store, nodes)
    hidden = bool(plan) and seen == plan.get('id') and plan.get('state') != 'running'
    return {'plan': {} if hidden else plan, 'nodes': nodes, 'now': time.time(),
            'cluster': bool(CONFIG.get('ha_mode')), 'helper': WEB_DIR.is_dir(),
            'power': power_plan(store) if power_busy(store) else {}}


def _osup_mark(part):
    """Which run a part's lines are of: the same mark, the same run."""
    return '%s|%s' % (part.get('plan') or part.get('id') or '', part.get('began') or '')


def _osup_cleared(store, nodes):
    """The lines cleared from the window (1.0.159) left out: of the run they
    were cleared in, only what came after the last line then shown. Kept in
    the database, so for every page and after a reload."""
    cl = _meta_obj(store, 'host:osup:cleared')
    for n in nodes:
        for part in ('row', 'check'):
            p = n.get(part) or {}
            c = (cl.get(n['name']) or {}).get(part) or {}
            lines = p.get('lines') or []
            if not lines or not c or c.get('mark') != _osup_mark(p):
                continue
            last = c.get('last')
            at = max((i for i, ln in enumerate(lines) if ln == last), default=None)
            n[part] = dict(p, lines=lines[at + 1:] if at is not None else lines)


def osup_clear(store, by):
    """The window of every node emptied: the lines there now not shown again."""
    plan = osup_plan(store)
    cl = {}
    for n in host_nodes(store):
        row = osup_row(store, n)
        parts = {'row': row if row.get('plan') == plan.get('id') else {},
                 'check': _meta_obj(store, 'host:osup:check:' + n)}
        cl[n] = {k: {'mark': _osup_mark(p), 'last': (p.get('lines') or [''])[-1]}
                 for k, p in parts.items() if p.get('lines')}
    store.set_meta('host:osup:cleared', json.dumps(cl))


def osup_check_ask(store, nodes, by):
    nodes = [n for n in host_nodes(store) if n in (nodes or [])]
    if not nodes:
        raise ValueError('which node?')
    for n in nodes:
        store.set_meta(node_key('host:osup:checkwant', n),
                       json.dumps({'id': secrets.token_hex(6), 'by': by, 'at': time.time()}))
    return nodes


def osup_start(store, nodes, reboot, by, security=False):
    plan = osup_plan(store)
    if plan.get('state') == 'running':
        raise ValueError('an update is going on already')
    if upgrade_plan(store) and upgrade_plan(store).get('state') == 'running':
        raise ValueError('an upgrade of acme is going on - wait for it to end')
    if power_busy(store):
        raise ValueError('a restart or a power off is going on - wait for it to end')
    known = host_nodes(store)
    alive = host_alive(store)
    nodes = [n for n in known if n in (nodes or known)]
    if not nodes:
        raise ValueError('which node?')
    gone = [n for n in nodes if not alive.get(n)]
    if gone:
        raise ValueError('%s is not heard from: bring it back first' % ', '.join(gone))
    if reboot not in ('ask', 'auto'):
        reboot = 'ask'
    # The others first, this one last - the page the person looks at stays
    # up the longest, as in an upgrade of acme.
    me = node_name()
    order = sorted(n for n in nodes if n != me) + ([me] if me in nodes else [])
    plan = {'id': secrets.token_hex(6), 'order': order, 'reboot': reboot, 'by': by,
            'at': time.time(), 'state': 'running', 'from': me, 'security': bool(security)}
    store.set_meta('host:osup:plan', json.dumps(plan))
    store.add_event('settings', '%s started the update of the system%s: %s, one at a time%s'
                    % (by, ' (security updates only)' if security else '', ', '.join(order),
                       ', each restarted when it needs it' if reboot == 'auto' else ''),
                    'warn', who=by)
    return plan


def osup_cancel(store, by):
    plan = osup_plan(store)
    if plan.get('state') != 'running':
        raise ValueError('no update is going on')
    plan.update(state='cancelled', ended=time.time(), cancelled_by=by)
    store.set_meta('host:osup:plan', json.dumps(plan))
    store.add_event('settings', '%s stopped the update of the system - a node being updated '
                    'finishes' % by, 'warn', who=by)


def _osup_job(kind, security=False):
    """The helper asked to start the work; its id."""
    got = root_ask('osup.ask', 'osup.ans', {'do': 'run', 'kind': kind,
                                             'security': bool(security),
                                             # dnf and apt through Settings → Proxy (1.0.166)
                                             'proxy': proxy_full('os'),
                                             'proxy_no': ','.join(proxy_no_list())}, 60)
    return got


OSUP_SILENT_S = int(os.environ.get('ACME_OSUP_SILENT_S') or 3600)


def _osup_read():
    try:
        return json.loads((WEB_DIR / 'osup.json').read_text())
    except (OSError, ValueError):
        return {}


def osup_tick(daemon):
    """Every few seconds: a look for updates asked of this node; its turn in an
    update; what the helper says while it works."""
    store = daemon.store
    me = node_name()
    if HOST_WORK['osup'] or HA_REBUILDING.is_set():
        return
    # Back up after a restart the update asked for: done, and back in service.
    row = osup_row(store, me)
    # ...or the restart refused or not done (1.0.79: "rebooting" for ever, the node in
    # maintenance with no work and no VIP, and every later update refused)
    if row.get('state') == 'rebooting' and not row.get('rebooted'):
        pw = _meta_obj(store, 'power:node:' + me)
        if pw.get('state') == 'failed' and float(pw.get('at') or 0) >= float(row.get('done_at') or 0) - 5:
            row['state'] = 'done'
            row['said'] = 'updated; the restart did not happen: %s - restart it by hand' % (
                pw.get('said') or pw.get('words') or 'refused')
            plan = osup_plan(store)
            if plan.get('state') == 'running' and (plan.get('order') or [None])[-1] == me and \
                    row.get('plan') == plan.get('id'):
                plan.update(state='done', ended=time.time())
                store.set_meta('host:osup:plan', json.dumps(plan))
            if row.get('maint'):
                try:
                    maintenance_set(store, False, '', 'acme (system update)')
                except Exception:                       # noqa: BLE001
                    pass
                row['maint'] = False
            osup_put(store, row)
            store.add_event('settings', 'the system of %s was updated, but the restart it needs '
                            'did not happen: %s' % (me, row['said']), 'warn', who='acme (system update)')
    if row.get('reboot') and not row.get('rebooted') and \
            boot_time() > float(row.get('done_at') or row.get('at') or 0) + 1:
        row['rebooted'] = True
        store.set_meta(node_key('host:osup:checkwant', me),
                       json.dumps({'id': secrets.token_hex(6), 'by': 'acme (system update)',
                                   'at': time.time()}))
        if row.get('state') == 'rebooting':
            row['state'] = 'done'
            row['said'] = 'up again after the restart'
            plan = osup_plan(store)
            if plan.get('state') == 'running' and (plan.get('order') or [None])[-1] == me and \
                    row.get('plan') == plan.get('id'):
                plan.update(state='done', ended=time.time())
                store.set_meta('host:osup:plan', json.dumps(plan))
            if row.get('maint'):
                try:
                    maintenance_set(store, False, '', 'acme (system update)')
                except Exception:                       # noqa: BLE001
                    pass
                row['maint'] = False
        osup_put(store, row)
    # A look for updates, asked.
    chk = _meta_obj(store, 'host:osup:check:' + me)
    # It said a restart was waiting and the node has restarted since: looked
    # at again, not left saying so (1.0.159).
    if chk.get('reboot_now') and chk.get('state') == 'done' and not chk.get('relook') and \
            boot_time() > float(chk.get('checked') or 0) + 1:
        chk['relook'] = True
        store.set_meta('host:osup:check:' + me, json.dumps(chk))
        store.set_meta(node_key('host:osup:checkwant', me),
                       json.dumps({'id': secrets.token_hex(6), 'by': 'acme (system update)',
                                   'at': time.time()}))
    for r in node_key_rows(store, 'host:osup:checkwant', me):
        try:
            a = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        if a.get('id') and a['id'] not in (chk.get('asked') or []) and \
                time.time() - float(a.get('at') or 0) < 900:
            _osup_go(daemon, 'check', a)
            return
    if chk.get('state') == 'running':
        _osup_follow_check(store, chk)
        return
    plan = osup_plan(store)
    if plan.get('state') != 'running' or me not in (plan.get('order') or []):
        return
    row = osup_row(store, me)
    if row.get('plan') != plan.get('id'):
        row = {'plan': plan.get('id'), 'state': 'waiting'}
    st = row.get('state') or 'waiting'
    if st == 'waiting':
        # My turn once every node before me is done.
        before = plan['order'][:plan['order'].index(me)]
        rows = {n: osup_row(store, n) for n in before}
        bad = [n for n in before if rows[n].get('plan') == plan['id'] and
               rows[n].get('state') == 'failed']
        if bad:
            return
        if all(rows[n].get('plan') == plan['id'] and rows[n].get('state') in ('done', 'skipped')
               for n in before):
            _osup_go(daemon, 'upgrade', {'plan': plan, 'row': row})
        return
    if st == 'draining':
        if time.time() - float(row.get('drain_at') or 0) >= 15:
            _osup_go(daemon, 'upgrade-now', {'plan': plan, 'row': row})
        return
    if st == 'updating':
        _osup_follow(daemon, plan, row)


def _osup_go(daemon, what, ctx):
    HOST_WORK['osup'] = True

    def go():
        store = daemon.store
        me = node_name()
        by = 'acme (system update)'
        try:
            if what == 'check':
                chk = _meta_obj(store, 'host:osup:check:' + me)
                asked = (list(chk.get('asked') or []) + [ctx['id']])[-20:]
                try:
                    _osup_job('check')
                    store.set_meta('host:osup:check:' + me, json.dumps(
                        dict(chk, state='running', asked=asked, began=time.time(), at=time.time(),
                             error='', lines=[])))
                except (ValueError, OSError) as e:
                    # the root helper not there an answer too (1.0.52): asked again every 5 s for
                    # a quarter of an hour, a line in the log each time
                    store.set_meta('host:osup:check:' + me, json.dumps(
                        dict(chk, state='failed', asked=asked, at=time.time(), error=str(e)[:300])))
                return
            plan, row = ctx['plan'], ctx['row']
            if what == 'upgrade':
                # Out of service first where another node answers meanwhile:
                # the VIP address moves to it, the work is done there.
                many = any(n.get('alive') and not n.get('me') for n in ha_nodes(store))
                if many:
                    maintenance_set(store, True, 'the system is being updated', by)
                    osup_put(store, row, state='draining', drain_at=time.time(), maint=True,
                             said='out of service - the other node answers', pct=0, lines=[])
                    return
                row['maint'] = False
            try:
                _osup_job('upgrade', bool(plan.get('security')))
                osup_put(store, row, state='updating', began=time.time(), pct=1, lines=[],
                         said='the packages are being updated')
            except ValueError as e:
                _osup_end(store, plan, row, False, str(e))
        except Exception as e:                          # noqa: BLE001
            log_sparing('osup-go', 'the update of the system: %s' % e, 'warn', every=600)
        finally:
            HOST_WORK['osup'] = False
    threading.Thread(target=go, name='acme-osup', daemon=True).start()


def _osup_follow_check(store, chk):
    me = node_name()
    got = _osup_read()
    if not got or got.get('kind') != 'check' or float(got.get('began') or 0) < \
            float(chk.get('began') or 0) - 5:
        if time.time() - float(chk.get('began') or 0) > 1800:
            store.set_meta('host:osup:check:' + me, json.dumps(
                dict(chk, state='failed', error='the helper did not say anything', at=time.time())))
        return
    if got.get('state') == 'running':
        if time.time() - float(chk.get('at') or 0) > 3:
            store.set_meta('host:osup:check:' + me, json.dumps(
                dict(chk, at=time.time(), lines=(got.get('lines') or [])[-40:])))
        return
    store.set_meta('host:osup:check:' + me, json.dumps(dict(
        chk, state=got.get('state'), at=time.time(), checked=time.time(), relook=False,
        packages=(got.get('packages') or [])[:1000], count=int(got.get('count') or 0),
        security=got.get('security'), pm=got.get('pm'), error=got.get('said') or '',
        reboot_after=bool(got.get('reboot_after')), reboot_why=(got.get('reboot_why') or [])[:20],
        reboot_now=bool(got.get('reboot_now')),
        lines=(got.get('lines') or [])[-40:])))


def _osup_follow(daemon, plan, row):
    store = daemon.store
    got = _osup_read()
    if not got or got.get('kind') != 'upgrade' or \
            float(got.get('began') or 0) < float(row.get('began') or 0) - 5:
        if time.time() - float(row.get('began') or 0) > 600:
            _osup_end(store, plan, row, False, 'the helper did not start the update')
        return
    if got.get('state') == 'running':
        # A helper that has said nothing for an hour is gone (1.0.207): killed half
        # way, it left "running" for ever - the node in maintenance, idle, every
        # later update refused.
        if got.get('at') and time.time() - float(got['at']) > OSUP_SILENT_S:
            _osup_end(store, plan, row, False, 'the helper stopped answering half way (nothing '
                      'from it for %d min) - look at the system\'s package manager'
                      % (OSUP_SILENT_S // 60))
            return
        if time.time() - HOST_WORK['osup_read'] > 2:
            HOST_WORK['osup_read'] = time.time()
            osup_put(store, row, pct=int(got.get('pct') or 0), phase=got.get('phase') or '',
                     lines=(got.get('lines') or [])[-300:])
        return
    row['lines'] = (got.get('lines') or [])[-300:]
    row['pct'] = 100
    _osup_end(store, plan, row, got.get('state') == 'done', got.get('said') or '',
              reboot=bool(got.get('reboot')))


def _osup_end(store, plan, row, ok, said='', reboot=False):
    me = node_name()
    by = 'acme (system update)'
    row.update(done_at=time.time(), reboot=reboot, rebooted=False)
    if not ok:
        osup_put(store, row, state='failed', said=said or 'it failed')
        if row.get('maint'):
            maintenance_set(store, False, '', by)
            row['maint'] = False
            osup_put(store, row)
        plan.update(state='failed', ended=time.time(), failed_on=me)
        store.set_meta('host:osup:plan', json.dumps(plan))
        store.add_event('settings', 'the update of the system failed on %s: %s' % (me, said),
                        'bad', who=by)
        return
    if reboot and plan.get('reboot') == 'auto':
        osup_put(store, row, state='rebooting', said='updated - restarting, as it needs')
        try:
            power_ask(store, 'reboot', [me], 'one', by, keep_service=True)
        except ValueError as e:
            osup_put(store, row, state='done', said='updated; the restart was not started: %s' % e)
        return
    osup_put(store, row, state='done', said='updated' + (' - it needs a restart' if reboot else ''))
    # What is waiting looked at again, not left at what was there before.
    store.set_meta(node_key('host:osup:checkwant', me),
                   json.dumps({'id': secrets.token_hex(6), 'by': by, 'at': time.time()}))
    if row.get('maint'):
        maintenance_set(store, False, '', by)
        row['maint'] = False
        osup_put(store, row)
    store.add_event('settings', 'the system of %s is updated%s' % (
        me, ' - it needs a restart' if reboot else ''), 'warn' if reboot else 'info', who=by)
    order = plan.get('order') or []
    if order and order[-1] == me:
        plan.update(state='done', ended=time.time())
        store.set_meta('host:osup:plan', json.dumps(plan))


# -- the SSH server and the notices at sign-in (1.0.163) --------------------------------------
# One wish for the whole cluster ('host:sshd:conf', with its hash); each node
# puts it in through its root helper and says what it has in a row of its own
# ('host:sshd:now:NODE'). A change is on trial on each node - its helper's
# own timer puts the one before back - until Keep it ('host:sshd:keep').
SSHD_DEFAULT = {'manage': False, 'permit_root': 'prohibit-password', 'password': True,
                'port': 22, 'allow_users': [], 'tries': 4, 'notice': '', 'notice_ssh': False,
                'notice_console': False, 'notice_motd': False, 'trial_min': 5,
                # A code from acme at SSH sign-in (1.0.40, as otp 1.0.178): pam_radius
                # asking this node's own gate (316).
                'radius': False, 'radius_users': [], 'radius_root': False,
                'radius_fallback': True, 'radius_with_key': False, 'radius_hide': False}
HOST_WORK.update(sshd=False, sshd_read=0.0)
SSHD_FMT = '191'           # how this version writes sshd's files (see sshd_tick)


def sshd_conf(store):
    c = dict(SSHD_DEFAULT)
    c.update(_meta_obj(store, 'host:sshd:conf'))
    return c


def sshd_checked_conf(b):
    """The page's wish, made whole; the root helper checks it again."""
    c = dict(SSHD_DEFAULT)
    c['manage'] = bool(b.get('manage'))
    if str(b.get('permit_root') or 'prohibit-password') not in ('yes', 'prohibit-password', 'no'):
        raise ValueError('root signs in with: yes, prohibit-password or no')
    c['permit_root'] = str(b.get('permit_root') or 'prohibit-password')
    c['password'] = bool(b.get('password'))
    try:
        c['port'] = int(b.get('port') or 22)
    except (TypeError, ValueError):
        raise ValueError('the port is a number')
    if not 1 <= c['port'] <= 65535:
        raise ValueError('the port is 1 to 65535')
    if c['port'] != 22 and c['port'] < 1024 and c['port'] in (25, 53, 80, 123, 443):
        raise ValueError('port %d is another service\'s' % c['port'])
    users = [u for u in re.split(r'[\s,]+', str(b.get('allow_users') or '')) if u] \
        if not isinstance(b.get('allow_users'), list) else [str(u) for u in b['allow_users'] if u]
    for u in users:
        if not re.match(r'^[A-Za-z0-9._@*?-]{1,64}\Z', u):
            raise ValueError('%r is not a user name' % u)
    c['allow_users'] = users[:50]
    try:
        c['tries'] = max(1, min(10, int(b.get('tries') or 4)))
        c['trial_min'] = max(0, min(60, int(b.get('trial_min') if b.get('trial_min') is not None
                                            else 5)))
    except (TypeError, ValueError):
        raise ValueError('a number is wanted')
    text = str(b.get('notice') or '').replace('\r\n', '\n')
    if len(text) > 4000:
        raise ValueError('the notice is 4000 characters at most')
    if re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text):
        raise ValueError('no control characters in the notice')
    c['notice'] = text
    for k in ('notice_ssh', 'notice_console', 'notice_motd'):
        c[k] = bool(b.get(k)) and bool(text.strip())
    c['radius'] = bool(b.get('radius')) and c['manage']
    raw = b.get('radius_users') or ''
    ru = [str(u) for u in raw if u] if isinstance(raw, list) else \
        [u for u in re.split(r'[\s,]+', str(raw)) if u]
    for u in ru:
        if not re.match(r'^[A-Za-z0-9._@-]{1,64}\Z', u):
            raise ValueError('%r is not a user name' % u)
    c['radius_users'] = ru[:100]
    c['radius_root'] = bool(b.get('radius_root'))
    # Passwords off: a node acme cannot ask lets nobody in with one either.
    c['radius_fallback'] = bool(b.get('radius_fallback', True)) and c['password']
    c['radius_with_key'] = bool(b.get('radius_with_key')) and c['radius']
    # The code not shown as it is typed (as otp 1.0.191): pam_radius asks with echo off.
    c['radius_hide'] = bool(b.get('radius_hide')) and c['radius']
    return c


def sshd_hash(c, at):
    """Each save a wish of its own: saved again, it is put in again - after
    one went back, too."""
    return hashlib.sha256((json.dumps({k: c.get(k) for k in SSHD_DEFAULT}, sort_keys=True) +
                           repr(at)).encode()).hexdigest()[:24]


def sshd_save(store, b, by):
    c = sshd_checked_conf(b)
    hisec_sshd(c)                           # 1.0.168
    if c['manage'] and c['allow_users'] and c['permit_root'] != 'no' and \
            not any(u in ('root', '*') for u in c['allow_users']) and not b.get('ok_no_root'):
        raise ValueError('AllowUsers without root lets nobody in as root - add root to it, or '
                         'let root not sign in at all')
    if c['radius']:
        ssh_gate_secret(store, make=True)
    at = time.time()
    c.update(hash=sshd_hash(c, at), at=at, by=by)
    store.set_meta('host:sshd:conf', json.dumps(c))
    what = ('root %s, passwords %s, port %d%s' % (
        c['permit_root'], 'on' if c['password'] else 'off', c['port'],
        ', AllowUsers ' + ' '.join(c['allow_users']) if c['allow_users'] else '')
        if c['manage'] else 'the SSH server as the system has it')
    if c['radius']:
        what += '; a code from acme at sign-in (%s%s)' % (
            ', '.join(c['radius_users']) or 'everybody but root' if not c['radius_root']
            else ', '.join(c['radius_users']) or 'everybody, root too',
            ', the system password when acme does not answer' if c['radius_fallback'] else '')
        if c['radius_with_key']:
            what += ', a key first'
        if c.get('radius_hide'):
            what += ', the code hidden as typed'
    notes = [w for k, w in (('notice_ssh', 'SSH'), ('notice_console', 'console'),
                            ('notice_motd', 'after sign-in')) if c[k]]
    store.add_event('settings', '%s set the SSH server: %s%s%s' % (
        by, what, '; the notice %s' % ', '.join(notes) if notes else '',
        '; on trial for %d min on each node' % c['trial_min'] if c['manage'] and c['trial_min']
        else ''), 'warn', who=by)
    return c


def sshd_now(store, n):
    return _meta_obj(store, 'host:sshd:now:' + n)


def sshd_view(store):
    c = sshd_conf(store)
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        now = sshd_now(store, n)
        keys = len((_meta_obj(store, 'host:sshkeys:now:' + n)).get('keys') or [])
        # What pam_radius of the node is (asked, not asked, not there) - on the node's row too:
        # the page reads it there (otp 1.0.243 left it in "now" only, and showed "-" always).
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'now': now, 'keys': keys, 'radius': now.get('radius'),
                      'state': ('failed' if now.get('failed') == c.get('hash') and c.get('hash')
                                else 'back' if now.get('back_hash') == c.get('hash') and c.get('hash')
                                else 'trial' if (now.get('trial') or {}).get('until')
                                else 'done' if now.get('hash') == c.get('hash') or not c.get('hash')
                                else 'waiting')})
    return {'conf': c, 'nodes': nodes, 'helper': WEB_DIR.is_dir(), 'sshotp': sshotp_all(store),
            'channels': code_channels(), 'gate_port': ssh_gate_port(store)}


def sshd_ports_open(store):
    """The SSH ports the firewall lets in: the one wished for, and while a
    change is not kept everywhere, the one each node has now too."""
    c = sshd_conf(store)
    ports = {int(c.get('port') or 22) if c.get('manage') else 22}
    for n in host_nodes(store):
        now = sshd_now(store, n)
        # ...and always the one sshd listens on now (1.0.51): not managed by acme, its own
        # sshd_config's Port 2222 was shut out by acme's firewall
        want = [(now.get('values') or {}).get('port')]
        if (now.get('trial') or {}).get('until') or now.get('hash') != c.get('hash'):
            want.append(now.get('before_port'))
        if True:
            for p in want:
                try:
                    if p:
                        ports.add(int(p))
                except ValueError:
                    pass
    return sorted(ports)


def sshd_tick(daemon):
    store = daemon.store
    me = node_name()
    if HOST_WORK['sshd']:
        return
    c = sshd_conf(store)
    now = sshd_now(store, me)
    keep = _meta_obj(store, 'host:sshd:keep')
    back = _meta_obj(store, 'host:sshd:back')
    try:
        gone = json.loads((WEB_DIR / 'sshd-back.json').read_text())
    except (OSError, ValueError):
        gone = {}
    todo = []
    if gone.get('at') and float(gone['at']) > float(now.get('back_at') or 0):
        todo.append(('went-back', gone))
    if c.get('hash') and c['hash'] != now.get('hash') and c['hash'] != now.get('failed') and \
            c['hash'] != now.get('back_hash'):
        todo.append(('apply', None))
    # (A machine built again starts with kept_at = when it was - machine_changed_check, 1.0.44 -
    # so that a Keep from before, in the backup, does not keep its trial at once.)
    if (now.get('trial') or {}).get('until') and keep.get('hash') == now.get('hash') and \
            float(keep.get('at') or 0) > float(now.get('kept_at') or 0):
        todo.append(('keep', None))
    if back.get('id') and back['id'] != now.get('back_id') and (now.get('trial') or {}).get('until'):
        todo.append(('back', back))
    # The files written anew once after an upgrade that writes them otherwise for
    # the same settings (1.0.191: root's own Match block) - no trial, nothing in
    # them chosen differently.
    if c.get('manage') and c.get('hash') and not todo and now.get('hash') == c.get('hash') and \
            not (now.get('trial') or {}).get('until') and now.get('failed') != c.get('hash') and \
            store.get_meta('host:sshd:fmt:' + me) != SSHD_FMT:
        todo.append(('apply', {'refit': True}))
    # pam_radius's file with another secret or port than the gate's (a port changed):
    # only that file is put right - or its PAM block from before skip_passwd.
    if c.get('manage') and c.get('radius') and (now.get('radius') or {}).get('pam') and \
            now.get('hash') == c.get('hash') and not todo and \
            ((now.get('radius') or {}).get('fp') != ssh_gate_fp(ssh_gate_secret(store, make=True),
                                                                ssh_gate_port(store)) or
             (now.get('radius') or {}).get('skip_passwd') is False):
        todo.append(('pamconf', None))
    if not todo and time.time() - HOST_WORK['sshd_read'] < 300 and now:
        return
    HOST_WORK['sshd'] = True

    def go():
        row = dict(now)
        try:
            for what, extra in todo or [('read', None)]:
                try:
                    if what == 'went-back':
                        row.update(back_at=extra['at'], back_hash=extra.get('hash') or '',
                                   hash='', trial={})
                        store.add_event('settings', 'the change of the SSH server went back on '
                                        '%s (%s)' % (me, extra.get('why') or 'not kept in time'),
                                        'warn')
                        got = root_ask('sshd.ask', 'sshd.json', {'do': 'read'}, 60)
                    elif what == 'apply':
                        refit = bool((extra or {}).get('refit'))
                        ask = {'do': 'apply', 'conf': c, 'trial_min': 0 if refit else (c.get('trial_min') or 0),
                               'hash': c['hash'], 'id': secrets.token_hex(4)}
                        if c.get('radius'):
                            # The gate's secret for pam_radius's file of 0600 - in the
                            # ask file, never on a command line.
                            ask.update(radius_secret=ssh_gate_secret(store, make=True),
                                       radius_port=ssh_gate_port(store))
                        got = root_ask('sshd.ask', 'sshd.json', ask, 120)
                        store.set_meta('host:sshd:fmt:' + me, SSHD_FMT)
                        if refit:
                            log('the SSH server\'s files written anew on %s, as this version '
                                'writes them' % me)
                        row.update(hash=c['hash'], failed='', error='', applied_at=time.time(),
                                   # Changed again while on trial: the helper
                                   # goes back to the first, so its port stays open.
                                   before_port=(row.get('before_port') if
                                                (row.get('trial') or {}).get('until') else None)
                                   or (row.get('values') or {}).get('port') or '22')
                    elif what == 'keep':
                        got = root_ask('sshd.ask', 'sshd.json', {'do': 'keep'}, 60)
                        row['kept_at'] = time.time()
                        store.add_event('settings', 'the change of the SSH server is kept on %s'
                                        % me, 'info')
                    elif what == 'back':
                        row['back_id'] = extra['id']
                        got = root_ask('sshd.ask', 'sshd.json', {'do': 'back', 'why': 'asked'}, 60)
                        continue
                    elif what == 'pamconf':
                        got = root_ask('sshd.ask', 'sshd.json', {
                            'do': 'pamconf', 'radius_secret': ssh_gate_secret(store),
                            'radius_port': ssh_gate_port(store)}, 60)
                    else:
                        got = root_ask('sshd.ask', 'sshd.json', {'do': 'read'}, 60)
                    row.update(values=got.get('values') or {}, there=got.get('there'),
                               dropins=got.get('dropins'), keys=got.get('keys'),
                               trial=got.get('trial') or {}, selinux=got.get('selinux') or '')
                    row.update(radius=got.get('radius') or {}, gate=dict(SSH_GATE_STATE))
                    if what != 'apply':
                        # A read that worked clears a read's own error (1.0.22: "did not
                        # answer in 60 s" from a moment the helper was being upgraded
                        # stayed on the card for good); a change that failed stays said.
                        row['error'] = row.get('error', '') if row.get('failed') else ''
                except ValueError as e:
                    if what == 'apply':
                        row.update(failed=c['hash'], error=str(e)[:300])
                        store.add_event('settings', 'the SSH server was not changed on %s: %s'
                                        % (me, e), 'bad')
                    else:
                        row['error'] = str(e)[:300]
            HOST_WORK['sshd_read'] = time.time()
            row['at'] = time.time()
            store.set_meta('host:sshd:now:' + me, json.dumps(row))
        except Exception as e:                          # noqa: BLE001
            log_sparing('sshd', 'the SSH server: %s' % e, 'warn', every=600)
        finally:
            HOST_WORK['sshd'] = False
    threading.Thread(target=go, name='acme-sshd', daemon=True).start()


# -- on a schedule (1.0.164) ---------------------------------------------------------------
# Updates in a window of their own - only the security ones, or all - one
# node at a time as by hand, restarted where needed; a look for updates every
# day; and a restart of the nodes in a window, one after the other. One node
# starts each (claim_once on the day); a run that cannot start (a node down,
# something going on) is said in the events, not tried over and over.
def _due(every, day, at, now=None):
    """(due now, the id of this window) for a schedule of HH:MM on a day."""
    n = datetime.fromtimestamp(now or time.time())
    try:
        hh, mm = (int(x) for x in str(at or '04:45').split(':', 1))
    except ValueError:
        hh, mm = 4, 45
    if every == 'weekly' and n.isoweekday() != int(day or 7):
        return False, ''
    if every == 'monthly' and n.day != 1:
        return False, ''
    return (n.hour, n.minute) >= (hh, mm), n.strftime('%Y-%m-%d')


def osup_settling(store):
    """An update going on, or a node still looking (again) for updates - what
    says which node needs a restart is not known yet (1.0.168)."""
    if osup_plan(store).get('state') == 'running':
        return True
    for n in host_nodes(store):
        chk = _meta_obj(store, 'host:osup:check:' + n)
        if chk.get('state') == 'running':
            return True
        for r in node_key_rows(store, 'host:osup:checkwant', n):
            try:
                a = json.loads(r['v'] or '{}')
            except ValueError:
                continue
            if a.get('id') and a['id'] not in (chk.get('asked') or []) and \
                    time.time() - float(a.get('at') or 0) < 900:
                return True
    return False


def osup_sched_tick(daemon):
    store = daemon.store
    if not alerts_lead(store):
        return
    by = 'acme (on a schedule)'
    if CONFIG.get('osup_check'):
        due, day = _due('daily', '', CONFIG.get('osup_check_at'))
        if due and store.get_meta('osup:check:day') != day and \
                claim_once(store, 'osup:check:day', day):
            alive = [n for n, a in host_alive(store).items() if a]
            try:
                osup_check_ask(store, alive, by)
            except ValueError as e:
                log('the daily look for updates: %s' % e, 'warn')
    if CONFIG.get('osup_auto'):
        due, day = _due(CONFIG.get('osup_auto_every') or 'weekly', CONFIG.get('osup_auto_day'),
                        CONFIG.get('osup_auto_at'))
        if due and store.get_meta('osup:auto:day') != day and \
                claim_once(store, 'osup:auto:day', day):
            try:
                osup_start(store, None, CONFIG.get('osup_auto_reboot') or 'auto', by,
                           security=(CONFIG.get('osup_auto_what') or 'security') == 'security')
            except ValueError as e:
                store.add_event('settings', 'the update of the system on a schedule did not '
                                'start: %s' % e, 'bad')
    if CONFIG.get('power_auto'):
        due, day = _due(CONFIG.get('power_auto_every') or 'weekly', CONFIG.get('power_auto_day'),
                        CONFIG.get('power_auto_at'))
        # Not while an update or a look for updates is still going on: the
        # nodes that need a restart are known only after it (1.0.168).
        if due and store.get_meta('power:auto:day') != day and not osup_settling(store) and \
                claim_once(store, 'power:auto:day', day):
            nodes = host_nodes(store)
            if CONFIG.get('power_auto_needed', 1):
                nodes = [n['name'] for n in osup_view(store)['nodes'] if n.get('reboot')]
            if not nodes:
                store.add_event('settings', 'the restart on a schedule: no node needs one', 'info')
                return
            try:
                power_ask(store, 'reboot', nodes, 'rolling', by, keep_service=True)
                store.add_event('settings', 'the restart on a schedule: %s, one after the other'
                                % ', '.join(nodes), 'warn')
            except ValueError as e:
                store.add_event('settings', 'the restart on a schedule did not start: %s' % e,
                                'bad')


