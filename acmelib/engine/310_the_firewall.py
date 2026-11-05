# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the firewall --------------------------------------------------------------------
def fw_trial_min():
    return int(CONFIG.get('fw_confirm_min') or 0)


ACCESS_INSTALLED = ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')


def access_in_nginx():
    """Who may reach the pages as nginx has it now (root reads it): kept for a
    trial's put-back when acme never set the lists itself (1.0.209)."""
    try:
        now = web_status().get('access') or {}
    except Exception:                                   # noqa: BLE001
        now = {}
    out = {}
    for k in ACCESS_WORDS:
        one = now.get(k)
        if not isinstance(one, dict):
            return {}
        out[k] = {'any': bool(one.get('any')), 'from': [str(x) for x in one.get('from') or []]}
    return out


def fw_trial_begin(store, by):
    """Before a change of the firewall or of who may reach the pages: what is
    there now kept, for going back to."""
    n = fw_trial_min()
    if not n:
        return None
    t = time.time()
    trial = _meta_obj(store, 'fw:trial')
    if not trial or trial.get('done'):
        trial = {'id': secrets.token_hex(6), 'was': fw_conf(store),
                 'access': access_conf(store) or access_in_nginx(), 'at': t, 'by': by}
    trial.update(until=t + n * 60, last_by=by, min=n)
    store.set_meta('fw:trial', json.dumps(trial))
    # The key the put-back is claimed by made now, by this node alone (1.0.139):
    # made by both at the moment it ran out, it came over to each as a second
    # row with the same key, and replication stopped.
    if store.get_meta('fw_trial_back') is None:
        store.set_meta('fw_trial_back', '')
    return trial


def fw_trial_answer(store, act, by):
    trial = _meta_obj(store, 'fw:trial')
    if not trial or trial.get('done'):
        raise ValueError('no change of the firewall waits to be kept')
    if act == 'keep':
        trial.update(done='kept', done_by=by, done_at=time.time())
        store.set_meta('fw:trial', json.dumps(trial))
        store.add_event('settings', '%s kept the change of the firewall and access' % by,
                        who=by)
        return 'kept'
    fw_put_back(store, trial, 'put back by %s' % by)
    return 'what was there before comes back - each node puts it in within a few seconds'


def fw_put_back(store, trial, why):
    was = trial.get('was') or {}
    # Put back as something said (1.0.146): a firewall never set before went
    # back as "not set", which root reads as "leave it as it is" - and the
    # rules of the trial stayed; so did the lists of who may reach the pages.
    store.set_meta('fw:conf', json.dumps(dict(was, set=True, at=time.time(),
                                              by='acme (%s)' % why)))
    # Never "everybody" when nothing was known (1.0.209): the lists never saved
    # here were nginx's own - the private networks of the install - and the
    # put-back opened the administration to the internet.
    store.set_meta('web:access', json.dumps(trial.get('access') or {
        k: {'any': k not in ('admin', 'portal'), 'from': [] if k not in ('admin', 'portal')
            else list(ACCESS_INSTALLED)} for k in ACCESS_WORDS}))
    trial.update(done='back', done_by=why, done_at=time.time())
    store.set_meta('fw:trial', json.dumps(trial))
    store.add_event('settings', 'the firewall and access went back to what they were before '
                    '%s: %s' % (time.strftime('%H:%M', time.localtime(trial.get('at') or 0)),
                                why), 'warn')
    log('the firewall went back: %s' % why, 'warn')


def fw_trial_tick(store):
    trial = _meta_obj(store, 'fw:trial')
    if not trial or trial.get('done') or time.time() <= float(trial.get('until') or 0):
        return
    # One node puts it back (both would write the same rows at once).
    if claim_once(store, 'fw_trial_back', trial.get('id')):
        fw_put_back(store, trial, 'not kept within %d min' % int(trial.get('min') or 0))


def trials_view(store):
    """What waits to be kept, for the banner of every page and --status."""
    out = []
    t = time.time()
    for r in dbguard_rows(store.db, store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'net:job:%'")):
        try:
            job = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(job, dict) and job.get('state') == 'trial':
            w = job.get('want') or {}
            out.append({'kind': 'net', 'node': job.get('node') or r['k'][8:],
                        'until': float(job.get('trial_until') or 0), 'by': job.get('by'),
                        'words': 'the new network of %s (%s)' % (
                            job.get('node') or r['k'][8:], w.get('new_ip') or '?'),
                        'back': (w.get('old_ip') or '')})
    trial = _meta_obj(store, 'fw:trial')
    if trial and not trial.get('done') and float(trial.get('until') or 0) > t - 60:
        out.append({'kind': 'fw', 'node': '', 'until': float(trial.get('until') or 0),
                    'by': trial.get('last_by') or trial.get('by'),
                    'words': 'the change of the firewall and access', 'back': ''})
    return out


def trial_problem_words(trials):
    return ['%s waits to be kept: %d min left, then it goes back by itself (Keep it on the '
            'banner, or  acme --change-keep %s%s)' % (
                x['words'], max(0, int((x['until'] - time.time()) // 60)), x['kind'],
                (' --node %s' % x['node']) if x.get('node') else '') for x in trials]
# ---- the time: chrony on every node (1.0.120) ----------------------------------------
# Codes from the app are worked out from the clock: a node whose clock is off by
# more than half a period refuses codes that are right. Settings → Time shows
# each node's clock as chrony sees it (offset, stratum, its sources) and sets
# the time servers for the whole cluster: kept in meta 'ntp:conf', put in by
# each node's root helper when it changes ('ntp:applied:NODE'), and in a
# cluster each node also takes the other as one more source.
NTP_READ_S = 60
NTP_WORK = {'busy': False, 'read_at': 0.0, 'last': {}}
NTP_WORK_LOCK = threading.Lock()
NTP_DEFAULT = {'manage': False, 'servers': [], 'peers': True, 'allow': [],
               'makestep': [1.0, 3], 'minsources': 1, 'timezone': ''}


ROOT_ASK_LOCKS = {}
ROOT_ASK_LOCKS_LOCK = threading.Lock()


def root_ask(ask_name, answer_name, data, wait=60):
    """One ask of a file at a time (1.0.51, as net_root's): a second thread wrote over the
    first one's ask, and the first waited for an answer that never came."""
    with ROOT_ASK_LOCKS_LOCK:
        lock = ROOT_ASK_LOCKS.setdefault(ask_name, threading.Lock())
    with lock:
        return _root_ask(ask_name, answer_name, data, wait)


def _root_ask(ask_name, answer_name, data, wait=60):
    ask_id = secrets.token_hex(8)
    data = dict(data, id=ask_id)
    tmp = WEB_DIR / ('.%s.%d.%d' % (ask_name, os.getpid(), threading.get_ident() % 100000))
    if not WEB_DIR.is_dir():
        # Said as such (1.0.46), not as a Python error with a path in it - still an OSError, so
        # that what is asked is asked again once it is set up (a ValueError is an answer).
        raise FileNotFoundError('the root helper is not set up on this node (no %s) - install.sh puts '
                         'it in' % WEB_DIR)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(data))
    os.replace(str(tmp), str(WEB_DIR / ask_name))
    end = time.time() + wait
    while time.time() < end:
        try:
            got = json.loads((WEB_DIR / answer_name).read_text())
        except (OSError, ValueError):
            got = None
        if isinstance(got, dict) and got.get('id') == ask_id:
            if not got.get('ok'):
                raise ValueError(got.get('said') or 'the root helper said no')
            data = got.get('data')
            return data if isinstance(data, (dict, list)) else {}
        time.sleep(0.4)
    raise ValueError('the root helper of this node did not answer in %d s - is acme-web.path '
                     'running?  systemctl status acme-web.path' % wait)


def ntp_conf(store):
    c = dict(NTP_DEFAULT)
    c.update(_meta_obj(store, 'ntp:conf'))
    return c


def ntp_desired(store):
    c = ntp_conf(store)
    peers = []
    if c.get('manage') and c.get('peers') and CONFIG.get('ha_mode') and CONFIG.get('ha_peer'):
        try:
            peers = [str(ipaddress.ip_address(str(CONFIG['ha_peer'])))]
        except ValueError:
            peers = []
    return {'manage': bool(c.get('manage')), 'servers': c.get('servers') or [],
            'peers': peers, 'allow': c.get('allow') or [],
            'makestep': c.get('makestep') or [1.0, 3], 'minsources': c.get('minsources') or 1,
            'timezone': c.get('timezone') or ''}


def ntp_checked(b):
    """The settings from the page, made whole - the root helper checks them
    again."""
    out = dict(NTP_DEFAULT)
    out['manage'] = bool(b.get('manage'))
    servers = []
    for x in (b.get('servers') or [])[:12]:
        if not isinstance(x, dict):
            continue
        host = str(x.get('host') or '').strip().lower().rstrip('.')
        if not host:
            continue
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.match(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                            r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', host):
                raise ValueError('%r is not a host name or an address' % host)
        servers.append({'host': host, 'pool': bool(x.get('pool')),
                        'iburst': bool(x.get('iburst', True)), 'prefer': bool(x.get('prefer')),
                        'nts': bool(x.get('nts'))})
    if out['manage'] and not servers:
        raise ValueError('at least one time server - or let the machines keep their own')
    out['servers'] = servers
    out['peers'] = bool(b.get('peers', True))
    allow = []
    for a in re.split(r'[\s,;]+', b.get('allow') if isinstance(b.get('allow'), str)
                      else ' '.join(b.get('allow') or [])):
        if not a:
            continue
        try:
            allow.append(str(ipaddress.ip_network(a, strict=False)))
        except ValueError:
            raise ValueError('%r is not a network (192.0.2.0/24)' % a)
    out['allow'] = allow[:20]
    try:
        th = float(b.get('step_s', 1.0))
        lim = int(b.get('step_n', 3))
    except (TypeError, ValueError):
        raise ValueError('the step: seconds, and how many updates')
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise ValueError('the step: 0.001 to 3600 s; -1 (always) to 1000 updates')
    out['makestep'] = [th, lim]
    try:
        out['minsources'] = max(1, min(10, int(b.get('minsources') or 1)))
    except (TypeError, ValueError):
        raise ValueError('how many sources have to agree is a number')
    tz = str(b.get('timezone') or '').strip()
    # as the root helper takes it (1.0.51): a letter first - "+1" passed here, was refused
    # there after the time servers were applied, and was tried again every 10 minutes
    if tz and not re.match(r'^[A-Za-z][A-Za-z0-9_+-]{0,39}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z', tz):
        raise ValueError('%r is not a time zone' % tz)
    if tz and os.path.isdir('/usr/share/zoneinfo') and \
            not os.path.isfile(os.path.join('/usr/share/zoneinfo', tz)):
        raise ValueError('%s is not a time zone this machine knows (Europe/Prague, UTC...)' % tz)
    out['timezone'] = tz
    return out


def ntp_save(store, b, by):
    c = ntp_checked(b)
    c.update(at=time.time(), by=by)
    store.set_meta('ntp:conf', json.dumps(c))
    what = ('the servers %s%s' % (', '.join(x['host'] for x in c['servers']),
                                  '; the nodes take each other too' if c['peers'] and
                                  CONFIG.get('ha_mode') else '')) if c['manage'] \
        else 'each machine keeps its own servers'
    if c['timezone']:
        what += '; time zone %s' % c['timezone']
    store.add_event('settings', '%s set the time: %s' % (by, what), 'warn', who=by)
    return c


def ntp_publish(store, zones=False):
    data = root_ask('ntp.ask', 'ntp.json', {'do': 'read', 'zones': zones}, 30)
    now = {'at': time.time(), 'data': {k: v for k, v in data.items() if k != 'zones'}}
    store.set_meta('ntp:now:' + node_name(), json.dumps(now))
    NTP_WORK['read_at'] = time.time()
    NTP_WORK['last'] = now
    if zones and data.get('zones'):
        store.set_meta('ntp:zones', json.dumps(data['zones']))
    return now


def ntp_apply(store):
    want = ntp_desired(store)
    h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
    row = {'hash': h, 'at': time.time()}
    try:
        got = root_ask('ntp.ask', 'ntp.json', dict(want, do='apply'), 300)
        row.update(ok=True, said='; '.join(got.get('said') or []) or 'as it was')
        log('the time: %s' % row['said'])
    except ValueError as e:
        row.update(ok=False, said=str(e)[:300])
        log_sparing('ntp-apply', 'the time servers could not be set: %s' % e, 'warn', every=900)
    store.set_meta('ntp:applied:' + node_name(), json.dumps(row))
    try:
        ntp_publish(store)
    except Exception:                                   # noqa: BLE001
        pass


def _ntp_thread(fn, *args):
    def go():
        try:
            fn(*args)
        except Exception as e:                          # noqa: BLE001
            log_sparing('ntp-thread', 'the time: %s' % e, 'warn', every=900)   # (1.0.207)
        finally:
            with NTP_WORK_LOCK:
                NTP_WORK['busy'] = False
    with NTP_WORK_LOCK:
        if NTP_WORK['busy']:
            return False
        NTP_WORK['busy'] = True
    threading.Thread(target=go, name='acme-ntp', daemon=True).start()
    return True


def ntp_sync(store):
    got = root_ask('ntp.ask', 'ntp.json', {'do': 'sync'}, 60)
    store.add_event('settings', '%s: the clock stepped to the time servers now (%s)' % (
        node_name(), '; '.join(got.get('said') or [])), 'warn')
    time.sleep(3)
    ntp_publish(store)


def ntp_tick(daemon):
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    store = daemon.store
    me = node_name()
    if NTP_WORK['busy']:
        return
    conf = _meta_json(store, 'ntp:conf')
    if conf:
        want = ntp_desired(store)
        h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
        done = _meta_obj(store, 'ntp:applied:' + me)
        # Tried again when it failed (1.0.207), every ten minutes: written down under
        # the hash wanted, a failure was never tried again once the helper was back.
        if (done.get('hash') != h and time.time() - float(done.get('at') or 0) > 30) or \
                (done.get('hash') == h and done.get('ok') is False and
                 time.time() - float(done.get('at') or 0) > 600):
            _ntp_thread(ntp_apply, store)
            return
    sync_at = float(store.get_meta('ntp:sync:' + me) or 0)
    if sync_at > float(NTP_WORK.get('synced') or 0) and time.time() - sync_at < 300:
        NTP_WORK['synced'] = sync_at
        _ntp_thread(ntp_sync, store)
        return
    wanted = float(store.get_meta('ntp:read:' + me) or 0)
    if time.time() - NTP_WORK['read_at'] > NTP_READ_S or wanted > NTP_WORK['read_at']:
        _ntp_thread(ntp_publish, store, wanted > NTP_WORK['read_at'] or
                    not store.get_meta('ntp:zones'))


def ntp_problem():
    """Words for the status when this node's clock is not to be trusted."""
    now = NTP_WORK.get('last') or {}
    d = now.get('data') or {}
    if not d or time.time() - float(now.get('at') or 0) > 600:
        return ''
    t = d.get('tracking') or {}
    if d.get('chrony') and t:
        if t.get('leap') == 'Not synchronised' or not t.get('stratum'):
            return ('the clock is not synchronised to a time server (chrony) - codes from the '
                    'app are worked out from it: Settings → Time')
        if abs(float(t.get('offset') or 0)) > 1.0:
            return ('the clock is %.1f s off the time servers - codes from the app are worked '
                    'out from it: Settings → Time' % abs(float(t['offset'])))
    elif d.get('ntpsynchronized') == 'no':
        return 'the clock is not synchronised (timedatectl): Settings → Time'
    return ''


def ntp_view(store):
    hb = {n['name']: n for n in ha_nodes(store)}
    names = [node_name()] + sorted(n for n in hb if n != node_name())
    nodes = []
    for n in names:
        nodes.append({'name': n, 'me': n == node_name(),
                      'alive': True if n == node_name() else bool((hb.get(n) or {}).get('alive')),
                      'now': _meta_obj(store, 'ntp:now:' + n),
                      'applied': _meta_obj(store, 'ntp:applied:' + n)})
    try:
        zones = json.loads(store.get_meta('ntp:zones') or '[]')
    except ValueError:
        zones = []
    conf = ntp_conf(store)
    want = ntp_desired(store)
    h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
    return {'nodes': nodes, 'conf': conf, 'zones': zones, 'cluster': len(nodes) > 1,
            'hash': h if _meta_json(store, 'ntp:conf') else '', 'now': time.time()}


