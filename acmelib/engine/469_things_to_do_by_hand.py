# What waits for a person (1.0.54; docs/things-to-do-by-hand.md): a step acme cannot take by
# itself - a command to run as root on a node after an update, SELinux switched off behind its
# back, nginx's file older than the pages it serves, the root helper not there. Each node looks
# once a minute with the checks below (cheap ones: files and /sys, no program run), keeps what
# it found in a row of its own ('attention:NODE'), and Settings → Upgrades and maintenance shows every node's at the top
# in a band that does not go away until the thing is done - with the command to run, to copy.
# The same go into the alerts (mail, SNMP) as problems of their own.
#
# A check is one function, registered with @hand_check: it gets the store and returns a list of
# {id, level ('bad'|'warn'), title, words, cmd (what to run as root, or ''), pane}. A release that
# needs a step by hand adds one (HAND_STEPS below for the simple case: a file that must say
# something) - and it goes away by itself once the step is done.

HAND_CHECKS = []
HAND_EVERY_S = 60
HAND = {'at': 0.0, 'items': [], 'cache_at': 0.0, 'cache': []}


def hand_check(fn):
    HAND_CHECKS.append(fn)
    return fn


# The steps a version asks for by hand, the simple kind: {id, since, file, has, title, words, cmd}
# - wanted while `file` is there and does not contain `has` (an install whose file is older than
# the version). Added to by the releases that need them.
HAND_STEPS = [
    {'id': 'nginx-manifest', 'since': '1.0.51', 'file': '/etc/nginx/conf.d/acme.conf',
     'has': 'webmanifest', 'level': 'warn', 'pane': 'web',
     'title': 'nginx\'s file for acme is older than the pages',
     'words': 'The home screen\'s manifest (the icon on an iPad) is served without its type. The '
              'upgrade of the command line brings the file up to date (a copy of it is kept).',
     'cmd': 'sudo bash /usr/local/lib/acme/current/install.sh --upgrade',
     'cs': {'title': 'Soubor nginx pro acme je starší než stránky',
            'words': 'Manifest pro plochu (ikona na iPadu) se posílá bez svého typu. Upgrade z '
                     'příkazové řádky soubor obnoví (jeho kopie se ponechá).'}},
]


def _hand_read(path, most=2000000):
    try:
        with open(path, 'rb') as f:
            return f.read(most).decode('utf-8', 'replace')
    except OSError:
        return None


# A step that cannot be checked from here ('manual': True, no 'file'): wanted until somebody
# presses Done on the pages (who and when are kept) - on a node where `if_file` is there, if given
# (an install, not a test). Use it only where no check can be written.
HAND_FIELDS = ('id', 'level', 'title', 'words', 'cmd', 'pane', 'cs')


@hand_check
def hand_steps(store):
    out = []
    for st in HAND_STEPS:
        if st.get('manual'):
            if st.get('if_file') and _hand_read(st['if_file'], 1) is None:
                continue
            if store.get_meta('handdone:%s:%s' % (st['id'], node_name())):
                continue
            out.append(dict({k: st.get(k, '') for k in HAND_FIELDS}, kind='manual'))
            continue
        text = _hand_read(st['file'])
        if text is None or st['has'] in text:
            continue
        out.append({k: st.get(k, '') for k in HAND_FIELDS})
    return out


@hand_check
def hand_selinux(store):
    """SELinux enforcing once, permissive or off now - switched off by somebody, or by an update."""
    enforce = _hand_read('/sys/fs/selinux/enforce', 16)
    k = 'handseen:selinux:' + node_name()   # was it ever enforcing here
    seen = store.get_meta(k) == 'enforcing'
    if enforce is not None and enforce.strip() == '1':
        if not seen:
            store.set_meta(k, 'enforcing')
        return []
    if not seen:
        return []                       # never seen enforcing here: as it was set up
    # Back to permissive asked on these pages, the command line or the console (1.0.62): a step
    # of acme's own, not SELinux switched off behind its back - forgotten, said again only once
    # it has been enforcing since.
    if enforce is not None and (_meta_obj(store, 'host:selinux:want:' + node_name()).get('do')
                                == 'permissive'):
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
        return []
    if enforce is None:
        cs = 'SELinux byl na tomto uzlu vynucující a teď je vypnutý (disabled) - nic z toho, čemu ' \
             'bránil, se už nebrání. Zapněte ho v /etc/selinux/config (SELINUX=enforcing) a ' \
             'restartujte stroj.'
        words = 'SELinux was enforcing on this node and is off now (disabled) - nothing it kept ' \
                'from happening is kept from happening. Switch it on in /etc/selinux/config ' \
                '(SELINUX=enforcing) and restart the machine.'
        cmd = "sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && " \
              "sudo touch /.autorelabel && sudo reboot"
    else:
        cs = 'SELinux byl na tomto uzlu vynucující a teď je jen permissive: nic se neodmítá, jen ' \
             'zapisuje.'
        words = 'SELinux was enforcing on this node and is only permissive now: nothing is ' \
                'refused, only written down.'
        cmd = "sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' " \
              "/etc/selinux/config"
    return [{'id': 'selinux-off', 'level': 'bad', 'pane': 'hisec',
             'title': 'SELinux was switched off', 'words': words, 'cmd': cmd,
             'cs': {'title': 'SELinux byl vypnut', 'words': cs}}]


@hand_check
def hand_helper(store):
    """The root helper not there on an installed node: nothing of the machine can be done."""
    if not Path('/usr/local/lib/acme').is_dir() or not Path('/etc/systemd/system').is_dir():
        return []                       # not an installed node (a test, a checkout)
    if WEB_DIR.is_dir() and Path('/etc/systemd/system/acme-web.path').exists():
        return []
    return [{'id': 'helper-missing', 'level': 'bad', 'pane': 'about',
             'title': 'The root helper is not set up on this node',
             'words': 'The network, the firewall, the users, the updates and the rest of the '
                      'machine cannot be looked after from the pages until it is.',
             'cmd': 'sudo bash /usr/local/lib/acme/current/install.sh --upgrade',
             'cs': {'title': 'Pomocník roota není na tomto uzlu nastaven',
                    'words': 'Síť, firewall, uživatele, aktualizace ani nic dalšího ze stroje '
                             'nelze ze stránek spravovat, dokud nebude.'}}]


HAND_LOG_MOST = 20


def hand_tick(store, force=False):
    """From the daemon's loop: the checks once a minute (at once when Look again was pressed),
    the row written when it changed; what went away written down with how and who."""
    t = time.time()
    try:
        look = float(store.get_meta('handlook') or 0)
    except (TypeError, ValueError):
        look = 0.0
    if not force and t - HAND['at'] < HAND_EVERY_S and look <= HAND['at']:
        return
    HAND['at'] = t
    me = node_name()
    items = []
    for fn in HAND_CHECKS:
        try:
            items += [dict(x, node=me, kind=x.get('kind') or 'check')
                      for x in (fn(store) or []) if isinstance(x, dict) and x.get('id')]
        except Exception as e:                          # noqa: BLE001
            log_sparing('hand-' + fn.__name__, 'a check of what waits for a person (%s): %s'
                        % (fn.__name__, e), 'warn', every=3600)
    k = 'attention:' + me
    was = _meta_obj(store, k)
    before = {x.get('id'): x for x in was.get('items') or [] if isinstance(x, dict)}
    for i in items:                                     # since when it waits
        i['since'] = float((before.get(i['id']) or {}).get('since') or t)

    def sig(lst):
        return [{x: i.get(x) for x in ('id', 'title', 'words', 'cmd')} for i in lst]
    same = sig(was.get('items') or []) == sig(items)
    if not same or t - float(was.get('at') or 0) > 3600:
        store.set_meta(k, json.dumps({'at': t, 'items': items}))
    if not same:
        HAND['cache_at'] = 0.0      # the pages see it at once, not in 20 s
        now_ids = {i['id'] for i in items}
        log = []
        for i in items:
            if i['id'] not in before:
                store.add_event('settings', 'waits for a person on %s: %s' % (me, i['title']),
                                'bad' if i.get('level') == 'bad' else 'warn')
        for bid, b in before.items():
            if bid in now_ids:
                continue
            done = _meta_obj(store, 'handdone:%s:%s' % (bid, me)) if b.get('kind') == 'manual' else {}
            how = 'done' if done else 'gone by itself'
            log.append({'key': bid, 'what': b.get('title') or bid, 'cs': (b.get('cs') or {}).get('title') or '',
                        'how': how, 'who': str(done.get('who') or ''), 'at': float(done.get('at') or t),
                        'node': me})
            store.add_event('settings', '%s on %s: %s' % (how, me, b.get('title') or bid), 'info',
                            str(done.get('who') or ''))
        if log:
            lk = 'handlog:' + me
            old = store.get_meta(lk)
            try:
                old = json.loads(old) if old else []
            except ValueError:
                old = []
            store.set_meta(lk, json.dumps((log + [x for x in old if isinstance(x, dict)])[:HAND_LOG_MOST]))
    HAND['items'] = items


def hand_all(store):
    """Every node's, for the pages (read again at most every 20 s): [{id, node, level, ...}]."""
    t = time.time()
    if t - HAND['cache_at'] < 20:
        return HAND['cache']
    out = []
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'attention:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    for r in rows:
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(v, dict) or t - float(v.get('at') or 0) > 86400 * 2:
            continue                    # a node gone for two days says nothing any more
        out += [i for i in v.get('items') or [] if isinstance(i, dict)]
    out.sort(key=lambda i: (i.get('level') != 'bad', str(i.get('node')), str(i.get('id'))))
    HAND['cache_at'], HAND['cache'] = t, out
    return out


def _hand_done_rows(store):
    out = []
    try:
        rows = store.db.rows("SELECT v FROM meta WHERE k LIKE 'handlog:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    for r in rows:
        try:
            v = json.loads(r['v'] or '[]')
        except ValueError:
            continue
        out += [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []
    return out


def _hand_done_id(x):
    """One entry of Done lately, the same on every node: its node, what, and when."""
    return '%s|%s|%.3f' % (str(x.get('node') or ''), str(x.get('key') or x.get('what') or ''),
                           float(x.get('at') or 0))


def _hand_cleared(store):
    try:
        v = json.loads(store.get_meta('handclear') or '[]')
    except ValueError:
        v = []
    return set(str(x) for x in v) if isinstance(v, list) else set()


def hand_done_lately(store, most=10):
    """What went away, every node's, newest first: [{key, what, how, who, at, node}] - without
    what Clear took away (each node's own row is written by that node alone, so Clear keeps a row
    of its own of what it took, rather than writing in another node's)."""
    gone = _hand_cleared(store)
    out = [x for x in _hand_done_rows(store) if _hand_done_id(x) not in gone]
    out.sort(key=lambda x: -float(x.get('at') or 0))
    return out[:most]


def hand_done_clear(store, items=None, who=''):
    """Done lately emptied (1.0.55): the entries the page shows ([node, key, at] each), or all
    of it when none are named (the command line). What is still to be done is not touched."""
    rows = _hand_done_rows(store)
    now = {_hand_done_id(x) for x in rows}
    gone = _hand_cleared(store) & now               # what no node keeps any more is forgotten
    if items is None:
        want = now - gone
    else:
        want = set()
        for one in list(items)[:200]:
            if isinstance(one, (list, tuple)) and len(one) == 3:
                try:
                    want.add('%s|%s|%.3f' % (str(one[0])[:80], str(one[1])[:120], float(one[2])))
                except (TypeError, ValueError):
                    continue
        want = (want & now) - gone
    store.set_meta('handclear', json.dumps(sorted(gone | want)))
    store.add_event('settings', '"done lately" cleared by %s (%d)' % (who or 'the command line',
                                                                       len(want)), 'info', who)
    return len(want)


@route('GET', '/api/attention')
def _hand_get(h):
    h.me('fulladmin')
    return {'items': hand_all(h.store), 'done': hand_done_lately(h.store)}


@route('POST', '/api/attention')
def _hand_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'look':
        # Every node looks again within its next turn (5 s); this one at once.
        h.store.set_meta('handlook', '%.3f' % time.time())
        hand_tick(h.store, force=True)
        HAND['cache_at'] = 0.0
    elif act == 'done':
        iid, node = str(b.get('id') or ''), str(b.get('node') or '')
        it = [i for i in hand_all(h.store) if i.get('id') == iid and i.get('node') == node]
        if not it:
            raise ApiError(404, 'that is not waiting any more')
        if it[0].get('kind') != 'manual':
            raise ApiError(409, 'this one is checked - it goes by itself once it is done (Look again)')
        h.store.set_meta('handdone:%s:%s' % (iid, node), json.dumps({'who': s['name'], 'at': time.time()}))
        h.store.set_meta('handlook', '%.3f' % time.time())
        if node == node_name():
            hand_tick(h.store, force=True)
        HAND['cache_at'] = 0.0
    elif act == 'clear_done':
        items = b.get('items') if isinstance(b.get('items'), list) else None
        n = hand_done_clear(h.store, items, s['name'])
        return {'ok': True, 'items': hand_all(h.store), 'done': hand_done_lately(h.store),
                'message': 'done lately cleared (%d)' % n}
    else:
        raise ApiError(400, 'no such action')
    return {'ok': True, 'items': hand_all(h.store), 'done': hand_done_lately(h.store)}
