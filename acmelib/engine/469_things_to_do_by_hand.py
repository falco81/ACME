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


@hand_check
def hand_steps(store):
    out = []
    for st in HAND_STEPS:
        text = _hand_read(st['file'])
        if text is None or st['has'] in text:
            continue
        out.append({k: st.get(k, '') for k in ('id', 'level', 'title', 'words', 'cmd', 'pane', 'cs')})
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


def hand_tick(store, force=False):
    """From the daemon's loop: the checks once a minute, the row written when it changed."""
    t = time.time()
    if not force and t - HAND['at'] < HAND_EVERY_S:
        return
    HAND['at'] = t
    items = []
    for fn in HAND_CHECKS:
        try:
            items += [dict(x, node=node_name()) for x in (fn(store) or []) if isinstance(x, dict)]
        except Exception as e:                          # noqa: BLE001
            log_sparing('hand-' + fn.__name__, 'a check of what waits for a person (%s): %s'
                        % (fn.__name__, e), 'warn', every=3600)
    k = 'attention:' + node_name()
    was = _meta_obj(store, k)
    same = [{x: i.get(x) for x in ('id', 'title', 'words', 'cmd')} for i in was.get('items') or []] == \
        [{x: i.get(x) for x in ('id', 'title', 'words', 'cmd')} for i in items]
    if not same or t - float(was.get('at') or 0) > 3600:
        store.set_meta(k, json.dumps({'at': t, 'items': items}))
        if not same:
            HAND['cache_at'] = 0.0      # the pages see it at once, not in 20 s
            for i in items:
                if i['id'] not in {x.get('id') for x in was.get('items') or []}:
                    store.add_event('settings', 'waits for a person on %s: %s' % (
                        node_name(), i['title']), 'bad' if i.get('level') == 'bad' else 'warn')
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
