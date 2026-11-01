# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- going back to an older version (1.0.143) ---------------------------------------
# Never by putting a database back: the tables stay as they are - every column
# a newer version added is one an older one leaves alone (they are all added
# NULL) - and the older program runs on them. That is safe only for a version
# that reads what the newer ones wrote, so each version says how far back it
# may go (DOWNGRADE_FLOOR), and going back is refused below the highest floor
#   * of any version that ran on this database (each node keeps its own in
#     'downgrade:floor:NODE' - one writer a row, as replication wants), and
#   * of any version installed on this machine (install.sh keeps it in
#     /usr/local/lib/acme/downgrade-floor, root's alone: the acme account cannot
#     lower it, so it cannot take the server back to a version with a hole);
# and the package itself is looked at before anything is put in: a column the
# database has as NOT NULL with no default that the older version does not
# know would make every row it writes there fail. Then it goes the road of an
# upgrade - one node at a time, each in maintenance while it is done.
# The floor lives at the top of /usr/local/lib/acme, beside versions/ - not in
# a tree, which the next upgrade replaces.
_LIB_TOP = UPGRADE_HELPER.resolve().parent
if _LIB_TOP.parent.name == 'versions':
    _LIB_TOP = _LIB_TOP.parent.parent
DOWNGRADE_FLOOR_FILE = Path(os.environ.get('ACME_LIB') or str(_LIB_TOP)) / 'downgrade-floor'


def downgrade_floor_note(store):
    """This node's floor in the database: the highest of what it had and what
    this version says."""
    k = 'downgrade:floor:' + node_name()
    had = _meta_json(store, k) or {}
    if had and _ver_tuple(had.get('floor')) >= _ver_tuple(DOWNGRADE_FLOOR):
        return
    store.set_meta(k, json.dumps({'floor': DOWNGRADE_FLOOR, 'version': __version__,
                                  'at': time.time()}))


def downgrade_db_floor(store):
    """(floor, set by): the highest floor of any version that ran on this
    database, on any node."""
    best, by = DOWNGRADE_FLOOR, '%s (%s)' % (__version__, node_name())
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'downgrade:floor:%'"):
        try:
            got = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(got, dict) and _ver_tuple(got.get('floor')) > _ver_tuple(best):
            best, by = str(got['floor']), '%s (%s)' % (got.get('version'),
                                                      r['k'][len('downgrade:floor:'):])
    return best, by


def downgrade_root_floor():
    """The floor root keeps, or None where no version that knows it was ever
    installed here."""
    try:
        text = DOWNGRADE_FLOOR_FILE.read_text().strip()
    except OSError:
        return None
    return text if re.match(r'^\d+\.\d+\.\d+\Z', text) else None


def downgrade_why_not(store, version):
    """What stands in the way of going back to `version` - before the package
    is fetched: [] when nothing does."""
    why = []
    v = _ver_tuple(version)
    if v >= _ver_tuple(__version__):
        why.append('%s is not older than %s, which runs here - that is an upgrade'
                   % (version, __version__))
        return why
    floor, by = downgrade_db_floor(store)
    if v < _ver_tuple(floor):
        why.append('older than %s: acme %s, which ran on this database, wrote what older '
                   'versions do not read the same (or have holes it fixed)' % (floor, by))
    root = downgrade_root_floor()
    if root is None:
        why.append('this machine was never upgraded on the command line to a version that '
                   'can go back (install.sh --upgrade once)')
    elif v < _ver_tuple(root):
        why.append('older than %s, the oldest the versions installed on this machine allow'
                   % root)
    return why


def downgrade_live_strict(db):
    """{table: [column]} - the columns of this database that are NOT NULL and
    have no default: a row written without one of them fails."""
    out = {}
    if db.engine == 'sqlite':
        for t in TABLES:
            for r in db.rows('PRAGMA table_info(%s)' % t):
                if r['notnull'] and r['dflt_value'] is None and not r['pk']:
                    out.setdefault(t, []).append(str(r['name']).lower())
        return out
    if db.engine == 'postgres':
        rows = db.rows("SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                       "WHERE table_schema = current_schema() AND is_nullable = 'NO' "
                       "AND column_default IS NULL")
    else:
        rows = db.rows("SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                       "WHERE table_schema = DATABASE() AND is_nullable = 'NO' "
                       "AND column_default IS NULL AND extra NOT LIKE '%auto_increment%'")
    for r in rows:
        t, c = str(r['t']).lower(), str(r['c']).lower()
        if t in TABLES and c != 'id':
            out.setdefault(t, []).append(c)
    return out


# Run in a process of its own, on the package's own acme.py and acmelib/: its
# tables as it makes them, made in a database in memory and read back.
_DOWNGRADE_SCHEMA_PY = r'''
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
sys.argv = ['acme']
import acme
c = sqlite3.connect(':memory:')
out = {}
for name, ddl in acme.SCHEMA:
    c.execute(ddl.format(**acme.TYPES['sqlite']))
    out[name] = [str(r[1]).lower() for r in c.execute('PRAGMA table_info(%s)' % name)]
print(json.dumps({'version': acme.__version__, 'tables': out}))
'''


def downgrade_package_schema(path):
    """The tables and columns the package's version knows, read off its own
    acme.py and acmelib/ (the package checked and signed first)."""
    work = Path(tempfile.mkdtemp(prefix='acme-down-', dir=str(UPGRADE_DIR)))
    try:
        with tarfile.open(str(path), 'r:gz') as tf:
            found = False
            for member in tf.getmembers():
                mm = re.match(r'^acme-[0-9.]+/(acme\.py|acmelib/[A-Za-z0-9_./-]+)\Z', member.name)
                if not mm or not member.isfile() or '..' in mm.group(1).split('/'):
                    continue
                found = found or mm.group(1) == 'acme.py'
                dest = work / mm.group(1)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src, open(str(dest), 'wb') as dst:
                    shutil.copyfileobj(src, dst)
            if not found or not (work / 'acmelib' / '__init__.py').is_file():
                raise ValueError('the package has no acme.py and acmelib/')
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
               'ACME_STATE': str(work), 'ACME_CONFIG': str(work / 'none.json'),
               'ACME_LOGDIR': str(work), 'ACME_RUN': str(work)}
        try:
            r = subprocess.run([sys.executable, '-I', '-c', _DOWNGRADE_SCHEMA_PY, str(work)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                               env=env, cwd=str(work))
        except subprocess.TimeoutExpired:
            raise ValueError('the tables of the package could not be read in 2 minutes')
        try:
            return json.loads(r.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise ValueError('the tables of the package could not be read: %s'
                             % r.stderr.decode('utf-8', 'replace').strip()[-300:])
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def downgrade_schema_why(store, path):
    """What in this database the package's version could not live with: []
    when nothing."""
    got = downgrade_package_schema(path)
    knows = got.get('tables') or {}
    why = []
    for t, cols in sorted(downgrade_live_strict(store.db).items()):
        if t not in knows:
            continue                    # a table it never writes
        lack = [c for c in cols if c not in knows[t]]
        if lack:
            why.append('the table %s has %s, which acme %s does not know and every row needs'
                       % (t, ', '.join(lack), got.get('version')))
    return why


def downgrade_list(store):
    """The older versions at upgrade_url, each with what stands in its way."""
    url = online_url()
    if not url:
        raise ValueError('no upgrade_url is set (Settings → Upgrades)')
    out = []
    for p in online_list(url):
        if _ver_tuple(p['version']) >= _ver_tuple(__version__):
            continue
        out.append(dict(p, why=downgrade_why_not(store, p['version'])))
    out.sort(key=lambda p: _ver_tuple(p['version']), reverse=True)
    floor, by = downgrade_db_floor(store)
    root = downgrade_root_floor()
    # A few words a version for the list (1.0.145) - the reasons in full once.
    lowest = max([floor] + ([root] if root else []), key=_ver_tuple)
    for p in out:
        if not p['why']:
            p['short'] = ''
        elif _ver_tuple(p['version']) < _ver_tuple(lowest):
            p['short'] = 'below %s' % lowest
        elif root is None:
            p['short'] = 'this machine cannot go back yet'
        else:
            p['short'] = p['why'][0][:80]
    return {'url': url, 'here': __version__, 'versions': out, 'floor': floor,
            'floor_by': by, 'root_floor': root, 'lowest': lowest}


def downgrade_take(store, path, info, by):
    """A checked package of an older version kept for going back: refused
    when anything stands in its way. Its meta."""
    why = downgrade_why_not(store, info['version'])
    if not why:
        why = downgrade_schema_why(store, path)
    if why:
        store.add_event('starting and stopping', 'going back to acme %s was refused: %s'
                        % (info['version'], '; '.join(why)), 'warn', who=by)
        raise ValueError('acme %s cannot be gone back to: %s' % (info['version'], '; '.join(why)))
    meta = upgrade_store_package(store, path, info, by)
    meta['downgrade'] = True
    store.set_meta('upgrade:pkg', json.dumps(meta))
    store.add_event('starting and stopping', '%s made acme %s ready to go back to (signed by %s; '
                    'the database checked for it)' % (by, meta['version'], meta.get('signed_by')),
                    'warn', who=by)
    return meta


def downgrade_fetch(store, version, by):
    """The older package from upgrade_url, checked, and kept for going back."""
    why = downgrade_why_not(store, version)
    if why:
        raise ValueError('acme %s cannot be gone back to: %s' % (version, '; '.join(why)))
    return online_fetch(store, version, by, older=True)


def downgrade_file(store, path, by):
    """An older package from a file (the command line), checked and kept."""
    info = upgrade_inspect(path)
    if not info.get('older'):
        raise ValueError('acme %s is not older than %s, which runs here - that is an upgrade'
                         % (info['version'], info.get('installed') or __version__))
    return downgrade_take(store, path, info, by)


def changelog_sections(text):
    """{version: its section of CHANGELOG.md, heading and all}."""
    out = {}
    for m in re.finditer(r'^## (\d+\.\d+\.\d+)\b.*?(?=^## |\Z)', text or '', re.M | re.S):
        out[m.group(1)] = m.group(0).strip()[:20000]
    return out


def downgrade_changelog(version):
    """What came in `version`, and what going back to it from here gives up -
    the sections of the versions after it, up to this one (1.0.144). From the
    CHANGELOG.md installed beside acme.py; where that does not have it, from
    the package at upgrade_url (read, not yet checked)."""
    version = str(version or '')
    if not re.match(r'^\d+\.\d+\.\d+\Z', version):
        raise ValueError('which version?')
    try:
        here = changelog_sections((Path(__file__).resolve().parent / 'CHANGELOG.md')
                                  .read_text(encoding='utf-8', errors='replace'))
    except OSError:
        here = {}
    lost = [{'version': v, 'text': here[v]} for v in sorted(
        here, key=_ver_tuple, reverse=True)
        if _ver_tuple(version) < _ver_tuple(v) <= _ver_tuple(__version__)]
    entry, src = here.get(version), 'here'
    if entry is None:
        src = 'package'
        pk = next((p for p in online_list(online_url()) if p['version'] == version), None)
        if not pk:
            raise ValueError('acme %s is not at %s' % (version, online_url()))
        data, _ct, _final = _online_get(pk['url'], limit=UPGRADE_MOST, timeout=120)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
            m = next((x for x in tf.getmembers() if x.isfile() and
                      x.name == 'acme-%s/CHANGELOG.md' % version), None)
            text = tf.extractfile(m).read(4 << 20).decode('utf-8', 'replace') if m else ''
        entry = changelog_sections(text).get(version) or ''
    return {'version': version, 'here': __version__, 'entry': entry, 'from': src,
            'lost': lost}


# ---------------------------------------------------------------------------
# The web side (1.0.47): TLS of each node and of the cluster's VIP address,
# and that address itself (VIP, active/standby, held by keepalived).
#
# Everything is kept in the database, so both nodes know all of it:
#   web:vip          the address, its name, the VRRP id, the node it is meant
#                    to be on, each node's interface
#   web:tls:NODE     a node's own certificate, chain, root and TLS settings
#   web:tls:vip      the same for the VIP address's own name
# Keys are sealed with the installation's key. Each node then asks root for its own
# part of it (acme_web.py, through /var/lib/acme/web/request.json) and keeps
# /run/acme/vip-state up to date for keepalived: whether this node is healthy
# enough to hold the address - its own pages answering /healthz end to end
# (nginx, PHP, the daemon, the database), the API listening, not in
# maintenance, not being upgraded or rebuilt - and whether it is the one the
# address is meant to be on.
# ---------------------------------------------------------------------------
WEB_DIR = STATE_DIR / 'web'
VIP_STATE = RUN_DIR / 'vip-state'
VIP_ROLE = RUN_DIR / 'vip-role'
VIP_HERE_BY_ROLE = bool(os.environ.get('ACME_VIP_HERE_BY_ROLE'))
WEB_HELPER = Path(__file__).parent / 'acme_web.py'
VIP_FAILS_BEFORE = 2
VIP_HEALTH_URL = os.environ.get('ACME_VIP_HEALTH_URL', 'https://127.0.0.1/healthz')                    # checks in a row before it is said unhealthy
TLS_PRESETS = {
    # The ciphers acme has always used: ECDHE only, AEAD only.
    'standard': {'protocols': ['TLSv1.2', 'TLSv1.3'], 'ciphers': (
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305')},
    # Mozilla's "intermediate": the same and the DHE ones (DH parameters).
    'intermediate': {'protocols': ['TLSv1.2', 'TLSv1.3'], 'ciphers': (
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
        'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305')},
    # Mozilla's "modern": TLS 1.3 alone - its ciphers are not chosen.
    'modern': {'protocols': ['TLSv1.3'], 'ciphers': ''},
}
DH_WORDS = {'none': 'none (ECDHE only needs none)',
            'ffdhe2048': 'RFC 7919 ffdhe2048', 'ffdhe3072': 'RFC 7919 ffdhe3072',
            'ffdhe4096': 'RFC 7919 ffdhe4096', 'gen2048': 'made here, 2048 bits',
            'gen3072': 'made here, 3072 bits (a minute or so)',
            'gen4096': 'made here, 4096 bits (several minutes)'}
WEB_LOCK = threading.Lock()
VIP_HEALTH = {'ok': None, 'why': '', 'fails': 0, 'at': 0.0}


def _json_meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or 'null')
        return got if isinstance(got, dict) else None
    except ValueError:
        return None


def vip_conf(store):
    return _json_meta(store, 'web:vip') or {'on': False}


def tls_profile(store, target):
    return _json_meta(store, 'web:tls:' + target)


def vip_auth():
    """The VRRP password: the same on every node, from the installation's key."""
    key = sealing_key() or b''
    raw = hmac.new(key, b'acme-vip-vrrp', hashlib.sha256).digest()
    abc = string.ascii_letters + string.digits
    return ''.join(abc[b % len(abc)] for b in raw[:8])


VIP_MOVE_S = 60          # a move asked for by hand, in 'stays' mode, is wanted this long


def vip_moving(conf):
    """The node a move by hand is going to, while it is still under way."""
    to = str(conf.get('move_to') or '')
    if to and time.time() - float(conf.get('move_at') or 0) < VIP_MOVE_S:
        return to
    return ''


def vip_prefer_me(store, conf=None):
    """Is this node the one the address should be on - asked every 3 s.

    'back' (the default): the chosen node, always; the address goes back to it
    as soon as it is healthy. 'stays' (1.0.52): no preference - the node that
    holds it keeps it (keepalived's own state says which: MASTER), until it is
    unhealthy or gone, or until it is moved by hand."""
    conf = conf or vip_conf(store)
    me = node_name()
    if conf.get('mode') != 'stays':
        return vip_prefer(store, conf) == me
    moving = vip_moving(conf)
    if moving:
        return moving == me
    try:
        role = VIP_ROLE.read_text().split()[0]
    except (OSError, IndexError):
        role = ''
    return role == 'MASTER' or (role == '' and vip_here(conf.get('address')))


def vip_prefer(store, conf=None):
    conf = conf or vip_conf(store)
    if conf.get('mode') == 'stays':
        # Whoever holds it now (or is getting it).
        moving = vip_moving(conf)
        if moving:
            return moving
        for n in ha_nodes(store):
            w = web_state(store) if n['me'] else (n.get('web') or {})
            if w.get('vip_here'):
                return n['name']
        return ''
    want = str(conf.get('prefer') or '')
    if want:
        return want
    # Nobody chosen: the first node of the cluster by name - the same answer
    # on both nodes (1.0.59); "this one if it is slot 1" let both pick
    # themselves where the other's name sorted first.
    names = sorted(n['name'] for n in ha_nodes(store))
    return names[0] if names else node_name()


