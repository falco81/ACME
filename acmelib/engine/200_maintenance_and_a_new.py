# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Maintenance, and a new version put in from the pages (1.0.37)
# ---------------------------------------------------------------------------
# Maintenance is per node: the node does no work of its own (the other one
# renews and deploys, as it would for a node that is down) and /healthz says
# 503 (the load balancer takes it out). The pages go on working, so the node
# can be looked at and brought back.
#
# An upgrade: the package goes into the database, in pieces (so the other
# node of a cluster has it too), and a plan says which nodes, in which
# order. Each node does its own turn when it comes - maintenance on, a
# moment for the balancer to notice, the package handed to root
# (acme_upgrade.py, by acme-upgrade.path), and after its restart its own
# check before it leaves maintenance. Then the next one.
#
# Every row has ONE node that writes it (the plan: the one that started it;
# `upgrade:node:X` and `maint:X`: node X - or, for maintenance, the pages,
# which only ever UPDATE it). Replicated, a newer version may add a column,
# and the older node then takes nothing more from it until it is upgraded
# too; so a node's own rows are also written straight into the other's
# database - an UPDATE of a row both have, never an INSERT, which the
# replication arriving later would then collide with.
UPGRADE_DIR = STATE_DIR / 'upgrade'
UPGRADE_HELPER = Path(os.environ.get('ACME_UPGRADE_HELPER',
                                     str(Path(__file__).resolve().parent / 'acme_upgrade.py')))
UPGRADE_MOST = 64 * 1024 * 1024
UPGRADE_PIECE = 40000                       # base64 characters in one meta row
UPGRADE_DRAIN_S = int(os.environ.get('ACME_UPGRADE_DRAIN_S', '20'))
UPGRADE_TIMEOUT_S = 30 * 60
MAINT_CACHE = {'at': 0.0, 'row': None}
RESTORE_RUNNING = threading.Event()
RESTORE_WHY = ['']


def _meta_json(store, k):
    try:
        got = store.get_meta(k)
        return json.loads(got) if got else None
    except (ValueError, TypeError):
        return None


def _meta_obj(store, k):
    """A row of meta that holds an object - {} when it holds anything else (1.0.46): a row of
    another shape (one an older version wrote) made each look fail where .get() was asked of
    it, and the row was never written anew."""
    got = _meta_json(store, k)
    return got if isinstance(got, dict) else {}


def _peer_update(k, v):
    """The same row changed in the other node's database too - UPDATE only."""
    if CONFIG.get('ha_mode') != 'replicated' or not CONFIG.get('ha_peer'):
        return False
    try:
        far = ha_peer_db()
    except Exception:                                   # noqa: BLE001
        return False
    try:
        done = bool(far.run('UPDATE meta SET v = ? WHERE k = ?', (v, k)))
        if done and dbguard_meta_signed(k):
            dbguard_sign(far, 'm', k, v, far=True)        # 1.0.231
        return done
    except Exception:                                   # noqa: BLE001
        return False
    finally:
        try:
            far.close()
        except Exception:                               # noqa: BLE001
            pass


def _row_write(store, k, data, mine=True, mirror=True):
    """A row of this node's own (made here if need be), or someone else's
    (only ever UPDATEd)."""
    v = json.dumps(data, default=str)
    if store.db.value('SELECT k FROM meta WHERE k = ?', (k,)) is None:
        if not mine:
            raise ValueError('that node has not been heard of here yet')
        store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, v))
    else:
        store.db.run('UPDATE meta SET v = ? WHERE k = ?', (v, k))
    if dbguard_meta_signed(k):
        dbguard_sign(store.db, 'm', k, v)                 # 1.0.231
    if mirror:
        _peer_update(k, v)


# ---- maintenance ---------------------------------------------------------------------
def maintenance_row(store, name=None):
    return _meta_json(store, 'maint:' + (name or node_name())) or {'on': False}


def maintenance_now(store):
    """This node's maintenance, read at most every two seconds - asked
    before every piece of work."""
    if HA_REBUILDING.is_set():
        return {'on': True, 'why': 'rebuilt from the other node'}
    if RESTORE_RUNNING.is_set():
        # A backup put back (1.0.149): the work waited for the whole of it with
        # the database held, or met tables being made again and failed. Room
        # given back in a cluster too (1.0.150): VACUUM FULL holds each table
        # shut - the other node answers meanwhile.
        return {'on': True, 'why': RESTORE_WHY[0] or 'a backup is being put back'}
    if split_aside():
        # Stepped aside while the nodes cannot reach each other (1.0.14): maintenance
        # nobody asked for, ended by itself - the VIP address goes, /healthz says so.
        return {'on': True, 'why': 'stepped aside: ' + (SPLIT['why'] or 'the nodes are apart'),
                'split': True}
    if clock_aside():
        # Stepped aside for its clock or the directory (1.0.21, clock_mode guard): only
        # while the other node is well, ended by itself.
        return {'on': True, 'why': 'stepped aside: ' + (CLOCK['why'] or 'this node is not well'),
                'clock': True}
    now = time.monotonic()      # not held by a clock stepped back (1.0.207)
    if now - MAINT_CACHE['at'] > 2:
        MAINT_CACHE['at'] = now
        try:
            MAINT_CACHE['row'] = maintenance_row(store)
        except Exception:                               # noqa: BLE001
            pass                                        # the last one known stands
    return MAINT_CACHE['row'] or {'on': False}


def maintenance_ensure(store):
    """The row of this node, made by this node: the pages only change it."""
    if HA_REBUILDING.is_set():
        return
    try:
        if store.get_meta('maint:' + node_name()) is None:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         ('maint:' + node_name(), json.dumps({'on': False})))
    except Exception:                                   # noqa: BLE001
        pass


def maintenance_set(store, on, why='', by='', name=None):
    name = name or node_name()
    row = {'on': bool(on), 'why': str(why or '')[:200], 'by': str(by or '')[:100],
           'at': time.time()}
    _row_write(store, 'maint:' + name, row, mine=(name == node_name()))
    MAINT_CACHE['at'] = 0
    store.add_event('starting and stopping', '%s: %s%s' % (
        name, 'in maintenance' if on else 'back in service',
        (' - ' + why) if why and on else ''), 'warn' if on else 'info', who=by or None)
    return row


# ---- the package --------------------------------------------------------------------
def upgrade_inspect(path):
    """What the package is, asked of acme_upgrade.py - the same check root
    makes again before putting it in."""
    if not UPGRADE_HELPER.exists():
        raise ValueError('acme_upgrade.py is not installed beside acme.py; upgrade once on the '
                         'command line (install.sh --upgrade)')
    try:
        r = subprocess.run([sys.executable, '-I', str(UPGRADE_HELPER), '--inspect', str(path)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        got = json.loads(r.stdout.decode('utf-8', 'replace') or '{}')
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        raise ValueError('the package could not be checked: %s' % e)
    if not got.get('ok'):
        raise ValueError(got.get('said') or 'the package was refused')
    return got


def upgrade_store_package(store, path, info, by):
    """The package into the database in pieces, the one before taken out."""
    raw = Path(path).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    text = base64.b64encode(raw).decode('ascii')
    pieces = [text[i:i + UPGRADE_PIECE] for i in range(0, len(text), UPGRADE_PIECE)]
    old = _meta_obj(store, 'upgrade:pkg')
    # Every other package's pieces out, not only the last one's (1.0.44).
    store.db.run("DELETE FROM meta WHERE k LIKE 'upgrade:piece:%' AND k NOT LIKE ?",
                 ('upgrade:piece:%s:%%' % sha[:16],))
    for i, one in enumerate(pieces):
        k = 'upgrade:piece:%s:%04d' % (sha[:16], i)
        if store.get_meta(k) is None:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, one))
    meta = {'sha': sha, 'version': info['version'], 'bytes': len(raw), 'pieces': len(pieces),
            'signed_by': info.get('signed_by'), 'changelog': info.get('changelog', ''),
            'by': by, 'at': time.time()}
    store.set_meta('upgrade:pkg', json.dumps(meta))
    return meta


def upgrade_package_file(store, meta):
    """The package back out of the database, to the folder root takes it
    from - from the other node's database when this one has not all of it
    yet."""
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    out = UPGRADE_DIR / ('acme-%s.tar.gz' % meta['version'])

    def pieces_of(db):
        rows = db.rows("SELECT k, v FROM meta WHERE k LIKE ? ESCAPE '!' ORDER BY k",
                       ('upgrade:piece:%s:%%' % meta['sha'][:16],))
        return [r['v'] for r in rows]
    got = pieces_of(store.db)
    if len(got) != int(meta['pieces']) and CONFIG.get('ha_mode') == 'replicated':
        far = ha_peer_db()
        try:
            got = pieces_of(far)
        finally:
            far.close()
    if len(got) != int(meta['pieces']):
        raise ValueError('the package has not all arrived in this node\'s database')
    raw = base64.b64decode(''.join(got))
    if hashlib.sha256(raw).hexdigest() != meta['sha']:
        raise ValueError('the package in the database is damaged')
    tmp = out.with_suffix('.part')
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
    os.replace(str(tmp), str(out))
    return out


