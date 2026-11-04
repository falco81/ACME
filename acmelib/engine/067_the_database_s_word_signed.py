# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# The database's word, signed (1.0.231): root's actions only from rows written by acme
# ---------------------------------------------------------------------------
# What a node has done as root - the firewall, sshd and root's SSH keys, the network, a
# restart, the system's updates and their proxy, the time servers, nginx's certificates, the
# VIP, the TLS of the database link - follows rows of the database: settings, rows of `meta`,
# requests one node leaves for another. Anybody who can write the database (its server, a
# db_password found out, a copy of it put back) could write those rows, and the node did as
# they said - even signing in to these pages, with an account or a session put in the table.
#
# Every such row is signed now when acme writes it: an HMAC under a key worked out from
# secrets.key, which is in no database (both nodes of a cluster have it). The signature is a row
# of its own beside it, `sig:<kind>:<hash of the name>:<node>` = {"n": counter, "m": mac} - versions
# before this one see a row of meta they do not know, and leave it. With `db_guard` on (a
# setting of config.json, never of the database; off by default - as until now) a node takes
# a row it acts on as root only when its signature is right and its counter not older than the
# one it saw last (kept in its own file, not in the database): a row written by somebody else
# reads as not there - an older signed row put back as well. Settings keep their last good
# value then; the certificate manager's own work is never held up by any of it.
#
# Not against the other node of a cluster: it holds the same key, and root on it is root of the
# cluster's database anyway.

DBGUARD_META_EXACT = frozenset((
    'web:vip', 'web:access', 'fw:conf', 'fw:trial', 'fw_trial_back', 'ntp:conf', 'power:plan',
    'readdress:ask', 'hatls:ca', 'hatls:want', 'host:osup:plan', 'host:sshd:conf',
    'host:sshd:keep', 'host:sshd:back', 'host:logs:again', 'upgrade:plan',
    'upgrade:pkg', 'acme_push:conf', 'acme_push:pairing', 'hisec:waive'))
DBGUARD_META_PREFIXES = (
    'web:tls:', 'web:retry:', 'ntp:sync:', 'net:want:', 'net:job:', 'net:undo:', 'net:keep:',
    'net:back:', 'readdress:dropold:', 'hatls:node:', 'dbtls:server:', 'ask:want:',
    'host:sshkeys:want:', 'host:rootkey:', 'host:osup:checkwant:',
    'console:want:', 'acme_push:key:', 'adm2fa:', 'host:selinux:want:',
    'host:users:want:')
# Settings whose word reaches root, or who may sign in to these pages.
DBGUARD_SETTINGS = frozenset((
    'acme', 'acme_challenge', 'acme_for', 'acme_node_name', 'pki_publish', 'snmp', 'snmp_from', 'snmp_port', 'net_confirm_min', 'fw_confirm_min',
    'web_proxy', 'web_proxy_from', 'web_proxy_header', 'web_proxy_recursive',
    'portal_sso', 'portal_sso_from', 'portal_sso_header', 'portal_sso_key', 'portal_sso_logout',
    'proxy', 'proxy_url', 'proxy_user', 'proxy_password', 'proxy_os', 'proxy_no', 'proxy_update',
    'osup_check', 'osup_check_at', 'osup_auto', 'osup_auto_every', 'osup_auto_day',
    'osup_auto_at', 'osup_auto_reboot', 'osup_auto_what', 'power_auto', 'power_auto_every',
    'power_auto_day', 'power_auto_at', 'power_auto_needed', 'logs_journal_mb',
    'logs_journal_days', 'logs_keep', 'logs_max_mb', 'upgrade_downgrade',
    'upgrade_check', 'upgrade_url', 'high_security', 'admin_directory', 'admin_group_full',
    'admin_group_cert', 'admin_group_portal', 'admin_group_token', 'admin_group_readonly', 'admin_2fa', 'admin_2fa_app', 'admin_2fa_mail',
    'admin_2fa_sms', 'session_hours', 'session_idle_min', 'login_tries', 'login_wait_min',
    'mail_mode', 'mail_from', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_auth',
    'smtp_user', 'smtp_password', 'sms_mode', 'sms_url', 'sms_token', 'sms_spool_dir',
    'sms_tel_host', 'sms_tel_user', 'sms_tel_password', 'sms_tel_https', 'sms_tel_verify'))
DBGUARD_FILE = STATE_DIR / 'guard.json'
DBGUARD = {'seen': None, 'good': None, 'seen_h': None, 'dirty': 0.0, 'refused': {}, 'nodes': {},
           'lock': threading.Lock()}


def dbguard_on():
    return bool(CONFIG.get('db_guard'))


def dbguard_key():
    key = sealing_key()
    return hmac.new(key, b'acme-db-guard-1', hashlib.sha256).digest() if key else None


def dbguard_meta_kept(k):
    """Whether a row of meta is one that is signed."""
    k = str(k or '')
    return k in DBGUARD_META_EXACT or k.startswith(DBGUARD_META_PREFIXES)


def dbguard_meta_signed(k):
    """Signed when written: those above, and the nodes' heartbeats (checked only where root
    uses them - the firewall's cluster rule, nginx's access, the VIP's and chrony's peer)."""
    return dbguard_meta_kept(k) or str(k or '').startswith('node:')


def dbguard_setting_kept(k):
    return str(k or '').split('@', 1)[0] in DBGUARD_SETTINGS


def _dbguard_hash(ident):
    return hashlib.sha256(str(ident).encode('utf-8')).hexdigest()[:40]


def _dbguard_sid(kind, ident, node=None):
    """This node's signature of a row (each node writes only its own - two nodes making one row
    at once is a duplicate key that stops replication for good)."""
    return 'sig:%s:%s:%s' % (kind, _dbguard_hash(ident), node or node_name())


def _dbguard_head_rows(db, head):
    """The rows of meta whose key starts with `head` (letters, digits and colons only), read by
    the key's index: a range on SQLite and MariaDB (their keys compare byte by byte), LIKE on
    PostgreSQL (a collation of a language may not order the colon as a byte would)."""
    if db.engine == 'postgres':
        return db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (head + '%',))
    return db.rows("SELECT k, v FROM meta WHERE k >= ? AND k < ?", (head, head[:-1] + ';'))


def _dbguard_sigs(db, kind, ident):
    """Every node's signature of a row: [(k, n, mac)]."""
    # A range of the key, not LIKE (1.0.231): LIKE read the whole of meta on SQLite at every
    # heartbeat - everything else waited behind it.
    head = 'sig:%s:%s:' % (kind, _dbguard_hash(ident))
    out = []
    for r in _dbguard_head_rows(db, head):
        if not r['k'].startswith(head):
            continue
        try:
            sig = json.loads(r['v'] or 'null')
            out.append((r['k'], int(sig.get('n') or 0), str(sig.get('m') or '')))
        except (ValueError, TypeError, AttributeError):
            continue
    return out


def _dbguard_mac(key, kind, ident, n, value):
    body = b'\x01deleted' if value is None else b'\x00' + str(value).encode('utf-8', 'surrogatepass')
    msg = ('%s\x00%s\x00%d' % (kind, ident, int(n))).encode('utf-8', 'surrogatepass') + body
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _dbguard_load():
    with DBGUARD['lock']:
        if DBGUARD['seen'] is None:
            try:
                got = json.loads(DBGUARD_FILE.read_text())
            except (OSError, ValueError):
                got = {}
            DBGUARD['seen'] = dict(got.get('seen') or {}) if isinstance(got, dict) else {}
            DBGUARD['good'] = dict(got.get('good') or {}) if isinstance(got, dict) else {}
            DBGUARD['seen_h'] = dict(got.get('seen_h') or {}) if isinstance(got, dict) else {}


def dbguard_flush(force=False):
    """The counters seen and the settings last found good, to this node's own file."""
    if DBGUARD['seen'] is None or not DBGUARD['dirty']:
        return
    if not force and time.time() - DBGUARD['dirty'] < 3:
        return
    with DBGUARD['lock']:
        data = json.dumps({'seen': DBGUARD['seen'], 'good': DBGUARD['good'],
                           'seen_h': DBGUARD['seen_h'] or {}})
        DBGUARD['dirty'] = 0.0
    try:
        write_replacing(DBGUARD_FILE, data, 0o600)
    except Exception as e:                              # noqa: BLE001
        log_sparing('guard-file', 'the counters of signed rows could not be written to %s: %s'
                    % (DBGUARD_FILE, e), 'warn', every=600)


def dbguard_sign(db, kind, ident, value, far=False):
    """The row's signature written beside it, in `db` - this node's database, or (`far`) the
    other node's for a row written straight there: only over this node's signature already
    there, never a new row (replication brings that). Without the key nothing is written."""
    key = dbguard_key()
    if not key:
        return False
    sid = _dbguard_sid(kind, ident)
    for _ in range(6):
        try:
            sigs = _dbguard_sigs(db, kind, ident)
        except Exception:                               # noqa: BLE001
            if getattr(db, 'in_tx', False):
                raise
            return False
        raw = db.value('SELECT v FROM meta WHERE k = ?', (sid,))
        # Newer than every node's (1.0.231): read in this order by every node, whatever the
        # clocks say.
        n = max([int(time.time() * 1000)] + [x[1] + 1 for x in sigs])
        new = json.dumps({'n': n, 'm': _dbguard_mac(key, kind, ident, n, value)})
        try:
            if raw is None:
                if far:
                    return False
                db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (sid, new))
                return True
            if db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?', (new, sid, raw)):
                return True
        except Exception:                               # noqa: BLE001
            # Inside a transaction (1.0.234): PostgreSQL has given it up already, so every
            # try after this failed too and the COMMIT became a ROLLBACK, saying nothing -
            # the row and its signature were lost without a word. Said to the caller.
            if getattr(db, 'in_tx', False):
                raise
            continue
    return False


def dbguard_ok(db, kind, ident, value, quiet=False):
    """Whether a row is as acme wrote it: True whenever the guard is off."""
    if not dbguard_on():
        return True
    key = dbguard_key()
    sid = 'sig:%s:%s:*' % (kind, _dbguard_hash(ident))
    why = ''
    try:
        sigs = _dbguard_sigs(db, kind, ident)
    except Exception:                                   # noqa: BLE001
        sigs = []
    if not key:
        why = 'this node has no key to check it with'
    elif not sigs:
        why = 'it is not signed'
    else:
        good = [n for _k, n, m in sigs if hmac.compare_digest(m, _dbguard_mac(key, kind, ident, n, value))]
        if not good:
            why = 'its signature is not right'
        else:
            n = max(good)
            vh = hashlib.sha256(json.dumps(value).encode('utf-8')).hexdigest()[:16]
            _dbguard_load()
            with DBGUARD['lock']:
                seen = int(DBGUARD['seen'].get(sid) or 0)
                hs = DBGUARD['seen_h']
                if hs is None:
                    hs = DBGUARD['seen_h'] = {}
                # An older signature of the same value is no older row (1.0.234): a row signed
                # here and again straight in the other node's database came over by
                # replication with the first signature after the second was seen - refused
                # there for good, though nothing had changed.
                if n < seen and hs.get(sid) != vh:
                    why = 'it is an older one put back'
                elif n > seen:
                    DBGUARD['seen'][sid] = n
                    hs[sid] = vh
                    DBGUARD['dirty'] = DBGUARD['dirty'] or time.time()
    if not why:
        with DBGUARD['lock']:
            DBGUARD['refused'].pop(sid, None)       # good again: no longer listed (1.0.234)
        return True
    if quiet:
        return False                                # asked again by the caller (1.0.234)
    with DBGUARD['lock']:
        was = DBGUARD['refused'].get(sid)
        DBGUARD['refused'][sid] = {'kind': kind, 'what': str(ident)[:120], 'why': why,
                                 'at': time.time(), 'first': (was or {}).get('first') or time.time()}
        if len(DBGUARD['refused']) > 200:
            for old in sorted(DBGUARD['refused'], key=lambda s: DBGUARD['refused'][s]['at'])[:50]:
                DBGUARD['refused'].pop(old, None)
    if not quiet:
        log_sparing('guard:' + sid, 'a row of the database not written by acme is not acted on: %s '
                    '%s - %s' % ({'m': 'meta', 's': 'the setting', 'a': 'the account',
                                  'x': 'a sign-in', 'd': 'the directory'}.get(kind, kind),
                                 str(ident)[:120], why), 'error', every=600)
    return False


def dbguard_settings(saved, store):
    """The settings of the database, those that reach root taken only as signed - else as
    they were last found good, else as config.json and the defaults have them."""
    if not dbguard_on() or store is None:
        return saved
    _dbguard_load()
    out = dict(saved)
    raw = {}
    try:
        raw = {r['k']: r['v'] for r in store.db.rows('SELECT k, v FROM settings')}
    except Exception:                                   # noqa: BLE001
        return saved
    keys = set(k for k in raw if dbguard_setting_kept(k)) | set(
        k for k in (DBGUARD['good'] or {}) if k not in raw)
    for k in keys:
        v = raw.get(k)
        if dbguard_ok(store.db, 's', k, v):
            with DBGUARD['lock']:
                if v is None:
                    DBGUARD['good'].pop(k, None)
                elif DBGUARD['good'].get(k) != v:
                    DBGUARD['good'][k] = v
                    DBGUARD['dirty'] = DBGUARD['dirty'] or time.time()
            continue
        good = (DBGUARD['good'] or {}).get(k)
        if good is None:
            out.pop(k, None)
        else:
            try:
                out[k] = json.loads(good)
            except (TypeError, ValueError):
                out.pop(k, None)
    return out


def dbguard_rows(db, rows):
    """Rows of meta read straight with SQL: those that are signed, the others left out."""
    if not dbguard_on():
        return rows
    return [r for r in rows if not dbguard_meta_kept(r.get('k')) or dbguard_ok(db, 'm', r['k'], r.get('v'))]


ACCOUNT_SIGNED = ('name', 'role', 'pw', 'source', 'disabled', 'must_change', 'dn')
DIRECTORY_SIGNED = ('name', 'hosts', 'port', 'tls', 'verify', 'ca', 'base', 'bind_dn', 'bind_pw',
                    'user_attr', 'enabled', 'weak')


def dbguard_row_text(row, cols):
    return json.dumps([None if row.get(c) is None else str(row.get(c)) for c in cols])


def dbguard_account_sign(db, name):
    row = db.row('SELECT * FROM accounts WHERE LOWER(name) = ?', (str(name or '').strip().lower(),))
    dbguard_sign(db, 'a', str(name or '').strip().lower(), dbguard_row_text(row, ACCOUNT_SIGNED) if row else None)


def dbguard_account_ok(db, row):
    if not row or not dbguard_on():
        return True
    return dbguard_ok(db, 'a', str(row.get('name') or '').lower(), dbguard_row_text(row, ACCOUNT_SIGNED))


def dbguard_directory_sign(db, name):
    row = db.row('SELECT * FROM directories WHERE LOWER(name) = ?', (str(name or '').lower(),))
    dbguard_sign(db, 'd', str(name or '').lower(), dbguard_row_text(row, DIRECTORY_SIGNED) if row else None)


def dbguard_directory_ok(db, name):
    if not dbguard_on():
        return True
    row = db.row('SELECT * FROM directories WHERE LOWER(name) = ?', (str(name or '').lower(),))
    return bool(row) and dbguard_ok(db, 'd', str(name or '').lower(), dbguard_row_text(row, DIRECTORY_SIGNED))


SESSION_SIGNED = ('kind', 'name', 'role', 'created', 'expires')


def dbguard_session_text(row):
    return json.dumps([str(row.get('kind') or ''), str(row.get('name') or ''),
                       str(row.get('role') or ''), '%.3f' % float(row.get('created') or 0),
                       '%.3f' % float(row.get('expires') or 0)])


def dbguard_node_ok(store, name):
    """Whether a node's heartbeat is acme's - before its address is let through the firewall,
    into nginx's lists, or taken for the VIP's and chrony's peer."""
    if not dbguard_on() or name == node_name():
        return True
    try:
        raw = store.db.value('SELECT v FROM meta WHERE k = ?', ('node:' + name,))
    except Exception:                                   # noqa: BLE001
        return False
    if raw is None:
        return False
    try:
        addr = str((json.loads(raw) or {}).get('address') or '')
    except (TypeError, ValueError, AttributeError):
        addr = ''
    if dbguard_ok(store.db, 'm', 'node:' + name, raw, quiet=True):
        with DBGUARD['lock']:
            DBGUARD['nodes'][name] = (addr, time.time())
        return True
    # The heartbeat and its signature come over in two pieces from a node before 1.0.232
    # (two statements): read between them, the new one is not signed yet. The address it
    # had when it was last signed is still taken (1.0.232) - a row written by somebody else
    # cannot point the cluster anywhere new by it.
    with DBGUARD['lock']:
        known = DBGUARD['nodes'].get(name)
    # For a few minutes only (1.0.234): long enough for a signature behind its row, not a
    # row written by somebody else kept for ever.
    if addr and known and known[0] == addr and time.time() - known[1] < 180:
        return True
    return dbguard_ok(store.db, 'm', 'node:' + name, raw)


class SimpleStore(object):
    """A database alone, as dbguard_resign needs it."""

    def __init__(self, db):
        self.db = db

    def add_event(self, *a, **k):
        return None


def dbguard_forget_seen(why=''):
    """The newest signatures seen of each row forgotten, nothing signed (1.0.234): after this
    node's database was taken from the other node, its rows are as old as they are there."""
    _dbguard_load()
    with DBGUARD['lock']:
        DBGUARD['seen'] = {}
        DBGUARD['seen_h'] = {}
        DBGUARD['refused'] = {}
        DBGUARD['dirty'] = time.time()
    dbguard_flush(force=True)
    if why:
        log('the guard against writes to the database starts its counts again: %s' % why)


def dbguard_resign(store, why=''):
    """Every row that is signed, signed again as it is now - when the guard is switched on, and
    after this node itself put rows in from elsewhere (a copy put back, an import, the
    database moved, a node renamed): what is there now is acme's word."""
    db = store.db
    n = 0
    if not dbguard_key():
        return 0
    for r in db.rows('SELECT k, v FROM meta'):
        if dbguard_meta_signed(r['k']):
            n += bool(dbguard_sign(db, 'm', r['k'], r['v']))
    for r in db.rows('SELECT k, v FROM settings'):
        if dbguard_setting_kept(r['k']):
            n += bool(dbguard_sign(db, 's', r['k'], r['v']))
    for r in db.rows('SELECT * FROM accounts'):
        n += bool(dbguard_sign(db, 'a', str(r['name']).lower(), dbguard_row_text(r, ACCOUNT_SIGNED)))
    for r in db.rows('SELECT * FROM directories'):
        n += bool(dbguard_sign(db, 'd', str(r['name']).lower(), dbguard_row_text(r, DIRECTORY_SIGNED)))
    for r in db.rows("SELECT * FROM sessions WHERE kind = 'admin'"):
        n += bool(dbguard_sign(db, 'x', r['token_hash'], dbguard_session_text(r)))
    # What is seen from now on starts here: older ones put back are older than these.
    with DBGUARD['lock']:
        DBGUARD['seen'] = {}
        DBGUARD['seen_h'] = {}
        DBGUARD['good'] = {}
        DBGUARD['refused'] = {}
        DBGUARD['dirty'] = time.time()
    if why:
        try:
            store.add_event('security', 'the rows of the database that reach root signed again '
                            '(%d) - %s' % (n, why), 'warn')
        except Exception:                               # noqa: BLE001
            pass
    return n


def dbguard_tidy(store):
    """Signatures of sign-ins that are over."""
    try:
        have = {_dbguard_sid('x', r['token_hash']) for r in store.db.rows(
            "SELECT token_hash FROM sessions WHERE kind = 'admin'")}
        for r in _dbguard_head_rows(store.db, 'sig:x:'):
            if r['k'] not in have and r['k'].endswith(':' + node_name()):
                try:
                    if time.time() * 1000 - float((json.loads(r['v']) or {}).get('n') or 0) < 3600e3:
                        continue
                except (ValueError, TypeError, AttributeError):
                    pass
                store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
    except Exception:                                   # noqa: BLE001
        pass
    dbguard_flush()


def dbguard_view():
    _dbguard_load()
    with DBGUARD['lock']:
        refused = sorted(DBGUARD['refused'].values(), key=lambda x: -x['at'])[:50]
    return {'on': dbguard_on(), 'key': bool(dbguard_key()), 'refused': refused}


