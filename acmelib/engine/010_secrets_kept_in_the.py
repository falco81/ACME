# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Secrets kept in the database, sealed
# ---------------------------------------------------------------------------
# The certificates' private keys, the passwords acme signs in to the targets
# and the issuers with, the directories' passwords and the secrets among the
# settings are kept in the database - sealed, with a key in a file of its own
# in the state directory, exactly as isemon seals its passwords. A copy of the
# database alone opens none of them; the daily copy is made with the key
# beside it, because a database of sealed keys without the key that opens
# them is a database of nothing, and every certificate would have to be
# issued again.
# Built from HMAC-SHA256 alone - a keystream and a tag - because the standard
# library has no cipher and this must not need anything installed.
SEALED = 'sealed:1:'


def scrub_secret(text):
    """Words that may carry a database password (a conninfo in an error, say)
    with the password taken out, before they are logged or shown. A quoted value is read as
    libpq quotes it - \\' and \\\\ inside, to the quote that ends it - and as SQL doubles it
    inside another string ('' for '): 1.0.96, a password with a quote and a space in it showed
    its end. Unquoted: up to the next space."""
    s = str(text or '')
    pat = re.compile(r'(password\s*=\s*)', re.I)
    out, pos = [], 0
    while True:
        m = pat.search(s, pos)
        if not m:
            out.append(s[pos:])
            break
        out.append(s[pos:m.end()] + '***')
        j = m.end()
        if j < len(s) and s[j] == "'":
            q = 2 if s.startswith("''", j) and not (j + 2 >= len(s) or s[j + 2].isspace()) else 1
            if q == 1 and s.startswith("''", j):
                j += 2                                  # an empty value
            else:
                quote = "'" * q
                j += q
                while j < len(s):
                    if s[j] == '\\':
                        j += 1 + (q if s.startswith(quote, j + 1) else 1)
                        continue
                    if s.startswith(quote, j):
                        j += q
                        break
                    j += 1
        else:
            while j < len(s) and not s[j].isspace():
                j += 1
        pos = j
    return ''.join(out)


def sealing_key_path():
    return Path(STATE_DIR) / 'secrets.key'


_KEY_CACHE = {}
_KEY_LOCK = threading.Lock()


def sealing_key(make=False):
    """The key every secret in the database is sealed with. Read once and
    kept while the file is unchanged (1.0.33) - it was read from disk for
    every secret opened, every key in a list of thousands. Made only where
    there is none, and then with O_EXCL, so two processes starting at once
    cannot each make one of their own."""
    path = sealing_key_path()
    try:
        st = os.stat(str(path))
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        stamp = None
    except OSError:
        stamp = 'unreadable'
    if stamp is not None and stamp != 'unreadable':
        got = _KEY_CACHE.get(str(path))
        if got and got[0] == stamp:
            return got[1]
    try:
        key = bytes.fromhex(path.read_text(encoding='ascii').strip())
    except FileNotFoundError:
        key = None
    except (OSError, ValueError):
        key = b''
    if key and len(key) == 32:
        if stamp and stamp != 'unreadable':
            _KEY_CACHE[str(path)] = (stamp, key)
        return key
    if not make:
        return b''
    if key is not None:
        raise OSError('%s is there but cannot be read as a key - it is never replaced, '
                      'because every secret sealed with it would be lost' % path)
    with _KEY_LOCK:
        key = secrets.token_bytes(32)
        # Written whole beside it, then linked into place (1.0.94): created
        # empty first, another process starting just then read an empty
        # key and stopped.
        tmp = '%s.new-%d-%s' % (path, os.getpid(), secrets.token_hex(4))
        # A name nobody made before, never through a link (1.0.101), and
        # given to the folder's owner while it is still open.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.geteuid() == 0:
                st = os.stat(str(path.parent))
                os.fchown(fd, st.st_uid, st.st_gid)
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(key.hex() + '\n')
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, str(path))
        except FileExistsError:
            # Made by somebody else a moment ago: theirs is the key.
            os.unlink(tmp)
            return sealing_key(make=False) or b''
        os.unlink(tmp)
        log('a new key to seal secrets with was made: %s - keep a copy of it beside every '
            'copy of the database' % path, 'warn')
    return key


def _seal_stream(key, nonce, size):
    out = bytearray()
    block = 0
    while len(out) < size:
        out += hmac.new(key, b'stream' + nonce + block.to_bytes(8, 'big'),
                        hashlib.sha256).digest()
        block += 1
    return bytes(out[:size])


SEALED2 = 'sealed:2:'
SEAL_GUARD = {'db': None}         # the database of this process, for _sealed_held


def sealed_columns():
    """(table, column) of every column that holds a sealed value: the
    settings' values, and every column of SCHEMA whose name ends in _sealed
    (a table a module appends to SCHEMA is looked at too)."""
    out = [('settings', 'v')]
    for table, create in SCHEMA:
        for col in re.findall(r'\b(\w+_sealed)\s+\{', create):
            out.append((table, col))
    return out


# How a sealed column's value is bound, by (table, column): a module whose
# values are sealed under a bind of its own registers it here, so a backup's
# check and the export of the configuration open them as the module does.
SEAL_BINDS = {}


def seal_bind(table, row, col):
    """The bind `row`'s `col` of `table` was sealed under."""
    fn = SEAL_BINDS.get((table, col))
    if fn is not None:
        try:
            return fn(row)
        except (KeyError, TypeError, ValueError):
            pass
    return '%s:%s:%s' % (table, row.get('id'), col)


def sealed_held(db):
    """Whether `db` holds anything sealed with a key (it cannot be asked:
    held, to be safe)."""
    for table, col in sealed_columns():
        try:
            if db.value("SELECT 1 FROM %s WHERE %s LIKE 'sealed:%%' LIMIT 1" % (table, col)):
                return True
        except Exception:                               # noqa: BLE001
            return True
    return False


def sealed_opens(db, most=5):
    """Whether the secrets sealed in `db` open with the key in use: True, False
    - or None when there is nothing to try. The settings sealed are tried (those
    are sealed without a place they are bound to)."""
    try:
        rows = db.rows("SELECT v FROM settings WHERE v LIKE ? LIMIT %d" % int(most),
                       ('%' + SEALED + '%',))
    except Exception:                                   # noqa: BLE001
        return None
    tried = []
    for row in rows:
        try:
            value = json.loads(row['v'])
        except (TypeError, ValueError):
            continue
        if isinstance(value, str) and value.startswith(SEALED):
            tried.append(unseal_secret(value) is not None)
    return any(tried) if tried else None


def _sealed_held():
    db = SEAL_GUARD.get('db')
    return False if db is None else sealed_held(db)


def seal_secret(text, bind=None):
    """Sealed with the key of this installation: a keystream from HMAC-SHA256,
    then a tag over it. With `bind`, the tag covers that too (sealed:2:), so
    the value opens only where it was sealed for."""
    key = sealing_key()
    if not key:
        # No new key while the database holds secrets sealed with one (1.0.205):
        # the first secret sealed after the key was lost - a setting saved, a
        # key imported - made a new one, past the daemon's own refusal at its
        # start; the secrets stayed lost, and two nodes sealed each with its own.
        if _sealed_held():
            raise OSError('%s is missing, and the database holds secrets sealed with it: no '
                          'new key is made - put the key back (it is beside every backup)'
                          % sealing_key_path())
        key = sealing_key(make=True)
    if not key:
        raise OSError('no key to seal with')
    data = str(text).encode('utf-8')
    nonce = secrets.token_bytes(16)
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    body = bytes(a ^ b for a, b in zip(data, _seal_stream(hide, nonce, len(data))))
    if bind is not None:
        tag = hmac.new(sign, b'2|' + str(bind).encode('utf-8') + b'|' + nonce + body,
                       hashlib.sha256).digest()[:16]
        return SEALED2 + base64.urlsafe_b64encode(nonce + body + tag).decode('ascii')
    tag = hmac.new(sign, nonce + body, hashlib.sha256).digest()[:16]
    return SEALED + base64.urlsafe_b64encode(nonce + body + tag).decode('ascii')


def unseal_secret(value, bind=None):
    """The secret back, or None where this machine's key is not the one it was
    sealed with - or, for one bound to a place, where it is not that place. A
    value never sealed is given back as it is."""
    if not isinstance(value, str):
        return value
    if value.startswith(SEALED2):
        v2, prefix = True, SEALED2
    elif value.startswith(SEALED):
        v2, prefix = False, SEALED
    else:
        return value
    if v2 and bind is None:
        return None
    key = sealing_key()
    try:
        raw = base64.urlsafe_b64decode(value[len(prefix):].encode('ascii'))
    except (ValueError, TypeError):
        return None
    if not key or len(raw) < 32:
        return None
    nonce, body, tag = raw[:16], raw[16:-16], raw[-16:]
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    signed = (b'2|' + str(bind).encode('utf-8') + b'|' if v2 else b'') + nonce + body
    if not hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()[:16]):
        return None
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    try:
        return bytes(a ^ b for a, b in zip(body, _seal_stream(hide, nonce, len(body)))
                     ).decode('utf-8')
    except UnicodeDecodeError:
        return None


