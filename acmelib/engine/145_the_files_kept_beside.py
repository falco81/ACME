# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The files kept beside the database, the disk under it, and putting one back
# ---------------------------------------------------------------------------
# As on isemon (1.10.160 on): two kinds of file are kept.
#
#   A *copy* is made by this program: every row of every table, written as a
#   portable file, which goes back into any of the three engines. That is
#   what carries an installation from the file to a server and back.
#
#   A *dump* is made by the engine's own program - pg_dump, mariadb-dump, or
#   for the file SQLite's own backup, which is the file. It is a fraction of
#   the size, the server's own tools read it, and it goes back into the
#   engine it came off.
#
# Every one of either kind has the key that opens its sealed secrets (the
# private keys, the passwords) beside it, in a file of its own, because one
# without the other is nothing.

DUMP_DIR = STATE_DIR / 'dumps'
DUMP_SUFFIX = {'sqlite': '.db', 'mariadb': '.sql.gz', 'postgres': '.pgc', 'copy': '.json.gz'}
DUMP_WORDS = {'sqlite': 'a copy of the file', 'mariadb': 'a MariaDB dump',
              'postgres': 'a PostgreSQL dump', 'copy': 'a portable copy'}
DUMP_TOOLS = {'sqlite': (),
              'mariadb': (('making one', ('mariadb-dump', 'mysqldump')),
                          ('putting one back', ('mariadb', 'mysql'))),
              'postgres': (('making one', ('pg_dump',)),
                           ('putting one back', ('pg_restore',)))}
DUMP_INSTALL = {'mariadb': 'dnf install mariadb (it is the client, not the server)',
                'postgres': 'dnf install postgresql (it is the client, not the server)'}
DRIVERS = {'mariadb': ('pymysql', 'python3-PyMySQL'),
           'postgres': ('psycopg2', 'python3-psycopg2')}
# The names acme gives them (1.0.39): acme-ENGINE-STAMP-WHY. Only otp's own
# (otp-, opt-) were taken, so the nightly dumps were never listed, counted
# on the card The database, kept to "Copies kept", or let downloaded.
NAME_RE = re.compile(r'^(?:acme|otp|opt)-(sqlite|mariadb|postgres|copy)?-?(\d{8}-\d{6})(?:-([a-z-]+))?'
                     r'(\.db|\.sql\.gz|\.pgc|\.json\.gz)$')


def drivers_state():
    """Whether the driver for each server engine is installed - said before
    somebody types an address rather than after they press a button."""
    out = {}
    for engine, (module, package) in DRIVERS.items():
        try:
            __import__(module)
            out[engine] = {'ready': True, 'package': package}
        except Exception as e:                          # noqa: BLE001
            out[engine] = {'ready': False, 'package': package,
                           'says': 'the driver %s is not installed (%s)' % (module, e)}
    return out


def dump_info(engine):
    """Which program tonight's dump will be made with, and whether it is here."""
    out = {'engine': engine, 'words': DUMP_WORDS.get(engine, engine),
           'suffix': DUMP_SUFFIX.get(engine, ''), 'where': str(DUMP_DIR),
           'install': DUMP_INSTALL.get(engine, ''), 'ready': True, 'why': ''}
    for what, names in DUMP_TOOLS.get(engine, ()):
        if not any(shutil.which(n) for n in names):
            out.update(ready=False, why='%s is not on this machine, so a dump cannot be %s'
                       % (names[0], 'made' if what == 'making one' else 'put back'))
            break
    return out


def _tool(names):
    for one in names:
        got = shutil.which(one)
        if got:
            return got
    raise ValueError('%s is not on this machine' % names[0])


def _db_conf():
    return {k: CONFIG.get(k) for k in DB_KEYS}


def safe_db_name(c):
    """The database's name, as it may stand on a command line: never one
    that reads as an option (1.0.33)."""
    name = str(c.get('db_name') or '')
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,62}\Z', name):
        raise DbError('the database name %r is not letters, digits and _' % name[:60])
    return name


def _my_cnf(c):
    """A defaults file holding the password and nothing else, 0600, gone the
    moment the program has finished with it: `--password=` on a command line
    is readable by everybody on the machine while it runs."""
    said = str(c.get('db_password') or '')
    if any(ord(ch) < 32 for ch in said):
        # Asked before the file is made (1.0.208): an empty one was left behind.
        raise DbError('the database password has a line break or another control '
                      'character in it')
    handle, name = tempfile.mkstemp(prefix='acme-my-', suffix='.cnf')
    os.close(handle)
    os.chmod(name, 0o600)
    with open(name, 'w') as f:
        f.write('[client]\npassword="%s"\n' % said.replace('\\', '\\\\').replace('"', '\\"'))
    return name


def _my_args(c, cnf):
    out = ['--defaults-extra-file=%s' % cnf,
           '--host=%s' % (str(c.get('db_host') or '127.0.0.1').strip('[]')),
           '--port=%d' % int(c.get('db_port') or 3306),
           '--user=%s' % (c.get('db_user') or '')]
    # The dump and restore tools encrypted as the daemon's own connection is
    # (1.0.36).
    mode = str((c.get('db_tls') if 'db_tls' in c else CONFIG.get('db_tls')) or '')
    ca = str((c.get('db_tls_ca') if 'db_tls_ca' in c else CONFIG.get('db_tls_ca')) or '')
    if mode:
        out.append('--ssl')
        if mode in ('verify-ca', 'verify-full'):
            out.append('--ssl-verify-server-cert')
        if ca:
            out.append('--ssl-ca=%s' % ca)
    return out


def _pg_args(c):
    return ['--host=%s' % (str(c.get('db_host') or '127.0.0.1').strip('[]')),
            '--port=%d' % int(c.get('db_port') or 5432),
            '--username=%s' % (c.get('db_user') or ''), '--no-password']


def _pg_passfile(c):
    """A password file for pg_dump / pg_restore (1.0.207): 0600, for this one run,
    gone after it - PGPASSWORD in their environment was readable in /proc as
    they ran, as the MariaDB side's defaults file already avoids."""
    handle, name = tempfile.mkstemp(prefix='acme-pg-', suffix='.pass')
    os.fchmod(handle, 0o600)
    said = str(c.get('db_password') or '')
    if any(ord(ch) < 32 for ch in said):
        os.close(handle)
        os.unlink(name)
        raise DbError('the database password has a line break or another control character in it')
    with os.fdopen(handle, 'w') as f:
        f.write('*:*:*:*:%s\n' % said.replace('\\', '\\\\').replace(':', '\\:'))
    return name


def _pg_env(c, passfile=None):
    env = dict(os.environ)
    env.pop('PGPASSWORD', None)
    if passfile:
        env['PGPASSFILE'] = passfile
    env['PGCONNECT_TIMEOUT'] = str(int(c.get('db_timeout_s') or 10))
    mode = str((c.get('db_tls') if 'db_tls' in c else CONFIG.get('db_tls')) or '')
    ca = str((c.get('db_tls_ca') if 'db_tls_ca' in c else CONFIG.get('db_tls_ca')) or '')
    if mode:
        env['PGSSLMODE'] = mode
        if ca:
            env['PGSSLROOTCERT'] = ca
    return env


def _run(args, words, stdin=None, stdout=None, env=None, seconds=3600):
    try:
        got = subprocess.run(args, stdin=stdin, stdout=stdout if stdout is not None
                             else subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                             timeout=seconds)
    except subprocess.TimeoutExpired:
        raise ValueError('%s took longer than %d s and was stopped' % (words, seconds))
    if got.returncode != 0:
        said = (got.stderr or b'').decode('utf-8', 'replace').strip().split('\n')
        raise ValueError('%s failed: %s' % (words, (said[-1] if said else
                                                     'exit %d' % got.returncode)[:300]))
    return got.stdout


def _stamp():
    return datetime.now().strftime('%Y%m%d-%H%M%S')


def _key_beside(path):
    p = str(path)
    for suf in ('.json.gz', '.sql.gz', '.pgc', '.db'):
        if p.endswith(suf):
            return Path(p[:-len(suf)] + '.key')
    return Path(p + '.key')


def _write_key_beside(path):
    key = sealing_key()
    if key:
        write_replacing(_key_beside(path), key.hex() + '\n', 0o600)


def _kind_of_name(name):
    for kind, suf in (('copy', '.json.gz'), ('mariadb', '.sql.gz'), ('postgres', '.pgc'),
                      ('sqlite', '.db')):
        if name.endswith(suf):
            return kind
    return ''


def _prune(folder, pattern, keep):
    files = sorted((f for f in folder.glob(pattern) if NAME_RE.match(f.name)),
                   key=lambda f: f.stat().st_mtime)
    for old in files[:-keep] if keep > 0 and len(files) > keep else []:
        for f in (old, _key_beside(old)):
            try:
                f.unlink()
            except OSError:
                pass


def copy_engine(path):
    """Which engine a copy was taken off: its first line says."""
    import gzip
    try:
        with gzip.open(str(path), 'rt', encoding='utf-8') as f:
            return json.loads(f.readline() or '{}').get('engine') or ''
    except Exception:                                   # noqa: BLE001
        return ''


def kept_copies():
    """The copies this program made, newest first."""
    if not BACKUP_DIR.is_dir():
        return []
    out = []
    for f in sorted(list(BACKUP_DIR.glob('acme-*.json.gz')) + list(BACKUP_DIR.glob('opt-*.json.gz')),
                   key=lambda x: x.stat().st_mtime,
                    reverse=True):
        st = f.stat()
        out.append({'name': f.name, 'bytes': st.st_size, 'size': st.st_size, 'at': st.st_mtime,
                    'from': copy_engine(f), 'key': _key_beside(f).exists(), 'kind': 'copy'})
    return out


def kept_dumps(engine):
    """The dumps the engine made of itself, newest first."""
    if not DUMP_DIR.is_dir():
        return []
    out = []
    for f in sorted(DUMP_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        m = NAME_RE.match(f.name)
        if not m:
            continue
        kind = _kind_of_name(f.name)
        came = m.group(1) or ''
        if kind == 'copy':
            came = copy_engine(f) or came
        st = f.stat()
        out.append({'name': f.name, 'bytes': st.st_size, 'at': st.st_mtime, 'kind': kind,
                    'from': came if kind != 'copy' else came,
                    'mine': kind == 'copy' or kind == engine,
                    'key': _key_beside(f).exists()})
    return out


def nightly_state(store):
    """How this node's nightly copy of the database stands (1.0.39) - what
    the card The database on Overview is coloured by, and what its popup
    says: on or off, when the last one was made, when the next one is
    due, why it is late.

    `why` is one of: '' (a copy of the last two days is here), 'off' (no
    copy every day), 'failed' (the last night's one failed - `failed` says
    how), 'other_node' (a cluster on one database: the other node made
    today's), 'none' (none made yet, the first one comes at `next`) or
    'late' (it is due, and none came)."""
    import datetime as _dt
    engine = store.db.engine
    kept = []
    try:
        kept = [dict(x, where='copy') for x in backups()]
    except Exception:                                   # noqa: BLE001
        pass
    try:
        kept += [dict(x, where='dump') for x in kept_dumps(engine)]
    except Exception:                                   # noqa: BLE001
        pass
    newest = max(kept, key=lambda x: float(x.get('at') or 0)) if kept else None
    last = float(newest.get('at') or 0) if newest else 0.0
    on = bool(CONFIG.get('backup_daily'))
    at = str(CONFIG.get('backup_at') or '03:30').strip()
    try:
        hh, mm = (int(x) for x in at.split(':', 1))
    except ValueError:
        hh, mm = 3, 30
    at = '%02d:%02d' % (hh, mm)
    ha = str(CONFIG.get('ha_mode') or '')
    key = 'backup_day' + (':' + node_name() if ha == 'replicated' else '')
    now = _dt.datetime.now()
    today = now.strftime('%Y-%m-%d')
    try:
        done = store.get_meta(key, '') or ''
    except Exception:                                   # noqa: BLE001
        done = ''
    nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if done == today or nxt <= now:
        nxt += _dt.timedelta(days=1)
    failed = None
    try:
        rows, _n = store.events(limit=20, kind='backups')
        me = log_node()
        for r in rows:
            if str(r.get('level') or '') != 'bad' or float(r.get('ts') or 0) <= last:
                continue
            if r.get('node') and str(r.get('node')) != me:
                continue
            failed = {'at': float(r.get('ts') or 0), 'words': str(r.get('words') or '')}
            break
    except Exception:                                   # noqa: BLE001
        pass
    fresh = bool(last) and time.time() - last < 2 * 86400
    why = ''
    if not fresh:
        if not on:
            why = 'off'
        elif failed:
            why = 'failed'
        elif ha and ha != 'replicated' and done and done >= (now - _dt.timedelta(days=1)).strftime('%Y-%m-%d'):
            why = 'other_node'
        elif not last:
            why = 'none'
        else:
            why = 'late'
    info = {}
    try:
        info = dump_info(engine)
    except Exception:                                   # noqa: BLE001
        pass
    return {'on': on, 'at': at, 'next': nxt.timestamp() if on else None, 'last': last or None,
            'last_name': newest.get('name') if newest else '', 'last_where': newest.get('where') if newest else '',
            'day_done': done, 'failed': failed, 'fresh': fresh, 'why': why,
            'shared': bool(ha and ha != 'replicated'), 'node': node_name(),
            'tool_ready': bool(info.get('ready', True)), 'tool_why': info.get('why') or '',
            'tool_words': info.get('words') or '', 'dump_dir': str(DUMP_DIR), 'copy_dir': str(BACKUP_DIR)}


def make_dump(store, label='daily', folder=None):
    """A dump of the database in use by its own engine's program - or, where
    that program is not on this machine, a portable copy in its place."""
    engine = store.db.engine
    folder = Path(folder) if folder else DUMP_DIR
    folder.mkdir(parents=True, exist_ok=True)
    backup_room_check(store, folder)            # never the disk filled (1.0.149)
    info = dump_info(engine)
    kind = engine if info['ready'] else 'copy'
    name = 'acme-%s-%s-%s%s' % (engine if kind != 'copy' else 'copy', _stamp(),
                              re.sub(r'[^a-z-]', '', label) or 'daily', DUMP_SUFFIX[kind])
    target = folder / name
    part = Path(str(target) + '.part')
    c = _db_conf()
    try:
        if kind == 'copy':
            dump_tables(store.db, part)
        elif engine == 'sqlite':
            # SQLite's own backup: a consistent copy of the file even while the
            # daemon writes to it.
            src = sqlite3.connect(str(store.db.path))
            dst = sqlite3.connect(str(part))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
        elif engine == 'mariadb':
            import gzip
            tool = _tool(('mariadb-dump', 'mysqldump'))
            cnf = _my_cnf(c)
            try:
                raw = Path(str(part) + '.raw')
                with open(str(raw), 'wb') as out:
                    _run([tool] + _my_args(c, cnf) + [
                        '--single-transaction', '--quick', '--skip-lock-tables',
                        '--default-character-set=utf8mb4', '--no-tablespaces',
                        '--add-drop-table', '--skip-comments', safe_db_name(c)],
                        'mariadb-dump', stdout=out)
                with open(str(raw), 'rb') as src, gzip.open(str(part), 'wb', 6) as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                raw.unlink()
            finally:
                os.unlink(cnf)
        else:
            tool = _tool(('pg_dump',))
            pf = _pg_passfile(c)
            try:
                _run([tool] + _pg_args(c) + ['--format=custom', '--compress=6', '--no-owner',
                                             '--no-privileges', '--file=%s' % part,
                                             '--dbname=%s' % safe_db_name(c)],
                     'pg_dump', env=_pg_env(c, pf))
            finally:
                os.unlink(pf)
        os.chmod(str(part), 0o640)
        part.replace(target)
    finally:
        for left in (part, Path(str(part) + '.raw')):
            if left.exists():
                try:
                    left.unlink()
                except OSError:
                    pass
    _write_key_beside(target)
    if folder == DUMP_DIR:
        _prune(DUMP_DIR, '*-*', int(CONFIG.get('backup_keep') or 14))
    store.add_event('backups', 'made %s (%s): %s' % (
        DUMP_WORDS[kind], {'daily': 'every night', 'by-hand': 'by hand',
                           'download': 'to be downloaded'}.get(label, label), target.name))
    return target


# ---- what is in a file, without putting any of it back ------------------------
def _magic(path):
    with open(str(path), 'rb') as f:
        return f.read(16)


PEEK_LINE_MOST = 64 << 20      # one row of a copy, unpacked (1.0.44)


def _lines_capped(f, most=PEEK_LINE_MOST):
    """The lines of an unpacked file, none longer than `most` - one line of a packed bomb
    unpacked into memory whole."""
    while True:
        line = f.readline(most + 1)
        if not line:
            return
        if len(line) > most and line[-1:] not in ('\n', b'\n'):
            raise ValueError('a line of the file is longer than %d MB - not a copy acme made'
                             % (most >> 20))
        yield line


def _copy_capped(src, dst, room):
    """src into dst, refused once more than `room` bytes came out (1.0.44): a small packed
    file that unpacks into the whole disk."""
    done = 0
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            return done
        done += len(chunk)
        if done > room:
            raise ValueError('unpacked, the file is larger than the room there is for it '
                             '(%d MB) - not put back' % (room >> 20))
        dst.write(chunk)


def _peek_copy(path):
    import gzip
    counts, admins, tables, table = {}, 0, 0, None
    with gzip.open(str(path), 'rt', encoding='utf-8') as f:
        head = json.loads(f.readline(PEEK_LINE_MOST) or '{}')
        if 'acme' not in head and 'opt' not in head:      # 'opt': before 1.0.37's new name
            return None, 'that is not a copy made by acme'
        for line in _lines_capped(f):
            got = json.loads(line)
            if set(got.keys()) == {'table'}:
                table = got['table']
                tables += 1
                counts.setdefault(table, 0)
                continue
            if table:
                counts[table] += 1
                if table == 'accounts' and got.get('role') == 'fulladmin' \
                        and not got.get('disabled'):
                    admins += 1
    return {'kind': 'copy', 'from': head.get('engine') or '', 'version': head.get('acme') or head.get('opt'),
            'made': head.get('made'), 'counts': counts, 'admins': admins, 'tables': tables,
            'key': bool(head.get('key')), 'machine': head.get('machine')}, ''


def _peek_sqlite(path):
    try:
        con = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    except sqlite3.Error as e:
        return None, 'that file could not be opened: %s' % e
    try:
        names = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")]
        if 'accounts' not in names or 'settings' not in names:
            return None, 'that is not a database of acme: it has no settings and no accounts'
        counts = {t: con.execute('SELECT COUNT(*) FROM %s' % t).fetchone()[0]
                  for t in TABLES if t in names}
        admins = con.execute("SELECT COUNT(*) FROM accounts WHERE role = 'fulladmin' AND "
                             "COALESCE(disabled, 0) = 0").fetchone()[0]
    except sqlite3.Error as e:
        return None, 'that database could not be read: %s' % e
    finally:
        con.close()
    return {'kind': 'sqlite', 'counts': counts, 'admins': admins,
            'tables': len([t for t in TABLES if t in names])}, ''


ACCOUNT_COLS_FIRST = ('id', 'name', 'role', 'pw', 'source', 'disabled')


def _my_rows(text):
    """The rows of a mysqldump VALUES list: (a,'b',NULL),(...) - each a list
    of its values as text, quotes taken off, NULL as 'NULL'."""
    rows, row, cur, depth, quote, esc, had_q = [], [], [], 0, False, False, False
    for ch in text:
        if quote:
            if esc:
                cur.append(ch)
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == "'":
                quote = False
            else:
                cur.append(ch)
            continue
        if ch == "'":
            quote, had_q = True, True
        elif ch == '(':
            depth += 1
            if depth == 1:
                row, cur, had_q = [], [], False
        elif ch == ')' and depth:
            depth -= 1
            if depth == 0:
                row.append(''.join(cur) if had_q else ''.join(cur).strip())
                rows.append(row)
        elif ch == ',' and depth == 1:
            row.append(''.join(cur) if had_q else ''.join(cur).strip())
            cur, had_q = [], False
        elif depth:
            cur.append(ch)
    return rows


def _peek_mariadb(path):
    import gzip
    tables, admins, users, in_users = set(), 0, 0, False
    cols = None
    with gzip.open(str(path), 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('CREATE TABLE'):
                got = re.search(r'CREATE TABLE `([^`]+)`', line)
                if got:
                    tables.add(got.group(1))
                continue
            first = line.startswith('INSERT INTO `accounts`')
            if first:
                in_users = True
            elif in_users and not line.startswith('('):
                in_users = False
            if in_users:
                head = re.match(r"INSERT INTO `accounts` \(([^)]*)\)", line)
                if head:
                    cols = [c.strip(' `') for c in head.group(1).split(',')]
                rest = line.split('VALUES', 1)[-1] if first else line
                # A full administrator switched off is nobody who signs in (1.0.208).
                for row in _my_rows(rest):
                    names = cols or ACCOUNT_COLS_FIRST
                    got = dict(zip(names, row))
                    if got.get('role') == 'fulladmin' and str(got.get('disabled') or '0') in (
                            '0', 'NULL', ''):
                        admins += 1
                users += rest.count('),(') + (1 if '(' in rest else 0)
                if line.rstrip().endswith(';'):
                    in_users = False
    if 'accounts' not in tables or 'settings' not in tables:
        return None, 'that dump is not one of acme - it has no settings and no accounts'
    return {'kind': 'mariadb', 'counts': {'accounts': users}, 'admins': admins,
            'tables': len(tables)}, ''


def _peek_postgres(path):
    tool = shutil.which('pg_restore')
    if not tool:
        return None, ('pg_restore is not on this machine, so what is in that dump cannot be '
                      'read: %s' % DUMP_INSTALL['postgres'])
    listed = _run([tool, '--list', str(path)], 'pg_restore --list', seconds=300)
    tables = set(re.findall(r'TABLE DATA\s+\S+\s+(\S+)', listed.decode('utf-8', 'replace')))
    if 'accounts' not in tables or 'settings' not in tables:
        return None, 'that dump is not one of acme - it has no settings and no accounts'
    rows = _run([tool, '--data-only', '--table=accounts', '--file=-', str(path)],
                'pg_restore', seconds=300).decode('utf-8', 'replace')
    users = admins = 0
    inside = False
    cols = list(ACCOUNT_COLS_FIRST)
    for line in rows.split('\n'):
        if line.startswith('COPY '):
            inside = True
            got = re.match(r'COPY \S+ \(([^)]*)\)', line)
            if got:
                cols = [c.strip(' "') for c in got.group(1).split(',')]
            continue
        if inside:
            if line == '\\.':
                break
            users += 1
            row = dict(zip(cols, line.split('\t')))
            # A full administrator switched off is nobody who signs in (1.0.208).
            if row.get('role') == 'fulladmin' and row.get('disabled', '\\N') in ('\\N', '0', ''):
                admins += 1
    return {'kind': 'postgres', 'counts': {'accounts': users}, 'admins': admins,
            'tables': len(tables)}, ''


def db_file_peek(path, engine, need_admin=True):
    """What is in a copy or a dump, and whether it may be put back here."""
    head = _magic(path)
    try:
        if head.startswith(b'SQLite format 3'):
            said, why = _peek_sqlite(path)
        elif head.startswith(b'PGDMP'):
            said, why = _peek_postgres(path)
        elif head[:2] == b'\x1f\x8b':
            import gzip
            with gzip.open(str(path), 'rb') as f:
                first = f.read(64)
            if first.startswith(b'{'):
                said, why = _peek_copy(path)
            else:
                said, why = _peek_mariadb(path)
        else:
            return None, 'that is neither a copy nor a dump made by acme'
    except Exception as e:                              # noqa: BLE001
        return None, 'that file could not be read: %s' % str(e).split('\n')[0][:200]
    if said is None:
        return None, why
    kind = said['kind']
    if kind not in ('copy', 'sqlite') and kind != engine:
        return None, ('that is %s, and this installation is on %s: a dump goes back only into '
                      'the engine it came off. Use a copy - a copy goes into any of the three.'
                      % (DUMP_WORDS[kind], ENGINE_WORDS.get(engine, engine)))
    if not said.get('admins'):
        # On the command line root makes one afterwards (1.0.62): a copy of
        # a server set up there alone was refused for good.
        if need_admin:
            return None, ('there is no full administrator who can sign in in that file: putting '
                          'it back would lock everybody out of these pages (on the command line '
                          'it can be put back, and an account made after it)')
        said['no_admin'] = True
    said['bytes'] = Path(path).stat().st_size
    return said, ''


def _sqlite_to_copy(path, out):
    """A SQLite file of ours, as a copy: so that it goes back into whatever
    engine is in use, by the same road as every copy."""
    src = Db('sqlite', path=path)
    try:
        dump_tables(src, out, [t for t in TABLES if t in src.tables()])
    finally:
        src.close()
    return out


def db_file_restore(store, path, by, key_file=None, from_name='', need_admin=True):
    """Put a copy or a dump back over everything. A copy of what is replaced
    is made first and kept with the others."""
    engine = store.db.engine
    said, why = db_file_peek(path, engine, need_admin)
    if said is None:
        raise ValueError(why)
    kind = said['kind']
    if CONFIG.get('ha_mode') == 'replicated' and kind in ('postgres', 'mariadb'):
        raise ValueError('a dump puts tables back by making them again, which replication '
                         'does not carry to the other node: put a copy back instead (it goes '
                         'over row by row)')
    # A kept copy is read from a copy of its own (1.0.44): the safety copy
    # below rotates the kept ones, and the oldest - the one being put back -
    # would be the one it took away.
    held = []
    try:
        if Path(path).resolve().parent == Path(BACKUP_DIR).resolve():
            ext = ''.join(Path(path).suffixes[-2:]) if str(path).endswith('.gz') else Path(path).suffix
            fd, tmpname = tempfile.mkstemp(prefix='acme-putback-', suffix=ext, dir=str(STATE_DIR))
            os.close(fd)
            shutil.copyfile(str(path), tmpname)
            os.chmod(tmpname, 0o600)
            held.append(Path(tmpname))
            kf = Path(key_file) if key_file else None
            if kf and kf.exists():
                fd, kname = tempfile.mkstemp(prefix='acme-putback-', suffix='.key', dir=str(STATE_DIR))
                os.close(fd)
                shutil.copyfile(str(kf), kname)
                os.chmod(kname, 0o600)
                held.append(Path(kname))
                key_file = kname
            path = tmpname
        # This node answers nothing while it is done (1.0.149): the VPN asks
        # the other node, as in maintenance.
        RESTORE_WHY[0] = 'a backup is being put back'
        RESTORE_RUNNING.set()
        try:
            got = _db_file_restore(store, path, by, key_file, from_name, kind)
            # What the copy holds signed as this node's word now (1.0.231): put back on
            # purpose, its rows are newer than any seen before it.
            try:
                dbguard_resign(store, 'a copy put back by %s' % by)
            except Exception as e:                      # noqa: BLE001
                log('the rows put back could not be signed: %s' % e, 'warn')
            return got
        finally:
            RESTORE_RUNNING.clear()
    finally:
        for x in held:
            try:
                x.unlink()
            except OSError:
                pass


def _db_file_restore(store, path, by, key_file, from_name, kind):
    # The key that opens the secrets in it: beside a kept file, or inside a copy
    # that was downloaded with it.
    key_hex = ''
    if key_file and Path(key_file).exists():
        key_hex = Path(key_file).read_text().strip()
    elif kind == 'copy':
        import gzip
        with gzip.open(str(path), 'rt', encoding='utf-8') as f:
            key_hex = str(json.loads(f.readline() or '{}').get('key') or '')
    # In a cluster the other node keeps its own key, and the rows going over
    # would be ones it cannot open (1.0.44): a copy sealed with another key
    # is refused there before anything is replaced.
    if CONFIG.get('ha_mode') == 'replicated' and re.match(r'^[0-9a-f]{64}\Z', key_hex):
        now = sealing_key()
        if now and now.hex() != key_hex:
            raise ValueError('this copy was sealed with another key than the one both nodes '
                             'use; in a cluster it cannot be put back - the other node could '
                             'not open its secrets')
    safety = make_backup(store, 'before putting %s back, by %s' % (from_name or 'a file', by))
    # The link between the databases describes the machines, not the data
    # (1.0.104): the authority and each node's steps as they are now stay;
    # a copy without them leaves them, one from before keeps no older ones.
    try:
        live_tls = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'hatls:%'")
    except Exception:                                   # noqa: BLE001
        live_tls = []
    # Who is signed in stays as it is now (1.0.147): the copy's sign-ins came
    # back with it - one signed out since, or of a password changed since,
    # opened the pages again until it ran out.
    try:
        live_sessions = store.db.rows('SELECT * FROM sessions')
    except Exception:                                   # noqa: BLE001
        live_sessions = None
    # The codes used up stay used up (otp 1.0.224): put back, the copy's used_once replaced the
    # one of now - every code of the administrators' app used since the copy was good again.
    try:
        live_once = store.db.rows('SELECT k, node, ts FROM used_once')
    except Exception:                                   # noqa: BLE001
        live_once = None
    c = _db_conf()
    if kind == 'copy':
        load_tables(store.db, path)
    elif kind == 'sqlite':
        fd, tmp = tempfile.mkstemp(prefix='acme-restore-', suffix='.json.gz', dir=str(STATE_DIR))
        os.close(fd)                    # not left open, one each time (1.0.139)
        tmp = Path(tmp)
        try:
            _sqlite_to_copy(path, tmp)
            load_tables(store.db, tmp)
        finally:
            tmp.unlink()
    elif kind == 'mariadb':
        import gzip
        tool = _tool(('mariadb', 'mysql'))
        with gzip.open(str(path), 'rb') as sent:
            for n, line in enumerate(_lines_capped(sent, 1 << 30)):
                if line[:1] == b'\\' or line[:7].lower() == b'system ':
                    raise ValueError('line %d of the dump is a client command, not SQL. '
                                     'A dump this program made has none.' % (n + 1))
        cnf = _my_cnf(c)
        # The client is given the SQL itself: a gzip reader has no file
        # descriptor of its own to hand a program, so it is unpacked first.
        fd, raw = tempfile.mkstemp(prefix='acme-sql-', dir=str(STATE_DIR))
        os.close(fd)
        raw = Path(raw)
        try:
            st = os.statvfs(str(STATE_DIR))
            room = max(0, st.f_bavail * st.f_frsize - (512 << 20))   # half a GB kept free
            with gzip.open(str(path), 'rb') as src, open(str(raw), 'wb') as dst:
                _copy_capped(src, dst, room)
            with open(str(raw), 'rb') as sent:
                _run([tool] + _my_args(c, cnf) + ['--default-character-set=utf8mb4',
                                                  '--local-infile=0', '--binary-mode',
                                                  safe_db_name(c)],
                     'the MariaDB client', stdin=sent)
        finally:
            os.unlink(cnf)
            try:
                raw.unlink()
            except OSError:
                pass
    else:
        tool = _tool(('pg_restore',))
        pf = _pg_passfile(c)
        try:
            _run([tool] + _pg_args(c) + ['--single-transaction', '--clean', '--if-exists',
                                         '--no-owner', '--no-privileges',
                                         '--dbname=%s' % safe_db_name(c), str(path)],
                 'pg_restore', env=_pg_env(c, pf))
        finally:
            os.unlink(pf)
    store.db.make_tables()
    if CONFIG.get('ha_mode') == 'replicated' and store.db.engine == 'postgres':
        ha_sequences(store.db, int(CONFIG.get('ha_slot') or 1))
    if live_sessions is not None:
        try:
            store.db.run('DELETE FROM sessions')
            have = set(c.lower() for c in store.db.columns('sessions'))
            for r in live_sessions:
                row = {k: v for k, v in dict(r).items() if k.lower() in have and k != 'id'}
                keys = sorted(row)
                store.db.insert_many('sessions', keys, [[row[k] for k in keys]])
        except Exception as e:                          # noqa: BLE001
            log('the sign-ins could not be kept as they were: %s' % e, 'warn')
    if live_once:
        eng = store.db.engine
        sql = ('INSERT IGNORE INTO used_once (k, node, ts) VALUES (?, ?, ?)' if eng == 'mariadb' else
               'INSERT OR IGNORE INTO used_once (k, node, ts) VALUES (?, ?, ?)' if eng == 'sqlite' else
               'INSERT INTO used_once (k, node, ts) VALUES (?, ?, ?) ON CONFLICT DO NOTHING')
        kept = 0
        for r in live_once:
            try:
                kept += 1 if store.db.run(sql, (r['k'], r['node'], r['ts'])) else 0
            except Exception:                           # noqa: BLE001
                pass
        if kept:
            log('put back: %d code(s) used since the copy kept used up' % kept, 'info')
    for r in live_tls:
        try:
            store.set_meta(r['k'], r['v'])
        except Exception:                               # noqa: BLE001
            pass
    hatls_check_soon()      # and then looked at: what is in place against what is wanted
    key_said = 'the key that opens the sealed secrets stays as it was'
    if re.match(r'^[0-9a-f]{64}\Z', key_hex):
        now = sealing_key()
        if not now or now.hex() != key_hex:
            # The cluster's authority kept from before is sealed with the key
            # going out (1.0.139): opened now, sealed again with the new one -
            # it could not be opened after, and had to be made anew.
            cas = None
            for r in live_tls:
                if r['k'] == 'hatls:ca':
                    try:
                        cas = (json.loads(r['v'] or 'null') or {}).get('cas')
                        for ca in cas or []:
                            ca['key'] = unseal_secret(ca.get('key'), bind='hatls:ca')
                    except (ValueError, AttributeError, TypeError):
                        cas = None
            write_replacing(sealing_key_path(), key_hex + '\n', 0o600)
            key_said = 'the key that opens the sealed secrets came with it and is in use now'
            if cas and all(ca.get('key') for ca in cas):
                for ca in cas:
                    ca['key'] = seal_secret(ca['key'], bind='hatls:ca')
                try:
                    store.set_meta('hatls:ca', json.dumps({'cas': cas}))
                except Exception as e:                  # noqa: BLE001
                    log('the authority of the cluster could not be sealed again: %s' % e, 'warn')
    else:
        # No key came with it (1.0.59): whether the secrets put back open with
        # the key in use is looked at, and said loudly when they do not.
        try:
            if sealed_opens(store.db) is False:
                key_said = ('NO KEY CAME WITH IT and its secrets do not open with the key in '
                            'use: put back the .key file that was beside the dump (or the '
                            'copy from the download) - until then no private key or password '
                            'kept in it can be used')
                store.add_event('backups', 'the database put back from %s came without its key '
                                'and its secrets cannot be opened' % (from_name or 'a file'),
                                'bad', who=by)
        except Exception as e:                          # noqa: BLE001
            log('the secrets put back could not be tried with the key: %s' % e, 'warn')
    bump(store)
    store.add_event('backups', '%s put the database back from %s (%s); what it replaced is in %s'
                    % (by, from_name or 'a file', DUMP_WORDS.get(kind, kind), safety.name),
                    'warn', who=by)
    return {'safety': safety.name, 'kind': kind, 'key': key_said}


# ---- the disk under it ----------------------------------------------------------
def note_size(store):
    """The size of the database, once a day, for how fast it grows."""
    try:
        sizes = json.loads(store.get_meta('db_sizes:' + node_name()) or '{}')
    except ValueError:
        sizes = {}
    today = datetime.now().strftime('%Y-%m-%d')
    if sizes.get('engine') != store.db.engine:
        sizes = {'engine': store.db.engine, 'days': {}}
    if today not in sizes['days']:
        sizes['days'][today] = int(store.db.size() or 0)
        for old in sorted(sizes['days'])[:-60]:
            del sizes['days'][old]
        store.set_meta('db_sizes:' + node_name(), json.dumps(sizes))
    return sizes


def db_growth(store):
    days = note_size(store).get('days', {})
    edge = (datetime.now().timestamp() - 15 * 86400)
    seen = sorted((d, b) for d, b in days.items()
                  if datetime.strptime(d, '%Y-%m-%d').timestamp() >= edge)
    if len(seen) < 2:
        return {'a_day': 0, 'over_days': 0}
    (d0, b0), (d1, b1) = seen[0], seen[-1]
    span = max(1, (datetime.strptime(d1, '%Y-%m-%d') - datetime.strptime(d0, '%Y-%m-%d')).days)
    return {'a_day': max(0, int((b1 - b0) / span)), 'over_days': span}


def _folder_bytes(folder):
    total = 0
    if Path(folder).is_dir():
        for f in Path(folder).iterdir():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def db_disk(store):
    db = store.db
    where = db.path.parent if db.engine == 'sqlite' else STATE_DIR
    out = {'where': str(where), 'total': 0, 'free': 0, 'share': 0, 'days_left': None,
           'holds': 'the database itself, its copies and its dumps' if db.engine == 'sqlite'
           else 'the copies and the dumps - the database itself is on the server'}
    try:
        u = shutil.disk_usage(str(where))
        out.update(total=u.total, free=u.free,
                   share=round(100.0 * (u.total - u.free) / u.total) if u.total else 0)
    except OSError:
        pass
    grew = db_growth(store)
    if grew['a_day'] and out['free']:
        out['days_left'] = int(out['free'] / grew['a_day'])
    parts = []
    if db.engine == 'sqlite':
        for suffix, what in (('', 'the database'), ('-wal', 'what is written, not yet folded in'),
                             ('-shm', 'the index of that')):
            f = Path(str(db.path) + suffix)
            if f.exists():
                parts.append({'name': f.name, 'what': what, 'bytes': f.stat().st_size})
    else:
        parts.append({'name': db.where(), 'what': 'the database, on the server',
                      'bytes': int(db.size() or 0)})
    parts.append({'name': str(BACKUP_DIR), 'what': 'the copies', 'bytes':
                  _folder_bytes(BACKUP_DIR)})
    parts.append({'name': str(DUMP_DIR), 'what': 'the dumps', 'bytes': _folder_bytes(DUMP_DIR)})
    return out, grew, parts


def db_cache(store):
    """The server's own cache, where it is left as installed and the database
    has outgrown it."""
    db = store.db
    if db.engine == 'sqlite':
        return None
    try:
        if db.engine == 'postgres':
            setting = 'shared_buffers'
            cache = int(db.value("SELECT setting::bigint * 8192 FROM pg_settings "
                                 "WHERE name = 'shared_buffers'") or 0)
        else:
            setting = 'innodb_buffer_pool_size'
            r = db.row("SHOW GLOBAL VARIABLES LIKE 'innodb_buffer_pool_size'")
            cache = int(list(r.values())[1]) if r else 0
    except Exception:                                   # noqa: BLE001
        return None
    size = int(db.size() or 0)
    ram = 0
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    ram = int(line.split()[1]) * 1024
    except OSError:
        pass
    return {'engine': ENGINE_WORDS.get(db.engine), 'setting': setting, 'cache': cache,
            'size': size, 'ram': ram, 'low': bool(cache and size > cache)}


# ---- erasing what was collected -----------------------------------------------
# (key, table, name, what it is) - a module appends its own logs (its jobs, say).
ERASABLE = [
    ('events', 'events', 'the event log',
     'what this program noted about itself: sign-ins, changes, copies, starts and stops, '
     'and what happened to the certificates. Nothing reads them back: they are the record '
     'of what happened.'),
]


def db_erasable(store):
    groups = []
    for key, table, name, says in ERASABLE:
        groups.append({'key': key, 'name': name, 'says': says,
                       'rows': int(store.db.value('SELECT COUNT(*) FROM %s' % table) or 0)})
    return {'groups': groups, 'bytes': int(store.db.size() or 0)}


def db_erase_job(store, groups, tidy, by):
    tables = [(t, n) for k, t, n, _ in ERASABLE if k in groups]
    if not tables:
        raise ValueError('nothing was ticked')

    def work(progress):
        progress(0, len(tables) + 2, 'making a copy first')
        copy = make_backup(store, 'before erasing, by %s' % by)
        gone = {}
        for i, (t, n) in enumerate(tables):
            progress(i + 1, len(tables) + 2, 'emptying %s' % n)
            gone[t] = store.db.run('DELETE FROM %s' % t)
        given = None
        if tidy:
            progress(len(tables) + 1, len(tables) + 2, 'giving the disk back')
            given = db_give_back(store, lambda *a: None)
        store.add_event('settings', '%s erased %s (a copy was made first: %s)'
                        % (by, ', '.join(n for _, n in tables), copy.name), 'warn', who=by)
        progress(len(tables) + 2, len(tables) + 2, 'done')
        return {'erased': gone, 'copy': copy.name, 'given': given}
    return db_job('erasing the collected data', work)


# ---- the server's settings: what was done, what waits for a start ---------------
def tune_state(store):
    db = store.db
    out = {'engine': db.engine, 'last': None, 'pending': [], 'lost': [],
           'restart': {'may': False, 'unit': {'postgres': 'postgresql',
                                              'mariadb': 'mariadb'}.get(db.engine, '')}}
    try:
        last = json.loads(store.get_meta('tune_last:' + node_name()) or 'null')
    except ValueError:
        last = None
    out['last'] = last
    if db.engine == 'postgres':
        try:
            out['pending'] = [r['name'] for r in db.rows(
                'SELECT name FROM pg_settings WHERE pending_restart')]
        except Exception:                               # noqa: BLE001
            pass
    elif db.engine == 'mariadb' and last and not last.get('undone') \
            and last.get('engine') == 'mariadb':
        now = tune_current(db, list((last.get('set') or {}).keys()))
        out['lost'] = [n for n, v in (last.get('set') or {}).items()
                       if not tune_same('mariadb', now.get(n, ''), v)]
    return out
# ---- a copy or a dump with the key that opens its secrets (1.0.123) ----------------
# A copy or a dump alone opens no secret anywhere else: the key that opens them
# is a file of its own (the .key beside it, /var/lib/acme/secrets.key). Downloaded
# from the page it can now go with the key in ONE file - a plain tar holding
#   acme-db.json          what it is (the file's name, size, sha256, where made)
#   <the file>           the copy or the dump, as it is
#   secrets.key.locked   the key, locked with a passphrase given on the page
#                        (the lock of the cluster's bundle: scrypt, HMAC)
# and the same file sent back to Put a copy back / Put a dump back is opened
# with that passphrase and put back with its key. The passphrase is never
# kept: lost, the key in the file is lost with it.
DBKEY_KIND = 'acme-db-key'
DBKEY_TAR_KIND = 'acme-db-with-key'
DBKEY_SUFFIX = '.with-key.tar'
DB_UPLOADS = STATE_DIR / 'db-uploads'
DB_TICKETS_DIR = STATE_DIR / 'db-downloads'
DB_TICKETS = {}
DB_TICKETS_LOCK = threading.Lock()
DBKEY_MIN_PASS = 10


def _sha256_file(path):
    h = hashlib.sha256()
    with open(str(path), 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def dbkey_passphrase_checked(passphrase):
    p = str(passphrase or '')
    if len(p) < DBKEY_MIN_PASS:
        raise ValueError('a passphrase of %d characters at least - it is all that guards the '
                         'key in the file' % DBKEY_MIN_PASS)
    return p


def dbkey_bundle(src, name, passphrase, work):
    """`src` (a copy or a dump called `name`) and this machine's key, locked
    with `passphrase`, in one tar in `work`. Its path."""
    passphrase = dbkey_passphrase_checked(passphrase)
    key = sealing_key()
    if not key:
        raise ValueError('this machine has no key that opens the sealed secrets')
    sha = _sha256_file(src)
    locked = bundle_lock({'key': key.hex(), 'file': name, 'sha256': sha}, passphrase,
                         kind=DBKEY_KIND)
    head = {'kind': DBKEY_TAR_KIND, 'format': 1, 'file': name,
            'bytes': Path(src).stat().st_size, 'sha256': sha, 'made': time.time(),
            'node': node_name(), 'site': CONFIG.get('site_name') or '', 'version': __version__}
    out = Path(work) / (name + DBKEY_SUFFIX)
    with tarfile.open(str(out), 'w') as tf:
        for arc, data in (('acme-db.json', json.dumps(head, indent=1).encode('utf-8')),
                          ('secrets.key.locked', json.dumps(locked).encode('utf-8'))):
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mtime = int(time.time())
            ti.mode = 0o600
            tf.addfile(ti, io.BytesIO(data))
        ti = tf.gettarinfo(str(src), arcname=name)
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ''
        ti.mode = 0o600
        with open(str(src), 'rb') as f:
            tf.addfile(ti, f)
    os.chmod(str(out), 0o600)
    return out


def dbkey_is_bundle(path):
    """Whether `path` is a file made by dbkey_bundle (its head, not its name)."""
    try:
        if not tarfile.is_tarfile(str(path)):
            return False
        with tarfile.open(str(path), 'r:') as tf:
            m = tf.getmember('acme-db.json')
            f = tf.extractfile(m)
            head = json.loads(f.read(1 << 16).decode('utf-8')) if f else {}
        return isinstance(head, dict) and head.get('kind') == DBKEY_TAR_KIND
    except (KeyError, OSError, ValueError, tarfile.TarError):
        return False


def dbkey_open(path, work, passphrase=None):
    """The file inside it, taken out into `work`, and - with the passphrase -
    the key next to it: (file, key file or None, head)."""
    try:
        tf = tarfile.open(str(path), 'r:')
    except (OSError, tarfile.TarError) as e:
        raise ValueError('that file does not open: %s' % e)
    with tf:
        members = {}
        for m in tf.getmembers():
            # Only plain files, by plain names: nothing it says goes anywhere
            # but where it is put.
            if not m.isreg() or '/' in m.name or m.name in ('', '.', '..') or '\\' in m.name:
                raise ValueError('that file holds something acme does not put in one: %s' % m.name)
            members[m.name] = m
        try:
            head = json.loads(tf.extractfile(members['acme-db.json']).read(1 << 16).decode('utf-8'))
            locked = json.loads(tf.extractfile(members['secrets.key.locked']).read(1 << 20)
                                .decode('utf-8'))
        except (KeyError, ValueError, AttributeError):
            raise ValueError('that is not a database with its key made by acme')
        name = os.path.basename(str(head.get('file') or ''))
        if head.get('kind') != DBKEY_TAR_KIND or not NAME_RE.match(name) or name not in members:
            raise ValueError('that is not a database with its key made by acme')
        out = Path(work) / name
        src = tf.extractfile(members[name])
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    if _sha256_file(out) != head.get('sha256'):
        raise ValueError('the file inside is not the one it was made with (damaged on the way?)')
    keyf = None
    if passphrase is not None:
        try:
            got = bundle_open(locked, str(passphrase), kinds=(DBKEY_KIND,))
        except ValueError as e:
            if 'passphrase' in str(e):
                raise ValueError('that passphrase does not open the key in the file')
            raise
        if got.get('sha256') != head.get('sha256') or \
                not re.match(r'^[0-9a-f]{64}\Z', str(got.get('key') or '')):
            raise ValueError('the key in the file is not the one made with it')
        keyf = Path(work) / 'secrets.key'
        write_replacing(keyf, got['key'] + '\n', 0o600)
    return out, keyf, head


def dbkey_keep_upload(tmp):
    """An upload kept for an hour to be put back with its passphrase: its id."""
    DB_UPLOADS.mkdir(mode=0o700, exist_ok=True)
    now = time.time()
    for p in DB_UPLOADS.iterdir():
        try:
            if now - p.stat().st_mtime > 3600:
                p.unlink()
        except OSError:
            pass
    up = secrets.token_hex(8)
    shutil.move(str(tmp), str(DB_UPLOADS / up))
    os.chmod(str(DB_UPLOADS / up), 0o600)
    return up


def dbkey_upload(up):
    if not re.match(r'^[0-9a-f]{16}\Z', str(up or '')):
        raise ValueError('which file?')
    p = DB_UPLOADS / up
    if not p.is_file():
        raise ValueError('the file sent is not here any more (an hour has gone by?): send it again')
    return p


def dbkey_ticket_put(path, name, who):
    """A file made for a download, waiting ten minutes for the one browser
    that asked for it: its ticket."""
    now = time.time()
    with DB_TICKETS_LOCK:
        for t, v in list(DB_TICKETS.items()):
            if now - v['at'] > 600:
                shutil.rmtree(str(v['dir']), ignore_errors=True)
                DB_TICKETS.pop(t, None)
        t = secrets.token_hex(16)
        DB_TICKETS[t] = {'path': Path(path), 'name': name, 'who': who, 'at': now,
                         'dir': Path(path).parent}
    return t


def dbkey_ticket_take(t, who):
    with DB_TICKETS_LOCK:
        v = DB_TICKETS.pop(str(t or ''), None)
    if not v or v['who'] != who or time.time() - v['at'] > 600:
        if v:
            shutil.rmtree(str(v['dir']), ignore_errors=True)
        return None
    return v

