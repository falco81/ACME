# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# A copy of everything, in a shape any of the three engines takes back
# ---------------------------------------------------------------------------
def machine_info():
    """The machine a copy was made on (1.0.63): its config.json - the
    database it opens, its name, its place in a cluster - with the
    password left out, and where it is. Only to be read: a copy put back
    never writes it, as the file belongs to the machine and not to the data."""
    try:
        with open(str(CONFIG_FILE), encoding='utf-8') as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raw = {}
    except (OSError, ValueError):
        raw = {k: FILE_CONFIG.get(k) for k in (FILE_KEYS or ())}
    conf = {k: ('(set - not kept in the copy)' if (k in SECRET_KEYS or 'password' in k) and v
                else v) for k, v in sorted(raw.items())}
    out = {'config_file': str(CONFIG_FILE), 'config': conf, 'host': socket.getfqdn()}
    try:
        out['node'] = node_name()
    except Exception:                                   # noqa: BLE001
        pass
    for k in ('ha_mode', 'ha_slot', 'ha_peer', 'db_engine', 'db_host', 'db_port', 'db_name'):
        out.setdefault('in_use', {})[k] = CONFIG.get(k)
    if not out['in_use'].get('db_port'):
        # 0 is "the engine's own" (1.0.66): said as the number it is.
        out['in_use']['db_port'] = {'postgres': 5432, 'mariadb': 3306}.get(
            CONFIG.get('db_engine'), 0)
    return out


DAEMON_DB = [None]       # the daemon's own database, once it runs (1.0.150)


def dump_tables(db, out, tables=None, child=False):
    """Every row of every table, as JSON a line, gzipped. The first line says
    what it is; each table starts with a line naming it."""
    if not child and tables is None and db is DAEMON_DB[0]:
        return _dump_tables_child(out)
    import gzip
    # A file already open may be given (1.0.101): root writing into a
    # folder the service's account can write opens it itself, never by name.
    with gzip.open(out if hasattr(out, 'write') else str(out), 'wt', encoding='utf-8') as f:
        f.write(json.dumps({'acme': __version__, 'schema': SCHEMA_VERSION,
                            'made': time.time(), 'engine': db.engine,
                            'machine': machine_info()}, default=str) + '\n')
        for table in (tables or TABLES):
            f.write(json.dumps({'table': table}) + '\n')
            last = 0
            while True:
                if table in ('meta', 'settings'):
                    # Not the pieces of an uploaded package (1.0.57): up to
                    # 90 MB read whole into memory with every copy.
                    rows = (db.rows("SELECT * FROM meta WHERE k NOT LIKE 'upgrade:piece:%'")
                            if table == 'meta' else db.rows('SELECT * FROM settings')) \
                        if last == 0 else []
                    last = 1
                else:
                    rows = db.rows('SELECT * FROM %s WHERE id > ? ORDER BY id LIMIT 2000'
                                   % table, (last,))
                    if rows:
                        last = rows[-1]['id']
                for r in rows:
                    f.write(json.dumps(r, default=str) + '\n')
                if not rows or table in ('meta', 'settings'):
                    break
    return out


def _dump_tables_child(out):
    """dump_tables of the daemon's database by `acme --dump-copy`, a process of
    its own (1.0.150): in the daemon, the minutes of a big copy held Python's
    one lock against everything else."""
    opened = not hasattr(out, 'write')
    f = open(str(out), 'wb') if opened else out
    try:
        try:
            f.flush()
        except (OSError, ValueError):
            pass
        env = dict(os.environ)
        r = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), '--dump-copy'],
                           stdout=f.fileno(), stderr=subprocess.PIPE, env=env,
                           timeout=6 * 3600)
        if r.returncode != 0:
            raise DbError('the copy could not be made: %s'
                          % r.stderr.decode('utf-8', 'replace').strip()[-300:])
    finally:
        if opened:
            f.close()
    return out


def load_tables(db, src, keep_logs=True, say=None):
    """Put a copy made by `dump_tables` back, over whatever is there.
    `say(table, done)` hears how far it has got, a batch at a time."""
    import gzip
    db.make_tables()
    # All of it or none of it (1.0.33): a copy that broke off half-way left
    # tables empty, and everybody locked out. The database is held for the
    # whole of it - a restore is not something done while work goes on.
    DB_RESTORING.set()
    db.restoring = True
    try:
        # No time limit (1.0.208): emptying a log of millions of rows took
        # longer than two minutes, and the copy could never be put back.
        with db.unlimited():
            return _load_tables_held(db, src, keep_logs, say, gzip)
    finally:
        db.restoring = False
        DB_RESTORING.clear()


def _load_tables_held(db, src, keep_logs, say, gzip):
    # The lanes wait for it too (1.0.136): DB_RESTORING sends their
    # statements to the main lane, whose lock this holds.
    with db.lock:
        if db.conn is None:
            db.connect()
        db.run('START TRANSACTION' if db.engine == 'mariadb' else 'BEGIN')
        db.in_tx = True
        try:
            counts = _load_tables(db, src, keep_logs, say, gzip)
            db.in_tx = False
            db.run('COMMIT')
        except BaseException:
            db.in_tx = False
            try:
                db.run('ROLLBACK')
            except Exception:                           # noqa: BLE001
                pass
            raise
    db_numbering_fix(db)
    return counts


def db_numbering_fix(db, tables=None):
    """After rows were written with their own numbers (a copy put back, an
    import): PostgreSQL's numbering moved past them - and, replicated, onto
    this node's side of odd and even again."""
    if db.engine != 'postgres':
        return
    for table in (tables or TABLES):
        if table in ('meta', 'settings'):
            continue
        try:
            db.run("SELECT setval(pg_get_serial_sequence('%s', 'id'), "
                   "COALESCE((SELECT MAX(id) FROM %s), 0) + 1, false)" % (table, table))
        except Exception:
            pass
    # Odd or even again at once (1.0.94): MAX+1 can be the other node's
    # parity, and a row written before the caller set it collided there.
    if CONFIG.get('ha_mode') == 'replicated':
        try:
            ha_sequences(db, int(CONFIG.get('ha_slot') or 1))
        except Exception as e:                      # noqa: BLE001
            log('the numbering could not be set after loading: %s' % e, 'warn')


META_TRANSIENT = ('db_job:', 'node:', 'maint:', 'upgrade:', 'hatls:node:')
# The tables that are a log, not a setting nor a thing kept: left as they are
# here when a copy is put back without its logs. A module appends its own
# (the certificate manager its jobs, say).
LOG_TABLES = []


def _load_tables(db, src, keep_logs, say, gzip):
    counts = {}
    batch, keys, table, have = [], None, None, set()

    def flush():
        if table and batch:
            db.insert_many(table, keys, batch)
            counts[table] += len(batch)
            if say:
                say(table, counts[table])
        del batch[:]

    with gzip.open(str(src), 'rt', encoding='utf-8') as f:
        head = json.loads(f.readline() or '{}')
        if 'acme' not in head and 'opt' not in head:      # 'opt': before 1.0.37's new name
            raise DbError('%s is not a copy made by acme' % src)
        for line in f:
            got = json.loads(line)
            if set(got.keys()) == {'table'}:
                flush()
                keys = None
                table = got['table']
                if table not in TABLES or (not keep_logs and table in LOG_TABLES):
                    table = None
                    continue
                if table == 'meta':
                    # What is going on here now stays (1.0.44): maintenance,
                    # heartbeats, upgrades and jobs are this machine's, not
                    # the copy's - and in a cluster the delete would reach
                    # the other node too.
                    db.run('DELETE FROM meta WHERE ' + ' AND '.join(
                        "k NOT LIKE '%s%%'" % p.replace("'", "") for p in META_TRANSIENT))
                else:
                    db.run('DELETE FROM %s' % table)
                have = set(c.lower() for c in db.columns(table))
                counts[table] = 0
                if say:
                    say(table, 0)
                continue
            if not table:
                continue
            row = {k: v for k, v in got.items() if k.lower() in have}
            if table == 'meta':
                # What only the running service means is not carried over
                # (1.0.37): the copy made at the start of a move held the
                # move itself as "going on", and the database moved into
                # showed it going on for ever - every button that waits for
                # a job stayed grey. Heartbeats, maintenance and upgrades
                # are of the machine that wrote them, too.
                if str(row.get('k') or '').startswith(META_TRANSIENT):
                    continue
                db.run('DELETE FROM meta WHERE k = ?', (row.get('k'),))
            these = sorted(row.keys())
            if keys is not None and these != keys:
                flush()
            keys = these
            batch.append([row[k] for k in keys])
            if len(batch) >= 1000:
                flush()
        flush()
    return counts


