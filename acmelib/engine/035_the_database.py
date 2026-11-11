# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The database
# ---------------------------------------------------------------------------
# One of three, as on isemon: a SQLite file on this machine unless somebody
# says otherwise, or a MariaDB or a PostgreSQL. The SQL below is written once,
# with `?` for every value, and said in each engine's own words where they
# differ - the types, the numbering of rows, the placeholders.
#
# One connection, behind one lock (and a few more for the threads that must not
# wait behind the pages - the lanes below). What costs time is the network -
# the CA, the targets, the directory - and that is never asked under the lock.

class DbError(Exception):
    pass


# The database's own trouble, not the request's (1.0.149): locked, full, out of
# space, a statement or a lock wait that ran out, a server shutting down.
DB_TROUBLE_KINDS = ('OperationalError', 'QueryCanceled', 'QueryCanceledError', 'LockNotAvailable',
                    'DiskFull', 'AdminShutdown', 'CannotConnectNow', 'SerializationFailure',
                    'DeadlockDetected', 'InterfaceError', 'InternalError', 'OutOfMemory',
                    'TooManyConnections', 'ConnectionFailure', 'ConnectionException')
DB_TROUBLE_WORDS = ('database is locked', 'disk is full', 'disk i/o error', 'no space left')


# When the daemon last could not use the database, and why (1.0.186) - for the
# alerts, through each node's health row.
DB_TROUBLE_SEEN = {'at': 0.0, 'said': ''}


def db_trouble(e):
    if isinstance(e, DbError):
        return True
    names = {c.__name__ for c in type(e).__mro__}
    said = str(e).lower()
    if 'out of range' in said:
        return False                # a value too big: the request's, said as such
    return bool(names & set(DB_TROUBLE_KINDS)) and (
        type(e).__module__.split('.')[0] in ('sqlite3', 'psycopg2', 'pymysql', 'MySQLdb') or
        any(w in said for w in DB_TROUBLE_WORDS))


SCHEMA_VERSION = 1

SCHEMA = [
    ('meta', '''CREATE TABLE IF NOT EXISTS meta (
        k {K} PRIMARY KEY, v {B})'''),
    ('settings', '''CREATE TABLE IF NOT EXISTS settings (
        k {K} PRIMARY KEY, v {B}, at {N}, by_who {K})'''),
    ('accounts', '''CREATE TABLE IF NOT EXISTS accounts (
        id {ID}, name {K} NOT NULL UNIQUE, role {K}, pw {T}, source {K}, disabled {I},
        must_change {I}, note {T}, created {N}, last_in {N}, last_from {K}, prefs {T},
        display {T}, dn {T}, group_list {T}, cols {B}, cols_at {N}, mail {T}, mobile {T}, mfa_on {I})'''),
    ('sessions', '''CREATE TABLE IF NOT EXISTS sessions (
        id {ID}, token_hash {K} NOT NULL UNIQUE, kind {K}, name {K}, role {K}, created {N},
        last {N}, expires {N}, ip {K}, data {B})'''),
    ('directories', '''CREATE TABLE IF NOT EXISTS directories (
        id {ID}, name {K} NOT NULL UNIQUE, hosts {T}, port {I}, tls {K}, verify {I},
        ca {B}, base {T}, bind_dn {T}, bind_pw {T}, user_attr {K}, nested {I},
        timeout_s {I}, enabled {I}, note {T}, created {N}, weak {I}, mail_attr {K},
        mobile_attr {K})'''),
    ('events', '''CREATE TABLE IF NOT EXISTS events (
        id {ID}, ts {N}, kind {K}, level {K}, who {K}, words {T}, node {K})'''),
    # What was used once and may never be again (1.0.101): the time step of
    # an administrator's code from the app - one row each, never changed,
    # written by each node only under its own number, so two replicating
    # nodes never write an older copy of one over the other.
    ('used_once', '''CREATE TABLE IF NOT EXISTS used_once (
        id {ID}, k {K} NOT NULL, node {I} NOT NULL, ts {N}, UNIQUE (k, node))'''),
]

INDEXES = [
    'CREATE INDEX IF NOT EXISTS events_ts ON events (ts)',
    'CREATE INDEX IF NOT EXISTS sessions_expires ON sessions (expires)',
    # 1.0.33: the events by kind (the kinds offered as one types), the
    # sign-ins by kind.
    'CREATE INDEX IF NOT EXISTS events_kind_ts ON events (kind, ts)',
    'CREATE INDEX IF NOT EXISTS sessions_kind_last ON sessions (kind, last)',
    'CREATE INDEX IF NOT EXISTS used_once_ts ON used_once (ts)',
]

TYPES = {
    'sqlite': {'ID': 'INTEGER PRIMARY KEY AUTOINCREMENT', 'K': 'TEXT', 'T': 'TEXT',
               'B': 'TEXT', 'N': 'REAL', 'I': 'INTEGER'},
    # Compared byte for byte, as SQLite and PostgreSQL compare (1.0.44): with
    # the default collation novák@x.cz was novak@x.cz, and one person's
    # account was written over another's.
    'mariadb': {'ID': 'BIGINT AUTO_INCREMENT PRIMARY KEY', 'K': 'VARCHAR(190) COLLATE utf8mb4_bin',
                'T': 'TEXT', 'B': 'MEDIUMTEXT', 'N': 'DOUBLE', 'I': 'BIGINT'},
    'postgres': {'ID': 'BIGSERIAL PRIMARY KEY', 'K': 'TEXT', 'T': 'TEXT', 'B': 'TEXT',
                 'N': 'DOUBLE PRECISION', 'I': 'BIGINT'},
}

class _SchemaTables(object):
    """TABLES: the names of the tables of SCHEMA, read off SCHEMA each time
    it is looked at - so a table a module appends to SCHEMA (acmelib/certs)
    is in every backup, copy, move, export and replication without anything
    else being told. Reads as a list does; append and extend are there for a
    module that adds its names here too, and add nothing SCHEMA has."""

    def _names(self):
        return [name for name, _ in SCHEMA]

    def __iter__(self):
        return iter(self._names())

    def __reversed__(self):
        return reversed(self._names())

    def __len__(self):
        return len(SCHEMA)

    def __contains__(self, name):
        return name in self._names()

    def __getitem__(self, i):
        return self._names()[i]

    def index(self, name):
        return self._names().index(name)

    def __repr__(self):
        return repr(self._names())

    def append(self, name):
        if name not in self:
            raise ValueError('the table %s is not in SCHEMA: append its CREATE TABLE there' % name)

    def extend(self, names):
        for name in names:
            self.append(name)


TABLES = _SchemaTables()


def schema_tables():
    """The tables as they are now, as a list."""
    return [name for name, _ in SCHEMA]


def schema_named_columns():
    """(table, column) of every table of SCHEMA whose rows have a name of
    their own besides the number: its first UNIQUE or PRIMARY KEY text
    column (name, k, token_hash). Read off the CREATE statements, so a table
    a module appends to SCHEMA has it too."""
    out = []
    for table, create in SCHEMA:
        m = re.search(r'\b(\w+)\s+\{K\}(?:\s+NOT NULL)?\s+(?:UNIQUE|PRIMARY KEY)\b', create)
        if m:
            out.append((table, m.group(1)))
    return out


def schema_unique_sets():
    """(table, [columns]) of every UNIQUE (a, b, ...) of more than one column
    in SCHEMA - a certificate's version, an authority's serial."""
    out = []
    for table, create in SCHEMA:
        for m in re.finditer(r'\bUNIQUE\s*\(([^)]*)\)', create):
            cols = [c.strip() for c in m.group(1).split(',') if c.strip()]
            if len(cols) > 1 and all(re.match(r'^[a-z_][a-z0-9_]*\Z', c) for c in cols):
                out.append((table, cols))
    return out


class RawSql(str):
    """A statement sent as it is, with no parameters (1.0.94): a conninfo
    with the password inside it, where a `?` of the password became `%s`
    and CREATE SUBSCRIPTION failed with "tuple index out of range"."""


def _qmarks(sql):
    """`?` as `%s`, for the two engines whose drivers want that. Nothing in
    the SQL this program writes has a `?` or a `%` inside a quoted string."""
    return sql.replace('%', '%%').replace('?', '%s')


def db_tls_args(engine, mode=None, ca=None):
    """How the connection to the database server is encrypted (1.0.33):
    as the driver decides, unless `db_tls` says otherwise. The settings of
    the connection asked for, not the running ones (1.0.36): a change was
    tried with the old values, then the service could not start."""
    mode = str((CONFIG.get('db_tls') if mode is None else mode) or '')
    ca = str((CONFIG.get('db_tls_ca') if ca is None else ca) or '')
    if not mode:
        return {}
    if engine == 'postgres':
        out = {'sslmode': mode}
        if ca:
            out['sslrootcert'] = ca
        return out
    import ssl as _ssl
    if mode == 'require':
        return {'ssl': {'check_hostname': False, 'verify_mode': _ssl.CERT_NONE}}
    # verify_mode True, not CERT_REQUIRED (1.0.36): pymysql took the number
    # with no authority file for "check nothing". True with no file checks
    # against the system's authorities.
    got = {'ssl': {'check_hostname': mode == 'verify-full', 'verify_mode': True}}
    if ca:
        got['ssl']['ca'] = ca
    else:
        # The system's authorities named (1.0.79): PyMySQL drops check_hostname when it is given
        # no authority - verify-full then took any trusted certificate for any name.
        paths = _ssl.get_default_verify_paths()
        if paths.cafile and os.path.exists(paths.cafile):
            got['ssl']['ca'] = paths.cafile
        elif paths.capath and os.path.isdir(paths.capath):
            got['ssl']['capath'] = paths.capath
    return got


DB_RESTORING = threading.Event()


class _Lane(object):
    """One connection to the database and the lock it is used under."""
    __slots__ = ('conn', 'lock', 'in_tx', 'failed_until', 'down_until', 'down_said')

    def __init__(self):
        self.conn = None
        self.lock = threading.RLock()
        self.in_tx = False
        self.failed_until = 0.0
        self.down_until = 0.0
        self.down_said = ''


class Db(object):
    """One database, of whichever engine."""

    # How long one statement may take, and one wait for a row another holds
    # (1.0.101): with no limit, one statement waiting on a lock or on a line
    # that dropped held every request behind this connection's lock - every
    # sign-in of the whole server, the health check too. 0: none.
    STATEMENT_S = 120
    LOCK_S = 10

    def __init__(self, engine='sqlite', host='', port=0, name='acme', user='acme',
                 password='', timeout=10, path=None, tls=None, tls_ca=None, statement_s=None):
        self.engine = engine if engine in TYPES else 'sqlite'
        self.statement_s = self.STATEMENT_S if statement_s is None else int(statement_s)
        # [fd00::1] as written in a URL is fd00::1 to the drivers. (1.0.36)
        host = str(host or '').strip()
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        self.host, self.port, self.name = host, int(port or 0), name
        self.user, self.password, self.timeout = user, password, int(timeout or 10)
        self.path = Path(path) if path else DB_FILE
        self.tls, self.tls_ca = tls, tls_ca
        self._lanes = {'main': _Lane()}
        self._lanes_lock = threading.Lock()
        self._tls = threading.local()
        self.lanes_on = False
        self.connect()

    # ---- lanes: a connection of their own for some threads (1.0.136) -----------
    # Every statement goes one at a time through a connection and its lock.
    # With one connection for everything, a slow page (an overview over a
    # month, uncached: 29 s under load) held everything behind it. Once the
    # daemon turns lanes on, the threads whose names start with 'lane' have
    # connections and locks of their own: nothing the pages, the console, the
    # backups or the ticks do waits in front of them. A lane whose connection
    # cannot be made falls back to the main one for a minute.
    LANE_RETRY_S = 60
    LANES = 4

    def _conn_timeout(self):
        """How long a new connection may take: 2 s at most for a lane's own
        (1.0.186) - made under its lane's lock, every statement on that lane
        waited out the whole db_timeout_s of a database that did not answer."""
        lane = getattr(self._tls, 'lane', None)
        if lane is not None and lane is not self._lanes.get('main'):
            return max(1, min(int(self.timeout), 2))
        return self.timeout

    def _lane(self):
        """The lane of this thread's statement: the one pinned for the call it
        is in, or the one it would take."""
        pinned = getattr(self._tls, 'lane', None)
        return pinned if pinned is not None else self._pick()

    def _pick(self):
        """Which lane a new call of this thread takes - chosen once, before
        any lock is taken, and kept for the whole call (1.0.136): chosen again
        at each look, one call took one lane's lock and used the other's
        connection, and two threads could wait on each other for good."""
        main = self._lanes['main']
        if not self.lanes_on or not threading.current_thread().name.startswith('lane'):
            return main
        # A copy put back holds the database whole, the lanes too (as before
        # them): their writes would collide with the rows coming in. This
        # database's own (1.0.139): a move loading another database sent the
        # lanes off for the whole of it.
        if getattr(self, 'restoring', False):
            return main
        # A few connections on a database server (1.0.150): with one, each
        # waited for the one before it there, and one row held by a lock
        # stopped them all. Each thread keeps to one of them. SQLite writes
        # one at a time anyway.
        key = 'lane'
        if self.engine != 'sqlite' and self.LANES > 1:
            tail = threading.current_thread().name.rsplit('-', 1)[-1]
            key = 'lane%d' % ((int(tail) if tail.isdigit() else 0) % self.LANES)
        lane = self._lanes.get(key)
        if lane is None:
            with self._lanes_lock:
                lane = self._lanes.setdefault(key, _Lane())
        if lane.conn is None and time.monotonic() < lane.failed_until:
            return main
        return lane

    @contextlib.contextmanager
    def _pinned(self):
        """The call's lane pinned for everything under it. A lane without
        a connection makes one first - under its own lock only; when it
        cannot while the main one works, the call goes to the main lane (and
        the lane's threads with it for a minute). Never the main lock taken
        while a lane's is held."""
        if getattr(self._tls, 'lane', None) is not None:
            yield
            return
        lane = self._pick()
        main = self._lanes['main']
        if lane is not main and lane.conn is None:
            with lane.lock:
                if lane.conn is None:
                    if time.monotonic() < lane.failed_until:
                        lane = main
                    elif time.monotonic() < lane.down_until:
                        # Tried a moment ago and the database did not answer:
                        # said at once, and no minute on the main lane for it
                        # (a restart of the database is not a lane gone bad).
                        raise DbError(lane.down_said or 'the database is not answering')
                    else:
                        self._tls.lane = lane
                        try:
                            self.connect()
                        except DbError:
                            # The database away altogether: said so, as the
                            # main lane would (no minute on the main lane).
                            if main.conn is None or time.monotonic() < main.down_until:
                                raise
                            lane.failed_until = time.monotonic() + self.LANE_RETRY_S
                            log_sparing('db-lane', '%s shares the main database '
                                        'connection for a minute: its own could not be made'
                                        % threading.current_thread().name, 'warn')
                            lane = main
                        finally:
                            self._tls.lane = None
        self._tls.lane = lane
        try:
            yield
        finally:
            self._tls.lane = None

    @property
    def lock(self):
        return self._lane().lock

    @property
    def conn(self):
        return self._lane().conn

    @conn.setter
    def conn(self, value):
        self._lane().conn = value

    @property
    def in_tx(self):
        return self._lane().in_tx

    @in_tx.setter
    def in_tx(self, value):
        self._lane().in_tx = value

    # ---- the connection ----------------------------------------------------
    def where(self):
        if self.engine == 'sqlite':
            return str(self.path)
        return '%s@%s:%s/%s' % (self.user, self.host or 'localhost',
                                self.port or {'mariadb': 3306, 'postgres': 5432}[self.engine],
                                self.name)

    # A database that does not answer is tried again at most every 2 s
    # (1.0.136): each try waits up to db_timeout_s under the lane's lock, and
    # every request behind it waited for its own try in turn - one request
    # answered every 10 s, the queue full, the health check stuck.
    DOWN_RETRY_S = 2

    def connect(self):
        lane = self._lane()
        with lane.lock:
            if lane.conn is None and time.monotonic() < lane.down_until:
                raise DbError(lane.down_said or 'the database is not answering')
            try:
                self._connect()
                lane.down_until = 0.0
            except DbError as e:
                lane.down_until = time.monotonic() + self.DOWN_RETRY_S
                lane.down_said = str(e)
                raise

    # A lane waits less (1.0.149): a statement there that waited 120 s held
    # everything on it behind it. Past these it is no answer, said at once.
    LANE_STATEMENT_S = 5
    LANE_LOCK_S = 2
    LANE_SQLITE_BUSY_S = 3

    def _connect(self):
        quick = self._lane() is not self._lanes['main']
        stmt_s = min(self.statement_s or self.LANE_STATEMENT_S, self.LANE_STATEMENT_S) \
            if quick else self.statement_s
        lock_s = self.LANE_LOCK_S if quick else self.LOCK_S
        with self.lock:
            if self.engine == 'sqlite':
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # A lane waits 3 s for the file (1.0.149), not 30: past that,
                # no answer, said at once.
                conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                       isolation_level=None,
                                       timeout=self.LANE_SQLITE_BUSY_S if quick else 30)
                conn.row_factory = sqlite3.Row
                # LOWER() over every letter, as PostgreSQL and MariaDB do it
                # (1.0.205): SQLite's own takes A-Z only - "Žofie" was never found
                # again by its name, and could neither sign in nor be dropped.
                try:
                    conn.create_function('lower', 1, lambda v: v.lower() if isinstance(v, str)
                                         else v, deterministic=True)
                except (sqlite3.Error, TypeError):
                    conn.create_function('lower', 1, lambda v: v.lower() if isinstance(v, str)
                                         else v)
                try:
                    conn.execute('PRAGMA journal_mode=WAL')
                    conn.execute('PRAGMA synchronous=NORMAL')
                    # The log of the file shrunk back after a big write (1.0.149):
                    # it stayed at its largest - 1.3 GB beside a 1 GB database.
                    conn.execute('PRAGMA journal_size_limit=67108864')
                except sqlite3.Error:
                    pass
                self.conn = conn
            elif self.engine == 'mariadb':
                try:
                    import pymysql
                    import pymysql.cursors
                    import pymysql.constants.CLIENT
                except ImportError:
                    raise DbError('MariaDB is chosen and its Python driver is not installed: '
                                  'dnf install python3-PyMySQL (or pip install PyMySQL)')
                try:
                    self.conn = pymysql.connect(
                        host=self.host or 'localhost', port=self.port or 3306,
                        user=self.user, password=self.password, database=self.name,
                        charset='utf8mb4', autocommit=True,
                        connect_timeout=self._conn_timeout(),
                        # A line that drops without a word no longer holds
                        # every request behind the lock for hours (1.0.57).
                        read_timeout=(stmt_s + 4) if quick else (
                            max(30, self.statement_s + 10) if self.statement_s else 300),
                        write_timeout=60,
                        # rows matched, as SQLite and PostgreSQL count them (1.0.52): an UPDATE
                        # to the values there already said 0 here only
                        client_flag=pymysql.constants.CLIENT.FOUND_ROWS,
                        cursorclass=pymysql.cursors.DictCursor,
                        **db_tls_args('mariadb', self.tls, self.tls_ca))
                except Exception as e:
                    raise DbError('MariaDB at %s could not be reached: %s' % (self.where(), e))
                for sql in ('SET SESSION innodb_lock_wait_timeout = %d' % lock_s,
                            'SET SESSION max_statement_time = %d' % stmt_s,
                            # A node stopped half way through a sign-in (otp 1.0.226), as on PG.
                            'SET SESSION idle_transaction_timeout = %d' % (10 if quick else 120)):
                    try:
                        with self.conn.cursor() as cur:
                            cur.execute(sql)
                    except Exception:                   # noqa: BLE001
                        pass            # MySQL, or an older MariaDB: without it
            else:
                try:
                    import psycopg2
                    import psycopg2.extras
                except ImportError:
                    raise DbError('PostgreSQL is chosen and its Python driver is not installed: '
                                  'dnf install python3-psycopg2 (or pip install psycopg2-binary)')
                try:
                    self.conn = psycopg2.connect(
                        host=self.host or 'localhost', port=self.port or 5432,
                        user=self.user, password=self.password, dbname=self.name,
                        connect_timeout=self._conn_timeout(),
                        # TCP keepalives (1.0.57): a connection lost in a
                        # failover or a firewall is found dead in ~20 s, not
                        # when the kernel gives up, with every request
                        # waiting behind it.
                        keepalives=1, keepalives_idle=10, keepalives_interval=3,
                        keepalives_count=3,
                        # ...and a line that drops while a statement is out:
                        # given up after 30 s, not the kernel's 15 min.
                        tcp_user_timeout=10000 if quick else 30000,
                        # ...and a node that stops half way through a sign-in (otp 1.0.226: a
                        # VM paused, a node cut off) no longer holds that person's row for
                        # the server's two hours: its open transaction ended after a while,
                        # the server's own keepalives finding it gone.
                        options='-c lock_timeout=%d -c statement_timeout=%d '
                                '-c idle_in_transaction_session_timeout=%d '
                                '-c tcp_keepalives_idle=10 -c tcp_keepalives_interval=3 '
                                '-c tcp_keepalives_count=3' % (
                                    lock_s * 1000, stmt_s * 1000, (10 if quick else 120) * 1000),
                        **db_tls_args('postgres', self.tls, self.tls_ca))
                    self.conn.autocommit = True
                    self.conn.set_client_encoding('UTF8')
                except Exception as e:
                    raise DbError('PostgreSQL at %s could not be reached: %s' % (self.where(), e))

    def close(self, lane_only=False):
        """Every lane's connection closed - or, from within a statement that
        lost its own, only the current lane's."""
        lanes = [self._lane()] if lane_only else list(self._lanes.values())
        for lane in lanes:
            with lane.lock:
                try:
                    if lane.conn:
                        lane.conn.close()
                except Exception:
                    pass
                lane.conn = None

    # ---- asking --------------------------------------------------------------
    def _run(self, sql, args, fetch):
        if self.engine == 'sqlite':
            # A number beyond 64 bits (1.0.19): SQLite raised OverflowError where
            # PostgreSQL and MariaDB find no row - `acme --job 99999999999999999999`
            # ended in a traceback. As a REAL it matches no row, as there.
            cur = self.conn.execute(sql, tuple(
                float(a) if type(a) is int and not -(1 << 63) <= a < (1 << 63) else a
                for a in (args or ())))
            rows = [dict(r) for r in cur.fetchall()] if fetch else None
            return rows, cur.rowcount, cur.lastrowid
        if self.engine == 'mariadb':
            cur = self.conn.cursor()
            try:
                if isinstance(sql, RawSql):
                    cur.execute(str(sql))
                else:
                    cur.execute(_qmarks(sql), tuple(args or ()))
                rows = [dict(r) for r in cur.fetchall()] if fetch else None
                return rows, cur.rowcount, cur.lastrowid
            finally:
                cur.close()
        import psycopg2.extras
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            # PostgreSQL takes no NUL in a text (1.0.59): a name with one in
            # it broke the request, and its write-down, every time.
            if isinstance(sql, RawSql):
                cur.execute(str(sql))
            else:
                cur.execute(_qmarks(sql), tuple(a.replace('\x00', '\ufffd')
                                                if isinstance(a, str) and '\x00' in a else a
                                                for a in (args or ())))
            rows = [dict(r) for r in cur.fetchall()] if (fetch or cur.description) else None
            return rows, cur.rowcount, rows[0].get('id') if (rows and not fetch) else None
        finally:
            cur.close()

    def _gone(self, e):
        """Whether an error is the server having gone away, which one new
        connection mends."""
        said = str(e).lower()
        return any(w in said for w in ('gone away', 'lost connection', 'server closed',
                                       'connection already closed', 'terminating connection',
                                       'broken pipe', 'connection reset', 'not connected',
                                       'interfaceerror', 'cursor already closed',
                                       'connection has been closed',
                                       'connection is closed', 'ssl connection has been closed',
                                       # tcp_user_timeout ran out (1.0.149): the line dropped
                                       'could not receive data', 'connection timed out',
                                       'server closed the connection'))

    def query(self, sql, args=(), fetch=True):
        # While this node is rebuilt from the other, nothing but the rebuild
        # writes (1.0.57): a sign-in or a code written meanwhile took an id
        # the copy then met again, and replication stopped on it for good.
        reb = globals().get('HA_REBUILDING')
        with self._pinned(), self.lock:
            # Looked at under the lock (1.0.59): a write that had passed the
            # look and was waiting for the lock went in after the tables were
            # emptied. Every kind of write, not only the three words.
            if reb is not None and reb.is_set() and \
                    globals().get('HA_REBUILDER', [None])[0] != threading.get_ident() and \
                    sql.lstrip()[:8].upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'WITH',
                                                         'TRUNCATE', 'REPLACE')):
                raise DbError('this node is being rebuilt from the other one; try again in a '
                              'few minutes')
            if self.conn is None:
                self.connect()
            try:
                return self._run(sql, args, fetch)
            except Exception as e:
                if self.engine == 'sqlite' or not (self._gone(e) or
                                                   type(e).__name__ == 'InterfaceError'):
                    raise
                if getattr(self, 'in_tx', False):
                    # Half a transaction is gone with the connection; going on
                    # on a new one would commit the second half alone. (1.0.36)
                    self.close(lane_only=True)
                    raise
                # A connection that is gone is made again - and the statement
                # run once more only where that cannot do it twice (1.0.33): a
                # read, or a connection known closed before it was sent. A
                # write whose answer was lost may have been done; done again,
                # a code just used up would be refused as used.
                self.close(lane_only=True)
                self.connect()
                said = str(e).lower()
                unsent = type(e).__name__ == 'InterfaceError' or any(
                    w in said for w in ('connection already closed', 'not connected',
                                        'cursor already closed'))
                if sql.lstrip()[:6].upper() in ('SELECT', 'WITH  ', 'SHOW  ') or \
                        sql.lstrip().upper().startswith(('SELECT', 'WITH', 'SHOW', 'EXPLAIN')) \
                        or unsent:
                    return self._run(sql, args, fetch)
                raise

    def rows(self, sql, args=()):
        return self.query(sql, args, True)[0]

    def row(self, sql, args=()):
        got = self.rows(sql, args)
        return got[0] if got else None

    def value(self, sql, args=(), default=None):
        got = self.row(sql, args)
        if not got:
            return default
        return list(got.values())[0]

    def run(self, sql, args=()):
        return self.query(sql, args, False)[1]

    def upsert(self, table, key, row):
        """One row by its primary key, made or changed in one statement
        (1.0.57): SELECT-then-INSERT on two nodes at once put the same key in
        twice, and replication then stopped on the duplicate."""
        keys = list(row.keys())
        cols = ', '.join(keys)
        marks = ', '.join('?' for _ in keys)
        rest = [k for k in keys if k != key]
        if self.engine == 'mariadb':
            sql = 'INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s' % (
                table, cols, marks, ', '.join('%s = VALUES(%s)' % (k, k) for k in rest))
        else:
            sql = 'INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s' % (
                table, cols, marks, key, ', '.join('%s = excluded.%s' % (k, k) for k in rest))
        return self.run(sql, tuple(row[k] for k in keys))

    def insert(self, table, row):
        keys = list(row.keys())
        sql = 'INSERT INTO %s (%s) VALUES (%s)' % (table, ', '.join(keys),
                                                   ', '.join('?' for _ in keys))
        if self.engine == 'postgres':
            sql += ' RETURNING id'
            return self.query(sql, [row[k] for k in keys], False)[2]
        return self.query(sql, [row[k] for k in keys], False)[2]

    def update(self, table, ident, row):
        keys = list(row.keys())
        if not keys:
            return 0
        return self.run('UPDATE %s SET %s WHERE id = ?' % (table, ', '.join('%s = ?' % k
                                                                          for k in keys)),
                        [row[k] for k in keys] + [ident])

    def name_order(self):
        """name in byte order on every engine (1.0.208): PostgreSQL under a
        language put "alpha" before "Zeta" - another client answered."""
        return 'name COLLATE "C"' if self.engine == 'postgres' else 'name'

    @contextlib.contextmanager
    def unlimited(self):
        """No time limit on this connection's statements meanwhile: the
        tables made and the columns added at start - an index made on a
        large log may take minutes."""
        if self.engine == 'sqlite' or not self.statement_s:
            yield
            return
        off, on = (('SET statement_timeout = 0', 'SET statement_timeout = %d' % (
            self.statement_s * 1000)) if self.engine == 'postgres' else (
            'SET SESSION max_statement_time = 0',
            'SET SESSION max_statement_time = %d' % self.statement_s))
        with self.lock:
            # Once for the outermost only (1.0.52), counted under the lock (the same thread
            # only gets here twice): add_missing_columns inside make_tables put the limit back on
            # before the indexes were made - an index on a large log failed the start.
            if getattr(self, '_unl_depth', 0):
                self._unl_depth += 1
                try:
                    yield
                finally:
                    self._unl_depth -= 1
                return
            try:
                # A connection the server dropped is made again first (1.0.208):
                # the SET went to the dead one, and the job ran limited after all.
                self.value('SELECT 1')
            except Exception:                           # noqa: BLE001
                pass
            try:
                self.run(RawSql(off))
            except Exception:                           # noqa: BLE001
                pass
            # MariaDB's socket waits as long too (1.0.52): pymysql's read_timeout cut a long
            # restore off whatever max_statement_time said
            rt = getattr(self.conn, '_read_timeout', None) if self.engine == 'mariadb' else None
            if rt is not None:
                self.conn._read_timeout = None
            self._unl_depth = 1
            try:
                yield
            finally:
                self._unl_depth = 0
                if rt is not None and self.conn is not None:
                    try:
                        self.conn._read_timeout = rt
                    except Exception:                   # noqa: BLE001
                        pass
                try:
                    self.run(RawSql(on))
                except Exception:                       # noqa: BLE001
                    pass

    @contextlib.contextmanager
    def transaction(self):
        """What is under it written all or nothing, on one connection (1.0.214): a code used
        up and its row in token_once were two writes, and a database that dropped between
        them left the code used here and the request unanswered - the other node, asked
        next, then refused it as used. SQLite and a transaction already open: as before."""
        with self._pinned(), self.lock:
            # Asked with the lane's lock held (1.0.217): a lane is shared by several RADIUS
            # workers, and one seeing another's transaction open took itself for inside
            # one - its writes went in one by one again. Held, it can only be its own.
            if getattr(self, 'in_tx', False):
                yield
                return
            if self.conn is None:
                self.connect()
            # SQLite too (1.0.222): its writes went in one by one, and another writer taking
            # the file between them left the code used and the request unanswered. IMMEDIATE:
            # the file's write lock taken at once - waited for before anything is written.
            # 10 s idle at most inside it, on every lane (1.0.227): a sign-in on the portal or
            # the pages runs on the main lane, 120 s there - a node frozen in the middle of
            # one held that person's row on the shared database two minutes.
            main = self._lane() is self._lanes['main']
            if self.engine == 'mariadb' and main:
                try:
                    self.run(RawSql('SET SESSION idle_transaction_timeout = 10'))
                except Exception:                       # noqa: BLE001
                    pass
            try:
                self.run(RawSql({'mariadb': 'START TRANSACTION', 'sqlite': 'BEGIN IMMEDIATE'}.get(
                    self.engine, 'BEGIN')))
                self.in_tx = True
                if self.engine == 'postgres' and main:
                    self.run(RawSql('SET LOCAL idle_in_transaction_session_timeout = 10000'))
                try:
                    yield
                    self.run(RawSql('COMMIT'))
                except BaseException:
                    self.in_tx = False
                    try:
                        if self.conn is not None:
                            self.run(RawSql('ROLLBACK'))
                    except Exception:                   # noqa: BLE001
                        self.close(lane_only=True)
                    raise
                finally:
                    self.in_tx = False
            finally:
                if self.engine == 'mariadb' and main and self.conn is not None:
                    try:
                        self.run(RawSql('SET SESSION idle_transaction_timeout = 120'))
                    except Exception:                   # noqa: BLE001
                        pass

    # ---- the tables ----------------------------------------------------------
    def make_tables(self):
        with self.unlimited():
            self._make_tables()

    def _make_tables(self):
        types = TYPES[self.engine]
        for _name, ddl in SCHEMA:
            sql = ddl.format(**types)
            if self.engine == 'mariadb':
                sql += ' DEFAULT CHARSET=utf8mb4'
            self.run(sql)
        # The columns first (1.0.208): an index on a column a later version adds
        # stopped every start of an older database ("no such column").
        self.add_missing_columns()
        for sql in INDEXES:
            if self.engine == 'mariadb':
                # MariaDB knows IF NOT EXISTS on an index from 10.1.4 on, and
                # wants a length on nothing here: every indexed column is a
                # VARCHAR(190) or a number.
                try:
                    self.run(sql)
                except Exception as e:
                    if 'Duplicate key name' in str(e):
                        continue
                    # MySQL has no IF NOT EXISTS on an index (1.0.44).
                    if '1064' not in str(e) and 'syntax' not in str(e).lower():
                        raise
                    try:
                        self.run(sql.replace(' IF NOT EXISTS', ''))
                    except Exception as e2:
                        if 'Duplicate key name' not in str(e2):
                            raise
            else:
                self.run(sql)
        if self.engine == 'mariadb':
            self._mariadb_bin_names()
            self._mariadb_meta_keys()
        if self.engine == 'postgres':
            self._pg_same_rows()
        if self.value('SELECT v FROM meta WHERE k = ?', ('schema',)) is None:
            self.run('INSERT INTO meta (k, v) VALUES (?, ?)', ('schema', str(SCHEMA_VERSION)))

    def _pg_same_rows(self):
        """Two replicating nodes (1.0.59, 1.0.207). A row made on both nodes
        under the same name - a certificate, a target or a meta key both
        wrote first while the link was down - stopped replication for good on
        the duplicate. Where one comes in that is already here, the same one
        of the two is kept on both nodes. Put on every table of SCHEMA that
        has a name of its own (a UNIQUE or PRIMARY KEY column) - a table a
        module appends to SCHEMA too. And a setting changed on both nodes
        while the link was down: the later one is kept on both."""
        try:
            self.run("""CREATE OR REPLACE FUNCTION acme_same_key() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
DECLARE
  col text := TG_ARGV[0];
  key text;
  here text;
  came text;
BEGIN
  IF current_setting('session_replication_role') <> 'replica' THEN
    RETURN NEW;
  END IF;
  key := row_to_json(NEW) ->> col;
  EXECUTE format('SELECT row_to_json(t)::text FROM %I.%I t WHERE %I = $1',
                 TG_TABLE_SCHEMA, TG_TABLE_NAME, col) INTO here USING key;
  IF here IS NULL THEN
    RETURN NEW;
  END IF;
  came := row_to_json(NEW)::text;
  -- Byte order on both nodes (1.0.94): under a language's collation the
  -- two could pick different winners and stay different for good.
  IF came COLLATE "C" > here COLLATE "C" THEN
    EXECUTE format('DELETE FROM %I.%I WHERE %I = $1', TG_TABLE_SCHEMA, TG_TABLE_NAME, col)
       USING key;
    RETURN NEW;
  END IF;
  RETURN NULL;
END $f$""")
            # A setting changed on both nodes while the link was down (1.0.207):
            # each node took the other's change over its own, and the two stayed
            # swapped for good. The later one is kept on both - the earlier, by
            # byte order, at the same moment.
            self.run("""CREATE OR REPLACE FUNCTION acme_newer_setting() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
BEGIN
  IF current_setting('session_replication_role') <> 'replica' THEN
    RETURN NEW;
  END IF;
  IF COALESCE(OLD.at, 0) > COALESCE(NEW.at, 0) THEN
    RETURN NULL;
  END IF;
  IF COALESCE(OLD.at, 0) = COALESCE(NEW.at, 0)
     AND row_to_json(OLD)::text COLLATE "C" > row_to_json(NEW)::text COLLATE "C" THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END $f$""")
            if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = 'acme_newer_setting' AND "
                              "tgrelid = 'settings'::regclass"):
                self.run('CREATE TRIGGER acme_newer_setting BEFORE UPDATE ON settings '
                         'FOR EACH ROW EXECUTE FUNCTION acme_newer_setting()')
            self.run('ALTER TABLE settings ENABLE ALWAYS TRIGGER acme_newer_setting')
            # A certificate renewed on one node while apart, and its row changed on the other
            # (a note, a tag, the portal) - the whole old row came over on reunion and the
            # older certificate was back, and deployed everywhere (1.0.44). A row of an older
            # version than the one here is not taken over it.
            if self.value("SELECT 1 FROM pg_tables WHERE tablename = 'certs'"):
                self.run("""CREATE OR REPLACE FUNCTION acme_newer_cert() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
BEGIN
  IF current_setting('session_replication_role') <> 'replica' THEN
    RETURN NEW;
  END IF;
  IF COALESCE(NEW.version, 0) < COALESCE(OLD.version, 0)
     OR COALESCE(NEW.alt_version, 0) < COALESCE(OLD.alt_version, 0) THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END $f$""")
                if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = 'acme_newer_cert' AND "
                                  "tgrelid = 'certs'::regclass"):
                    self.run('CREATE TRIGGER acme_newer_cert BEFORE UPDATE ON certs '
                             'FOR EACH ROW EXECUTE FUNCTION acme_newer_cert()')
                self.run('ALTER TABLE certs ENABLE ALWAYS TRIGGER acme_newer_cert')
            for table, col in schema_named_columns():
                trg = 'acme_same_%s' % table
                if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = ? AND "
                                  "tgrelid = ?::regclass", (trg, table)):
                    self.run("CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE "
                             "FUNCTION acme_same_key('%s')" % (trg, table, col))
                self.run('ALTER TABLE %s ENABLE ALWAYS TRIGGER %s' % (table, trg))
            # The same for a key of several columns (a certificate's version,
            # an authority's serial): made on both nodes while the link was
            # down - the leader's renewal and one by hand on the other node -
            # the second one stopped replication for good on the duplicate.
            self.run("""CREATE OR REPLACE FUNCTION acme_same_keys() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
DECLARE
  cond text := '';
  i int;
  here text;
  came text;
BEGIN
  IF current_setting('session_replication_role') <> 'replica' THEN
    RETURN NEW;
  END IF;
  FOR i IN 0 .. TG_NARGS - 1 LOOP
    cond := cond || CASE WHEN i > 0 THEN ' AND ' ELSE '' END
                 || format('t.%1$I = ($1).%1$I', TG_ARGV[i]);
  END LOOP;
  EXECUTE format('SELECT row_to_json(t)::text FROM %I.%I t WHERE %s',
                 TG_TABLE_SCHEMA, TG_TABLE_NAME, cond) INTO here USING NEW;
  IF here IS NULL THEN
    RETURN NEW;
  END IF;
  came := row_to_json(NEW)::text;
  IF came COLLATE "C" > here COLLATE "C" THEN
    EXECUTE format('DELETE FROM %I.%I t WHERE %s', TG_TABLE_SCHEMA, TG_TABLE_NAME, cond)
       USING NEW;
    RETURN NEW;
  END IF;
  RETURN NULL;
END $f$""")
            for table, cols in schema_unique_sets():
                trg = 'acme_same2_%s' % table
                if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = ? AND "
                                  "tgrelid = ?::regclass", (trg, table)):
                    self.run("CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE "
                             "FUNCTION acme_same_keys(%s)" % (
                                 trg, table, ', '.join("'%s'" % c for c in cols)))
                self.run('ALTER TABLE %s ENABLE ALWAYS TRIGGER %s' % (table, trg))
        except Exception as e:                          # noqa: BLE001
            log('the guard of rows made on both nodes could not be put in: %s'
                % str(e).split('\n')[0], 'warn')

    def _mariadb_meta_keys(self):
        """meta's keys to 255 characters (1.0.208): a name may be 180, and a key
        made of a prefix, the name and @@NODE went past 190 - writing it failed
        ("Data too long")."""
        try:
            n = self.value("SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS "
                           "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'meta' "
                           "AND COLUMN_NAME = 'k'")
            if n is not None and int(n) < 255:
                self.run('ALTER TABLE meta MODIFY k VARCHAR(255) CHARACTER SET utf8mb4 '
                         'COLLATE utf8mb4_bin NOT NULL')
        except Exception as e:                          # noqa: BLE001
            log('meta\'s keys stay 190 characters long: %s' % str(e).split('\n')[0], 'warn')

    def _mariadb_bin_names(self):
        """Tables made before 1.0.44 compared names ignoring case and
        accents: their VARCHAR columns made byte for byte, once."""
        try:
            rows = self.rows("SELECT TABLE_NAME AS t, COLUMN_NAME AS c, IS_NULLABLE AS n, "
                             "CHARACTER_MAXIMUM_LENGTH AS l FROM information_schema.COLUMNS "
                             "WHERE TABLE_SCHEMA = DATABASE() AND DATA_TYPE = 'varchar' "
                             "AND COLLATION_NAME <> 'utf8mb4_bin'")
        except Exception as e:                          # noqa: BLE001
            log('the names could not be checked for their collation: %s' % e, 'warn')
            return
        for r in rows:
            r = {k.lower(): v for k, v in r.items()}
            if r['t'] not in TABLES:
                continue
            try:
                self.run('ALTER TABLE %s MODIFY %s VARCHAR(%d) CHARACTER SET utf8mb4 '
                         'COLLATE utf8mb4_bin%s' % (r['t'], r['c'], int(r['l'] or 190),
                                                    ' NOT NULL' if r['n'] == 'NO' else ''))
            except Exception as e:                      # noqa: BLE001
                log('%s.%s stays compared without case: %s' % (r['t'], r['c'], e), 'warn')

    def tables(self):
        """The tables that are there, whatever made them."""
        if self.engine == 'sqlite':
            return [r['name'] for r in self.rows(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        if self.engine == 'mariadb':
            return [list(r.values())[0] for r in self.rows(
                'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')]
        return [r['tablename'] for r in self.rows(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")]

    def insert_many(self, table, keys, rows):
        """Many rows at once, in one transaction - a copy of a million rows
        is minutes this way and hours a row at a time."""
        if not rows:
            return 0
        sql = 'INSERT INTO %s (%s) VALUES (%s)' % (table, ', '.join(keys),
                                                   ', '.join('?' for _ in keys))
        with self._pinned(), self.lock:
            if self.conn is None:
                self.connect()
            if self.engine == 'sqlite' and getattr(self, 'in_tx', False):
                self.conn.executemany(sql, rows)
            elif self.engine == 'sqlite':
                self.conn.execute('BEGIN')
                try:
                    self.conn.executemany(sql, rows)
                    self.conn.execute('COMMIT')
                except Exception:
                    self.conn.execute('ROLLBACK')
                    raise
            elif self.engine == 'mariadb':
                cur = self.conn.cursor()
                try:
                    cur.executemany(_qmarks(sql), rows)
                finally:
                    cur.close()
            else:
                import psycopg2.extras
                cur = self.conn.cursor()
                try:
                    # No NUL in a text here either (1.0.94): an old SQLite
                    # row with one stopped the whole move to PostgreSQL.
                    rows = [tuple(a.replace('\x00', '\ufffd') if isinstance(a, str) and '\x00' in a
                                  else a for a in r) for r in rows]
                    psycopg2.extras.execute_batch(cur, _qmarks(sql), rows, page_size=500)
                finally:
                    cur.close()
        return len(rows)

    def columns(self, table):
        if self.engine == 'sqlite':
            return [r['name'] for r in self.rows('PRAGMA table_info(%s)' % table)]
        if self.engine == 'mariadb':
            return [r.get('COLUMN_NAME') or r.get('column_name') for r in self.rows(
                'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '
                'DATABASE() AND TABLE_NAME = ?', (table,))]
        return [r['column_name'] for r in self.rows(
            'SELECT column_name FROM information_schema.columns WHERE table_name = ? '
            'AND table_schema = current_schema()', (table,))]

    def add_missing_columns(self):
        with self.unlimited():
            return self._add_missing_columns()

    def _add_missing_columns(self):
        """A column added in a later version, added to a database made by an
        earlier one. Read off the CREATE statements above, so there is one
        place a column is declared."""
        types = TYPES[self.engine]
        for name, ddl in SCHEMA:
            have = set(c.lower() for c in self.columns(name))
            body = ddl.format(**types).split('(', 1)[1].rsplit(')', 1)[0]
            for piece in re.split(r',\s*(?=[a-z_]+ )', body):
                piece = piece.strip()
                col = piece.split(' ', 1)[0].lower()
                if not col or col in have or col == 'id':
                    continue
                kind = piece.split(' ', 2)[1] if ' ' in piece else 'TEXT'
                # The column's type only (1.0.23): a table constraint after the last
                # column (", UNIQUE (ca_id, serial)") left "BLOB," - a column added
                # last before it was never added.
                kind = re.sub(r',?\s*(NOT NULL|UNIQUE|PRIMARY KEY).*$', '', piece.split(' ', 1)[1],
                              flags=re.S).strip().rstrip(',').strip()
                try:
                    self.run('ALTER TABLE %s ADD COLUMN %s %s' % (name, col, kind))
                except Exception as e:
                    log('could not add the column %s.%s: %s' % (name, col, e), 'warn')

    def size(self):
        try:
            if self.engine == 'sqlite':
                return sum(os.path.getsize(str(self.path) + s) for s in ('', '-wal')
                           if os.path.exists(str(self.path) + s))
            if self.engine == 'mariadb':
                return int(self.value(
                    'SELECT SUM(data_length + index_length) FROM information_schema.TABLES '
                    'WHERE table_schema = DATABASE()') or 0)
            return int(self.value('SELECT pg_database_size(current_database())') or 0)
        except Exception:
            return 0

    def version(self):
        try:
            if self.engine == 'sqlite':
                return 'SQLite ' + sqlite3.sqlite_version
            if self.engine == 'mariadb':
                return 'MariaDB ' + str(self.value('SELECT VERSION()'))
            return str(self.value('SELECT version()')).split(' on ')[0]
        except Exception as e:
            return '? (%s)' % e


def open_db(conf=None):
    """The database the settings name."""
    c = conf or CONFIG
    return Db(c.get('db_engine') or 'sqlite', c.get('db_host') or '', c.get('db_port') or 0,
              c.get('db_name') or 'acme', c.get('db_user') or 'acme', c.get('db_password') or '',
              c.get('db_timeout_s') or 10, tls=c.get('db_tls') or '',
              tls_ca=c.get('db_tls_ca') or '', path=c.get('db_path') or None)


