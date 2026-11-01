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
# One connection, behind one lock. A token server answers a few requests a
# second at its busiest; what costs time is the directory, and that is asked
# outside the lock.

class DbError(Exception):
    pass


# The database's own trouble, not the request's (1.0.149): locked, full, out of
# space, a statement or a lock wait that ran out, a server shutting down.
DB_TROUBLE_KINDS = ('OperationalError', 'QueryCanceled', 'QueryCanceledError', 'LockNotAvailable',
                    'DiskFull', 'AdminShutdown', 'CannotConnectNow', 'SerializationFailure',
                    'DeadlockDetected', 'InterfaceError', 'InternalError', 'OutOfMemory',
                    'TooManyConnections', 'ConnectionFailure', 'ConnectionException')
DB_TROUBLE_WORDS = ('database is locked', 'disk is full', 'disk i/o error', 'no space left')


# When RADIUS last could not use the database, and why (1.0.186) - for the
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
        display {T}, dn {T}, group_list {T}, cols {B}, cols_at {N})'''),
    ('sessions', '''CREATE TABLE IF NOT EXISTS sessions (
        id {ID}, token_hash {K} NOT NULL UNIQUE, kind {K}, name {K}, role {K}, created {N},
        last {N}, expires {N}, ip {K}, data {B})'''),
    ('tokens', '''CREATE TABLE IF NOT EXISTS tokens (
        id {ID}, name {K} NOT NULL UNIQUE, secret {T}, digits {I}, period {I}, algorithm {K},
        window_steps {I}, state {K}, last_step {I}, scratch {B}, scratch_left {I},
        created {N}, created_by {K}, activated {N}, last_used {N}, last_from {K},
        last_how {K}, failures {I}, fail_times {T}, note {T}, issuer {K}, label {K},
        pending_secret {T}, pending_scratch {B}, pending_at {N}, pending_by {K},
        display {T}, scratch_sealed {T}, locked_until {N}, last_client {K},
        key_at {N}, state_at {N}, lock_at {N}, scratch_at {N}, kind {K}, dest {T},
        lang {K}, mail_fmt {K})'''),
    ('clients', '''CREATE TABLE IF NOT EXISTS clients (
        id {ID}, name {K} NOT NULL UNIQUE, address {K}, secret {T}, realm {K},
        require_ma {I}, enabled {I}, note {T}, created {N}, last_seen {N}, nas_type {K},
        position {I}, realms {T})'''),
    ('realms', '''CREATE TABLE IF NOT EXISTS realms (
        id {ID}, name {K} NOT NULL UNIQUE, suffix {K}, directory {K}, lookup {K},
        auth_mode {K}, group_list {B}, check_disabled {I}, reply {T}, enabled {I},
        position {I}, note {T}, created {N}, token_name {K}, nested {I}, methods {T},
        aliases {T})'''),
    ('directories', '''CREATE TABLE IF NOT EXISTS directories (
        id {ID}, name {K} NOT NULL UNIQUE, hosts {T}, port {I}, tls {K}, verify {I},
        ca {B}, base {T}, bind_dn {T}, bind_pw {T}, user_attr {K}, nested {I},
        timeout_s {I}, enabled {I}, note {T}, created {N}, weak {I})'''),
    ('radius_log', '''CREATE TABLE IF NOT EXISTS radius_log (
        id {ID}, ts {N}, client {K}, nas_ip {K}, src {K}, packet {K}, username {K},
        realm {K}, calling {K}, called {K}, result {K}, reason {T}, acme {K}, rid {K},
        took_ms {I}, attrs {B}, reply {B}, steps {B}, device {K}, tunnel {K}, node {K})'''),
    ('acme_log', '''CREATE TABLE IF NOT EXISTS acme_log (
        id {ID}, ts {N}, name {K}, ok {I}, said {T}, how {K}, src {K}, rid {K},
        step_off {I}, node {K})'''),
    ('events', '''CREATE TABLE IF NOT EXISTS events (
        id {ID}, ts {N}, kind {K}, level {K}, who {K}, words {T}, node {K})'''),
    # What was used once and may never be again (1.0.101): a code's time
    # step, a recovery code, an answered question - one row each, never
    # changed, written by each node only under its own number. Two nodes
    # replicating whole token rows wrote an older copy of one over the
    # other, and a used recovery code came back.
    ('token_once', '''CREATE TABLE IF NOT EXISTS token_once (
        id {ID}, k {K} NOT NULL, node {I} NOT NULL, ts {N}, UNIQUE (k, node))'''),
]

INDEXES = [
    'CREATE INDEX IF NOT EXISTS radius_log_ts ON radius_log (ts)',
    'CREATE INDEX IF NOT EXISTS radius_log_user ON radius_log (username, ts)',
    'CREATE INDEX IF NOT EXISTS radius_log_result ON radius_log (result, ts)',
    'CREATE INDEX IF NOT EXISTS acme_log_ts ON acme_log (ts)',
    'CREATE INDEX IF NOT EXISTS acme_log_name ON acme_log (name, ts)',
    'CREATE INDEX IF NOT EXISTS events_ts ON events (ts)',
    'CREATE INDEX IF NOT EXISTS sessions_expires ON sessions (expires)',
    # 1.0.33: the events by kind (the enrolment tab, the kinds offered as one
    # types), the log by packet and by client, the sign-ins by kind.
    'CREATE INDEX IF NOT EXISTS events_kind_ts ON events (kind, ts)',
    'CREATE INDEX IF NOT EXISTS radius_log_packet_ts ON radius_log (packet, ts, result)',
    'CREATE INDEX IF NOT EXISTS radius_log_client_ts ON radius_log (client, ts)',
    'CREATE INDEX IF NOT EXISTS sessions_kind_last ON sessions (kind, last)',
    'CREATE INDEX IF NOT EXISTS token_once_ts ON token_once (ts)',
]

TYPES = {
    'sqlite': {'ID': 'INTEGER PRIMARY KEY AUTOINCREMENT', 'K': 'TEXT', 'T': 'TEXT',
               'B': 'TEXT', 'N': 'REAL', 'I': 'INTEGER'},
    # Compared byte for byte, as SQLite and PostgreSQL compare (1.0.44): with
    # the default collation novák@x.cz was novak@x.cz, and one person's
    # token was written over another's.
    'mariadb': {'ID': 'BIGINT AUTO_INCREMENT PRIMARY KEY', 'K': 'VARCHAR(190) COLLATE utf8mb4_bin',
                'T': 'TEXT', 'B': 'MEDIUMTEXT', 'N': 'DOUBLE', 'I': 'BIGINT'},
    'postgres': {'ID': 'BIGSERIAL PRIMARY KEY', 'K': 'TEXT', 'T': 'TEXT', 'B': 'TEXT',
                 'N': 'DOUBLE PRECISION', 'I': 'BIGINT'},
}

TABLES = [name for name, _ in SCHEMA]


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

    # ---- lanes: RADIUS on a connection of its own (1.0.136) ---------------------
    # Every statement goes one at a time through a connection and its lock.
    # With one connection for everything, a slow page (the overview over a
    # month, uncached: 29 s under load) held every sign-in behind it, and the
    # VPN timed out. Once the daemon turns lanes on, the RADIUS threads (their
    # names start with 'radius') have their own connection and lock: nothing
    # the pages, the console, the backups or the ticks do waits in front of
    # them. A lane whose connection cannot be made falls back to the main one
    # for a minute.
    LANE_RETRY_S = 60
    RADIUS_LANES = 4

    def _conn_timeout(self):
        """How long a new connection may take: 2 s at most for RADIUS's own
        (1.0.186) - made under its lane's lock, every request on that lane
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
        connection, and two RADIUS threads could wait on each other for good."""
        main = self._lanes['main']
        if not self.lanes_on or not threading.current_thread().name.startswith('radius'):
            return main
        # A copy put back holds the database whole, RADIUS too (as before
        # the lanes): its writes would collide with the rows coming in.
        # This database's own (1.0.139): a move loading another database sent
        # RADIUS off its lane for the whole of it.
        if getattr(self, 'restoring', False):
            return main
        # A few connections for RADIUS on a database server (1.0.150): one,
        # every sign-in waited for the one before it there - about 125 a
        # second, and one row held by a lock stopped them all. Each RADIUS
        # thread keeps to one of them. SQLite writes one at a time anyway.
        key = 'radius'
        if self.engine != 'sqlite' and self.RADIUS_LANES > 1:
            tail = threading.current_thread().name.rsplit('-', 1)[-1]
            key = 'radius%d' % ((int(tail) if tail.isdigit() else 0) % self.RADIUS_LANES)
        lane = self._lanes.get(key)
        if lane is None:
            with self._lanes_lock:
                lane = self._lanes.setdefault(key, _Lane())
        if lane.conn is None and time.time() < lane.failed_until:
            return main
        return lane

    @contextlib.contextmanager
    def _pinned(self):
        """The call's lane pinned for everything under it. A RADIUS lane
        without a connection makes one first - under its own lock only;
        when it cannot while the main one works, the call goes to the main
        lane (and RADIUS with it for a minute). Never the main lock taken
        while the RADIUS lane's is held."""
        if getattr(self._tls, 'lane', None) is not None:
            yield
            return
        lane = self._pick()
        main = self._lanes['main']
        if lane is not main and lane.conn is None:
            with lane.lock:
                if lane.conn is None:
                    if time.time() < lane.failed_until:
                        lane = main
                    elif time.time() < lane.down_until:
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
                            if main.conn is None or time.time() < main.down_until:
                                raise
                            lane.failed_until = time.time() + self.LANE_RETRY_S
                            log_sparing('db-lane', 'RADIUS shares the main database '
                                        'connection for a minute: its own could not be made',
                                        'warn')
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
            if lane.conn is None and time.time() < lane.down_until:
                raise DbError(lane.down_said or 'the database is not answering')
            try:
                self._connect()
                lane.down_until = 0.0
            except DbError as e:
                lane.down_until = time.time() + self.DOWN_RETRY_S
                lane.down_said = str(e)
                raise

    # RADIUS's own lane waits less (1.0.149): a VPN gives up on an answer in
    # 5 to 15 s; a statement there that waited 120 s held every sign-in behind
    # it. Past these it is no answer, and the VPN asks the other node.
    RADIUS_STATEMENT_S = 5
    RADIUS_LOCK_S = 2
    RADIUS_SQLITE_BUSY_S = 3

    def _connect(self):
        quick = self._lane() is not self._lanes['main']
        stmt_s = min(self.statement_s or self.RADIUS_STATEMENT_S, self.RADIUS_STATEMENT_S) \
            if quick else self.statement_s
        lock_s = self.RADIUS_LOCK_S if quick else self.LOCK_S
        with self.lock:
            if self.engine == 'sqlite':
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # RADIUS's lane waits 3 s for the file (1.0.149), not 30: past
                # that, no answer, and the VPN asks the other node.
                conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                       isolation_level=None,
                                       timeout=self.RADIUS_SQLITE_BUSY_S if quick else 30)
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
                        cursorclass=pymysql.cursors.DictCursor,
                        **db_tls_args('mariadb', self.tls, self.tls_ca))
                except Exception as e:
                    raise DbError('MariaDB at %s could not be reached: %s' % (self.where(), e))
                for sql in ('SET SESSION innodb_lock_wait_timeout = %d' % lock_s,
                            'SET SESSION max_statement_time = %d' % stmt_s):
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
                        options='-c lock_timeout=%d -c statement_timeout=%d' % (
                            lock_s * 1000, stmt_s * 1000),
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
            cur = self.conn.execute(sql, tuple(args or ()))
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
            # PostgreSQL takes no NUL in a text (1.0.59): a RADIUS name with
            # one in it broke the request, and its write-down, every time.
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
            try:
                yield
            finally:
                try:
                    self.run(RawSql(on))
                except Exception:                       # noqa: BLE001
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
            self._pg_keep_used()
        if self.value('SELECT v FROM meta WHERE k = ?', ('schema',)) is None:
            self.run('INSERT INTO meta (k, v) VALUES (?, ?)', ('schema', str(SCHEMA_VERSION)))

    def _pg_keep_used(self):
        """Two replicating nodes (1.0.57, 1.0.59). Logical replication sends
        the whole row with every UPDATE, so the other node's later write of
        anything in a token's row carried its older values of everything
        else over the newer ones: a code or a recovery code used up came
        back, a token switched off came back on, a lockout was lost, new
        recovery codes never got across. Each group of a token's columns -
        the key, the state, the lockout, the recovery codes - now carries the
        time it was last changed on the node that changed it, and where a row
        comes in from the other node the newer of each group is kept; the
        last code step only ever goes up, and recovery codes of the same
        issue used on either node stay used.

        A row made on both nodes under the same name (1.0.59) - a token
        enrolled on each at once, a meta key both wrote first - stopped
        replication for good on the duplicate. Where one comes in that is
        already here, the same one of the two is kept on both nodes."""
        try:
            self.run("""CREATE OR REPLACE FUNCTION acme_codes(t text) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT
AS $f$ SELECT COALESCE(NULLIF($1, ''), '[]')::jsonb $f$""")
            # The schema it is made in kept with each function (1.0.59): the
            # replication's apply worker runs with an empty search_path, and
            # "meta" or acme_codes() were not found there - replication stopped.
            self.run("""CREATE OR REPLACE FUNCTION acme_keep_used() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
DECLARE
  now_ double precision := extract(epoch FROM clock_timestamp());
  same_key boolean;
BEGIN
  IF current_setting('session_replication_role') <> 'replica' THEN
    IF TG_OP = 'INSERT' THEN
      NEW.key_at := COALESCE(NEW.key_at, now_);
      NEW.state_at := COALESCE(NEW.state_at, now_);
      NEW.lock_at := COALESCE(NEW.lock_at, now_);
      NEW.scratch_at := COALESCE(NEW.scratch_at, now_);
      RETURN NEW;
    END IF;
    IF NEW.secret IS DISTINCT FROM OLD.secret
       OR NEW.pending_secret IS DISTINCT FROM OLD.pending_secret
       OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.dest IS DISTINCT FROM OLD.dest THEN
      NEW.key_at := now_;
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
      NEW.state_at := now_;
    END IF;
    IF NEW.failures IS DISTINCT FROM OLD.failures
       OR NEW.locked_until IS DISTINCT FROM OLD.locked_until
       OR NEW.fail_times IS DISTINCT FROM OLD.fail_times THEN
      NEW.lock_at := now_;
    END IF;
    BEGIN
      -- Issued (a code that was not there before), not merely used.
      IF NEW.scratch IS DISTINCT FROM OLD.scratch
         AND NOT (acme_codes(OLD.scratch) @> acme_codes(NEW.scratch)) THEN
        NEW.scratch_at := now_;
      END IF;
    EXCEPTION WHEN others THEN
      NEW.scratch_at := now_;
    END;
    RETURN NEW;
  END IF;
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  END IF;
  IF NEW.key_at IS NULL AND NEW.state_at IS NULL AND NEW.lock_at IS NULL
     AND NEW.scratch_at IS NULL THEN
    -- From a node still on a version before these times (a rolling
    -- upgrade, 1.0.62): taken as it comes, as then, and the code step
    -- never goes down.
    IF NEW.secret IS NOT DISTINCT FROM OLD.secret THEN
      NEW.last_step := GREATEST(COALESCE(NEW.last_step, 0), COALESCE(OLD.last_step, 0));
    END IF;
    RETURN NEW;
  END IF;
  same_key := NEW.secret IS NOT DISTINCT FROM OLD.secret;
  IF COALESCE(NEW.key_at, 0) < COALESCE(OLD.key_at, 0) THEN
    NEW.secret := OLD.secret; NEW.digits := OLD.digits; NEW.period := OLD.period;
    NEW.algorithm := OLD.algorithm; NEW.issuer := OLD.issuer; NEW.label := OLD.label;
    NEW.pending_secret := OLD.pending_secret; NEW.pending_scratch := OLD.pending_scratch;
    NEW.pending_at := OLD.pending_at; NEW.pending_by := OLD.pending_by;
    NEW.created := OLD.created; NEW.created_by := OLD.created_by;
    NEW.activated := OLD.activated;
    NEW.kind := OLD.kind; NEW.dest := OLD.dest;     -- how codes go, with the key (1.0.76)
    NEW.last_step := CASE WHEN same_key
                          THEN GREATEST(COALESCE(NEW.last_step, 0), COALESCE(OLD.last_step, 0))
                          ELSE OLD.last_step END;
    NEW.key_at := OLD.key_at;
  ELSIF NEW.secret IS NOT DISTINCT FROM OLD.secret THEN
    NEW.last_step := GREATEST(COALESCE(NEW.last_step, 0), COALESCE(OLD.last_step, 0));
  END IF;
  IF COALESCE(NEW.state_at, 0) < COALESCE(OLD.state_at, 0) THEN
    NEW.state := OLD.state; NEW.state_at := OLD.state_at;
  END IF;
  IF COALESCE(NEW.lock_at, 0) < COALESCE(OLD.lock_at, 0) THEN
    NEW.failures := OLD.failures; NEW.fail_times := OLD.fail_times;
    NEW.locked_until := OLD.locked_until; NEW.lock_at := OLD.lock_at;
  END IF;
  BEGIN
    IF COALESCE(NEW.scratch_at, 0) < COALESCE(OLD.scratch_at, 0) THEN
      NEW.scratch := OLD.scratch; NEW.scratch_sealed := OLD.scratch_sealed;
      NEW.scratch_left := OLD.scratch_left; NEW.scratch_at := OLD.scratch_at;
    ELSIF COALESCE(NEW.scratch_at, 0) = COALESCE(OLD.scratch_at, 0)
          AND NEW.scratch IS DISTINCT FROM OLD.scratch THEN
      -- The same issue: what was used on either node stays used.
      IF COALESCE(OLD.scratch_left, 0) < COALESCE(NEW.scratch_left, 0) THEN
        NEW.scratch_sealed := OLD.scratch_sealed;
      END IF;
      NEW.scratch := (SELECT COALESCE(jsonb_agg(e), '[]'::jsonb)::text
                        FROM jsonb_array_elements(acme_codes(NEW.scratch)) e
                       WHERE acme_codes(OLD.scratch) @> jsonb_build_array(e));
      NEW.scratch_left := jsonb_array_length(NEW.scratch::jsonb);
    END IF;
  EXCEPTION WHEN others THEN NULL;
  END;
  RETURN NEW;
END $f$""")
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
            if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = 'acme_keep_used' AND "
                              "tgrelid = 'tokens'::regclass"):
                self.run('CREATE TRIGGER acme_keep_used BEFORE UPDATE ON tokens '
                         'FOR EACH ROW EXECUTE FUNCTION acme_keep_used()')
            if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = 'acme_keep_made' AND "
                              "tgrelid = 'tokens'::regclass"):
                self.run('CREATE TRIGGER acme_keep_made BEFORE INSERT ON tokens '
                         'FOR EACH ROW EXECUTE FUNCTION acme_keep_used()')
            self.run('ALTER TABLE tokens ENABLE ALWAYS TRIGGER acme_keep_used')
            self.run('ALTER TABLE tokens ENABLE ALWAYS TRIGGER acme_keep_made')
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
            for table, col in (('tokens', 'name'), ('accounts', 'name'), ('clients', 'name'),
                               ('realms', 'name'), ('directories', 'name'), ('meta', 'k'),
                               ('settings', 'k'), ('sessions', 'token_hash')):
                trg = 'acme_same_%s' % table
                if not self.value("SELECT 1 FROM pg_trigger WHERE tgname = ? AND "
                                  "tgrelid = ?::regclass", (trg, table)):
                    # The name sorts after acme_keep_made: that one fills the
                    # times first.
                    self.run("CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE "
                             "FUNCTION acme_same_key('%s')" % (trg, table, col))
                self.run('ALTER TABLE %s ENABLE ALWAYS TRIGGER %s' % (table, trg))
        except Exception as e:                          # noqa: BLE001
            log('the guard of used codes between two nodes could not be put in: %s'
                % str(e).split('\n')[0], 'warn')

    def _mariadb_meta_keys(self):
        """meta's keys to 255 characters (1.0.208): a token's name may be 180, and
        disabled_from:NAME or scratchguard:NAME@@NODE went past 190 - switching
        such a token off or sending it a code failed ("Data too long")."""
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
                kind = re.sub(r'\s*(NOT NULL|UNIQUE|PRIMARY KEY).*$', '', piece.split(' ', 1)[1])
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
              tls_ca=c.get('db_tls_ca') or '')


