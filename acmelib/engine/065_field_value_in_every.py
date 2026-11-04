# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# `field:value` in every search box (1.0.19, as isemon's ListQuery)
# ---------------------------------------------------------------------------
# What is typed into a list's search box is read as isemon reads it: words
# as before, and besides them `field:value` - `kind:settings who:admin`,
# `-level:info`, `to:*@example.cz`, `tries:>2`, `(kind:certs OR kind:alerts)
# what~renewed`. A name the list does not have is not a field at all -
# `10.1.2.3:443` is a word - and a box with no field in it searches exactly
# as it did. A module adds a list of its own to LIST_FIELDS, LIST_FIELD_SAYS
# and LIST_WORD_COLUMNS (and LIST_TABLES, for the values offered as one types).
#
# kind: text (folded; `*` a wildcard), num (a number, a range, > <), ip (an
# address or the start of one; `/24` a range), ok (yes/no as 1/0), list (a JSON
# list of words - one of them matches; 1.0.24), none (not in this list: no row).
LIST_FIELDS = {
    'events': {
        'kind': ('kind', 'text'), 'who': ('who', 'text'), 'by': ('who', 'text'),
        'what': ('words', 'text'), 'level': ('level', 'text'), 'node': ('node', 'text'),
        'server': ('node', 'text'),
    },
    # The outgoing mail (1.0.95): its rows searched in a table of their own
    # made for the search (memory_search below), with the same words.
    'mailq': {
        'to': ('to_addr', 'text'), 'state': ('state', 'text'), 'kind': ('kind', 'text'),
        'name': ('name', 'text'), 'user': ('name', 'text'),
        'by': ('by_who', 'text'), 'said': ('said', 'text'), 'why': ('said', 'text'),
        'subject': ('subject', 'text'), 'tries': ('tries', 'num'), 'node': ('node', 'text'),
        'server': ('node', 'text'),
    },
}
# What each field means, with an example - what the box offers as one types.
LIST_FIELD_SAYS = {
    'events': [('kind', 'the kind of event', 'kind:settings'),
               ('who', 'who did it', 'who:admin'),
               ('what', 'what it says', 'what~renewed'),
               ('level', 'info or warn', 'level:warn'),
               ('node', 'the node it happened on (high availability)', 'node:acme2')],
    'mailq': [('to', 'whom it goes to', 'to:*@example.cz'),
              ('state', 'waiting, sending, sent, failed or expired', 'state:waiting'),
              ('kind', 'code, verify, alert, report or test', 'kind:code'),
              ('name', 'the account it is about', 'name:novak*'),
              ('said', 'what the receiving server said', 'said~greylist'),
              ('tries', 'how many times it was tried', 'tries:>2'),
              ('by', 'who had it sent', 'by:admin'),
              ('subject', 'its subject', 'subject~certificate'),
              ('node', 'the node that sends it (high availability)', 'node:acme2')],
}
LIST_WORD_COLUMNS = {
    'events': ('words', 'who', 'kind'),
    'mailq': ('to_addr', 'name', 'subject', 'said', 'by_who'),
}
# The table each list reads, for the values offered as one types (list_values);
# a list with none here offers none. 'ts' in it: only the last 30 days grouped.
LIST_TABLES = {'events': 'events'}
# What a list offers as one types where it is not a table's column grouped
# (1.0.24): {list: fn(handler, field, typed) -> [{'val', 'n'}]} - a list whose
# rows are read for the person asking (the certificates of their teams).
LIST_VALUES = {}
LIST_TOKEN = re.compile(r'\s*(\(|\)|[-!]?(?:[A-Za-z_][\w.]*(?:!=|>=|<=|[:~=<>]))?'
                        r'(?:"[^"]*"?|[^\s()"]+)|"[^"]*"?)')
LIST_TERM = re.compile(r'^([-!]?)([A-Za-z_][\w]*)(!=|>=|<=|[:~=<>])(.*)\Z', re.S)


def memory_search(listname, create, cols, rows, text):
    """Rows that live nowhere a query can reach - the outgoing mail, a
    backup being read - searched with the very words every list takes
    (1.0.96): put into a table in memory, and the list's query run there.
    Returns the indexes of the rows that match."""
    lq = ListQuery(listname, text)
    import sqlite3
    conn = sqlite3.connect(':memory:')
    try:
        conn.execute(create)
        conn.executemany('INSERT INTO t (%s) VALUES (%s)' % (', '.join(['i'] + list(cols)),
                                                          ', '.join('?' * (len(cols) + 1))),
                         [[i] + [r.get(c) for c in cols] for i, r in enumerate(rows)])
        where, args = [], []
        if lq.sql:
            where.append(lq.sql)
            args += list(lq.args)
        if lq.words:
            w = lq._word(lq.words)
            where.append(w[0])
            args += list(w[1])
        sql = 'SELECT i FROM t' + (' WHERE ' + ' AND '.join('(%s)' % x for x in where)
                                   if where else '')
        return [r[0] for r in conn.execute(sql, args)]
    finally:
        conn.close()


class ListQueryError(ValueError):
    pass


def log_node():
    """The node a log line is written on (1.0.45) - whose it is, in a
    cluster."""
    try:
        return node_name()[:190]
    except Exception:                                   # noqa: BLE001
        return ''


def like_pattern(text):
    """`*` a wildcard, everything else itself; `!` is the escape."""
    out = ''
    for c in str(text):
        if c == '*':
            out += '%'
        elif c in '%_!':
            out += '!' + c
        else:
            out += c
    return out


class ListQuery(object):
    """`sql`/`args` is the piece of the WHERE the fields make (empty where
    there are none); `words` is what goes to the list's own word search."""

    def __init__(self, listname, text):
        self.list = listname
        self.fields = LIST_FIELDS.get(listname, {})
        self.text = str(text or '').strip()
        self.sql, self.args, self.words = '', [], self.text
        if len(self.text) > 2000:
            raise ListQueryError('that search is too long - 2000 characters at most')
        self.tokens = [m.group(1) for m in LIST_TOKEN.finditer(self.text) if m.group(1)]
        if not any(self._field(t) for t in self.tokens):
            return
        if len(self.tokens) > 300:
            raise ListQueryError('that search has too many parts')
        # NOT on NOT on NOT, or bracket in bracket, a few hundred deep, made
        # SQLite give up parsing (1.0.33): twenty is more than anybody writes.
        if sum(1 for t in self.tokens if t in ('NOT', '!', '(')) > 40:
            raise ListQueryError('that search has too many NOTs and brackets in it')
        self.at, self.top_words = 0, []
        node = self._or(True)
        if self.at < len(self.tokens):
            raise ListQueryError('a closing bracket with nothing open before it')
        words = [w.strip('"') for w in self.top_words if w.strip('"')]
        self.words = words[0] if words else ''
        node = self._join('AND', [node] + [self._word(w) for w in words[1:]])
        if node:
            self.sql, self.args = node

    def _field(self, token):
        m = LIST_TERM.match(token or '')
        return m if m and m.group(2).lower() in self.fields else None

    def _peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    @staticmethod
    def _join(op, parts):
        parts = [p for p in parts if p]
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return ('(' + (' %s ' % op).join(p[0] for p in parts) + ')',
                [a for p in parts for a in p[1]])

    def _or(self, top=False):
        parts, alone = [self._and(top)], True
        while self._peek() in ('OR', '|', '||'):
            alone = False
            self.at += 1
            if self._peek() in (None, ')'):
                raise ListQueryError('OR with nothing after it')
            parts.append(self._and(False))
        if not alone and top and self.top_words:
            raise ListQueryError('a word on its own beside OR - write it as a field, or put '
                                 'the OR in brackets')
        return self._join('OR', parts)

    def _and(self, top):
        parts = [self._not(top)]
        while self._peek() not in (None, ')', 'OR', '|', '||'):
            if self._peek() in ('AND', '&', '&&'):
                self.at += 1
                continue
            parts.append(self._not(top))
        return self._join('AND', parts)

    def _not(self, top):
        t = self._peek()
        if t in ('NOT', '!'):
            self.at += 1
            inner = self._not(False)
            return ('NOT COALESCE((%s), 1=0)' % inner[0], inner[1]) if inner else None
        if t == '(':
            self.at += 1
            inner = self._or(False)
            if self._peek() != ')':
                raise ListQueryError('a bracket opened and never closed')
            self.at += 1
            return inner
        if t == ')':
            raise ListQueryError('a closing bracket with nothing open before it')
        if t is None:
            # The end, where a word was still to come (1.0.103): "x !" or
            # "x (" read past the end and failed with a TypeError.
            raise ListQueryError('NOT, ! or a bracket with nothing after it')
        self.at += 1
        return self._leaf(t, top)

    def _word(self, word):
        cols = LIST_WORD_COLUMNS.get(self.list, ())
        like = '%' + like_pattern(word.lower()) + '%'
        sql = ["LOWER(COALESCE(%s, '')) LIKE ? ESCAPE '!'" % c for c in cols]
        args = [like] * len(cols)
        return ('(' + ' OR '.join(sql) + ')', args)

    def _leaf(self, token, top):
        m = self._field(token)
        if not m:
            lead = token[:1] if token[:1] in '-!' and len(token) > 1 else ''
            word = token[len(lead):].strip('"')
            if not word:
                return None
            if top and not lead:
                self.top_words.append(token)
                return None
            w = self._word(word)
            return ('NOT (%s)' % w[0], w[1]) if lead else w
        lead, name, op, value = m.groups()
        column, kind = self.fields[name.lower()]
        self._name = name.lower()
        quoted = value.startswith('"')
        value = value.strip('"')
        if value == '':
            return None                      # still being typed
        neg = bool(lead) != (op == '!=')
        if kind == 'none':
            clause = ('1=0', [])
        else:
            items = [value] if quoted else [v for v in value.split(',') if v.strip()]
            clause = self._join('OR', [self._one(column, kind, op, v.strip()) for v in items])
        if not clause:
            return None                      # "name:," - nothing in it yet (1.0.139)
        if neg:
            return ('NOT COALESCE((%s), 1=0)' % clause[0], clause[1])
        return clause

    def _one(self, col, kind, op, item):
        low = item.lower()
        cmp = (op in (':', '=')) and re.match(r'^(>=|<=|>|<)\s*(.+)\Z', low)
        if cmp:
            op, low = cmp.group(1), cmp.group(2)
        if kind == 'num':
            rng = re.match(r'^(-?[\d.]+)\s*-\s*(-?[\d.]+)\Z', low)
            try:
                if rng:
                    return ('(%s BETWEEN ? AND ?)' % col, [float(rng.group(1)),
                                                           float(rng.group(2))])
                n = float(low)
            except ValueError:
                raise ListQueryError('%s is a number - %r is not one' % (getattr(self, '_name', col), item))
            sign = {'>': '>', '<': '<', '>=': '>=', '<=': '<='}.get(op, '=')
            return ('(%s %s ?)' % (col, sign), [n])
        if op in ('>', '<', '>=', '<='):
            raise ListQueryError('only a number can be more or less than something')
        if kind == 'ok':
            v = {'accept': 1, 'accepted': 1, 'right': 1, 'yes': 1, 'ok': 1, 'reject': 0,
                 'rejected': 0, 'wrong': 0, 'no': 0, 'refused': 0}.get(low)
            if v is None:
                return ('1=0', [])
            return ('%s = ?' % ('ok' if col in ('', None) else col), [v])
        if kind == 'node':
            return ("LOWER(%s) LIKE ? ESCAPE '!'" % col, ['% on ' + like_pattern(low) + '%'])
        if kind == 'ip' and '/' in low and op != '~':
            try:
                net = ipaddress.ip_network(low, strict=False)
            except ValueError:
                raise ListQueryError('%r is not an address or a range of them' % item)
            if net.version == 4 and net.prefixlen % 8 == 0:
                keep = '.'.join(str(net.network_address).split('.')[:net.prefixlen // 8])
                return ("LOWER(%s) LIKE ? ESCAPE '!'" % col,
                        [like_pattern(keep) + ('.%' if keep else '%')])
            raise ListQueryError('a range is /8, /16 or /24 here')
        c = "LOWER(COALESCE(%s, ''))" % col
        if kind == 'list':
            # One word of a JSON list: ["www.example.cz", ...] - `*` within it.
            if op == '~':
                return ("%s LIKE ? ESCAPE '!'" % c, ['%' + like_pattern(low) + '%'])
            return ("%s LIKE ? ESCAPE '!'" % c, ['%"' + like_pattern(low) + '"%'])
        if op == '~':
            return ("%s LIKE ? ESCAPE '!'" % c, ['%' + like_pattern(low) + '%'])
        if kind == 'ip' and '*' not in low:
            # An address as it was written down may carry its port.
            return ("(%s = ? OR %s LIKE ? ESCAPE '!')" % (c, c), [low, like_pattern(low) + ':%'])
        if '*' in low:
            return ("%s LIKE ? ESCAPE '!'" % c, [like_pattern(low)])
        return ('%s = ?' % c, [low])

def list_position(v):
    """A place in a list: a whole number, not past what the database holds
    (1.0.103: 1e20 broke the save with a 500)."""
    try:
        n = int(float(v or 0))
    except (TypeError, ValueError, OverflowError):
        raise ValueError('the position is a number')
    return max(-1000000, min(1000000, n))


# Letters of any language (1.0.153): an administrator from the directory whose
# account is called žofie could not sign in - the name was refused.
ACCOUNT_NAME_RE = re.compile(r'[^\W_][\w.@\\-]{0,120}\Z')


def _yes(data, key, default):
    """A yes/no field of a form: 1 or 0, its default where it is missing or null
    (1.0.146: null raised a TypeError - an error 500 for a typed request)."""
    v = data.get(key)
    if v is None or v == '':
        return int(default)
    try:
        return int(bool(int(v)))
    except (TypeError, ValueError):
        raise ValueError('%s is 0 or 1' % key)


class Storage(object):
    """Everything this daemon keeps, over whichever database it is."""

    # The lists kept read (1.0.206): set to None by a save, which counts a new
    # generation; a list read meanwhile - from before the save - is not kept
    # over it. It was, and a directory just added stayed unknown on that node
    # until the next change or a restart.
    def _cache_get(self, k):
        return self.__dict__.get(k)

    def _cache_set(self, k, v):
        with self.__dict__.setdefault('_cache_lock', threading.Lock()):
            if v is None:
                self.__dict__['cache_gen'] = self.__dict__.get('cache_gen', 0) + 1
            self.__dict__[k] = v

    @property
    def cache_gen(self):
        return self.__dict__.get('cache_gen', 0)

    def _cache_put(self, k, rows, gen):
        with self.__dict__.setdefault('_cache_lock', threading.Lock()):
            if self.cache_gen == gen:
                self.__dict__[k] = rows

    _dirs = property(lambda self: self._cache_get('_dirs'),
                     lambda self, v: self._cache_set('_dirs', v))

    @classmethod
    def view(cls, db):
        """The same database through another connection, nothing made
        (1.0.101)."""
        st = cls.__new__(cls)
        st.db = db
        st.lock = threading.RLock()
        st._dirs = None
        return st

    def __init__(self, db, quick=False):
        self.db = db
        SEAL_GUARD['db'] = db           # asked before a new key is made (1.0.205)
        # The command line (and so the console, every 20 s) made the tables,
        # indexes and triggers again on each run (1.0.136): on PostgreSQL
        # that takes locks that hold every write of the daemon behind them. Now it
        # does that only when this node's database was not made by this
        # version yet; the daemon still does it at each start.
        mark = 'schema:%s' % node_name()
        done = False
        if quick:
            try:
                done = db.value('SELECT v FROM meta WHERE k = ?', (mark,)) == __version__
            except Exception:                           # noqa: BLE001
                done = False
        if done:
            self.lock = threading.RLock()
            self._dirs = None
            return
        self.db.make_tables()
        try:
            self.db.upsert('meta', 'k', {'k': mark, 'v': __version__})
        except Exception:                               # noqa: BLE001
            pass
        if CONFIG.get('ha_mode') == 'replicated' and db.engine == 'postgres':
            # A table new in this version numbered on this node's side of odd
            # and even before anything is written to it (1.0.101).
            try:
                ha_sequences_check(db, int(CONFIG.get('ha_slot') or 1))
            except Exception as e:                      # noqa: BLE001
                log('the numbering of the tables could not be checked: %s' % e, 'warn')
        self.lock = threading.RLock()
        self._dirs = None

    # ---- meta, settings, events ------------------------------------------
    def get_meta(self, k, default=None):
        got = self.db.value('SELECT v FROM meta WHERE k = ?', (k,))
        if got is not None and dbguard_on() and dbguard_meta_kept(k) and \
                not dbguard_ok(self.db, 'm', k, got, quiet=True):
            # Read again once (1.0.234): the row and its signature are two reads, and a write
            # between them paired the old row with the new signature - web:vip read as not
            # there for a moment, and the VIP address could move.
            got = self.db.value('SELECT v FROM meta WHERE k = ?', (k,))
            if got is not None and not dbguard_ok(self.db, 'm', k, got):
                return default      # not acme's word (1.0.231): as if it were not there
        return default if got is None else got

    def set_meta(self, k, v):
        # One statement, no lock of Python's (1.0.139): a thread noting
        # something waited here behind a page holding the lock for a slow
        # query on the main connection.
        if not dbguard_meta_signed(k):
            self.db.upsert('meta', 'k', {'k': k, 'v': str(v)})
            return
        # The row and its signature in one transaction (1.0.232): replication brought them
        # over as two, and the other node, reading between them, took a heartbeat for one
        # not written by otp.
        with self.db.transaction():
            self.db.upsert('meta', 'k', {'k': k, 'v': str(v)})
            dbguard_sign(self.db, 'm', k, str(v))     # 1.0.231

    def settings_saved(self):
        out = {}
        for r in self.db.rows('SELECT k, v FROM settings'):
            try:
                out[r['k']] = json.loads(r['v'])
            except (TypeError, ValueError):
                continue
        return out

    def settings_written(self):
        return {r['k']: {'at': r['at'], 'by': r['by_who']}
                for r in self.db.rows('SELECT k, at, by_who FROM settings')}

    def save_setting(self, k, v, by=''):
        # Never stamped before what it changes (1.0.44): the other node's trigger keeps the
        # newer of two by this stamp, and a node whose clock was behind wrote a change that
        # the other threw away for good - the nodes held two values.
        at = time.time()
        try:
            was = float(self.db.value('SELECT at FROM settings WHERE k = ?', (k,)) or 0)
            if was >= at:
                at = was + 0.001
        except (TypeError, ValueError):
            pass
        row = {'k': k, 'v': json.dumps(v), 'at': at, 'by_who': str(by or '')[:190]}
        if not dbguard_setting_kept(k):
            self.db.upsert('settings', 'k', row)
            return
        with self.db.transaction():                 # with its signature (1.0.234)
            self.db.upsert('settings', 'k', row)
            dbguard_sign(self.db, 's', k, json.dumps(v))     # 1.0.231

    def drop_setting(self, k):
        if not dbguard_setting_kept(k):
            self.db.run('DELETE FROM settings WHERE k = ?', (k,))
            return
        with self.db.transaction():                 # with its signature (1.0.234)
            self.db.run('DELETE FROM settings WHERE k = ?', (k,))
            dbguard_sign(self.db, 's', k, None)

    def add_event(self, kind, words, level='info', who=''):
        if HA_REBUILDING.is_set():
            log('(not written while the node is rebuilt) %s: %s' % (kind, words))
            return None
        try:
            self.db.insert('events', {'ts': time.time(), 'kind': str(kind)[:60],
                                      'node': log_node(),
                                      'level': level, 'who': str(who or '')[:190],
                                      'words': str(words)[:4000]})
        except Exception as e:
            log('the event could not be written down: %s (%s)' % (words, e), 'warn')
        log('%s: %s%s' % (kind, words, (' (%s)' % who) if who else ''),
            'warn' if level in ('warn', 'bad') else 'info')
        hook = getattr(self, 'on_event', None)
        if hook:
            try:
                hook(kind, words, level, who)
            except Exception:
                pass

    def events(self, limit=100, offset=0, q='', kind='', extra=None):
        where, args = [], []
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if q:
            where.append("(LOWER(words) LIKE ? ESCAPE '!' OR LOWER(who) LIKE ? ESCAPE '!' OR LOWER(kind) LIKE ? ESCAPE '!')")
            like = '%' + like_pattern(str(q).lower()) + '%'
            args += [like, like, like]
        if kind:
            where.append('kind = ?')
            args.append(kind)
        sql = ' WHERE ' + ' AND '.join(where) if where else ''
        total = self.db.value('SELECT COUNT(*) AS n FROM events' + sql, args, 0)
        rows = self.db.rows('SELECT * FROM events' + sql + ' ORDER BY ts DESC, id DESC '
                            'LIMIT %d OFFSET %d' % (int(limit), int(offset)), args)
        return rows, int(total or 0)

    def list_values(self, listname, field, typed='', since=0, most=15):
        """What one field of one list holds, busiest first, for the search
        box over it to offer as somebody types (1.0.19, as isemon)."""
        spec = LIST_FIELDS.get(listname, {}).get(field)
        if not spec:
            return []
        column, kind = spec
        typed = str(typed or '').strip().lower()
        if kind == 'ok':
            return [{'val': v, 'n': 0} for v in ('yes', 'no') if v.startswith(typed)]
        if kind == 'none' or not column:
            return []
        if kind == 'text' and column == 'words':
            return []           # never offered - not grouped over every event first (1.0.57)
        table = LIST_TABLES.get(listname)
        if not table:
            return []
        where, args = [], []
        # A window always (1.0.57): with none, every keystroke grouped the
        # whole log - seconds on a big one.
        logged = 'ts' in [c.lower() for c in self.db.columns(table)]
        if not since and logged:
            since = time.time() - 30 * 86400
        if since and logged:
            where.append('ts >= ?')
            args.append(since)
        # A number is compared as a number (1.0.33): PostgreSQL refuses
        # COALESCE(a number, '').
        if kind == 'num':
            where.append('%s IS NOT NULL' % column)
        else:
            where.append("COALESCE(%s, '') <> ''" % column)
        sql = ' WHERE ' + ' AND '.join(where)
        rows = self.db.rows('SELECT %s AS val, COUNT(*) AS n FROM %s%s GROUP BY %s '
                            'ORDER BY n DESC LIMIT 2000' % (column, table, sql, column), args)
        got = collections.Counter()
        for r in rows:
            v = str(r['val'])
            if kind == 'ip':
                v = re.sub(r':\d+$', '', v) if v.count(':') == 1 else v
            elif kind == 'node':
                m = re.search(r' on (\S+)', v)
                v = m.group(1).rstrip(',') if m else ''
            elif kind == 'text' and column == 'words':
                continue
            if v:
                got[v] += int(r['n'] or 0)
        out = [{'val': v, 'n': n} for v, n in got.items()
               if not typed or typed.strip('*') in v.lower()]
        out.sort(key=lambda x: (not x['val'].lower().startswith(typed.strip('*')), -x['n'],
                                x['val'].lower()))
        return out[:most]

    _KINDS = (0.0, [])

    def event_kinds(self):
        # Kept a minute (1.0.57): every page of Events read the whole table
        # for its few kinds.
        at, kinds = Storage._KINDS
        if time.time() - at < 60 and kinds:
            return kinds
        kinds = [r['kind'] for r in self.db.rows('SELECT DISTINCT kind FROM events ORDER BY kind')]
        Storage._KINDS = (time.time(), kinds)
        return kinds

    # ---- accounts of the administration pages ----------------------------
    def accounts(self):
        rows = self.db.rows('SELECT * FROM accounts ORDER BY name')
        for r in rows:
            r.pop('pw', None)
            # How somebody laid out their tables is theirs and can be big:
            # only whether there is any, for the Accounts list.
            r['cols_tables'] = len(self._cols_of(r.pop('cols', None)))
            r.pop('cols_at', None)
        return rows

    def account(self, name, checked=False):
        row = self.db.row('SELECT * FROM accounts WHERE LOWER(name) = ?',
                          (str(name or '').strip().lower(),))
        if checked and row and not dbguard_account_ok(self.db, row):
            return None             # put in by somebody else than acme (1.0.231)
        return row

    def add_account(self, name, role, password=None, source='local', note='', must_change=0,
                    display='', dn='', groups=''):
        name = str(name or '').strip()
        if not ACCOUNT_NAME_RE.match(name):
            raise ValueError('a name has letters, digits, dots, dashes, @ and nothing else')
        bad = name_letters_problem(name)
        if bad:
            raise ValueError(bad)
        if role not in ROLES_ALL:
            raise ValueError('the role is one of %s' % ', '.join(ROLES_ALL))
        if self.account(name):
            raise ValueError('there is an account called %s already' % name)
        if source == 'local':
            bad = password_problem(password)
            if bad:
                raise ValueError(bad)
        # A second step left by an account of this name taken away before
        # (1.0.146) is not this one's: somebody else's phone would answer it.
        self.db.run('DELETE FROM meta WHERE k = ?', ('adm2fa:' + name.lower(),))
        pw = password_hash(password) if password else ''
        with self.db.transaction():                 # with its signature (1.0.234)
            got = self.db.insert('accounts', {
                'name': name, 'role': role, 'pw': pw,
                'source': source, 'disabled': 0, 'must_change': int(bool(must_change)),
                'note': str(note or '')[:400], 'created': time.time(), 'last_in': None,
                'last_from': '', 'prefs': '{}', 'display': display, 'dn': dn,
                'group_list': groups})
            dbguard_account_sign(self.db, name)
        return got

    def set_account(self, name, **fields):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        if 'password' in fields:
            bad = password_problem(fields['password'])
            if bad:
                raise ValueError(bad)
            fields['pw'] = password_hash(fields.pop('password'))
        if 'role' in fields and fields['role'] not in ROLES_ALL:
            raise ValueError('the role is one of %s' % ', '.join(ROLES_ALL))
        if not set(fields) & (set(ACCOUNT_SIGNED) | {'mail', 'mobile', 'mfa_on'}):
            self.db.update('accounts', one['id'], fields)
            return
        with self.db.transaction():                 # with its signature (1.0.234)
            self.db.update('accounts', one['id'], fields)
            dbguard_account_sign(self.db, fields.get('name') or one['name'])

    def drop_account(self, name):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        with self.db.transaction():                 # with its signature (1.0.234)
            self.db.run('DELETE FROM accounts WHERE id = ?', (one['id'],))
            dbguard_account_sign(self.db, one['name'])
        self.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                    ('admin', one['name'].lower()))
        # Its second step with it (1.0.146): a new account of the same name
        # took it over - the old owner's authenticator signing it in.
        self.db.run('DELETE FROM meta WHERE k = ?', ('adm2fa:' + one['name'].lower(),))

    # ---- how somebody laid out the tables (as on isemon, 1.10.146 on) -------
    COLS_MOST_TABLES = 300
    COLS_MOST_COLUMNS = 60
    COLS_MOST_BYTES = 60000

    @staticmethod
    def _cols_of(text):
        if not text:
            return {}
        try:
            got = json.loads(text)
        except (TypeError, ValueError):
            return {}
        return got if isinstance(got, dict) else {}

    @classmethod
    def clean_cols(cls, cols):
        """A layout as the page sent it, reduced to what a layout can hold:
        `{table: {"w": {column: pixels}, "o": [order], "h": [hidden],
        "v": [optional shown], "s": [empty columns], "t": when}}` and nothing
        else. Anything not understood is dropped rather than kept."""
        if cols == [] or cols is None:
            cols = {}                       # PHP passes an empty object on as []
        if not isinstance(cols, dict):
            raise ValueError('a layout of the columns is an object of tables')
        out = {}

        def names(v, most):
            return [str(c)[:80] for c in v[:most] if isinstance(c, (str, int))] \
                if isinstance(v, list) else []

        for key, one in list(cols.items())[:cls.COLS_MOST_TABLES]:
            key = str(key)[:160]
            if not key or not isinstance(one, dict):
                continue
            kept = {}
            widths = one.get('w')
            if isinstance(widths, dict):
                w = {}
                for col, px in list(widths.items())[:cls.COLS_MOST_COLUMNS]:
                    try:
                        px = int(round(float(px)))
                    except (TypeError, ValueError, OverflowError):
                        continue
                    w[str(col)[:80]] = max(24, min(3000, px))
                if w:
                    kept['w'] = w
            for k in ('o', 'h', 'v'):
                got = names(one.get(k), cls.COLS_MOST_COLUMNS)
                if got:
                    kept[k] = got
            sp = [c for c in names(one.get('s'), 20) if re.match(r'^~\d{1,4}\Z', c)]
            if sp:
                kept['s'] = sp
            if kept:
                try:
                    kept['t'] = int(float(one.get('t') or 0))
                except (TypeError, ValueError, OverflowError):
                    kept['t'] = 0
                out[key] = kept
        if len(json.dumps(out, separators=(',', ':'))) > cls.COLS_MOST_BYTES:
            raise ValueError('that layout of the columns is too big to keep (more than %d '
                             'characters)' % cls.COLS_MOST_BYTES)
        return out

    def user_cols(self, name):
        """How this person has laid out the tables, or {} for as they come."""
        try:
            one = self.account(name)
        except Exception:                               # noqa: BLE001
            return {}
        return self._cols_of(one.get('cols')) if one else {}

    def put_user_cols(self, name, cols):
        """Keep this person's layout; an empty one puts every table back."""
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        cols = self.clean_cols(cols or {})
        self.db.update('accounts', one['id'], {
            'cols': json.dumps(cols, separators=(',', ':')) if cols else None,
            'cols_at': time.time()})
        return cols

    @staticmethod
    def clean_prefs(prefs):
        if prefs == [] or prefs is None:
            prefs = {}
        if not isinstance(prefs, dict):
            raise ValueError('the choices are an object')
        out = {}
        if 'lang' in prefs:
            if str(prefs['lang']) not in ('cs', 'en'):
                raise ValueError('no such language here: %s' % prefs['lang'])
            out['lang'] = str(prefs['lang'])
        return out

    def user_prefs(self, name):
        one = self.account(name)
        return self._cols_of(one.get('prefs')) if one else {}

    def put_user_prefs(self, name, prefs):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        kept = dict(self._cols_of(one.get('prefs')))
        kept.update(self.clean_prefs(prefs))
        self.db.update('accounts', one['id'], {'prefs': json.dumps(kept)})
        return kept

    def fulladmins_left(self, but=''):
        return sum(1 for a in self.accounts() if a['role'] == 'fulladmin' and not a['disabled']
                   and a['name'].lower() != str(but).lower())

    # ---- sessions ----------------------------------------------------------
    def session_new(self, kind, name, role, ip, hours, data=None):
        token = secrets.token_urlsafe(32)
        t = time.time()
        row = {'token_hash': hashlib.sha256(token.encode()).hexdigest(), 'kind': kind,
               'name': name, 'role': role, 'created': t, 'last': t,
               'expires': t + float(hours) * 3600, 'ip': str(ip or '')[:60],
               'data': json.dumps(data or {})}
        if kind != 'admin':
            self.db.insert('sessions', row)
            return token
        with self.db.transaction():                 # with its signature (1.0.234)
            self.db.insert('sessions', row)
            dbguard_sign(self.db, 'x', row['token_hash'], dbguard_session_text(row))     # 1.0.231
        return token

    def session_get(self, token, kind, idle_s, touch=True):
        if not token:
            return None
        row = self.db.row('SELECT * FROM sessions WHERE token_hash = ? AND kind = ?',
                          (hashlib.sha256(str(token).encode()).hexdigest(), kind))
        if not row:
            return None
        if kind == 'admin' and dbguard_on() and \
                not dbguard_ok(self.db, 'x', row['token_hash'], dbguard_session_text(row)):
            return None             # a sign-in acme did not open (1.0.231)
        t = time.time()
        if row['expires'] < t or t - float(row['last'] or 0) > idle_s:
            self.db.run('DELETE FROM sessions WHERE id = ?', (row['id'],))
            return None
        if touch and t - float(row['last'] or 0) > 20:
            self.db.run('UPDATE sessions SET last = ? WHERE id = ?', (t, row['id']))
        try:
            row['data'] = json.loads(row.get('data') or '{}')
        except ValueError:
            row['data'] = {}
        return row

    def session_take(self, ident, field):
        """`field` taken out of a session's data, by one request only
        (1.0.101): written back only if nobody changed the data meanwhile.
        True if this request took it."""
        for _round in range(8):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return False
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                return False
            if field not in data:
                return False
            data.pop(field, None)
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return True
        return False

    def session_merge(self, ident, changes, expect=None):
        """Only the keys given changed in a session's data, over what the
        database holds now (1.0.101): the whole of a copy read at the start of
        a request, written back at its end, put back what another request
        had taken meanwhile - a code already used became usable again.
        None as a value takes the key out. The data as it is now."""
        data = {}
        for _round in range(8):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return None
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                data = {}
            # `expect`: written only while these keys still hold what the
            # caller read - else nothing, and False.
            for k, v in (expect or {}).items():
                if data.get(k) != v:
                    return False
            for k, v in changes.items():
                if v is None:
                    data.pop(k, None)
                else:
                    data[k] = v
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return data
        return data

    def session_count_try(self, ident, field, code, most, keep=()):
        """A wrong try counted on the one-time code kept under `field` - the
        one whose hash is `code` - as the database holds it now (1.0.101);
        taken away at the last try (but the fields named in `keep`). Whether
        it is gone now."""
        for _round in range(16):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return True
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                return True
            cur = data.get(field)
            if not isinstance(cur, dict) or cur.get('hash', cur.get('code')) != code:
                return True             # taken, or another code asked for since
            cur['tries'] = int(cur.get('tries') or 0) + 1
            gone = cur['tries'] >= most
            if gone and keep:
                data[field] = {k: cur[k] for k in keep if k in cur}
            elif gone:
                data.pop(field, None)
            else:
                data[field] = cur
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return gone
        return False

    def session_set_data(self, ident, data):
        self.db.run('UPDATE sessions SET data = ? WHERE id = ?', (json.dumps(data), ident))

    def session_end(self, token):
        self.db.run('DELETE FROM sessions WHERE token_hash = ?',
                    (hashlib.sha256(str(token or '').encode()).hexdigest(),))

    def sessions(self, kind=None):
        sql, args = 'SELECT id, kind, name, role, created, last, expires, ip FROM sessions', []
        if kind:
            sql += ' WHERE kind = ?'
            args.append(kind)
        return self.db.rows(sql + ' ORDER BY last DESC', args)

    def session_drop(self, ident):
        self.db.run('DELETE FROM sessions WHERE id = ?', (int(ident),))

    def sessions_tidy(self, idle_admin_s=None, idle_portal_s=None):
        """Sign-ins that have run out go; so do the ones that sat untouched
        longer than they may (1.0.15: they stayed on the list of who is
        signed in, though a request from them would have been refused)."""
        t = time.time()
        self.db.run('DELETE FROM sessions WHERE expires < ?', (t,))
        for kind, idle in (('admin', idle_admin_s), ('portal', idle_portal_s)):
            if idle:
                self.db.run('DELETE FROM sessions WHERE kind = ? AND last < ?', (kind, t - float(idle)))

    def directories(self, with_secret=False, last=True):
        rows = self._dirs
        if rows is None:
            gen = self.cache_gen
            rows = self.db.rows('SELECT * FROM directories ORDER BY name')
            for r in rows:
                r['_pw'] = unseal_secret(r.get('bind_pw') or '')
            self._cache_put('_dirs', rows, gen)
        out = []
        for r in rows:
            one = {k: v for k, v in r.items() if not k.startswith('_') and k != 'bind_pw'}
            one['bind_pw_set'] = bool(r['_pw'])
            one['bind_pw_lost'] = r['_pw'] is None
            one['bind_pw'] = r['_pw'] if with_secret else secret_shown(r['_pw'], last)
            one['ca_says'] = describe_certificate(r.get('ca') or '') if r.get('ca') else None
            one['ca_list'] = describe_certificates(r.get('ca') or '') if r.get('ca') else []
            out.append(one)
        return out

    def directory(self, name, with_secret=False):
        for one in self.directories(with_secret):
            if one['name'].lower() == str(name or '').strip().lower():
                return one
        return None

    def directory_set_ca(self, ident, pem, mode='set', fingerprint=''):
        """The certificate authorities of one directory, and nothing else of
        it: several chains may be kept - one per domain the directory's
        controllers come from - each added and taken out by itself."""
        pem = str(pem or '').strip()
        row = self.db.row('SELECT ca FROM directories WHERE id = ?', (int(ident),))
        have = split_certificates((row or {}).get('ca') or '')
        if mode == 'add' or (mode == 'set' and pem):
            new = split_certificates(pem)
            if not new or not all(describe_certificate(b) for b in new):
                raise ValueError('that is not a certificate this can read: a PEM certificate '
                                 'starts -----BEGIN CERTIFICATE-----')
            if mode == 'add':
                seen = {c['fingerprint'] for c in describe_certificates('\n'.join(have))}
                have += [b for b, c in zip(new, describe_certificates('\n'.join(new)))
                         if c['fingerprint'] not in seen]
            else:
                have = new
        elif mode == 'drop':
            keep = [b for b, c in zip(have, describe_certificates('\n'.join(have)))
                    if c['fingerprint'] != fingerprint]
            if len(keep) == len(have):
                raise ValueError('that certificate is not among the ones kept')
            have = keep
        elif mode in ('set', 'clear'):
            have = []
        else:
            raise ValueError('add, set, drop or clear?')
        pem = '\n'.join(have)
        with self.lock:
            self.db.run('UPDATE directories SET ca = ? WHERE id = ?', (pem, int(ident)))
            self._dirs = None

    def directory_save(self, data, by=''):
        for k in ('name', 'hosts', 'base', 'bind_dn', 'bind_pw', 'note', 'ca', 'user_attr', 'tls',
                  'mail_attr', 'mobile_attr'):
            if data.get(k) is not None and not isinstance(data.get(k), str):
                raise ValueError('%s is a piece of text' % k)
        name = str(data.get('name') or '').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}\Z', name):
            raise ValueError('a directory needs a name: letters, digits, dots, dashes and spaces')
        hosts = [h.strip() for h in re.split(r'[,;\s]+', str(data.get('hosts') or ''))
                 if h.strip()]
        clean = []
        for h in hosts:
            h = re.sub(r'^ldaps?://', '', h, flags=re.I).rstrip('/')
            if not re.match(r'^[A-Za-z0-9.\-:\[\]]+\Z', h):
                raise ValueError('%r is not a server name or address' % h)
            clean.append(h)
        if not clean:
            raise ValueError('a directory needs at least one server')
        tls = str(data.get('tls') or 'ldaps')
        if tls not in ('none', 'ldaps', 'starttls'):
            raise ValueError('tls is none, ldaps or starttls')
        try:
            port = int(data.get('port') or (636 if tls == 'ldaps' else 389))
        except (TypeError, ValueError):
            raise ValueError('the port is a number')
        if not 1 <= port <= 65535:
            raise ValueError('the port is 1 to 65535')
        base = str(data.get('base') or '').strip()
        if not re.match(r'(?i)^(dc|ou|o|cn)=', base):
            raise ValueError('the base is a distinguished name: DC=example,DC=local')
        ca = str(data.get('ca') or '').strip()
        if ca and '-----BEGIN CERTIFICATE-----' not in ca:
            raise ValueError('the certificate authority is a PEM certificate, starting '
                             '-----BEGIN CERTIFICATE-----')
        ident = data.get('id')
        old = self.db.row('SELECT * FROM directories WHERE id = ?',
                          (int(ident),)) if ident else None
        if ident and not old:
            raise ValueError('that directory was taken away meanwhile - open it again')
        clash = self.db.row('SELECT id FROM directories WHERE LOWER(name) = ?', (name.lower(),))
        if clash and (not old or clash['id'] != old['id']):
            raise ValueError('there is a directory called %s already' % name)
        row = {'name': name, 'hosts': ', '.join(clean), 'port': port, 'tls': tls,
               'verify': _yes(data, 'verify', 1), 'base': base,
               'weak': _yes(data, 'weak', 0),
               'bind_dn': str(data.get('bind_dn') or '').strip(),
               'user_attr': str(data.get('user_attr') or 'sAMAccountName').strip(),
               'nested': _yes(data, 'nested', 1),
               'timeout_s': max(2, min(60, int(data.get('timeout_s') or 10))),
               'enabled': _yes(data, 'enabled', 1),
               'note': str(data.get('note') or '')[:400]}
        # Where the e-mail address and the mobile number are read (as otp 1.0.229): kept as given
        # when sent, as before when not - empty is the default (mail; mobile, telephoneNumber).
        for k, what, default in (('mail_attr', 'the e-mail address', DIR_MAIL_DEFAULT),
                                 ('mobile_attr', 'the mobile number', DIR_MOBILE_DEFAULT)):
            if k in data and data.get(k) is not None:
                v = dir_attr_checked(data.get(k), what)
                row[k] = '' if dir_attr_list(v, default) == tuple(default) else v
            elif not old:
                row[k] = ''
        if 'ca' in data:
            row['ca'] = ca
        hisec_directory(row)                # 1.0.168
        pw = data.get('bind_pw')
        if pw is not None and not is_masked(pw):
            row['bind_pw'] = seal_secret(pw) if str(pw) else ''
        elif old and old.get('bind_pw') and (
                str(old.get('hosts') or '') != row['hosts'] or int(old.get('port') or 0) != port or
                str(old.get('tls') or '') != tls or int(old.get('verify') or 0) != row['verify'] or
                str(old.get('bind_dn') or '') != row['bind_dn']):
            # The password kept goes to the server it was given for only (1.0.207):
            # another host typed in, it was sent there - in clear with TLS off -
            # while the page never showed it.
            raise ValueError('the server changed: type the password of the binding account again')
        with self.lock:
            if old:
                if old['name'] != name:
                    # The one administrators (and the enrolment pages) sign in
                    # against goes with the name (1.0.146): left on the old
                    # name, every directory administrator was signed out and
                    # could not sign in again.
                    for key in ('admin_directory', 'portal_directory'):
                        if str(CONFIG.get(key) or '').lower() == old['name'].lower():
                            self.save_setting(key, name, by)
                            CONFIG[key] = name
                    # Its own cap of wrong passwords too (as otp 1.0.234): left on the old
                    # name, the directory fell back to the setting - or to no cap at all.
                    self._dirpw_move(old['name'], name)
                self.db.update('directories', old['id'], row)
                ident = old['id']
            else:
                row['created'] = time.time()
                ident = self.db.insert('directories', row)
            self._dirs = None
        if old and old['name'] != name:
            dbguard_directory_sign(self.db, old['name'])
        dbguard_directory_sign(self.db, name)          # 1.0.231
        return ident

    def directory_drop(self, ident):
        one = self.db.row('SELECT name FROM directories WHERE id = ?', (int(ident),))
        if one:
            if str(CONFIG.get('admin_directory') or '').lower() == one['name'].lower():
                raise ValueError('administrators sign in against it (Settings → Accounts); '
                                 'choose another directory for them first')
            if str(CONFIG.get('portal_directory') or '').lower() == one['name'].lower():
                raise ValueError('the enrolment pages sign people in against it (Settings → '
                                 'The enrolment pages); choose another directory for them first')
        self.db.run('DELETE FROM directories WHERE id = ?', (int(ident),))
        self._dirs = None
        if one:
            self._dirpw_move(one['name'], None)         # its own cap gone with it (otp 1.0.234)

    def _dirpw_move(self, old, new):
        """A directory's own cap of wrong passwords (meta 'dirpw:conf') under its new name,
        or taken away with it."""
        try:
            caps = json.loads(self.get_meta('dirpw:conf') or '{}')
        except (TypeError, ValueError):
            return
        if not isinstance(caps, dict) or str(old).lower() not in caps:
            return
        mine = caps.pop(str(old).lower())
        if new:
            caps[str(new).lower()] = mine
        self.set_meta('dirpw:conf', json.dumps(caps))

    def log_forget(self, table, ids=None, where_sql='', args=()):
        """Lines of a log taken away - by id, or every line a filter matches."""
        if table != 'events' and table not in LOG_TABLES:
            raise ValueError('not a log')
        if ids is not None:
            ids = [int(i) for i in ids][:5000]
            if not ids:
                return 0
            return self.db.run('DELETE FROM %s WHERE id IN (%s)'
                               % (table, ', '.join('?' for _ in ids)), ids)
        return self.db.run('DELETE FROM %s%s' % (table, where_sql), list(args))

    _OVERVIEW = {}

    def overview(self, hours=24, since=None, until=None):
        """overview_now, kept 20 s per window (1.0.57): every open tab asked
        for it again whenever a request came in."""
        key = (int(hours), int(float(since) // 60) if since else None,
               int(float(until) // 60) if until else None)
        got = Storage._OVERVIEW.get(key)
        if got and time.time() - got[0] < 20:
            return got[1]
        out = self.overview_now(hours, since, until)
        if len(Storage._OVERVIEW) > 50:
            Storage._OVERVIEW.clear()
        Storage._OVERVIEW[key] = (time.time(), out)
        return out

    def overview_now(self, hours=24, since=None, until=None):
        """What the front page counts of the engine's own: per bar, the events
        that went well and the ones worth a look (warn, bad), and the kinds,
        people and words behind the latter. `since`/`until` (1.0.53): a window
        of its own, from the time picker. A module's own numbers come from
        its own routes."""
        now = time.time()
        until = float(until) if until else now
        since = float(since) if since else until - float(hours) * 3600
        hours = max(1.0, (until - since) / 3600)
        step = 3600 if hours <= 72 else (6 * 3600 if hours <= 24 * 31 else 86400)
        # Bars on the local clock (1.0.57): a day ran from 01:00 or 02:00
        # in Prague, aligned to UTC.
        off = time.localtime(since).tm_gmtoff or 0
        start = int((since + off) // step) * step - off
        # Counted by the database, hour by hour (1.0.33).
        slot = ('CAST((ts - ?) / ? AS INTEGER)' if self.db.engine == 'sqlite'
                else 'FLOOR((ts - ?) / ?)')
        rows = self.db.rows("SELECT %s AS b, CASE WHEN level IN ('warn', 'bad') THEN 'warn' "
                            "ELSE 'info' END AS lv, COUNT(*) AS n FROM events WHERE ts >= ? "
                            "AND ts < ? GROUP BY 1, 2" % slot, (start, 3600, since, until))

        def bar_of(ts):
            if step == 3600:
                return int(ts)
            lt = time.localtime(ts)
            hour = 0 if step == 86400 else (lt.tm_hour // 6) * 6
            return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1)))
        buckets = collections.OrderedDict()
        t = start
        while t < min(until, now):
            b = bar_of(t)
            if b not in buckets:
                buckets[b] = {'t': b, 'info': 0, 'warn': 0}
            t += 3600
        good = bad = 0
        for r in rows:
            b = bar_of(start + int(r['b'] or 0) * 3600)
            if b not in buckets:
                buckets[b] = {'t': b, 'info': 0, 'warn': 0}
            n = int(r['n'] or 0)
            if r['lv'] == 'warn':
                buckets[b]['warn'] += n
                bad += n
            else:
                buckets[b]['info'] += n
                good += n

        def top(col, where, n=10):
            return self.db.rows(
                "SELECT %s AS said, COUNT(*) AS n, MAX(ts) AS last FROM events WHERE ts >= ? "
                "AND ts < ? AND %s GROUP BY %s ORDER BY n DESC LIMIT %d"
                % (col, where, col, n), (since, until))
        return {
            'hours': hours, 'step': step, 'since': since, 'until': until,
            'series': list(buckets.values()), 'events': good + bad, 'warnings': bad,
            'top_kinds': top('kind', '1 = 1'),
            'top_warn_kinds': top('kind', "level IN ('warn', 'bad')"),
            'top_warn_who': top('who', "level IN ('warn', 'bad') AND COALESCE(who, '') <> ''"),
            'sign_ins_refused': int(self.db.value(
                "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ? AND kind = "
                "'sign-ins' AND level IN ('warn', 'bad')", (since, until), 0) or 0),
        }

    def tidy(self):
        """What has been kept long enough, deleted."""
        said = {}
        days = int(CONFIG.get('retain_events_days') or 0)
        if days > 0:
            said['events'] = self.delete_older('events', time.time() - days * 86400)
        self.sessions_tidy(int(CONFIG.get('session_idle_min') or 120) * 60,
                           int(CONFIG.get('portal_session_min') or 15) * 60)
        return said

    def delete_older(self, table, cut):
        """Rows older than `cut`, deleted in batches (1.0.33), with a breath
        between them (1.0.57) so whatever waits on the database gets its
        turn."""
        # 1000 at a time and a fifth of a second between (1.0.149): 5000 with
        # 0.02 s left the rest a quarter of its pace for the whole of it.
        gone, batch = 0, 1000
        for _ in range(1000000):
            if self.db.engine == 'mariadb':
                n = self.db.run('DELETE FROM %s WHERE ts < ? LIMIT %d' % (table, batch), (cut,))
            else:
                n = self.db.run('DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE '
                                'ts < ? LIMIT %d)' % (table, table, batch), (cut,))
            gone += int(n or 0)
            if not n or n < batch:
                break
            time.sleep(0.2)
        if gone and self.db.engine == 'sqlite':
            try:
                # PASSIVE (1.0.186): TRUNCATE waited for every reader - the night's
                # backup reading the whole file - with the writer's lock held, and
                # every other write waited behind it until it gave up.
                self.db.run(RawSql('PRAGMA wal_checkpoint(PASSIVE)'))
            except Exception:                           # noqa: BLE001
                pass
        return gone

    def counts(self):
        return {t: int(self.db.value('SELECT COUNT(*) AS n FROM %s' % t, (), 0) or 0)
                for t in TABLES if t not in ('meta',)}


