# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# `field:value` in every search box (1.0.19, as isemon's ListQuery)
# ---------------------------------------------------------------------------
# What is typed into a list's search box is read as isemon reads it: words
# as before, and besides them `field:value` - `result:reject client:ASA`,
# `name:novak*`, `-state:active`, `realm:dpmo.cz,corpnet.cz`, `ms:>500`,
# `(client:ASA OR client:localhost) reason~ldap`. A name the list does not
# have is not a field at all - `10.1.2.3:1812` is a word - and a box with no
# field in it searches exactly as it did.
#
# kind: text (folded; `*` a wildcard), num (a number, a range, > <), ip (an
# address or the start of one; `/24` a range), ok (accept/reject as 1/0),
# realm (what follows the @ in the name), none (not in this list: no row).
LIST_FIELDS = {
    'tokens': {
        'name': ('name', 'text'), 'user': ('name', 'text'), 'token': ('name', 'text'),
        'owner': ('display', 'text'), 'who': ('display', 'text'),
        'state': ('state', 'text'), 'realm': ('name', 'realm'),
        'by': ('created_by', 'text'), 'made_by': ('created_by', 'text'),
        'note': ('note', 'text'), 'from': ('last_from', 'ip'), 'ip': ('last_from', 'ip'),
        'how': ('last_how', 'text'), 'recovery': ('scratch_left', 'num'),
        'client': ('last_client', 'text'),
        'wrong': ('failures', 'num'), 'digits': ('digits', 'num'),
        # How the codes come, where to, in which language and form (1.0.85).
        'kind': ('kind', 'tkind'), 'type': ('kind', 'tkind'), 'by_way': ('kind', 'tkind'),
        'to': ('dest', 'tdest'), 'dest': ('dest', 'tdest'),
        'lang': ('lang', 'tlang'), 'language': ('lang', 'tlang'),
        'mail': ('mail_fmt', 'tfmt'), 'format': ('mail_fmt', 'tfmt'),
    },
    'radius': {
        'name': ('username', 'text'), 'user': ('username', 'text'),
        'result': ('result', 'text'), 'client': ('client', 'text'),
        'where': ('client', 'text'), 'from': ('calling', 'ip'), 'ip': ('calling', 'ip'),
        'address': ('calling', 'ip'), 'nas': ('nas_ip', 'ip'),
        'reason': ('reason', 'text'), 'why': ('reason', 'text'), 'realm': ('realm', 'text'),
        'device': ('device', 'text'), 'machine': ('device', 'text'),
        'tunnel': ('tunnel', 'text'), 'group': ('tunnel', 'text'),
        'packet': ('packet', 'text'), 'ms': ('took_ms', 'num'), 'code': ('acme', 'text'),
        'how': ('', 'none'), 'node': ('node', 'text'), 'server': ('node', 'text'),
    },
    'acme': {
        'name': ('name', 'text'), 'user': ('name', 'text'), 'result': ('ok', 'ok'),
        'why': ('said', 'text'), 'reason': ('said', 'text'), 'code': ('said', 'text'),
        'from': ('src', 'ip'), 'ip': ('src', 'ip'), 'address': ('src', 'ip'),
        'how': ('how', 'text'), 'where': ('how', 'text'),
        'client': ('', 'none'), 'realm': ('name', 'realm'), 'device': ('', 'none'),
        'tunnel': ('', 'none'), 'nas': ('', 'none'), 'packet': ('', 'none'),
        'ms': ('', 'none'), 'machine': ('', 'none'), 'group': ('', 'none'),
        'node': ('node', 'text'), 'server': ('node', 'text'),
    },
    'events': {
        'kind': ('kind', 'text'), 'who': ('who', 'text'), 'by': ('who', 'text'),
        'what': ('words', 'text'), 'level': ('level', 'text'), 'node': ('node', 'text'),
        'server': ('node', 'text'),
    },
    # The outgoing mail (1.0.95): its rows searched in a table of their own
    # made for the search (memory_search below), with the same words.
    'mailq': {
        'to': ('to_addr', 'text'), 'state': ('state', 'text'), 'kind': ('kind', 'text'),
        'name': ('name', 'text'), 'user': ('name', 'text'), 'realm': ('name', 'realm'),
        'by': ('by_who', 'text'), 'said': ('said', 'text'), 'why': ('said', 'text'),
        'subject': ('subject', 'text'), 'tries': ('tries', 'num'), 'node': ('node', 'text'),
        'server': ('node', 'text'),
    },
    'enrolment': {
        'who': ('who', 'text'), 'name': ('who', 'text'), 'what': ('words', 'text'),
        'step': ('words', 'step'), 'from': ('words', 'fromip'), 'ip': ('words', 'fromip'),
        'node': ('node', 'text'), 'server': ('node', 'text'),
    },
}
# What each field means, with an example - what the box offers as one types.
LIST_FIELD_SAYS = {
    'tokens': [('name', 'the name of the token', 'name:novak*'),
               ('owner', 'the owner\'s name from the directory', 'owner:"Jan Novak"'),
               ('state', 'active, pending or disabled', 'state:pending'),
               ('realm', 'what follows the @', 'realm:example.cz'),
               ('by', 'who or what made it', 'by:import*'),
               ('note', 'the note', 'note~totpcgi'),
               ('from', 'the address it was last used from', 'from:10.1.*'),
               ('recovery', 'recovery codes left', 'recovery:<2'),
               ('wrong', 'wrong codes in a row', 'wrong:>0'),
               ('kind', 'how the codes come: app, mail or sms', 'kind:mail'),
               ('to', 'where the codes are sent: a mail address, or a phone number however written', 'to:603364754'),
               ('lang', 'the language of the codes: cs or en', 'lang:en'),
               ('mail', 'a mail token\'s mail: html or text', 'mail:text')],
    'radius': [('name', 'the name the VPN sent', 'name:novak*'),
               ('result', 'accept, reject, drop or acct', 'result:reject'),
               ('client', 'the client that asked', 'client:ASA'),
               ('reason', 'why - what the token said', 'reason~ldap'),
               ('from', 'the person\'s own address', 'from:203.0.113.*'),
               ('realm', 'the realm it fell in', 'realm:example.cz'),
               ('device', 'the computer name the VPN passed', 'device:DESKTOP*'),
               ('tunnel', 'the tunnel group', 'tunnel:VPN*'),
               ('nas', 'the address of the client', 'nas:192.0.2.1'),
               ('ms', 'how long the answer took', 'ms:>500'),
               ('how', 'where a code was checked besides RADIUS', 'how:portal'),
               ('node', 'the node that answered (high availability)', 'node:acme2')],
    'events': [('kind', 'the kind of event', 'kind:tokens'),
               ('who', 'who did it', 'who:admin'),
               ('what', 'what it says', 'what~realm'),
               ('level', 'info or warn', 'level:warn'),
               ('node', 'the node it happened on (high availability)', 'node:acme2')],
    'mailq': [('to', 'whom it goes to', 'to:*@example.cz'),
              ('state', 'waiting, sending, sent, failed or expired', 'state:waiting'),
              ('kind', 'token, code, verify or test', 'kind:code'),
              ('name', 'the token it is about', 'name:novak*'),
              ('said', 'what the receiving server said', 'said~greylist'),
              ('tries', 'how many times it was tried', 'tries:>2'),
              ('by', 'who had it sent', 'by:admin'),
              ('subject', 'its subject', 'subject~token'),
              ('node', 'the node that sends it (high availability)', 'node:acme2')],
    'enrolment': [('who', 'the person', 'who:novak*'),
                  ('step', 'signed_in, enrolled, confirmed, replacing, stopped, refused, not_allowed',
                   'step:refused'),
                  ('from', 'the address they came from', 'from:10.*'),
                  ('what', 'what happened', 'what~groups'),
                  ('node', 'the node it happened on (high availability)', 'node:acme2')],
}
LIST_WORD_COLUMNS = {
    'tokens': ('name', 'note', 'display', 'dest'),
    'radius': ('username', 'calling', 'reason', 'client', 'device', 'acme'),
    'acme': ('name', 'said', 'src'),
    'events': ('words', 'who', 'kind'),
    'enrolment': ('words', 'who'),
    'mailq': ('to_addr', 'name', 'subject', 'said', 'by_who'),
}
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


# A phone number found however it is written (1.0.93): +420 603 364 754,
# 603364754, 00420-603-364-754 - the digits of the token's number compared
# with the digits typed, its country code or not.
DEST_DIGITS_SQL = "REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(dest, ''), " \
    "' ', ''), '-', ''), '+', ''), '/', ''), '.', ''), '(', ''), ')', '')"


def phone_digits(text):
    """The digits of something typed that looks like a phone number - and
    `*` kept as a wildcard - or '' for anything else."""
    t = str(text or '').strip()
    if not re.fullmatch(r'[\d\s+()./*-]+', t):
        return ''
    d = re.sub(r'[^\d*]', '', t)
    if d.startswith('00'):
        d = d[2:]
    return d if len(d.replace('*', '')) >= 3 else ''


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
        digits = phone_digits(word) if 'dest' in cols else ''
        if digits:
            sql.append("%s LIKE ? ESCAPE '!'" % DEST_DIGITS_SQL)
            args.append('%' + like_pattern(digits) + '%')
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
            return ('ok = ?', [v])
        if kind == 'tkind':
            v = {'app': 'totp', 'totp': 'totp', 'phone': 'totp', 'mail': 'mail',
                 'email': 'mail', 'e-mail': 'mail', 'sms': 'sms', 'text': 'sms'}.get(low)
            if v is None:
                raise ListQueryError('kind is app, mail or sms - not %r' % item)
            return ("(CASE WHEN %s IN ('mail', 'sms') THEN %s ELSE 'totp' END) = ?" % (col, col),
                    [v])
        if kind == 'tlang':
            # The language in effect: the token's own, else the setting's.
            if low not in ('cs', 'en'):
                raise ListQueryError('lang is cs or en - not %r' % item)
            return ("(CASE WHEN %s IN ('cs', 'en') THEN %s ELSE ? END) = ?" % (col, col),
                    [code_lang(), low])
        if kind == 'tfmt':
            v = {'html': 'html', 'text': 'text', 'plain': 'text', 'txt': 'text'}.get(low)
            if v is None:
                raise ListQueryError('mail is html or text - not %r' % item)
            return ("(kind = 'mail' AND (CASE WHEN %s IN ('html', 'text') THEN %s ELSE ? END) = ?)"
                    % (col, col), ['text' if CONFIG.get('code_mail_fmt') == 'text' else 'html', v])
        if kind == 'tdest':
            digits = phone_digits(low)
            if digits:
                # A number: its digits, the country code in front or not.
                pat = like_pattern(digits)
                return ("%s LIKE ? ESCAPE '!'" % DEST_DIGITS_SQL,
                        ['%' + pat + ('%' if op == '~' or '*' in digits else '')])
            kind = 'text'
        if kind == 'realm':
            pat = '%@' + like_pattern(low.lstrip('@'))
            return ("LOWER(%s) LIKE ? ESCAPE '!'" % col, [pat if op != '~' else pat + '%'])
        if kind == 'step':
            marks = dict(Storage.ENROL_STEPS)
            if low not in marks:
                return ('1=0', [])
            return ("%s LIKE ? ESCAPE '!'" % col, ['%' + like_pattern(marks[low]) + '%'])
        if kind == 'fromip':
            return ("LOWER(%s) LIKE ? ESCAPE '!'" % col,
                    ['% from ' + like_pattern(low.rstrip('*')) + '%'])
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
        if op == '~':
            return ("%s LIKE ? ESCAPE '!'" % c, ['%' + like_pattern(low) + '%'])
        if kind == 'ip' and '*' not in low:
            # An address as it was written down may carry its port.
            return ("(%s = ? OR %s LIKE ? ESCAPE '!')" % (c, c), [low, like_pattern(low) + ':%'])
        if '*' in low:
            return ("%s LIKE ? ESCAPE '!'" % c, [like_pattern(low)])
        return ('%s = ?' % c, [low])

def old_methods_of(store, ident):
    """The kinds of token a realm offers as it is saved (a save that did
    not say keeps them, 1.0.76)."""
    if not ident:
        return None
    try:
        return store.db.value('SELECT methods FROM realms WHERE id = ?', (int(ident),))
    except Exception:                                   # noqa: BLE001
        return None


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
    # over it. It was, and a client just added stayed unknown on that node until
    # the next change or a restart.
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

    _clients = property(lambda self: self._cache_get('_clients'),
                        lambda self, v: self._cache_set('_clients', v))
    _realms = property(lambda self: self._cache_get('_realms'),
                       lambda self, v: self._cache_set('_realms', v))
    _dirs = property(lambda self: self._cache_get('_dirs'),
                     lambda self, v: self._cache_set('_dirs', v))

    @classmethod
    def view(cls, db):
        """The same database through another connection, nothing made
        (1.0.101)."""
        st = cls.__new__(cls)
        st.db = db
        st.lock = threading.RLock()
        st._clients = None
        st._realms = None
        st._dirs = None
        return st

    def __init__(self, db, quick=False):
        self.db = db
        SEAL_GUARD['db'] = db           # asked before a new key is made (1.0.205)
        # The command line (and so the console, every 20 s) made the tables,
        # indexes and triggers again on each run (1.0.136): on PostgreSQL
        # that takes locks that hold every RADIUS write behind them. Now it
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
            self._clients = None
            self._realms = None
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
        self._clients = None
        self._realms = None
        self._dirs = None

    # ---- meta, settings, events ------------------------------------------
    def get_meta(self, k, default=None):
        got = self.db.value('SELECT v FROM meta WHERE k = ?', (k,))
        return default if got is None else got

    def set_meta(self, k, v):
        # One statement, no lock of Python's (1.0.139): a RADIUS thread noting a
        # client seen waited here behind a page holding the lock for a slow
        # query on the main connection - the VPN timed out.
        self.db.upsert('meta', 'k', {'k': k, 'v': str(v)})

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
        self.db.upsert('settings', 'k', {'k': k, 'v': json.dumps(v), 'at': time.time(),
                                         'by_who': str(by or '')[:190]})

    def drop_setting(self, k):
        self.db.run('DELETE FROM settings WHERE k = ?', (k,))

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

    # ---- the enrolment pages: who came, what they did (1.0.16) ------------
    # The events of kind 'enrolment' tell the whole story of a person making
    # their own token; here they are read back as steps, so the pages can
    # draw them as a card of their own and count them.
    ENROL_STEPS = (('signed_in', ' signed in to the enrolment pages'),
                   ('enrolled', ' enrolled a token for themselves'),
                   ('confirmed', ' confirmed their token'),
                   ('replacing', ' is replacing their token'),
                   ('refused', ' could not sign in to the enrolment pages'),
                   ('not_allowed', ' may not enrol a token'),
                   ('stopped', ' stopped replacing their token'))

    @classmethod
    def enrol_step(cls, words):
        for step, mark in cls.ENROL_STEPS:
            if mark in words:
                return step
        return 'other'

    def enrolment(self, limit=100, offset=0, q='', step='', since_s=0, extra=None):
        where, args = ["kind = 'enrolment'"], []
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if since_s:
            where.append('ts > ?')
            args.append(time.time() - float(since_s))
        if q:
            where.append("(LOWER(words) LIKE ? ESCAPE '!' OR LOWER(who) LIKE ? ESCAPE '!')")
            like = '%' + like_pattern(str(q).lower()) + '%'
            args += [like, like]
        marks = dict(self.ENROL_STEPS)
        if step in marks:
            where.append('words LIKE ?')
            args.append('%' + marks[step] + '%')
        sql = ' WHERE ' + ' AND '.join(where)
        total = self.db.value('SELECT COUNT(*) AS n FROM events' + sql, args, 0)
        rows = self.db.rows('SELECT * FROM events' + sql + ' ORDER BY ts DESC, id DESC '
                            'LIMIT %d OFFSET %d' % (int(limit), int(offset)), args)
        out = []
        for r in rows:
            words = str(r.get('words') or '')
            m = re.search(r' from (\S+?)(?::|$)', words)
            out.append({'id': r['id'], 'ts': r['ts'], 'who': r.get('who') or '',
                        'step': self.enrol_step(words), 'src': m.group(1) if m else '',
                        'words': words, 'level': r.get('level') or 'info',
                        'node': r.get('node') or ''})
        return out, int(total or 0)

    def enrolment_counts(self, since_s=0, since=0, until=0):
        """How many of each step in the window - the tiles over the list, in
        one pass over the window (1.0.57), not one per step."""
        parts, args = [], []
        for _step, mark in self.ENROL_STEPS:
            parts.append('SUM(CASE WHEN words LIKE ? THEN 1 ELSE 0 END) AS c%d' % len(parts))
            args.append('%' + mark + '%')
        sql = "SELECT %s FROM events WHERE kind = 'enrolment'" % ', '.join(parts)
        if since_s:
            sql += ' AND ts > ?'
            args.append(time.time() - float(since_s))
        if since:
            sql += ' AND ts >= ?'
            args.append(float(since))
        if until:
            sql += ' AND ts < ?'
            args.append(float(until))
        row = (self.db.rows(sql, args) or [{}])[0]
        return {step: int(row.get('c%d' % i) or 0) for i, (step, _m) in enumerate(self.ENROL_STEPS)}

    def list_values(self, listname, field, typed='', since=0, most=15):
        """What one field of one list holds, busiest first, for the search
        box over it to offer as somebody types (1.0.19, as isemon)."""
        spec = LIST_FIELDS.get(listname, {}).get(field)
        if not spec:
            return []
        column, kind = spec
        typed = str(typed or '').strip().lower()
        if kind == 'step':
            return [{'val': k, 'n': 0} for k, _ in self.ENROL_STEPS if typed in k]
        if kind in ('tkind', 'tlang', 'tfmt'):
            # Fixed choices (1.0.85), not whatever the column happens to hold.
            opts = {'tkind': ('app', 'mail', 'sms'), 'tlang': ('cs', 'en'),
                    'tfmt': ('html', 'text')}[kind]
            return [{'val': v, 'n': 0} for v in opts if v.startswith(typed)]
        if kind == 'ok':
            return [{'val': v, 'n': 0} for v in ('accept', 'reject') if v.startswith(typed)]
        if kind == 'none' or not column:
            return []
        if kind == 'text' and column == 'words':
            return []           # never offered - not grouped over every event first (1.0.57)
        table = {'tokens': 'tokens', 'radius': 'radius_log', 'acme': 'acme_log',
                 'events': 'events', 'enrolment': 'events'}[listname]
        where, args = [], []
        # A window always (1.0.57): with none, every keystroke grouped the
        # whole log - seconds on a big one, with RADIUS waiting behind it.
        if not since and table != 'tokens':
            since = time.time() - 30 * 86400
        if since and table != 'tokens':
            where.append('ts >= ?')
            args.append(since)
        if listname == 'enrolment':
            where.append("kind = 'enrolment'")
        # A number is compared as a number (1.0.33): PostgreSQL refuses
        # COALESCE(a number, '') - the suggestions for "recovery codes" broke.
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
            if kind == 'realm':
                v = v.rsplit('@', 1)[1] if '@' in v else ''
            elif kind == 'ip':
                v = re.sub(r':\d+$', '', v) if v.count(':') == 1 else v
            elif kind == 'fromip':
                m = re.search(r' from (\S+?)(?::|$)', v)
                v = m.group(1) if m else ''
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

    def account(self, name):
        return self.db.row('SELECT * FROM accounts WHERE LOWER(name) = ?',
                           (str(name or '').strip().lower(),))

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
        return self.db.insert('accounts', {
            'name': name, 'role': role, 'pw': password_hash(password) if password else '',
            'source': source, 'disabled': 0, 'must_change': int(bool(must_change)),
            'note': str(note or '')[:400], 'created': time.time(), 'last_in': None,
            'last_from': '', 'prefs': '{}', 'display': display, 'dn': dn,
            'group_list': groups})

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
        self.db.update('accounts', one['id'], fields)

    def drop_account(self, name):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        self.db.run('DELETE FROM accounts WHERE id = ?', (one['id'],))
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
        self.db.insert('sessions', {
            'token_hash': hashlib.sha256(token.encode()).hexdigest(), 'kind': kind,
            'name': name, 'role': role, 'created': t, 'last': t,
            'expires': t + float(hours) * 3600, 'ip': str(ip or '')[:60],
            'data': json.dumps(data or {})})
        return token

    def session_get(self, token, kind, idle_s, touch=True):
        if not token:
            return None
        row = self.db.row('SELECT * FROM sessions WHERE token_hash = ? AND kind = ?',
                          (hashlib.sha256(str(token).encode()).hexdigest(), kind))
        if not row:
            return None
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

    def session_count_try(self, ident, field, code, most):
        """A wrong try counted on the one-time code kept under `field` - the
        one whose hash is `code` - as the database holds it now (1.0.101);
        taken away at the last try. Whether it is gone now."""
        for _round in range(16):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return True
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                return True
            cur = data.get(field)
            if not isinstance(cur, dict) or cur.get('code') != code:
                return True             # taken, or another code asked for since
            cur['tries'] = int(cur.get('tries') or 0) + 1
            gone = cur['tries'] >= most
            if gone:
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

    # ---- RADIUS clients ----------------------------------------------------
    def _client_rows(self):
        """The clients as read, secrets opened - one list, never None, even
        when a save empties the cache between two lines (1.0.33)."""
        rows = self._clients
        if rows is None:
            gen = self.cache_gen
            rows = self.db.rows('SELECT * FROM clients ORDER BY position, ' + self.db.name_order())
            for r in rows:
                r['_secret'] = unseal_secret(r.get('secret') or '')
                try:
                    r['_net'] = address_net(r['address'])
                except ValueError:
                    r['_net'] = None
            self._cache_put('_clients', rows, gen)
        return rows

    def clients_seen(self):
        """When each client was last heard from, by any node (1.0.98)."""
        seen = {}
        try:
            for r in self.db.rows("SELECT k, v FROM meta WHERE k LIKE 'clientseen:%'"):
                try:
                    ident = int(r['k'].rsplit(':', 1)[1])
                    seen[ident] = max(seen.get(ident, 0), float(r['v']))
                except (ValueError, IndexError):
                    continue
        except Exception:                               # noqa: BLE001
            pass
        return seen

    def clients(self, with_secret=False, last=True):
        out = []
        seen = self.clients_seen()
        for r in self._client_rows():
            one = {k: v for k, v in r.items() if not k.startswith('_') and k != 'secret'}
            if seen.get(r.get('id')):
                one['last_seen'] = max(float(one.get('last_seen') or 0), seen[r['id']])
            one['secret_set'] = bool(r['_secret'])
            one['secret_lost'] = r['_secret'] is None
            one['secret'] = r['_secret'] if with_secret else secret_shown(r['_secret'], last)
            out.append(one)
        return out

    def client_name_of(self, tok):
        """The RADIUS client a token was last let in through (1.0.58)."""
        # Only what was kept (1.0.61): the address beside it is the person's
        # (Calling-Station-Id), not the NAS's, and looked up as a client's it
        # named a wrong one.
        return str(tok.get('last_client') or '')

    def client_for(self, ip):
        """The client a packet from this address belongs to: the narrowest
        range holding it, and of two the same width the one named first."""
        rows = self._client_rows()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        # The narrowest range holding it decides (1.0.136): of that width an
        # enabled one (the first named); when every one of that width is
        # switched off, the address is not answered - not answered under a
        # wider range's secret and realms instead.
        width, best = -1, None
        for r in rows:
            net = r['_net']
            if not net or addr.version != net.version or addr not in net:
                continue
            if net.prefixlen > width:
                width, best = net.prefixlen, (r if r.get('enabled') else None)
            elif net.prefixlen == width and best is None and r.get('enabled'):
                best = r
        return best

    def client_save(self, data, by=''):
        """A client made or changed. Returns its id."""
        name = str(data.get('name') or '').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}\Z', name):
            raise ValueError('a client needs a name: letters, digits, dots, dashes and spaces')
        try:
            net = address_net(data.get('address'))
        except ValueError:
            raise ValueError('%r is not an address or a range of them'
                             % str(data.get('address') or '')[:60])
        secret = data.get('secret')
        # Each field of its own kind (1.0.103): a secret sent as a list was
        # kept as the text "['a']".
        for k in ('secret', 'note', 'realm', 'nas_type', 'address', 'name'):
            if data.get(k) is not None and not isinstance(data.get(k), str):
                raise ValueError('%s is a piece of text' % k)
        ident = data.get('id')
        try:
            old = self.db.row('SELECT * FROM clients WHERE id = ?', (int(ident),)) if ident else None
        except (TypeError, ValueError):
            raise ValueError('the id of a client is a number')
        if ident and not old:
            # Taken away meanwhile (1.0.146): saved from a form opened before,
            # it came back - without its secret.
            raise ValueError('that client was taken away meanwhile - open it again')
        clash = self.db.row('SELECT id FROM clients WHERE LOWER(name) = ?', (name.lower(),))
        if clash and (not old or clash['id'] != old['id']):
            raise ValueError('there is a client called %s already' % name)
        row = {'name': name, 'address': str(net) if net.num_addresses > 1 else
               str(net.network_address),
               'realm': str(data.get('realm') or '').strip().lstrip('@').rstrip('.')[:190],
               'require_ma': _yes(data, 'require_ma', 0),
               'enabled': int(bool(int(data.get('enabled', 1) if data.get('enabled')
                                       is not None else 1))),
               'note': str(data.get('note') or '')[:400],
               'nas_type': str(data.get('nas_type') or '')[:60],
               'position': list_position(data.get('position'))}
        # The realms it may use (1.0.33): none named, any.
        if 'realms' in data or not old:
            raw = data.get('realms') or ''
            # Split on commas only (1.0.36): a realm's name may have spaces.
            want = [str(x).strip() for x in (raw if isinstance(raw, (list, tuple))
                                             else re.split(r'[,;\n]+', str(raw)))
                    if str(x).strip()]
            known = {r['name'].lower(): r['name'] for r in self.realms()}
            bad = [x for x in want if x.lower() not in known]
            if bad:
                raise ValueError('there is no realm called %s' % ', '.join(bad))
            row['realms'] = ', '.join(known[x.lower()] for x in want)
        if secret is not None and not is_masked(secret):
            secret = str(secret)
            if not secret.strip():
                raise ValueError('a client needs a shared secret')
            if len(secret) > 128:
                raise ValueError('a shared secret of more than 128 characters is more than '
                                 'RADIUS hides properly')
            hisec_client_secret(secret)     # 1.0.168
            row['secret'] = seal_secret(secret)
        elif not old:
            raise ValueError('a client needs a shared secret')
        with self.lock:
            if old:
                self.db.update('clients', old['id'], row)
                ident = old['id']
            else:
                row['created'] = time.time()
                ident = self.db.insert('clients', row)
            self._clients = None
        return ident

    def client_drop(self, ident):
        self.db.run('DELETE FROM clients WHERE id = ?', (int(ident),))
        try:
            for r in self.db.rows("SELECT k FROM meta WHERE k LIKE 'clientseen:%'"):
                if r['k'].rsplit(':', 1)[-1] == str(int(ident)):
                    self.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            # Which of its addresses signed their requests, on every node
            # (1.0.101): maseen:<node>:<client>:<address>.
            for r in self.db.rows("SELECT k FROM meta WHERE k LIKE 'maseen:%'"):
                parts = r['k'].split(':', 3)
                if len(parts) == 4 and parts[2] == str(int(ident)):
                    self.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
        except Exception:                               # noqa: BLE001
            pass
        self._clients = None

    _SEEN_AT = {}

    def client_seen(self, ident):
        """When a client was last heard from - written at most once a minute
        a client (1.0.33), not on every packet."""
        t = time.time()
        if t - self._SEEN_AT.get(ident, 0) < 60:
            return
        self._SEEN_AT[ident] = t
        # Not into the client's own row (1.0.98): logical replication sends a
        # row whole, and this write once a minute on one node could put back
        # a shared secret changed on the other at that moment. A key of this
        # node's own, which nobody else writes.
        self.set_meta('clientseen:%s:%s' % (node_name(), ident), repr(t))

    # ---- realms --------------------------------------------------------------
    def realms(self):
        rows = self._realms
        if rows is None:
            gen = self.cache_gen
            rows = self.db.rows('SELECT * FROM realms ORDER BY position, ' + self.db.name_order())
            for r in rows:
                try:
                    r['groups'] = json.loads(r.get('group_list') or '[]')
                except ValueError:
                    r['groups'] = []
                r.pop('group_list', None)
                r['methods'] = realm_methods(r)          # a list (1.0.76)
                # The other suffixes the realm takes (1.0.117): dpmo.local
                # beside dpmo.cz, one person, one token.
                r['aliases'] = [a for a in str(r.get('aliases') or '').split(',') if a]
                # A column added later is NULL in the rows from before it
                # (1.0.94): get('nested', 1) gave None - nested groups off
                # for every realm older than the switch.
                for k, dflt in (('nested', 1), ('check_disabled', 1)):
                    if r.get(k) is None:
                        r[k] = dflt
            self._cache_put('_realms', rows, gen)
        return [dict(r) for r in rows]

    def realm_for(self, user):
        """The realm a name belongs to: by what follows its @, else the realm
        for names with none, else the one that takes everything (`*`)."""
        suffix = user.rsplit('@', 1)[1].lower() if '@' in user else ''
        realms = [r for r in self.realms() if r.get('enabled')]
        for r in realms:
            if str(r.get('suffix') or '').lower() == suffix and r.get('suffix') != '*':
                return r
        if suffix:
            # Taken as one of a realm's other suffixes (1.0.117).
            for r in realms:
                if suffix in (r.get('aliases') or []):
                    return r
        for r in realms:
            if r.get('suffix') == '*':
                return r
        return None

    def realm_save(self, data, by='', absorb=None):
        if data.get('groups') is not None and not isinstance(data.get('groups'), list):
            # "abc" was read letter by letter: groups a, b and c (1.0.103).
            raise ValueError('groups is a list')
        for k in ('name', 'suffix', 'directory', 'note', 'reply', 'lookup', 'auth_mode'):
            if data.get(k) is not None and not isinstance(data.get(k), str):
                raise ValueError('%s is a piece of text' % k)
        name = str(data.get('name') or '').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}\Z', name):
            raise ValueError('a realm needs a name: letters, digits, dots, dashes and spaces')
        suffix = str(data.get('suffix') or '').strip().lstrip('@').lower()
        if suffix and suffix != '*' and not re.match(r'^[a-z0-9][a-z0-9.-]*\Z', suffix):
            raise ValueError('the realm is what comes after the @ - example.cz - or * for '
                             'every name, or nothing for names written without one')
        lookup = str(data.get('lookup') or 'upn')
        if lookup not in ('upn', 'sam', 'none'):
            raise ValueError('lookup is upn, sam or none')
        mode = str(data.get('auth_mode') or 'acme')
        if mode not in ('acme', 'password_acme', 'password', 'challenge'):
            raise ValueError('auth_mode is acme, password_acme, password or challenge')
        # The kinds of token people may choose here (1.0.76): the app, a code
        # by mail, a code by SMS. A code is only ever sent after the
        # directory password, so mail and SMS need a directory.
        raw = data.get('methods')
        if raw is None and old_methods_of(self, data.get('id')) is not None:
            raw = old_methods_of(self, data.get('id'))
        methods = realm_methods({'methods': raw})
        token_name = str(data.get('token_name') or 'whole')
        if token_name not in ('whole', 'bare'):
            raise ValueError('token_name is whole or bare')
        # The other suffixes it takes (1.0.117): a list, or words split by
        # commas and spaces, each written as a suffix is.
        raw_al = data.get('aliases') or []
        if 'aliases' not in data and data.get('id'):
            # Not sent - by an older page, an import, the command line - is
            # kept as it is, not emptied.
            was = self.db.row('SELECT aliases FROM realms WHERE id = ?', (int(data['id']),))
            raw_al = str((was or {}).get('aliases') or '')
        if isinstance(raw_al, str):
            raw_al = re.split(r'[\s,;]+', raw_al)
        if not isinstance(raw_al, list):
            raise ValueError('aliases is a list of what may come after the @')
        aliases = []
        for a in raw_al:
            a = str(a or '').strip().lstrip('@').rstrip('.').lower()
            if not a:
                continue
            if not re.match(r'^[a-z0-9][a-z0-9.-]*\Z', a) or len(a) > 120:
                raise ValueError('%s is not something that can come after the @ - example.local'
                                 % a)
            if a == suffix:
                raise ValueError('@%s is what the realm takes already' % a)
            if suffix in ('', '*'):
                raise ValueError('only a realm of one suffix (example.cz) can take others too')
            if a not in aliases:
                aliases.append(a)
        if len(aliases) > 20:
            raise ValueError('20 other suffixes at most')
        directory = str(data.get('directory') or '').strip()
        if directory and not self.directory(directory):
            raise ValueError('there is no directory called %s' % directory)
        if directory:
            # As the directory is called (1.0.146): typed in another case it
            # was kept so, and a rename of the directory left the realm behind.
            directory = self.directory(directory)['name']
        def plain_names(tn, sfx):
            # A realm whose tokens are kept under the name alone: bare, or
            # whole with no suffix to add - * or none (1.0.149): a bare a.cz
            # and a * of another directory both kept "falco", and one falco
            # signed in as the other.
            return tn == 'bare' or str(sfx or '') in ('', '*')
        if plain_names(token_name, suffix):
            # Names without their realm are one person's only within one
            # directory (1.0.101): novak@a in one and novak@b in another
            # shared the token "novak", and the second could enrol it, or
            # sign in to the first realm with it.
            for r in self.realms():
                if plain_names(r.get('token_name'), r.get('suffix')) and \
                        str(r.get('name')).lower() != \
                        str(data.get('name') or '').strip().lower() and \
                        str(r.get('directory') or '').lower() != directory.lower() and \
                        (token_name == 'bare' and r.get('token_name') == 'bare' or
                         (directory and r.get('directory'))):
                    raise ValueError('the realm %s already keeps its tokens under the name '
                                     'alone, with the directory %s: names alone are one '
                                     'person\'s only within one directory - keep this '
                                     'realm\'s under the whole name'
                                     % (r['name'], r.get('directory') or '(none)'))
        if lookup != 'none' and not directory:
            lookup = 'none'
        if mode in ('password', 'password_acme', 'challenge') and lookup == 'none':
            raise ValueError('a password can only be checked against a directory: choose one, '
                             'and how names are looked up in it')
        if any(m in methods for m in ('mail', 'sms')) and lookup == 'none':
            raise ValueError('a code by mail or SMS is sent only after the directory password '
                             'is right: the realm needs a directory')
        groups = []
        for one in data.get('groups') or []:
            if isinstance(one, str):
                one = {'group': one, 'reply': ''}
            g = str(one.get('group') or '').strip()
            if not g:
                continue
            try:
                reply_lines(one.get('reply') or '')
            except RadiusError as e:
                raise ValueError('the answer for the group %s: %s' % (g, e))
            groups.append({'group': g, 'reply': str(one.get('reply') or '').strip()})
        try:
            reply_lines(data.get('reply') or '')
        except RadiusError as e:
            raise ValueError('the answer for everybody in the realm: %s' % e)
        ident = data.get('id')
        old = self.db.row('SELECT * FROM realms WHERE id = ?', (int(ident),)) if ident else None
        if ident and not old:
            raise ValueError('that realm was taken away meanwhile - open it again')
        for other in self.realms():
            if old and other['id'] == old['id']:
                continue
            if other['name'].lower() == name.lower():
                raise ValueError('there is a realm called %s already' % name)
            if str(other.get('suffix') or '').lower() == suffix:
                raise ValueError('the realm %s takes %s already' % (
                    other['name'], ('@' + suffix) if suffix not in ('', '*') else
                    ('every name' if suffix == '*' else 'names written without a realm')))
            if suffix and suffix in (other.get('aliases') or []):
                raise ValueError('the realm %s takes @%s already, as another suffix of its own'
                                 % (other['name'], suffix))
            for a in aliases:
                if a == str(other.get('suffix') or '').lower() and \
                        other['name'].lower() in [str(x).lower() for x in absorb or []]:
                    continue            # taken into this one below (1.0.117)
                if a == str(other.get('suffix') or '').lower():
                    raise ValueError('@%s is the realm %s - to make it a second suffix of this '
                                     'one, take that realm away first (its tokens stay and are '
                                     'found under this one)' % (a, other['name']))
                if a in (other.get('aliases') or []):
                    raise ValueError('the realm %s takes @%s already' % (other['name'], a))
        # Realms taken into this one (1.0.117): their suffixes become its
        # other suffixes, their groups follow its own, and the clients allowed
        # them are allowed this one.
        taken = []
        for other in self.realms():
            if not absorb or other['name'].lower() not in [str(x).lower() for x in absorb]:
                continue
            if old and other['id'] == old['id']:
                continue
            osuf = str(other.get('suffix') or '').lower()
            if osuf in ('', '*'):
                raise ValueError('the realm %s takes %s - it cannot become another suffix of '
                                 'this one' % (other['name'], 'every name' if osuf == '*'
                                               else 'names written without a realm'))
            if str(other.get('directory') or '').lower() != directory.lower():
                raise ValueError('the realm %s reads another directory (%s): its people are '
                                 'not this realm\'s' % (other['name'],
                                                         other.get('directory') or 'none'))
            for a in [osuf] + list(other.get('aliases') or []):
                if a != suffix and a not in aliases:
                    aliases.append(a)
            have = [g['group'].lower() for g in groups]
            for g in other.get('groups') or []:
                if str(g.get('group') or '').lower() not in have:
                    groups.append({'group': g['group'], 'reply': g.get('reply') or ''})
            taken.append(other)
        row = {'name': name, 'suffix': suffix, 'directory': directory, 'lookup': lookup,
               'auth_mode': mode, 'group_list': json.dumps(groups),
               'check_disabled': _yes(data, 'check_disabled', 1),
               'nested': _yes(data, 'nested', 1),
               'reply': str(data.get('reply') or '').strip(),
               'enabled': _yes(data, 'enabled', 1),
               'position': list_position(data.get('position')),
               'note': str(data.get('note') or '')[:400], 'token_name': token_name,
               'methods': ','.join(methods), 'aliases': ','.join(aliases)}
        with self.lock:
            if old:
                self.db.update('realms', old['id'], row)
                ident = old['id']
                if old.get('name') and row.get('name') and old['name'] != row['name']:
                    # The clients that may use it, told its new name (1.0.36).
                    self._client_realms_rename(old['name'], row['name'])
            else:
                row['created'] = time.time()
                ident = self.db.insert('realms', row)
            for other in taken:
                self._client_realms_rename(other['name'], name)
                self.db.run('DELETE FROM realms WHERE id = ?', (int(other['id']),))
            self._realms = None
        return ident

    def clients_only_realm(self, name):
        """The clients that take this realm and no other."""
        out = []
        for c in self.db.rows("SELECT id, name, realms FROM clients WHERE COALESCE(realms, '') <> ''"):
            names = [x.strip().lower() for x in re.split(r'[,;\n]+', c['realms'] or '')
                     if x.strip()]
            if names and all(x == str(name).lower() for x in names):
                out.append(c)
        return out

    def realm_drop(self, ident, force=False):
        """A realm taken away. A client that took only this one would take every
        realm once it was out of its list (1.0.146) - refused; `force` (a
        configuration put back whole) switches such a client off instead."""
        one = self.db.row('SELECT name FROM realms WHERE id = ?', (int(ident),))
        only = self.clients_only_realm(one['name']) if one else []
        if only and not force:
            raise ValueError('the client(s) %s take only this realm - without it they would '
                             'take every realm; change them first' % ', '.join(
                                 c['name'] for c in only))
        for c in only:
            self.db.update('clients', c['id'], {'enabled': 0})
            log('the client %s took only the realm %s, which was taken away: switched off'
                % (c['name'], one['name']), 'warn')
        self.db.run('DELETE FROM realms WHERE id = ?', (int(ident),))
        self._realms = None
        if one:
            # ...and out of the clients' lists: a name left there made every
            # later save of the client fail (1.0.36).
            self._client_realms_rename(one['name'], None)

    def _client_realms_rename(self, was, now):
        for c in self.db.rows("SELECT id, realms FROM clients WHERE COALESCE(realms, '') <> ''"):
            names = [x.strip() for x in re.split(r'[,;\n]+', c['realms'] or '') if x.strip()]
            if not any(x.lower() == str(was).lower() for x in names):
                continue
            names = [(now if x.lower() == str(was).lower() else x) for x in names]
            names = [x for x in names if x]
            self.db.update('clients', c['id'], {'realms': ', '.join(names)})
        self._clients = None

    # ---- directories -------------------------------------------------------
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
        for k in ('name', 'hosts', 'base', 'bind_dn', 'bind_pw', 'note', 'ca', 'user_attr', 'tls'):
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
                    self.db.run('UPDATE realms SET directory = ? WHERE LOWER(directory) = ?',
                                (name, old['name'].lower()))
                    self._realms = None
                    # The one administrators sign in against too (1.0.146):
                    # left on the old name, every directory administrator was
                    # signed out and could not sign in again.
                    if str(CONFIG.get('admin_directory') or '').lower() == old['name'].lower():
                        self.save_setting('admin_directory', name, by)
                        CONFIG['admin_directory'] = name
                self.db.update('directories', old['id'], row)
                ident = old['id']
            else:
                row['created'] = time.time()
                ident = self.db.insert('directories', row)
            self._dirs = None
        return ident

    def directory_drop(self, ident):
        one = self.db.row('SELECT name FROM directories WHERE id = ?', (int(ident),))
        if one:
            used = [r['name'] for r in self.realms()
                    if str(r.get('directory') or '').lower() == one['name'].lower()]
            if used:
                raise ValueError('the realm(s) %s look people up in it; change them first'
                                 % ', '.join(used))
            if str(CONFIG.get('admin_directory') or '').lower() == one['name'].lower():
                raise ValueError('administrators sign in against it (Settings → Accounts); '
                                 'choose another directory for them first')
        self.db.run('DELETE FROM directories WHERE id = ?', (int(ident),))
        self._dirs = None

    # ---- tokens --------------------------------------------------------------
    TOKEN_SORTS = {'name': 'name', 'created': 'created', 'last_used': 'last_used',
                   'state': 'state', 'failures': 'failures', 'scratch_left': 'scratch_left'}

    def token(self, name):
        return self.db.row('SELECT * FROM tokens WHERE name = ?', (norm_name(name),))

    def tokens(self, q='', state='', limit=100, offset=0, sort='name', desc=False, extra=None,
               kind=''):
        where, args = [], []
        if kind in ('totp', 'mail', 'sms'):
            # How the codes come (1.0.85): an app token has no kind written.
            where.append("(CASE WHEN kind IN ('mail', 'sms') THEN kind ELSE 'totp' END) = ?")
            args.append(kind)
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if q:
            where.append("(LOWER(name) LIKE ? ESCAPE '!' OR LOWER(note) LIKE ? ESCAPE '!' OR LOWER(display) LIKE ? ESCAPE '!' OR LOWER(COALESCE(dest, '')) LIKE ? ESCAPE '!')")
            like = '%' + like_pattern(str(q).lower()) + '%'
            args += [like, like, like, like]
            digits = phone_digits(q)
            if digits:
                # 603 364 754 finds +420603364754 (1.0.93).
                where[-1] = where[-1][:-1] + " OR %s LIKE ? ESCAPE '!')" % DEST_DIGITS_SQL
                args.append('%' + like_pattern(digits) + '%')
        if state:
            where.append('state = ?')
            args.append(state)
        sql = ' WHERE ' + ' AND '.join(where) if where else ''
        total = self.db.value('SELECT COUNT(*) AS n FROM tokens' + sql, args, 0)
        col = self.TOKEN_SORTS.get(sort, 'name')
        # The empty ones last on every engine (1.0.207): PostgreSQL put a column's
        # NULLs first when newest first - the never used before the last used.
        rows = self.db.rows('SELECT * FROM tokens%s ORDER BY (%s IS NULL), %s %s, name LIMIT %d OFFSET %d'
                            % (sql, col, col, 'DESC' if desc else 'ASC', int(limit), int(offset)),
                            args)
        return [self.token_shown(r) for r in rows], int(total or 0)

    @staticmethod
    def token_shown(r):
        """A token as the pages may see it: never its key, never its codes."""
        if not r:
            return None
        out = {k: r.get(k) for k in ('id', 'name', 'digits', 'period', 'algorithm',
                                     'window_steps', 'state', 'scratch_left', 'created',
                                     'created_by', 'activated', 'last_used', 'last_from',
                                     'last_how', 'failures', 'note', 'issuer', 'label',
                                     'pending_at', 'pending_by', 'display', 'last_client')}
        out['kind'] = token_kind(r)
        out['dest'] = r.get('dest') or ''
        out['lang'] = r.get('lang') or ''               # 1.0.82
        out['mail_fmt'] = r.get('mail_fmt') or ''
        out['key_lost'] = unseal_secret(r.get('secret') or '', token_bind(r.get('name'))) is None
        out['pending'] = bool(r.get('pending_secret'))
        out['scratch_kept'] = bool(r.get('scratch_sealed'))
        # Until when wrong codes keep it shut (1.0.101): a lock that grows
        # with each round is shown, not guessed at from the count.
        lu = float(r.get('locked_until') or 0)
        out['locked_until'] = lu if lu > time.time() else None
        return out

    def token_counts(self):
        out = {'all': 0, 'active': 0, 'pending': 0, 'disabled': 0}
        for r in self.db.rows('SELECT state, COUNT(*) AS n FROM tokens GROUP BY state'):
            out[r['state'] or 'active'] = int(r['n'])
            out['all'] += int(r['n'])
        out['used_30d'] = int(self.db.value('SELECT COUNT(*) AS n FROM tokens WHERE '
                                            'last_used > ?', (time.time() - 30 * 86400,), 0))
        out['never_used'] = int(self.db.value('SELECT COUNT(*) AS n FROM tokens WHERE '
                                              'last_used IS NULL', (), 0))
        for r in self.db.rows("SELECT CASE WHEN kind IN ('mail', 'sms') THEN kind ELSE 'totp' END "
                              "AS k, COUNT(*) AS n FROM tokens GROUP BY 1"):
            out['kind_' + r['k']] = int(r['n'])        # 1.0.85
        return out

    def token_write(self, name, fields):
        """A token made, or the fields given changed on the one there is."""
        name = norm_name(name)
        with self.lock:
            old = self.token(name)
            if old:
                self.db.update('tokens', old['id'], fields)
                return old['id']
            # A new one only with letters this server takes (1.0.154).
            bad = name_letters_problem(name)
            if bad:
                raise ValueError(bad)
            row = {'name': name, 'state': 'active', 'last_step': 0, 'failures': 0,
                   'fail_times': '[]', 'scratch': '[]', 'scratch_left': 0,
                   'created': time.time(), 'window_steps': -1}
            row.update(fields)
            return self.db.insert('tokens', row)

    def token_update(self, ident, fields):
        """Fields changed on the token that was read, by its id, and never a
        token made: a check whose token was deleted meanwhile wrote a new,
        empty one back under the name (1.0.36)."""
        return self.db.update('tokens', ident, fields)

    def token_drop(self, name):
        return self.db.run('DELETE FROM tokens WHERE name = ?', (norm_name(name),))

    # ---- the logs ------------------------------------------------------------
    def radius_add(self, row):
        if HA_REBUILDING.is_set():
            return None
        row.setdefault('node', log_node())
        hook = getattr(self, 'on_radius', None)
        if hook:
            try:
                hook(row)                   # only put in a queue (1.0.166)
            except Exception:               # noqa: BLE001
                pass
        return self.db.insert('radius_log', row)

    def radius_rows(self, hours=24, q='', result='', client='', limit=100, offset=0,
                    since=None, sort='ts', desc=True, user='', where_only=False, extra=None):
        where, args = ['ts >= ?'], [since if since is not None else
                                    time.time() - float(hours) * 3600]
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if q:
            like = '%' + like_pattern(str(q).lower()) + '%'
            where.append("(LOWER(username) LIKE ? ESCAPE '!' OR LOWER(calling) LIKE ? ESCAPE '!' OR LOWER(reason) "
                         "LIKE ? ESCAPE '!' OR LOWER(client) LIKE ? ESCAPE '!' OR LOWER(device) LIKE ? ESCAPE '!' OR "
                         "LOWER(acme) LIKE ? ESCAPE '!')")
            args += [like] * 6
        if result:
            if result == 'access':
                where.append("packet = 'Access-Request'")
            else:
                where.append('result = ?')
                args.append(result)
        if client:
            where.append('client = ?')
            args.append(client)
        if user:
            where.append('username = ?')
            args.append(user)
        sql = ' WHERE ' + ' AND '.join(where)
        if where_only:
            return sql, args
        total = self.db.value('SELECT COUNT(*) AS n FROM radius_log' + sql, args, 0)
        col = {'ts': 'ts', 'username': 'username', 'result': 'result', 'client': 'client',
               'calling': 'calling', 'took_ms': 'took_ms', 'reason': 'reason',
               'node': 'node'}.get(sort, 'ts')
        rows = self.db.rows('SELECT id, ts, client, nas_ip, src, packet, username, realm, '
                            'calling, called, result, reason, acme, rid, took_ms, device, tunnel, '
                            'node '
                            'FROM radius_log%s ORDER BY %s %s, id DESC LIMIT %d OFFSET %d'
                            % (sql, col, 'DESC' if desc else 'ASC', int(limit), int(offset)),
                            args)
        return rows, int(total or 0)

    def radius_row(self, ident):
        r = self.db.row('SELECT * FROM radius_log WHERE id = ?', (int(ident),))
        if r:
            for k in ('attrs', 'reply', 'steps'):
                try:
                    r[k] = json.loads(r.get(k) or '[]')
                except ValueError:
                    r[k] = []
        return r

    def acme_add(self, row):
        row.setdefault('node', log_node())
        return self.db.insert('acme_log', row)

    def log_forget(self, table, ids=None, where_sql='', args=()):
        """Lines of a log taken away - by id, or every line a filter matches."""
        if table not in ('radius_log', 'acme_log', 'events'):
            raise ValueError('not a log')
        if ids is not None:
            ids = [int(i) for i in ids][:5000]
            if not ids:
                return 0
            return self.db.run('DELETE FROM %s WHERE id IN (%s)'
                               % (table, ', '.join('?' for _ in ids)), ids)
        return self.db.run('DELETE FROM %s%s' % (table, where_sql), list(args))

    def acme_where(self, hours=24, q='', ok=None, name='', not_how='', extra=None):
        where, args = ['ts >= ?'], [time.time() - float(hours) * 3600]
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if not_how:
            where.append('(how IS NULL OR how <> ?)')
            args.append(not_how)
        if q:
            like = '%' + like_pattern(str(q).lower()) + '%'
            where.append("(LOWER(name) LIKE ? ESCAPE '!' OR LOWER(said) LIKE ? ESCAPE '!' OR LOWER(src) LIKE ? ESCAPE '!')")
            args += [like] * 3
        if ok is not None:
            where.append('ok = ?')
            args.append(1 if ok else 0)
        if name:
            where.append('name = ?')
            args.append(name)
        return ' WHERE ' + ' AND '.join(where), args

    def acme_rows(self, hours=24, q='', ok=None, limit=100, offset=0, name='', not_how='',
                 extra=None):
        if not_how or extra:
            sql, args = self.acme_where(hours, q, ok, name, not_how, extra)
            total = self.db.value('SELECT COUNT(*) AS n FROM acme_log' + sql, args, 0)
            rows = self.db.rows('SELECT * FROM acme_log%s ORDER BY ts DESC, id DESC LIMIT %d '
                                'OFFSET %d' % (sql, int(limit), int(offset)), args)
            return rows, int(total or 0)
        where, args = ['ts >= ?'], [time.time() - float(hours) * 3600]
        if q:
            like = '%' + like_pattern(str(q).lower()) + '%'
            where.append("(LOWER(name) LIKE ? ESCAPE '!' OR LOWER(said) LIKE ? ESCAPE '!' OR LOWER(src) LIKE ? ESCAPE '!')")
            args += [like] * 3
        if ok is not None:
            where.append('ok = ?')
            args.append(1 if ok else 0)
        if name:
            where.append('name = ?')
            args.append(name)
        sql = ' WHERE ' + ' AND '.join(where)
        total = self.db.value('SELECT COUNT(*) AS n FROM acme_log' + sql, args, 0)
        rows = self.db.rows('SELECT * FROM acme_log%s ORDER BY ts DESC, id DESC LIMIT %d OFFSET %d'
                            % (sql, int(limit), int(offset)), args)
        return rows, int(total or 0)

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
        """What the front page counts: per hour, what was let in and what was
        refused, and the names, reasons and clients behind the refusals.
        `since`/`until` (1.0.53): a window of its own, from the time picker."""
        now = time.time()
        until = float(until) if until else now
        since = float(since) if since else until - float(hours) * 3600
        hours = max(1.0, (until - since) / 3600)
        step = 3600 if hours <= 72 else (6 * 3600 if hours <= 24 * 31 else 86400)
        # Bars on the local clock (1.0.57): a day ran from 01:00 or 02:00
        # in Prague, aligned to UTC.
        off = time.localtime(since).tm_gmtoff or 0
        start = int((since + off) // step) * step - off
        # Counted by the database, hour by hour (1.0.33): every request of
        # the window was read into Python - over a second for a month.
        slot = ('CAST((ts - ?) / ? AS INTEGER)' if self.db.engine == 'sqlite'
                else 'FLOOR((ts - ?) / ?)')
        # Counted by the hour, and the hours put into bars of the local clock
        # (1.0.59): a day bar is local midnight to midnight across a change
        # of summer time too, where a fixed 24 h step drifted by an hour.
        rows = self.db.rows("SELECT %s AS b, result, COUNT(*) AS n FROM radius_log "
                            "WHERE ts >= ? AND ts < ? AND packet = 'Access-Request' "
                            "AND result IN ('accept', 'reject', 'drop') GROUP BY 1, 2"
                            % slot, (start, 3600, since, until))

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
                buckets[b] = {'t': b, 'accept': 0, 'reject': 0}
            t += 3600
        acc = rej = 0
        for r in rows:
            b = bar_of(start + int(r['b'] or 0) * 3600)
            if b not in buckets:
                buckets[b] = {'t': b, 'accept': 0, 'reject': 0}
            n = int(r['n'] or 0)
            if r['result'] == 'accept':
                buckets[b]['accept'] += n
                acc += n
            else:
                buckets[b]['reject'] += n
                rej += n

        def top(col, where, n=10):
            return self.db.rows(
                "SELECT %s AS said, COUNT(*) AS n, MAX(ts) AS last FROM radius_log WHERE ts >= ? "
                "AND ts < ? AND packet = 'Access-Request' AND %s GROUP BY %s ORDER BY n DESC "
                "LIMIT %d" % (col, where, col, n), (since, until))
        return {
            'hours': hours, 'step': step, 'since': since, 'until': until, 'series': list(buckets.values()),
            'accepted': acc, 'refused': rej,
            'people': int(self.db.value(
                "SELECT COUNT(DISTINCT username) AS n FROM radius_log WHERE ts >= ? AND "
                "ts < ? AND result = 'accept'", (since, until), 0) or 0),
            'top_refused_names': top('username', "result = 'reject'"),
            'top_reasons': top('reason', "result = 'reject'"),
            'top_clients': top('client', '1 = 1'),
            'top_places': top('calling', "calling <> ''"),
            'acme_bad': int(self.db.value('SELECT COUNT(*) AS n FROM acme_log WHERE ts >= ? AND '
                                         'ts < ? AND ok = 0', (since, until), 0) or 0),
            'acme_good': int(self.db.value('SELECT COUNT(*) AS n FROM acme_log WHERE ts >= ? AND '
                                          'ts < ? AND ok = 1', (since, until), 0) or 0),
        }

    def tidy(self):
        """What has been kept long enough, deleted."""
        said = {}
        for table, key in (('radius_log', 'retain_radius_days'), ('acme_log', 'retain_acme_days'),
                           ('events', 'retain_events_days')):
            days = int(CONFIG.get(key) or 0)
            if days > 0:
                said[table] = self.delete_older(table, time.time() - days * 86400)
        self.sessions_tidy(int(CONFIG.get('session_idle_min') or 120) * 60,
                           int(CONFIG.get('portal_session_min') or 15) * 60)
        return said

    def delete_older(self, table, cut):
        """Rows older than `cut`, deleted in batches (1.0.33), with a breath
        between them (1.0.57) so RADIUS requests waiting on the database get
        their turn."""
        # 1000 at a time and a fifth of a second between (1.0.149): 5000 with
        # 0.02 s left RADIUS a quarter of its pace for the whole of it.
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
                # every RADIUS write waited behind it until it gave up.
                self.db.run(RawSql('PRAGMA wal_checkpoint(PASSIVE)'))
            except Exception:                           # noqa: BLE001
                pass
        return gone

    def counts(self):
        return {t: int(self.db.value('SELECT COUNT(*) AS n FROM %s' % t, (), 0) or 0)
                for t in TABLES if t not in ('meta',)}


