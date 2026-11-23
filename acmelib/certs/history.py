# -*- coding: utf-8 -*-
"""
Trash, object history and saved views (1.0.138, docs/history-and-trash.md).

One hook, in the store layer: every statement the daemon writes goes through
Db.query; while a request of the API is being answered (api.api -> acting), a
write to one of the configuration's tables (TYPES) is noted - the row as it
was before an UPDATE or a DELETE, the number of a row an INSERT made. When the
request is over, each row noted is compared with what it is now:

- a row that changed in a setting (not only in what acme writes by itself - its
  state, its last error, when it ran) is a line of its history (obj_history):
  who, when, from where, which route, the row before and after;
- a row that is gone goes to the trash (obj_trash) for `history_trash_days`
  (30, 0 = no trash): as it was, its secrets sealed as they were - never opened,
  never sent. Rows that went with it in the same request (a certificate's
  deployments and tests, a DNS set's uses, a target's deployments, a test's
  attachments) go with it, under it.

Nothing is changed in how anything is saved or deleted; what is noted is read,
never written back. A restore is a normal save: the route that saves that kind
of object is run (its checks of who may, its checks of what is given), with the
values of the version or of the trash - a secret opened here, inside the daemon,
and sealed again for its new place by that route. Certificates come back as a
request (held, not issued): their key and their certificates never go to the
trash, a deleted key never comes back.
"""
from __future__ import annotations

import contextlib
import json
import re
import threading
import time
import uuid

from acmelib import engine as E
from acmelib.certs import store as S

HIST = 'obj_history'
TRASH = 'obj_trash'
VIEWS = 'saved_views'

# table -> (type, the column that names it)
TYPES = {
    'certs': ('cert', 'name'),
    'cert_targets': ('target', 'name'),
    'cert_issuers': ('source', 'name'),
    'cert_challenges': ('validation', 'name'),
    'cert_tests': ('test', 'name'),
    'cert_deploys': ('deploy', None),
    'cert_checks': ('check', None),
    'cert_req_profiles': ('profile', 'name'),
    'cert_teams': ('team', 'name'),
    'cert_roles': ('role', 'name'),
    'cert_tags': ('tag', 'name'),
    'dns_sets': ('dnsset', 'name'),
    'dns_set_uses': ('dnsuse', 'purpose'),
    'dns_records': ('dnsrecord', 'name'),
}
TABLE_OF_TYPE = {v[0]: k for k, v in TYPES.items()}
# Kept in the trash only as a part of the object they went with (a DNS set's uses).
ONLY_WITH = {'dnsuse'}
# No history of their own.
NO_HISTORY = {'dnsuse'}
# A full administrator saves these (their routes' role); the rest a certificate administrator
# of the certificate's team.
FULL_TYPES = {'target', 'source', 'validation', 'test', 'profile', 'team', 'role', 'tag',
              'dnsset', 'dnsuse', 'dnsrecord'}
CERT_BOUND = {'cert', 'deploy', 'check'}

# What acme writes by itself: never a change of a setting.
RUNTIME = {'id', 'created', 'created_by', 'updated', 'updated_by', 'last_ok', 'last_error',
           'last_try', 'next_try', 'fails', 'state_at', 'deployed_version', 'deployed_fp',
           'last_at', 'last_state', 'last_said', 'last_detail', 'expires'}
# ...and per table (a module's `state` is its own memory, a deployment's its progress).
RUNTIME_OF = {'cert_targets': {'state'}, 'cert_issuers': {'state'}, 'cert_challenges': {'state'},
              'cert_tests': {'state'}, 'cert_deploys': {'state'}}
# A certificate's settings - the rest of its row is what it holds (PEMs, its key) and how
# it is doing: never kept here.
CERT_CONFIG = ('name', 'names', 'key_type', 'key_type_alt', 'issuer', 'challenge',
               'challenge_map', 'auto_renew', 'renew_days', 'reuse_key', 'profile', 'tags',
               'note', 'owner', 'enabled', 'csr_from')
CERT_KEEP = CERT_CONFIG + ('id', 'cn', 'state', 'version', 'not_after', 'source', 'csr_given')
JSON_COLS = {'config', 'options', 'members', 'policy', 'caps', 'profile', 'challenge_map',
             'names', 'tags'}
# A row that went with another (child table, its column, the parent table, the parent's column)
PARENTS = [('cert_deploys', 'cert_id', 'certs', 'id'),
           ('cert_checks', 'cert_id', 'certs', 'id'),
           ('dns_set_uses', 'set_name', 'dns_sets', 'name'),
           ('cert_deploys', 'target', 'cert_targets', 'name'),
           ('cert_checks', 'test', 'cert_tests', 'name')]

WORDS = {'cert': 'certificate', 'target': 'target', 'source': 'source',
         'validation': 'validation', 'test': 'test', 'deploy': 'deployment',
         'check': 'test of a certificate', 'profile': 'request profile', 'team': 'owner',
         'role': 'role', 'tag': 'tag', 'dnsset': 'DNS set', 'dnsuse': 'use of a DNS set',
         'dnsrecord': 'DNS record'}

_TL = threading.local()
_ORIG = {}
_LOCK = threading.Lock()


def _now():
    return time.time()


def _low(v):
    return str(v or '').strip().lower()


def _days(v, default):
    try:
        v = int(v if v not in (None, '') else default)
    except (TypeError, ValueError):
        v = default
    return max(0, min(3650, v))


def trash_days():
    """Settings → Trash and history: how long what was deleted is kept (0: no trash)."""
    return _days(E.CONFIG.get('history_trash_days', 30), 30)


def keep_days():
    """...and the history of changes (0: none written)."""
    return _days(E.CONFIG.get('history_keep_days', 365), 365)


# ---------------------------------------------------------------------------
# The hook: Db.query, while a request is answered
# ---------------------------------------------------------------------------
_WRITE_RE = re.compile(r'^\s*(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+([A-Za-z_][A-Za-z0-9_]*)',
                       re.I)
_UPD_RE = re.compile(r'^\s*UPDATE\s+\w+\s+SET\s+(.*?)(?:\s+WHERE\s+(.*))?\s*$', re.I | re.S)
_DEL_RE = re.compile(r'^\s*DELETE\s+FROM\s+\w+(?:\s+WHERE\s+(.*))?\s*$', re.I | re.S)


class _Ctx(object):
    def __init__(self, h, s, method, path):
        self.h = h
        self.store = getattr(h, 'store', None)
        self.who = str((s or {}).get('name') or '?')[:190]
        ip = ''
        try:
            ip = str(h.client_ip() or '') if hasattr(h, 'client_ip') else ''
        except Exception:                               # noqa: BLE001
            ip = ''
        if not ip and (s or {}).get('cli'):
            ip = 'command line'
        self.ip = ip[:60]
        self.via = str(path or '')[:120]
        self.inside = False
        self.seen = {}          # (table, id) -> {'row': before | None, 'meta': ...}
        self.order = []
        self.db = None
        self.note = ''
        self.action = ''        # 'restore' while a restore runs
        self.trash_from = None  # the trash entry being restored (its old ids follow)
        self.depth = 0

    def touch(self, db, table, ident, row, meta=None):
        key = (table, int(ident))
        if key in self.seen:
            return
        if self.db is None:
            self.db = db
        self.seen[key] = {'row': row, 'meta': meta}
        self.order.append(key)


def _note_before(db, ctx, table, verb, sql, args):
    args = list(args or ())
    if verb == 'UPDATE':
        m = _UPD_RE.match(sql)
        if not m:
            return
        where = m.group(2)
        wargs = args[m.group(1).count('?'):]
    else:
        m = _DEL_RE.match(sql)
        if not m:
            return
        where = m.group(1)
        wargs = args
    # at most the 5000 noted (hunt f1): a source renamed under 50 000 certificates read every
    # one of them whole - their PEMs too - into the request's memory, to keep 5000
    q = 'SELECT * FROM %s' % table + ((' WHERE ' + where) if where else '') + ' LIMIT 5000'
    rows = _ORIG['query'](db, q, tuple(wargs), True)[0] or []
    for r in rows[:5000]:
        if r.get('id') is None:
            continue
        meta = None
        if verb == 'DELETE':
            meta = _meta_of(ctx.store, table, r)
        ctx.touch(db, table, r['id'], dict(r), meta)


def _meta_of(store, table, row):
    """What of it is kept in meta (as the configuration's export carries it)."""
    if store is None:
        return None
    try:
        if table == 'certs':
            return S.cert_meta_out(store, row['id']) or None
        if table == 'cert_tests' and row.get('name'):
            from acmelib.certs import checks as C
            return C.test_meta_out(store, row['name']) or None
    except Exception:                                   # noqa: BLE001
        return None
    return None


def _query(self, sql, args=(), fetch=True):
    ctx = getattr(_TL, 'ctx', None)
    if ctx is None or ctx.inside or type(sql) is not str:
        return _ORIG['query'](self, sql, args, fetch)
    m = _WRITE_RE.match(sql)
    if not m:
        return _ORIG['query'](self, sql, args, fetch)
    table = m.group(2).lower()
    if table not in TYPES:
        return _ORIG['query'](self, sql, args, fetch)
    verb = m.group(1)[:6].upper()
    if verb in ('UPDATE', 'DELETE'):
        ctx.inside = True
        try:
            _note_before(self, ctx, table, 'UPDATE' if verb == 'UPDATE' else 'DELETE', sql, args)
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('history-note', 'history: a change could not be noted: %s' % e,
                          'warn', every=600)
        finally:
            ctx.inside = False
        return _ORIG['query'](self, sql, args, fetch)
    got = _ORIG['query'](self, sql, args, fetch)
    up = sql.upper()
    if 'ON CONFLICT' not in up and 'ON DUPLICATE' not in up:
        try:
            ident = got[2]
            if ident:
                ctx.touch(self, table, int(ident), None)
        except Exception:                               # noqa: BLE001
            pass
    return got


def install():
    """The hook put on the database's one way in (once per process)."""
    with _LOCK:
        if 'query' in _ORIG:
            return
        _ORIG['query'] = E.Db.query
        E.Db.query = _query


@contextlib.contextmanager
def acting(h, s, method, path):
    """Around one route of the API (api.api): what it changes noted, written when it is over."""
    if method != 'POST':
        yield
        return
    cur = getattr(_TL, 'ctx', None)
    if cur is not None:
        cur.depth += 1
        try:
            yield
        finally:
            cur.depth -= 1
        return
    install()
    ctx = _Ctx(h, s, method, path)
    _TL.ctx = ctx
    try:
        yield
    finally:
        _TL.ctx = None
        if ctx.order:
            try:
                flush(ctx)
            except Exception as e:                      # noqa: BLE001
                E.log('history: what %s changed could not be written down: %s' % (path, e),
                      'warn')


# ---------------------------------------------------------------------------
# What is kept of a row
# ---------------------------------------------------------------------------
def _jl(v):
    if isinstance(v, str) and v[:1] in ('{', '['):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def snapshot(table, row):
    """The settings of a row (what a change of is history): without what acme writes by
    itself, and of a certificate only its settings."""
    if row is None:
        return None
    if table == 'certs':
        return {k: row.get(k) for k in CERT_CONFIG if k in row}
    skip = RUNTIME | RUNTIME_OF.get(table, set())
    return {k: v for k, v in row.items() if k not in skip}


def trash_row(table, row):
    """The row as the trash keeps it: whole, its secrets sealed as they were - a certificate
    without its key, its certificates and its state (it comes back as a request)."""
    if table == 'certs':
        return {k: row.get(k) for k in CERT_KEEP if k in row}
    return dict(row)


def _name_of(store, table, row):
    if not row:
        return ''
    t, col = TYPES[table]
    if col:
        return str(row.get(col) or '')[:190]
    cert = ''
    try:
        c = store.db.row('SELECT name FROM certs WHERE id = ?', (int(row.get('cert_id') or 0),))
        cert = (c or {}).get('name') or ''
    except Exception:                                   # noqa: BLE001
        pass
    other = row.get('target') if table == 'cert_deploys' else row.get('test')
    return ('%s → %s' % (cert or '#%s' % row.get('cert_id'), other or '?'))[:190]


def _owner_of(store, table, row, gone=None):
    """The team whose it is - of a certificate, a deployment and a test of one: the
    certificate's (who may see its history, its trash)."""
    if not row:
        return None
    if table == 'certs':
        return row.get('owner') or None
    if table in ('cert_deploys', 'cert_checks'):
        cid = row.get('cert_id')
        for k, info in (gone or {}).items():
            if k == ('certs', int(cid or 0)) and info.get('row'):
                return info['row'].get('owner') or None
        try:
            c = store.db.row('SELECT owner FROM certs WHERE id = ?', (int(cid or 0),))
            return (c or {}).get('owner') or None
        except Exception:                               # noqa: BLE001
            return None
    if table in ('cert_targets', 'cert_tests'):
        return row.get('owner') or None
    return None


def _same(a, b):
    return json.dumps(_jl(a), sort_keys=True, default=str) == \
        json.dumps(_jl(b), sort_keys=True, default=str)


def changed_fields(table, before, after):
    a, b = snapshot(table, before) or {}, snapshot(table, after) or {}
    return [k for k in sorted(set(a) | set(b)) if not _same(a.get(k), b.get(k))]


# ---------------------------------------------------------------------------
# Written down when the request is over
# ---------------------------------------------------------------------------
def _ignored(table, row):
    """A row that is not a setting somebody keeps: a DNS record acme puts in for a while (a
    challenge), a request of the portal waiting or declined, a certificate with no source."""
    if not row:
        return False
    if table == 'dns_records':
        return bool(row.get('expires'))
    return False


def _trashable(table, row):
    if table == 'certs':
        # its source renews it - without one (imported, a CSR) nothing could be issued again;
        # a request of the portal that waits or was declined is the portal's
        return bool(row.get('issuer')) and str(row.get('state') or '') not in (
            'pending-approval', 'declined', 'deleting')
    return True


def flush(ctx):
    store = ctx.store
    db = (store.db if store is not None else None) or ctx.db
    if db is None:
        return
    keep, tdays = keep_days(), trash_days()
    if not keep and not tdays:
        return
    gone, batch = {}, uuid.uuid4().hex[:16]
    t = _now()
    hist = []
    for key in ctx.order:
        table, ident = key
        info = ctx.seen[key]
        before = info['row']
        ctx.inside = True
        try:
            now = db.row('SELECT * FROM %s WHERE id = ?' % table, (ident,))
        finally:
            ctx.inside = False
        if before is None and now is None:
            continue
        if _ignored(table, before or now):
            continue
        typ = TYPES[table][0]
        if now is None:
            gone[key] = info
            action = 'delete'
        elif before is None:
            action = ctx.action or 'create'
        else:
            if not changed_fields(table, before, now):
                continue
            action = ctx.action or 'change'
        if typ in NO_HISTORY or not keep:
            continue
        row = now or before
        hist.append({'ts': t, 'otable': table, 'otype': typ, 'oid': ident,
                     'oname': _name_of(store, table, row), 'action': action,
                     'who': ctx.who, 'ip': ctx.ip, 'via': ctx.via, 'note': ctx.note[:500],
                     'owner': _owner_of(store, table, row, ctx.seen),
                     'was_v': json.dumps(snapshot(table, before), default=str)
                     if before is not None else None,
                     'now_v': json.dumps(snapshot(table, now), default=str)
                     if now is not None else None,
                     'fields': ','.join(changed_fields(table, before, now))[:2000]
                     if before is not None and now is not None else '',
                     'batch': batch})
    ctx.inside = True
    try:
        for h in hist:
            db.insert(HIST, h)
        if tdays and gone:
            _to_trash(ctx, db, gone, batch, t, tdays)
    finally:
        ctx.inside = False


def _parent_key(table, row, gone):
    for child, col, ptable, pcol in PARENTS:
        if child != table:
            continue
        want = row.get(col)
        if want in (None, ''):
            continue
        for (gt, gid), info in gone.items():
            if gt != ptable or not info.get('row'):
                continue
            have = gid if pcol == 'id' else info['row'].get(pcol)
            if str(have) == str(want) and (gt != 'certs' or _trashable(gt, info['row'])):
                return (gt, gid)
    return None


def _to_trash(ctx, db, gone, batch, t, days):
    store = ctx.store
    made = {}
    # parents first
    keys = sorted(gone, key=lambda k: 0 if _parent_key(k[0], gone[k]['row'], gone) is None
                  else 1)
    for key in keys:
        table, ident = key
        info = gone[key]
        row = info['row']
        typ = TYPES[table][0]
        pk = _parent_key(table, row, gone)
        if pk is None and (typ in ONLY_WITH or not _trashable(table, row)):
            continue
        parent = made.get(pk) if pk else None
        if pk and parent is None:
            continue                # its parent was not kept: neither is it
        made[key] = db.insert(TRASH, {
            'ts': t, 'otable': table, 'otype': typ, 'oid': ident,
            'oname': _name_of(store, table, row) if table not in ('cert_deploys', 'cert_checks')
            else _child_name(gone, table, row, store),
            'owner': _owner_of(store, table, row, gone), 'who': ctx.who, 'ip': ctx.ip,
            'via': ctx.via, 'parent': parent, 'batch': batch,
            'row_v': json.dumps(trash_row(table, row), default=str),
            'meta': json.dumps(info.get('meta')) if info.get('meta') else None,
            'detail': _detail(table, row)[:500], 'expires': t + days * 86400})


def _child_name(gone, table, row, store):
    cert = ''
    for (gt, gid), info in gone.items():
        if gt == 'certs' and str(gid) == str(row.get('cert_id')) and info.get('row'):
            cert = info['row'].get('name') or ''
    if not cert:
        return _name_of(store, table, row)
    other = row.get('target') if table == 'cert_deploys' else row.get('test')
    return ('%s → %s' % (cert, other or '?'))[:190]


def _detail(table, row):
    if table in ('cert_targets', 'cert_issuers', 'cert_challenges', 'cert_tests'):
        return str(row.get('kind') or '')
    if table == 'certs':
        names = S.jload(row.get('names'), []) or []
        return ', '.join(str(n) for n in names[:4]) + (' …' if len(names) > 4 else '')
    if table == 'cert_teams':
        return str(row.get('kind') or 'team')
    if table == 'dns_records':
        return '%s %s' % (row.get('rtype') or '', str(row.get('value') or '')[:80])
    if table == 'dns_sets':
        return str(row.get('protocol') or '')
    return ''


# ---------------------------------------------------------------------------
# Forgotten after their time (the node that leads, every hour)
# ---------------------------------------------------------------------------
_PURGE = {'at': 0.0, 'stop': None, 'thread': None}


def purge(store, force=False):
    t = _now()
    if not force and t - _PURGE['at'] < 300:
        return 0
    if not force:
        # by the node that leads only (hunt f1): a look at the trash or the history on the other
        # node of a pair deleted there too - each node its own deletes, replicated both ways
        try:
            if not E.ha_lead(store):
                return 0
        except Exception:                               # noqa: BLE001
            return 0
    _PURGE['at'] = t
    n = 0
    tdays, kdays = trash_days(), keep_days()
    try:
        # the trash: what ran out (all of it when the trash is off)
        n += int(store.db.run('DELETE FROM %s WHERE expires < ? OR ts < ?' % TRASH,
                              (t, t - max(tdays, 0) * 86400 - 1)) or 0)
        n += int(store.db.run('DELETE FROM %s WHERE ts < ?' % HIST,
                              (t - kdays * 86400 - 1,)) or 0)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('history-purge', 'history: old entries could not be forgotten: %s' % e,
                      'warn', every=3600)
    return n


def start(daemon):
    install()
    if _PURGE['thread'] is not None:
        return
    stop = threading.Event()
    _PURGE['stop'] = stop

    def loop():
        stop.wait(60)
        while not stop.is_set():
            try:
                store = daemon.store
                if E.ha_lead(store):
                    purge(store, force=True)
            except Exception as e:                      # noqa: BLE001
                E.log_sparing('history-loop', 'history: %s' % e, 'warn', every=3600)
            stop.wait(3600)
    th = threading.Thread(target=loop, name='history-purge', daemon=True)
    _PURGE['thread'] = th
    th.start()


def stop(_daemon=None):
    if _PURGE['stop'] is not None:
        _PURGE['stop'].set()
    _PURGE['thread'] = None


# ---------------------------------------------------------------------------
# Who may see what
# ---------------------------------------------------------------------------
def _teams():
    from acmelib.certs import teams as T
    return T


def full(s):
    return str((s or {}).get('role') or '') == 'fulladmin' or bool((s or {}).get('cli'))


def may_see(store, s, otype, owner, team=None):
    if full(s):
        return True
    if otype in CERT_BOUND:
        T = _teams()
        return T.owner_in(T.scope(store, s, 'view'), owner)
    if otype == 'team':
        # a team's members and addresses only to who sees the team (as /api/teams shows them)
        T = _teams()
        return T.owner_in(T.scope(store, s, 'view'), team)
    return True


def _team_of(store, r, cache=None):
    """The name a team's entry of the history is seen under: the team's name now (renamed
    since), else the name it had then."""
    if (r or {}).get('otype') != 'team':
        return None
    oid = r.get('oid')
    if cache is not None and oid in cache:
        return cache[oid]
    got = None
    try:
        row = store.db.row('SELECT name FROM cert_teams WHERE id = ?', (int(oid or 0),))
        got = (row or {}).get('name')
    except Exception:                                   # noqa: BLE001
        got = None
    got = got or r.get('oname') or None
    if cache is not None:
        cache[oid] = got
    return got


def may_restore_trash(store, s, otype, owner):
    """Offered (the route it runs checks again)."""
    if full(s):
        return True
    role = str((s or {}).get('role') or '')
    if otype in FULL_TYPES or role not in ('certadmin', 'tokenadmin'):
        return False
    T = _teams()
    cap = 'cert.edit' if otype == 'cert' else 'deploy.manage'
    return T.owner_in(T.scope(store, s, cap), owner)


def may_restore_version(store, s, otype, owner):
    if otype in ('check', 'dnsrecord', 'dnsuse'):
        return False
    return may_restore_trash(store, s, otype, owner)


# ---------------------------------------------------------------------------
# The difference, field by field - a secret only as "changed"
# ---------------------------------------------------------------------------
def _secret_keys(store, table, row):
    col = S.JSON_SECRET_COLS.get(table)
    if not col or not row:
        return set(), col
    keys = set()
    try:
        keys = set(S._row_secrets(store, table, row) or ())
    except Exception:                                   # noqa: BLE001
        keys = set()
    cfg = _jl(row.get(col))
    if isinstance(cfg, dict):
        keys |= {k for k, v in cfg.items() if isinstance(v, str) and v.startswith('sealed:')}
    return keys, col


def _labels(store, table, row):
    """{config key: its label} from the module (a target's options from the target's)."""
    out = {}
    try:
        if table in S.FAMILY_OF:
            cls = S.row_class(S.FAMILY_OF[table], row)
            for f in (getattr(cls, 'fields', None) or []):
                if f.get('key'):
                    out[f['key']] = str(f.get('label') or f['key'])
        elif table == 'cert_deploys':
            trow = S.plugin_row(store, 'target', row.get('target'))
            cls = S.row_class('target', trow) if trow else None
            for f in (getattr(cls, 'deploy_fields', None) or []):
                if f.get('key'):
                    out[f['key']] = str(f.get('label') or f['key'])
    except Exception:                                   # noqa: BLE001
        pass
    return out


def _shown(v):
    v = _jl(v)
    if isinstance(v, str) and v.startswith('sealed:'):
        return None
    if isinstance(v, str) and len(v) > 4000:
        return v[:4000] + '…'
    return v


def _masked_deep(v, depth=0):
    """Anything sealed inside a value (a certificate's overrides) never shown."""
    if depth > 6:
        return None
    if isinstance(v, str) and v.startswith('sealed:'):
        return S.SECRET_DOTS
    if isinstance(v, dict):
        return {k: _masked_deep(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_masked_deep(x, depth + 1) for x in v]
    return v


def diff(store, table, before, after):
    """[{field, sub, label, before, after, secret, set_before, set_after}] - every setting
    that differs; a JSON setting (a module's settings, a team's members...) key by key."""
    a = snapshot(table, before) or {}
    b = snapshot(table, after) or {}
    row = after or before or {}
    secrets, scol = _secret_keys(store, table, before or {})
    s2, _ = _secret_keys(store, table, after or {})
    secrets |= s2
    labels = _labels(store, table, row) if scol else {}
    out = []
    for k in sorted(set(a) | set(b)):
        if k == 'id':
            continue
        va, vb = _jl(a.get(k)), _jl(b.get(k))
        if _same(va, vb):
            continue
        if k == scol and isinstance(va or {}, dict) and isinstance(vb or {}, dict):
            da, db_ = va or {}, vb or {}
            for sk in sorted(set(da) | set(db_)):
                xa, xb = da.get(sk), db_.get(sk)
                if _same(xa, xb):
                    continue
                if sk in secrets:
                    out.append({'field': k, 'sub': sk, 'label': labels.get(sk, sk),
                                'secret': True, 'set_before': bool(xa), 'set_after': bool(xb)})
                else:
                    out.append({'field': k, 'sub': sk, 'label': labels.get(sk, sk),
                                'before': _masked_deep(_shown(xa)),
                                'after': _masked_deep(_shown(xb))})
            continue
        if k in ('policy', 'profile', 'challenge_map') and isinstance(va or {}, dict) and \
                isinstance(vb or {}, dict):
            da, db_ = va or {}, vb or {}
            for sk in sorted(set(da) | set(db_)):
                if _same(da.get(sk), db_.get(sk)):
                    continue
                out.append({'field': k, 'sub': sk, 'label': sk,
                            'before': _masked_deep(_shown(da.get(sk))),
                            'after': _masked_deep(_shown(db_.get(sk)))})
            continue
        out.append({'field': k, 'sub': '', 'label': k,
                    'before': _masked_deep(_shown(va)), 'after': _masked_deep(_shown(vb))})
    return out


def _snap(v):
    if not v:
        return None
    try:
        got = json.loads(v)
    except (TypeError, ValueError):
        return None
    return got if isinstance(got, dict) else None


def entry_public(store, s, r):
    before, after = _snap(r.get('was_v')), _snap(r.get('now_v'))
    return {'id': r['id'], 'ts': r.get('ts'), 'type': r.get('otype'), 'oid': r.get('oid'),
            'name': r.get('oname') or '', 'action': r.get('action') or '',
            'who': r.get('who') or '', 'ip': r.get('ip') or '', 'via': r.get('via') or '',
            'note': r.get('note') or '',
            'changes': diff(store, r['otable'], before, after) if before is not None and
            after is not None else [],
            # what it was made with (a creation, or brought back from the trash)
            'made': diff(store, r['otable'], {}, after) if before is None and after is not None
            else [],
            'fields': [f for f in str(r.get('fields') or '').split(',') if f],
            'can_restore': after is not None and r.get('action') != 'delete' and
            may_restore_version(store, s, r.get('otype'), r.get('owner'))}


def object_of(store, otype, oid=None, name=None):
    table = TABLE_OF_TYPE.get(otype)
    if not table:
        raise ValueError('there is no kind of object %r' % otype)
    row = None
    if oid not in (None, '', 0, '0'):
        try:
            oid = int(oid)
        except (TypeError, ValueError):
            raise ValueError('id is a number')
        row = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (oid,))
    elif name and TYPES[table][1]:
        row = store.db.row('SELECT * FROM %s WHERE %s = ?' % (table, TYPES[table][1]),
                           (str(name),))
        oid = (row or {}).get('id')
        if row is None:
            # gone: its last name in the history
            last = store.db.row('SELECT oid FROM %s WHERE otable = ? AND oname = ? ORDER BY '
                                'ts DESC, id DESC' % HIST, (table, str(name)))
            oid = (last or {}).get('oid')
    return table, oid, row


def history(store, s, otype, oid=None, name=None, limit=200):
    install()
    purge(store)
    table, oid, row = object_of(store, otype, oid, name)
    if not oid:
        raise LookupError('there is no such %s' % WORDS.get(otype, otype))
    rows = store.db.rows('SELECT * FROM %s WHERE otable = ? AND oid = ? ORDER BY ts DESC, id DESC'
                         % HIST, (table, int(oid)))[:max(1, min(1000, int(limit)))]
    owner = _owner_of(store, table, row) if row else (rows[0].get('owner') if rows else None)
    name_now = _name_of(store, table, row) if row else (rows[0].get('oname') if rows else '')
    if not may_see(store, s, otype, owner, team=name_now):
        raise E.ApiError(403, 'you may not see the history of that %s' % WORDS.get(otype, otype))
    in_trash = store.db.value('SELECT id FROM %s WHERE otable = ? AND oid = ? ORDER BY id DESC'
                              % TRASH, (table, int(oid))) if not row else None
    return {'object': {'type': otype, 'id': int(oid), 'name': name_now or '', 'exists': bool(row),
                       'trash_id': in_trash, 'words': WORDS.get(otype, otype)},
            'entries': [entry_public(store, s, r) for r in rows],
            'keep_days': keep_days(), 'trash_days': trash_days()}


def feed(store, s, otype='', who='', since=0, q='', limit=100, offset=0):
    """The latest changes of everything this session may see."""
    install()
    purge(store)
    where, args = [], []
    if otype:
        if otype not in TABLE_OF_TYPE:
            raise ValueError('there is no kind of object %r' % otype)
        where.append('otype = ?')
        args.append(otype)
    if who:
        where.append('LOWER(who) = ?')
        args.append(_low(who))
    if since:
        where.append('ts >= ?')
        args.append(float(since))
    sql = 'SELECT * FROM %s%s ORDER BY ts DESC, id DESC' % (
        HIST, (' WHERE ' + ' AND '.join(where)) if where else '')
    rows = store.db.rows(sql, tuple(args))
    names = {}
    seen = [r for r in rows[:5000] if may_see(store, s, r.get('otype'), r.get('owner'),
                                              team=_team_of(store, r, names))
            and (not q or _low(q) in _low(r.get('oname')))]
    out = []
    for r in seen[offset:offset + max(1, min(500, limit))]:
        out.append({'id': r['id'], 'ts': r.get('ts'), 'type': r.get('otype'),
                    'oid': r.get('oid'), 'name': r.get('oname') or '',
                    'action': r.get('action') or '', 'who': r.get('who') or '',
                    'ip': r.get('ip') or '', 'note': r.get('note') or '',
                    'fields': [f for f in str(r.get('fields') or '').split(',') if f]})
    people = sorted({r.get('who') or '' for r in seen if r.get('who')}, key=_low)[:200]
    return {'entries': out, 'total': len(seen), 'people': people, 'keep_days': keep_days()}


# ---------------------------------------------------------------------------
# A restore: the route that saves it, run with the values to restore
# ---------------------------------------------------------------------------
class _Sub(object):
    """The request as another route sees it: the same person, the same session, its body."""

    def __init__(self, h, path, body):
        self._h = h
        self._b = body
        self.route_path = path
        self.args = {}

    def __getattr__(self, k):
        return getattr(self._h, k)

    def body(self):
        return self._b

    def arg(self, name, default=''):
        return default


def call_route(h, path, body, method='POST'):
    fn = E.ROUTES.get((method, path))
    if fn is None:
        raise ValueError('acme has no %s here' % path)
    return fn(_Sub(h, path, body)) or {}


def _open_secrets(store, table, ident, row, col):
    """A row's JSON settings with each secret opened for its place (`ident` its number) -
    inside the daemon only, handed to the route that seals it again. [keys not opened]."""
    cfg = _jl(row.get(col)) if row else {}
    if not isinstance(cfg, dict):
        return {}, []
    out, lost = {}, []
    for k, v in cfg.items():
        if isinstance(v, str) and v.startswith('sealed:'):
            plain = E.unseal_secret(v, '%s:%s:%s' % (table, ident, k))
            if plain is None:
                lost.append(k)
                continue
            out[k] = plain
        else:
            out[k] = v
    return out, lost


def _blank_secrets(store, table, row, col):
    """The settings with every secret "" - the one kept stays (config_seal)."""
    cfg = _jl(row.get(col)) if row else {}
    if not isinstance(cfg, dict):
        return {}
    keys, _ = _secret_keys(store, table, row)
    return {k: ('' if (k in keys or (isinstance(v, str) and v.startswith('sealed:'))) else v)
            for k, v in cfg.items()}


def body_for(store, table, row, ident, current=None, secrets=True):
    """(path, body, lost secrets) - what the route that saves this kind of object is given
    to make it again as `row` says (`current`: the row it changes, None - a new one)."""
    lost = []
    j = lambda k, d=None: _jl(row.get(k)) if row.get(k) not in (None, '') else d  # noqa: E731
    if table in S.FAMILY_OF:
        fam = S.FAMILY_OF[table]
        if secrets:
            cfg, lost = _open_secrets(store, table, ident, row, 'config')
        else:
            cfg = _blank_secrets(store, table, row, 'config')
        b = {'name': row.get('name'), 'kind': row.get('kind'), 'config': cfg,
             'enabled': row.get('enabled', 1), 'note': row.get('note') or ''}
        if fam == 'target':
            b['tags'] = j('tags', []) or []
        if fam in ('target', 'check') and 'owner' in row:
            b['owner'] = row.get('owner') or ''
        if current:
            b['id'] = current['id']
        path = {'issuer': 'sources', 'challenge': 'validations', 'target': 'targets',
                'check': 'tests'}[fam]
        return '/api/%s/save' % path, b, lost
    if table == 'cert_deploys':
        if secrets:
            opts, lost = _open_secrets(store, table, ident, row, 'options')
        else:
            opts = _blank_secrets(store, table, row, 'options')
        b = {'cert_id': row.get('cert_id'), 'target': row.get('target'), 'options': opts,
             'enabled': row.get('enabled', 1), 'note': row.get('note') or ''}
        if row.get('position') is not None:
            b['position'] = row.get('position')
        if current:
            b['id'] = current['id']
        return '/api/deploys/save', b, lost
    if table == 'certs':
        b = {'name': row.get('name'), 'names': j('names', []) or [],
             'key_type': row.get('key_type') or 'ec-256', 'issuer': row.get('issuer') or '',
             'challenge': row.get('challenge') or '', 'challenge_map': j('challenge_map', {}) or {},
             'auto_renew': row.get('auto_renew', 1), 'renew_days': row.get('renew_days'),
             'reuse_key': row.get('reuse_key') or 0, 'profile': j('profile', {}) or {},
             'tags': j('tags', []) or [], 'note': row.get('note') or '',
             'owner': row.get('owner') or '', 'enabled': row.get('enabled', 1)}
        if row.get('key_type_alt'):
            b['key_type_alt'] = row.get('key_type_alt')
        if row.get('csr_from'):
            b['csr_from'] = row.get('csr_from')
        if current:
            b['id'] = current['id']
        else:
            b['hold'] = 1
        return '/api/certs/save', b, lost
    if table == 'cert_teams':
        b = {'name': row.get('name'), 'kind': row.get('kind') or 'team',
             'members': j('members', []) or [], 'contact_mail': row.get('contact_mail') or '',
             'contact_phone': row.get('contact_phone') or '', 'note': row.get('note') or '',
             'parent': row.get('parent') or '', 'policy': j('policy', None),
             'description': row.get('description') or ''}
        if current:
            b['old_name'] = current['name']
        return '/api/teams/save', b, lost
    if table == 'cert_roles':
        b = {'name': row.get('name'), 'description': row.get('description') or '',
             'caps': j('caps', []) or []}
        if current:
            b['old_name'] = current['name']
        return '/api/roles/save', b, lost
    if table == 'cert_tags':
        b = {'name': row.get('name'), 'colour': row.get('colour') or 'dim',
             'description': row.get('description') or ''}
        if current:
            b['old_name'] = current['name']
        return '/api/tags/save', b, lost
    if table == 'cert_req_profiles':
        cfg = j('config', {}) or {}
        b = dict(cfg if isinstance(cfg, dict) else {})
        b.update({'name': row.get('name'), 'description': row.get('description') or '',
                  'enabled': row.get('enabled', 1)})
        if current:
            b['old_name'] = current['name']
        return '/api/reqprofiles/save', b, lost
    if table == 'dns_sets':
        b = {'name': row.get('name'), 'servers': row.get('servers') or '',
             'protocol': row.get('protocol') or 'udp', 'tls_name': row.get('tls_name') or '',
             'timeout': row.get('timeout_s'), 'note': row.get('note') or ''}
        if current:
            b['old_name'] = current['name']
        return '/api/dnssets/save', b, lost
    if table == 'dns_set_uses':
        return '/api/dnssets/assign', {'purpose': row.get('purpose'),
                                       'set': row.get('set_name')}, lost
    if table == 'dns_records':
        b = {'name': row.get('name'), 'rtype': row.get('rtype'), 'value': row.get('value'),
             'ttl': row.get('ttl'), 'note': row.get('note') or ''}
        if current:
            b['id'] = current['id']
        return '/api/dns/record', b, lost
    if table == 'cert_checks':
        return '/api/checks/attach', {'cert_id': row.get('cert_id'), 'test': row.get('test'),
                                      'after_target': row.get('after_target') or ''}, lost
    raise ValueError('a %s cannot be restored' % WORDS.get(TYPES.get(table, ('?',))[0], table))


def _route_id(table, got, row):
    """The number of what the route made."""
    if not isinstance(got, dict):
        return None
    for k in ('id',):
        if isinstance(got.get(k), int):
            return got[k]
    for k in ('team', 'role', 'tag', 'profile', 'set'):
        if isinstance(got.get(k), dict) and got[k].get('id'):
            return int(got[k]['id'])
    if isinstance(got.get('ids'), list) and got['ids']:
        return int(got['ids'][0])
    return None


def _find_new(store, table, row, name=None):
    col = TYPES[table][1]
    if table == 'cert_deploys':
        r = store.db.row('SELECT id FROM cert_deploys WHERE cert_id = ? AND target = ? ORDER BY '
                         'id DESC', (row.get('cert_id'), row.get('target')))
    elif table == 'cert_checks':
        r = store.db.row('SELECT id FROM cert_checks WHERE cert_id = ? AND test = ? ORDER BY '
                         'id DESC', (row.get('cert_id'), row.get('test')))
    elif col:
        r = store.db.row('SELECT id FROM %s WHERE %s = ? ORDER BY id DESC' % (table, col),
                         (name or row.get(col),))
    else:
        r = None
    return (r or {}).get('id')


def _err(e):
    if isinstance(e, E.ApiError):
        return str(e)
    return str(e).strip('\'"') or type(e).__name__


def restore_version(store, h, s, entry_id, secrets=False):
    """The object as it was after that change, saved by its own route."""
    install()
    r = store.db.row('SELECT * FROM %s WHERE id = ?' % HIST, (int(entry_id),))
    if not r:
        raise LookupError('there is no such entry of the history')
    table, otype = r['otable'], r['otype']
    if not may_see(store, s, otype, r.get('owner'), team=_team_of(store, r)):
        raise E.ApiError(403, 'you may not see the history of that %s' % WORDS.get(otype, otype))
    if r.get('action') == 'delete' or not r.get('now_v'):
        raise ValueError('that was a deletion - what was deleted is in the trash')
    if not may_restore_version(store, s, otype, r.get('owner')):
        raise E.ApiError(403, 'you may not change that %s' % WORDS.get(otype, otype))
    current = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (int(r['oid']),))
    if not current:
        raise ValueError('it is not here any more - restore it from the trash first')
    want = _snap(r['now_v']) or {}
    row = dict(current)
    row.update(want)
    if table == 'certs':
        row = dict(current, **{k: want.get(k) for k in CERT_CONFIG if k in want})
    path, body, lost = body_for(store, table, row, int(r['oid']), current=current,
                                secrets=bool(secrets))
    ctx = getattr(_TL, 'ctx', None)
    if ctx is not None:
        ctx.action = 'restore'
        ctx.note = 'the version of %s restored' % time.strftime('%Y-%m-%d %H:%M',
                                                                time.localtime(r['ts']))
    got = call_route(h, path, body)
    store.add_event('certificates', 'the %s %s: the version of %s restored by %s' % (
        WORDS.get(otype, otype), r.get('oname') or '', time.strftime(
            '%Y-%m-%d %H:%M', time.localtime(r['ts'])), str(s.get('name') or '?')),
        who=str(s.get('name') or ''))
    return {'ok': True, 'message': 'restored', 'lost': lost, 'route': got.get('message') or ''}


def preview_version(store, s, entry_id):
    r = store.db.row('SELECT * FROM %s WHERE id = ?' % HIST, (int(entry_id),))
    if not r:
        raise LookupError('there is no such entry of the history')
    if not may_see(store, s, r['otype'], r.get('owner'), team=_team_of(store, r)):
        raise E.ApiError(403, 'you may not see that')
    current = store.db.row('SELECT * FROM %s WHERE id = ?' % r['otable'], (int(r['oid']),))
    # what it is now is shown too: only to who may see it as it is now (a certificate given to
    # another team since)
    if current and not may_see(store, s, r['otype'], _owner_of(store, r['otable'], current),
                               team=_team_of(store, r)):
        raise E.ApiError(403, 'you may not see that')
    want = _snap(r.get('now_v'))
    if not current or want is None:
        return {'changes': [], 'exists': bool(current)}
    target = dict(current)
    target.update(want)
    changes = diff(store, r['otable'], current, target)
    return {'changes': changes, 'exists': True,
            'secrets': [c['label'] for c in changes if c.get('secret')],
            'can_restore': may_restore_version(store, s, r['otype'], r.get('owner'))}


# ---------------------------------------------------------------------------
# The trash
# ---------------------------------------------------------------------------
def _trash_public(store, s, r, kids=None):
    return {'id': r['id'], 'ts': r.get('ts'), 'type': r.get('otype'),
            'words': WORDS.get(r.get('otype'), r.get('otype')), 'oid': r.get('oid'),
            'name': r.get('oname') or '', 'who': r.get('who') or '', 'ip': r.get('ip') or '',
            'owner': r.get('owner') or '', 'detail': r.get('detail') or '',
            'expires': r.get('expires'),
            'children': [{'id': k['id'], 'type': k.get('otype'),
                          'words': WORDS.get(k.get('otype'), k.get('otype')),
                          'name': k.get('oname') or ''} for k in (kids or [])],
            'can_restore': may_restore_trash(store, s, r.get('otype'), r.get('owner')),
            'can_purge': full(s)}


def trash_list(store, s, otype='', who='', since=0, q=''):
    install()
    purge(store)
    t = _now()
    # what ran out is never shown, whenever the purge last went by
    rows = store.db.rows('SELECT * FROM %s WHERE (expires IS NULL OR expires >= ?) AND ts >= ? '
                         'ORDER BY ts DESC, id DESC' % TRASH, (t, t - trash_days() * 86400 - 1))
    kids = {}
    for r in rows:
        if r.get('parent'):
            kids.setdefault(r['parent'], []).append(r)
    top = [r for r in rows if not r.get('parent')]
    seen = [r for r in top if may_restore_trash(store, s, r.get('otype'), r.get('owner'))
            or full(s)]
    types, people = {}, set()
    for r in seen:
        types[r['otype']] = types.get(r['otype'], 0) + 1
        if r.get('who'):
            people.add(r['who'])
    out = [r for r in seen
           if (not otype or r['otype'] == otype) and (not who or _low(r.get('who')) == _low(who))
           and (not since or float(r.get('ts') or 0) >= float(since))
           and (not q or _low(q) in _low(r.get('oname')) or _low(q) in _low(r.get('detail')))]
    return {'items': [_trash_public(store, s, r, kids.get(r['id'])) for r in out[:1000]],
            'types': types, 'people': sorted(people, key=_low), 'days': trash_days(),
            'keep_days': keep_days(), 'can_purge': full(s), 'total': len(seen)}


def _trash_get(store, ident):
    r = store.db.row('SELECT * FROM %s WHERE id = ?' % TRASH, (int(ident),))
    if not r or (r.get('expires') and float(r['expires']) < _now()):
        raise LookupError('it is not in the trash (any more)')
    return r


def _row_of(r):
    got = _snap(r.get('row_v')) or {}
    return got


def _taken(store, table, name):
    col = TYPES[table][1]
    if not col or not name:
        return None
    if table == 'dns_set_uses':
        return None
    r = store.db.row('SELECT id, %s FROM %s WHERE LOWER(%s) = ?' % (col, table, col), (_low(name),))
    return r


def suggest_name(store, table, name):
    """A name free here for what comes back: "web1 2", "web1 3"... (as a copy is named)."""
    base = re.sub(r'\s+\d{1,3}$', '', str(name or '')).strip() or 'restored'
    sep = '-' if table == 'cert_tags' else ' '
    for n in range(2, 200):
        cand = ('%s%s%d' % (base[:110], sep, n))
        if not _taken(store, table, cand):
            return cand
    return '%s%s%s' % (base[:100], sep, uuid.uuid4().hex[:6])


def _needs(store, table, row):
    """What must be here before it can come back: [(trash id | None, words)]."""
    out = []
    if table in ('cert_deploys', 'cert_checks'):
        if not store.db.row('SELECT id FROM certs WHERE id = ?', (int(row.get('cert_id') or 0),)):
            out.append((None, 'its certificate is not here any more'))
    if table == 'cert_deploys' and row.get('target'):
        if not S.plugin_row(store, 'target', row['target']):
            t = store.db.row('SELECT id FROM %s WHERE otable = ? AND oname = ? AND parent IS NULL '
                             'ORDER BY id DESC' % TRASH, ('cert_targets', row['target']))
            out.append(((t or {}).get('id'), 'the target %s is not here' % row['target']))
    if table == 'cert_checks' and row.get('test'):
        if not S.plugin_row(store, 'check', row['test']):
            t = store.db.row('SELECT id FROM %s WHERE otable = ? AND oname = ? AND parent IS NULL '
                             'ORDER BY id DESC' % TRASH, ('cert_tests', row['test']))
            out.append(((t or {}).get('id'), 'the test %s is not here' % row['test']))
    if table == 'cert_teams' and row.get('parent'):
        from acmelib.certs import teams as T
        if not T.team_get(store, row['parent']):
            t = store.db.row('SELECT id FROM %s WHERE otable = ? AND LOWER(oname) = ? AND parent '
                             'IS NULL ORDER BY id DESC' % TRASH, ('cert_teams', _low(row['parent'])))
            out.append(((t or {}).get('id'), 'the team above it, %s, is not here' % row['parent']))
    if table == 'dns_set_uses':
        pass
    return out


def trash_preview(store, s, ident):
    install()
    r = _trash_get(store, ident)
    if not (full(s) or may_restore_trash(store, s, r['otype'], r.get('owner'))):
        raise E.ApiError(403, 'you may not see that')
    table = r['otable']
    row = _row_of(r)
    kids = store.db.rows('SELECT * FROM %s WHERE parent = ? ORDER BY id' % TRASH, (r['id'],))
    notes = []
    col = TYPES[table][1]
    conflict = None
    if col and table != 'dns_set_uses':
        other = _taken(store, table, row.get(col))
        if other:
            conflict = {'name': row.get(col), 'suggestion': suggest_name(store, table, row.get(col))}
    if table == 'certs':
        notes.append('It comes back as a request, not issued: its key and its certificates were '
                     'not kept - Issue now issues a new one.')
    if table == 'cert_targets' and str(row.get('kind') or '') in ('agent', 'agent_windows'):
        notes.append('Its agent was let go when it was deleted: pair the agent again after.')
    if table == 'cert_issuers':
        notes.append('An account it had at its CA is used again when it opens; else a new one '
                     'is made at the first certificate.')
    secrets = []
    scol = S.JSON_SECRET_COLS.get(table)
    if scol:
        keys, _ = _secret_keys(store, table, row)
        secrets = sorted(keys)
    needs = [{'trash_id': n[0], 'words': n[1]} for n in _needs(store, table, row)]
    kid_out = []
    for k in kids:
        kr = _row_of(k)
        kn = [n[1] for n in _needs(store, k['otable'], kr)
              if not (k['otable'] in ('cert_deploys', 'cert_checks') and
                      'certificate' in n[1] and table == 'certs')]
        kid_out.append({'id': k['id'], 'type': k['otype'], 'words': WORDS.get(k['otype']),
                        'name': k.get('oname') or '', 'needs': kn})
    fields = []
    for k, v in sorted(snapshot(table, row).items()):
        if k in ('id',) or v in (None, '', '{}', '[]'):
            continue
        val = _jl(v)
        if k == scol and isinstance(val, dict):
            val = {kk: (S.SECRET_DOTS if kk in secrets or (isinstance(vv, str) and
                                                           vv.startswith('sealed:')) else vv)
                   for kk, vv in val.items()}
        fields.append({'field': k, 'value': _masked_deep(_shown(val))})
    return {'item': _trash_public(store, s, r, kids), 'fields': fields, 'children': kid_out,
            'conflict': conflict, 'notes': notes, 'needs': needs, 'secrets': secrets}


def _restore_one(store, h, s, r, name=None, cert_map=None):
    """One entry of the trash brought back by its route -> (new id, [words])."""
    table = r['otable']
    row = dict(_row_of(r))
    said = []
    col = TYPES[table][1]
    if name and col:
        row[col] = name
    if cert_map and table in ('cert_deploys', 'cert_checks') and \
            str(row.get('cert_id')) in cert_map:
        row['cert_id'] = cert_map[str(row['cert_id'])]
    if table == 'cert_deploys':
        if store.db.row('SELECT id FROM cert_deploys WHERE cert_id = ? AND target = ?',
                        (row.get('cert_id'), row.get('target'))):
            raise ValueError('the certificate is deployed on %s already' % row.get('target'))
    if table == 'cert_checks':
        if store.db.row('SELECT id FROM cert_checks WHERE cert_id = ? AND test = ?',
                        (row.get('cert_id'), row.get('test'))):
            raise ValueError('the test %s is attached already' % row.get('test'))
    if table == 'dns_set_uses':
        # a function that asks another set since keeps it
        if store.db.row('SELECT id FROM dns_set_uses WHERE purpose = ?', (row.get('purpose'),)):
            return None, []
    path, body, lost = body_for(store, table, row, int(r['oid']), current=None, secrets=True)
    if lost:
        said.append('%s could not be opened - enter it again' % ', '.join(lost))
    got = call_route(h, path, body)
    new = _route_id(table, got, row) or _find_new(store, table, row, row.get(col) if col else None)
    if new and table in S.FAMILY_OF and row.get('state') not in (None, '', '{}') and \
            not (table == 'cert_targets' and str(row.get('kind') or '') in ('agent',
                                                                            'agent_windows')):
        # the module's own memory (an account at its CA), as it was
        store.db.update(table, int(new), {'state': row['state']})
    if table == 'cert_teams' and new and (row.get('extras') or row.get('hooks_sealed')):
        # its governance (separation of duties, reviews, temporary roles, channels) and its
        # webhooks sealed again for its new number (hunt f1): the route saving a team takes
        # neither, and a team came back without its rules
        _team_extras_back(store, int(new), int(r['oid']), row)
    if table == 'cert_checks' and new and int(row.get('enabled', 1) or 0) == 0:
        call_route(h, '/api/checks/switch', {'id': new, 'enabled': False})
    meta = _snap(r.get('meta'))
    if meta and new:
        try:
            if table == 'cert_tests':
                from acmelib.certs import checks as C
                C.test_meta_in(store, row.get('name'), meta)
        except Exception:                               # noqa: BLE001
            pass
    if new:
        # its history follows it to its new number
        store.db.run('UPDATE %s SET oid = ? WHERE otable = ? AND oid = ?' % HIST,
                     (int(new), table, int(r['oid'])))
    return new, said


def _team_extras_back(store, new, old, row):
    ch = {}
    if row.get('extras'):
        ch['extras'] = row['extras']
    raw = row.get('hooks_sealed')
    if raw:
        place = 'cert_teams:%s:hooks_sealed'
        plain = E.unseal_secret(raw, place % old) if str(raw).startswith(E.SEALED2) else \
            E.unseal_secret(raw)
        if plain:
            ch['hooks_sealed'] = E.seal_secret(plain, place % new)
    if ch:
        store.db.update('cert_teams', new, ch)
        try:
            from acmelib.certs import teams as T
            T.changed()
        except Exception:                               # noqa: BLE001
            pass


def trash_restore(store, h, s, ident, name=None, with_needs=False):
    install()
    r = _trash_get(store, ident)
    if r.get('parent'):
        raise ValueError('it comes back with what it was deleted with - restore that')
    if not may_restore_trash(store, s, r['otype'], r.get('owner')):
        raise E.ApiError(403, 'you may not restore that %s' % WORDS.get(r['otype'], r['otype']))
    table = r['otable']
    row = _row_of(r)
    ctx = getattr(_TL, 'ctx', None)
    if ctx is not None:
        ctx.action = 'restore'
        ctx.note = 'restored from the trash'
    col = TYPES[table][1]
    if name is not None:
        name = str(name).strip()
        if not name:
            raise ValueError('give it a name')
    if col and table != 'dns_set_uses':
        other = _taken(store, table, name or row.get(col))
        if other:
            raise E.ApiError(409, 'there is a %s called %s already - restore it under another '
                                  'name' % (WORDS.get(r['otype']), name or row.get(col)),
                             extra={'suggestion': suggest_name(store, table,
                                                               name or row.get(col))})
    done = []
    for tid, words in _needs(store, table, row):
        if tid and with_needs:
            trash_restore(store, h, s, tid)
            done.append(words)
        else:
            raise ValueError('%s - %s' % (words, 'restore it first' if tid else
                                          'it cannot come back'))
    new, said = _restore_one(store, h, s, r, name=name)
    kids = store.db.rows('SELECT * FROM %s WHERE parent = ? ORDER BY id' % TRASH, (r['id'],))
    cert_map = {str(r['oid']): new} if table == 'certs' and new else {}
    back, left = [], []
    for k in kids:
        kr = _row_of(k)
        try:
            for tid, words in _needs(store, k['otable'],
                                     dict(kr, cert_id=cert_map.get(str(kr.get('cert_id')),
                                                                   kr.get('cert_id')))):
                if tid and with_needs:
                    trash_restore(store, h, s, tid)
                elif not tid or not with_needs:
                    raise ValueError(words)
            kid_new, ks = _restore_one(store, h, s, k, cert_map=cert_map)
            said.extend(ks)
            back.append(k.get('oname') or WORDS.get(k['otype']))
            store.db.run('DELETE FROM %s WHERE id = ?' % TRASH, (k['id'],))
        except (ValueError, LookupError, E.ApiError) as e:
            left.append('%s: %s' % (k.get('oname') or WORDS.get(k['otype']), _err(e)))
            # left in the trash on its own - naming the certificate by its number now (hunt
            # f1): with the old one it could never come back ("its certificate is not here")
            upd = {'parent': None}
            if k['otable'] in ('cert_deploys', 'cert_checks') and \
                    str(kr.get('cert_id')) in cert_map:
                upd['row_v'] = json.dumps(dict(kr, cert_id=cert_map[str(kr['cert_id'])]),
                                          default=str)
            store.db.update(TRASH, k['id'], upd)
    store.db.run('DELETE FROM %s WHERE id = ?' % TRASH, (r['id'],))
    who = str(s.get('name') or '?')
    store.add_event('certificates', 'the %s %s restored from the trash by %s%s' % (
        WORDS.get(r['otype'], r['otype']), name or r.get('oname') or '', who,
        (' with %s' % ', '.join(back)) if back else ''), who=who)
    return {'ok': True, 'id': new, 'name': name or r.get('oname') or '', 'with': back,
            'left': left, 'said': said, 'needs_done': done,
            'message': '%s is back' % (name or r.get('oname') or WORDS.get(r['otype']))}


def trash_purge(store, s, ids=None, everything=False):
    if not full(s):
        raise E.ApiError(403, 'only a full administrator may empty the trash')
    n = 0
    if everything:
        n = int(store.db.run('DELETE FROM %s' % TRASH) or 0)
    else:
        for i in ids or []:
            try:
                i = int(i)
            except (TypeError, ValueError):
                raise ValueError('ids are numbers')
            n += int(store.db.run('DELETE FROM %s WHERE parent = ?' % TRASH, (i,)) or 0)
            n += int(store.db.run('DELETE FROM %s WHERE id = ?' % TRASH, (i,)) or 0)
    who = str(s.get('name') or '?')
    store.add_event('certificates', '%d item(s) deleted from the trash for good by %s' % (n, who),
                    'warn', who=who)
    return {'ok': True, 'deleted': n, 'message': '%d deleted for good' % n}


# ---------------------------------------------------------------------------
# Saved views (filter + sort + columns of a table), kept per person, team or for everybody
# ---------------------------------------------------------------------------
KEY_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,79}\Z')
CTL_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,60}\Z')
VIEWS_MOST = 50
SCOPES = ('user', 'team', 'global')


def _tkey(v):
    v = str(v or '').strip()
    if not KEY_RE.match(v):
        raise ValueError('the table is named by letters, digits and . _ : - (80 at most)')
    return v


def _str_list(v, most=200):
    if not isinstance(v, list):
        return []
    out, seen = [], set()
    for x in v[:most]:
        if isinstance(x, str) and 0 < len(x) <= 80 and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def clean_state(v):
    """{filters: {control id: value}, sort: {col, dir}, cols: {o, h, s, w}, key} - given as
    `view` (a body's `state` is a word, engine BODY_WORDS)."""
    if not isinstance(v, dict):
        raise ValueError('a view is an object')
    out = {}
    f = v.get('filters') if isinstance(v.get('filters'), dict) else {}
    filters = {}
    for k, x in list(f.items())[:40]:
        if not CTL_RE.match(str(k)):
            continue
        if isinstance(x, bool):
            filters[k] = x
        elif isinstance(x, (int, float)):
            filters[k] = str(x)
        elif isinstance(x, str):
            filters[k] = x[:500]
    out['filters'] = filters
    srt = v.get('sort') if isinstance(v.get('sort'), dict) else None
    if srt and isinstance(srt.get('col'), str) and srt.get('dir') in ('asc', 'desc'):
        out['sort'] = {'col': srt['col'][:80], 'dir': srt['dir']}
    c = v.get('cols') if isinstance(v.get('cols'), dict) else None
    if c:
        cols = {}
        for k in ('o', 'h', 's'):
            got = _str_list(c.get(k))
            if got:
                cols[k] = got
        if isinstance(c.get('w'), dict):
            w = {}
            for k, x in list(c['w'].items())[:200]:
                try:
                    n = float(x)
                except (TypeError, ValueError):
                    continue
                if isinstance(k, str) and len(k) <= 80 and 0 < n <= 5000:
                    w[k] = round(n)
            if w:
                cols['w'] = w
        if cols:
            out['cols'] = cols
    if isinstance(v.get('key'), str) and len(v['key']) <= 120:
        out['key'] = v['key']
    if len(json.dumps(out)) > 20000:
        raise ValueError('the view is too big')
    return out


def _team_views_scope(store, s):
    T = _teams()
    return T.scope_cap(store, s, 'team.view')


def _view_visible(store, s, r, sc=None):
    sc = sc if sc is not None else ('?' if r.get('scope') == 'team' else None)
    if r.get('scope') == 'global':
        return True
    if r.get('scope') == 'user':
        return _low(r.get('owner_user')) == _low(s.get('name'))
    if r.get('scope') == 'team':
        if full(s):
            return True
        if sc == '?':
            sc = _team_views_scope(store, s)
        return sc is None or _low(r.get('team')) in sc
    return False


def _view_mine(store, s, r):
    """May change or delete it."""
    if r.get('scope') == 'user':
        return _low(r.get('owner_user')) == _low(s.get('name'))
    if full(s):
        return True
    if r.get('scope') == 'team':
        sc = _team_views_scope(store, s)
        return _low(r.get('created_by')) == _low(s.get('name')) and \
            (sc is None or _low(r.get('team')) in sc)
    return False


def _default_key(s, tkey):
    return 'views:default:%s:%s' % (_low(s.get('name'))[:120], tkey)


def view_public(store, s, r):
    st = _snap(r.get('state')) or {}
    return {'id': r['id'], 'table': r.get('tbl'), 'name': r.get('name') or '',
            'scope': r.get('scope') or 'user', 'team': r.get('team') or '',
            'state': st, 'by': r.get('created_by') or '', 'updated': r.get('updated'),
            'mine': _view_mine(store, s, r)}


def views(store, s, tkey=None):
    """The views of one table this session sees, and which opens by itself - or (no table) of
    every table at once, for the page's first look: {views, default | defaults}."""
    tkey = _tkey(tkey) if tkey not in (None, '') else None
    if tkey:
        rows = store.db.rows('SELECT * FROM %s WHERE tbl = ? ORDER BY name' % VIEWS, (tkey,))
    else:
        rows = store.db.rows('SELECT * FROM %s ORDER BY tbl, name' % VIEWS)
    sc = _team_views_scope(store, s) if any(r.get('scope') == 'team' for r in rows) and \
        not full(s) else None
    seen = [r for r in rows if _view_visible(store, s, r, sc)]
    ids = {r['id'] for r in seen}
    pre = _default_key(s, '')
    defaults = {}
    # escaped (hunt w7): PostgreSQL and MariaDB took the backslash of CORP\novak for LIKE's
    # escape - the view that opens by itself was never found for such a name there
    for m in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ? ESCAPE '!'",
                           (E.like_escaped(pre) + '%',)):
        if not str(m['k']).startswith(pre):
            continue
        try:
            v = int(m['v'])
        except (TypeError, ValueError):
            continue
        if v in ids:
            defaults[m['k'][len(pre):]] = v
    T = _teams()
    if full(s):
        teams = [t['name'] for t in T.team_rows(store)]
    else:
        tsc = _team_views_scope(store, s)
        teams = [t['name'] for t in T.team_rows(store) if tsc is None or _low(t['name']) in tsc]
    out = {'views': [view_public(store, s, r) for r in seen], 'teams': teams,
           'can_global': full(s)}
    if tkey:
        out['default'] = defaults.get(tkey)
    else:
        out['defaults'] = defaults
    return out


def view_save(store, s, b):
    tkey = _tkey(b.get('table'))
    name = str(b.get('name') or '').strip()
    if not name or len(name) > 80:
        raise ValueError('a view has a name (80 characters at most)')
    scope = str(b.get('scope') or 'user')
    if scope not in SCOPES:
        raise ValueError('a view is yours, a team\'s or everybody\'s')
    team = ''
    if scope == 'team':
        T = _teams()
        t = T.team_get(store, b.get('team'))
        if not t:
            raise ValueError('there is no team %s' % str(b.get('team') or '')[:80])
        sc = _team_views_scope(store, s)
        if not (full(s) or sc is None or _low(t['name']) in sc):
            raise E.ApiError(403, 'a view is shared with a team only by those who may see the '
                                  'team (team.view)')
        team = t['name']
    if scope == 'global' and not full(s):
        raise E.ApiError(403, 'only a full administrator may make a view for everybody')
    state = clean_state(b.get('view') or {})
    who = str(s.get('name') or '?')[:190]
    t = _now()
    row = {'tbl': tkey, 'name': name, 'scope': scope, 'team': team or None,
           'owner_user': who if scope == 'user' else None,
           'state': json.dumps(state), 'updated': t, 'updated_by': who}
    old = None
    if b.get('id') not in (None, '', 0):
        old = store.db.row('SELECT * FROM %s WHERE id = ?' % VIEWS, (int(b['id']),))
        if not old or not _view_visible(store, s, old):
            raise LookupError('there is no such view')
        if not _view_mine(store, s, old):
            raise E.ApiError(403, 'that view is not yours to change')
        if old.get('scope') == 'user' and scope == 'user':
            row['owner_user'] = old.get('owner_user')
    clash = [r for r in store.db.rows('SELECT * FROM %s WHERE tbl = ? AND LOWER(name) = ?' %
                                      VIEWS, (tkey, _low(name)))
             if (not old or r['id'] != old['id']) and r.get('scope') == scope and
             (scope != 'user' or _low(r.get('owner_user')) == _low(who)) and
             (scope != 'team' or _low(r.get('team')) == _low(team))]
    if clash:
        raise ValueError('there is a view called %s already' % name)
    if old:
        store.db.update(VIEWS, old['id'], row)
        ident = old['id']
    else:
        n = store.db.value('SELECT COUNT(*) FROM %s WHERE tbl = ? AND (owner_user = ? OR '
                           'created_by = ?)' % VIEWS, (tkey, who, who), 0)
        if int(n or 0) >= VIEWS_MOST:
            raise ValueError('%d views of one table at most' % VIEWS_MOST)
        row.update(created=t, created_by=who)
        ident = store.db.insert(VIEWS, row)
    if b.get('default'):
        store.set_meta(_default_key(s, tkey), str(ident))
    r = store.db.row('SELECT * FROM %s WHERE id = ?' % VIEWS, (ident,))
    return {'view': view_public(store, s, r), 'message': 'the view %s was saved' % name}


def view_delete(store, s, ident):
    r = store.db.row('SELECT * FROM %s WHERE id = ?' % VIEWS, (int(ident),))
    if not r or not _view_visible(store, s, r):
        raise LookupError('there is no such view')
    if not _view_mine(store, s, r):
        raise E.ApiError(403, 'that view is not yours to delete')
    store.db.run('DELETE FROM %s WHERE id = ?' % VIEWS, (r['id'],))
    if store.get_meta(_default_key(s, r['tbl'])) == str(r['id']):
        store.db.run('DELETE FROM meta WHERE k = ?', (_default_key(s, r['tbl']),))
    return {'message': 'the view %s was deleted' % r['name']}


def view_default(store, s, tkey, ident):
    tkey = _tkey(tkey)
    if ident in (None, '', 0, '0'):
        store.db.run('DELETE FROM meta WHERE k = ?', (_default_key(s, tkey),))
        return {'default': None, 'message': 'no view opens by itself now'}
    r = store.db.row('SELECT * FROM %s WHERE id = ? AND tbl = ?' % VIEWS, (int(ident), tkey))
    if not r or not _view_visible(store, s, r):
        raise LookupError('there is no such view')
    store.set_meta(_default_key(s, tkey), str(r['id']))
    return {'default': r['id'], 'message': 'the view %s opens by itself now' % r['name']}
