# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- what happened to the cluster, written down (1.0.52) -------------------------------
# Every five seconds this node looks at what it can see - the VIP address
# here or not, its own health, the other node, replication both ways - and
# writes an event (kind 'ha') whenever one of them changes. Settings -
# High availability - History shows them, with what was changed by hand.
HA_SEEN = {}
PGLOG_ASK = 'pglog.ask'
PGLOG_FILE = 'pglog.json'


def _ha_change(store, key, now, words, level='warn'):
    """An event when `key` was something else before; nothing the first time."""
    was = HA_SEEN.get(key, '__first__')
    HA_SEEN[key] = now
    if was == '__first__' or was == now:
        return False
    store.add_event('ha', words, level)
    return True


def ha_planned_away(store):
    """{node: why} of the other nodes away on purpose now (1.0.56): a network job of theirs
    under way (asked, running, rebooting - its row, last come over, still names it; a job not
    moving for NET_JOB_LIVE_S is not), or a restart of a power plan going. A re-addressing
    stops replication from the node for a minute or two and restarts it - asked for, not a
    failure."""
    out = {}
    try:
        me = node_name()
        plan = power_plan(store)
        for n in ha_nodes(store):
            name = n['name']
            if name == me:
                continue
            if net_job_active(_meta_json(store, 'net:job:' + name)):
                out[name] = '%s is changing its network' % name
                continue
            row = _meta_obj(store, 'power:node:' + name)
            try:
                moved = float(row.get('moved') or row.get('at') or 0)
            except (TypeError, ValueError):
                moved = 0.0
            if plan and row.get('id') == plan.get('id') and row.get('state') == 'going' and \
                    time.time() - moved < 900:
                out[name] = '%s is restarting' % name
    except Exception:                                   # noqa: BLE001
        return {}
    return out


def ha_watch_tick(store):
    me = node_name()
    if not CONFIG.get('ha_mode'):
        return
    v = vip_conf(store)
    if v.get('on'):
        try:
            role = VIP_ROLE.read_text().split()[0]
        except (OSError, IndexError):
            role = ''
        held = vip_here(v.get('address')) if role else False
        why = VIP_HEALTH.get('why') or ''
        _ha_change(store, 'vip', 'here' if held else 'not',
                   ('the VIP address %s came to %s%s' % (v.get('address'), me,
                                                           ' (%s)' % role if role else '')) if held
                   else ('the VIP address %s left %s%s' % (
                       v.get('address'), me, ' - %s' % why if why else
                       (' (%s)' % role if role else ''))))
        ok = VIP_HEALTH.get('ok')
        if ok is not None:
            _ha_change(store, 'health', 'ok' if ok else 'bad',
                       ('%s is healthy again: the VIP address may come back to it' % me) if ok
                       else ('%s is not healthy - %s: the VIP address leaves it' % (me, why or '?')),
                       # Maintenance asked for is not a failure (1.0.56): warn, not bad.
                       'info' if ok else ('warn' if why == 'in maintenance' else 'bad'))
    else:
        HA_SEEN.pop('vip', None)
        HA_SEEN.pop('health', None)
    # The other nodes away on purpose (1.0.56): a re-addressing or a restart asked for said
    # as expected (warn), not as a failure (bad) - the alerts mailed every one of them.
    planned = ha_planned_away(store)
    for n in ha_nodes(store):
        if n['me']:
            continue
        _ha_change(store, 'node:' + n['name'], 'alive' if n.get('alive') else 'gone',
                   ('%s answers again (seen from %s)' % (n['name'], me)) if n.get('alive')
                   else ('%s stopped answering (seen from %s, last heard %d s ago)%s'
                         % (n['name'], me, int(n.get('age') or 0),
                            (' - expected: %s' % planned[n['name']]) if n['name'] in planned
                            else '')),
                   'info' if n.get('alive') else ('warn' if n['name'] in planned else 'bad'))
        m = bool((n.get('maintenance')))
        _ha_change(store, 'maint:' + n['name'], 'on' if m else 'off',
                   '%s %s maintenance' % (n['name'], 'went into' if m else 'came out of'), 'info')
    if CONFIG.get('ha_mode') != 'replicated':
        return
    r = ha_repl_state(store)
    if r.get('trouble'):
        return
    why_planned = '; '.join(planned[k] for k in sorted(planned))
    for x in r.get('incoming') or []:
        name = x.get('name')
        state = 'running' if x.get('running') else ('paused' if not x.get('enabled') else 'stopped')
        _ha_change(store, 'in:' + name, state,
                   'replication coming in (%s): %s' % (name, {
                       'running': 'running again', 'paused': 'paused',
                       'stopped': ('stopped - expected while %s; it starts again by itself once '
                                   'that is over' % why_planned) if why_planned else
                                  ('stopped - the other node or its PostgreSQL is not reached, '
                                   'or an error stops it')}[state]),
                   {'running': 'info', 'paused': 'warn'}.get(
                       state, 'warn' if why_planned else 'bad'))
        errs = int(x.get('apply_errors') or 0) + int(x.get('sync_errors') or 0)
        was = HA_SEEN.get('err:' + name)
        HA_SEEN['err:' + name] = errs
        if was is not None and errs > was:
            store.add_event('ha', 'replication coming in (%s): %d new error(s), %d in all - '
                                  'Settings - High availability - the errors say what'
                                  % (name, errs - was, errs), 'bad')
    for x in r.get('outgoing') or []:
        _ha_change(store, 'out:' + x['name'], x.get('wal_status') or '',
                   'replication going out (%s): %s' % (x['name'], {
                       'lost': 'LOST - the other node waited too long and has to be rebuilt',
                       'unreserved': 'about to be lost - the other node is far behind',
                       'extended': 'the other node is behind', 'reserved': 'caught up'}.get(
                           x.get('wal_status'), x.get('wal_status') or '?')),
                   'bad' if x.get('wal_status') in ('lost', 'unreserved') else 'info')


def ha_history(store, limit=300, since=0, until=0):
    """The cluster's story: what this watch saw and what was done by hand."""
    span, args = '', []
    cleared = float(store.get_meta('ha:history_cleared') or 0)
    since = max(float(since or 0), cleared)
    if since:
        span += ' AND ts >= ?'
        args.append(float(since))
    if until:
        span += ' AND ts < ?'
        args.append(float(until))
    rows = store.db.rows(
        "SELECT ts, kind, node, level, who, words FROM events WHERE (kind = 'ha' OR "
        "(kind = 'settings' AND (words LIKE '%VIP address%' OR words LIKE '%replication%' OR "
        "words LIKE '%maintenance%' OR words LIKE '%rebuilt%' OR words LIKE '%cluster%' OR "
        "words LIKE '%upgrade%') AND words NOT LIKE '%certificate%' AND "
        "words NOT LIKE '%TLS%'))" + span +
        " ORDER BY ts DESC LIMIT " + str(int(limit)), args)
    for r in rows:
        w = (r.get('words') or '').lower()
        r['what'] = ('vip' if 'VIP address' in w else 'replication' if 'replication' in w
                     or 'rebuilt' in w else 'maintenance' if 'maintenance' in w or 'upgrade' in w
                     else 'node')
    return rows


# ---- replication's errors: counted since cleared, read from PostgreSQL's log -----------
def repl_errors(store, ask_log=True):
    """The errors of each subscription since they were last cleared, and what
    PostgreSQL's log says about them (root reads it: the log is postgres's)."""
    r = ha_repl_state(store)
    base = _json_meta(store, 'ha:errbase:' + node_name()) or {}
    subs = []
    for x in r.get('incoming') or []:
        b = base.get(x['name']) or {}
        subs.append({'name': x['name'], 'running': x.get('running'), 'enabled': x.get('enabled'),
                     'apply': int(x.get('apply_errors') or 0),
                     'sync': int(x.get('sync_errors') or 0),
                     'apply_new': max(0, int(x.get('apply_errors') or 0) - int(b.get('apply') or 0)),
                     'sync_new': max(0, int(x.get('sync_errors') or 0) - int(b.get('sync') or 0)),
                     'cleared': base.get('at'), 'cleared_by': base.get('by')})
    got = {}
    if ask_log and WEB_DIR.is_dir():
        ask = WEB_DIR / PGLOG_ASK
        t0 = time.time()
        try:
            ask.write_text(json.dumps({'at': t0, 'port': int(CONFIG.get('db_port') or 5432)}))
        except OSError:
            pass
        while time.time() - t0 < 8:
            got = _pglog_read()
            if float(got.get('at') or 0) >= t0:
                break
            time.sleep(0.4)
    else:
        got = _pglog_read()
    since = float(base.get('at') or 0)
    lines = [e for e in got.get('entries') or [] if float(e.get('ts') or 0) >= since or
             not e.get('ts')]
    return {'subs': subs, 'log': lines[-60:], 'log_at': got.get('at'),
            'log_file': got.get('file') or '', 'log_said': got.get('said') or '',
            'fresh': float(got.get('at') or 0) >= time.time() - 15}


def _pglog_read():
    try:
        fd = os.open(str(WEB_DIR / PGLOG_FILE), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(1 << 20).decode('utf-8', 'replace'))
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def repl_errors_clear(store, by):
    r = ha_repl_state(store)
    base = {'at': time.time(), 'by': by}
    for x in r.get('incoming') or []:
        base[x['name']] = {'apply': int(x.get('apply_errors') or 0),
                           'sync': int(x.get('sync_errors') or 0)}
    store.set_meta('ha:errbase:' + node_name(), json.dumps(base))
    return base


