# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the database on this machine, shown as a database server (opt-in, 1.0.115) -------------
# Settings -> The database -> "Show this machine's database as a database server"
# (db_local_card, off by default). On, every node whose database is PostgreSQL or MariaDB on
# its own machine (localhost, 127.0.0.1, ::1 or a socket, no acme-db-agent) looks at it every
# 30 s by itself - with what it reads anyway: its own connection to it (as acme's own account,
# nothing more), /proc of this machine, the row of its database's certificate - and writes what
# it saw into its row of meta, 'dblocal:node:NODE'. The rows go to the other node as every
# node's rows of meta do (replicated, or the one database of a shared pair): nothing new is
# opened, asked or let in. GET /api/db-agent then has `local: [...]`, and the card of Settings
# -> The database draws a tile for each, as it does for a server with an agent.
#
# Off: nothing of it is read, written or said - GET /api/db-agent is as it was.

DBLOCAL_EVERY = float(os.environ.get('ACME_DBLOCAL_EVERY') or 30)
DBLOCAL_STATE = {'watching': False, 'wrote': None, 'at': 0.0}
DBLOCAL_LOCK = threading.Lock()


def db_local_on():
    """The setting: show this machine's database as a database server."""
    v = CONFIG.get('db_local_card')
    return bool(v) and str(v).strip().lower() not in ('0', 'false', 'off', 'no')


def db_local_here(c=None):
    """This node's database is PostgreSQL or MariaDB on this machine, and no agent looks after
    this node's database (with one, the card is the agent's)."""
    c = c or CONFIG
    if str(c.get('db_engine') or '') not in ('postgres', 'mariadb'):
        return False
    host = str(c.get('db_host') or '').strip()
    if not (host.startswith('/') or host.lower().strip('[]') in LOCAL_HOSTS):
        return False
    try:
        return not db_agent_on()
    except Exception:                                   # noqa: BLE001
        return False


def _db_local_disk(engine, data):
    """The disk of the database's data: its folder where acme's account may name it, else the
    usual place of the engine's data on this machine (statvfs only - nothing is read)."""
    places = ([data] if data else []) + (['/var/lib/pgsql', '/var/lib/postgresql']
                                         if engine == 'postgres' else ['/var/lib/mysql'])
    for p in places:
        try:
            s = os.statvfs(p)
        except (OSError, TypeError, ValueError):
            continue
        if s.f_blocks:
            return {'total': s.f_blocks * s.f_frsize, 'free': s.f_bavail * s.f_frsize}
    return None


def db_local_facts(store):
    """This machine and its database server, in the shape of an agent's facts (host, cpus, ram,
    avail, load, uptime, virtual, engine, running, version, ssl, started, connections, disk)."""
    db = store.db
    engine = str(db.engine or CONFIG.get('db_engine') or '')
    m = tune_machine({}, {})            # the machine, as the server's own settings read it
    f = {'host': socket.gethostname(), 'engine': engine, 'cpus': m.get('cpus'),
         'ram': m.get('ram'), 'avail': m.get('avail'), 'virtual': m.get('virtual')}
    try:
        f['load'] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        pass
    try:
        with open('/proc/uptime') as fh:
            f['uptime'] = float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    data = ''
    try:
        if engine == 'postgres':
            r = db.row("SELECT current_setting('server_version') AS v, current_setting('ssl') AS s, "
                       "current_setting('wal_level') AS w, "
                       "extract(epoch from pg_postmaster_start_time()) AS t, "
                       "(SELECT count(*) FROM pg_stat_activity) AS n") or {}
            f.update(running=True, version=str(r.get('v') or ''), ssl=str(r.get('s')) == 'on',
                     wal_level=str(r.get('w') or ''), started=float(r.get('t') or 0) or None,
                     connections=int(r.get('n') or 0))
            try:
                # Only where acme's account may read it (pg_read_all_settings): else the usual.
                data = str(db.value("SELECT current_setting('data_directory')") or '')
            except Exception:                           # noqa: BLE001
                data = ''
        else:
            r = db.row('SELECT VERSION() AS v, @@have_ssl AS s, @@datadir AS d') or {}
            f.update(running=True, version=str(r.get('v') or ''),
                     ssl=str(r.get('s') or '').upper() == 'YES')
            data = str(r.get('d') or '')
            st = {}
            for x in db.rows("SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime', "
                             "'Threads_connected')"):
                vals = list(x.values())
                if len(vals) >= 2:
                    st[str(vals[0])] = vals[1]
            if st.get('Uptime') not in (None, ''):
                f['started'] = round(time.time() - float(st['Uptime']))
            if st.get('Threads_connected') not in (None, ''):
                f['connections'] = int(st['Threads_connected'])
    except Exception as e:                              # noqa: BLE001
        f.update(running=False, said=str(e)[:200])
    disk = _db_local_disk(engine, data)
    if disk:
        f['disk'] = disk
    return f


def db_local_cert(store, node=None):
    """The certificate acme gave this node's PostgreSQL, and who renews it: Settings -> The
    database -> Encryption ('dbtls'), or the link between the databases ('link')."""
    n = node or node_name()
    hat = hatls_state(store, n) if CONFIG.get('ha_mode') == 'replicated' else {}
    if hat.get('step') == 'done' and hat.get('cert_end'):
        # the link's, renewed with it (Settings -> High availability), whatever else is kept
        return {'cert_end': hat.get('cert_end'), 'cert_by': 'link'}
    srv = _meta_obj(store, 'dbtls:server:' + n)
    if srv.get('cert_end'):
        return {'cert_end': srv.get('cert_end'), 'cert_by': 'dbtls'}
    return {'cert_end': None, 'cert_by': ''}


def db_local_look(store):
    """One look at this machine's database server, into this node's row (with the setting on
    and the database here only)."""
    if not (db_local_on() and db_local_here()):
        return None
    c = CONFIG
    engine = str(c.get('db_engine') or '')
    host = str(c.get('db_host') or '').strip() or 'localhost'
    port = int(c.get('db_port') or 0) or (3306 if engine == 'mariadb' else 5432)
    row = {'at': time.time(), 'node': node_name(), 'host': host, 'port': port,
           'engine': engine, 'facts': db_local_facts(store)}
    row.update(db_local_cert(store) if engine == 'postgres' else {'cert_end': None, 'cert_by': ''})
    store.set_meta('dblocal:node:' + node_name(), json.dumps(row, default=str))
    DBLOCAL_STATE.update(wrote=True, at=row['at'])
    return row


def db_local_drop(store):
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', ('dblocal:node:' + node_name(),))
    except Exception as e:                              # noqa: BLE001
        log_sparing('dblocal-drop', 'the row of this machine\'s database server: %s' % e,
                    'warn', every=3600)
    DBLOCAL_STATE['wrote'] = False


def db_local_watch(daemon):
    """A look every 30 s while the setting is on and the database here; this node's row taken
    away when it no longer is (once - nothing is touched while the setting stays off)."""
    with DBLOCAL_LOCK:
        if DBLOCAL_STATE.get('watching'):
            return
        DBLOCAL_STATE['watching'] = True
    while True:
        try:
            on = db_local_on()
            if on and db_local_here():
                if time.time() - DBLOCAL_STATE['at'] >= DBLOCAL_EVERY:
                    db_local_look(daemon.store)
            elif DBLOCAL_STATE['wrote'] or (on and DBLOCAL_STATE['wrote'] is None):
                db_local_drop(daemon.store)
        except Exception as e:                          # noqa: BLE001
            DBLOCAL_STATE['at'] = time.time()           # not again at once
            log_sparing('dblocal-watch', 'looking at this machine\'s database server: %s' % e,
                        'warn', every=600)
        time.sleep(3)


@hook('daemon_start')
def _db_local_start(daemon):
    threading.Thread(target=db_local_watch, args=(daemon,), name='dblocal', daemon=True).start()


def db_local_rows(store):
    """Every node's row: [{kind, name, node, me, at, stale, ok, host, port, engine, cert_end,
    cert_by, facts{...}}] - of the nodes of this cluster, heard from within a week."""
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'dblocal:node:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    try:
        nodes = set(host_nodes(store))
    except Exception:                                   # noqa: BLE001
        nodes = {node_name()}
    now = time.time()
    out = []
    for r in rows:
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        n = str(r['k'])[len('dblocal:node:'):]
        if not isinstance(v, dict) or n not in nodes:
            continue
        age = now - float(v.get('at') or 0)
        if age > 7 * 86400:
            continue
        v.update(kind='db', name='db:%s' % n, node=n, me=n == node_name(), ok=True,
                 stale=age > max(3 * DBLOCAL_EVERY, 120))
        out.append(v)
    out.sort(key=lambda x: (not x['me'], x['node']))
    return out


def db_local_into(store, view):
    """GET /api/db-agent with the setting on, no agent here: `local`, and for this node's own
    PostgreSQL whether its restart for settings waiting may be done from the pages."""
    if not db_local_on() or db_agent_on():
        return view
    rows = db_local_rows(store)
    for v in rows:
        if v['me'] and v.get('engine') == 'postgres' and db_local_here():
            try:
                waiting = tune_pending(store.db)
                if waiting:
                    ready = tune_restart_ready(store)
                    v['restart'] = {'may': bool(ready.get('may')), 'unit': ready.get('unit') or '',
                                    'waiting': waiting}
            except Exception:                           # noqa: BLE001
                pass
    view['local'] = rows
    return view
