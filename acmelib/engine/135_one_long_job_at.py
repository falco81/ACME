# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- one long job at a time, which the page asks after ---------------------
DB_JOB = {'id': 0, 'what': '', 'running': False, 'done': 0, 'whole': 0, 'says': '',
          'error': '', 'result': None, 'began': 0, 'ended': 0}
DB_JOB_LOCK = threading.Lock()


def db_job(what, work):
    with DB_JOB_LOCK:
        if DB_JOB['running']:
            raise ValueError('%s is going on already' % DB_JOB['what'])
        DB_JOB.update({'id': DB_JOB['id'] + 1, 'what': what, 'running': True, 'done': 0,
                       'whole': 0, 'says': '', 'error': '', 'result': None,
                       'began': time.time(), 'ended': 0})

    def progress(done, whole, says):
        DB_JOB.update({'done': done, 'whole': whole, 'says': says})
        if time.time() - DB_JOB.get('_pub', 0) > 1:
            DB_JOB['_pub'] = time.time()
            job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    def run():
        try:
            DB_JOB['result'] = work(progress)
        except Exception as e:
            DB_JOB['error'] = scrub_secret(str(e).split('\n')[0][:400])
            log('%s failed: %s' % (what, scrub_secret(e)), 'error')
        finally:
            DB_JOB.update({'running': False, 'ended': time.time()})
            job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    def beat():
        # Said again every half minute, so the other node - or this one,
        # after a restart - can tell a job going on from one that died.
        while DB_JOB.get('running'):
            time.sleep(30)
            if DB_JOB.get('running'):
                job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    threading.Thread(target=run, name='db-job', daemon=True).start()
    threading.Thread(target=beat, name='db-job-beat', daemon=True).start()
    return dict(DB_JOB)


def db_move(store, c, by):
    """Everything here into the other database, through a copy."""
    def work(progress):
        progress(0, 0, 'making a copy of what is here')
        began = time.time()
        before = store.counts()
        copy = make_backup(store, 'before moving, by %s' % by)
        whole = sum(before.values())
        far = db_open(c)
        tally = {}
        try:
            def along(table, done):
                tally[table] = done
                progress(sum(tally.values()), whole, '%s: %s' % (table, done))
            load_tables(far, copy, say=along)
            dbguard_resign(SimpleStore(far))       # the rows carried signed there (1.0.231)
            after = {t: int(far.value('SELECT COUNT(*) FROM %s' % t) or 0)
                     for t in TABLES if t != 'meta'}
            words = 'everything was carried into %s (%s), by %s' % (
                ENGINE_WORDS.get(c['db_engine']), db_where(c), by)
            store.add_event('settings', words, who=by)
            # What was written here while it was carried goes across too, the
            # move's own words with it (1.0.208): its newest event older than this
            # one's by more than a minute, "Start using it" refused the copy just
            # made, for good.
            try:
                for r in store.db.rows('SELECT ts, kind, node, level, who, words FROM events '
                                       'WHERE ts >= ? ORDER BY ts', (began,)):
                    far.insert('events', dict(r))
            except Exception as e:                      # noqa: BLE001
                log('the events of the move could not be carried as well: %s' % e, 'warn')
        finally:
            far.close()
        short = {t: (before.get(t, 0), after.get(t, 0)) for t in after
                 if after.get(t, 0) < before.get(t, 0) and t not in ('sessions',)}
        progress(whole, whole, 'done')
        return {'copy': copy.name, 'rows': sum(after.values()), 'short': short,
                'where': db_where(c)}
    return db_job('carrying everything across', work)


def db_where(c):
    if c.get('db_engine') == 'sqlite':
        return str(c.get('db_path') or DB_FILE)
    return '%s@%s:%s/%s' % (c.get('db_user'), c.get('db_host') or 'localhost',
                            c.get('db_port') or {'mariadb': 3306, 'postgres': 5432}
                            [c['db_engine']], c.get('db_name'))


# ---- looking after the one in use --------------------------------------------
def db_table_sizes(db):
    """Rows and bytes of every table, as far as the engine says."""
    out = []
    sizes = {}
    try:
        if db.engine == 'mariadb':
            for r in db.rows('SELECT TABLE_NAME AS t, DATA_LENGTH + INDEX_LENGTH AS b, '
                             'DATA_FREE AS f FROM information_schema.TABLES '
                             'WHERE TABLE_SCHEMA = DATABASE()'):
                sizes[r['t']] = (int(r['b'] or 0), int(r['f'] or 0))
        elif db.engine == 'postgres':
            for t in TABLES:
                sizes[t] = (int(db.value('SELECT pg_total_relation_size(?)', (t,)) or 0), 0)
        else:
            try:
                for r in db.rows('SELECT name AS t, SUM(pgsize) AS b FROM dbstat GROUP BY name'):
                    sizes[r['t']] = (int(r['b'] or 0), 0)
            except Exception:
                pass
    except Exception:
        pass
    for t in TABLES:
        try:
            n = int(db.value('SELECT COUNT(*) FROM %s' % t) or 0)
        except Exception:
            n = 0
        b, free = sizes.get(t, (None, 0))
        out.append({'table': t, 'rows': n, 'bytes': b, 'free': free})
    return out


def db_free_inside(db):
    """Room the engine holds that it would give back to the disk."""
    try:
        if db.engine == 'sqlite':
            pages = int(db.value('PRAGMA freelist_count') or 0)
            return pages * int(db.value('PRAGMA page_size') or 4096)
        if db.engine == 'mariadb':
            return int(db.value('SELECT SUM(DATA_FREE) FROM information_schema.TABLES '
                                'WHERE TABLE_SCHEMA = DATABASE()') or 0)
        return int(db.value('SELECT COALESCE(SUM(n_dead_tup), 0) FROM pg_stat_user_tables') or 0)
    except Exception:
        return 0


def db_check(db):
    """Read the database through and say whether anything is broken."""
    said = []
    if db.engine == 'sqlite':
        got = [r for r in db.rows('PRAGMA integrity_check')]
        words = [list(r.values())[0] for r in got]
        return {'ok': words == ['ok'], 'said': words[:20]}
    if db.engine == 'mariadb':
        ok = True
        for t in TABLES:
            for r in db.rows('CHECK TABLE %s' % t):
                v = {k.lower(): x for k, x in r.items()}
                if str(v.get('msg_type')).lower() in ('error', 'warning') or \
                        str(v.get('msg_text')).lower() not in ('ok', 'table is already up to date'):
                    ok = False
                    said.append('%s: %s' % (t, v.get('msg_text')))
        return {'ok': ok, 'said': said or ['every table: OK']}
    ok = True
    for t in TABLES:
        try:
            n = db.value('SELECT COUNT(*) FROM %s' % t)
            said.append('%s: %s row(s) read' % (t, n))
        except Exception as e:
            ok = False
            said.append('%s: %s' % (t, str(e).split('\n')[0]))
    return {'ok': ok, 'said': said}


def db_statistics(db):
    """Fresh statistics for the planner - quick, nothing is locked."""
    if db.engine == 'sqlite':
        db.run('ANALYZE')
        db.run('PRAGMA optimize')
    elif db.engine == 'mariadb':
        for t in TABLES:
            db.rows('ANALYZE TABLE %s' % t)
    else:
        db.run('ANALYZE')
    return 'the statistics of every table are fresh'


def db_give_back(store, progress):
    """Give the room deleted rows left back to the disk: VACUUM, OPTIMIZE
    TABLE, VACUUM FULL. Each holds a table shut while it works."""
    own = db_own(store)
    # In a cluster this node rests meanwhile (1.0.150): the tables are held
    # shut, and the work waited on them - the other node does it. Alone, the
    # page says first that the work waits for it.
    rest = bool(CONFIG.get('ha_mode')) and any(n.get('alive') and not n.get('me')
                                               for n in ha_nodes(store))
    if rest:
        RESTORE_WHY[0] = 'the database gives its room back'
        RESTORE_RUNNING.set()
    try:
        return _db_give_back(own or store.db, progress)
    finally:
        if rest:
            RESTORE_RUNNING.clear()
        if own:
            own.close()


def _db_give_back(db, progress):
    before = db.size()
    if db.engine == 'sqlite':
        progress(0, 1, 'VACUUM')
        db.run('PRAGMA wal_checkpoint(TRUNCATE)')
        db.run('VACUUM')
        db.run('PRAGMA wal_checkpoint(TRUNCATE)')
    else:
        for i, t in enumerate(TABLES):
            progress(i, len(TABLES), t)
            if db.engine == 'mariadb':
                db.rows('OPTIMIZE TABLE %s' % t)
            else:
                db.run('VACUUM (FULL, ANALYZE) %s' % t)
    after = db.size()
    progress(1, 1, 'done')
    return {'before': before, 'after': after}


def db_prune(store, days):
    """Forget the events - and the rows of every log a module keeps (LOG_TABLES)
    - older than `days`."""
    edge = time.time() - int(days) * 86400 if int(days) > 0 else time.time() + 86400
    gone = {}
    for t in ['events'] + [x for x in LOG_TABLES if x != 'events']:
        # In batches (1.0.57): one DELETE of millions of rows held the daemon -
        # and the health check the VIP address follows - for minutes.
        gone[t] = store.delete_older(t, edge)
    return gone


