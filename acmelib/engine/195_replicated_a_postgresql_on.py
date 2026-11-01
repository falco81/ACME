# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Replicated: a PostgreSQL on each node, each replicating to the other (1.0.14)
# ---------------------------------------------------------------------------
# Each node opens only its own PostgreSQL, on this machine, and goes on alone
# when the other is gone. The two replicate both ways with PostgreSQL's own
# logical replication: a publication of every table on each (inserts, updates
# and deletes - never TRUNCATE, so that a node being rebuilt cannot empty the
# other), and on each a subscription to the other with `origin = none`, so
# that what came from the other is not sent back to it. PostgreSQL 16 or
# later on both.
#
# Rows made on both at once never collide: the numbering of every table goes
# up in twos, odd on node 1 and even on node 2.
#
# A node that was away comes back by itself: what it missed waited in its
# replication slot on the other (up to max_slot_wal_keep_size). A node that
# was lost - or reinstalled - is rebuilt from the living one: its tables
# emptied, every row copied over by the subscription, and the other node's
# subscription to it made afresh.

HA_PUB = 'acme_pub'
# Before 1.0.37 the program was called opt, and its replication objects so:
# a publication and subscriptions are renamed at the upgrade, a slot keeps
# its name until it is next made (a rebuild) - so both are looked for.
HA_PUB_OLD = 'opt_pub'
HA_SLOT_KEEP = '16GB'


def ha_sub_name(slot):
    """The subscription that brings node `slot`'s rows in (and its slot on
    node `slot`)."""
    return 'acme_from_%d' % int(slot)


def ha_sub_names(slot):
    return ['acme_from_%d' % int(slot), 'opt_from_%d' % int(slot)]


def ha_sub_here(db, slot):
    """The subscription for node `slot` as it is called in `db`."""
    for name in ha_sub_names(slot):
        if db.value(SUB_HERE_SQL, (name,)):
            return name
    return ha_sub_name(slot)


def pg_admin(sql, port=5432, db='postgres', secret=False):
    """A statement as the postgres account on this machine (root only). As
    pg_local_admin: the SQL on standard input, a `secret` one unlogged."""
    for runner in (['runuser', '-u', 'postgres', '--'], ['sudo', '-u', 'postgres']):
        if shutil.which(runner[0]):
            got = subprocess.run(runner + ['psql', '-XAtq', '-p', str(int(port)), '-d', db,
                                           '-v', 'ON_ERROR_STOP=1', '-f', '-'],
                                 capture_output=True, text=True, timeout=120,
                                 input=pg_script(sql, secret))
            if got.returncode == 0:
                return got.stdout.strip()
            raise ValueError(scrub_secret((got.stderr or got.stdout).strip()[:400])
                             or 'psql failed')
    raise ValueError('neither runuser nor sudo is on this machine')


def pg_local_running(port=5432):
    try:
        return pg_admin('SELECT 1', port) == '1'
    except Exception:                                   # noqa: BLE001
        return False


def pg_install_local(major, say):
    """PostgreSQL `major` on this machine, installed, initialised and running."""
    if shutil.which('dnf'):
        say('installing PostgreSQL %s (dnf)' % major)
        subprocess.run(['dnf', '-y', 'module', 'reset', 'postgresql'], capture_output=True)
        subprocess.run(['dnf', '-y', 'module', 'enable', 'postgresql:%s' % major],
                       capture_output=True)
        got = subprocess.run(['dnf', '-y', 'install', 'postgresql-server', 'postgresql',
                              'postgresql-contrib'], capture_output=True, text=True)
        if got.returncode != 0:
            raise ValueError('dnf could not install PostgreSQL %s: %s'
                             % (major, (got.stderr or got.stdout).strip()[-300:]))
        if not Path('/var/lib/pgsql/data/PG_VERSION').exists():
            subprocess.run(['postgresql-setup', '--initdb'], capture_output=True)
        subprocess.run(['systemctl', 'enable', '--now', 'postgresql'], capture_output=True)
    elif shutil.which('apt-get'):
        say('installing PostgreSQL %s (apt)' % major)
        got = subprocess.run(['apt-get', 'install', '-y', 'postgresql-%s' % major,
                              'postgresql-client-%s' % major], capture_output=True, text=True)
        if got.returncode != 0:
            got = subprocess.run(['apt-get', 'install', '-y', 'postgresql'],
                                 capture_output=True, text=True)
        if got.returncode != 0:
            raise ValueError('apt could not install PostgreSQL: %s'
                             % (got.stderr or got.stdout).strip()[-300:])
    else:
        raise ValueError('install PostgreSQL %s on this machine first' % major)
    for _ in range(30):
        if pg_local_running():
            return
        time.sleep(1)
    raise ValueError('PostgreSQL was installed but does not answer')


def pg_restart_local(port=5432):
    unit = tune_restart_unit()
    if unit:
        subprocess.run(['systemctl', 'restart', unit], capture_output=True)
    elif shutil.which('pg_lsclusters'):
        for line in subprocess.run(['pg_lsclusters', '-h'], capture_output=True,
                                   text=True).stdout.splitlines():
            f = line.split()
            if len(f) >= 3 and f[2] == str(port):
                subprocess.run(['pg_ctlcluster', f[0], f[1], 'restart'], capture_output=True)
    else:
        raise ValueError('PostgreSQL could not be restarted: no service of it was found')
    for _ in range(60):
        if pg_local_running(port):
            return
        time.sleep(1)
    raise ValueError('PostgreSQL did not come back after its restart')


def pg_prepare_local(port, peer, name, user, password, say):
    """PostgreSQL on this machine ready to replicate with `peer`: logical
    WAL, listening on the network, the peer let in, the account able to
    replicate and to subscribe, the database there. True when it has to be
    restarted for it."""
    major = int(pg_admin('SHOW server_version_num', port)) // 10000
    if major < 16:
        raise ValueError('PostgreSQL %d is here; replicating both ways needs 16 or later '
                         '(dnf module enable postgresql:16, then upgrade it)' % major)
    restart = False
    for key, want in (('wal_level', 'logical'), ('listen_addresses', '*'),
                      ('max_slot_wal_keep_size', HA_SLOT_KEEP)):
        now = pg_admin('SHOW %s' % key, port)
        if key == 'max_slot_wal_keep_size' and now not in ('-1',) and now.upper() == want:
            continue
        if now != want:
            pg_admin("ALTER SYSTEM SET %s = '%s'" % (key, want), port)
            say('%s = %s (was %s)' % (key, want, now))
            if key != 'max_slot_wal_keep_size':
                restart = True
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', user) or \
            not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', name):
        raise ValueError('the database and its account are letters, digits and _')
    lit = "'%s'" % str(password).replace("'", "''")
    if pg_admin("SELECT 1 FROM pg_roles WHERE rolname = '%s'" % user, port) != '1':
        pg_admin('CREATE ROLE %s LOGIN PASSWORD %s' % (user, lit), port, secret=True)
        say('the account %s was made' % user)
    else:
        pg_admin('ALTER ROLE %s LOGIN PASSWORD %s' % (user, lit), port, secret=True)
    pg_admin('ALTER ROLE %s REPLICATION' % user, port)
    pg_admin('GRANT pg_create_subscription TO %s' % user, port)
    if pg_admin("SELECT 1 FROM pg_database WHERE datname = '%s'" % name, port) != '1':
        # UTF-8 whatever the cluster was made with: one made under LANG=C is
        # SQL_ASCII, and every name with an accent would come back unreadable.
        pg_admin("CREATE DATABASE %s OWNER %s ENCODING 'UTF8' TEMPLATE template0 "
                 "LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'" % (name, user), port)
        say('the database %s was made' % name)
    pg_admin('GRANT CREATE ON DATABASE %s TO %s' % (name, user), port)
    hba = pg_admin('SHOW hba_file', port)
    text = Path(hba).read_text()
    added = []
    for who in sorted(set(([peer] if peer else []) + ['127.0.0.1'])):
        line = 'host    %s    %s    %s    scram-sha-256' % (name, user, peer_net(who))
        # Taken over TLS only already (1.0.104): no plain line put back in front.
        if line not in text and ('hostssl' + line[4:]) not in text:
            added.append(line)
    if added:
        # In front of whatever is there: pg_hba.conf is read top down, and a
        # "reject" or an "ident" line further up would win otherwise.
        Path(hba).write_text('# acme high availability (%s)\n%s\n%s'
                             % (datetime.now().strftime('%Y-%m-%d'), '\n'.join(added), text))
        say('%s: %s' % (hba, '; '.join(added)))
    pg_admin('SELECT pg_reload_conf()', port)
    return restart, major


def pg_publication(port, name):
    if pg_admin("SELECT 1 FROM pg_publication WHERE pubname = '%s'" % HA_PUB_OLD, port, name) == '1':
        pg_admin('ALTER PUBLICATION %s RENAME TO %s' % (HA_PUB_OLD, HA_PUB), port, name)
    if pg_admin("SELECT 1 FROM pg_publication WHERE pubname = '%s'" % HA_PUB, port, name) != '1':
        pg_admin("CREATE PUBLICATION %s FOR ALL TABLES WITH (publish = 'insert, update, delete')"
                 % HA_PUB, port, name)


def ha_conninfo(host, port, name, user, password):
    def q(v):
        return "'%s'" % str(v).replace('\\', '\\\\').replace("'", "\\'")
    tls = ''
    mode, ca = ha_link_tls()
    if mode:
        # The other node's link encrypted as the database's own is (1.0.33),
        # or as its own setting says (1.0.104).
        tls = ' sslmode=%s' % q(mode)
        if ca:
            tls += ' sslrootcert=%s' % q(ca)
    return 'host=%s port=%d dbname=%s user=%s password=%s connect_timeout=10%s' % (
        q(host), int(port), q(name), q(user), q(password), tls)


def ha_drop_sub(db, sub):
    """A subscription taken away without asking the other side for its slot
    (which may be gone with a lost node) - under its name now or before."""
    names = ha_sub_names(sub.rsplit('_', 1)[1]) if sub[:9] in ('acme_from_', 'opt_from_') \
        else [sub]
    for one in names:
        if db.value(SUB_HERE_SQL, (one,)):
            db.run('ALTER SUBSCRIPTION %s DISABLE' % one)
            db.run('ALTER SUBSCRIPTION %s SET (slot_name = NONE)' % one)
            db.run('DROP SUBSCRIPTION %s' % one)


def ha_drop_slot(db, slot_name):
    if slot_name[:9] in ('acme_from_', 'opt_from_'):
        gone = False
        for one in ha_sub_names(slot_name.rsplit('_', 1)[1]):
            gone = _ha_drop_slot(db, one) or gone
        return gone
    return _ha_drop_slot(db, slot_name)


def _ha_drop_slot(db, slot_name):
    # This database's only (1.0.170): the catalog is the server's, and a slot
    # of the same name may be another database's - in use by it.
    got = db.row('SELECT active, active_pid FROM pg_replication_slots WHERE slot_name = ? '
                 'AND database = current_database()', (slot_name,))
    if not got:
        return False
    if got.get('active') and got.get('active_pid'):
        db.value('SELECT pg_terminate_backend(?)', (int(got['active_pid']),))
        time.sleep(1)
    db.value('SELECT pg_drop_replication_slot(?)', (slot_name,))
    return True


def ha_sequences(db, slot):
    """Every table numbered in twos: odd on node 1, even on node 2."""
    slot = int(slot)
    for table in TABLES:
        if table in ('meta', 'settings'):
            continue                    # keyed by name, not numbered
        seq = db.value("SELECT pg_get_serial_sequence(?, 'id')", (table,))
        if not seq:
            continue
        top = int(db.value('SELECT COALESCE(MAX(id), 0) FROM %s' % table) or 0)
        start = top + 1
        while start % 2 != slot % 2:
            start += 1
        db.run('ALTER SEQUENCE %s INCREMENT BY 2' % seq)
        # The next nextval() is `start`.
        db.value('SELECT setval(?, ?, false)', (seq, start))


def ha_sequences_check(db, slot):
    """Every hour, and once at start (1.0.59): a table whose next number is
    not above every row in it - rows put back on the other node, a database
    restored from an older snapshot - would hand out a number the other
    node already has, and replication stops on it. Moved past them, on this
    node's side of odd and even."""
    fixed = []
    for table in TABLES:
        if table in ('meta', 'settings'):
            continue
        seq = db.value("SELECT pg_get_serial_sequence(?, 'id')", (table,))
        if not seq:
            continue
        st = db.row('SELECT last_value, is_called FROM %s' % seq)
        inc = int(db.value('SELECT increment_by FROM pg_sequences WHERE '
                           "schemaname || '.' || sequencename = ? OR sequencename = ?",
                           (seq, seq.split('.')[-1])) or 1)
        nxt = int(st['last_value']) + (inc if st['is_called'] else 0)
        top = int(db.value('SELECT COALESCE(MAX(id), 0) FROM %s' % table) or 0)
        if nxt > top and inc == 2 and nxt % 2 == int(slot) % 2:
            continue
        if inc == 2 and nxt % 2 == int(slot) % 2:
            # (1.0.61) Only behind the other node's rows - the usual thing where one
            # node takes more of the traffic, and harmless: moved past them
            # quietly, so no number of its own can ever meet a row put back.
            start = top + 1 + ((int(slot) - top - 1) % 2)
            db.value('SELECT setval(?, ?, false)', (seq, start))
            continue
        start = top + 1
        while start % 2 != int(slot) % 2:
            start += 1
        db.run('ALTER SEQUENCE %s INCREMENT BY 2' % seq)
        db.value('SELECT setval(?, ?, false)', (seq, max(start, nxt if nxt % 2 == int(slot) % 2
                                                      else start)))
        fixed.append(table)
    if fixed:
        log('the numbering of %s was behind the rows in it, or on the other node\'s side: '
            'moved on' % ', '.join(fixed), 'warn')
    return fixed


def ha_wait_copied(db, sub, say, seconds=3600):
    t0 = time.time()
    while time.time() - t0 < seconds:
        left = db.rows("SELECT c.relname AS t, r.srsubstate AS s FROM pg_subscription_rel r "
                       "JOIN pg_subscription s ON s.oid = r.srsubid "
                       "JOIN pg_class c ON c.oid = r.srrelid WHERE s.subname = ? "
                       "AND r.srsubstate <> 'r'", (sub,))
        if not left and db.value('SELECT COUNT(*) FROM pg_subscription_rel r JOIN '
                                 'pg_subscription s ON s.oid = r.srsubid WHERE s.subname = ?',
                                 (sub,)):
            return True
        say('copying: %s still to come' % ', '.join(sorted(x['t'] for x in left)[:6]))
        time.sleep(2)
    raise ValueError('the copy from the other node did not finish in %d s' % seconds)


def ha_subscribe(db, sub, conninfo, copy_data):
    """A subscription made on `db`. The statement carries the password of
    the account in its conninfo, so it is kept out of PostgreSQL's log for
    the session, and out of any error that comes back."""
    # Tried from here first (1.0.44): the SETs below need a superuser, which
    # the acme account is not, so a CREATE SUBSCRIPTION that fails - the
    # other node unreachable, a wrong password - would be written to
    # PostgreSQL's log with the password in it. What fails here is never
    # sent.
    try:
        import psycopg2
        probe = psycopg2.connect(conninfo + ' connect_timeout=10')
        probe.close()
    except ImportError:
        pass
    except Exception as e:                              # noqa: BLE001
        raise ValueError('the other node\'s database cannot be reached from here, so the '
                         'subscription %s was not made: %s'
                         % (sub, scrub_secret(str(e).split('\n')[0][:300])))
    for quiet in ("SET log_statement = 'none'", "SET log_min_error_statement = 'panic'"):
        try:
            db.run(quiet)
        except Exception:                               # noqa: BLE001
            pass                                        # not a superuser: logged as usual
    try:
        db.run(RawSql("CREATE SUBSCRIPTION %s CONNECTION '%s' PUBLICATION %s WITH (copy_data = %s, "
                      "origin = none)" % (sub, conninfo.replace("'", "''"), HA_PUB,
                                          'true' if copy_data else 'false')))
    except Exception as e:                              # noqa: BLE001
        raise ValueError('the subscription %s could not be made: %s'
                         % (sub, scrub_secret(str(e).split('\n')[0][:300])))
    finally:
        for back in ('RESET log_statement', 'RESET log_min_error_statement'):
            try:
                db.run(back)
            except Exception:                           # noqa: BLE001
                pass


HA_REBUILD_FAILED_WHY = ('a rebuild from the other node failed half way - its tables are '
                         'not whole: rebuild it again (Settings → High availability)')


def ha_rebuild(local, remote, *args):
    """Never two at once (1.0.59): both nodes rebuilding from each other
    emptied both. The same lock is taken in both databases - the other
    node's rebuild holds it in its own and in this one."""
    held = []
    try:
        for db in (local, remote):
            if not db.value('SELECT pg_try_advisory_lock(?)', (HA_REBUILD_LOCK,)):
                raise ValueError('a rebuild is running already (on this node or the other one)')
            held.append(db)
        return _ha_rebuild(local, remote, *args)
    finally:
        for db in held:
            try:
                db.value('SELECT pg_advisory_unlock(?)', (HA_REBUILD_LOCK,))
            except Exception:                           # noqa: BLE001
                pass


def _ha_rebuild(local, remote, my_slot, peer_slot, my_host, my_port, peer_host, peer_port,
                name, user, password, say):
    """This node rebuilt from the other: both subscriptions made afresh, this
    node's tables emptied and every row copied over. What this node held is
    replaced by what the other holds."""
    mine_on_peer = ha_sub_name(my_slot)       # on the peer: brings my rows to it
    theirs_here = ha_sub_name(peer_slot)      # here: brings the peer's rows to me
    say('the other node stops taking rows from this one')
    ha_drop_sub(remote, mine_on_peer)
    ha_drop_slot(local, mine_on_peer)
    say('this node stops taking rows from the other')
    ha_drop_sub(local, theirs_here)
    ha_drop_slot(remote, theirs_here)
    say('this node\'s tables emptied')
    local.make_tables()
    # Nothing written here while the rows come over (1.0.44): the heartbeat
    # and the job's own progress wrote rows the copy then met again, and it
    # stopped on a duplicate key for good.
    HA_REBUILDER[0] = threading.get_ident()    # before the flag (1.0.59)
    HA_REBUILDING.set()
    done = False
    try:
        local.run('TRUNCATE %s RESTART IDENTITY' % ', '.join(TABLES))
        say('every row copied from the other node')
        ha_subscribe(local, theirs_here, ha_conninfo(peer_host, peer_port, name, user, password),
                     copy_data=True)
        ha_wait_copied(local, theirs_here, say)
        ha_sequences(local, my_slot)
        # The other node's subscription - and with it the point it starts
        # from - made before this node writes anything again (1.0.57): what
        # was written in between never went over.
        say('the other node takes this one\'s rows from now on')
        ha_subscribe(remote, mine_on_peer, ha_conninfo(my_host, my_port, name, user, password),
                     copy_data=False)
        done = True
    finally:
        # Odd or even again whatever happened (1.0.57): RESTART IDENTITY
        # left them at 1 with the other node's numbering.
        try:
            ha_sequences(local, my_slot)
        except Exception as e:                          # noqa: BLE001
            log('the numbering could not be set again: %s' % e, 'warn')
        HA_REBUILDER[0] = None
        HA_REBUILDING.clear()
        # Failed after its tables were emptied (1.0.94): the node stays out of
        # service, not back answering every person "no such token" with
        # nothing replicating - until a rebuild goes through.
        store = HA_STORE.get('store')
        if store is not None:
            try:
                row = maintenance_row(store)
                if not done:
                    maintenance_set(store, True, HA_REBUILD_FAILED_WHY, 'the rebuild')
                elif row.get('on') and row.get('why') == HA_REBUILD_FAILED_WHY:
                    maintenance_set(store, False, '', 'the rebuild')
            except Exception as e:                      # noqa: BLE001
                log('maintenance after the rebuild could not be written: %s' % e, 'error')
    rows = sum(int(local.value('SELECT COUNT(*) FROM %s' % t) or 0) for t in TABLES)
    return {'rows': rows}


def ha_repl_state(store):
    """Both directions, as this node's PostgreSQL sees them."""
    db = store.db
    out = {'mode': CONFIG.get('ha_mode') or '', 'slot': CONFIG.get('ha_slot') or 0,
           'peer': CONFIG.get('ha_peer') or '', 'incoming': [], 'outgoing': []}
    if out['mode'] != 'replicated' or db.engine != 'postgres':
        return out
    try:
        for r in db.rows(
                'SELECT s.subname AS name, s.subenabled AS enabled, st.pid AS pid, '
                'EXTRACT(EPOCH FROM st.last_msg_receipt_time) AS last_msg, '
                'EXTRACT(EPOCH FROM st.latest_end_time) AS latest_end, '
                'COALESCE(ss.apply_error_count, 0) AS apply_errors, '
                'COALESCE(ss.sync_error_count, 0) AS sync_errors '
                'FROM pg_subscription s LEFT JOIN pg_stat_subscription st '
                'ON st.subid = s.oid AND st.relid IS NULL '
                'LEFT JOIN pg_stat_subscription_stats ss ON ss.subid = s.oid '
                # Only this database's (1.0.57): the catalog is the server's.
                'WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = '
                'current_database())'):
            r['running'] = bool(r.get('pid'))
            out['incoming'].append(r)
        for r in db.rows(
                "SELECT slot_name AS name, active, wal_status, "
                "pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn) AS behind "
                "FROM pg_replication_slots WHERE slot_name LIKE 'o__!_from!_%' ESCAPE '!' "
                "AND database = current_database()"):
            r['behind'] = int(float(r.get('behind') or 0))
            out['outgoing'].append(r)
    except Exception as e:                              # noqa: BLE001
        out['trouble'] = str(e).split('\n')[0][:300]
    healthy = bool(out['incoming']) and all(x['enabled'] and x['running'] for x in
                                            out['incoming']) and bool(out['outgoing']) and \
        all(x['wal_status'] not in ('lost',) for x in out['outgoing'])
    out['healthy'] = healthy
    out['lost'] = any(x.get('wal_status') == 'lost' for x in out['outgoing'])
    return out


def ha_peer_columns():
    """Columns of a later version added to the other node's tables too."""
    try:
        far = ha_peer_db()
    except Exception as e:                              # noqa: BLE001
        log('the other node\'s database could not be reached to add new columns: %s'
            % str(e).split('\n')[0][:200], 'warn')
        return
    try:
        far.add_missing_columns()
    except Exception as e:                              # noqa: BLE001
        log('new columns could not be added on the other node: %s' % e, 'warn')
    finally:
        try:
            far.close()
        except Exception:                               # noqa: BLE001
            pass


# ---- used once, on either node (1.0.101) -------------------------------------
# A code's time step, a recovery code, an answered question: each is written
# as a row of its own in token_once, by this node under its own number, and
# never changed - so replication, which writes whole rows, cannot write an
# older copy over it. And with two replicating databases, a node that takes
# one also looks in the other node's database for that node's row, after
# writing its own: of two nodes asked for the same code at the same moment,
# at least one sees the other's row - so it is never let in twice. (One may
# refuse it when both see each other; the next code then goes through.)
ONCE_PEER = {'pool': [], 'made': 0, 'down_until': 0.0, 'said': 0.0, 'fails': 0, 'gen': 0}
ONCE_PEER_LOCK = threading.Lock()
ONCE_PEER_MOST = 4               # connections to the other node's database, at most
ONCE_KEEP_S = {'step': 3 * 86400, 'chal': 3 * 86400, 'scratch': 800 * 86400}


def once_node():
    return int(CONFIG.get('ha_slot') or 1) if CONFIG.get('ha_mode') == 'replicated' else 0


def once_key(kind, name, value):
    h = hashlib.sha256(('%s\n%s' % (norm_name(name), value)).encode('utf-8')).hexdigest()
    return '%s:%s' % (kind, h[:48])


def once_peer_forget():
    """The connections to the other node closed - its address or TLS changed."""
    with ONCE_PEER_LOCK:
        pool, ONCE_PEER['pool'] = ONCE_PEER['pool'], []
        ONCE_PEER['made'] = 0
        ONCE_PEER['gen'] += 1           # one out on a question now is not taken back (1.0.206)
        ONCE_PEER['down_until'] = 0.0
        ONCE_PEER['fails'] = 0
    for db in pool:
        try:
            db.close()
        except Exception:                               # noqa: BLE001
            pass


def _once_peer_has(k, me, store=None):
    """Whether the other node's database has the other node's row for `k`:
    True, False, or None when it cannot be asked just now. Asked on a
    connection of its own with a 2 s limit, and waited for 1.5 s at most
    (1.0.101; 1.0.186): a peer that drops packets without a word must not hold
    every sign-in that was let in. A few connections (1.0.186): with one, the
    sign-ins of a busy morning asked one after the other and timed out on each
    other - and the peer was taken for gone. Not asked again for 20 s, then
    longer each time it does not answer, up to 5 minutes."""
    # Asked whatever its heartbeat says (1.0.205): the heartbeat comes through
    # replication, and a replication stopped while the other node still lets
    # people in made it look gone - a code used there was let in here again. A
    # node really gone costs one sign-in 1.5 s now and then: not asked again
    # for 20 s, then longer each time, up to 5 minutes (down_until below).
    with ONCE_PEER_LOCK:
        if ONCE_PEER['down_until'] > time.time():
            return None
        if ONCE_PEER['pool']:
            db = ONCE_PEER['pool'].pop()
        elif ONCE_PEER['made'] < ONCE_PEER_MOST:
            db = None
            ONCE_PEER['made'] += 1
        else:
            db = 'wait'
    if db == 'wait':
        # Every connection in use: one comes back within a moment.
        for _ in range(30):
            time.sleep(0.05)
            with ONCE_PEER_LOCK:
                if ONCE_PEER['pool']:
                    db = ONCE_PEER['pool'].pop()
                    break
        if db == 'wait':
            return None
    got = {'db': db}
    gen = ONCE_PEER['gen']

    def ask():
        try:
            if got['db'] is None:
                got['db'] = db_open(ha_peer_conf(timeout=2), statement_s=2)
            got['v'] = bool(got['db'].value('SELECT 1 FROM token_once WHERE k = ? AND node <> ?',
                                            (k, me)))
        except Exception as e:                          # noqa: BLE001
            got['e'] = e
    t = threading.Thread(target=ask, name='once-peer', daemon=True)
    t.start()
    t.join(1.5)
    if 'v' in got:
        with ONCE_PEER_LOCK:
            if gen == ONCE_PEER['gen']:
                ONCE_PEER['pool'].append(got['db'])
            else:
                # Made before the address or the TLS of the link changed (1.0.206):
                # closed, not kept for good in the new pool.
                try:
                    got['db'].close()
                except Exception:                       # noqa: BLE001
                    pass
            ONCE_PEER['fails'] = 0
        return got['v']
    e = got.get('e') or TimeoutError('no answer within 1.5 s')
    with ONCE_PEER_LOCK:
        ONCE_PEER['made'] = max(0, ONCE_PEER['made'] - 1)
        ONCE_PEER['fails'] += 1
        ONCE_PEER['down_until'] = time.time() + min(300, 20 * 2 ** (ONCE_PEER['fails'] - 1))
        say = ONCE_PEER['said'] < time.time() - 300
        if say:
            ONCE_PEER['said'] = time.time()
    if got.get('db') is not None and not t.is_alive():
        try:
            got['db'].close()
        except Exception:                               # noqa: BLE001
            pass
    if say:
        log('the other node\'s database cannot be asked whether a code was used there '
            '(%s): codes are checked against this node\'s rows alone until it can'
            % str(e).split('\n')[0][:200], 'warn')
    return None


def once_take(store, kind, name, value):
    """True if this is the first use of it anywhere; False if it was used
    before, here or on the other node. A database error here raises: the
    request then goes unanswered, never let in."""
    k = once_key(kind, name, value)
    me = once_node()
    db = store.db
    if db.engine == 'mariadb':
        sql = 'INSERT IGNORE INTO token_once (k, node, ts) VALUES (?, ?, ?)'
    elif db.engine == 'sqlite':
        sql = 'INSERT OR IGNORE INTO token_once (k, node, ts) VALUES (?, ?, ?)'
    else:
        sql = 'INSERT INTO token_once (k, node, ts) VALUES (?, ?, ?) ON CONFLICT DO NOTHING'
    if not db.run(sql, (k, me, time.time())):
        return False                    # this node took it already
    if db.value('SELECT 1 FROM token_once WHERE k = ? AND node <> ?', (k, me)):
        return False                    # the other node took it, and it came over
    if me and CONFIG.get('ha_mode') == 'replicated' and CONFIG.get('ha_peer'):
        if _once_peer_has(k, me, store):
            return False                # the other node took it, not over yet
    return True


def once_tidy(store):
    """Rows no longer needed: a time step or a question long past."""
    t = time.time()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'scratchguard:%'"):
        try:
            last = max([float(x) for x in json.loads(r['v'] or '[]')] or [0])
        except (ValueError, TypeError):
            last = 0
        if t - last > 86400:
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'scratchclear:%'"):
        try:
            if t - float(r['v'] or 0) > 86400:      # older than every place it hides (1.0.187)
                store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
        except (ValueError, TypeError):
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
    for kind, keep in ONCE_KEEP_S.items():
        store.db.run('DELETE FROM token_once WHERE substr(k, 1, ?) = ? AND ts < ?',
                     (len(kind) + 1, kind + ':', t - keep))


def ha_peer_db():
    return db_open(ha_peer_conf())


def ha_control(store, act, by=''):
    """Replication worked by hand: paused, resumed, switched off, refreshed.
    `in` is what this node takes from the other (its own subscription);
    `out` is what the other takes from this one (the other's subscription,
    reached over its PostgreSQL). (1.0.14)"""
    if CONFIG.get('ha_mode') != 'replicated':
        raise ValueError('this node does not replicate')
    slot = int(CONFIG.get('ha_slot') or 1)
    peer_slot = 3 - slot
    here = store.db
    sub_in = ha_sub_here(here, peer_slot)
    said = []

    def on_peer(fn):
        try:
            far = ha_peer_db()
        except Exception as e:                          # noqa: BLE001
            raise ValueError('the other node\'s PostgreSQL cannot be reached: %s'
                             % str(e).split('\n')[0][:200])
        try:
            return fn(far)
        finally:
            far.close()

    def has(db, sub):
        return bool(db.value(SUB_HERE_SQL, (sub,)))

    if act in ('pause_in', 'pause'):
        if has(here, sub_in):
            here.run('ALTER SUBSCRIPTION %s DISABLE' % sub_in)
            said.append('this node takes nothing from the other for now')
    if act in ('pause_out', 'pause'):
        def p(far):
            sub_out = ha_sub_here(far, slot)
            if has(far, sub_out):
                far.run('ALTER SUBSCRIPTION %s DISABLE' % sub_out)
                said.append('the other node takes nothing from this one for now')
        on_peer(p)
    if act in ('resume_in', 'resume'):
        if has(here, sub_in):
            here.run('ALTER SUBSCRIPTION %s ENABLE' % sub_in)
            said.append('this node takes the other\'s rows again, from where it stopped')
    if act in ('resume_out', 'resume'):
        def r(far):
            sub_out = ha_sub_here(far, slot)
            if has(far, sub_out):
                far.run('ALTER SUBSCRIPTION %s ENABLE' % sub_out)
                said.append('the other node takes this one\'s rows again, from where it '
                            'stopped')
        on_peer(r)
    if act == 'refresh':
        if has(here, sub_in):
            here.run('ALTER SUBSCRIPTION %s REFRESH PUBLICATION WITH (copy_data = false)'
                     % sub_in)
        said.append('the list of tables taken from the other was read again')
    if act == 'stop':
        # Both directions taken away; both nodes go on alone, each with what
        # it has. Joining them again is a rebuild of one from the other.
        ha_drop_sub(here, sub_in)
        try:
            on_peer(lambda far: (ha_drop_sub(far, ha_sub_name(slot)), ha_drop_slot(far, sub_in)))
        except ValueError as e:
            said.append('the other node could not be reached (%s): take its subscription '
                        'away there with acme --ha-stop' % e)
        ha_drop_slot(here, ha_sub_name(slot))
        said.append('replication is off: each node goes on alone with what it has')
    if not said:
        raise ValueError('nothing to do: %s' % act)
    store.add_event('settings', '%s: replication - %s' % (by or 'command line', '; '.join(said)),
                    'warn', who=by or 'command line')
    return {'message': '; '.join(said)}


def ha_resync_job(store, by):
    """This node rebuilt from the other, as a job the pages can follow."""
    if CONFIG.get('ha_mode') != 'replicated':
        raise ValueError('this node does not replicate')

    def work(progress):
        steps = []

        def say(t):
            steps.append(t)
            progress(len(steps), 8, t)
        progress(0, 8, 'making a copy of what is here first')
        copy = make_backup(store, 'before rebuilding from the other node, by %s' % by)
        remote = ha_peer_db()
        try:
            got = ha_rebuild(store.db, remote, int(CONFIG.get('ha_slot') or 2),
                             3 - int(CONFIG.get('ha_slot') or 2),
                             CONFIG.get('ha_address') or node_address(),
                             int(CONFIG.get('db_port') or 5432), CONFIG.get('ha_peer'),
                             int(CONFIG.get('ha_peer_port') or 5432), CONFIG.get('db_name'),
                             CONFIG.get('db_user'), CONFIG.get('db_password'), say)
        finally:
            remote.close()
        store._clients = store._realms = None
        store.set_meta('conf_serial', '%.6f:%s' % (time.time(), node_name()))
        store.add_event('settings', '%s rebuilt this node from the other: %d row(s); what it '
                        'held is in %s' % (by, got['rows'], copy.name), 'warn', who=by)
        progress(8, 8, 'done')
        return {'rows': got['rows'], 'copy': copy.name, 'where': CONFIG.get('ha_peer')}
    return db_job('rebuilding this node from the other', work)


def bytes_words(n):
    n = float(n or 0)
    for unit in ('B', 'kB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024.0


