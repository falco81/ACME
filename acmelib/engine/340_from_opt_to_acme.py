# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# From opt to acme (1.0.37): the database's own names
# ---------------------------------------------------------------------------
# Until 1.0.37 this program was called opt, and so were the database and the
# account it made, and its replication. install.sh --upgrade moves the files,
# folders and system accounts; this (acme --rename-from-opt, as root) does the
# databases on this machine:
#
#   * PostgreSQL here: the database opt and the account opt are renamed acme,
#     and pg_hba.conf with them;
#   * MariaDB here: the tables are moved into a database acme, the account is
#     renamed and given that database;
#   * replicated: the publication, this node's subscription, and the slot on
#     this node with the other node's subscription to it - renamed without a
#     row lost: the other node's subscription is paused, the slot copied
#     under its new name at the same place, the subscription pointed at it
#     (and at the renamed database and account), resumed, and the old slot
#     dropped. Whichever node goes first, the second finishes the job.
#
# A database on another machine is left as it is (that takes its own
# administrator): its names are written into config.json, so nothing breaks.
RENAME_OLD, RENAME_NEW = 'opt', 'acme'


def _local_host(c):
    h = str(c.get('db_host') or '').strip()
    return h in ('', '127.0.0.1', 'localhost', '::1') or h.startswith('/')


def _pg_hba_rename(port, say):
    """'opt' as a database or an account in pg_hba.conf becomes 'acme'."""
    path = pg_admin('SHOW hba_file', port)
    try:
        lines = Path(path).read_text().splitlines(True)
    except OSError as e:
        say('pg_hba.conf could not be read (%s): look at it by hand' % e)
        return
    out, changed = [], 0
    for line in lines:
        bare = line.split('#', 1)[0]
        bits = bare.split()
        if bits and bits[0] in ('local', 'host', 'hostssl', 'hostnossl', 'hostgssenc',
                                'hostnogssenc') and len(bits) >= 3:
            def fix(field):
                return ','.join(RENAME_NEW if x == RENAME_OLD else x for x in field.split(','))
            db_f, user_f = fix(bits[1]), fix(bits[2])
            if (db_f, user_f) != (bits[1], bits[2]):
                rest = line[len(line) - len(line.lstrip()):]
                head = line[:len(line) - len(rest)]
                parts = re.split(r'(\s+)', rest)
                # parts: word, space, word, space, word, ... - fields 1 and 2
                words = [i for i, p in enumerate(parts) if p and not p.isspace()]
                parts[words[1]], parts[words[2]] = db_f, user_f
                line = head + ''.join(parts)
                changed += 1
        out.append(line)
    if changed:
        shutil.copy2(path, path + '.before-acme')
        Path(path).write_text(''.join(out))
        pg_admin('SELECT pg_reload_conf()', port)
        say('pg_hba.conf: %d line(s) now name acme (the old one is %s.before-acme)'
            % (changed, path))


def _pg_rename_local(c, say, new=None):
    port = int(c.get('db_port') or 5432)
    name, user = str(c.get('db_name') or RENAME_OLD), str(c.get('db_user') or RENAME_OLD)
    # Names this goes on to put into SQL run as root (1.0.101): a config file
    # the acme group may write is no place to take anything else from.
    for what, v in (('db_name', name), ('db_user', user)):
        if not DB_IDENT.fullmatch(v):
            raise ValueError('%s in %s is not a plain name: %r' % (what, CONFIG_FILE, v))
    # Each rename written down as it is done (1.0.59): one that fails half
    # way still leaves the names that changed in the caller's hands.
    new = {} if new is None else new
    before = dict(new)

    def exists(sql):
        return pg_admin(sql, port) == '1'
    if name == RENAME_OLD:
        if exists("SELECT 1 FROM pg_database WHERE datname = '%s'" % RENAME_NEW):
            say('PostgreSQL already has a database acme: the database opt keeps its name')
        elif exists("SELECT 1 FROM pg_database WHERE datname = '%s'" % RENAME_OLD):
            pg_admin("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = "
                     "'%s' AND pid <> pg_backend_pid()" % RENAME_OLD, port)
            time.sleep(1)
            pg_admin('ALTER DATABASE %s RENAME TO %s' % (RENAME_OLD, RENAME_NEW), port)
            new['db_name'] = RENAME_NEW
            say('PostgreSQL: the database opt is now acme')
    if user == RENAME_OLD:
        if exists("SELECT 1 FROM pg_roles WHERE rolname = '%s'" % RENAME_NEW):
            say('PostgreSQL already has an account acme: the account opt keeps its name')
        elif exists("SELECT 1 FROM pg_roles WHERE rolname = '%s'" % RENAME_OLD):
            pg_admin('ALTER ROLE %s RENAME TO %s' % (RENAME_OLD, RENAME_NEW), port)
            new['db_user'] = RENAME_NEW
            if c.get('db_password'):
                # An MD5 password does not survive a rename; it is set again.
                pg_admin("ALTER ROLE %s PASSWORD '%s'" % (
                    RENAME_NEW, str(c['db_password']).replace("'", "''")), port, secret=True)
            new['db_user'] = RENAME_NEW
            say('PostgreSQL: the account opt is now acme')
    if new != before:
        _pg_hba_rename(port, say)
    return new


def _mariadb(sql):
    for cmd in ('mariadb', 'mysql'):
        if shutil.which(cmd):
            got = subprocess.run([cmd, '-uroot', '-N', '-B', '-e', sql], capture_output=True,
                                 text=True, timeout=300)
            if got.returncode == 0:
                return got.stdout.strip()
            raise ValueError((got.stderr or got.stdout).strip()[:300] or 'mariadb failed')
    raise ValueError('the mariadb client is not on this machine')


def _mariadb_rename_local(c, say, new=None):
    name, user = str(c.get('db_name') or RENAME_OLD), str(c.get('db_user') or RENAME_OLD)
    # Names this goes on to put into SQL run as root (1.0.101): a config file
    # the acme group may write is no place to take anything else from.
    for what, v in (('db_name', name), ('db_user', user)):
        if not DB_IDENT.fullmatch(v):
            raise ValueError('%s in %s is not a plain name: %r' % (what, CONFIG_FILE, v))
    # Each rename written down as it is done (1.0.59): one that fails half
    # way still leaves the names that changed in the caller's hands.
    new = {} if new is None else new
    before = dict(new)
    if name == RENAME_OLD:
        if _mariadb("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = "
                    "'%s'" % RENAME_NEW) != '0':
            say('MariaDB already has a database acme: the database opt keeps its name')
        else:
            tables = [t for t in _mariadb("SELECT TABLE_NAME FROM information_schema.TABLES "
                                          "WHERE TABLE_SCHEMA = '%s'" % RENAME_OLD).split('\n')
                      if t.strip()]
            _mariadb('CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
                     % RENAME_NEW)
            if tables:
                _mariadb('RENAME TABLE ' + ', '.join('`%s`.`%s` TO `%s`.`%s`' % (
                    RENAME_OLD, t, RENAME_NEW, t) for t in tables))
            new['db_name'] = RENAME_NEW
            _mariadb('DROP DATABASE `%s`' % RENAME_OLD)
            say('MariaDB: the database opt is now acme (%d tables moved)' % len(tables))
    target_db = new.get('db_name', name)
    hosts = [h for h in _mariadb("SELECT Host FROM mysql.user WHERE User = '%s'"
                                 % (RENAME_OLD if user == RENAME_OLD else user)).split('\n')
             if h.strip()]
    if user == RENAME_OLD and hosts:
        if _mariadb("SELECT COUNT(*) FROM mysql.user WHERE User = '%s'" % RENAME_NEW) != '0':
            say('MariaDB already has an account acme: the account opt keeps its name')
        else:
            for h in hosts:
                _mariadb("RENAME USER '%s'@'%s' TO '%s'@'%s'" % (RENAME_OLD, h, RENAME_NEW, h))
            new['db_user'] = RENAME_NEW
            say('MariaDB: the account opt is now acme')
    who = new.get('db_user', user)
    if new != before:
        for h in hosts:
            _mariadb("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'" % (target_db, who, h))
            try:
                _mariadb("REVOKE ALL PRIVILEGES ON `%s`.* FROM '%s'@'%s'" % (RENAME_OLD, who, h))
            except ValueError:
                pass
        _mariadb('FLUSH PRIVILEGES')
    return new


def _ha_rename(c, say):
    """The replication's objects, on this node and the other one's
    subscription to it. Run with this node's daemon stopped."""
    port = int(c.get('db_port') or 5432)
    db = str(c.get('db_name') or RENAME_NEW)
    slot = int(c.get('ha_slot') or 1)
    peer_slot = 3 - slot
    if pg_admin("SELECT 1 FROM pg_publication WHERE pubname = '%s'" % HA_PUB_OLD, port, db) == '1':
        if pg_admin("SELECT 1 FROM pg_publication WHERE pubname = '%s'" % HA_PUB, port, db) != '1':
            pg_admin('ALTER PUBLICATION %s RENAME TO %s' % (HA_PUB_OLD, HA_PUB), port, db)
            say('replication: the publication is now %s' % HA_PUB)
    # This node's subscription, bringing the other's rows: its name.
    old_in, new_in = 'opt_from_%d' % peer_slot, ha_sub_name(peer_slot)
    if pg_admin("SELECT 1 FROM pg_subscription WHERE subdbid = (SELECT oid FROM pg_database "
                "WHERE datname = current_database()) AND subname = '%s'" % old_in, port, db) == '1':
        pg_admin('ALTER SUBSCRIPTION %s RENAME TO %s' % (old_in, new_in), port, db)
        say('replication: this node\'s subscription is now %s' % new_in)
    # The slot here, and the other node's subscription that reads it.
    old_slot, new_slot = 'opt_from_%d' % slot, ha_sub_name(slot)
    have_old = pg_admin("SELECT 1 FROM pg_replication_slots WHERE slot_name = '%s' AND "
                        "database = '%s'" % (old_slot, db), port) == '1'
    far = None
    for name, user in ((RENAME_NEW, RENAME_NEW), (RENAME_OLD, RENAME_OLD),
                       (c.get('db_name'), c.get('db_user'))):
        try:
            tls, tls_ca = ha_link_tls(c)
            far = db_open(dict(c, db_host=c.get('ha_peer'), db_port=c.get('ha_peer_port') or 5432,
                               db_name=name, db_user=user, db_tls=tls, db_tls_ca=tls_ca))
            far.value('SELECT 1')
            break
        except Exception:                               # noqa: BLE001
            far = None
    if far is None:
        say('the other node\'s PostgreSQL could not be reached: its subscription to this node '
            'is put right when it is upgraded too')
        return
    try:
        sub = None
        for one in ha_sub_names(slot):
            if far.value(SUB_HERE_SQL, (one,)):
                sub = one
                break
        if not sub:
            say('the other node has no subscription to this one: nothing to put right there')
            return
        conninfo = ha_conninfo(c.get('ha_address') or node_address(), port, db,
                               str(c.get('db_user') or RENAME_NEW), c.get('db_password') or '')
        far.run('ALTER SUBSCRIPTION %s DISABLE' % sub)
        time.sleep(2)
        try:
            if have_old and pg_admin("SELECT 1 FROM pg_replication_slots WHERE slot_name = "
                                     "'%s' AND database = '%s'" % (new_slot, db), port) != '1':
                # Copied at the same place: what the other node had not yet
                # taken is still there for it under the new name.
                pg_admin("SELECT pg_copy_logical_replication_slot('%s', '%s')"
                         % (old_slot, new_slot), port, db)
            for quiet in ("SET log_statement = 'none'",):
                try:
                    far.run(quiet)
                except Exception:                       # noqa: BLE001
                    pass
            far.run(RawSql("ALTER SUBSCRIPTION %s CONNECTION '%s'" % (sub, conninfo.replace("'", "''"))))
            far.run('ALTER SUBSCRIPTION %s SET PUBLICATION %s WITH (refresh = false)'
                    % (sub, HA_PUB))
            far.run("ALTER SUBSCRIPTION %s SET (slot_name = '%s')" % (sub, new_slot))
            if sub != new_slot:
                far.run('ALTER SUBSCRIPTION %s RENAME TO %s' % (sub, new_slot))
                sub = new_slot
        finally:
            far.run('ALTER SUBSCRIPTION %s ENABLE' % sub)
        if have_old:
            pg_admin("SELECT pg_drop_replication_slot('%s') FROM pg_replication_slots WHERE "
                     "slot_name = '%s' AND database = '%s' AND NOT active"
                     % (old_slot, old_slot, db), port)
        say('replication: the other node reads this one as %s, from where it was' % new_slot)
    finally:
        far.close()


def rename_from_opt(say=print):
    """acme --rename-from-opt, as root, with the service stopped."""
    if os.geteuid() != 0:
        raise SystemExit('acme: --rename-from-opt is for root (install.sh runs it)')
    load_config()
    c = dict(CONFIG)
    eng = c.get('db_engine') or 'sqlite'
    changes = {}
    if eng != 'sqlite':
        # Whatever happens below, the names in use are written down: the
        # defaults are acme now, and a database still called opt must be
        # found under that name.
        for k in ('db_name', 'db_user'):
            if k not in FILE_KEYS:
                changes[k] = c.get(k) if c.get(k) != DEFAULTS[k] else RENAME_OLD
                c[k] = changes[k]
        if _local_host(c):
            try:
                if eng == 'postgres':
                    _pg_rename_local(c, say, changes)
                else:
                    _mariadb_rename_local(c, say, changes)
            except Exception as e:                      # noqa: BLE001
                say('the database could not be renamed (%s): the names it has now are '
                    'written into %s' % (str(e).split('\n')[0][:200], CONFIG_FILE))
                # Half done (1.0.59): what follows a rename is still done for
                # the part that was renamed, so the daemon can come in.
                try:
                    if eng == 'postgres' and (changes.get('db_name') == RENAME_NEW or
                                              changes.get('db_user') == RENAME_NEW):
                        _pg_hba_rename(int(c.get('db_port') or 5432), say)
                    elif eng != 'postgres' and changes.get('db_name') == RENAME_NEW:
                        who = changes.get('db_user') or RENAME_OLD
                        for h in [x for x in _mariadb("SELECT Host FROM mysql.user WHERE "
                                                      "User = '%s'" % who).split('\n')
                                  if x.strip()]:
                            _mariadb("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'"
                                     % (RENAME_NEW, who, h))
                        _mariadb('FLUSH PRIVILEGES')
                except Exception as e2:                 # noqa: BLE001
                    say('and what follows it could not be done either (%s): see the '
                        'database\'s access by hand' % str(e2).split('\n')[0][:200])
        else:
            say('the database is on %s, not here: it keeps its names (%s, %s)'
                % (c.get('db_host'), c['db_name'], c['db_user']))
        c.update(changes)
        if eng == 'postgres' and CONFIG.get('ha_mode') == 'replicated':
            try:
                _ha_rename(c, say)
            except Exception as e:                      # noqa: BLE001
                say('replication could not be renamed (%s): it goes on under its old names'
                    % str(e).split('\n')[0][:200])
    if changes:
        # Written as given: the old names stay explicit, the new are the
        # defaults and drop out.
        write_file_settings(changes)
    return 0


