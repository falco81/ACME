# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Moving to another database, step by step (1.0.210)
# ---------------------------------------------------------------------------
# Settings → The database → Move to another database: the wizard asks where to,
# checks it, says what will happen, and then does all of it as one job - a copy
# made first, the tables made there, every row copied, the rows counted and every
# sealed secret opened there, config.json switched, acme started again on it and
# asked whether it answers. The old database is never touched: it is the way
# back. The job's state is kept in a file beside the database (db-move.json), so
# the page that started it follows it through the restart and reads its end from
# the daemon that answers on the new database. `acme --db-move ENGINE` is the same
# from the command line. Refused on a node of a cluster: its database is the
# cluster's.
MOVE_FILE = STATE_DIR / 'db-move.json'
MOVE_CA_FILE = STATE_DIR / 'db-move-ca.pem'
MOVE = {}
MOVE_LOCK = threading.Lock()
MOVE_CANCEL = threading.Event()
MOVE_PEER_STALE_S = 3600
MOVE_STEPS = (('backup', 'A copy of everything here, first'),
              ('schema', 'The tables made there'),
              ('copy', 'Every row copied'),
              ('verify', 'The rows counted there, every sealed secret opened'),
              ('switch', 'config.json switched to it'),
              ('restart', 'acme started again on it'),
              ('reconnect', 'It answers on the new database'))
MOVE_ENGINES = {
    'sqlite': {'words': 'SQLite - a file on this machine', 'port': 0,
               'note': 'Nothing to install or look after; one server only. Copied with the backups.'},
    'mariadb': {'words': 'MariaDB (or MySQL)', 'port': 3306,
                'note': 'A database server you run already. One server: a cluster of two acme '
                        'nodes needs PostgreSQL.'},
    'postgres': {'words': 'PostgreSQL', 'port': 5432,
                 'note': 'A database server; the one high availability needs (16 or later) - '
                         'two acme nodes, shared or replicated.'},
}
LOCAL_HOSTS = ('', 'localhost', '127.0.0.1', '::1', 'localhost.localdomain')


class MoveCancelled(Exception):
    pass


def _ago_words(secs):
    secs = int(max(0, secs))
    if secs < 120:
        return '%d s' % secs
    if secs < 7200:
        return '%d min' % (secs // 60)
    if secs < 3 * 86400:
        return '%d h' % (secs // 3600)
    return '%d days' % (secs // 86400)


# ---- the guard: never on a node of a cluster ------------------------------------
def db_move_guard(store):
    """None when this node may move its database; otherwise why not, and how
    to get there. A node of a cluster (ha_mode) is refused - and so is a node
    whose database another node is heard using right now."""
    mode = str(CONFIG.get('ha_mode') or '')
    try:
        nodes = ha_nodes(store)
    except Exception:                                   # noqa: BLE001
        nodes = []
    others = [n for n in nodes if not n.get('me')]
    alive = [n for n in others if n.get('alive')]
    if not mode and not alive:
        return None
    seen = [{'name': n['name'], 'age': int(n.get('age') or 0), 'alive': bool(n.get('alive'))}
            for n in others]
    recent = [n for n in others if float(n.get('age') or 1e12) < MOVE_PEER_STALE_S]
    out = {'refused': True, 'mode': mode, 'nodes': seen, 'stale': False, 'pane': 'ha'}
    if mode and not recent:
        out['stale'] = True
        last = min((float(n.get('age') or 0) for n in others), default=None)
        out['why'] = ('config.json says this node is one of a cluster (ha_mode "%s"), but no '
                      'other node has been heard from %s. Its database is still the cluster\'s '
                      'as far as acme knows, so it is not moved.'
                      % (mode, ('for %s' % _ago_words(last)) if last is not None else 'at all'))
        out['how'] = [
            'If this node really is alone for good, take it out of the cluster mode: as root '
            'on this machine, acme --ha-standalone --yes - it keeps the database, the key and '
            'everything in them, and starts acme again as a single server.',
            'Then move the database here: Settings → The database → Move to another database.',
            'Build the cluster again afterwards if you want one: Settings → High availability.']
        return out
    if mode:
        out['why'] = ('this node is one of a cluster (%s): its database is the cluster\'s. '
                      'Moving it would break the %s and leave the other node on its own.'
                      % ('replicated - a PostgreSQL on each node' if mode == 'replicated'
                         else 'shared - both nodes open one PostgreSQL',
                         'replication' if mode == 'replicated' else 'cluster'))
    else:
        out['why'] = ('another node (%s) is using this database right now: moving it would '
                      'take it away from under that node.'
                      % ', '.join(n['name'] for n in alive))
    out['how'] = [
        ('Take the cluster apart first: Settings → High availability → Switch it off… (the '
         'replication), then as root on this node acme --ha-standalone --yes, and the same on '
         'the other node (or uninstall it there).') if mode == 'replicated' else
        ('Take the cluster apart first: stop acme on the other node (or uninstall it), then as '
         'root on this node acme --ha-standalone --yes.'),
        'Then move the database here: Settings → The database → Move to another database.',
        'Then build the cluster again: Settings → High availability → Make the bundle… here, '
        'and Join a cluster… on the other node.']
    return out


def db_move_refuse(store):
    """ApiError 409 when the guard says no."""
    g = db_move_guard(store)
    if g:
        raise ApiError(409, 'the database of this node is not moved: %s %s'
                       % (g['why'], ' '.join(g['how'][:1])))


# ---- what the page is told about here and there ---------------------------------
def db_move_target(c):
    """The database `c` names, said without its password."""
    out = {'engine': c.get('db_engine'), 'words': ENGINE_WORDS.get(c.get('db_engine'), ''),
           'where': db_where(c)}
    if c.get('db_engine') == 'sqlite':
        out['path'] = str(c.get('db_path') or DB_FILE)
    else:
        for k in ('db_host', 'db_port', 'db_name', 'db_user', 'db_tls', 'db_tls_ca'):
            out[k[3:]] = c.get(k)
        out['port'] = int(c.get('db_port') or MOVE_ENGINES[c['db_engine']]['port'])
    return out


def db_move_here(store):
    db = store.db
    tables = db_table_sizes(db)
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    return {'engine': db.engine, 'words': ENGINE_WORDS.get(db.engine), 'where': db.where(),
            'version': db.version(), 'size': db.size(), 'tables': tables,
            'rows': sum(t['rows'] for t in tables if t['table'] != 'meta'),
            'settings': {k: v for k, v in c.items() if k != 'db_password'},
            'has_password': bool(c.get('db_password'))}


def db_driver_hint(engine):
    """The exact package that gives this Python its driver, as install.sh puts it
    in: the distribution's for this Python where it has one, else acme's own
    virtual environment with it from PyPI."""
    if engine not in DRIVERS:
        return ''
    module, _pkg = DRIVERS[engine]
    name = 'psycopg2' if engine == 'postgres' else 'PyMySQL'
    v = '%d.%d' % sys.version_info[:2]
    exe = os.path.realpath(sys.executable)
    system = exe in (os.path.realpath('/usr/bin/python3'),)
    if sys.prefix != getattr(sys, 'base_prefix', sys.prefix):
        return '%s/bin/pip install %s' % (sys.prefix, 'psycopg2-binary' if engine == 'postgres'
                                          else 'PyMySQL')
    if shutil.which('dnf'):
        return 'dnf install %s' % ('python3-%s' % name if system else 'python%s-%s' % (v, name))
    if shutil.which('apt-get') and system:
        return 'apt install python3-%s' % name.lower()
    return './install.sh --with-db %s --yes   (it makes acme its own Python environment with ' \
           'the driver)' % engine


def db_drivers_said():
    out = {}
    for engine, (module, _pkg) in DRIVERS.items():
        try:
            __import__(module)
            out[engine] = {'ready': True, 'module': module}
        except Exception as e:                          # noqa: BLE001
            out[engine] = {'ready': False, 'module': module, 'install': db_driver_hint(engine),
                           'says': '%s is not in %s (%s)' % (module, sys.executable, e)}
    return out


def db_is_local(c):
    return str(c.get('db_host') or '').strip().lower().strip('[]') in LOCAL_HOSTS


def db_move_start_info(store):
    return {'here': db_move_here(store), 'guard': db_move_guard(store),
            'drivers': db_drivers_said(), 'engines': MOVE_ENGINES,
            'sqlite_default': str(DB_FILE), 'state_dir': str(STATE_DIR),
            'backup_dir': str(BACKUP_DIR), 'config_file': str(CONFIG_FILE),
            'helper': bool(web_helper_path()), 'root': os.geteuid() == 0,
            'move': db_move_state(), 'node': node_name(),
            'this_address': db_this_address('')}


def db_this_address(toward):
    """This machine's address as a server at `toward` sees it (best guess)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((str(toward or '192.0.2.1'), 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return '127.0.0.1'


# ---- the settings the page sends -------------------------------------------------
def db_move_settings(given, ca_pem=''):
    """The target as engine_asked reads it, and checked a little more: the file
    of SQLite, the TLS asked for, an authority sent as PEM kept beside the
    database."""
    given = dict(given or {})
    if given.get('db_engine') != 'sqlite' and given.get('db_password') is None:
        # Never the password of the database in use sent to another server.
        given['db_password'] = ''
    if given.get('db_engine') == 'sqlite':
        path = str(given.get('db_path') or '').strip() or str(DB_FILE)
        if not os.path.isabs(path) or '\x00' in path or not path.endswith('.db'):
            raise ValueError('the file of SQLite is a full path ending in .db, as %s' % DB_FILE)
        given['db_path'] = os.path.normpath(path)
    if str(given.get('db_tls') or '') not in ('', 'require', 'verify-ca', 'verify-full'):
        raise ValueError('the encryption is off, require or verify-full')
    pem = str(ca_pem or '').strip()
    if pem:
        if '-----BEGIN CERTIFICATE-----' not in pem or len(pem) > 200000:
            raise ValueError('the authority is a PEM file: -----BEGIN CERTIFICATE----- …')
        write_replacing(MOVE_CA_FILE, pem + '\n', 0o640)
        given['db_tls_ca'] = str(MOVE_CA_FILE)
    c = engine_asked(given)
    if c.get('db_engine') != 'sqlite':
        c['db_path'] = ''
    if str(c.get('db_tls') or '') in ('verify-ca', 'verify-full') and c.get('db_tls_ca') and \
            not os.path.isfile(str(c['db_tls_ca'])):
        raise ValueError('the authority file %s is not on this machine' % c['db_tls_ca'])
    return c


# ---- the checks, each a row with what to do --------------------------------------
def _db_fix(c, err):
    """What to do about a database that could not be reached, in plain words."""
    e = str(err).lower()
    eng = c.get('db_engine')
    host = str(c.get('db_host') or '127.0.0.1')
    port = int(c.get('db_port') or MOVE_ENGINES.get(eng, {}).get('port') or 0)
    svc = 'postgresql' if eng == 'postgres' else 'mariadb'
    if 'password authentication failed' in e or 'access denied' in e:
        return ('the account %s or its password is wrong - or that account may not come in from '
                'this machine (%s). Type the password again, or let the wizard make the account '
                '(Back → Make the database and the account).'
                % (c.get('db_user'), 'pg_hba.conf' if eng == 'postgres'
                   else "the host part of a MariaDB account, 'acme'@'this machine'"))
    if 'no pg_hba.conf entry' in e:
        return ('PostgreSQL does not let this machine in: add to its pg_hba.conf "hostssl %s %s '
                '%s/32 scram-sha-256" and reload it (systemctl reload postgresql).'
                % (c.get('db_name'), c.get('db_user'), db_this_address(host)))
    if ('does not exist' in e and 'database' in e) or 'unknown database' in e:
        return ('the database %s is not there yet: let the wizard make it (Back → Make the '
                'database and the account), or run the SQL it shows on that server.'
                % c.get('db_name'))
    if 'refused' in e or "can't connect" in e or 'could not connect' in e:
        return ('nothing answers at %s:%d. Is the server running (systemctl status %s)? Is the '
                'port right? On another machine: does it listen there (%s) and does its firewall '
                'let this machine in?'
                % (host, port, svc, 'listen_addresses in postgresql.conf' if eng == 'postgres'
                   else 'bind-address in its server.cnf'))
    if 'timeout' in e or 'timed out' in e:
        return ('no answer from %s:%d in %s s - a firewall in between, or the wrong address?'
                % (host, port, c.get('db_timeout_s') or 10))
    if 'name or service not known' in e or 'translate host name' in e or 'unknown host' in e \
            or 'nodename nor servname' in e:
        return 'the name %s does not resolve here: use its IP address, or put the name in DNS.' % host
    if 'ssl' in e or 'certificate' in e or 'tls' in e:
        return ('the encryption did not go: "require" needs TLS switched on at the server; '
                '"verify-full" also needs the authority that signed its certificate, and the '
                'server\'s name as that certificate has it.')
    if 'no module named' in e:
        return 'the driver is missing: %s' % db_driver_hint(eng)
    return 'read what the server said above; the address, the account and its password are asked in step 2.'


def _probe_rights(db):
    """What this account may do there: each right tried on a table of its own,
    taken away again."""
    t = 'acme_probe_move'
    tried = []
    steps = [('CREATE TABLE', 'CREATE TABLE %s (id INTEGER, x VARCHAR(40))' % t),
             ('CREATE INDEX', 'CREATE INDEX %s_x ON %s (x)' % (t, t)),
             ('INSERT', "INSERT INTO %s (id, x) VALUES (1, 'a')" % t),
             ('UPDATE', "UPDATE %s SET x = 'b' WHERE id = 1" % t),
             ('SELECT', 'SELECT COUNT(*) FROM %s' % t),
             ('DELETE', 'DELETE FROM %s' % t),
             ('ALTER', 'ALTER TABLE %s ADD COLUMN y INTEGER' % t),
             ('DROP', 'DROP TABLE %s' % t)]
    try:
        db.run('DROP TABLE IF EXISTS %s' % t)
    except Exception:                                   # noqa: BLE001
        pass
    for right, sql in steps:
        try:
            if right == 'SELECT':
                db.value(sql)
            else:
                db.run(sql)
            tried.append((right, True, ''))
        except Exception as e:                          # noqa: BLE001
            tried.append((right, False, str(e).split('\n')[0][:160]))
            if right == 'CREATE TABLE':
                break
    try:
        db.run('DROP TABLE IF EXISTS %s' % t)
    except Exception:                                   # noqa: BLE001
        pass
    return tried


def _rights_fix(c):
    if c['db_engine'] == 'postgres':
        return ('as postgres on that server: ALTER DATABASE "%s" OWNER TO "%s"; and in that '
                'database GRANT ALL ON SCHEMA public TO "%s";'
                % (c['db_name'], c['db_user'], c['db_user']))
    return ("as root on that server: GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'; FLUSH PRIVILEGES;"
            % (c['db_name'], c['db_user'], 'localhost' if db_is_local(c) else '%'))


def db_move_checks(store, c, overwrite=False):
    """Every check of the target, each {key, what, ok (True/False/'warn'),
    said, fix}; ok is False when one of them is."""
    rows = []

    def row(key, what, ok, said='', fix=''):
        rows.append({'key': key, 'what': what, 'ok': ok, 'said': str(said or ''),
                     'fix': str(fix or '')})
        return ok
    eng = c['db_engine']
    here_size = store.db.size()
    target = {'tables': [], 'rows': 0, 'ours': False, 'other_tables': 0}
    if same_database(c, store.db):
        row('same', 'Another database than the one in use', False,
            'that is the database acme uses now (%s)' % store.db.where(),
            'choose another one in step 1 or 2')
        return {'checks': rows, 'ok': False, 'target': target}
    if not sealing_key():
        row('key', 'The key of the sealed secrets', False, 'there is no %s' % sealing_key_path(),
            'put the key back first (it is beside every backup): without it nothing sealed opens')
    try:
        backup_room_check(store)
        free = shutil.disk_usage(str(BACKUP_DIR if BACKUP_DIR.exists() else STATE_DIR)).free
        row('backup', 'Room for the copy made first', True, '%s free in %s' % (
            human_bytes(free), BACKUP_DIR))
    except ValueError as e:
        row('backup', 'Room for the copy made first', False, str(e),
            'take old copies away from %s, or give the disk more room' % BACKUP_DIR)
    except OSError:
        pass
    db = None
    if eng == 'sqlite':
        path = Path(c.get('db_path') or DB_FILE)
        parent = path.parent
        if not parent.is_dir():
            row('file', 'The file', False, '%s is not a folder on this machine' % parent,
                'make it first (mkdir -p %s; chown acme: %s) or choose another place' % (parent, parent))
            return {'checks': rows, 'ok': False, 'target': target}
        writable = os.access(str(path if path.exists() else parent), os.W_OK)
        row('file', 'The file', writable,
            '%s %s' % (path, 'is there already' if path.exists() else 'is made there'),
            '' if writable else 'acme may not write there: chown acme: %s, or choose the state '
            'folder (%s)' % (parent, STATE_DIR))
        try:
            free = shutil.disk_usage(str(parent)).free
            need = here_size * 2 + (64 << 20)
            row('room', 'Room on the disk', free >= need, '%s free, about %s needed' % (
                human_bytes(free), human_bytes(need)),
                '' if free >= need else 'give %s more room, or choose another place' % parent)
        except OSError:
            pass
        if not writable:
            return {'checks': rows, 'ok': False, 'target': target}
        if path.exists():
            try:
                db = db_open(c)
            except Exception as e:                      # noqa: BLE001
                row('reach', 'It opens', False, str(e).split('\n')[0][:300],
                    'that file is not a SQLite database acme can open: choose another name')
                return {'checks': rows, 'ok': False, 'target': target}
            row('version', 'The engine', True, db.version())
    else:
        d = db_drivers_said().get(eng) or {}
        if not d.get('ready'):
            row('driver', 'The driver in acme\'s Python', False, d.get('says'),
                'install it: %s - then press Check again (if it still says so: systemctl '
                'restart acme)' % d.get('install'))
            return {'checks': rows, 'ok': False, 'target': target}
        row('driver', 'The driver in acme\'s Python', True, '%s, in %s' % (d.get('module'),
                                                                          sys.executable))
        try:
            db = db_open(c)
            db.value('SELECT 1')
        except Exception as e:                          # noqa: BLE001
            said = scrub_secret(str(e).split('\n')[0][:300])
            if c.get('db_password'):
                said = said.replace(str(c['db_password']), '…')
            row('reach', 'Reached as %s' % c.get('db_user'), False, said, _db_fix(c, said))
            if db is not None:
                db.close()
            return {'checks': rows, 'ok': False, 'target': target}
        row('reach', 'Reached as %s' % c.get('db_user'), True, db_where(c))
        ver = db.version()
        warn = ''
        if eng == 'postgres':
            m = re.search(r'PostgreSQL (\d+)', ver)
            if m and int(m.group(1)) < 16:
                warn = 'fine for one server; two acme nodes (high availability) need 16 or later'
        row('version', 'The engine', 'warn' if warn else True, ver + ('; ' + warn if warn else ''))
        enc = None
        try:
            if eng == 'postgres':
                enc = bool(db.value('SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()'))
            else:
                got = db.rows("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
                enc = bool(got and list(got[0].values())[-1])
        except Exception:                               # noqa: BLE001
            enc = None
        tls = str(c.get('db_tls') or '')
        if enc:
            row('tls', 'Encrypted', True, 'TLS%s' % ({'verify-full': ', the server\'s certificate '
                                                      'and name checked', 'verify-ca':
                                                      ', the server\'s certificate checked'}
                                                     .get(tls, '')))
        elif db_is_local(c):
            row('tls', 'Encrypted', True, 'not encrypted - on this machine, nothing travels '
                'over the network')
        else:
            row('tls', 'Encrypted', 'warn', 'not encrypted: the keys and passwords travel to '
                'that server as they are', 'choose require or verify-full in step 2 (the server '
                'needs TLS switched on)')
    if db is not None:
        try:
            names = db.tables()
            ours = [t for t in TABLES if t in names]
            target['tables'] = ours
            target['other_tables'] = len([n for n in names if n not in TABLES and
                                          n != 'acme_probe_move'])
            target['rows'] = sum(int(db.value('SELECT COUNT(*) FROM %s' % t) or 0)
                                 for t in ours if t not in ('meta',))
            target['ours'] = bool(ours)
            if True:
                tried = _probe_rights(db)
                bad = [r for r in tried if not r[1]]
                row('rights', 'What the account may do there', not bad,
                    ', '.join(r[0] for r in tried if r[1]) + (
                        '; not: %s' % '; '.join('%s (%s)' % (r[0], r[2]) for r in bad)
                        if bad else ''),
                    _rights_fix(c) if bad and eng != 'sqlite' else
                    ('acme may not write that file' if bad else ''))
            if target['rows']:
                newest = 0
                try:
                    newest = float(db.value('SELECT MAX(ts) FROM events') or 0)
                except Exception:                       # noqa: BLE001
                    pass
                when = (' (its newest event %s)' % datetime.fromtimestamp(newest).strftime(
                    '%d-%m-%Y %H:%M')) if newest else ''
                if overwrite:
                    row('empty', 'Empty', 'warn', 'it holds %s record(s) of acme%s - they are '
                        'thrown away, as you said' % (target['rows'], when))
                else:
                    row('empty', 'Empty', False, 'it holds %s record(s) of acme already%s'
                        % (target['rows'], when),
                        'if it is a copy left from before (an earlier move, the way back): '
                        'choose "throw what is there away" below. Otherwise choose another '
                        'database - two installations are never mixed.')
            else:
                row('empty', 'Empty', True, 'nothing of acme in it' + (
                    ' (%d table(s) of acme, empty - used as they are)' % len(ours) if ours else '')
                    + (' · %d other table(s), left alone' % target['other_tables']
                       if target['other_tables'] else ''))
            if eng == 'mariadb':
                got = db.row('SELECT @@character_set_database AS cs, @@collation_database AS co, '
                             '@@datadir AS dir')
                cs, co = str(got.get('cs') or ''), str(got.get('co') or '')
                row('charset', 'Characters', True if cs == 'utf8mb4' else 'warn',
                    '%s / %s; acme\'s tables are utf8mb4 and their names utf8mb4_bin (compared '
                    'byte for byte) whatever the database says' % (cs, co),
                    '' if cs == 'utf8mb4' else 'ALTER DATABASE `%s` CHARACTER SET utf8mb4 '
                    'COLLATE utf8mb4_bin;' % c['db_name'])
                if db_is_local(c) and got.get('dir') and os.path.isdir(str(got['dir'])):
                    _room_row(row, str(got['dir']), here_size)
            elif eng == 'postgres':
                got = db.row('SELECT pg_encoding_to_char(encoding) AS enc, datcollate AS co '
                             'FROM pg_database WHERE datname = current_database()')
                enc_, co = str(got.get('enc') or ''), str(got.get('co') or '')
                row('charset', 'Characters', True if enc_ == 'UTF8' else False,
                    '%s, collation %s%s' % (enc_, co, '' if co in ('C', 'C.UTF-8', 'C.utf8',
                                                                  'POSIX') else
                                            ' (names are compared as C by acme itself)'),
                    '' if enc_ == 'UTF8' else 'make the database again with ENCODING \'UTF8\' '
                    'TEMPLATE template0 (the wizard does)')
                if db_is_local(c):
                    try:
                        d = str(db.value('SHOW data_directory') or '')
                        if d and os.path.isdir(d):
                            _room_row(row, d, here_size)
                    except Exception:                   # noqa: BLE001
                        pass
        finally:
            db.close()
    elif eng == 'sqlite':
        row('empty', 'Empty', True, 'a new file')
    ok = not any(r['ok'] is False for r in rows)
    return {'checks': rows, 'ok': ok, 'target': target}


def _room_row(row, folder, here_size):
    try:
        free = shutil.disk_usage(folder).free
    except OSError:
        return
    need = here_size * 3 + (64 << 20)
    row('room', 'Room on the server\'s disk', True if free >= need else 'warn',
        '%s free under %s, about %s needed' % (human_bytes(free), folder, human_bytes(need)),
        '' if free >= need else 'give that disk more room before moving')


def human_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024.0
    return '%d B' % n


# ---- making the database and its account ------------------------------------------
def db_move_sql(c, password_shown=True):
    """The SQL to run on a server elsewhere, as its administrator."""
    eng, name, user = c['db_engine'], c['db_name'], c['db_user']
    pw = str(c.get('db_password') or '') if password_shown else '…'
    me = db_this_address(c.get('db_host'))
    if eng == 'mariadb':
        at = 'localhost' if db_is_local(c) else me
        return {'run': 'as root on the MariaDB server: mariadb -u root -p',
                'sql': "CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;\n"
                       "CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s';\n"
                       "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';\n"
                       "FLUSH PRIVILEGES;" % (name, user, at, pw, name, user, at),
                'also': '' if db_is_local(c) else
                ('The server must listen on its network address (bind-address in its server.cnf) '
                 'and its firewall let %s in on port %s.' % (me, c.get('db_port') or 3306))}
    return {'run': 'as postgres on the PostgreSQL server: sudo -u postgres psql',
            'sql': "CREATE ROLE \"%s\" WITH LOGIN PASSWORD '%s';\n"
                   "CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE template0;\n"
                   "\\c %s\n"
                   "GRANT ALL ON SCHEMA public TO \"%s\";" % (user, pw.replace("'", "''"), name,
                                                              user, name, user),
            'also': '' if db_is_local(c) else
            ('In its pg_hba.conf: "hostssl %s %s %s/32 scram-sha-256", listen_addresses = \'*\' in '
             'postgresql.conf, then systemctl reload postgresql (restart for listen_addresses); '
             'its firewall must let %s in on port %s.' % (name, user, me, me,
                                                          c.get('db_port') or 5432))}


DBMAKE_ASK = 'dbmake.ask'
DBMAKE_FILE = 'dbmake.json'
DBMAKE_LOCK = threading.Lock()


def db_make_here(c):
    """The database and its account made on the server on this machine, by root
    (the root helper, acme_web.py --dbmake): PostgreSQL as postgres, MariaDB as
    root over its socket. Returns what was made."""
    req = {'engine': c['db_engine'], 'name': c['db_name'], 'user': c['db_user'],
           'password': c['db_password'], 'port': int(c.get('db_port') or 0)}
    helper = web_helper_path()
    if os.geteuid() == 0:
        if not helper:
            raise ValueError('the root helper (acme_web.py) is not on this machine')
        r = subprocess.run([sys.executable, '-I', str(helper), '--dbmake'], input=json.dumps(req),
                           capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, ACME_STATE=str(STATE_DIR)))
        try:
            got = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise ValueError('the root helper said: %s' % (r.stderr or r.stdout).strip()[-300:])
    else:
        with DBMAKE_LOCK:
            ask_id = secrets.token_hex(8)
            WEB_DIR.mkdir(parents=True, exist_ok=True)
            tmp = WEB_DIR / ('.%s.%s' % (DBMAKE_ASK, secrets.token_hex(6)))
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(json.dumps(dict(req, id=ask_id)))
            os.replace(str(tmp), str(WEB_DIR / DBMAKE_ASK))
            end = time.time() + 90
            got = None
            while time.time() < end:
                try:
                    one = json.loads((WEB_DIR / DBMAKE_FILE).read_text())
                except (OSError, ValueError):
                    one = None
                if isinstance(one, dict) and one.get('id') == ask_id:
                    got = one
                    break
                time.sleep(0.4)
            if got is None:
                try:
                    (WEB_DIR / DBMAKE_ASK).unlink()
                except OSError:
                    pass
                raise ValueError('the root helper of this machine did not answer in 90 s - is '
                                 'acme-web.path running? (systemctl status acme-web.path) - or '
                                 'run the SQL shown on the server yourself')
    if not got.get('ok'):
        raise ValueError(str(got.get('said') or 'the root helper said no'))
    return list(got.get('said') or [])


# ---- the move itself ---------------------------------------------------------------
def _mv_save(force=True):
    data = {k: v for k, v in MOVE.items() if not k.startswith('_')}
    now = time.time()
    if not force and now - MOVE.get('_saved', 0) < 1:
        return
    MOVE['_saved'] = now
    try:
        write_replacing(MOVE_FILE, json.dumps(data, default=str), 0o640)
    except OSError as e:
        log('the state of the move could not be written: %s' % e, 'warn')


def _mv_step(key, state, said=''):
    for s in MOVE.get('steps') or []:
        if s['key'] == key:
            s['state'] = state
            if said or state in ('run', 'ok'):
                s['said'] = str(said or '')
            if state == 'run':
                s['began'] = time.time()
            elif state in ('ok', 'bad', 'skip'):
                s['ended'] = time.time()
    MOVE['step'] = key
    MOVE['at'] = time.time()
    _mv_save()


def db_move_state():
    """The move going on, or the last one, as the file beside the database says."""
    if MOVE.get('id'):
        return {k: v for k, v in MOVE.items() if not k.startswith('_')}
    try:
        got = json.loads(MOVE_FILE.read_text())
        return got if isinstance(got, dict) else None
    except (OSError, ValueError):
        return None


def _sealed_check(db, key, progress=None):
    """Every sealed value in `db` tried against `key`, each under the bind it was
    sealed with (the certificate manager's own binds too): (tried, opened, [bad])."""
    tried = opened = 0
    bad = []
    for table, col in sealed_columns():
        if table not in db.tables():
            continue
        if table == 'settings':
            for r in db.rows('SELECT k, v FROM settings WHERE v LIKE ?', ('%sealed:%',)):
                try:
                    value = json.loads(r['v'])
                except (TypeError, ValueError):
                    continue
                ok = _seal_tag_ok(key, value, None)
                if ok is None:
                    continue
                tried += 1
                opened += 1 if ok else 0
                if not ok:
                    bad.append('settings %s' % r['k'])
            continue
        last = 0
        while True:
            rows = db.rows("SELECT * FROM %s WHERE id > ? AND %s LIKE 'sealed:%%' ORDER BY id "
                           "LIMIT 500" % (table, col), (last,))
            if not rows:
                break
            last = rows[-1]['id']
            for r in rows:
                ok = _seal_tag_ok(key, r.get(col), seal_bind(table, r, col))
                if ok is None:
                    continue
                tried += 1
                opened += 1 if ok else 0
                if not ok:
                    bad.append('%s %s.%s' % (table, r.get('id'), col))
    return tried, opened, bad


def db_move_begin(store, c, by, overwrite=False, cli=False):
    """The move's state made afresh: what is moved where, and its steps."""
    here = store.counts()
    with MOVE_LOCK:
        if MOVE.get('id') and MOVE.get('state') in ('running', 'switching', 'restarting'):
            raise ValueError('a move is going on already (started by %s)' % MOVE.get('by'))
        MOVE.clear()
        MOVE_CANCEL.clear()
        MOVE.update({
            'id': secrets.token_hex(6), 'state': 'running', 'by': by, 'node': node_name(),
            'began': time.time(), 'ended': 0, 'error': '', 'fix': '', 'cli': bool(cli),
            'from': dict(db_move_target({k: CONFIG.get(k) for k in DB_KEYS}),
                         words=ENGINE_WORDS.get(store.db.engine), where=store.db.where(),
                         engine=store.db.engine),
            'to': db_move_target(c), 'overwrite': bool(overwrite),
            'steps': [{'key': k, 'what': w, 'state': 'wait', 'said': ''} for k, w in MOVE_STEPS],
            'tables': [{'table': t, 'whole': int(here.get(t, 0)), 'done': 0}
                       for t in TABLES if t != 'meta'],
            'whole': sum(here.values()), 'done': 0, 'backup': '', 'step': 'backup'})
        _mv_save()
    return MOVE['id']


def db_move_work(store, c, by, overwrite=False, progress=None, restart=None):
    """backup → the tables → every row → counted and opened → config.json →
    started again. `restart()` is called last (the daemon ends itself: systemd
    starts it on the new database)."""
    progress = progress or (lambda *a: None)
    began = MOVE.get('began') or time.time()

    def stop_if_asked():
        if MOVE_CANCEL.is_set():
            raise MoveCancelled('cancelled by %s' % (MOVE.get('cancelled_by') or by))
    far = None
    held = False
    try:
        _mv_step('backup', 'run', 'making a copy of what is here')
        progress(0, MOVE['whole'], 'making a copy of what is here')
        copy = make_backup(store, 'before moving to %s, by %s' % (
            ENGINE_WORDS.get(c['db_engine']), by))
        MOVE['backup'] = str(copy)
        _mv_step('backup', 'ok', '%s (with its key beside it)' % copy)
        stop_if_asked()
        # Nothing of the work here meanwhile (renewals, deployments): what it
        # wrote here would not be there.
        if DAEMON_DB[0] is not None:
            RESTORE_WHY[0] = 'the database is being moved'
            RESTORE_RUNNING.set()
            held = True
        _mv_step('schema', 'run')
        if overwrite:
            gone = db_empty(c)
            said_gone = ('%d table(s) of acme there thrown away; ' % len(gone)) if gone else ''
        else:
            said_gone = ''
        far = db_open(c, statement_s=0)
        far.make_tables()
        far.add_missing_columns()
        _mv_step('schema', 'ok', '%s%d table(s) ready in %s' % (said_gone, len(TABLES), far.where()))
        stop_if_asked()
        _mv_step('copy', 'run')
        tally = {}
        whole = MOVE['whole']

        def along(table, done):
            stop_if_asked()
            tally[table] = done
            for t in MOVE['tables']:
                if t['table'] == table:
                    t['done'] = done
            MOVE['done'] = sum(tally.values())
            progress(MOVE['done'], whole, '%s: %s' % (table, done))
            _mv_save(force=False)
        loaded = load_tables(far, copy, say=along)
        _mv_step('copy', 'ok', '%d row(s) in %d table(s)' % (sum(loaded.values()), len(loaded)))
        stop_if_asked()
        _mv_step('verify', 'run')
        short = []
        for t in MOVE['tables']:
            n = int(far.value('SELECT COUNT(*) FROM %s' % t['table']) or 0)
            t['there'] = n
            t['copied'] = int(loaded.get(t['table'], 0))
            if n != t['copied']:
                short.append('%s: %d there, %d in the copy' % (t['table'], n, t['copied']))
        if short:
            raise ValueError('the rows there are not the rows copied: %s' % '; '.join(short))
        key = sealing_key()
        tried, opened, bad = _sealed_check(far, key) if key else (0, 0, [])
        MOVE['sealed'] = {'tried': tried, 'opened': opened}
        if bad:
            raise ValueError('%d sealed secret(s) there do not open with the key: %s'
                             % (len(bad), ', '.join(bad[:5])))
        # What was written here while it was carried: the events (the move's own).
        carried = 0
        try:
            for r in store.db.rows('SELECT ts, kind, node, level, who, words FROM events '
                                   'WHERE ts >= ? ORDER BY ts', (began,)):
                far.insert('events', dict(r))
                carried += 1
        except Exception as e:                          # noqa: BLE001
            log('the events of the move could not be carried as well: %s' % e, 'warn')
        _mv_step('verify', 'ok', 'every table has the rows of the copy (%d); %d sealed secret(s), '
                 'each opened with the key%s' % (sum(loaded.values()), opened,
                                                  (' · %d event(s) of the move carried' % carried)
                                                  if carried else ''))
        stop_if_asked()
        far.close()
        far = None
        # From here on there is no Cancel: the new database is the one.
        MOVE['state'] = 'switching'
        _mv_step('switch', 'run')
        write_file_settings({k: c.get(k) for k in DB_KEYS})
        if c['db_engine'] == 'sqlite':
            for sfx in ('', '-wal', '-shm'):
                p = str(c.get('db_path') or DB_FILE) + sfx
                if os.path.exists(p) and os.geteuid() == 0:
                    try:
                        chown_to_service(p)
                    except Exception:                   # noqa: BLE001
                        pass
        store.add_event('settings', '%s moved the database to %s (%s): %d row(s), the old one (%s) '
                        'left as it was; acme starts again on the new one'
                        % (by, ENGINE_WORDS.get(c['db_engine']), db_where(c),
                           sum(loaded.values()), store.db.where()), 'warn', who=by)
        _mv_step('switch', 'ok', '%s now names %s' % (CONFIG_FILE, db_where(c)))
        MOVE['state'] = 'restarting'
        _mv_step('restart', 'run', 'acme stops here and starts again on %s' % db_where(c))
        progress(whole, whole, 'restarting on the new database')
        if restart:
            restart()
        return {'moved': True, 'to': db_where(c), 'copied': sum(loaded.values()),
                'backup': str(copy)}
    except MoveCancelled as e:
        _mv_fail('cancelled', str(e), 'nothing was switched: acme goes on with %s as before. '
                 'The other database may hold the tables made - the wizard throws them away '
                 'next time.' % store.db.where())
        raise
    except Exception as e:
        said = scrub_secret(str(e).split('\n')[0][:400])
        if c.get('db_password'):
            said = said.replace(str(c['db_password']), '…')
        if MOVE.get('step') in ('switch', 'restart'):
            fix = 'config.json may name the new database already: look at %s.' % CONFIG_FILE
        else:
            fix = (_db_fix(c, said) + ' ' if MOVE.get('step') == 'schema' else '') + \
                'Nothing was switched: acme goes on with %s as before.' % store.db.where()
        _mv_fail('failed', said, fix)
        raise
    finally:
        if far is not None:
            try:
                far.close()
            except Exception:                           # noqa: BLE001
                pass
        if held and MOVE.get('state') not in ('restarting',):
            RESTORE_RUNNING.clear()


def _mv_fail(state, error, fix):
    MOVE['state'] = state
    MOVE['error'] = error
    MOVE['fix'] = fix
    MOVE['ended'] = time.time()
    for s in MOVE.get('steps') or []:
        if s['state'] == 'run':
            s['state'] = 'bad'
            s['said'] = error
        elif s['state'] == 'wait':
            s['state'] = 'skip'
    _mv_save()


def db_move_job(store, c, by, overwrite=False):
    """The move as the daemon's one long job, the page following it."""
    db_move_begin(store, c, by, overwrite)

    def restart():
        log('the database is now %s; starting again on it' % db_where(c), 'warn')
        # systemd starts it again (Restart=always), on the new one.
        threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()

    def work(progress):
        return db_move_work(store, c, by, overwrite, progress, restart)
    try:
        db_job('moving to another database', work)
    except ValueError:
        MOVE.clear()
        raise
    return db_move_state()


def db_move_cancel(by):
    if not MOVE.get('id') or MOVE.get('state') != 'running':
        raise ValueError('there is nothing to cancel: %s' % (
            'it is switching over already - it cannot be stopped half-way'
            if MOVE.get('state') in ('switching', 'restarting') else 'no move is going on'))
    MOVE['cancelled_by'] = by
    MOVE_CANCEL.set()
    return {'message': 'the move stops at its next step'}


@hook('daemon_start')
def db_move_after_start(daemon):
    """Started again after a move: on the database it was moved to? Asked of it,
    and the move's end written down - the page that started it reads it here."""
    try:
        got = json.loads(MOVE_FILE.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(got, dict) or got.get('state') not in ('restarting', 'switching', 'running'):
        return
    MOVE.clear()
    MOVE.update(got)
    store = daemon.store
    if got.get('state') == 'running':
        _mv_fail('failed', 'it stopped with the acme that ran it (restarted, or stopped) before '
                 'the switch', 'nothing was switched: acme goes on with %s. Start the move again: '
                 'the wizard throws away what the first try left there.' % store.db.where())
        MOVE.clear()
        return
    to = got.get('to') or {}
    c = {'db_engine': to.get('engine'), 'db_host': to.get('host'), 'db_port': to.get('port'),
         'db_name': to.get('name'), 'db_path': to.get('path') or ''}
    _mv_step('restart', 'ok', 'acme %s started again' % __version__)
    _mv_step('reconnect', 'run')
    if not same_database(c, store.db):
        _mv_fail('failed', 'acme started again, but on %s - not on %s' % (store.db.where(),
                                                                           to.get('where')),
                 'config.json (%s) does not name the new database: put its address there, or '
                 'move again' % CONFIG_FILE)
        MOVE.clear()
        return
    try:
        counts = store.counts()
        opened = sealed_opens(store.db)
        key = sealing_key()
        tried, ok_, bad = _sealed_check(store.db, key) if key else (0, 0, [])
        MOVE['state'] = 'done'
        MOVE['ended'] = time.time()
        MOVE['result'] = {'rows': sum(counts.values()), 'version': store.db.version(),
                          'where': store.db.where(), 'sealed': {'tried': tried, 'opened': ok_}}
        _mv_step('reconnect', 'ok' if not bad and opened is not False else 'bad',
                 '%s answers: %d row(s), %d sealed secret(s) open' % (
                     store.db.version(), sum(counts.values()), ok_))
        if bad:
            MOVE['state'] = 'failed'
            MOVE['error'] = '%d sealed secret(s) do not open here' % len(bad)
        store.add_event('settings', 'acme runs on %s (%s) since the move by %s'
                        % (ENGINE_WORDS.get(store.db.engine), store.db.where(), got.get('by')),
                        who=got.get('by') or '')
    except Exception as e:                              # noqa: BLE001
        _mv_fail('failed', 'the new database did not answer as it should: %s'
                 % str(e).split('\n')[0][:300], 'look at the log (journalctl -u acme)')
    _mv_save()
    MOVE.clear()


# ---- the page's questions ------------------------------------------------------------
def db_move_api(h, s, act, b):
    """POST /api/db with action wiz_*: the wizard's questions."""
    store, by = h.store, s['name']
    if act == 'wiz_start':
        return db_move_start_info(store)
    if act == 'wiz_state':
        return {'move': db_move_state(), 'engine': store.db.engine, 'where': store.db.where()}
    if act == 'wiz_cancel':
        return db_move_cancel(by)
    if act == 'wiz_forget':
        if MOVE.get('id') and MOVE.get('state') in ('running', 'switching', 'restarting'):
            raise ApiError(409, 'a move is going on')
        try:
            MOVE_FILE.unlink()
        except OSError:
            pass
        return {'message': 'forgotten'}
    # Everything after this asks of the target: refused on a node of a cluster.
    db_move_refuse(store)
    c = db_move_settings(b.get('settings') or {}, b.get('ca_pem') or '')
    if act == 'wiz_check':
        got = db_move_checks(store, c, bool(b.get('overwrite')))
        got['to'] = db_move_target(c)
        got['here'] = {'engine': store.db.engine, 'where': store.db.where(),
                       'counts': store.counts(), 'size': store.db.size()}
        rows = sum(got['here']['counts'].values())
        got['estimate_s'] = int(rows / (3000.0 if c['db_engine'] != 'sqlite' else 8000.0)) + 15
        got['backup_dir'] = str(BACKUP_DIR)
        got['config_file'] = str(CONFIG_FILE)
        return got
    if act == 'wiz_sql':
        if c['db_engine'] == 'sqlite':
            raise ApiError(400, 'a file needs no SQL')
        made = ''
        if not c.get('db_password'):
            made = c['db_password'] = db_password_made()
        got = db_move_sql(c)
        got['password'] = made
        return got
    if act == 'wiz_make':
        if c['db_engine'] == 'sqlite':
            raise ApiError(400, 'a file needs nothing made')
        made = ''
        if not c.get('db_password'):
            made = c['db_password'] = db_password_made()
        if b.get('how') == 'admin':
            who = str(b.get('admin_user') or '').strip()
            if not who:
                raise ApiError(400, 'an administrator of that server is needed to make a '
                                    'database and an account on it')
            said = db_make(c, who, str(b.get('admin_password') or ''))
        else:
            if not db_is_local(c):
                raise ApiError(400, 'only a server on this machine is made by acme itself: run '
                                    'the SQL shown on that server, or give an administrator of it')
            said = db_make_here(c)
        store.add_event('settings', '%s made the database and the account for the move at %s'
                        % (by, db_where(c)), who=by)
        return {'made': said, 'password': made, 'message': 'made: %s' % '; '.join(said)}
    if act == 'wiz_go':
        got = db_move_checks(store, c, bool(b.get('overwrite')))
        if not got['ok']:
            bad = [r for r in got['checks'] if r['ok'] is False]
            raise ApiError(400, 'it is not ready: %s' % '; '.join(
                '%s - %s' % (r['what'], r['said']) for r in bad[:3]))
        if got['target']['rows'] and not b.get('overwrite'):
            raise ApiError(400, 'it holds records of acme already')
        try:
            return {'move': db_move_job(store, c, by, bool(b.get('overwrite')))}
        except ValueError as e:
            raise ApiError(409, str(e))
    raise ApiError(400, 'no such step of the wizard')


# ---- the command line: acme --db-move ENGINE ----------------------------------------
@hook('cli_args')
def db_move_cli_args(p):
    g = p.add_argument_group('MOVING TO ANOTHER DATABASE')
    g.add_argument('--db-move', metavar='ENGINE', choices=('sqlite', 'mariadb', 'postgres'),
                   help='everything carried into another database, checked there, config.json '
                        'switched and acme started again on it (--yes); its password in '
                        'ACME_DB_PASSWORD. Not on a node of a cluster')
    g.add_argument('--db-host', metavar='HOST', help='--db-move: the server (127.0.0.1)')
    g.add_argument('--db-port', metavar='N', type=int, default=None, help='--db-move: its port')
    g.add_argument('--db-name', metavar='NAME', help='--db-move: the database (acme)')
    g.add_argument('--db-user', metavar='NAME', help='--db-move: the account (acme)')
    g.add_argument('--db-path', metavar='FILE', help='--db-move sqlite: the file '
                   '(/var/lib/acme/acme.db)')
    g.add_argument('--db-overwrite', action='store_true', help='--db-move: what of acme is in '
                   'the other database already is thrown away first')
    g.add_argument('--db-check', action='store_true', help='--db-move: only the checks')


@hook('cli_run')
def db_move_cli(args):
    if not getattr(args, 'db_move', None):
        return None
    try:
        store = Storage(open_db())
    except DbError as e:
        raise SystemExit('acme: %s' % e)
    load_config(saved=store.settings_saved())
    HA_STORE['store'] = store
    g = db_move_guard(store)
    if g:
        print('acme: the database of this node is not moved: %s' % g['why'], file=sys.stderr)
        for line in g['how']:
            print('  - %s' % line, file=sys.stderr)
        return 3
    given = {'db_engine': args.db_move}
    if args.db_move == 'sqlite':
        given['db_path'] = args.db_path or str(DB_FILE)
    else:
        given.update({'db_host': args.db_host or '127.0.0.1',
                      'db_port': args.db_port or MOVE_ENGINES[args.db_move]['port'],
                      'db_name': args.db_name or 'acme', 'db_user': args.db_user or 'acme',
                      'db_password': os.environ.get('ACME_DB_PASSWORD') or ''})
        if getattr(args, 'db_tls_mode', None):
            given['db_tls'] = args.db_tls_mode
        if getattr(args, 'ca', None):
            given['db_tls_ca'] = args.ca
        if not given['db_password']:
            given['db_password'] = ask_password('the password of %s' % given['db_user'],
                                                env='ACME_DB_PASSWORD')
    try:
        c = db_move_settings(given)
    except ValueError as e:
        raise SystemExit('acme: %s' % e)
    got = db_move_checks(store, c, args.db_overwrite)
    for r in got['checks']:
        mark = {True: 'ok  ', False: 'FAIL', 'warn': 'warn'}[r['ok']]
        print('  %s %s: %s' % (mark, r['what'], r['said']))
        if r['fix'] and r['ok'] is not True:
            print('       what to do: %s' % r['fix'])
    if not got['ok']:
        print('acme: %s is not ready for the move' % db_where(c), file=sys.stderr)
        return 1
    if args.db_check:
        return 0
    if not args.yes:
        print('acme: this copies everything into %s, checks it there, writes it into %s and '
              'starts acme again on it (the database here is left as it is) - again with --yes'
              % (db_where(c), CONFIG_FILE), file=sys.stderr)
        return 2
    who = 'command line'
    db_move_begin(store, c, who, args.db_overwrite, cli=True)
    shown = {}

    def progress(done, whole, says):
        if time.time() - shown.get('at', 0) > 2 or done == whole:
            shown['at'] = time.time()
            print('  … %s (%s of %s)' % (says, done, whole))

    def restart():
        if os.environ.get('ACME_NO_RESTART') or os.geteuid() != 0:
            print('  acme has to be started again on it: systemctl restart acme')
            return
        subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
    try:
        got = db_move_work(store, c, who, args.db_overwrite, progress, restart)
    except Exception as e:                              # noqa: BLE001
        print('acme: the move failed: %s' % (MOVE.get('error') or e), file=sys.stderr)
        if MOVE.get('fix'):
            print('  %s' % MOVE['fix'], file=sys.stderr)
        return 1
    for s_ in MOVE.get('steps') or []:
        if s_['state'] == 'ok':
            print('  ok   %s: %s' % (s_['what'], s_['said']))
    print('acme: moved to %s; the copy made first: %s; the old database is left as it was'
          % (got['to'], got['backup']))
    return 0
