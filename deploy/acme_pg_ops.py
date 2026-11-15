"""acme_pg_ops.py - what root does to a database server on its own machine (1.0.110).

Shared by the root helper's PostgreSQL parts and by acme-db-agent (the small
agent on a database server of its own, docs/external-database.md). The root
helper (acme_web.py) is not changed by it: this module loads acme_web.py as a
library - the very functions that check and do it today (pgtls_checked,
pgtls_server, pgtls_hba, pgtls_peer, pgtls_hba_off, pgtls_server_off,
pgtls_ha_open, dbmake_do, pglog_part, pg_restart_here, pg_path_checked,
pg_file_put ...) - and adds what acme's command line did as root with its own
code until now (wal_level, listen_addresses, the account able to replicate,
pg_hba.conf lines for the other servers, the publication, the firewall), done
the same careful way: every value checked against the one shape it may have,
files of PostgreSQL's written through acme_web.py's link-safe helpers and put
back when PostgreSQL does not read them, never a shell.

Each op takes (args, conf) and returns a dict, or raises Refused. `conf` is
the agent's own configuration (root's): the port of the server, how to
restart it, where MariaDB's socket is. Nothing in `args` names a file.
"""
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time

_HERE = os.path.dirname(os.path.realpath(__file__))


def _load_web():
    """acme_web.py beside this file, as a module (it runs nothing when imported)."""
    spec = importlib.util.spec_from_file_location('acme_web_lib', os.path.join(_HERE, 'acme_web.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


W = _load_web()
Refused = W.Refused
HA_PUB = 'acme_pub'
HA_PUB_OLD = 'opt_pub'
HA_SLOT_KEEP = '16GB'
PEERS_MOST = 8


# ---- what a request may hold -------------------------------------------------------
def name_checked(v, what):
    """acme's database or account: a plain name, not one of the server's own nor a word
    of pg_hba.conf (as acme_web.pgtls_checked has it)."""
    v = str(v or '')
    if not W.PG_NAME_RE.match(v):
        raise Refused('%s is letters, digits and _ only, starting with a letter' % what)
    low = v.lower()
    if low in W.PG_HBA_WORDS or low.startswith('pg_') or low in (
            'postgres', 'template0', 'template1', 'root', 'replication', 'mysql', 'sys',
            'information_schema', 'performance_schema'):
        raise Refused('%s is the database server\'s own, not acme\'s' % v)
    return v


def password_checked(v):
    pw = str(v or '')
    if not W.DBMAKE_PW_RE.match(pw) or "'" in pw or '\\' in pw:
        raise Refused('the password is 8 to 128 printable characters, without \' and \\')
    return pw


def addresses_checked(v, what='the addresses'):
    if v in (None, ''):
        return []
    if not isinstance(v, list) or len(v) > PEERS_MOST:
        raise Refused('%s are a list of at most %d' % (what, PEERS_MOST))
    out = []
    for a in v:
        try:
            one = str(W.plain(str(a or '').strip(), 'address'))
        except ValueError:
            raise Refused('%s are plain addresses (192.0.2.10), not %r' % (what, str(a)[:60]))
        if one not in out:
            out.append(one)
    return out


def pg_port(conf):
    return int(conf.get('pg_port') or 5432)


def sql(conf, text, db='postgres'):
    return W.pg_sql(pg_port(conf), text, db)


# ---- pg_hba.conf ---------------------------------------------------------------------
def hba_add(conf, db, user, peers, why):
    """A line for each address not let in yet, in front (read top down): host, or hostssl
    when one for it is there already. The file as it was kept beside it, put back when
    PostgreSQL does not read the new one."""
    hba = W.pg_path_checked(sql(conf, 'SHOW hba_file'))
    text = W.pg_file_read(hba)
    added = []
    for who in peers:
        net = W.pg_peer_net(who)
        line = 'host    %s    %s    %s    scram-sha-256' % (db, user, net)
        if line in text or ('hostssl' + line[4:]) in text:
            continue
        # one of acme's for it in another spelling (spaces) counts too
        if any(len(f) >= 4 and f[0] in ('host', 'hostssl') and f[1] == db and f[2] == user
               and f[3] == net for f in (x.split() for x in text.split('\n'))):
            continue
        added.append(line)
    if not added:
        return []
    st = os.lstat(hba)
    W.pg_file_copy(hba, hba + '.acme-before-' + why)
    W.pg_file_put(hba, '# acme (%s, %s)\n%s\n%s' % (why, time.strftime('%Y-%m-%d'), '\n'.join(added),
                                                     text), stat.S_IMODE(st.st_mode), st.st_uid,
                  st.st_gid)
    try:
        sql(conf, 'SELECT pg_reload_conf()')
        bad = sql(conf, 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')
        if bad not in ('', '0'):
            raise Refused('PostgreSQL does not read pg_hba.conf as written')
    except Refused:
        W.pg_file_copy(hba + '.acme-before-' + why, hba)
        sql(conf, 'SELECT pg_reload_conf()')
        raise
    return ['%s: %s' % (hba, x) for x in added]


# ---- the ops ---------------------------------------------------------------------------
def op_pgtls(args, conf):
    """The link's and the database's TLS, exactly as the root helper does it on acme's own
    machine (pgtls.ask): server, hba, peer, hba_off, server_off, ha_open. `peers` (a list)
    does hba / hba_off for each of them: the other database server and the other acme node."""
    if not isinstance(args, dict):
        raise Refused('the request is not an object')
    r = dict(args)
    r['port'] = pg_port(conf)            # the server this agent looks after, never another
    r.setdefault('id', '%016x' % int(time.time() * 1000))
    peers = addresses_checked(r.pop('peers', None), 'the other servers')
    do = r.get('do')
    fn = {'server': W.pgtls_server, 'peer': W.pgtls_peer, 'hba': W.pgtls_hba,
          'hba_off': W.pgtls_hba_off, 'server_off': W.pgtls_server_off,
          'ha_open': W.pgtls_ha_open}
    if do in ('hba', 'hba_off') and peers:
        said = []
        for p in peers:
            one = W.pgtls_checked(dict(r, peer=p))
            said.append(fn[do](one)['said'])
        return {'said': '; '.join(said)}
    one = W.pgtls_checked(r)
    return fn[one['do']](one)


def op_pg_prepare(args, conf):
    """What  acme --ha-setup / --ha-join  did as root on the node's own PostgreSQL
    (pg_prepare_local), for a server of its own: logical WAL, listening on the network,
    16 GB kept for a node away, acme's account able to replicate and to subscribe, the
    database (UTF-8), and pg_hba.conf letting in the addresses given. Never restarts:
    says whether it has to (pg_restart)."""
    db = name_checked(args.get('db'), 'the database')
    user = name_checked(args.get('user'), 'the account')
    pw = password_checked(args.get('password'))
    peers = addresses_checked(args.get('peers'), 'the addresses let in')
    replicate = bool(args.get('replicate', True))
    said, restart = [], False
    major = int(sql(conf, 'SHOW server_version_num')) // 10000
    if replicate and major < 16:
        raise Refused('PostgreSQL %d is there; replicating both ways needs 16 or later' % major)
    want = [('listen_addresses', '*')]
    if replicate:
        want = [('wal_level', 'logical'), ('listen_addresses', '*'),
                ('max_slot_wal_keep_size', HA_SLOT_KEEP)]
    for key, value in want:
        now = sql(conf, 'SHOW %s' % key)
        if key == 'max_slot_wal_keep_size' and now.upper() == value:
            continue
        if key == 'listen_addresses' and now.strip() in ('*', '0.0.0.0'):
            continue
        if now != value:
            sql(conf, 'ALTER SYSTEM SET %s = %s' % (key, W.pg_lit(value)))
            said.append('%s = %s (was %s)' % (key, value, now))
            if key != 'max_slot_wal_keep_size':
                restart = True
    quiet = "SET log_statement = 'none';\nSET log_min_error_statement = 'panic';\n"
    have = sql(conf, 'SELECT 1 FROM pg_roles WHERE rolname = %s' % W.pg_lit(user)) == '1'
    if have and sql(conf, 'SELECT 1 FROM pg_roles WHERE rolname = %s AND (rolsuper OR '
                    'rolcreaterole OR rolcreatedb OR rolbypassrls)' % W.pg_lit(user)) == '1':
        raise Refused('the account %s is there with rights over the whole server - not taken '
                      'over; choose another name' % user)
    sql(conf, quiet + '%s ROLE "%s" WITH LOGIN PASSWORD %s' % ('ALTER' if have else 'CREATE', user,
                                                                W.pg_lit(pw)))
    said.append('the account %s %s' % (user, 'has the password given' if have else 'was made'))
    if replicate:
        sql(conf, 'ALTER ROLE "%s" REPLICATION' % user)
        sql(conf, 'GRANT pg_create_subscription TO "%s"' % user)
    owner = sql(conf, 'SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s'
                % W.pg_lit(db))
    if not owner:
        try:
            sql(conf, "CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE template0 "
                      "LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'" % (db, user))
        except Refused:
            sql(conf, "CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE template0"
                % (db, user))
        said.append('the database %s was made' % db)
    elif owner != user:
        raise Refused('the database %s is there, owned by %s - not taken over' % (db, owner))
    sql(conf, 'GRANT CREATE ON DATABASE "%s" TO "%s"' % (db, user))
    sql(conf, 'GRANT ALL ON SCHEMA public TO "%s"' % user, db=db)
    said += hba_add(conf, db, user, peers, 'ha')
    sql(conf, 'SELECT pg_reload_conf()')
    pending = sql(conf, "SELECT string_agg(name, ',') FROM pg_settings WHERE pending_restart")
    restart = restart or bool(pending.strip())
    return {'said': said, 'restart': restart, 'major': major}


def op_pg_allow(args, conf):
    """pg_hba.conf lets these addresses into acme's database (an acme node, the other
    database server), host - hostssl once the link's TLS is on (pgtls hba)."""
    db = name_checked(args.get('db'), 'the database')
    user = name_checked(args.get('user'), 'the account')
    peers = addresses_checked(args.get('peers'), 'the addresses let in')
    return {'said': hba_add(conf, db, user, peers, 'allow') or ['pg_hba.conf lets them in already']}


def op_pg_publication(args, conf):
    """Every table of acme's database published (inserts, updates, deletes - never
    TRUNCATE), as acme --ha-setup did as postgres: FOR ALL TABLES needs a superuser."""
    db = name_checked(args.get('db'), 'the database')
    if sql(conf, 'SELECT 1 FROM pg_publication WHERE pubname = %s' % W.pg_lit(HA_PUB_OLD), db) == '1':
        sql(conf, 'ALTER PUBLICATION %s RENAME TO %s' % (HA_PUB_OLD, HA_PUB), db)
    if sql(conf, 'SELECT 1 FROM pg_publication WHERE pubname = %s' % W.pg_lit(HA_PUB), db) == '1':
        return {'said': 'every table of %s is published already (%s)' % (db, HA_PUB)}
    sql(conf, "CREATE PUBLICATION %s FOR ALL TABLES WITH (publish = 'insert, update, delete')"
        % HA_PUB, db)
    return {'said': 'every table of %s is published (%s)' % (db, HA_PUB)}


def _restart_cmd(conf, key):
    cmd = conf.get(key)
    if cmd is None:
        return None
    if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd) or \
            not cmd[0].startswith('/'):
        raise Refused('%s in the agent\'s configuration is a list: an absolute program and its '
                      'arguments' % key)
    return cmd


def op_pg_restart(args, conf):
    """PostgreSQL started again - its systemd unit or Debian's pg_ctlcluster (as the root
    helper does it), or the command the agent's configuration names - and waited for."""
    cmd = _restart_cmd(conf, 'pg_restart_cmd')
    if cmd is None:
        return {'said': 'PostgreSQL started again (%s)' % W.pg_restart_here(pg_port(conf))}
    got = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd='/')
    if got.returncode != 0:
        raise Refused('the restart said: %s' % (got.stderr or got.stdout).strip()[-300:])
    for _ in range(60):
        try:
            if sql(conf, 'SELECT 1') == '1':
                return {'said': 'PostgreSQL started again (%s)' % os.path.basename(cmd[0])}
        except Refused:
            pass
        time.sleep(1)
    raise Refused('PostgreSQL did not come back after its restart')


def op_pg_reload(args, conf):
    sql(conf, 'SELECT pg_reload_conf()')
    return {'said': 'PostgreSQL read its configuration again'}


def op_pglog(args, conf):
    """The lines of PostgreSQL's log about logical replication (the root helper's pglog):
    asked through a folder of the agent's own, answered the same way."""
    work = os.path.join(str(conf.get('state') or '/var/lib/acme-db-agent'), 'web')
    os.makedirs(work, mode=0o700, exist_ok=True)
    W.STATE_DIR = os.path.dirname(work)
    if W.FD[0] is not None:
        try:
            os.close(W.FD[0])
        except OSError:
            pass
        W.FD[0] = None
    with open(os.path.join(work, W.PGLOG_ASK), 'w') as f:
        f.write(json.dumps({'port': pg_port(conf)}))
    W.pglog_part()
    with open(os.path.join(work, W.PGLOG_FILE)) as f:
        return json.load(f)


def op_dbmake(args, conf):
    """A database and its account made on this server (the root helper's dbmake), and let
    in from the acme nodes given (pg_hba.conf; MariaDB: the account at those addresses)."""
    eng = str(conf.get('engine') or 'postgres')
    req = {'engine': eng, 'name': name_checked(args.get('name'), 'the database'),
           'user': name_checked(args.get('user'), 'the account'),
           'password': password_checked(args.get('password')),
           'port': pg_port(conf) if eng == 'postgres' else int(conf.get('my_port') or 3306),
           'id': 'agent'}
    peers = addresses_checked(args.get('peers'), 'the acme nodes')
    got = W.dbmake_do(json.dumps(req))
    if not got.get('ok'):
        raise Refused(str(got.get('said') or 'it was not made'))
    said = list(got.get('said') or [])
    if eng == 'postgres':
        said += hba_add(conf, req['name'], req['user'], peers, 'dbmake')
        now = sql(conf, 'SHOW listen_addresses')
        if now.strip() not in ('*', '0.0.0.0') and peers:
            sql(conf, "ALTER SYSTEM SET listen_addresses = '*'")
            said.append('listen_addresses = * (was %s) - PostgreSQL has to start again' % now)
    else:
        sqls = ['SET SESSION sql_log_off = 1;']
        for at in peers:
            sqls += ["CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s';" % (req['user'], at, req['password']),
                     "ALTER USER '%s'@'%s' IDENTIFIED BY '%s';" % (req['user'], at, req['password']),
                     "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';" % (req['name'], req['user'], at)]
            said.append("the account '%s'@'%s'" % (req['user'], at))
        if peers:
            my_sql(conf, '\n'.join(sqls + ['FLUSH PRIVILEGES;']), secret=req['password'])
    return {'said': said}


# ---- MariaDB ----------------------------------------------------------------------------
def my_prog():
    prog = shutil.which('mariadb') or shutil.which('mysql')
    if not prog:
        raise Refused('neither mariadb nor mysql (the client) is on this machine')
    return prog


def my_sql(conf, text, secret=''):
    got = subprocess.run([my_prog(), '--protocol=socket', '-u', 'root', '--batch', '-N'],
                         input=text + '\n', capture_output=True, text=True, timeout=60)
    if got.returncode != 0:
        said = (got.stderr or got.stdout).strip()
        raise Refused('MariaDB said: %s' % (said.replace(secret, '…') if secret else said)[:300])
    return got.stdout.strip()


MY_CNF_NAME = 'zz-acme-tls.cnf'


def _my_cnf_dir(conf):
    d = conf.get('my_cnf_dir')
    if d:
        return str(d)
    for d in ('/etc/my.cnf.d', '/etc/mysql/mariadb.conf.d', '/etc/mysql/conf.d'):
        if os.path.isdir(d):
            return d
    raise Refused('no folder of MariaDB\'s configuration was found (/etc/my.cnf.d)')


def op_my_tls(args, conf):
    """MariaDB given a certificate from acme's authority: the key, the certificate and the
    authorities into the agent's folder for it (the mysql account's to read), a file of
    acme's own in MariaDB's configuration folder naming them, and MariaDB started again
    the first time - after that FLUSH SSL takes a renewed one without a restart. Checked
    to have TLS on afterwards, put back as it was when it does not."""
    pem = W.pem_set(args.get('cert'), args.get('key'))
    if not pem:
        raise Refused('the certificate and its key are missing')
    trust = str(args.get('trust') or '').strip()
    if not W.CERT_RE.match(trust):
        raise Refused('the authorities are PEM certificates')
    with tempfile.TemporaryDirectory(prefix='acme-mytls-') as t:
        for n, v in (('ca.pem', trust + '\n'), ('c.pem', pem['cert'])):
            with open(os.path.join(t, n), 'w') as f:
                f.write(v)
        W.openssl(['verify', '-CAfile', os.path.join(t, 'ca.pem'), os.path.join(t, 'c.pem')],
                  'the certificate is not from these authorities')
    folder = str(conf.get('my_tls_dir') or '/etc/acme-db-agent/mariadb')
    os.makedirs(folder, mode=0o750, exist_ok=True)
    try:
        import pwd
        pw = pwd.getpwnam(str(conf.get('my_user') or 'mysql'))
        uid, gid = pw.pw_uid, pw.pw_gid
    except (KeyError, ImportError):
        uid = gid = None
    if uid is not None:
        os.chown(folder, 0, gid)
    files = {'server.key': (pem['key'], 0o640), 'server.crt': (pem['cert'], 0o644),
             'ca.pem': (trust + '\n', 0o644)}
    was = {}
    for n in files:
        try:
            was[n] = W.pg_file_read(os.path.join(folder, n))
        except (OSError, Refused):
            was[n] = None
    for n, (text, mode) in files.items():
        W.pg_file_put(os.path.join(folder, n), text, mode, 0 if uid is not None else None, gid)
    cnf_dir = _my_cnf_dir(conf)
    cnf = os.path.join(cnf_dir, MY_CNF_NAME)
    body = ('# written by acme-db-agent - acme renews these; take this file away to stop it\n'
            '[mariadb]\nssl_cert = %s\nssl_key = %s\nssl_ca = %s\n' % (
                os.path.join(folder, 'server.crt'), os.path.join(folder, 'server.key'),
                os.path.join(folder, 'ca.pem')))
    try:
        cnf_was = W.pg_file_read(cnf)
    except (OSError, Refused):
        cnf_was = None
    how = ''
    try:
        if cnf_was == body and my_sql(conf, "SELECT @@have_ssl") == 'YES':
            my_sql(conf, 'FLUSH SSL')
            how = 'FLUSH SSL - no restart'
        else:
            W.write_root(cnf, body, 0o644)
            how = op_my_restart({}, conf)['said']
        if my_sql(conf, 'SELECT @@have_ssl') != 'YES':
            raise Refused('MariaDB does not have TLS on with it')
    except Exception:
        for n, old in was.items():
            p = os.path.join(folder, n)
            if old is None:
                try:
                    os.unlink(p)
                except OSError:
                    pass
            else:
                W.pg_file_put(p, old, files[n][1], 0 if uid is not None else None, gid)
        if cnf_was is None:
            try:
                os.unlink(cnf)
            except OSError:
                pass
        else:
            W.write_root(cnf, cnf_was, 0o644)
        raise
    end = W.openssl(['x509', '-noout', '-enddate'], 'the certificate', pem['cert'])
    import ssl as _ssl
    return {'said': 'MariaDB answers over TLS with its certificate from acme\'s authority (%s)' % how,
            'cert_end': float(_ssl.cert_time_to_seconds(end.strip().split('=', 1)[-1]))}


def op_my_restart(args, conf):
    cmd = _restart_cmd(conf, 'my_restart_cmd')
    if cmd is None:
        unit = ''
        for u in ('mariadb', 'mysqld', 'mysql'):
            if subprocess.run(['systemctl', 'is-active', '--quiet', u],
                              capture_output=True).returncode == 0:
                unit = u
                break
        if not unit:
            raise Refused('no running service of MariaDB was found - restart it yourself')
        cmd = ['systemctl', 'restart', unit]
    got = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd='/')
    if got.returncode != 0:
        raise Refused('the restart said: %s' % (got.stderr or got.stdout).strip()[-300:])
    for _ in range(60):
        try:
            if my_sql(conf, 'SELECT 1') == '1':
                return {'said': 'MariaDB started again (%s)' % ' '.join(cmd[-2:])}
        except Refused:
            pass
        time.sleep(1)
    raise Refused('MariaDB did not come back after its restart')


# ---- the firewall -----------------------------------------------------------------------
def op_fw_allow(args, conf):
    """firewalld lets these addresses reach the database server's port (and the agent's,
    with `agent`) - one rich rule each, permanent and now. Without firewalld running,
    nothing to do (said)."""
    peers = addresses_checked(args.get('peers'), 'the addresses let in')
    ports = [pg_port(conf) if str(conf.get('engine') or 'postgres') == 'postgres'
             else int(conf.get('my_port') or 3306)]
    if args.get('agent'):
        ports.append(int(conf.get('port') or 9443))
    if os.environ.get('ACME_AGENT_NO_FIREWALL') or not shutil.which('firewall-cmd') or \
            subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode != 0:
        return {'said': ['firewalld is not running here: nothing to open (open TCP %s from %s '
                         'in the firewall that is)' % (', '.join(map(str, ports)),
                                                     ', '.join(peers) or '-')], 'firewalld': False}
    said = []
    for p in peers:
        a = ipaddress.ip_address(p)
        for port in ports:
            rule = ('rule family="%s" source address="%s/%d" port port="%d" protocol="tcp" accept'
                    % ('ipv4' if a.version == 4 else 'ipv6', a, 32 if a.version == 4 else 128, port))
            for extra in (['--permanent'], []):
                got = subprocess.run(['firewall-cmd'] + extra + ['--add-rich-rule=' + rule],
                                     capture_output=True, text=True)
                if got.returncode != 0 and 'ALREADY_ENABLED' not in (got.stderr + got.stdout):
                    raise Refused('firewalld: %s' % (got.stderr or got.stdout).strip()[-200:])
            said.append('firewalld lets %s reach TCP %d' % (p, port))
    return {'said': said, 'firewalld': True}


# ---- what the machine is ------------------------------------------------------------------
def facts(conf):
    out = {'host': socket.gethostname(), 'fqdn': socket.getfqdn(), 'cpus': os.cpu_count(),
           'engine': str(conf.get('engine') or 'postgres'), 'at': time.time()}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    out['ram'] = int(line.split()[1]) * 1024
                elif line.startswith('MemAvailable:'):
                    out['avail'] = int(line.split()[1]) * 1024
    except OSError:
        pass
    try:
        out['load'] = list(os.getloadavg())
        with open('/proc/uptime') as f:
            out['uptime'] = float(f.read().split()[0])
        with open('/proc/cpuinfo') as f:
            out['virtual'] = ' hypervisor' in f.read()
    except OSError:
        pass
    if out['engine'] == 'postgres':
        try:
            row = sql(conf, "SELECT current_setting('server_version') || '|' || "
                            "current_setting('data_directory') || '|' || current_setting('ssl') || "
                            "'|' || current_setting('wal_level') || '|' || "
                            "extract(epoch from pg_postmaster_start_time())::bigint || '|' || "
                            "(SELECT count(*) FROM pg_stat_activity)")
            v, data, ssl_on, wal, started, conns = row.split('|')
            out.update(running=True, version=v, ssl=ssl_on == 'on', wal_level=wal,
                       started=float(started), connections=int(conns))
            try:
                d = W.pg_path_checked(data, folder=True)
                s = os.statvfs(d)
                out['disk'] = {'total': s.f_blocks * s.f_frsize, 'free': s.f_bavail * s.f_frsize}
            except (Refused, OSError):
                pass
        except Refused as e:
            out.update(running=False, said=str(e)[:200])
    else:
        try:
            got = my_sql(conf, "SELECT CONCAT(VERSION(), '|', @@have_ssl, '|', @@datadir)")
            v, ssl_on, data = got.split('|')
            out.update(running=True, version=v, ssl=ssl_on == 'YES')
            try:
                s = os.statvfs(data)
                out['disk'] = {'total': s.f_blocks * s.f_frsize, 'free': s.f_bavail * s.f_frsize}
            except OSError:
                pass
        except Refused as e:
            out.update(running=False, said=str(e)[:200])
    return out


def op_status(args, conf):
    return {'facts': facts(conf)}


# ---- how busy the machine is: the header's meter, the same shape as a node's ---------------
LOAD_LAST = {'raw': None}


def _load_raw():
    raw = {'at': time.time()}
    try:
        with open('/proc/stat') as f:
            v = [int(x) for x in f.readline().split()[1:9]]
        v += [0] * (8 - len(v))
        raw['cpu_idle'], raw['cpu_all'] = v[3] + v[4], sum(v)
    except (OSError, ValueError):
        pass
    try:
        mem = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, _s, rest = line.partition(':')
                mem[k] = int(rest.split()[0]) * 1024
        raw['mem_total'] = mem.get('MemTotal', 0)
        raw['mem_used'] = mem.get('MemTotal', 0) - mem.get('MemAvailable', mem.get('MemFree', 0))
        raw['swap_used'] = mem.get('SwapTotal', 0) - mem.get('SwapFree', 0)
    except (OSError, ValueError, IndexError):
        pass
    try:
        rd = wr = 0
        whole = set(os.listdir('/sys/block'))
        with open('/proc/diskstats') as f:
            for line in f:
                x = line.split()
                if len(x) < 10 or x[2] not in whole or \
                        x[2].startswith(('loop', 'ram', 'dm-', 'zram', 'sr')):
                    continue
                rd += int(x[5]) * 512
                wr += int(x[9]) * 512
        raw['disk_rd'], raw['disk_wr'] = rd, wr
    except (OSError, ValueError):
        pass
    try:
        rx = tx = 0
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, _s, rest = line.partition(':')
                name = name.strip()
                if name == 'lo' or name.startswith(('veth', 'docker', 'br-', 'virbr', 'cni', 'flannel')):
                    continue
                x = rest.split()
                rx += int(x[0])
                tx += int(x[8])
        raw['net_rx'], raw['net_tx'] = rx, tx
    except (OSError, ValueError, IndexError):
        pass
    return raw


def op_load(args, conf):
    """What the header's meter shows of a node (acme's server_load(): cpu %, mem_used /
    mem_total, swap_used, disk_rd / disk_wr and net_rx / net_tx in B/s, load, cores), of this
    database server - and the database's own: its version, since when it runs, connections,
    how far behind replication is, the size of acme's database, the disk it is on."""
    raw = _load_raw()
    was = LOAD_LAST['raw']
    out = {'at': raw['at'], 'cores': os.cpu_count() or 1, 'mem_total': raw.get('mem_total'),
           'mem_used': raw.get('mem_used'), 'swap_used': raw.get('swap_used')}
    try:
        out['load'] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        out['load'] = None
    if was:
        dt = max(0.2, raw['at'] - was['at'])
        if raw.get('cpu_all') and was.get('cpu_all') and raw['cpu_all'] > was['cpu_all']:
            busy = 1 - (raw['cpu_idle'] - was['cpu_idle']) / float(raw['cpu_all'] - was['cpu_all'])
            out['cpu'] = round(max(0.0, min(1.0, busy)) * 100, 1)
        for k in ('disk_rd', 'disk_wr', 'net_rx', 'net_tx'):
            if k in raw and k in was and raw[k] >= was[k]:
                out[k] = round((raw[k] - was[k]) / dt)
        out['over_s'] = round(dt, 1)
    LOAD_LAST['raw'] = raw
    f = facts(conf)
    db = {'engine': f.get('engine'), 'running': f.get('running'), 'version': f.get('version'),
          'started': f.get('started'), 'connections': f.get('connections'), 'ssl': f.get('ssl'),
          'disk': f.get('disk')}
    name = str(args.get('db') or '')
    if f.get('running') and f.get('engine') == 'postgres':
        try:
            lag = sql(conf, "SELECT COALESCE(max(pg_wal_lsn_diff(pg_current_wal_lsn(), "
                            "confirmed_flush_lsn)), 0)::bigint FROM pg_replication_slots")
            db['repl_behind'] = int(lag or 0)
            if name and W.PG_NAME_RE.match(name):
                db['size'] = int(sql(conf, 'SELECT pg_database_size(%s)' % W.pg_lit(name)) or 0)
        except (Refused, ValueError):
            pass
    elif f.get('running') and name and W.PG_NAME_RE.match(name):
        try:
            db['size'] = int(my_sql(conf, "SELECT COALESCE(SUM(data_length + index_length), 0) "
                                          "FROM information_schema.tables WHERE table_schema = "
                                          "'%s'" % name) or 0)
        except (Refused, ValueError):
            pass
    out['db'] = db
    return out


# The closed set, PostgreSQL's and MariaDB's: nothing else is ever done.
OPS = {'status': op_status, 'load': op_load, 'pgtls': op_pgtls, 'pg_prepare': op_pg_prepare,
       'pg_allow': op_pg_allow, 'pg_publication': op_pg_publication,
       'pg_restart': op_pg_restart, 'pg_reload': op_pg_reload, 'pglog': op_pglog,
       'dbmake': op_dbmake, 'my_tls': op_my_tls, 'my_restart': op_my_restart,
       'fw_allow': op_fw_allow}
OPS_PG_ONLY = ('pgtls', 'pg_prepare', 'pg_allow', 'pg_publication', 'pg_restart', 'pg_reload',
               'pglog')
OPS_MY_ONLY = ('my_tls', 'my_restart')


def run_op(op, args, conf):
    if op not in OPS:
        raise Refused('%s is not something this agent does' % str(op)[:40])
    eng = str(conf.get('engine') or 'postgres')
    if (eng != 'postgres' and op in OPS_PG_ONLY) or (eng != 'mariadb' and op in OPS_MY_ONLY):
        raise Refused('%s is not for %s' % (op, 'MariaDB' if eng != 'postgres' else 'PostgreSQL'))
    if not isinstance(args, dict):
        raise Refused('the request is not an object')
    got = OPS[op](args, conf)
    return got if isinstance(got, dict) else {'said': got}
