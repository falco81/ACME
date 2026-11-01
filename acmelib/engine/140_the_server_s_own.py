# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the server's own settings, for its machine (isemon's DbTune, smaller) --
def tune_machine(c, typed):
    """What the database server's machine has: read here when it is this
    machine, typed on the page when it is not."""
    host = str(c.get('db_host') or '').lower()
    local = host in ('', 'localhost', '127.0.0.1', '::1') or host == socket.gethostname().lower()
    facts = {'local': local, 'ram_gb': None, 'cpus': None, 'disk': None, 'avail': None,
             'ram': None, 'virtual': None, 'rotational': None,
             'source': 'this machine' if local else ''}
    if local:
        try:
            with open('/proc/meminfo') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        facts['ram'] = int(line.split()[1]) * 1024
                    elif line.startswith('MemAvailable:'):
                        facts['avail'] = int(line.split()[1]) * 1024
            if facts['ram']:
                facts['ram_gb'] = round(facts['ram'] / 1073741824.0, 1)
        except OSError:
            pass
        facts['cpus'] = os.cpu_count()
        try:
            with open('/proc/cpuinfo') as f:
                facts['virtual'] = ' hypervisor' in f.read()
        except OSError:
            pass
        try:
            rot = [open(p).read().strip() for p in
                   [str(x) for x in Path('/sys/block').glob('*/queue/rotational')]
                   if not re.search(r'/(loop|ram|zram|sr|dm-)\d', p)]
            if rot:
                facts['rotational'] = all(r == '1' for r in rot)
        except OSError:
            pass
    for k in ('ram_gb', 'cpus'):
        if typed.get(k) not in (None, ''):
            try:
                v = float(str(typed[k]).replace(',', '.')) if k == 'ram_gb' else int(typed[k])
            except ValueError:
                raise ValueError('the memory is a number of GB, the processors a whole number')
            if k == 'ram_gb' and facts['ram_gb'] and abs(v - facts['ram_gb']) > 0.05 * v:
                facts['source'] = 'typed' if not local else facts['source']
            if k == 'cpus' and v != facts['cpus'] and not local:
                facts['source'] = 'typed'
            facts[k] = v
            if k == 'ram_gb':
                facts['ram'] = int(v * 1073741824)
    return facts


def tune_commit_ms(db):
    """How long the server takes to make one small write safe: the middle of
    twenty, each its own transaction, less a round trip."""
    if db.engine == 'sqlite':
        return None
    took, trip = [], []
    # A row of this node's own (1.0.59): two nodes measuring at once wrote
    # the same key, and replication stopped on the duplicate.
    probe = 'tune_probe:' + node_name()
    try:
        # The row is there to be written (1.0.44): an UPDATE of nothing
        # commits nothing and every disk looked fast.
        db.run('DELETE FROM meta WHERE k = ?', (probe,))
        db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (probe, '0'))
        for _ in range(5):
            t = time.perf_counter()
            db.value('SELECT 1')
            trip.append(time.perf_counter() - t)
        for i in range(20):
            t = time.perf_counter()
            db.run('UPDATE meta SET v = ? WHERE k = ?', (str(i), probe))
            took.append(time.perf_counter() - t)
        db.run('DELETE FROM meta WHERE k = ?', (probe,))
    except Exception:                                   # noqa: BLE001
        return None
    took.sort()
    trip.sort()
    return max(0.0, (took[len(took) // 2] - trip[len(trip) // 2]) * 1000.0)


def tune_disk_guess(facts, commit_ms):
    """As isemon's: what the disk says of itself first - except in a virtual
    machine, where a disk says it spins whatever it is on - then how long a
    small write takes to be made safe."""
    rot = facts.get('rotational')
    if rot is False:
        return 'ssd', 'the disk says it does not spin'
    if rot is True and not facts.get('virtual'):
        return 'hdd', 'the disk says it spins'
    if commit_ms is not None:
        if commit_ms < 2.5:
            return 'ssd', 'a write is made safe in %.1f ms, which is an SSD' % commit_ms
        if commit_ms > 6:
            return 'hdd', 'a write is made safe in %.1f ms, which is a disk that spins' % commit_ms
    return 'ssd', ('not known for certain - most servers are on SSDs now; choose the other if '
                   'this one is not')


def _mb(n):
    n = int(n)
    return '%dGB' % (n // 1024) if n >= 1024 and n % 1024 == 0 else '%dMB' % n


def tune_plan(engine, m):
    """name -> (value, why, needs_restart)"""
    ram = int((m.get('ram_gb') or 4) * 1024)
    cpus = max(1, int(m.get('cpus') or 2))
    ssd = (m.get('disk') or 'ssd') == 'ssd'
    # Shared with acme itself (and nginx, PHP) when it is this machine.
    share = 0.8 if m.get('local') else 1.0
    if engine == 'postgres':
        sb = max(128, min(int(ram * share / 4), 16384))
        return {
            'shared_buffers': (_mb(sb), 'a quarter of the memory: the server’s own cache', True),
            'effective_cache_size': (_mb(int(ram * share * 3 / 4)),
                                     'how much the planner may assume is cached', False),
            'maintenance_work_mem': (_mb(max(64, min(ram // 16, 2048))),
                                     'for VACUUM and building indexes', False),
            'work_mem': (_mb(max(4, min(ram // 256, 64))), 'for each sort and hash', False),
            'wal_buffers': ('16MB', 'the write-ahead log’s buffer', True),
            'max_wal_size': ('4GB' if ssd else '2GB', 'fewer checkpoints under load', False),
            'min_wal_size': ('1GB', 'kept between checkpoints', False),
            'checkpoint_completion_target': ('0.9', 'checkpoints spread out', False),
            'random_page_cost': ('1.1' if ssd else '4', 'an SSD reads anywhere as fast', False),
            'effective_io_concurrency': ('200' if ssd else '2', 'reads the disk takes at once', False),
            'max_worker_processes': (str(max(8, cpus)), 'one per processor', True),
            'max_parallel_workers': (str(cpus), 'parallel queries over every processor', False),
            'max_parallel_workers_per_gather': (str(max(1, min(4, cpus // 2))),
                                                'per query', False),
        }
    pool = max(128, int(ram * share * (0.5 if m.get('local') else 0.7)) // 128 * 128)
    return {
        'innodb_buffer_pool_size': (str(pool * 1048576), 'the server’s own cache: %s'
                                    % _mb(pool), False),
        'innodb_log_file_size': (str(min(pool // 4, 2048) * 1048576),
                                 'a log large enough for a busy hour', True),
        'innodb_flush_method': ('O_DIRECT', 'no second copy in the system’s cache', True),
        'innodb_io_capacity': ('2000' if ssd else '200', 'what the disk takes per second', False),
        'innodb_io_capacity_max': ('4000' if ssd else '400', '...at most', False),
        'innodb_flush_neighbors': ('0' if ssd else '1', 'an SSD has no neighbours', False),
        'tmp_table_size': (str(64 * 1048576), 'in-memory temporary tables', False),
        'max_heap_table_size': (str(64 * 1048576), '...the same', False),
        'table_open_cache': ('2000', 'tables kept open', False),
    }


def tune_current(db, names):
    out = {}
    for n in names:
        try:
            if db.engine == 'postgres':
                out[n] = str(db.value('SHOW %s' % n))
            else:
                r = db.row("SHOW GLOBAL VARIABLES LIKE ?", (n,))
                out[n] = str(list(r.values())[1]) if r else ''
        except Exception:
            out[n] = ''
    return out


def tune_same(engine, a, b):
    def norm(v):
        v = str(v).strip()
        m = re.match(r'^(\d+(?:\.\d+)?)\s*(kB|MB|GB|TB)?\Z', v, re.I)
        if not m:
            return v.lower()
        mult = {'kb': 1, 'mb': 1024, 'gb': 1048576, 'tb': 1073741824}.get(
            (m.group(2) or '').lower(), None)
        return float(m.group(1)) * mult if mult else float(m.group(1))
    try:
        x, y = norm(a), norm(b)
        if isinstance(x, float) and isinstance(y, float) and max(x, y) >= 1024:
            # Memory: within a tenth is the same - what is free moves from one
            # look to the next, and a setting is not changed for that.
            return abs(x - y) <= 0.1 * max(x, y)
        return x == y
    except Exception:
        return str(a) == str(b)


def tune_connect(store, admin_user, admin_password):
    """The server, as an administrator when one is given, else as ourselves."""
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    if admin_user:
        c['db_user'], c['db_password'] = admin_user, admin_password
        if c['db_engine'] == 'postgres':
            pass
    return db_open(c) if admin_user else store.db


def tune_last(store):
    try:
        return json.loads(store.get_meta('tune_last:' + node_name()) or 'null')
    except ValueError:
        return None


def tune_pending(db):
    if db.engine != 'postgres':
        return []
    try:
        return [r['name'] for r in db.rows('SELECT name FROM pg_settings WHERE pending_restart')]
    except Exception:                                   # noqa: BLE001
        return []


def tune_plan_for(store, typed, probe=True):
    db = store.db
    if db.engine == 'sqlite':
        raise ValueError('the file on this machine has no server to tune: this program sets '
                         'it up itself')
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    typed = typed or {}
    m = tune_machine(c, typed)
    commit_ms = tune_commit_ms(db) if probe else None
    disk, why = tune_disk_guess(m, commit_ms)
    if typed.get('disk') in ('ssd', 'hdd') and typed['disk'] != disk:
        disk, why = typed['disk'], 'chosen'
    m['disk'], m['why'], m['commit_ms'] = disk, why, commit_ms
    out = {'engine': db.engine, 'words': ENGINE_WORDS.get(db.engine), 'where': db.where(),
           'version': str(db.version() or '').split(' on ')[0].split(',')[0],
           'size': int(db.size() or 0), 'machine': m, 'facts': m,
           'restart': tune_restart_ready(store), 'last': tune_last(store), 'rows': [],
           'items': []}
    try:
        if db.engine == 'postgres':
            out['connections'] = int(db.value('SHOW max_connections') or 0)
        else:
            r = db.row("SHOW GLOBAL VARIABLES LIKE 'max_connections'")
            out['connections'] = int(list(r.values())[1]) if r else 0
    except Exception:                                   # noqa: BLE001
        pass
    if not m.get('ram_gb') or not m.get('cpus'):
        out['need_facts'] = True
        return out
    plan = tune_plan(db.engine, m)
    now = tune_current(db, plan.keys())
    pending = set(tune_pending(db))
    last = out['last'] or {}
    mine = last.get('engine') == db.engine and not last.get('undone') \
        and last.get('where') == db.where()
    put = (last.get('set') or {}) if mine else {}
    rows = []
    for n, (v, why_, rs) in plan.items():
        same = tune_same(db.engine, now.get(n, ''), v)
        row = {'name': n, 'now': now.get(n, ''), 'want': v, 'why': why_, 'restart': rs,
               'takes': 'at the next start' if rs else 'at once', 'same': same,
               'change': not same, 'pending': n in pending}
        if n in pending and n in put and tune_same(db.engine, put[n], v):
            row.update(change=False, waiting=True)
        rows.append(row)
    out['rows'] = out['items'] = rows
    if db.engine == 'mariadb':
        out['snippet'] = out['cnf'] = (
            '# Written by acme %s for this machine, as zz-acme-tuning.cnf in /etc/my.cnf.d/\n'
            '# (or /etc/mysql/mariadb.conf.d/) so that the settings outlast a restart.\n'
            '[mariadb]\n' % __version__) + ''.join('%s = %s\n' % (r['name'], r['want'])
                                                    for r in rows)
    return out


def tune_apply(store, typed, admin_user, admin_password, by):
    plan = tune_plan_for(store, typed, probe=False)
    if plan.get('need_facts'):
        raise ValueError('say what the machine has first: its memory and its processors')
    db = tune_connect(store, admin_user, admin_password)
    done, later, failed = [], [], []
    before = json.loads(store.get_meta('tune_before:' + node_name()) or '{}')
    try:
        for r in plan['rows']:
            if not r['change']:
                continue
            before.setdefault(r['name'], r['now'])
            try:
                if plan['engine'] == 'postgres':
                    db.run("ALTER SYSTEM SET %s = '%s'" % (r['name'], r['want'].replace("'", '')))
                    (later if r['restart'] else done).append(r['name'])
                else:
                    if r['restart']:
                        later.append(r['name'])
                        continue
                    db.run('SET GLOBAL %s = %s' % (r['name'], r['want'] if r['want'].isdigit()
                                                  else "'%s'" % r['want']))
                    done.append(r['name'])
            except Exception as e:
                failed.append('%s: %s' % (r['name'], str(e).split('\n')[0][:160]))
        if plan['engine'] == 'postgres' and (done or later):
            db.run('SELECT pg_reload_conf()')
    finally:
        if db is not store.db:
            db.close()
    store.set_meta('tune_before:' + node_name(), json.dumps(before))
    if done or later:
        store.set_meta('tune_last:' + node_name(), json.dumps({
            'engine': plan['engine'], 'where': store.db.where(), 'at': time.time(), 'by': by,
            'set': {r['name']: r['want'] for r in plan['rows'] if r['name'] in done + later},
            'undone': 0}))
    store.add_event('settings', 'the database server was tuned for its machine by %s: %s'
                    % (by, ', '.join(done + later) or 'nothing'), 'warn', who=by)
    plan2 = tune_plan_for(store, typed, probe=False)
    plan2.update({'done': done, 'later': later, 'failed': failed})
    return plan2


TUNE_RESTART_MARK = CONFIG_FILE.parent / 'may-restart-database'


def tune_restart_unit():
    """The postgresql service on this machine, as systemd knows it, or ''."""
    try:
        said = subprocess.run(['systemctl', 'list-units', '--type=service', '--all', '--plain',
                               '--no-legend', '--no-pager', 'postgresql*'],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ''
    found = []
    for line in said.stdout.splitlines():
        f = line.split()
        if len(f) >= 3 and f[2] == 'active' and \
                re.match(r'^postgresql(-\d+)?(@[\w.-]+)?\.service\Z', f[0]):
            found.append(f[0])
    return found[0] if len(found) == 1 else ''


def tune_restart_ready(store):
    db = store.db
    if db.engine != 'postgres':
        return {'may': False, 'unit': ''}
    host = str(CONFIG.get('db_host') or '').lower()
    if host not in ('', 'localhost', '127.0.0.1', '::1', socket.gethostname().lower()):
        return {'may': False, 'unit': 'postgresql',
                'why': 'PostgreSQL runs on another machine, which this program cannot restart'}
    unit = tune_restart_unit()
    if not unit:
        return {'may': False, 'unit': 'postgresql',
                'why': 'no single running postgresql service was found on this machine'}
    if not TUNE_RESTART_MARK.exists():
        return {'may': False, 'unit': unit,
                'why': 'install.sh has not let this program restart it (run install.sh --upgrade '
                       'without --no-db-restart)'}
    return {'may': True, 'unit': unit, 'why': ''}


def tune_restart(store, by):
    """PostgreSQL on this machine started again, for the settings that take
    only at a start - through systemd, where install.sh let this account do
    that - and waited for."""
    db = store.db
    ready = tune_restart_ready(store)
    if db.engine != 'postgres' or not ready['unit']:
        raise ValueError('no database server is running as a service on this machine')
    unit = ready['unit']
    if not TUNE_RESTART_MARK.exists():
        raise ValueError('this program may not restart %s: run  systemctl restart %s  as root'
                         % (unit, unit))
    waiting = tune_pending(db)
    if not waiting:
        raise ValueError('nothing waits for a restart')
    try:
        if str(db.value('SHOW huge_pages')).lower() == 'on':
            raise ValueError('huge_pages is on, and a start needs enough of them for the new '
                             'shared_buffers: check vm.nr_hugepages, then run  systemctl '
                             'restart %s  as root' % unit)
    except ValueError:
        raise
    except Exception:                                   # noqa: BLE001
        pass
    if 'shared_buffers' in waiting:
        try:
            want = int(db.value("SELECT pg_size_bytes(setting) FROM pg_file_settings WHERE "
                                "name = 'shared_buffers' AND applied = false ORDER BY seqno "
                                "DESC LIMIT 1") or 0)
        except Exception:                               # noqa: BLE001
            want = 0
        try:
            want = want or 0
            running = int(db.value("SELECT setting::bigint * 8192 FROM pg_settings WHERE "
                                   "name = 'shared_buffers'") or 0)
            avail = tune_machine({}, {}).get('avail') or 0
        except Exception:                               # noqa: BLE001
            running = avail = 0
        if want and avail and want - running > avail - 512 * 1048576:
            raise ValueError('the machine has %d MB free now, too little for shared_buffers of '
                             '%d MB - restarted now, PostgreSQL might not start. Free some '
                             'memory, or put back as it was' % (avail // 1048576,
                                                                 want // 1048576))
    began = time.time()
    try:
        said = subprocess.run(['systemctl', '--no-ask-password', '--no-block', 'restart', unit],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        raise ValueError('systemctl: %s' % str(e)[:160])
    if said.returncode != 0:
        raise ValueError('%s was not restarted: %s - run  systemctl restart %s  as root'
                         % (unit, (said.stderr or said.stdout).strip()[:160], unit))
    store.add_event('settings', '%s restarted %s for the settings waiting for it: %s'
                    % (by, unit, ', '.join(waiting)), 'warn', who=by)
    time.sleep(2)
    back = False
    while time.time() < began + 62:
        try:
            state = subprocess.run(['systemctl', 'is-failed', unit], capture_output=True,
                                   text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            state = ''
        if state == 'failed':
            raise ValueError('%s did not start again - see  journalctl -u %s ; if it does not '
                             'start: as root, take the shared_buffers line out of '
                             'postgresql.auto.conf and run  systemctl start %s'
                             % (unit, unit, unit))
        try:
            started = float(db.value('SELECT extract(epoch from pg_postmaster_start_time())'))
            if started >= began - 1:
                back = True
                break
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(1)
    if not back:
        raise ValueError('%s was asked to restart and has not answered yet - look again in a '
                         'minute' % unit)
    left = tune_pending(db)
    return {'unit': unit, 'waiting': waiting, 'still': left,
            'message': '%s started again%s' % (unit, '; still waiting: ' + ', '.join(left)
                                                if left else ': every setting is in effect')}


def tune_undo(store, admin_user, admin_password, by):
    before = json.loads(store.get_meta('tune_before:' + node_name()) or '{}')
    if not before:
        raise ValueError('nothing was changed here, so there is nothing to put back')
    db = tune_connect(store, admin_user, admin_password)
    done, failed = [], []
    try:
        for n, v in before.items():
            try:
                if store.db.engine == 'postgres':
                    db.run('ALTER SYSTEM RESET %s' % n)
                else:
                    db.run('SET GLOBAL %s = %s' % (n, v if str(v).isdigit() else "'%s'" % v))
                done.append(n)
            except Exception as e:
                failed.append('%s: %s' % (n, str(e).split('\n')[0][:160]))
        if store.db.engine == 'postgres':
            db.run('SELECT pg_reload_conf()')
    finally:
        if db is not store.db:
            db.close()
    store.set_meta('tune_before:' + node_name(), '')
    last = tune_last(store) or {}
    if last:
        last.update(undone=time.time(), undone_by=by)
        store.set_meta('tune_last:' + node_name(), json.dumps(last))
    store.add_event('settings', 'the database server’s settings were put back by %s: %s'
                    % (by, ', '.join(done)), 'warn', who=by)
    return {'done': done, 'failed': failed}


# Where each secret is sent (1.0.207): a change of any of these, the secret kept as
# its dots, is refused - it would go to the new place unseen.
SECRET_GOES_TO = {
    'smtp_password': ('smtp_host', 'smtp_port', 'smtp_security', 'smtp_verify', 'smtp_user'),
    'proxy_password': ('proxy_url', 'proxy_user'),
    'sms_tel_password': ('sms_tel_host', 'sms_tel_https', 'sms_tel_verify', 'sms_tel_user'),
    'sms_token': ('sms_url', 'sms_mode'),
    'acme_dns_key': ('acme_dns_url', 'acme_dns_user'),
    'acme_dns_tsig_secret': ('acme_dns_server', 'acme_dns_tsig_name'),
}

