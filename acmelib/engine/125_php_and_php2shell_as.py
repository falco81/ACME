# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# PHP and php2shell, as the daemon can tell from outside it
# ---------------------------------------------------------------------------
# The pages say what version of PHP they run on, and a version below the
# fixed ones (8.2.35, 8.3.36, 8.4.27, 8.5.12) is "may be affected" - because a
# distribution that backported the fix keeps its old number. The packages'
# own changelog says whether the fix is in, and the daemon can read it where
# PHP cannot: so the warning on the pages goes away when the fix is there.
PHP_FIXED = {'8.2': (8, 2, 35), '8.3': (8, 3, 36), '8.4': (8, 4, 27), '8.5': (8, 5, 12)}
_PHP_STATE = {'at': 0, 'state': None}


_SOFTWARE = {'at': 0.0, 'state': None}


def _first_line(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ''
    text = (r.stdout or '') + (r.stderr or '')
    return (text.strip().splitlines() or [''])[0].strip()[:200]


def software_info(store=None):
    """What _software_now found, made in a thread of its own once in 10 minutes
    (1.0.186): asked in the heartbeat, its ten programs (5 s each at most) and
    the database's version held the main loop, and the other node took this
    one for gone."""
    now = time.time()
    if now - _SOFTWARE.get('full_at', 0) > 600 and not _SOFTWARE.get('busy'):
        _SOFTWARE['busy'] = True

        def go():
            try:
                _SOFTWARE['full'] = _software_now(store)
                _SOFTWARE['full_at'] = time.time()
            except Exception:                           # noqa: BLE001
                _SOFTWARE['full_at'] = time.time()
            finally:
                _SOFTWARE['busy'] = False
        threading.Thread(target=go, name='acme-software', daemon=True).start()
    return dict(_SOFTWARE.get('full') or {'acme': __version__})


def _software_now(store=None):
    """What this node runs on (1.0.99): acme, its Python and the modules it
    uses, the libraries under them, the programs beside it and the system -
    for Settings → About, of every node. Asked at most once an hour."""
    if time.time() - _SOFTWARE['at'] < 3600 and _SOFTWARE['state'] is not None:
        out = dict(_SOFTWARE['state'])
    else:
        import platform
        import sqlite3
        out = {'acme': __version__,
               'python': '%s %s' % (platform.python_implementation(), platform.python_version()),
               'python_path': os.path.realpath(sys.executable),
               'openssl': ssl.OPENSSL_VERSION, 'sqlite': sqlite3.sqlite_version,
               'kernel': '%s %s' % (platform.system(), platform.release()),
               'arch': platform.machine(), 'modules': {}, 'programs': {}}
        try:
            with open('/etc/os-release', encoding='utf-8') as f:
                rel = dict(l.strip().split('=', 1) for l in f if '=' in l)
            out['os'] = rel.get('PRETTY_NAME', '').strip('"')
        except OSError:
            out['os'] = ''
        for mod, attr in (('psycopg2', '__version__'), ('pymysql', '__version__'),
                          ('colorama', '__version__')):
            try:
                m = __import__(mod)
                v = str(getattr(m, attr, '') or '').split(' ')[0]
                if mod == 'psycopg2':
                    lib = getattr(m, '__libpq_version__', 0)
                    if lib:
                        v += ' (libpq %d.%d)' % (lib // 10000, lib % 10000 // 100 if lib < 100000
                                                 else lib % 100)
                out['modules'][mod] = v
            except Exception:                           # noqa: BLE001
                out['modules'][mod] = ''
        progs = (('nginx', ['nginx', '-v']), ('php', ['php', '-v']),
                 ('php-fpm', None), ('keepalived', ['keepalived', '--version']),
                 ('pg_dump', ['pg_dump', '--version']),
                 ('mariadb-dump', ['mariadb-dump', '--version']),
                 ('openssl', ['openssl', 'version']), ('systemd', ['systemctl', '--version']),
                 ('iptables', ['iptables', '--version']),
                 ('firewalld', ['firewall-cmd', '--version']))
        for name, cmd in progs:
            if name == 'php-fpm':
                import glob
                fpm = sorted(glob.glob('/usr/sbin/php-fpm*') + glob.glob('/usr/sbin/php*-fpm*'))
                line = _first_line([fpm[-1], '-v']) if fpm else ''
            else:
                exe = shutil.which(cmd[0]) or next((p for p in ('/usr/sbin/' + cmd[0], '/sbin/' + cmd[0])
                                                    if os.path.exists(p)), None)
                line = _first_line([exe] + cmd[1:]) if exe else ''
            m = re.search(r'(\d+\.\d+(?:\.\d+)?[^\s,()]*)', line or '')
            if m and not re.search(r'(?i)denied|not found|error', line):
                out['programs'][name] = m.group(1)
            elif name == 'systemd':
                m = re.search(r'^systemd\s+(\d+)', line or '')
                if m:
                    out['programs'][name] = m.group(1)
        _SOFTWARE.update(at=time.time(), state=dict(out))
    # What changes without a restart, asked each time it is wanted.
    if store is not None:
        try:
            out['database'] = store.db.version() or ''
        except Exception:                               # noqa: BLE001
            pass
    try:
        out['php_cli'] = (php_state() or {}).get('version') or ''
    except Exception:                                   # noqa: BLE001
        pass
    return out


def php_state():
    if time.time() - _PHP_STATE['at'] < 3600 and _PHP_STATE['state'] is not None:
        return _PHP_STATE['state']
    out = {'version': '', 'fixed': None, 'how': ''}
    php = shutil.which('php') or next((p for p in ('/usr/bin/php', '/usr/local/bin/php')
                                       if os.path.exists(p)), None)
    if php:
        try:
            out['version'] = subprocess.run([php, '-r', 'echo PHP_VERSION;'], capture_output=True,
                                            text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)', out['version'])
    if m:
        v = tuple(int(x) for x in m.groups())
        want = PHP_FIXED.get('%d.%d' % v[:2])
        if want and v >= want or (not want and v[:2] > (8, 5)):
            out.update(fixed=True, how='version')
    if not out['fixed']:
        said = ''
        rpm = shutil.which('rpm')
        if rpm:
            for pkg in ('php-fpm', 'php-common'):
                try:
                    said += subprocess.run([rpm, '-q', '--changelog', pkg], capture_output=True,
                                           text=True, timeout=20).stdout
                except (OSError, subprocess.SubprocessError):
                    pass
        else:
            import gzip
            import glob
            for f in glob.glob('/usr/share/doc/php*-fpm/changelog.Debian.gz') + glob.glob(
                    '/usr/share/doc/php*-common/changelog.Debian.gz'):
                try:
                    with gzip.open(f, 'rt', errors='replace') as g:
                        said += g.read(200000)
                except OSError:
                    pass
        if 'CVE-2026-109618' in said:
            out.update(fixed=True, how='changelog')
        elif out['version']:
            out['fixed'] = False
    _PHP_STATE.update(at=time.time(), state=out)
    return out


