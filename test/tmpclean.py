#!/usr/bin/env python3
"""What a test made is taken away again - also when it fails half way or is stopped.

    try:
        import tmpclean  # noqa: F401
    except ImportError:
        from test import tmpclean  # noqa: F401

Imported once by a test file (right after `import tempfile`), it:

- remembers every folder (tempfile.mkdtemp) and file (tempfile.mkstemp) a test file makes
  (made from a file of this folder - not what the code under test makes, so the tests still
  see the leftovers of acme itself) and removes them when the process ends: a normal end, an
  error in setUpClass/setUpModule (where tearDownClass is never called), Ctrl+C, SIGTERM or
  SIGHUP (the `timeout` of a runner);
- stops what the test started and left running when it ends (a daemon, php -S, node and its
  browser): every process below this one gets SIGTERM, after ten seconds SIGKILL;
- writes what it made into <tmp>/acme-test-runs/<pid>.<start>: a run that was killed
  (SIGKILL, out of memory, a machine stopped) is cleaned up by the next test that starts -
  its folders removed, the daemons and servers still running inside them stopped.

ACME_TEST_KEEP=1 keeps the folders (for a look afterwards); the processes are stopped anyway.

    python3 test/tmpclean.py                 runs left by killed tests cleaned up now
    python3 test/tmpclean.py --old HOURS     also the leftovers of the tests from before this
                                             helper (the test prefixes in /tmp, older than
                                             HOURS; daemons and servers left running in them
                                             with their test gone are stopped)
"""
import atexit
import os
import re
import shutil
import signal
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_TOP = tempfile.gettempdir()
RUNS = os.path.join(_TOP, 'acme-test-runs')
_OWNER = os.getpid()
_made = []
_lock = threading.Lock()
_record = None
_done = False


def _start(pid):
    """The start time of a process (to tell it from a later one with the same number)."""
    try:
        with open('/proc/%d/stat' % pid) as f:
            return f.read().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _stat(pid):
    try:
        with open('/proc/%d/stat' % pid) as f:
            rest = f.read().rsplit(')', 1)[1].split()
        return rest[0], int(rest[1])
    except (OSError, IndexError, ValueError):
        return None, None


def _alive(pid):
    state, _ppid = _stat(pid)
    return state is not None and state not in ('Z', 'X')


def _pids():
    for name in os.listdir('/proc'):
        if name.isdigit():
            yield int(name)


def _below(top):
    """The processes below `top` (children, their children ...)."""
    kids = {}
    for pid in _pids():
        _state, ppid = _stat(pid)
        if ppid is not None:
            kids.setdefault(ppid, []).append(pid)
    out, todo = [], [top]
    while todo:
        for kid in kids.get(todo.pop(), ()):
            out.append(kid)
            todo.append(kid)
    return out


def _stop(pids, wait=10.0):
    pids = [p for p in pids if p != os.getpid()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    end = time.time() + wait
    while time.time() < end and any(_alive(p) for p in pids):
        time.sleep(0.1)
    for pid in pids:
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def _remove(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)
    except OSError:
        pass


def _inside(path, folders):
    return any(path == f or path.startswith(f.rstrip(os.sep) + os.sep) for f in folders)


def _note(path):
    global _record
    if os.getpid() != _OWNER:
        return
    path = os.path.abspath(path)
    with _lock:
        if _inside(path, _made):
            return
        _made.append(path)
        try:
            if _record is None:
                os.makedirs(RUNS, mode=0o700, exist_ok=True)
                name = os.path.join(RUNS, '%d.%s' % (_OWNER, _start(_OWNER)))
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                _record = (name, fd)
            os.write(_record[1], (path + '\n').encode('utf-8', 'surrogateescape'))
        except OSError:
            pass


def _from_a_test():
    try:
        f = sys._getframe(2).f_code.co_filename
    except ValueError:
        return False
    return os.path.dirname(os.path.abspath(f)) == HERE and \
        os.path.abspath(f) != os.path.abspath(__file__)


_mkdtemp, _mkstemp = tempfile.mkdtemp, tempfile.mkstemp


def mkdtemp(*a, **kw):
    d = _mkdtemp(*a, **kw)
    if _from_a_test():
        _note(d)
    return d


def mkstemp(*a, **kw):
    fd, name = _mkstemp(*a, **kw)
    if _from_a_test():
        _note(name)
    return fd, name


def cleanup():
    """Stop what is still running below this process, remove what the tests made."""
    global _done, _record
    if os.getpid() != _OWNER or _done:
        return
    _done = True
    try:
        _stop(_below(_OWNER))
    except Exception:  # noqa: BLE001 - never in the way of the end of a test run
        pass
    if os.environ.get('ACME_TEST_KEEP'):
        if _made:
            sys.stderr.write('kept: %s\n' % ' '.join(_made))
    else:
        for path in reversed(_made):
            _remove(path)
    if _record is not None:
        try:
            os.close(_record[1])
        except OSError:
            pass
        _remove(_record[0])               # kept or removed: not for the next sweep
        _record = None


def _on_signal(signum, _frame):
    cleanup()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _path_of(link):
    try:
        p = os.readlink(link)
    except OSError:
        return None
    return p[:-len(' (deleted)')] if p.endswith(' (deleted)') else p


_ENV = re.compile(rb'^ACME_(?:CONFIG|STATE|RUN|LOGDIR|PLUGINS)=(.*)$')


def _users_of(folders, with_paths=False):
    """Processes of ours working inside `folders` (their folder or acme's ACME_* paths)."""
    me, mine = os.getuid(), set()
    pid = os.getpid()
    while pid > 1:                       # never this process nor what started it
        mine.add(pid)
        _state, pid = _stat(pid)
        if pid is None:
            break
    out = []
    for pid in _pids():
        if pid in mine:
            continue
        try:
            if os.stat('/proc/%d' % pid).st_uid != me:
                continue
        except OSError:
            continue
        paths = [_path_of('/proc/%d/cwd' % pid)]
        try:
            with open('/proc/%d/environ' % pid, 'rb') as f:
                for item in f.read().split(b'\0'):
                    m = _ENV.match(item)
                    if m:
                        paths.append(m.group(1).decode('utf-8', 'surrogateescape'))
        except OSError:
            pass
        paths = [os.path.abspath(p) for p in paths if p]
        if any(_inside(p, folders) for p in paths):
            out.append((pid, paths) if with_paths else pid)
    return out


def sweep():
    """Clean up after runs that were killed: what their record lists, what runs inside it."""
    try:
        names = os.listdir(RUNS)
    except OSError:
        return 0
    folders, records = [], []
    for name in names:
        m = re.match(r'^(\d+)\.(\d+|None)$', name)
        if not m:
            continue
        pid = int(m.group(1))
        if _alive(pid) and str(_start(pid)) == m.group(2):
            continue                      # still running
        path = os.path.join(RUNS, name)
        try:
            with open(path, encoding='utf-8', errors='surrogateescape') as f:
                folders += [x for x in f.read().splitlines() if x.startswith(os.sep)]
        except OSError:
            continue
        records.append(path)
    if not records:
        return 0
    if folders:
        _stop(_users_of(folders))
        for path in folders:
            _remove(path)
    for path in records:
        _remove(path)
    return len(records)


def _test_prefixes():
    """The prefixes of the folders the tests make (prefix='...' in the test files)."""
    out = set()
    for name in os.listdir(HERE):
        if name.endswith('.py'):
            try:
                with open(os.path.join(HERE, name), encoding='utf-8', errors='replace') as f:
                    text = f.read()
            except OSError:
                continue
            out.update(re.findall(r"mk[sd]temp\([^)]*?prefix=['\"]([A-Za-z0-9._-]{3,})['\"]",
                                  text))
    return sorted(out, key=len, reverse=True)


def sweep_old(hours):
    """The leftovers of earlier test runs in the temporary folder: a folder named by a test's
    prefix (or Python's tmpXXXXXXXX), older than `hours`, nothing running inside it."""
    prefixes = _test_prefixes()
    plain = re.compile(r'^tmp[a-z0-9_]{8}$')
    limit = time.time() - hours * 3600
    found = []
    for name in os.listdir(_TOP):
        if not (plain.match(name) or any(name.startswith(p) for p in prefixes)):
            continue
        path = os.path.join(_TOP, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if st.st_uid != os.getuid() or st.st_mtime > limit:
            continue
        found.append(path)
    busy, orphans = set(), []
    for pid, paths in _users_of(found, with_paths=True):
        if _stat(pid)[1] == 1:            # its test is gone: a daemon or server left behind
            orphans.append(pid)
            continue
        busy.update(f for f in found if any(_inside(p, [f]) for p in paths))
    _stop(orphans)
    removed = 0
    for path in found:
        if path not in busy:
            _remove(path)
            removed += 1
    return removed, len(busy)


def _install():
    tempfile.mkdtemp, tempfile.mkstemp = mkdtemp, mkstemp
    atexit.register(cleanup)
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGHUP):
            try:
                if signal.getsignal(sig) == signal.SIG_DFL:
                    signal.signal(sig, _on_signal)
            except (OSError, ValueError):
                pass
    try:
        sweep()
    except Exception:  # noqa: BLE001 - a sweep never stops a test from running
        pass


if __name__ == '__main__':
    n = sweep()
    print('runs of killed tests cleaned up: %d' % n)
    if len(sys.argv) == 3 and sys.argv[1] == '--old':
        removed, busy = sweep_old(float(sys.argv[2]))
        print('old leftovers removed: %d (in use, kept: %d)' % (removed, busy))
elif not getattr(tempfile, '_acme_tmpclean', False):
    tempfile._acme_tmpclean = True
    _install()
