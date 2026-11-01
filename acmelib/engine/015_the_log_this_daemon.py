# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The log this daemon writes about itself
# ---------------------------------------------------------------------------
_LOG_FILE = None
_LOG_LOCK = threading.Lock()
_LOG_TO_STDERR = True


def log_open():
    global _LOG_FILE
    with _LOG_LOCK:
        _LOG_WANTED[0] = True
        try:
            if _LOG_FILE:
                _LOG_FILE.close()
        except (OSError, ValueError):
            pass
        _LOG_FILE = None
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            _LOG_FILE = open(LOG_DIR / 'acme.log', 'a', encoding='utf-8')
        except OSError:
            _LOG_FILE = None


_LOG_WANTED = [False]           # this process writes acme.log (the daemon)
# A SIGHUP noted from the first moment of the daemon (1.0.186): one that came
# while it was still starting (a slow migration after an upgrade at night,
# logrotate's) ended the process - Python's default for it.
HUP_ASKED = threading.Event()


_LOG_SPARING = {}
_LOG_CHECKED = [0.0]


def log_sparing(key, words, level='warn', every=30):
    """A line that can come thousands of times a second (a database gone,
    a flood): written once per `every` seconds a key, with how many were left
    out since (1.0.59) - a database outage under load wrote 50 MB of log."""
    t = time.time()
    with _LOG_LOCK:
        at, quiet = _LOG_SPARING.get(key, (0.0, 0))
        if t - at < every:
            _LOG_SPARING[key] = (at, quiet + 1)
            return
        _LOG_SPARING[key] = (t, 0)
        if len(_LOG_SPARING) > 1000:
            _LOG_SPARING.clear()
    log(words + (' (and %d more like it in the last %d s)' % (quiet, int(t - at)) if quiet else ''),
        level)


_UNDER_SYSTEMD = bool(os.environ.get('INVOCATION_ID'))


def log(words, level='info'):
    # A line of its own begins only with a time (1.0.57): a newline in what
    # is written - a User-Name, say - continues indented, so it cannot pass
    # for a line of acme's; other control characters are shown, not written.
    words = str(words)
    if len(words) > 20000:
        # A line, not megabytes (1.0.146): a name typed at the sign-in went in whole.
        words = words[:20000] + ' ... (%d characters more)' % (len(words) - 20000)
    words = re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', lambda m: '\\x%02x' % ord(m.group(0)),
                   words).replace('\n', '\n    ')
    line = '%s %-5s %s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), level, words)
    try:
        _log_line(line, level)
    except Exception:                                   # noqa: BLE001
        # Never out of log() (1.0.186): a closed file after a rotation the
        # disk had no room for raised here, out of every RADIUS worker that
        # logged - one by one they ended, and nothing was answered.
        pass


def _log_line(line, level):
    global _LOG_FILE
    with _LOG_LOCK:
        # Rotated away from under it (1.0.94): logrotate's reload is refused
        # to the acme account, and the lines went on into a file deleted the
        # next day. Looked at every 10 s; a new acme.log is opened - and one
        # that could not be (a disk full at night) is tried again (1.0.186).
        t = time.monotonic()
        if _LOG_WANTED[0] and t - _LOG_CHECKED[0] > 10:
            _LOG_CHECKED[0] = t
            try:
                stale = _LOG_FILE is None or _LOG_FILE.closed or \
                    os.stat(str(LOG_DIR / 'acme.log')).st_ino != os.fstat(_LOG_FILE.fileno()).st_ino
            except (OSError, ValueError):
                stale = True
            if stale:
                try:
                    if _LOG_FILE is not None:
                        _LOG_FILE.close()
                except (OSError, ValueError):
                    pass
                _LOG_FILE = None
                try:
                    _LOG_FILE = open(LOG_DIR / 'acme.log', 'a', encoding='utf-8')
                except OSError:
                    _LOG_FILE = None
        if _LOG_FILE:
            try:
                _LOG_FILE.write(line + '\n')
                _LOG_FILE.flush()
            except (OSError, ValueError):
                pass
        # Under systemd, with acme.log open, only warnings and errors go to
        # the journal as well (1.0.136): every line twice, debugging on, and
        # a journald slow to take them held every thread that logs.
        to_err = _LOG_TO_STDERR and (level != 'debug' or CONFIG.get('debug')) and (
            not _LOG_FILE or not _UNDER_SYSTEMD or level in ('warn', 'error', 'crit'))
    if not to_err:
        return
    if _UNDER_SYSTEMD:
        # To the journal by a thread of its own (1.0.186): a journald or a
        # disk that stalls (the night's dumps) held every thread that logs,
        # RADIUS's too, in this write. Full, a line is left out, not waited for.
        try:
            _ERR_Q.put_nowait(line)
        except queue.Full:
            _ERR_DROPPED[0] += 1
        if _ERR_THREAD[0] is None or not _ERR_THREAD[0].is_alive():
            with _LOG_LOCK:
                if _ERR_THREAD[0] is None or not _ERR_THREAD[0].is_alive():
                    _ERR_THREAD[0] = threading.Thread(target=_err_writer, name='log-journal',
                                                      daemon=True)
                    _ERR_THREAD[0].start()
        return
    try:
        sys.stderr.write(line + '\n')
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


_ERR_Q = queue.Queue(maxsize=5000)
_ERR_THREAD = [None]
_ERR_DROPPED = [0]


def _err_writer():
    while True:
        try:
            line = _ERR_Q.get()
            if _ERR_DROPPED[0]:
                n, _ERR_DROPPED[0] = _ERR_DROPPED[0], 0
                sys.stderr.write('(%d lines left out of the journal: it did not take them in '
                                 'time)\n' % n)
            sys.stderr.write(line + '\n')
            sys.stderr.flush()
        except Exception:                               # noqa: BLE001
            time.sleep(0.5)


def debugging(what):
    return bool(CONFIG.get('debug')) and bool(CONFIG.get('debug_' + what, 1))


def log_tail(lines=400):
    path = LOG_DIR / 'acme.log'
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 400 * 1024))
            got = f.read().decode('utf-8', 'replace').splitlines()
        return got[-int(lines):]
    except OSError as e:
        return ['%s cannot be read: %s' % (path, e)]


