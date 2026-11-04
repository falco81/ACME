# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Sending the logs to isemon
# ---------------------------------------------------------------------------
# What happens to the certificates - an order, a renewal, a deployment, a
# failure, one running out - goes to isemon's syslog receivers as it happens,
# one event a line, from the program `acme-certs`:
#
#   Oct 22 15:31:02 acme1 acme-certs[812]: level=warn kind=certificates
#       node=acme1 who="acme" msg="www.example.cz: the renewal failed - ..."
#
# (one line; key=value, a value with a space or a quote in it in quotes, its
# quotes and backslashes escaped) - and every other event of acme, with
# isemon_events on, the same way from the program `acme`. The very same lines
# go into /var/log/acme/acme-certs.log here too (ship_files). The events are
# the engine's own (Storage.add_event): a module says what happened with
# store.add_event('certificates', words, level, who) and nothing else.

SYSLOG_FACILITY = {'auth': 4, 'authpriv': 10, 'local5': 21, 'daemon': 3, 'user': 1}

# The kinds of event that are the certificates' (acme-certs lines, always
# shipped); a module appends its own. Any other kind is an `acme` line, sent
# only with isemon_events.
ISEMON_KINDS = ['certificates']


def syslog_targets(text, strict=False):
    """`host[:port][/udp|/tcp|/tls]` (or `tls://host:port`), comma separated,
    as (host, port, proto). TLS (1.0.172): 6514 when no port is given."""
    out = []
    for one in re.split(r'[,;\s]+', str(text or '')):
        one = one.strip()
        if not one:
            continue
        m = re.match(r'^(?:(udp|tcp|tls)://)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+)(?::(\d+))?'
                     r'(?:/(udp|tcp|tls))?/?\Z', one, re.I)
        if not m:
            if strict:
                raise BadSetting('isemon_targets: %r is not host[:port][/udp|/tcp|/tls]' % one)
            continue
        proto = (m.group(4) or m.group(1) or 'udp').lower()
        port = int(m.group(3) or (6514 if proto == 'tls' else 514))
        if strict and not 0 < port < 65536:
            raise BadSetting('isemon_targets: %d is not a port' % port)
        out.append((m.group(2).strip('[]'), port, proto))
    return out


def syslog_stamp(ts=None):
    """`Oct 22 15:31:02` - RFC 3164, the shape the readers on the other side
    expect: no year, no zone, the day padded with a space."""
    t = datetime.fromtimestamp(float(ts if ts is not None else time.time()))
    return '%s %2d %s' % (t.strftime('%b'), t.day, t.strftime('%H:%M:%S'))


def kv_quote(value):
    """A value of a key=value line: as it is when it is one word, else in
    quotes with its quotes and backslashes escaped - and never a line break."""
    said = re.sub(r'[\r\n\t]+', ' ', str(value if value is not None else ''))
    if said and re.match(r'^[A-Za-z0-9_.:@/+-]+\Z', said):
        return said
    return '"%s"' % said.replace('\\', '\\\\').replace('"', '\\"')


def event_kv(kind, words, level, who, node='', fields=None):
    """One event as the key=value words of its syslog line - with what a
    module says of it (`fields`: cert=www action=renewed ...) before msg."""
    out = ['level=%s' % kv_quote(level or 'info'), 'kind=%s' % kv_quote(kind)]
    if node:
        out.append('node=%s' % kv_quote(node))
    if who:
        out.append('who=%s' % kv_quote(who))
    for k, v in sorted((fields or {}).items()):
        if k not in ('level', 'kind', 'node', 'who', 'msg'):
            out.append('%s=%s' % (k, kv_quote(v)))
    out.append('msg=%s' % kv_quote(words))
    return ' '.join(out)


# What an event is about, in fields of their own (the certificate, its serial,
# the target, how it went), for isemon and the SIEM to search by: said by the
# one who writes the event (with event_with(...): store.add_event(...)), else
# read out of its words by a module (HOOKS['event_fields']: fn(kind, words,
# level) -> {key: value}). Keys are a-z0-9_, at most 32; values one line.
EVENT_LOCAL = threading.local()
EVENT_KEY_RE = re.compile(r'^[a-z][a-z0-9_]{0,31}\Z')


@contextlib.contextmanager
def event_with(**fields):
    """with event_with(cert='www', action='renewed'): store.add_event(...)"""
    was = getattr(EVENT_LOCAL, 'fields', None)
    EVENT_LOCAL.fields = dict(was or {}, **fields)
    try:
        yield
    finally:
        EVENT_LOCAL.fields = was


def event_fields(kind, words, level):
    """The fields of one event (see above) - {} when nobody says any. Never raises."""
    got = {}
    try:
        said = getattr(EVENT_LOCAL, 'fields', None)
        if said:
            got.update(said)
        else:
            for fn in HOOKS.get('event_fields') or ():
                try:
                    got.update(fn(kind, words, level) or {})
                except Exception:                       # noqa: BLE001
                    pass
    except Exception:                                   # noqa: BLE001
        return {}
    out = {}
    for k, v in got.items():
        if v in (None, '') or not EVENT_KEY_RE.match(str(k)):
            continue
        if isinstance(v, (list, tuple)):
            v = ','.join(str(x) for x in v)
        out[str(k)] = re.sub(r'[\r\n\t]+', ' ', str(v))[:500]
    return out


def _conn_alive(sock):
    """Whether a connection the other side never writes into is still open:
    readable means closed (or, over TLS, a session ticket - read, and still
    open)."""
    try:
        r, _w, _x = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return False
    if not r:
        return True
    was = sock.gettimeout()
    try:
        sock.setblocking(False)
        got = sock.recv(4096)
        return bool(got)
    except (ssl.SSLWantReadError, BlockingIOError):
        return True
    except (OSError, ssl.SSLError):
        return False
    finally:
        try:
            sock.settimeout(was)
        except OSError:
            pass


class Shipper(object):
    """A queue and a thread that empties it into isemon's receivers and the
    files here. Nothing that does the work ever waits for any of it."""

    def __init__(self):
        self.q = queue.Queue(maxsize=20000)
        self.targets = []
        self.tcp = {}
        self.udp4 = None
        self.udp6 = None
        self.files = {}
        self.sent = collections.Counter()
        self.trouble = {}
        self.down = {}              # a TCP target that failed: (until, wait) - 1.0.59
        self.missed = collections.Counter()
        self.dropped = 0
        self.last_sent = 0.0
        self.ctx = None
        self.stop_flag = False
        self.thread = threading.Thread(target=self.run, name='shipper', daemon=True)
        self.configure()
        self.thread.start()

    def configure(self):
        self.targets = syslog_targets(CONFIG.get('isemon_targets')) if CONFIG.get('isemon') \
            else []
        self.ctx = None                 # the TLS settings may have changed (1.0.172)
        # And every connection made again when they did (1.0.206): one made
        # unchecked went on unchecked for weeks, as SIEM's did.
        tls = (CONFIG.get('isemon_verify'), CONFIG.get('isemon_ca'), CONFIG.get('isemon_mtls'))
        again = tls != getattr(self, '_tls_was', tls)
        self._tls_was = tls
        for key, sock in list(self.tcp.items()):
            if again or key not in self.targets:
                try:
                    sock.close()
                except OSError:
                    pass
                self.tcp.pop(key, None)

    def host(self):
        return str(CONFIG.get('isemon_hostname') or '').strip() or short_host()

    # ---- what is said ----------------------------------------------------------
    def put(self, tag, facility, words, ts=None, file_name=None):
        if not CONFIG.get('isemon') and not CONFIG.get('ship_files'):
            return
        most = int(CONFIG.get('isemon_max_bytes') or 1800)
        if len(words.encode('utf-8')) > most:
            words = words.encode('utf-8')[:most].decode('utf-8', 'ignore') + ' ...TRUNCATED'
        line = '%s %s %s[%d]: %s' % (syslog_stamp(ts), self.host(), tag, os.getpid(),
                                     words.replace('\n', ' ').replace('\r', ' '))
        pri = SYSLOG_FACILITY.get(facility, 1) * 8 + 5          # notice
        try:
            self.q.put_nowait((pri, line, file_name))
        except queue.Full:
            self.dropped += 1

    def event_line(self, kind, words, level, who):
        """An event of the engine's (store.add_event) as a syslog line: the
        certificates' always (acme-certs), the others with isemon_events."""
        kind = str(kind or '')
        cert = kind in ISEMON_KINDS
        if not cert and not CONFIG.get('isemon_events'):
            return
        line = event_kv(kind, words, level, who, log_node(), event_fields(kind, words, level))
        if cert:
            self.put('acme-certs', 'daemon', line, file_name='acme-certs.log')
        else:
            self.put('acme', 'daemon', line, file_name=None)

    # ---- sending ---------------------------------------------------------------
    def run(self):
        while not self.stop_flag:
            try:
                pri, line, file_name = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            # Nothing ends this thread (1.0.186): one error took isemon's
            # sending and its files away until a restart.
            try:
                if file_name and CONFIG.get('ship_files'):
                    self._to_file(file_name, line)
                if CONFIG.get('isemon'):
                    for target in list(self.targets):
                        self._to_target(target, '<%d>%s' % (pri, line))
            except Exception as e:                      # noqa: BLE001
                log_sparing('shipper', 'isemon: a line could not go: %s' % e, 'warn', every=300)

    def _to_file(self, name, line):
        path = LOG_DIR / name
        f = self.files.get(name)
        try:
            if f is not None:
                try:
                    if f.closed or os.fstat(f.fileno()).st_ino != os.stat(path).st_ino:
                        raise OSError('rotated')
                except (OSError, ValueError):
                    try:
                        f.close()
                    except (OSError, ValueError):
                        pass
                    self.files.pop(name, None)
                    f = None
            if f is None:
                LOG_DIR.mkdir(parents=True, exist_ok=True)
                f = open(path, 'a', encoding='utf-8')
                self.files[name] = f
            f.write(line + '\n')
            f.flush()
        except (OSError, ValueError) as e:
            self.trouble['file:' + name] = str(e)

    def _to_target(self, target, data):
        host, port, proto = target
        key = '%s:%d/%s' % target
        raw = data.encode('utf-8', 'replace')
        try:
            if proto == 'udp':
                fam = socket.AF_INET6 if ':' in host else socket.AF_INET
                if fam == socket.AF_INET6:
                    if self.udp6 is None:
                        self.udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                    self.udp6.sendto(raw, (host, port))
                else:
                    if self.udp4 is None:
                        self.udp4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp4.sendto(raw, (host, port))
            else:
                # A TCP target that cannot be reached is left alone for a
                # while (1.0.59): every line waited 5 s on it, the queue
                # filled, and the files here lost lines with it.
                until, wait = self.down.get(key, (0.0, 0.0))
                if time.monotonic() < until:
                    self.missed[key] += 1
                    return
                sock = self.tcp.get(target)
                if sock is not None and not _conn_alive(sock):
                    # Closed by the other side - isemon restarted (1.0.172): the
                    # first line written into it would have been lost unsaid.
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                    self.tcp.pop(target, None)
                for attempt in (1, 2):
                    if sock is None:
                        sock = socket.create_connection((host, port), timeout=5)
                        if proto == 'tls':
                            # Encrypted, isemon's certificate checked (1.0.172).
                            if self.ctx is None:
                                self.ctx = isemon_tls_ctx()
                            sock = self.ctx.wrap_socket(sock, server_hostname=host)
                        sock.settimeout(5)
                        self.tcp[target] = sock
                    try:
                        sock.sendall(raw + b'\n')
                        break
                    except OSError:
                        try:
                            sock.close()
                        except OSError:
                            pass
                        sock = None
                        self.tcp.pop(target, None)
                        if attempt == 2:
                            raise
            self.sent[key] += 1
            self.last_sent = time.time()
            self.trouble.pop(key, None)
            self.down.pop(key, None)
        except (OSError, ssl.SSLError, ValueError) as e:
            if key not in self.trouble:
                log('isemon at %s cannot be sent to: %s' % (key, e), 'warn')
            if proto != 'udp':
                _u, wait = self.down.get(key, (0.0, 0.0))
                wait = min(300.0, max(15.0, wait * 2))
                self.down[key] = (time.monotonic() + wait, wait)
                self.missed[key] += 1
                e = '%s - tried again in %d s, %d line(s) not sent to it' % (
                    e, int(wait), self.missed[key])
            self.trouble[key] = '%s (%s)' % (e, datetime.now().strftime('%H:%M:%S'))

    def state(self):
        return {'on': bool(CONFIG.get('isemon')), 'host': self.host(),
                'targets': ['%s:%d/%s' % t for t in self.targets],
                'tls': {'verify': bool(CONFIG.get('isemon_verify', 1)),
                        'mtls': bool(CONFIG.get('isemon_mtls')),
                        'ca': 'given' if str(CONFIG.get('isemon_ca') or '').strip() else 'system'},
                'sent': dict(self.sent), 'trouble': dict(self.trouble),
                'queued': self.q.qsize(), 'dropped': self.dropped,
                'last_sent': self.last_sent, 'files': bool(CONFIG.get('ship_files')),
                'file_dir': str(LOG_DIR)}

    def flush(self, wait=3.0):
        until = time.time() + wait
        while not self.q.empty() and time.time() < until:
            time.sleep(0.05)
