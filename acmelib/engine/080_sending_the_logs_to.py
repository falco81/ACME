# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Sending the logs to isemon
# ---------------------------------------------------------------------------
# isemon reads a token server through two files rsyslog writes for it: what
# totpcgi said about every code (`totp.cgi`), and every RADIUS packet the
# FreeRADIUS in front of it wrote into its detail files, one to a line
# (`radius-detail`). This writes both, in exactly those shapes, as syslog to
# isemon's receiver - and into files here as well - so that isemon reads this
# server with the readers it already has and nothing changed on its side.

SYSLOG_FACILITY = {'auth': 4, 'authpriv': 10, 'local5': 21, 'daemon': 3, 'user': 1}


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


def detail_quote(value):
    """A value as FreeRADIUS writes it in a detail file: a string in quotes,
    with its quotes and backslashes escaped."""
    said = str(value)
    if re.match(r'^(0x[0-9a-fA-F]*|\d+|\d+\.\d+\.\d+\.\d+)\Z', said) or said in (
            'Access-Request', 'Access-Accept', 'Access-Reject', 'Access-Challenge',
            'Accounting-Request') or re.match(r'^[A-Z][A-Za-z0-9.-]*\Z', said) and \
            said in [w for d in RADIUS_VALUES.values() for w in d.values()]:
        return said
    return '"%s"' % said.replace('\\', '\\\\').replace('"', '\\"')


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
    files here. Nothing that answers a VPN ever waits for any of it."""

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

    def token_line(self, name, ok, said, how, src, rid):
        """`totp.cgi[pid]: Success: user=..., mode=PAM_SM_AUTH, host=..., rid=...,
        message=...` - totpcgi's own line, with the request id isemon joins it
        to the RADIUS packet by."""
        if how not in ('radius', 'test'):
            mode = 'PROVISION' if how == 'portal' else how.upper()
        else:
            mode = 'PAM_SM_AUTH'
        clean = lambda s: re.sub(r'[\r\n]', ' ', str(s or ''))
        rid = re.sub(r'[^A-Za-z0-9.:_-]', '', str(rid or ''))[:64]
        words = '%s: user=%s, mode=%s, host=%s, %smessage=%s' % (
            'Success' if ok else 'Failure', re.sub(r'[,=\s]', '_', clean(name)), mode, '127.0.0.1',
            ('rid=%s, ' % rid) if rid else '', clean(said))
        self.put('totp.cgi', 'auth', words, file_name='totp.cgi.log')

    def detail_line(self, nas, kind, ts, pairs, ident=''):
        """`radius-detail[pid]: nas=... id=... file=auth-detail-YYYYMMDD ts=[ctime]
        Name = value, ...` - one detail record a line, the way the shipper
        isemon ships with writes it."""
        if not CONFIG.get('isemon_detail', 1):
            return
        fname = '%s-%s' % (kind, datetime.fromtimestamp(ts).strftime('%Y%m%d'))
        body = ', '.join('%s = %s' % (k, detail_quote(v)) for k, v in pairs)
        rid = ident or hashlib.sha1(('%s|%s|%s|%s' % (nas, fname, ts, body))
                                    .encode('utf-8', 'replace')).hexdigest()[:16]
        words = 'nas=%s id=%s file=%s ts=[%s] %s' % (nas, rid, fname, time.ctime(ts), body)
        self.put('radius-detail', 'local5', words, file_name='radius-detail.log')

    def event_line(self, kind, words, level, who):
        if CONFIG.get('isemon_events'):
            self.put('acme', 'daemon', '%s: %s%s' % (kind, words, (' (by %s)' % who) if who
                                                    else ''), file_name=None)

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
                if time.time() < until:
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
                self.down[key] = (time.time() + wait, wait)
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


def codes_open(tok):
    """A token's recovery codes as kept to be shown again, each one no longer
    in its list of hashes marked used (1.0.61). Two nodes using a code each
    at the same moment end with the same list of hashes, but each node's
    sealed copy may still hold the other's code as unused - and a rename,
    an export or the codes view would have brought it back."""
    shown = open_codes(tok.get('scratch_sealed'), token_bind(tok.get('name')))
    if shown is None:
        return None
    try:
        kept = [str(k) for k in json.loads(tok.get('scratch') or '[]')]
    except (ValueError, TypeError):
        return shown
    key = sealing_key()
    for one in shown:
        if isinstance(one, dict) and not one.get('used') and \
                not scratch_find(tok.get('name'), one.get('c'), kept, key)[0]:
            one['used'] = time.time()
    return shown


