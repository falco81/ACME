# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Every event and every sign-in to a syslog server / SIEM (1.0.166)
# ---------------------------------------------------------------------------
# isemon's shapes are isemon's own; this is for whatever else collects the
# logs - rsyslog, syslog-ng, Graylog, Splunk, Wazuh, QRadar, Sentinel: every
# event of the Events page and every RADIUS sign-in with its result, as RFC
# 5424 syslog over UDP, TCP or TLS (RFC 5425), the message as JSON, CEF or
# key="value" pairs. A queue and a thread of its own: a sign-in only puts a
# line into the queue, never waits for any of it; a full queue drops lines and
# counts them.
SIEM_PEN = 32473                    # the example enterprise number of RFC 5612
SIEM_SEVERITY = {'bad': 3, 'warn': 4, 'info': 6}


def siem_targets(text, strict=False):
    """`udp://host:514`, `tcp://host:514`, `tls://host:6514` - or
    `host[:port][/udp|/tcp|/tls]` - comma separated, as (host, port, proto)."""
    out = []
    for one in re.split(r'[,;\s]+', str(text or '')):
        one = one.strip()
        if not one:
            continue
        m = re.match(r'^(?:(udp|tcp|tls)://)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+)(?::(\d+))?'
                     r'(?:/(udp|tcp|tls))?/?\Z', one, re.I)
        if not m:
            if strict:
                raise BadSetting('siem_targets: %r is not tls://host:6514, tcp://host:514 or '
                                 'udp://host:514' % one)
            continue
        proto = (m.group(1) or m.group(4) or 'udp').lower()
        port = int(m.group(3) or (6514 if proto == 'tls' else 514))
        if strict and not 0 < port < 65536:
            raise BadSetting('siem_targets: %d is not a port' % port)
        out.append((m.group(2).strip('[]'), port, proto))
    return out


def _cef_head(text):
    return str(text).replace('\\', '\\\\').replace('|', '\\|')


def _cef_val(text):
    return str(text).replace('\\', '\\\\').replace('=', '\\=').replace('\r', ' ') \
        .replace('\n', ' ')


def _sd_val(text):
    return str(text).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')


class Siem(object):
    def __init__(self):
        self.q = queue.Queue(maxsize=20000)
        self.targets = []
        self.conns = {}
        self.udp = {}
        self.sent = collections.Counter()
        self.trouble = {}
        self.down = {}
        self.dropped = 0
        self.last_sent = 0.0
        self.stop_flag = False
        self.ctx = None
        self.lock = threading.Lock()        # one line at a time on a connection
        self.configure()
        self.thread = threading.Thread(target=self.run, name='siem', daemon=True)
        self.thread.start()

    def configure(self):
        self.targets = siem_targets(CONFIG.get('siem_targets')) if CONFIG.get('siem') else []
        self.ctx = None
        # Every connection made again when its TLS changed (1.0.205): one made
        # without checking the server went on unchecked after the check was
        # switched on, until it broke - weeks.
        tls = (CONFIG.get('siem_verify'), CONFIG.get('siem_ca'))
        again = tls != getattr(self, '_tls_was', tls)
        self._tls_was = tls
        for key, sock in list(self.conns.items()):
            if again or key not in self.targets:
                try:
                    sock.close()
                except OSError:
                    pass
                self.conns.pop(key, None)

    def host(self):
        return str(CONFIG.get('siem_hostname') or '').strip() or node_name()

    # ---- what is said ---------------------------------------------------------------
    def frame(self, kind, severity, fields, words):
        """One message, in the shape siem_format says."""
        fmt = CONFIG.get('siem_format') or 'json'
        fields = dict(fields, node=node_name())
        if fmt == 'json':
            body = json.dumps(dict(fields, type=kind, message=words), ensure_ascii=False,
                              sort_keys=True, default=str)
            sd = '-'
        elif fmt == 'cef':
            ext = ' '.join('%s=%s' % (k, _cef_val(v)) for k, v in fields.items()
                           if v not in (None, ''))
            body = 'CEF:0|acme|acme|%s|%s|%s|%d|%s msg=%s' % (
                _cef_head(__version__), _cef_head(fields.get('event') or kind),
                _cef_head(words[:120]), {3: 7, 4: 5, 6: 2}.get(severity, 3), ext, _cef_val(words))
            sd = '-'
        else:
            sd = '[acme@%d %s]' % (SIEM_PEN, ' '.join(
                '%s="%s"' % (re.sub(r'[^A-Za-z0-9_.-]', '_', k)[:32], _sd_val(v))
                for k, v in fields.items() if v not in (None, '')))
            body = words
        stamp = datetime.now(timezone.utc).astimezone().isoformat(timespec='milliseconds')
        pri = int(CONFIG.get('siem_facility') or 13) * 8 + severity
        return '<%d>1 %s %s acme %d %s %s \ufeff%s' % (
            pri, stamp, self.host(), os.getpid(), kind, sd, body.replace('\n', ' '))

    def put(self, kind, severity, fields, words):
        if not CONFIG.get('siem') or not self.targets:
            return
        try:
            self.q.put_nowait((kind, severity, fields, words))
        except queue.Full:
            self.dropped += 1

    def event_line(self, kind, words, level, who):
        if CONFIG.get('siem_events', 1):
            self.put('event', SIEM_SEVERITY.get(level, 6),
                     {'event': 'event', 'kind': kind, 'level': level, 'who': who or ''},
                     '%s: %s' % (kind, words))

    def signin_line(self, row):
        """A RADIUS request as the log has it - its result and why."""
        if not CONFIG.get('siem_signins', 1) or row.get('packet') != 'Access-Request':
            return
        res = row.get('result') or ''
        if res not in ('accept', 'reject', 'drop', 'challenge'):
            return
        fields = {'event': 'signin-' + res, 'user': row.get('username') or '',
                  'realm': row.get('realm') or '', 'result': res,
                  'reason': row.get('reason') or '', 'client': row.get('client') or '',
                  'nas_ip': row.get('nas_ip') or '', 'src': row.get('src') or '',
                  'calling': row.get('calling') or '', 'device': row.get('device') or '',
                  'ms': row.get('took_ms')}
        words = '%s %s%s%s' % ('let in' if res == 'accept' else
                               ('asked for a code' if res == 'challenge' else 'refused'),
                               fields['user'] or '?',
                               ' from %s' % fields['calling'] if fields['calling'] else '',
                               ': %s' % fields['reason'] if fields['reason'] and res != 'accept'
                               else '')
        self.put('signin', 6 if res in ('accept', 'challenge') else 4, fields, words)

    def test(self, by):
        """A line to every target, sent before this returns where it can be."""
        if not self.targets:
            raise ValueError('no syslog server is set')
        line = self.frame('test', 6, {'event': 'test', 'who': by},
                          'a test from acme %s, sent by %s' % (__version__, by))
        out = {}
        for t in self.targets:
            out['%s:%d/%s' % t] = self._send(t, line) or 'sent'
        return out

    # ---- sending --------------------------------------------------------------------
    def run(self):
        while not self.stop_flag:
            try:
                kind, severity, fields, words = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                line = self.frame(kind, severity, fields, words)
            except Exception as e:                      # noqa: BLE001
                self.trouble['frame'] = str(e)[:200]
                continue
            for t in list(self.targets):
                try:
                    self._send(t, line)
                except Exception as e:                  # noqa: BLE001
                    # Nothing ends this thread (1.0.186).
                    self.trouble[str(t)] = str(e)[:200]

    def _tls(self):
        if self.ctx is None:
            ctx = ssl.create_default_context()
            ca = str(CONFIG.get('siem_ca') or '').strip()
            if ca:
                ctx.load_verify_locations(cadata=ca)
            if not CONFIG.get('siem_verify', 1):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.ctx = ctx
        return self.ctx

    def _send(self, target, line):
        """'' when it went, or what stopped it."""
        with self.lock:
            return self._send_one(target, line)

    def _send_one(self, target, line):
        host, port, proto = target
        key = '%s:%d/%s' % target
        raw = line.encode('utf-8', 'replace')
        try:
            if proto == 'udp':
                fam = socket.AF_INET6 if ':' in host else socket.AF_INET
                sock = self.udp.get(fam)
                if sock is None:
                    sock = self.udp[fam] = socket.socket(fam, socket.SOCK_DGRAM)
                sock.sendto(raw[:8000], (host, port))
            else:
                until = self.down.get(key, 0.0)
                if time.time() < until:
                    # Counted (1.0.206): thrown away without a word, the metrics
                    # said nothing was lost while events and sign-ins were.
                    self.dropped += 1
                    return 'not reachable - tried again at %s' % time.strftime(
                        '%H:%M:%S', time.localtime(until))
                # RFC 5425 / 6587: a length and a space before each message.
                data = b'%d ' % len(raw) + raw
                for attempt in (1, 2):
                    sock = self.conns.get(target)
                    if sock is not None and not _conn_alive(sock):
                        # Closed by the other side (1.0.206), as isemon's: written
                        # into, the first line after a restart was lost - and
                        # counted as sent.
                        try:
                            sock.close()
                        except OSError:
                            pass
                        self.conns.pop(target, None)
                        sock = None
                    if sock is None:
                        sock = socket.create_connection((host, port), timeout=5)
                        if proto == 'tls':
                            sock = self._tls().wrap_socket(sock, server_hostname=host)
                        sock.settimeout(5)
                        self.conns[target] = sock
                    try:
                        sock.sendall(data)
                        break
                    except OSError:
                        try:
                            sock.close()
                        except OSError:
                            pass
                        self.conns.pop(target, None)
                        if attempt == 2:
                            raise
            self.sent[key] += 1
            self.last_sent = time.time()
            self.trouble.pop(key, None)
            self.down.pop(key, None)
            return ''
        except (OSError, ssl.SSLError, ValueError) as e:
            said = str(e)[:200] or e.__class__.__name__
            self.trouble[key] = said
            if proto != 'udp':
                self.down[key] = time.time() + 30
                self.conns.pop(target, None)
            return said

    def state(self):
        return {'on': bool(CONFIG.get('siem')), 'host': self.host(),
                'targets': ['%s:%d/%s' % t for t in self.targets], 'sent': dict(self.sent),
                'trouble': dict(self.trouble), 'queued': self.q.qsize(),
                'dropped': self.dropped, 'last_sent': self.last_sent,
                'format': CONFIG.get('siem_format') or 'json'}

    def flush(self, wait=3.0):
        until = time.time() + wait
        while not self.q.empty() and time.time() < until:
            time.sleep(0.05)
