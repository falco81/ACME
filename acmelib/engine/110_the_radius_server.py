# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The RADIUS server
# ---------------------------------------------------------------------------
class SentReply(bytes):
    """An answer, and whether it has gone out already."""
    sent = False
    late = False


class RadiusServer(object):
    """Two UDP sockets - authentication and accounting - read by a thread
    each and answered by a pool of workers."""

    def __init__(self, daemon):
        self.d = daemon
        self.socks = {}
        self.jobs = queue.Queue(maxsize=5000)
        # Accounting apart (1.0.186): a NAS restarted sends thousands of Stops
        # and Interim-Updates at once; in the same queue and workers they held
        # the sign-ins behind them. Their own workers, on the main connection.
        self.acct_jobs = queue.Queue(maxsize=5000)
        # duplicate key -> (time, reply or None), oldest first, never more
        # than SEEN_MAX: a flood fills it to the brim and no further (1.0.33).
        self.seen = collections.OrderedDict()
        self.seen_lock = threading.Lock()
        self.unknown_said = {}
        self.unknown_lock = threading.Lock()
        # What is not written down one by one - malformed packets, and more
        # than a few unknown addresses a minute - is counted and summed up
        # once a minute instead (1.0.33): a flood of junk was a row each.
        self.quiet = collections.Counter()
        self.quiet_at = time.time()
        self.drops_this_minute = 0
        # Clients that have sent a right Message-Authenticator (1.0.33).
        self.ma_seen = set()
        self.ma_asked = {}
        # Refusals waiting out radius_reject_delay_ms (1.0.36).
        self.late = []
        self.late_lock = threading.Lock()
        self.late_wake = threading.Event()
        self.late_thread = None
        self.workers = []
        self.readers = []
        self.stop_flag = False
        self.counts = collections.Counter()
        self.bound = []
        self.trouble = ''

    # ---- the sockets -------------------------------------------------------------
    def want(self):
        bind = str(CONFIG.get('radius_bind') or '0.0.0.0')
        if bind == '::' and not ipv6_usable():
            # IPv4 and IPv6 asked for, on a machine without IPv6 (1.0.119):
            # IPv4 still, not RADIUS on nothing.
            log_sparing('radius-no-v6', 'radius: IPv6 is not on this machine - listening on '
                        'IPv4 (0.0.0.0) only', 'warn', every=3600)
            bind = '0.0.0.0'
        out = [('auth', bind, int(CONFIG.get('radius_auth_port') or 1812))]
        if int(CONFIG.get('radius_acct_port') or 0):
            out.append(('acct', bind, int(CONFIG.get('radius_acct_port'))))
        return out

    def start(self):
        self.stop_flag = False
        self.open_sockets()
        for i in range(int(CONFIG.get('radius_workers') or 16)):
            t = threading.Thread(target=self.work, name='radius-%d' % i, daemon=True)
            t.start()
            self.workers.append(t)
        for i in range(4):
            t = threading.Thread(target=self.work, args=(self.acct_jobs,), name='acct-%d' % i,
                                 daemon=True)
            t.start()
            self.workers.append(t)

    def open_sockets(self):
        want = self.want()
        if [(k, b, p) for k, (b, p, _s) in sorted(self.socks.items())] == sorted(want):
            return
        # Only what changed is closed and opened again (1.0.67): the auth port
        # changed closed the accounting socket too, and binding it again while
        # its reader was still inside recvfrom failed - accounting stopped.
        keep = {}
        wanted = {(k, b, p) for k, b, p in want}
        old_readers = []
        for kind, (b, p, sock) in list(self.socks.items()):
            if (kind, b, p) in wanted:
                keep[kind] = (b, p, sock)
                continue
            try:
                sock.close()
            except OSError:
                pass
            old_readers += [t for t in self.readers if t.name == 'radius-' + kind]
        self.socks = dict(keep)
        for t in old_readers:
            t.join(2.5)             # out of its recvfrom (1 s timeout) before the port is taken again
        self.readers = [t for t in self.readers if t.is_alive()]
        self.bound = ['%s:%d/%s' % (b, p, k) for k, (b, p, _s) in sorted(keep.items())]
        troubles = []
        for kind, bind, port in want:
            if kind in keep:
                continue
            fam = socket.AF_INET6 if ':' in bind else socket.AF_INET
            try:
                sock = socket.socket(fam, socket.SOCK_DGRAM)
            except OSError as e:
                # IPv6 switched off on the machine (1.0.94): said, as a port in
                # use is - it killed the daemon at start, round and round.
                troubles.append('%s:%d (%s) could not be listened on: %s' % (bind, port, kind, e))
                continue
            # No SO_REUSEADDR: on UDP it lets a second process bind the very same
            # port and take half the packets. A port in use has to say so.
            if fam == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            err = None
            for _try in range(6):
                try:
                    sock.bind((bind, port))
                    err = None
                    break
                except OSError as e:
                    err = e
                    time.sleep(0.5)
            if err is not None:
                troubles.append('%s:%d (%s) could not be listened on: %s' % (bind, port, kind, err))
                sock.close()
                continue
            sock.settimeout(1.0)
            self.socks[kind] = (bind, port, sock)
            self.bound.append('%s:%d/%s' % (bind, port, kind))
            t = threading.Thread(target=self.read, args=(kind, sock), name='radius-' + kind,
                                 daemon=True)
            t.start()
            self.readers.append(t)
        self.trouble = '; '.join(troubles)
        if troubles:
            self.d.store.add_event('radius', self.trouble, 'bad')
        else:
            log('RADIUS listening on %s' % ', '.join(self.bound))

    def stop(self):
        self.stop_flag = True
        for _b, _p, sock in self.socks.values():
            try:
                sock.close()
            except OSError:
                pass

    def read(self, kind, sock):
        while not self.stop_flag:
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self.socks.get(kind, (None, None, None))[2] is not sock:
                    return
                time.sleep(0.2)
                continue
            if self.socks.get(kind, (None, None, None))[2] is not sock:
                return
            try:
                (self.acct_jobs if kind == 'acct' else self.jobs).put_nowait(
                    (kind, sock, data, peer, time.time()))
            except queue.Full:
                self.counts['overflow'] += 1

    def work(self, jobs=None):
        jobs = jobs if jobs is not None else self.jobs
        while not self.stop_flag:
            try:
                kind, sock, data, peer, arrived = jobs.get(timeout=1.0)
            except queue.Empty:
                continue
            # Older than any NAS waits (1.0.57): after a stall the queue held
            # minutes of requests whose NAS had long given up, each with its
            # directory binds and its code used up, ahead of the new ones.
            # 10 s (1.0.149): past what a VPN waits for an answer before it asks
            # again or asks the other node - 15 s worked on requests long given
            # up behind a slow directory, each using its code up.
            if time.time() - arrived > int(CONFIG.get('radius_stale_s') or 10):
                self.counts['stale'] += 1
                with self.unknown_lock:
                    self.quiet['too old to answer'] += 1
                continue
            # The checks of a code written down after the answer went (1.0.186),
            # not before it: kept by Tokens._said, written below.
            ACME_LOG_LATER.rows = []
            ACME_LOG_LATER.sparse = False
            try:
                self.handle(kind, sock, data, peer, arrived)
            except DbError as e:
                # Not answered, as any request while the database is away.
                self.counts['no_database'] += 1
                DB_TROUBLE_SEEN.update(at=time.time(), said=str(e).split('\n')[0][:200])
                log_sparing('radius-db', 'RADIUS requests go unanswered: %s'
                            % str(e).split('\n')[0][:200], 'error')
            except Exception as e:
                # Sparingly (1.0.59): a packet that breaks it once breaks it
                # every time it is sent, by anybody using the NAS's address.
                log_sparing('radius-broke:%s:%s' % (type(e).__name__, str(e)[:60]),
                            'a RADIUS request from %s broke: %s\n%s'
                            % (peer[0], e, traceback.format_exc()), 'error', every=300)
            finally:
                rows, ACME_LOG_LATER.rows = ACME_LOG_LATER.rows, None
                for row in rows or ():
                    try:
                        self.d.store.acme_add(row)
                    except Exception as e:              # noqa: BLE001
                        log_sparing('acme-log', 'the check of a code could not be written down: '
                                    '%s' % e, 'warn')

    @staticmethod
    def draining():
        """Maintenance asked for, the VIP address still on this node (1.0.186):
        answered on until keepalived has moved it - 20 s at most - so the VPN
        asking the VIP address is not left without an answer meanwhile. Never
        while this node is rebuilt or a backup is put back."""
        if HA_REBUILDING.is_set() or RESTORE_RUNNING.is_set() or not VIP_HEALTH.get('here'):
            return False
        since = VIP_HEALTH.setdefault('drain_since', time.time())
        return time.time() - since < 20

    # ---- one packet -----------------------------------------------------------
    def handle(self, kind, sock, data, peer, arrived):
        ip, port = peer[0], peer[1]
        if ip.startswith('::ffff:'):
            ip = ip[7:]
        self.counts['packets'] += 1
        self.sum_up()
        # In maintenance nothing is answered (1.0.37): the VPN takes this
        # node for down and asks the other, as it would any node that is.
        if maintenance_now(self.d.store).get('on') and not self.draining():
            self.counts['maintenance'] += 1
            return
        client = self.d.store.client_for(ip)
        try:
            pkt = Packet.parse(data)
        except RadiusError as e:
            self.counts['malformed'] += 1
            # Only from a client is one written down, and then sparingly:
            # anybody can send junk to the port, from any address.
            if client:
                self.drop(ip, port, '', 'not a RADIUS packet: %s' % e, client=client, sparing=True)
            else:
                with self.unknown_lock:
                    self.quiet['malformed from %s' % ip if len(self.quiet) < 1000
                               else 'malformed, from other addresses'] += 1
            return
        if not client:
            self.counts['unknown'] += 1
            self.drop(ip, port, pkt.text(1), 'the address %s is not one of the clients' % ip,
                      pkt=pkt, unknown=True)
            return
        secret = (client.get('_secret') or '').encode('utf-8')
        if not secret:
            self.drop(ip, port, pkt.text(1), 'the secret of the client %s cannot be opened '
                      'on this machine' % client['name'], pkt=pkt, client=client)
            return
        # The whole packet in the key (1.0.57), as FreeRADIUS compares it: a
        # made-up packet with the same ident and authenticator from the NAS's
        # address can no longer stand in for the real one.
        key = (ip, port, pkt.ident, pkt.authenticator, kind, hashlib.sha256(data).digest()[:16])
        window = int(CONFIG.get('radius_dup_window_s') or 0)
        if window:
            with self.seen_lock:
                got = self.seen.get(key)
                if got and arrived - got[0] < window:
                    self.counts['repeated'] += 1
                    # A refusal sent late is given to a repeat once it went
                    # (1.0.136) - before, the NAS's repeats got nothing and it
                    # took the server for dead.
                    again = got[1] if got[1] and time.time() >= (got[2] if len(got) > 2 else 0) \
                        else None
                    hit = True
                else:
                    hit = False
                    self.seen[key] = (arrived, None)
                    self.seen.move_to_end(key)
                    # Old ones go from the front; past the limit the oldest go
                    # whatever their age - never a rebuild of the whole table.
                    cut = arrived - window
                    while self.seen:
                        k0, v0 = next(iter(self.seen.items()))
                        if v0[0] >= cut and len(self.seen) <= self.SEEN_MAX:
                            break
                        self.seen.popitem(last=False)
            if hit:
                # Sent outside the lock (1.0.186): a full send buffer held every
                # packet's look for repeats behind it.
                if again:
                    try:
                        sock.sendto(again, peer)
                    except OSError:
                        pass
                return
        try:
            if kind == 'acct':
                reply = self.accounting(pkt, client, ip, port, secret, arrived)
            elif pkt.code == STATUS_SERVER:
                reply = self.status(pkt, client, ip, port, secret)
            elif pkt.code == ACCESS_REQUEST:
                remember = None
                if window:
                    def remember(b, key=key):
                        # The answer kept for a repeat the moment it is sent
                        # (1.0.101), not after it is written down: a repeat
                        # coming meanwhile got nothing.
                        with self.seen_lock:
                            if key in self.seen:
                                self.seen[key] = (arrived, b)
                reply = self.access(pkt, client, ip, port, secret, arrived, sock, peer, remember)
            else:
                # Not proven to come from the client: written down sparingly
                # (1.0.57) - anybody can send it from the NAS's address.
                self.drop(ip, port, pkt.text(1), 'a %s is not something this port answers'
                          % CODE_WORDS.get(pkt.code, 'code %d' % pkt.code), pkt=pkt,
                          client=client, sparing=True)
                reply = None
        except BaseException:
            # Nothing answered: a repeat of it is not swallowed as "repeated"
            # for the whole window (1.0.57).
            if window:
                with self.seen_lock:
                    self.seen.pop(key, None)
            raise
        if reply and not getattr(reply, 'sent', False):
            try:
                sock.sendto(reply, peer)
            except OSError as e:
                log('the answer to %s could not be sent: %s' % (ip, e), 'warn')
        if window:
            with self.seen_lock:
                # A refusal still waiting out its delay is not handed to a
                # repeat of the request either (1.0.36): it would have skipped
                # the wait.
                if reply is None and pkt.code == ACCESS_REQUEST:
                    # Left unanswered (no database, 1.0.59): the NAS's repeat
                    # is tried again, not swallowed as "repeated".
                    self.seen.pop(key, None)
                elif key in self.seen:
                    self.seen[key] = (arrived, bytes(reply) if reply else None,
                                      getattr(reply, 'late_until', 0))
        try:
            self.d.store.client_seen(client['id'])
        except Exception as e:                          # noqa: BLE001
            log_sparing('radius-client-seen', 'the client %s could not be marked as seen: %s'
                        % (client['name'], str(e).split('\n')[0][:200]), 'warn')

    SEEN_MAX = 20000

    def sum_up(self):
        """Once a minute, what was only counted, in one line."""
        t = time.time()
        if t - self.quiet_at < 60:
            return
        with self.unknown_lock:
            if t - self.quiet_at < 60:
                return
            said, self.quiet = self.quiet, collections.Counter()
            self.quiet_at = t
            self.drops_this_minute = 0
        if said:
            top = ', '.join('%s: %d' % kv for kv in said.most_common(8))
            try:
                self.d.store.add_event('radius', 'not answered and not written down one by one '
                                       'in the last minute: %d packet(s) - %s'
                                       % (sum(said.values()), top), 'warn')
            except Exception as e:                      # noqa: BLE001
                log('could not write the minute\'s summary: %s' % e, 'warn')

    def drop(self, ip, port, user, reason, pkt=None, client=None, unknown=False,
             sparing=False):
        """A packet that is not answered: written down - for an unknown
        address only once a minute, so a VPN pointed here before it was
        added does not fill the log, and never more than 30 a minute in
        all, so a flood from made-up addresses does not either (1.0.33)."""
        self.counts['dropped'] += 1
        if unknown or sparing:
            if unknown and not CONFIG.get('radius_unknown_log', 1):
                return
            with self.unknown_lock:
                t = time.time()
                last = self.unknown_said.get(ip, 0)
                if t - last < 60 or self.drops_this_minute >= 30:
                    # Bounded (1.0.57): a flood from made-up addresses made
                    # one key each until the minute was up.
                    self.quiet[(('unknown address %s' if unknown else 'dropped from %s') % ip)
                               if len(self.quiet) < 1000 else 'from other addresses'] += 1
                    return
                self.unknown_said[ip] = t
                self.drops_this_minute += 1
                if len(self.unknown_said) > 4000:
                    # Kept to the newest addresses, so a scan of the port
                    # cannot grow this table without end.
                    newest = sorted(self.unknown_said.items(), key=lambda kv: kv[1])[-2000:]
                    self.unknown_said = dict(newest)
        self.d.store.radius_add({
            'ts': time.time(), 'client': (client or {}).get('name') or '', 'nas_ip': ip,
            'src': '%s:%d' % (ip, port), 'packet': CODE_WORDS.get(pkt.code, '?') if pkt else '?',
            'username': str(user or '')[:190], 'realm': '', 'calling': '', 'called': '',
            'result': 'drop', 'reason': reason[:500], 'acme': '', 'rid': '', 'took_ms': 0,
            'attrs': json.dumps(pkt.words() if pkt else []), 'reply': '[]',
            'steps': json.dumps([{'what': 'answered', 'ok': False, 'said': reason}]),
            'device': '', 'tunnel': ''})
        if unknown:
            self.d.store.add_event('radius', 'a request from %s, which is not a client, was '
                                   'not answered' % ip, 'warn')

    def ma_check(self, pkt, client, secret, ip, port):
        """Whether the Message-Authenticator lets this one through."""
        got = pkt.message_authenticator_ok(secret)
        if got is False:
            self.drop(ip, port, pkt.text(1), 'the Message-Authenticator is wrong: the shared '
                      'secret is not the same as on the client', pkt=pkt, client=client,
                      sparing=True)
            return False
        if got is True:
            # Per address of the client (1.0.57): one device of a range that
            # sends it no longer made it required of all the others. Only an
            # Access-Request's makes it required (1.0.59): a Status-Server
            # always carries one, and a monitor asking that from the NAS's
            # address had every plain PAP request after it dropped.
            if pkt.code == ACCESS_REQUEST and (client['id'], ip) not in self.ma_seen:
                self.ma_seen.add((client['id'], ip))
                # Kept in the database too (1.0.101): a restart, or the other
                # node, no longer forgets that this NAS signs its requests.
                try:
                    # Under this node's name (1.0.101): one key written by
                    # both nodes at once stopped replication on the second.
                    self.d.store.set_meta('maseen:%s:%s:%s' % (node_name(), client['id'], ip),
                                          '1')
                except Exception:                       # noqa: BLE001
                    pass
            return True
        # None: there is none. A client that has sent one before must go on
        # sending one (1.0.33) - what is stripped off on the way, as
        # BlastRADIUS does, is refused.
        sticky = CONFIG.get('radius_ma_sticky', 1) and self.ma_known(client['id'], ip)
        # Proxy-State and no Message-Authenticator: the shape BlastRADIUS
        # needs (CVE-2024-3596), refused as FreeRADIUS's limit_proxy_state
        # does (1.0.57).
        if pkt.code == ACCESS_REQUEST and pkt.all(33):
            self.drop(ip, port, pkt.text(1), 'Proxy-State without a Message-Authenticator '
                      '(the shape of a BlastRADIUS forgery)', pkt=pkt, client=client,
                      sparing=True)
            return False
        if client.get('require_ma') or pkt.code == STATUS_SERVER or sticky:
            self.drop(ip, port, pkt.text(1), 'there is no Message-Authenticator, and this '
                      'client must send one%s' % (' - it has sent one before' if sticky and
                                                  not client.get('require_ma') else ''),
                      pkt=pkt, client=client, sparing=True)
            return False
        return True

    def ma_known(self, cid, ip):
        """Whether this address of the client has signed a request before -
        here, or on the other node, or before a restart (1.0.101). Looked up
        at most once a minute for an address that has not."""
        if (cid, ip) in self.ma_seen:
            return True
        t = time.time()
        if self.ma_asked.get((cid, ip), 0) > t - 60:
            return False
        if len(self.ma_asked) > 20000:
            self.ma_asked.clear()
        self.ma_asked[(cid, ip)] = t
        try:
            want = ':%s:%s' % (cid, ip)
            for r in self.d.store.db.rows("SELECT k FROM meta WHERE k LIKE 'maseen:%' AND "
                                          "substr(k, length(k) - ? + 1) = ?",
                                          (len(want), want)):
                if r['k'].split(':', 2)[-1] == want[1:]:
                    self.ma_seen.add((cid, ip))
                    return True
        except Exception as e:                          # noqa: BLE001
            # Not known is not "it never signed" (1.0.149): the database not
            # answering let an unsigned request past the rule that a client
            # which signs must always sign. Asked again next time, and this
            # request is not answered.
            self.ma_asked.pop((cid, ip), None)
            raise DbError('whether %s signs its requests could not be read: %s' % (ip, e))
        return False

    def status(self, pkt, client, ip, port, secret):
        if not CONFIG.get('radius_status_server', 1):
            return None
        if not self.ma_check(pkt, client, secret, ip, port):
            return None
        self.counts['status'] += 1
        return build_reply(pkt, ACCESS_ACCEPT, [attr_bytes('Reply-Message', 'acme is alive')],
                           secret, True)

    def access(self, pkt, client, ip, port, secret, arrived, sock=None, peer=None,
               remember=None):
        if not self.ma_check(pkt, client, secret, ip, port):
            return None
        rid = '%s:%d' % (ip, port)
        user = pkt.text(1)
        try:
            password = pkt.password(secret)
        except RadiusError:
            password = None
        chap = pkt.get(3) is not None
        # Another secret leaves control characters in what comes out (random
        # bytes); a password in another encoding than UTF-8 (cp1250, say)
        # does not, and is refused as before - not left unanswered.
        unreadable = pkt.get(2) is not None and (
            password is None or re.search(r'[\x01-\x1f\x7f]', password) is not None)
        # Refused all the same, but written down once a minute a client
        # (1.0.186): unsigned, with no password to read (none, CHAP) or one that
        # decodes to U+FFFD - anyone can send such from a NAS's address, and each
        # was a row in the database, uncounted by the sign-in protection.
        ACME_LOG_LATER.sparse = pkt.get(80) is None and (
            pkt.get(2) is None or (password is not None and '\ufffd' in password))
        if unreadable and not chap and pkt.get(80) is None:
            # A password that does not come out (another secret) and nothing
            # proving the packet is the client's: not written down one row a
            # packet (1.0.136) - anyone can send such from the NAS's address,
            # thousands a second. The NAS, had it sent it, could not have
            # read a refusal made with this secret either.
            self.drop(ip, port, user, 'the password cannot be read with this client\'s shared '
                      'secret (and there is no Message-Authenticator)', pkt=pkt,
                      client=client, sparing=True)
            return None
        words = pkt.words()
        w = dict(words)
        state = pkt.get(24)
        # Sign-in protection (1.0.137): a place blocked for guessing is
        # refused at once - nothing of it checked, nothing counted against a
        # token.
        # Never in the way of an answer: whatever goes wrong in it, the
        # request is decided as it would be without it.
        try:
            src = guard_source(w) if guard_on() else ''
            if src and guard_trusted(src):
                src = ''
            blocked = guard_blocked(self.d, src) if src else None
        except Exception as e:                          # noqa: BLE001
            log_sparing('radius-guard', 'the sign-in protection: %s' % e, 'warn')
            src, blocked = '', None
        # Where the person is, for the recovery codes' guard (1.0.149).
        try:
            REQUEST_PLACE.v = guard_source(w)
        except Exception:                               # noqa: BLE001
            REQUEST_PLACE.v = ''
        try:
            if blocked:
                d = Decision()
                d.user = str(user or '')[:190]
                d.step('sign-in protection', False, '%s is blocked for %s more: %s' % (
                    src, guard_left(blocked[0]), blocked[1]))
                d.refuse('Denied by the token server: too many wrong sign-ins from %s - '
                         'blocked for a while' % src)
            elif state is not None and bytes(state).startswith(CHAL_PREFIX):
                # The code from the second window (1.0.76).
                d = self.d.auth.answer(user, password, bytes(state), client.get('realm') or '',
                                       src=ip, rid=rid, chap=chap, client=client)
            else:
                d = self.d.auth.decide(user, password, client.get('realm') or '', src=ip,
                                       rid=rid, chap=chap, client=client)
        except DbError as e:
            # The database gone (1.0.59): no answer, as a node in maintenance
            # gives none - the VPN asks the other node, where a refusal would
            # have refused everybody until the database was back.
            self.counts['no_database'] += 1
            # Told to the alerts too (1.0.207): only a DbError out of handle() was,
            # and the common case went unanswered with no word to anybody.
            DB_TROUBLE_SEEN.update(at=time.time(), said=str(e).split('\n')[0][:200])
            log_sparing('radius-db', 'RADIUS requests go unanswered: the database cannot be '
                        'reached (%s)' % str(e).split('\n')[0][:200], 'error')
            return None
        except Exception as e:
            if db_trouble(e):
                # The database there but not answering - locked, full, a
                # statement or a lock that ran out (1.0.149): as when it is
                # gone, no answer. A refusal refused everybody with a right
                # code, and the VPN never asked the other node.
                self.counts['no_database'] += 1
                DB_TROUBLE_SEEN.update(at=time.time(), said=str(e).split('\n')[0][:200])
                log_sparing('radius-db', 'RADIUS requests go unanswered: the database is not '
                            'answering (%s)' % str(e).split('\n')[0][:200], 'error')
                return None
            # Whatever went wrong inside, the VPN gets an answer - a refusal
            # with the reason written down - rather than silence and a retry.
            log_sparing('radius-decide:%s' % type(e).__name__,
                        'a request for %s could not be decided: %s' % (user, e), 'error')
            d = Decision()
            d.user = str(user or '')
            d.step('the decision', False, 'it could not be made: %s' % e)
            d.refuse('the token server could not decide: %s' % str(e)[:120])
        if src and not blocked and guard_is_guess(d):
            try:
                guard_count(self.d, src, d.user or user)
            except Exception as e:                      # noqa: BLE001
                log_sparing('radius-guard', 'the sign-in protection: %s' % e, 'warn')
        pairs = []
        for name, value in d.reply:
            try:
                pairs.append(attr_bytes(name, value))
            except RadiusError as e:
                d.step('the answer', False, str(e))
                # Never an Accept without what limits it (1.0.101): one
                # attribute that cannot be built refuses, not drops.
                if d.result == 'accept':
                    d.refuse('the answer cannot be built whole: %s' % e)
        if d.result == 'accept':
            self.counts['accept'] += 1
            code = ACCESS_ACCEPT
        elif d.result == 'challenge' and d.state:
            # The second window (1.0.76): the State the VPN sends back with
            # the code, and the words it shows. Nothing that lets in.
            self.counts['challenge'] += 1
            code = ACCESS_CHALLENGE
            pairs = [attr_bytes('State', '0x' + bytes(d.state).hex())]
            said = (d.message or '').encode('utf-8')[:253].decode('utf-8', 'ignore')
            if said:
                pairs.append(attr_bytes('Reply-Message', said))
        else:
            self.counts['reject'] += 1
            code = ACCESS_REJECT
            # The reason is cut by bytes, not characters, so a reason full of
            # accented letters still fits the attribute; and if the attribute
            # cannot be built for whatever reason the reject still goes out
            # without it rather than the request going unanswered and unlogged.
            pairs = []
            # The reason stays here unless asked for (1.0.33): sent back, a
            # VPN may show it to whoever is signing in - whether the name has
            # a token, whether the code was right and the password not.
            if CONFIG.get('radius_reject_reason'):
                try:
                    said = (d.reason or '').encode('utf-8')[:253].decode('utf-8', 'ignore')
                    if said:
                        pairs = [attr_bytes('Reply-Message', said)]
                except (RadiusError, ValueError) as e:
                    d.step('the answer', False, 'the reason could not be sent along: %s' % e)
                    pairs = []
        try:
            reply = build_reply(pkt, code, pairs, secret, bool(CONFIG.get('radius_reply_ma', 1)))
        except RadiusError as e:
            # Too long with what the realm and the groups add (1.0.44): a
            # refusal still goes out and is written down - never an Accept
            # without the attributes that limit what it lets in to.
            d.step('the answer', False, '%s - refused, since it cannot be sent whole' % e)
            if code == ACCESS_ACCEPT:
                self.counts['accept'] -= 1
                self.counts['reject'] += 1
                d.refuse('the answer would be longer than a RADIUS packet may be: too many '
                         'reply attributes in the realm and its groups')
                code = ACCESS_REJECT
            reply = build_reply(pkt, code, [], secret, bool(CONFIG.get('radius_reply_ma', 1)))
        took = int((time.time() - arrived) * 1000)
        # The answer goes out before anything is written down (1.0.33): a
        # database that is slow or locked delays the log, not the person -
        # and never leaves a request that was let in without its answer.
        reply = SentReply(reply)
        delay = int(CONFIG.get('radius_reject_delay_ms') or 0) if code == ACCESS_REJECT else 0
        # To the address the request came from, as it came (1.0.36): on a
        # socket listening on :: an IPv4 client is ::ffff:a.b.c.d there, and
        # the bare a.b.c.d could not be sent to - every answer was lost.
        sock = sock or self.socks.get('auth', (None, None, None))[2]
        peer = peer or (ip, port)
        if delay:
            # Waited out by one thread for all of them, not a thread each
            # (1.0.36), and not in a worker: a flood of wrong codes cannot
            # tie up the workers sleeping.
            reply.late = True
            reply.late_until = time.time() + min(delay, 10000) / 1000.0
            self.later(min(delay, 10000) / 1000.0, sock, bytes(reply), peer)
        else:
            try:
                if sock is not None:
                    sock.sendto(bytes(reply), peer)
            except OSError as e:
                log('the answer to %s could not be sent: %s' % (ip, e), 'warn')
            if remember is not None:
                remember(bytes(reply))
        reply.sent = True
        try:
            self.write_down(pkt, client, ip, port, rid, arrived, d, code, reply, took, words, w)
        except Exception as e:                          # noqa: BLE001
            log_sparing('radius-write', 'the request from %s for %s could not be written down: %s'
                        % (ip, d.user, str(e).split('\n')[0][:200]), 'error')
        return reply

    def later(self, wait, sock, data, peer):
        """An answer sent after `wait` seconds, by the one thread that sends
        the late ones. Past 10 000 waiting the newest are sent at once rather
        than kept."""
        with self.late_lock:
            if len(self.late) >= 10000:
                # Dropped, not sent at once (1.0.57): sent at once, a flood
                # of wrong guesses went round the delay. The NAS asks again.
                self.counts['late_dropped'] += 1
                return
            heapq.heappush(self.late, (time.monotonic() + wait, id(data), sock, data, peer))
            if self.late_thread is None or not self.late_thread.is_alive():
                self.late_thread = threading.Thread(target=self.send_lates, name='radius-late',
                                                    daemon=True)
                self.late_thread.start()
        self.late_wake.set()

    def send_lates(self):
        while not self.stop_flag:
            # Cleared before the queue is looked at, not after the wait: one
            # put in between would otherwise sleep a whole second.
            self.late_wake.clear()
            with self.late_lock:
                due = []
                now = time.monotonic()      # a clock stepped back no longer holds them (1.0.207)
                while self.late and self.late[0][0] <= now:
                    due.append(heapq.heappop(self.late))
                wait = (self.late[0][0] - now) if self.late else 1.0
            for _t, _i, sock, data, peer in due:
                self.send_late(sock, data, peer)
            self.late_wake.wait(max(0.005, min(wait, 1.0)))

    @staticmethod
    def send_late(sock, data, peer):
        try:
            if sock is not None:
                sock.sendto(data, peer)
        except OSError:
            pass

    SPARSE = {}

    def write_down(self, pkt, client, ip, port, rid, arrived, d, code, reply, took, words, w):
        if getattr(ACME_LOG_LATER, 'sparse', False) and d.result != 'accept':
            k = ((client or {}).get('name') or ip, d.reason[:60])
            now = time.time()
            if now - self.SPARSE.get(k, 0) < 60:
                self.counts['not_written'] += 1
                return
            if len(self.SPARSE) > 5000:
                self.SPARSE.clear()
            self.SPARSE[k] = now
        if d.result == 'accept' and d.token_name:
            self.d.tokens.mark_from(d.token_name, w.get('Calling-Station-Id') or ip,
                                    (client or {}).get('name') or '')
        av = {}
        for name, value in words:
            if name == 'Cisco-AVPair' and '=' in value:
                k, _, v = value.partition('=')
                if k == 'mdm-tlv':
                    k, _, v = v.partition('=')
                av[k] = v
        tunnel = ''
        for name, value in words:
            if name == 'Vendor-3076-Attr-146' and value.startswith('0x'):
                try:
                    tunnel = bytes.fromhex(value[2:]).decode('ascii', 'ignore').strip('\x00')
                except ValueError:
                    pass
        reply_words = [(n, v) for n, v in Packet.parse(bytes(reply)).words()
                       if n != 'Message-Authenticator']
        self.d.store.radius_add({
            'ts': arrived, 'client': client['name'], 'nas_ip': w.get('NAS-IP-Address') or ip,
            'src': rid, 'packet': 'Access-Request',
            'username': d.user[:190] or (pkt.text(1) or '')[:190],
            'realm': d.realm, 'calling': (w.get('Calling-Station-Id') or '')[:190],
            'called': (w.get('Called-Station-Id') or '')[:190], 'result': d.result,
            'reason': d.reason[:1000], 'acme': d.acme[:190], 'rid': rid, 'took_ms': took,
            'attrs': json.dumps(words), 'reply': json.dumps(reply_words),
            'steps': json.dumps(d.steps), 'device': (av.get('computer-name') or '')[:190],
            'tunnel': tunnel[:190]})
        self.ship(pkt, words, reply_words, code, ip, port, rid, arrived)

    def accounting(self, pkt, client, ip, port, secret, arrived):
        if pkt.code == STATUS_SERVER:
            # Asked on the accounting port, answered with an
            # Accounting-Response (RFC 5997 4; 1.0.44).
            if not CONFIG.get('radius_status_server', 1):
                return None
            if not self.ma_check(pkt, client, secret, ip, port):
                return None
            self.counts['status'] += 1
            return build_reply(pkt, ACCOUNTING_RESPONSE, [], secret, True)
        # Sparingly, as on the other port (1.0.59): neither is proven to come
        # from the client, and each one was a row in the database.
        if pkt.code != ACCOUNTING_REQUEST:
            self.drop(ip, port, pkt.text(1), 'only Accounting-Request is answered on this port',
                      pkt=pkt, client=client, sparing=True)
            return None
        if not pkt.accounting_ok(secret):
            self.drop(ip, port, pkt.text(1), 'the authenticator of the accounting request is '
                      'wrong: the shared secret is not the same as on the client', pkt=pkt,
                      client=client, sparing=True)
            return None
        # A Message-Authenticator, where there is one, has to be right too
        # (1.0.59) - over the packet with the authenticator as noughts.
        if pkt.message_authenticator_ok(secret, zero_authenticator=True) is False and \
                pkt.message_authenticator_ok(secret) is not True:
            self.drop(ip, port, pkt.text(1), 'the Message-Authenticator of the accounting '
                      'request is wrong', pkt=pkt, client=client, sparing=True)
            return None
        self.counts['accounting'] += 1
        words = pkt.words()
        w = dict(words)
        self.d.store.radius_add({
            'ts': arrived, 'client': client['name'], 'nas_ip': w.get('NAS-IP-Address') or ip,
            'src': '%s:%d' % (ip, port), 'packet': 'Accounting-Request',
            'username': (w.get('User-Name') or '')[:190], 'realm': '',
            'calling': (w.get('Calling-Station-Id') or '')[:190],
            'called': (w.get('Called-Station-Id') or '')[:190], 'result': 'acct',
            'reason': (w.get('Acct-Status-Type') or '')[:100], 'acme': '', 'rid': '',
            'took_ms': int((time.time() - arrived) * 1000), 'attrs': json.dumps(words),
            'reply': '[]', 'steps': '[]', 'device': '', 'tunnel': ''})
        if self.d.shipper:
            self.d.shipper.detail_line(ip, 'detail', arrived, self.header(
                'Accounting-Request', ip, port, port_here=self.port_of('acct')) + words)
        return build_reply(pkt, ACCOUNTING_RESPONSE, [], secret, with_ma=False)

    def port_of(self, kind):
        got = self.socks.get(kind)
        return got[1] if got else 0

    @staticmethod
    def header(packet, ip, port, port_here, reply=False):
        """What FreeRADIUS writes first in a detail record under
        `log_packet_header = yes`."""
        if reply:
            return [('Packet-Type', packet), ('Packet-Dst-IP-Address', ip),
                    ('Packet-Dst-IP-Port', str(port))]
        return [('Packet-Type', packet), ('Packet-Src-IP-Address', ip),
                ('Packet-Src-IP-Port', str(port)), ('Packet-Dst-IP-Port', str(port_here))]

    def ship(self, pkt, words, reply_words, code, ip, port, rid, arrived):
        sh = self.d.shipper
        if not sh:
            return
        here = self.port_of('auth')
        ask = self.header('Access-Request', ip, port, here) + words + [('Totp-Request-Id', rid)]
        sh.detail_line(ip, 'auth-detail', arrived, ask)
        answer = self.header(CODE_WORDS[code], ip, port, here, reply=True) + reply_words + [
            ('Totp-Request-Id', rid)]
        sh.detail_line(ip, 'reply-detail', time.time(), answer)

    def state(self):
        return {'listening': self.bound, 'trouble': self.trouble, 'counts': dict(self.counts),
                'queued': self.jobs.qsize() + self.acct_jobs.qsize()}
# ---- RADIUS: guessing from one place held back (1.0.137) -----------------------------
# Every token counts its own wrong codes and locks itself (lockout_after), and
# that is all there was: from one place - one address behind the VPN - a
# guesser could try every user's code a few times a day, or lock every token
# out on purpose. Switched on (radius_guard), the place each request comes
# from is counted too: the Calling-Station-Id the VPN sends (the address the
# person connects from; a MAC address on Wi-Fi). Too many refusals from one
# place in the window - or too many different names refused from it - and the
# place is blocked for a while: its requests are refused at once, nothing of
# them checked, so they neither guess further nor count against anybody's
# token. Counted in each node's memory, as the pages' sign-ins are, and shown
# with them (Settings - Sign-in protection), each cleared by hand or all.
GUARD_KIND = 'radius-src'
# Refusals that are this server's trouble, not somebody's guess: never counted.
GUARD_NOT_GUESSES = ('gone away', 'could not decide', 'cannot be built', 'is not set up',
                     'cannot be sent', 'does not decode', 'too many codes sent',
                     'has no directory', 'nowhere to send', 'too many answers at once',
                     'longer than a RADIUS packet', 'no realm takes', 'may not use the realm',
                     'carries no', 'already been used', 'could not be asked',
                     # The account's own state in the directory, refused before any
                     # password or code is looked at (1.0.207): a disabled account's
                     # VPN reconnecting blocked everybody behind the same address.
                     'is disabled in the directory', 'has expired in the directory',
                     'the account may not sign in', 'more than one account in')


def guard_on():
    return bool(CONFIG.get('radius_guard'))


def guard_source(w):
    """Where a request comes from, as the VPN says it: an address (IPv6 by its
    /64 - one machine's to choose from), or what else it sends (a MAC)."""
    raw = str((w or {}).get('Calling-Station-Id') or '').strip()
    if not raw:
        return ''
    # An address with its port (1.0.139): 203.0.113.5:51234 or [2001:db8::5]:51234
    # was a new place at every connection, and never blocked.
    m = re.match(r'^\[([^\]]+)\](?::\d+)?\Z', raw) or \
        re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):\d+\Z', raw)
    if m:
        raw = m.group(1)
    try:
        a = ipaddress.ip_address(raw.split('%')[0].strip('[]'))
        if a.version == 6:
            if a.ipv4_mapped:
                return str(a.ipv4_mapped)
            return str(ipaddress.ip_network('%s/64' % a, strict=False))
        return str(a)
    except ValueError:
        return re.sub(r'[^0-9A-Za-z:._-]', '', raw).lower()[:64]


def guard_trusted(src):
    """A place never blocked: radius_guard_trusted (an office behind one
    address, a monitor that signs in)."""
    raw = str(CONFIG.get('radius_guard_trusted') or '')
    if not raw.strip() or not src:
        return False
    try:
        a = ipaddress.ip_network(src, strict=False)
    except ValueError:
        return src in [x.strip().lower() for x in re.split(r'[\s,;]+', raw) if x.strip()]
    for x in re.split(r'[\s,;]+', raw):
        if not x.strip():
            continue
        try:
            net = ipaddress.ip_network(x.strip(), strict=False)
        except ValueError:
            continue
        if net.version != a.version:
            continue
        if a.prefixlen >= net.prefixlen and a.subnet_of(net):
            return True
        # One IPv6 address (1.0.146): requests are told apart by their /64
        # only, so the /64 it is in is the one trusted.
        if a.version == 6 and a.prefixlen == 64 and net.overlaps(a):
            return True
    return False


def guard_blocked(daemon, src):
    """(until, why) while the place is blocked, else None."""
    if not src:
        return None
    info = daemon.login_info.get((GUARD_KIND, src))
    if not info:
        return None
    until = float(info.get('blocked_until') or 0)
    if until > time.time():
        return until, info.get('blocked_why') or 'too many wrong sign-ins'
    return None


def guard_is_guess(d):
    # A wrong code asked again is a guess too (1.0.207): in challenge, mail and
    # SMS realms only the last refusal of a round was counted.
    if d.result == 'challenge' and str(d.reason or '').startswith('the code was not right'):
        return True
    if d.result != 'reject':
        return False
    reason = str(d.reason or '')
    return not any(w in reason for w in GUARD_NOT_GUESSES)


def guard_count(daemon, src, name):
    """One refusal from `src` for `name`: counted; blocked at the limit."""
    t = time.time()
    tries = int(CONFIG.get('radius_guard_tries') or 20)
    nlimit = int(CONFIG.get('radius_guard_names') or 0)
    span = 60 * int(CONFIG.get('radius_guard_window_min') or 15)
    block = 60 * int(CONFIG.get('radius_guard_block_min') or 30)
    key = (GUARD_KIND, src)
    name = str(name or '').strip().lower()[:120]
    newly = None
    with ApiHandler.THROTTLE_LOCK:
        fails = [x for x in daemon.login_fails[key] if t - x < span] + [t]
        # Kept to the limits set (1.0.139): tries up to 10000, names up to 1000.
        daemon.login_fails[key] = fails[-max(1000, tries):]
        info = daemon.login_info.setdefault(key, {'others': []})
        names = {n: ts for n, ts in (info.get('names') or {}).items() if t - ts < span}
        if name:
            names[name] = t
            cap = max(500, nlimit)
            if len(names) > cap:
                names = dict(sorted(names.items(), key=lambda kv: kv[1])[-cap:])
            others = [x for x in info.get('others') or [] if x != name]
            info['others'] = (others + [name])[-6:]
        info.update(limit=tries, span=span, what='wrong sign-ins', at=t, names=names,
                    names_limit=nlimit, guard=True)
        if float(info.get('blocked_until') or 0) <= t:
            why = None
            if len(fails) >= tries:
                why = '%d wrong sign-ins in %d min' % (len(fails), span // 60)
            elif nlimit and len(names) >= nlimit:
                why = '%d different names refused in %d min' % (len(names), span // 60)
            if why:
                info['blocked_until'] = t + block
                info['blocked_why'] = why
                info['blocked_at'] = t
                newly = why
    if newly:
        try:
            daemon.store.add_event('radius', '%s is blocked for %d min - %s; the names: %s'
                                   % (src, block // 60, newly, ', '.join(
                                       (daemon.login_info.get(key) or {}).get('others') or [])),
                                   'warn')
        except Exception:                               # noqa: BLE001
            pass
        LOCKOUTS_SENT['sig'] = None


def guard_left(until):
    left = max(0, int(until - time.time()))
    return '%d min' % ((left + 59) // 60) if left >= 60 else '%d s' % left


