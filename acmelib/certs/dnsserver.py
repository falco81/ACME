# -*- coding: utf-8 -*-
"""
acme's own DNS server - authoritative for its zones only, UDP and TCP.

The customer's DNS points the _acme-challenge names at it once:

    _acme-challenge.www.example.com.  CNAME  www.example.com.acme.example.net.

(and acme.example.net is delegated to acme by NS records in example.net), or a
subzone of the customer's own is delegated to acme by NS. acme then puts each
DNS-01 TXT record into the table dns_records and this server answers with it.

    srv = DnsServer(store)          store.db.rows() / store.db.run() as the engine's
    srv.start(); srv.state(); srv.reload(); srv.stop()

Settings (E.CONFIG, or a dict handed in):

    dns_listen        addresses to listen on, comma separated ('0.0.0.0,::')
    dns_port          53
    dns_zone          the zone(s) it serves, comma separated ('acme.example.net')
    dns_ns_names      its NS names ('ns1.acme.example.net,ns2.acme.example.net')
    dns_ns_addresses  glue: 'ns1.acme.example.net=192.0.2.10, ns2...=192.0.2.11', or bare
                      addresses (one per NS name in order, or all for each)
    dns_soa_mail      the SOA's mail ('hostmaster@example.net')
    dns_ttl           60 (the records' TTL where none is given, and the negative TTL)
    dns_static        lines "name type value [ttl]" (or "name ttl type value"):
                      relative to the first zone, '@' the apex, a name ending in '.'
                      as it is
    dns_rate          answers a second to one source (/24, /56) before it is
                      slowed (100; 0: no limit)
    dns_cache         seconds the records are read again after (1)

Answers SOA, NS, A/AAAA (glue and static), TXT, CNAME (followed inside its own
zones), CAA, MX, SRV; NXDOMAIN / NODATA with the SOA in the authority section;
REFUSED for names outside its zones, AXFR and UPDATE; no recursion. EDNS0:
the OPT echoed with 1232 bytes of room; an answer too big for UDP comes back
cut short (TC), so the resolver asks over TCP. Names are matched without
regard to case and the question goes back as it came (0x20). The parser
never raises on what arrives: a message that cannot be read is FORMERR, or
nothing at all when not even the header holds.

Port 53 needs CAP_NET_BIND_SERVICE (AmbientCapabilities= in the unit) - when
it cannot be bound, state() says so in words.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import struct
import sys
import threading
import time
import zlib

from acmelib.plugins.challenges import _dns as D

DEFAULTS = {'dns_listen': '0.0.0.0,::', 'dns_port': 53, 'dns_zone': '', 'dns_ns_names': '',
            'dns_ns_addresses': '', 'dns_soa_mail': '', 'dns_ttl': 60, 'dns_static': '',
            'dns_rate': 100, 'dns_cache': 1.0}
EDNS_SIZE = 1232
TCP_MAX_CONN = 64
TCP_IDLE = 10.0
TCP_MAX_QUERIES = 100
SERVED_TYPES = (1, 2, 5, 6, 15, 16, 28, 33, 257)


def _engine():
    """The engine when it is there (the daemon) - never imported for a test."""
    return sys.modules.get('acmelib.engine')


def _log(words, level='info'):
    E = _engine()
    if E is not None and hasattr(E, 'log'):
        try:
            E.log('dns: ' + words, level)
        except Exception:                               # noqa: BLE001
            pass


def _split(text):
    if isinstance(text, (list, tuple)):
        return [str(x).strip() for x in text if str(x).strip()]
    return [x.strip() for x in str(text or '').replace(';', ',').replace('\n', ',').split(',')
            if x.strip()]


class Zones(object):
    """Everything this server answers with at one moment: {name: {type: [(ttl, text)]}}
    and the zones. Built again when the records or the settings change."""

    def __init__(self, cfg, rows, now):
        self.zones = sorted({D.norm(z) for z in _split(cfg.get('dns_zone')) if D.norm(z)},
                            key=lambda z: -len(z))
        # the first one written is "the" zone relative names belong to
        self.first = D.norm(_split(cfg.get('dns_zone'))[0]) if self.zones else ''
        try:
            self.ttl = max(0, int(cfg.get('dns_ttl') or 60))
        except (TypeError, ValueError):
            self.ttl = 60
        self.data = {}
        self.problems = []
        self.ns = [D.norm(x) for x in _split(cfg.get('dns_ns_names'))] or \
            (['ns1.' + self.first] if self.first else [])
        mail = str(cfg.get('dns_soa_mail') or '').strip()
        if '@' in mail:
            local, _, dom = mail.partition('@')
            mail = local.replace('.', '\\.') + '.' + dom
        self.rname = mail.rstrip('.') or ('hostmaster.' + self.first if self.first else 'hostmaster')
        serial = 1
        for z in self.zones:
            for ns in self.ns:
                self.add(z, 'NS', ns, self.ttl)
        self._glue(cfg)
        for line in str(cfg.get('dns_static') or '').splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(';') else ''
            if not line:
                continue
            try:
                name, rtype, value, ttl = parse_static(line)
                self.add(self.absolute(name), rtype, value, ttl if ttl is not None else self.ttl)
            except ValueError as e:
                self.problems.append('dns_static "%s": %s' % (line[:60], e))
        for r in rows:
            try:
                exp = float(r.get('expires') or 0)
            except (TypeError, ValueError):
                exp = 0
            if exp and exp < now:
                continue
            try:
                ttl = int(r.get('ttl')) if r.get('ttl') not in (None, '') else self.ttl
                self.add(self.absolute(r.get('name')), r.get('rtype'), r.get('value'), ttl)
            except (ValueError, TypeError) as e:
                self.problems.append('record %s %s: %s' % (r.get('name'), r.get('rtype'), e))
                continue
            try:
                serial = max(serial, int(float(r.get('created') or 0)))
            except (TypeError, ValueError):
                pass
        cfgsum = zlib.crc32(repr([str(cfg.get(k)) for k in (       # what is answered, not where
            'dns_zone', 'dns_ns_names', 'dns_ns_addresses', 'dns_soa_mail', 'dns_ttl',
            'dns_static')]).encode())
        self.serial = (serial + cfgsum % 1000) & 0xFFFFFFFF or 1
        for z in self.zones:
            self.data.setdefault(z, {})[6] = [(self.ttl, '%s %s %d 3600 600 1209600 %d' % (
                self.ns[0] if self.ns else z, self.rname, self.serial, self.ttl))]
        # Every name and every name above it inside a zone exists (an empty
        # non-terminal is NODATA, never NXDOMAIN - RFC 8020 resolvers would
        # take NXDOMAIN to mean nothing below it either).
        self.exists = set()
        for name in self.data:
            z = self.zone_of(name)
            n = name
            while z is not None and n and D.in_zone(n, z):
                self.exists.add(n)
                if n == z:
                    break
                n = n.split('.', 1)[1] if '.' in n else ''
        self.count = sum(len(v) for t in self.data.values() for v in t.values())

    def _glue(self, cfg):
        bare, named = [], {}
        for item in _split(cfg.get('dns_ns_addresses')):
            if '=' in item:
                n, _, a = item.partition('=')
                named.setdefault(D.norm(n), []).append(a.strip())
            else:
                bare.append(item)
        inside = [n for n in self.ns if self.zone_of(n) is not None]
        if bare and inside:
            if len(bare) == len(inside) and len(inside) > 1:
                for n, a in zip(inside, bare):
                    named.setdefault(n, []).append(a)
            else:
                for n in inside:
                    named.setdefault(n, []).extend(bare)
        for n, addrs in named.items():
            if self.zone_of(n) is None:
                self.problems.append('glue for %s, a name outside the zones, is not served' % n)
                continue
            for a in addrs:
                try:
                    ip = ipaddress.ip_address(a)
                except ValueError:
                    self.problems.append('glue "%s" is not an address' % a)
                    continue
                self.add(n, 'A' if ip.version == 4 else 'AAAA', str(ip), self.ttl)

    def absolute(self, name):
        name = str(name or '').strip()
        if name in ('@', ''):
            return self.first
        if name.endswith('.'):
            return D.norm(name)
        n = D.norm(name)
        if self.zone_of(n) is not None or not self.first:
            return n
        if n.endswith('.@'):
            n = n[:-2]
        return n + '.' + self.first

    def add(self, name, rtype, value, ttl):
        t = D.type_code(str(rtype or '').strip())
        if t not in SERVED_TYPES:
            raise ValueError('type %s is not served' % D.type_name(t))
        name = D.norm(name)
        if not name:
            raise ValueError('no name')
        if t in (2, 5, 12):
            value = D.norm(value)
        value = str(value if value is not None else '').strip()
        D.rdata_to_wire(t, value)                       # a value that cannot be written is said now
        D.name_labels(name)
        if self.zone_of(name) is None:
            raise ValueError('%s is not in %s' % (name, ', '.join(self.zones) or 'any zone'))
        rr = self.data.setdefault(name, {}).setdefault(t, [])
        if not any(v == value for _t, v in rr):
            rr.append((int(ttl), value))

    def zone_of(self, name):
        name = D.norm(name)
        for z in self.zones:                            # longest first
            if name == z or name.endswith('.' + z):
                return z
        return None


def parse_static(line):
    """'name type value [ttl]' or 'name ttl type value' -> (name, type, value, ttl|None)."""
    bits = line.split(None, 2)
    if len(bits) < 3:
        raise ValueError('a line is "name type value [ttl]"')
    name, a, rest = bits
    ttl = None
    if a.isdigit():
        more = rest.split(None, 1)
        if len(more) < 2:
            raise ValueError('a line is "name ttl type value"')
        ttl, (a, rest) = int(a), more
    rtype = a.upper()
    D.type_code(rtype)
    rest = rest.strip()
    if ttl is None:
        tail = rest.rsplit(None, 1)
        if len(tail) == 2 and tail[1].isdigit() and rtype not in ('SOA',):
            # a number at the end is the TTL unless it is part of the value
            # (an MX ends in a name, a quoted TXT in a quote)
            ttl, rest = int(tail[1]), tail[0]
    return name, rtype, rest, ttl


class _Bucket(object):
    __slots__ = ('tokens', 'at', 'slip')

    def __init__(self, burst, now):
        self.tokens = burst
        self.at = now
        self.slip = 0


class DnsServer(object):
    """The server. `store` has .db.rows(sql, args) and .db.run(sql, args)
    (the engine's Store, or anything shaped so). `config` defaults to the
    engine's CONFIG."""

    def __init__(self, store, config=None, clock=time.time):
        self.store = store
        self._config = config
        self.clock = clock
        self.lock = threading.Lock()
        self.socks = []                 # [(sock, proto, address)]
        self.threads = []
        self.running = False
        self.stopping = threading.Event()
        self.failed = []                # [{'address', 'proto', 'error'}]
        self.listening = []
        self.stats = {'queries': 0, 'udp': 0, 'tcp': 0, 'answered': 0, 'nxdomain': 0,
                      'nodata': 0, 'refused': 0, 'formerr': 0, 'servfail': 0, 'notimp': 0,
                      'truncated': 0, 'rate_limited': 0, 'dropped': 0}
        self.last_error = ''
        self.last_error_at = 0.0
        self.started = 0.0
        self.zones = None
        self.loaded_at = 0.0
        self.load_ok_at = 0.0
        self.load_error = ''
        self._rows_sig = None
        self._cfg_sig = None
        self.buckets = {}
        self.tcp_slots = threading.BoundedSemaphore(TCP_MAX_CONN)
        self._last_tidy = 0.0
        self._bound_cfg = None

    # ---- settings ----------------------------------------------------------
    def cfg(self):
        src = self._config
        if src is None:
            E = _engine()
            src = getattr(E, 'CONFIG', {}) if E is not None else {}
        out = dict(DEFAULTS)
        for k in DEFAULTS:
            v = src.get(k) if hasattr(src, 'get') else None
            if v not in (None, ''):
                out[k] = v
        return out

    def _listen_conf(self, cfg):
        try:
            port = int(cfg.get('dns_port') or 53)
        except (TypeError, ValueError):
            port = 53
        return tuple(_split(cfg.get('dns_listen'))), port

    # ---- starting and stopping ------------------------------------------------
    def start(self):
        with self.lock:
            if self.running:
                return self.state()
            self.stopping.clear()
            cfg = self.cfg()
            self._bind(cfg)
            self.running = True
            self.started = self.clock()
            t = threading.Thread(target=self._housekeeping, name='dns-house', daemon=True)
            t.start()
            self.threads.append(t)
        try:
            self.records(force=True)
        except Exception:                               # noqa: BLE001
            pass
        return self.state()

    def _bind(self, cfg):
        addrs, port = self._listen_conf(cfg)
        self._bound_cfg = (addrs, port)
        self.failed, self.listening = [], []
        for a in addrs:
            try:
                ip = ipaddress.ip_address(a.strip('[]'))
            except ValueError:
                self._fail(a, 'udp+tcp', '"%s" is not an address' % a)
                continue
            fam = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            for proto in ('udp', 'tcp'):
                s = None
                try:
                    s = socket.socket(fam, socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if fam == socket.AF_INET6:
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    s.bind((str(ip), port))
                    if proto == 'tcp':
                        s.listen(64)
                    s.settimeout(0.5)
                except OSError as e:
                    if s is not None:
                        s.close()
                    # no IPv6 on this machine is no failure of the server
                    fatal = not (fam == socket.AF_INET6 and e.errno in (
                        errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL) and
                        str(ip) in ('::', '::1'))
                    self._fail(str(ip), proto, self._bind_words(e, str(ip), port, proto), fatal)
                    continue
                where = ('[%s]:%d' if fam == socket.AF_INET6 else '%s:%d') % (ip, s.getsockname()[1])
                self.socks.append((s, proto, where))
                self.listening.append('%s/%s' % (where, proto))
                t = threading.Thread(target=self._udp_loop if proto == 'udp' else self._tcp_loop,
                                     args=(s,), name='dns-%s-%s' % (proto, where), daemon=True)
                t.start()
                self.threads.append(t)
        if self.listening:
            _log('listening on %s' % ', '.join(self.listening))
        for f in self.failed:
            _log('%s %s: %s' % (f['address'], f['proto'], f['error']),
                 'error' if f['fatal'] else 'info')

    @staticmethod
    def _bind_words(e, addr, port, proto):
        if e.errno in (errno.EACCES, errno.EPERM):
            return ('permission denied for port %d: acme needs CAP_NET_BIND_SERVICE '
                    '(AmbientCapabilities=CAP_NET_BIND_SERVICE in acme.service) to listen '
                    'on a port below 1024' % port)
        if e.errno == errno.EADDRINUSE:
            return ('port %d/%s is already taken on %s - another DNS server (systemd-resolved\'s '
                    'stub on 127.0.0.53, dnsmasq, named)? Free it or listen on one address only'
                    % (port, proto, addr))
        if e.errno == errno.EADDRNOTAVAIL:
            return '%s is not an address of this machine' % addr
        if e.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            return 'this machine has no IPv%s' % ('6' if ':' in addr else '4')
        return str(e)

    def _fail(self, addr, proto, words, fatal=True):
        self.failed.append({'address': addr, 'proto': proto, 'error': words, 'fatal': fatal})
        if fatal:
            self._error('%s/%s: %s' % (addr, proto, words))

    def _error(self, words):
        self.last_error = words
        self.last_error_at = self.clock()

    def stop(self):
        with self.lock:
            self.stopping.set()
            for s, _p, _w in self.socks:
                try:
                    s.close()
                except OSError:
                    pass
            self.socks = []
            threads, self.threads = self.threads, []
            self.running = False
            self.listening = []
        for t in threads:
            if t is not threading.current_thread():
                t.join(2)

    def reload(self):
        """The settings and the records read again; the sockets made again
        when where it listens changed."""
        cfg = self.cfg()
        if self.running and self._listen_conf(cfg) != self._bound_cfg:
            self.stop()
            self.start()
        self.records(force=True)
        return self.state()

    def state(self):
        z = self.zones
        cfg = self.cfg()
        addrs, port = self._listen_conf(cfg)
        return {
            'running': self.running,
            'ok': self.running and bool(self.listening) and
            not any(f.get('fatal', True) for f in self.failed),
            'zones': list(z.zones) if z else [D.norm(x) for x in _split(cfg.get('dns_zone'))],
            'ns': list(z.ns) if z else [],
            'serial': z.serial if z else None,
            'port': port,
            'listen': list(addrs),
            'listening': list(self.listening),
            'failed': [dict(f) for f in self.failed],
            'records': z.count if z else 0,
            'records_loaded_at': self.load_ok_at,
            'records_error': self.load_error,
            'problems': list(z.problems) if z else [],
            'started': self.started,
            'stats': dict(self.stats),
            'queries': self.stats['queries'],
            'last_error': self.last_error,
            'last_error_at': self.last_error_at,
        }

    # ---- the records -----------------------------------------------------------
    def records(self, force=False):
        """The Zones as now - read again at most once every dns_cache seconds,
        so both nodes of a cluster answer alike within a second."""
        now = self.clock()
        cfg = self.cfg()
        try:
            cache = float(cfg.get('dns_cache') or 1.0)
        except (TypeError, ValueError):
            cache = 1.0
        if not force and self.zones is not None and now - self.loaded_at < cache:
            return self.zones
        self.loaded_at = now
        try:
            rows = self.store.db.rows(
                'SELECT name, rtype, value, ttl, expires, created FROM dns_records')
            rows = [dict(r) for r in rows]
            self.load_ok_at = now
            self.load_error = ''
        except Exception as e:                          # noqa: BLE001
            self.load_error = 'the records could not be read: %s' % e
            self._error(self.load_error)
            if self.zones is not None and now - self.load_ok_at < 60:
                return self.zones                       # the last ones read, for a minute
            rows = None
        sig = (repr(sorted((k, str(v)) for k, v in cfg.items())),
               None if rows is None else zlib.crc32(repr(sorted(
                   tuple(str(r.get(k)) for k in ('name', 'rtype', 'value', 'ttl', 'expires'))
                   for r in rows)).encode()))
        if self.zones is None or rows is None or sig != self._rows_sig or \
                (self._next_expiry and now >= self._next_expiry):
            self.zones = Zones(cfg, rows or [], now)
            self.zones.broken = rows is None
            self._rows_sig = sig
            later = []
            for r in rows or []:
                try:
                    x = float(r.get('expires') or 0)
                except (TypeError, ValueError):
                    continue
                if x > now:
                    later.append(x)
            self._next_expiry = min(later) if later else 0
        return self.zones

    _next_expiry = 0

    def tidy(self):
        """Records run out a while ago taken away (an hour after: a node that
        replicates late does not stumble on a row already gone)."""
        now = self.clock()
        try:
            return self.store.db.run(
                'DELETE FROM dns_records WHERE expires IS NOT NULL AND expires > 0 '
                'AND expires < ?', (now - 3600,))
        except Exception as e:                          # noqa: BLE001
            self._error('expired records could not be taken away: %s' % e)
            return 0

    def _housekeeping(self):
        while not self.stopping.wait(1.0):
            try:
                # (a change of where it listens is the caller's to act on:
                # reload(), or the renewer's dns_watch making a new server)
                now = self.clock()
                if now - self._last_tidy > 300:
                    self._last_tidy = now
                    if self._may_tidy():
                        self.tidy()
                with self.lock:
                    if len(self.buckets) > 5000:
                        old = [k for k, b in self.buckets.items() if now - b.at > 10]
                        for k in old:
                            self.buckets.pop(k, None)
            except Exception as e:                      # noqa: BLE001
                self._error('housekeeping: %s' % e)

    def _may_tidy(self):
        """Only the node that leads deletes (acmelib.certs.renewer.leader), so
        two nodes of a replicated database do not delete the same rows."""
        if _engine() is None:
            return True
        try:
            from acmelib.certs import renewer
            cur = renewer.leader(self.store)
        except Exception:                               # noqa: BLE001
            return False
        return bool(cur and cur.get('me'))

    # ---- the rate limit -----------------------------------------------------------
    def _allowed(self, addr):
        """A token bucket per /24 (IPv4) or /56 (IPv6)."""
        cfg = self.cfg()
        try:
            rate = float(cfg.get('dns_rate') or 0)
        except (TypeError, ValueError):
            rate = 100.0
        if rate <= 0:
            return True
        try:
            ip = ipaddress.ip_address(addr.split('%')[0])
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            key = str(ipaddress.ip_network('%s/%d' % (ip, 24 if ip.version == 4 else 56),
                                           strict=False))
        except ValueError:
            key = addr
        now = time.monotonic()
        burst = rate * 2
        with self.lock:
            b = self.buckets.get(key)
            if b is None:
                b = self.buckets[key] = _Bucket(burst, now)
            b.tokens = min(burst, b.tokens + (now - b.at) * rate)
            b.at = now
            if b.tokens >= 1:
                b.tokens -= 1
                return True
            b.slip += 1
            return 'slip' if b.slip % 2 == 0 else False

    # ---- the loops ------------------------------------------------------------------
    def _udp_loop(self, s):
        while not self.stopping.is_set():
            try:
                data, peer = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                time.sleep(0.05)
                continue
            try:
                self.stats['queries'] += 1
                self.stats['udp'] += 1
                ok = self._allowed(peer[0])
                if ok is False:
                    self.stats['rate_limited'] += 1
                    continue
                out = self.answer(data, peer[0], tcp=False, slip=(ok == 'slip'))
                if out:
                    s.sendto(out, peer)
            except Exception as e:                      # noqa: BLE001
                self._error('a UDP question from %s: %s' % (peer[0], e))

    def _tcp_loop(self, s):
        while not self.stopping.is_set():
            try:
                c, peer = s.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                time.sleep(0.05)
                continue
            if not self.tcp_slots.acquire(blocking=False):
                self.stats['dropped'] += 1
                c.close()
                continue
            threading.Thread(target=self._tcp_conn, args=(c, peer), daemon=True).start()

    def _tcp_conn(self, c, peer):
        try:
            c.settimeout(TCP_IDLE)
            for _ in range(TCP_MAX_QUERIES):
                head = self._read(c, 2)
                if not head:
                    return
                n = struct.unpack('>H', head)[0]
                data = self._read(c, n)
                if data is None or len(data) < n:
                    return
                self.stats['queries'] += 1
                self.stats['tcp'] += 1
                out = self.answer(data, peer[0], tcp=True)
                if not out:
                    return
                c.sendall(struct.pack('>H', len(out)) + out)
        except (OSError, socket.timeout):
            pass
        except Exception as e:                          # noqa: BLE001
            self._error('a TCP question from %s: %s' % (peer[0], e))
        finally:
            try:
                c.close()
            except OSError:
                pass
            self.tcp_slots.release()

    @staticmethod
    def _read(c, n):
        buf = b''
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                return buf or None
            buf += chunk
        return buf

    # ---- one answer -------------------------------------------------------------------
    def answer(self, data, peer='', tcp=False, slip=False):
        """The answer to one message as bytes, or None when nothing is to be
        said (not even a header, or it is an answer itself). Never raises."""
        try:
            return self._answer(data, tcp, slip)
        except Exception as e:                          # noqa: BLE001
            self._error('answering %s: %s: %s' % (peer, type(e).__name__, e))
            try:
                if len(data) >= 12 and not (data[2] & 0x80):
                    self.stats['servfail'] += 1
                    return self._bare(data, D.SERVFAIL)
            except Exception:                           # noqa: BLE001
                pass
            return None

    def _bare(self, data, rcode, question=b'', qd=0):
        """A header-only answer (with the question when it could be read)."""
        ident, flags = struct.unpack('>HH', data[:4])
        flags = 0x8000 | (flags & 0x7900) | (rcode & 0xF)       # QR, opcode and RD kept
        return struct.pack('>HHHHHH', ident, flags, qd, 0, 0, 0) + question

    def _answer(self, data, tcp, slip):
        if len(data) < 12:
            self.stats['dropped'] += 1
            return None
        if data[2] & 0x80:                              # an answer: never answered
            self.stats['dropped'] += 1
            return None
        try:
            q = D.parse(data)
        except D.FormErr:
            self.stats['formerr'] += 1
            return self._bare(data, D.FORMERR)
        if q.opcode != D.OP_QUERY:
            if q.opcode == D.OP_UPDATE:
                self.stats['refused'] += 1
                return self._bare(data, D.REFUSED, q.raw_question, len(q.question))
            self.stats['notimp'] += 1
            return self._bare(data, D.NOTIMP)
        if len(q.question) != 1:
            self.stats['formerr'] += 1
            return self._bare(data, D.FORMERR)
        qname, qtype, qclass = q.question[0]
        opts = [r for r in q.additional if r.rtype == 41]
        if len(opts) > 1 or (opts and opts[0].name not in ('',)):
            self.stats['formerr'] += 1
            return self._bare(data, D.FORMERR, q.raw_question, 1)
        opt = opts[0] if opts else None
        if opt is not None and (opt.ttl >> 16) & 0xFF != 0:
            # EDNS version other than 0: BADVERS, said in the OPT
            out = self._bare(data, 0, q.raw_question, 1)
            out = out[:10] + struct.pack('>H', 1) + out[12:] + \
                b'\x00' + struct.pack('>HHIH', 41, EDNS_SIZE, (BADVERS_HI << 24), 0)
            self.stats['formerr'] += 1
            return out
        if tcp:
            limit = 65535
        elif opt is not None:
            limit = max(512, min(opt.rclass, EDNS_SIZE))
        else:
            limit = 512

        resp = D.Message(q.id, 0x8000 | (q.flags & 0x0100))
        resp.question = [(qname, qtype, qclass)]
        if opt is not None:
            resp.additional.append(D.RR('', 41, EDNS_SIZE, 0, None, b''))

        def done(rcode, aa):
            resp.flags = 0x8000 | (q.flags & 0x0100) | (0x0400 if aa else 0) | rcode
            return self._finish(resp, data, q, limit, slip)

        if qclass not in (D.CLASS_IN, D.CLASS_ANY):
            self.stats['refused'] += 1
            return done(D.REFUSED, False)
        zones = self.records()
        name = D.norm(qname)
        zone = zones.zone_of(name)
        if zone is None or qtype in (251, 252):         # not ours; no zone transfers
            self.stats['refused'] += 1
            return done(D.REFUSED, False)
        if getattr(zones, 'broken', False) and not (name == zone and qtype in (2, 6)):
            # the records cannot be read: SERVFAIL, so no resolver keeps "not there"
            self.stats['servfail'] += 1
            return done(D.SERVFAIL, False)
        soa = zones.data[zone][6][0]
        owner = qname                                   # 0x20: names as asked
        seen = set()
        for _hop in range(8):
            rrsets = zones.data.get(name, {})
            if qtype == 255:
                got = [(t, v) for t, v in sorted(rrsets.items())]
            else:
                got = [(qtype, rrsets[qtype])] if qtype in rrsets else []
            if got:
                for t, vals in got:
                    for ttl, text in vals:
                        resp.answer.append(D.RR(owner, t, D.CLASS_IN, ttl, text))
                if qtype == 2 or (qtype == 255 and 2 in rrsets):
                    self._glue(zones, rrsets.get(2, []), resp)
                self.stats['answered'] += 1
                return done(D.NOERROR, True)
            if 5 in rrsets and qtype != 5:
                ttl, target = rrsets[5][0]
                resp.answer.append(D.RR(owner, 5, D.CLASS_IN, ttl, target))
                seen.add(name)
                tz = zones.zone_of(target)
                if tz is None or target in seen:
                    self.stats['answered'] += 1
                    return done(D.NOERROR, True)        # the resolver follows it on
                name, owner, zone = target, target, tz
                soa = zones.data[zone][6][0]
                continue
            break
        resp.authority.append(D.RR(zone, 6, D.CLASS_IN, min(soa[0], zones.ttl), soa[1]))
        if name in zones.exists:
            self.stats['nodata'] += 1
            return done(D.NOERROR, True)
        self.stats['nxdomain'] += 1
        return done(D.NXDOMAIN, True)

    @staticmethod
    def _glue(zones, ns_vals, resp):
        for _ttl, ns in ns_vals:
            for t in (1, 28):
                for ttl, a in zones.data.get(D.norm(ns), {}).get(t, []):
                    resp.additional.insert(len(resp.additional) - (1 if resp.opt is not None else 0),
                                           D.RR(ns, t, D.CLASS_IN, ttl, a))

    def _finish(self, resp, data, q, limit, slip):
        """The answer written with the question exactly as it came (0x20); cut
        short (TC) when it does not fit, or when the rate limit lets it slip."""
        wire = self._wire(resp, q)
        if slip or len(wire) > limit:
            if slip:
                self.stats['rate_limited'] += 1
            else:
                self.stats['truncated'] += 1
            # the glue may go; anything more and it is cut short
            extra = [r for r in resp.additional if r.rtype != 41]
            if not slip and extra:
                resp.additional = [r for r in resp.additional if r.rtype == 41]
                wire = self._wire(resp, q)
                if len(wire) <= limit:
                    return wire
            resp.answer, resp.authority = [], []
            resp.additional = [r for r in resp.additional if r.rtype == 41]
            resp.flags |= 0x0200
            wire = self._wire(resp, q)
        return wire

    @staticmethod
    def _wire(resp, q):
        """resp.to_wire, with the question's bytes as they came - and names
        equal to it pointing at them, so their case is the asker's too."""
        comp = {}
        out = bytearray(struct.pack('>HHHHHH', resp.id, resp.flags, 1, len(resp.answer),
                                    len(resp.authority), len(resp.additional)))
        qname = resp.question[0][0]
        # note the question's own name (and its suffixes) where they are
        out += D.name_to_wire(qname, comp, len(out))
        out += struct.pack('>HH', resp.question[0][1], resp.question[0][2])
        raw = q.raw_question
        if raw and len(raw) == len(out) - 12 and raw.lower() == bytes(out[12:]).lower():
            out[12:] = raw                              # the asker's case, byte for byte
        for sec in (resp.answer, resp.authority, resp.additional):
            for r in sec:
                out += D.rr_to_wire(r, comp, len(out))
        return bytes(out)


BADVERS_HI = 1          # BADVERS (16): the upper eight bits of the rcode are 1
