# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- SNMPv3 (1.0.182) ------------------------------------------------------------------------
# Each node answers SNMPv3 itself - an agent of this daemon, in a thread of its
# own, no snmpd: GET, GETNEXT and GETBULK on the system group, the engine's
# own and acme's subtree (ACME-MIB, deploy/ACME-MIB.txt), read only. One user,
# authPriv only (USM, RFC 3414): HMAC-SHA-1/-256/-512 (RFC 7860) and AES-128
# or AES-256 in CFB (RFC 3826; AES-256 with the key extended the way net-snmp
# and Zabbix do it, "Blumenthal"). Its passphrases kept sealed. Each node an
# engine of its own (the engine ID in STATE_DIR, the boots counted there);
# the same user on both. Traps (SNMPv2-Trap, authPriv, this node's engine ID)
# from the node that sends the alerts, when something goes wrong and when it
# is right again. Nothing else waits for any of it.
SNMP_BASE = (1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 7)       # netSnmpPlaypen.acme
SNMP_SYS = (1, 3, 6, 1, 2, 1, 1)
SNMP_ENGINE_OID = (1, 3, 6, 1, 6, 3, 10, 2, 1)
SNMP_USM_STATS = (1, 3, 6, 1, 6, 3, 15, 1, 1)
SNMP_TRAP_OID = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
SNMP_UPTIME_OID = SNMP_SYS + (3, 0)
SNMP_AUTH = {'SHA-1': ('sha1', 12), 'SHA-256': ('sha256', 24), 'SHA-512': ('sha512', 48)}
SNMP_PRIV = {'AES-128': 16, 'AES-256': 32}
SNMP_USER_RE = re.compile(r'^[A-Za-z0-9._-]{1,32}\Z')
SNMP_WINDOW_S = 150
SNMP_CACHE_S = 10.0
SNMP_STATE = {'listening': False, 'port': 0, 'error': '', 'since': 0.0, 'asked': 0,
              'answered': 0, 'last_from': '', 'last_at': 0.0, 'traps': 0, 'trap_error': '',
              'engine': '', 'boots': 0}
# usmStats: 1 unsupportedSecLevels, 2 notInTimeWindows, 3 unknownUserNames,
# 4 unknownEngineIDs, 5 wrongDigests, 6 decryptionErrors
SNMP_USM = collections.Counter()


# -- BER ------------------------------------------------------------------------------------
def ber(tag, body):                         # _ber_len: the directory's (30_ldap)
    return bytes([tag]) + _ber_len(len(body)) + body


def ber_int(v, tag=2):
    v = int(v)
    if v == 0:
        return ber(tag, b'\x00')
    raw = v.to_bytes((v.bit_length() + 8) // 8, 'big', signed=True)
    while len(raw) > 1 and ((raw[0] == 0 and raw[1] < 0x80) or (raw[0] == 0xFF and raw[1] >= 0x80)):
        raw = raw[1:]
    return ber(tag, raw)


def ber_str(v):
    return ber(4, v if isinstance(v, bytes) else str(v).encode('utf-8'))


def ber_oid(oid):
    oid = tuple(int(x) for x in oid)
    out = bytearray([40 * oid[0] + oid[1]])
    for n in oid[2:]:
        part = [n & 0x7F]
        n >>= 7
        while n:
            part.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(part))
    return ber(6, bytes(out))


def ber_read(data, at):
    """(tag, where its value starts, where it ends) - offsets into `data`."""
    if at + 2 > len(data):
        raise ValueError('cut short')
    tag, n = data[at], data[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or at + k > len(data):
            raise ValueError('a length that is not one')
        n = int.from_bytes(data[at:at + k], 'big')
        at += k
    if at + n > len(data):
        raise ValueError('cut short')
    return tag, at, at + n


def ber_items(data, start, end):
    out = []
    at = start
    while at < end:
        tag, s, e = ber_read(data, at)
        out.append((tag, s, e))
        at = e
    return out


def oid_decode(b):
    if not b:
        return ()
    out = [b[0] // 40, b[0] % 40] if b[0] < 80 else [2, b[0] - 80]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            out.append(n)
            n = 0
    return tuple(out)


def snmp_value(kind, v):
    """One value, as its type wants it."""
    if kind == 'int':
        return ber_int(v)
    if kind == 'str':
        return ber_str(v)
    if kind == 'oid':
        return ber_oid(v)
    if kind == 'counter':
        return ber_int(int(v) & 0xFFFFFFFF, 0x41)
    if kind == 'gauge':
        return ber_int(max(0, min(int(v), 0xFFFFFFFF)), 0x42)
    if kind == 'ticks':
        return ber_int(int(v) & 0xFFFFFFFF, 0x43)
    if kind == 'counter64':
        return ber_int(int(v) & 0xFFFFFFFFFFFFFFFF, 0x46)
    return ber(0x05, b'')


# -- USM ------------------------------------------------------------------------------------
def snmp_key(passphrase, engine, hname):
    """RFC 3414 A.2: the passphrase to a key, localized to the engine."""
    pw = str(passphrase).encode('utf-8')
    if not pw:
        raise ValueError('no passphrase')
    h = hashlib.new(hname)
    reps, rest = divmod(1048576, len(pw))
    h.update(pw * reps + pw[:rest])
    ku = h.digest()
    return hashlib.new(hname, ku + engine + ku).digest()


def snmp_priv_key(passphrase, engine, hname, size):
    k = snmp_key(passphrase, engine, hname)
    while len(k) < size:                    # AES-256 with SHA-1: net-snmp's extension
        k += hashlib.new(hname, k).digest()
    return k[:size]


class _AesAny(object):
    """AES-128 or -256, encryption only (CFB needs no more) - where the
    cryptography module is not there."""
    def __init__(self, key):
        sb = _aes_tables()
        nk = len(key) // 4
        rounds = nk + 6
        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        rcon = 1
        for i in range(nk, 4 * (rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = [sb[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _xt(rcon)
            elif nk > 6 and i % nk == 4:
                t = [sb[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        self.rk = [sum(w[r * 4:r * 4 + 4], []) for r in range(rounds + 1)]
        self.rounds = rounds
        self.sb = sb

    def block(self, data):
        sb, rk = self.sb, self.rk
        s = [a ^ b for a, b in zip(data, rk[0])]
        for r in range(1, self.rounds + 1):
            s = [sb[x] for x in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
            if r != self.rounds:
                m = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t = a0 ^ a1 ^ a2 ^ a3
                    m += [a0 ^ t ^ _xt(a0 ^ a1), a1 ^ t ^ _xt(a1 ^ a2),
                          a2 ^ t ^ _xt(a2 ^ a3), a3 ^ t ^ _xt(a3 ^ a0)]
                s = m
            s = [a ^ b for a, b in zip(s, rk[r])]
        return bytes(s)


def snmp_cfb(key, iv, data, decrypt):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:                                # CFB moved there in cryptography 47
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB
        c = Cipher(algorithms.AES(key), CFB(iv))
        x = c.decryptor() if decrypt else c.encryptor()
        return x.update(data) + x.finalize()
    except ImportError:
        pass
    aes, prev, out = _AesAny(key), iv, bytearray()
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        ks = aes.block(prev)
        got = bytes(a ^ b for a, b in zip(chunk, ks))
        out += got
        prev = (chunk if decrypt else got) + ks[len(chunk):]
    return bytes(out)


# -- the engine of this node -----------------------------------------------------------------
def _snmp_meta(store, what):
    try:
        return str(store.get_meta('snmp:%s:%s' % (what, node_name()), '') or '') if store else ''
    except Exception:                                   # noqa: BLE001
        return ''


def _snmp_meta_put(store, what, v):
    try:
        if store is not None:
            store.set_meta('snmp:%s:%s' % (what, node_name()), str(v))
    except Exception:                                   # noqa: BLE001
        pass


def snmp_engine_id(store=None):
    """0x80001F88 (net-snmp's number, RFC 3411's format 5) and 12 bytes of
    this node's own, made once - and kept in the database too (1.0.43): a node made
    again from a backup (or rebuilt into a cluster under its name) keeps the engine
    its managers know, whose ID a trap receiver has to be told."""
    p = STATE_DIR / 'snmp-engine'
    raw = None
    try:
        raw = bytes.fromhex(p.read_text().strip())
        if not 9 <= len(raw) <= 32:
            raw = None
    except (OSError, ValueError):
        raw = None
    if raw is None:
        try:
            kept = bytes.fromhex(_snmp_meta(store, 'engine'))
            raw = kept if 9 <= len(kept) <= 32 else None
        except ValueError:
            raw = None
    if raw is None:
        raw = bytes.fromhex('80001f8805') + secrets.token_bytes(12)
    try:
        if not p.exists():
            p.write_text(raw.hex() + '\n')
    except OSError:
        pass
    if _snmp_meta(store, 'engine') != raw.hex():
        _snmp_meta_put(store, 'engine', raw.hex())
    return raw


def snmp_boots_next(store=None):
    p = STATE_DIR / 'snmp-boots'
    try:
        n = int(p.read_text().strip() or 0)
    except (OSError, ValueError):
        n = 0
    # The count kept in the database too (1.0.43): with the engine back from a backup, its
    # count of starts must not go back either.
    try:
        n = max(n, int(_snmp_meta(store, 'boots') or 0))
    except ValueError:
        pass
    n = n + 1 if n < 2147483646 else 1
    _snmp_meta_put(store, 'boots', n)
    try:
        # Written whole and put in its place (1.0.234): cut short by a crash or a full disk, it
        # read as 0 - the count went back, and answers seen before could be sent again.
        write_replacing(p, '%d\n' % n, 0o600)
    except OSError as e:
        log_sparing('snmp-boots', 'SNMPv3: the count of starts could not be written (%s): %s'
                    % (p, e), 'warn', every=3600)
    return n


def snmp_conf():
    """The user, its protocols and its keys' passphrases - or None while off
    or not set."""
    user = str(CONFIG.get('snmp_user') or '').strip()
    auth = str(CONFIG.get('snmp_auth') or 'SHA-256')
    priv = str(CONFIG.get('snmp_priv') or 'AES-128')
    ap = unseal_secret(CONFIG.get('snmp_auth_pass') or '') or '' if CONFIG.get('snmp_auth_pass') else ''
    pp = unseal_secret(CONFIG.get('snmp_priv_pass') or '') or '' if CONFIG.get('snmp_priv_pass') else ''
    if not (user and ap and pp) or auth not in SNMP_AUTH or priv not in SNMP_PRIV:
        return None
    return {'user': user, 'auth': auth, 'priv': priv, 'ap': ap, 'pp': pp}


def snmp_keys(c, engine):
    hname, _ = SNMP_AUTH[c['auth']]
    return snmp_key(c['ap'], engine, hname), snmp_priv_key(c['pp'], engine, hname,
                                                           SNMP_PRIV[c['priv']])


# -- what is answered ------------------------------------------------------------------------
def _sn_metrics(text):
    """Prometheus' text back into (name, labels, value) - every sample, for
    the table of them."""
    out = []
    for line in text.split('\n'):
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([a-zA-Z_:][\w:]*)(\{.*\})? (\S+)$', line)
        if m:
            out.append((m.group(1), (m.group(2) or '')[1:-1], m.group(3)))
    return out


def snmp_mib(daemon, agent):
    """Every object answered now, sorted: [(oid, kind, value)]."""
    B = SNMP_BASE
    up = int((time.monotonic() - agent.started) * 100)
    rows = [
        (SNMP_SYS + (1, 0), 'str', 'acme %s - certificates kept, renewed and deployed, node %s'
         % (__version__, node_name())),
        (SNMP_SYS + (2, 0), 'oid', B),
        (SNMP_SYS + (3, 0), 'ticks', up),
        (SNMP_SYS + (4, 0), 'str', str(CONFIG.get('snmp_contact') or '')),
        (SNMP_SYS + (5, 0), 'str', short_host()),
        (SNMP_SYS + (6, 0), 'str', str(CONFIG.get('snmp_location') or '')),
        (SNMP_SYS + (7, 0), 'int', 72),
        (SNMP_ENGINE_OID + (1, 0), 'str', agent.engine),
        (SNMP_ENGINE_OID + (2, 0), 'int', agent.boots),
        (SNMP_ENGINE_OID + (3, 0), 'int', int(time.monotonic() - agent.started)),
        (SNMP_ENGINE_OID + (4, 0), 'int', 65507),
    ]
    for i in range(1, 7):
        rows.append((SNMP_USM_STATS + (i, 0), 'counter', SNMP_USM[i]))
    store = daemon.store
    rows += [(B + (1, 1, 0), 'str', __version__), (B + (1, 2, 0), 'str', node_name()),
             (B + (1, 3, 0), 'str', str(CONFIG.get('site_name') or short_host())),
             (B + (1, 4, 0), 'str', store.db.engine),
             (B + (1, 5, 0), 'int', 1 if CONFIG.get('high_security') else 0),
             (B + (1, 6, 0), 'int', 1 if CONFIG.get('ha_mode') else 0),
             (B + (1, 7, 0), 'ticks', up)]
    t0 = time.time()
    try:
        store.db.value('SELECT 1')
        db_ok = 1
    except Exception:                                   # noqa: BLE001
        db_ok = 0
    rows += [(B + (3, 1, 0), 'int', db_ok), (B + (3, 2, 0), 'gauge', int((time.time() - t0) * 1e6))]
    try:
        probs = alert_problems(store, 'en') if db_ok else {}
    except Exception:                                   # noqa: BLE001
        probs = {}
    rows += [(B + (5, 1, 0), 'gauge', sum(1 for p in probs.values() if p.get('level') == 'bad')),
             (B + (5, 2, 0), 'gauge', sum(1 for p in probs.values() if p.get('level') == 'warn'))]
    for i, (k, p) in enumerate(sorted(probs.items()), 1):
        rows += [(B + (5, 3, 1, 1, i), 'int', i), (B + (5, 3, 1, 2, i), 'str', k),
                 (B + (5, 3, 1, 3, i), 'str', p.get('level') or ''),
                 (B + (5, 3, 1, 4, i), 'str', str(p.get('title') or '')[:255]),
                 (B + (5, 3, 1, 5, i), 'str', str(p.get('said') or '')[:255])]
    try:
        i = 0
        for t in tls_targets(store) if db_ok else []:
            info = (tls_profile(store, t) or {}).get('info') or {}
            if info.get('not_after'):
                i += 1
                end = int(float(info['not_after']))
                rows += [(B + (6, 1, 1, 1, i), 'int', i), (B + (6, 1, 1, 2, i), 'str', t),
                         (B + (6, 1, 1, 3, i), 'str', info.get('cn') or ''),
                         (B + (6, 1, 1, 4, i), 'int', int((end - time.time()) // 86400)),
                         (B + (6, 1, 1, 5, i), 'int', end)]
    except Exception:                                   # noqa: BLE001
        pass
    # What a module answers under acme's subtree (HOOKS['snmp']: fn(store) ->
    # [(oid under acme, kind, value)]) - the certificate manager's table of the
    # certificates it keeps (acmeManagedCertTable, ACME-MIB).
    for fn in HOOKS.get('snmp') or () if db_ok else ():
        try:
            for sub, kind, value in list(fn(store) or []):
                sub = tuple(int(x) for x in sub)
                if sub and sub[0] not in (1, 3, 5, 7, 9) and kind in (
                        'int', 'str', 'oid', 'counter', 'gauge', 'ticks', 'counter64'):
                    rows.append((B + sub, kind, value))
        except Exception as e:                          # noqa: BLE001
            log_sparing('snmp-hook', 'SNMP, a module: %s: %s' % (
                getattr(fn, '__qualname__', fn), e), 'warn', every=600)
    if CONFIG.get('ha_mode') and db_ok:
        try:
            for i, n in enumerate(ha_nodes(store), 1):
                rows += [(B + (7, 1, 1, 1, i), 'int', i), (B + (7, 1, 1, 2, i), 'str', n['name']),
                         (B + (7, 1, 1, 3, i), 'int', 1 if n.get('alive') else 0),
                         (B + (7, 1, 1, 4, i), 'gauge', int(float(n.get('age') or 0)))]
        except Exception:                               # noqa: BLE001
            pass
    # Every sample Prometheus gets, as a table (name, labels, value) - nothing
    # it has is missing here.
    try:
        for i, (name, labels, value) in enumerate(_sn_metrics(metrics_text(daemon)), 1):
            rows += [(B + (9, 1, 1, 1, i), 'int', i), (B + (9, 1, 1, 2, i), 'str', name),
                     (B + (9, 1, 1, 3, i), 'str', labels[:255]),
                     (B + (9, 1, 1, 4, i), 'str', value)]
    except Exception as e:                              # noqa: BLE001
        log_sparing('snmp-metrics', 'SNMP, the table of metrics: %s' % e, 'warn', every=600)
    rows.sort(key=lambda x: x[0])
    return rows


# -- the agent -------------------------------------------------------------------------------
class SnmpAgent(object):
    def __init__(self, daemon):
        self.d = daemon
        self.sock = None
        self.bound = None
        store = getattr(daemon, 'store', None)
        self.engine = snmp_engine_id(store)
        self.boots = snmp_boots_next(store)
        # Monotonic (1.0.206): RFC 3414's engine time never goes back - an NTP
        # step back put it below zero, and the agent answered nothing.
        self.started = time.monotonic()
        self.keys = None
        self.keyed = None
        self.mib = []
        self.mib_at = 0.0
        self.lock = threading.Lock()
        self.looked = 0.0
        self.salt = int.from_bytes(secrets.token_bytes(8), 'big')
        SNMP_STATE.update(engine=self.engine.hex(), boots=self.boots)
        self.thread = threading.Thread(target=self.run, name='acme-snmp', daemon=True)
        self.thread.start()

    def configure(self):
        want = bool(CONFIG.get('snmp'))
        try:
            port = int(CONFIG.get('snmp_port') or 161)
        except (TypeError, ValueError):
            port = 161
        bind = str(CONFIG.get('snmp_bind') or '').strip() or '::'
        key = (bind, port) if want else None
        if key != self.bound and self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock, self.bound = None, None
            SNMP_STATE.update(listening=False)
        if want and not self.sock:
            try:
                try:
                    fam = socket.AF_INET6 if ':' in bind else socket.AF_INET
                    s = socket.socket(fam, socket.SOCK_DGRAM)
                    try:
                        if fam == socket.AF_INET6:
                            try:
                                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                            except OSError:
                                pass
                        s.bind((bind, port))
                    except OSError:
                        s.close()
                        raise
                except OSError as e6:
                    # Every address, and no IPv6 on this machine (ipv6.disable=1):
                    # IPv4's every address instead. A port taken is said as it is.
                    if bind != '::' or getattr(e6, 'errno', 0) in (errno.EADDRINUSE, errno.EACCES,
                                                                    errno.EPERM):
                        raise
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        s.bind(('0.0.0.0', port))
                    except OSError:
                        s.close()
                        raise
                s.settimeout(1.0)
                self.sock, self.bound = s, key
                SNMP_STATE.update(listening=True, port=port, error='', since=time.time())
                where = s.getsockname()[0]
                log('SNMPv3 listening on %s:%d/udp' % ('[%s]' % where if ':' in where else where,
                                                       port))
            except OSError as e:
                why = str(e)
                if port < 1024 and getattr(e, 'errno', 0) in (errno.EACCES, errno.EPERM):
                    why = ('port %d needs CAP_NET_BIND_SERVICE in acme.service - install.sh '
                           '--upgrade puts it in; or a port above 1024' % port)
                SNMP_STATE.update(listening=False, port=port, error=why)
                log_sparing('snmp-bind', 'SNMPv3 cannot listen on %s:%d: %s' % (bind, port, why),
                            'warn', every=600)
        c = snmp_conf()
        sig = json.dumps(c, sort_keys=True) if c else None
        if sig != self.keyed:
            self.keys = snmp_keys(c, self.engine) if c else None
            self.keyed = sig

    def run(self):
        while True:
            if time.time() - self.looked > 5:
                self.looked = time.time()
                try:
                    self.configure()
                except Exception as e:                  # noqa: BLE001
                    log_sparing('snmp-conf', 'SNMPv3: %s' % e, 'warn', every=600)
            s = self.sock
            if not s:
                time.sleep(1.0)
                continue
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.5)
                continue
            SNMP_STATE['asked'] += 1
            try:
                out = self.answer(data, addr)
                if out:
                    s.sendto(out, addr)
                    SNMP_STATE['answered'] += 1
            except Exception as e:                      # noqa: BLE001
                log_sparing('snmp-req', 'SNMPv3: a request from %s: %s' % (addr[0], e), 'warn',
                            every=300)

    def now_time(self):
        return int(time.monotonic() - self.started)

    # -- one message ------------------------------------------------------------------------
    def answer(self, data, addr):
        client = str(addr[0])
        if client.startswith('::ffff:'):
            client = client[7:]
        if not snmp_allowed(client):
            return None
        tag, s, e = ber_read(data, 0)
        if tag != 0x30:
            return None
        items = ber_items(data, s, e)
        if len(items) != 4 or items[0][0] != 2:
            return None
        if int.from_bytes(data[items[0][1]:items[0][2]], 'big', signed=True) != 3:
            return None                             # v1 and v2c: not answered at all
        g = ber_items(data, items[1][1], items[1][2])
        if len(g) != 4:
            return None
        msg_id = int.from_bytes(data[g[0][1]:g[0][2]], 'big', signed=True)
        their_max = int.from_bytes(data[g[1][1]:g[1][2]], 'big', signed=True)
        flags = data[g[2][1]] if g[2][2] > g[2][1] else 0
        if int.from_bytes(data[g[3][1]:g[3][2]], 'big', signed=True) != 3:
            return None
        if items[2][0] != 4:
            return None
        sp = ber_read(data, items[2][1])
        sec = ber_items(data, sp[1], sp[2])
        if len(sec) != 6:
            return None
        engine = data[sec[0][1]:sec[0][2]]
        boots = int.from_bytes(data[sec[1][1]:sec[1][2]], 'big', signed=True)
        etime = int.from_bytes(data[sec[2][1]:sec[2][2]], 'big', signed=True)
        user = data[sec[3][1]:sec[3][2]].decode('utf-8', 'replace')
        auth_at, auth_end = sec[4][1], sec[4][2]
        salt = data[sec[5][1]:sec[5][2]]
        reportable = bool(flags & 4)
        # A plain scoped PDU's request-id, for reports to a discovery.
        rid = 0
        if items[3][0] == 0x30:
            try:
                sc = ber_items(data, items[3][1], items[3][2])
                pdu = ber_items(data, sc[2][1], sc[2][2])
                rid = int.from_bytes(data[pdu[0][1]:pdu[0][2]], 'big', signed=True)
            except (ValueError, IndexError):
                rid = 0
        c = snmp_conf()
        if engine != self.engine:
            SNMP_USM[4] += 1
            return self.report(msg_id, rid, 4, user, None, reportable)
        if not c or user != c['user']:
            SNMP_USM[3] += 1
            return self.report(msg_id, rid, 3, user, None, reportable)
        if flags & 3 != 3:
            SNMP_USM[1] += 1
            return self.report(msg_id, rid, 1, user, None, reportable)
        hname, alen = SNMP_AUTH[c['auth']]
        akey, pkey = self.keys or snmp_keys(c, self.engine)
        if auth_end - auth_at != alen:
            SNMP_USM[5] += 1
            return self.report(msg_id, rid, 5, user, None, reportable)
        zeroed = data[:auth_at] + b'\x00' * alen + data[auth_end:]
        want = hmac.new(akey, zeroed, hname).digest()[:alen]
        if not hmac.compare_digest(want, data[auth_at:auth_end]):
            SNMP_USM[5] += 1
            return self.report(msg_id, rid, 5, user, None, reportable)
        if boots != self.boots or abs(etime - self.now_time()) > SNMP_WINDOW_S:
            SNMP_USM[2] += 1
            return self.report(msg_id, rid, 2, user, c, reportable)
        if items[3][0] != 4 or len(salt) != 8:
            SNMP_USM[6] += 1
            return self.report(msg_id, rid, 6, user, c, reportable)
        iv = boots.to_bytes(4, 'big') + etime.to_bytes(4, 'big') + salt
        plain = snmp_cfb(pkey, iv, data[items[3][1]:items[3][2]], True)
        try:
            tag, s2, e2 = ber_read(plain, 0)
            sc = ber_items(plain, s2, e2)
            if tag != 0x30 or len(sc) != 3:
                raise ValueError('not a scoped PDU')
        except ValueError:
            SNMP_USM[6] += 1
            return self.report(msg_id, rid, 6, user, c, reportable)
        ctx_engine = plain[sc[0][1]:sc[0][2]]
        ctx_name = plain[sc[1][1]:sc[1][2]]
        pdu_tag = sc[2][0]
        pdu = ber_items(plain, sc[2][1], sc[2][2])
        rid = int.from_bytes(plain[pdu[0][1]:pdu[0][2]], 'big', signed=True)
        a = int.from_bytes(plain[pdu[1][1]:pdu[1][2]], 'big', signed=True)
        b = int.from_bytes(plain[pdu[2][1]:pdu[2][2]], 'big', signed=True)
        oids = []
        for vb in ber_items(plain, pdu[3][1], pdu[3][2]):
            parts = ber_items(plain, vb[1], vb[2])
            oids.append(oid_decode(plain[parts[0][1]:parts[0][2]]))
        SNMP_STATE.update(last_from=client, last_at=time.time())
        most = max(484, min(their_max, 65507)) - 200
        if ctx_engine not in (self.engine, b'') or ctx_name:
            # One context only, the default one ('').
            vbs, err, idx = [(o, ber(0x80, b'')) for o in oids], 0, 0
        else:
            vbs, err, idx = self.vars(pdu_tag, oids, a, b, most)
        body = ber_int(rid) + ber_int(err) + ber_int(idx) + \
            ber(0x30, b''.join(ber(0x30, ber_oid(o) + v) for o, v in vbs))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(ctx_name) + ber(0xA2, body))
        if len(scoped) > most and pdu_tag != 0xA5:
            body = ber_int(rid) + ber_int(1) + ber_int(0) + ber(0x30, b'')      # tooBig
            scoped = ber(0x30, ber_str(self.engine) + ber_str(ctx_name) + ber(0xA2, body))
        return self.wrap(msg_id, scoped, c, 3)

    def vars(self, pdu_tag, oids, a, b, most):
        with self.lock:
            if time.time() - self.mib_at > SNMP_CACHE_S or not self.mib:
                self.mib = snmp_mib(self.d, self)
                self.mib_at = time.time()
                self.mib_oids = [x[0] for x in self.mib]
            mib, keys = self.mib, self.mib_oids
        exact = {x[0]: x for x in mib}

        def nxt(o):
            i = bisect.bisect_right(keys, tuple(o))
            return mib[i] if i < len(mib) else None
        out = []
        if pdu_tag == 0xA0:                         # GET
            for o in oids:
                x = exact.get(tuple(o))
                if x:
                    out.append((o, snmp_value(x[1], x[2])))
                else:
                    out.append((o, ber(0x80, b'')))         # noSuchObject
            return out, 0, 0
        if pdu_tag == 0xA1:                         # GETNEXT
            for o in oids:
                x = nxt(o)
                out.append((x[0], snmp_value(x[1], x[2])) if x else (o, ber(0x82, b'')))
            return out, 0, 0
        if pdu_tag == 0xA5:                         # GETBULK: a non-repeaters, b repetitions
            n = max(0, min(a, len(oids)))
            reps = max(0, min(b, 200))
            size = 0
            for o in oids[:n]:
                x = nxt(o)
                out.append((x[0], snmp_value(x[1], x[2])) if x else (o, ber(0x82, b'')))
            cur = list(oids[n:])
            for _ in range(reps):
                if not cur:
                    break
                row, ended = [], True
                for j, o in enumerate(cur):
                    x = nxt(o)
                    if x:
                        row.append((x[0], snmp_value(x[1], x[2])))
                        cur[j] = x[0]
                        ended = False
                    else:
                        row.append((o, ber(0x82, b'')))
                size += sum(len(ber_oid(o)) + len(v) + 4 for o, v in row)
                if size > most and out:
                    break
                out += row
                if ended:
                    break
            return out, 0, 0
        if pdu_tag == 0xA3:                         # SET: nothing here is written
            return [(o, ber(0x05, b'')) for o in oids], 17, 1
        return [(o, ber(0x05, b'')) for o in oids], 5, 1       # genErr

    def report(self, msg_id, rid, which, user, c, reportable):
        """A Report of usmStats.<which> - authenticated (authNoPriv) when the
        time window was the trouble and the user is known."""
        if not reportable:
            return None
        body = ber_int(rid) + ber_int(0) + ber_int(0) + ber(0x30, ber(0x30, ber_oid(
            SNMP_USM_STATS + (which, 0)) + snmp_value('counter', SNMP_USM[which])))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(b'') + ber(0xA8, body))
        return self.wrap(msg_id, scoped, c if which == 2 else None, 1 if which == 2 else 0,
                         user=user)

    def wrap(self, msg_id, scoped, c, level, user=None, boots=None, etime=None):
        """The whole message around a scoped PDU: level 0 noAuthNoPriv, 1
        authNoPriv, 3 authPriv."""
        boots = self.boots if boots is None else boots
        etime = self.now_time() if etime is None else etime
        alen = SNMP_AUTH[c['auth']][1] if c and level & 1 else 0
        priv = b''
        data = scoped
        if c and level & 2:
            self.salt = (self.salt + 1) & 0xFFFFFFFFFFFFFFFF
            priv = self.salt.to_bytes(8, 'big')
            iv = boots.to_bytes(4, 'big') + etime.to_bytes(4, 'big') + priv
            data = ber_str(snmp_cfb((self.keys or snmp_keys(c, self.engine))[1], iv, scoped, False))
        name = (c['user'] if c else (user or '')).encode('utf-8')
        front = ber_str(self.engine) + ber_int(boots) + ber_int(etime) + ber_str(name)
        inner = ber(0x30, front + ber_str(b'\x00' * alen) + ber_str(priv))
        sec = ber_str(inner)
        glob = ber(0x30, ber_int(msg_id) + ber_int(65507) + ber_str(bytes([level])) + ber_int(3))
        body = ber_int(3) + glob + sec + data
        msg = ber(0x30, body)
        if alen:
            at = (len(msg) - len(body)) + len(ber_int(3)) + len(glob) + (len(sec) - len(inner)) + \
                (len(inner) - len(front) - len(ber_str(b'\x00' * alen)) - len(ber_str(priv))) + \
                len(front) + 2
            hname = SNMP_AUTH[c['auth']][0]
            mac = hmac.new((self.keys or snmp_keys(c, self.engine))[0], msg, hname).digest()[:alen]
            msg = msg[:at] + mac + msg[at + alen:]
        return msg

    # -- traps ------------------------------------------------------------------------------
    def trap(self, what, binds):
        """An SNMPv2-Trap, authPriv, to every receiver set: what is 1 raised, 2
        cleared, 3 a test. {target: 'sent' | why not}."""
        c = snmp_conf()
        if not c:
            raise ValueError('the SNMPv3 user and its two passphrases are not set')
        if not self.keys:
            self.keys = snmp_keys(c, self.engine)
        vbs = [(SNMP_UPTIME_OID, snmp_value('ticks', int((time.monotonic() - self.started) * 100))),
               (SNMP_TRAP_OID, ber_oid(SNMP_BASE + (0, what)))]
        for i, (kind, v) in enumerate(binds, 1):
            vbs.append((SNMP_BASE + (8, i, 0), snmp_value(kind, v)))
        rid = secrets.randbelow(2 ** 31)
        body = ber_int(rid) + ber_int(0) + ber_int(0) + \
            ber(0x30, b''.join(ber(0x30, ber_oid(o) + v) for o, v in vbs))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(b'') + ber(0xA7, body))
        msg = self.wrap(secrets.randbelow(2 ** 31), scoped, c, 3)
        out = {}
        for t in snmp_trap_targets(CONFIG.get('snmp_trap_to')):
            host, port = t
            key = '%s:%d' % (host if ':' not in host else '[%s]' % host, port)
            try:
                for fam, _, _, _, sa in socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[:1]:
                    s = socket.socket(fam, socket.SOCK_DGRAM)
                    try:
                        s.sendto(msg, sa)
                    finally:
                        s.close()
                out[key] = 'sent'
                SNMP_STATE['traps'] += 1
            except OSError as e:
                out[key] = str(e)
                SNMP_STATE['trap_error'] = '%s: %s' % (key, e)
        return out


def snmp_trap_targets(text, strict=False):
    out = []
    for w in [x for x in re.split(r'[\s,;]+', str(text or '')) if x]:
        m = re.match(r'^\[([0-9A-Fa-f:.]+)\](?::(\d+))?\Z', w) or \
            re.match(r'^([A-Za-z0-9.-]+)(?::(\d+))?\Z', w) or \
            re.match(r'^([0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)\Z', w)
        if not m:
            if strict:
                raise BadSetting('snmp_trap_to: %r is not host or host:port' % w)
            continue
        port = int(m.group(2)) if m.lastindex and m.lastindex >= 2 and m.group(2) else 162
        if not 0 < port < 65536:
            if strict:
                raise BadSetting('snmp_trap_to: %r - the port is 1 to 65535' % w)
            continue
        out.append((m.group(1), port))
    return out


SNMP_SELF = {'until': 0.0}        # the page's own test under way (1.0.206)


def snmp_allowed(client):
    nets = [w for w in re.split(r'[\s,;]+', str(CONFIG.get('snmp_from') or '')) if w]
    if not nets:
        return True
    try:
        a = ipaddress.ip_address(str(client or '').strip('[]'))
    except ValueError:
        return False
    if time.time() < SNMP_SELF['until'] and (
            a.is_loopback or str(a) == str(CONFIG.get('snmp_bind') or '').strip().strip('[]')):
        # This machine itself, while the page's own test asks (1.0.206): it timed
        # out wherever the managers' network was set - as advised.
        return True
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def snmp_traps_tick(daemon, cur):
    """On the node that sends the alerts: a trap for each thing that went
    wrong, and for each that is right again - its own state, apart from the
    mails'."""
    ag = getattr(daemon, 'snmp', None)
    if not ag or not CONFIG.get('snmp') or not CONFIG.get('snmp_traps') or \
            not snmp_trap_targets(CONFIG.get('snmp_trap_to')):
        return
    store = daemon.store
    try:
        known = json.loads(store.get_meta('snmp:trapped') or '{}')
    except ValueError:
        known = {}
    delay = 60 * int(CONFIG.get('alerts_delay_min') or 0)
    now = time.time()
    changed = False
    for k, p in cur.items():
        was = known.get(k)
        since = float((was or {}).get('since') or now)
        if not was:
            known[k] = {'since': now, 'sent': False, 'level': p.get('level')}
            changed = True
            was = known[k]
        if (not was.get('sent') and now - since >= delay) or \
                (was.get('sent') and was.get('level') == 'warn' and p.get('level') == 'bad'):
            got = ag.trap(1, [('str', k), ('str', p.get('level') or ''),
                              ('str', str(p.get('title') or '')[:255]),
                              ('str', str(p.get('said') or '')[:255]), ('str', node_name())])
            was.update(sent=any(v == 'sent' for v in got.values()), level=p.get('level'))
            changed = True
    for k in [k for k in known if k not in cur]:
        p = known.pop(k)
        changed = True
        if p.get('sent'):
            ag.trap(2, [('str', k), ('str', 'ok'), ('str', 'right again'), ('str', ''),
                        ('str', node_name())])
    if changed:
        store.set_meta('snmp:trapped', json.dumps(known))


def snmp_view(store):
    """Each node's agent, as its health row says, and the settings' state."""
    nodes = []
    for n in host_nodes(store):
        row = _meta_json(store, 'host:health:' + n) or {}
        nodes.append({'node': n, 'me': n == node_name(), 'at': row.get('at'),
                      'snmp': row.get('snmp') or {}})
    c = snmp_conf()
    return {'on': bool(CONFIG.get('snmp')), 'ready': bool(c), 'nodes': nodes,
            'user': c['user'] if c else str(CONFIG.get('snmp_user') or ''),
            'auth': str(CONFIG.get('snmp_auth') or 'SHA-256'),
            'priv': str(CONFIG.get('snmp_priv') or 'AES-128'),
            'port': int(CONFIG.get('snmp_port') or 161),
            'base': '.'.join(str(x) for x in SNMP_BASE),
            'traps': bool(CONFIG.get('snmp_traps')),
            'trap_to': ['%s:%d' % t for t in snmp_trap_targets(CONFIG.get('snmp_trap_to'))]}


@route('GET', '/api/snmp')
def _snmp(h):
    h.me()
    return snmp_view(h.store)


@route('POST', '/api/snmp')
def _snmp_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'result':
        return {'nodes': node_ask_results(h.store, 'snmp', str(b.get('id') or ''))}
    if act in ('test', 'trap'):
        if not CONFIG.get('snmp'):
            raise ApiError(400, 'SNMPv3 is off')
        return node_ask(h.d, 'snmp', {'by': s['name'], 'what': act,
                                      'only': str(b.get('node') or '')}, s['name'])
    raise ApiError(400, 'no such thing to do')


@node_ask_kind('snmp')
def _ask_snmp(daemon, args):
    """From the node itself: its own agent asked as a manager would ask it
    (on 127.0.0.1, discovery, authPriv), or a test trap to every receiver."""
    ag = getattr(daemon, 'snmp', None)
    if not ag:
        raise ValueError('no SNMP agent in this process')
    if args.get('what') == 'trap':
        got = ag.trap(3, [('str', 'test'), ('str', 'info'),
                          ('str', 'a test trap from acme, sent by %s' % (args.get('by') or '?')),
                          ('str', ''), ('str', node_name())])
        if not got:
            raise ValueError('no receiver of traps is set')
        return {'ok': all(v == 'sent' for v in got.values()), 'sent': got,
                'engine': ag.engine.hex()}
    c = snmp_conf()
    if not c:
        raise ValueError('the SNMPv3 user and its two passphrases are not set')
    if not SNMP_STATE.get('listening'):
        raise ValueError(SNMP_STATE.get('error') or 'not listening')
    t0 = time.time()
    bound = str(CONFIG.get('snmp_bind') or '').strip()
    at = bound if bound and bound not in ('0.0.0.0', '::') else '127.0.0.1'
    SNMP_SELF['until'] = time.time() + 5
    got = snmp_get(at, int(SNMP_STATE.get('port') or 161), c,
                   [SNMP_SYS + (1, 0), SNMP_SYS + (3, 0), SNMP_BASE + (1, 1, 0)])
    return {'ok': True, 'said': got, 'ms': int((time.time() - t0) * 1000),
            'engine': ag.engine.hex()}


def snmp_get(host, port, c, oids, timeout=3.0):
    """A small SNMPv3 manager: discovery, then one authPriv GET - for the
    node's own test. {oid: value as text}."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        def ask(msg):
            s.sendto(msg, (host, port))
            return s.recv(65535)

        def pdu(rid):
            return ber(0xA0, ber_int(rid) + ber_int(0) + ber_int(0) + ber(0x30, b''.join(
                ber(0x30, ber_oid(o) + ber(0x05, b'')) for o in oids)))
        rid = secrets.randbelow(2 ** 31)
        disc = ber(0x30, ber_int(3) + ber(0x30, ber_int(rid) + ber_int(65507) + ber_str(b'\x04') +
                                          ber_int(3)) +
                   ber_str(ber(0x30, ber_str(b'') + ber_int(0) + ber_int(0) + ber_str(b'') +
                               ber_str(b'') + ber_str(b''))) +
                   ber(0x30, ber_str(b'') + ber_str(b'') + pdu(rid)))
        raw = ask(disc)
        _, s0, e0 = ber_read(raw, 0)
        it = ber_items(raw, s0, e0)
        sp = ber_read(raw, it[2][1])
        sec = ber_items(raw, sp[1], sp[2])
        engine = raw[sec[0][1]:sec[0][2]]
        boots = int.from_bytes(raw[sec[1][1]:sec[1][2]], 'big')
        etime = int.from_bytes(raw[sec[2][1]:sec[2][2]], 'big')
        fake = SnmpAgent.__new__(SnmpAgent)
        fake.engine, fake.boots, fake.started = engine, boots, time.monotonic() - etime
        fake.keys = snmp_keys(c, engine)
        fake.salt = int.from_bytes(secrets.token_bytes(8), 'big')
        rid += 1
        scoped = ber(0x30, ber_str(engine) + ber_str(b'') + pdu(rid))
        msg = fake.wrap(rid, scoped, c, 7)
        raw = ask(msg)
        _, s0, e0 = ber_read(raw, 0)
        it = ber_items(raw, s0, e0)
        sp = ber_read(raw, it[2][1])
        sec = ber_items(raw, sp[1], sp[2])
        if it[3][0] != 4:
            raise ValueError('the answer is not encrypted - a report?')
        iv = int.from_bytes(raw[sec[1][1]:sec[1][2]], 'big').to_bytes(4, 'big') + \
            int.from_bytes(raw[sec[2][1]:sec[2][2]], 'big').to_bytes(4, 'big') + \
            raw[sec[5][1]:sec[5][2]]
        plain = snmp_cfb(fake.keys[1], iv, raw[it[3][1]:it[3][2]], True)
        _, s2, e2 = ber_read(plain, 0)
        sc = ber_items(plain, s2, e2)
        p = ber_items(plain, sc[2][1], sc[2][2])
        out = {}
        for vb in ber_items(plain, p[3][1], p[3][2]):
            parts = ber_items(plain, vb[1], vb[2])
            o = '.'.join(str(x) for x in oid_decode(plain[parts[0][1]:parts[0][2]]))
            tag = parts[1][0]
            v = plain[parts[1][1]:parts[1][2]]
            out[o] = v.decode('utf-8', 'replace') if tag == 4 else \
                str(int.from_bytes(v, 'big')) if tag in (2, 0x41, 0x42, 0x43, 0x46) else v.hex()
        return out
    finally:
        s.close()
