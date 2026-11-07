# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the clocks and the health of the nodes: gray failures (1.0.21) ----------------------
# A node that is up, answers at once and answers wrongly. Its clock off: the codes of the
# second step (the app's, admin_2fa - the administration and the portal) are refused though
# they are right, its heartbeat and its lease look dead or alive for ever on the other node,
# the pauses after wrong passwords are off with it - and the node goes on holding the VIP
# address, so nobody is sent to the other one. A node that cannot reach the directory its
# administrators (or the portal's people) sign in against refuses every password the same
# way. Chosen on Settings -> Time -> The clocks of the nodes (docs/clock-guard.md - as otp
# 1.0.222-1.0.227 does it, in acme's terms):
#
#   clock_mode     off    as until now: nothing of this runs
#                  watch  each node measures its clock against a reference (SNTP to the time
#                         servers of Settings -> Time, or its own) and against the other node
#                         (its database server's clock), says it on the card, warns
#                  guard  and a node whose clock is off (or that cannot reach the directory,
#                         with health_dir) steps aside - only while the other node is well
#   clock_warn_s   off by more than this: a warning (and the correction applies)
#   clock_aside_s  off by more than this: guard steps the node aside
#   clock_ref      each node's own reference servers (empty: the time servers of Settings -> Time)
#   clock_codes    the second step's codes worked out from the corrected time
#   clock_beat     the other node's heartbeat and its lead's lease judged with the measured
#                  difference of the clocks
#   clock_locks    the pauses after wrong passwords and codes on the corrected time
#   health_dir     guard: step aside when this node cannot reach the directory and the other can
#
# Stepping aside is the split's own way (197): maintenance nobody asked for, ended by itself -
# no lead (renewals, deployments, CRLs, signing), acme's DNS server silent, the VIP address and
# the load balancer's /healthz go to the other node; the pages stay.
CLOCK_MODES = ('off', 'watch', 'guard')
CLOCK_LOCK = threading.Lock()
CLOCK = {'thread': None, 'ref': None, 'ref_src': '', 'ref_err': '', 'ref_at': 0.0, 'refs': [],
         'ref_mono': 0.0, 'ref_wall': 0.0,
         'skew': None, 'skew_err': '', 'skew_at': 0.0, 'skew_of': '', 'dir_ok': None,
         'dir_at': 0.0, 'dirs': [], 'role': 'serve', 'why': '', 'written': 0.0}
CLOCK_STEP_S = 5.0
CLOCK_REF_EVERY_S = 30.0
CLOCK_DIR_EVERY_S = 15.0
CLOCK_FRESH_S = 120.0
CLOCK_DB_SERVER = 'the database server'
CLOCK_KEYS = ('clock_mode', 'clock_warn_s', 'clock_aside_s', 'clock_codes', 'clock_beat',
              'clock_locks', 'health_dir')


def clock_mode():
    m = str(CONFIG.get('clock_mode') or 'off')
    return m if m in CLOCK_MODES else 'off'


def clock_engaged():
    """Anything of it at all. "As until now" (off) runs nothing: exactly as before 1.0.21."""
    return clock_mode() != 'off'


# ---- the reference: SNTP (RFC 4330), one question each -----------------------------------------
NTP_EPOCH = 2208988800                                  # 1900-01-01 to 1970-01-01, in seconds


def sntp_offset(server, timeout=1.5):
    """(offset, delay) of one server: offset > 0 when this machine's clock is behind it.
    RFC 4330: a client packet (LI 0, VN 4, mode 3) with our transmit time, echoed back as the
    originate time - an answer to another question (or an old one) is not taken; a server
    of stratum 0 (kiss of death, unsynchronised) is not believed. Raises OSError / ValueError."""
    got = split_targets_parse(server)
    if len(got) != 1:
        raise ValueError('one server: a name or address, name:port')
    host, port = got[0][0], got[0][1] or 123
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
    fam, addr = infos[0][0], infos[0][4]
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        pkt = bytearray(48)
        pkt[0] = 0x23                                   # LI 0, version 4, mode 3 (client)
        t0 = time.time()
        sec = int(t0) + NTP_EPOCH
        frac = int((t0 - int(t0)) * (1 << 32))
        pkt[40:48] = struct.pack('!II', sec & 0xffffffff, frac)
        s.sendto(bytes(pkt), addr)
        end = time.monotonic() + timeout
        while True:
            s.settimeout(max(0.05, end - time.monotonic()))
            data, _a = s.recvfrom(512)
            t3 = time.time()
            if len(data) >= 48 and data[24:32] == bytes(pkt[40:48]):
                break
            if time.monotonic() > end:
                raise socket.timeout('no answer of its own')
        mode, stratum = data[0] & 7, data[1]
        if mode not in (4, 5) or stratum == 0 or stratum > 15:
            raise ValueError('the server is not synchronised itself (stratum %d)' % stratum)

        def ts(off):
            a, b = struct.unpack('!II', data[off:off + 8])
            return a - NTP_EPOCH + b / float(1 << 32)
        t1, t2 = ts(32), ts(40)
        return ((t1 - t0) + (t2 - t3)) / 2.0, (t3 - t0) - (t2 - t1)
    finally:
        s.close()


def clock_common_servers(store):
    """The time servers of Settings -> Time (the whole cluster's)."""
    try:
        return [str(x.get('host') if isinstance(x, dict) else x) for x in
                (ntp_conf(store).get('servers') or []) if x]
    except Exception:                                   # noqa: BLE001
        return []


def clock_ref_servers(value=None, store=None):
    """This node's reference servers: its own (clock_ref), else the time servers of
    Settings -> Time."""
    given = CONFIG.get('clock_ref') if value is None else value
    out = [w for w in re.split(r'[\s,;]+', str(given or '').strip()) if w]
    if not out and store is not None:
        out = clock_common_servers(store)
    return [x for x in out if x][:5]


def clock_ref_check(servers):
    """[(server, offset or None, words)], and the median offset of those that answered (or
    None) - one server gone wild does not move it."""
    got = []
    for srv in servers:
        try:
            try:
                off, delay = sntp_offset(srv)
            except socket.timeout:
                off, delay = sntp_offset(srv)           # one packet lost: asked again
            got.append((srv, off, 'delay %.0f ms' % (delay * 1000)))
        except (OSError, ValueError, struct.error, UnicodeError) as e:
            got.append((srv, None, str(e)[:160] or 'no answer'))
    offs = sorted(o for _s, o, _w in got if o is not None)
    if not offs:
        return got, None
    mid = len(offs) // 2
    return got, (offs[mid] if len(offs) % 2 else (offs[mid - 1] + offs[mid]) / 2.0)


# ---- the other node: its database server's clock ---------------------------------------------
def clock_peer_skew(store):
    """(name, skew) - the other side's clock minus this one's, from its database server: the
    other node's own PostgreSQL in a replicated pair (on that machine, so its clock), the shared
    database server otherwise ('the database server'). (None, None) when there is no other side
    to ask. Asked in a thread of its own, 3.5 s at most. Raises RuntimeError."""
    if CONFIG.get('ha_mode') == 'replicated' and CONFIG.get('ha_peer'):
        conf = ha_peer_conf(timeout=2)
        # the one alive first (1.0.52): a row of a node gone, sorted first, was taken for the peer
        others = sorted((n for n in ha_nodes(store) if not n.get('me')),
                        key=lambda n: not n.get('alive'))
        name = others[0]['name'] if others else 'the other node'
    elif CONFIG.get('ha_mode') and store.db.engine in ('postgres', 'mariadb'):
        conf = {k: CONFIG.get(k) for k in DB_KEYS}
        name = CLOCK_DB_SERVER
    else:
        return None, None
    got = {}

    def ask():
        db = None
        try:
            db = db_open(conf, statement_s=2)
            db.value('SELECT 1')                        # connected before the clock is read
            if db.engine == 'mariadb':
                # In UTC: NOW() of a zone with summer time is the same twice in the hour it
                # goes back (otp 1.0.226).
                db.run(RawSql("SET time_zone = '+00:00'"))
                sql = 'SELECT UNIX_TIMESTAMP(NOW(6))'
            else:
                sql = 'SELECT extract(epoch from clock_timestamp())'
            best = None
            for _ in range(3):                          # the shortest of three round trips
                t0 = time.time()
                there = float(db.value(RawSql(sql)))
                t1 = time.time()
                if best is None or t1 - t0 < best[0]:
                    best = (t1 - t0, there - (t0 + t1) / 2.0)
            got['skew'] = best[1]
        except Exception as e:                          # noqa: BLE001
            got['e'] = str(e).split('\n')[0][:160] or 'no answer'
        finally:
            try:
                if db is not None:
                    db.close()
            except Exception:                           # noqa: BLE001
                pass
    t = threading.Thread(target=ask, name='acme-clock-peer', daemon=True)
    t.start()
    t.join(3.5)
    if 'skew' in got:
        return name, got['skew']
    raise RuntimeError(got.get('e') or 'no answer within 3.5 s')


# ---- the directory -----------------------------------------------------------------------------
def clock_dirs_used():
    """The directories signed in against: the administrators' and the portal's."""
    used = []
    for k, on in (('admin_directory', True), ('portal_directory', bool(CONFIG.get('portal')))):
        v = str(CONFIG.get(k) or '').strip().lower()
        if v and on and v not in used:
            used.append(v)
    return used


def clock_dir_check(store):
    """(True | False | None, [(directory, reached, words)]): every directory signed in against,
    reached on one of its servers - connected, its TLS made and its reading account let in, 3 s
    at most a server. Only the reading account signs in; nobody's password is sent. None: no
    directory is used."""
    used = clock_dirs_used()
    if not used:
        return None, []
    out = []
    try:
        rows = store.directories(with_secret=True)
    except Exception:                                   # noqa: BLE001
        return None, []
    for row in rows:
        if str(row.get('name') or '').lower() not in used or not row.get('enabled', 1):
            continue
        try:
            ad = Directory(row)
            ad.timeout = min(float(ad.timeout or 10), 3.0)
            ad.DEAD = {}                                # its own: the sign-ins' passed-over list untouched
            link = ad.link()
            try:
                words = '%s' % (getattr(link, 'host', '') or 'reached')
            finally:
                link.close()
            out.append((row['name'], True, words))
        except (LdapError, OSError, ValueError) as e:
            out.append((row['name'], False, str(e)[:160]))
    if not out:
        return None, out
    return all(x[1] for x in out), out


# ---- the decision ----------------------------------------------------------------------------
def clock_decide(mode, ref, aside_s, codes_fixed, dir_ok, health_dir, peer, aside_now=False,
                 back_s=None, peer_newer=True):
    """('serve' | 'aside', why). `peer`: the other node's state row as known here (None when
    not heard from) - a node steps aside only for one that is well: fresh, serving, not in
    maintenance, its clock within aside_s of the reference, and (for the directory) reaching
    it. Never both: each steps aside only for the other being better."""
    if mode != 'guard':
        return 'serve', ''
    peer_well = bool(peer) and bool(peer.get('fresh')) and peer.get('role') == 'serve' and \
        not peer.get('maintenance')
    # Back only below aside_s less the warning (otp 1.0.224): a clock wobbling about the limit
    # moved the VIP address again and again.
    limit = (back_s if back_s is not None else aside_s) if aside_now else aside_s
    clock_bad = ref is not None and abs(ref) > limit and not codes_fixed
    if clock_bad:
        pr = (peer or {}).get('ref')
        # The other node's word measured after this node's own, or already aside: both clocks
        # off alike, the first to measure stepped aside on the other's old word (otp 1.0.224).
        if peer_well and pr is not None and abs(pr) <= aside_s and (peer_newer or aside_now):
            return 'aside', 'this node\'s clock is %+.1f s off the time servers - the other node answers' % (-ref)
        return 'serve', 'this node\'s clock is off, but the other node cannot take over - it answers'
    if health_dir and dir_ok is False:
        # Only for a peer whose clock is good too (1.0.56): one serving only because this node
        # could not take over for its clock was stepped aside for. Not measured: as before.
        pr = (peer or {}).get('ref')
        if peer_well and (peer or {}).get('dir_ok') is True and \
                (pr is None or abs(pr) <= aside_s):
            return 'aside', 'this node cannot reach the directory - the other node answers'
        return 'serve', 'the directory cannot be reached, but neither can the other node take over'
    return 'serve', ''


def clock_aside():
    return clock_engaged() and CLOCK['role'] == 'aside'


def clock_stepped():
    """Whether the machine's clock moved by more than a second, against the monotonic one,
    since the reference was measured."""
    if not CLOCK['ref_mono']:
        return False
    return abs((time.time() - time.monotonic()) - CLOCK['ref_wall']) > 1.0


def clock_ref_noted():
    CLOCK['ref_mono'] = time.monotonic()
    CLOCK['ref_wall'] = time.time() - CLOCK['ref_mono']


def clock_correction():
    """Seconds to add to this machine's clock, by the reference - 0 when not known, not fresh
    (aged on the monotonic clock), the clock stepped since, or within clock_warn_s."""
    ref = CLOCK['ref']
    if ref is None or time.monotonic() - CLOCK['ref_mono'] > CLOCK_FRESH_S * 2 or clock_stepped():
        return 0.0
    if abs(ref) <= float(CONFIG.get('clock_warn_s') or 2):
        return 0.0
    return ref


def clock_now(kind='codes'):
    """The time the second step's codes (kind 'codes') or the pauses after wrong tries (kind
    'locks') are worked out with: the machine's clock, corrected by the reference with
    clock_codes / clock_locks. As until now: time.time(), nothing else."""
    t = time.time()
    if not clock_engaged():
        return t
    if (kind == 'codes' and CONFIG.get('clock_codes')) or \
            (kind == 'locks' and CONFIG.get('clock_locks')):
        return t + clock_correction()
    return t


def clock_skew_of(store, name):
    """The other node's clock minus this one's, as measured here (or as this node's own row
    says, from a process that does not watch): None when not known. With one shared database
    server both nodes measure against it: the other's minus this one's is the difference."""
    def mine():
        if CLOCK['skew'] is not None and time.time() - CLOCK['skew_at'] < CLOCK_FRESH_S:
            return CLOCK['skew_of'], CLOCK['skew']
        row = _meta_obj(store, 'clock:state:' + node_name())
        if row.get('skew') is not None and time.time() - float(row.get('at') or 0) < CLOCK_FRESH_S:
            return row.get('skew_of'), float(row['skew'])
        return None, None
    of, sk = mine()
    if sk is None:
        return None
    if of == name:
        return sk
    if of == CLOCK_DB_SERVER:
        row = _meta_obj(store, 'clock:state:' + name)
        if row.get('skew_of') == CLOCK_DB_SERVER and row.get('skew') is not None:
            return sk - float(row['skew'])
    return None


def clock_their_time(store, name, at):
    """A moment written by another node (a heartbeat, the lead's lease) in this node's time:
    with clock_beat, less the measured difference of the clocks - a node 10 min behind looked
    dead, one ahead lived for ever. Without it, or not measured: as written."""
    if not (clock_engaged() and CONFIG.get('clock_beat')) or not name or name == node_name():
        return at
    try:
        sk = clock_skew_of(store, name)
    except Exception:                                   # noqa: BLE001
        sk = None
    return at if sk is None else at - sk


def clock_beat_age(store, name, at, now):
    return now - clock_their_time(store, name, at)


def clock_row_age(store, name, row, now=None):
    """How old another node's state row is, by the measured difference of the clocks."""
    now = time.time() if now is None else now
    try:
        sk = clock_skew_of(store, name)
    except Exception:                                   # noqa: BLE001
        sk = None
    return now - (float((row or {}).get('at') or 0) - (sk or 0.0))


# ---- the watch -------------------------------------------------------------------------------
def clock_tick(daemon):
    """From the daemon's loop. As until now nothing is started; switched off while aside (or
    with measurements of the time it ran) one look puts it back at once."""
    if not clock_engaged():
        if CLOCK['role'] != 'serve' or CLOCK['ref_at'] or CLOCK['skew_at'] or CLOCK['dir_at']:
            clock_step(daemon.store)
        return
    with CLOCK_LOCK:
        t = CLOCK['thread']
        if t is not None and t.is_alive():
            return
        t = threading.Thread(target=_clock_loop, args=(daemon,), name='acme-clock', daemon=True)
        CLOCK['thread'] = t
    t.start()


def _clock_loop(daemon):
    while not daemon.stop_flag.is_set():
        try:
            clock_step(daemon.store)
        except Exception as e:                          # noqa: BLE001
            log_sparing('clock', 'watching the clocks: %s' % e, 'warn', every=600)
        if not clock_engaged():
            return                                      # switched off: put back, and gone
        daemon.stop_flag.wait(CLOCK_STEP_S)


def clock_watching():
    t = CLOCK['thread']
    return t is not None and t.is_alive()


def clock_peer_row(store, now=None):
    """The other node's row, with 'fresh' worked out by the measured difference of the clocks
    (younger than 25 s, and its heartbeat alive) and its maintenance as written."""
    now = time.time() if now is None else now
    for n in sorted(ha_nodes(store), key=lambda n: not n.get('alive')):   # alive first (1.0.52)
        if n.get('me'):
            continue
        row = _meta_obj(store, 'clock:state:' + n['name'])
        if not row:
            return None
        row['fresh'] = clock_row_age(store, n['name'], row, now) < 25 and bool(n.get('alive'))
        try:
            m = bool((maintenance_row(store, n['name']) or {}).get('on'))
        except Exception:                               # noqa: BLE001
            m = False
        row['maintenance'] = bool(n.get('maintenance')) or m
        if row.get('ref_at') != CLOCK.get('peer_ref_at'):
            CLOCK['peer_ref_at'], CLOCK['peer_ref_seen'] = row.get('ref_at'), time.monotonic()
        return row
    return None


def clock_step(store, now=None, ref=None, skew=None, dir_ok=None, peer=None):
    """One look. `ref`, `skew`, `dir_ok`, `peer` given only by the tests ('none' for None)."""
    now = time.time() if now is None else now
    if not clock_engaged():
        if CLOCK['role'] != 'serve':
            CLOCK.update(role='serve', why='')
            _clock_told()
        # Nothing kept from the time it ran: switched off, the card showed the last
        # measurements as if they were now (otp 1.0.223).
        if CLOCK['ref_at'] or CLOCK['skew_at'] or CLOCK['dir_at']:
            CLOCK.update(ref=None, ref_at=0.0, ref_mono=0.0, ref_wall=0.0, ref_src='', ref_err='',
                         refs=[], skew=None, skew_at=0.0, skew_of='', skew_err='', dir_ok=None,
                         dirs=[], dir_at=0.0)
        return
    if ref is not None:
        CLOCK.update(ref=None if ref == 'none' else ref, ref_at=now, ref_src='test', ref_err='',
                     refs=[])
        clock_ref_noted()
    elif time.monotonic() - CLOCK['ref_mono'] > CLOCK_REF_EVERY_S or not CLOCK['ref_mono'] or \
            clock_stepped() or CLOCK.pop('measure_now', False):
        servers = clock_ref_servers(store=store)
        got, med = clock_ref_check(servers) if servers else ([], None)
        if med is None and servers and CLOCK['ref'] is not None and not clock_stepped() and \
                time.monotonic() - CLOCK['ref_mono'] < CLOCK_FRESH_S * 2:
            # No answer just now: the last measurement kept until it is too old (otp 1.0.224).
            CLOCK.update(refs=got, ref_err='no time server answered just now - the last '
                                           'measurement is used')
        else:
            CLOCK.update(refs=got, ref=med, ref_at=now, ref_src=', '.join(servers),
                         ref_err='' if med is not None else (
                             'no time server given (Settings -> Time, or this node\'s own)'
                             if not servers else 'no time server answered'))
            clock_ref_noted()
    if skew is not None:
        of, val = skew if isinstance(skew, tuple) else ('test-peer', skew)
        CLOCK.update(skew=None if val == 'none' else val, skew_at=now, skew_of=of, skew_err='')
    else:
        try:
            name, sk = clock_peer_skew(store)
            if name is not None:
                CLOCK.update(skew=sk, skew_at=now, skew_of=name, skew_err='')
        except Exception as e:                          # noqa: BLE001
            CLOCK.update(skew_err=str(e).split('\n')[0][:160])
    if dir_ok is not None:
        CLOCK.update(dir_ok=None if dir_ok == 'none' else dir_ok, dir_at=now)
    elif CONFIG.get('health_dir') and now - CLOCK['dir_at'] > CLOCK_DIR_EVERY_S:
        ok, dirs = clock_dir_check(store)
        CLOCK.update(dir_ok=ok, dirs=dirs, dir_at=now)
    elif not CONFIG.get('health_dir') and CLOCK['dir_at']:
        CLOCK.update(dir_ok=None, dirs=[], dir_at=0.0)
    p = clock_peer_row(store, now) if peer is None else (None if peer == 'none' else peer)
    aside_s = float(CONFIG.get('clock_aside_s') or 20)
    role, why = clock_decide(clock_mode(), CLOCK['ref'], aside_s,
                             bool(CONFIG.get('clock_codes')) and CLOCK['ref'] is not None,
                             CLOCK['dir_ok'], bool(CONFIG.get('health_dir')), p,
                             aside_now=CLOCK['role'] == 'aside',
                             back_s=max(1.0, aside_s - float(CONFIG.get('clock_warn_s') or 2)),
                             peer_newer=peer is not None or
                             CLOCK.get('peer_ref_seen', 0.0) >= CLOCK['ref_mono'])
    changed = role != CLOCK['role']
    if changed:
        CLOCK['role'], CLOCK['why'] = role, why
        _clock_told()
        if role == 'aside':
            log('time: this node steps aside - %s' % why, 'warn')
            _clock_event(store, 'bad', 'this node steps aside: %s - the renewals, the deployments '
                         'and the DNS answers are left to the other node, the VIP address goes '
                         'to it' % why)
        else:
            log('time: this node answers again', 'info')
            _clock_event(store, 'good', 'this node answers again%s' % (' - ' + why if why else ''))
    else:
        CLOCK['why'] = why
    if now - CLOCK['written'] > 10 or changed:
        CLOCK['written'] = now
        try:
            store.set_meta('clock:state:' + node_name(), json.dumps(clock_state_here(now)))
        except Exception:                               # noqa: BLE001
            pass


def _clock_told():
    """A change of role said at once: the VIP check, /healthz and the renewer (its lead and
    its DNS server) - silent at once, not after a moment of "draining" (otp 1.0.227)."""
    MAINT_CACHE['at'] = 0
    try:
        HEALTH_SEEN.pop('db', None)
    except Exception:                                   # noqa: BLE001
        pass
    _split_renewer_wake()


def clock_state_here(now=None):
    now = time.time() if now is None else now
    return {'at': now, 'node': node_name(), 'engaged': clock_engaged(), 'mode': clock_mode(),
            'ref': CLOCK['ref'], 'ref_at': CLOCK['ref_at'], 'ref_src': CLOCK['ref_src'],
            'ref_err': CLOCK['ref_err'],
            'refs': [{'server': s, 'offset': o, 'words': w} for s, o, w in CLOCK['refs']],
            'skew': CLOCK['skew'], 'skew_of': CLOCK['skew_of'], 'skew_err': CLOCK['skew_err'],
            'dir_ok': CLOCK['dir_ok'],
            'dirs': [{'name': n, 'ok': ok, 'words': w} for n, ok, w in CLOCK['dirs']],
            'role': CLOCK['role'], 'why': CLOCK['why'],
            'codes_fixed': bool(CONFIG.get('clock_codes')) and clock_correction() != 0.0,
            'correction': clock_correction()}


def clock_state_of(store, name):
    if name == node_name() and (clock_watching() or CLOCK['ref_at'] > 0):
        return clock_state_here()                       # measured in this process
    return _meta_obj(store, 'clock:state:' + name)


def _clock_event(store, level, words):
    try:
        store.add_event('time', words, 'warn' if level == 'bad' else 'info', who='acme (clock)')
    except Exception:                                   # noqa: BLE001
        pass


def clock_view(store):
    nodes = []
    saved = store.settings_saved()
    on = clock_engaged()
    for n in ha_nodes(store):
        # Switched off: nothing measured is shown - a row of the time it ran is old.
        st = clock_state_of(store, n['name']) if on else {}
        if n.get('me') and not st:
            st = clock_state_here()
        fresh = bool(st) and (clock_row_age(store, n['name'], st) < 60 if not n.get('me')
                              else time.time() - float(st.get('at') or 0) < 60)
        nodes.append({'name': n['name'], 'me': bool(n.get('me')), 'alive': bool(n.get('alive')),
                      'state': st, 'ref': str(saved.get('clock_ref@' + n['name'])
                                              or (CONFIG.get('clock_ref') if n.get('me') else '')
                                              or ''),
                      'fresh': fresh})
    if not nodes:
        nodes = [{'name': node_name(), 'me': True, 'alive': True, 'state': clock_state_here(),
                  'ref': str(CONFIG.get('clock_ref') or ''), 'fresh': True}]
    common = clock_common_servers(store)
    return {'engaged': on, 'ha_mode': CONFIG.get('ha_mode') or '',
            'cluster': bool(CONFIG.get('ha_mode')) and len(nodes) > 1,
            'conf': {k: CONFIG.get(k, DEFAULTS.get(k)) for k in CLOCK_KEYS},
            'me': node_name(), 'nodes': nodes, 'common': [c for c in common if c][:5]}
