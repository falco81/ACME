# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- when the two nodes lose each other: split brain (1.0.14) --------------------------
# Two replicating nodes that cannot reach each other each take the other for gone and go on
# alone: both renew (two versions of one certificate, a paid one paid twice, a CA's rate
# limits counted twice), both let acme's own authorities sign, the wrong passwords are
# counted on each half apart, and what the administrators change on each half goes its own
# way. With no third machine this cannot be ruled out; what can be done is chosen on
# Settings -> High availability -> When the nodes lose each other (docs/split-brain.md says
# it all - the same as otp 1.0.218 does it, in acme's terms):
#
#   split_mode      who answers while they are apart:
#                     off       both nodes, as before
#                     arbiter   a node that cannot reach its arbiter either (its default
#                               gateway, or addresses given - each node its own) is the one
#                               cut off: it steps aside
#                     priority  the preferred node alone; the other steps aside
#   split_prefer    the preferred node (empty: the first node of the cluster, ha_slot 1)
#   split_arbiter   each node's arbiter: addresses (ping) or host:port (TCP), empty = its gateway
#   split_after_s   how long the other node's database must not answer before they are apart
#   split_renew     renewals, deployments and the own authorities' signing only on the
#                   preferred node while apart (otp's place of "recovery codes only with the
#                   other node asked" - acme has no recovery codes)
#   split_halve     the pause after wrong passwords and codes at half its tries while apart
#   split_freeze    changes on the pages only on the preferred node while apart
#   split_report    a warning while apart, and a report when they are together again
#
# "Apart" is told by the other node's database: asked every two seconds on a connection of
# its own - the very database asked before a code of the second step is let in. Stepping
# aside is maintenance that nobody asked for and that ends by itself: the node does not lead
# (no renewals, no deployments, no CRLs, nothing signed), acme's DNS server stops answering
# there (the NS records name both nodes: resolvers ask the other), the VIP address and the
# load balancer's /healthz go to the other node, the pages stay. It ends as soon as the
# other node's database answers again, or when this node can reach its arbiter again.
SPLIT_MODES = ('off', 'arbiter', 'priority')
SPLIT_LOCK = threading.Lock()
SPLIT = {'thread': None, 'peer_ok_at': 0.0, 'peer_err': '', 'peer_db': None, 'apart_since': 0.0,
         'role': 'serve', 'why': '', 'arb': [], 'arb_state': None, 'arb_at': 0.0,
         'together_at': 0.0, 'report_due': 0.0, 'report_by': 0.0, 'outage_since': 0.0,
         'written': 0.0, 'started': 0.0, 'gen': 0, 'unable': '', 'there': None}
SPLIT_STEP_S = 2.0
SPLIT_SWITCHES = ('split_renew', 'split_halve', 'split_freeze', 'split_report')
# What is written down while apart, and which of it done on both halves is a clash (a
# sign-in on each half is not).
SPLIT_CLASH = ('renew', 'revoke', 'sign', 'change', 'step')


def split_active():
    """Only two replicating nodes can be split: with one shared database (or one node) the
    database itself decides who leads and what was used."""
    return CONFIG.get('ha_mode') == 'replicated' and bool(CONFIG.get('ha_peer'))


def split_engaged():
    """Whether anything of this runs at all. "As until now" - both nodes go on, every
    switch off - runs nothing: no question to the other node, no arbiter, nothing written,
    nothing changed. Exactly as before 1.0.14."""
    return split_active() and (split_mode() != 'off' or any(
        CONFIG.get(k) for k in SPLIT_SWITCHES))


def split_mode():
    m = str(CONFIG.get('split_mode') or 'off')
    return m if m in SPLIT_MODES else 'off'


def split_preferred_name(store=None):
    """The preferred node's name: the one chosen, else the first node (ha_slot 1)."""
    want = str(CONFIG.get('split_prefer') or '').strip()
    if want:
        return want
    if int(CONFIG.get('ha_slot') or 1) == 1:
        return node_name()
    if store is not None:
        for n in sorted(ha_nodes(store), key=lambda n: not n.get('alive')):   # alive first (1.0.52)
            if not n.get('me'):
                return n['name']
    return ''


def split_me_preferred():
    want = str(CONFIG.get('split_prefer') or '').strip()
    if want:
        return want == node_name()
    return int(CONFIG.get('ha_slot') or 1) == 1


def split_decide(mode, apart, arbiter, preferred, unable=''):
    """('serve' | 'aside', why). `arbiter`: True reached, False not reached, None cannot be
    told (no way to ask) - never a reason to step aside. `unable`: why the preferred node
    cannot answer itself (its database down while its machine is there, its last word that
    it stepped aside for its clock or is in maintenance) - the other node then goes on."""
    if not apart:
        return 'serve', ''
    if mode == 'priority':
        if preferred:
            return 'serve', 'the preferred node answers while the nodes are apart'
        if unable:
            return 'serve', '%s - this node answers' % unable
        return 'aside', 'the nodes cannot reach each other and this is not the preferred node'
    if mode == 'arbiter':
        if arbiter is False:
            return 'aside', 'neither the other node nor the arbiter can be reached - this node is the one cut off'
        if arbiter is None:
            return 'serve', 'the arbiter cannot be asked from here - this node answers'
        return 'serve', 'the arbiter is reached - this node answers'
    return 'serve', 'both nodes answer while they are apart (no rule chosen)'


# ---- the preferred node unable (otp 1.0.226/1.0.227) ------------------------------------------
# "Apart" is "the other node's database does not answer". The preferred node's database down
# (stopped, restarting) while its machine and the link are fine is not a cut link: with
# priority the other node stepped aside, and the preferred node, without its database, answered
# nobody either. A cut link gives no answer at all; a refusal from PostgreSQL itself ("shutting
# down", "starting up") is an answer. A bare "connection refused" is what a firewall between the
# nodes that rejects says too (both nodes up): it counts only when the preferred node's machine
# takes a TCP connection on 443, 22 or 80 - the machine there, only its database refusing.
SPLIT_DB_SAYS = ('shutting down', 'starting up', 'not yet accepting connections',
                 'in recovery mode')
SPLIT_THERE_PORTS = (443, 22, 80)


def split_db_refusal(words):
    """'said' (PostgreSQL itself answered that it is not taking connections), 'refused' (a
    bare connection refused) or ''."""
    w = str(words or '').lower()
    if any(x in w for x in SPLIT_DB_SAYS):
        return 'said'
    if 'connection refused' in w or 'errno 111' in w:
        return 'refused'
    return ''


def split_machine_there(host, ports=SPLIT_THERE_PORTS, timeout=1.0):
    """Whether the machine takes a TCP connection on any of these ports - a connection made,
    not refused (a firewall that rejects refuses too)."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            continue
    return False


def split_peer_says(host, timeout=5.0):
    """What the other node's own /healthz says (1.0.58; 5 s since 1.0.62 - it waits 3 s for its
    daemon before it says "down: the daemon is not answering", and 2 s never heard that): 'up' (200, ok), 'down' (503: its
    daemon or its database does not answer), '' (not asked, refused, anything else). Over
    HTTPS unchecked - only whether to go on serving is taken from it, never data."""
    try:
        import urllib.request
        import urllib.error
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        h = host if ':' not in host or host.startswith('[') else '[%s]' % host
        req = urllib.request.Request('https://%s/healthz' % h, headers={'User-Agent': 'acme-split'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(200).decode('utf-8', 'replace')
                return 'up' if r.status == 200 and body.startswith('ok') else ''
        except urllib.error.HTTPError as e:
            body = e.read(200).decode('utf-8', 'replace') if e.fp else ''
            return 'down' if e.code == 503 and body.startswith('down') else ''
    except Exception:                                   # noqa: BLE001
        return ''


def split_preferred_unable(store, now=None):
    """Why the preferred node cannot answer while the nodes are apart, or '' - only then the
    other node goes on in priority mode."""
    now = time.time() if now is None else now
    kind = split_db_refusal(SPLIT['peer_err'])
    if kind == 'said':
        return 'the preferred node\'s database refuses (%s) - its machine is there' % (
            SPLIT['peer_err'][:120])
    if kind == 'refused':
        # Its machine there AND its own /healthz saying its database (or its daemon) is down
        # (1.0.58): a TCP connection to 443/22/80 alone was taken for it - a firewall that
        # let 5432 in from an old address only (a node re-addressed) cut replication, and
        # both nodes served and led.
        was = SPLIT.get('there')
        if not was or now - was[0] > 10 or now < was[0]:
            host = str(CONFIG.get('ha_peer') or '')
            got = bool(host) and split_machine_there(host) and split_peer_says(host) == 'down'
            SPLIT['there'] = was = (now, got)
        if was[1]:
            return ('the preferred node\'s database refuses connections and its own health '
                    'check says it is down')
    pref = split_preferred_name(store)
    if not pref or pref == node_name():
        return ''
    try:
        if (maintenance_row(store, pref) or {}).get('on'):
            return 'the preferred node is in maintenance'
    except Exception:                                   # noqa: BLE001
        pass
    # Being re-addressed (1.0.56): told the new address, then rebooting, it is silent too -
    # with priority neither node answered. Its network job (as last come over) or a restart
    # of it under way.
    try:
        if net_job_active(_meta_json(store, 'net:job:' + pref)):
            return 'the preferred node is changing its network'
        if pref in ha_planned_away(store):
            return 'the preferred node is restarting'
    except Exception:                                   # noqa: BLE001
        pass
    # Its clock "aside" only while its row is fresh (otp 1.0.227): kept aside for as long as
    # the nodes were apart, with the other node dead nobody answered.
    try:
        c = _meta_obj(store, 'clock:state:' + pref)
        if c.get('role') == 'aside' and clock_row_age(store, pref, c, now) < 32:
            return 'the preferred node stepped aside for its clock'
    except Exception:                                   # noqa: BLE001
        pass
    return ''


# ---- the arbiter ----------------------------------------------------------------------
def default_gateway():
    """This machine's default gateway (IPv4), from /proc/net/route - '' when none."""
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) > 3 and p[1] == '00000000' and int(p[3], 16) & 2:
                    g = int(p[2], 16)
                    return '%d.%d.%d.%d' % (g & 255, (g >> 8) & 255, (g >> 16) & 255, g >> 24)
    except (OSError, ValueError):
        pass
    return ''


SPLIT_TARGET_RE = re.compile(r'^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.:-]{1,253}?)(?::(\d{1,5}))?\Z')


def split_targets_parse(text):
    """'192.0.2.1, gw.example.cz:443, [2001:db8::1]:53' -> [(host, port or None)]; ValueError."""
    out = []
    for one in [w for w in re.split(r'[\s,;]+', str(text or '').strip()) if w]:
        if one.count(':') > 1 and not one.startswith('['):
            out.append((one, None))                     # a bare IPv6 address
            continue
        m = SPLIT_TARGET_RE.match(one)
        if not m:
            raise ValueError('%s is not an address, a name or name:port' % one[:80])
        host, port = m.group(1).strip('[]'), m.group(2)
        if port is not None and not 0 < int(port) < 65536:
            raise ValueError('%s: the port is 1-65535' % one[:80])
        out.append((host, int(port) if port else None))
    if len(out) > 5:
        raise ValueError('five arbiters at most')
    return out


def split_targets(value=None):
    """This node's arbiters: given, or its default gateway."""
    given = CONFIG.get('split_arbiter') if value is None else value
    try:
        got = split_targets_parse(given)
    except ValueError:
        got = []
    if got:
        return got
    gw = default_gateway()
    return [(gw, None)] if gw else []


def _icmp_sum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def split_ping(host, timeout=1.0):
    """(True | False | None, how, words): one echo request. A datagram ICMP socket (any user
    in ping_group_range - RHEL's default), else a raw one (root), else /usr/bin/ping. None:
    this machine cannot send one at all - not "unreachable"."""
    try:
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_DGRAM)
    except (socket.gaierror, UnicodeError) as e:
        return False, 'dns', 'the name does not resolve: %s' % e
    fam, addr = infos[0][0], infos[0][4]
    v6 = fam == socket.AF_INET6
    proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
    ident = os.getpid() & 0xffff
    payload = b'acme-split' + os.urandom(8)
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            s = socket.socket(fam, kind, proto)
        except (PermissionError, OSError):
            continue
        try:
            s.settimeout(timeout)
            hdr = struct.pack('!BBHHH', 128 if v6 else 8, 0, 0, ident, 1)
            pkt = hdr + payload
            if not v6:
                pkt = struct.pack('!BBHHH', 8, 0, _icmp_sum(pkt), ident, 1) + payload
            s.sendto(pkt, addr)
            end = time.time() + timeout
            while time.time() < end:
                s.settimeout(max(0.05, end - time.time()))
                data = s.recv(2048)
                if kind == socket.SOCK_RAW and not v6:
                    data = data[(data[0] & 15) * 4:]          # the IP header first
                if data[:1] in (b'\x00', b'\x81') and payload in data:
                    return True, 'ping', ''
            return False, 'ping', 'no answer to ping within %.1f s' % timeout
        except socket.timeout:
            return False, 'ping', 'no answer to ping within %.1f s' % timeout
        except OSError as e:
            return False, 'ping', str(e)[:200]
        finally:
            s.close()
    tool = shutil.which('ping')
    if tool:
        try:
            r = subprocess.run([tool, '-c', '1', '-W', str(max(1, int(timeout))), str(host)],
                               capture_output=True, timeout=timeout + 2)
            return r.returncode == 0, 'ping', '' if r.returncode == 0 else 'no answer to ping'
        except (OSError, subprocess.SubprocessError) as e:
            return None, 'ping', str(e)[:200]
    return None, 'none', ('this machine lets nobody send a ping (net.ipv4.ping_group_range) - '
                          'give the arbiter as host:port, checked over TCP')


def split_tcp(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, 'tcp', ''
    except ConnectionRefusedError:
        return True, 'tcp', 'refused, but it answered - it is there'
    except (OSError, socket.timeout) as e:
        return False, 'tcp', str(e)[:200]


def split_arbiter_check(targets=None):
    """[(target words, True | False | None, how, words)] and the verdict: True when any one
    answers, False when every one could be asked and none answered, None when none could
    be asked at all (or there is none)."""
    out = []
    for host, port in (split_targets() if targets is None else targets):
        if port:
            ok, how, words = split_tcp(host, port)
        else:
            ok, how, words = split_ping(host)
        out.append(('%s:%s' % (host, port) if port else host, ok, how, words))
    if any(x[1] is True for x in out):
        verdict = True
    elif out and all(x[1] is False for x in out):
        verdict = False
    else:
        verdict = None
    return out, verdict


# ---- the other node's database ------------------------------------------------------------
def _split_peer_probe():
    """Whether the other node's database answers now: True, or the words why not."""
    got = {}

    def ask():
        try:
            db = SPLIT['peer_db']
            if db is None or SPLIT.get('peer_gen') != ONCE_PEER.get('gen'):
                if db is not None:
                    try:
                        db.close()
                    except Exception:                   # noqa: BLE001
                        pass
                db = db_open(ha_peer_conf(timeout=2), statement_s=2)
                SPLIT['peer_db'], SPLIT['peer_gen'] = db, ONCE_PEER.get('gen')
            db.value('SELECT 1')
            got['ok'] = True
        except Exception as e:                          # noqa: BLE001
            got['e'] = str(e).split('\n')[0][:200]
            try:
                if SPLIT['peer_db'] is not None:
                    SPLIT['peer_db'].close()
            except Exception:                           # noqa: BLE001
                pass
            SPLIT['peer_db'] = None
    t = threading.Thread(target=ask, name='acme-split-peer', daemon=True)
    t.start()
    t.join(3.5)
    if got.get('ok'):
        return True
    if t.is_alive():
        SPLIT['peer_db'] = None                         # left to time out by itself
        return 'no answer within 3.5 s'
    return got.get('e') or 'no answer'


# ---- the watch ---------------------------------------------------------------------------
def split_tick(daemon):
    """Started once from the daemon's loop: the watch runs in a thread of its own, so a
    peer that does not answer holds nothing else."""
    with SPLIT_LOCK:
        t = SPLIT['thread']
        if t is not None and t.is_alive():
            return
        SPLIT['started'] = time.time()
        SPLIT['peer_ok_at'] = time.time()           # given its time from the start
        t = threading.Thread(target=_split_loop, args=(daemon,), name='acme-split', daemon=True)
        SPLIT['thread'] = t
    t.start()


def _split_loop(daemon):
    while not daemon.stop_flag.is_set():
        try:
            split_step(daemon.store)
        except Exception as e:                          # noqa: BLE001
            log_sparing('split', 'watching the other node: %s' % e, 'warn', every=600)
        daemon.stop_flag.wait(SPLIT_STEP_S)


def split_watching():
    """Whether this process runs the watch (the daemon does; a command line does not - it
    reads the daemon's row instead)."""
    t = SPLIT['thread']
    return t is not None and t.is_alive()


def split_state_of(store, name):
    """A node's state: this node's own live where the watch runs here, else its row."""
    if name == node_name() and split_watching():
        return split_state_here()
    return _meta_obj(store, 'split:state:' + name)


def split_apart():
    return bool(SPLIT['apart_since']) and split_engaged()


def split_aside():
    return split_engaged() and SPLIT['role'] == 'aside'


def split_step(store, now=None, peer=None, arbiter=None):
    """One look: the other node's database, the arbiter, what this node does. `peer` and
    `arbiter` given only by the tests."""
    live = now is None
    now = time.time() if now is None else now
    if live:
        # The wall clock stepped since the last look (1.0.52: chrony's step of 25 s read as 25 s
        # without the other node - apart at once): the times kept moved with it.
        mono = time.monotonic()
        lw, lm = SPLIT.get('wall_last'), SPLIT.get('mono_last')
        if lw and lm:
            step = (now - lw) - (mono - lm)
            if abs(step) > 5:
                for k in ('peer_ok_at', 'apart_since'):
                    if SPLIT.get(k):
                        SPLIT[k] += step
        SPLIT['wall_last'], SPLIT['mono_last'] = now, mono
    if not split_engaged():
        if SPLIT['apart_since'] or SPLIT['role'] != 'serve':
            SPLIT.update(apart_since=0.0, role='serve', why='')
            _split_told()
        SPLIT['peer_ok_at'] = now
        # In any mode, as until now too (otp 1.0.224): while the question before a code of
        # the second step is let in is held off (the other node's database did not answer),
        # it is asked every 2 s and the hold lifted the moment it answers - not after its
        # back-off of up to five minutes. With no hold nothing is asked.
        if split_active() and ONCE_PEER['down_until'] > time.monotonic():
            p = _split_peer_probe() if peer is None else peer
            if p is True:
                with ONCE_PEER_LOCK:
                    ONCE_PEER['down_until'], ONCE_PEER['fails'] = 0.0, 0
            db, SPLIT['peer_db'] = SPLIT['peer_db'], None
            if db is not None:
                try:
                    db.close()                          # nothing kept open as until now
                except Exception:                       # noqa: BLE001
                    pass
        return
    p = _split_peer_probe() if peer is None else peer
    if p is True:
        SPLIT['peer_ok_at'], SPLIT['peer_err'] = now, ''
        # The other node's database answers: the question before a code of the second step
        # is let in is asked again at once - not after its back-off of up to five minutes,
        # while codes would be written down as let in unasked.
        if ONCE_PEER['down_until'] > time.monotonic():
            with ONCE_PEER_LOCK:
                ONCE_PEER['down_until'], ONCE_PEER['fails'] = 0.0, 0
    else:
        SPLIT['peer_err'] = str(p)
    mode = split_mode()
    if arbiter is not None:
        SPLIT.update(arb=[], arb_state=arbiter, arb_at=now)
    elif mode == 'arbiter' or now - SPLIT['arb_at'] > 30:
        got, verdict = split_arbiter_check()
        SPLIT.update(arb=got, arb_state=verdict, arb_at=now)
    after = max(5, int(CONFIG.get('split_after_s') or 20))
    apart = now - SPLIT['peer_ok_at'] > after
    was_apart = bool(SPLIT['apart_since'])
    if apart and not was_apart:
        SPLIT['apart_since'] = SPLIT['peer_ok_at'] or now
        log('ha: the other node\'s database has not answered for %d s (%s) - the nodes are '
            'apart' % (now - SPLIT['peer_ok_at'], SPLIT['peer_err']), 'warn')
        _split_event(store, 'bad', 'the nodes lost each other: the other node\'s database has not '
                     'answered for %d s (%s)' % (now - SPLIT['peer_ok_at'], SPLIT['peer_err']))
    elif not apart and was_apart:
        took = now - SPLIT['apart_since']
        # The report 30 s later at the soonest, once the other node's row written after it
        # found this one again has come over (its earlier rows come before it), at the latest
        # 10 min later (otp 1.0.224: after a long cut the replication took 40 s, and what was
        # done on both was not found).
        SPLIT.update(outage_since=SPLIT['apart_since'], apart_since=0.0, together_at=now,
                     report_due=now + 30, report_by=now + 600)
        # The pooled connections to it from before closed: made before the cut, they hang.
        try:
            once_peer_forget()
        except Exception:                               # noqa: BLE001
            pass
        log('ha: the other node\'s database answers again - the nodes are together after %s'
            % human_span(took), 'info')
        _split_event(store, 'good', 'the nodes reach each other again, after %s apart' % human_span(took))
    unable = ''
    if apart and mode == 'priority' and not split_me_preferred():
        try:
            unable = split_preferred_unable(store, now)
        except Exception:                               # noqa: BLE001
            unable = ''
    SPLIT['unable'] = unable
    role, why = split_decide(mode, apart, SPLIT['arb_state'], split_me_preferred(), unable)
    if role != SPLIT['role']:
        SPLIT['role'], SPLIT['why'] = role, why
        _split_told()                                   # the VIP check and /healthz told at once
        if role == 'aside':
            log('ha: this node steps aside - %s' % why, 'warn')
            _split_event(store, 'bad', 'this node steps aside: %s - the renewals, the deployments '
                         'and the DNS answers are left to the other node, the VIP address goes '
                         'to it' % why)
        else:
            log('ha: this node answers again%s' % (' - ' + why if why else ''), 'info')
            _split_event(store, 'good', 'this node answers again%s' % (' - ' + why if why else ''))
        _split_renewer_wake()
    else:
        SPLIT['why'] = why
    if apart != was_apart:
        _split_renewer_wake()
    if now - SPLIT['written'] > 10 or apart != was_apart:
        SPLIT['written'] = now
        try:
            store.set_meta('split:state:' + node_name(), json.dumps(split_state_here(now)))
        except Exception:                               # noqa: BLE001
            pass
    if SPLIT['report_due'] and now >= SPLIT['report_due'] and not apart and \
            (split_peer_caught_up(store, now) or now >= SPLIT['report_by']):
        SPLIT['report_due'] = 0.0
        try:
            split_report(store, now, since=SPLIT['outage_since'])
        except Exception as e:                          # noqa: BLE001
            log('ha: the report of the time apart could not be made: %s' % e, 'warn')


def _split_told():
    """A change of role said at once: the VIP check and /healthz (no moment of "draining" -
    otp 1.0.227: a code was let in there while keepalived moved the address)."""
    MAINT_CACHE['at'] = 0
    try:
        HEALTH_SEEN.pop('db', None)
    except Exception:                                   # noqa: BLE001
        pass


def split_peer_caught_up(store, now=None):
    """Whether the other node's state row written after it found this one again has come
    over by replication - everything it wrote before it is here then."""
    now = time.time() if now is None else now
    since = SPLIT['together_at'] or now
    for n in ha_nodes(store):
        if n.get('me'):
            continue
        row = _meta_obj(store, 'split:state:' + n['name'])
        if not row or row.get('apart'):
            continue
        try:
            sk = clock_skew_of(store, n['name']) or 0.0
        except Exception:                               # noqa: BLE001
            sk = 0.0
        if float(row.get('at') or 0) - sk >= since:
            return True
    return False


def _split_renewer_wake():
    """The renewer told at once (it lets its lead go, stops or starts its DNS server)."""
    try:
        from acmelib.certs import renewer as _rn
        r = _rn.RENEWER[0]
        if r is not None:
            r.wake.set()
    except Exception:                                   # noqa: BLE001
        pass


def split_state_here(now=None):
    now = time.time() if now is None else now
    return {'at': now, 'node': node_name(), 'active': split_active(), 'engaged': split_engaged(),
            'mode': split_mode(),
            'apart': split_apart(), 'since': SPLIT['apart_since'],
            'peer_ok_at': SPLIT['peer_ok_at'], 'peer_err': SPLIT['peer_err'],
            'role': SPLIT['role'], 'why': SPLIT['why'], 'preferred': split_me_preferred(),
            'arbiter': SPLIT['arb_state'], 'arbiter_at': SPLIT['arb_at'],
            'arbiters': [{'target': t, 'ok': ok, 'how': how, 'words': w}
                         for t, ok, how, w in SPLIT['arb']],
            'gateway': default_gateway(), 'frozen': split_frozen(),
            'halved': bool(CONFIG.get('split_halve')) and split_apart(),
            'held': split_no_lead(), 'together_at': SPLIT['together_at'],
            'unable': SPLIT.get('unable') or ''}


def _split_event(store, level, words):
    try:
        store.add_event('ha', words, 'warn' if level == 'bad' else 'info', who='acme (split)')
    except Exception:                                   # noqa: BLE001
        pass


# ---- what changes while apart ---------------------------------------------------------------
def split_limit(key, default=0):
    """login_tries / portal_tries as in force now: half (rounded up) while apart, with
    split_halve on - both halves together then allow what one did."""
    v = int(CONFIG.get(key) or default)
    if v > 0 and CONFIG.get('split_halve') and split_apart():
        return max(1, (v + 1) // 2)
    return v


def split_frozen():
    """Whether changes on the pages wait here: apart, split_freeze on, and this node is not
    the preferred one answering."""
    if not (CONFIG.get('split_freeze') and split_apart()):
        return False
    return SPLIT['role'] == 'aside' or not split_me_preferred()


def split_no_lead():
    """Whether this node must not lead now - no renewals, no deployments, no CRLs, nothing
    signed: stepped aside, or apart with split_renew on and not the preferred node."""
    if not split_engaged():
        return False
    if SPLIT['role'] == 'aside':
        return True
    return bool(CONFIG.get('split_renew')) and split_apart() and not split_me_preferred()


def no_lead_now(store=None):
    """Whether this node must not lead the certificates' work now (1.0.44): apart and held
    back (split_no_lead), stepped aside by the clock guard (docs/clock-guard.md: its clock is
    wrong - nothing renewed, deployed or signed by it), or in maintenance in a cluster (being
    upgraded: the other node works meanwhile). Only the first was asked; the node out of
    service, or with its clock off, kept renewing and deploying beside the other."""
    if split_no_lead():
        return True
    try:
        if clock_aside():
            return True
        if CONFIG.get('ha_mode') and store is not None and maintenance_now(store).get('on'):
            return True
    except Exception:                                   # noqa: BLE001
        pass
    return False


def split_issue_refused():
    """The words why a certificate may not be issued, renewed, revoked or signed here now
    (a renewal by hand, a request on the portal, Sign a CSR) - '' when it may."""
    try:
        if clock_aside():
            return ('this node has stepped aside: its clock is not right (Settings -> Time) - '
                    'certificates are issued and signed by the other node')
    except Exception:                                   # noqa: BLE001
        pass
    if not split_no_lead():
        return ''
    other = split_preferred_name(HA_STORE.get('store')) or 'the preferred node'
    if SPLIT['role'] == 'aside':
        return ('this node has stepped aside while the two nodes cannot reach each other (%s): '
                'certificates are issued and signed by the other node' % (SPLIT['why'] or 'apart'))
    return ('the two nodes cannot reach each other: certificates are issued, renewed, revoked '
            'and signed on %s only until they do (Settings -> High availability -> When the '
            'nodes lose each other)' % other)


# The pages' requests that go on while frozen: signing in and out (the pages and the
# portal), looking at the cluster, the card of this itself (to switch it off), restarts,
# certificates pushed here, and what only reads (a PEM taken apart, a dry run, an export).
SPLIT_FREE = ('/api/auth/', '/api/split', '/api/ha', '/api/power', '/api/acme-push/',
              '/api/health', '/api/alerts', '/api/logs', '/api/portal/login',
              '/api/portal/logout', '/api/portal/mfa', '/api/console-login',
              '/api/certs/parse', '/api/certs/dry_run', '/api/certs/export', '/api/cas/export',
              '/api/cas/pki_check', '/api/deploys/dry_run', '/api/deploys/preview',
              '/api/sshkey/show', '/api/sshkey/download', '/api/portal/cert_download')


# What only reads, though asked with POST (1.0.19): refused while frozen, the page of a
# job, a copy to download, the wizard's choices and a preview stayed empty there - and,
# asked on both halves, each was in the report as a change done on both.
SPLIT_READS = {'/api/certs/compat': None,
               '/api/db': ('job', 'download_ticket', 'check', 'tune_plan'),
               '/api/rbackup': ('job', 'list', 'verified', 'restore_md'),
               '/api/texts': ('preview',), '/api/metrics': ('preview',),
               '/api/firewall': ('rule_check',), '/api/directories': ('lookup',),
               # a module's list read live for its form (1.0.21: SSLS.cz products)
               '/api/sources/catalog': None, '/api/validations/catalog': None,
               '/api/targets/catalog': None,
               # Show a certificate (1.0.23): a file read and described, nothing kept
               '/api/certs/inspect': None}


def split_free_path(path, action=''):
    if any(path == p.rstrip('/') or path.startswith(p) for p in SPLIT_FREE):
        return True
    if path in SPLIT_READS and (SPLIT_READS[path] is None or action in SPLIT_READS[path]):
        return True
    # A node into maintenance and back (Settings -> Upgrades): as otp's /api/maintenance.
    return path == '/api/upgrade' and action == 'maintenance'


def split_refuses(method, path, action=''):
    if method != 'POST' or not split_frozen():
        return ''
    if split_free_path(path, action):
        return ''
    other = split_preferred_name(HA_STORE.get('store')) or 'the preferred node'
    return ('the two nodes cannot reach each other: changes are made on %s only until they '
            'do (Settings -> High availability -> When the nodes lose each other)' % other)


def split_noting():
    """Whether what this node does now is written down for the report: apart, split_report on."""
    return bool(CONFIG.get('split_report')) and split_apart()


def split_took(store, kind, name, k):
    """Something done here while the other node could not know of it: written down for the
    report. `k` is the same on both nodes for the same thing (a certificate's id, an
    authority's, a code's hash), so that what was done on both halves is found."""
    if not (split_engaged() and CONFIG.get('split_report')):
        return
    try:
        store.set_meta('split:took:%s:%s' % (node_name(), k),
                       json.dumps({'name': str(name)[:190], 'kind': kind, 'at': time.time()}))
    except Exception:                                   # noqa: BLE001
        pass


def split_note(store, kind, name, k):
    """split_took while apart only - renewals, revocations, signing, changes, sign-ins."""
    if split_noting():
        split_took(store, kind, name, k)


SPLIT_REPORT_SLACK_S = 5.0


def split_report(store, now=None, since=None):
    """Once together again: what was done on both halves - the same certificate renewed or
    revoked, the same authority signing, the same thing changed, the same code let in. Made
    by the preferred node (both have every row by now). Counted from the first thing the other
    node could not be asked about in this time apart (`since`: when it last answered, less a
    few seconds for the two clocks) - the rows of an earlier short outage left out - and each
    thing once, by its key."""
    now = time.time() if now is None else now
    rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'split:took:%'")
    if not rows:
        return None
    if not split_me_preferred():
        return None
    cut = float(since) - SPLIT_REPORT_SLACK_S if since else 0.0
    by_key, per_node, kinds = {}, {}, {}
    for r in rows:
        parts = r['k'].split(':', 3)
        if len(parts) < 4:
            continue
        node, k = parts[2], parts[3]
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            v = {}
        at = float(v.get('at') or 0)
        if node != node_name():
            try:
                at -= clock_skew_of(store, node) or 0.0
            except Exception:                           # noqa: BLE001
                pass
        if cut and at < cut:
            continue                                    # an earlier short outage's
        if node in by_key.get(k, {}):
            continue                                    # counted once
        by_key.setdefault(k, {})[node] = v
        per_node[node] = per_node.get(node, 0) + 1
        kd = kinds.setdefault(node, {})
        kd[v.get('kind') or '?'] = kd.get(v.get('kind') or '?', 0) + 1
    if not by_key:
        # Only rows of an earlier short outage: nothing of this time apart - they go.
        for r in rows:
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
        return None
    twice = []
    for k, nodes in by_key.items():
        one = list(nodes.values())[0]
        if len(nodes) > 1 and (one.get('kind') or '?') in SPLIT_CLASH:
            twice.append({'name': one.get('name') or '?', 'kind': one.get('kind') or '?',
                          'nodes': sorted(nodes), 'at': min(float(v.get('at') or 0)
                                                           for v in nodes.values())})
    twice.sort(key=lambda x: x['at'])
    rep = {'at': now, 'taken': per_node, 'kinds': kinds, 'twice': twice[:200],
           'twice_n': len(twice),
           'since': min((float(v.get('at') or now) for n in by_key.values() for v in n.values()),
                        default=float(since or now))}
    store.set_meta('split:report', json.dumps(rep))
    for r in rows:
        store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))
    if twice:
        _split_event(store, 'bad', 'while the nodes were apart, %d thing(s) were done on both: %s'
                     % (len(twice), ', '.join('%s (%s)' % (x['name'], x['kind'])
                                              for x in twice[:20])))
    else:
        _split_event(store, 'good', 'while the nodes were apart, %s thing(s) were done without '
                     'the other node knowing, none of them on both'
                     % ', '.join('%d on %s' % (v, n) for n, v in sorted(per_node.items())))
    return rep


# ---- the card ----------------------------------------------------------------------------
SPLIT_KEYS = ('split_mode', 'split_prefer', 'split_after_s', 'split_renew', 'split_halve',
              'split_freeze', 'split_report')


def split_view(store):
    nodes = []
    saved = store.settings_saved()
    for n in ha_nodes(store):
        st = split_state_of(store, n['name'])
        if n.get('me') and not st:
            st = split_state_here()
        nodes.append({'name': n['name'], 'me': bool(n.get('me')), 'alive': bool(n.get('alive')),
                      'state': st, 'arbiter': str(saved.get('split_arbiter@' + n['name'])
                                                  or (CONFIG.get('split_arbiter') if n.get('me') else '')
                                                  or ''),
                      'fresh': bool(st) and time.time() - float(st.get('at') or 0) < 60})
    if not nodes:
        nodes = [{'name': node_name(), 'me': True, 'alive': True, 'state': split_state_here(),
                  'arbiter': str(CONFIG.get('split_arbiter') or ''), 'fresh': True}]
    return {'active': split_active(), 'engaged': split_engaged(), 'ha_mode': CONFIG.get('ha_mode') or '',
            'conf': {k: CONFIG.get(k, DEFAULTS.get(k)) for k in SPLIT_KEYS},
            'preferred': split_preferred_name(store), 'me': node_name(), 'nodes': nodes,
            'report': _meta_json(store, 'split:report')}
