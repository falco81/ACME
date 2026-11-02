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
         'together_at': 0.0, 'report_due': 0.0, 'written': 0.0, 'started': 0.0, 'gen': 0}
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
        for n in ha_nodes(store):
            if not n.get('me'):
                return n['name']
    return ''


def split_me_preferred():
    want = str(CONFIG.get('split_prefer') or '').strip()
    if want:
        return want == node_name()
    return int(CONFIG.get('ha_slot') or 1) == 1


def split_decide(mode, apart, arbiter, preferred):
    """('serve' | 'aside', why). `arbiter`: True reached, False not reached, None cannot be
    told (no way to ask) - never a reason to step aside."""
    if not apart:
        return 'serve', ''
    if mode == 'priority':
        if preferred:
            return 'serve', 'the preferred node answers while the nodes are apart'
        return 'aside', 'the nodes cannot reach each other and this is not the preferred node'
    if mode == 'arbiter':
        if arbiter is False:
            return 'aside', 'neither the other node nor the arbiter can be reached - this node is the one cut off'
        if arbiter is None:
            return 'serve', 'the arbiter cannot be asked from here - this node answers'
        return 'serve', 'the arbiter is reached - this node answers'
    return 'serve', 'both nodes answer while they are apart (no rule chosen)'


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
    return _meta_json(store, 'split:state:' + name) or {}


def split_apart():
    return bool(SPLIT['apart_since']) and split_engaged()


def split_aside():
    return split_engaged() and SPLIT['role'] == 'aside'


def split_step(store, now=None, peer=None, arbiter=None):
    """One look: the other node's database, the arbiter, what this node does. `peer` and
    `arbiter` given only by the tests."""
    now = time.time() if now is None else now
    if not split_engaged():
        if SPLIT['apart_since'] or SPLIT['role'] != 'serve':
            SPLIT.update(apart_since=0.0, role='serve', why='')
            MAINT_CACHE['at'] = 0
        SPLIT['peer_ok_at'] = now
        return
    p = _split_peer_probe() if peer is None else peer
    if p is True:
        SPLIT['peer_ok_at'], SPLIT['peer_err'] = now, ''
        # The other node's database answers: the question before a code of the second step
        # is let in is asked again at once - not after its back-off of up to five minutes,
        # while codes would be written down as let in unasked.
        if ONCE_PEER['down_until'] > time.time():
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
        SPLIT.update(apart_since=0.0, together_at=now, report_due=now + 30)
        log('ha: the other node\'s database answers again - the nodes are together after %s'
            % human_span(took), 'info')
        _split_event(store, 'good', 'the nodes reach each other again, after %s apart' % human_span(took))
    role, why = split_decide(mode, apart, SPLIT['arb_state'], split_me_preferred())
    if role != SPLIT['role']:
        SPLIT['role'], SPLIT['why'] = role, why
        MAINT_CACHE['at'] = 0                           # the VIP check and /healthz told at once
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
    if SPLIT['report_due'] and now >= SPLIT['report_due'] and not apart:
        SPLIT['report_due'] = 0.0
        try:
            split_report(store, now)
        except Exception as e:                          # noqa: BLE001
            log('ha: the report of the time apart could not be made: %s' % e, 'warn')


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
            'held': split_no_lead()}


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


def split_issue_refused():
    """The words why a certificate may not be issued, renewed, revoked or signed here now
    (a renewal by hand, a request on the portal, Sign a CSR) - '' when it may."""
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
               '/api/firewall': ('rule_check',), '/api/directories': ('lookup',)}


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


def split_report(store, now=None):
    """Once together again: what was done on both halves - the same certificate renewed or
    revoked, the same authority signing, the same thing changed, the same code let in. Made
    by the preferred node (both have every row by now)."""
    now = time.time() if now is None else now
    rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'split:took:%'")
    if not rows:
        return None
    if not split_me_preferred():
        return None
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
        by_key.setdefault(k, {})[node] = v
        per_node[node] = per_node.get(node, 0) + 1
        kd = kinds.setdefault(node, {})
        kd[v.get('kind') or '?'] = kd.get(v.get('kind') or '?', 0) + 1
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
                        default=now)}
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
