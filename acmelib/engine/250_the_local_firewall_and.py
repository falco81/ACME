# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the local firewall and who may reach which pages (1.0.52) -------------------------
# Kept for the whole cluster in meta, put in by each node's root helper with
# the rest of the web side (one request, one status). What acme's functions
# need is worked out here from what is set up; the rules somebody adds by
# hand come first, so a DROP or REJECT of theirs wins over what acme opens.
# The openings that may be switched off; a module's (HOOKS['firewall']) join them.
FW_AUTO_OPTIONAL = ['ssh', 'icmp', 'dhcpv6', 'web', 'ntp']
ACCESS_WORDS = {'portal': 'the enrolment pages', 'admin': 'the administration pages',
                'health': 'the health check (/healthz)'}


def fw_conf(store):
    c = _json_meta(store, 'fw:conf') or {}
    c.setdefault('on', False)
    c.setdefault('off', [])
    c.setdefault('rules', [])
    return c


def access_conf(store):
    return _json_meta(store, 'web:access') or {}


# A node being joined (1.0.210): its address, given when the bundle is made on
# the first node - and the first node's, taken from the bundle on the second -
# let in AT ONCE, before the cluster is made: the firewall otherwise held
# PostgreSQL, the pages and the health checks shut until the heartbeat of the
# other node came, which it never did, since the join failed on it. Kept per
# node ('ha:pending:NODE', written by that node only - two nodes writing one
# row of a replicated meta stop the replication) and for a day at most. Not a
# part of fw:conf: a firewall change on trial that goes back never takes it.
HA_PENDING_S = 24 * 3600


def ha_pending(store, node=None):
    """The addresses `node` (this one by default) lets in for a node being
    joined: [{address, until, at, by, why}], the ones run out left out."""
    node = node or node_name()
    try:
        raw = _json_meta(store, 'ha:pending:' + node) or {}
    except Exception:                                   # noqa: BLE001
        raw = {}
    now = time.time()
    out = []
    for x in (raw.get('peers') if isinstance(raw, dict) else None) or []:
        if isinstance(x, dict) and x.get('address') and float(x.get('until') or 0) > now:
            out.append(x)
    return out


def ha_pending_add(store, address, by='', why='', seconds=None):
    """`address` let into this node for a day (or `seconds`): one plain
    address; a host name is taken by its addresses. Returns the addresses."""
    said = str(address or '').strip()
    if not said:
        raise ValueError('the other node\'s address is needed')
    try:
        ips = [str(plain_ip(said, 'address'))]
    except ValueError:
        ips = []
        for ip in addresses_cached(said):
            try:
                ips.append(str(plain_ip(ip, 'address')))
            except ValueError:
                pass
        if not ips:
            raise ValueError('%s is not an address, nor a name that resolves here' % said[:80])
    now = time.time()
    keep = [x for x in ha_pending(store) if x.get('address') not in ips]
    for ip in ips:
        keep.append({'address': ip, 'at': now, 'until': now + (seconds or HA_PENDING_S),
                     'by': str(by or '')[:80], 'why': str(why or '')[:120],
                     'name': said if said != ip else ''})
    store.set_meta('ha:pending:' + node_name(), json.dumps({'peers': keep[-8:]}))
    return ips


def ha_pending_drop(store, address=None):
    """One address (or all of them) no longer let in as a node being joined."""
    keep = [x for x in ha_pending(store) if address and x.get('address') != address]
    store.set_meta('ha:pending:' + node_name(), json.dumps({'peers': keep}))


def web_helper_path():
    """The root helper beside acme.py (installed), or in the source tree."""
    here = Path(__file__).resolve().parent
    for p in (os.environ.get('ACME_WEB_HELPER'), here / 'acme_web.py',
              here / 'deploy' / 'acme_web.py'):
        if p and Path(p).is_file():
            return Path(p)
    return None


def fw_apply_wait(store, wait=60, run_helper=False):
    """The firewall as it is wanted now, given to the root helper and waited for
    (1.0.210): {'state': 'off' | 'done' | 'failed' | 'no-helper' | 'timeout',
    'said'}. 'off' when acme does not manage this node's firewall, or it is off:
    nothing to open then."""
    want = fw_desired(store)
    if want is None or not want.get('on'):
        return {'state': 'off', 'said': 'the firewall of this node is not managed by acme, or '
                'is off: nothing to open'}
    if not WEB_DIR.is_dir():
        return {'state': 'no-helper', 'said': 'the root helper is not installed here (%s)'
                % WEB_DIR}
    try:
        h = web_hash(web_desired(store))
    except Exception as e:                              # noqa: BLE001
        return {'state': 'failed', 'said': 'what to ask for could not be made: %s' % e}
    end = time.time() + wait
    while True:
        st = web_status()
        if st.get('hash') == h and st.get('state') in ('done', 'failed'):
            said = '; '.join(st.get('said') or [])[:400]
            if st.get('state') == 'done':
                try:
                    fw_now_publish(store)
                except Exception:                       # noqa: BLE001
                    pass
                return {'state': 'done', 'said': said or 'the firewall is as wanted'}
            return {'state': 'failed', 'said': said or 'the root helper said no'}
        if time.time() > end:
            return {'state': 'timeout', 'said': 'the root helper did not apply it in %d s - is '
                    'acme-web.path running?  systemctl status acme-web.path' % wait}
        try:
            web_tick(store)
        except Exception as e:                          # noqa: BLE001
            return {'state': 'failed', 'said': 'it could not be asked for: %s' % e}
        if run_helper and os.geteuid() == 0 and (WEB_DIR / 'request.json').exists():
            # As root on the command line (1.0.210): the helper run here and
            # now, not waited for from its path unit - which may not be there
            # on a machine half set up, and the join went on with it shut.
            helper = web_helper_path()
            if helper:
                try:
                    subprocess.run([sys.executable, '-I', str(helper)], capture_output=True,
                                   timeout=max(30, wait), env=dict(os.environ,
                                                                    ACME_STATE=str(STATE_DIR)))
                except (OSError, subprocess.TimeoutExpired) as e:
                    return {'state': 'failed', 'said': 'the root helper %s: %s' % (helper, e)}
            run_helper = False
            continue
        time.sleep(0.5)


FW_HERE = {'store': None}         # the command line's database, for fw_here_words


def iptables_blocks(src):
    """Whether this machine's own INPUT (iptables-services, not acme's chain)
    ends in a REJECT or a DROP that `src` would meet, read as root (1.0.210):
    the words with the rule that lets it in, or ''."""
    if os.geteuid() != 0 or not shutil.which('iptables'):
        return ''
    fam = 'ip6tables' if ':' in str(src) else 'iptables'
    try:
        lines = subprocess.run([fam, '-S', 'INPUT'], capture_output=True, text=True,
                               timeout=10).stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return ''
    policy_drop = any(x.startswith('-P INPUT') and ('DROP' in x or 'REJECT' in x) for x in lines)
    for x in lines:
        if x.startswith('-A INPUT') and re.search(r'-s %s(/(32|128))? .*-j ACCEPT' %
                                                    re.escape(str(src)), x):
            return ''
        if x.startswith('-A INPUT -j ACME-IN'):
            # acme's chain first: enough when it lets the other node in.
            try:
                chain = subprocess.run([fam, '-S', 'ACME-IN'], capture_output=True, text=True,
                                       timeout=10).stdout.splitlines()
            except (OSError, subprocess.TimeoutExpired):
                chain = []
            if any(re.search(r'-s %s(/(32|128))? .*-j ACCEPT' % re.escape(str(src)), y)
                   for y in chain):
                return ''
        if x.startswith('-A INPUT') and re.search(r'-j (REJECT|DROP)\b', x) and ' -s ' not in x \
                and ' --dport ' not in x:
            return ('this machine\'s iptables (INPUT) %s everything not let in before it: '
                    'iptables -I INPUT 1 -s %s -j ACCEPT  lets the other node in' % (
                        'rejects' if 'REJECT' in x else 'drops', src))
    if policy_drop:
        return ('this machine\'s iptables drops what INPUT does not let in: iptables -I INPUT 1 '
                '-s %s -j ACCEPT  lets the other node in' % src)
    return ''


def iptables_open(src):
    """As root on the command line (1.0.210): the other node let in ahead of
    this machine's own INPUT when that would turn it away and acme's chain
    is not what decides - one rule, live, checked with -C afterwards.
    Returns (ok, words); (True, '') when nothing was needed."""
    if not iptables_blocks(src):
        return True, ''
    fam = 'ip6tables' if ':' in str(src) else 'iptables'
    rule = ['INPUT', '-s', str(src), '-m', 'comment', '--comment', 'acme: the other node (join)',
            '-j', 'ACCEPT']
    try:
        got = subprocess.run([fam, '-I'] + rule[:1] + ['1'] + rule[1:], capture_output=True,
                             text=True, timeout=15)
        there = subprocess.run([fam, '-C'] + rule, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, '%s could not be changed: %s' % (fam, e)
    if got.returncode != 0 or not there:
        return False, ('%s does NOT let %s in: %s - as root:  %s -I INPUT 1 -s %s -j ACCEPT' % (
            fam, src, (got.stderr or '').strip()[-200:] or 'the rule is not there', fam, src))
    return True, ('%s lets %s in: -I INPUT 1 -s %s -j ACCEPT ("acme: the other node (join)") - '
                  'live, not kept over a reboot; acme\'s own firewall (Settings → Firewall) '
                  'keeps the cluster open for good' % (fam, src, src))


def fw_here_words(src, port=5432):
    """What could keep `src` from reaching this node's PostgreSQL, said
    plainly (1.0.210): acme's own chain (ACME-IN) and whether it lets `src`
    in, as the root helper last applied it, and firewalld if it runs here."""
    out = []
    store = HA_STORE.get('store') or FW_HERE.get('store')
    try:
        src_ip = str(plain_ip(str(src), 'address'))
    except ValueError:
        src_ip = str(src or '')
    if store is not None:
        try:
            want = fw_desired(store)
        except Exception:                               # noqa: BLE001
            want = None
        if want and want.get('on'):
            ours = [r for r in want.get('rules') or [] if r.get('source') in (
                src_ip, src_ip + '/32', src_ip + '/128') and r.get('action') == 'accept']
            st = web_status()
            applied = st.get('state') == 'done' and st.get('hash') == web_hash(web_desired(store))
            out.append('acme\'s firewall (ACME-IN) on this node is on and %s %s%s' % (
                'lets' if ours else 'does NOT let', src_ip,
                (' in: -A ACME-IN -s %s -j ACCEPT ("%s")%s' % (
                    src_ip, ours[0].get('note') or '', '' if applied else
                    ' - but the root helper has not applied it yet (%s)' % (
                        '; '.join(st.get('said') or []) or 'acme-web.path not running?')))
                if ours else ' in (Settings → Firewall)'))
        elif want is not None:
            out.append('acme\'s firewall (ACME-IN) on this node is off')
    if shutil.which('firewall-cmd'):
        try:
            on = subprocess.run(['firewall-cmd', '--state'], capture_output=True,
                                timeout=10).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            on = False
        if on:
            out.append('firewalld runs on this node (zone %s): it has to let %s reach TCP %d - '
                       'firewall-cmd --permanent --add-rich-rule=\'rule family="ipv%d" source '
                       'address="%s" port port="%d" protocol="tcp" accept\' && firewall-cmd '
                       '--reload' % (_fw_zone(), src_ip, port, 6 if ':' in src_ip else 4,
                                     src_ip, port))
    blocks = iptables_blocks(src_ip)
    if blocks:
        out.append(blocks)
    return '; '.join(out)


def _fw_zone():
    try:
        return subprocess.run(['firewall-cmd', '--get-default-zone'], capture_output=True,
                              text=True, timeout=10).stdout.strip() or '?'
    except (OSError, subprocess.TimeoutExpired):
        return '?'


def cluster_addresses(store, node):
    """The other nodes' addresses, seen from `node`: what must always get in."""
    me = node_name()
    out = set(x['address'] for x in ha_pending(store, node))
    for n in ha_nodes(store):
        if n['name'] != node and n.get('address') and dbguard_node_ok(store, n['name']):
            out.add(n['address'])
    if CONFIG.get('ha_mode'):
        if node == me and CONFIG.get('ha_peer'):
            out.add(CONFIG['ha_peer'])
        if node != me:
            out.add(CONFIG.get('ha_address') or node_address())
    v = vip_conf(store)
    if v.get('on') and v.get('address'):
        out.add(str(v['address']).split('/')[0])
    good = set()
    for a in out:
        try:
            good.add(str(plain_ip(a, 'address')))
        except ValueError:
            # A host name (ha_peer may be one, 1.0.59): its addresses, not
            # left out of the rules and the lists.
            for ip in addresses_cached(str(a)):
                try:
                    good.add(str(plain_ip(ip, 'address')))
                except ValueError:
                    pass
    return sorted(good)


ADDR_CACHE = {}                   # name: (when, [addresses], asking)


def addresses_cached(name):
    """A host name's addresses (1.0.207): asked of DNS once, then again every ten
    minutes in a thread of its own - asked in the main loop on every turn, a DNS
    that did not answer held it 20 s and more, and the heartbeat with it. The
    first time it is waited for: the firewall's rules are not made without it."""
    def ask():
        got = []
        try:
            got = [info[4][0] for info in
                   socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM)[:4]]
        except (OSError, ValueError, UnicodeError):
            got = ADDR_CACHE.get(name, (0, [], False))[1]
        ADDR_CACHE[name] = (time.monotonic(), got, False)
        return got
    was = ADDR_CACHE.get(name)
    if was is None:
        return ask()
    if time.monotonic() - was[0] > 600 and not was[2]:
        ADDR_CACHE[name] = (was[0], was[1], True)
        threading.Thread(target=ask, name='acme-resolve', daemon=True).start()
    return list(was[1])


def _fam(addr):
    try:
        return ipaddress.ip_network(addr, strict=False).version
    except ValueError:
        return 0


def access_desired(store, node=None):
    """The three lists as nginx gets them: what was set, the cluster added."""
    a = access_conf(store)
    if not a:
        return None
    inner = cluster_addresses(store, node or node_name())
    out = {}
    for k in ACCESS_WORDS:
        one = a.get(k) or {'any': True, 'from': []}
        nets = list(one.get('from') or [])
        if not one.get('any'):
            # The cluster first (1.0.59): a list cut at its length cut the
            # other node and the VIP address off, not one of somebody's.
            nets = list(inner) + [x for x in nets if x not in inner]
        out[k] = {'any': bool(one.get('any')), 'from': nets}
    return out


def fw_auto(store, node):
    """What acme's functions need on `node`: [{key, title, why, fixed, rules}]."""
    peers = cluster_addresses(store, node)
    v = vip_conf(store)
    out = [{'key': 'ssh', 'title': 'SSH', 'why': 'to manage the machine - turned off, '
            'take care to keep a rule of your own for it',
            # The port Settings - SSH server says, and while a change is on
            # trial the one before as well (1.0.163).
            'rules': [{'family': f, 'proto': 'tcp', 'port': str(p), 'source': ''}
                      for p in sshd_ports_open(store) for f in (4, 6)]},
           {'key': 'icmp', 'title': 'ICMP / ICMPv6', 'why': 'ping, and IPv6 cannot work without '
            'ICMPv6 (neighbour discovery)',
            'rules': [{'family': f, 'proto': 'icmp', 'port': '', 'source': ''} for f in (4, 6)]},
           {'key': 'dhcpv6', 'title': 'DHCPv6 client', 'why': 'answers of a DHCPv6 server, for '
            'an address given that way', 'rules': [{'family': 6, 'proto': 'udp', 'port': '546',
                                                     'source': 'fe80::/10'}]}]
    # The pages: from everybody when one of the three is for everybody, else
    # from the networks of the three lists (nginx then says who sees which).
    a = access_conf(store)
    srcs = ['']
    if a and not any((a.get(k) or {}).get('any') for k in ACCESS_WORDS):
        srcs = []
        for k in ACCESS_WORDS:
            for n in (a.get(k) or {}).get('from') or []:
                if n not in srcs:
                    srcs.append(n)
    web = []
    for s in srcs:
        for f in ((4, 6) if not s else (_fam(s),)):
            web.append({'family': f, 'proto': 'tcp', 'port': '80,443', 'source': s})
    acme80 = bool(CONFIG.get('acme')) and \
        (CONFIG.get('acme_challenge') or 'http-01') == 'http-01'
    if '' not in srcs and (acme80 or certs_port80_why(store)):
        # The CA asks from the internet (1.0.209): with the pages kept to some
        # networks, port 80 was too - and no certificate was renewed. Port 80
        # answers the CA's question and sends everything else to HTTPS. The
        # same for the certificate manager: HTTP-01 answered here (a validation
        # "This server") and the CRLs of acme's own authorities (/pki/), which
        # every client checking a certificate fetches - from anywhere.
        for f in (4, 6):
            web.append({'family': f, 'proto': 'tcp', 'port': '80', 'source': ''})
    out.append({'key': 'web', 'title': 'HTTP / HTTPS', 'why': 'the enrolment and '
                'administration pages and the health check; who sees which is under '
                '"Who may reach the pages"', 'rules': web})
    # What a module needs open (its DNS server for DNS-01, say).
    for fn in HOOKS['firewall']:
        try:
            got = list(fn(store, node) or [])
        except Exception as e:                          # noqa: BLE001
            log_sparing('fw-hook', 'a module\'s openings of the firewall: %s' % e, 'warn')
            continue
        for item in got:
            if not item.get('key') or any(x['key'] == item['key'] for x in out):
                continue
            item = dict(item, rules=list(item.get('rules') or []))
            if not item.get('fixed') and item['key'] not in FW_AUTO_OPTIONAL:
                FW_AUTO_OPTIONAL.append(item['key'])
            out.append(item)
    # Time served to the networks set in Settings → Time (1.0.120).
    nc = _meta_json(store, 'ntp:conf') or {}
    if nc.get('manage') and nc.get('allow'):
        out.append({'key': 'ntp', 'title': 'NTP (time served)', 'why': 'this node serves the '
                    'time to the networks set under Settings → Time',
                    'rules': [{'family': _fam(a.split('/')[0]), 'proto': 'udp', 'port': '123',
                               'source': a} for a in nc['allow']]})
    # SNMPv3 (1.0.182): from the networks set, or from everywhere.
    if CONFIG.get('snmp'):
        nets = [w for w in re.split(r'[\s,;]+', str(CONFIG.get('snmp_from') or '')) if w]
        port = str(int(CONFIG.get('snmp_port') or 161))
        out.append({'key': 'snmp', 'title': 'SNMPv3', 'why': 'the monitoring asks each node '
                    '(Settings → Monitoring); from the networks set there only',
                    'rules': [{'family': _fam(n.split('/')[0]), 'proto': 'udp', 'port': port,
                               'source': n} for n in nets] or
                    [{'family': f, 'proto': 'udp', 'port': port, 'source': ''} for f in (4, 6)]})
    # Inside the cluster: always, never turned off. And from a node being
    # joined (1.0.210), before the cluster is made, for as long as it waits.
    pend = ha_pending(store, node)
    if (CONFIG.get('ha_mode') or pend) and peers:
        # Said as waiting only until the node itself is heard from.
        heard = {str(n.get('address') or '') for n in ha_nodes(store) if n['name'] != node}
        pend = [x for x in pend if x['address'] not in heard]
        nodes_only = [p for p in peers if p != str(v.get('address') or '').split('/')[0]]
        out.append({'key': 'cluster', 'title': 'The other node', 'fixed': True,
                    'why': 'replication (PostgreSQL), its pages and the health check - inside '
                    'the cluster everything has to work',
                    'pending': [{'address': x['address'], 'until': x.get('until'),
                                 'why': x.get('why') or ''} for x in pend],
                    # Everything from it (1.0.59): its answers to this node's
                    # own asking came from other ports and were dropped.
                    'rules': [{'family': _fam(p), 'proto': 'any', 'port': '',
                               'source': p} for p in nodes_only]})
        if v.get('on'):
            out.append({'key': 'vrrp', 'title': 'VRRP (the VIP address)', 'fixed': True,
                        'why': 'keepalived of the other node says it is there',
                        'rules': [{'family': _fam(p), 'proto': 'vrrp', 'port': '', 'source': p}
                                  for p in nodes_only]})
    off = set(fw_conf(store).get('off') or [])
    for item in out:
        item['fixed'] = bool(item.get('fixed'))
        item['on'] = item['fixed'] or item['key'] not in off
        for r in item['rules']:
            r.setdefault('note', item['title'])
            r['action'] = 'accept'
    return out


def fw_rules_for(store, node):
    """Everything the chain of `node` holds, in order."""
    c = fw_conf(store)
    auto = fw_auto(store, node)
    # The cluster first (1.0.52): nothing of anybody's can shut the other
    # node out; then the rules of your own; then the rest acme needs.
    rules = [r for item in auto if item['fixed'] for r in item['rules']]
    for r in c.get('rules') or []:
        if r.get('scope', 'all') not in ('all', node) or r.get('disabled'):
            continue
        for f in ((4, 6) if not r.get('family') else (int(r['family']),)):
            if r.get('source') and _fam(r['source']) != f:
                continue
            rules.append({'family': f, 'proto': r.get('proto') or 'any',
                          'port': r.get('port') or '', 'source': r.get('source') or '',
                          'action': r.get('action') or 'accept', 'note': r.get('note') or 'manual'})
    for item in auto:
        if item['on'] and not item['fixed']:
            rules += item['rules']
    return rules


def fw_desired(store):
    c = fw_conf(store)
    if not c.get('set'):
        return None
    return {'on': bool(c.get('on')), 'rules': fw_rules_for(store, node_name()) if c.get('on')
            else []}


FW_PROTOS = ('tcp', 'udp', 'icmp', 'vrrp', 'any')


def fw_rule_checked(b, store):
    """A rule somebody adds by hand, as it is kept."""
    fam = int(b.get('family') or 0)
    if fam not in (0, 4, 6):
        raise ApiError(400, 'IPv4, IPv6 or both')
    proto = str(b.get('proto') or 'any')
    if proto not in FW_PROTOS:
        raise ApiError(400, 'the protocol is one of %s' % ', '.join(FW_PROTOS))
    port = str(b.get('port') or '').replace(' ', '')
    if port:
        if proto not in ('tcp', 'udp'):
            raise ApiError(400, 'a port is for TCP or UDP')
        for p in port.split(','):
            m = re.fullmatch(r'([0-9]{1,5})(?:-([0-9]{1,5}))?', p)    # ASCII only (1.0.61)
            if not m or not 1 <= int(m.group(1)) <= 65535 or \
                    (m.group(2) and not int(m.group(1)) <= int(m.group(2)) <= 65535):
                raise ApiError(400, '%s is not a port or a range (80, 1812-1813, 80,443)' % p)
        if sum(2 if '-' in p else 1 for p in port.split(',')) > 15:
            raise ApiError(400, 'fifteen ports at most in one rule (a range counts as two)')
    src = str(b.get('source') or '').strip()
    if src:
        try:
            net = plain_ip(src, 'network')
        except ValueError:
            raise ApiError(400, '%s is not an address or a network' % src[:60])
        if fam and net.version != fam:
            raise ApiError(400, '%s is not an IPv%d address' % (src, fam))
        src, fam = str(net), net.version
    action = str(b.get('action') or 'accept')
    if action not in ('accept', 'drop', 'reject'):
        raise ApiError(400, 'accept, drop or reject')
    scope = str(b.get('scope') or 'all')
    if scope != 'all' and scope not in {n['name'] for n in ha_nodes(store)} | {node_name()}:
        raise ApiError(400, 'there is no node called %s' % scope)
    note = re.sub(r'[^A-Za-z0-9 ._:/@()+,-]', '', str(b.get('note') or ''))[:80]
    return {'family': fam, 'proto': proto, 'port': port, 'source': src, 'action': action,
            'scope': scope, 'note': note, 'disabled': bool(b.get('disabled'))}


def fw_set(store, by, **changes):
    # On trial (1.0.137): what is there now kept, to come back unless kept.
    try:
        fw_trial_begin(store, by)
    except Exception as e:                              # noqa: BLE001
        log('the firewall change could not be put on trial: %s' % e, 'warn')
    c = fw_conf(store)
    c.update(changes)
    c.update(set=True, at=time.time(), by=by)
    store.set_meta('fw:conf', json.dumps(c))
    return c


def access_checked_api(b):
    out = {}
    for k, words in ACCESS_WORDS.items():
        one = b.get(k) or {}
        nets = []
        raw = one.get('from') or []
        if isinstance(raw, str):
            raw = re.split(r'[\s,;]+', raw)
        for x in raw[:200]:
            x = str(x).strip()
            if not x:
                continue
            try:
                n = str(plain_ip(x, 'network'))
            except ValueError:
                raise ApiError(400, '%s: %s is not an address or a network' % (words, x[:60]))
            if n not in nets:
                nets.append(n)
        if not one.get('any') and not nets:
            raise ApiError(400, '%s would be for nobody: give a network, or let everybody in'
                           % words)
        out[k] = {'any': bool(one.get('any')), 'from': nets}
    try:
        hisec_access(out)                   # 1.0.168
    except ValueError as e:
        raise ApiError(400, str(e))
    return out


