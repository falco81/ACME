# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the local firewall and who may reach which pages (1.0.52) -------------------------
# Kept for the whole cluster in meta, put in by each node's root helper with
# the rest of the web side (one request, one status). What acme's functions
# need is worked out here from what is set up; the rules somebody adds by
# hand come first, so a DROP or REJECT of theirs wins over what acme opens.
FW_AUTO_OPTIONAL = ('ssh', 'icmp', 'dhcpv6', 'web', 'radius', 'ntp')
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


def cluster_addresses(store, node):
    """The other nodes' addresses, seen from `node`: what must always get in."""
    me = node_name()
    out = set()
    for n in ha_nodes(store):
        if n['name'] != node and n.get('address'):
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
    if '' not in srcs and CONFIG.get('acme') and \
            (CONFIG.get('acme_challenge') or 'http-01') == 'http-01':
        # The CA asks from the internet (1.0.209): with the pages kept to some
        # networks, port 80 was too - and no certificate was renewed. Port 80
        # answers the CA's question and sends everything else to HTTPS.
        for f in (4, 6):
            web.append({'family': f, 'proto': 'tcp', 'port': '80', 'source': ''})
    out.append({'key': 'web', 'title': 'HTTP / HTTPS', 'why': 'the enrolment and '
                'administration pages and the health check; who sees which is under '
                '"Who may reach the pages"', 'rules': web})
    ports = str(int(CONFIG.get('radius_auth_port') or 1812))
    if int(CONFIG.get('radius_acct_port') or 0):
        ports += ',%d' % int(CONFIG.get('radius_acct_port'))
    rad = []
    for c in store.clients():
        if not c.get('enabled'):
            continue
        try:
            net = address_net(c['address'])
        except (ValueError, KeyError):
            continue
        if net is None:
            continue
        rad.append({'family': net.version, 'proto': 'udp', 'port': ports, 'source': str(net),
                    'note': 'RADIUS %s' % c.get('name', '')})
    out.append({'key': 'radius', 'title': 'RADIUS', 'why': 'from each RADIUS client set up '
                '(Clients), and only from them', 'rules': rad})
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
    # Inside the cluster: always, never turned off.
    if CONFIG.get('ha_mode') and peers:
        nodes_only = [p for p in peers if p != str(v.get('address') or '').split('/')[0]]
        out.append({'key': 'cluster', 'title': 'The other node', 'fixed': True,
                    'why': 'replication (PostgreSQL), its pages and the health check - inside '
                    'the cluster everything has to work',
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


