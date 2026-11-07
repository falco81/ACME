# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the machine's network, its name, and switching it off (1.0.119) ------------------
# Settings → Network: each node's IPv4 address, gateway, DNS, host name and -
# switched on - IPv6, set from the pages of either node. Settings → Restart and
# power off: a reboot or a power-off of one node, the other or both.
#
# Who does what. The page asks through whichever node answers it (the web
# address, or a node's own address); what is asked is written into the
# database for the node it is about - 'net:want:NODE' or 'power:plan' - and
# that node's daemon does it, writing how far it got into a row only it
# writes ('net:job:NODE', 'power:node:NODE'). Replication brings both to the
# other node, so either node's pages show the progress, and a page whose node
# restarts goes on with the other - or waits for its own to come back.
#
# A new address in a cluster is done in this order, so nothing is cut off:
#   1. the other node is told the new address (ha_readdress): its pg_hba.conf,
#      its subscription and its ha_peer move to it - it waits for this node
#      there;
#   2. this node's ha_address, its own settings that name the old address or
#      name (SNMP's address, the mail greeting, the isemon name), and its
#      self-made certificate are made again with the new ones;
#   3. maintenance: the VIP address goes to the other node;
#   4. NetworkManager, the host name and /etc/hosts, then a reboot;
#   5. back up: the new address checked, the link between the databases made
#      again for it (hatls), replication both ways, keepalived and nginx
#      rewritten from the database (web_tick) - then out of maintenance.
NET_ASK_NAME = 'net.ask'
NET_ANSWER_NAME = 'net.json'
NET_READ_S = 300                # how often each node says what its network is
NET_JOB_LIVE_S = 1800           # a job not moving for this long is over
NET_WORK = {'busy': False, 'read_at': 0.0}
NET_WORK_LOCK = threading.Lock()


def boot_time():
    """When this machine started (the kernel's btime) - a restart of the
    service is not a reboot."""
    fake = os.environ.get('ACME_BTIME_FILE')         # tests: a reboot without one
    if fake:
        try:
            return float(Path(fake).read_text().strip() or 0)
        except (OSError, ValueError):
            pass
    try:
        with open('/proc/stat') as f:
            for line in f:
                if line.startswith('btime '):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


NET_ROOT_LOCK = threading.Lock()


def net_root(data, wait=60):
    """One request to the root helper (acme_web.py) and its answer - one at a
    time (1.0.146): "Read it again" on the pages during a job wrote over the
    job's request, or took its answer, and the job waited for nothing."""
    if not WEB_DIR.is_dir():
        # said as root_ask says it (1.0.52), not a 500 from os.open
        raise FileNotFoundError('the root helper is not set up on this node (no %s) - install.sh '
                                'puts it in' % WEB_DIR)
    with NET_ROOT_LOCK:
        ask_id = secrets.token_hex(8)
        data = dict(data, id=ask_id)
        tmp = WEB_DIR / ('.%s.%s' % (NET_ASK_NAME, secrets.token_hex(6)))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(data))
        os.replace(str(tmp), str(WEB_DIR / NET_ASK_NAME))
        end = time.time() + wait
        while time.time() < end:
            try:
                got = json.loads((WEB_DIR / NET_ANSWER_NAME).read_text())
            except (OSError, ValueError):
                got = None
            if isinstance(got, dict) and got.get('id') == ask_id:
                if not got.get('ok'):
                    raise ValueError(got.get('said') or 'the root helper said no')
                return got.get('data') or {}
            time.sleep(0.4)
    raise ValueError('the root helper of this node did not answer in %d s - is acme-web.path '
                     'running?  systemctl status acme-web.path' % wait)


def net_publish(store):
    """This node's network as root reads it, into the database for the pages
    of either node."""
    data = net_root({'do': 'read'}, 30)
    now = {'at': time.time(), 'data': data, 'boot': boot_time(),
           'snmp_bind': str(CONFIG.get('snmp_bind') or ''),
           'ha_address': str(CONFIG.get('ha_address') or ''),
           'node_name_pinned': bool(str(FILE_CONFIG.get('node_name') or '').strip())}
    store.set_meta('net:now:' + node_name(), json.dumps(now))
    NET_WORK['read_at'] = time.time()
    return now


# ---- what is asked, checked ---------------------------------------------------------
def _net_list(v, most=4):
    if isinstance(v, str):
        v = re.split(r'[\s,;]+', v)
    return [str(x).strip() for x in (v or []) if str(x).strip()][:most]


def net_node_now(store, node):
    return _meta_obj(store, 'net:now:' + node)


def net_current_ip(now):
    """This node's IPv4 address as NetworkManager has it (or the one on its
    default route)."""
    d = now.get('data') or {}
    conf = d.get('conf') or {}
    for a in conf.get('ipv4_addresses') or []:
        return str(a)
    dev = d.get('dev')
    for a in (d.get('live') or {}).get('addrs4') or []:
        if not dev or a.get('dev') == dev:
            return str(a.get('addr') or '')
    return ''


def net_check(store, node, want, rollback=False):
    """What the page asked for, made whole and checked against the node as it
    said it is; with the plan in words. Raises ValueError."""
    now = net_node_now(store, node)
    d = now.get('data') or {}
    if not d:
        raise ValueError('%s has not said what its network is yet - press Read it again and '
                         'wait a few seconds' % node)
    if not d.get('nm'):
        raise ValueError('NetworkManager (nmcli) is not on %s: its network is set by hand '
                         'there' % node)
    con = str(want.get('con') or d.get('con') or '')
    if not con or con not in [x.get('con') for x in d.get('devices') or []]:
        raise ValueError('which connection of %s? It has: %s' % (node, ', '.join(
            '%s (%s)' % (x.get('con'), x.get('dev')) for x in d.get('devices') or []
            if x.get('con')) or 'none'))
    v4 = want.get('ipv4') or {}
    try:
        a4 = ipaddress.ip_interface(str(v4.get('addr') or '').strip())
    except ValueError:
        raise ValueError('the IPv4 address is an address with its prefix: 192.0.2.10/24')
    if a4.version != 4 or '/' not in str(v4.get('addr')):
        raise ValueError('the IPv4 address is an address with its prefix: 192.0.2.10/24')
    if (a4.ip.is_loopback and not os.environ.get('ACME_NET_LOOPBACK_OK')) or \
            a4.ip.is_multicast or a4.ip.is_unspecified or \
            (a4.network.prefixlen < 31 and a4.ip in (a4.network.network_address,
                                                     a4.network.broadcast_address)):
        # /31 and /32 have no network or broadcast address of their own (1.0.209).
        raise ValueError('%s cannot be the address of a machine in %s' % (a4.ip, a4.network))
    gw = str(v4.get('gw') or '').strip()
    if gw:
        try:
            g = ipaddress.ip_address(gw)
        except ValueError:
            g = None
            if not rollback:
                raise ValueError('the gateway is one IPv4 address')
        if g is None or g.version != 4:
            # Going back is never refused for its gateway (1.0.56): what the
            # node had is put back as it was - an on-link gateway outside the
            # subnet too; one that is no IPv4 address at all is left out.
            if not rollback:
                raise ValueError('the gateway %s is not another address in %s' % (g, a4.network))
            gw = ''
        elif not rollback and (g not in a4.network or g == a4.ip):
            raise ValueError('the gateway %s is not another address in %s' % (g, a4.network))
    dns = _net_list(v4.get('dns'))
    if rollback:
        # Nor for a DNS server (1.0.56): one that is no IPv4 address left out.
        dns = [x for x in dns if _net_ip(x, 4)]
    for x in dns:
        try:
            d4 = ipaddress.ip_address(x)
        except ValueError:
            raise ValueError('%r is not the address of a DNS server' % x)
        if d4.version != 4:
            # The IPv4 side's servers are IPv4 ones (1.0.209): root refused the
            # whole change for an IPv6 one put here.
            raise ValueError('%s is an IPv6 address - put it with the IPv6 DNS servers' % x)
    search = _net_list(v4.get('search'), 6)
    v6 = want.get('ipv6') or {}
    on6 = bool(v6.get('on'))
    mode6 = 'off'
    a6 = None
    if on6:
        mode6 = 'manual' if str(v6.get('mode') or 'manual') == 'manual' else 'auto'
        if mode6 == 'manual':
            try:
                a6 = ipaddress.ip_interface(str(v6.get('addr') or '').strip())
            except ValueError:
                raise ValueError('the IPv6 address is an address with its prefix: '
                                 '2001:db8::10/64')
            if a6.version != 6 or a6.ip.is_link_local or '/' not in str(v6.get('addr')):
                raise ValueError('the IPv6 address is a global one with its prefix: '
                                 '2001:db8::10/64')
        g6 = str(v6.get('gw') or '').strip()
        if g6 and not _net_ip(g6, 6):
            if not rollback:
                raise ValueError('the IPv6 gateway is one IPv6 address')
            g6 = ''                     # going back: left out (1.0.56)
    dns6 = _net_list(v6.get('dns')) if on6 else []
    if rollback:
        dns6 = [x for x in dns6 if _net_ip(x)]
    for x in dns6:
        try:
            ipaddress.ip_address(x)
        except ValueError:
            raise ValueError('%r is not the address of a DNS server' % x)
    host = str(want.get('hostname') or '').strip().rstrip('.').lower()
    if len(host) > 64:
        raise ValueError('a host name is 64 characters at most (hostnamectl takes no more)')
    # The name the node has now, kept as it is, may be a short one - and going
    # back after a trial asks for the old one again: refused, the new network
    # stayed (1.0.139). Still a name, one part or more.
    same = rollback or host == str(d.get('hostname') or '').strip().rstrip('.').lower()
    if not re.match(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)%s$' % ('*' if same else '+'), host):
        raise ValueError('the host name is the whole name: acme1.example.cz')
    old_ip = net_current_ip(now).split('/')[0]
    new_ip = str(a4.ip)
    conf = d.get('conf') or {}
    # The IPv6 addresses set by hand now, without prefix (1.0.56): the node's
    # own certificate names them, and they go when the change takes them away.
    old_ip6 = []
    if conf.get('ipv6_method') == 'manual':
        for x in conf.get('ipv6_addresses') or []:
            k = _cert_name_key(str(x).split('/')[0])
            if k and k not in old_ip6:
                old_ip6.append(k)
    many = bool(CONFIG.get('ha_mode'))
    if not rollback and CONFIG.get('ha_mode') == 'replicated':
        # Replication over IPv6 (1.0.56): the other node is told only the new
        # IPv4 address - an IPv6 change that takes away the address the nodes
        # replicate over would cut them apart.
        rep6 = str(CONFIG.get('ha_address' if node == node_name() else 'ha_peer') or '')
        k6 = _cert_name_key(rep6)
        if ':' in k6 and k6 in old_ip6 and not (a6 and _cert_name_key(str(a6.ip)) == k6):
            raise ValueError('the nodes replicate over %s, which this change takes away from %s: '
                             'change the addresses of the two nodes first (Settings → High '
                             'availability → The addresses of the two nodes)' % (rep6, node))
    others = [n for n in ha_nodes(store) if n['name'] != node]
    for n in others:
        if str(n.get('address') or '') == new_ip:
            raise ValueError('%s is the address of %s' % (new_ip, n['name']))
    v = vip_conf(store)
    if v.get('on') and many:
        try:
            vnet = ipaddress.ip_interface(v.get('address'))
        except ValueError:
            vnet = None
        if vnet and vnet.ip == a4.ip:
            raise ValueError('%s is the VIP address of the cluster' % new_ip)
        if vnet and vnet.ip not in a4.network and not want.get('vip_elsewhere'):
            raise ValueError('the VIP address %s is not in %s: the node could not hold it. '
                             'Change the VIP address first (High availability), or tick that '
                             'it is meant to be so' % (vnet.ip, a4.network))
    plan = []
    ip_changed = bool(old_ip) and old_ip != new_ip
    host_old = str(d.get('hostname') or '')
    was6 = conf.get('ipv6_method') not in (None, '', 'disabled', 'ignore')
    if ip_changed and many and CONFIG.get('ha_mode') == 'replicated' and \
            net_ha_on_old(old_ip, None if node == node_name() else
                          str(now.get('ha_address') or '')):
        plan.append('the other node is told %s: its pg_hba.conf, its subscription and its '
                    'ha_peer move to it' % new_ip)
    if ip_changed:
        plan.append('this node\'s settings that name %s - and its own certificate, where it was '
                    'made here - are made again for %s' % (old_ip, new_ip))
    if host and host != host_old:
        plan.append('the host name %s → %s (the node keeps its name in acme: %s)'
                    % (host_old or '?', host, node))
    if on6 != was6:
        plan.append('IPv6 %s' % ('on' if on6 else 'off'))
    if many:
        plan.append('maintenance on %s - the VIP address goes to the other node' % node)
    plan.append('NetworkManager (%s): %s via %s, DNS %s%s' % (
        con, a4, gw or 'no gateway', ', '.join(dns) or 'none',
        '' if not on6 else ', IPv6 %s' % (a6 if a6 else 'automatic')))
    plan.append('a reboot of %s; back up, it checks the new address%s and comes out of '
                'maintenance by itself' % (node, ', replication and the link between the '
                                           'databases' if many else ''))
    return {'con': con, 'dev': next((x.get('dev') for x in d.get('devices') or []
                                     if x.get('con') == con), ''),
            'ipv4': {'addr': str(a4), 'gw': gw, 'dns': dns, 'search': search},
            'ipv6': {'on': on6, 'mode': mode6, 'addr': str(a6) if a6 else '',
                     'gw': g6 if on6 else '', 'dns': dns6},
            'hostname': host, 'old_ip': old_ip, 'new_ip': new_ip, 'old_hostname': host_old,
            'old_ip6': old_ip6,
            'ip_changed': ip_changed, 'was6': was6, 'plan': plan}


def _net_ip(text, version=None):
    """`text` one address (of that IP version) - True/False."""
    try:
        a = ipaddress.ip_address(str(text or '').strip())
    except ValueError:
        return False
    return version is None or a.version == version


def net_ha_on_old(old_ip, had=None):
    """Replication on the address the change takes away (1.0.56): this
    node's ha_address empty (the address it has) or that very address. On a
    second address (one kept by the change), the other node is not told the
    new primary one - nor is ha_address moved to it. `had`: another node's
    ha_address as it says it; None: this node's."""
    had = str((CONFIG.get('ha_address') if had is None else had) or '').strip()
    return not had or (bool(old_ip) and _cert_name_key(had) == _cert_name_key(old_ip))


def net_others_held(store, node):
    """Why `node` may not go out of service now (1.0.56) - [] when it may: a
    network change in a cluster puts it in maintenance and restarts it, and it
    was asked while the other node was in maintenance or stepped aside, so the
    whole service stopped. Held only by another node heard from (a fresh
    heartbeat) but out of service, or by another node's network being changed
    or on trial (as a restart is) - a dead or absent node never holds it:
    re-addressing is how a node whose partner died is put right."""
    if not CONFIG.get('ha_mode'):
        return []
    out = []
    for n in ha_nodes(store):
        name = n['name']
        if name == node:
            continue
        job = _meta_obj(store, 'net:job:' + name)
        if net_job_active(job) or (job.get('state') == 'trial' and (
                n.get('alive') or
                time.time() < float(job.get('trial_until') or 0) + NET_JOB_LIVE_S)):
            out.append('the network of %s is being changed or is on trial - keep it (or let it '
                       'go back) first' % name)
        elif n.get('alive') and (beat_aside(n) or maintenance_row(store, name).get('on')):
            out.append('%s answers but is out of service (maintenance, or stepped aside): '
                       'the VIP address would have nowhere to go' % name)
    return out


def net_job_active(job):
    return bool(job) and job.get('state') in ('asked', 'running', 'rebooting') and \
        time.time() - float(job.get('moved') or job.get('at') or 0) < NET_JOB_LIVE_S


def net_ask(store, node, want, by, rollback=False, maint=False, snap=''):
    """The page asks: written for the node, which does it. `rollback`: the
    old network asked back by the node itself - not put on trial again."""
    if net_job_active(_meta_json(store, 'net:job:' + node)):
        raise ValueError('%s is changing its network already' % node)
    if power_busy(store):
        raise ValueError('a restart or a power-off is under way')
    checked = net_check(store, node, want, rollback=rollback)
    if not rollback:
        # Going back is never refused (1.0.56).
        held = net_others_held(store, node)
        if held:
            raise ValueError('not now: %s' % '; '.join(held))
    ask = {'id': secrets.token_hex(6), 'node': node, 'want': checked, 'by': by,
           'at': time.time(), 'from': node_name(), 'rollback': bool(rollback),
           'maint': bool(maint), 'snap': str(snap or '')}
    store.set_meta('net:want:' + node, json.dumps(ask))
    store.add_event('settings', '%s asked %s for a new network: %s' % (
        by, node, '; '.join(checked['plan'])), 'warn', who=by)
    return ask


