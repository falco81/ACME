"""How busy this node is - the performance meter in the header of the pages (1.0.48, from ai
1.0.72-1.0.76; docs/performance-meter.md). Off unless an account switches it on (Your account):
the pages then ask GET /api/load every 3 s while they are shown, and the details (each core,
the disks, the filesystems, the network cards, the processes) only while a panel is open.
Only the standard library; /proc and /sys read when asked - nothing runs in the background.
A full administrator's only: what the server is doing, and its processes, are said.
"""

# ---- how busy the server is, for the header (otp/ai 1.0.72, here 1.0.48) -------------------------
# CPU, memory, the disks read and written, the network in and out - worked
# out only when a page asks (every 3 s while it is shown), from the kernel's
# counters in /proc: no thread of its own, nothing kept but the last
# counters. Pages asking within the same second share one reading.
# What an account may choose (Your account): the look in the header, 'off' the default - and the
# style of the details opened from it.
HLOAD_LOOKS = ('off', 'graphs', 'pills', 'line', 'rings')
HLOAD_PANELS = ('tiles', 'table', 'map', 'wide', 'off')
LOAD_LOCK = threading.Lock()
LOAD_LAST = {'at': 0.0, 'raw': None, 'out': None}
LOAD_HIST = collections.deque(maxlen=120)        # (at, cpu, mem %, disk B/s, net B/s)


def _load_raw():
    raw = {'at': time.time()}
    try:
        with open('/proc/stat') as f:
            parts = f.readline().split()[1:]
        v = [int(x) for x in parts[:8]] + [0] * (8 - len(parts[:8]))
        raw['cpu_idle'] = v[3] + v[4]
        raw['cpu_all'] = sum(v)
    except (OSError, ValueError):
        pass
    try:
        mem = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, _s, rest = line.partition(':')
                mem[k] = int(rest.split()[0]) * 1024
        raw['mem_total'] = mem.get('MemTotal', 0)
        raw['mem_used'] = mem.get('MemTotal', 0) - mem.get('MemAvailable', mem.get('MemFree', 0))
        raw['swap_used'] = mem.get('SwapTotal', 0) - mem.get('SwapFree', 0)
    except (OSError, ValueError, IndexError):
        pass
    try:
        rd = wr = 0
        whole = set(os.listdir('/sys/block'))
        with open('/proc/diskstats') as f:
            for line in f:
                x = line.split()
                # whole disks only (a partition is in its disk's numbers already),
                # no loop devices, no RAM disks, no device-mapper twice over
                if len(x) < 10 or x[2] not in whole or x[2].startswith(('loop', 'ram', 'dm-', 'zram', 'sr')):
                    continue
                rd += int(x[5]) * 512
                wr += int(x[9]) * 512
        raw['disk_rd'], raw['disk_wr'] = rd, wr
    except (OSError, ValueError):
        pass
    try:
        rx = tx = 0
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, _s, rest = line.partition(':')
                name = name.strip()
                # the cards, not the loopback nor the bridges and pairs of containers
                if not load_nic_counted(name):
                    continue
                x = rest.split()
                rx += int(x[0])
                tx += int(x[8])
        raw['net_rx'], raw['net_tx'] = rx, tx
    except (OSError, ValueError, IndexError):
        pass
    return raw


LOAD_SYS = '/sys'                # the tests point it at a sysfs of their own
LOAD_DETAIL = {'at': 0.0, 'raw': None, 'out': None}


def load_nic_counted(name):
    """A network card counted: not the loopback, not the bridges and pairs of
    containers, not a card that is a slave of a bond (the bond is counted)."""
    if name == 'lo' or name.startswith(('veth', 'docker', 'br-', 'virbr', 'podman', 'cni', 'flannel', 'tun', 'tap',
                                       'vnet', 'ifb', 'dummy', 'lxc', 'kube', 'cali', 'vxlan', 'genev')):
        return False
    master = os.path.join(LOAD_SYS, 'class/net', name, 'master')
    if os.path.islink(master) and os.path.isdir(os.path.join(os.path.realpath(master), 'bonding')):
        return False
    return True


def _read_first(path, default=''):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def load_temps():
    """What the sensors say: {'cpu': [(label, °C)], 'cores': {core n: °C}, 'disks': {name: °C}, 'other': [...]}.
    hwmon first (coretemp, k10temp, zenpower, nvme, drivetemp, acpitz...), then the thermal zones."""
    out = {'cpu': [], 'cores': {}, 'disks': {}, 'other': []}
    base = os.path.join(LOAD_SYS, 'class/hwmon')
    try:
        mons = sorted(os.listdir(base))
    except OSError:
        mons = []
    for m in mons:
        d = os.path.join(base, m)
        chip = _read_first(os.path.join(d, 'name'))
        try:
            files = sorted(f for f in os.listdir(d) if re.match(r'^temp\d+_input$', f))
        except OSError:
            continue
        for f in files:
            n = f.split('_')[0]
            try:
                t = int(_read_first(os.path.join(d, f), 'x')) / 1000.0
            except ValueError:
                continue
            if t <= -40 or t > 150:
                continue
            label = _read_first(os.path.join(d, n + '_label')) or chip
            core = re.match(r'^Core (\d+)$', label)
            if chip in ('coretemp', 'k10temp', 'zenpower', 'cpu_thermal', 'soc_thermal', 'k8temp', 'via_cputemp'):
                if core:
                    out['cores'][int(core.group(1))] = round(t, 1)
                else:
                    out['cpu'].append([label, round(t, 1)])
            elif chip in ('nvme', 'drivetemp'):
                dev = ''
                try:
                    dev = os.path.basename(os.path.realpath(os.path.join(d, 'device')))
                except OSError:
                    pass
                if chip == 'nvme':
                    try:
                        nv = [x for x in os.listdir(os.path.join(d, 'device')) if re.match(r'^nvme\d+n\d+$', x)]
                        dev = nv[0] if nv else dev
                    except OSError:
                        pass
                elif chip == 'drivetemp':
                    try:
                        blk = os.listdir(os.path.join(d, 'device', 'block'))
                        dev = blk[0] if blk else dev
                    except OSError:
                        pass
                if label.lower() in ('composite', chip, '') or dev not in out['disks']:
                    out['disks'][dev or chip] = round(t, 1)
            else:
                out['other'].append([chip + (' ' + label if label != chip else ''), round(t, 1)])
    if not out['cpu'] and not out['cores']:
        tz = os.path.join(LOAD_SYS, 'class/thermal')
        try:
            zones = sorted(z for z in os.listdir(tz) if z.startswith('thermal_zone'))
        except OSError:
            zones = []
        for z in zones:
            kind = _read_first(os.path.join(tz, z, 'type'))
            try:
                t = int(_read_first(os.path.join(tz, z, 'temp'), 'x')) / 1000.0
            except ValueError:
                continue
            if -40 < t < 150:
                (out['cpu'] if re.search(r'cpu|x86_pkg|soc|core', kind, re.I) else out['other']).append(
                    [kind, round(t, 1)])
    return out


def _load_detail_raw():
    raw = {'at': time.time(), 'cores': {}, 'disks': {}, 'nics': {}, 'procs': {}}
    try:
        with open('/proc/stat') as f:
            for line in f:
                m = re.match(r'^cpu(\d+)\s+(.*)$', line)
                if m:
                    v = [int(x) for x in m.group(2).split()[:8]]
                    raw['cores'][int(m.group(1))] = (v[3] + v[4], sum(v))
    except (OSError, ValueError):
        pass
    try:
        whole = set(os.listdir(os.path.join(LOAD_SYS, 'block')))
        with open('/proc/diskstats') as f:
            for line in f:
                x = line.split()
                if len(x) < 13 or x[2] not in whole or x[2].startswith(('loop', 'ram', 'zram', 'sr')):
                    continue
                raw['disks'][x[2]] = (int(x[5]) * 512, int(x[9]) * 512, int(x[12]))
    except (OSError, ValueError):
        pass
    try:
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, _s, rest = line.partition(':')
                name = name.strip()
                if load_nic_counted(name):
                    x = rest.split()
                    raw['nics'][name] = (int(x[0]), int(x[8]))
    except (OSError, ValueError, IndexError):
        pass
    tick = os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100
    page = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open('/proc/%s/stat' % pid) as f:
                st = f.read()
            name = st[st.index('(') + 1:st.rindex(')')]
            rest = st[st.rindex(')') + 2:].split()
            raw['procs'][int(pid)] = (name[:40], (int(rest[11]) + int(rest[12])) / float(tick), int(rest[21]) * page)
        except (OSError, ValueError, IndexError):
            continue
    return raw


def load_detail():
    """What the header's panels show when opened: each core, its frequency and
    temperature, the disks one by one and the filesystems, the cards one by one,
    the processes taking most - read only while a panel is open."""
    with LOAD_LOCK:
        now = time.time()
        if LOAD_DETAIL['out'] and now - LOAD_DETAIL['at'] < 1.0:
            return LOAD_DETAIL['out']
        raw = _load_detail_raw()
        was = LOAD_DETAIL['raw'] or {}
        if not was or now - was.get('at', 0) > 30:
            # the first look (or one long after the last): two readings a
            # moment apart, so the panel opens with numbers, not dots
            was = raw
            time.sleep(0.3)
            raw = _load_detail_raw()
        dt = max(0.2, raw['at'] - was.get('at', raw['at'] - 1)) if was else None
        temps = load_temps()
        cores = []
        for n in sorted(raw['cores']):
            idle, allc = raw['cores'][n]
            busy = None
            if dt and n in was.get('cores', {}):
                pi, pa = was['cores'][n]
                if allc > pa:
                    busy = round(max(0.0, min(1.0, 1 - (idle - pi) / float(allc - pa))) * 100, 1)
            mhz = _read_first(os.path.join(LOAD_SYS, 'devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq' % n))
            cores.append({'n': n, 'busy': busy, 'mhz': round(int(mhz) / 1000) if mhz.isdigit() else None,
                          'temp': temps['cores'].get(n)})
        if cores and not any(c['mhz'] for c in cores):
            try:
                with open('/proc/cpuinfo') as f:
                    mh = [float(x.split(':')[1]) for x in f if x.startswith('cpu MHz')]
                for c, m in zip(cores, mh):
                    c['mhz'] = round(m)
            except (OSError, ValueError, IndexError):
                pass
        model = ''
        try:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if line.startswith(('model name', 'Hardware', 'Model')):
                        model = line.split(':', 1)[1].strip()
                        break
        except OSError:
            pass
        disks = []
        for name, (rd, wr, ms) in sorted(raw['disks'].items()):
            one = {'name': name, 'temp': temps['disks'].get(name),
                   'size': int(_read_first(os.path.join(LOAD_SYS, 'block', name, 'size'), '0') or 0) * 512,
                   'model': _read_first(os.path.join(LOAD_SYS, 'block', name, 'device/model'))}
            if dt and name in was.get('disks', {}):
                prd, pwr, pms = was['disks'][name]
                one['rd'] = max(0, round((rd - prd) / dt))
                one['wr'] = max(0, round((wr - pwr) / dt))
                one['util'] = round(max(0.0, min(100.0, (ms - pms) / (dt * 10.0))), 1)
            disks.append(one)
        fss = []
        seen = set()
        try:
            with open('/proc/mounts') as f:
                for line in f:
                    dev, mnt, kind = line.split()[:3]
                    if kind in ('proc', 'sysfs', 'tmpfs', 'devtmpfs', 'devpts', 'cgroup', 'cgroup2', 'overlay',
                                'squashfs', 'mqueue', 'debugfs', 'tracefs', 'securityfs', 'pstore', 'bpf', 'autofs',
                                'fusectl', 'configfs', 'hugetlbfs', 'binfmt_misc', 'efivarfs', 'nsfs', 'ramfs',
                                'rpc_pipefs', 'selinuxfs', 'fuse.lxcfs', 'iso9660') or dev in seen:
                        continue
                    if not dev.startswith('/') and kind not in ('nfs', 'nfs4', 'cifs', 'smb3', 'zfs', 'btrfs'):
                        continue
                    seen.add(dev)
                    try:
                        sv = os.statvfs(mnt)
                    except OSError:
                        continue
                    total = sv.f_blocks * sv.f_frsize
                    if not total:
                        continue
                    free = sv.f_bavail * sv.f_frsize
                    fss.append({'mount': mnt, 'dev': dev, 'kind': kind, 'total': total, 'used': total - sv.f_bfree * sv.f_frsize,
                                'free': free})
        except OSError:
            pass
        nics = []
        for name, (rx, tx) in sorted(raw['nics'].items()):
            sp = _read_first(os.path.join(LOAD_SYS, 'class/net', name, 'speed'))
            one = {'name': name, 'state': _read_first(os.path.join(LOAD_SYS, 'class/net', name, 'operstate')),
                   'speed': int(sp) if sp.lstrip('-').isdigit() and int(sp) > 0 else None, 'rx_all': rx, 'tx_all': tx}
            if dt and name in was.get('nics', {}):
                one['rx'] = max(0, round((rx - was['nics'][name][0]) / dt))
                one['tx'] = max(0, round((tx - was['nics'][name][1]) / dt))
            nics.append(one)
        procs = []
        for pid, (name, cpu_s, rss) in raw['procs'].items():
            p = {'pid': pid, 'name': name, 'rss': rss}
            if dt and pid in was.get('procs', {}):
                p['cpu'] = round(max(0.0, (cpu_s - was['procs'][pid][1]) / dt) * 100, 1)
            procs.append(p)
        mem = {}
        try:
            with open('/proc/meminfo') as f:
                for line in f:
                    k, _s, rest = line.partition(':')
                    mem[k] = int(rest.split()[0]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        up = 0.0
        try:
            up = float(_read_first('/proc/uptime', '0').split()[0])
        except ValueError:
            pass
        out = {'cores': cores, 'model': model, 'temps': temps, 'disks': disks, 'filesystems': fss, 'nics': nics,
               'top_cpu': sorted([p for p in procs if p.get('cpu')], key=lambda p: -p['cpu'])[:6],
               'top_mem': sorted(procs, key=lambda p: -p['rss'])[:6], 'uptime': up,
               'mem': {k: mem.get(v) for k, v in (('total', 'MemTotal'), ('available', 'MemAvailable'),
                                                  ('cached', 'Cached'), ('buffers', 'Buffers'),
                                                  ('swap_total', 'SwapTotal'), ('swap_free', 'SwapFree'),
                                                  ('shared', 'Shmem'))},
               'procs': len(procs)}
        LOAD_DETAIL.update(at=now, raw=raw, out=out)
        return out


def server_load():
    """{cpu %, mem used/total, disk read/write B/s, net in/out B/s, load}."""
    with LOAD_LOCK:
        now = time.time()
        if LOAD_LAST['out'] and now - LOAD_LAST['at'] < 1.0:
            return LOAD_LAST['out']
        raw = _load_raw()
        was = LOAD_LAST['raw']
        out = {'at': now, 'cores': os.cpu_count() or 1, 'mem_total': raw.get('mem_total'),
               'mem_used': raw.get('mem_used'), 'swap_used': raw.get('swap_used')}
        try:
            out['load'] = [round(x, 2) for x in os.getloadavg()]
        except OSError:
            out['load'] = None
        if was:
            dt = max(0.2, raw['at'] - was['at'])

            def rate(k):
                if k in raw and k in was and raw[k] >= was[k]:
                    return round((raw[k] - was[k]) / dt)
                return None
            if raw.get('cpu_all') and was.get('cpu_all') and raw['cpu_all'] > was['cpu_all']:
                busy = 1 - (raw['cpu_idle'] - was['cpu_idle']) / float(raw['cpu_all'] - was['cpu_all'])
                out['cpu'] = round(max(0.0, min(1.0, busy)) * 100, 1)
            for k in ('disk_rd', 'disk_wr', 'net_rx', 'net_tx'):
                out[k] = rate(k)
            out['over_s'] = round(dt, 1)
        LOAD_LAST.update(at=now, raw=raw, out=out)
        if out.get('cpu') is not None:
            # The last two minutes of what was read (1.0.48), for a page loaded again (F5) or
            # opened beside: its graphs go on from them, not drawn from nothing. Only readings
            # made because a page asked - nothing is read for it.
            mt = out.get('mem_total') or 0
            LOAD_HIST.append((now, out['cpu'], 100.0 * (out.get('mem_used') or 0) / mt if mt else 0,
                              (out.get('disk_rd') or 0) + (out.get('disk_wr') or 0),
                              (out.get('net_rx') or 0) + (out.get('net_tx') or 0)))
        return out


def load_history(span=125):
    """{cpu, mem, disk, net: [...]} of the readings of the last `span` seconds, oldest first -
    at most one each 2.5 s (as the pages ask every 3 s), 40 of each."""
    t = time.time()
    with LOAD_LOCK:
        rows = [r for r in LOAD_HIST if t - r[0] <= span]
    picked, last = [], 0.0
    for r in rows:
        if r[0] - last >= 2.5:
            picked.append(r)
            last = r[0]
    picked = picked[-40:]
    return {'cpu': [r[1] for r in picked], 'mem': [round(r[2], 1) for r in picked],
            'disk': [r[3] for r in picked], 'net': [r[4] for r in picked],
            'from': picked[0][0] if picked else None}


def api_load(detail=False, hist=False):
    """GET /api/load (full administrators only): the summary; with ?detail=1 also the details,
    with ?hist=1 the last two minutes read (a page loaded anew)."""
    out = dict(server_load())
    if detail:
        out['detail'] = load_detail()
    if hist:
        out['hist'] = load_history()
    return out


@route('GET', '/api/load')
def _load(h):
    h.me('fulladmin')
    out = api_load(detail=h.arg('detail') in ('1', 'true', 'yes'),
                   hist=h.arg('hist') in ('1', 'true', 'yes'))
    out['node'] = node_name()
    return out
