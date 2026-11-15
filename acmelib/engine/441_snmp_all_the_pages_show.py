# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- SNMP: all the pages show of a node (1.0.108) ------------------------------------------
# What Settings, the Overview and the cards say of each node, as objects of ACME-MIB of their
# own (deploy/ACME-MIB.txt) - not only as samples of acmeMetricTable: this node's machine
# (acmeSystem: its disks, processors, memory, clock, SELinux, firewall, the updates of the
# system), its backups (acmeBackup), the sign-ins (acmeSignIn: accounts, lockouts, Windows and
# certificates, the CRLs), where the logs, mails and codes go (acmeServices), more of acme
# itself, its database and the cluster. Read once for SNMP and Prometheus alike (snmp_facts,
# 10 s), every part on its own: one that fails leaves the others answered.
SNMP_FACTS = {'at': 0.0, 'got': None, 'raw': None, 'lock': threading.Lock()}
SNMP_FACTS_S = 10.0
# Subtrees of acme a module may not answer under (HOOKS['snmp']): the engine's.
SNMP_ENGINE_PARTS = (1, 3, 5, 7, 9, 10, 11, 12, 13, 20)
SNMP_LEVELS = {'ok': 0, 'info': 1, 'warn': 2, 'bad': 3}
SNMP_RESULT = {None: 0, True: 1, False: 2}
SNMP_SELINUX = {'': 0, 'absent': 1, 'disabled': 2, 'permissive': 3, 'enforcing': 4}
SNMP_VRRP = {'': 0, 'MASTER': 1, 'BACKUP': 2, 'FAULT': 3}


def _sf_int(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return default


def _sf_i32(v):
    return max(-2147483648, min(2147483647, _sf_int(v)))


def _sf_part(out, name, fn):
    """One part of the facts: {} when it cannot be told, said in the log now and then."""
    try:
        out[name] = fn() or {}
    except Exception as e:                              # noqa: BLE001
        out[name] = {}
        log_sparing('snmp-facts-' + name, 'SNMP, %s: %s' % (name, e), 'warn', every=900)


def _sf_info(daemon, store):
    on = online_view(store).get('online') or {}
    newest = str((on.get('newest') or {}).get('version') or '')
    return {'newest': newest, 'newer': bool(on.get('newer')), 'checked': _sf_int(on.get('at')),
            'started': _sf_int(getattr(daemon, 'started', 0)),
            'maintenance': bool(maintenance_now(store).get('on')),
            'lead': bool(alerts_lead(store))}


def _sf_db(store, health):
    on = globals().get('dbguard_on')
    return {'size': max(0, _sf_int(store.db.size())),
            'guard': bool(CONFIG.get('db_guard')) or bool(on and on()),
            'refused': len(health.get('dbguard_refused') or []),
            'trouble': str(health.get('db_trouble') or '')[:255]}


def _sf_cluster(store):
    nodes = ha_nodes(store) if CONFIG.get('ha_mode') else []
    v = vip_conf(store)
    holders = [n['name'] for n in nodes if n.get('alive') and ((n.get('web') or {}).get('vip_here'))]
    if not nodes and v.get('on'):
        try:
            if vip_here(v.get('address')):
                holders = [node_name()]
        except Exception:                               # noqa: BLE001
            pass
    rep = ha_repl_state(store) if CONFIG.get('ha_mode') == 'replicated' else {}
    if rep.get('mode') == 'replicated' and (rep.get('incoming') or rep.get('outgoing') or
                                            rep.get('trouble')):
        repl = 3 if rep.get('lost') else (1 if rep.get('healthy') else 2)
    else:
        repl = 0
    split = 0
    role = ''
    if split_active():
        split = 2 if split_apart() else 1
        role = str(SPLIT.get('role') or '') if split == 2 else ''
    lead = ''
    try:
        r = sys.modules.get('acmelib.certs.renewer')
        lead = str((r.leader(store) or {}).get('node') or '') if r is not None else ''
    except Exception:                                   # noqa: BLE001
        lead = ''
    return {'mode': str(CONFIG.get('ha_mode') or ''), 'nodes': nodes,
            'vip': str(v.get('address') or '') if v.get('on') else '',
            'holders': holders, 'repl': repl,
            'behind': max([_sf_int(x.get('behind')) for x in rep.get('outgoing') or []] or [0]),
            'repl_errors': sum(_sf_int(x.get('apply_errors')) + _sf_int(x.get('sync_errors'))
                               for x in rep.get('incoming') or []),
            'split': split, 'split_role': role, 'leader': lead,
            'up': sum(1 for n in nodes if n.get('alive')) if nodes else 1,
            'known': len(nodes) or 1}


def _sf_system(store, health):
    raw = _load_raw()
    was = SNMP_FACTS.get('raw')
    busy = 0
    if was and raw.get('cpu_all') and was.get('cpu_all') and raw['cpu_all'] > was['cpu_all']:
        busy = 1 - (raw['cpu_idle'] - was['cpu_idle']) / float(raw['cpu_all'] - was['cpu_all'])
        busy = round(max(0.0, min(1.0, busy)) * 100)
    elif raw.get('cpu_all'):
        # the first look: the average since the machine started, not nothing
        busy = round(max(0.0, min(1.0, 1 - raw.get('cpu_idle', 0) / float(raw['cpu_all']))) * 100)
    SNMP_FACTS['raw'] = raw
    try:
        load = os.getloadavg()
    except OSError:
        load = (0.0, 0.0, 0.0)
    me = node_name()
    ntp = (_meta_obj(store, 'ntp:now:' + me).get('data') or {})
    tr = ntp.get('tracking') or {}
    if ntp.get('chrony') and tr:
        sync = 2 if str(tr.get('leap') or '').lower().startswith('not') else 1
        off = float(tr.get('offset') or 0)
    else:
        sync = 2 if health.get('ntp_problem') else 0
        off = CLOCK.get('ref')
    se = _meta_obj(store, 'host:selinux:now:' + me).get('data') or {}
    beat = _meta_obj(store, 'node:' + me)
    fw = ((beat.get('web') or {}).get('fw') or {})
    ck = _meta_obj(store, 'host:osup:check:' + me)
    sshd = ''
    try:
        sshd = str(([n for n in sshd_view(store).get('nodes') or [] if n.get('me')] or
                    [{}])[0].get('state') or '')
    except Exception:                                   # noqa: BLE001
        sshd = ''
    hand = 0
    try:
        hand = sum(1 for i in hand_all(store) if str(i.get('node') or me) == me)
    except Exception:                                   # noqa: BLE001
        hand = 0
    return {'disks': disks_now(), 'cores': os.cpu_count() or 1, 'busy': busy,
            'load': [round(x * 100) for x in load],
            'mem_total': _sf_int(raw.get('mem_total')), 'mem_used': _sf_int(raw.get('mem_used')),
            'swap_used': _sf_int(raw.get('swap_used')),
            'disk_rd': _sf_int(raw.get('disk_rd')), 'disk_wr': _sf_int(raw.get('disk_wr')),
            'net_rx': _sf_int(raw.get('net_rx')), 'net_tx': _sf_int(raw.get('net_tx')),
            'boot': _sf_int(boot_time()),
            'skew': 0 if CLOCK.get('skew') is None else round(float(CLOCK['skew']) * 1000),
            'offset': 0 if off is None else round(float(off) * 1000),
            'sync': sync, 'problem': str(health.get('ntp_problem') or '')[:255],
            'selinux': SNMP_SELINUX.get(str(se.get('mode') or '').lower(), 0),
            'denials': _sf_int((se.get('denials') or {}).get('total')),
            'fw': bool(fw.get('on')),
            'updates': _sf_int(ck.get('count')) if ck.get('state') == 'done' else 0,
            'security': _sf_int(ck.get('security')) if ck.get('state') == 'done' else 0,
            'reboot': bool(ck.get('reboot_now')),
            'checked': _sf_int(ck.get('checked') or ck.get('at')),
            'sshd': sshd, 'key_lost': bool(health.get('key_lost')),
            'clash': str(health.get('name_clash') or '')[:255], 'hand': hand}


def _sf_backup(store, health):
    me = node_name()
    kept = backups()
    try:
        kept = kept + kept_dumps(store.db.engine)
    except Exception:                                   # noqa: BLE001
        pass
    last = max([float(b.get('at') or b.get('mtime') or 0) for b in kept] or [0]) or \
        float(health.get('last_backup') or 0)
    runs = [r for r in rb_history(store) if r.get('node') == me] if CONFIG.get('rbackup') else []
    good = [r for r in runs if r.get('ok')]
    targets = {}
    for r in reversed(runs):                    # oldest first: the newest of each kept last
        for t in r.get('targets') or []:
            name = str(t.get('name') or '')
            if not name:
                continue
            row = targets.setdefault(name, {'name': name, 'last_ok': 0})
            row.update(ok=bool(t.get('ok')), at=_sf_int(r.get('at')),
                       error=str(t.get('error') or '')[:255] if not t.get('ok') else '')
            if t.get('ok'):
                row['last_ok'] = _sf_int(r.get('at'))
    tried = [r for r in rb_verified(store) if r.get('node') == me]
    err = ''
    if runs and not runs[0].get('ok'):
        bad = [x for x in runs[0].get('targets') or [] if not x.get('ok')]
        err = ('; '.join('%s: %s' % (x.get('name'), x.get('error')) for x in bad) or
               str(runs[0].get('error') or ''))[:255]
    return {'last': _sf_int(last), 'age': max(0, int(time.time() - last)) if last else 0,
            'kept': len(kept), 'daily': bool(CONFIG.get('backup_daily')),
            'remote': bool(CONFIG.get('rbackup')),
            'rlast': _sf_int(runs[0].get('at')) if runs else 0,
            'rlast_ok': _sf_int(good[0].get('at')) if good else 0,
            'result': SNMP_RESULT[bool(runs[0].get('ok'))] if runs else 0, 'error': err,
            'verify': SNMP_RESULT[bool(tried[0].get('ok'))] if tried else 0,
            'verify_at': _sf_int(tried[0].get('at')) if tried else 0,
            'targets': [targets[k] for k in sorted(targets)]}


def _sf_signin(daemon, store):
    me = node_name()
    accounts = store.db.rows('SELECT source, COUNT(*) AS n FROM accounts GROUP BY source')
    locked = fails = 0
    if hasattr(daemon, 'login_fails'):
        with ApiHandler.THROTTLE_LOCK:          # as the counts are written
            held = lockouts_view(daemon)
        for r in held:
            locked += 1 if r.get('locked') else 0
            fails += _sf_int(r.get('fails'))
    krb = krb_node_state(store, me)
    row = krb_keytab_row(store) or {}
    cl = cl_node_state(store, me)
    crls = []
    for c in cl.get('crls') or []:
        nxt = _sf_int(c.get('next'))
        crls.append({'url': str(c.get('url') or '')[:255], 'ok': bool(c.get('ok')),
                     'at': _sf_int(c.get('at')), 'next': nxt,
                     'left': int((nxt - time.time()) // 3600) if nxt else 0,
                     'error': str(c.get('err') or '')[:255]})
    try:
        cas = len(cl_cas_row(store) or [])
    except Exception:                                   # noqa: BLE001
        cas = 0
    return {'accounts': sum(_sf_int(r['n']) for r in accounts),
            'local': sum(_sf_int(r['n']) for r in accounts if r.get('source') != 'directory'),
            'sessions': _sf_int(store.db.value('SELECT COUNT(*) FROM sessions WHERE expires > ?',
                                               (time.time(),), 0)),
            'locked': locked, 'fails': fails,
            'krb': any(krb_usable(p, store) for p in KRB_PARTS),
            'keytab': bool(krb.get('written')), 'entries': len(row.get('entries') or []),
            'krb_error': str(krb.get('error') or '')[:255],
            'cl': any(cl_usable(p, store) for p in KRB_PARTS),
            'cl_listening': bool(cl.get('listening')), 'cl_cas': cas,
            'cl_error': str(cl.get('error') or '')[:255], 'crls': crls}


def _sf_services(daemon, store, health):
    ships = []
    dropped = 0
    on = {}
    for code, what in ((1, 'isemon'), (2, 'siem')):
        obj = getattr(daemon, 'shipper' if what == 'isemon' else 'siem', None)
        st = obj.state() if obj else {}
        on[what] = bool(st.get('on'))
        if not st.get('on'):
            continue
        dropped += _sf_int(st.get('dropped'))
        for i, t in enumerate(st.get('targets') or [], 1):
            trouble = (st.get('trouble') or {}).get(t)
            ships.append({'index': code * 1000 + i, 'kind': what, 'target': str(t)[:255],
                          'sent': _sf_int((st.get('sent') or {}).get(t)),
                          'trouble': bool(trouble), 'said': str(trouble or '')[:255]})
    q = mailq_counts(store)
    dirs = 0
    for d in list((getattr(daemon, 'dirs', None) or {}).values()):
        row = getattr(d, 'row', None) or {}
        if int(row.get('enabled') if row.get('enabled') is not None else 1):
            dirs += 1
    return {'ships': ships, 'isemon': on.get('isemon', False), 'siem': on.get('siem', False),
            'dropped': dropped, 'waiting': q.get('waiting', 0) + q.get('sending', 0),
            'failed': q.get('failed', 0) + q.get('expired', 0), 'sent': q.get('sent', 0),
            'dirs': dirs, 'dirs_down': len(health.get('dirs_down') or []),
            'sms_fails': _sf_int(SMS_HEALTH.get('fails'))}


def snmp_facts(daemon, fresh=False):
    """What a node says of itself beside the certificates: {part: {...}}, read at most every
    10 s (SNMP and Prometheus asking together read it once)."""
    with SNMP_FACTS['lock']:
        if not fresh and SNMP_FACTS['got'] is not None and \
                time.time() - SNMP_FACTS['at'] < SNMP_FACTS_S:
            return SNMP_FACTS['got']
        store = daemon.store
        out = {}
        health = _meta_obj(store, 'host:health:' + node_name())
        _sf_part(out, 'info', lambda: _sf_info(daemon, store))
        _sf_part(out, 'db', lambda: _sf_db(store, health))
        _sf_part(out, 'cluster', lambda: _sf_cluster(store))
        _sf_part(out, 'system', lambda: _sf_system(store, health))
        _sf_part(out, 'backup', lambda: _sf_backup(store, health))
        _sf_part(out, 'signin', lambda: _sf_signin(daemon, store))
        _sf_part(out, 'services', lambda: _sf_services(daemon, store, health))
        SNMP_FACTS.update(at=time.time(), got=out)
        return out


def snmp_more_rows(daemon):
    """The objects of 1.0.108 under acme: [(oid under acme, kind, value)]."""
    f = snmp_facts(daemon)
    rows = []

    def put(sub, kind, value):
        if value is not None:
            rows.append((sub, kind, value))
    i = f.get('info') or {}
    if i:
        put((1, 8, 0), 'str', i['newest'])
        put((1, 9, 0), 'int', 1 if i['newer'] else 0)
        put((1, 10, 0), 'int', _sf_i32(i['started']))
        put((1, 11, 0), 'int', 1 if i['maintenance'] else 0)
        put((1, 12, 0), 'int', 1 if i['lead'] else 0)
        put((1, 13, 0), 'int', _sf_i32(i['checked']))
    d = f.get('db') or {}
    if d:
        put((3, 3, 0), 'counter64', d['size'])
        put((3, 4, 0), 'int', 1 if d['guard'] else 0)
        put((3, 5, 0), 'gauge', d['refused'])
        put((3, 6, 0), 'str', d['trouble'])
    c = f.get('cluster') or {}
    if c:
        put((7, 2, 0), 'str', c['mode'])
        put((7, 3, 0), 'str', c['vip'])
        put((7, 4, 0), 'gauge', len(c['holders']))
        put((7, 5, 0), 'str', c['holders'][0] if len(c['holders']) == 1 else
            ', '.join(c['holders']))
        put((7, 6, 0), 'int', c['repl'])
        put((7, 7, 0), 'counter64', c['behind'])
        put((7, 8, 0), 'counter', c['repl_errors'])
        put((7, 9, 0), 'int', c['split'])
        put((7, 10, 0), 'str', c['split_role'])
        put((7, 11, 0), 'str', c['leader'])
        put((7, 12, 0), 'gauge', c['up'])
        put((7, 13, 0), 'gauge', c['known'])
        # acmeNodeTable's new columns, the rows numbered as snmp_mib numbers them
        for k, n in enumerate(c['nodes'], 1):
            web = n.get('web') or {}
            put((7, 1, 1, 5, k), 'str', str(n.get('version') or ''))
            put((7, 1, 1, 6, k), 'int', 1 if n.get('maintenance') else 0)
            put((7, 1, 1, 7, k), 'int', 1 if web.get('vip_here') else 0)
            put((7, 1, 1, 8, k), 'int', SNMP_VRRP.get(str(web.get('role') or '').upper(), 0))
            put((7, 1, 1, 9, k), 'int', 1 if n.get('me') else 0)
            put((7, 1, 1, 10, k), 'int', _sf_i32(n.get('started')))
            put((7, 1, 1, 11, k), 'str', str(n.get('address') or '')[:255])
    s = f.get('system') or {}
    if s:
        for k, x in enumerate(s['disks'], 1):
            put((10, 1, 1, 1, k), 'int', k)
            put((10, 1, 1, 2, k), 'str', str(x.get('path') or '')[:255])
            put((10, 1, 1, 3, k), 'counter64', _sf_int(x.get('total')))
            put((10, 1, 1, 4, k), 'counter64', _sf_int(x.get('used')))
            put((10, 1, 1, 5, k), 'counter64', _sf_int(x.get('free')))
            put((10, 1, 1, 6, k), 'gauge', min(100, round(float(x.get('pct') or 0))))
            put((10, 1, 1, 7, k), 'gauge', min(100, round(float(x.get('inodes') or 0))))
        put((10, 2, 0), 'gauge', s['cores'])
        put((10, 3, 0), 'gauge', s['busy'])
        for k, v in enumerate(s['load'][:3]):
            put((10, 4 + k, 0), 'gauge', v)
        put((10, 7, 0), 'counter64', s['mem_total'])
        put((10, 8, 0), 'counter64', s['mem_used'])
        put((10, 9, 0), 'counter64', s['swap_used'])
        put((10, 10, 0), 'counter64', s['disk_rd'])
        put((10, 11, 0), 'counter64', s['disk_wr'])
        put((10, 12, 0), 'counter64', s['net_rx'])
        put((10, 13, 0), 'counter64', s['net_tx'])
        put((10, 14, 0), 'int', _sf_i32(s['boot']))
        put((10, 15, 0), 'int', _sf_i32(s['skew']))
        put((10, 16, 0), 'int', _sf_i32(s['offset']))
        put((10, 17, 0), 'int', s['sync'])
        put((10, 18, 0), 'str', s['problem'])
        put((10, 19, 0), 'int', s['selinux'])
        put((10, 20, 0), 'gauge', s['denials'])
        put((10, 21, 0), 'int', 1 if s['fw'] else 0)
        put((10, 22, 0), 'gauge', s['updates'])
        put((10, 23, 0), 'gauge', s['security'])
        put((10, 24, 0), 'int', 1 if s['reboot'] else 0)
        put((10, 25, 0), 'int', _sf_i32(s['checked']))
        put((10, 26, 0), 'str', s['sshd'])
        put((10, 27, 0), 'int', 1 if s['key_lost'] else 0)
        put((10, 28, 0), 'str', s['clash'])
        put((10, 32, 0), 'gauge', s['hand'])
    # the agent's own counts, read when asked (not cached with the rest)
    put((10, 29, 0), 'counter', SNMP_STATE.get('asked') or 0)
    put((10, 30, 0), 'counter', SNMP_STATE.get('answered') or 0)
    put((10, 31, 0), 'counter', SNMP_STATE.get('traps') or 0)
    b = f.get('backup') or {}
    if b:
        put((11, 1, 0), 'int', _sf_i32(b['last']))
        put((11, 2, 0), 'gauge', b['age'])
        put((11, 3, 0), 'gauge', b['kept'])
        put((11, 4, 0), 'int', 1 if b['daily'] else 0)
        put((11, 5, 0), 'int', 1 if b['remote'] else 0)
        put((11, 6, 0), 'int', _sf_i32(b['rlast']))
        put((11, 7, 0), 'int', _sf_i32(b['rlast_ok']))
        put((11, 8, 0), 'int', b['result'])
        put((11, 9, 0), 'str', b['error'])
        put((11, 10, 0), 'int', b['verify'])
        put((11, 11, 0), 'int', _sf_i32(b['verify_at']))
        for k, t in enumerate(b['targets'], 1):
            put((11, 12, 1, 1, k), 'int', k)
            put((11, 12, 1, 2, k), 'str', t['name'][:255])
            put((11, 12, 1, 3, k), 'int', 1 if t.get('ok') else 2)
            put((11, 12, 1, 4, k), 'int', _sf_i32(t.get('at')))
            put((11, 12, 1, 5, k), 'int', _sf_i32(t.get('last_ok')))
            put((11, 12, 1, 6, k), 'str', t.get('error') or '')
    g = f.get('signin') or {}
    if g:
        put((12, 1, 0), 'gauge', g['accounts'])
        put((12, 2, 0), 'gauge', g['local'])
        put((12, 3, 0), 'gauge', g['sessions'])
        put((12, 4, 0), 'gauge', g['locked'])
        put((12, 5, 0), 'gauge', g['fails'])
        put((12, 6, 0), 'int', 1 if g['krb'] else 0)
        put((12, 7, 0), 'int', 1 if g['keytab'] else 0)
        put((12, 8, 0), 'gauge', g['entries'])
        put((12, 9, 0), 'str', g['krb_error'])
        put((12, 10, 0), 'int', 1 if g['cl'] else 0)
        put((12, 11, 0), 'int', 1 if g['cl_listening'] else 0)
        put((12, 12, 0), 'gauge', g['cl_cas'])
        put((12, 13, 0), 'str', g['cl_error'])
        for k, x in enumerate(g['crls'], 1):
            put((12, 14, 1, 1, k), 'int', k)
            put((12, 14, 1, 2, k), 'str', x['url'])
            put((12, 14, 1, 3, k), 'int', 1 if x['ok'] else 0)
            put((12, 14, 1, 4, k), 'int', _sf_i32(x['at']))
            put((12, 14, 1, 5, k), 'int', _sf_i32(x['next']))
            put((12, 14, 1, 6, k), 'int', _sf_i32(x['left']))
            put((12, 14, 1, 7, k), 'str', x['error'])
    v = f.get('services') or {}
    if v:
        for x in v['ships']:
            k = x['index']
            put((13, 1, 1, 1, k), 'int', k)
            put((13, 1, 1, 2, k), 'str', x['kind'])
            put((13, 1, 1, 3, k), 'str', x['target'])
            put((13, 1, 1, 4, k), 'counter', x['sent'])
            put((13, 1, 1, 5, k), 'int', 1 if x['trouble'] else 0)
            put((13, 1, 1, 6, k), 'str', x['said'])
        put((13, 2, 0), 'int', 1 if v['isemon'] else 0)
        put((13, 3, 0), 'int', 1 if v['siem'] else 0)
        put((13, 4, 0), 'counter', v['dropped'])
        put((13, 5, 0), 'gauge', v['waiting'])
        put((13, 6, 0), 'gauge', v['failed'])
        put((13, 7, 0), 'gauge', v['dirs'])
        put((13, 8, 0), 'gauge', v['dirs_down'])
        put((13, 9, 0), 'gauge', v['sms_fails'])
        put((13, 10, 0), 'gauge', v['sent'])
    return rows


def metrics_more(m, daemon):
    """Prometheus' share of the same facts (1.0.108) - what SNMP has of a node, /metrics has
    too."""
    f = snmp_facts(daemon)
    i, s, b, g, c, v = (f.get(k) or {} for k in ('info', 'system', 'backup', 'signin', 'cluster',
                                                  'services'))
    if i:
        m.put('acme_update_available', 'gauge', 'Whether a newer version of acme was found.',
              [({'newest': i['newest']}, 1 if i['newer'] else 0)])
        m.put('acme_maintenance', 'gauge', 'Whether this node is in maintenance.',
              [({}, 1 if i['maintenance'] else 0)])
    if s:
        m.put('acme_cpu_busy_ratio', 'gauge', 'How busy the processors were since last looked '
              '(0-1).', [({}, round(s['busy'] / 100.0, 2))])
        m.put('acme_load', 'gauge', 'The load averages.',
              [({'span': w}, round(x / 100.0, 2)) for w, x in zip(('1m', '5m', '15m'), s['load'])])
        m.put('acme_memory_bytes', 'gauge', 'Memory of the machine, by kind.',
              [({'kind': 'total'}, s['mem_total']), ({'kind': 'used'}, s['mem_used']),
               ({'kind': 'swap_used'}, s['swap_used'])])
        m.put('acme_os_updates', 'gauge', 'Updates of the system waiting, by kind.',
              [({'kind': 'all'}, s['updates']), ({'kind': 'security'}, s['security'])])
        m.put('acme_os_reboot_needed', 'gauge', 'Whether a new kernel or libraries wait for a '
              'restart.', [({}, 1 if s['reboot'] else 0)])
        m.put('acme_selinux_mode', 'gauge', 'SELinux: 0 unknown, 1 absent, 2 disabled, '
              '3 permissive, 4 enforcing.', [({}, s['selinux'])])
        m.put('acme_firewall_on', 'gauge', 'Whether acme\'s firewall is on here.',
              [({}, 1 if s['fw'] else 0)])
    if b:
        m.put('acme_backups_kept', 'gauge', 'Copies kept on this node.', [({}, b['kept'])])
        if b['remote']:
            m.put('acme_rbackup_last_result', 'gauge', 'The last backup sent away: 0 none, 1 ok, '
                  '2 failed.', [({}, b['result'])])
            m.put('acme_rbackup_last_ok_timestamp_seconds', 'gauge', 'When the last good backup '
                  'went away (unix time).', [({}, b['rlast_ok'])] if b['rlast_ok'] else [])
        m.put('acme_backup_verify_result', 'gauge', 'The last try of putting a backup back: 0 '
              'none, 1 ok, 2 failed.', [({}, b['verify'])])
    if g:
        m.put('acme_accounts', 'gauge', 'Accounts of the pages, by source.',
              [({'source': 'local'}, g['local']),
               ({'source': 'directory'}, g['accounts'] - g['local'])])
        m.put('acme_sessions', 'gauge', 'Sign-ins open now.', [({}, g['sessions'])])
        m.put('acme_signin_locked', 'gauge', 'Addresses and names held back on this node now.',
              [({}, g['locked'])])
        if g['krb']:
            m.put('acme_kerberos_keytab_written', 'gauge', 'Whether the keytab is written out '
                  'here.', [({}, 1 if g['keytab'] else 0)])
        m.put('acme_certlogin_crl_next_timestamp_seconds', 'gauge', 'The next update of each CRL '
              'kept for the sign-in with a certificate (unix time).',
              [({'url': x['url']}, x['next']) for x in g['crls'] if x['next']])
    if c and c['mode']:
        m.put('acme_vip_holders', 'gauge', 'Nodes holding the VIP address now.',
              [({}, len(c['holders']))] if c['vip'] else [])
        m.put('acme_split_apart', 'gauge', 'Whether the two nodes are apart.',
              [({}, 1 if c['split'] == 2 else 0)] if c['split'] else [])
    if v:
        m.put('acme_directories_down', 'gauge', 'Directories none of whose servers answers here.',
              [({}, v['dirs_down'])])


# ---- the files for the monitoring: ACME-MIB and the Zabbix template -------------------------
def snmp_mib_path():
    here = Path(__file__).resolve().parent
    for p in (here / 'deploy' / 'ACME-MIB.txt', here / 'ACME-MIB.txt'):
        if p.is_file():
            return p
    raise ValueError('ACME-MIB.txt is not beside acme (deploy/)')


def snmp_mib_text():
    return snmp_mib_path().read_text(encoding='utf-8')


def snmp_file(what):
    """{'name', 'text', 'type'} - the MIB or the Zabbix 7.0 template made from it."""
    if what == 'mib':
        return {'name': 'ACME-MIB.txt', 'text': snmp_mib_text(), 'type': 'text/plain'}
    if what == 'zabbix':
        return {'name': 'acme_zabbix7_template.yaml', 'text': zabbix_template_yaml(),
                'type': 'application/yaml'}
    raise ValueError('mib or zabbix')


def cli_snmp_file(what, out_path):
    """acme --snmp-mib / --snmp-zabbix-template [--out FILE]: the file, made here - nothing
    asked of the daemon."""
    got = snmp_file(what)
    if not out_path or out_path == '-':
        sys.stdout.write(got['text'] if got['text'].endswith('\n') else got['text'] + '\n')
        return 0
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(got['text'])
    sys.stderr.write('%s written: %s (%d bytes)\n' % (got['name'], out_path,
                                                      len(got['text'].encode('utf-8'))))
    return 0
