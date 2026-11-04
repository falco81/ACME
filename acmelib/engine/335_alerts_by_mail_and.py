# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- alerts by mail, and the report (1.0.162) ------------------------------------------
# Each node writes what only it can see into a row of its own every minute
# ('host:health:NODE': its disks, the directories it cannot reach, the SMS
# gateway as it last found it, its last nightly copy). The node that does
# what one node does for both (alerts_lead) looks at everything - those rows, the
# heartbeats, the certificates, the backups, the clocks, the updates, the
# replication - and mails what is wrong: once when it has lasted
# alerts_delay_min, again every alerts_repeat_h while it lasts, and once more
# when it is over. Its state is one row only it writes ('alerts:state'); the
# other node takes it over as it is when it becomes the one.
ALERT_WORK = {'at': 0.0, 'health_at': 0.0, 'busy': False}
SMS_HEALTH = {'ok_at': 0.0, 'fail_at': 0.0, 'fails': 0, 'said': ''}
ALERT_LEVELS = ('bad', 'warn')
ALERTS_EVERY = float(os.environ.get('ACME_ALERTS_EVERY') or 60)    # tests look more often


def sms_health(ok, said=''):
    """What the last SMS did, for the alerts: called where codes go out."""
    if ok:
        SMS_HEALTH.update(ok_at=time.time(), fails=0, said='')
    else:
        SMS_HEALTH.update(fail_at=time.time(), fails=SMS_HEALTH['fails'] + 1,
                          said=str(said)[:200])


def disks_now():
    """The file systems acme lives on: each once, with how full it is."""
    seen, out = set(), []
    for p in ('/', str(STATE_DIR), str(LOG_DIR), '/var/lib/pgsql', '/var/lib/mysql',
              '/var/log', '/var', '/tmp', '/boot'):
        try:
            st = os.statvfs(p)
            dev = os.stat(p).st_dev
        except OSError:
            continue
        if dev in seen or not st.f_blocks:
            continue
        seen.add(dev)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        inodes = (100.0 * (st.f_files - st.f_ffree) / st.f_files) if st.f_files else 0.0
        out.append({'path': p, 'total': total, 'free': free, 'used': used,
                    'pct': round(100.0 * (total - free) / total, 1), 'inodes': round(inodes, 1)})
    return out


def alerts_lead(store):
    """The node that looks and sends: the first by name of the nodes heard
    from, in every kind of cluster - ha_lead is every node of a shared one."""
    if not CONFIG.get('ha_mode'):
        return True
    return lead_of(store)


def health_publish(daemon):
    """This node's own row: what the node that sends the alerts cannot see."""
    now = time.time()
    dead = []
    for name, d in list((getattr(daemon, 'dirs', None) or {}).items()):
        hosts = [h.lower() for h in (getattr(d, 'hosts', None) or [])]
        if not hosts or not int(d.row.get('enabled') if d.row.get('enabled') is not None else 1):
            continue
        with Directory.DEAD_LOCK:
            if all(float(Directory.DEAD.get(h) or 0) > now for h in hosts):
                dead.append(d.name)
    last = None
    try:
        kept = backups()
        try:
            kept = kept + kept_dumps(daemon.store.db.engine)
        except Exception:                               # noqa: BLE001
            pass
        last = max([float(b.get('at') or b.get('mtime') or 0) for b in kept] or [0]) or None
    except Exception:                                   # noqa: BLE001
        pass
    row = {'at': now, 'disks': disks_now(), 'dirs_down': dead, 'sms': dict(SMS_HEALTH),
           'siem': daemon.siem.state() if getattr(daemon, 'siem', None) else {},
           'isemon': daemon.shipper.state() if getattr(daemon, 'shipper', None) else {},
           'snmp': dict(SNMP_STATE) if getattr(daemon, 'snmp', None) else {},
           # The daemon left without the database in the last 5 minutes (1.0.186).
           'db_trouble': DB_TROUBLE_SEEN['said'] if now - DB_TROUBLE_SEEN['at'] < 300 else '',
           'last_backup': last}
    daemon.store.set_meta('host:health:' + node_name(), json.dumps(row))
    return row


def _al(lang, cs, en):
    return cs if lang == 'cs' else en


def _al_ago(t, lang):
    s = max(0, int(time.time() - float(t or 0)))
    if s < 90:
        return _al(lang, '%d s' % s, '%d s' % s)
    if s < 5400:
        return _al(lang, '%d min' % (s // 60), '%d min' % (s // 60))
    if s < 2 * 86400:
        return _al(lang, '%d h' % (s // 3600), '%d h' % (s // 3600))
    return _al(lang, '%d dní' % (s // 86400), '%d days' % (s // 86400))


def _al_when(t):
    return time.strftime('%d.%m.%Y %H:%M', time.localtime(float(t))) if t else '–'


ALERTS_QUIET_AFTER_S = float(os.environ.get('ACME_ALERTS_QUIET_S') or 600)


def alerts_quiet(store, names):
    """Why the cluster is being worked on now, or '' (1.0.194): a node in
    maintenance, an upgrade, the system's updates or a restart under way - and
    for 10 min after the last of them, while replication catches up and the VIP
    address settles."""
    why = ''
    try:
        for n in names:
            if (maintenance_row(store, n) or {}).get('on'):
                why = '%s in maintenance' % n
                break
        if not why:
            up = upgrade_plan(store) or {}
            if up.get('id') and up.get('state') not in ('done', 'failed') and \
                    time.time() - float(up.get('at') or 0) < 6 * 3600:
                why = 'an upgrade'
        if not why and (osup_plan(store) or {}).get('state') == 'running':
            why = 'the system\'s updates'
        if not why and power_busy(store):
            why = 'a restart'
    except Exception:                                   # noqa: BLE001
        why = ''
    now = time.time()
    if why:
        store.set_meta('alerts:quiet', json.dumps({'why': why, 'until': now + ALERTS_QUIET_AFTER_S}))
        return why
    was = _meta_json(store, 'alerts:quiet') or {}
    if float(was.get('until') or 0) > now:
        return '%s (ended - quiet %d s more)' % (was.get('why'), int(float(was['until']) - now))
    return ''


def alert_problems(store, lang='en'):
    """What is wrong now, every node together: {key: {level, node, title, said, pane}}."""
    out = {}
    now = time.time()

    def add(key, level, node, title, said, pane):
        out[key] = {'level': level, 'node': node or '', 'title': title, 'said': said,
                    'pane': pane}
    cluster = bool(CONFIG.get('ha_mode'))
    nodes = ha_nodes(store) if cluster else []
    names = [n['name'] for n in nodes] or [node_name()]
    beats = {n['name']: n for n in nodes}
    if not beats:
        try:
            beats[node_name()] = json.loads(store.get_meta('node:' + node_name()) or '{}')
        except ValueError:
            beats[node_name()] = {}
    health = {n: _meta_json(store, 'host:health:' + n) or {} for n in names}
    # The nodes, the replication, the database.
    if CONFIG.get('alerts_nodes', 1):
        for n in nodes:
            if not n.get('me') and not n.get('alive'):
                add('node:' + n['name'], 'bad', n['name'],
                    _al(lang, 'Uzel %s neodpovídá' % n['name'], '%s is not heard from' % n['name']),
                    _al(lang, 'Naposledy se ozval před %s. Práci dělá druhý uzel - je-li '
                              'naživu, nebo nefunguje replikace.' % _al_ago(now - n['age'], lang),
                        'Last heard from %s ago. The other node does the work - if it is up, '
                        'or the replication is down.' % _al_ago(now - n['age'], lang)), 'ha')
        vers = sorted({str(b.get('version')) for b in beats.values()
                       if b.get('version') and b.get('alive', True)})
        if len(vers) > 1:
            add('versions', 'warn', '', _al(lang, 'Uzly mají různé verze', 'The nodes run '
                                                  'different versions'),
                ', '.join('%s %s' % (k, b.get('version')) for k, b in sorted(beats.items())),
                'upgrade')
    # The database and its replication (1.0.194): a switch of their own, and
    # quiet while the cluster is being worked on (maintenance, an upgrade, the
    # system's updates, a restart) and 10 min after - not otherwise.
    quiet = alerts_quiet(store, names)
    if CONFIG.get('alerts_db', 1) and not quiet:
        if CONFIG.get('ha_mode') == 'replicated':
            try:
                rs = ha_repl_state(store)
            except Exception:                           # noqa: BLE001
                rs = {}
            if rs and not rs.get('healthy', True):
                add('repl', 'bad', node_name(),
                    _al(lang, 'Replikace databáze neběží', 'The database replication is down'),
                    _al(lang, 'Změny z jednoho uzlu se nedostávají na druhý%s.',
                        'Changes on one node do not reach the other%s.') % (
                        ' (%s)' % rs['trouble'] if rs.get('trouble') else ''), 'ha')
        # Each node's own (1.0.186): db_trouble() was called with nothing to
        # look at - it raised, and this never said a word.
        for n in names:
            trouble = (health.get(n) or {}).get('db_trouble')
            if trouble:
                add('db:%s' % n, 'bad', n, _al(lang, 'Potíže s databází', 'The database is in '
                                                     'trouble'),
                    _al(lang, 'acme na %s nemohl použít databázi: %s',
                        'acme on %s could not use the database: %s') % (n, str(trouble)[:300]),
                    'db')
    # The nodes apart (1.0.14, docs/split-brain.md): each node's own word, and the report
    # of the time apart.
    if CONFIG.get('split_report') and split_engaged():
        for n in names:
            st = split_state_of(store, n)
            if st.get('apart') and now - float(st.get('at') or 0) < 90:
                aside = st.get('role') == 'aside'
                held = bool(st.get('held'))
                add('split:' + n, 'bad', n,
                    _al(lang, '%s nevidí druhý uzel%s' % (n, ' a ustoupil stranou' if aside else ''),
                        '%s cannot reach the other node%s' % (n, ' and stepped aside' if aside else '')),
                    _al(lang, 'Databáze druhého uzlu neodpovídá od %s. %s',
                        'The other node\'s database has not answered since %s. %s')
                    % (_al_when(st.get('since') or now),
                       _al(lang, 'Tento uzel neobnovuje, nenasazuje ani neodpovídá na DNS - '
                                 'nechává to druhému uzlu.' if aside else
                           ('Tento uzel obsluhuje, ale obnovy a nasazení nechává '
                            'upřednostněnému uzlu.' if held else
                            'Tento uzel obnovuje, nasazuje a odpovídá na DNS sám.'),
                           'This node does not renew, deploy or answer DNS - it leaves that '
                           'to the other node.' if aside else
                           ('This node answers, but leaves the renewals and deployments to '
                            'the preferred node.' if held else
                            'This node renews, deploys and answers DNS alone.'))), 'ha')
        rep = _meta_json(store, 'split:report') or {}
        if rep.get('twice_n') and now - float(rep.get('at') or 0) < 86400:
            add('split:twice', 'warn', '',
                _al(lang, 'Během rozpojení se totéž udělalo na obou uzlech',
                    'The same was done on both nodes while they were apart'),
                _al(lang, '%d: %s', '%d: %s') % (
                    rep['twice_n'], ', '.join('%s (%s)' % (x.get('name'), x.get('kind'))
                                              for x in (rep.get('twice') or [])[:10])), 'ha')
    # The clocks of the nodes (1.0.21, docs/clock-guard.md): each node's own word, only when
    # the mode is not off - as until now nothing of it is said.
    if clock_engaged():
        warn_s = float(CONFIG.get('clock_warn_s') or 2)
        aside_s = float(CONFIG.get('clock_aside_s') or 20)
        for n in names:
            st = clock_state_of(store, n)
            if not st or now - float(st.get('at') or 0) > 90 + abs(float(st.get('skew') or 0)):
                continue
            if st.get('role') == 'aside':
                add('clock:aside:' + n, 'bad', n,
                    _al(lang, '%s ustoupil stranou' % n, '%s stepped aside' % n),
                    _al(lang, 'Neobnovuje, nenasazuje ani neodpovídá na DNS, VIP adresa je na '
                              'druhém uzlu: %s.', 'It does not renew, deploy or answer DNS, the '
                                                  'VIP address is on the other node: %s.')
                    % (st.get('why') or '?'), 'time')
            ref = st.get('ref')
            if ref is None:
                add('clock:ref:' + n, 'warn', n,
                    _al(lang, '%s se nemůže zeptat na správný čas' % n,
                        '%s cannot ask for the right time' % n),
                    _al(lang, 'Žádný referenční časový server neodpověděl: %s. Podle ničeho se '
                              'neposoudí - stranou neustoupí.',
                        'No reference time server answered: %s. It is judged by nothing - '
                        'never stepped aside.') % (st.get('ref_err') or '?'), 'time')
            elif abs(float(ref)) > warn_s:
                off = abs(float(ref))
                fixed = bool(st.get('codes_fixed'))
                add('clock:skew:' + n, 'bad' if off > aside_s else 'warn', n,
                    _al(lang, 'Hodiny %s jdou o %.1f s %s' % (n, off, 'pozadu' if ref > 0 else 'napřed'),
                        'The clock of %s is %.1f s %s' % (n, off, 'behind' if ref > 0 else 'ahead')),
                    _al(lang, 'Proti referenčním časovým serverům (%s). %s',
                        'Against the reference time servers (%s). %s')
                    % (st.get('ref_src') or '?',
                       _al(lang, 'Kódy druhého kroku se počítají z opraveného času.' if fixed else
                           'Správné kódy druhého kroku mohou být odmítnuty.',
                           'The codes of the second step are worked out with the corrected time.'
                           if fixed else 'Right codes of the second step may be refused.')), 'time')
            sk = st.get('skew')
            if sk is not None and abs(float(sk)) > warn_s:
                add('clock:peer:' + n, 'warn', n,
                    _al(lang, 'Hodiny uzlů se liší o %.1f s' % abs(float(sk)),
                        'The clocks of the nodes differ by %.1f s' % abs(float(sk))),
                    _al(lang, 'Změřeno na %s proti %s.', 'Measured on %s against %s.')
                    % (n, st.get('skew_of') or '?'), 'time')
            if CONFIG.get('health_dir') and st.get('dir_ok') is False:
                bad = ', '.join('%s (%s)' % (d.get('name'), d.get('words'))
                                for d in (st.get('dirs') or []) if not d.get('ok'))
                add('clock:dir:' + n, 'bad', n,
                    _al(lang, '%s nedosáhne na adresář' % n, '%s cannot reach the directory' % n),
                    bad[:400] or '?', 'time')
    # The VIP address (1.0.194): where keepalived put it, from each node's heartbeat.
    if CONFIG.get('alerts_vrrp', 1) and cluster and not quiet:
        try:
            vc = vip_conf(store)
        except Exception:                               # noqa: BLE001
            vc = {}
        if vc.get('on') and vc.get('address'):
            up = {n: b for n, b in beats.items() if b.get('alive', True) or b.get('me')}
            webs = {n: (b.get('web') or {}) for n, b in up.items()}
            holders = sorted(n for n, w in webs.items() if w.get('vip_here'))
            addr = str(vc.get('address')).split('/')[0]
            if up and not holders:
                add('vip:none', 'bad', '', _al(lang, 'VIP adresu %s nedrží žádný uzel' % addr,
                                               'No node holds the VIP address %s' % addr),
                    _al(lang, 'Kdo se na ni ptá, nedostane odpověď - ani stránky.',
                        'Whoever asks it gets no answer - the pages neither.'), 'ha')
            elif len(holders) > 1:
                add('vip:both', 'bad', '', _al(lang, 'VIP adresu %s drží oba uzly' % addr,
                                               'Both nodes hold the VIP address %s' % addr),
                    _al(lang, 'Uzly se přes VRRP nevidí (%s) - odpovědi chodí střídavě z obou.',
                        'The nodes do not see each other over VRRP (%s) - answers come from '
                        'either.') % ', '.join(holders), 'ha')
            for n, w in sorted(webs.items()):
                role = str(w.get('role') or '')
                why = str((w.get('health') or {}).get('why') or '')
                if role == 'FAULT':
                    add('vip:fault:' + n, 'warn', n,
                        _al(lang, '%s nemůže držet VIP adresu' % n, '%s cannot hold the VIP address' % n),
                        why or _al(lang, 'keepalived hlásí FAULT.', 'keepalived says FAULT.'), 'ha')
                elif not role and w:
                    add('vip:ka:' + n, 'warn', n,
                        _al(lang, 'keepalived na %s neběží' % n, 'keepalived is not running on %s' % n),
                        _al(lang, 'Uzel VIP adresu nepřevezme, kdyby druhý vypadl.',
                            'The node does not take the VIP address if the other goes.'), 'ha')
    # Backups: the nightly copy of each node, and the backups sent away.
    if CONFIG.get('alerts_backup', 1):
        if CONFIG.get('backup_daily'):
            for n in names:
                h = health.get(n) or {}
                if not h:
                    continue
                last = float(h.get('last_backup') or 0)
                if now - last > 36 * 3600:
                    add('backup:' + n, 'warn', n,
                        _al(lang, 'Noční záloha na %s chybí' % n, 'No nightly copy on %s' % n),
                        _al(lang, 'Poslední je z %s.' % _al_when(last) if last else
                            'Žádná tam není.', 'The last one is from %s.' % _al_when(last)
                            if last else 'There is none.'), 'db')
        if CONFIG.get('rbackup'):
            runs = rb_history(store)
            span = (8 * 86400 if CONFIG.get('rbackup_every') == 'weekly' else 36 * 3600)
            for n in names:
                mine = [r for r in runs if r.get('node') == n]
                if mine and not mine[0].get('ok'):
                    bad = [x for x in mine[0].get('targets') or [] if not x.get('ok')]
                    add('rbackup:' + n, 'bad', n,
                        _al(lang, 'Záloha z %s se nepovedla' % n, 'The backup of %s failed' % n),
                        '; '.join('%s: %s' % (x.get('name'), x.get('error')) for x in bad)
                        or str(mine[0].get('error') or '')[:300], 'backup')
                elif not any(r.get('ok') and now - float(r.get('at') or 0) < span for r in mine):
                    ok = [r for r in mine if r.get('ok')]
                    add('rbackup:' + n, 'warn', n,
                        _al(lang, 'Z %s neodešla včas žádná záloha' % n,
                            'No backup of %s went out in time' % n),
                        _al(lang, 'Poslední úspěšná: %s.', 'The last good one: %s.')
                        % (_al_when(ok[0]['at']) if ok else '–'), 'backup')
        # The last try of a backup (1.0.169): one that cannot be put back.
        tried = rb_verified(store)
        for n in names:
            mine = [r for r in tried if r.get('node') == n]
            if mine and not mine[0].get('ok'):
                bad = [c for c in mine[0].get('checks') or [] if not c.get('ok')]
                add('rbverify:' + n, 'bad', n,
                    _al(lang, 'Záloha z %s nejde obnovit' % n,
                        'The backup of %s cannot be put back' % n),
                    '%s: %s' % (mine[0].get('file') or '?', '; '.join(
                        c['what'] + (' (%s)' % c['said'] if c.get('said') else '')
                        for c in bad)[:400]), 'backup')
    # Certificates running out.
    days = int(CONFIG.get('alerts_cert_days') or 0)
    if days:
        seen = set()
        for n, b in sorted(beats.items()):
            web = b.get('web') or {}
            for what, c in (('node', web.get('cert_now')), ('vip', web.get('vip_cert_now'))):
                if not isinstance(c, dict) or not c.get('not_after'):
                    continue
                fp = c.get('fingerprint') or ''
                if what == 'vip' and fp in seen:
                    continue
                seen.add(fp)
                left = (float(c['not_after']) - now) / 86400
                if left < days:
                    who = _al(lang, 'VIP adresy', 'the VIP address') if what == 'vip' else n
                    add('cert:%s:%s' % (what, n if what == 'node' else 'vip'),
                        'bad' if left < 7 else 'warn', n if what == 'node' else '',
                        _al(lang, 'Certifikát %s %s' % (who, 'vypršel' if left < 0 else
                                                       'brzy vyprší'),
                            'The certificate of %s %s' % (who, 'ran out' if left < 0 else
                                                          'runs out soon')),
                        _al(lang, '%s - platí do %s (%d dní).', '%s - good until %s (%d days).')
                        % (c.get('cn') or c.get('subject') or '?', _al_when(c['not_after']),
                           int(left)), 'web')
    # Disks.
    pct = int(CONFIG.get('alerts_disk_pct') or 0)
    if pct:
        for n in names:
            for d in (health.get(n) or {}).get('disks') or []:
                if float(d.get('pct') or 0) >= pct or float(d.get('inodes') or 0) >= pct:
                    add('disk:%s:%s' % (n, d['path']), 'bad' if d['pct'] >= 95 else 'warn', n,
                        _al(lang, 'Na %s dochází místo (%s)' % (n, d['path']),
                            '%s is running out of room (%s)' % (n, d['path'])),
                        _al(lang, 'Zaplněno %s %% - volných %s.', '%s %% full - %s free.')
                        % (d['pct'], human_bytes(d.get('free') or 0)), 'osup')
    # The clocks: the certificates' dates and the app's codes are worked out from them.
    if CONFIG.get('alerts_time', 1):
        for n in names:
            data = ((_meta_json(store, 'ntp:now:' + n) or {}).get('data') or {})
            tr = data.get('tracking') or {}
            if not data.get('chrony') or not tr:
                continue
            off = abs(float(tr.get('offset') or 0))
            unsynced = str(tr.get('leap') or '').lower().startswith('not')
            if unsynced or off > 0.5:
                add('time:' + n, 'bad' if off > 5 or unsynced else 'warn', n,
                    _al(lang, 'Hodiny na %s nejdou přesně' % n, 'The clock of %s is off' % n),
                    _al(lang, 'chrony %s, odchylka %.2f s - platnost certifikátů i kódy z '
                              'aplikace se počítají z hodin.',
                        'chrony %s, off by %.2f s - the dates of the certificates and the codes '
                        'of the app are worked out from the clock.') % (_al(lang, 'není synchronizované', 'is not in sync')
                                              if unsynced else 'OK', off), 'time')
    # The updates of the system.
    if CONFIG.get('alerts_updates', 1):
        for n in names:
            ck = _meta_json(store, 'host:osup:check:' + n) or {}
            if ck.get('state') != 'done':
                continue
            if int(ck.get('security') or 0):
                add('sec:' + n, 'warn', n,
                    _al(lang, 'Bezpečnostní aktualizace na %s' % n,
                        'Security updates waiting on %s' % n),
                    _al(lang, 'Čeká %d bezpečnostních z %d aktualizací (zjištěno %s).',
                        '%d security updates of %d waiting (looked %s).')
                    % (int(ck['security']), int(ck.get('count') or 0),
                       _al_when(ck.get('checked'))), 'osup')
            if ck.get('reboot_now'):
                add('reboot:' + n, 'warn', n,
                    _al(lang, '%s čeká na restart' % n, '%s waits for a restart' % n),
                    _al(lang, 'Nové jádro nebo knihovny se použijí až po restartu.',
                        'A new kernel or libraries come into use only after a restart.'), 'osup')
    # The directories and the SMS gateway, as the nodes found them.
    if CONFIG.get('alerts_dir', 1):
        for n in names:
            for d in (health.get(n) or {}).get('dirs_down') or []:
                add('dir:%s:%s' % (n, d), 'bad', n,
                    _al(lang, 'Active Directory %s je nedostupná' % d,
                        'The directory %s cannot be reached' % d),
                    _al(lang, 'Z uzlu %s neodpovídá žádný její server - přihlášení '
                              'administrátorů z ní neprojdou.' % n, 'None of its servers '
                              'answers %s - administrators from it cannot sign in.' % n), 'dir')
    if CONFIG.get('alerts_sms', 1) and (CONFIG.get('sms_mode') or 'off') != 'off':
        for n in names:
            s = (health.get(n) or {}).get('sms') or {}
            if int(s.get('fails') or 0) >= 3 and now - float(s.get('fail_at') or 0) < 6 * 3600:
                add('sms:' + n, 'bad', n,
                    _al(lang, 'SMS brána neposílá', 'The SMS gateway does not send'),
                    _al(lang, '%d SMS z %s za sebou se nepovedlo: %s',
                        '%d SMS from %s failed in a row: %s') % (int(s['fails']), n,
                                                              s.get('said') or '?'), 'codes')
    # SELinux (as otp 1.0.242; off by default).
    if CONFIG.get('alerts_selinux'):
        for n in names:
            try:
                probs = [p for p in selinux_problems(store, n) if 'ready for enforcing' not in p]
            except Exception:                           # noqa: BLE001
                probs = []
            if probs:
                add('selinux:' + n, 'warn', n,
                    _al(lang, 'SELinux na %s: něco není, jak acme potřebuje' % n,
                        'SELinux on %s: something is not as acme needs it' % n),
                    '; '.join(probs)[:300], 'hisec')
    # What a module sees wrong (HOOKS['alerts']): mailed like the engine's own.
    for fn in HOOKS['alerts']:
        try:
            got = list(fn(store) or [])
        except Exception as e:                          # noqa: BLE001
            log_sparing('alerts-hook', 'a module\'s alerts could not be asked: %s: %s'
                        % (getattr(fn, '__qualname__', fn), e), 'warn', every=600)
            continue
        for a in got:
            if not isinstance(a, dict) or not a.get('key') or not a.get('words'):
                continue
            words = str(a['words'])
            add('mod:%s' % a['key'], 'bad' if a.get('level') == 'bad' else 'warn',
                str(a.get('node') or ''), str(a.get('title') or words)[:300],
                words if a.get('title') else '', str(a.get('pane') or 'certs'))
    return out


def _alerts_to(key='alerts_to'):
    raw = str(CONFIG.get(key) or '')
    if key == 'report_to' and not raw.strip():
        raw = str(CONFIG.get('alerts_to') or '')
    return [a for a in re.split(r'[\s,;]+', raw) if a][:20]


def alerts_link():
    url = str(CONFIG.get('alerts_url') or '').strip()
    return url or 'https://%s/admin/' % socket.getfqdn()


# -- the mails ------------------------------------------------------------------------------
AL_FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
AL_COLORS = {'bad': ('#dc2626', '#fef2f2', '#991b1b'), 'warn': ('#d97706', '#fffbeb', '#92400e'),
             'good': ('#16a34a', '#f0fdf4', '#166534'), 'info': ('#2563eb', '#eff6ff', '#1e3a8a')}


def _al_page(lang, title, kicker, band, body, foot, width=640):
    """The frame every alert and report mail has: tables and styles on each
    element, as acme's other mails - what every mail program draws the same."""
    return ('<!doctype html><html lang="%s"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>'
            '</head><body style="margin:0;padding:0;background:#f3f4f6;%s">'
            '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'bgcolor="#f3f4f6" style="background:#f3f4f6"><tr><td align="center" '
            'style="padding:24px 10px">'
            '<table role="presentation" %s cellspacing="0" cellpadding="0" border="0" '
            'bgcolor="#ffffff" style="%s;background:#ffffff;'
            'border-radius:14px;overflow:hidden;border:1px solid #e5e7eb">'
            '<tr><td bgcolor="%s" style="background:%s;padding:20px 28px;color:#ffffff;%s">'
            '<p style="margin:0;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;'
            'color:#ffffff;opacity:.85">%s</p><p style="margin:4px 0 0;font-size:21px;'
            'font-weight:700;color:#ffffff">%s</p></td></tr>'
            '<tr><td style="padding:22px 28px;%s">%s</td></tr>'
            '<tr><td style="padding:14px 28px 22px;font-size:12px;color:#9ca3af;%s'
            'border-top:1px solid #f3f4f6">%s</td></tr></table></td></tr></table></body></html>'
            % (lang, _h(title), AL_FONT,
               # 0: as wide as what it holds, never less than 1000 px (the report).
               'width="%d"' % width if width else '',
               'max-width:%dpx;width:100%%' % width if width else 'min-width:1000px;width:auto',
               band, band, AL_FONT, _h(kicker), _h(title),
               AL_FONT, body, AL_FONT, foot))


def _al_card(level, title, lines, link=''):
    edge, back, ink = AL_COLORS.get(level, AL_COLORS['info'])
    rows = ''.join('<div style="margin-top:4px;font-size:13.5px;line-height:1.5;color:#374151">'
                   '%s</div>' % ln for ln in lines if ln)
    if link:
        rows += ('<div style="margin-top:8px;font-size:13px"><a href="%s" style="color:#1d4ed8;'
                 'text-decoration:none;font-weight:600">%s</a></div>' % (_h(link[0]), _h(link[1])))
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
            'border="0" style="margin:0 0 10px"><tr><td bgcolor="%s" style="background:%s;'
            'border-left:4px solid %s;border-radius:8px;padding:12px 16px;%s">'
            '<div style="font-size:15px;font-weight:700;color:%s">%s</div>%s</td></tr></table>'
            % (back, back, edge, AL_FONT, ink, _h(title), rows))


def _al_h(text):
    return ('<p style="margin:18px 0 8px;font-size:12px;font-weight:700;letter-spacing:1px;'
            'text-transform:uppercase;color:#6b7280">%s</p>' % _h(text))


def _al_msg(subject, page, text, to):
    sender = mail_sender()
    if not sender:
        raise MailError('no sender address is set - Settings → Mail → From (address)')
    site = str(CONFIG.get('site_name') or socket.gethostname())
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = formataddr((str(CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = ', '.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(text)
    msg.add_alternative(page, subtype='html')
    return msg


def alert_mail(new, still, gone, events, to, lang, test=False, left=0):
    """One mail: what went wrong, what still is, what is over, what happened."""
    site = str(CONFIG.get('site_name') or socket.gethostname())
    link = alerts_link()
    bad = [p for p in new + still if p['level'] == 'bad']
    if test:
        subject = _al(lang, '[acme] Zkušební upozornění - %s', '[acme] A test alert - %s') % site
        band = AL_COLORS['info'][0]
        title = _al(lang, 'Upozornění chodí', 'Alerts come through')
    elif new or still:
        n = len(new) + len(still)
        subject = (_al(lang, '[acme] %s %d %s - %s', '[acme] %s %d %s - %s')
                   % ('✖' if bad else '⚠', n, _al(lang, 'problém' if n == 1 else
                                                     ('problémy' if n < 5 else 'problémů'),
                                                     'problem' if n == 1 else 'problems'), site))
        band = AL_COLORS['bad' if bad else 'warn'][0]
        title = _al(lang, 'Něco není v pořádku', 'Something is wrong')
    elif gone and left:
        subject = (_al(lang, '[acme] ✔ %d vyřešeno, %d trvá - %s', '[acme] ✔ %d over, %d still so - %s')
                   % (len(gone), left, site))
        band = AL_COLORS['good'][0]
        title = _al(lang, 'Něco je vyřešeno', 'Some of it is over')
    elif gone:
        subject = _al(lang, '[acme] ✔ Vyřešeno - %s', '[acme] ✔ Back to normal - %s') % site
        band = AL_COLORS['good'][0]
        title = _al(lang, 'Vše je zase v pořádku', 'All is well again')
    else:
        subject = _al(lang, '[acme] Události - %s', '[acme] Events - %s') % site
        band = AL_COLORS['info'][0]
        title = _al(lang, 'Co se stalo', 'What happened')
    body, text = [], [title, '']

    def section(head, items, level=None):
        if not items:
            return
        body.append(_al_h(head))
        text.append(head.upper())
        for p in items:
            lv = level or p['level']
            lines = [_h(p['said'])]
            if p.get('node'):
                lines.append('<span style="color:#6b7280">%s %s</span>' % (
                    _h(_al(lang, 'Uzel:', 'Node:')), _h(p['node'])))
            if p.get('since'):
                lines.append('<span style="color:#6b7280">%s %s</span>' % (
                    _h(_al(lang, 'Od:', 'Since:')), _h(_al_when(p['since']))))
            body.append(_al_card(lv, p['title'], lines,
                                 (link + '#settings/' + p['pane'], _al(lang, 'Otevřít v administraci →',
                                                                      'Open in the administration →'))
                                 if p.get('pane') and lv != 'good' else ''))
            text.append('- %s: %s%s' % (p['title'], p['said'],
                                        (' [%s]' % p['node']) if p.get('node') else ''))
        text.append('')
    if test:
        body.append(_al_card('info', _al(lang, 'Toto je zkouška', 'This is a test'), [
            _h(_al(lang, 'Upozornění z %s dorazí sem. Teď je hlášeno problémů: %d.',
                   'The alerts of %s arrive here. Problems now: %d.') % (site, len(still)))]))
        section(_al(lang, 'Co je teď špatně', 'What is wrong now'), still)
    else:
        allp = new + still
        body.append(_rep_tiles([
            (_al(lang, 'nefunguje', 'down'), str(len([p for p in allp if p['level'] == 'bad'])),
             'bad' if any(p['level'] == 'bad' for p in allp) else 'good'),
            (_al(lang, 'varování', 'warnings'), str(len([p for p in allp if p['level'] != 'bad'])),
             'warn' if any(p['level'] != 'bad' for p in allp) else 'good'),
            (_al(lang, 'vyřešeno', 'over'), str(len(gone)), 'good')]))
        section(_al(lang, 'Nové', 'New'), new)
        section(_al(lang, 'Pořád trvá', 'Still so'), still)
        section(_al(lang, 'Vyřešeno', 'Over'), [dict(p, said=p['said'] + _al(
            lang, ' (trvalo %s)', ' (it lasted %s)') % _al_ago(p.get('since') or time.time(), lang))
            for p in gone], 'good')
        section(_al(lang, 'Události', 'Events'), events, 'info')
    foot = _h(_al(lang, 'Poslal %s z %s, %s. Nastavení → Upozornění a reporty.',
                  'Sent by %s from %s, %s. Settings → Alerts and reports.')
              % (node_name(), site, _al_when(time.time())))
    text += ['-- ', html.unescape(re.sub('<[^>]+>', '', foot)), link]
    return _al_msg(subject, _al_page(lang, title, 'acme · ' + site, band, ''.join(body), foot),
                   '\n'.join(text), to)


def _alert_state(store):
    st = _meta_json(store, 'alerts:state') or {}
    st.setdefault('problems', {})
    st.setdefault('log', [])
    return st


def alert_send(store, msg, to, kind, keys):
    st = _alert_state(store)
    entry = {'at': time.time(), 'kind': kind, 'keys': keys[:20], 'to': to, 'ok': True,
             'subject': str(msg.get('Subject') or '')[:200], 'node': node_name()}
    try:
        mail_deliver(store, msg, to, kind='alert', purpose=kind)
    except MailError as e:
        # Waiting for another try in the outgoing mail is sent as far as the
        # alerts go: it is not made again every minute.
        entry.update(ok=False, said=str(e)[:200], queued=getattr(e, 'queued', '') or '')
    st = _alert_state(store)
    if not entry['ok'] and entry.get('queued') != 'waiting':
        st['fail_at'] = entry['at']
    st['log'] = ([entry] + st['log'])[:50]
    store.set_meta('alerts:state', json.dumps(st))
    return entry


def alerts_lang():
    return CONFIG.get('alerts_lang') or CONFIG.get('mail_lang') or 'cs'


def report_lang():
    return CONFIG.get('report_lang') or alerts_lang()


def alerts_evaluate(store, force=False):
    """The alerts' turn: what is wrong compared with what was said, mailed."""
    lang = alerts_lang()
    now = time.time()
    cur = alert_problems(store, lang)
    st = _alert_state(store)
    known = st['problems']
    delay = 60 * int(CONFIG.get('alerts_delay_min') or 0)
    repeat = 3600 * int(CONFIG.get('alerts_repeat_h') or 0)
    new, still, gone = [], [], []
    for k, p in cur.items():
        was = known.get(k) or {}
        p['key'] = k
        p['since'] = was.get('since') or now
        p['sent'] = bool(was.get('sent'))
        p['sent_at'] = was.get('sent_at')
        # The worst level mailed so far (1.0.205): a disk at 95 % going between
        # warn and bad mailed "worse than said" at every turn back to bad.
        p['mailed'] = was.get('mailed') or (was.get('level') if was.get('sent') else None)
        if not p['sent'] and now - p['since'] >= delay:
            new.append(p)
        elif p['sent'] and repeat and now - float(was.get('sent_at') or 0) >= repeat:
            still.append(p)
        elif p['sent'] and p['mailed'] == 'warn' and p['level'] == 'bad':
            new.append(p)                               # worse than said
        known[k] = dict(p)
    # Held while the cluster is worked on (1.0.194): the database's and the VIP
    # address's, not looked at then, are not "over" - kept as they were, the
    # time they were said too, until they are looked at again.
    held = ('repl', 'db:', 'vip:')
    quiet = bool(_meta_json(store, 'alerts:quiet') or {}) and \
        float((_meta_json(store, 'alerts:quiet') or {}).get('until') or 0) > now
    for k in list(known):
        if k not in cur:
            if quiet and k.startswith(held):
                continue
            p = known.pop(k)
            if p.get('sent') and CONFIG.get('alerts_resolved', 1):
                gone.append(p)
    events = []
    st['problems'] = known
    st['checked'] = now
    store.set_meta('alerts:state', json.dumps(st))
    to = _alerts_to()
    if (new or still or gone or events) and to and CONFIG.get('alerts') and \
            now - float(st.get('fail_at') or 0) > 900:
        said = {p['key'] for p in new + still}
        # A mail about something new names what else is still wrong too.
        others = [p for p in cur.values() if p['key'] not in said and p['sent']] \
            if new or gone else []
        msg = alert_mail(new, still + others, gone, events, to, lang,
                         left=len([p for p in cur.values() if p['sent'] or p['key'] in said]))
        entry = alert_send(store, msg, to, 'alert', sorted(said) +
                           ['over:' + str(p.get('key') or '') for p in gone])
        if entry['ok'] or entry.get('queued') == 'waiting':
            st = _alert_state(store)
            for k in said | {p['key'] for p in others}:
                if k in st['problems']:
                    one = st['problems'][k]
                    one.update(sent=True, sent_at=now,
                               mailed='bad' if 'bad' in (one.get('mailed'), one.get('level'))
                               else one.get('level'))
            store.set_meta('alerts:state', json.dumps(st))
    return {'now': cur, 'new': len(new), 'still': len(still), 'over': len(gone),
            'events': len(events)}


# -- the report ------------------------------------------------------------------------------
def report_period(now=None):
    """(since, until, id) of the last period that has ended, as report_every says."""
    now = datetime.fromtimestamp(now or time.time())
    every = CONFIG.get('report_every') or 'weekly'
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if every == 'daily':
        until = day0
        since = until - timedelta(days=1)
    elif every == 'monthly':
        until = day0.replace(day=1)
        since = (until - timedelta(days=1)).replace(day=1)
    else:
        until = day0 - timedelta(days=(day0.isoweekday() - 1))
        since = until - timedelta(days=7)
    return time.mktime(since.timetuple()), time.mktime(until.timetuple()), \
        '%s:%s' % (every, since.strftime('%Y-%m-%d'))


def report_due(now=None):
    n = datetime.fromtimestamp(now or time.time())
    try:
        hh, mm = (int(x) for x in str(CONFIG.get('report_at') or '07:30').split(':', 1))
    except ValueError:
        hh, mm = 7, 30
    every = CONFIG.get('report_every') or 'weekly'
    if every == 'weekly' and n.isoweekday() != int(CONFIG.get('report_day') or 1):
        return False
    if every == 'monthly' and n.day != 1:
        return False
    return (n.hour, n.minute) >= (hh, mm)


def _rep_table(head, rows, widths=None):
    th = ''.join('<td style="padding:6px 10px;white-space:nowrap;font-size:11.5px;font-weight:700;'
                 'letter-spacing:.5px;text-transform:uppercase;color:#6b7280;'
                 'border-bottom:1px solid #e5e7eb;%s">%s</td>'
                 % ('text-align:right;' if i and str(h).startswith('#') else '', _h(str(h).lstrip('#')))
                 for i, h in enumerate(head))
    trs = []
    for r in rows:
        trs.append('<tr>%s</tr>' % ''.join(
            '<td style="padding:6px 10px;font-size:13px;color:#111827;border-bottom:1px solid '
            '#f3f4f6;white-space:nowrap;%s">%s</td>' % ('text-align:right;' if i and
                                                         str(head[i]).startswith('#') else '', c)
            for i, c in enumerate(r)))
    if not rows:
        trs.append('<tr><td colspan="%d" style="padding:8px;font-size:13px;color:#9ca3af">–</td>'
                   '</tr>' % len(head))
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:0 0 6px;%s"><tr>%s</tr>%s</table>' % (AL_FONT, th, ''.join(trs)))


def _rep_tiles(tiles):
    cells = ''.join(
        '<td width="%d%%" valign="top" style="padding:4px"><table role="presentation" '
        'width="100%%" cellspacing="0" cellpadding="0" border="0"><tr><td bgcolor="%s" '
        'style="background:%s;border-radius:10px;padding:12px 12px;%s">'
        '<div style="font-size:22px;font-weight:700;color:%s">%s</div>'
        '<div style="margin-top:2px;font-size:12px;color:#4b5563">%s</div></td></tr></table></td>'
        % (100 // len(tiles), AL_COLORS[lv][1], AL_COLORS[lv][1], AL_FONT, AL_COLORS[lv][2],
           _h(v), _h(k)) for k, v, lv in tiles)
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:0 0 8px"><tr>%s</tr></table>' % cells)


def _rep_bars(series, lang):
    """The events per day as bars - those that went well green, those worth
    a look red: a table of cells, which every mail program draws (no
    pictures, no SVG)."""
    if not series:
        return ''
    top = max([s['accept'] + s['reject'] for s in series] or [1]) or 1
    cols = []
    for s in series:
        a = int(round(80.0 * s['accept'] / top))
        r = int(round(80.0 * s['reject'] / top))
        day = time.strftime('%d.%m.', time.localtime(s['t']))
        cols.append(
            '<td align="center" valign="bottom" style="padding:0 2px;%s">'
            '<div style="font-size:10px;color:#6b7280">%d</div>'
            '%s%s<div style="font-size:10px;color:#6b7280;margin-top:3px">%s</div></td>'
            % (AL_FONT, s['accept'] + s['reject'],
               ('<div style="height:%dpx;background:#dc2626;border-radius:3px 3px 0 0;'
                'line-height:%dpx;font-size:1px">&nbsp;</div>' % (r, r)) if r else '',
               '<div style="height:%dpx;background:#16a34a;%sline-height:%dpx;font-size:1px">'
               '&nbsp;</div>' % (max(a, 1), '' if r else 'border-radius:3px 3px 0 0;', max(a, 1)),
               _h(day)))
    legend = ('<div style="margin-top:6px;font-size:11.5px;color:#6b7280;%s">'
              '<span style="color:#16a34a">■</span> %s &nbsp; <span style="color:#dc2626">■</span>'
              ' %s</div>' % (AL_FONT, _h(_al(lang, 'v pořádku', 'went well')),
                             _h(_al(lang, 'k pozornosti', 'worth a look'))))
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:4px 0 4px;table-layout:fixed"><tr>%s</tr></table>%s'
            % (''.join(cols), legend))


def report_build(store, since, until, lang='cs'):
    """The report of a period, as a mail: (subject, html, text) - the engine's
    own (the events, the sign-ins to the administration, what is wrong, the
    servers) and a section of each module's (HOOKS['report'])."""
    site = str(CONFIG.get('site_name') or socket.gethostname())
    db = store.db
    days = max(1, int(round((until - since) / 86400)))
    # By day, whatever the period: the events that went well and those worth a
    # look. Counted by the database, a day a row (never the rows themselves read in).
    slot = ('CAST((ts - ?) / 86400 AS INTEGER)' if db.engine == 'sqlite'
            else 'FLOOR((ts - ?) / 86400)')
    rows = db.rows("SELECT %s AS d, CASE WHEN level IN ('warn', 'bad') THEN 'warn' ELSE 'info' "
                   "END AS lv, COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ? GROUP BY 1, 2"
                   % slot, (since, since, until)) if days <= 62 else []
    per = collections.OrderedDict()
    for i in range(min(days, 62)):
        per[i] = {'t': since + i * 86400, 'accept': 0, 'reject': 0}
    for r in rows:
        i = int(r['d'] or 0)
        if i in per:
            per[i]['reject' if r['lv'] == 'warn' else 'accept'] += int(r['n'] or 0)
    total = int(db.value('SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ?',
                         (since, until), 0) or 0)
    worth = int(db.value("SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ? AND level IN "
                         "('warn', 'bad')", (since, until), 0) or 0)
    admins = db.rows("SELECT words, ts, level FROM events WHERE ts >= ? AND ts < ? AND "
                     "kind = 'sign-ins' ORDER BY ts DESC LIMIT 400", (since, until))
    adm_bad = [a for a in admins if a.get('level') in ('warn', 'bad')]
    important = db.rows("SELECT ts, kind, level, who, words FROM events WHERE ts >= ? AND ts < ? "
                        "AND level IN ('warn', 'bad') AND kind <> 'sign-ins' ORDER BY ts DESC "
                        "LIMIT 25", (since, until))
    kinds = db.rows("SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ? GROUP BY "
                    "kind ORDER BY n DESC", (since, until))
    probs = alert_problems(store, lang)
    # The modules' own sections (HOOKS['report']): (heading, [lines]) each.
    sections = []
    for fn in HOOKS['report']:
        try:
            for heading, lines in list(fn(store, since) or []):
                sections.append((str(heading), [str(x) for x in (lines or [])]))
        except Exception as e:                          # noqa: BLE001
            log_sparing('report-hook', 'a module\'s part of the report: %s: %s'
                        % (getattr(fn, '__qualname__', fn), e), 'warn', every=600)
    period = '%s – %s' % (time.strftime('%d.%m.%Y', time.localtime(since)),
                          time.strftime('%d.%m.%Y', time.localtime(until - 1)))
    every = CONFIG.get('report_every') or 'weekly'
    kind_w = {'daily': _al(lang, 'Denní', 'Daily'), 'weekly': _al(lang, 'Týdenní', 'Weekly'),
              'monthly': _al(lang, 'Měsíční', 'Monthly')}.get(every, '')
    title = _al(lang, '%s report', '%s report') % kind_w
    body = []
    body.append('<p style="margin:0 0 12px;font-size:14px;color:#374151">%s <b>%s</b></p>'
                % (_h(_al(lang, 'Období:', 'Period:')), _h(period)))
    body.append(_rep_tiles([
        (_al(lang, 'událostí', 'events'), str(total), 'info'),
        (_al(lang, 'k pozornosti', 'worth a look'), str(worth), 'warn' if worth else 'good'),
        (_al(lang, 'neúspěšných přihlášení', 'sign-ins refused'), str(len(adm_bad)),
         'warn' if adm_bad else 'good'),
        (_al(lang, 'problémů teď', 'problems now'), str(len(probs)), 'bad' if probs else 'good')]))
    for heading, lines in sections:
        body.append(_al_h(heading))
        body.append(''.join('<p style="margin:0 0 4px;font-size:13.5px;color:#374151">%s</p>'
                            % _h(x) for x in lines) or
                    '<p style="margin:0 0 4px;font-size:13px;color:#9ca3af">–</p>')
    if per:
        body.append(_al_h(_al(lang, 'Události po dnech', 'Events by day')))
        body.append(_rep_bars(list(per.values()), lang))
    if probs:
        body.append(_al_h(_al(lang, 'Co je teď špatně', 'What is wrong now')))
        for p in probs.values():
            body.append(_al_card(p['level'], p['title'], [_h(p['said'])] + (
                ['<span style="color:#6b7280">%s %s</span>' % (_h(_al(lang, 'Uzel:', 'Node:')),
                                                                _h(p['node']))]
                if p.get('node') else [])))
    body.append(_al_h(_al(lang, 'Přihlášení do administrace', 'Sign-ins to the administration')))
    body.append('<p style="margin:0 0 6px;font-size:13.5px;color:#374151">%s</p>' % _h(
        _al(lang, 'Celkem %d záznamů, z toho %d neúspěšných nebo s varováním.',
            '%d in all, %d of them failed or warned about.') % (len(admins), len(adm_bad))))
    body.append(_rep_table([_al(lang, 'Kdy', 'When'), _al(lang, 'Co', 'What')],
                           [[_h(_al_when(a['ts'])), _h(str(a['words'])[:600])] for a in adm_bad[:10]]))
    body.append(_al_h(_al(lang, 'Důležité události', 'Events worth a look')))
    body.append(_rep_table([_al(lang, 'Kdy', 'When'), _al(lang, 'Druh', 'Kind'), _al(lang, 'Co', 'What')],
                           [[_h(_al_when(e['ts'])), _h(e.get('kind') or ''),
                             '<span style="color:%s">%s</span>' % (
                                 AL_COLORS['bad' if e.get('level') == 'bad' else 'warn'][2],
                                 _h(str(e.get('words') or '')[:600]))] for e in important]))
    body.append('<p style="margin:4px 0 0;font-size:12.5px;color:#6b7280">%s %s</p>' % (
        _h(_al(lang, 'Všechny události podle druhu:', 'All events by kind:')),
        _h(', '.join('%s %d' % (k['kind'], int(k['n'])) for k in kinds) or '–')))
    # The servers.
    srows = []
    cluster = ha_nodes(store) if CONFIG.get('ha_mode') else []
    for n in [x['name'] for x in cluster] or [node_name()]:
        h = _meta_json(store, 'host:health:' + n) or {}
        ck = _meta_json(store, 'host:osup:check:' + n) or {}
        tr = (((_meta_json(store, 'ntp:now:' + n) or {}).get('data') or {}).get('tracking') or {})
        disk = max([d.get('pct') or 0 for d in h.get('disks') or []] or [0])
        srows.append([_h(n), '%s %%' % disk, ('%.3f s' % float(tr['offset'])) if tr else '–',
                      ('%s / %s' % (ck.get('count', '–'), ck.get('security', '–'))) if ck else '–',
                      _h(_al_when(h.get('last_backup')))])
    body.append(_al_h(_al(lang, 'Servery', 'The servers')))
    body.append(_rep_table([_al(lang, 'Uzel', 'Node'), '#' + _al(lang, 'Disk', 'Disk'),
                            '#' + _al(lang, 'Čas', 'Clock'),
                            '#' + _al(lang, 'Aktualizace / bezp.', 'Updates / security'),
                            '#' + _al(lang, 'Noční záloha', 'Nightly copy')], srows))
    runs = [r for r in rb_history(store) if since <= float(r.get('at') or 0) < until]
    if CONFIG.get('rbackup') or runs:
        ok = len([r for r in runs if r.get('ok')])
        body.append('<p style="margin:8px 0 0;font-size:13.5px;color:#374151">%s</p>' % _h(
            _al(lang, 'Zálohy pryč: %d, z toho %d v pořádku.', 'Backups sent: %d, %d of them good.')
            % (len(runs), ok)))
    foot = _h(_al(lang, 'Poslal %s z %s, %s. Nastavení → Upozornění a reporty.',
                  'Sent by %s from %s, %s. Settings → Alerts and reports.')
              % (node_name(), site, _al_when(time.time())))
    # Wide, and the tables' lines never wrapped or cut (1.0.163).
    page = _al_page(lang, title, 'acme · ' + site, AL_COLORS['info'][2], ''.join(body), foot,
                    width=0)
    text = ['%s - %s' % (title, site), period, '',
            _al(lang, 'Událostí: %d, k pozornosti %d. Přihlášení do administrace: %d, '
                      'neúspěšných %d.',
                'Events: %d, worth a look %d. Sign-ins to the administration: %d, refused %d.')
            % (total, worth, len(admins), len(adm_bad)), '']
    for heading, lines in sections:
        text.append(heading.upper())
        text += ['- %s' % x for x in lines] or ['-']
        text.append('')
    if probs:
        text.append(_al(lang, 'Co je teď špatně:', 'What is wrong now:'))
        text += ['- %s: %s' % (p['title'], p['said']) for p in probs.values()]
        text.append('')
    text.append(_al(lang, 'Důležité události:', 'Events worth a look:'))
    text += ['- %s %s: %s' % (_al_when(e['ts']), e.get('kind') or '', str(e.get('words') or '')[:300])
             for e in important] or ['-']
    subject = _al(lang, '[acme] %s report %s - %s', '[acme] %s report %s - %s') % (kind_w, period,
                                                                                 site)
    return subject, page, '\n'.join(text)


def report_send(store, since=None, until=None, to=None, by='', reader=None):
    """`reader`: the pages' own connection for the long counts (1.0.162) -
    never the one every sign-in shares."""
    lang = report_lang()
    if since is None:
        since, until, _ = report_period()
    to = to or _alerts_to('report_to')
    if not to:
        raise ValueError('no address to send the report to - Report to, or Alerts to')
    subject, page, text = report_build(reader or store, since, until, lang)
    msg = _al_msg(subject, page, text, to)
    entry = alert_send(store, msg, to, 'report', [])
    if by:
        store.add_event('settings', '%s sent the report (%s) to %s%s' % (
            by, time.strftime('%d.%m.%Y', time.localtime(since)), ', '.join(to),
            '' if entry['ok'] else ' - it did not go: %s' % entry.get('said')), 'info', who=by)
    return entry


def alerts_tick(daemon):
    """Every minute: this node's own row; on the node that sends them, the
    alerts and the report when it is due. In a thread of its own - a mail
    server that takes its time holds nothing up."""
    if time.monotonic() - ALERT_WORK['at'] < ALERTS_EVERY or ALERT_WORK['busy']:
        return
    ALERT_WORK['at'] = time.monotonic()  # (1.0.207)
    ALERT_WORK['busy'] = True

    def go():
        store = daemon.store
        try:
            try:
                health_publish(daemon)
            except Exception as e:                      # noqa: BLE001
                log_sparing('health', 'this node\'s health row: %s' % e, 'warn', every=900)
            logs_start(daemon)
            if not alerts_lead(store):
                return
            cur = None
            if CONFIG.get('alerts') or CONFIG.get('report'):
                cur = alerts_evaluate(store)['now']
            if CONFIG.get('snmp') and CONFIG.get('snmp_traps'):
                # SNMPv3 traps (1.0.182): what the alerts see, apart from the mails.
                try:
                    snmp_traps_tick(daemon, cur if cur is not None else
                                    alert_problems(store, 'en'))
                except Exception as e:              # noqa: BLE001
                    log_sparing('snmp-traps', 'SNMPv3 traps: %s' % e, 'warn', every=900)
            if CONFIG.get('report') and report_due():
                since, until, pid = report_period()
                was_sent = store.get_meta('report:sent')
                if was_sent != pid and claim_once(store, 'report:sent', pid):
                    try:
                        report_send(store, since, until, reader=daemon.reader())
                    except Exception as e:      # noqa: BLE001
                        # The period given back (1.0.207): claimed before it was
                        # made, a report that failed to be made was never tried again.
                        if not isinstance(e, MailError):
                            try:
                                if store.get_meta('report:sent') == pid:
                                    store.set_meta('report:sent', was_sent or '')
                            except Exception:   # noqa: BLE001
                                pass
                        log_sparing('report-fail', 'the report did not go: %s' % e, 'warn',
                                    every=3600)
        except Exception as e:                          # noqa: BLE001
            log_sparing('alerts', 'the alerts: %s' % e, 'warn', every=900)
        finally:
            ALERT_WORK['busy'] = False
    threading.Thread(target=go, name='acme-alerts', daemon=True).start()


def alerts_view(store):
    lang = CONFIG.get('ui_lang') or 'en'
    st = _alert_state(store)
    now = alert_problems(store, 'en')
    nodes = [n['name'] for n in ha_nodes(store)] if CONFIG.get('ha_mode') else [node_name()]
    since, until, pid = report_period()
    return {'problems': [dict(p, key=k, since=(st['problems'].get(k) or {}).get('since'),
                              sent=bool((st['problems'].get(k) or {}).get('sent')))
                         for k, p in sorted(now.items(), key=lambda kv: (kv[1]['level'] != 'bad', kv[0]))],
            'log': st['log'][:30], 'checked': st.get('checked'),
            'health': {n: _meta_json(store, 'host:health:' + n) or {} for n in nodes},
            'to': _alerts_to(), 'report_to': _alerts_to('report_to'),
            'mail': (CONFIG.get('mail_mode') or 'off') != 'off', 'lead': alerts_lead(store),
            'report': {'since': since, 'until': until, 'sent': store.get_meta('report:sent') == pid},
            'link': alerts_link(), 'lang': lang}


