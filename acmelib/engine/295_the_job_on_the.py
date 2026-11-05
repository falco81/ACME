# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the job, on the node it is about -------------------------------------------------
def _job_put(store, job, words=None, pct=None, ok=True, state=None):
    if words:
        job.setdefault('steps', []).append({'at': time.time(), 'what': str(words)[:400],
                                            'ok': bool(ok)})
        log('network: %s' % words, 'info' if ok else 'warn')
    if pct is not None:
        job['pct'] = int(pct)
    if state:
        job['state'] = state
    job['moved'] = time.time()
    store.set_meta('net:job:' + node_name(), json.dumps(job))


def _cert_names_swap(names, swap):
    out = []
    for n in names:
        n = swap.get(n, n)
        if n and n not in out:
            out.append(n)
    return out


def net_cert_again(store, w, by):
    """This node's own certificate, made here, made again with the new
    address and name where it named the old ones. One from an authority is
    said, not changed."""
    me = node_name()
    prof = tls_profile(store, me)
    if not prof or not prof.get('cert'):
        return ''
    info = prof.get('info') or {}
    try:
        info = cert_info(prof['cert'])
    except ValueError:
        pass
    names = list(info.get('san') or [])
    cn = info.get('cn') or ''
    swap = {}
    if w['ip_changed'] and w['old_ip']:
        swap[w['old_ip']] = w['new_ip']
    if w['hostname'] and w['old_hostname'] and w['hostname'] != w['old_hostname']:
        swap[w['old_hostname']] = w['hostname']
        swap[w['old_hostname'].split('.')[0]] = w['hostname'].split('.')[0]
    if not any(k in names or k == cn for k in swap):
        return ''
    if not info.get('self_signed'):
        return ('this node\'s certificate is from an authority and names %s - get one for %s'
                % (', '.join(k for k in swap if k in names or k == cn),
                   ', '.join(swap[k] for k in swap if k in names or k == cn)))
    kind = 'rsa2048'
    k = str(info.get('key') or '')
    if k.startswith('EC'):
        kind = 'ec'
    elif '4096' in k:
        kind = 'rsa4096'
    elif '3072' in k:
        kind = 'rsa3072'
    new_names = _cert_names_swap(names, swap)
    if w['ipv6'].get('addr'):
        ip6 = w['ipv6']['addr'].split('/')[0]
        if ip6 not in new_names:
            new_names.append(ip6)
    new_cn = swap.get(cn, cn) or w['hostname']
    key, crt = make_selfsigned(new_cn, [x for x in new_names if x != new_cn], 825, kind)
    got = cert_bundle(crt, key)
    prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                key=seal_secret(got['key'], 'web:tls'), info=got['info'],
                chain_info=got['chain_info'], root_info=got['root_info'],
                verify=got['verify'], how='self-signed, made here (the network changed)')
    tls_save(store, me, prof, by)
    return 'this node\'s own certificate made again for %s' % ', '.join(new_names[:6])


NET_UNDO_KEYS = ('snmp_bind', 'mail_helo', 'isemon_hostname')
NET_UNDO_FILE_KEYS = ('db_host', 'ha_address')


def net_undo_keep(store, snap):
    """This node's own settings and certificate as they are before a change on
    trial (1.0.139) - not in the job, which the pages read."""
    store.set_meta('net:undo:' + node_name(), json.dumps({
        'snap': snap, 'at': time.time(),
        'settings': {k: CONFIG.get(k) for k in NET_UNDO_KEYS},
        'file': {k: FILE_CONFIG.get(k) for k in NET_UNDO_FILE_KEYS if k in FILE_CONFIG},
        'tls': store.get_meta('web:tls:' + node_name()) or ''}))


def net_undo_get(store, snap):
    got = _meta_obj(store, 'net:undo:' + node_name())
    return got if snap and got.get('snap') == snap else None


def net_job_undo_told(daemon, job, by):
    """A job stopped before the network changed, after the other node was told
    the new address (1.0.146): its pg_hba.conf, its subscription and its
    ha_peer - and this node's ha_address - moved back to the address the node
    still has. Left, the cluster pointed at an address that never came."""
    w = job.get('want') or {}
    if not job.get('told') or not w.get('ip_changed') or not w.get('old_ip'):
        return
    store = daemon.store
    try:
        got = ha_readdress(store, mine=w['old_ip'], by='%s (put back)' % by, daemon=daemon)
        _job_put(store, job, 'the other node told the address again: %s' % (
            got.get('message') or w['old_ip']), job.get('pct'), ok=not got.get('left'))
    except Exception as e:                              # noqa: BLE001
        _job_put(store, job, 'the other node could not be told the address again (%s): '
                 'Settings → High availability → The addresses of the two nodes' % e,
                 job.get('pct'), ok=False)
    job['told'] = False


def net_job_run(daemon, ask):
    store = daemon.store
    me = node_name()
    w = ask['want']
    by = '%s (network)' % (ask.get('by') or 'acme')
    job = {'id': ask['id'], 'node': me, 'state': 'running', 'at': time.time(), 'pct': 0,
           'by': ask.get('by'), 'want': w, 'steps': [], 'boot': boot_time()}
    many = bool(CONFIG.get('ha_mode'))
    # On trial (1.0.137): what the node has now kept, to go back to unless the
    # new one is kept in time.
    if net_trial_min() and not ask.get('rollback'):
        job['back'], job['back_why'] = net_back_want(net_node_now(store, me))
        job['trial_min'] = net_trial_min() if job['back'] else 0
        if job['trial_min']:
            # Going back puts back exactly what is here now (1.0.139): the root
            # helper keeps the network whole, this node its own settings and
            # certificate - not worked out again the other way round.
            job['snap'] = secrets.token_hex(8)
            net_undo_keep(store, job['snap'])
    job['rollback'] = bool(ask.get('rollback'))
    undo = net_undo_get(store, ask.get('snap')) if ask.get('rollback') else None
    # Maintenance put on by the job it goes back from: taken off by this one.
    if ask.get('maint'):
        job['maint'] = True
    job['keep_old'] = bool(job.get('trial_min')) and CONFIG.get('ha_mode') == 'replicated'
    try:
        _job_put(store, job, 'started - %s' % '; '.join(w['plan'][:2]), 3)
        if job.get('trial_min'):
            _job_put(store, job, 'on trial: unless it is kept within %d min of coming back up, '
                     'the network it has now comes back by itself' % job['trial_min'], 4)
        elif job.get('back_why'):
            _job_put(store, job, job['back_why'], 4, ok=False)
        # 1. The node keeps its name, whatever the machine is called.
        if not str(FILE_CONFIG.get('node_name') or '').strip():
            write_file_settings({'node_name': me})
            CONFIG['node_name'] = me
            _job_put(store, job, 'the node\'s name %s kept in config.json, whatever the host '
                     'name' % me, 8)
        # 2. The other node told the new address.
        if w['ip_changed'] and CONFIG.get('ha_mode') == 'replicated':
            _job_put(store, job, 'telling the other node %s' % w['new_ip'], 12)
            # From here the other node (and ha_address) may have the new one:
            # stopped before the network changed, they are told back (1.0.146).
            job['told'] = True
            asked_at = time.time()
            got = ha_readdress(store, mine=w['new_ip'], by=by, daemon=daemon,
                               keep_old=job.get('keep_old'))
            if got.get('left'):
                if not job.get('rollback'):
                    raise ValueError('; '.join(got['left']))
                # Going back from an address the other node cannot reach:
                # told once this node is back at its old one (1.0.137).
                job['tell_after'] = True
                _job_put(store, job, 'the other node is told once this node is back at %s'
                         % w['new_ip'], 25, ok=False)
            end = time.time() + (0 if job.get('tell_after') else 90)
            done = None
            while time.time() < end:
                a = _meta_obj(store, 'readdress:ask')
                # This job's request, not one answered before (1.0.146).
                if a.get('from') == me and a.get('done') and \
                        float(a.get('at') or 0) >= asked_at - 1:
                    done = a
                    break
                time.sleep(2)
            if done and done.get('error'):
                raise ValueError('the other node: %s' % done['error'])
            if not job.get('tell_after'):
                _job_put(store, job, 'the other node expects %s now%s' % (
                    w['new_ip'], '' if done else ' (it had not said so yet - it does it by '
                    'itself)'), 25)
        elif w['ip_changed'] and CONFIG.get('ha_address'):
            write_file_settings({'ha_address': w['new_ip']})
            CONFIG['ha_address'] = w['new_ip']
        # 3. This node's own settings that name the old address or name.
        changes = {}
        sb = str(CONFIG.get('snmp_bind') or '')
        if undo:
            # Back to the values it had, as they were.
            changes = {k: v for k, v in (undo.get('settings') or {}).items()
                       if str(CONFIG.get(k) or '') != str(v or '')}
        elif w['ip_changed'] and sb == w['old_ip']:
            changes['snmp_bind'] = w['new_ip']
        if not undo and w['hostname'] and w['old_hostname'] and \
                w['hostname'] != w['old_hostname']:
            for k in ('mail_helo', 'isemon_hostname'):
                if str(CONFIG.get(k) or '') in (w['old_hostname'], w['old_hostname'].split('.')[0]):
                    changes[k] = w['hostname']
        if changes:
            daemon.save_settings(changes, by=by, node=me)
            _job_put(store, job, 'this node\'s settings: %s' % ', '.join(
                '%s = %s' % kv for kv in sorted(changes.items())), 35)
        if undo:
            files = {k: v for k, v in (undo.get('file') or {}).items()
                     if str(FILE_CONFIG.get(k) or '') != str(v or '')}
            if files:
                write_file_settings(files)
                CONFIG.update(files)
                _job_put(store, job, 'config.json as it was: %s' % ', '.join(
                    '%s = %s' % kv for kv in sorted(files.items())), 37)
        elif w['ip_changed'] and str(CONFIG.get('db_host') or '') == w['old_ip']:
            write_file_settings({'db_host': w['new_ip']})
            _job_put(store, job, 'db_host = %s' % w['new_ip'], 37)
        # 4. Its own certificate - going back, the one it had.
        if undo and undo.get('tls') is not None:
            if (store.get_meta('web:tls:' + me) or '') != undo['tls']:
                if undo['tls']:
                    store.set_meta('web:tls:' + me, undo['tls'])
                else:
                    store.db.run('DELETE FROM meta WHERE k = ?', ('web:tls:' + me,))
                _job_put(store, job, 'this node\'s certificate as it was before', 45)
        else:
            try:
                said = net_cert_again(store, w, by)
                if said:
                    _job_put(store, job, said, 45, ok='authority' not in said)
            except ValueError as e:
                _job_put(store, job, 'this node\'s certificate could not be made again: %s' % e,
                         45, ok=False)
        # 5. Out of the way: the VIP address to the other node.
        if many:
            if not (maintenance_row(store) or {}).get('on'):
                maintenance_set(store, True, 'the network is being changed', by)
                job['maint'] = True
            _job_put(store, job, 'maintenance on - the VIP address goes to the other node', 55)
            v = vip_conf(store)
            end = time.time() + 30
            while v.get('on') and vip_here(v.get('address')) and time.time() < end:
                time.sleep(1)
        # 6. The network, the name - and the reboot.
        job['down_at'] = time.time()
        job['wait_from'] = time.time()      # how long the restart is waited for (1.0.147)
        _job_put(store, job, 'NetworkManager, the host name and /etc/hosts', 70, state='rebooting')
        got = None
        if ask.get('rollback') and ask.get('snap'):
            try:
                got = net_root({'do': 'restore', 'snapshot': ask['snap'], 'reboot_in': 8}, 90)
            except ValueError as e:
                _job_put(store, job, 'what was kept could not be put back (%s) - the old '
                         'addresses are asked for instead' % e, 72, ok=False)
        if got is None:
            got = net_root({'do': 'apply', 'con': w['con'], 'ipv4': w['ipv4'],
                            'ipv6': {'mode': w['ipv6']['mode'] if w['ipv6']['on'] else 'off',
                                     'addr': w['ipv6']['addr'], 'gw': w['ipv6']['gw'],
                                     'dns': w['ipv6']['dns']},
                            'hostname': w['hostname'],
                            'old': [w['old_ip']] if w['old_ip'] else [],
                            'old_hostname': w['old_hostname'], 'reboot_in': 8,
                            'snapshot': job.get('snap') or '',
                            'rollback': bool(ask.get('rollback'))}, 90)
        job['before'] = got.get('before') or {}
        job['down_at'] = time.time() + 8
        _job_put(store, job, '; '.join(got.get('said') or []) or 'set', 80)
        _job_put(store, job, 'restarting %s - back in a minute or two at %s' % (
            me, w['new_ip']), 85)
    except Exception as e:                              # noqa: BLE001
        job['error'] = str(e)[:400]
        if job.get('state') == 'rebooting' and 'did not answer' in str(e):
            # Root may still put it in and restart (1.0.146): waited for, and
            # checked after the restart as any other - not left failed.
            _job_put(store, job, 'root did not answer in time - it may still put the network '
                     'in and restart; waiting for that', job.get('pct'), ok=False)
            return
        net_job_undo_told(daemon, job, by)
        if job.get('maint'):
            try:
                maintenance_set(store, False, '', by)
            except Exception:                           # noqa: BLE001
                pass
        _job_put(store, job, 'stopped: %s - nothing of the network was changed' % e
                 if job.get('state') != 'rebooting' else 'stopped: %s' % e, job.get('pct'),
                 ok=False, state='failed')
        store.add_event('settings', 'the new network of %s was not put in: %s' % (me, e),
                        'bad', who=by)


def net_job_after(daemon, job):
    """Back up after the reboot: is it what was asked, and is the cluster
    whole again."""
    store = daemon.store
    me = node_name()
    w = job.get('want') or {}
    by = '%s (network)' % (job.get('by') or 'acme')
    many = bool(CONFIG.get('ha_mode'))
    _job_put(store, job, '%s is back up' % me, 88)
    have = set(a for a in local_addresses() if not a.startswith('fe80'))
    if w.get('new_ip') and w['new_ip'] not in have:
        if job.get('trial_min') and job.get('back'):
            # Not even the address: back at once, not after the trial.
            _job_put(store, job, '%s came up without %s (it has %s)' % (
                me, w['new_ip'], ', '.join(sorted(have)) or 'none'), 90, ok=False)
            net_go_back(daemon, job, 'it came up without its new address')
            return
        _job_put(store, job, '%s came up without %s (it has %s) - look at its console; it stays '
                 'in maintenance' % (me, w['new_ip'], ', '.join(sorted(have)) or 'none'),
                 90, ok=False, state='failed')
        store.add_event('settings', '%s came up without its new address %s' % (me, w['new_ip']),
                        'bad', who=by)
        return
    words = ['%s is at %s' % (me, w.get('new_ip'))]
    if w.get('ipv6', {}).get('on'):
        six = [a for a in have if ':' in a]
        words.append('IPv6: %s' % (', '.join(six) or 'none yet'))
    if w.get('hostname') and socket.gethostname().split('.')[0] != w['hostname'].split('.')[0]:
        words.append('the host name is %s, not %s' % (socket.gethostname(), w['hostname']))
    _job_put(store, job, '; '.join(words), 90)
    try:
        net_publish(store)
    except Exception:                                   # noqa: BLE001
        pass
    if job.get('tell_after') and CONFIG.get('ha_mode') == 'replicated':
        d2, l2 = readdress_tell(str(CONFIG.get('ha_peer') or ''), w.get('new_ip') or '', by)
        _job_put(store, job, '; '.join(d2 + l2), 91, ok=not l2)
    if CONFIG.get('ha_mode') == 'replicated':
        hatls_check_soon()
        good = net_repl_wait(store, 240)
        _job_put(store, job, 'replication both ways: running' if good else
                 'replication is not running both ways yet - Settings → High availability '
                 'says why; the link between the databases puts itself right within minutes',
                 96, ok=good)
    if CONFIG.get('ha_mode') == 'replicated' and (hatls_want(store) or CONFIG.get('ha_tls')) \
            and not (hatls_want(store) or {}).get('off'):
        # The link between the databases encrypted and checked again for the
        # address the node has now (1.0.139) - both nodes' steps done, and this
        # node's certificate naming every address the other reaches it by.
        hatls_check_soon()
        end = time.time() + 300
        ok, said = False, ''
        while time.time() < end:
            ok, said = net_hatls_ok(store)
            if ok:
                break
            time.sleep(5)
        _job_put(store, job, 'the link between the databases: %s' % said, 97, ok=ok)
        if ok and not good:
            good = net_repl_wait(store, 120)
            _job_put(store, job, 'replication both ways: running' if good else
                     'replication is still not running both ways - Settings → High '
                     'availability says why', 97, ok=good)
    if many and vip_conf(store).get('on'):
        # keepalived set up for the new address (1.0.120): asked before the
        # restart it failed - the machine did not have the address yet - and a
        # failed request is asked again only when somebody says so.
        ok, said = net_vip_again(store)
        _job_put(store, job, 'the VIP address (keepalived) set up for %s: %s' % (
            w.get('new_ip') or me, said) if ok else 'the VIP address (keepalived) on this node: %s - '
            'Settings → High availability, Try again' % said, 97, ok=ok)
    if many and job.get('maint'):
        maintenance_set(store, False, '', by)
        _job_put(store, job, 'out of maintenance - the VIP address may come back', 98)
    if job.get('trial_min') and job.get('back'):
        net_trial_start(store, job, by)
        return
    _job_put(store, job, 'done', 100, state='done')
    store.add_event('settings', 'the network of %s is changed: %s' % (
        me, '; '.join(words)), 'warn', who=by)


def net_repl_wait(store, secs):
    """Replication running both ways within `secs`."""
    end = time.time() + secs
    while True:
        rep = ha_repl_state(store)
        inc = rep.get('incoming') or []
        outg = rep.get('outgoing') or []
        if inc and all(r.get('enabled') and r.get('running') for r in inc) and \
                outg and all(r.get('active') for r in outg):
            return True
        if time.time() >= end:
            return False
        time.sleep(5)


def net_hatls_ok(store):
    """(ok, words): the link between the databases encrypted and checked, on
    this node and the other."""
    st = hatls_state(store)
    if st.get('step') != 'done':
        return False, 'this node is at the step %s%s' % (
            st.get('step') or 'none', (' (%s)' % st['error'][:200]) if st.get('error') else '')
    pn = hatls_peer_name(store)
    peer = hatls_state(store, pn) if pn else {}
    if pn and peer.get('step') != 'done':
        return False, '%s is at the step %s' % (pn, peer.get('step') or 'none')
    if CONFIG.get('ha_tls') != 'verify-full':
        return False, 'the link is not set to verify-full'
    try:
        _end, sans = hatls_own_cert(store)
    except Exception as e:                              # noqa: BLE001
        return False, str(e)[:200]
    named = set(str(v).lower() for _k, v in sans)
    lack = [n for n in hatls_needs(store) if n.lower() not in named]
    if lack:
        return False, 'this node\'s certificate does not name %s yet' % ', '.join(lack)
    return True, 'encrypted and checked (verify-full) both ways; this node\'s certificate ' \
                 'names %s' % ', '.join(hatls_needs(store))


def _net_thread(fn, *args):
    def go():
        try:
            fn(*args)
        except Exception as e:                          # noqa: BLE001
            log_sparing('net-thread', 'network: %s' % e, 'warn', every=900)    # (1.0.207)
        finally:
            with NET_WORK_LOCK:
                NET_WORK['busy'] = False
    with NET_WORK_LOCK:
        if NET_WORK['busy']:
            return False
        NET_WORK['busy'] = True
    threading.Thread(target=go, name='acme-net', daemon=True).start()
    return True


NET_REBOOT_GIVE_UP_S = 3600


def net_job_stalled(daemon, job, by):
    store = daemon.store
    net_job_undo_told(daemon, job, by)
    if job.get('maint'):
        try:
            maintenance_set(store, False, '', by)
        except Exception:                               # noqa: BLE001
            pass
    _job_put(store, job, 'it stopped half way (the service restarted?)%s' % (
        ' - out of maintenance' if job.get('maint') else ''), job.get('pct'),
        ok=False, state='failed')


def net_job_give_up(daemon, job):
    """A restart waited for an hour that never came (1.0.147). Where the new
    address is on the machine all the same, it is checked as after a
    restart; where it is not, the other node gets this one's address back,
    maintenance ends and the job is failed."""
    w = job.get('want') or {}
    new_ip = str(w.get('new_ip') or '')
    if new_ip and new_ip in set(local_addresses()):
        net_job_after(daemon, job)
        return
    by = '%s (network)' % (job.get('by') or 'acme')
    store = daemon.store
    net_job_undo_told(daemon, job, by)
    if job.get('maint'):
        try:
            maintenance_set(store, False, '', by)
        except Exception:                               # noqa: BLE001
            pass
    _job_put(store, job, 'the machine did not restart in an hour and the new address is not '
             'on it: the other node was given this one\'s address back%s' % (
                 ' and maintenance ended' if job.get('maint') else ''), job.get('pct'),
             ok=False, state='failed')
    store.add_event('settings', 'the new network of %s was not put in: no restart in an hour'
                    % node_name(), 'bad', who=by)


def net_tick(daemon):
    """Every few seconds: something asked of this node, a job to finish after
    a reboot, the network said again now and then."""
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    store = daemon.store
    me = node_name()
    job = _meta_obj(store, 'net:job:' + me) or None
    ask = _meta_obj(store, 'net:want:' + me) or None
    if job and job.get('state') == 'trial':
        net_trial_tick(daemon, job)
        return
    if job and job.get('state') == 'rebooting':
        late = time.time() - float(job.get('wait_from') or job.get('moved') or 0)
        if boot_time() > float(job.get('boot') or 0) + 1:
            _net_thread(net_job_after, daemon, job)
        elif late > NET_REBOOT_GIVE_UP_S:
            # Not for ever (1.0.147): no restart in an hour, and nothing else
            # of the network, the restart or power off went on meanwhile.
            _net_thread(net_job_give_up, daemon, job)
        elif late > 900 and not job.get('late_said'):
            # Still waited for (1.0.146): marked failed, the restart by hand
            # was never followed - no check, no trial, maintenance left on.
            job['late_said'] = True
            _job_put(store, job, 'the machine did not restart in 15 minutes - restart it by '
                     'hand; the network starts as set, and is checked when it is back',
                     job.get('pct'), ok=False)
        return
    if ask and ask.get('node') == me and (not job or job.get('id') != ask.get('id')) and \
            time.time() - float(ask.get('at') or 0) < 600:
        _net_thread(net_job_run, daemon, ask)
        return
    if job and job.get('state') == 'running' and not NET_WORK['busy'] and \
            time.time() - float(job.get('moved') or 0) > 300:
        by = '%s (network)' % (job.get('by') or 'acme')
        if job.get('down_at'):
            # Root was asked already: it may restart with the new network - then
            # it is checked as after any restart (1.0.146).
            job['wait_from'] = time.time()
            _job_put(store, job, 'it stopped while root put the network in (the service '
                     'restarted?) - waiting for the restart', job.get('pct'), ok=False,
                     state='rebooting')
            return
        # On the network's own thread (1.0.147): telling the other node
        # waits for its database.
        _net_thread(net_job_stalled, daemon, job, by)
        return
    if power_tick(daemon):
        return
    wanted = float(store.get_meta('net:read:' + me) or 0)
    if time.time() - NET_WORK['read_at'] > NET_READ_S or wanted > NET_WORK['read_at']:
        _net_thread(net_publish, store)


