# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- changes that could cut the server off: kept, or taken back (1.0.137) -------------
# A node's new network and a change of the firewall (or of who may reach the
# pages) are put in on trial: unless somebody presses Keep it - on the pages
# of either node, `acme --change-keep`, or the console - within net_confirm_min
# / fw_confirm_min minutes, what was there before comes back by itself. A typo
# in a gateway, a prefix, or a DROP rule in front of SSH no longer leaves the
# machine to be put right at its console.
#
# The network: the node keeps what it had (its NetworkManager settings, its
# host name) in its job; back up after the reboot the job waits as 'trial'.
# Not kept in time - or come up without the new address at all - the node
# asks itself for the old network, which is the same job the other way round
# (a reboot, the other node told the old address again). So that the other
# node can still be told, its pg_hba.conf keeps letting the old address in
# while the new one is on trial; kept, it lets only the new one in again.
# Who asks to keep or to go back writes 'net:keep:NODE' / 'net:back:NODE'; the
# node itself writes its job, as before.
#
# The firewall: what was set before the first change of a trial is kept in
# 'fw:trial'; later changes in the same trial move its deadline on. Not kept in
# time, one node (claim_once) puts it back; every node puts that in as usual.

def net_back_want(now):
    """What the node has now, as a request for the network page would say it -
    what it goes back to. None (and why) where it cannot be said so. The root
    helper keeps the network itself whole as well (1.0.139) and puts that back;
    this is what the other node is told, and what is asked where nothing was
    kept."""
    d = (now or {}).get('data') or {}
    conf = d.get('conf') or {}
    live = d.get('live') or {}
    addr = net_current_ip(now or {})
    if not addr or '/' not in addr:
        return None, 'what the node has now could not be read (%s) - it cannot be put back ' \
                     'by itself' % (conf.get('ipv4_method') or '?')
    m6 = conf.get('ipv6_method')
    on6 = m6 not in (None, '', 'disabled', 'ignore')
    manual = conf.get('ipv4_method') == 'manual'
    return {'con': d.get('con') or '',
            'ipv4': {'addr': addr, 'gw': conf.get('ipv4_gateway') or ('' if manual else
                                                                       live.get('gw4') or ''),
                     'dns': list(conf.get('ipv4_dns') or [x for x in live.get('dns') or []
                                                          if ':' not in x][:4]),
                     'search': list(conf.get('ipv4_search') or [])},
            'ipv6': {'on': on6, 'mode': 'manual' if m6 == 'manual' else 'auto',
                     'addr': (conf.get('ipv6_addresses') or [''])[0] if m6 == 'manual' else '',
                     'gw': conf.get('ipv6_gateway') or '', 'dns': list(conf.get('ipv6_dns') or [])},
            'hostname': str(d.get('hostname') or ''), 'vip_elsewhere': True}, ''


def net_trial_min():
    return int(CONFIG.get('net_confirm_min') or 0)


def net_trial_start(store, job, by):
    """Back up after the reboot, all well: the job waits to be kept."""
    n = int(job.get('trial_min') or 0)
    job['trial_until'] = time.time() + n * 60
    _job_put(store, job, 'it waits to be kept: Keep it within %d min (Settings - Network, '
             'the banner on every page, or  acme --change-keep net --node %s), or the old '
             'network comes back by itself at %s' % (
                 n, node_name(), time.strftime('%H:%M', time.localtime(job['trial_until']))),
             99, state='trial')
    store.add_event('settings', 'the new network of %s is on trial: kept within %d min, or it '
                    'goes back to %s' % (node_name(), n, (job.get('want') or {}).get('old_ip')),
                    'warn', who=by)


def net_go_back(daemon, job, why):
    """The old network asked for, on this node - the same job the other way."""
    store = daemon.store
    me = node_name()
    back = job.get('back')
    job['back_asked'] = time.time()
    if not back:
        _job_put(store, job, 'not kept (%s), and it cannot go back by itself: %s' % (
            why, job.get('back_why') or '?'), job.get('pct'), ok=False, state='failed')
        store.add_event('settings', 'the old network of %s could not be put back: not kept (%s), and '
                        'it cannot go back by itself' % (me, why), 'bad')      # mailed (as otp 1.0.242)
        return
    # The network as it is now read first: going back is planned from what
    # the node has (the new address), so the other node is told the old one.
    try:
        net_publish(store)
    except Exception as e:                              # noqa: BLE001
        log('network: read before going back: %s' % e, 'warn')
    _job_put(store, job, 'not kept: %s - the old network (%s) comes back' % (
        why, (back.get('ipv4') or {}).get('addr')), job.get('pct'), ok=False,
        state='going back')
    # In the events too (as otp 1.0.242): mailed, as the firewall's and the SSH server's are.
    store.add_event('settings', '%s went back to the network it had before (%s): %s'
                    % (me, (back.get('ipv4') or {}).get('addr') or '?', why), 'warn')
    try:
        net_ask(store, me, back, 'acme (%s)' % why, rollback=True, maint=bool(job.get('maint')),
                snap=job.get('snap') or '')
    except Exception as e:                              # noqa: BLE001
        _job_put(store, job, 'the old network could not be asked for: %s' % e, job.get('pct'),
                 ok=False, state='failed')
        store.add_event('settings', 'the old network of %s could not be put back: %s' % (me, e),
                        'bad')


def net_trial_tick(daemon, job):
    """A job on trial: kept, asked to go back, or out of time."""
    store = daemon.store
    me = node_name()
    keep = _meta_obj(store, 'net:keep:' + me)
    back = _meta_obj(store, 'net:back:' + me)
    if keep.get('id') == job.get('id'):
        job['kept'] = keep.get('by')
        _job_put(store, job, 'kept by %s' % keep.get('by'), 100, state='done')
        store.add_event('settings', '%s kept the new network of %s' % (keep.get('by'), me),
                        who=keep.get('by'))
        w = job.get('want') or {}
        # Only where the other node was told a new address (1.0.56, as otp
        # 1.0.262 R3-1): a trial of a gateway, DNS or host name kept, the
        # other node dropped "the old" line - the one this node still uses.
        if job.get('keep_old') and job.get('told') and w.get('ip_changed') and \
                w.get('old_ip') and w.get('new_ip') and \
                _addr_key(w['old_ip']) != _addr_key(w['new_ip']):
            # The other node may let only the new address in again.
            store.set_meta('readdress:dropold:' + me, json.dumps({
                'id': job.get('id'), 'from': me, 'old': w['old_ip'], 'new': w['new_ip'],
                'at': time.time()}))
        return
    if back.get('id') == job.get('id'):
        net_go_back(daemon, job, 'put back by %s' % back.get('by'))
        return
    if time.time() > float(job.get('trial_until') or 0):
        net_go_back(daemon, job, 'not kept within %d min' % int(job.get('trial_min') or 0))


def net_trial_answer(store, node, act, by):
    """The pages (of either node) or the command line: keep it, or go back."""
    job = _meta_obj(store, 'net:job:' + node)
    if job.get('state') != 'trial':
        raise ValueError('the network of %s is not waiting to be kept' % node)
    store.set_meta('net:%s:%s' % ('keep' if act == 'keep' else 'back', node),
                   json.dumps({'id': job.get('id'), 'by': by, 'at': time.time()}))
    return ('kept - %s says so within a few seconds' % node if act == 'keep' else
            'the old network comes back - %s restarts with it' % node)


def readdress_dropold_tick(store):
    """The other node's new address kept: its old one no longer let in."""
    me = node_name()
    for r in dbguard_rows(store.db, store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'readdress:dropold:%'")):
        try:
            ask = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(ask, dict) or ask.get('from') in (me, None):
            continue
        done_key = 'readdress:dropold:done:' + me
        if (store.get_meta(done_key) or '') == str(ask.get('id')):
            continue
        if _addr_key(ask.get('old')) == _addr_key(ask.get('new')):
            # Nothing to drop (1.0.56): "the old" line is the one in use
            # (a row of an older version, written for a trial that kept the address).
            store.set_meta(done_key, str(ask.get('id')))
            continue
        try:
            said = _readdress_hba(ask['old'], ask['new'], False, drop_old=True)
            log('the other node kept its new address %s: %s' % (ask['new'], said), 'info')
        except Exception as e:                          # noqa: BLE001
            log('the old address of the other node could not be taken out of pg_hba.conf: %s'
                % e, 'warn')
        store.set_meta(done_key, str(ask.get('id')))


