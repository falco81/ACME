# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- restart and power off ------------------------------------------------------------
POWER_LIVE_S = 1800


def power_plan(store):
    return _meta_obj(store, 'power:plan')


def power_busy(store):
    p = power_plan(store)
    if not p or time.time() - float(p.get('at') or 0) > POWER_LIVE_S:
        return False
    for n in p.get('targets') or []:
        row = _meta_obj(store, 'power:node:' + n)
        if row.get('id') != p.get('id') or row.get('state') in ('asked', 'going'):
            if p.get('how') == 'poweroff' and row.get('state') == 'going':
                continue
            return True
    return False


def power_ask(store, how, targets, order, by, keep_service=False):
    """`keep_service` (1.0.165): a node goes down only while another one
    answers - asked of every restart one after the other, on a schedule and
    after an update; a node that does not come back stops the rest."""
    if how not in ('reboot', 'poweroff'):
        raise ValueError('reboot or poweroff')
    known = [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]
    targets = [t for t in known if t in (targets or [])]
    if not targets:
        raise ValueError('which node?')
    if order not in ('one', 'rolling', 'together'):
        order = 'one' if len(targets) == 1 else 'rolling'
    if how == 'poweroff' and order == 'rolling':
        order = 'together'
    if power_busy(store):
        raise ValueError('a restart or a power-off is under way already')
    for t in targets:
        if net_job_active(_meta_json(store, 'net:job:' + t)):
            raise ValueError('%s is changing its network' % t)
    if order == 'rolling':
        # The node this page is not on last: the page stays with the other
        # while the first restarts.
        targets.sort(key=lambda n: n == node_name())
    keep_service = bool(keep_service or (order == 'rolling' and len(targets) > 1))
    if keep_service and CONFIG.get('ha_mode') and how == 'reboot':
        alive = [n['name'] for n in ha_nodes(store) if n.get('alive') or n.get('me')]
        if len(alive) < 2:
            raise ValueError('only %s answers: restarting it would stop the service - bring the '
                             'other node back first' % (', '.join(alive) or 'this node'))
    plan = {'id': secrets.token_hex(6), 'how': how, 'targets': targets, 'order': order,
            'by': by, 'at': time.time(), 'from': node_name(), 'keep_service': keep_service}
    store.set_meta('power:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s asked for a %s of %s%s' % (
        by, 'restart' if how == 'reboot' else 'power-off', ', '.join(targets),
        ' one after the other' if order == 'rolling' and len(targets) > 1 else
        (' at once' if len(targets) > 1 else '')), 'warn', who=by)
    return plan


def _power_put(store, row, state, words=''):
    row.update(state=state, moved=time.time())
    if words:
        row['said'] = str(words)[:300]
    store.set_meta('power:node:' + node_name(), json.dumps(row))


def power_go(daemon, plan):
    store = daemon.store
    row = {'id': plan['id'], 'how': plan['how'], 'at': time.time(), 'boot': boot_time()}
    try:
        many = bool(CONFIG.get('ha_mode'))
        # Another node in service (1.0.48): alive, and not in maintenance or stepped aside.
        if many and plan.get('keep_service') and plan['how'] == 'reboot' and \
                not any(n.get('alive') and not n.get('me') and not (
                    isinstance(n.get('maintenance'), dict) and n['maintenance'].get('on'))
                    and not maintenance_row(store, n['name']).get('on')
                    for n in ha_nodes(store)):
            # Its turn come, nobody else answers (1.0.165): it stays up.
            raise ValueError('no other node answers now - not restarted, the service goes on here')
        if many and plan.get('order') != 'together' and not (maintenance_row(store) or {}).get('on'):
            maintenance_set(store, True, 'a %s asked by %s' % (
                'restart' if plan['how'] == 'reboot' else 'power-off', plan.get('by')),
                plan.get('by') or '')
            row['maint'] = True
            v = vip_conf(store)
            end = time.time() + 90
            while v.get('on') and vip_here(v.get('address')) and time.time() < end:
                time.sleep(1)
            if v.get('on') and vip_here(v.get('address')) and plan.get('keep_service'):
                # The VIP address did not move (1.0.165): not restarted under it.
                raise ValueError('the VIP address did not move to the other node in 90 s - not '
                                 'restarted')
        row['down_at'] = time.time() + 5
        _power_put(store, row, 'going', 'going down')
        net_root({'do': 'power', 'how': plan['how'], 'in': 5}, 30)
        log('starting and stopping: %s in 5 s, asked by %s' % (plan['how'], plan.get('by')),
            'warn')
    except Exception as e:                              # noqa: BLE001
        if row.get('maint'):
            try:
                maintenance_set(store, False, '', plan.get('by') or '')
            except Exception:                           # noqa: BLE001
                pass
        _power_put(store, row, 'failed', str(e))


def power_back(daemon, row):
    store = daemon.store
    if row.get('maint'):
        maintenance_set(store, False, '', 'after the restart')
    _power_put(store, row, 'back', 'up again')
    store.add_event('starting and stopping', '%s is up again after the restart' % node_name())


def power_tick(daemon):
    """This node's part of a restart or power-off: its turn, and after it."""
    store = daemon.store
    me = node_name()
    plan = power_plan(store)
    row = _meta_obj(store, 'power:node:' + me)
    if row.get('state') == 'going' and row.get('how') == 'reboot':
        if boot_time() > float(row.get('boot') or 0) + 1:
            _net_thread(power_back, daemon, row)
            return True
        if time.time() - float(row.get('moved') or 0) > 900:
            _power_put(store, row, 'failed', 'it did not restart in 15 minutes')
        return False
    if not plan or me not in (plan.get('targets') or []) or row.get('id') == plan.get('id'):
        return False
    if time.time() - float(plan.get('at') or 0) > POWER_LIVE_S:
        return False
    if plan.get('order') == 'rolling':
        for t in plan['targets']:
            if t == me:
                break
            other = _meta_obj(store, 'power:node:' + t)
            if other.get('id') != plan['id'] or other.get('state') not in ('back', 'failed'):
                return False                # not my turn yet
            if other.get('state') == 'failed' and plan.get('keep_service'):
                # One before did not come back (1.0.165): the rest stays up.
                _power_put(store, {'id': plan['id'], 'how': plan['how'], 'at': time.time(),
                                   'boot': boot_time()}, 'failed',
                           'not restarted: %s did not restart and come back' % t)
                store.add_event('starting and stopping', '%s was not restarted: %s did not come '
                                'back - the service goes on here' % (me, t), 'bad')
                return False
    _net_thread(power_go, daemon, plan)
    return True


def power_view(store):
    plan = power_plan(store)
    nodes = []
    hb = {n['name']: n for n in ha_nodes(store)}
    names = [node_name()] + [n for n in hb if n != node_name()]
    for n in names:
        b = hb.get(n) or {}
        row = _meta_obj(store, 'power:node:' + n)
        nodes.append({'name': n, 'me': n == node_name(), 'alive': bool(b.get('alive', True)
                                                                      if n == node_name() else
                                                                      b.get('alive')),
                      'started': b.get('started'), 'age': b.get('age'),
                      'address': b.get('address') or '', 'version': b.get('version') or '',
                      'row': row if row.get('id') == plan.get('id') else {}})
    # Hidden from the page by whoever pressed Hide this (1.0.123).
    seen = store.get_meta('power:seen') == str(plan.get('id') or '')
    return {'plan': plan if plan and not seen and time.time() - float(plan.get('at') or 0) < POWER_LIVE_S
            else {}, 'nodes': nodes, 'now': time.time(), 'cluster': len(nodes) > 1,
            'busy': power_busy(store)}


def net_vip_again(store, wait=120):
    """This node's part of the VIP address asked of root again, and waited
    for."""
    h = web_hash(web_desired(store))
    st = web_status()
    if st.get('hash') == h and st.get('state') == 'done':
        return True, 'as it was'
    store.set_meta('web:retry:' + node_name(), repr(time.time()))
    end = time.time() + wait
    while time.time() < end:
        st = web_status()
        if st.get('hash') == h and float(st.get('at') or 0) > 0 and \
                st.get('state') in ('done', 'failed'):
            if st.get('state') == 'done':
                return True, 'in place'
            if float(store.get_meta('web:retry:' + node_name()) or 0) <= float(st.get('at') or 0):
                said = st.get('said') or ['failed']
                return False, ('; '.join(said) if isinstance(said, list) else str(said))[:300]
        time.sleep(3)
    return False, 'root had not said yet'


def net_view(store):
    hb = {n['name']: n for n in ha_nodes(store)}
    names = [node_name()] + sorted(n for n in hb if n != node_name())
    out = []
    for n in names:
        b = hb.get(n) or {}
        job = _meta_obj(store, 'net:job:' + n)
        # A finished change is shown until somebody hides it (1.0.120), or for
        # 6 hours when it went through, a day when it did not.
        if job and job.get('state') in ('done', 'failed'):
            keep = 6 * 3600 if job.get('state') == 'done' else 86400
            if store.get_meta('net:seen:' + n) == str(job.get('id')) or \
                    time.time() - float(job.get('moved') or job.get('at') or 0) > keep:
                job = {}
        out.append({'name': n, 'me': n == node_name(),
                    'alive': True if n == node_name() else bool(b.get('alive')),
                    'address': b.get('address') or '', 'now': net_node_now(store, n),
                    'job': job if job and time.time() - float(job.get('moved') or 0) < 86400
                    else {}})
    v = vip_conf(store)
    return {'nodes': out, 'cluster': len(out) > 1, 'now': time.time(),
            'vip': {'on': bool(v.get('on')), 'address': v.get('address') or '',
                    'address6': v.get('address6') or ''} if CONFIG.get('ha_mode') else {}}
