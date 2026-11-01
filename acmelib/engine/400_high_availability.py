# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- high availability (1.0.13) ---------------------------------------------------
@route('GET', '/api/ha')
def _ha(h):
    me = h.me()
    nodes = [dict(n, web=web_unmapped(n['web'], me)) if isinstance(n, dict) and 'web' in n else n
             for n in ha_nodes(h.store)]
    return {'node': node_name(), 'address': node_address(), 'nodes': nodes,
            'replication': ha_repl_state(h.store), 'job': job_read(),
            'checks': ha_checks(h.store), 'engine': h.store.db.engine,
            'mode': CONFIG.get('ha_mode') or '',
            'db_where': h.store.db.where(), 'db_host': CONFIG.get('db_host') or '',
            'config_file': str(CONFIG_FILE), 'version': __version__, 'lb': lb_facts(h.store),
            'errbase': _json_meta(h.store, 'ha:errbase:' + node_name()) or {},
            # How the link between the databases is protected (1.0.101), and
            # where the button that protects it is (1.0.104).
            'db_tls': CONFIG.get('db_tls') or '', 'link_tls': _hatls_view_safe(h.store),
            'readdress': readdress_view(h.store) if CONFIG.get('ha_mode') == 'replicated' else None,
            # Setting the pair up (1.0.210): who is let in for being joined,
            # PostgreSQL here as the node being joined will find it, and
            # what this node holds of its own that a join would leave behind.
            'pending': ha_pending(h.store), 'pg_open': ha_pg_view(h.store),
            'fw_on': bool((fw_desired(h.store) or {}).get('on')),
            'peer': CONFIG.get('ha_peer') or '', 'local': ha_local_held(h.store)}


def ha_local_held(store):
    """What this node has of its own - what a join leaves behind (1.0.210):
    None in a cluster already."""
    if CONFIG.get('ha_mode'):
        return None
    out = {'engine': store.db.engine, 'certs': 0, 'accounts': 0, 'sealed': False}
    for k, t in (('certs', 'certs'), ('accounts', 'accounts')):
        try:
            out[k] = int(store.db.value('SELECT COUNT(*) FROM %s' % t) or 0)
        except Exception:                               # noqa: BLE001
            pass
    try:
        out['sealed'] = bool(sealed_held(store.db))
    except Exception:                                   # noqa: BLE001
        out['sealed'] = True
    # One account is the one signed in now, made at the install: not "its own".
    out['held'] = bool(out['certs'] or out['sealed'] or out['accounts'] > 1)
    return out


def _hatls_view_safe(store):
    try:
        return hatls_view(store) if CONFIG.get('ha_mode') == 'replicated' else None
    except Exception as e:                              # noqa: BLE001
        return {'error': str(e)[:200]}


def lb_facts(store):
    """What the load balancer guides on the pages fill in (1.0.52): the real
    names, addresses and ports of this installation."""
    server_name, proxies = '', []
    for p in NGINX_CONF_PATHS:
        try:
            text = Path(p).read_text()
        except OSError:
            continue
        m = re.search(r'(?m)^\s*listen[^;]*443[^;]*;[\s\S]*?^\s*server_name\s+([^;\s]+)', text)
        if m:
            server_name = m.group(1)
        b = re.search(r'# REALIP-BEGIN(.*?)# REALIP-END', text, re.S)
        if b:
            proxies = re.findall(r'set_real_ip_from\s+([^;\s]+);', b.group(1))
        break
    v = vip_conf(store)
    return {'server_name': server_name, 'trusted': proxies,
            'vip': {'on': bool(v.get('on')), 'address': v.get('address') or '',
                    'fqdn': v.get('fqdn') or ''}}


@route('GET', '/api/ha/history')
def _ha_history(h):
    h.me()
    return {'rows': ha_history(h.store, h.num('limit', 300, 1, 2000), h.num('from', 0, 0, 10 ** 11),
                               h.num('to', 0, 0, 10 ** 11)), 'node': node_name()}


@route('POST', '/api/ha')
def _ha_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    if act == 'readdress':
        # A node's address changed: this node's side put right, the other
        # told (1.0.106).
        try:
            return ha_readdress(h.store, str(b.get('mine') or ''), str(b.get('peer') or ''),
                                by=s['name'], daemon=h.d)
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'tls_off':
        # TLS between the databases off again, both nodes (1.0.107).
        try:
            return hatls_off(h.store, s['name'])
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'tls_link':
        # Encrypt and check the link between the databases, both nodes,
        # without stopping anything (1.0.104).
        try:
            return hatls_start(h.store, s['name'])
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'errors':
        h.store.add_event('settings', '%s read the replication errors in PostgreSQL\'s log'
                          % s['name'], who=s['name'])
        return repl_errors(h.store, ask_log=bool(b.get('log', True)))
    if act == 'history_clear':
        # What the nodes saw is deleted; what was done by hand stays in
        # Events (the audit) and is only no longer shown here (1.0.56).
        now = time.time()
        n = h.store.db.run("DELETE FROM events WHERE kind = 'ha' AND ts <= ?", (now,))
        h.store.set_meta('ha:history_cleared', str(now))
        h.store.add_event('settings', '%s cleared the cluster\'s history' % s['name'], 'warn',
                          who=s['name'])
        return {'message': 'the history is cleared', 'gone': n if isinstance(n, int) else None}
    if act == 'errors_clear':
        repl_errors_clear(h.store, s['name'])
        h.store.add_event('settings', '%s cleared the replication errors of %s (counted from now '
                          'on)' % (s['name'], node_name()), who=s['name'])
        return {'message': 'cleared: the errors are counted from now on', **repl_errors(
            h.store, ask_log=False)}
    if act == 'prepare':
        # The first node made ready for the node being joined (1.0.210), one
        # step at a time so the page shows each as it goes: 'pending' lets its
        # address in, 'firewall' waits for root to put it in, 'pg' opens
        # PostgreSQL here to it (listen_addresses, pg_hba.conf, a restart).
        step = str(b.get('step') or '')
        peer = str(b.get('peer') or '').strip()
        try:
            if step == 'pending':
                ips = ha_pending_add(h.store, str(peer_address(peer)), s['name'],
                                     'the node being joined')
                one = ha_pending(h.store)
                until = max([float(x.get('until') or 0) for x in one if x['address'] in ips] or [0])
                h.store.add_event('settings', '%s let %s into %s for being joined (until %s)' % (
                    s['name'], ', '.join(ips), node_name(),
                    time.strftime('%Y-%m-%d %H:%M', time.localtime(until))), 'warn', who=s['name'])
                return {'steps': [{'key': 'pending', 'ok': True, 'until': until,
                                   'said': '%s is let in as the node being joined, until %s' % (
                                       ', '.join(ips), time.strftime('%d.%m. %H:%M',
                                                                     time.localtime(until)))}]}
            if step == 'firewall':
                got = fw_apply_wait(h.store, 60)
                return {'steps': [{'key': 'firewall', 'ok': got['state'] in ('done', 'off'),
                                   'state': got['state'], 'said': got['said']}]}
            if step == 'pg':
                return {'steps': ha_pg_open(h.store, peer, s['name'])}
            if step == 'forget':
                ha_pending_drop(h.store, peer or None)
                return {'message': 'no longer let in as a node being joined'}
        except ValueError as e:
            raise ApiError(400, str(e))
        raise ApiError(400, 'pending, firewall, pg or forget')
    if act == 'bundle':
        joining = str(b.get('peer') or '').strip()
        try:
            if joining:
                joining = str(peer_address(joining))
            if CONFIG.get('ha_mode') == 'replicated':
                # The second node of two replicating ones - or the same one
                # again, after it was lost or reinstalled.
                data = ha_replicated_bundle_data(h.store)
            else:
                data = ha_bundle_data(h.store, str(b.get('db_host') or '').strip())
        except ValueError as e:
            raise ApiError(400, str(e))
        if joining:
            data['joining'] = joining
        phrase = ha_passphrase()
        locked = bundle_lock(data, phrase)
        locked['about'] = ha_bundle_about(data)
        h.store.add_event('settings', '%s made a bundle for a second node to join this one '
                          '(the database at %s) - it carries the key that opens every secret'
                          % (s['name'], data['db']['db_host']), 'warn', who=s['name'])
        return {'bundle': locked, 'passphrase': phrase, 'db_host': data['db'].get('db_host', ''),
                'mode': data.get('mode') or 'shared',
                'name': 'acme-join-%s-%s.json' % (node_name(), datetime.now().strftime('%Y%m%d'))}
    if act == 'join_step':
        # The join taken a step at a time (1.0.210), for the page to show:
        # 'bundle' opens it and says what it holds, 'firewall' lets the first
        # node in here, 'db' tries its database from here and says why not.
        step = str(b.get('step') or '')
        try:
            data = bundle_open(b.get('bundle'), str(b.get('passphrase') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        view = ha_bundle_view(data)
        if step == 'bundle':
            return {'bundle': view, 'local': ha_local_held(h.store), 'node': node_name(),
                    'steps': [{'key': 'bundle', 'ok': True, 'said': 'the bundle opens: the '
                               'cluster %s of %s (%s)' % (view['cluster'], view['node'] or '?',
                                                          view['address'] or '?')}]}
        if data.get('mode') == 'replicated':
            raise ApiError(400, 'this bundle makes this node replicate with its own PostgreSQL, '
                                'which takes root on this machine: copy it here and run  acme '
                                '--ha-join FILE  as root')
        if step == 'firewall':
            got = ha_join_open(h.store, data, s['name'])
            return {'steps': [{'key': 'firewall', 'ok': got['state'] in ('done', 'off'),
                               'state': got['state'], 'said': got['said']}]}
        if step == 'db':
            db = {k: v for k, v in (data.get('db') or {}).items() if k in DB_KEYS}
            got = db_try(db)
            if got.get('reached'):
                return {'steps': [{'key': 'db', 'ok': True, 'said': 'the database answers from '
                                   'here: %s, %s record(s)' % (db_where(db), got.get('rows'))}]}
            fwv = {'state': 'off' if not (fw_desired(h.store) or {}).get('on') else
                   ('done' if ha_pending(h.store) else 'failed'),
                   'said': 'it was not opened to the first node yet'}
            why = db_trouble(got.get('trouble') or '', db, fwv)
            return {'steps': [{'key': 'db', 'ok': False, 'said': why['says'], 'fix': why['fix'],
                               'kind': why['kind']}]}
        raise ApiError(400, 'bundle, firewall or db')
    if act == 'join':
        try:
            data = bundle_open(b.get('bundle'), str(b.get('passphrase') or ''))
            if data.get('mode') == 'replicated':
                raise ValueError('this bundle makes this node replicate with its own PostgreSQL, '
                                 'which takes root on this machine (installing and setting up '
                                 'PostgreSQL): copy it here and run  acme --ha-join FILE  as root')
            steps = []
            got = ha_join(data, str(b.get('name') or '').strip(), bool(b.get('even_if_data')),
                          s['name'], say=lambda k, ok, words: steps.append(
                              {'key': k, 'ok': ok, 'said': words}))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('settings', '%s joined this node to the cluster of %s; it starts '
                          'again on %s' % (s['name'], (data.get('peer') or {}).get('name', '?'),
                                           got['where']), 'warn', who=s['name'])
        log('joining the cluster: starting again on %s' % got['where'], 'warn')
        threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
        got['restarting'] = True
        got['steps'] = steps
        got['cluster'] = str(data.get('cluster') or '')
        return got
    if act in ('pause', 'resume', 'pause_in', 'pause_out', 'resume_in', 'resume_out', 'stop',
               'refresh'):
        want = str(b.get('node') or '')
        if want and want != node_name() and act.endswith(('_in', '_out')):
            # One direction is the other one's opposite (1.0.94): behind a
            # balancer the request can reach the node the page did not show.
            raise ApiError(409, 'this request reached %s, not %s: open the page of %s itself '
                                '(its own address) to do that' % (node_name(), want, want))
        try:
            return ha_control(h.store, act, s['name'])
        except (ValueError, DbError) as e:
            raise ApiError(400, str(e).split('\n')[0][:400])
        except Exception as e:                          # noqa: BLE001
            raise ApiError(400, str(e).split('\n')[0][:400])
    if act == 'resync':
        want = str(b.get('node') or '')
        if want and want != node_name():
            # Behind a balancer the request can come to the other node
            # (1.0.59): it is refused, not that node rebuilt instead.
            raise ApiError(409, 'this request reached %s, not %s: open the page of %s itself '
                                '(its own address) to rebuild it' % (node_name(), want, want))
        try:
            return {'job': ha_resync_job(h.store, s['name'])}
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'forget':
        try:
            ha_forget(h.store, str(b.get('name') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('settings', '%s took the node %s off the list' % (s['name'], b.get('name')),
                          who=s['name'])
        return {'message': 'gone from the list; it comes back by itself if it is still running'}
    raise ApiError(400, 'no such thing to do')


