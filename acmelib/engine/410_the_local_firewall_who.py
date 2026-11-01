# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the local firewall, who may reach which pages (1.0.52) ---------------------------
FW_WAIT = threading.Lock()


@route('GET', '/api/firewall')
def _firewall(h):
    me = h.me('tokenadmin')     # the map of the network, not for every reader (1.0.57)
    store = h.store
    fresh = h.arg('fresh')
    if fresh and fresh in ('1', node_name()):
        fw_now_ask()            # this node's firewall read again, now (1.0.67)
    elif fresh and fresh in [n['name'] for n in ha_nodes(store) if not n['me']]:
        # The other node's (1.0.71): asked through the database, and waited
        # for - its daemon looks every 5 s, root reads it, the row comes back.
        t0 = time.time()
        try:
            had = float(json.loads(store.get_meta('fw:now:' + fresh) or '{}').get('full_at') or 0)
        except (ValueError, AttributeError, TypeError):
            had = 0
        store.set_meta('fw:ask:' + fresh, str(t0))
        # One page waiting at a time (1.0.101): each held a worker of the
        # pages for up to 15 s, and a dozen of them stalled the enrolment
        # pages and the health check with it. The others are answered with
        # what is known now.
        if FW_WAIT.acquire(False):
            try:
                while time.time() - t0 < 15:
                    time.sleep(0.5)
                    try:
                        if float(json.loads(store.get_meta('fw:now:' + fresh) or '{}')
                                 .get('full_at') or 0) > had:
                            break
                    except (ValueError, AttributeError, TypeError):
                        pass
            finally:
                FW_WAIT.release()
    nodes = []
    for n in ha_nodes(store):
        w = web_state(store) if n['me'] else (n.get('web') or {})
        fwv = dict(w.get('fw') or {})
        if not n['me']:
            try:
                fwv.update(json.loads(store.get_meta('fw:now:' + n['name']) or '{}'))
            except ValueError:
                pass
        nodes.append({'name': n['name'], 'me': n['me'], 'alive': n.get('alive'),
                      'address': n.get('address'), 'version': n.get('version'),
                      'fw': fwv, 'access': w.get('access') or {},
                      'state': w.get('state') or '', 'said': w.get('said') or [],
                      'current': w.get('current'), 'waiting': w.get('waiting'),
                      'progress': w.get('progress'),
                      'auto': fw_auto(store, n['name'])})
    if not any(x['me'] for x in nodes):
        w = web_state(store)
        nodes.insert(0, {'name': node_name(), 'me': True, 'alive': True,
                         'address': node_address(), 'fw': w.get('fw') or {},
                         'access': w.get('access') or {}, 'state': w.get('state') or '',
                         'said': w.get('said') or [], 'current': w.get('current'),
                         'waiting': w.get('waiting'), 'progress': w.get('progress'),
                         'auto': fw_auto(store, node_name())})
    c = fw_conf(store)
    a = access_conf(store)
    if not a:
        # Not set here yet: what nginx says now, from this node.
        now = next((x['access'] for x in nodes if x['me']), {}) or {}
        a = {k: {'any': bool((now.get(k) or {}).get('any', k == 'health')),
                 'from': list((now.get(k) or {}).get('from') or [])} for k in ACCESS_WORDS}
        a['from_nginx'] = True
    return {'node': node_name(), 'cluster': bool(CONFIG.get('ha_mode')), 'nodes': nodes,
            'conf': {'on': bool(c.get('on')), 'set': bool(c.get('set')), 'off': c.get('off') or [],
                     'rules': c.get('rules') or [], 'by': c.get('by'), 'at': c.get('at')},
            'access': a, 'access_words': ACCESS_WORDS,
            'inner': {x['name']: cluster_addresses(store, x['name']) for x in nodes},
            'optional': list(FW_AUTO_OPTIONAL), 'may': me.get('role') == 'fulladmin'}


def access_not_me_out(h, store, a, b):
    """Not the administration shut to the one saving it (1.0.57) - from every
    place it can be set (1.0.59)."""
    adm = a.get('admin') or {}
    if adm.get('any') or b.get('even_if_me'):
        return
    try:
        me_ip = ipaddress.ip_address(h.client_ip())
        inside = me_ip.is_loopback or any(
            me_ip in ipaddress.ip_network(n, strict=False) for n in adm.get('from') or [])
    except ValueError:
        inside = True
    if not inside and h.client_ip() not in cluster_addresses(store, node_name()):
        raise ApiError(409, 'your own address (%s) is not among the networks that may reach '
                            'the administration: you would be shut out. Add it, or let '
                            'everybody in' % h.client_ip())


@route('POST', '/api/trial')
def _trial_do(h):
    """A change on trial (1.0.137): keep it, or put back what was there."""
    s = h.me('fulladmin')
    b = h.body()
    kind, act = str(b.get('kind') or ''), str(b.get('action') or '')
    if act not in ('keep', 'back'):
        raise ApiError(400, 'keep or back')
    try:
        if kind == 'net':
            node = str(b.get('node') or '')
            if node not in [n['name'] for n in ha_nodes(h.store)] + [node_name()]:
                raise ApiError(400, 'there is no node %s' % node)
            return {'message': net_trial_answer(h.store, node, act, s['name'])}
        if kind == 'fw':
            return {'message': fw_trial_answer(h.store, act, s['name'])}
    except ValueError as e:
        raise ApiError(409, str(e))
    raise ApiError(400, 'net or fw')


@route('POST', '/api/firewall')
def _firewall_do(h):
    s = h.me('fulladmin')
    who = s['name']
    b = h.body()
    act = str(b.get('action') or '')
    store = h.store
    c = fw_conf(store)
    if act == 'rule_check':
        return {'rule': fw_rule_checked(b.get('rule') if isinstance(b.get('rule'), dict) else {},
                                        store)}
    if act == 'save':
        # Everything at once, from the save bar (1.0.54).
        raw = b.get('rules') or []
        if not isinstance(raw, list) or len(raw) > 200:
            raise ApiError(400, 'two hundred rules at most')
        rules = []
        for x in raw:
            if not isinstance(x, dict):
                raise ApiError(400, 'a rule is not an object')
            r = fw_rule_checked(x, store)
            r['id'] = re.sub(r'[^0-9a-z]', '', str(x.get('id') or ''))[:16] or secrets.token_hex(4)
            if r['id'].startswith('n'):
                r['id'] = secrets.token_hex(4)
            rules.append(r)
        off = [k for k in (b.get('off') or []) if k in FW_AUTO_OPTIONAL]
        was = fw_conf(store)
        said = []
        if 'access' in b and isinstance(b.get('access'), dict):
            a = access_checked_api(b['access'])
            access_not_me_out(h, store, a, b)
            fw_trial_begin(store, who)
            store.set_meta('web:access', json.dumps(dict(a, at=time.time(), by=who)))
            said.append('who may reach the pages: %s' % '; '.join(
                '%s %s' % (k, 'everybody' if v['any'] else ', '.join(v['from']))
                for k, v in a.items()))
        on = bool(b.get('on'))
        if on != bool(was.get('on')):
            said.append('acme\'s firewall rules %s' % ('on' if on else 'off'))
        if rules != (was.get('rules') or []):
            said.append('%d rule(s) of your own' % len(rules))
        if sorted(off) != sorted(was.get('off') or []):
            said.append('turned off: %s' % (', '.join(off) or 'nothing'))
        fw_set(store, who, on=on, off=off, rules=rules)
        if said:
            store.add_event('settings', '%s changed the firewall and access: %s'
                            % (who, ' · '.join(said)), 'warn', who=who)
        return {'message': 'saved; each node puts it in within a few seconds'}
    if act in ('on', 'off'):
        fw_set(store, who, on=act == 'on')
        store.add_event('settings', '%s turned acme\'s firewall rules %s' % (who, act), 'warn',
                        who=who)
        return {'message': 'acme\'s rules are %s; each node puts that in within a few seconds'
                           % ('on' if act == 'on' else 'taken away (the rest of the firewall '
                                                       'stays as it was)')}
    if act == 'auto':
        key = str(b.get('key') or '')
        if key not in FW_AUTO_OPTIONAL:
            raise ApiError(400, 'that one cannot be turned off')
        off = [k for k in c.get('off') or [] if k != key]
        if not b.get('on'):
            off.append(key)
        fw_set(store, who, off=off)
        store.add_event('settings', '%s turned the firewall rule for %s %s' % (
            who, key, 'on' if b.get('on') else 'off'), 'warn', who=who)
        return {'message': 'kept'}
    if act in ('rule_add', 'rule_save'):
        r = fw_rule_checked(b.get('rule') if isinstance(b.get('rule'), dict) else {}, store)
        rules = list(c.get('rules') or [])
        if act == 'rule_add':
            if len(rules) >= 200:
                raise ApiError(400, 'two hundred rules at most')
            r['id'] = secrets.token_hex(4)
            rules.append(r)
        else:
            i = next((i for i, x in enumerate(rules) if x.get('id') == b.get('id')), None)
            if i is None:
                raise ApiError(404, 'no such rule')
            r['id'] = rules[i]['id']
            rules[i] = r
        fw_set(store, who, rules=rules)
        store.add_event('settings', '%s %s a firewall rule: %s %s%s%s (%s)' % (
            who, 'added' if act == 'rule_add' else 'changed', r['action'], r['proto'],
            ' ' + r['port'] if r['port'] else '', ' from ' + r['source'] if r['source'] else '',
            r['scope']), 'warn', who=who)
        return {'message': 'kept', 'id': r['id']}
    if act == 'rule_drop':
        rules = [x for x in c.get('rules') or [] if x.get('id') != b.get('id')]
        fw_set(store, who, rules=rules)
        store.add_event('settings', '%s took a firewall rule away' % who, 'warn', who=who)
        return {'message': 'gone'}
    if act == 'rule_move':
        rules = list(c.get('rules') or [])
        i = next((i for i, x in enumerate(rules) if x.get('id') == b.get('id')), None)
        if i is None:
            raise ApiError(404, 'no such rule')
        j = i + (-1 if b.get('dir') == 'up' else 1)
        if 0 <= j < len(rules):
            rules[i], rules[j] = rules[j], rules[i]
            fw_set(store, who, rules=rules)
            # The order decides which rule wins (1.0.146): written down as the others.
            store.add_event('settings', '%s moved a firewall rule %s (now %d of %d)' % (
                who, 'up' if j < i else 'down', j + 1, len(rules)), 'warn', who=who)
        return {'message': 'moved'}
    if act == 'access':
        a = access_checked_api(b)
        access_not_me_out(h, store, a, b)      # here too (1.0.59)
        fw_trial_begin(store, who)
        store.set_meta('web:access', json.dumps(dict(a, at=time.time(), by=who)))
        store.add_event('settings', '%s set who may reach the pages: %s' % (who, '; '.join(
            '%s %s' % (k, 'everybody' if v['any'] else ', '.join(v['from'])) for k, v in a.items())),
            'warn', who=who)
        return {'message': 'kept; each node\'s nginx takes it within a few seconds (the other '
                           'node and the VIP address are always let in)'}
    raise ApiError(400, 'no such thing to do')


