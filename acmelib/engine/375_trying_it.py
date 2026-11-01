# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- trying it --------------------------------------------------------------------------
@route('POST', '/api/radtest')
def _radtest(h):
    s = h.me('tokenadmin')
    b = h.body()
    node = str(b.get('node') or '').strip()
    if node and node != node_name():
        # Asked on another node of the cluster (1.0.45): through the
        # database both open, the password sealed with the key both have.
        # Counted here too (1.0.94): it tries a directory password as well.
        rkey = h.throttle('radtest', 20, 15, name='%s>%s' % (s['name'], str(b.get('user') or '')[:120]),
                      ip_tries=100, name_tries=RADTEST_NAME_TRIES)
        got = radtest_elsewhere(h.store, node, s['name'], h.client_ip(), b)
        if not (isinstance(got, dict) and got.get('result') in ('accept', 'challenge')):
            h.failed(rkey)
        return got
    server = str(b.get('server') or '127.0.0.1')
    if server not in ('127.0.0.1', '::1', 'localhost'):
        h.me('fulladmin')
    # Counted per administrator and person tried (1.0.57): each test tries a
    # directory password, and nothing else limited how many.
    rkey = h.throttle('radtest', 20, 15, name='%s>%s' % (s['name'], str(b.get('user') or '')[:120]),
                      ip_tries=100, name_tries=RADTEST_NAME_TRIES)
    got = radtest_do(h.store, h.d, s['name'], h.client_ip(), b)
    # The first step of a mail or SMS token is a challenge, not a wrong
    # password (1.0.103): counted as one here (not on the other node), it
    # locked every administrator of the address out after a few tests.
    if not (isinstance(got, dict) and got.get('result') in ('accept', 'challenge')):
        h.failed(rkey)
    return got


def radtest_do(store, daemon, by, src, b):
    """One test of a name and a password, on this node - asked on its pages,
    or by another node of the cluster for its pages."""
    user = str(b.get('user') or '')
    password = str(b.get('password') or '')
    how = str(b.get('how') or 'udp')
    # The answer to a second window (1.0.81): the code, with the State the
    # first answer carried.
    state = str(b.get('state') or '').strip().lower()
    if state.startswith('0x'):
        state = state[2:]
    if state and not re.fullmatch(r'[0-9a-f]{2,500}', state):
        raise ApiError(400, 'the State is hex')
    if how == 'direct':
        client = next((c for c in store.clients() if c['id'] == int(b.get('client') or 0)),
                      None)
        realm = (client or {}).get('realm') or str(b.get('realm') or '')
        if state:
            d = daemon.auth.answer(user, password, bytes.fromhex(state), realm, src=src,
                                   rid='', how='test')
        else:
            d = daemon.auth.decide(user, password, realm, src=src, rid='', how='test')
        store.radius_add({
            'ts': d.began, 'client': '%s (a test by %s)' % ((client or {}).get('name') or
                                                            'no client', by),
            'nas_ip': '', 'src': src, 'packet': 'Access-Request',
            'username': d.user or user, 'realm': d.realm, 'calling': '', 'called': '',
            'result': d.result, 'reason': d.reason, 'acme': d.acme, 'rid': '',
            'took_ms': int((time.time() - d.began) * 1000), 'attrs': '[]',
            'reply': json.dumps(d.reply), 'steps': json.dumps(d.steps), 'device': '',
            'tunnel': ''})
        return {'result': d.result, 'reason': d.reason, 'steps': d.steps, 'reply': d.reply,
                'user': d.user, 'realm': d.realm, 'how': 'direct', 'node': node_name(),
                'state': bytes(d.state).hex() if d.state else '', 'message': d.message}
    secret = str(b.get('secret') or '')
    server = str(b.get('server') or '127.0.0.1')
    if not secret and server not in ('127.0.0.1', '::1', 'localhost'):
        # The localhost client's secret only to this machine (1.0.149): sent
        # to a server anybody typed, it could be cracked from the packet there.
        raise ApiError(400, 'give the secret of that server - the one of this machine\'s own '
                       'client is only used for 127.0.0.1')
    if not secret:
        local = store.client_for('127.0.0.1')
        if not local:
            raise ApiError(400, 'there is no client for 127.0.0.1 to send the test from: add '
                           'one (the installer makes "localhost"), or give the secret')
        secret = local['_secret']
    port = int(b.get('port') or CONFIG.get('radius_auth_port') or 1812)
    code, words, took = radius_ask(server, port, secret, user, password,
                                   extra=[('State', '0x' + state)] if state else ())
    got_state = next((v for k, v in words if k == 'State'), '')
    row = store.db.row("SELECT id FROM radius_log WHERE username = ? ORDER BY id DESC "
                       "LIMIT 1", (Authenticator.full_name(
                           user, (store.client_for('127.0.0.1') or {}).get('realm', '')),))
    return {'result': {2: 'accept', 3: 'reject', 11: 'challenge'}.get(code, str(code)),
            'answer': words, 'took_ms': took, 'row': row['id'] if row else None,
            'how': 'udp', 'node': node_name(), 'cli': 'radtest %s %s %s %d <secret>' % (
                user, '******', server, port),
            'state': str(got_state)[2:] if str(got_state).startswith('0x') else '',
            'message': next((v for k, v in words if k == 'Reply-Message'), '')}


RADTEST_WAIT_S = 25


def radtest_elsewhere(store, node, by, src, b):
    alive = {n['name']: n for n in ha_nodes(store)}
    if node not in alive:
        raise ApiError(404, 'there is no node called %s' % node)
    if not alive[node].get('alive'):
        raise ApiError(409, '%s has not been heard from for %d s' % (
            node, int(alive[node].get('age') or 0)))
    ident = secrets.token_hex(8)
    ask = {'by': by, 'src': src, 'at': time.time(), 'from': node_name(),
           'user': str(b.get('user') or ''), 'how': str(b.get('how') or 'udp'),
           'client': b.get('client'), 'realm': str(b.get('realm') or ''),
           # The second window's answer goes with its State (1.0.84).
           'state': str(b.get('state') or '')[:600],
           'password': seal_secret(str(b.get('password') or ''), 'radtest:' + ident)}
    # Written straight into the other node's database (1.0.87), not left to
    # replication: one direction of it stopped, or behind, and the test was
    # never seen there. Replication only when that database cannot be
    # reached from here.
    k_ask = 'radtest:ask:%s:%s' % (node, ident)
    k_ans, k_took = 'radtest:answer:' + ident, 'radtest:taken:' + ident
    far, far_err = None, ''
    if CONFIG.get('ha_mode') == 'replicated':
        try:
            far = ha_peer_db()
        except Exception as e:                          # noqa: BLE001
            far_err = str(e).split('\n')[0][:200]
    where = far or store.db
    # Two tests waiting on the other node at most (1.0.101): each holds a
    # worker of the pages while it waits.
    if not RADTEST_PEER.acquire(False):
        if far:
            far.close()
        raise ApiError(429, 'tests on the other node are running already - try again in a '
                            'moment')
    try:
        where.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k_ask, json.dumps(ask)))
    except Exception:
        RADTEST_PEER.release()
        if far:
            far.close()
        raise
    t0 = time.time()

    def look(k):
        got = where.value('SELECT v FROM meta WHERE k = ?', (k,))
        return got if got is not None or where is store.db else store.get_meta(k)
    try:
        while time.time() - t0 < RADTEST_WAIT_S:
            got = look(k_ans)
            if got:
                out = json.loads(got)
                if out.get('error'):
                    raise ApiError(int(out.get('status') or 400), out['error'])
                return out
            time.sleep(0.3)
        raise ApiError(504, radtest_why_not(store, node, where, far_err, look(k_took), t0,
                                            look(k_ask) is not None))
    finally:
        RADTEST_PEER.release()
        for db in ((far, store.db) if far else (store.db,)):
            try:
                db.run('DELETE FROM meta WHERE k IN (?, ?, ?)', (k_ask, k_ans, k_took))
            except Exception:                           # noqa: BLE001
                pass
        if far:
            try:
                far.close()
            except Exception:                           # noqa: BLE001
                pass


RADTEST_PEER = threading.BoundedSemaphore(2)


def radtest_why_not(store, node, where, far_err, took, t0, still_there):
    """What the page says when the other node did not answer (1.0.87)."""
    beat = next((n for n in ha_nodes(store) if n['name'] == node), {})
    ver = str(beat.get('version') or '')
    if took:
        try:
            at = float(took) - t0
        except ValueError:
            at = 0
        return ('%s took the test %.1f s after it was asked, but did not finish it within %d s: '
                'the directory or the RADIUS port there answer slowly or not at all - its Log '
                'and Events say more' % (node, max(at, 0), RADTEST_WAIT_S))
    if where is not store.db:
        if still_there:
            return ('%s has the test in its database but did not take it within %d s: is acme '
                    'running there%s? (systemctl status acme, journalctl -u acme)' % (
                        node, RADTEST_WAIT_S, ' - it is %s, this is %s' % (ver, __version__)
                        if ver and ver != __version__ else ''))
        return '%s took the test but its answer did not come back within %d s' % (
            node, RADTEST_WAIT_S)
    rep = {}
    try:
        rep = ha_repl_state(store)
    except Exception:                                   # noqa: BLE001
        pass
    why = []
    if far_err:
        why.append('its database could not be reached from here (%s)' % far_err)
    if rep.get('mode') == 'replicated' and not rep.get('healthy'):
        why.append('the replication between the nodes is not running as it should - see '
                   'Settings → High availability')
    return '%s did not answer the test within %d s%s' % (
        node, RADTEST_WAIT_S, ': ' + '; '.join(why) if why else '')


def radtest_serve(daemon):
    """Tests the other node's pages asked of this one (1.0.45)."""
    store = daemon.store
    me = node_name()
    # The first characters of the key compared as they are (1.0.89). The
    # range k >= 'radtest:ask:acme2:' AND k < 'radtest:ask:acme2;' of 1.0.57
    # was empty in a database with a language's collation (en_US.UTF-8,
    # cs_CZ.UTF-8 - what PostgreSQL takes from the system), which leaves
    # ':' and ';' out of the first comparison: the other node never saw a
    # test asked of it. substr compares the characters, in both engines.
    lo = 'radtest:ask:%s:' % me
    rows = [r for r in store.db.rows('SELECT k, v FROM meta WHERE substr(k, 1, %d) = ?'
                                     % len(lo), (lo,))
            if r['k'].startswith(lo)]
    for r in rows:
        ident = r['k'].rsplit(':', 1)[1]
        # Taken once: the row out first, so a second look does not run it again.
        store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
        try:
            # Seen and taken (1.0.87): the asking node says so if it waits too long.
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         ('radtest:taken:' + ident, repr(time.time())))
        except Exception:                               # noqa: BLE001
            pass
        try:
            ask = json.loads(r['v'] or '{}')
            if time.time() - float(ask.get('at') or 0) > RADTEST_WAIT_S:
                continue
            ask['password'] = unseal_secret(ask.get('password') or '', 'radtest:' + ident)
            out = radtest_do(store, daemon, '%s on %s' % (ask.get('by'), ask.get('from')),
                             ask.get('src') or '', ask)
        except ApiError as e:
            out = {'error': str(e), 'status': e.status}
        except Exception as e:                          # noqa: BLE001
            out = {'error': 'the test could not be made on %s: %s' % (me, e), 'status': 500}
        try:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         ('radtest:answer:' + ident, json.dumps(out, default=str)))
        except Exception as e:                          # noqa: BLE001
            log('the answer to a test asked by the other node could not be written: %s' % e,
                'warn')


