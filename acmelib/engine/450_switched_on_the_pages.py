# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- switched on the pages (1.0.141) ------------------------------------------------
# Settings → About: each node's switch. The page writes 'console:want:NODE'; that
# node's daemon has its root helper write /etc/acme-console-login, and says how
# it is in 'console:now:NODE' - read from the file itself, so a change made with
# acme --console-at-login shows too.
CONSOLE_WORK = {'busy': False, 'seen': 0.0}


def console_login_view(store):
    nodes = [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]
    out = []
    for n in nodes:
        now = _meta_json(store, 'console:now:' + n) or {}
        want = _meta_json(store, 'console:want:' + n) or {}
        out.append({'name': n, 'me': n == node_name(), 'on': now.get('on'),
                    'at': now.get('at'), 'error': now.get('error') or '',
                    'pending': bool(want) and want.get('id') != now.get('done')})
    return {'nodes': out}


def console_login_ask(store, node, on, by):
    known = [node_name()] + [n['name'] for n in ha_nodes(store)]
    if node not in known:
        raise ValueError('there is no node %s' % node)
    store.set_meta('console:want:' + node, json.dumps({
        'id': secrets.token_hex(6), 'on': bool(on), 'by': by, 'at': time.time()}))
    store.add_event('settings', ('%s switched on the acme console at login on %s' if on else
                                 '%s switched off the acme console at login on %s') % (by, node),
                    'warn', who=by)


def console_login_tick(daemon):
    """Every few seconds: a switch asked for this node done; how it is, said."""
    store = daemon.store
    me = node_name()
    want = _meta_json(store, 'console:want:' + me) or {}
    now = _meta_json(store, 'console:now:' + me) or {}
    if want and want.get('id') != now.get('done') and not CONSOLE_WORK['busy']:
        CONSOLE_WORK['busy'] = True

        def go():
            try:
                err = ''
                try:
                    root_ask('console.ask', 'console.json',
                             {'do': 'set', 'on': bool(want.get('on'))}, 60)
                except ValueError as e:
                    err = str(e)[:300]
                    log('the console at login could not be switched: %s' % err, 'warn')
                store.set_meta('console:now:' + me, json.dumps({
                    'on': console_at_login(), 'at': time.time(), 'done': want.get('id'),
                    'error': err}))
            finally:
                CONSOLE_WORK['busy'] = False
        threading.Thread(target=go, name='acme-console-login', daemon=True).start()
        return
    if time.time() - CONSOLE_WORK['seen'] > 60 and not CONSOLE_WORK['busy']:
        CONSOLE_WORK['seen'] = time.time()
        on = console_at_login()
        if now.get('on') != on or 'on' not in now:
            store.set_meta('console:now:' + me, json.dumps(dict(now, on=on, at=time.time())))


def console_main(pal):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit('acme: the console needs a terminal')
    return Console(pal).run()


