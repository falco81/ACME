# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the card of the clocks (1.0.21): Settings -> Time -> The clocks of the nodes
# The routes of otp 1.0.222 as they are: GET /api/clock (the view), POST /api/clock with
# action save, try (each node asks its own reference, the other side's clock and its
# directory) or poll. docs/clock-guard.md.
@node_ask_kind('clock_try')
def _ask_clock_try(daemon, args):
    """Try it on the card: each node asks its own reference servers (as written in the form),
    the other side's clock and its directory."""
    mine = (args.get('refs') or {}).get(node_name())
    servers = clock_ref_servers(mine, daemon.store) if mine is not None else \
        clock_ref_servers(store=daemon.store)
    got, med = clock_ref_check(servers) if servers else ([], None)
    try:
        name, sk = clock_peer_skew(daemon.store)
        skerr = ''
    except Exception as e:                              # noqa: BLE001
        name, sk = 'the other node', None
        skerr = str(e).split('\n')[0][:160]
    ok, dirs = clock_dir_check(daemon.store)
    return {'ok': med is not None, 'ref': med, 'servers': servers,
            'refs': [{'server': s, 'offset': o, 'words': w} for s, o, w in got],
            'skew': sk, 'skew_of': name, 'skew_err': skerr,
            'dir_ok': ok, 'dirs': [{'name': n, 'ok': o, 'words': w} for n, o, w in dirs]}


@route('GET', '/api/clock')
def _clock_get(h):
    h.me('fulladmin')       # the network's map, as /api/ntp (otp 1.0.225)
    return clock_view(h.store)


def _clock_refs_checked(names, refs):
    out = {}
    for n, v in refs.items():
        if n not in names:
            raise ApiError(400, 'there is no node called %s' % n)
        try:
            if len(split_targets_parse(v)) > 5:
                raise ValueError('five servers at most')
        except ValueError as e:
            raise ApiError(400, '%s: %s' % (n, e))
        out[str(n)] = str(v or '').strip()
    return out


@route('POST', '/api/clock')
def _clock_post(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    names = [n['name'] for n in ha_nodes(h.store)] or [node_name()]
    refs = _clock_refs_checked(names, b.get('refs') if isinstance(b.get('refs'), dict) else {})
    if act == 'try':
        return node_ask(h.d, 'clock_try', {'refs': refs}, s['name'])
    if act == 'poll':
        return {'nodes': node_ask_results(h.store, 'clock_try', str(b.get('id') or ''))}
    if act != 'save':
        raise ApiError(400, 'save, try or poll')
    conf = b.get('conf') if isinstance(b.get('conf'), dict) else {}
    want = {k: conf[k] for k in CLOCK_KEYS if k in conf}
    if 'clock_mode' in want and want['clock_mode'] not in CLOCK_MODES:
        raise ApiError(400, 'the mode is off, watch or guard')
    for k, (lo, hi) in (('clock_warn_s', (1, 60)), ('clock_aside_s', (5, 600))):
        if k in want:
            try:
                want[k] = int(want[k])
            except (TypeError, ValueError):
                raise ApiError(400, '%s is a number' % k)
            if not lo <= want[k] <= hi:
                raise ApiError(400, '%s is %d-%d' % (k, lo, hi))
    for k in ('clock_codes', 'clock_beat', 'clock_locks', 'health_dir'):
        if k in want:
            want[k] = 1 if want[k] in (1, True, '1', 'on') else 0
    warn = int(want.get('clock_warn_s', CONFIG.get('clock_warn_s') or 2))
    aside = int(want.get('clock_aside_s', CONFIG.get('clock_aside_s') or 20))
    if aside <= warn:
        raise ApiError(400, 'stepping aside comes after the warning: more seconds than it')
    if want.get('clock_mode') == 'guard' and CONFIG.get('clock_mode') != 'guard' \
            and b.get('checked') is not True:
        raise ApiError(409, 'try the reference from every node first (Try it): a node that cannot '
                            'ask it is never stepped aside, but you would not know it is unguarded')
    many = len(names) > 1
    if want:
        h.d.save_settings(want, by=s['name'], node='*' if many else None)
    for n, v in refs.items():
        h.d.save_settings({'clock_ref': v}, by=s['name'], node=n)
    # Asked again at the next look, the last measurement kept meanwhile (otp 1.0.224).
    CLOCK['measure_now'] = True
    h.store.add_event('settings', '%s chose what the nodes do about their clocks: %s' % (
        s['name'], ', '.join('%s=%s' % kv for kv in sorted(want.items())) or 'reference servers'),
        'warn', who=s['name'])
    return {'message': 'kept - each node follows it within seconds', 'view': clock_view(h.store)}
