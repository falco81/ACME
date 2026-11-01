# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the card of the split (1.0.14): Settings -> High availability -> When the nodes lose each other
# The routes of otp 1.0.218 as they are: GET /api/split (the view), POST /api/split with
# action save, try (each node asks its own arbiter) or poll. docs/split-brain.md.
@node_ask_kind('split_arbiter')
def _ask_split_arbiter(daemon, args):
    """Try it on the card: each node asks its own arbiter, as written in the form."""
    mine = (args.get('targets') or {}).get(node_name())
    try:
        targets = split_targets(mine) if mine is not None else split_targets()
    except ValueError as e:
        return {'ok': False, 'error': str(e)}
    got, verdict = split_arbiter_check(targets)
    return {'ok': verdict is not False, 'verdict': verdict, 'gateway': default_gateway(),
            'targets': [{'target': t, 'ok': ok, 'how': how, 'words': w} for t, ok, how, w in got]}


@route('GET', '/api/split')
def _split_get(h):
    h.me()
    return split_view(h.store)


@route('POST', '/api/split')
def _split_post(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'try':
        targets = b.get('targets') if isinstance(b.get('targets'), dict) else {}
        for n, v in targets.items():
            try:
                split_targets_parse(v)
            except ValueError as e:
                raise ApiError(400, '%s: %s' % (n, e))
        return node_ask(h.d, 'split_arbiter', {'targets': {str(k): str(v or '') for k, v in
                                                          targets.items()}}, s['name'])
    if act == 'poll':
        return {'nodes': node_ask_results(h.store, 'split_arbiter', str(b.get('id') or ''))}
    if act != 'save':
        raise ApiError(400, 'save, try or poll')
    conf = b.get('conf') if isinstance(b.get('conf'), dict) else {}
    want = {k: conf[k] for k in SPLIT_KEYS if k in conf}
    if 'split_mode' in want and want['split_mode'] not in SPLIT_MODES:
        raise ApiError(400, 'the mode is off, arbiter or priority')
    names = [n['name'] for n in ha_nodes(h.store)] or [node_name()]
    if want.get('split_prefer') and want['split_prefer'] not in names:
        raise ApiError(400, 'there is no node called %s' % want['split_prefer'])
    arb = b.get('arbiter') if isinstance(b.get('arbiter'), dict) else {}
    for n, v in arb.items():
        if n not in names:
            raise ApiError(400, 'there is no node called %s' % n)
        try:
            split_targets_parse(v)
        except ValueError as e:
            raise ApiError(400, '%s: %s' % (n, e))
    if want.get('split_mode') == 'arbiter' and CONFIG.get('split_mode') != 'arbiter' and \
            b.get('checked') is not True:
        raise ApiError(409, 'try the arbiter from every node first (Try it): a node that cannot '
                            'reach its arbiter would step aside the moment the other is away')
    many = len(names) > 1
    if want:
        h.d.save_settings(want, by=s['name'], node='*' if many else None)
    for n, v in arb.items():
        h.d.save_settings({'split_arbiter': str(v or '').strip()}, by=s['name'], node=n)
    h.store.add_event('settings', '%s chose what the nodes do when they lose each other: %s' % (
        s['name'], ', '.join('%s=%s' % kv for kv in sorted(want.items())) or 'arbiters'), 'warn',
        who=s['name'])
    return {'message': 'kept - each node follows it within seconds', 'view': split_view(h.store)}
