# -*- coding: utf-8 -*-
"""
Discovery for acme push (targets/acme_push.py, docs/acme-push-protocol.md):
which certificates an application of ours has and needs, and the
certificates and deployments made for them in one go.

    POST /api/targets/push_discover {name}  -> {app, cluster, slots: [slot + covered_by]}
                                 the application asked (inventory), changes nothing
    POST /api/targets/adopt      {name, slots: [ids], plan: each | together,
                                  issuer, challenge, key_type, key_type_alt}
                                 -> {made: [{cert, cert_id, deploy_id, slots, names}],
                                     left: [{slot, why}]}
                                 each: a certificate for each slot (its names); together:
                                 one certificate holding the names of all those chosen
                                 (the nodes' and the VIP address's) and one deployment
                                 to all of them. A slot covered already, one that
                                 follows another, or one without a name is left, and said.
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import runtime
from acmelib.plugins.base import PluginError

KIND = 'acme_push'


def _target(store, b):
    row = S.plugin_row(store, 'target', b.get('id') if b.get('id') not in (None, '', 0)
                       else str(b.get('name') or b.get('target') or ''))
    if not row:
        raise LookupError('there is no such target')
    if row.get('kind') != KIND:
        raise ValueError('%s is not an application of ours (acme push)' % row['name'])
    return row


def _plugin(store, row):
    ctx = runtime.RunContext(store, None, scope='target:%s' % row['name'])
    return S.plugin_instance(store, 'target', row, ctx), ctx


def _covers(names, host):
    from acmelib import engine as E
    return E.push_covers(names, host)


def covered_by(store, row, slot):
    """The deployments to this target that put a certificate into the slot:
    named in their slots, or 'auto' (and the like) with a certificate holding its
    names."""
    out = []
    for dep in store.db.rows('SELECT * FROM cert_deploys WHERE target = ?', (row['name'],)):
        opts = S.jload(dep.get('options'), {}) or {}
        raw = opts.get('slots') or 'auto'
        if isinstance(raw, (list, tuple)):
            raw = '\n'.join(str(x) for x in raw)
        asked = [x.strip() for x in str(raw).replace(',', '\n').splitlines()
                 if x.strip()] or ['auto']
        cert = store.db.row('SELECT id, name, names FROM certs WHERE id = ?', (dep['cert_id'],))
        if not cert:
            continue
        names = S.jload(cert.get('names'), []) or []
        hit = slot['id'] in asked or (slot.get('node') and slot['node'] in asked)
        if not hit and slot.get('names'):
            holds = all(_covers(names, n) for n in slot['names'])
            hit = holds and ('auto' in asked or (slot.get('kind') == 'node' and 'nodes' in asked)
                             or (slot['id'] == 'vip' and 'vip' in asked))
        if hit:
            out.append({'cert': cert['name'], 'cert_id': cert['id'], 'deploy_id': dep['id'],
                        'enabled': bool(dep.get('enabled', 1))})
    return out


def discover(store, b):
    row = _target(store, b)
    plug, ctx = _plugin(store, row)
    try:
        inv = plug.inventory()
    finally:
        ctx.tidy()
    slots = []
    for s in inv.get('slots') or []:
        s = dict(s)
        s['covered_by'] = covered_by(store, row, s)
        slots.append(s)
    return {'target': row['name'], 'app': inv.get('app'), 'version': inv.get('version'),
            'cluster': inv.get('cluster'), 'slots': slots, 'steps': ctx.steps}


def _slot_free(s):
    if str(s.get('managed_by') or '').startswith('follows:'):
        return 'follows %s by itself' % s['managed_by'][8:]
    if not s.get('installable', True):
        return 'cannot be put in: %s' % (s.get('why_not') or '?')
    if not s.get('names'):
        return 'has no name to order a certificate for'
    if s.get('covered_by'):
        return 'has a certificate of acme already (%s)' % ', '.join(
            c['cert'] for c in s['covered_by'])
    return ''


def adopt(store, b, by):
    got = discover(store, b)
    want = [str(x) for x in (b.get('slots') or [])]
    plan = str(b.get('plan') or 'each')
    if plan not in ('each', 'together'):
        raise ValueError('the plan is each or together')
    chosen, left = [], []
    for s in got['slots']:
        if want and s['id'] not in want:
            continue
        why = _slot_free(s)
        shown = (b.get('shown') or {}).get(s['id']) if isinstance(b.get('shown'), dict) else None
        if why:
            left.append({'slot': s['id'], 'why': why})
        elif shown is not None and sorted(str(x).lower() for x in shown) != \
                sorted(str(x).lower() for x in s['names']):
            # the names asked again from the application (1.0.51): other names than those the
            # administrator was shown are not ordered - and their key pushed to it
            left.append({'slot': s['id'], 'why': 'the application now names %s, not the names '
                                                 'shown - look again' % ', '.join(s['names'])})
        else:
            chosen.append(s)
    unknown = [x for x in want if x not in {s['id'] for s in got['slots']}]
    for x in unknown:
        left.append({'slot': x, 'why': 'the application has no such slot'})
    base = {}
    for k in ('issuer', 'challenge', 'key_type', 'key_type_alt'):
        if b.get(k) not in (None, ''):
            base[k] = str(b[k])
    groups = []
    if plan == 'together' and chosen:
        names = []
        for s in chosen:
            names += [n for n in s['names'] if n not in names]
        groups.append((chosen, names))
    else:
        groups = [([s], list(s['names'])) for s in chosen]
    made = []
    for slots, names in groups:
        req = dict(base, names=names)
        if not any('ec' in (s.get('key_types') or ['ec', 'rsa']) for s in slots) and \
                'key_type' not in base:
            req['key_type'] = 'rsa-2048'
        if 'key_type_alt' in req and not all(s.get('dual') for s in slots):
            req.pop('key_type_alt')
        cid = A.cert_save(store, req, by)
        did = A.deploy_save(store, {'cert_id': cid, 'target': got['target'],
                                    'options': {'slots': '\n'.join(s['id'] for s in slots)},
                                    'note': 'made by Discover'}, by)
        cert = S.cert_need(store, cid)
        made.append({'cert': cert['name'], 'cert_id': cid, 'deploy_id': did,
                     'slots': [s['id'] for s in slots], 'names': names})
    store.add_event('certificates', '%s: Discover on %s made %d certificate(s) and deployment(s)'
                    '%s' % (by, got['target'], len(made), (' - left: ' + '; '.join(
                        '%s (%s)' % (x['slot'], x['why']) for x in left)) if left else ''),
                    who=by)
    return {'made': made, 'left': left, 'target': got['target'],
            'message': '%d certificate(s) made - each is issued and pushed by itself' % len(made)
            if made else 'nothing to make'}


# A path of its own (1.0.51): /api/targets/discover is the modules' own Discover (api_discover),
# registered after this one - the push dialog asked it, and was told there was no module ''.
@A.api('POST', '/api/targets/push_discover', 'certadmin')
def _discover(h, s):
    try:
        got = discover(h.store, h.body())
    except PluginError as e:
        raise ValueError(str(e))
    # the certificates of other owners not named to a scoped account (1.0.79)
    mine = A.visible_cert_ids(h.store, s)
    if mine is not None:
        for sl in got.get('slots') or []:
            sl['covered_by'] = [c if int(c.get('cert_id') or 0) in mine else
                                {'cert': '(another owner\'s certificate)', 'cert_id': None,
                                 'deploy_id': None, 'enabled': c.get('enabled')}
                                for c in sl.get('covered_by') or []]
    return got


@A.api('POST', '/api/targets/adopt', 'fulladmin')
def _adopt(h, s):
    return adopt(h.store, h.body(), A.who(s))

