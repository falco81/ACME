# -*- coding: utf-8 -*-
"""
Discovery for acme push (targets/acme_push.py, docs/acme-push-protocol.md):
which certificates an application of ours has and needs, and the
certificates and deployments made for them in one go.

    POST /api/targets/push_discover {name}  -> {app, cluster, slots: [slot + covered_by]}
                                 the application asked (inventory), changes nothing;
                                 each slot with `fits`: the certificates holding its names
    POST /api/targets/adopt      {name, slots: [ids], plan: each | together,
                                  issuer, challenge, key_type, key_type_alt}
                                 -> {made: [{cert, cert_id, deploy_id, slots, names}],
                                     left: [{slot, why}]}
                                 each: a certificate for each slot (its names); together:
                                 one certificate holding the names of all those chosen
                                 (the nodes' and the VIP address's) and one deployment
                                 to all of them. A slot covered already, one that
                                 follows another, or one without a name is left, and said.
                                 Or each slot as chosen for it (1.0.90): `each` {slot id:
                                 {how: existing, cert_id} | {how: new, issuer, challenge}},
                                 `deploy_now` - see adopt_each.
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
    pool = certs_pool(store)
    for s in inv.get('slots') or []:
        s = dict(s)
        s['covered_by'] = covered_by(store, row, s)
        s['fits'] = fits(pool, s)
        slots.append(s)
    return {'target': row['name'], 'app': inv.get('app'), 'version': inv.get('version'),
            'cluster': inv.get('cluster'), 'slots': slots, 'steps': ctx.steps}


def certs_pool(store):
    """The certificates a slot could be given (1.0.90): not revoked, with names."""
    out = []
    for c in store.db.rows('SELECT id, name, names, state, not_after, enabled, key_type, '
                           'key_type_alt FROM certs'):
        if str(c.get('state') or '') in ('revoked',) or c.get('enabled') == 0:
            continue                    # nothing to give: revoked, or switched off (1.0.93)
        names = S.jload(c.get('names'), []) or []
        if names:
            out.append(dict(c, names=names))
    return out


def fits(pool, slot):
    """The certificates of `pool` that hold every name of the slot (a wildcard too) - those
    it can be given as they are."""
    want = list(slot.get('names') or [])
    if not want:
        return []
    out = []
    for c in pool:
        if all(_covers(c['names'], n) for n in want):
            out.append({'cert_id': c['id'], 'cert': c['name'], 'names': c['names'],
                        'state': c.get('state'), 'not_after': c.get('not_after'),
                        'enabled': bool(c.get('enabled', 1))})
    out.sort(key=lambda x: (x['state'] != 'ok', -(x['not_after'] or 0)))
    return out


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
    if isinstance(b.get('each'), dict):
        return adopt_each(store, b, by)
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
            sl['fits'] = [c for c in sl.get('fits') or [] if int(c['cert_id']) in mine]
    return got


@A.api('POST', '/api/targets/adopt', 'fulladmin')
def _adopt(h, s):
    return adopt(h.store, h.body(), A.who(s))


def _give_up_slot(store, target, slot, keep_cid, by):
    """The deployments of other certificates naming this slot take it out of their slots.
    (deployment's certificate, the word) when one covers it by auto, nodes or vip - that one
    is not changed here; else None."""
    for c in slot.get('covered_by') or []:
        if keep_cid and int(c.get('cert_id') or 0) == int(keep_cid):
            continue
        dep = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (c.get('deploy_id'),))
        if not dep:
            continue
        opts = S.jload(dep.get('options'), {}) or {}
        raw = opts.get('slots') or 'auto'
        had = [x.strip() for x in (raw if isinstance(raw, (list, tuple))
                                   else str(raw).replace(',', '\n').splitlines()) if str(x).strip()]
        named = [x for x in had if x == slot['id'] or (slot.get('node') and x == slot['node'])]
        if not named:
            word = next((x for x in had if x in ('auto', 'nodes', 'vip', 'this')), 'auto')
            return (c.get('cert') or '?', word)
        rest = [x for x in had if x not in named]
        if not rest:
            return (c.get('cert') or '?', slot['id'])  # its only slot: take it off by hand
        opts['slots'] = '\n'.join(rest)
        A.deploy_save(store, {'id': dep['id'], 'cert_id': dep['cert_id'], 'target': target,
                              'options': opts, 'enabled': dep.get('enabled', 1)}, by)
    return None


def adopt_each(store, b, by):
    """Each slot as chosen for it (1.0.90) - `each`: {slot id: {how: 'existing', cert_id} |
    {how: 'new', issuer, challenge}}: an existing certificate holding the slot's names gets a
    deployment to it (its deployment to this target, when it has one, takes the slot beside
    those it has); new ones are made as Make the certificates makes them - one for each slot,
    or (`plan` together) one for the new slots of the same source and validation.
    `deploy_now`: the existing ones pushed at once."""
    got = discover(store, b)
    target = got['target']
    each = b['each']
    by_id = {str(s['id']): s for s in got['slots']}
    left, linked, made = [], [], []
    existing, new = {}, []
    for sid, want in each.items():
        sid = str(sid)
        want = want if isinstance(want, dict) else {}
        s = by_id.get(sid)
        if s is None:
            left.append({'slot': sid, 'why': 'the application has no such slot'})
            continue
        how = str(want.get('how') or '')
        if how in ('', 'leave', 'none'):
            continue
        if str(s.get('managed_by') or '').startswith('follows:'):
            left.append({'slot': sid, 'why': 'follows %s by itself' % s['managed_by'][8:]})
            continue
        if s.get('installable') is False:
            left.append({'slot': sid, 'why': 'cannot be put in: %s' % (s.get('why_not') or '?')})
            continue
        if how in ('existing', 'new') and s.get('covered_by'):
            # another certificate in it already (1.0.93): two took turns in the slot at each
            # renewal - one naming the slot itself gives it up, one by auto/nodes/vip cannot
            keep_cid = A._id(want.get('cert_id')) if how == 'existing' else None
            stuck = _give_up_slot(store, target, s, keep_cid, by)
            if stuck:
                left.append({'slot': sid, 'why': '%s puts a certificate there by "%s" - change '
                             'that deployment first' % stuck})
                continue
        if how == 'existing':
            cid = A._id(want.get('cert_id'))
            fit = next((c for c in s.get('fits') or [] if int(c['cert_id']) == int(cid or 0)),
                       None)
            if fit is None:
                cert = store.db.row('SELECT name FROM certs WHERE id = ?', (cid,))
                left.append({'slot': sid, 'why': '%s does not hold its names (%s)' % (
                    cert['name'] if cert else 'that certificate',
                    ', '.join(s.get('names') or []))})
                continue
            if any(int(c.get('cert_id') or 0) == int(cid) for c in s.get('covered_by') or []):
                left.append({'slot': sid, 'why': 'has %s already' % fit['cert']})
                continue
            existing.setdefault(int(cid), []).append(sid)
        elif how == 'new':
            if not s.get('names'):
                left.append({'slot': sid, 'why': 'has no name to order a certificate for'})
                continue
            new.append((s, str(want.get('issuer') or ''), str(want.get('challenge') or '')))
        else:
            raise ValueError('a slot is left, given an existing certificate or a new one')
    for cid, sids in existing.items():
        cert = S.cert_need(store, cid)
        dep = store.db.row('SELECT * FROM cert_deploys WHERE cert_id = ? AND target = ? '
                           'ORDER BY id LIMIT 1', (cid, target))
        if dep:
            opts = S.jload(dep.get('options'), {}) or {}
            raw = opts.get('slots') or 'auto'
            had = [x.strip() for x in (raw if isinstance(raw, (list, tuple))
                                       else str(raw).replace(',', '\n').splitlines())
                   if str(x).strip()]
            opts['slots'] = '\n'.join(had + [x for x in sids if x not in had])
            A.deploy_save(store, {'id': dep['id'], 'cert_id': cid, 'target': target,
                                  'options': opts, 'enabled': dep.get('enabled', 1)}, by)
            did = dep['id']
        else:
            did = A.deploy_save(store, {'cert_id': cid, 'target': target,
                                        'options': {'slots': '\n'.join(sids)},
                                        'note': 'given by Discover'}, by)
        job = None
        if b.get('deploy_now') and cert.get('cert_pem'):
            # one that cannot go now (its version revoked, a job busy on it) is said, and the
            # rest still done (1.0.93: the request failed half way, the new ones never made)
            try:
                job = A.start_deploy(store, cid, did, by)
            except (ValueError, LookupError) as e:
                left.append({'slot': ', '.join(sids), 'why': 'given %s, not pushed now: %s'
                             % (cert['name'], e)})
            except Exception as e:                      # noqa: BLE001
                if getattr(e, 'status', None) != 409:
                    raise
                left.append({'slot': ', '.join(sids), 'why': 'given %s, pushed after the job '
                             'busy on it' % cert['name']})
        linked.append({'cert': cert['name'], 'cert_id': cid, 'deploy_id': did, 'slots': sids,
                       'job_id': job})
    groups = []
    if str(b.get('plan') or 'each') == 'together':
        keyed = {}
        for s, iss, ch in new:
            keyed.setdefault((iss, ch), []).append(s)
        groups = [(v, k[0], k[1]) for k, v in keyed.items()]
    else:
        groups = [([s], iss, ch) for s, iss, ch in new]
    for slots, iss, ch in groups:
        names = []
        for s in slots:
            names += [n for n in s['names'] if n not in names]
        req = {'names': names}
        if iss:
            req['issuer'] = iss
        if ch:
            req['challenge'] = ch
        if not any('ec' in (s.get('key_types') or ['ec', 'rsa']) for s in slots):
            req['key_type'] = 'rsa-2048'
        cid = A.cert_save(store, req, by)
        did = A.deploy_save(store, {'cert_id': cid, 'target': target,
                                    'options': {'slots': '\n'.join(s['id'] for s in slots)},
                                    'note': 'made by Discover'}, by)
        cert = S.cert_need(store, cid)
        made.append({'cert': cert['name'], 'cert_id': cid, 'deploy_id': did,
                     'slots': [s['id'] for s in slots], 'names': names})
    store.add_event('certificates', '%s: Discover on %s gave %d slot(s) an existing certificate '
                    'and made %d new one(s)%s' % (
                        by, target, sum(len(x['slots']) for x in linked), len(made),
                        (' - left: ' + '; '.join('%s (%s)' % (x['slot'], x['why'])
                                                 for x in left)) if left else ''), who=by)
    words = []
    if linked:
        words.append('%d slot(s) given an existing certificate%s' % (
            sum(len(x['slots']) for x in linked),
            ' - being pushed' if b.get('deploy_now') else ' - pushed at its next deployment'))
    if made:
        words.append('%d certificate(s) made - each is issued and pushed by itself' % len(made))
    return {'made': made, 'linked': linked, 'left': left, 'target': target,
            'message': '; '.join(words) or 'nothing to do'}

