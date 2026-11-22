# -*- coding: utf-8 -*-
"""
Where the keys of an agent's certificates are made (1.0.140, B7 - docs/target-agent.md "Where
keys are made"). The key made by the agent exists since phase 3 (devicekey.py, targets/agent.py
device_csr, the certificate's "Key made by the device" = certs.csr_from); this is the overview
and the switch:

    overview(store, s)      every target with an agent: how many of the certificates deployed
                            there have the agent's own key and how many acme's - and which of
                            acme's could switch (deployed to that one target only, nothing else
                            in the way: devicekey.save_problem, the very check of the
                            certificate's form); `require key local` of its policy (A1) beside it
    switch(...)             "Switch to a key made on the server": at the next renewal (a mark;
                            sweep() makes the switch a day before the certificate would be
                            renewed - the renewal then makes the key there) or now (switched,
                            and renewed at once)
    cancel(...)             a switch waiting for the next renewal taken back
    sweep(store)            agents.tick: the switches whose renewal comes
    target_counts(store, row)   the policy builder's "Key only from this server"

What acme keeps: meta agentkeys:switch:<cert id> = {target, by, at} while a switch waits for
the renewal (in every backup, on every node; nothing at all until a switch is asked).
Nothing changes until a switch is asked; a switch changes exactly what the certificate's form
changes ("Key made by the device"), by the same code (api.cert_save).
"""
from __future__ import annotations

import json
import time

M_SWITCH = 'agentkeys:switch:%d'
AHEAD_S = 86400                 # a waiting switch made this long before the renewal would come
CERTS_MOST = 500                # certificates of one target looked at


def _G():
    from acmelib.certs import agents
    return agents


def _jload(v, default):
    try:
        got = json.loads(v) if v else default
    except (TypeError, ValueError):
        return default
    return got if isinstance(got, type(default)) else default


def pending(store, cid):
    got = _jload(store.get_meta(M_SWITCH % int(cid)), {})
    return got if got.get('target') else None


def _may(store, s, row, right):
    if s is None:
        return True
    from acmelib.certs import teams
    return teams.cert_may(store, s, row, right)


def _targets_of(store, cid):
    return sorted({r['target'] for r in store.db.rows(
        'SELECT target FROM cert_deploys WHERE cert_id = ?', (int(cid),)) if r.get('target')})


def _why_not(store, crow, tname, targets, s=None):
    """Why the certificate cannot have its key made by `tname` - words, or ''."""
    if crow.get('csr_from'):
        return 'its key is made by %s already' % crow['csr_from']
    other = [t for t in targets if t != tname]
    if other:
        return 'it is deployed to %s too - a key made on the server goes to that server alone' \
               % ', '.join(other[:3]) + (' …' if len(other) > 3 else '')
    from acmelib.certs import devicekey
    cur = dict(crow, csr_from=tname)
    may_see = None
    if s is not None:
        from acmelib.certs import teams
        may_see = lambda r: teams.cert_may(store, s, r, 'view')    # noqa: E731
    try:
        return devicekey.save_problem(store, cur, deploys=targets, may_see=may_see) or ''
    except Exception as e:                              # noqa: BLE001
        return str(e)[:300]


def _renew_at(crow):
    """When the certificate is renewed by itself (its renew window), or None."""
    try:
        from acmelib.certs import renewer
        na = float(crow.get('not_after') or 0)
        if not na or not crow.get('auto_renew'):
            return None
        return na - renewer.renew_window(crow, na, crow.get('not_before'))
    except Exception:                                   # noqa: BLE001
        return None


def target_view(store, trow, s=None):
    """One target with an agent: its certificates and where each one's key is made."""
    G = _G()
    name = trow['name']
    rows = store.db.rows('SELECT DISTINCT c.* FROM certs c WHERE c.csr_from = ? OR c.id IN '
                         '(SELECT cert_id FROM cert_deploys WHERE target = ?) ORDER BY c.name',
                         (name, name))[:CERTS_MOST]
    st = G.state(store, trow['id'])
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    from acmelib.certs import agent_deployguard as DG
    guard = DG.summary(pol)
    out = {'id': trow['id'], 'name': name, 'kind': trow.get('kind') or 'agent',
           'platform': st.get('platform') or ('windows' if trow.get('kind') == 'agent_windows'
                                              else 'linux'),
           'joined': bool(st.get('cert_fp')), 'guard': guard,
           'key_local': bool(guard and guard.get('key_local')), 'certs': [],
           'counts': {'agent': 0, 'acme': 0, 'switchable': 0, 'pending': 0, 'refused': 0,
                      'elsewhere': 0, 'hidden': 0}}
    for c in rows:
        if not _may(store, s, c, 'view'):
            out['counts']['hidden'] += 1
            continue
        targets = _targets_of(store, c['id'])
        one = {'id': c['id'], 'name': c['name'], 'state': c.get('state') or '',
               'not_after': c.get('not_after'), 'renew_at': _renew_at(c), 'targets': targets,
               'alone': targets == [name], 'issuer': c.get('issuer') or '',
               'key_type': c.get('key_type') or ''}
        src = str(c.get('csr_from') or '')
        if src == name:
            one['key'] = 'agent'
            out['counts']['agent'] += 1
        elif src:
            one['key'] = 'elsewhere'
            one['key_by'] = src
            out['counts']['elsewhere'] += 1
        else:
            one['key'] = 'acme'
            out['counts']['acme'] += 1
            why = _why_not(store, c, name, targets, s)
            one['switchable'] = not why
            if why:
                one['why'] = why
            else:
                out['counts']['switchable'] += 1
            p = pending(store, c['id'])
            if p and p.get('target') == name:
                one['pending'] = {'by': p.get('by') or '', 'at': p.get('at')}
                out['counts']['pending'] += 1
            if out['key_local']:
                one['refused'] = True           # require key local: the agent refuses it
                out['counts']['refused'] += 1
            one['may'] = _may(store, s, c, 'cert.edit')
        out['certs'].append(one)
    return out


def overview(store, s=None):
    G = _G()
    out = []
    for r in G.rows(store):
        try:
            out.append(target_view(store, r, s))
        except Exception as e:                          # noqa: BLE001
            out.append({'id': r['id'], 'name': r['name'], 'error': str(e)[:300], 'certs': [],
                        'counts': {}})
    tot = {'agent': 0, 'acme': 0, 'switchable': 0, 'pending': 0, 'refused': 0}
    for t in out:
        for k in tot:
            tot[k] += int((t.get('counts') or {}).get(k) or 0)
    return {'targets': out, 'totals': tot}


def target_counts(store, trow):
    """For the policy builder: {agent, acme, switchable, switch_ids}."""
    v = target_view(store, trow)
    return {'agent': v['counts']['agent'], 'acme': v['counts']['acme'],
            'switchable': v['counts']['switchable'],
            'switch_ids': [c['id'] for c in v['certs'] if c.get('switchable')][:200]}


# ---- the switch ---------------------------------------------------------------------------------
def _cert(store, ref):
    from acmelib.certs import store as S
    return S.cert_need(store, ref)


def _apply(store, crow, tname, by, s=None, full=True):
    """Where its key is made set to the target's agent - as the certificate's form sets it
    (api.cert_save: checked again, the certificate due for a new issue)."""
    from acmelib.certs import api
    api.cert_save(store, {'id': crow['id'], 'csr_from': tname}, by, full=full, s=s)


def switch(store, ids, when, by, s=None, full=True):
    """Each certificate (by id or name) switched to a key made by the agent of the one target
    it is deployed to: when 'next' (a mark - at its next renewal) or 'now' (switched and renewed
    at once). -> {done: [{id, name, target, when, job_id?}], refused: [{id, name, why}]}.
    `s`: the session - each certificate checked against what it may (cert.edit; now also
    cert.renew)."""
    if when not in ('next', 'now'):
        raise ValueError('when is next (at its next renewal) or now')
    if not isinstance(ids, list) or not ids:
        raise ValueError('no certificate given')
    if len(ids) > 200:
        raise ValueError('200 certificates at most at once')
    G = _G()
    agent_targets = {r['name'] for r in G.rows(store)}
    done, refused = [], []
    for ref in ids:
        try:
            c = _cert(store, ref)
        except LookupError as e:
            refused.append({'id': ref, 'name': str(ref), 'why': str(e)})
            continue
        if not _may(store, s, c, 'view'):
            refused.append({'id': ref, 'name': str(ref), 'why': 'there is no such certificate'})
            continue
        if not _may(store, s, c, 'cert.edit'):
            refused.append({'id': c['id'], 'name': c['name'], 'why': 'you may not change it'})
            continue
        if when == 'now' and not _may(store, s, c, 'cert.renew'):
            refused.append({'id': c['id'], 'name': c['name'], 'why': 'you may not renew it'})
            continue
        targets = _targets_of(store, c['id'])
        here = [t for t in targets if t in agent_targets]
        if not here:
            refused.append({'id': c['id'], 'name': c['name'],
                            'why': 'it is not deployed to a server with acme-agent'})
            continue
        tname = here[0]
        why = _why_not(store, c, tname, targets, s)
        if why:
            refused.append({'id': c['id'], 'name': c['name'], 'why': why})
            continue
        one = {'id': c['id'], 'name': c['name'], 'target': tname, 'when': when}
        if when == 'next':
            store.set_meta(M_SWITCH % int(c['id']), json.dumps(
                {'target': tname, 'by': str(by)[:120], 'at': time.time()}, sort_keys=True))
            store.add_event('certificates', 'the key of %s will be made on %s (its agent) from '
                            'its next renewal on - asked by %s' % (c['name'], tname, by), who=by)
        else:
            try:
                _apply(store, c, tname, by, s=s, full=full)
            except Exception as e:                      # noqa: BLE001
                refused.append({'id': c['id'], 'name': c['name'], 'why': str(e)[:300]})
                continue
            store.db.run('DELETE FROM meta WHERE k = ?', (M_SWITCH % int(c['id']),))
            store.add_event('certificates', 'the key of %s is made on %s (its agent) from now on '
                            '- switched by %s, renewed now' % (c['name'], tname, by), who=by)
            try:
                from acmelib.certs import api
                one['job_id'] = api.start_renew(store, c['id'], False, by)
            except Exception as e:                      # noqa: BLE001
                one['renew_error'] = str(e)[:300]
        done.append(one)
    return {'done': done, 'refused': refused}


def cancel(store, ids, by, s=None):
    out = []
    for ref in ids if isinstance(ids, list) else []:
        try:
            c = _cert(store, ref)
        except LookupError:
            continue
        if not _may(store, s, c, 'cert.edit') or not pending(store, c['id']):
            continue
        store.db.run('DELETE FROM meta WHERE k = ?', (M_SWITCH % int(c['id']),))
        store.add_event('certificates', 'the switch of %s to a key made on the server was taken '
                        'back by %s' % (c['name'], by), who=by)
        out.append({'id': c['id'], 'name': c['name']})
    return {'cancelled': out}


def sweep(store, now=None):
    """The switches waiting for the next renewal: made a day before it comes (the renewal then
    makes the key on the server), dropped when the certificate went or changed."""
    from acmelib.certs import renewer
    now = now or time.time()
    made = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'agentkeys:switch:%'"):
        p = _jload(r['v'], {})
        try:
            cid = int(r['k'].rsplit(':', 1)[1])
        except ValueError:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            continue
        c = store.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        tname = str(p.get('target') or '')
        if not c or c.get('csr_from') or not tname:
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            continue
        if not (renewer.main_due(c, now + AHEAD_S) or renewer.main_due(c, now)):
            continue
        targets = _targets_of(store, cid)
        why = _why_not(store, c, tname, targets)
        store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
        if why:
            store.add_event('certificates', 'the key of %s was not switched to %s at its renewal: '
                            '%s' % (c['name'], tname, why), 'warn')
            continue
        by = '%s (at its renewal)' % (p.get('by') or 'acme')
        try:
            _apply(store, c, tname, by)
        except Exception as e:                          # noqa: BLE001
            store.add_event('certificates', 'the key of %s was not switched to %s at its '
                            'renewal: %s' % (c['name'], tname, e), 'warn')
            continue
        store.add_event('certificates', 'the key of %s is made on %s (its agent) from this '
                        'renewal on - asked by %s' % (c['name'], tname, p.get('by') or '?'))
        made.append(c['name'])
    return made
