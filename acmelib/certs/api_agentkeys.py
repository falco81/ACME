# -*- coding: utf-8 -*-
"""
What a target agent deploys (A1) and where its keys are made (B7) - 1.0.140, docs/target-agent.md
"What the agent deploys" and "Where keys are made". Imported at the end of api.py.

    GET  /api/agents/keyplace                   every target with an agent: how many of the
                                                certificates deployed there have the agent's
                                                own key, how many acme's, which could switch,
                                                `require key local` of its policy - only the
                                                certificates the session may see
    POST /api/agents/keyplace/switch {ids, when: next|now}   "Switch to a key made on the
                                                server" - each certificate checked against what
                                                the session may (cert.edit; now: cert.renew too)
                                                                      certificate administrator
    POST /api/agents/keyplace/cancel {ids}      a switch waiting for the renewal taken back
                                                                      certificate administrator
    GET  /api/agents/deployguard?id=            the guard of a target's agent: its lines, whether
                                                the agent knows them, each deployment there
                                                judged by them, the CAs acme knows

The command line (acme --agent-keys, --agent-keys-switch, --agent-keys-cancel, --agent-guard,
--agent-cas) and the console (Target agents) do the same - the same functions.
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import agent_keyplace as K
from acmelib.certs import agent_deployguard as DG


def _ids(v):
    if not isinstance(v, list):
        raise ValueError('ids is a list of certificates')
    out = []
    for x in v[:200]:
        if isinstance(x, bool) or not isinstance(x, (int, str)):
            raise ValueError('ids is a list of certificates')
        out.append(x)
    return out


@A.api('GET', '/api/agents/keyplace')
def _keyplace(h, s):
    return K.overview(h.store, s)


@A.api('POST', '/api/agents/keyplace/switch', 'certadmin')
def _keyplace_switch(h, s):
    b = h.body()
    when = str(b.get('when') or 'next')
    return K.switch(h.store, _ids(b.get('ids')), when, A.who(s), s=s,
                    full=A.may(s, 'fulladmin'))


@A.api('POST', '/api/agents/keyplace/cancel', 'certadmin')
def _keyplace_cancel(h, s):
    return K.cancel(h.store, _ids(h.body().get('ids')), A.who(s), s=s)


def guard_view(store, row, s=None):
    """A target's agent and the guard of its policy: the lines, whether its agent knows them,
    each deployment there judged by them (as acme judges it before sending)."""
    from acmelib.certs import agents as G
    from acmelib.certs import teams
    st = G.state(store, row['id'])
    pol = st.get('policy') if isinstance(st.get('policy'), dict) else None
    g = DG.guard_of(pol)
    out = {'target': row['name'], 'said': bool(pol), 'guard': DG.summary(pol),
           'supported': DG.supported(st) if isinstance(st.get('features'), list) else None,
           'lines': G.agent_mod().guard_lines(g) if g else [], 'deployments': []}
    if g:
        from acmelib.certs import api_deploys
        for d in store.db.rows('SELECT d.id, d.cert_id, c.name, c.csr_from, c.owner FROM '
                               'cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE '
                               'd.target = ? ORDER BY c.name', (row['name'],))[:200]:
            if s is not None and not teams.cert_may(store, s, d, 'view'):
                continue
            one = {'id': d['id'], 'cert': d['name'], 'key': 'agent' if d.get('csr_from') ==
                   row['name'] else 'acme'}
            try:
                _t, cls, cert, _d, opts, _sv = api_deploys._setup(store, {'id': d['id']}, None)
                b = api_deploys._bundle(cert, {}, cls, store, opts)
            except Exception:                           # noqa: BLE001
                b = _Empty()
            one['issued'] = bool(getattr(b, 'cert_pem', ''))
            one['problems'] = DG.check(store, pol, b, one['key'] == 'agent', row['name'])
            if not one['issued'] and g['names'] and getattr(b, 'names', None):
                m = G.agent_mod()
                out_n = [n for n in b.names if not m.name_allowed(g['names'], n)]
                if out_n:
                    one['problems'].append('not sent: the policy of the agent on %s refuses it '
                                           '(allow names): the name %s is not one it allows'
                                           % (row['name'], out_n[0]))
            one['ok'] = not one['problems']
            out['deployments'].append(one)
    return out


class _Empty(object):
    cert_pem = ''
    chain_pems = []


@A.api('GET', '/api/agents/deployguard')
def _deployguard(h, s):
    from acmelib.certs import agents as G
    ref = h.arg('id')
    try:
        ref = int(ref)
    except (TypeError, ValueError):
        pass
    row = G.target_row(h.store, ref)
    out = guard_view(h.store, row, s)
    out['cas'] = [{k: c[k] for k in ('fp', 'title', 'subject', 'root', 'kind', 'sources', 'certs',
                                     'here', 'not_after')} for c in DG.known_cas(h.store, row)]
    out['names'] = DG.deployed_names(h.store, row)
    return out


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------
KEYS = ('agent_keys', 'agent_keys_switch', 'agent_keys_cancel', 'agent_guard', 'agent_cas')


def add_args(p):
    g = p.add_argument_group('TARGET AGENTS: WHAT THEY DEPLOY, WHERE THEIR KEYS ARE MADE',
                             'The guard of an agent\'s policy (allow issuer, allow names, require '
                             'key local) and the keys made on the servers (docs/target-agent.md, '
                             '1.0.140).')
    g.add_argument('--agent-keys', nargs='?', const='*', metavar='TARGET',
                   help='where the keys of the certificates deployed to each target with an '
                        'agent are made - on the server, or acme\'s - and which could switch '
                        '(TARGET: only that one)')
    g.add_argument('--agent-keys-switch', nargs='+', metavar='CERT',
                   help='"Switch to a key made on the server": each certificate\'s key made by '
                        'the agent of the one target it is deployed to - from its next renewal '
                        'on (--now: switched and renewed now)')
    g.add_argument('--agent-keys-cancel', nargs='+', metavar='CERT',
                   help='a switch waiting for the next renewal taken back')
    g.add_argument('--now', action='store_true',
                   help='with --agent-keys-switch: switched and renewed now')
    g.add_argument('--agent-guard', metavar='TARGET',
                   help='what the agent of TARGET checks of what it deploys (allow issuer, allow '
                        'names, require key local) and each deployment there judged by it')
    g.add_argument('--agent-cas', nargs='?', const='*', metavar='TARGET',
                   help='the CAs acme knows, with their SHA-256 - what allow issuer names '
                        '(TARGET: the ones of its certificates first)')


def _when(ts):
    import time
    if not ts:
        return '-'
    return time.strftime('%Y-%m-%d', time.localtime(float(ts)))


def cli(c):
    from acmelib.certs import agents as G
    a, store, by = c.args, c.store, c.WHO
    try:
        if getattr(a, 'agent_keys_switch', None):
            if not c.json:
                c.sure('%d certificate(s): the key made on the server%s' % (
                    len(a.agent_keys_switch), ' - renewed now' if a.now else
                    ' from the next renewal on'))
            got = K.switch(store, list(a.agent_keys_switch), 'now' if a.now else 'next', by)
            if c.json:
                c.out(got)
            else:
                for x in got['done']:
                    print(c.pal.ok_line('%s: the key made on %s %s%s' % (
                        x['name'], x['target'], 'from now on - renewing (job %s)' % x.get('job_id')
                        if x['when'] == 'now' else 'from its next renewal on',
                        (' - ' + x['renew_error']) if x.get('renew_error') else '')))
                for x in got['refused']:
                    print(c.pal.bad_line('%s: not switched - %s' % (x['name'], x['why'])))
            return 0 if not got['refused'] else 1
        if getattr(a, 'agent_keys_cancel', None):
            got = K.cancel(store, list(a.agent_keys_cancel), by)
            return c.done('%d switch(es) taken back' % len(got['cancelled']), got)
        if getattr(a, 'agent_keys', None):
            got = K.overview(store)
            if a.agent_keys != '*':
                got['targets'] = [t for t in got['targets'] if t['name'] == a.agent_keys]
                if not got['targets']:
                    raise SystemExit('acme: %s is no target with an agent' % a.agent_keys)
            if c.json:
                c.out(got)
                return 0
            for t in got['targets']:
                n = t.get('counts') or {}
                print('%s - the key made on the server: %d, acme\'s key: %d%s%s' % (
                    t['name'], n.get('agent', 0), n.get('acme', 0),
                    (', could switch: %d' % n['switchable']) if n.get('switchable') else '',
                    ' - its policy: require key local' if t.get('key_local') else ''))
                rows = []
                for x in t.get('certs') or []:
                    if x['key'] == 'agent':
                        how = 'made on the server'
                    elif x['key'] == 'elsewhere':
                        how = 'made by %s' % x.get('key_by')
                    else:
                        how = 'acme\'s'
                    if x.get('pending'):
                        what = 'switches at its next renewal'
                    elif x.get('switchable'):
                        what = 'could switch' + (' - REFUSED by require key local'
                                                 if x.get('refused') else '')
                    elif x['key'] == 'acme':
                        what = x.get('why') or ''
                    else:
                        what = ''
                    rows.append([x['name'], how, _when(x.get('not_after')), what])
                if rows:
                    c.table(rows, ['certificate', 'key', 'until', ''])
                print('')
            if not got['targets']:
                print('no target with an agent')
            return 0
        if getattr(a, 'agent_guard', None):
            try:
                row = G.target_row(store, a.agent_guard)
            except LookupError as e:
                raise SystemExit('acme: %s' % e)
            got = guard_view(store, row)
            if c.json:
                c.out(got)
                return 0
            if not got['said']:
                print('the agent of %s has not said its policy yet' % row['name'])
                return 0
            if not got['guard']:
                print('the policy of the agent of %s does not check what it deploys (no allow '
                      'issuer, allow names, require key local) - on the server, as root:\n'
                      '  acme-agent allow issuer CA.pem\n  acme-agent allow names NAME...\n'
                      '  acme-agent require key local' % row['name'])
                return 0
            print('the agent of %s checks what it deploys (%s):' % (row['name'],
                                                                   got['guard']['words']))
            for line in got['lines']:
                print('  ' + line)
            if got['supported'] is False:
                print(c.pal.bad_line('its agent does not know these lines - update it'))
            bad = 0
            for d in got['deployments']:
                if d['ok']:
                    print(c.pal.ok_line('%s: allowed' % d['cert']))
                else:
                    bad += 1
                    print(c.pal.bad_line('%s: %s' % (d['cert'], d['problems'][0])))
            return 1 if bad else 0
        if getattr(a, 'agent_cas', None):
            row = None
            if a.agent_cas != '*':
                try:
                    row = G.target_row(store, a.agent_cas)
                except LookupError as e:
                    raise SystemExit('acme: %s' % e)
            cas = DG.known_cas(store, row)
            if c.json:
                c.out([{k: x[k] for k in ('fp', 'title', 'subject', 'root', 'kind', 'sources',
                                          'certs', 'here')} for x in cas])
                return 0
            rows = [[x['title'], 'root' if x['root'] else 'intermediate', ', '.join(
                x['sources'][:3]), 'yes' if x['here'] else '', x['fp']] for x in cas]
            if rows:
                c.table(rows, ['CA', 'kind', 'from', 'used there' if row else '', 'sha256'])
                print('(on the server, as root: acme-agent allow issuer sha256=HEX)')
            else:
                print('acme knows no CA yet')
            return 0
    except (ValueError, LookupError) as e:
        raise SystemExit('acme: %s' % e)
    return None
