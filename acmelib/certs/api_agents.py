# -*- coding: utf-8 -*-
"""
The routes of target agents (1.0.116, docs/target-agent.md) - imported at the end of api.py.

    GET  /api/agents                    the pane: the agents' port, the authority, the package,
                                        every target with an agent and its state
    GET  /api/agents/one?id=            one target's agent (the card, the wizard)
    POST /api/agents/code {id}          a join code (an hour, once)            full administrator
    POST /api/agents/look {id}          the join as far as acme drives it (a passive agent
                                        reached), or a hello; -> the card
    POST /api/agents/confirm {id, fp}   the agent's fingerprint confirmed       full administrator
    POST /api/agents/renew {id}         its certificate renewed now             full administrator
    POST /api/agents/forget {id}        forgotten: no longer let in             full administrator
    POST /api/agents/update {id}        the signed agent this acme ships sent to it (the agent
                                        checks its signature and that it is newer; only with
                                        `allow self-update` in its policy)  full administrator
    GET  /api/agents/package            the install package {name, version, sha256, size,
                                        signed, data_b64, windows: {name, version, sha256,
                                        size, signed, product_code} | null, windows_why}
    GET  /api/agents/package?platform=windows   the Windows agent's MSI, the same way (1.0.120;
                                        404 "comes with a release" in a source tree)
    GET  /api/agents/updates            the agents a newer one is offered to: whether acme can
                                        update each now, and why not (1.0.118)
    GET  /api/agents/builder?id=        the policy builder: the agent, the lists the agent
                                        checks with, the templates, what each deployment needs,
                                        acme's addresses, the saved design (1.0.118)
    GET  /api/agents/adcs?target=NAME[&ca=HOST\\CA]   the Microsoft CAs and templates a
                                        Windows server's agent reads (1.0.125, read-only; what
                                        its policy lets it list)        certificate administrator
    GET  /api/agents/discover?target=NAME[&kind=K,K][&cached=1]   what services of the server
                                        use certificates (1.0.125, docs/target-agent.md
                                        "Discovery"): a signed job `discover`, read-only on
                                        the server, only where its policy says `allow discover`
                                        (else the refusal with the line that allows it); the
                                        answer kept with the target. cached=1: the last one kept,
                                        the agent not asked             certificate administrator
    GET  /api/agents/design?id=         the saved design, its history, the server compared
    POST /api/agents/design {id, text, design_state, title, note}   a design saved (documentation
                                        only - acme never sends it)          full administrator
    POST /api/agents/design/forget {id} the design deleted                   full administrator

    GET  /api/agents/enroll             the company enrollment codes and every agent waiting
                                        for confirmation (1.0.120)
    POST /api/agents/enroll {title, mode, port, days, most, auto, team?}   a company enrollment code
                                        (shown once)                         full administrator
    POST /api/agents/enroll/revoke {id} no other server joins with it        full administrator
    GET  /api/agents/waiting            the agents asking to join, not confirmed yet
    POST /api/agents/confirm-many {items: [{id, fp}]}   several confirmed, each by the
                                        fingerprint it asks with              full administrator

    1.0.138 - watched more closely (agent_guard.py; each chosen per target, off by default):
    GET  /api/agents/guard?id=          the audit chain (A6), anomalies (A7), keys and their age
                                        (A8), what the services serve (B6) of one target's agent
    POST /api/agents/guard {id, audit?, anomaly?, rotate?, rotate_days?, health?}   the choices
                                                                             full administrator
    POST /api/agents/guard/verify {id}  the chain read and checked now   certificate administrator
    POST /api/agents/guard/ack {id, what: audit|anomaly}   looked at: what did not agree put
                                        away, what is there now the usual    full administrator
    POST /api/agents/guard/rotate {id, what: command|seal|both}   Rotate now  full administrator
    POST /api/agents/guard/served {id}  what the services serve asked now
                                                                      certificate administrator
    GET  /api/agents/keys               the age of every key (acme's and each agent's)
    POST /api/agents/keys/rotate        a new command key for acme; the agents whose keys are
                                        changed on a schedule moved to it   full administrator

    POST /api/agent-wire/{join,status,poll,enroll}   an active agent (enroll: one joining with a
                                        company enrollment code), through nginx (the agents' port)
                                        and web/agent.php only - the API's token, never a
                                        session: the pages' relay does not reach it.
"""
from __future__ import annotations

import base64
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import agents as G
from acmelib.certs import agent_policy as P
from acmelib.plugins.base import PluginError


class _Seer(object):
    """A session of the administration as portal_teams._others_hidden reads a member: `all`, or
    the teams (lower case) whose certificates it sees."""

    def __init__(self, store, s):
        from acmelib.certs import teams
        self.store = store
        self.sc = teams.scope(store, s, 'view')
        self.all = self.sc is None

    def reach(self, _cap):
        return self.sc or ()


def _seen_only(store, s, out):
    """What a target's agent says, as a session kept to its teams sees it (hunt v2): the
    certificates of the agent's server of other teams (and of none) not named - the builder's
    needs and "Allowed names", the certificates whose key the agent makes, a discovery's
    certificates acme holds - as the Targets list (targets_seen) and the portal
    (_others_hidden) already said them."""
    me = _Seer(store, s)
    if me.all or not isinstance(out, dict):
        return out
    if 'agent' not in out:
        # an agent's row (the list, the card): the certificates whose key it makes
        if isinstance(out.get('keys_of'), list):
            out['keys_of'] = [n for n in out['keys_of'] if _cert_seen(me, n)]
        if isinstance(out.get('guard'), dict):
            # what its services serve (hunt w1): the certificates of other teams named too
            from acmelib.certs import portal_teams
            portal_teams._served_hidden(me, out['guard'].get('served'))
        return out
    from acmelib.certs import portal_teams
    return portal_teams._others_hidden(me, out)


def _cert_seen(me, name):
    r = me.store.db.row('SELECT owner FROM certs WHERE name = ?', (name,))
    return r is not None and str(r.get('owner') or '').strip().lower() in me.reach('cert.view')


def _row(h, b=None):
    ref = (b or {}).get('id') if b is not None else h.arg('id')
    try:
        ref = int(ref)
    except (TypeError, ValueError):
        pass
    return G.target_row(h.store, ref)


def _install(store, row=None):
    pkg = G.package(build=True) or {}
    name = pkg.get('name') or 'acme-agent.tar.gz'
    top = name[:-len('.tar.gz')]
    out = {'package': {k: pkg.get(k) for k in ('name', 'version', 'sha256', 'size', 'signed')},
           'commands': ['sha256sum %s' % name, 'tar xzf %s' % name,
                        'cd %s && sudo ./install.sh' % top,
                        'sudo acme-agent join CODE']}
    out['package']['windows'], out['package']['windows_why'] = _windows()
    win = out['package']['windows']
    out['windows_commands'] = G.windows_commands(win['name']) if win else []
    return out


def _windows():
    """The Windows MSI's facts for the pages (1.0.120), or None and why."""
    try:
        win, why = G.package_windows()
    except OSError as e:
        return None, str(e)[:300]
    if not win:
        return None, why
    return {k: win.get(k) for k in ('name', 'version', 'sha256', 'size', 'signed',
                                    'product_code')}, None


@A.api('GET', '/api/agents')
def _agents(h, s):
    rows = []
    for r in G.rows(h.store):
        try:
            rows.append(_seen_only(h.store, s, G.info(h.store, r)))
        except Exception as e:                          # noqa: BLE001
            rows.append({'id': r['id'], 'name': r['name'], 'state': 'new', 'error': str(e)[:200]})
    st = E.web_status() if hasattr(E, 'web_status') else {}
    out = {'active': G.active_on(), 'port': G.active_port(), 'endpoints': G.endpoints(h.store),
           'names': str(E.CONFIG.get('certs_agents_names') or ''),
           'ca': G.ca_public(h.store), 'rows': rows, 'node': E.node_name(),
           'nginx': (st or {}).get('agents') if isinstance(st, dict) else None,
           'shipped_code': G.shipped_code(), 'shipped_codes': G.shipped_codes()}
    try:
        out.update(_install(h.store))
    except Exception as e:                              # noqa: BLE001
        out['package'] = None
        out['package_error'] = str(e)[:300]
    # 1.0.120: the company enrollment codes, the agents waiting to be confirmed
    try:
        out['enroll'] = G.enroll_list(h.store)
        out['waiting'] = G.waiting(h.store)
    except Exception as e:                              # noqa: BLE001
        out['enroll'], out['waiting'] = [], []
        out['enroll_error'] = str(e)[:300]
    return out


@A.api('GET', '/api/agents/one')
def _one(h, s):
    row = _row(h)
    out = G.info(h.store, row)
    out.update(_install(h.store, row))
    out['ca'] = G.ca_public(h.store)
    out['port'] = G.active_port()
    out['design'] = P.design_view(h.store, row, out.get('policy'))
    return _seen_only(h.store, s, out)


@A.api('GET', '/api/agents/updates')
def _updates(h, s):
    return {'rows': G.update_candidates(h.store)}


@A.api('GET', '/api/agents/builder')
def _builder(h, s):
    return _seen_only(h.store, s, P.builder(h.store, _row(h)))


@A.api('GET', '/api/agents/adcs', 'certadmin')
def _adcs(h, s):
    """The CAs and templates the agent of a Windows server reads (1.0.125) - read-only."""
    ref = h.arg('target') or h.arg('id')
    try:
        ref = int(ref)
    except (TypeError, ValueError):
        pass
    return P.adcs_lists(h.store, G.target_row(h.store, ref), ca=h.arg('ca') or '')


@A.api('GET', '/api/agents/discover', 'certadmin')
def _discover(h, s):
    """A discovery on the server of a target's agent (1.0.125) - read-only."""
    from acmelib.certs import agent_discover
    ref = h.arg('target') or h.arg('id')
    try:
        ref = int(ref)
    except (TypeError, ValueError):
        pass
    row = G.target_row(h.store, ref)
    if str(h.arg('cached') or '') in ('1', 'true', 'yes'):
        got = agent_discover.cached(h.store, row)
        return {'discovery': _seen_disc(h.store, s, got), 'target': row['name']}
    if s.get('view_as_by'):
        # a GET that is no read (hunt w1): a signed job sent to the server, its answer kept with
        # the target and an event in the member's name - while viewing the pages as them, which
        # changes nothing; the last discovery kept (cached=1) is still shown
        h.store.add_event('certificates', '%s, viewing the pages as %s (read-only), was refused: '
                          'GET /api/agents/discover' % (s['view_as_by'], A.who(s)), 'warn',
                          who=str(s['view_as_by'])[:190])
        raise E.ApiError(403, 'read-only: you are viewing the pages as %s - nothing is changed '
                              'while you do (Stop viewing as first)' % A.who(s))
    return {'discovery': _seen_disc(h.store, s, agent_discover.run(
        h.store, row, h.arg('kind') or None, A.who(s))), 'target': row['name']}


def _seen_disc(store, s, got):
    me = _Seer(store, s)
    if me.all or not isinstance(got, dict):
        return got
    from acmelib.certs import portal_teams
    return portal_teams._disc_hidden(me, got)


@A.api('GET', '/api/agents/design')
def _design(h, s):
    row = _row(h)
    return {'design': P.design_view(h.store, row, G.info(h.store, row).get('policy'))}


@A.api('POST', '/api/agents/design', 'fulladmin')
def _design_save(h, s):
    b = h.body()
    row = _row(h, b)
    if not isinstance(b.get('text'), str):
        raise ValueError('text is the policy file')
    # the builder's state as `design_state` (hunt R t4): `state` is a word of every body (the
    # API refuses an object there) - the designer's Save said "state is a piece of text here"
    st = b.get('design_state') if b.get('design_state') is not None else b.get('state')
    v = P.design_save(h.store, row, b.get('text'), st, A._text(b, 'title', 500),
                      A._text(b, 'note', 4000), A.who(s))
    return {'saved': {k: v.get(k) for k in ('n', 'at', 'by', 'title', 'entries')},
            'design': P.design_view(h.store, row, G.info(h.store, row).get('policy'))}


@A.api('POST', '/api/agents/design/forget', 'fulladmin')
def _design_forget(h, s):
    row = _row(h, h.body())
    P.design_forget(h.store, row, A.who(s))
    return {'design': None}


@A.api('POST', '/api/agents/code', 'fulladmin')
def _code(h, s):
    row = _row(h, h.body())
    got = G.code_new(h.store, row, A.who(s))
    got['agent'] = G.info(h.store, row)
    return got


@A.api('POST', '/api/agents/look', 'certadmin')
def _look(h, s):
    row = _row(h, h.body())
    out = G.look(h.store, row, A.who(s))
    out['design'] = P.design_view(h.store, row, out.get('policy'))
    # as the card's GET /api/agents/one says it (hunt w1: the certificates whose key the agent
    # makes and what its services serve were named of other teams' certificates too)
    return {'agent': _seen_only(h.store, s, out)}


@A.api('POST', '/api/agents/confirm', 'fulladmin')
def _confirm(h, s):
    b = h.body()
    row = _row(h, b)
    G.confirm(h.store, row, A._text(b, 'fp', 200), A.who(s))
    out = {'agent': G.info(h.store, row)}
    if G.mode_of(row) == 'passive':
        try:
            out['agent'] = G.look(h.store, row, A.who(s))
            # hunt R u3: look says what went wrong in its answer (it raises nothing) - the
            # pages said "the agent is confirmed" while its certificate never reached it
            if out['agent'].get('said'):
                out['said'] = out['agent']['said']
        except PluginError as e:
            out['said'] = str(e)
    return out


@A.api('POST', '/api/agents/renew', 'fulladmin')
def _renew(h, s):
    row = _row(h, h.body())
    end = G.renew_cert(h.store, row, A.who(s))
    return {'cert_end': end, 'agent': G.info(h.store, row)}


@A.api('POST', '/api/agents/forget', 'fulladmin')
def _forget(h, s):
    row = _row(h, h.body())
    G.forget(h.store, row, A.who(s))
    return {'agent': G.info(h.store, row)}


@A.api('POST', '/api/agents/update', 'fulladmin')
def _update(h, s):
    row = _row(h, h.body())
    got = G.update_agent(h.store, row, A.who(s))
    return {'said': got.get('said') or '', 'agent': G.info(h.store, row)}


@A.api('GET', '/api/agents/package', 'certadmin')
def _package(h, s):
    if (h.arg('platform') or 'linux').lower() == 'windows':
        # the Windows agent's MSI (1.0.120): only the one a release brought
        win, why = G.package_windows()
        if not win:
            raise E.ApiError(404, why)
        with open(win['path'], 'rb') as f:
            data = f.read()
        return {'name': win['name'], 'version': win['version'], 'sha256': win['sha256'],
                'size': win['size'], 'signed': win['signed'],
                'product_code': win['product_code'], 'platform': 'windows',
                'mime': 'application/x-msi', 'filename': win['name'],
                'data_b64': base64.b64encode(data).decode('ascii')}
    pkg = G.package(build=True)
    with open(pkg['path'], 'rb') as f:
        data = f.read()
    win, why = _windows()
    return {'name': pkg['name'], 'version': pkg['version'], 'sha256': pkg['sha256'],
            'size': pkg['size'], 'signed': pkg['signed'], 'mime': 'application/gzip',
            'filename': pkg['name'], 'data_b64': base64.b64encode(data).decode('ascii'),
            'platform': 'linux', 'windows': win, 'windows_why': why}


# ---- watched more closely (1.0.138, agent_guard.py) ------------------------------------------
def _guard():
    from acmelib.certs import agent_guard
    return agent_guard


def _guard_seen(store, s, view):
    """The card's "Watching this agent" as a session kept to its teams sees it (hunt w1): what
    the services serve - the certificate, the names and the subject it serves - of its own
    certificates only."""
    me = _Seer(store, s)
    if not me.all and isinstance(view, dict):
        from acmelib.certs import portal_teams
        portal_teams._served_hidden(me, view.get('served'))
    return view


@A.api('GET', '/api/agents/guard')
def _guard_view(h, s):
    return {'guard': _guard_seen(h.store, s, _guard().view(h.store, _row(h)))}


@A.api('POST', '/api/agents/guard', 'fulladmin')
def _guard_save(h, s):
    b = h.body()
    row = _row(h, b)
    body = {k: b[k] for k in ('audit', 'anomaly', 'rotate', 'rotate_days', 'health') if k in b}
    _guard().set_opts(h.store, row, body, A.who(s))
    return {'guard': _guard().view(h.store, row), 'agent': G.info(h.store, row)}


@A.api('POST', '/api/agents/guard/verify', 'certadmin')
def _guard_verify(h, s):
    row = _row(h, h.body())
    if not _guard().opts(h.store, row['id'])['audit']:
        raise ValueError('acme does not compare the audit chain of this agent (switch it on)')
    _guard().read_chain(h.store, row, A.who(s), recheck=True)
    return {'guard': _guard_seen(h.store, s, _guard().view(h.store, row))}


@A.api('POST', '/api/agents/guard/ack', 'fulladmin')
def _guard_ack(h, s):
    b = h.body()
    row = _row(h, b)
    _guard().ack(h.store, row, A._text(b, 'what', 20), A.who(s))
    return {'guard': _guard().view(h.store, row), 'agent': G.info(h.store, row)}


@A.api('POST', '/api/agents/guard/rotate', 'fulladmin')
def _guard_rotate(h, s):
    b = h.body()
    row = _row(h, b)
    got = _guard().rotate_now(h.store, row, A._text(b, 'what', 20) or 'both', A.who(s))
    return {'rotated': got, 'guard': _guard().view(h.store, row)}


@A.api('POST', '/api/agents/guard/served', 'certadmin')
def _guard_served(h, s):
    row = _row(h, h.body())
    st = G.state(h.store, row['id'])
    if not _guard().served_on(h.store, row, st):
        raise ValueError('what the services serve is asked only where the agent\'s policy allows '
                         '"allow probe local" (and it is not switched off on the card)')
    _guard().served_check(h.store, row, force=True, by=A.who(s))
    return {'guard': _guard_seen(h.store, s, _guard().view(h.store, row))}


@A.api('GET', '/api/agents/keys')
def _keys(h, s):
    return {'keys': _guard().keys_report(h.store)}


@A.api('POST', '/api/agents/keys/rotate', 'fulladmin')
def _keys_rotate(h, s):
    got = _guard().rotate_all(h.store, A.who(s))
    return {'rotated': got, 'keys': _guard().keys_report(h.store)}


# ---- the company enrollment code (1.0.120) ---------------------------------------------------
@A.api('GET', '/api/agents/enroll')
def _enroll_list(h, s):
    return {'codes': G.enroll_list(h.store), 'waiting': G.waiting(h.store),
            'active': G.active_on()}


@A.api('POST', '/api/agents/enroll', 'fulladmin')
def _enroll_new(h, s):
    b = h.body()
    return G.enroll_new(h.store, A.who(s), title=A._text(b, 'title', 200),
                        mode=b.get('mode') or 'passive', port=b.get('port'), days=b.get('days'),
                        most=b.get('most'), auto=bool(b.get('auto')),
                        team=A._text(b, 'team', 190) or None)


@A.api('POST', '/api/agents/enroll/revoke', 'fulladmin')
def _enroll_revoke(h, s):
    b = h.body()
    return {'code': G.enroll_revoke(h.store, A._text(b, 'id', 40), A.who(s))}


@A.api('GET', '/api/agents/waiting')
def _waiting(h, s):
    return {'rows': G.waiting(h.store)}


@A.api('POST', '/api/agents/confirm-many', 'fulladmin')
def _confirm_many(h, s):
    b = h.body()
    if not isinstance(b.get('items'), list) or not b['items']:
        raise ValueError('items: the agents to confirm, each {id, fp}')
    got = G.confirm_many(h.store, b['items'], A.who(s))
    return {'rows': got, 'confirmed': sum(1 for x in got if x['ok']),
            'waiting': G.waiting(h.store)}


# ---- the wire: an active agent (no session - the API's token, from web/agent.php) ------------
def _wire(op):
    def run(h):
        t0 = time.time()
        try:
            b = h.body()
        except E.ApiError as e:
            return h.send_json({'ok': False, 'said': str(e)}, e.status)
        body = b.get('body') if isinstance(b.get('body'), dict) else {}
        try:
            status, out = G.wire(h.store, op, body, b.get('cert') or '', b.get('verify') or '',
                                 str(b.get('ip') or '')[:45])
        except PluginError as e:
            status, out = 400, {'ok': False, 'said': str(e)}
        if status >= 400 and op != 'poll':
            E.log('agent wire %s from %s: %s (%d ms)' % (op, str(b.get('ip') or '?')[:45],
                                                        out.get('said'), (time.time() - t0) * 1000),
                  'info')
        return h.send_json(out, status)
    run.__name__ = 'agent_wire_' + op
    E.route('POST', '/api/agent-wire/' + op)(run)


for _op in ('join', 'status', 'poll', 'enroll'):
    _wire(_op)
del _op
