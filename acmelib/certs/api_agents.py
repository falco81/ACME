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
    GET  /api/agents/design?id=         the saved design, its history, the server compared
    POST /api/agents/design {id, text, state, title, note}   a design saved (documentation
                                        only - acme never sends it)          full administrator
    POST /api/agents/design/forget {id} the design deleted                   full administrator

    GET  /api/agents/enroll             the company enrollment codes and every agent waiting
                                        for confirmation (1.0.120)
    POST /api/agents/enroll {title, mode, port, days, most, auto}   a company enrollment code
                                        (shown once)                         full administrator
    POST /api/agents/enroll/revoke {id} no other server joins with it        full administrator
    GET  /api/agents/waiting            the agents asking to join, not confirmed yet
    POST /api/agents/confirm-many {items: [{id, fp}]}   several confirmed, each by the
                                        fingerprint it asks with              full administrator

    POST /api/agent-wire/{join,status,poll,enroll}   an active agent, through nginx (the agents' port)
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
            rows.append(G.info(h.store, r))
        except Exception as e:                          # noqa: BLE001
            rows.append({'id': r['id'], 'name': r['name'], 'state': 'new', 'error': str(e)[:200]})
    st = E.web_status() if hasattr(E, 'web_status') else {}
    out = {'active': G.active_on(), 'port': G.active_port(), 'endpoints': G.endpoints(h.store),
           'names': str(E.CONFIG.get('certs_agents_names') or ''),
           'ca': G.ca_public(h.store), 'rows': rows, 'node': E.node_name(),
           'nginx': (st or {}).get('agents') if isinstance(st, dict) else None,
           'shipped_code': G.shipped_code()}
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
    return out


@A.api('GET', '/api/agents/updates')
def _updates(h, s):
    return {'rows': G.update_candidates(h.store)}


@A.api('GET', '/api/agents/builder')
def _builder(h, s):
    return P.builder(h.store, _row(h))


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
    v = P.design_save(h.store, row, b.get('text'), b.get('state'), A._text(b, 'title', 500),
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
    return {'agent': out}


@A.api('POST', '/api/agents/confirm', 'fulladmin')
def _confirm(h, s):
    b = h.body()
    row = _row(h, b)
    G.confirm(h.store, row, A._text(b, 'fp', 200), A.who(s))
    out = {'agent': G.info(h.store, row)}
    if G.mode_of(row) == 'passive':
        try:
            out['agent'] = G.look(h.store, row, A.who(s))
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
                        most=b.get('most'), auto=bool(b.get('auto')))


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
