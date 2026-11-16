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
                                        signed, data_b64}

    POST /api/agent-wire/{join,status,poll}   an active agent, through nginx (the agents' port)
                                        and web/agent.php only - the API's token, never a
                                        session: the pages' relay does not reach it.
"""
from __future__ import annotations

import base64
import time

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import agents as G
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
    return {'package': {k: pkg.get(k) for k in ('name', 'version', 'sha256', 'size', 'signed')},
            'commands': ['sha256sum %s' % name, 'tar xzf %s' % name,
                         'cd %s && sudo ./install.sh' % top,
                         'sudo acme-agent join CODE']}


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
    return out


@A.api('GET', '/api/agents/one')
def _one(h, s):
    row = _row(h)
    out = G.info(h.store, row)
    out.update(_install(h.store, row))
    out['ca'] = G.ca_public(h.store)
    out['port'] = G.active_port()
    return out


@A.api('POST', '/api/agents/code', 'fulladmin')
def _code(h, s):
    row = _row(h, h.body())
    got = G.code_new(h.store, row, A.who(s))
    got['agent'] = G.info(h.store, row)
    return got


@A.api('POST', '/api/agents/look', 'certadmin')
def _look(h, s):
    row = _row(h, h.body())
    return {'agent': G.look(h.store, row, A.who(s))}


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
    pkg = G.package(build=True)
    with open(pkg['path'], 'rb') as f:
        data = f.read()
    return {'name': pkg['name'], 'version': pkg['version'], 'sha256': pkg['sha256'],
            'size': pkg['size'], 'signed': pkg['signed'], 'mime': 'application/gzip',
            'filename': pkg['name'], 'data_b64': base64.b64encode(data).decode('ascii')}


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


for _op in ('join', 'status', 'poll'):
    _wire(_op)
del _op
