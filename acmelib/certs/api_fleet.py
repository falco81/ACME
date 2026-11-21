# -*- coding: utf-8 -*-
"""
The routes of the agents' fleet (1.0.138, docs/agent-fleet.md) - imported at the end of api.py.
The pages ask them as fleet, fleet/templates, fleet/act ... (admin/index.php relays /api/fleet/*).

    GET  /api/fleet                         the fleet: every agent (health, version, groups,
                                            template, drift), the groups, the templates, the
                                            versions, the rollout, how many certificates found
                                            are not managed
    GET  /api/fleet/templates[?platform=]   the templates with their builder state (the policy
                                            builder prefills from them)
    GET  /api/fleet/template?ref=           one template with its policy text
    POST /api/fleet/template_save {ref?, title, note, platform, text, design_state}
                                                                             full administrator
    POST /api/fleet/template_delete {ref}                                    full administrator
    POST /api/fleet/group_save {id?, name, color, note, members, template, canary}
                                                                             full administrator
    POST /api/fleet/group_delete {id}                                        full administrator
    POST /api/fleet/assign {ids, template}  the template these agents follow  full administrator
    GET  /api/fleet/drift?ids=1,2           each agent's template against its policy
    POST /api/fleet/act {action: ask | update, ids}   a job: asked now (a certificate
                                            administrator) or updated (a full administrator)
    GET  /api/fleet/rollout_plan[?canary=]  who the canary ring would be, who the rest, who not
    POST /api/fleet/rollout {canary, wait, healthy}   an update in rings     full administrator
    POST /api/fleet/rollout_step {do: continue | stop | forget}             full administrator
    GET  /api/fleet/unmanaged               the certificates discovery found that acme does
                                            not manage, by risk
    POST /api/fleet/takeover_preview {target, service, name?, names?, issuer?}
    POST /api/fleet/takeover {..., confirm, issue_now, auto_renew}       certificate administrator

Every route needs a session that sees every certificate (a full administrator, or an
administrator not limited to teams): the fleet is the whole of the agents.
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import fleet as FL


def _whole(s, right='view'):
    from acmelib.certs import teams
    if not teams.unscoped(s, right):
        raise E.ApiError(403, 'the agents\' fleet is for whoever sees every certificate')
    return s


@A.api('GET', '/api/fleet')
def _fleet(h, s):
    _whole(s)
    return FL.view(h.store)


@A.api('GET', '/api/fleet/templates')
def _templates(h, s):
    _whole(s)
    return {'templates': FL.templates(h.store, h.arg('platform') or None)}


@A.api('GET', '/api/fleet/template')
def _template(h, s):
    _whole(s)
    t = FL.template_get(h.store, h.arg('ref'))
    if not t:
        raise LookupError('there is no such template')
    return {'template': t}


@A.api('POST', '/api/fleet/template_save', 'fulladmin')
def _template_save(h, s):
    return {'template': FL.template_save(h.store, h.body(), A.who(s))}


@A.api('POST', '/api/fleet/template_delete', 'fulladmin')
def _template_delete(h, s):
    FL.template_delete(h.store, A._text(h.body(), 'ref', 80), A.who(s))
    return {'deleted': True}


@A.api('POST', '/api/fleet/group_save', 'fulladmin')
def _group_save(h, s):
    return {'group': FL.group_save(h.store, h.body(), A.who(s))}


@A.api('POST', '/api/fleet/group_delete', 'fulladmin')
def _group_delete(h, s):
    FL.group_delete(h.store, A._text(h.body(), 'id', 40), A.who(s))
    return {'deleted': True}


@A.api('POST', '/api/fleet/assign', 'fulladmin')
def _assign(h, s):
    b = h.body()
    return {'done': FL.assign(h.store, b.get('ids'), A._text(b, 'template', 80), A.who(s))}


@A.api('GET', '/api/fleet/drift')
def _drift(h, s):
    _whole(s)
    ids = [x for x in str(h.arg('ids') or h.arg('id') or '').split(',') if x.strip()]
    return {'rows': FL.drift_many(h.store, ids)}


@A.api('POST', '/api/fleet/act', 'certadmin')
def _act(h, s):
    _whole(s, 'manage')
    b = h.body()
    action = A._text(b, 'action', 20)
    if action == 'update' and not A.may(s, 'fulladmin'):
        raise E.ApiError(403, A.ROLE_WORDS['fulladmin'])
    return FL.act(h.store, action, b.get('ids'), A.who(s))


@A.api('GET', '/api/fleet/rollout_plan')
def _rollout_plan(h, s):
    _whole(s)
    return FL.rollout_plan(h.store, h.arg('canary') or '')


@A.api('POST', '/api/fleet/rollout', 'fulladmin')
def _rollout(h, s):
    return {'rollout': FL.rollout_start(h.store, h.body(), A.who(s))}


@A.api('POST', '/api/fleet/rollout_step', 'fulladmin')
def _rollout_step(h, s):
    return {'rollout': FL.rollout_step(h.store, A._text(h.body(), 'do', 20), A.who(s))}


@A.api('GET', '/api/fleet/unmanaged')
def _unmanaged(h, s):
    _whole(s)
    return {'rows': FL.unmanaged(h.store)}


@A.api('POST', '/api/fleet/takeover_preview', 'certadmin')
def _takeover_preview(h, s):
    _whole(s, 'manage')
    return {'preview': FL.takeover_preview(h.store, h.body())}


@A.api('POST', '/api/fleet/takeover', 'certadmin')
def _takeover(h, s):
    _whole(s, 'manage')
    return FL.takeover(h.store, h.body(), A.who(s), full=A.may(s, 'fulladmin'), s=s)
