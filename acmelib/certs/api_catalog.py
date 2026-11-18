# -*- coding: utf-8 -*-
"""
The lists a module's form picks from - a field of the type `catalog`
(acmelib/plugins/base.py): a CA's products, its server types. The page's
"Load the list" (web/assets/catalog.js) asks here with the form as it is,
saved or not; the module's catalog(<the field's catalog>) asks its server and
answers {'options': [[value, words]], 'sets': {value: {field: value}}, 'said', 'pick'?}
('pick': the one to choose when nothing is chosen yet; a deployment's form may send the
certificate's `names` for the module to suggest by - 1.0.128).

    POST /api/sources/catalog       {id | (kind), name, config, field}
    POST /api/validations/catalog   the same for a validation
    POST /api/targets/catalog       the same for a target

Read-only, as Try it: the module may only read (its catalog() orders and
changes nothing), the settings given are used over the saved ones, a secret
left empty or as its dots is the one kept - and only a full administrator
tries settings that are not saved with the secrets kept (api.kept_secrets_guard,
as for Try it). No job is made: what the module says comes back in `steps`.
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import runtime
from acmelib.plugins.base import PluginError
from acmelib import engine as E

PATHS = {'issuer': 'sources', 'challenge': 'validations', 'target': 'targets'}


def catalog(store, family, b):
    row = S.plugin_row(store, family, A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    if b.get('id') not in (None, '', 0) and not row:
        raise LookupError('there is no such %s' % family)
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.given_class(family, kind, b.get('config'), row)
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (family, kind))
    key = str(b.get('field') or '').strip()
    pool = list(cls.fields or [])
    if family == 'target':
        # a deployment's form may pick from a list too (the virtual servers, services or
        # rules of the target): asked with the target's settings and the deployment's
        # options as they are in the form
        pool += list(getattr(cls, 'deploy_fields', None) or [])
    f = next((x for x in pool if x.get('key') == key and
              x.get('type') == 'catalog'), None)
    if f is None or not callable(getattr(cls, 'catalog', None)):
        raise ValueError('%s has no list to load for %s' % (kind, key or '?'))
    cfg = S.plugin_config(family, row) if row and row.get('kind') == kind else {}
    # a deployment's option left empty means "the target's" (a FortiGate's VDOM): it does
    # not wipe the target's own setting of the same name (1.0.128)
    dkeys = {x.get('key') for x in (getattr(cls, 'deploy_fields', None) or [])} \
        if family == 'target' else set()
    tkeys = {x.get('key') for x in cls.fields or []}
    for k, v in (A._dict(b.get('config'), 'config') or {}).items():
        if k in S.secret_fields(cls) and (v in (None, '') or E.is_masked(v)):
            continue                # "" or the dots shown: the one kept
        if v in (None, '') and k in dkeys and k in tkeys and cfg.get(k) not in (None, ''):
            continue
        cfg[k] = v
    name = (row or {}).get('name') or str(b.get('name') or 'unsaved')
    ctx = runtime.RunContext(store, None, scope='%s:%s' % (family, name), on_hostkey=False)
    try:
        mod = cls(cfg, ctx)
        # the names of the certificate a deployment's form is for (the page sends them): a
        # module may suggest the item that has them (a FortiGate's certificate to replace)
        hint = b.get('names')
        if family == 'target' and isinstance(hint, list):
            mod.hint_names = [str(x)[:255] for x in hint[:200] if isinstance(x, str) and x]
        got = mod.catalog(f.get('catalog') or key) or {}
    finally:
        ctx.tidy()
    opts = []
    for o in got.get('options') or []:
        if isinstance(o, (list, tuple)) and o:
            opts.append([str(o[0]), str(o[1] if len(o) > 1 else o[0])])
    sets = {str(k): dict(v) for k, v in (got.get('sets') or {}).items() if isinstance(v, dict)}
    pick = str(got.get('pick') or '')
    return {'ok': True, 'field': key, 'options': opts, 'sets': sets,
            'pick': pick if any(o[0] == pick for o in opts) else '',
            'said': str(got.get('said') or '%d' % len(opts)),
            'steps': [s[2] for s in ctx.steps][-50:]}


def _route(family, path):
    @A.api('POST', '/api/%s/catalog' % path, 'certadmin')
    def _catalog(h, s):
        b = h.body()
        A.kept_secrets_guard(h.store, family, b, s)
        b = A.saved_only(s, b, 'ask with')
        try:
            return catalog(h.store, family, b)
        except PluginError as e:
            # the CA's refusal in words, as the form shows it beside the list
            raise E.ApiError(400, str(e), detail=e.detail or '')
    return _catalog


for _fam, _path in PATHS.items():
    _route(_fam, _path)
