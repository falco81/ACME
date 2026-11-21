# -*- coding: utf-8 -*-
"""
A module cloned with the same credentials (1.0.138, the right button's Clone - web/assets/
ctxmenu.js, docs/context-menu.md).

    POST /api/sources/save_copy       {copy_of: ID, name, kind, config, enabled, note, tags,
    POST /api/validations/save_copy    owner} - a NEW source / validation / target / test, as
    POST /api/targets/save_copy        /save makes one, whose secrets left empty (or given as
    POST /api/tests/save_copy          the dots the page shows) are the ones `copy_of` keeps

The page never sees a secret, so a copy that should sign in as the original does cannot carry
one: it names the original instead, and the secrets are copied here - opened from the
original's row and sealed again for the copy's own place (store.config_seal), as if they had
been typed in. Nothing else of the original is taken: every other setting is what the form
sends. A full administrator's, as /save is; the original must be of the same module (another
module's secret means something else), and a copy only - never a change of an existing one
(no `id`). The event says which secrets came from where; no value is logged or answered.
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S


PATHS = {'issuer': 'sources', 'challenge': 'validations', 'target': 'targets', 'check': 'tests'}


def save_copy(store, family, b, by):
    """{id, copied: [the keys of the secrets taken from the original]}."""
    if not isinstance(b, dict):
        raise ValueError('a copy is a JSON object')
    if b.get('id') not in (None, '', 0):
        raise ValueError('a copy is a new one - it has no id (to change one, save it)')
    src = S.plugin_row(store, family, A._id(b.get('copy_of'), 'copy_of'))
    if not src:
        raise LookupError('there is no such %s to copy' % family)
    kind = str(b.get('kind') or src.get('kind') or '')
    if kind != src.get('kind'):
        raise ValueError('the same credentials go only with the same module: %s is %s, the copy %s'
                         % (src['name'], src.get('kind'), kind))
    cls = S.row_class(family, src)
    if cls is None:
        raise ValueError('the module %s of %s is missing (taken away, or it did not load)'
                         % (src.get('kind'), src['name']))
    secrets_ = S.secret_fields(cls)
    given = A._dict(b.get('config'), 'config') if 'config' in b else {}
    given = dict(given or {})
    plain = S.plugin_config(family, src)
    copied = []
    for k in sorted(secrets_):
        v = given.get(k)
        if (v in (None, '') or E.is_masked(v)) and plain.get(k) not in (None, ''):
            given[k] = plain[k]
            copied.append(k)
    body = dict(b)
    body.pop('copy_of', None)
    body.pop('id', None)
    body['kind'] = kind
    body['config'] = given
    ident = A.family_save(store, family, body, by)       # api_sshkeys' when it is there
    if copied:
        row = S.plugin_row(store, family, ident) or {}
        store.add_event('certificates', '%s %s made as a copy of %s - with its credentials (%s) by %s'
                        % ({'issuer': 'source', 'challenge': 'validation', 'target': 'target',
                            'check': 'test'}[family], row.get('name') or body.get('name'),
                            src['name'], ', '.join(copied), by), who=by)
    return {'id': ident, 'copied': copied}


def _route(family, path):
    @A.api('POST', '/api/%s/save_copy' % path, 'fulladmin')
    def _save_copy(h, s):
        return save_copy(h.store, family, h.body(), A.who(s))
    return _save_copy


for _fam, _path in PATHS.items():
    _route(_fam, _path)
