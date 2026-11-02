# -*- coding: utf-8 -*-
"""
The search box over the certificates (1.0.24): `field:value` read as every
list reads it (engine ListQuery - `state:failed`, `source:"Let's Encrypt"`,
`dns:*.example.cz`, `-tag:test`, `(owner:novak OR owner:svoboda)`), offered as
one types (GET /api/suggest?list=certs). Words alone search as before: the
name, the names, the note, the serial.

The values offered are read for the person asking: only the certificates of
the teams they may see (teams.where), and only fields whose values tell
nothing of a certificate one may not see beyond what the pages show anyway.
"""
from __future__ import annotations

import collections
import json

from acmelib import engine as E

FIELDS = {
    'name': ('name', 'text'), 'cn': ('cn', 'text'), 'dns': ('names', 'list'),
    'names': ('names', 'list'), 'state': ('state', 'text'), 'source': ('issuer', 'text'),
    'issuer': ('issuer', 'text'), 'validation': ('challenge', 'text'),
    'key': ('key_type', 'text'), 'tag': ('tags', 'list'), 'owner': ('owner', 'text'),
    'note': ('note', 'text'), 'serial': ('serial', 'text'), 'by': ('created_by', 'text'),
    'renew': ('auto_renew', 'ok'), 'days': ('renew_days', 'num'), 'version': ('version', 'num'),
}
SAYS = [
    ('name', 'its name in acme', 'name:www*'),
    ('dns', 'one of its names', 'dns:*.example.cz'),
    ('state', 'ok, new, failed, pending, revoked, disabled…', 'state:failed'),
    ('source', 'the source it comes from', 'source:LetsEncrypt'),
    ('validation', 'how its names are proved', 'validation:webglobe'),
    ('key', 'its key type', 'key:rsa-2048'),
    ('tag', 'one of its tags', 'tag:prod'),
    ('owner', 'who it belongs to', 'owner:novak'),
    ('note', 'its note', 'note~customer'),
    ('serial', 'its serial number', 'serial:5DD2*'),
    ('renew', 'renewed by itself: yes or no', 'renew:no'),
    ('days', 'renewed that many days before the end', 'days:<20'),
    ('cn', 'its common name', 'cn:www.example.cz'),
    ('by', 'who added it', 'by:admin'),
]
WORDS = ('name', 'cn', 'names', 'note', 'serial')
# Offered as one types: what these hold, counted over the certificates one sees.
OFFERED = ('state', 'source', 'issuer', 'validation', 'key', 'tag', 'owner', 'dns', 'names',
           'name', 'by', 'renew')


def register():
    E.LIST_FIELDS['certs'] = FIELDS
    E.LIST_FIELD_SAYS['certs'] = SAYS
    E.LIST_WORD_COLUMNS['certs'] = WORDS
    E.LIST_VALUES['certs'] = values


def where(text):
    """(sql, args) of what was typed - raised as ValueError in words when it does
    not read (a bracket never closed...)."""
    try:
        lq = E.ListQuery('certs', text)
    except E.ListQueryError as e:
        raise ValueError(str(e))
    parts, args = [], []
    if lq.sql:
        parts.append(lq.sql)
        args += list(lq.args)
    if lq.words:
        w = lq._word(lq.words)
        parts.append(w[0])
        args += list(w[1])
    return (' AND '.join('(%s)' % p for p in parts), args) if parts else ('', [])


def values(h, field, typed):
    if field not in OFFERED or field not in FIELDS:
        return []
    from acmelib.certs import teams as T
    s = h.me('readonly')
    col, kind = FIELDS[field]
    if kind == 'ok':
        return [{'val': v, 'n': 0} for v in ('yes', 'no') if v.startswith(typed.lower())]
    sw, sa = T.where(h.store, s, 'view')
    rows = h.store.db.rows('SELECT %s AS v FROM certs WHERE 1=1%s' % (col, sw), tuple(sa))
    got = collections.Counter()
    want = str(typed or '').strip('*').lower()
    for r in rows:
        v = r.get('v')
        items = []
        if kind == 'list':
            try:
                items = [str(x) for x in (json.loads(v) if v else []) or []]
            except (TypeError, ValueError):
                items = []
        elif v not in (None, ''):
            items = [str(v)]
        for one in items:
            if one and (not want or want in one.lower()):
                got[one] += 1
    out = [{'val': v, 'n': n} for v, n in got.items()]
    out.sort(key=lambda x: (not x['val'].lower().startswith(want), -x['n'], x['val'].lower()))
    return out[:15]


register()
