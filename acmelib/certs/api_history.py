# -*- coding: utf-8 -*-
"""
The routes of the trash, the history of an object and the saved views (1.0.138,
acmelib/certs/history.py, docs/history-and-trash.md). Relayed by the pages as
history, history/restore, trash, trash/restore, views, views/save...

    GET  /api/history            ?type=target&id=5 (or &name=web1): one object's history;
                                 ?feed=1[&type&who&since&q&offset]: the latest changes
    POST /api/history/preview    {entry}: what restoring that version would change
    POST /api/history/restore    {entry, secrets}: that version saved again by its own route
    GET  /api/trash              [?type&who&since&q]: what is in the trash (certadmin)
    POST /api/trash/preview      {id}: what comes back, what it needs, a name taken since
    POST /api/trash/restore      {id, name?, with_needs?}: brought back by its own route
    POST /api/trash/purge        {ids: [...]} | {all: true}: gone for good (fulladmin)
    GET  /api/views              ?table=KEY: the views of a table this person sees
    POST /api/views/save         {id?, table, name, scope user|team|global, team, state, default}
    POST /api/views/delete       {id}
    POST /api/views/default      {table, id | null}
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import history as H


def _num(v, what='id'):
    if isinstance(v, bool):
        raise ValueError('%s is a number' % what)
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a number' % what)
    if n <= 0:
        raise ValueError('%s is a number' % what)
    return n


def _since(v):
    if v in (None, ''):
        return 0
    try:
        return max(0.0, float(v))
    except (TypeError, ValueError):
        raise ValueError('since is a time (seconds)')


@A.api('GET', '/api/history')
def _history(h, s):
    H.install()
    if h.arg('feed'):
        return H.feed(h.store, s, otype=str(h.arg('type') or ''), who=str(h.arg('who') or ''),
                      since=_since(h.arg('since')), q=str(h.arg('q') or '')[:200],
                      limit=h.num('limit', 100, 1, 500), offset=h.num('offset', 0, 0, 100000))
    otype = str(h.arg('type') or '')
    if otype not in H.TABLE_OF_TYPE or otype in H.NO_HISTORY:
        raise ValueError('type is one of %s' % ', '.join(
            sorted(t for t in H.TABLE_OF_TYPE if t not in H.NO_HISTORY)))
    oid = h.arg('id')
    name = str(h.arg('name') or '')[:200]
    if oid in (None, '') and not name:
        raise ValueError('which one: id or name')
    return H.history(h.store, s, otype, oid=_num(oid) if oid not in (None, '') else None,
                     name=name or None)


@A.api('POST', '/api/history/preview')
def _history_preview(h, s):
    return H.preview_version(h.store, s, _num(h.body().get('entry'), 'entry'))


@A.api('POST', '/api/history/restore', 'certadmin')
def _history_restore(h, s):
    b = h.body()
    return H.restore_version(h.store, h, s, _num(b.get('entry'), 'entry'),
                             secrets=A._flag(b.get('secrets'), 0))


@A.api('GET', '/api/trash', 'certadmin')
def _trash(h, s):
    return H.trash_list(h.store, s, otype=str(h.arg('type') or '')[:40],
                        who=str(h.arg('who') or '')[:190], since=_since(h.arg('since')),
                        q=str(h.arg('q') or '')[:200])


@A.api('POST', '/api/trash/preview', 'certadmin')
def _trash_preview(h, s):
    return H.trash_preview(h.store, s, _num(h.body().get('id')))


@A.api('POST', '/api/trash/restore', 'certadmin')
def _trash_restore(h, s):
    b = h.body()
    name = b.get('name')
    if name is not None and not isinstance(name, str):
        raise ValueError('name is a piece of text')
    return H.trash_restore(h.store, h, s, _num(b.get('id')), name=name,
                           with_needs=A._flag(b.get('with_needs'), 0))


@A.api('POST', '/api/trash/purge', 'fulladmin')
def _trash_purge(h, s):
    b = h.body()
    if A._flag(b.get('all'), 0):
        return H.trash_purge(h.store, s, everything=True)
    ids = b.get('ids') if isinstance(b.get('ids'), list) else [b.get('id')]
    if not ids or ids == [None]:
        raise ValueError('which: ids')
    return H.trash_purge(h.store, s, ids=[_num(i) for i in ids[:1000]])


@A.api('GET', '/api/views')
def _views(h, s):
    return H.views(h.store, s, h.arg('table'))


@A.api('POST', '/api/views/save')
def _views_save(h, s):
    return H.view_save(h.store, s, h.body())


@A.api('POST', '/api/views/delete')
def _views_delete(h, s):
    return H.view_delete(h.store, s, _num(h.body().get('id')))


@A.api('POST', '/api/views/default')
def _views_default(h, s):
    b = h.body()
    return H.view_default(h.store, s, b.get('table'), b.get('id'))

