# -*- coding: utf-8 -*-
"""
The page Modules (1.0.32): every module there is - shipped, your own on the disk
of a node, uploaded on the page - with its versions, where it comes from and what
uses it; the source of any of them to download (a start for one of your own),
an upload checked before it is kept, an uploaded one taken away.

    GET  /api/modules                      the list (plugins_view + uploads + usage)
    GET  /api/modules/source?family=&kind=&version=   {file, text} of a loaded module
         &copy=1&as_version=&as_label=[&override=1]  its whole source as a file of your own
         &original=1   the shipped code an override of yours replaces
    GET  /api/modules/uploaded?path=        {file, text} of an uploaded file
    POST /api/modules/analyse  {family, filename, text}   what it would add or replace
    POST /api/modules/install  {family, filename, text, note}
    POST /api/modules/remove   {path}
    POST /api/modules/default  {family, kind, version | null}  the default version chosen

An upload is Python run by acme: a full administrator's alone, written to the
events, checked in a process of its own first (it must load and hold a module of
that family). It is kept in the database - every copy, the other node of a
cluster - and each node writes it into its own folder (custom_modules.py).
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import custom_modules as CM
from acmelib.certs import store as S

FAMILY_WORDS = {'issuer': 'source', 'challenge': 'validation', 'target': 'target',
                'check': 'test'}


def usage(store):
    """{family: {kind: {version used: count}}} of the saved sources, validations, targets."""
    out = {}
    for fam, table in S.TABLE_OF.items():
        if fam not in FAMILY_WORDS:
            continue
        got = out.setdefault(fam, {})
        for r in store.db.rows('SELECT id, kind, config FROM %s' % table):
            cls = S.row_class(fam, r)
            ver = (cls.module_version or '') if cls else (S.version_of(r) or '')
            k = got.setdefault(r['kind'], {})
            k[ver] = k.get(ver, 0) + 1
    return out


def unversioned(store):
    """{family: {kind: how many name no version}} - they follow the default one."""
    out = {}
    for fam, table in S.TABLE_OF.items():
        if fam not in FAMILY_WORDS:
            continue
        got = out.setdefault(fam, {})
        for r in store.db.rows('SELECT kind, config FROM %s' % table):
            if S.version_of(r) is None:
                got[r['kind']] = got.get(r['kind'], 0) + 1
    return out


@A.api('GET', '/api/modules', 'certadmin')
def _modules(h, s):
    d = A.plugins_view(h.store)
    d['uploaded'] = CM.uploaded(h.store)
    d['usage'] = usage(h.store)
    d['unversioned'] = unversioned(h.store)
    d['dirs'] = {'disk': CM.plugins_dir(), 'uploaded': CM.uploaded_dir()}
    d['may_upload'] = A.may(s, 'fulladmin')
    d['marks'] = CM.marks(h.store)
    d['released'] = CM.released()
    return d


@A.api('POST', '/api/modules/mark', 'fulladmin')
def _mark(h, s):
    """{family, kind, version, state: tested | works | problem | '' (taken away), note}"""
    b = h.body()
    fam = str(b.get('family') or '').strip()
    if fam not in FAMILY_WORDS:
        raise ValueError('family is issuer, challenge, target or check')
    kind = str(b.get('kind') or '').strip()
    ver = str(b.get('version') or '')
    state = str(b.get('state') or '').strip()
    by = A.who(s)
    got = CM.set_mark(h.store, fam, kind, ver, state, b.get('note') or '', by)
    h.store.add_event('certificates', 'module %s%s marked %s by %s' % (
        kind, (' ' + ver) if ver else '', state or 'with nothing', by), who=by)
    return {'ok': True, 'mark': got, 'message': 'marked' if got else 'the mark is taken away'}


@A.api('GET', '/api/modules/source', 'fulladmin')
def _source(h, s):
    fam = h.arg('family').strip()
    if fam not in FAMILY_WORDS:
        raise ValueError('family is issuer, challenge, target or check')
    ver = h.arg('version')
    ver = ver if ver is not None and h.arg('has_version') == '1' else None
    if h.arg('copy') == '1':
        # the whole of it, made into a version (or an override) of your own (1.0.34)
        name, text = CM.copy_as(fam, h.arg('kind').strip(), ver, h.arg('as_version'),
                                h.arg('as_label'), h.arg('override') == '1',
                                h.arg('original') == '1')
    else:
        name, text = CM.source_of(fam, h.arg('kind').strip(), ver, h.arg('original') == '1')
    return {'file': name, 'text': text}


@A.api('GET', '/api/modules/uploaded', 'fulladmin')
def _uploaded(h, s):
    import base64
    rel = h.arg('path').strip()
    got = CM.uploaded(h.store, text=True).get(rel)
    if not got:
        raise LookupError('there is no uploaded module %s' % rel)
    return {'file': rel.split('/')[-1],
            'text': base64.b64decode(got['text']).decode('utf-8', 'replace')}


def _body(b):
    fam = str(b.get('family') or '').strip()
    name = str(b.get('filename') or '').strip()
    text = b.get('text')
    if not isinstance(text, str):
        raise ValueError('text: the file\'s text')
    return fam, name, text


@A.api('POST', '/api/modules/analyse', 'fulladmin')
def _analyse(h, s):
    fam, name, text = _body(h.body())
    got = CM.analyse(fam, name, text)
    rel = '%s/%s' % (CM.FOLDER_OF.get(fam, '?'), name)
    got['replaces_upload'] = rel in CM.uploaded(h.store)
    got['on_disk'] = rel in CM.inventory(text=False)
    return got


@A.api('POST', '/api/modules/install', 'fulladmin')
def _install(h, s):
    b = h.body()
    fam, name, text = _body(b)
    by = A.who(s)
    got = CM.install(h.store, fam, name, text, by, b.get('note') or '')
    words = ', '.join('%s %s%s' % (c['does'], c['kind'], (' ' + c['version'])
                                   if c['version'] else '') for c in got['classes'])
    h.store.add_event('certificates', 'module %s uploaded by %s (%s)' % (
        got['path'], by, words), who=by)
    return {'ok': True, 'path': got['path'], 'classes': got['classes'],
            'message': 'the module %s is loaded' % got['path']}


@A.api('POST', '/api/modules/remove', 'fulladmin')
def _remove(h, s):
    rel = str(h.body().get('path') or '').strip()
    by = A.who(s)
    CM.remove(h.store, rel, by)
    h.store.add_event('certificates', 'uploaded module %s taken away by %s' % (rel, by), who=by)
    return {'ok': True, 'message': 'the module %s is taken away' % rel}


@A.api('POST', '/api/modules/default', 'fulladmin')
def _default(h, s):
    """The default version of a module (1.0.34): what a source, validation, target or
    test that names none uses - kept in the database, over default_version in the code.
    version null: as the code says again."""
    b = h.body()
    fam = str(b.get('family') or '')
    kind = str(b.get('kind') or '').strip()
    ver = b.get('version')
    got = CM.set_default(h.store, fam, kind, None if ver is None else str(ver), A.who(s))
    return {'ok': True, 'default': got, 'using_default': CM.using_default(h.store, fam, kind),
            'message': 'the default version of %s is %s' % (kind, got or 'plain')}


# ---- the setup guides of the modules (1.0.94, acmelib/certs/guides.py) ------------------
@A.api('GET', '/api/modules/guide', 'readonly')
def _guide(h, s):
    """The guide of one version of a module, as it is shown - read by anybody signed in (it is
    help, no secret); `default=1`: the one it has without what was written on the page."""
    from acmelib.certs import guides as G
    args = (h.arg('family'), h.arg('kind'), h.arg('version'), h.arg('lang') or 'en')
    if h.arg('default'):
        return G.default_of(*args)
    got = G.guide(h.store, *args)
    got['may'] = s.get('role') == 'fulladmin'
    return got


@A.api('POST', '/api/modules/guide', 'fulladmin')
def _guide_save(h, s):
    """A guide written over on the page Modules; md empty or null: given back."""
    from acmelib.certs import guides as G
    b = h.body()
    got = G.save(h.store, b.get('family'), b.get('kind'), b.get('version'), b.get('lang') or 'en',
                 b.get('md'), A.who(s))
    return {'ok': True, 'written': bool(got),
            'message': 'the guide is kept' if got else 'the guide is the module\'s own again'}


@A.api('GET', '/api/modules/guides', 'certadmin')
def _guides_written(h, s):
    from acmelib.certs import guides as G
    return {'rows': G.written(h.store)}
