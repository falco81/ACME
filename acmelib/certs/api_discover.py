# -*- coding: utf-8 -*-
"""
Discovery - "Find the settings from the account" (1.0.29). A popup of the module's
form asks only what signing in takes (the module's discover_keys_of()); the module
asks its server for the rest (Plugin.discover_setup(): its lists, a DNS module's
zones, what a module of its own finds - an SSLmarket order's owner and contact) and
the form is offered it: ticked values, choices. Nothing is saved here - the form
takes what was ticked, Save keeps it - and every field stays settable by hand.

    POST /api/sources/discover       {id | (kind), name, config}
    POST /api/validations/discover   the same for a validation
    POST /api/targets/discover       the same for a target
    -> {ok, said, job_id, found: {sets, choices, facts, notes}}

Read-only, as Try it and the lists (api_catalog): the module only reads, the
settings given are used over the saved ones, a secret left empty or as its dots is
the one kept - and only a full administrator tries settings that are not saved with
the secrets kept (api.kept_secrets_guard). What it does is a job of the kind
"test", its steps written down.
"""
from __future__ import annotations

from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.plugins.base import PluginError
from acmelib import engine as E

PATHS = {'issuer': 'sources', 'challenge': 'validations', 'target': 'targets'}
WORDS = {'issuer': 'source', 'challenge': 'validation', 'target': 'target'}


def _clean(cls, got):
    """The module's answer as the page takes it: only its own fields, values as text,
    numbers or yes/no, lists of text."""
    keys = {f.get('key'): f for f in cls.fields or [] if f.get('key')}
    secrets_ = S.secret_fields(cls)

    def val(v):
        if isinstance(v, bool) or isinstance(v, (int, float)):
            return v
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x not in (None, '')]
        return '' if v is None else str(v)
    sets = {}
    for k, v in (got.get('sets') or {}).items():
        if k in keys and k not in secrets_ and v not in (None, ''):
            sets[k] = val(v)
    choices = {}
    for k, c in (got.get('choices') or {}).items():
        if k not in keys or k in secrets_ or not isinstance(c, dict):
            continue
        opts = [[str(o[0]), str(o[1] if len(o) > 1 else o[0])] for o in c.get('options') or []
                if isinstance(o, (list, tuple)) and o]
        if not opts:
            continue
        osets = {}
        for ov, more in (c.get('sets') or {}).items():
            if isinstance(more, dict):
                osets[str(ov)] = {mk: val(mv) for mk, mv in more.items()
                                  if mk in keys and mk not in secrets_}
        choices[k] = {'options': opts[:1000], 'pick': str(c.get('pick') or ''), 'sets': osets}
        sets.pop(k, None)
    facts = [[str(f[0]), str(f[1])] for f in got.get('facts') or []
             if isinstance(f, (list, tuple)) and len(f) > 1]
    notes = [str(n) for n in got.get('notes') or [] if n]
    return {'sets': sets, 'choices': choices, 'facts': facts[:40], 'notes': notes[:40]}


def discover(store, family, b, by):
    from acmelib.certs import jobs, runtime
    row = S.plugin_row(store, family, A._id(b['id'])) if b.get('id') not in (None, '', 0) \
        else None
    if b.get('id') not in (None, '', 0) and not row:
        raise LookupError('there is no such %s' % WORDS[family])
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.plugin_class(family, kind)
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (WORDS[family], kind))
    if not cls.discover_offered():
        raise ValueError('%s finds no settings by itself - set them by hand' % (
            cls.title or kind))
    cfg = S.plugin_config(family, row) if row and row.get('kind') == kind else {}
    for k, v in (A._dict(b.get('config'), 'config') or {}).items():
        if k in S.secret_fields(cls) and (v in (None, '') or E.is_masked(v)):
            continue                # "" or the dots shown: the one kept
        cfg[k] = v
    name = (row or {}).get('name') or str(b.get('name') or 'unsaved')
    out = {}

    def fn(job):
        ctx = runtime.RunContext(store, job, scope='%s:%s' % (family, name))
        try:
            job.step('what the account says of the settings - read-only, nothing is saved')
            mod = cls(cfg, ctx)
            got = mod.discover_setup() or {}
            found = _clean(cls, got)
            tried = ''
            try:
                tried = mod.test() or ''
            except PluginError as e:
                if not (found['sets'] or found['choices']):
                    raise
                found['notes'].append('Try it: %s' % e)
            except NotImplementedError:
                pass
            out['found'] = found
            for n in found['notes']:
                job.step(n, 'warn')
            n = len(found['sets']) + len(found['choices'])
            if not n:
                words = 'the account told nothing to fill in%s' % (
                    (' - ' + str(tried)) if tried else '')
                job.step(words, 'warn')
                return True, words
            words = '%d setting(s) found' % n + ((' - ' + str(tried)) if tried else '')
            job.step(words, 'ok')
            return True, words
        except PluginError as e:
            job.step(str(e), 'bad')
            return False, '%s - every field can be set by hand' % e
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'test', fn, by=by,
                       said='%s %s: find the settings from the account' % (WORDS[family], name))
    return {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id,
            'found': out.get('found') or {'sets': {}, 'choices': {}, 'facts': [],
                                          'notes': []}}


def _route(family, path):
    @A.api('POST', '/api/%s/discover' % path, 'certadmin')
    def _discover(h, s):
        b = h.body()
        A.kept_secrets_guard(h.store, family, b, s)
        return discover(h.store, family, b, A.who(s))
    return _discover


for _fam, _path in PATHS.items():
    _route(_fam, _path)
