# -*- coding: utf-8 -*-
"""
Setup guides of the modules (1.0.94): for every source, validation, target and test -
each version of it - a Markdown text saying how to set up the other side (the device, the
service, the DNS provider, the CA) for acme: its account and least rights, the commands,
what goes into acme's fields. Shown read-only in a popup by the module's forms and windows;
written over on the page Modules (a Markdown editor), and given back.

Where a guide comes from, the first that has one (each for the language asked, then
English):

  1. written on the page Modules - kept in the database (meta guide:<family>:<kind>@<version>
     :<lang>), so on both nodes of a cluster and in every backup;
  2. the module itself - a module of your own (or an override) may carry `guide` /
     `guide_cs` (Markdown in the class), or a file beside its .py: <name>.md / <name>.cs.md;
  3. shipped with acme: acmelib/plugins/guides/<folder>/<kind>@<version>[.cs].md, then the
     same without the version (one guide for every version that has the same steps);
  4. made from the module: its title, description and fields - so none is without one.

    GET  /api/modules/guide?family=&kind=&version=&lang=   {md, origin, ...}
    POST /api/modules/guide  {family, kind, version, lang, md}   written over (md '' or
                             null: given back to the module's own)
"""
from __future__ import annotations

import json
import os
import re
import time

from acmelib.plugins import base

LANGS = ('en', 'cs')
MAX_MD = 300000
HERE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'plugins', 'guides')


def _check(family, kind, version, lang):
    if family not in base.FAMILIES:
        raise ValueError('there is no family of modules called %s' % family)
    kind = str(kind or '').strip()
    if not re.match(r'^[a-z0-9_]{1,64}\Z', kind):
        raise ValueError('that is no module')
    version = str(version or '').strip()
    if version and not re.match(r'^[A-Za-z0-9_.+-]{1,40}\Z', version):
        raise ValueError('that is no version of a module')
    lang = str(lang or 'en').strip().lower()
    if lang not in LANGS:
        lang = 'en'
    return family, kind, version, lang


def meta_key(family, kind, version, lang):
    return 'guide:%s:%s@%s:%s' % (family, kind, version or '', lang)


def _read(path):
    try:
        with open(path, encoding='utf-8') as f:
            return f.read(MAX_MD)
    except OSError:
        return None


def _class(family, kind, version):
    reg = base.REGISTRY
    if not any(reg.found.values()):
        reg.reload()                    # not read yet (a command, a test)
    vers = reg.versions_of(family, kind) or {}
    if version in vers:
        return vers[version]
    try:
        return reg.get(family, kind)
    except Exception:                                   # noqa: BLE001
        return None


def _from_module(cls, lang):
    """A guide the module carries: in its class, or a file beside its .py."""
    if cls is None:
        return None
    attr = 'guide_cs' if lang == 'cs' else 'guide'
    text = cls.__dict__.get(attr)
    if isinstance(text, str) and text.strip():
        return text
    path = getattr(cls, '_module_file', '') or ''
    if path and getattr(cls, '_origin', 'builtin') != 'builtin':
        stem = os.path.splitext(path)[0]
        for p in ([stem + '.cs.md'] if lang == 'cs' else []) + ([] if lang == 'cs' else
                                                                 [stem + '.md']):
            got = _read(p)
            if got:
                return got
    return None


def _shipped(family, kind, version, lang):
    folder = base.FOLDERS[family]
    names = []
    suffix = '.cs.md' if lang == 'cs' else '.md'
    if version:
        names.append('%s@%s%s' % (kind, version, suffix))
    names.append('%s%s' % (kind, suffix))
    for n in names:
        got = _read(os.path.join(HERE, folder, n))
        if got:
            return got, n
    return None, None


def _made(cls, family, kind, version, lang):
    """None anywhere: a short one made from the module."""
    d = {}
    try:
        d = cls.describe() if cls is not None else {}
    except Exception:                                   # noqa: BLE001
        d = {}
    title = d.get('title') or kind
    cs = lang == 'cs'
    out = ['# %s%s' % (title, ' - nastavení pro acme' if cs else ' - setup for acme'), '']
    if d.get('description'):
        out += [str(d['description']), '']
    if version:
        out += [('*Verze modulu:* `%s`' if cs else '*Module version:* `%s`') % version, '']
    out += [('Pro tento modul zatím není podrobný návod. Na stránce **Moduly** ho můžete '
             'napsat - uloží se pro všechny.') if cs else
            ('There is no detailed guide for this module yet. On the page **Modules** you can '
             'write one - it is kept for everybody.'), '']
    hidden = ('verify', 'verify_sni', 'verify_tries', 'verify_wait', 'verify_served')
    rows = [f for f in list(d.get('fields') or []) + list(d.get('deploy_fields') or [])
            if isinstance(f, dict) and f.get('key') and f['key'] not in hidden]
    if rows:
        out += ['## %s' % ('Pole v acme' if cs else 'Fields in acme'), '',
                '| %s | %s |' % (('Pole', 'K čemu je') if cs else ('Field', 'What it is')),
                '|---|---|']
        for f in rows[:60]:
            words = str(f.get('help') or '').replace('|', '\\|').replace('\n', ' ')
            out.append('| %s | %s |' % (str(f.get('label') or f['key']).replace('|', '\\|'),
                                        words or '-'))
        out.append('')
    if d.get('doc'):
        out += [('Více v `docs/%s`.' if cs else 'More in `docs/%s`.') % str(d['doc']).replace(
            'docs/', ''), '']
    return '\n'.join(out)


def _acmes_kind(family, kind, cls):
    """A kind acme ships - its guide is shipped too: the module itself, an override of it, or
    a version of your own of a kind acme has (1.0.95: fortigate@7.8 of your own got none)."""
    if cls is None or getattr(cls, '_origin', 'builtin') == 'builtin' or getattr(cls, '_overrides', ''):
        return True
    try:
        vers = base.REGISTRY.versions_of(family, kind) or {}
    except Exception:                                   # noqa: BLE001
        vers = {}
    return any(getattr(c, '_origin', 'builtin') == 'builtin' or getattr(c, '_overrides', '')
               for c in vers.values())


def check_key(k, v):
    """A row from a configuration file: (key, value) as acme writes them, or None."""
    m = re.match(r'^guide:([a-z]+):([a-z0-9_]+)@([A-Za-z0-9_.+-]{0,40}):([a-z]{2})\Z', str(k or ''))
    if not m or m.group(1) not in base.FAMILIES or m.group(4) not in LANGS:
        return None
    try:
        got = json.loads(v) if isinstance(v, str) else None
    except ValueError:
        return None
    if not isinstance(got, dict) or not isinstance(got.get('md'), str) or not got['md'].strip() \
            or len(got['md']) > MAX_MD:
        return None
    keep = {'md': got['md'].replace('\r\n', '\n'), 'at': got.get('at') if isinstance(
        got.get('at'), (int, float)) else time.time(), 'by': str(got.get('by') or '')[:200]}
    return k, json.dumps(keep)


def guide(store, family, kind, version='', lang='en'):
    """The guide to show: {md, origin: written | module | shipped | made, lang, written_at,
    written_by, has_default}."""
    family, kind, version, lang = _check(family, kind, version, lang)
    cls = _class(family, kind, version)
    tries = [lang] if lang == 'en' else [lang, 'en']
    for lg in tries:
        raw = store.get_meta(meta_key(family, kind, version, lg)) if store else None
        if raw:
            try:
                got = json.loads(raw)
            except ValueError:
                got = None
            if isinstance(got, dict) and got.get('md'):
                return {'md': got['md'], 'origin': 'written', 'lang': lg,
                        'written_at': got.get('at'), 'written_by': got.get('by'),
                        'has_default': True, 'family': family, 'kind': kind,
                        'version': version}
        own = _from_module(cls, lg)
        if own:
            return {'md': own, 'origin': 'module', 'lang': lg, 'has_default': True,
                    'family': family, 'kind': kind, 'version': version}
        if _acmes_kind(family, kind, cls):
            text, name = _shipped(family, kind, version, lg)
            if text:
                return {'md': text, 'origin': 'shipped', 'lang': lg, 'file': name,
                        'has_default': True, 'family': family, 'kind': kind,
                        'version': version}
    return {'md': _made(cls, family, kind, version, lang), 'origin': 'made', 'lang': lang,
            'has_default': False, 'family': family, 'kind': kind, 'version': version}


def default_of(family, kind, version='', lang='en'):
    """What it would be without the one written on the page."""
    return guide(None, family, kind, version, lang)


def save(store, family, kind, version, lang, md, by):
    family, kind, version, lang = _check(family, kind, version, lang)
    k = meta_key(family, kind, version, lang)
    md = '' if md is None else str(md)
    if len(md) > MAX_MD:
        raise ValueError('a guide is %d characters at most' % MAX_MD)
    md = md.replace('\r\n', '\n')
    if not md.strip():
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
        store.add_event('settings', '%s gave the setup guide of %s %s%s (%s) back to the '
                        'module\'s own' % (by, family, kind, '@' + version if version else '',
                                           lang), who=by)
        return None
    store.set_meta(k, json.dumps({'md': md, 'at': time.time(), 'by': by}))
    store.add_event('settings', '%s wrote the setup guide of %s %s%s (%s)' % (
        by, family, kind, '@' + version if version else '', lang), who=by)
    return True


def written(store):
    """Every guide written on the page: [{family, kind, version, lang, at, by}]."""
    out = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'guide:%'"):
        m = re.match(r'^guide:([a-z]+):([a-z0-9_]+)@([^:]*):([a-z]+)\Z', r['k'])
        if not m:
            continue
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            v = {}
        out.append({'family': m.group(1), 'kind': m.group(2), 'version': m.group(3),
                    'lang': m.group(4), 'at': v.get('at'), 'by': v.get('by')})
    return out

