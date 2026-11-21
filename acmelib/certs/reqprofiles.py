# -*- coding: utf-8 -*-
"""
Request profiles (Settings → Request profiles, docs/request-profiles.md): what
people may ask for on the portal with everything but the names given
beforehand - the source and the validation, the names allowed, whether acme
makes the key or the person sends a CSR, the subject, renewal, approval, the
owner, the tags and who may use it. A full administrator defines them; with
none, the portal is as it was (the free form of portal_cert_suffixes /
portal_cert_issuers).

    profiles(store) / profile_get / save_profile / delete_profile   the catalog
    options(store)                  what a profile picks from (sources, validations, ...)
    usable(h, s)                    the profiles a portal sign-in may use, as it sees them
    read_csr(b) / csr_review(...)   a CSR decoded and checked against one profile
    request(h, s, b)                a certificate asked for from a profile (portal.py)
    rename_ref(store, kind, old, new)   an owner or a tag renamed: the profiles follow

A certificate asked for with a CSR holds no key: the CSR is kept (certs.csr_given)
and sent again at every renewal; renewer._issue_one uses it.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import schema

SUBJECT_FIELDS = (('O', 'Organisation'), ('OU', 'Unit'), ('L', 'City'), ('ST', 'Region'),
                  ('C', 'Country'), ('emailAddress', 'E-mail'))
SUBJECT_MODES = ('off', 'fixed', 'person')
OWNER_MODES = ('person', 'team', 'fixed')
EKUS = ('serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping',
        'OCSPSigning')
# Sources that sign only a key acme holds: a self-signed certificate is signed by
# its own key, CMP and SCEP sign their messages with it.
NO_CSR_KINDS = ('selfsigned', 'cmp', 'scep')
CSR_MAX = 65536
MAIL_RE = re.compile(r'^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+\Z')
META_PORTAL = 'certs:portal:'


def _low(v):
    return str(v or '').strip().lower()


def _flag(v, default=False):
    if v in (None, ''):
        return bool(default)
    if isinstance(v, str):
        return v.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(v)


def _int(v, what, lo, hi, empty=None):
    if v in (None, '', 0, '0'):
        return empty
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a number' % what)
    if not lo <= n <= hi:
        raise ValueError('%s: %d to %d' % (what, lo, hi))
    return n


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------
def raw_rows(store):
    """The rows as they are kept: `config` the profile's own settings (1.0.138: of a profile
    with a base, only what it overrides, with `base` and `inherit`)."""
    try:
        return store.db.rows('SELECT * FROM cert_req_profiles ORDER BY %s'
                             % store.db.name_order())
    except Exception:                                   # noqa: BLE001
        return store.db.rows('SELECT * FROM cert_req_profiles ORDER BY name')


def rows(store):
    """The rows with `config` as the profile works (1.0.138): what it inherits from its base
    put in (resolve), its own settings kept in `_own`. Without a base: as kept."""
    return resolve(raw_rows(store))


# ---------------------------------------------------------------------------
# A base profile (1.0.138, docs/request-profiles.md "A base profile")
# ---------------------------------------------------------------------------
# What a profile may take from its base, by the groups the editor overrides or inherits:
# a group's keys go together (the source and its validation, the key types and the one
# offered first, whose it is and the team).
INHERIT_GROUPS = (('source', ('issuer', 'challenge')), ('suffixes', ('suffixes',)),
                  ('wildcards', ('wildcards',)), ('max_names', ('max_names',)),
                  ('make_key', ('make_key',)), ('csr', ('csr',)),
                  ('key_types', ('key_types', 'key_default')),
                  ('auto_renew', ('auto_renew',)), ('renew_days', ('renew_days',)),
                  ('days', ('days',)), ('eku', ('eku',)), ('approval', ('approval',)),
                  ('owner', ('owner', 'owner_team')), ('tags', ('tags',)), ('teams', ('teams',)),
                  ('pfx', ('pfx',))) + tuple(('subject.' + k, ()) for k, _w in SUBJECT_FIELDS)
INHERIT_KEYS = dict(INHERIT_GROUPS)
BASE_DEPTH = 8


def own_of(row):
    """A profile's own settings, as kept (`_own` of a row of rows(), else its config)."""
    raw = (row or {}).get('_own') if (row or {}).get('_own') is not None else \
        (row or {}).get('config')
    cfg = S.jload(raw, {}) or {}
    return cfg if isinstance(cfg, dict) else {}


def clean_inherit(v):
    v = v if isinstance(v, (list, tuple)) else []
    return [g for g, _k in INHERIT_GROUPS if g in v]


def merge_base(own, bcfg):
    """A profile's own settings with what it inherits taken from its base's (as it works)."""
    out = dict(own)
    for g in clean_inherit(own.get('inherit')):
        if g.startswith('subject.'):
            f = g[8:]
            subj = dict(out.get('subject') or {})
            subj[f] = dict((bcfg.get('subject') or {}).get(f) or {'mode': 'off', 'value': ''})
            out['subject'] = subj
        else:
            for k in INHERIT_KEYS[g]:
                v = bcfg.get(k)
                out[k] = json.loads(json.dumps(v)) if isinstance(v, (list, dict)) else v
    return out


def resolve(raw):
    """Rows (raw_rows) with `config` as each works, `_own` as kept, `_base_problems`."""
    by = {_low(r['name']): r for r in raw}
    memo = {}

    def eff(r, path):
        key = _low(r['name'])
        if key in memo:
            return memo[key]
        own = own_of(r)
        out, probs = dict(own), []
        b = str(own.get('base') or '').strip()
        if b:
            br = by.get(_low(b))
            if not br:
                probs.append('its base profile %s is gone' % b)
            elif _low(b) in path or _low(b) == key or len(path) > BASE_DEPTH:
                probs.append('its base profiles go round in a circle')
            else:
                bcfg, bp = eff(br, path | {key})
                out = merge_base(own, bcfg)
                probs += [p for p in bp if p not in probs]
        memo[key] = (out, probs)
        return memo[key]

    res = []
    for r in raw:
        cfg, probs = eff(r, frozenset())
        one = dict(r)
        one['_own'] = r.get('config') or '{}'
        one['config'] = json.dumps(cfg)
        one['_base_problems'] = probs
        res.append(one)
    return res


def chain_of(store, name, rws=None):
    """[name, its base, the base's base, ...] (the profile first)."""
    by = {_low(r['name']): r for r in (rws if rws is not None else raw_rows(store))}
    out, r = [], by.get(_low(name))
    while r is not None and len(out) <= BASE_DEPTH and r['name'] not in out:
        out.append(r['name'])
        r = by.get(_low(own_of(r).get('base')))
    return out


def children_of(store, name, rws=None, deep=False):
    """The profiles whose base is this one (deep: theirs too)."""
    rws = rws if rws is not None else raw_rows(store)
    out = []
    want = {_low(name)}
    while want:
        got = [r['name'] for r in rws if _low(own_of(r).get('base')) in want
               and r['name'] not in out and _low(r['name']) != _low(name)]
        out += got
        want = {_low(x) for x in got} if deep else set()
    return out


def profile_get(store, name):
    n = _low(name)
    if not n:
        return None
    for r in rows(store):
        if _low(r['name']) == n:
            return r
    return None


def config_of(row):
    cfg = S.jload((row or {}).get('config'), {}) or {}
    return cfg if isinstance(cfg, dict) else {}


def issuer_info(store, name):
    """(row, class, compat.source_info) of a source - Nones when there is none."""
    from acmelib.certs import compat
    irow = S.plugin_row(store, 'issuer', name) if name else None
    if not irow:
        return None, None, None
    cls = S.row_class('issuer', irow)
    if cls is None:
        return irow, None, None
    return irow, cls, compat.source_info(cls, S.jload(irow.get('config'), {}) or {},
                                         irow.get('kind'))


def csr_ok(irow, cls):
    return bool(irow and cls is not None and irow.get('kind') not in NO_CSR_KINDS
                and not getattr(cls, 'makes_key', False))


def clean_subject(v):
    v = v if isinstance(v, dict) else {}
    out = {}
    for k, _w in SUBJECT_FIELDS:
        one = v.get(k) if isinstance(v.get(k), dict) else {'mode': 'off'}
        mode = str(one.get('mode') or 'off')
        if mode not in SUBJECT_MODES:
            raise ValueError('a subject field is off, fixed or person, not %r' % mode)
        value = str(one.get('value') or '').strip()
        if value:
            value = check_value(k, value) or value     # as it is written (C upper) - 1.0.52
        if mode == 'fixed' and not value:
            raise ValueError('the subject field %s is fixed by the profile: give its value' % k)
        out[k] = {'mode': mode, 'value': value if mode != 'off' else ''}
    return out


# The longest value of a subject field (RFC 5280's upper bounds, 1.0.101): L and ST 128, the
# e-mail 255, the others (CN, O, OU, ...) 64 - L and ST of 65 to 128 renewed and were refused
SUBJECT_MAX = {'L': 128, 'ST': 128, 'emailAddress': 255}
# an e-mail in the subject: local@domain without spaces (a domain without a dot, pki@corp,
# is one inside a company)
SUBJECT_MAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\Z')


def check_value(k, value):
    most = SUBJECT_MAX.get(k, 64)
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or len(value) > most:
        raise ValueError('%s: %d characters at most, no control characters' % (k, most))
    if k == 'C' and not re.match(r'^[A-Za-z]{2}\Z', value):
        raise ValueError('the country (C) is two letters (CZ, SK, DE…)')
    if k == 'emailAddress' and not SUBJECT_MAIL_RE.match(value):
        raise ValueError('\u201c%s\u201d is not a mail address' % str(value)[:120])
    return value.upper() if k == 'C' else value


def check_subject(subj, where='profile.subject'):
    """A certificate's own subject ({C: .., O: .., OU: [..]}) checked as a request profile's
    fields are and as pki.py writes it into a CSR (hunt M): saved with C "Czech Republic" or
    an e-mail that is none, it was taken, What happens drew a CSR with it, and every renewal
    failed. The same dict back, C in capitals."""
    from acmelib.certs import pki
    if not subj:
        return {}
    if not isinstance(subj, dict):
        raise ValueError('%s is {field: value}' % where)
    known = dict(SUBJECT_FIELDS)
    out = {}
    for k, v in subj.items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        if len(vals) > 20:
            raise ValueError('%s: %s has 20 values at most' % (where, k))
        good = []
        for one in vals:
            if one in (None, ''):
                continue
            if isinstance(one, bool) or not isinstance(one, (str, int, float)):
                raise ValueError('%s: %s is words, not %s' % (where, k, type(one).__name__))
            one = str(one).strip()
            if not one:
                continue
            key = pki._SUBJECT_ALIAS.get(str(k).strip().lower().replace(' ', ''), str(k).strip())
            if key in known:
                try:
                    one = check_value(key, one)
                except ValueError as e:
                    # the field it is about (hunt M round 3): the wizard marks it on its
                    # profile step, not only a toast at the last one
                    e.field = 'subject.' + key
                    raise
            elif any(ord(c) < 32 for c in one) or len(one) > 128:
                raise ValueError('%s: 128 characters at most, no control characters' % k)
            good.append(one)
        if good:
            out[k] = good if isinstance(v, (list, tuple)) else good[0]
    try:
        pki.subject_pairs(out)
    except pki.PkiError as e:
        raise ValueError('%s: %s' % (where, e))
    return out


def clean_suffixes(v):
    if isinstance(v, str):
        v = re.split(r'[\s,;]+', v)
    out = []
    for w in v or []:
        w = str(w).strip().lower().rstrip('.').lstrip('*').lstrip('.')
        if not w:
            continue
        try:
            w = S.clean_names([w])[0]
        except (ValueError, IndexError):
            raise ValueError('%r is not a domain' % w)
        if w not in out:
            out.append(w)
    return out[:50]


def save_profile(store, b, by, why='', keep_ends=True):
    """A profile added or changed, every value checked against its catalog. With `base`
    (1.0.138): what `inherit` names is taken from that profile, the rest is its own; the
    profiles based on this one are checked as they will be. Every save is a new version
    (reqprofiles_more.py); `why` says what made it (a restore)."""
    from acmelib.certs import reqprofiles_more as RM
    old = profile_get(store, b.get('old_name')) if b.get('old_name') else None
    if b.get('old_name') and not old:
        raise LookupError('there is no request profile %s' % b.get('old_name'))
    name = S.clean_name(b.get('name'), 'the profile\'s name')
    other = profile_get(store, name)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is a request profile called %s already' % other['name'])
    raw = raw_rows(store)
    base_name = str(b.get('base') or '').strip()
    inherit = clean_inherit(b.get('inherit')) if base_name else []
    base = None
    body = dict(b)
    if base_name:
        base = profile_get(store, base_name)
        if not base:
            raise ValueError('there is no request profile %s to base it on' % base_name)
        if _low(base['name']) == _low(name) or (old and base['id'] == old['id']):
            raise ValueError('a profile is not its own base')
        if old and old['name'] in chain_of(store, base['name'], raw):
            raise ValueError('%s is based on %s already - the bases would go round in a circle'
                             % (base['name'], old['name']))
        if len(chain_of(store, base['name'], raw)) >= BASE_DEPTH:
            raise ValueError('%d bases one on another at most' % BASE_DEPTH)
        body = merge_base(dict(b, inherit=inherit), config_of(base))
    cfg = build_cfg(store, body)
    own = dict(cfg)
    if base:
        for g in inherit:
            if g.startswith('subject.'):
                own['subject'] = {k: v for k, v in (own.get('subject') or {}).items()
                                  if k != g[8:]}
            else:
                for k in INHERIT_KEYS[g]:
                    own.pop(k, None)
        own['base'] = base['name']
        own['inherit'] = inherit
    if old and keep_ends and own_of(old).get('ends'):
        own['ends'] = own_of(old)['ends']        # marked as ending: kept as it is (P5)
    if 'ends' in b and not keep_ends:
        if b.get('ends'):
            own['ends'] = b['ends']
        else:
            own.pop('ends', None)
    desc = str(b.get('description') or '').strip()[:2000]
    row = {'name': name, 'description': desc, 'enabled': 1 if _flag(b.get('enabled'), True) else 0,
           'config': json.dumps(own), 'updated': time.time(), 'updated_by': str(by)[:190]}
    if old:
        # The profiles based on this one, as they will be (1.0.138): one that would no longer
        # fit together refuses the change of its base, in its words.
        sim = [dict(r, **row) if r['id'] == old['id'] else r for r in raw]
        if old['name'] != name:
            # renamed too: the profiles based on it as they will be (RM.renamed below)
            sim = [dict(r, config=json.dumps(dict(own_of(r), base=name)))
                   if _low(own_of(r).get('base')) == _low(old['name']) else r for r in sim]
        for r in resolve(sim):
            if r['id'] == old['id'] or not any(_low(x) == _low(name) for x in
                                               chain_of(store, r['name'], sim)[1:]):
                continue
            try:
                build_cfg(store, dict(config_of(r)))
            except (ValueError, LookupError, E.ApiError) as e:
                raise ValueError('the profile %s is based on it and would not fit: %s'
                                 % (r['name'], getattr(e, 'message', None) or str(e)))
    before = dict(old) if old else None
    if old:
        store.db.update('cert_req_profiles', old['id'], row)
        if old['name'] != name:
            asked_follow(store, old['name'], name)
            RM.renamed(store, old['name'], name)
        store.add_event('certificates', 'the request profile %s changed by %s%s' % (
            name, by, (' (was %s)' % old['name']) if old['name'] != name else ''), who=by)
    else:
        row.update(created=time.time(), created_by=str(by)[:190])
        store.db.insert('cert_req_profiles', row)
        store.add_event('certificates', 'the request profile %s added by %s' % (name, by), who=by)
    RM.record(store, before, name, by, why)
    return public(store, profile_get(store, name))


def build_cfg(store, b):
    """The settings of a profile out of what was sent, every value checked against its
    catalog and what fits together (compat.py) - ValueError / ApiError when not."""
    from acmelib.certs import compat
    from acmelib.certs import teams as T
    irow, icls, info = issuer_info(store, str(b.get('issuer') or '').strip())
    if not irow:
        raise ValueError('choose the source (Certificates → Sources)')
    if icls is None:
        raise ValueError('the module %s of the source %s is missing' % (irow.get('kind'),
                                                                          irow['name']))
    cfg = {'issuer': irow['name'], 'challenge': ''}
    if info['needs_validation']:
        crow = S.plugin_row(store, 'challenge', str(b.get('challenge') or '').strip())
        if not crow:
            raise ValueError('%s proves names: choose how (Certificates → Validation)'
                             % irow['name'])
        cfg['challenge'] = crow['name']
    cfg['suffixes'] = clean_suffixes(b.get('suffixes'))
    if not cfg['suffixes']:
        raise ValueError('say under which domains names may be asked for')
    cfg['wildcards'] = _flag(b.get('wildcards'))
    if cfg['wildcards'] and not info['wildcards']:
        raise ValueError('%s gives no wildcard certificates' % irow['name'])
    cfg['max_names'] = _int(b.get('max_names'), 'names in one certificate', 1, 50, 1) or 1
    cfg['make_key'] = _flag(b.get('make_key'), True)
    cfg['csr'] = _flag(b.get('csr'))
    if not cfg['make_key'] and not cfg['csr']:
        raise ValueError('either acme makes the key, or the person sends a CSR - or both')
    if cfg['csr'] and not csr_ok(irow, icls):
        raise ValueError('%s signs only a key acme makes and holds - switch the CSR off, or '
                         'choose another source' % irow['name'])
    kts = [k for k in (b.get('key_types') or []) if k in schema.KEY_TYPES]
    if not kts:
        raise ValueError('choose at least one key type')
    bad = [k for k in kts if k not in info['key_types']]
    if bad:
        raise ValueError('%s does not sign %s keys' % (irow['name'], ', '.join(
            compat.KEY_WORDS.get(k, k) for k in bad)))
    cfg['key_types'] = [k for k in schema.KEY_TYPES if k in kts]
    kd = str(b.get('key_default') or cfg['key_types'][0])
    cfg['key_default'] = kd if kd in cfg['key_types'] else cfg['key_types'][0]
    cfg['subject'] = clean_subject(b.get('subject'))
    cfg['auto_renew'] = _flag(b.get('auto_renew'), True)
    cfg['renew_days'] = _int(b.get('renew_days'), 'days before the end', 1, 3650)
    cfg['days'] = _int(b.get('days'), 'the validity', 1, 36500) \
        if getattr(icls, 'choose_days', False) else None
    eku = b.get('eku') or []
    if isinstance(eku, str):
        eku = [w for w in re.split(r'[\s,;]+', eku) if w]
    for e in eku:
        if e not in EKUS:
            raise ValueError('an extended key usage is one of %s' % ', '.join(EKUS))
    cfg['eku'] = [e for e in EKUS if e in eku]
    cfg['approval'] = _flag(b.get('approval'))
    mode = str(b.get('owner') or 'person')
    if mode not in OWNER_MODES:
        raise ValueError('the owner is the person, a team they pick, or a team of the profile')
    cfg['owner'] = mode
    cfg['owner_team'] = ''
    if mode == 'fixed':
        t = T.team_get(store, b.get('owner_team'))
        if not t:
            raise ValueError('choose the team that owns what is asked for (Owners and teams)')
        cfg['owner_team'] = t['name']
    tags = []
    for x in b.get('tags') or []:
        t = T.tag_get(store, x)
        if not t:
            raise ValueError('there is no tag %s (Owners and teams)' % x)
        if t['name'] not in tags:
            tags.append(t['name'])
    cfg['tags'] = tags[:20]
    who = []
    for x in b.get('teams') or []:
        t = T.team_get(store, x)
        if not t:
            raise ValueError('there is no owner or team %s (Owners and teams)' % x)
        if t['name'] not in who:
            who.append(t['name'])
    cfg['teams'] = who
    cfg['pfx'] = _flag(b.get('pfx')) and cfg['make_key']
    # What fits (compat.py): a name under each domain, a wildcard, every key type.
    samples = ['www.' + cfg['suffixes'][0]] + (['*.' + cfg['suffixes'][0]]
                                              if cfg['wildcards'] else [])
    probs = []
    for k in cfg['key_types']:
        for p in compat.check(store, samples, irow, cfg['challenge'] or None, {}, k, '',
                              profile={'subject': fixed_subject(cfg)}):
            if p not in probs:
                probs.append(p)
    if probs:
        raise E.ApiError(400, 'it does not fit together: %s' % compat.words(probs),
                         detail=json.dumps(probs)[:20000])
    return cfg


def asked_follow(store, old, new):
    """A profile renamed (1.0.19): what was asked for from it says its new name - it
    counted no more, and a new CSR for one of them was no longer checked against it."""
    # the teams' limits naming it follow too (hunt Rt1)
    from acmelib.certs import teams as T
    T.policy_rename(store, 'profiles', old, new)
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (META_PORTAL + '%',)):
        try:
            got = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(got, dict) and got.get('profile') and _low(got['profile']) == _low(old):
            got['profile'] = new
            store.set_meta(r['k'], json.dumps(got))


def delete_profile(store, name, by, detach=False):
    """A profile deleted. The base of others (1.0.138): refused - unless `detach`, when each of
    them takes what it inherited as its own first (a new version of it) and stands alone. The
    successor of a profile that ends: refused."""
    from acmelib.certs import reqprofiles_more as RM
    r = profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    after = [x['name'] for x in rows(store) if _low((own_of(x).get('ends') or {}).get('successor'))
             == _low(r['name'])]
    if after:
        raise ValueError('it is the successor of %s, which ends - choose another successor there '
                         'first' % ', '.join(after))
    kids = children_of(store, r['name'])
    if kids and not detach:
        raise E.ApiError(409, 'it is the base of %s - make them stand alone, or change their base '
                         'first' % ', '.join(kids), extra={'children': kids})
    for k in kids:
        kr = profile_get(store, k)
        cfg = config_of(kr)
        before = dict(kr)
        cfg.pop('base', None)
        cfg.pop('inherit', None)
        store.db.update('cert_req_profiles', kr['id'], {'config': json.dumps(cfg),
                                                        'updated': time.time(),
                                                        'updated_by': str(by)[:190]})
        RM.record(store, before, kr['name'], by, 'its base %s was deleted: it stands alone'
                  % r['name'])
    store.db.run('DELETE FROM cert_req_profiles WHERE id = ?', (r['id'],))
    RM.forget(store, r['name'])
    store.add_event('certificates', 'the request profile %s deleted by %s - the certificates '
                    'asked for from it stay' % (r['name'], by), 'warn', who=by)
    return {'deleted': r['name']}


def rename_ref(store, kind, old, new):
    """An owner (kind 'team') or a tag renamed - or deleted, new None: every profile follows.
    A profile whose teams end up none through its base (1.0.138) is switched off too."""
    had = {r['id']: bool(config_of(r).get('teams')) for r in rows(store)}
    for r in raw_rows(store):
        cfg = own_of(r)
        hit = False
        keys = ('teams',) if kind == 'team' else ('tags',)
        for k in keys:
            have = cfg.get(k) or []
            if any(_low(x) == _low(old) for x in have):
                cfg[k] = [x for x in ((new if _low(x) == _low(old) else x) for x in have) if x]
                hit = True
                if k == 'teams' and have and not cfg[k]:
                    # its only team deleted (1.0.52): no teams means anybody - it is switched
                    # off instead, for an administrator to say who may use it now
                    r['enabled'] = 0
        if kind == 'team' and _low(cfg.get('owner_team')) == _low(old):
            cfg['owner_team'] = new or ''       # deleted (1.0.45): no longer one that is not
            hit = True
        if hit:
            store.db.update('cert_req_profiles', r['id'], {'config': json.dumps(cfg),
                                                           'enabled': 1 if r.get('enabled', 1)
                                                           else 0})
    if kind == 'team':
        for r in rows(store):
            if had.get(r['id']) and not config_of(r).get('teams') and r.get('enabled', 1):
                store.db.update('cert_req_profiles', r['id'], {'enabled': 0})


def rename_source(store, family, old, new):
    """A source or a validation renamed (new) or deleted (None): the profiles naming it follow
    (1.0.45) - renamed, a profile said "there is no source" and the portal no longer offered it."""
    key = 'issuer' if family == 'issuer' else 'challenge'
    # the teams' limits naming it follow too (hunt Rt1)
    from acmelib.certs import teams as T
    T.policy_rename(store, 'issuers' if family == 'issuer' else 'validations', old, new)
    for r in raw_rows(store):
        cfg = own_of(r)
        if str(cfg.get(key) or '') == old and new:
            cfg[key] = new
            store.db.update('cert_req_profiles', r['id'], {'config': json.dumps(cfg)})


def using_source(store, family, name):
    """The profiles that ask for a certificate from this source / with this validation."""
    key = 'issuer' if family == 'issuer' else 'challenge'
    return [r['name'] for r in rows(store) if str(config_of(r).get(key) or '') == name]


def fixed_subject(cfg):
    return {k: v['value'] for k, v in (cfg.get('subject') or {}).items()
            if isinstance(v, dict) and v.get('mode') in ('fixed', 'person') and v.get('value')}


def used_counts(store):
    """{profile name lower: certificates asked for from it and still kept}."""
    out = {}
    have = {r['id'] for r in store.db.rows('SELECT id FROM certs')}
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (META_PORTAL + '%',)):
        try:
            cid = int(r['k'][len(META_PORTAL):])
            p = (json.loads(r['v'] or '{}') or {}).get('profile')
        except (ValueError, TypeError):
            continue
        if p and cid in have:
            out[_low(p)] = out.get(_low(p), 0) + 1
    return out


def problems(store, cfg, row=None):
    """What is wrong with a profile now (a source switched off or gone, its base gone, ...) -
    words."""
    from acmelib.certs import teams as T
    out = list((row or {}).get('_base_problems') or [])
    irow, icls, _info = issuer_info(store, cfg.get('issuer'))
    if not irow:
        out.append('there is no source %s' % cfg.get('issuer'))
    elif icls is None:
        out.append('the module %s of the source %s is missing' % (irow.get('kind'), irow['name']))
    elif not irow.get('enabled', 1):
        out.append('the source %s is switched off' % irow['name'])
    if cfg.get('challenge') and not S.plugin_row(store, 'challenge', cfg['challenge']):
        out.append('there is no validation %s' % cfg['challenge'])
    if cfg.get('owner') == 'fixed' and not T.team_get(store, cfg.get('owner_team')):
        out.append('there is no owner %s' % cfg.get('owner_team'))
    for t in cfg.get('teams') or []:
        if not T.team_get(store, t):
            out.append('there is no team %s' % t)
    return out


def public(store, r, used=None, rws=None, versions=None):
    from acmelib.certs import reqprofiles_more as RM
    cfg = config_of(r)
    out = dict(cfg)
    rws = rws if rws is not None else raw_rows(store)
    own = own_of(r)
    out.update({'id': r['id'], 'name': r['name'], 'description': r.get('description') or '',
                'enabled': bool(r.get('enabled', 1)), 'updated': r.get('updated'),
                'updated_by': r.get('updated_by') or '', 'problems': problems(store, cfg, r),
                # 1.0.138: its base and what it inherits, the profiles based on it, its version,
                # whether it ends (and its successor)
                'base': own.get('base') or '', 'inherit': clean_inherit(own.get('inherit'))
                if own.get('base') else [], 'children': children_of(store, r['name'], rws),
                'version': (versions or {}).get(_low(r['name'])) if versions is not None
                else RM.current(store, r['name']), 'ends': own.get('ends') or None})
    if used is not None:
        out['used'] = used.get(_low(r['name']), 0)
    return out


def profiles(store):
    from acmelib.certs import reqprofiles_more as RM
    used = used_counts(store)
    rws = raw_rows(store)
    vers = RM.currents(store)
    return [public(store, r, used, rws, vers) for r in resolve(rws)]


def options(store):
    """What a profile picks from - every list a catalog."""
    from acmelib.certs import teams as T
    iss = []
    for r in store.db.rows('SELECT * FROM cert_issuers ORDER BY name'):
        irow, cls, info = issuer_info(store, r['name'])
        if cls is None:
            continue
        iss.append({'name': r['name'], 'kind': r.get('kind') or '', 'title': info['title'],
                    'enabled': bool(r.get('enabled', 1)),
                    'needs_validation': info['needs_validation'],
                    'choose_days': bool(getattr(cls, 'choose_days', False)),
                    'csr': csr_ok(irow, cls), 'wildcards': info['wildcards'],
                    'key_types': info['key_types'], 'public': info['public']})
    return {'issuers': iss,
            'challenges': [{'name': r['name'], 'kind': r.get('kind') or ''} for r in
                           store.db.rows('SELECT name, kind FROM cert_challenges ORDER BY name')],
            'key_types': list(schema.KEY_TYPES), 'ekus': list(EKUS),
            'subject_fields': [list(x) for x in SUBJECT_FIELDS],
            'teams': [t['name'] for t in T.team_rows(store)],
            'tags': [{'name': t['name'], 'colour': t.get('colour') or 'dim'}
                     for t in T.tag_rows(store)]}


# ---------------------------------------------------------------------------
# On the portal
# ---------------------------------------------------------------------------
def request_teams(h, s):
    """The teams a portal sign-in may ask for (their right request)."""
    from acmelib.certs import portal as P
    from acmelib.certs import teams as T
    if E.portal_sees_all(s):
        return [t['name'] for t in T.team_rows(h.store)]
    return sorted(n for n, r in P.my_teams(h, s).values() if 'request' in r)


def may_use(h, s, r, mine=None):
    cfg = config_of(r)
    if not r.get('enabled', 1) or problems(h.store, cfg, r):
        return False
    if cfg.get('ends'):
        # it ends (1.0.138, P5): no longer offered - its certificates go to the successor
        return False
    if E.portal_sees_all(s):
        return True
    who = cfg.get('teams') or []
    if who:
        mine = request_teams(h, s) if mine is None else mine
        if not any(_low(t) in {_low(m) for m in mine} for t in who):
            return False
    if cfg.get('owner') == 'team' and not pickable(
            cfg, mine if mine is not None else request_teams(h, s)):
        return False
    return True


def pickable(cfg, mine):
    """The teams a person may pick as the owner: theirs (right request) - only
    the profile's own when the profile is for certain teams (1.0.18)."""
    who = {_low(t) for t in cfg.get('teams') or []}
    return [t for t in mine if not who or _low(t) in who]


def portal_view(store, r, mine):
    """A profile as the portal shows it: what it gives, what is left to the person."""
    cfg = config_of(r)
    irow, icls, info = issuer_info(store, cfg.get('issuer'))
    return {'name': r['name'], 'description': r.get('description') or '',
            'issuer': cfg.get('issuer'), 'issuer_title': (info or {}).get('title') or '',
            'challenge': cfg.get('challenge') or '', 'suffixes': cfg.get('suffixes') or [],
            'wildcards': bool(cfg.get('wildcards')), 'max_names': cfg.get('max_names') or 1,
            'make_key': bool(cfg.get('make_key', True)), 'csr': bool(cfg.get('csr')),
            'key_types': cfg.get('key_types') or [], 'key_default': cfg.get('key_default'),
            'subject': [{'field': k, 'mode': (cfg.get('subject') or {}).get(k, {}).get('mode',
                                                                                    'off'),
                         'value': (cfg.get('subject') or {}).get(k, {}).get('value', '')}
                        for k, _w in SUBJECT_FIELDS],
            'auto_renew': bool(cfg.get('auto_renew', True)), 'renew_days': cfg.get('renew_days'),
            'days': cfg.get('days'), 'eku': cfg.get('eku') or [],
            'approval': bool(cfg.get('approval')), 'owner': cfg.get('owner') or 'person',
            'owner_team': cfg.get('owner_team') or '',
            'owner_choices': pickable(cfg, mine) if cfg.get('owner') == 'team' else [],
            'tags': cfg.get('tags') or [], 'pfx': bool(cfg.get('pfx')),
            'acme': bool((info or {}).get('needs_validation'))}


def usable(h, s):
    mine = request_teams(h, s)
    return [portal_view(h.store, r, mine) for r in rows(h.store) if may_use(h, s, r, mine)]


def need_usable(h, s, name):
    r = profile_get(h.store, name)
    if not r or not may_use(h, s, r):
        raise E.ApiError(404, 'there is no request profile %s you may use' % name)
    return r


# ---------------------------------------------------------------------------
# A CSR
# ---------------------------------------------------------------------------
def read_csr(b):
    """The CSR of a request: pasted text (csr) or a file (csr_b64: PEM or DER) -> PEM."""
    pki = S.pki()
    text = str(b.get('csr') or '').strip()
    if not text and b.get('csr_b64'):
        try:
            raw = base64.b64decode(str(b.get('csr_b64')), validate=False)
        except (binascii.Error, ValueError):
            raise ValueError('the file could not be read')
        if len(raw) > CSR_MAX:
            raise ValueError('a CSR is a few kilobytes - that file is too big')
        if b'-----BEGIN' in raw:
            text = raw.decode('ascii', 'replace')
        else:
            text = pki.der_to_pem(raw, 'CERTIFICATE REQUEST')
    if not text:
        raise ValueError('paste the CSR, or choose its file')
    if len(text) > CSR_MAX:
        raise ValueError('a CSR is a few kilobytes - that is too much')
    try:
        info = pki.csr_info(text)
    except pki.PkiError as e:
        raise ValueError(str(e))
    return info


def name_why(n, cfg):
    """'' when a name may be asked for in this profile, else why not."""
    wild = n.startswith('*.')
    bare = n[2:] if wild else n
    if wild and not cfg.get('wildcards'):
        return 'no wildcards in this profile'
    if not any(bare == suf or bare.endswith('.' + suf) for suf in cfg.get('suffixes') or []):
        return 'not under the domains of the profile: %s' % ', '.join(cfg.get('suffixes') or [])
    return ''


def subject_for(cfg, given):
    """The subject a certificate of this profile gets: fixed fields as the profile says,
    the person's (`given`: what they typed, or what their CSR says) or the default."""
    out = {}
    for k, _w in SUBJECT_FIELDS:
        one = (cfg.get('subject') or {}).get(k) or {}
        mode = one.get('mode') or 'off'
        if mode == 'fixed':
            out[k] = one.get('value') or ''
        elif mode == 'person':
            v = str((given or {}).get(k) or '').strip() or one.get('value') or ''
            if v:
                out[k] = check_value(k, v)
    return {k: v for k, v in out.items() if v}


SAN_TAKEN = ('DNS', 'IP', 'email', 'URI')


def csr_refusals(info):
    """What makes a CSR sent on the portal refused whatever its profile says (1.0.102) -
    a list of words: a certificate authority asked for, names of a kind a profile never
    gives, an extension that could not be read."""
    out = []
    if info.get('ms_ext_req'):
        # AD CS reads its names and extensions, which acme does not (1.0.102)
        out.append(S.pki().MS_EXT_REQ_WORDS)
    if info.get('is_ca'):
        out.append('it asks to be a certificate authority (basicConstraints CA:TRUE)')
    odd = ['%s:%s' % (t, v) for t, v in info.get('san') or [] if t not in SAN_TAKEN]
    odd += list(info.get('san_bad') or [])
    if odd:
        out.append('names of a kind no profile gives (only DNS names, IP addresses, e-mail '
                   'addresses and URIs are read): %s' % ', '.join(odd))
    unread = [x for x in info.get('ext_unread') or []]
    if unread:
        out.append('extensions that cannot be read: %s' % ', '.join(unread))
    return out


def csr_eku_why(info, cfg):
    """'' when the extended key usages the CSR asks for are among those the profile gives
    (serverAuth and clientAuth where it says none), else why not."""
    want = list(cfg.get('eku') or []) or ['serverAuth', 'clientAuth']
    extra = [e for e in info.get('eku') or [] if e not in want]
    if not extra:
        return ''
    return 'it asks for the extended key usage %s - the profile gives %s' % (
        ', '.join(extra), ', '.join(want))


def csr_review(store, r, info):
    """A CSR set beside a profile: what it says, what the certificate will say, and
    every check one by one ({what, ok, said}); fits when none of them fails."""
    from acmelib.certs import compat
    pki = S.pki()
    cfg = config_of(r)
    checks = []
    why = pki.csr_verify_why(info['pem'])
    sig = why is None
    checks.append({'what': 'signature', 'ok': sig,
                   'said': 'signed by its own key' if sig else
                   why if why == pki.CSR_SHA1_REFUSED else 'not signed by the key in it'})
    dns = [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')]
    # e-mail and URI names: left out by acme's own CA, refused for any other (below); every
    # other kind - a UPN or another otherName, a directory name, an OID, an x400 or EDI party
    # name, one that does not read - is refused whatever the source (1.0.102: skipped, and
    # the CSR went to the CA as it was).
    other = [(t, v) for t, v in info.get('san') or [] if t in ('email', 'URI')]
    for why in csr_refusals(info):
        checks.append({'what': 'refused', 'ok': False, 'said': why})
    if not dns and info.get('cn'):
        dns = [info['cn']]
    try:
        names = S.clean_names(dns)
    except ValueError as e:
        names = []
        checks.append({'what': 'names', 'ok': False, 'said': str(e)})
    if not names and not any(c['what'] == 'names' for c in checks):
        checks.append({'what': 'names', 'ok': False, 'said': 'the CSR names no DNS name'})
    for n in names:
        why = name_why(n, cfg)
        checks.append({'what': 'name', 'name': n, 'ok': not why, 'said': why or 'allowed'})
    most = cfg.get('max_names') or 1
    if len(names) > most:
        checks.append({'what': 'count', 'ok': False,
                       'said': '%d names - the profile gives at most %d' % (len(names), most)})
    if other:
        # Left out only by acme's own CA, which writes the names itself (1.0.45); any other
        # source takes the CSR as it is - an e-mail, UPN or URI name went to the CA.
        irow_k = (S.plugin_row(store, 'issuer', cfg.get('issuer')) or {}).get('kind') \
            if cfg.get('issuer') else ''
        own = irow_k == 'internal_ca'
        checks.append({'what': 'other', 'ok': None if own else False,
                       'said': ('not put in the certificate: %s' if own else
                                'names the profile does not give (the source takes the CSR as '
                                'it is): %s') % ', '.join('%s:%s' % (t, v) for t, v in other)})
    eku_why = csr_eku_why(info, cfg)
    if eku_why:
        # what the CSR asks for goes to a source that takes it as it is (1.0.102: shown, never
        # checked); acme's own CA writes the profile's
        irow_e = (S.plugin_row(store, 'issuer', cfg.get('issuer')) or {}).get('kind') \
            if cfg.get('issuer') else ''
        own_e = irow_e == 'internal_ca'
        checks.append({'what': 'eku', 'ok': None if own_e else False,
                       'said': ('not put in the certificate: %s' if own_e else '%s')
                       % eku_why})
    kt = info.get('key_type') or ''
    kok = kt in (cfg.get('key_types') or [])
    checks.append({'what': 'key', 'ok': kok, 'said': '%s%s' % (
        compat.KEY_WORDS.get(kt, kt or '?'), '' if kok else ' - the profile takes %s' % ', '.join(
            compat.KEY_WORDS.get(k, k) for k in cfg.get('key_types') or []))})
    # The subject: field by field, the CSR beside what the certificate will say.
    csr_subj = info.get('subject') or {}
    try:
        will = subject_for(cfg, csr_subj)
        sub_err = ''
    except ValueError as e:
        will, sub_err = {}, str(e)
    if sub_err:
        checks.append({'what': 'subject', 'ok': False, 'said': sub_err})
    irow_kind = (S.plugin_row(store, 'issuer', cfg.get('issuer')) or {}).get('kind') \
        if cfg.get('issuer') else ''
    # ...not for an ACME source (it writes only the names, whatever the CSR's subject says)
    acme_like = 'acme' in irow_kind
    try:
        from acmelib.plugins.issuers import acme as _acme_mod
        icls = S.row_class('issuer', S.plugin_row(store, 'issuer', cfg.get('issuer')) or {})
        acme_like = acme_like or bool(icls and issubclass(icls, _acme_mod.AcmeIssuer))
    except Exception:                                   # noqa: BLE001
        pass
    if irow_kind != 'internal_ca' and not acme_like:
        # A source that takes the CSR as it is (1.0.51): its subject is what the certificate
        # says - a CN not among the names allowed, or a field other than the profile's, went
        # to the CA unchecked.
        if info.get('cn') and _low(info.get('cn')) not in names:
            checks.append({'what': 'subject', 'ok': False,
                           'said': 'the CN %s is not one of its names - the source takes the CSR '
                                   'as it is' % info.get('cn')})
        for k, _w in SUBJECT_FIELDS:
            got_v = str(csr_subj.get(k) or '').strip()
            if got_v and got_v.lower() != str(will.get(k) or '').strip().lower():
                checks.append({'what': 'subject', 'ok': False,
                               'said': '%s=%s is not what the profile gives (%s) - the source '
                                       'takes the CSR as it is' % (k, got_v, will.get(k) or 'none')})
        extra = [k for k, _v in (info.get('subject_list') or [])
                 if k not in ('CN',) and k not in dict(SUBJECT_FIELDS)]
        if extra:
            checks.append({'what': 'subject', 'ok': False,
                           'said': 'fields the profile does not give: %s' % ', '.join(sorted(set(extra)))})
    cn = info.get('cn') if info.get('cn') and _low(info.get('cn')) in names else \
        (names[0] if names else '')
    subject = [{'field': 'CN', 'csr': info.get('cn') or '', 'cert': cn, 'how': 'names'}]
    for k, _w in SUBJECT_FIELDS:
        mode = ((cfg.get('subject') or {}).get(k) or {}).get('mode') or 'off'
        subject.append({'field': k, 'csr': csr_subj.get(k, ''), 'cert': will.get(k, ''),
                        'how': mode})
    for k, v in (info.get('subject_list') or []):
        if k not in ('CN',) and k not in dict(SUBJECT_FIELDS):
            subject.append({'field': k, 'csr': v, 'cert': '', 'how': 'off'})
    if not cfg.get('csr'):
        checks.append({'what': 'csr', 'ok': False, 'said': 'this profile takes no CSR'})
    if names and sig and kok:
        irow = S.plugin_row(store, 'issuer', cfg.get('issuer'))
        sj = dict(will)
        if cn:
            sj['CN'] = cn
        probs = compat.check(store, names, irow, cfg.get('challenge') or None, {}, kt, '',
                             profile={'subject': sj})
        if probs:
            checks.append({'what': 'fit', 'ok': False, 'said': compat.words(probs)})
    if other and cfg.get('challenge'):
        checks.append({'what': 'other', 'ok': False, 'said': 'the CA takes a CSR with only the '
                       'names it proves - make the CSR without e-mail or URI names'})
    fits = all(c['ok'] is not False for c in checks)
    shown = {'subject_dn': info.get('subject_dn') or '',
             'subject_list': [[k, v] for k, v in info.get('subject_list') or []],
             'cn': info.get('cn') or '', 'san': [[t, v] for t, v in info.get('san') or []],
             'key_type': kt, 'key_bits': info.get('key_bits') or 0,
             'sig_alg': info.get('sig_alg') or '', 'sig_ok': sig, 'eku': info.get('eku') or [],
             'is_ca': bool(info.get('is_ca')),
             'key_usage': info.get('key_usage') or [],
             'must_staple': bool(info.get('must_staple')),
             'challenge_password': bool(info.get('challenge_password')),
             'sha256': info.get('sha256') or ''}
    return {'csr': shown, 'names': names, 'cn': cn, 'key_type': kt, 'checks': checks,
            'subject': subject, 'will': dict(will, CN=cn) if cn else will,
            'eku': cfg.get('eku') or [], 'fits': fits}


# ---------------------------------------------------------------------------
# Asking for a certificate from a profile
# ---------------------------------------------------------------------------
def request(h, s, b):
    """POST /api/portal/cert_request with `profile`: everything the profile fixes taken
    from it, the rest from the person - checked as the profile says."""
    from acmelib.certs import compat
    from acmelib.certs import portal as P
    from acmelib.certs import teams as T
    from acmelib.certs import reqprofiles_more as RM
    store = h.store
    r = need_usable(h, s, b.get('profile'))
    cfg = config_of(r)
    who = P.owner_word(s)
    if P.used(store, who) >= P.most():
        raise E.ApiError(403, 'you have asked for as many certificates as one person may (%d)'
                         % P.most())
    csr_pem = ''
    if b.get('csr') or b.get('csr_b64'):
        if not cfg.get('csr'):
            raise E.ApiError(400, 'this profile takes no CSR')
        try:
            info = read_csr(b)
        except ValueError as e:
            raise E.ApiError(400, str(e))
        rv = csr_review(store, r, info)
        if not rv['fits']:
            raise E.ApiError(400, 'the CSR does not fit the profile: %s' % '; '.join(
                c['said'] for c in rv['checks'] if c['ok'] is False))
        names, kt, cn, subject = rv['names'], rv['key_type'], rv['cn'], dict(rv['will'])
        csr_pem = info['pem']
    else:
        if not cfg.get('make_key', True):
            raise E.ApiError(400, 'this profile takes a CSR: send yours')
        try:
            names = S.clean_names(b.get('names'))
        except ValueError as e:
            raise E.ApiError(400, str(e))
        if not names:
            raise E.ApiError(400, 'which names?')
        if len(names) > (cfg.get('max_names') or 1):
            raise E.ApiError(400, 'this profile gives at most %d name(s) in one certificate'
                             % (cfg.get('max_names') or 1))
        bad = ['%s (%s)' % (n, name_why(n, cfg)) for n in names if name_why(n, cfg)]
        if bad:
            raise E.ApiError(403, 'not a name you may ask for here: %s' % ', '.join(bad))
        kt = str(b.get('key_type') or cfg.get('key_default') or '')
        if kt not in (cfg.get('key_types') or []):
            raise E.ApiError(400, 'the key type is one of %s' % ', '.join(cfg.get('key_types')
                                                                          or []))
        try:
            subject = subject_for(cfg, b.get('subject') if isinstance(b.get('subject'), dict)
                                  else {})
        except ValueError as e:
            raise E.ApiError(400, str(e))
        cn = names[0]
    irow = S.plugin_row(store, 'issuer', cfg.get('issuer'))
    probs = compat.check(store, names, irow, cfg.get('challenge') or None, {}, kt, '',
                         profile={'subject': subject})
    if probs:
        raise E.ApiError(400, compat.words(probs))
    # Whose it is: the person, a team they pick (their right request), the profile's team.
    owner = who
    if cfg.get('owner') == 'fixed':
        owner = T.team_get(store, cfg.get('owner_team'))['name']
    elif cfg.get('owner') == 'team':
        pick = str(b.get('team') or '').strip()
        mine = pickable(cfg, request_teams(h, s))
        got = [t for t in mine if _low(t) == _low(pick)]
        if not got:
            store.add_event('certificates', '%s was refused on the portal: a certificate of the '
                            'profile %s for the team %s (needs the right request)' % (
                                who, r['name'], pick or '-'), 'warn', who=who)
            raise E.ApiError(403, 'choose one of your teams: %s' % (', '.join(mine) or 'none'))
        owner = got[0]
    waits = bool(cfg.get('approval')) or P.held_by_others(store, names, owner)   # (1.0.51)
    if owner != who:
        # The team's limits and its approval rule (1.0.125, docs/teams.md "Enterprise teams"):
        # nothing for a team without a policy.
        from acmelib.certs import teampolicy as TP
        TP.need_request(store, owner, who, profile=r['name'], issuer=cfg.get('issuer'),
                        validation=cfg.get('challenge') or None, names=names,
                        days=cfg.get('days'), key_type=kt)
        rule_waits = TP.request_waits(store, owner, waits, r['name'], names, cfg.get('days'),
                                      kt)
        if rule_waits is not None:
            waits = rule_waits or P.held_by_others(store, names, owner)
    held_now = P.holders(store, names, owner, waiting=False)       # who approves it (1.0.102)
    auto = bool(cfg.get('auto_renew', True))
    # a name the rules take (1.0.79: "_svc.example.test" stayed as it was, and every save of the
    # certificate by an administrator was refused until it was renamed)
    base_name = S.safe_name(names[0].replace('*.', 'wildcard.'), most=80)
    name, n = base_name, 1
    while store.db.row('SELECT id FROM certs WHERE name = ?', (name,)):
        n += 1
        name = '%s-%d' % (base_name, n)
    prof = {}
    if subject:
        prof['subject'] = subject
    if cfg.get('eku'):
        prof['eku'] = list(cfg['eku'])
    if cfg.get('days'):
        prof['days'] = int(cfg['days'])
    t = time.time()
    note = str(b.get('note') or '').strip()[:500]
    tags = ['portal'] + [x for x in cfg.get('tags') or [] if x != 'portal']
    row_new = {
        'name': name, 'cn': cn[:190], 'names': json.dumps(names), 'key_type': kt,
        'issuer': irow['name'], 'challenge': cfg.get('challenge') or '', 'challenge_map': '{}',
        'auto_renew': 1 if (auto and not waits) else 0, 'renew_days': cfg.get('renew_days'),
        'reuse_key': 0, 'profile': json.dumps(prof), 'source': 'portal',
        'state': P.WAITING if waits else 'new', 'state_at': t, 'version': 0, 'fails': 0,
        'tags': json.dumps(tags),
        'note': ('asked for on the portal by %s (request profile %s%s). %s' % (
            who, r['name'], ', with a CSR' if csr_pem else '', note)).strip(),
        'owner': owner[:190], 'created': t, 'created_by': P.asked_word(who), 'enabled': 1,
        'ari': '{}', 'csr_given': csr_pem or None}
    # Two asks at once (1.0.102, as the portal's own form since 1.0.45): the name another took
    # meanwhile is taken next - it was a 500 and a Traceback
    cid = None
    for _ in range(50):
        try:
            cid = store.db.insert('certs', dict(row_new, name=name))
            break
        except Exception as e:                          # noqa: BLE001
            if not re.search(r'unique|duplicate', str(e), re.I):
                raise
            n += 1
            name = '%s-%d' % (base_name, n)
    if cid is None:
        raise E.ApiError(409, 'no free name for the certificate - try again')
    if P.used(store, who) > P.most():
        # two asked at once both passed the count before (1.0.51, as the portal's own form)
        store.db.run('DELETE FROM certs WHERE id = ?', (cid,))
        raise E.ApiError(403, 'you have asked for as many certificates as one person may (%d)'
                         % P.most())
    data = s.get('data') or {}
    store.set_meta(P.META + str(cid), json.dumps({
        'who': who, 'display': data.get('display') or '', 'mail': data.get('mail') or '',
        'at': t, 'note': note, 'profile': r['name'], 'pfx': bool(cfg.get('pfx')) and not csr_pem,
        'auto': auto, 'held': P.held_list(held_now), 'ids': P.asker_ids(s),
        'waits': bool(waits),         # approved only by an approval (1.0.106)
        # the version of the profile (and of its bases) it was asked for from (1.0.138)
        'profile_version': RM.current(store, r['name']),
        'base_versions': [[b_, RM.current(store, b_)] for b_ in chain_of(store, r['name'])[1:]]}))
    if waits and held_now:
        P.tell_holders(store, cid, held_now, who)
    what = '%s asked on the portal for %s (%s) from the request profile %s%s' % (
        who, name, ', '.join(names), r['name'], ' with a CSR' if csr_pem else '')
    job_id = None
    waits_for = None
    if waits:
        from acmelib.certs import teampolicy as TP
        # whom it waits for: its team's rule where it has one (hunt C1)
        waits_for = TP.waits_words(store, S.cert_get(store, cid)) if owner != who else None
        store.add_event('certificates', what + ' - it waits for %s' % (
            waits_for or 'approval'), 'warn', who=who)
        if owner != who:
            TP.request_started_waiting(store, cid, owner)
    else:
        store.add_event('certificates', what + ' - issued without approval', who=who)
        job_id = P.start_issue(store, cid, 'portal:' + who, 'asked for on the portal (%s)'
                               % r['name'])
    out = {'id': cid, 'name': name, 'job_id': job_id, 'state': P.WAITING if waits else 'new',
           'waits': waits, 'profile': r['name']}
    if waits_for:
        out['waits_for'] = waits_for
    return out
