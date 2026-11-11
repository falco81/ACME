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
def rows(store):
    try:
        return store.db.rows('SELECT * FROM cert_req_profiles ORDER BY %s'
                             % store.db.name_order())
    except Exception:                                   # noqa: BLE001
        return store.db.rows('SELECT * FROM cert_req_profiles ORDER BY name')


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


def check_value(k, value):
    if any(ord(c) < 32 for c in value) or len(value) > 64:
        raise ValueError('%s: 64 characters at most, no control characters' % k)
    if k == 'C' and not re.match(r'^[A-Za-z]{2}\Z', value):
        raise ValueError('the country (C) is two letters (CZ, SK, DE…)')
    if k == 'emailAddress' and not MAIL_RE.match(value):
        raise ValueError('%r is not a mail address' % value)
    return value.upper() if k == 'C' else value


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


def save_profile(store, b, by):
    """A profile added or changed, every value checked against its catalog."""
    from acmelib.certs import compat
    from acmelib.certs import teams as T
    old = profile_get(store, b.get('old_name')) if b.get('old_name') else None
    if b.get('old_name') and not old:
        raise LookupError('there is no request profile %s' % b.get('old_name'))
    name = S.clean_name(b.get('name'), 'the profile\'s name')
    other = profile_get(store, name)
    if other and (not old or other['id'] != old['id']):
        raise ValueError('there is a request profile called %s already' % other['name'])
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
    desc = str(b.get('description') or '').strip()[:2000]
    row = {'name': name, 'description': desc, 'enabled': 1 if _flag(b.get('enabled'), True) else 0,
           'config': json.dumps(cfg), 'updated': time.time(), 'updated_by': str(by)[:190]}
    if old:
        store.db.update('cert_req_profiles', old['id'], row)
        if old['name'] != name:
            asked_follow(store, old['name'], name)
        store.add_event('certificates', 'the request profile %s changed by %s%s' % (
            name, by, (' (was %s)' % old['name']) if old['name'] != name else ''), who=by)
    else:
        row.update(created=time.time(), created_by=str(by)[:190])
        store.db.insert('cert_req_profiles', row)
        store.add_event('certificates', 'the request profile %s added by %s' % (name, by), who=by)
    return public(store, profile_get(store, name))


def asked_follow(store, old, new):
    """A profile renamed (1.0.19): what was asked for from it says its new name - it
    counted no more, and a new CSR for one of them was no longer checked against it."""
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (META_PORTAL + '%',)):
        try:
            got = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(got, dict) and got.get('profile') and _low(got['profile']) == _low(old):
            got['profile'] = new
            store.set_meta(r['k'], json.dumps(got))


def delete_profile(store, name, by):
    r = profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    store.db.run('DELETE FROM cert_req_profiles WHERE id = ?', (r['id'],))
    store.add_event('certificates', 'the request profile %s deleted by %s - the certificates '
                    'asked for from it stay' % (r['name'], by), 'warn', who=by)
    return {'deleted': r['name']}


def rename_ref(store, kind, old, new):
    """An owner (kind 'team') or a tag renamed - or deleted, new None: every profile follows."""
    for r in rows(store):
        cfg = config_of(r)
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


def rename_source(store, family, old, new):
    """A source or a validation renamed (new) or deleted (None): the profiles naming it follow
    (1.0.45) - renamed, a profile said "there is no source" and the portal no longer offered it."""
    key = 'issuer' if family == 'issuer' else 'challenge'
    for r in rows(store):
        cfg = config_of(r)
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


def problems(store, cfg):
    """What is wrong with a profile now (a source switched off or gone, ...) - words."""
    from acmelib.certs import teams as T
    out = []
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


def public(store, r, used=None):
    cfg = config_of(r)
    out = dict(cfg)
    out.update({'id': r['id'], 'name': r['name'], 'description': r.get('description') or '',
                'enabled': bool(r.get('enabled', 1)), 'updated': r.get('updated'),
                'updated_by': r.get('updated_by') or '', 'problems': problems(store, cfg)})
    if used is not None:
        out['used'] = used.get(_low(r['name']), 0)
    return out


def profiles(store):
    used = used_counts(store)
    return [public(store, r, used) for r in rows(store)]


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
    if not r.get('enabled', 1) or problems(h.store, cfg):
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


def csr_review(store, r, info):
    """A CSR set beside a profile: what it says, what the certificate will say, and
    every check one by one ({what, ok, said}); fits when none of them fails."""
    from acmelib.certs import compat
    pki = S.pki()
    cfg = config_of(r)
    checks = []
    sig = pki.csr_verify(info['pem'])
    checks.append({'what': 'signature', 'ok': sig,
                   'said': 'signed by its own key' if sig else 'not signed by the key in it'})
    dns = [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')]
    other = [(t, v) for t, v in info.get('san') or [] if t not in ('DNS', 'IP')]
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
    cid = store.db.insert('certs', {
        'name': name, 'cn': cn[:190], 'names': json.dumps(names), 'key_type': kt,
        'issuer': irow['name'], 'challenge': cfg.get('challenge') or '', 'challenge_map': '{}',
        'auto_renew': 1 if (auto and not waits) else 0, 'renew_days': cfg.get('renew_days'),
        'reuse_key': 0, 'profile': json.dumps(prof), 'source': 'portal',
        'state': P.WAITING if waits else 'new', 'state_at': t, 'version': 0, 'fails': 0,
        'tags': json.dumps(tags),
        'note': ('asked for on the portal by %s (request profile %s%s). %s' % (
            who, r['name'], ', with a CSR' if csr_pem else '', note)).strip(),
        'owner': owner[:190], 'created': t, 'created_by': 'portal:' + who[:180], 'enabled': 1,
        'ari': '{}', 'csr_given': csr_pem or None})
    if P.used(store, who) > P.most():
        # two asked at once both passed the count before (1.0.51, as the portal's own form)
        store.db.run('DELETE FROM certs WHERE id = ?', (cid,))
        raise E.ApiError(403, 'you have asked for as many certificates as one person may (%d)'
                         % P.most())
    data = s.get('data') or {}
    store.set_meta(P.META + str(cid), json.dumps({
        'who': who, 'display': data.get('display') or '', 'mail': data.get('mail') or '',
        'at': t, 'note': note, 'profile': r['name'], 'pfx': bool(cfg.get('pfx')) and not csr_pem,
        'auto': auto}))
    what = '%s asked on the portal for %s (%s) from the request profile %s%s' % (
        who, name, ', '.join(names), r['name'], ' with a CSR' if csr_pem else '')
    job_id = None
    if waits:
        store.add_event('certificates', what + ' - it waits for approval', 'warn', who=who)
    else:
        store.add_event('certificates', what + ' - issued without approval', who=who)
        job_id = P.start_issue(store, cid, 'portal:' + who, 'asked for on the portal (%s)'
                               % r['name'])
    return {'id': cid, 'name': name, 'job_id': job_id, 'state': P.WAITING if waits else 'new',
            'waits': waits, 'profile': r['name']}
