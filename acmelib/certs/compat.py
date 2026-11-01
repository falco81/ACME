# -*- coding: utf-8 -*-
"""What fits together: a certificate's names, its source, the validation of
each name and its key type - decided in one place, for every way in.

    check(store, names, issuer, challenge, challenge_map, key_type, key_type_alt)
        -> [problem]   empty when it all fits; each problem
           {'key': 'names' | 'issuer' | 'validation' | 'key' | 'twin',
            'step': the wizard's step it belongs to ('source', 'names', 'key', 'validation'),
            'name': the name it is about (or None), 'validation': (or None),
            'what': what does not fit, in words, 'fix': what to do}
    options(store, ...)  the same ({fits, problems, ...}), and for the wizard what can be chosen: each
                         validation with whether (and why not) it fits each name, each
                         key type, the twin
    words(problems)      one sentence of them all (the 400 of the API, the CLI)

Used by POST /api/certs/save (400 with the words), the command line (which
saves through it), the portal's request, the renewer (a clear failure, the CA
not asked), the readiness plan (its blocking steps) and POST /api/certs/compat
(the wizard greys what does not fit, with the reason).

The rules
---------
* A source says what proves a name to it (base.Issuer.proofs_for: ACME's
  acme-dns-01 / acme-http-01, a commercial CA's DCV - txt-any, cname-any,
  http-file-any, or e-mail and nothing at all), a validation what it can put in
  place (base.Challenge.proofs_for and place_problem): a name fits where they
  meet. A wildcard only by a DNS proof, an IP address only by an HTTP one.
  dns-persist-01 (a TXT record set once, challenges/dns_persist.py) proves
  names only to an ACME source that takes it: any other source is told so in
  plain words (its place_problem).
* The source takes the kind of name: wildcards, IP addresses (its ip_names);
  a publicly trusted CA (public_for) only fully qualified names under a public
  suffix - no single label ("intranet"), no .local, .internal, .lan, .home.arpa,
  .localhost, .test, .invalid, .example, .corp..., no private address.
  An authority of its own, self-signed, AD CS, SCEP, EST take them all.
* The common name (profile.subject.CN) of a public CA is one of the names and at
  most 64 characters; a source of your own may name anything (cn_free). E-mail
  and URI subjectAltNames (profile.san_other) only where the source puts them
  in (san_types). Let's Encrypt gives IP addresses only in its "shortlived"
  profile.
* The key type is one the source signs (key_types_for; a public CA no Ed25519),
  the twin of a dual certificate only from a source that gives one (dual_for).

Nothing here asks the network: it is quick, and the same everywhere.
"""
from __future__ import annotations

import ipaddress
import json
import re

from acmelib.plugins import base
from acmelib.certs import schema
from acmelib.certs import store as S

# Suffixes no public CA issues for (RFC 6761, RFC 6762, RFC 8375, ICANN's
# name-collision list): a name ending in one is internal.
RESERVED = ('local', 'localhost', 'internal', 'lan', 'home.arpa', 'test', 'invalid', 'example',
            'corp', 'home', 'localdomain', 'intranet', 'private', 'mail', 'onion', 'alt')
PUBLIC_KEYS = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
DNS_RE = re.compile(r'^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*'
                    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')

KEY_WORDS = {'ec-256': 'ECDSA P-256', 'ec-384': 'ECDSA P-384', 'rsa-2048': 'RSA 2048',
             'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096', 'ed25519': 'Ed25519'}


def _settings(settings=None):
    if settings is not None:
        return settings
    try:
        from acmelib import engine as E
        return E.CONFIG
    except Exception:                                   # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# A name
# ---------------------------------------------------------------------------
def kind_of(name):
    """'ip' | 'wild' | 'dns' | 'bad' of a name as typed."""
    n = str(name or '').strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(n)
        return 'ip'
    except ValueError:
        pass
    if not n or len(n) > 253 or not DNS_RE.match(n) or n.count('*') > 1:
        return 'bad'
    return 'wild' if n.startswith('*.') else 'dns'


def bare(name):
    n = str(name or '').strip().lower().rstrip('.')
    return n[2:] if n.startswith('*.') else n


def internal_why(name):
    """Why a publicly trusted CA cannot issue for this name ('' when it can)."""
    k = kind_of(name)
    n = bare(name)
    if k == 'ip':
        a = ipaddress.ip_address(n)
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or \
                a.is_unspecified or a.is_multicast:
            return '%s is a private or reserved address - a public CA issues only for public ' \
                   'addresses' % n
        return ''
    if '.' not in n:
        return '%s is a single label, not a fully qualified name - a public CA needs one like ' \
               '%s.example.com' % (n, n)
    tld = n.rsplit('.', 1)[1]
    if tld.isdigit():
        return '%s does not end in a top-level domain' % n
    for suf in RESERVED:
        if n == suf or n.endswith('.' + suf):
            return '%s ends in .%s, a name that is never public - a public CA does not issue ' \
                   'for it' % (n, suf)
    return ''


# ---------------------------------------------------------------------------
# A source
# ---------------------------------------------------------------------------
def source_info(cls, config, kind=''):
    """What a source of this class, with these settings, takes."""
    config = config or {}
    dcv = dict(getattr(cls, 'dcv', None) or {})
    method = cls.dcv_method(config) if dcv else ''
    proofs = cls.proofs_for(config)
    public = bool(cls.public_for(config))
    kts = cls.key_types_for(config)
    if kts is None:
        kts = list(PUBLIC_KEYS) if public else list(schema.KEY_TYPES)
    if public:
        kts = [k for k in kts if k != 'ed25519']
    needs = bool(proofs) if dcv else bool(getattr(cls, 'needs_challenge', False))
    return {'kind': getattr(cls, 'kind', kind), 'title': getattr(cls, 'title', '') or kind,
            'needs_validation': needs, 'proofs': proofs, 'dcv_method': method,
            'dcv': {k: dict(v) for k, v in dcv.items()},
            'wildcards': bool(getattr(cls, 'wildcards', True)),
            'ip_names': bool(getattr(cls, 'ip_names', False)), 'public': public,
            'key_types': [k for k in schema.KEY_TYPES if k in kts],
            'san_types': list(cls.san_types_for(config)),
            'cn_free': bool(cls.cn_free_for(config)),
            'ip_profile': _ip_profile(cls, config),
            'dual': bool(cls.dual_for(config))}


def _ip_profile(cls, config):
    """The ACME profile an IP address needs at this CA ('' none): Let's Encrypt
    issues for IP addresses only in its short-lived profile (6-day certificates,
    "shortlived" - letsencrypt.org/docs/profiles, IP addresses generally available
    since 2025)."""
    if getattr(cls, 'kind', '') == 'acme' and str((config or {}).get('directory') or
                                                  'letsencrypt') in ('letsencrypt',
                                                                     'letsencrypt-staging'):
        return 'shortlived'
    return ''


def _where(cls, config, name, proof):
    fn = getattr(cls, 'dcv_where', None)
    try:
        return fn(config, name, proof) if callable(fn) else bare(name)
    except Exception:                                   # noqa: BLE001
        return bare(name)


def allowed_proofs(info, name):
    """The source's proofs that can prove this name at all (by its kind)."""
    k = kind_of(name)
    ps = list(info['proofs'])
    if k == 'wild':
        ps = [p for p in ps if p in base.DNS_PROOFS]
    elif k == 'ip':
        ps = [p for p in ps if p in base.HTTP_PROOFS]
    return ps


def _proof_words(p):
    return {'acme-dns-01': 'DNS-01', 'acme-http-01': 'HTTP-01',
            'acme-dns-persist-01': 'DNS-PERSIST-01 (a TXT record set once)',
            'txt-any': 'a DNS TXT record',
            'cname-any': 'a DNS CNAME record', 'http-file-any': 'an HTTP file'}.get(p, p)


def validation_fits(icls, iconfig, info, crow, name, settings):
    """'' when the validation (a row of cert_challenges) proves `name` to this
    source, else why not, in words."""
    if not crow:
        return 'there is no such validation'
    if not crow.get('enabled', 1) or str(crow.get('enabled')) in ('0', 'False'):
        return 'the validation %s is switched off' % crow['name']
    ccls = S.plugin_class('challenge', crow.get('kind'))
    if ccls is None:
        return 'the module %s of %s is missing' % (crow.get('kind'), crow['name'])
    cconf = S.jload(crow.get('config'), {}) or {}
    k = kind_of(name)
    want = allowed_proofs(info, name)
    if not want:
        if k == 'wild':
            return ('a wildcard can only be proved by DNS, and %s checks the domain by %s - '
                    'choose a DNS method of validation (DCV) in the source' % (
                        info['title'], ', '.join(_proof_words(p) for p in info['proofs'])))
        if k == 'ip':
            return 'an IP address can only be proved by HTTP, and %s checks by %s' % (
                info['title'], ', '.join(_proof_words(p) for p in info['proofs']))
        return '%s checks the domain in no way a validation can help with' % info['title']
    has = list(ccls.proofs_for(cconf))
    can = [p for p in want if p in has]
    if not can:
        try:
            own = ccls.place_problem(want[0], _where(icls, iconfig, name, want[0]), cconf, settings)
        except Exception:                               # noqa: BLE001
            own = ''
        generic = ' cannot put %s in place' % base.PROOFS.get(want[0], want[0])
        if own and generic not in own:
            return own
        if k == 'wild' and not any(p in base.DNS_PROOFS for p in has):
            return 'a wildcard can only be proved by DNS: %s is an HTTP validation' % crow['name']
        if k == 'ip' and not any(p in base.HTTP_PROOFS for p in has):
            return 'an IP address can only be proved by HTTP-01: %s is a DNS validation' % \
                crow['name']
        return '%s cannot put %s in place, which %s checks' % (
            crow['name'], ' or '.join(_proof_words(p) for p in want), info['title'])
    why = []
    for p in can:
        try:
            bad = ccls.place_problem(p, _where(icls, iconfig, name, p), cconf, settings)
        except Exception as e:                          # noqa: BLE001
            bad = '%s: %s' % (type(e).__name__, e)
        if not bad:
            return ''
        why.append(bad)
    return why[0]


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------
def _problem(key, step, what, fix, name=None, validation=None):
    return {'key': key, 'step': step, 'name': name, 'validation': validation,
            'what': str(what), 'fix': str(fix)}


def _names_of(names):
    if isinstance(names, str):
        names = [n for n in re.split(r'[\s,;]+', names) if n]
    out = []
    for n in names or []:
        n = str(n).strip().lower().rstrip('.')
        if n and n not in out:
            out.append(n)
    return out


def _issuer(store, issuer):
    if isinstance(issuer, dict):
        return issuer
    return S.plugin_row(store, 'issuer', issuer) if issuer else None


def name_why(info, name):
    """Why the source cannot take this name ('' when it can) - by the name alone."""
    k = kind_of(name)
    if k == 'bad':
        return '%s is not a DNS name or an IP address' % name
    if info is None:
        return ''
    if k == 'wild' and not info['wildcards']:
        return '%s gives no wildcard certificates' % info['title']
    if k == 'ip' and not info['ip_names']:
        return '%s gives no certificates for IP addresses' % info['title']
    if info['public']:
        return internal_why(name)
    return ''


def _evaluate(store, names, issuer, challenge, challenge_map, key_type, key_type_alt,
              settings, all_validations=False, profile=None):
    settings = _settings(settings)
    profile = profile if isinstance(profile, dict) else {}
    names = _names_of(names)
    out = {'problems': [], 'source': None, 'names': {}, 'validations': [], 'key_types': [],
           'twin': {'ok': True, 'why': ''}}
    P = out['problems']
    irow = _issuer(store, issuer)
    icls = info = iconf = None
    if issuer and not irow:
        P.append(_problem('issuer', 'source', 'there is no source %s' % issuer,
                          'Choose a source (Certificates → Sources)'))
    elif irow:
        icls = S.plugin_class('issuer', irow.get('kind'))
        if icls is None:
            P.append(_problem('issuer', 'source', 'the module %s of the source %s is missing'
                              % (irow.get('kind'), irow['name']), 'Choose another source'))
        else:
            iconf = S.jload(irow.get('config'), {}) or {}
            info = source_info(icls, iconf, irow.get('kind'))
            info['name'] = irow['name']
            out['source'] = info
    # -- the names --
    for n in names:
        why = name_why(info, n)
        out['names'][n] = why
        if why:
            fix = 'Correct the name'
            if kind_of(n) == 'wild':
                fix = 'Take the wildcard out, or choose a source that gives wildcards'
            elif kind_of(n) == 'ip':
                fix = 'Take the address out, or choose a source that takes IP addresses'
            elif info and info['public'] and kind_of(n) != 'bad':
                fix = ('Use the full public name (e.g. %s.example.com), or take an authority of '
                       'your own, AD CS or self-signed for internal names' % bare(n).split('.')[0])
            P.append(_problem('names', 'names', why, fix, name=n))
    # -- the other subjectAltNames and the common name --
    others = [x for x in (profile.get('san_other') or []) if isinstance(x, str)]
    out['san_other'] = {}
    for x in others:
        t = x.split(':', 1)[0].lower()
        why = ''
        if info and t not in info['san_types']:
            why = '%s puts no %s names in its certificates (only %s)' % (
                info['title'], {'email': 'e-mail', 'uri': 'URI'}.get(t, t),
                ', '.join({'dns': 'DNS', 'ip': 'IP', 'email': 'e-mail', 'uri': 'URI'}.get(y, y)
                          for y in info['san_types']))
        out['san_other'][x] = why
        if why:
            P.append(_problem('names', 'names', why, 'Take %s out, or choose an authority of '
                              'your own, AD CS or self-signed' % x.split(':', 1)[1], name=x))
    cn = str((profile.get('subject') or {}).get('CN') or '').strip().lower().rstrip('.')
    out['cn'] = {'value': cn, 'why': ''}
    if cn:
        try:
            cn_norm = S.clean_names([cn])[0]
        except (ValueError, IndexError):
            cn_norm = cn
        if len(cn) > 64:
            out['cn']['why'] = 'the common name is longer than 64 characters'
        elif info and not info['cn_free'] and cn_norm not in names:
            out['cn']['why'] = ('%s puts in the common name only one of the certificate\'s '
                                'names (CA/B Forum) - %s is not one of them' % (info['title'], cn))
        if out['cn']['why']:
            P.append(_problem('names', 'names', out['cn']['why'],
                              'Make the common name one of the names (the CN is also a SAN), or '
                              'leave it empty: the first name is taken', name=cn))
    if info and info.get('ip_profile') and any(kind_of(n) == 'ip' for n in names):
        want = info['ip_profile']
        have = str(profile.get('acme_profile') or (S.jload(irow.get('config'), {}) or {}).get(
            'profile') or '').strip()
        if have != want:
            P.append(_problem('names', 'names', '%s issues for IP addresses only in its "%s" '
                              'profile (certificates of 6 days)' % (info['title'], want),
                              'Set the ACME profile to %s (Profile step, or the source), or take '
                              'the addresses out' % want))
    # -- the key --
    kt = str(key_type or 'ec-256')
    kta = str(key_type_alt or '')
    allowed = info['key_types'] if info else list(schema.KEY_TYPES)
    for k in schema.KEY_TYPES:
        ok = k in allowed
        out['key_types'].append({'key': k, 'ok': ok, 'why': '' if ok else (
            '%s signs %s keys only' % (info['title'], ', '.join(KEY_WORDS.get(x, x)
                                                                 for x in allowed)))})
    if info and kt not in allowed:
        P.append(_problem('key', 'key', '%s does not sign a %s key' % (info['title'],
                                                                      KEY_WORDS.get(kt, kt)),
                          'Choose one of: %s' % ', '.join(KEY_WORDS.get(x, x) for x in allowed)))
    if info and not info['dual']:
        out['twin'] = {'ok': False, 'why': '%s gives no twin (a second certificate with another '
                                           'kind of key)' % info['title']}
    if kta and info:
        if not info['dual']:
            P.append(_problem('twin', 'key', out['twin']['why'],
                              'Leave the twin out, or choose a source that gives one'))
        elif kta not in allowed:
            P.append(_problem('twin', 'key', '%s does not sign a %s key (the twin)' % (
                info['title'], KEY_WORDS.get(kta, kta)), 'Choose another twin'))
    # -- the validations --
    if info and info['needs_validation']:
        cert = {'challenge': challenge or '', 'challenge_map': json.dumps(challenge_map or {})}
        rows = {}

        def row_of(ref):
            if ref not in rows:
                rows[ref] = S.plugin_row(store, 'challenge', ref)
            return rows[ref]
        for n in names:
            if out['names'].get(n) and kind_of(n) == 'bad':
                continue
            which = S.challenge_for(cert, n)
            if not which:
                P.append(_problem('validation', 'validation', 'no validation is chosen for %s' % n,
                                  'Choose a validation for it', name=n))
                continue
            crow = row_of(which)
            why = validation_fits(icls, iconf, info, crow, n, settings)
            if why:
                fix = 'Choose a validation that can prove it'
                if kind_of(n) == 'wild':
                    fix = 'Choose a DNS validation for %s' % n
                elif kind_of(n) == 'ip':
                    fix = 'Choose an HTTP-01 validation for %s' % n
                P.append(_problem('validation', 'validation', why, fix, name=n,
                                  validation=crow['name'] if crow else which))
        if all_validations:
            for crow in store.db.rows('SELECT * FROM cert_challenges ORDER BY name'):
                each = {n: validation_fits(icls, iconf, info, crow, n, settings)
                        for n in names if kind_of(n) != 'bad'}
                ccls = S.plugin_class('challenge', crow.get('kind'))
                cconf = S.jload(crow.get('config'), {}) or {}
                whole = ''
                if ccls is not None and not any(p in ccls.proofs_for(cconf)
                                                for p in info['proofs']):
                    whole = '%s cannot put %s in place, which %s checks' % (
                        crow['name'], ' or '.join(_proof_words(p) for p in info['proofs']),
                        info['title'])
                elif ccls is None:
                    whole = 'the module %s is missing' % crow.get('kind')
                out['validations'].append({
                    'name': crow['name'], 'kind': crow.get('kind'),
                    'proofs': list(ccls.proofs_for(cconf)) if ccls else [],
                    'ok': not whole and not any(each.values()),
                    'why': whole or next((v for v in each.values() if v), ''),
                    'names': each})
    elif all_validations:
        out['validations'] = []
    return out


def check(store, names, issuer, challenge=None, challenge_map=None, key_type=None,
          key_type_alt=None, settings=None, profile=None):
    """[problem] - see the top of this file. `profile`: the certificate's
    (subject.CN, san_other, acme_profile)."""
    return _evaluate(store, names, issuer, challenge, challenge_map, key_type, key_type_alt,
                     settings, profile=profile)['problems']


def options(store, names, issuer, challenge=None, challenge_map=None, key_type=None,
            key_type_alt=None, settings=None, profile=None):
    out = _evaluate(store, names, issuer, challenge, challenge_map, key_type, key_type_alt,
                    settings, all_validations=True, profile=profile)
    out['fits'] = not out['problems']        # ('ok' is the API's own: the answer came)
    return out


def check_cert(store, cert, settings=None):
    """check() of a row of certs."""
    return check(store, S.jload(cert.get('names'), []) or [], cert.get('issuer') or None,
                 cert.get('challenge') or None, S.jload(cert.get('challenge_map'), {}) or {},
                 cert.get('key_type') or 'ec-256', cert.get('key_type_alt') or '', settings,
                 profile=S.jload(cert.get('profile'), {}) or {})


def words(problems):
    """One sentence of the problems: what, then what to do, each once."""
    out = []
    for p in problems or []:
        w = p['what'] + (' - ' + p['fix'] if p.get('fix') else '')
        if w not in out:
            out.append(w)
    return '; '.join(out)
