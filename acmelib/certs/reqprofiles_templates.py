# -*- coding: utf-8 -*-
"""
Request profiles from a template (1.0.140, docs/request-profiles.md "From a template"):
built-in starting points for the usual services - a web server, a mail server, a VPN
gateway, an internal service, a load balancer with a wildcard, code signing. A template is
acme's words and settings only; choosing one makes a NORMAL request profile (saved as every
other, its first version saying which template it came from) that is then edited as any.
A template never changes a profile that is there: a name taken is refused.

What a template sets is fitted to the source chosen: only the key types the source signs,
a wildcard only where it gives them, a CSR only where it takes one, a validity only where the
source lets it be chosen - and then within the CA/Browser Forum's limit for a public source
(reqprofiles_more.limit_on) and the company's own rules (reqprofiles_more.rules: the shortest
RSA key, forbidden key types, the longest validity, wildcards only with approval, no PFX,
the most names). Code signing is offered only with a source that puts the profile's extended
key usages into what it signs (an authority of acme's own); with none, it is not offered.

    GET  /api/reqprofiles/templates          the templates, each with the sources that fit
    POST /api/reqprofiles/template_preview   {template, issuer?, challenge?, suffixes[]?}
                                             the profile it would make and what the compliance
                                             check says of it - nothing kept
    POST /api/reqprofiles/from_template      {template, name, suffixes[], issuer?, challenge?,
                                             description?} (full administrator) - the profile
"""
from __future__ import annotations

import datetime

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import reqprofiles as R

# Sources that put the profile's extended key usages into the certificate they sign (code
# signing needs that; an ACME CA or a commercial one gives TLS server certificates only).
EKU_KINDS = ('internal_ca',)

TEMPLATES = (
    {'id': 'web', 'title': 'Web server', 'icon': 'globe', 'prefer': 'public',
     'name': 'Web servers',
     'about': 'HTTPS for web sites and APIs: a TLS server certificate browsers trust.',
     'cfg': {'eku': ['serverAuth'], 'key_types': ['ec-256', 'rsa-2048'], 'key_default': 'ec-256',
             'max_names': 10, 'wildcards': False, 'make_key': True, 'csr': True,
             'approval': False, 'pfx': False, 'days_private': 365}},
    {'id': 'mail', 'title': 'Mail server', 'icon': 'mail', 'prefer': 'public',
     'name': 'Mail servers',
     'about': 'SMTP, IMAP and POP3 over TLS - mail., smtp., imap., autodiscover. in one '
              'certificate; a server and a client of other mail servers.',
     'cfg': {'eku': ['serverAuth', 'clientAuth'], 'key_types': ['rsa-2048', 'ec-256'],
             'key_default': 'rsa-2048', 'max_names': 8, 'wildcards': False, 'make_key': True,
             'csr': True, 'approval': False, 'pfx': True, 'days_private': 365}},
    {'id': 'vpn', 'title': 'VPN gateway', 'icon': 'shield', 'prefer': 'any',
     'name': 'VPN gateways',
     'about': 'The certificate of a VPN concentrator or firewall (IPsec, SSL VPN): a stronger '
              'key, a CSR from the device or a PFX to import.',
     'cfg': {'eku': ['serverAuth', 'clientAuth'], 'key_types': ['rsa-3072', 'ec-384', 'rsa-2048'],
             'key_default': 'rsa-3072', 'max_names': 3, 'wildcards': False, 'make_key': True,
             'csr': True, 'approval': False, 'pfx': True, 'days_private': 397}},
    {'id': 'internal', 'title': 'Internal service', 'icon': 'net', 'prefer': 'private',
     'name': 'Internal services',
     'about': 'Servers inside the company that trust your own CA - a longer validity, more '
              'names, a server and a client.',
     'cfg': {'eku': ['serverAuth', 'clientAuth'], 'key_types': ['ec-256', 'rsa-2048', 'rsa-3072'],
             'key_default': 'ec-256', 'max_names': 20, 'wildcards': False, 'make_key': True,
             'csr': True, 'approval': False, 'pfx': True, 'days_private': 730}},
    {'id': 'wildcard', 'title': 'Load balancer / wildcard', 'icon': 'fold', 'prefer': 'public',
     'name': 'Load balancers (wildcard)',
     'about': 'One wildcard certificate for a load balancer or reverse proxy in front of many '
              'sites - it waits for approval before it is issued.',
     'cfg': {'eku': ['serverAuth'], 'key_types': ['rsa-2048', 'ec-256'], 'key_default': 'rsa-2048',
             'max_names': 4, 'wildcards': True, 'make_key': True, 'csr': True,
             'approval': True, 'pfx': False, 'days_private': 365}},
    {'id': 'codesign', 'title': 'Code signing', 'icon': 'key', 'prefer': 'private',
     'name': 'Code signing', 'eku_kinds': EKU_KINDS,
     'about': 'Signing scripts, packages and programs inside the company with your own CA: '
              'the key stays with the developer (a CSR), each one approved.',
     'cfg': {'eku': ['codeSigning'], 'key_types': ['rsa-3072', 'rsa-4096', 'ec-384'],
             'key_default': 'rsa-3072', 'max_names': 1, 'wildcards': False, 'make_key': False,
             'csr': True, 'approval': True, 'pfx': False, 'days_private': 365}},
)
BY_ID = {t['id']: t for t in TEMPLATES}

KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048',
             'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096', 'ed25519': 'Ed25519'}
EKU_WORDS = {'serverAuth': 'TLS server', 'clientAuth': 'TLS client', 'codeSigning': 'code signing',
             'emailProtection': 'e-mail (S/MIME)', 'timeStamping': 'time stamping',
             'OCSPSigning': 'OCSP signing'}


def template(tid):
    t = BY_ID.get(str(tid or '').strip().lower())
    if not t:
        raise LookupError('there is no template %s (%s)' % (tid, ', '.join(BY_ID)))
    return t


def _issuers(store):
    return [i for i in R.options(store)['issuers']]


def fits(t, info):
    """'' when the source can give what the template asks for, else why not (words)."""
    if not info.get('enabled'):
        return 'it is switched off'
    if t.get('eku_kinds') and info.get('kind') not in t['eku_kinds']:
        return 'it does not put the extended key usage %s into what it signs' % ', '.join(
            EKU_WORDS.get(e, e) for e in t['cfg']['eku'])
    if t['cfg'].get('wildcards') and not info.get('wildcards'):
        return 'it gives no wildcard certificates'
    if not info.get('key_types'):
        return 'it signs no key type'
    # (a key that stays with the person, at a source that signs only a key acme holds: acme
    # makes it then - said in the notes of build(), not refused)
    return ''


def _rank(t, info):
    pref = t.get('prefer')
    if pref == 'public':
        return 0 if info.get('public') else 1
    if pref == 'private':
        return 0 if not info.get('public') else 1
    return 0


def sources_for(store, t, issuers=None):
    """[{name, title, kind, public, fits, why}] - those that fit first, the preferred kind
    (public or private) first among them."""
    out = []
    for i in (issuers if issuers is not None else _issuers(store)):
        why = fits(t, i)
        out.append({'name': i['name'], 'title': i.get('title') or i.get('kind') or '',
                    'kind': i.get('kind') or '', 'public': bool(i.get('public')),
                    'needs_validation': bool(i.get('needs_validation')),
                    'fits': not why, 'why': why, '_rank': _rank(t, i)})
    out.sort(key=lambda x: (not x['fits'], x['_rank']))
    for x in out:
        x.pop('_rank', None)
    return out


def _rsa_bits(kt):
    if str(kt).startswith('rsa-'):
        try:
            return int(str(kt).split('-', 1)[1])
        except ValueError:
            return 0
    return None


def sets(cfg, public=None):
    """What a template (or the profile it makes) sets, as words (English, the pages translate)."""
    out = ['used for: %s' % ', '.join(EKU_WORDS.get(e, e) for e in cfg.get('eku') or [])]
    out.append('keys: %s' % ', '.join(KEY_WORDS.get(k, k) for k in cfg.get('key_types') or []))
    n = int(cfg.get('max_names') or 1)
    out.append('one name in a certificate' if n == 1 else 'up to %d names in a certificate' % n)
    if cfg.get('wildcards'):
        out.append('wildcards (*.)')
    if cfg.get('make_key') and cfg.get('csr'):
        out.append('acme makes the key, or the person sends a CSR')
    elif cfg.get('csr'):
        out.append('the person sends a CSR - the key stays with them')
    else:
        out.append('acme makes the key')
    if cfg.get('days'):
        out.append('valid for %d days' % int(cfg['days']))
    elif public is not False:
        out.append('the CA chooses the validity')
    if cfg.get('days_private') and public is None:
        out.append('valid for %d days from your own CA' % int(cfg['days_private']))
    out.append('waits for approval' if cfg.get('approval') else 'issued at once')
    if cfg.get('pfx') and cfg.get('make_key', True):
        out.append('a PFX with the key may be downloaded')
    return out


def build(store, tid, issuer='', challenge='', suffixes=None, name='', description='',
          saved=False):
    """The profile a template makes with this source: {body, source, public, findings,
    status, sets, notes}. ValueError when no source fits (or the one named does not).
    `saved`: also what saving it would refuse, as a finding (the preview)."""
    from acmelib.certs import defaults as DF
    from acmelib.certs import reqprofiles_more as RM
    from acmelib.certs import store as S
    t = template(tid)
    iss = _issuers(store)
    cands = sources_for(store, t, iss)
    issuer = str(issuer or '').strip()
    if issuer:
        one = [c for c in cands if c['name'] == issuer]
        if not one:
            raise ValueError('there is no source %s (Certificates → Sources)' % issuer)
        if not one[0]['fits']:
            raise ValueError('the source %s does not fit the template %s: %s' % (
                issuer, t['title'], one[0]['why']))
        pick = issuer
    else:
        good = [c['name'] for c in cands if c['fits']]
        if not good:
            raise ValueError('no source here fits the template %s%s' % (
                t['title'], ' - it needs an authority of acme\'s own (Certificates → Sources)'
                if t.get('eku_kinds') else ''))
        # the default source when it is of the kind the template prefers, else the first
        dflt = DF.default_issuer(store)
        same = [c['name'] for c in cands if c['fits'] and c['public'] == cands[0]['public']]
        pick = dflt['name'] if dflt and dflt['name'] in same else good[0]
    info = [i for i in iss if i['name'] == pick][0]
    rl = RM.rules(store)
    cfg = t['cfg']
    notes = []
    # the key types: the template's the source signs, none the company forbids
    kts = [k for k in cfg['key_types'] if k in info['key_types']]
    allowed = [k for k in kts if k not in rl['forbid_keys'] and
               (_rsa_bits(k) is None or _rsa_bits(k) >= rl['min_rsa'])]
    if allowed != kts:
        notes.append('key types the company\'s rules forbid are left out')
    # none left: a key type of the source's the rules allow (the shortest RSA too - hunt v1: an
    # RSA 2048 key was taken under "RSA 3072 at least" while the source signed EC P-256)
    kts = allowed or [k for k in info['key_types'] if k not in rl['forbid_keys'] and
                      (_rsa_bits(k) is None or _rsa_bits(k) >= rl['min_rsa'])][:1] or \
        [k for k in info['key_types'] if k not in rl['forbid_keys']][:1] or \
        info['key_types'][:1]
    kd = cfg['key_default'] if cfg['key_default'] in kts else kts[0]
    csr = bool(cfg['csr'] and info.get('csr'))
    make_key = bool(cfg['make_key'] or not csr)
    if cfg['csr'] and not csr:
        notes.append('%s signs only a key acme makes - no CSR' % info['name'])
    if not cfg['make_key'] and make_key:
        notes.append('acme makes the key: %s takes no CSR' % info['name'])
    wild = bool(cfg['wildcards'] and info.get('wildcards'))
    days = None
    if info.get('choose_days'):
        days = int(cfg.get('days_private') or 365)
        if info.get('public'):
            days = min(days, RM.limit_on(datetime.date.today()))
        if rl['max_days'] and days > int(rl['max_days']):
            days = int(rl['max_days'])
            notes.append('the validity is the company\'s longest: %d days' % days)
    pfx = bool(cfg['pfx'] and make_key and not rl['no_pfx'])
    if cfg['pfx'] and make_key and rl['no_pfx']:
        notes.append('no PFX with the key: the company\'s rules forbid it')
    approval = bool(cfg['approval'] or (rl['wildcards_approval'] and wild))
    most = int(cfg['max_names'])
    if rl['max_names'] and most > int(rl['max_names']):
        most = int(rl['max_names'])
    chal = ''
    if info.get('needs_validation'):
        chal = str(challenge or '').strip()
        if chal and not S.plugin_row(store, 'challenge', chal):
            raise ValueError('there is no validation %s (Certificates → Validation)' % chal)
        if not chal:
            row = DF.default_challenge(store)
            chal = row['name'] if row else ''
        if not chal:
            first = store.db.row('SELECT name FROM cert_challenges WHERE COALESCE(enabled, 1) = 1 '
                                 'ORDER BY name')
            chal = first['name'] if first else ''
    body = {'name': str(name or '').strip(), 'description': str(description or '').strip() or
            t['about'], 'enabled': True, 'issuer': info['name'], 'challenge': chal,
            'suffixes': list(suffixes or []), 'wildcards': wild, 'max_names': most,
            'make_key': make_key, 'csr': csr, 'key_types': kts, 'key_default': kd,
            'subject': {}, 'auto_renew': True, 'renew_days': None, 'days': days,
            'eku': list(cfg['eku']), 'approval': approval, 'owner': 'person', 'owner_team': '',
            'tags': [], 'teams': [], 'pfx': pfx}
    finds = RM.lint_settings(store, body, datetime.date.today(), bool(info.get('public')), rl=rl)
    if saved and body['suffixes']:
        # what saving it checks (reqprofiles.build_cfg: what fits together - a public CA and a
        # name never public, ...): said here as it would refuse it (hunt v2: the preview said
        # "complies" and "Make the profile" was refused)
        try:
            R.build_cfg(store, body)
        except (ValueError, LookupError, E.ApiError) as e:
            finds.append({'rule': 'fits', 'level': 'bad', 'from': '',
                          'said': getattr(e, 'message', None) or str(e)})
    status = 'bad' if any(f['level'] == 'bad' and not f['from'] for f in finds) else \
        'warn' if any(f['level'] in ('bad', 'warn') for f in finds) else 'ok'
    return {'template': t['id'], 'body': body, 'source': info['name'],
            'public': bool(info.get('public')), 'findings': finds, 'status': status,
            'sets': sets(body, bool(info.get('public'))), 'notes': notes,
            'needs_validation': bool(info.get('needs_validation'))}


def catalog(store):
    """Every template: what it is, what it sets, the sources that fit, and what the compliance
    check says of it with the best one."""
    iss = _issuers(store)
    out = []
    for t in TEMPLATES:
        srcs = sources_for(store, t, iss)
        one = {'id': t['id'], 'title': t['title'], 'icon': t['icon'], 'about': t['about'],
               'name': t['name'], 'sets': sets(t['cfg']), 'cfg': dict(t['cfg']), 'sources': srcs,
               'needs_own_ca': bool(t.get('eku_kinds')), 'prefer': t['prefer'],
               'available': any(s['fits'] for s in srcs)}
        if one['available']:
            try:
                got = build(store, t['id'], suffixes=['example.com'])
                one.update(status=got['status'], source=got['source'], public=got['public'],
                           findings=got['findings'], preview_sets=got['sets'])
            except (ValueError, LookupError, E.ApiError) as e:
                one.update(status='bad', findings=[{'rule': 'build', 'level': 'bad', 'from': '',
                                                    'said': getattr(e, 'message', None) or str(e)}])
        else:
            one['status'] = 'none'
        out.append(one)
    return out


def create(store, b, by):
    """A new request profile from a template: saved as every profile is (checked, a version
    of its own saying the template). A name taken is refused - nothing there changes."""
    b = b if isinstance(b, dict) else {}
    t = template(b.get('template'))
    name = str(b.get('name') or '').strip()
    if not name:
        raise ValueError('give the new profile a name')
    if R.profile_get(store, name):
        raise ValueError('there is a request profile called %s already - a template never '
                         'changes one; choose another name' % name)
    sufs = b.get('suffixes')
    if isinstance(sufs, str):
        sufs = [w for w in sufs.replace(',', ' ').split() if w]
    sufs = R.clean_suffixes(sufs or [])
    if not sufs:
        raise ValueError('say under which domains names may be asked for')
    got = build(store, t['id'], b.get('issuer'), b.get('challenge'), sufs, name,
                b.get('description'))
    if got['needs_validation'] and not got['body']['challenge']:
        raise ValueError('%s proves names: add a validation first (Certificates → Validation)'
                         % got['source'])
    body = dict(got['body'])
    if b.get('enabled') is not None:
        body['enabled'] = R._flag(b.get('enabled'), True)
    prof = R.save_profile(store, body, by, why='made from the template %s' % t['title'])
    return {'profile': prof, 'template': t['id'], 'findings': got['findings'],
            'notes': got['notes'], 'status': got['status']}


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------
@A.api('GET', '/api/reqprofiles/templates')
def _templates(h, s):
    return {'templates': catalog(h.store), 'can_change': s.get('role') == 'fulladmin'}


@A.api('POST', '/api/reqprofiles/template_preview')
def _preview(h, s):
    b = h.body()
    sufs = b.get('suffixes') or []
    if isinstance(sufs, str):
        sufs = [w for w in sufs.replace(',', ' ').split() if w]
    try:
        sufs = R.clean_suffixes(sufs)
        return build(h.store, b.get('template'), b.get('issuer'), b.get('challenge'), sufs,
                     b.get('name'), b.get('description'), saved=True)
    except ValueError as e:
        raise E.ApiError(400, str(e))


@A.api('POST', '/api/reqprofiles/from_template', 'fulladmin')
def _from_template(h, s):
    got = create(h.store, h.body(), A.who(s))
    got['message'] = 'the request profile %s was made from the template %s' % (
        got['profile']['name'], template(got['template'])['title'])
    return got
