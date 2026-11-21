# -*- coding: utf-8 -*-
"""
Request profiles, 1.0.138 (docs/request-profiles.md): what reqprofiles.py does not do itself.

    Versions (P1)       record(store, before, name, by, why) - every saved change is a new
                        version (table cert_req_profile_versions); versions(), diff(), restore();
                        current(store, name) - its number, stamped on what is asked for from it
    Compliance (P3)     report(store, at) - the profiles and the certificates asked for from them
                        against the CA/Browser Forum's schedule of the longest validity of a
                        public TLS certificate (ballot SC-081v3), the keys and algorithms, and
                        the company's own rules (rules() / save_rules())
    Dry run (P4)        dryrun(store, b) - what a profile would issue for these names or this
                        CSR, nothing kept or asked of a CA
    Ending (P5)         set_ends() / impact() - a profile that ends: not offered, its
                        certificates move to the successor at their next renewal
                        (migrate_on_renew, called by renewer.renew_cert)

Nothing of it runs until used: a profile without a base, never marked as ending, with no rule
set, works as before; its first version is written at its first change.
"""
from __future__ import annotations

import datetime
import json
import secrets
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.certs import reqprofiles as R

TABLE = 'cert_req_profile_versions'
META_RULES = 'certs:reqprofiles:rules'


def _low(v):
    return str(v or '').strip().lower()


# ---------------------------------------------------------------------------
# Versions (P1)
# ---------------------------------------------------------------------------
def _vrows(store, name=None):
    try:
        got = store.db.rows('SELECT * FROM %s ORDER BY version, created, id' % TABLE)
    except Exception:                                   # noqa: BLE001 - not made yet
        return []
    if name is None:
        return got
    return [r for r in got if _low(r.get('profile')) == _low(name)]


def snapshot(row):
    """A profile as a version keeps it: its name, words, whether offered, its own settings."""
    return {'name': row['name'], 'description': row.get('description') or '',
            'enabled': bool(row.get('enabled', 1)), 'config': R.own_of(row)}


def _snap_of(v):
    return {'name': v.get('name') or v.get('profile') or '',
            'description': v.get('description') or '', 'enabled': bool(v.get('enabled', 1)),
            'config': S.jload(v.get('config'), {}) or {}}


def flat(snap):
    """{key: value} of a version, as the diff compares it - an inherited field
    {'inherited': base}."""
    cfg = snap.get('config') or {}
    base = cfg.get('base') or ''
    inh = set(R.clean_inherit(cfg.get('inherit'))) if base else set()
    out = {'name': snap.get('name') or '', 'description': snap.get('description') or '',
           'enabled': bool(snap.get('enabled', True)), 'base': base,
           'inherit': sorted(inh)}
    for g, keys in R.INHERIT_GROUPS:
        if g.startswith('subject.'):
            f = g[8:]
            if g in inh:
                out[g] = {'inherited': base}
            else:
                one = (cfg.get('subject') or {}).get(f) or {}
                mode = one.get('mode') or 'off'
                out[g] = mode if mode == 'off' else '%s: %s' % (mode, one.get('value') or '')
            continue
        for k in keys:
            out[k] = {'inherited': base} if g in inh else cfg.get(k)
    ends = cfg.get('ends') or None
    out['ends'] = ends.get('successor') if isinstance(ends, dict) else None
    return out


def diff_snaps(a, b):
    """What changed from a to b: [{key, a, b, added, removed}] (added/removed: of a list)."""
    fa, fb = flat(a or {'config': {}}), flat(b or {'config': {}})
    out = []
    for k in fb:
        va, vb = fa.get(k), fb.get(k)
        if json.dumps(va, sort_keys=True) == json.dumps(vb, sort_keys=True):
            continue
        one = {'key': k, 'a': va, 'b': vb}
        if isinstance(va, list) and isinstance(vb, list):
            one['added'] = [x for x in vb if x not in va]
            one['removed'] = [x for x in va if x not in vb]
        out.append(one)
    return out


def record(store, before, name, by, why=''):
    """A profile was saved: a new version of it - none when nothing it keeps changed. The
    first change of a profile made before 1.0.138 writes it as it was first, as version 1."""
    now = R.profile_get(store, name)
    if not now:
        return None
    have = _vrows(store, name) or (_vrows(store, before['name']) if before else [])
    nxt = max([int(v.get('version') or 0) for v in have] or [0]) + 1
    if not have and before:
        _insert(store, before['name'], 1, snapshot(before), [], 'as it was before versions were '
                'kept', before.get('updated') or before.get('created') or time.time(),
                before.get('updated_by') or before.get('created_by') or '')
        have = [{'version': 1}]
        nxt = 2
        prev = snapshot(before)
    else:
        prev = _snap_of(have[-1]) if have else None
    snap = snapshot(now)
    changes = diff_snaps(prev, snap) if prev else []
    if prev is not None and not changes:
        return None
    _insert(store, now['name'], nxt, snap, [c['key'] for c in changes],
            why or ('added' if prev is None else ''), time.time(), by)
    return nxt


def _insert(store, profile, n, snap, changes, why, at, by):
    store.db.insert(TABLE, {'uid': secrets.token_hex(12), 'profile': profile, 'version': n,
                            'name': snap['name'], 'description': snap['description'],
                            'enabled': 1 if snap['enabled'] else 0,
                            'config': json.dumps(snap['config']), 'changes': json.dumps(changes),
                            'why': str(why or '')[:500], 'created': at,
                            'created_by': str(by or '')[:190]})


def current(store, name):
    """The version a profile is at: its newest - 1 for one never changed since 1.0.138."""
    if not name:
        return None
    got = [int(v.get('version') or 0) for v in _vrows(store, name)]
    return max(got) if got else 1


def currents(store):
    out = {}
    for v in _vrows(store):
        k = _low(v.get('profile'))
        out[k] = max(out.get(k, 0), int(v.get('version') or 0))
    for r in R.raw_rows(store):
        out.setdefault(_low(r['name']), 1)
    return out


def renamed(store, old, new):
    """A profile renamed: its versions, the profiles based on it, those it is the successor of."""
    for v in _vrows(store, old):
        store.db.update(TABLE, v['id'], {'profile': new})
    for r in R.raw_rows(store):
        own = R.own_of(r)
        hit = False
        if _low(own.get('base')) == _low(old):
            own['base'] = new
            hit = True
        ends = own.get('ends')
        if isinstance(ends, dict) and _low(ends.get('successor')) == _low(old):
            ends['successor'] = new
            hit = True
        if hit:
            store.db.update('cert_req_profiles', r['id'], {'config': json.dumps(own)})


def forget(store, name):
    for v in _vrows(store, name):
        store.db.run('DELETE FROM %s WHERE id = ?' % TABLE, (v['id'],))


def issued_from(store):
    """{profile lower: [(cert row, its portal meta)]} - the certificates asked for from each
    profile and still kept."""
    from acmelib.certs import portal as P
    certs = {r['id']: r for r in store.db.rows('SELECT * FROM certs')}
    out = {}
    for m in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (P.META + '%',)):
        try:
            cid = int(m['k'][len(P.META):])
            a = json.loads(m['v'] or '{}') or {}
        except (ValueError, TypeError):
            continue
        if isinstance(a, dict) and a.get('profile') and cid in certs:
            out.setdefault(_low(a['profile']), []).append((certs[cid], a))
    return out


def versions(store, name):
    """GET /api/reqprofiles/versions: every version, newest first - with what changed, and how
    many of the certificates kept were asked for from it."""
    r = R.profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    vs = _vrows(store, r['name'])
    counts = {}
    for _c, a in issued_from(store).get(_low(r['name']), []):
        n = int(a.get('profile_version') or 1)
        counts[n] = counts.get(n, 0) + 1
    out = []
    for v in vs:
        out.append({'version': int(v.get('version') or 0), 'at': v.get('created'),
                    'by': v.get('created_by') or '', 'why': v.get('why') or '',
                    'changes': S.jload(v.get('changes'), []) or [],
                    'certs': counts.get(int(v.get('version') or 0), 0),
                    'snapshot': _snap_of(v)})
    if not out:
        # never changed since versions are kept: as it is now, version 1 - not written
        out.append({'version': 1, 'at': r.get('updated') or r.get('created'),
                    'by': r.get('updated_by') or r.get('created_by') or '',
                    'why': 'as it was before versions were kept', 'changes': [],
                    'certs': counts.get(1, 0), 'snapshot': snapshot(r), 'unsaved': True})
    out.sort(key=lambda x: -x['version'])
    return {'profile': r['name'], 'current': out[0]['version'], 'versions': out}


def _snap_at(store, name, n):
    if n in (None, '', 'now'):
        r = R.profile_get(store, name)
        return snapshot(r) if r else None
    n = int(n)
    for v in _vrows(store, name):
        if int(v.get('version') or 0) == n:
            return _snap_of(v)
    if n == 1 and not _vrows(store, name):
        r = R.profile_get(store, name)
        return snapshot(r) if r else None
    return None


def diff(store, name, a, b):
    """GET /api/reqprofiles/diff: two versions side by side, field by field."""
    r = R.profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    sa, sb = _snap_at(store, r['name'], a), _snap_at(store, r['name'], b)
    if sa is None or sb is None:
        raise LookupError('there is no such version of %s' % r['name'])
    fa, fb = flat(sa), flat(sb)
    keys = list(fb.keys())
    return {'profile': r['name'], 'a': a, 'b': b,
            'rows': [{'key': k, 'a': fa.get(k), 'b': fb.get(k),
                      'same': json.dumps(fa.get(k), sort_keys=True) ==
                      json.dumps(fb.get(k), sort_keys=True)} for k in keys],
            'changes': diff_snaps(sa, sb)}


def restore(store, name, n, by):
    """POST /api/reqprofiles/restore: the profile as version n said - written as a new version
    (its name, and whether it ends, stay as they are now), checked as every save is."""
    r = R.profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    snap = _snap_at(store, r['name'], n)
    if snap is None:
        raise LookupError('there is no version %s of %s' % (n, r['name']))
    body = dict(snap['config'])
    body.pop('ends', None)
    body.update({'name': r['name'], 'old_name': r['name'], 'description': snap['description'],
                 'enabled': snap['enabled']})
    return R.save_profile(store, body, by, why='restored from version %d' % int(n))


# ---------------------------------------------------------------------------
# Compliance (P3)
# ---------------------------------------------------------------------------
# The longest a publicly trusted TLS server certificate may be valid, by the date it is issued:
# CA/Browser Forum Baseline Requirements 6.3.2 as ballot SC-081v3 (2025) changed it.
# A private CA (an authority of acme's own, AD CS, ...) is not bound by it.
CABF_SCHEDULE = (('2020-09-01', 398), ('2026-03-15', 200), ('2027-03-15', 100),
                 ('2029-03-15', 47))
MIN_RSA = 2048
SHA1_SIGS = ('sha1WithRSAEncryption', 'ecdsa-with-SHA1', 'dsaWithSHA1', 'sha1',
             '1.2.840.113549.1.1.5', '1.2.840.10045.4.1', '1.3.14.3.2.29', '1.2.840.10040.4.3')
RULE_KEYS = ('max_days', 'min_rsa', 'forbid_keys', 'wildcards_approval', 'no_pfx', 'max_names',
             'private_too')


def _day(v):
    if isinstance(v, datetime.date):
        return v
    if v in (None, ''):
        return datetime.date.today()
    try:
        return datetime.date.fromisoformat(str(v)[:10])
    except ValueError:
        raise ValueError('a date is YYYY-MM-DD')


def limit_on(d):
    """The longest validity (days) of a public TLS certificate issued on date d."""
    d = _day(d)
    most = 398
    for since, days in CABF_SCHEDULE:
        if d >= _day(since):
            most = days
    return most


def rules(store):
    """The company's own rules (none by default: nothing is checked beyond the CA/B Forum's)."""
    try:
        got = json.loads(store.get_meta(META_RULES) or '{}') or {}
    except ValueError:
        got = {}
    got = got if isinstance(got, dict) else {}
    return {'max_days': got.get('max_days') or None, 'min_rsa': int(got.get('min_rsa') or MIN_RSA),
            'forbid_keys': [k for k in got.get('forbid_keys') or [] if k in _key_types()],
            'wildcards_approval': bool(got.get('wildcards_approval')),
            'no_pfx': bool(got.get('no_pfx')), 'max_names': got.get('max_names') or None}


def _key_types():
    from acmelib.certs import schema
    return list(schema.KEY_TYPES)


def save_rules(store, b, by):
    b = b if isinstance(b, dict) else {}
    out = {'max_days': R._int(b.get('max_days'), 'the longest validity', 1, 36500),
           'min_rsa': int(b.get('min_rsa') or MIN_RSA),
           'forbid_keys': [k for k in _key_types() if k in (b.get('forbid_keys') or [])],
           'wildcards_approval': bool(b.get('wildcards_approval')),
           'no_pfx': bool(b.get('no_pfx')),
           'max_names': R._int(b.get('max_names'), 'names in one certificate', 1, 50)}
    if out['min_rsa'] not in (2048, 3072, 4096):
        raise ValueError('the shortest RSA key is 2048, 3072 or 4096 bits')
    store.set_meta(META_RULES, json.dumps(out))
    store.add_event('certificates', 'the rules of the request profiles changed by %s' % by, who=by)
    return rules(store)


def _f(rule, level, said, since=''):
    return {'rule': rule, 'level': level, 'said': said, 'from': since}


def _steps_from(today):
    """[(date, days)] of the schedule from today on - today's limit first."""
    out = [(today.isoformat(), limit_on(today))]
    for since, days in CABF_SCHEDULE:
        if _day(since) > today:
            out.append((since, days))
    return out


def _rsa_bits(kt):
    if str(kt or '').startswith('rsa-'):
        try:
            return int(str(kt).rsplit('-', 1)[1])
        except ValueError:
            return 0
    return None


def lint_settings(store, cfg, today, public, src_days=None, rl=None):
    """Findings of a profile's settings (or a dry run's): [{rule, level, said, from}]. `from`
    '' - now; a date - from then on."""
    rl = rl or rules(store)
    out = []
    days = cfg.get('days') or src_days
    if public:
        for since, most in _steps_from(today):
            if days and days > most:
                out.append(_f('cabf_days', 'bad', 'valid for %d days - a public TLS certificate '
                              'issued from %s is valid for at most %d days' % (days, since, most),
                              '' if since == today.isoformat() else since))
                break
        rd = cfg.get('renew_days')
        if rd:
            for since, most in _steps_from(today):
                if rd >= most:
                    out.append(_f('renew_days', 'warn', 'renewed %d days before the end - from %s '
                                  'a public certificate lasts at most %d days: it would be renewed '
                                  'again at once' % (rd, since, most),
                                  '' if since == today.isoformat() else since))
                    break
        if not days:
            nxt = [s for s in _steps_from(today)[1:]]
            out.append(_f('cabf_ca', 'info', 'the CA chooses the validity - it keeps to the '
                          'CA/Browser Forum\'s schedule by itself%s' % (
                              (' (at most %d days from %s)' % (nxt[0][1], nxt[0][0])) if nxt
                              else '')))
        if 'ed25519' in (cfg.get('key_types') or []):
            out.append(_f('key', 'bad', 'a public CA does not sign Ed25519 keys'))
    for kt in cfg.get('key_types') or []:
        bits = _rsa_bits(kt)
        if bits is not None and bits < MIN_RSA:
            out.append(_f('key', 'bad', 'an RSA key of %d bits - %d at least' % (bits, MIN_RSA)))
        elif bits is not None and bits < rl['min_rsa']:
            out.append(_f('rule_min_rsa', 'bad', 'an RSA key of %d bits - the company\'s rule '
                          'is %d at least' % (bits, rl['min_rsa'])))
        if kt in rl['forbid_keys']:
            out.append(_f('rule_keys', 'bad', 'the company\'s rules forbid the key type %s' % kt))
    if rl['max_days'] and days and days > rl['max_days']:
        out.append(_f('rule_max_days', 'bad', 'valid for %d days - the company\'s rule is %d '
                      'at most' % (days, rl['max_days'])))
    if rl['wildcards_approval'] and cfg.get('wildcards') and not cfg.get('approval'):
        out.append(_f('rule_wildcards', 'bad', 'wildcards issued at once - the company\'s rule '
                      'is that a profile with wildcards waits for approval'))
    if rl['no_pfx'] and cfg.get('pfx'):
        out.append(_f('rule_pfx', 'bad', 'a PFX with the key may be downloaded - the company\'s '
                      'rules forbid it'))
    if rl['max_names'] and (cfg.get('max_names') or 1) > rl['max_names']:
        out.append(_f('rule_names', 'bad', '%d names in one certificate - the company\'s rule is '
                      '%d at most' % (cfg.get('max_names') or 1, rl['max_names'])))
    return out


def _cert_days(info):
    try:
        return int(round((float(info['not_after']) - float(info['not_before'])) / 86400.0))
    except (TypeError, ValueError, KeyError):
        return None


def lint_cert(store, row, cfg, public, today, rl):
    """Findings of a certificate asked for from a profile: what it is now, and its renewal."""
    from acmelib.certs import pki
    from acmelib.certs import renewer
    out = []
    if not row.get('cert_pem'):
        return out
    try:
        info = pki.cert_info(row['cert_pem'])
    except Exception:                                   # noqa: BLE001
        return [_f('read', 'warn', 'the certificate could not be read')]
    alg = str(info.get('sig_alg') or '')
    if alg in SHA1_SIGS or 'sha1' in alg.lower():
        out.append(_f('sha1', 'bad', 'signed with SHA-1 (%s)' % alg))
    kt, bits = str(info.get('key_type') or ''), int(info.get('key_bits') or 0)
    if kt.startswith('rsa') and bits and bits < MIN_RSA:
        out.append(_f('key', 'bad', 'an RSA key of %d bits - %d at least' % (bits, MIN_RSA)))
    elif kt.startswith('rsa') and bits and bits < rl['min_rsa']:
        out.append(_f('rule_min_rsa', 'bad', 'an RSA key of %d bits - the company\'s rule is %d '
                      'at least' % (bits, rl['min_rsa'])))
    if kt.startswith('ec') and bits and bits < 256:
        out.append(_f('key', 'bad', 'an EC key of %d bits - 256 at least' % bits))
    days = _cert_days(info)
    if public and days:
        try:
            issued = datetime.datetime.utcfromtimestamp(float(info['not_before'])).date()
        except (TypeError, ValueError, KeyError, OverflowError):
            issued = today
        if days > limit_on(issued) + 1:
            out.append(_f('cabf_days', 'bad', 'valid for %d days - longer than the %d days a '
                          'public certificate issued on %s may be' % (days, limit_on(issued),
                                                               issued.isoformat())))
        try:
            due = datetime.datetime.utcfromtimestamp(
                float(row.get('not_after') or info['not_after']) -
                renewer.renew_days(row) * 86400).date()
        except (TypeError, ValueError, KeyError, OverflowError):
            due = today
        due = max(due, today)
        for since, most in [(due.isoformat(), limit_on(due))] + [
                (s, d) for s, d in CABF_SCHEDULE if _day(s) > due]:
            if days > most + 1:
                mine = bool(cfg.get('days'))
                out.append(_f('cabf_renew', 'bad' if mine else 'info',
                              ('renewed from %s with the %d days of its profile - a public '
                               'certificate is valid for at most %d days then' if mine else
                               'valid for %d days - renewed from %s the CA gives at most %d days'
                               ) % ((since, days, most) if mine else (days, since, most)),
                              since if _day(since) > today else ''))
                break
    if rl['max_days'] and days and days > rl['max_days'] + 1:
        out.append(_f('rule_max_days', 'bad', 'valid for %d days - the company\'s rule is %d at '
                      'most' % (days, rl['max_days'])))
    return out


def _is_public(store, issuer):
    irow, cls, info = R.issuer_info(store, issuer)
    return bool(info and info.get('public'))


def _src_days(store, issuer):
    irow = S.plugin_row(store, 'issuer', issuer) if issuer else None
    try:
        return int((S.jload((irow or {}).get('config'), {}) or {}).get('days') or 0) or None
    except (TypeError, ValueError):
        return None


def _status(findings, today, at):
    def bad_on(d):
        return any(f['level'] == 'bad' and (not f['from'] or _day(f['from']) <= d)
                   for f in findings)
    now, then = bad_on(today), bad_on(at)
    return 'bad' if now else 'ends' if then else 'ok'


def report(store, at=None):
    """GET /api/reqprofiles/compliance?at=YYYY-MM-DD: every profile and the certificates asked
    for from it - ok, bad (now) or ends (complies today, not on `at`)."""
    today = datetime.date.today()
    at = _day(at) if at else today
    if at < today:
        at = today
    rl = rules(store)
    by_prof = issued_from(store)
    profs, certs = [], []
    for r in R.rows(store):
        cfg = R.config_of(r)
        public = _is_public(store, cfg.get('issuer'))
        sd = None if cfg.get('days') else _src_days(store, cfg.get('issuer'))
        fs = lint_settings(store, cfg, today, public, sd, rl)
        profs.append({'name': r['name'], 'public': public, 'issuer': cfg.get('issuer') or '',
                      'days': cfg.get('days') or sd, 'findings': fs,
                      'status': _status(fs, today, at), 'ends': bool(cfg.get('ends')),
                      'enabled': bool(r.get('enabled', 1))})
        for c, a in by_prof.get(_low(r['name']), []):
            cp = _is_public(store, c.get('issuer'))
            cf = lint_cert(store, c, cfg, cp, today, rl)
            certs.append({'id': c['id'], 'name': c['name'], 'profile': r['name'],
                          'version': a.get('profile_version') or 1, 'public': cp,
                          'not_after': c.get('not_after'), 'findings': cf,
                          'status': _status(cf, today, at)})
    steps = []
    for since, most in _steps_from(today):
        d = _day(since)
        steps.append({'from': since, 'days': most, 'now': d == today,
                      'profiles': sum(1 for p in profs if _status(p['findings'], today, d) != 'ok'),
                      'certs': sum(1 for c in certs if _status(c['findings'], today, d) != 'ok')})
    count = {k: sum(1 for p in profs if p['status'] == k) for k in ('ok', 'bad', 'ends')}
    ccount = {k: sum(1 for p in certs if p['status'] == k) for k in ('ok', 'bad', 'ends')}
    return {'today': today.isoformat(), 'at': at.isoformat(), 'limit_now': limit_on(today),
            'limit_at': limit_on(at), 'schedule': [list(x) for x in CABF_SCHEDULE],
            'rules': rl, 'profiles': profs, 'certs': certs, 'steps': steps,
            'count': count, 'cert_count': ccount}


# ---------------------------------------------------------------------------
# A dry run (P4)
# ---------------------------------------------------------------------------
class _Quiet(object):
    """The store with its events kept quiet: a dry run asks the teams' limits, which note a
    refusal - nothing of a dry run is written."""
    def __init__(self, store):
        self._s = store

    def __getattr__(self, k):
        return getattr(self._s, k)

    def add_event(self, *_a, **_k):
        return None


def dryrun(store, b, owners=True):
    """POST /api/reqprofiles/dryrun {profile, names[] | csr | csr_b64, key_type, subject{},
    team, who}: what would be issued - nothing is asked of a CA, nothing is kept."""
    from acmelib.certs import compat
    from acmelib.certs import portal as P
    from acmelib.certs import teampolicy as TP
    from acmelib.certs import teams as T
    r = R.profile_get(store, b.get('profile'))
    if not r:
        raise LookupError('there is no request profile %s' % b.get('profile'))
    cfg = R.config_of(r)
    refused, checks = [], []
    csr = None
    if b.get('csr') or b.get('csr_b64'):
        info = R.read_csr(b)
        rv = R.csr_review(store, r, info)
        names, kt, cn, subj = rv['names'], rv['key_type'], rv['cn'], dict(rv['will'])
        subj.pop('CN', None)
        checks = rv['checks']
        refused += [c['said'] for c in rv['checks'] if c['ok'] is False]
        csr = {'key_bits': info.get('key_bits') or 0, 'sha256': info.get('sha256') or '',
               'subject_dn': info.get('subject_dn') or ''}
    else:
        if not cfg.get('make_key', True):
            refused.append('this profile takes a CSR: send yours')
        try:
            names = S.clean_names(b.get('names') or [])
        except ValueError as e:
            names = []
            refused.append(str(e))
        if not names and not refused:
            refused.append('which names?')
        if len(names) > (cfg.get('max_names') or 1):
            refused.append('this profile gives at most %d name(s) in one certificate'
                           % (cfg.get('max_names') or 1))
        for n in names:
            why = R.name_why(n, cfg)
            checks.append({'what': 'name', 'name': n, 'ok': not why, 'said': why or 'allowed'})
            if why:
                refused.append('%s: %s' % (n, why))
        kt = str(b.get('key_type') or cfg.get('key_default') or '')
        if kt not in (cfg.get('key_types') or []):
            refused.append('the key type is one of %s' % ', '.join(cfg.get('key_types') or []))
        try:
            subj = R.subject_for(cfg, b.get('subject') if isinstance(b.get('subject'), dict)
                                 else {})
        except ValueError as e:
            subj = {}
            refused.append(str(e))
        cn = names[0] if names else ''
    irow = S.plugin_row(store, 'issuer', cfg.get('issuer')) if cfg.get('issuer') else None
    _ir, icls, info = R.issuer_info(store, cfg.get('issuer'))
    probs = R.problems(store, cfg, r)
    refused += probs
    if names and irow and not probs:
        got = compat.check(store, names, irow, cfg.get('challenge') or None, {}, kt, '',
                           profile={'subject': dict(subj, CN=cn) if cn else subj})
        if got:
            refused.append(compat.words(got))
    if cfg.get('ends'):
        refused.append('it ends - the portal no longer offers it (its successor: %s)'
                       % (cfg['ends'] or {}).get('successor', ''))
    elif not r.get('enabled', 1):
        refused.append('it is switched off - the portal does not offer it')
    # whose it is
    mode = cfg.get('owner') or 'person'
    who = str(b.get('who') or '').strip()[:190]
    if mode == 'fixed':
        owner = cfg.get('owner_team') or ''
    elif mode == 'team':
        team = T.team_get(store, b.get('team')) if b.get('team') else None
        choices = R.pickable(cfg, [t['name'] for t in T.team_rows(store)])
        owner = team['name'] if team else ''
        if not owner:
            refused.append('choose a team: %s' % (', '.join(choices) or 'none'))
        elif owner not in choices:
            refused.append('the team %s may not ask from this profile' % owner)
    else:
        owner = who
    # who approves
    waits = bool(cfg.get('approval'))
    why = ['the profile waits for approval'] if waits else []
    held = P.holders(store, names, owner, waiting=False, unowned=True) if names else {}
    if held:
        waits = True
        why.append('its names are held by certificates of another owner: %s' % ', '.join(
            sorted(o or 'nobody' for o in held)) if owners else
            'its names are held by certificates of another owner')
    team_words = None
    if owner and T.team_get(store, owner):
        q = _Quiet(store)
        try:
            TP.need_request(q, owner, who or '?', profile=r['name'], issuer=cfg.get('issuer'),
                            validation=cfg.get('challenge') or None, names=names,
                            days=cfg.get('days'), key_type=kt, count=False)
        except E.ApiError as e:
            refused.append(str(e))
        rule = TP.request_waits(q, owner, waits, r['name'], names, cfg.get('days'), kt)
        if rule is not None:
            waits = bool(rule) or bool(held)
            team_words = TP.waits_words(q, {'owner': owner})
            if team_words:
                why.append(team_words)
    approver = ''
    if waits:
        approver = team_words or ('an approver of the owner of those names' if held else
                                  'the certificate administrators - on the portal, the members '
                                  'with the right approve of %s' % (owner or 'its owner'))
    sd = _src_days(store, cfg.get('issuer'))
    days = cfg.get('days') or sd
    public = bool(info and info.get('public'))
    today = datetime.date.today()
    eku = cfg.get('eku') or []
    return {'profile': r['name'], 'version': current(store, r['name']),
            'chain': R.chain_of(store, r['name']), 'fits': not refused, 'refused': refused,
            'checks': checks, 'cn': cn,
            'subject': [['CN', cn]] + [[k, subj[k]] for k, _w in R.SUBJECT_FIELDS if subj.get(k)],
            'sans': names, 'eku': eku,
            'eku_by': 'the CA' if public and irow and irow.get('kind') != 'internal_ca'
            else 'the profile',
            'key': {'type': kt, 'by': 'csr' if csr else 'acme', 'csr': csr},
            'issuer': cfg.get('issuer') or '', 'issuer_title': (info or {}).get('title') or '',
            'public': public, 'challenge': cfg.get('challenge') or '',
            'validity': {'days': days, 'by': 'profile' if cfg.get('days') else
                         'source' if sd else 'ca', 'limit': limit_on(today) if public else None,
                         'until': (time.time() + days * 86400) if days else None},
            'renew': {'auto': bool(cfg.get('auto_renew', True)), 'days': cfg.get('renew_days')},
            'approval': {'waits': waits, 'why': why, 'approver': approver},
            'owner': {'mode': mode, 'name': owner},
            'tags': ['portal'] + [x for x in cfg.get('tags') or [] if x != 'portal'],
            'pfx': bool(cfg.get('pfx')) and not csr,
            'findings': lint_settings(store, dict(cfg, key_types=[kt] if kt else []), today,
                                      public, None if cfg.get('days') else sd)}


# ---------------------------------------------------------------------------
# A profile that ends (P5)
# ---------------------------------------------------------------------------
def successor_of(store, r):
    """The profile its certificates move to: its successor - or the successor's, where that
    ends too (never round in a circle). None when there is none."""
    seen = set()
    while r is not None:
        ends = R.config_of(r).get('ends')
        if not ends:
            return r
        if _low(r['name']) in seen or len(seen) > R.BASE_DEPTH:
            return None
        seen.add(_low(r['name']))
        r = R.profile_get(store, (ends or {}).get('successor'))
    return None


def set_ends(store, name, successor, note, by):
    """POST /api/reqprofiles/ends {name, successor, note} - and {name, undo: true} takes it back."""
    r = R.profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    before = dict(r)
    own = R.own_of(r)
    if successor is None:
        if not own.get('ends'):
            raise ValueError('%s does not end' % r['name'])
        own.pop('ends', None)
        words = 'the request profile %s no longer ends (by %s): it is offered again' % (
            r['name'], by)
        why = 'no longer ends'
    else:
        s = R.profile_get(store, successor)
        if not s:
            raise ValueError('choose its successor among the request profiles')
        if s['id'] == r['id']:
            raise ValueError('a profile is not its own successor')
        if R.config_of(s).get('ends'):
            raise ValueError('%s ends itself - choose one that does not' % s['name'])
        own['ends'] = {'successor': s['name'], 'since': time.time(), 'by': str(by)[:190],
                       'note': str(note or '').strip()[:500]}
        words = 'the request profile %s ends (by %s): no longer offered, its certificates move ' \
                'to %s at their next renewal' % (r['name'], by, s['name'])
        why = 'ends: its successor is %s' % s['name']
    store.db.update('cert_req_profiles', r['id'], {'config': json.dumps(own),
                                                   'updated': time.time(),
                                                   'updated_by': str(by)[:190]})
    store.add_event('certificates', words, 'warn', who=by)
    record(store, before, r['name'], by, why)
    return R.public(store, R.profile_get(store, r['name']))


def move_plan(store, cert, scfg):
    """What moving one certificate to the successor's settings changes: (ok, why, changes,
    fields) - fields what is written to it."""
    from acmelib.certs import compat
    names = S.jload(cert.get('names'), []) or []
    changes = []
    bad = ['%s (%s)' % (n, R.name_why(n, scfg)) for n in names if R.name_why(n, scfg)]
    if bad:
        return False, 'names the successor does not give: %s' % ', '.join(bad), [], {}
    if len(names) > (scfg.get('max_names') or 1):
        return False, '%d names - the successor gives at most %d' % (
            len(names), scfg.get('max_names') or 1), [], {}
    given = bool(str(cert.get('csr_given') or '').strip())
    if given and not scfg.get('csr'):
        return False, 'issued for a CSR - the successor takes no CSR', [], {}
    if not given and not scfg.get('make_key', True):
        return False, 'its key is made by acme - the successor takes only a CSR', [], {}
    kt = cert.get('key_type') or ''
    if kt not in (scfg.get('key_types') or []):
        if given:
            return False, 'the key of its CSR (%s) is not one the successor takes' % kt, [], {}
        changes.append({'field': 'key_type', 'from': kt, 'to': scfg.get('key_default')})
        kt = scfg.get('key_default')
    fields = {'key_type': kt, 'issuer': scfg.get('issuer'),
              'challenge': scfg.get('challenge') or ''}
    if cert.get('issuer') != scfg.get('issuer'):
        changes.append({'field': 'issuer', 'from': cert.get('issuer') or '',
                        'to': scfg.get('issuer')})
    if (cert.get('challenge') or '') != (scfg.get('challenge') or ''):
        changes.append({'field': 'challenge', 'from': cert.get('challenge') or '',
                        'to': scfg.get('challenge') or ''})
    alt = cert.get('key_type_alt')
    if alt and alt not in (scfg.get('key_types') or []):
        fields['key_type_alt'] = None
        changes.append({'field': 'key_type_alt', 'from': alt, 'to': ''})
    pf = S.jload(cert.get('profile'), {}) or {}
    had = dict(pf)
    try:
        subj = R.subject_for(scfg, pf.get('subject') or {})
    except ValueError as e:
        return False, str(e), [], {}
    pf.pop('subject', None)
    if subj:
        pf['subject'] = subj
    pf.pop('eku', None)
    if scfg.get('eku'):
        pf['eku'] = list(scfg['eku'])
    pf.pop('days', None)
    if scfg.get('days'):
        pf['days'] = int(scfg['days'])
    for k in ('subject', 'eku', 'days'):
        if json.dumps(had.get(k), sort_keys=True) != json.dumps(pf.get(k), sort_keys=True):
            changes.append({'field': k, 'from': had.get(k), 'to': pf.get(k)})
    fields['profile'] = json.dumps(pf)
    if (cert.get('renew_days') or None) != (scfg.get('renew_days') or None):
        changes.append({'field': 'renew_days', 'from': cert.get('renew_days'),
                        'to': scfg.get('renew_days')})
    fields['renew_days'] = scfg.get('renew_days')
    tags = S.jload(cert.get('tags'), []) or []
    more = [t for t in scfg.get('tags') or [] if t not in tags]
    if more:
        fields['tags'] = json.dumps(tags + more)
        changes.append({'field': 'tags', 'from': tags, 'to': tags + more})
    irow = S.plugin_row(store, 'issuer', scfg.get('issuer')) if scfg.get('issuer') else None
    if not irow:
        return False, 'the successor\'s source %s is gone' % scfg.get('issuer'), [], {}
    sj = dict(subj)
    if cert.get('cn'):
        sj['CN'] = cert['cn']
    probs = compat.check(store, names, irow, scfg.get('challenge') or None, {}, kt, '',
                         profile={'subject': sj})
    if probs:
        return False, compat.words(probs), [], {}
    return True, '', changes, fields


def impact(store, name, successor=None):
    """GET /api/reqprofiles/impact?name=&successor=: the certificates asked for from it and what
    moving each to the successor would change - nothing written."""
    from acmelib.certs import renewer
    r = R.profile_get(store, name)
    if not r:
        raise LookupError('there is no request profile %s' % name)
    s = R.profile_get(store, successor) if successor else \
        successor_of(store, r) if R.config_of(r).get('ends') else None
    if successor and not s:
        raise LookupError('there is no request profile %s' % successor)
    out = []
    for c, a in issued_from(store).get(_low(r['name']), []):
        one = {'id': c['id'], 'name': c['name'], 'names': S.jload(c.get('names'), []) or [],
               'state': c.get('state') or '', 'owner': c.get('owner') or '',
               'version': a.get('profile_version') or 1, 'not_after': c.get('not_after'),
               'renews': (float(c['not_after']) - renewer.renew_days(c) * 86400)
               if c.get('not_after') else None}
        if s is not None:
            ok, why, changes, _f2 = move_plan(store, c, R.config_of(s))
            one.update(moves=ok, why=why, changes=changes)
        out.append(one)
    out.sort(key=lambda x: (x['renews'] is None, x['renews'] or 0))
    return {'profile': r['name'], 'successor': s['name'] if s is not None else '',
            'certs': out, 'moves': sum(1 for x in out if x.get('moves')),
            'stays': sum(1 for x in out if x.get('moves') is False)}


def migrate_on_renew(store, job, cert):
    """renewer.renew_cert, before a certificate already issued is renewed: asked for from a
    profile that ends, it takes its successor's settings now - the row written, its request
    noted as the successor's. The certificate (changed) - or None, nothing to do. Whatever
    goes wrong here, the renewal goes on as it would have."""
    try:
        return _migrate(store, job, cert)
    except Exception as e:                              # noqa: BLE001
        if job is not None:
            try:
                job.step('it could not move to the successor of its request profile: %s' % e,
                         'warn')
            except Exception:                           # noqa: BLE001
                pass
        return None


def _migrate(store, job, cert):
    from acmelib.certs import portal as P
    try:
        a = P.asker(store, cert['id'])
    except Exception:                                   # noqa: BLE001
        return None
    if not a.get('profile'):
        return None
    r = R.profile_get(store, a['profile'])
    if not r or not R.config_of(r).get('ends'):
        return None
    s = successor_of(store, r)
    if s is None or s['id'] == r['id']:
        return None
    ok, why, changes, fields = move_plan(store, cert, R.config_of(s))
    if not ok:
        if job is not None:
            job.step('its request profile %s ends, but it cannot move to %s: %s - renewed as it '
                     'is' % (r['name'], s['name'], why), 'warn')
        return None
    fields['updated'] = time.time()
    fields['updated_by'] = 'profile:%s' % s['name'][:180]
    store.db.update('certs', cert['id'], fields)

    def change(m):
        m['moved_from'] = {'profile': r['name'], 'version': m.get('profile_version') or 1,
                           'at': time.time()}
        m['profile'] = s['name']
        m['profile_version'] = current(store, s['name'])
        m['base_versions'] = [[b_, current(store, b_)] for b_ in R.chain_of(store, s['name'])[1:]]
        return m
    got = P.asker(store, cert['id'])
    store.set_meta(P.META + str(cert['id']), json.dumps(change(dict(got))))
    store.add_event('certificates', '%s moved from the request profile %s, which ends, to %s at '
                    'its renewal' % (cert['name'], r['name'], s['name']), who='acme')
    if job is not None:
        job.step('its request profile %s ends: it takes the settings of %s now (%s)' % (
            r['name'], s['name'], ', '.join(c['field'] for c in changes) or 'nothing else changes'))
    return S.cert_need(store, cert['id'])
