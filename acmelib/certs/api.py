# -*- coding: utf-8 -*-
"""
The JSON API of the certificate manager - every endpoint of the table in
docs/architecture.md, for the pages (through /admin/api.php) and for the
command line (engine cli_api, as a full administrator).

Roles: `readonly` looks; `certadmin` (called `tokenadmin` until the rename
is through) adds, imports, renews, deploys and exports certificates - no
private key; `fulladmin` does everything: the authorities, the issuers,
the challenges, the targets, acme's DNS server, private keys out.

A secret setting of a module is never sent back in clear: `config` holds
it as the engine's secret_shown has it - eight dots and its last two
characters for a full administrator, eight dots for anybody else, "" when
it is not set - and `secret_set` lists which are set. Saved as "" or as
what was shown (starting with a dot), the one kept stays.
"""
from __future__ import annotations

import base64
import inspect
import ipaddress
import json
import os
import re
import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S
from acmelib.certs import jobs, deployer, renewer, runtime, schema
from acmelib.certs import compat
from acmelib.certs import defaults as DF

# ---------------------------------------------------------------------------
# Who may
# ---------------------------------------------------------------------------
ROLE_WORDS = {'readonly': 'that account may only look',
              'certadmin': 'only a certificate administrator (or a full one) may do that',
              'fulladmin': 'only a full administrator may do that'}


def role_rank(role):
    """A role's rank, `certadmin` and `tokenadmin` being one role (renamed)."""
    got = E.ROLE_RANK.get(role)
    if got is None and role in ('certadmin', 'tokenadmin'):
        got = E.ROLE_RANK.get('certadmin') or E.ROLE_RANK.get('tokenadmin')
    return got or 0


def need(h, role='readonly'):
    """The session, when its role is at least `role` - else 401 / 403."""
    s = h.me('readonly')
    if role_rank(s.get('role')) < role_rank(role):
        raise E.ApiError(403, ROLE_WORDS.get(role, 'that account may not do that'))
    return s


def may(s, role):
    return role_rank(s.get('role')) >= role_rank(role)


def api(method, path, role='readonly'):
    """@api('POST', '/api/certs/save', 'certadmin') - a route with its role
    checked first; fn(h, s). A thing not found is 404, a module's refusal 400."""
    def wrap(fn):
        def run(h):
            s = need(h, role)
            try:
                # Who may do this with which certificate (teams.py, docs/teams.md).
                _lib('teams').guard(h, s, method, path)
                return fn(h, s)
            except LookupError as e:
                raise E.ApiError(404, str(e).strip('\'"'))
            except base.PluginError as e:
                raise E.ApiError(400, str(e), detail=e.detail or '')
            except ImportError as e:
                raise E.ApiError(503, 'a part of the certificate manager is missing: %s' % e)
        run.__name__ = fn.__name__
        run.__qualname__ = fn.__qualname__
        E.route(method, path)(run)
        return fn
    return wrap


def who(s):
    return str(s.get('name') or '?')


def _id(v, what='id'):
    if isinstance(v, bool):
        raise ValueError('%s is a number' % what)       # true is no id (1.0.45): it was 1
    try:
        got = int(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a number' % what)
    if got <= 0:
        raise ValueError('%s is a number' % what)
    return got


def _text(b, k, most=500, default=''):
    v = b.get(k, default)
    if v is None:
        return default
    if isinstance(v, (dict, list)):
        raise ValueError('%s is a piece of text' % k)
    v = str(v)
    if len(v) > most:
        raise ValueError('%s: %d characters at most' % (k, most))
    return v


def _flag(v, default=0):
    if v in (None, ''):
        return default
    if isinstance(v, str):
        return 1 if v.strip().lower() in ('1', 'true', 'yes', 'on') else 0
    return 1 if v else 0


def _list(v, what):
    if v in (None, ''):
        return []
    if isinstance(v, str):
        v = [x for x in re.split(r'[\s,;]+', v) if x]
    if not isinstance(v, list):
        raise ValueError('%s is a list' % what)
    return [str(x).strip() for x in v if str(x).strip()]


def _dict(v, what):
    if v in (None, ''):
        return {}
    if not isinstance(v, dict):
        raise ValueError('%s is an object' % what)
    return v


def _b64(v, what='data_b64'):
    if not v:
        raise ValueError('%s: no file was given' % what)
    try:
        return base64.b64decode(str(v), validate=False)
    except (ValueError, TypeError):
        raise ValueError('%s is not base64' % what)


def _wake():
    r = renewer.RENEWER[0]
    if r is not None:
        r.scan_soon()


def call(fn, *args, **kw):
    """A function of the PKI library called with the keywords it takes."""
    try:
        sig = inspect.signature(fn)
        if not any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values()):
            kw = {k: v for k, v in kw.items() if k in sig.parameters}
    except (TypeError, ValueError):
        pass
    return fn(*args, **kw)


def _lib(name):
    import importlib
    return importlib.import_module('acmelib.certs.' + name)


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
LIST_COLS = ('id', 'name', 'cn', 'names', 'key_type', 'issuer', 'challenge', 'auto_renew',
             'renew_days', 'reuse_key', 'serial', 'fingerprint', 'not_before', 'not_after',
             'issuer_dn', 'subject_dn', 'source', 'state', 'state_at', 'last_try', 'last_ok',
             'last_error', 'next_try', 'fails', 'version', 'tags', 'note', 'owner', 'created',
             'created_by', 'updated', 'updated_by', 'enabled', 'key_type_alt', 'alt_not_after',
             'alt_state', 'alt_version', 'alt_fingerprint', 'alt_serial', 'setup_due')


def cert_list(store, search='', state='', issuer='', tag='', owner='', page=1, per=50,
              s=None):
    where, args = [], []
    if s is not None:
        # Only the certificates of the teams this account may see (teams.py).
        sw, sa = _lib('teams').where(store, s, 'view')
        if sw:
            where.append(sw[len(' AND '):])
            args += list(sa)
    if search:
        # `field:value` as every list reads it (listsearch.py); words alone as before.
        from acmelib.certs import listsearch
        sq, sa = listsearch.where(search)
        if sq:
            where.append(sq)
            args += list(sa)
    if state:
        if state == 'expiring':
            t = time.time()
            where.append('not_after > ? AND not_after < ?')
            args += [t, t + int(E.CONFIG.get('certs_notify_days') or 14) * 86400]
        else:
            where.append('state = ?')
            args.append(state)
    if issuer:
        where.append('issuer = ?')
        args.append(issuer)
    if tag:
        # Escaped as LIKE wants it on every engine (1.0.48): MariaDB took the \\ of a \\u escape
        # for its own escape, and a tag of other letters was never found there.
        where.append("tags LIKE ? ESCAPE '!'")
        # (a `*` in a tag is the tag's own, not a wildcard)
        args.append('%' + ''.join('!' + c if c in '%_!' else c for c in json.dumps(tag)) + '%')
    if owner:
        where.append('LOWER(owner) = ?')
        args.append(owner.lower())
    w = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = int(store.db.value('SELECT COUNT(*) FROM certs' + w, tuple(args), 0) or 0)
    per = max(1, min(1000, int(per or 50)))
    page = max(1, int(page or 1))
    rows = store.db.rows('SELECT %s FROM certs%s ORDER BY %s LIMIT %d OFFSET %d' % (
        ', '.join(LIST_COLS), w, store.db.name_order(), per, (page - 1) * per), tuple(args))
    out = []
    for r in rows:
        one = S.cert_public(r)
        one['deploys'] = int(store.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                            (r['id'],), 0) or 0)
        one['deploys_failed'] = int(store.db.value(
            "SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ? AND state = 'failed'",
            (r['id'],), 0) or 0)
        # Deployments whose target is switched off (1.0.23): said in the list.
        one['deploys_target_off'] = int(store.db.value(
            'SELECT COUNT(*) FROM cert_deploys d JOIN cert_targets t ON t.name = d.target '
            'WHERE d.cert_id = ? AND t.enabled = 0', (r['id'],), 0) or 0)
        # Its latest job (1.0.26): the list's "Last job" opens it - a job's window
        # closed while it ran can be opened again from there.
        from acmelib.certs import portal as _portal
        one['last_job'] = _portal.last_job(store, r['id'])
        one['deploy_hold'] = S.deploy_hold(store, r['id']) is not None   # the console (1.0.88)
        out.append(one)
    return {'rows': out, 'total': total, 'page': page, 'per': per}


# span -> (bars, days a bar, what a bar is)
OV_SPANS = {'4w': (28, 1, 'day'), '12w': (12, 7, 'week'), '26w': (26, 7, 'week'),
            '52w': (52, 7, 'week'), '2y': (24, 30.4375, 'month'), '5y': (20, 91.3125, 'quarter')}


@api('GET', '/api/certs/overview')
def _overview(h, s):
    store = h.store
    t = time.time()
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    T = _lib('teams')
    sc_ = T.scope(store, s, 'view')
    sw, sa = T.where(store, s, 'view')
    by_state = renewer.counts(store) if sc_ is None else {}
    if sc_ is not None:
        # Scoped (teams.py): the numbers and the alerts of its own certificates
        # only - they said every team's, and the alerts named the others' (1.0.19).
        for r in store.db.rows('SELECT state, COUNT(*) AS n FROM certs WHERE 1 = 1%s GROUP BY '
                               'state' % sw, sa):
            k = r['state'] or 'new'
            by_state[k] = by_state.get(k, 0) + int(r['n'])
    soon = store.db.rows("SELECT id, name, not_after, state, auto_renew, issuer FROM certs "
                         "WHERE not_after IS NOT NULL AND state NOT IN ('revoked', 'disabled')%s "
                         "ORDER BY not_after LIMIT 10" % sw, sa)
    for r in soon:
        r['days_left'] = S.days_left(r, t)
    # The window of "When certificates run out" (1.0.77): chosen on the page - days for the
    # next 4 weeks, weeks up to a year, months for 2 years, quarters for 5.
    span = h.arg('span').strip() or '12w'
    count, size, unit = OV_SPANS.get(span, OV_SPANS['12w'])
    if span not in OV_SPANS:
        span = '12w'
    weeks = []
    for i in range(count):
        a, b = t + i * size * 86400, t + (i + 1) * size * 86400
        # Those renewed by hand apart, and the revoked and switched off not counted (1.0.51): the
        # grey part of the bars was never drawn, the revoked ones counted as running out.
        r = store.db.row("SELECT COUNT(*) AS n, SUM(CASE WHEN COALESCE(auto_renew, 0) = 0 THEN 1 "
                         "ELSE 0 END) AS m FROM certs WHERE not_after >= ? AND not_after < ? AND "
                         "state NOT IN ('revoked', 'disabled')" + sw, (a, b) + tuple(sa)) or {}
        weeks.append({'from': a, 'to': b, 'n': int(r.get('n') or 0), 'manual': int(r.get('m') or 0)})
    recent = jobs.job_rows(store, per=10, where=T.where(store, s, 'view', 'c.owner'))['rows']
    alerts = renewer.alerts(store)
    if sc_ is not None:
        mine = {r['id'] for r in store.db.rows('SELECT id FROM certs WHERE 1 = 1' + sw, sa)}
        deps = {r['id']: r['cert_id'] for r in store.db.rows('SELECT id, cert_id FROM cert_deploys')}

        def _mine(a):
            if a.get('cert_id') is not None:            # a test's: its certificate (1.0.79)
                return int(a['cert_id']) in mine
            kind, _, ident = str(a.get('key') or '').partition(':')
            try:
                ident = int(ident)
            except ValueError:
                return False
            return (deps.get(ident) if kind == 'cert-deploy' else ident) in mine
        alerts = [a for a in alerts if _mine(a)]
    lead = renewer.leader(store)
    DF.ensure(store)
    di = DF.default_issuer(store)
    dc = DF.default_challenge(store, di) if di else None
    dt, dca = DF.default_target(store), DF.default_ca(store)
    return {'defaults': {'issuer': di['name'] if di else '', 'challenge': dc['name'] if dc else '',
                         'target': dt['name'] if dt else '', 'ca': dca['name'] if dca else '',
                         'ca_id': int(dca['id']) if dca else None},
            'contact_missing': DF.contact_missing(store),
            'by_state': by_state, 'total': sum(by_state.values()), 'soonest': soon,
            # how many renew by themselves (1.0.52): Settings → Certificates said 0 always
            'auto_renew': int(store.db.value("SELECT COUNT(*) FROM certs WHERE COALESCE(auto_renew, "
                                             "0) <> 0 AND state NOT IN ('revoked', 'disabled')"
                                             + sw, tuple(sa), 0) or 0),
            'expiring': int(store.db.value('SELECT COUNT(*) FROM certs WHERE not_after > ? AND '
                                           'not_after < ?' + sw, (t, t + days * 86400) + tuple(sa),
                                           0) or 0),
            'expired': int(store.db.value("SELECT COUNT(*) FROM certs WHERE not_after < ? AND "
                                          "state NOT IN ('revoked', 'disabled')" + sw,
                                          (t,) + tuple(sa), 0) or 0),
            'deploys_failed': int(store.db.value(
                "SELECT COUNT(*) FROM cert_deploys d JOIN certs c ON c.id = d.cert_id WHERE "
                "d.state = 'failed'" + T.where(store, s, 'view', 'c.owner')[0],
                tuple(sa), 0) or 0),
            'weeks': weeks, 'span': span, 'unit': unit, 'jobs': recent, 'running': len(jobs.RUNNING),
            'leader': lead, 'last_scan': S.jload(store.get_meta('certs:last_scan'), None),
            'alerts': alerts[:50], 'notify_days': days,
            'states': schema.STATES, 'key_types': list(schema.KEY_TYPES)}


@api('GET', '/api/certs')
def _certs(h, s):
    return cert_list(h.store, h.arg('search').strip(), h.arg('state').strip(),
                     h.arg('issuer').strip(), h.arg('tag').strip(), h.arg('owner').strip(),
                     h.num('page', 1, 1), h.num('per', 50, 1, 1000), s=s)


def cert_one(store, ref, full=False):
    row = S.cert_need(store, ref)
    out = S.cert_public(row, full=True)
    versions = [S.version_public(v) for v in store.db.rows(
        'SELECT * FROM cert_versions WHERE cert_id = ? ORDER BY version DESC', (row['id'],))]
    deps = [S.deploy_public(store, d, full) for d in deployer.deploys_of(store, row['id'],
                                                                          enabled=False)]
    js = jobs.job_rows(store, cert_id=row['id'], per=20)['rows']
    if row.get('cert_pem'):
        try:
            out['info'] = S.info_of(row['cert_pem'])
        except Exception as e:                          # noqa: BLE001
            out['info'] = {'error': str(e)}
    # A dual certificate: both, side by side - the main one and its twin.
    dual_ok = bool(row.get('key_type_alt')) and S.issuer_dual(store, row.get('issuer'), row) \
        if row.get('issuer') else bool(row.get('key_type_alt'))
    out['variants'] = [_variant_view(row, '')]
    if row.get('key_type_alt') or row.get('alt_cert_pem'):
        out['variants'].append(_variant_view(row, 'alt'))
    out['dual_source'] = dual_ok
    out['due'] = renewer.due_why(row, dual=dual_ok)
    out['busy'] = jobs.cert_busy(store, row['id'])
    out['revoke_no'] = revocable(store, row)
    hold = S.deploy_hold(store, row['id'])
    out['deploy_hold'] = dict(hold, now=S.deploy_held(store, row)) if hold else None
    return {'cert': out, 'versions': versions, 'deploys': deps, 'jobs': js}


def _variant_view(row, variant):
    """One of a dual certificate's two, as the page shows it side by side."""
    p = 'alt_' if variant == 'alt' else ''
    pem = row.get(p + 'cert_pem')
    out = {'variant': variant or 'main',
           'key_type': row.get('key_type_alt' if variant == 'alt' else 'key_type') or '',
           'version': row.get(p + 'version'), 'serial': row.get(p + 'serial'),
           'fingerprint': row.get(p + 'fingerprint'), 'not_before': row.get(p + 'not_before'),
           'not_after': row.get(p + 'not_after'), 'issuer_dn': row.get(p + 'issuer_dn'),
           'has_key': bool(row.get(p + 'key_sealed')), 'issued': bool(pem),
           'days_left': S.days_left({'not_after': row.get(p + 'not_after')}),
           'ari': S.jload(row.get(p + 'ari'), {}) or {}}
    out['family'] = S.key_family(out['key_type'])
    if variant == 'alt':
        out.update(state=row.get('alt_state') or ('ok' if pem else 'new'),
                   error=row.get('alt_error') or '', next_try=row.get('alt_next_try'),
                   fails=int(row.get('alt_fails') or 0))
    else:
        out.update(state=row.get('state') or 'new', error=row.get('last_error') or '',
                   next_try=row.get('next_try'), fails=int(row.get('fails') or 0))
    if pem:
        try:
            info = S.info_of(pem)
            out['info'] = {k: info.get(k) for k in ('key_type', 'key_bits', 'sig_alg',
                                                     'issuer_cn', 'subject_dn', 'names', 'sha1',
                                                     'sha256') if k in info}
            out['key_type'] = out['key_type'] or info.get('key_type') or ''
        except Exception as e:                          # noqa: BLE001
            out['info'] = {'error': str(e)}
    return out


def key_type_alt_of(v, key_type):
    """The twin's key type as saved: '' (none) or a key type of another kind than
    the main one - ECDSA beside RSA, RSA beside ECDSA."""
    kt = str(v or '').strip().lower()
    if kt in ('', 'none', 'no', 'off', '-', '0'):
        return ''
    if kt not in schema.KEY_TYPES:
        raise ValueError('the twin\'s key type is one of %s, or none' % ', '.join(schema.KEY_TYPES))
    if S.key_family(kt) == S.key_family(key_type):
        raise ValueError('the twin needs another kind of key than %s (ECDSA beside RSA, or RSA '
                         'beside ECDSA)' % key_type)
    return kt


@api('GET', '/api/certs/one')
def _cert_one(h, s):
    return cert_one(h.store, h.arg('id') or h.arg('name'), may(s, 'fulladmin'))


KEEP_STATES = ('revoked', 'pending-approval', 'declined', 'pending', 'deleting', 'revoke-failed',
               'held')


def cert_save(store, b, by, full=False):
    t = time.time()
    ident = b.get('id')
    row = S.cert_need(store, _id(ident)) if ident not in (None, '', 0) else None
    given = b.get('name') if 'name' in b or not row else row['name']
    if not row and not str(given or '').strip():
        # None said: made from its first name, safe (a wildcard as "wildcard.").
        first_ = (_list(b.get('names'), 'names') or ['certificate'])[0]
        given = S.safe_name(re.sub(r'^\*\.', 'wildcard.', first_), _names_in(store, 'certs'))
    name = S.clean_name(given, 'the certificate\'s name')
    other = store.db.row('SELECT id FROM certs WHERE name = ?', (name,))
    if other and (not row or other['id'] != row['id']):
        raise ValueError('there is a certificate called %s already' % name)
    fields = {'name': name}
    if 'names' in b or not row:
        names = S.clean_names(b.get('names'))
        if not names:
            raise ValueError('a certificate needs at least one name')
        fields['names'] = json.dumps(names)
        fields['cn'] = names[0]
    if 'key_type' in b or not row:
        kt = str(b.get('key_type') or 'ec-256')
        if kt not in schema.KEY_TYPES:
            raise ValueError('the key type is one of %s' % ', '.join(schema.KEY_TYPES))
        fields['key_type'] = kt
    if 'key_type_alt' in b or (row and 'key_type' in fields and row.get('key_type_alt')):
        kta = key_type_alt_of(b.get('key_type_alt', (row or {}).get('key_type_alt')),
                              fields.get('key_type') or (row or {}).get('key_type') or 'ec-256')
        fields['key_type_alt'] = kta
        if row and kta != (row.get('key_type_alt') or ''):
            # Another twin (or none): the one it had is no longer current - the next look
            # issues the new one; versions keep the old.
            fields.update(S.ALT_CLEAR)
    if not row:
        # Not said at all (not said empty): Let's Encrypt first (defaults.py),
        # and an ACME issuer's names proved by this server's HTTP-01 unless a
        # validation is said.
        di = DF.default_issuer(store) if 'issuer' not in b else \
            S.plugin_row(store, 'issuer', str(b.get('issuer') or '').strip())
        if di and 'issuer' not in b:
            b = dict(b, issuer=di['name'])
        if di and 'challenge' not in b and not b.get('challenge_map'):
            dc = DF.default_challenge(store, di)
            if dc:
                b = dict(b, challenge=dc['name'])
    if 'issuer' in b or not row:
        iss = str(b.get('issuer') or '').strip()
        if iss and not S.plugin_row(store, 'issuer', iss):
            raise ValueError('there is no issuer %s' % iss)
        if iss:
            iss = S.plugin_row(store, 'issuer', iss)['name']
        fields['issuer'] = iss
        if row and row.get('issuer_ref') and iss != (row.get('issuer') or ''):
            # The source's own id of it means nothing to another source.
            fields['issuer_ref'] = None
    if 'challenge' in b or not row:
        ch = str(b.get('challenge') or '').strip()
        if ch and not S.plugin_row(store, 'challenge', ch):
            raise ValueError('there is no challenge %s' % ch)
        fields['challenge'] = S.plugin_row(store, 'challenge', ch)['name'] if ch else ''
    if 'challenge_map' in b:
        cmap = {}
        for k, v in _dict(b.get('challenge_map'), 'challenge_map').items():
            k = str(k).strip().lower().rstrip('.')
            v = str(v or '').strip()
            if not k or not v:
                continue
            if not re.match(r'^(\*\.|\.)?[a-z0-9_.-]{1,253}\Z', k):
                raise ValueError('%r is not a name or a pattern of names' % k)
            if not S.plugin_row(store, 'challenge', v):
                raise ValueError('there is no challenge %s (for %s)' % (v, k))
            cmap[k] = v
        fields['challenge_map'] = json.dumps(cmap)
    elif not row:
        fields['challenge_map'] = '{}'
    if 'auto_renew' in b or not row:
        fields['auto_renew'] = _flag(b.get('auto_renew'), 1)
        if fields['auto_renew'] and row and row.get('state') in ('pending-approval', 'declined'):
            fields['auto_renew'] = 0            # as Renew by itself refuses it (1.0.45)
    if 'renew_days' in b or not row:
        rd = b.get('renew_days')
        if rd in (None, '', 0, '0'):
            fields['renew_days'] = None
        else:
            rd = int(rd)
            if not 1 <= rd <= 3650:
                raise ValueError('renew_days: 1 to 3650')
            fields['renew_days'] = rd
    if 'reuse_key' in b or not row:
        fields['reuse_key'] = _flag(b.get('reuse_key'), 0)
    if 'profile' in b or 'cn' in b or 'san_other' in b or not row:
        prof = _dict(b.get('profile'), 'profile') if 'profile' in b or not row else \
            (S.jload(row.get('profile'), {}) or {})
        # The common name of its own (profile.subject.CN) and the e-mail and URI
        # subjectAltNames (profile.san_other) - given there, or as cn / san_other.
        if 'cn' in b:
            prof['subject'] = dict(_dict(prof.get('subject'), 'profile.subject'),
                                   CN=str(b.get('cn') or '').strip())
        if 'san_other' in b:
            prof['san_other'] = b.get('san_other')
        subj = _dict(prof.get('subject'), 'profile.subject') if prof.get('subject') else {}
        if 'CN' in subj:
            cnv = str(subj.get('CN') or '').strip()
            if len(cnv) > 64:
                raise ValueError('the common name is 64 characters at most')
            if cnv:
                subj['CN'] = cnv
            else:
                subj.pop('CN')
            prof['subject'] = subj
        if prof.get('san_other') not in (None, '', []):
            prof['san_other'] = S.clean_sans(prof.get('san_other'))
        else:
            prof.pop('san_other', None)
        old_over = (S.jload((row or {}).get('profile'), {}) or {}).get('over') if row else None
        if prof.get('over') or (old_over and not full):
            # A certificate's own settings of its source and validations (1.0.24); where
            # a file is written only a full administrator sets (1.0.26).
            iss_ = fields.get('issuer') if 'issuer' in fields else (row or {}).get('issuer')
            ch_ = fields.get('challenge') if 'challenge' in fields else (row or {}).get('challenge')
            cm_ = S.jload(fields['challenge_map'], {}) if 'challenge_map' in fields else \
                (S.jload((row or {}).get('challenge_map'), {}) or {})
            used = set([ch_] if ch_ else []) | set((cm_ or {}).values())
            prof['over'] = S.clean_over(store, prof.get('over'), iss_, used, full=full,
                                        old=old_over)
            if not prof['over']:
                prof.pop('over')
        else:
            prof.pop('over', None)
        if len(json.dumps(prof)) > 20000:
            raise ValueError('the profile is too big')
        fields['profile'] = json.dumps(prof)
        if subj.get('CN'):
            fields['cn'] = subj['CN']
        elif 'names' not in fields and row:
            fields['cn'] = (S.jload(row.get('names'), []) or [row.get('cn')])[0]
    if 'tags' in b or not row:
        fields['tags'] = json.dumps(_tags_of(b))
    if 'note' in b or not row:
        fields['note'] = _text(b, 'note', 4000)
    if 'owner' in b or not row:
        fields['owner'] = _text(b, 'owner', 190).strip()
    if row and row.get('setup_due') and _flag(b.get('setup_done'), 0):
        # Imported from a source, its set-up gone through in the wizard.
        fields['setup_due'] = 0
    if 'enabled' in b:
        fields['enabled'] = _flag(b.get('enabled'), 1)
        if row and row.get('state') in KEEP_STATES:
            # Switched off and on again, a revoked certificate came back "valid", and a
            # request not approved (or declined) "not issued yet" - issued by itself,
            # past its approval (1.0.19). Their state stays; `enabled` says off.
            pass
        elif row and not fields['enabled']:
            fields['state'] = 'disabled'
        elif row and row.get('state') == 'disabled':
            ended = row.get('not_after') and float(row['not_after']) < time.time()
            fields['state'] = ('expired' if ended else 'ok') if row.get('cert_pem') else 'new'
    # What fits together (acmelib/certs/compat.py): the names, the source, each name's
    # validation, the key type and the twin - refused here, in the words of the problem.
    if not row or any(k in b for k in ('names', 'issuer', 'challenge', 'challenge_map',
                                       'key_type', 'key_type_alt', 'profile', 'cn',
                                       'san_other')):
        cur = dict(row or {})
        cur.update(fields)
        if cur.get('issuer'):
            probs = compat.check_cert(store, cur)
            if probs:
                raise E.ApiError(400, compat.words(probs), detail=json.dumps(probs)[:20000])
    moved = row is not None and 'issuer' in fields and \
        (fields['issuer'] or '') != (row.get('issuer') or '')
    if moved and not fields['issuer']:
        # Moved to by hand (1.0.69): renewed by importing a new one - nothing asks a source,
        # nothing proves its names. Its deployments, tests and versions stay as they are.
        fields.update({'auto_renew': 0, 'challenge': '', 'challenge_map': '{}', 'source': 'import',
                       'next_try': None, 'fails': 0, 'last_error': None, 'issuer_ref': None})
        if row.get('state') in ('failed', 'held'):
            fields['state'] = 'ok' if row.get('cert_pem') else 'new'
    elif moved:
        fields['source'] = 'issuer'
        # the old source's wait after a failure not carried over (1.0.77)
        fields.update({'next_try': None, 'fails': 0, 'last_error': None})
        if row.get('state') == 'failed':
            fields['state'] = 'ok' if row.get('cert_pem') else 'new'
    fields['updated'], fields['updated_by'] = t, str(by)[:190]
    if row:
        store.db.update('certs', row['id'], fields)
        if moved:
            # The version in use came from the old source (1.0.77): the new one cannot revoke it.
            if row.get('issuer'):          # from by hand: its imported version says so itself
                store.set_meta('cert:moved:%s' % row['id'], str(int(row.get('version') or 0)))
            store.add_event('certificates', 'certificate %s moved from %s to %s by %s' % (
                name, row.get('issuer') or 'by hand', fields['issuer'] or 'by hand', by), who=by)
        else:
            store.add_event('certificates', 'certificate %s changed by %s' % (name, by), who=by)
        ident = row['id']
    else:
        # "Add only" (1.0.26): kept, not issued by itself - Issue now issues it.
        fields.update({'state': 'held' if _flag(b.get('hold'), 0) and fields.get('issuer')
                       else 'new', 'state_at': t, 'version': 0, 'fails': 0, 'source':
                       'issuer' if fields.get('issuer') else 'manual', 'created': t,
                       'created_by': str(by)[:190], 'enabled': fields.get('enabled', 1),
                       'ari': '{}'})
        ident = store.db.insert('certs', fields)
        store.add_event('certificates', 'certificate %s added by %s' % (name, by), who=by)
    _wake()
    return ident


@api('POST', '/api/certs/save', 'certadmin')
def _cert_save(h, s):
    return {'id': cert_save(h.store, h.body(), who(s), full=may(s, 'fulladmin'))}


def cert_auto(store, ref, on, by):
    """Renewal by itself switched on or off - nothing else touched: the
    certificate stays valid and deployed, it is just not renewed (or is again)."""
    row = S.cert_need(store, ref)
    on = 1 if on else 0
    if on and not row.get('issuer'):
        raise ValueError('%s has no source acme could renew it from - it is renewed by '
                         'importing a new one' % row['name'])
    if on and row.get('state') == 'revoked':
        raise ValueError('%s is revoked - issue a new one first' % row['name'])
    if on and row.get('state') in ('pending-approval', 'declined'):
        # Asked for on the portal and not approved (1.0.19): renewed by itself, the
        # renewer issued it as one "not issued yet" - past the approval, or a decline.
        raise ValueError('%s has not been approved' % row['name'])
    if int(row.get('auto_renew') or 0) != on:
        store.db.update('certs', row['id'], {'auto_renew': on, 'updated': time.time(),
                                             'updated_by': str(by)[:190]})
        store.add_event('certificates', ('%s is renewed by itself again (switched on by %s)' if on
                                         else '%s is no longer renewed by itself (switched off by %s)')
                        % (row['name'], by), who=by)
        _wake()
    return {'id': row['id'], 'auto_renew': on,
            'said': ('%s will be renewed by itself' if on else
                     '%s will not be renewed by itself - it stays valid and deployed')
            % row['name']}


@api('POST', '/api/certs/auto', 'certadmin')
def _cert_auto(h, s):
    b = h.body()
    return cert_auto(h.store, _id(b.get('id')), _flag(b.get('auto_renew'), 1), who(s))


@api('POST', '/api/certs/compat')
def _cert_compat(h, s):
    """What fits: {names, issuer, challenge, challenge_map, key_type, key_type_alt} ->
    {fits, problems, source, names, validations, key_types, twin} (compat.options) -
    for the wizard, which greys what does not fit with the reason. Read-only."""
    b = h.body()
    names = b.get('names') or []
    if isinstance(names, str):
        names = [n for n in re.split(r'[\s,;]+', names) if n]
    if not isinstance(names, list) or len(names) > 200:
        raise ValueError('names: a list of at most 200')
    cmap = _dict(b.get('challenge_map'), 'challenge_map') if b.get('challenge_map') else {}
    prof = _dict(b.get('profile'), 'profile') if b.get('profile') else {}
    if prof.get('san_other'):
        # as typed: each checked by itself, the bad ones said by name
        good, bad = [], {}
        for x in prof['san_other'] if isinstance(prof['san_other'], list) else []:
            try:
                good.extend(S.clean_sans([x]))
            except ValueError as e:
                bad[str(x)] = str(e)
        prof['san_other'] = good
    else:
        bad = {}
    out = compat.options(h.store, [str(n) for n in names], str(b.get('issuer') or '').strip()
                         or None, str(b.get('challenge') or '').strip() or None, cmap,
                         str(b.get('key_type') or 'ec-256'), str(b.get('key_type_alt') or ''),
                         profile=prof)
    out['san_bad'] = bad
    return out


def _truthy(v):
    return str(v).strip().lower() in ('1', 'true', 'yes', 'on')


def field_shown(f, values, fields=None):
    """Whether a field is in use with these values - its show_if met, as the page
    draws it (1.0.21): a required field of a part switched off (a Windows role
    not chosen) is not asked for."""
    cond = f.get('show_if')
    if not isinstance(cond, dict):
        return True
    for k, want in cond.items():
        want = want if isinstance(want, (list, tuple)) else [want]
        have = values.get(k)
        ok = False
        for w in want:
            if isinstance(w, bool) or isinstance(have, bool):
                ok = _truthy(w) == _truthy(have) if have is not None else (w is False)
            else:
                ok = str(w) == str('' if have is None else have)
            if ok:
                break
        if not ok:
            return False
    return True


def cert_drop(store, row, by):
    """A certificate gone from acme: its deployments, versions, finished jobs and
    what the portal kept of who asked for it (nothing on the targets, nothing at the CA)."""
    db = store.db
    db.run('DELETE FROM cert_checks WHERE cert_id = ?', (row['id'],))
    db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (row['id'],))
    db.run('DELETE FROM cert_versions WHERE cert_id = ?', (row['id'],))
    # Its jobs that are over go with it (1.0.19); one still at work stays until it ends.
    db.run("DELETE FROM cert_jobs WHERE cert_id = ? AND state NOT IN ('queued', 'running')",
           (row['id'],))
    db.run('DELETE FROM certs WHERE id = ?', (row['id'],))
    # Who asked for it on the portal (portal.META) goes with it (1.0.19): kept, a
    # certificate given the same id later (MariaDB counts from the highest one left
    # after a restart) was that person's - their mail, their profile, its PFX.
    db.run('DELETE FROM meta WHERE k = ?', ('certs:portal:%d' % int(row['id']),))
    db.run('DELETE FROM meta WHERE k = ?', ('cert:moved:%d' % int(row['id']),))
    db.run('DELETE FROM meta WHERE k = ?', (S.HOLD_KEY % int(row['id']),))
    store.add_event('certificates', 'certificate %s deleted by %s' % (row['name'], by),
                    'warn', who=by)


def revocable(store, row):
    """'' when acme can revoke the certificate at its CA, else why not (1.0.21)."""
    if not row.get('cert_pem'):
        return 'it has not been issued'
    # ...but not its twin (1.0.80): its revoke failed and could not be asked again here
    if row.get('state') == 'revoked' and row.get('alt_state') != 'revoke-failed':
        return 'it is revoked already'
    if row.get('state') == 'deleting':
        return 'it is being revoked now'
    irow = S.plugin_row(store, 'issuer', row.get('issuer')) if row.get('issuer') else None
    if not irow:
        return 'it has no source acme speaks to'
    moved_at = str(store.get_meta('cert:moved:%s' % row['id']) or '')
    if moved_at.isdigit() and int(row.get('version') or 0) <= int(moved_at):
        return 'the one in use is from its source before it was moved - %s did not issue it' \
            % row.get('issuer')
    cur = store.db.row("SELECT why FROM cert_versions WHERE cert_id = ? AND version = ? AND "
                       "COALESCE(variant, '') = ''", (row['id'], int(row.get('version') or 0)))
    if cur and cur.get('why') in ('import', 'csr') and not row.get('issuer_ref'):
        # Imported (or from a CSR) and moved to a source since (1.0.69): not issued by it.
        return 'the one in use was imported, not issued by %s - only its own CA could revoke it' \
            % row.get('issuer')
    if str(irow.get('kind') or '') == 'selfsigned':
        return 'a self-signed certificate has no CA to revoke it at'
    # a source that cannot revoke at all (1.0.51): Revoke was offered and its job failed
    cls = S.row_class('issuer', irow)
    if cls is not None and getattr(cls, 'revoke', None) is getattr(base.Issuer, 'revoke', None):
        return '%s cannot revoke a certificate' % (getattr(cls, 'title', '') or irow.get('kind'))
    return ''


@api('POST', '/api/certs/delete', 'certadmin')
def _cert_delete(h, s):
    b = h.body()
    row = S.cert_need(h.store, _id(b.get('id')))
    if jobs.cert_busy(h.store, row['id']):
        raise E.ApiError(409, 'a job is working on %s: stop it first' % row['name'])
    by = who(s)
    if not _flag(b.get('revoke'), 0):
        cert_drop(h.store, row, by)
        return {'message': '%s deleted' % row['name']}
    # Revoked first, at its CA, then deleted (1.0.21) - in one job: a revocation
    # that fails leaves the certificate here, as it was, and says why.
    why_not = revocable(h.store, row)
    if why_not:
        raise E.ApiError(400, '%s cannot be revoked: %s - delete it without revoking'
                         % (row['name'], why_not))
    reason = str(b.get('reason') or 'cessationOfOperation')
    if reason not in REVOKE_REASONS:
        raise ValueError('the reason is one of %s' % ', '.join(REVOKE_REASONS))

    # Seen in the list as it goes (1.0.23): "being revoked, then deleted" until the
    # CA has it; a revocation that fails leaves it "revocation failed", not deleted.
    h.store.db.update('certs', row['id'], {'state': 'deleting', 'state_at': time.time()})

    def fn(job):
        try:
            ok, said = renewer.revoke_cert(job.store, job, row['id'], reason, by)
            if not ok:
                # its twin not revoked (1.0.51): deleted, it stayed valid at its CA and acme
                # could not revoke it any more - kept, revoked itself, the twin to try again
                job.store.add_event('certificates', '%s: its twin was not revoked - it is kept, '
                                    'not deleted' % row['name'], 'warn', who=by)
                return False, '%s - nothing was deleted; revoke it again, then delete it' % said
        except Exception as e:
            job.store.db.update('certs', row['id'], {
                'state': 'revoke-failed', 'state_at': time.time(),
                'last_error': ('the revocation failed, nothing was deleted: %s' % e)[:2000]})
            job.store.add_event('certificates', '%s: the revocation failed, it was not deleted: '
                                '%s' % (row['name'], e), 'warn', who=by)
            raise
        job.step('revoked - now deleted from acme', 'ok')
        cert_drop(job.store, row, by)
        return True, '%s revoked and deleted' % row['name']
    try:
        job_id = jobs.submit(h.store, 'revoke', fn, cert_id=row['id'], by=by,
                             said='reason: %s, then deleted' % reason)
    except ValueError as e:
        h.store.db.update('certs', row['id'], {'state': row.get('state') or 'ok'})
        raise E.ApiError(409, str(e))
    return {'job_id': job_id, 'message': '%s is being revoked, then deleted' % row['name']}


@api('POST', '/api/certs/keep', 'certadmin')
def _cert_keep(h, s):
    """A certificate whose revocation (to delete it) failed, kept after all (1.0.23):
    back to what it is - valid, or expired - and renewed by itself again."""
    row = S.cert_need(h.store, _id(h.body().get('id')))
    if row.get('state') != 'revoke-failed':
        raise E.ApiError(409, '%s is not waiting after a failed revocation' % row['name'])
    t = time.time()
    na = float(row.get('not_after') or 0)
    state = ('ok' if na > t else 'expired') if row.get('cert_pem') else 'new'
    h.store.db.update('certs', row['id'], {'state': state, 'state_at': t, 'last_error': '',
                                           'updated': t, 'updated_by': who(s)[:190]})
    h.store.add_event('certificates', '%s kept after a failed revocation, by %s' % (
        row['name'], who(s)), who=who(s))
    return {'message': '%s is kept' % row['name']}


def start_renew(store, ref, force, by):
    row = S.cert_need(store, ref)
    if row.get('state') in ('pending-approval', 'declined'):
        # Not past the approval (1.0.45): Renew now issued a portal request that was waiting,
        # or declined, with no one told - Approve is the way.
        raise ValueError('%s %s - approve it first' % (
            row['name'], 'waits for approval' if row['state'] == 'pending-approval'
            else 'was declined'))
    if not row.get('issuer'):
        raise ValueError('%s has no issuer - it was imported or is answered by a CSR; import the '
                         'new certificate instead' % row['name'])
    if row.get('enabled') == 0:
        # Switched off (1.0.77): renewed by hand it was deployed everywhere and shown "valid"
        # while still off.
        raise ValueError('%s is switched off - switch it on first' % row['name'])
    # Asked by a person, it is renewed whether due or not; `force` also takes a
    # certificate that failed out of its wait - and both are written in the job.
    try:
        # the first one is an issue, not a renewal (1.0.79: "renewal no. 140", and the filter
        # "issue" did not find it)
        return jobs.submit(store, 'renew' if row.get('cert_pem') else 'issue',
                           renewer.renew_job(row['id'], force, by),
                           cert_id=row['id'], by=by,
                           said='asked by %s%s' % (by, ' (forced)' if force else ''))
    except ValueError as e:
        # A job on it already (a new certificate is issued by the look right after
        # it is saved): "Add and issue now", "Renew now" get that job to watch.
        running = jobs.cert_job(store, row['id'])
        if running is not None:
            return running
        raise E.ApiError(409, str(e))


@api('POST', '/api/certs/renew', 'certadmin')
def _cert_renew(h, s):
    b = h.body()
    return {'job_id': start_renew(h.store, _id(b.get('id')), _flag(b.get('force')), who(s))}


def start_deploy(store, ref, deploy_id, by):
    row = S.cert_need(store, ref)
    if not row.get('cert_pem'):
        raise ValueError('%s has not been issued yet' % row['name'])
    if row.get('enabled') == 0:
        raise ValueError('%s is switched off - switch it on first' % row['name'])
    if S.current_revoked(store, row):
        raise ValueError('the certificate %s holds is revoked - issue a new one first'
                         % row['name'])
    only = None
    if deploy_id not in (None, '', 0):
        d = store.db.row('SELECT * FROM cert_deploys WHERE id = ? AND cert_id = ?',
                         (_id(deploy_id, 'deploy_id'), row['id']))
        if not d:
            raise LookupError('that deployment is not one of %s' % row['name'])
        only = [d['id']]
    end = time.time() + (20 if only else 0)
    while True:
        try:
            return jobs.submit(store, 'deploy', deployer.deploy_job(row['id'], only, force=True),
                               cert_id=row['id'], deploy_id=only[0] if only else None,
                               target=d['target'] if only else None, by=by,
                               said='asked by %s' % by)
        except ValueError as e:
            running = jobs.cert_job(store, row['id'])
            # The look already deploying it (1.0.48): "Save and deploy now" saved the deployment,
            # the look started on it at once - and this ran it a second time after; the files
            # were written twice. That job is this one.
            if only and running is not None:
                rj = store.db.row('SELECT kind, deploy_id, state FROM cert_jobs WHERE id = ?',
                                  (running,)) or {}
                # ...that very deployment's job - not the look's of others (deploy_id empty): this
                # one would never be run then
                if rj.get('kind') == 'deploy' and rj.get('deploy_id') == only[0]:
                    return running
            # One deployment asked for while a job works on the certificate (the look
            # that deploys a deployment just saved): it is run once that job is done -
            # waited for a little (1.0.19); that job's result is not this one's.
            if only and running is not None and time.time() < end:
                time.sleep(0.25)
                continue
            # The whole certificate: the job at work puts it in place too (1.0.18).
            if running is not None and not only:
                return running
            raise E.ApiError(409, str(e))


@api('POST', '/api/certs/hold', 'certadmin')
def _cert_hold(h, s):
    """{id, hold}: a new version of it issued from now on is not deployed until Deploy now
    (1.0.86) - or, false, deployed by itself again."""
    b = h.body()
    row = S.cert_need(h.store, _id(b.get('id')))
    on = _flag(b.get('hold'))
    had = S.deploy_hold(h.store, row['id'])
    S.deploy_hold_set(h.store, row, on, who(s))
    if bool(had) == on:
        return {'message': 'held' if on else 'deployed by itself'}   # no change: no event
    h.store.add_event('certificates', '%s: %s by %s' % (
        row['name'], 'a new version is not deployed until Deploy now' if on else
        'a new version is deployed by itself again', who(s)), who=who(s))
    return {'message': 'held' if on else 'deployed by itself'}


@api('POST', '/api/certs/deploy', 'certadmin')
def _cert_deploy(h, s):
    b = h.body()
    return {'job_id': start_deploy(h.store, _id(b.get('id')), b.get('deploy_id'), who(s))}


DEPLOY_COMMANDS = ('pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd', 'script_path',
                   'script_args', 'script_mode', 'script_interp',
                   'post_ps',       # Windows' PowerShell after (1.0.45): run as Administrator
                   'wac_msi')       # an installer run as Administrator (1.0.51)


# Where the private key goes, and its password (1.0.48): a full administrator's, as the commands.
# Of `outputs` only the lines that carry the key; the others, and a module's presets, stay a
# certificate administrator's.
DEPLOY_KEY_OPTIONS = ('outputs', 'pfx_password', 'pfx_password_mode', 'include_key', 'key_file',
                      'key_target',
                      # and (1.0.51) Windows' store of shared certificates (a PFX in a folder or
                      # share, with its password), who may read the key, the key exportable,
                      # haproxy's file (the key in it) and its crt-list
                      'ccs_path', 'ccs_password', 'key_read', 'exportable', 'cert_path', 'crt_list')
KEY_SECRETS = ('pfx_password', 'ccs_password')
# ...and of a module of its own, the options that say where its key goes (1.0.51): a file and its
# owner, a secret of Kubernetes and its namespace, a path of Vault, a folder, the services a
# Docker secret is given to, a certificate's name in an Azure key vault.
KEY_OPTIONS_OF = {
    'caddy': ('cert_file', 'owner'),
    'kubernetes': ('namespace', 'secret'),
    'vault': ('mount', 'path', 'namespace'),
    'strongswan': ('dir', 'file_name'),
    'traefik': ('cert_dir',),
    'docker_swarm': ('services',),
    'azure_keyvault': ('vault', 'cert_name'),
    'azure_appgw': ('cert_name', 'key_vault_secret_id'),
}


def key_options(cls):
    return DEPLOY_KEY_OPTIONS[1:] + KEY_OPTIONS_OF.get(str(getattr(cls, 'kind', '') or ''), ())
KEY_FORMATS = ('key-pem', 'key-rsa', 'key-der', 'key-traditional', 'combined-pem', 'pfx', 'p12',
               'p12-legacy', 'jks', 'pkcs12')


def _key_lines(v):
    """The lines of `outputs` that write the private key, as (format, path, mode, owner)."""
    from acmelib.plugins.targets._common import lines, FORMAT_ALIASES
    out = set()
    for ln in lines(v):
        w = ln.split()
        fmt = w[0].lower().split('@', 1)[0] if w else ''
        # the words a module takes for a format too (1.0.78: "haproxy", "combined", "rsa" wrote
        # the key where a certificate administrator said, not seen as the key)
        fmt = FORMAT_ALIASES.get(fmt, fmt)
        if fmt in KEY_FORMATS or 'key' in fmt or 'keystore' in fmt:
            out.add(tuple([fmt] + w[1:4]))
    return out


def _deploy_key_check(cls, given, old):
    """A certificate administrator's save of a deployment: where the key goes and its password as
    they were - or as one of the module's presets puts them. Only what was sent is looked at."""
    fields = {f['key']: f for f in ((cls.deploy_fields if cls else None) or [])}
    refused = E.ApiError(403, 'only a full administrator may change where a deployment writes '
                              'the private key, or its password')
    if 'outputs' in given:
        new_keys = _key_lines(given.get('outputs'))
        allowed = _key_lines(old.get('outputs'))
        fills = (fields.get('preset') or {}).get('fills') or {}
        for fill in (fills.values() if isinstance(fills, dict) else []):
            if isinstance(fill, dict):
                allowed |= _key_lines(fill.get('outputs'))
        if not new_keys <= allowed:
            raise refused
    for k in key_options(cls):
        if k not in given:
            continue
        nv, ov = given.get(k), old.get(k)
        dv = (fields.get(k) or {}).get('default')
        if E.is_masked(nv) if isinstance(nv, str) else False:
            continue                                    # the dots: the one kept
        norm = lambda v: '' if v in (None, '', [], False, 0, '0') else str(v)  # noqa: E731
        if k in KEY_SECRETS:
            if nv in (None, '') or (old.get(k) and nv == old.get(k)):
                continue                                # unchanged or sealed as kept
            raise refused
        # the safe ways stay theirs: a password nobody knows, the key not sent
        if (k == 'pfx_password_mode' and nv == 'generate') or \
                (k in ('include_key', 'exportable') and not norm(nv)):
            continue
        if norm(nv) != norm(ov if k in old else dv) and norm(nv) != norm(dv):
            raise refused


REVOKE_REASONS = ('unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                  'superseded', 'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn')


@api('POST', '/api/certs/revoke', 'certadmin')
def _cert_revoke(h, s):
    b = h.body()
    row = S.cert_need(h.store, _id(b.get('id')))
    reason = str(b.get('reason') or 'unspecified')
    if reason not in REVOKE_REASONS:
        raise ValueError('the reason is one of %s' % ', '.join(REVOKE_REASONS))
    by = who(s)

    again = _flag(b.get('renew'), 0)
    no = revocable(store=h.store, row=row)
    if no:
        raise ValueError('%s cannot be revoked here: %s' % (row['name'], no))
    if again and (row.get('csr_given') or not row.get('issuer')):
        # As the portal (1.0.19): issued for a CSR sent in, a new one needs a new CSR - it was
        # left revoked with renewal switched on (1.0.77).
        raise ValueError('%s was issued for a CSR sent in: a new one needs a new CSR - revoke '
                         'it alone' % row['name'])

    def fn(job):
        got = renewer.revoke_cert(job.store, job, row['id'], reason, by)
        if not again:
            return got
        # Not renewed over a revocation not done in full (1.0.79: the twin not revoked was
        # replaced and forgotten - its compromised key still valid at the CA)
        if isinstance(got, tuple) and got and got[0] is False:
            return got
        # A new one at once (the key got out: a new key too, whatever reuse_key says),
        # deployed where the revoked one is - and renewed by itself again.
        job.step('issuing a new one in its place')
        job.store.db.update('certs', row['id'], {'auto_renew': 1})
        return renewer.renew_cert(job.store, job, row['id'], True, by)
    try:
        return {'job_id': jobs.submit(h.store, 'revoke', fn, cert_id=row['id'], by=by,
                                      said='reason: %s%s' % (reason, ', a new one at once'
                                                             if again else ''))}
    except ValueError as e:
        raise E.ApiError(409, str(e))


def _with_more(data, filename, more):
    """Several files brought at once (both halves of a dual certificate: rsa.pfx and
    ec.pfx, say - 1.0.34): read together, as one ZIP holding them would be."""
    if not more:
        return data, filename
    import io
    import zipfile
    buf = io.BytesIO()
    seen = set()
    with zipfile.ZipFile(buf, 'w') as z:
        for d, n in [(data, filename)] + list(more):
            n = os.path.basename(str(n or 'file')) or 'file'
            while n in seen:
                n = '_' + n
            seen.add(n)
            z.writestr(n, d)
    return buf.getvalue(), 'files.zip'


def _more_of(b):
    out = []
    for m in (b.get('more') or [])[:8]:
        if isinstance(m, dict) and m.get('data_b64'):
            out.append((_b64(m.get('data_b64'), 'more'), str(m.get('filename') or 'file')[:200]))
    return out


def parse_file(data, filename, password, more=None):
    """What is in a file: the certificates (each described), a key or not."""
    formats = _lib('formats')
    data, filename = _with_more(data, filename, more)
    got = formats.read_any(data, filename or '', password or None) or {}
    out = {'format': got.get('format'), 'needs_password': bool(got.get('needs_password')),
           'notes': list(got.get('notes') or []), 'has_key': bool(got.get('key')),
           'keys': len(got.get('keys') or []), 'certs': []}
    leaf = got.get('leaf')
    for pem in got.get('certs') or []:
        try:
            info = S.info_of(pem)
        except Exception as e:                          # noqa: BLE001
            info = {'error': str(e)}
        info['leaf'] = bool(leaf) and pem.strip() == str(leaf).strip()
        out['certs'].append(info)
    # the other half of a dual certificate in the same file (1.0.34): said, kept as the twin
    if leaf:
        try:
            sec = _second_half(got, leaf, got.get('key'), S.info_of(leaf))
        except Exception:                               # noqa: BLE001
            sec = None
        if sec:
            for info in out['certs']:
                if info.get('sha256') == sec[2].get('sha256'):
                    info['twin'] = True
            out['twin'] = _key_type_words(sec[2])
            out['notes'] = [n for n in out['notes'] if 'could each be the certificate' not in n
                            and 'not in the chain of the certificate' not in n]
    if leaf and got.get('key'):
        try:
            out['key_matches'] = bool(S.pki().key_matches(leaf, got['key']))
        except Exception as e:                          # noqa: BLE001
            out['key_matches'] = None
            out['notes'].append('whether the key fits could not be checked: %s' % e)
    return out, got


@api('POST', '/api/certs/parse', 'certadmin')
def _cert_parse(h, s):
    b = h.body()
    out, _got = parse_file(_b64(b.get('data_b64')), _text(b, 'filename', 300),
                           _text(b, 'password', 1000), _more_of(b))
    return out


def cert_import(store, b, by):
    data = _b64(b.get('data_b64'))
    more = _more_of(b)
    _out, got = parse_file(data, _text(b, 'filename', 300), _text(b, 'password', 1000), more)
    if got.get('needs_password') and not _text(b, 'password', 1000) and _text(b, 'key_password', 1000):
        # the key's password given for a file that holds the key itself (1.0.33)
        _out, got = parse_file(data, _text(b, 'filename', 300), _text(b, 'key_password', 1000), more)
    if got.get('needs_password'):
        raise ValueError('that password does not open the file' if (_text(b, 'password', 1000) or _text(b, 'key_password', 1000))
                         else 'the file is locked: give its password')
    leaf = got.get('leaf') or ((got.get('certs') or [None])[0])
    if not leaf:
        raise ValueError('there is no certificate in that file')
    key = got.get('key')
    if not key and got.get('keys') and not b.get('key_b64'):
        # a key in the file, of no certificate in it (1.0.51): imported "without its key" -
        # said, as a key given apart is
        raise ValueError('the key in the file does not belong to the certificate')
    if b.get('key_b64'):
        formats = _lib('formats')
        kg = formats.read_any(_b64(b.get('key_b64'), 'key_b64'), _text(b, 'key_filename', 300) or
                              'key.pem', _text(b, 'key_password', 1000) or None) or {}
        if kg.get('needs_password'):
            raise ValueError('that password does not open the key' if _text(b, 'key_password', 1000)
                             else 'the key is locked: give its password (key_password)')
        key = kg.get('key') or ((kg.get('keys') or [None])[0])
        if not key:
            raise ValueError('there is no private key in the key file')
    if key:
        try:
            if S.pki().key_matches(leaf, key) is False:
                raise ValueError('the key does not belong to the certificate')
        except ValueError:
            raise
        except Exception:                               # noqa: BLE001
            pass
    chain = [p for p in (got.get('chain') or []) if p.strip() != leaf.strip()]
    try:
        ordered = S.pki().order_chain(leaf, chain)
        if isinstance(ordered, (list, tuple)) and ordered:
            chain = [p for p in ordered if p.strip() != leaf.strip()]
    except Exception:                                   # noqa: BLE001
        pass
    info = S.info_of(leaf)
    t = time.time()
    # A dual certificate (1.0.34): the other half - the same names, the other key
    # type - in the same file (a PEM holding both, with both keys) is kept as the
    # twin; brought into a certificate that has the other half, it is its twin.
    as_ = str(b.get('as') or 'auto').strip().lower()
    if as_ not in ('auto', 'main', 'alt'):
        raise ValueError('as: auto, main or alt (the twin)')
    second = _second_half(got, leaf, key, info)
    if b.get('id') not in (None, '', 0):
        row = S.cert_need(store, _id(b.get('id')))
        # its names, all of them, in the one brought in (1.0.88: another certificate went into
        # it - its key dropped - and the next deployment put it on the servers); `force` takes it
        have = [str(n).lower() for n in (S.jload(row.get('names'), []) or [])]
        brings = [str(n).lower() for n in (info.get('names') or [])] or \
            ([str(info.get('cn')).lower()] if info.get('cn') else [])

        def covered(n):
            return any(n == m or (m.startswith('*.') and n.count('.') == m.count('.') and
                                  n.split('.', 1)[-1] == m[2:]) for m in brings)
        missing = [n for n in have if not covered(n)]
        if missing and brings and b.get('force') in (None, '', 0, '0', False, 'false'):
            raise ValueError('the certificate brought in is not for %s: it lacks %s (it is for %s)'
                             ' - import it as a certificate of its own, or with force'
                             % (row['name'], ', '.join(missing[:5]), ', '.join(brings[:5])))
        if as_ == 'auto':
            as_ = 'alt' if _other_half_of(row, info) else 'main'
        if as_ == 'alt':
            if not key and row.get('alt_cert_pem'):
                key = S.cert_key(row, 'alt')
            if key and S.pki().key_matches(leaf, key) is False:
                key = None
            main_fam = 'ec' if str(row.get('key_type') or '').startswith('ec') else (
                'rsa' if 'rsa' in str(row.get('key_type') or '') else '')
            if main_fam and _key_family(info) == main_fam and not row.get('key_type_alt'):
                # A twin is the other kind of key (1.0.77): an RSA twin of an RSA certificate
                # made it "dual" and every later save was refused.
                raise ValueError('a twin is the other kind of key: %s has a %s key, this one too'
                                 % (row['name'], main_fam.upper()))
            version = S.save_alt(store, row['id'], leaf, chain, key, 'import', by, info=info,
                                 extra={'key_type_alt': _key_type_words(info)})
            store.add_event('certificates', 'certificate %s: its twin (%s) imported by %s (version %d%s)' % (
                row['name'], _key_type_words(info), by, version, '' if key else ', without its key'), who=by)
            return row['id'], version
        if not key:
            key = S.cert_key(row)       # a new certificate for the key it has (a CSR's answer)
            # ...only when it is that key's (1.0.48): renewed elsewhere with a new key, it was kept
            # with the old one, and every server was given a certificate its key does not fit.
            if key and S.pki().key_matches(leaf, key) is False:
                key = None
        cid = row['id']
    else:
        name = S.clean_name(b.get('name'), 'the certificate\'s name') if b.get('name') else \
            S.safe_name(info.get('cn') or (info.get('names') or [''])[0] or 'imported',
                        _names_in(store, 'certs'))
        if store.db.row('SELECT id FROM certs WHERE name = ?', (name,)):
            raise ValueError('there is a certificate called %s already' % name)
        # the common name stands in for the names only when it is a DNS name or an address
        # (1.0.80: "ZZ Issuing CA" of a chain was kept as a DNS name)
        names = list(info.get('names') or [])
        if not names and info.get('cn'):
            try:
                names = S.clean_names([info['cn']])
            except ValueError:
                names = []
        cid = store.db.insert('certs', {
            'name': name, 'cn': str(info.get('cn') or (names[0] if names else ''))[:190],
            'names': json.dumps(names), 'key_type': str(info.get('key_type') or '')[:60],
            'issuer': '', 'challenge': '', 'challenge_map': '{}', 'auto_renew': 0,
            'renew_days': None, 'reuse_key': 0, 'profile': '{}', 'source': 'import',
            'state': 'new', 'state_at': t, 'version': 0, 'fails': 0,
            'tags': json.dumps(_tags_of(b)),
            'note': _text(b, 'note', 4000), 'owner': _text(b, 'owner', 190), 'created': t,
            'created_by': str(by)[:190], 'enabled': 1, 'ari': '{}'})
    version = S.save_version(store, cid, leaf, chain, key, 'import', by, info=info)
    store.add_event('certificates', 'certificate %s imported by %s (version %d%s)' % (
        S.cert_need(store, cid)['name'], by, version, '' if key else ', without its key'), who=by)
    if second:
        s_leaf, s_key, s_info = second
        s_chain = [p for p in (got.get('certs') or []) if p.strip() not in (leaf.strip(), s_leaf.strip())
                   and S.info_of(p).get('is_ca')]
        try:
            ordered = S.pki().order_chain(s_leaf, s_chain)
            if isinstance(ordered, (list, tuple)) and ordered:
                s_chain = [p for p in ordered if p.strip() != s_leaf.strip()]
        except Exception:                               # noqa: BLE001
            pass
        v2 = S.save_alt(store, cid, s_leaf, s_chain, s_key, 'import', by, info=s_info,
                        extra={'key_type_alt': _key_type_words(s_info)})
        store.add_event('certificates', 'certificate %s: its twin (%s) imported with it by %s (version %d)' % (
            S.cert_need(store, cid)['name'], _key_type_words(s_info), by, v2), who=by)
    return cid, version


def _tags_of(b):
    """A certificate's or a target's tags, each one word as the teams' (1.0.77): any length of
    anything was kept, and teams.adopt() skipped it quietly."""
    out = []
    for t in _list(b.get('tags'), 'tags')[:50]:
        t = _lib('teams').clean_tag(t)
        if t not in out:
            out.append(t)
    return out


def _key_family(info):
    w = str((info or {}).get('key_type') or '').strip().lower()
    return 'ec' if w.startswith('ec') else ('rsa' if 'rsa' in w else w)


def _key_type_words(info):
    """rsa-4096, ec-384 - as a certificate's key type is said (key_type_alt)."""
    fam = _key_family(info)
    bits = (info or {}).get('key_bits')
    return ('%s-%s' % (fam, bits)) if fam and bits else (fam or '')


def _names_of(info):
    return set(str(n).lower() for n in ((info or {}).get('names') or ([info['cn']] if (info or {}).get('cn') else [])))


def _other_half_of(row, info):
    """Is the certificate brought in the other half of this one - the same names, the
    other key type - rather than its next version?"""
    try:
        main = S.info_of(row['cert_pem']) if row.get('cert_pem') else None
    except Exception:                                   # noqa: BLE001
        main = None
    if not main:
        return False
    return _key_family(main) != _key_family(info) and _names_of(main) == _names_of(info)


def _second_half(got, leaf, key, info):
    """(cert, key, info) of the other half of a dual certificate in the same file:
    an end entity of the same names and the other key type, with its own key."""
    for pem in got.get('certs') or []:
        if pem.strip() == leaf.strip():
            continue
        try:
            i2 = S.info_of(pem)
        except Exception:                               # noqa: BLE001
            continue
        if i2.get('is_ca') or _key_family(i2) == _key_family(info) or _names_of(i2) != _names_of(info):
            continue
        for k in got.get('keys') or []:
            if k == key:
                continue
            try:
                if S.pki().key_matches(pem, k):
                    return pem, k, i2
            except Exception:                           # noqa: BLE001
                continue
    return None


@api('POST', '/api/certs/import', 'certadmin')
def _cert_import(h, s):
    cid, version = cert_import(h.store, h.body(), who(s))
    return {'id': cid, 'version': version}


FORMAT_FILES = {
    'cert-pem': ('.crt', 'application/x-pem-file'),
    'cert-der': ('.cer', 'application/pkix-cert'),
    'key-pem': ('.key', 'application/x-pem-file'),
    'key-rsa': ('.rsa.key', 'application/x-pem-file'),
    'key-der': ('.key.der', 'application/octet-stream'),
    'chain-pem': ('.chain.pem', 'application/x-pem-file'),
    'fullchain-pem': ('.fullchain.pem', 'application/x-pem-file'),
    'combined-pem': ('.pem', 'application/x-pem-file'),
    'p7b': ('.p7b', 'application/x-pkcs7-certificates'),
    'pfx': ('.pfx', 'application/x-pkcs12'),
    'p12': ('.p12', 'application/x-pkcs12'),
    'p12-legacy': ('.legacy.pfx', 'application/x-pkcs12'),
    'jks': ('.jks', 'application/octet-stream'),
}


def cert_export(store, b, s, allowed=None):
    row = S.cert_need(store, _id(b.get('id')))
    fmt = str(b.get('format') or 'fullchain-pem')
    if fmt not in FORMAT_FILES or (allowed and fmt not in allowed):
        raise ValueError('the format is one of %s' % ', '.join(allowed or FORMAT_FILES))
    if fmt in S.KEY_FORMATS and not may(s, 'fulladmin'):
        raise E.ApiError(403, 'only a full administrator may take a private key out')
    vrow = None
    variant = str(b.get('variant') or 'main').strip().lower()
    if variant == 'both':
        # a dual certificate's two halves in one PEM file, each with its chain (and
        # its key) - as acme imports it again (1.0.34)
        if not row.get('alt_cert_pem'):
            raise ValueError('%s has no twin' % row['name'])
        if fmt not in ('cert-pem', 'fullchain-pem', 'combined-pem'):
            raise ValueError('both go into a PEM file only: cert-pem, fullchain-pem or combined-pem')
        one = cert_export(store, dict(b, variant='main', version=None), s, allowed)
        two = cert_export(store, dict(b, variant='alt', version=None), s, allowed)
        data = base64.b64decode(one['data_b64']) + base64.b64decode(two['data_b64'])
        ext, mime = FORMAT_FILES[fmt]
        return {'filename': re.sub(r'[^A-Za-z0-9._-]+', '_', row['name']) + '.both' + ext,
                'mime': mime, 'data_b64': base64.b64encode(data).decode('ascii'),
                'format': fmt, 'variant': 'both', 'key_type': '%s + %s' % (
                    one.get('key_type') or '', two.get('key_type') or '')}
    if variant not in ('main', 'alt', 'ec', 'rsa', 'ed', 'ecdsa'):
        raise ValueError('the variant is main, alt or both (or ec, rsa)')
    if b.get('version') not in (None, '', 0):
        vrow = S.version_row(store, row['id'], int(b['version']))
        if not vrow:
            raise LookupError('%s has no version %s' % (row['name'], b['version']))
    if not (vrow or row).get('cert_pem'):
        raise ValueError('%s has not been issued yet' % row['name'])
    if vrow is None and variant != 'main':
        try:
            bundle = S.bundle_of(row).variant(variant)
        except Exception as e:                          # noqa: BLE001
            raise ValueError(str(e))
    else:
        bundle = S.bundle_of(row, vrow, 'main' if vrow is None else None)
    from acmelib.certs.bundle import VARIANT_ALIASES
    asked = VARIANT_ALIASES.get(variant, variant)
    variant = getattr(bundle, 'variant_name', 'main')
    if vrow is not None and asked != 'main' and asked not in (variant, getattr(bundle, 'family', None)):
        # A version is one certificate - the twin's has a number of its own (1.0.45): asked
        # for "alt of version 1", the main one came back without a word.
        raise ValueError('version %s of %s is its %s certificate, not the %s one' % (
            b['version'], row['name'], variant, asked))
    if fmt in S.KEY_FORMATS and row.get('csr_given'):
        raise ValueError('%s was issued for a CSR that was sent in: acme never had its key - it '
                         'stays where the CSR was made, so no file with the key can be made here'
                         % row['name'])
    if fmt in S.KEY_FORMATS and not getattr(bundle, 'key_pem', None):
        raise ValueError('acme does not have the key of %s' % row['name'])
    # The alias the page asks for (a Java keystore, PKCS#12's friendly name) - it was
    # never handed on: every keystore held the default one (1.0.19).
    alias = _text(b, 'alias', 100).strip() or None
    if alias and any(ord(ch) < 32 for ch in alias):
        raise ValueError('the alias is one line of text')
    data = bundle.as_format(fmt, _text(b, 'password', 1000) or None, alias)
    if isinstance(data, str):
        data = data.encode('utf-8')
    ext, mime = FORMAT_FILES[fmt]
    fname = re.sub(r'[^A-Za-z0-9._-]+', '_', row['name'])
    if variant == 'alt' or (row.get('key_type_alt') and vrow is None):
        fname += '.' + (getattr(bundle, 'family', '') or variant)   # site.rsa.crt, site.ec.crt
    fname += ext
    if fmt in S.KEY_FORMATS:
        store.add_event('certificates', 'the private key of %s%s was exported (%s) by %s' % (
            row['name'], ' (its twin)' if variant == 'alt' else '', fmt, who(s)), 'warn',
            who=who(s))
    return {'filename': fname, 'mime': mime, 'data_b64': base64.b64encode(data).decode('ascii'),
            'format': fmt, 'variant': variant, 'key_type': getattr(bundle, 'key_type', '')}


@api('POST', '/api/certs/export', 'certadmin')
def _cert_export(h, s):
    return cert_export(h.store, h.body(), s)


@api('POST', '/api/certs/csr', 'certadmin')
def _cert_csr(h, s):
    b = h.body()
    store = h.store
    row = S.cert_need(store, _id(b.get('id')))
    pend = S.jload(row.get('csr_pending'), None)
    if pend and pend.get('csr_pem') and not _flag(b.get('again')):
        return {'csr_pem': pend['csr_pem'], 'made': pend.get('at')}
    pki = S.pki()
    names = S.jload(row.get('names'), []) or []
    if not names:
        raise ValueError('%s has no names' % row['name'])
    prof = S.jload(row.get('profile'), {}) or {}
    key = pki.make_key(row.get('key_type') or 'ec-256')
    csr = pki.make_csr(key, S.sans_of(names, prof), subject=prof.get('subject') or None,
                       must_staple=bool(prof.get('must_staple')), eku=prof.get('eku'))
    csr_pem = csr[0] if isinstance(csr, (tuple, list)) else csr
    t = time.time()
    store.db.update('certs', row['id'], {
        'csr_pending': json.dumps({'csr_pem': csr_pem, 'at': t, 'by': who(s),
                                   'key_sealed': E.seal_secret(key, 'certs:%s:csr_pending'
                                                               % row['id'])}),
        'state': row['state'] if row.get('cert_pem') else 'pending', 'state_at': t})
    store.add_event('certificates', 'a CSR for %s given out to %s' % (row['name'], who(s)),
                    who=who(s))
    return {'csr_pem': csr_pem, 'made': t}


@api('POST', '/api/certs/csr_answer', 'certadmin')
def _cert_csr_answer(h, s):
    b = h.body()
    store = h.store
    row = S.cert_need(store, _id(b.get('id')))
    pend = S.jload(row.get('csr_pending'), None)
    if not pend:
        raise ValueError('no CSR of %s is waiting for its answer' % row['name'])
    key = E.unseal_secret(pend.get('key_sealed'), 'certs:%s:csr_pending' % row['id'])
    if not key:
        raise ValueError('the key of the CSR cannot be opened on this machine')
    _out, got = parse_file(_b64(b.get('data_b64')), _text(b, 'filename', 300), None)
    leaf = got.get('leaf') or ((got.get('certs') or [None])[0])
    if not leaf:
        raise ValueError('there is no certificate in that file')
    if S.pki().key_matches(leaf, key) is False:
        raise ValueError('that certificate is not the answer to the CSR (another key)')
    chain = [p for p in (got.get('chain') or []) if p.strip() != leaf.strip()]
    try:
        # nearest first, as an import puts it (1.0.48): kept in the file's order before
        ordered = S.pki().order_chain(leaf, chain)
        if ordered:
            chain = ordered
    except Exception:                                   # noqa: BLE001
        pass
    version = S.save_version(store, row['id'], leaf, chain, key, 'csr', who(s),
                             extra={'csr_pending': None})
    store.add_event('certificates', 'the answer to the CSR of %s taken (version %d) by %s' % (
        row['name'], version, who(s)), who=who(s))
    job_id = None
    if deployer.deploys_of(store, row['id']):
        job_id = start_deploy(store, row['id'], None, who(s))
    return {'id': row['id'], 'version': version, 'job_id': job_id}


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
@api('GET', '/api/certs/jobs')
def _jobs(h, s):
    ok = h.arg('ok')
    # Scoped in the query (1.0.19): a page of every job kept to its own had a few
    # rows, or none, while its jobs were on the pages after it.
    return jobs.job_rows(h.store, cert_id=h.arg('cert_id') or None, kind=h.arg('kind'),
                         ok=ok if ok in ('0', '1') else None, page=h.num('page', 1, 1),
                         per=h.num('per', 50, 1, 500), state=h.arg('state') or '',
                         where=_lib('teams').where(h.store, s, 'view', 'c.owner'))


def _scoped_rows(store, s, got, key='cert_id'):
    """Rows about certificates (jobs, deployments) kept to those this account
    may see (teams.py) - every one when it is not scoped."""
    T = _lib('teams')
    sc = T.scope(store, s, 'view')
    if sc is None:
        return got
    owners = {r['id']: r.get('owner') for r in store.db.rows('SELECT id, owner FROM certs')}
    keep = [r for r in got['rows'] if r.get(key) in owners and T.owner_in(sc, owners[r[key]])]
    return dict(got, rows=keep, total=len(keep) if len(keep) < len(got['rows']) else
                got.get('total', len(keep)))


@api('GET', '/api/certs/job')
def _job(h, s):
    return {'job': jobs.job_view(h.store, _id(h.arg('id')))}


@api('POST', '/api/certs/job_stop', 'certadmin')
def _job_stop(h, s):
    said = jobs.stop(h.store, _id(h.body().get('id')))
    h.store.add_event('certificates', '%s (by %s)' % (said, who(s)), who=who(s))
    return {'message': said}


# ---------------------------------------------------------------------------
# The authorities of acme's own
# ---------------------------------------------------------------------------
CA_COLS = ('id', 'name', 'parent_id', 'subject_dn', 'key_type', 'serial_next', 'crl_number',
           'crl_at', 'crl_days', 'crl_url', 'aia_url', 'ocsp_url', 'days_default', 'path_len',
           'not_before', 'not_after', 'fingerprint', 'external', 'disabled', 'note', 'created',
           'created_by')


def ca_row(store, ref):
    if ref in (None, ''):
        raise LookupError('which authority?')
    r = None
    if isinstance(ref, int) or str(ref).isdigit():
        r = store.db.row('SELECT * FROM cert_cas WHERE id = ?', (int(ref),))
    if not r:
        r = store.db.row('SELECT * FROM cert_cas WHERE name = ?', (str(ref),))
    if not r:
        raise LookupError('there is no authority %s' % ref)
    return r


def ca_list(store):
    """The authorities as a tree (ca.ca_list), each saying whether it can sign."""
    keys = {r['id']: bool(r.get('key_sealed')) for r in
            store.db.rows('SELECT id, key_sealed FROM cert_cas')}
    try:
        rows = _lib('ca').ca_list(store)
    except ImportError:
        rows = [{k: r.get(k) for k in CA_COLS} for r in
                store.db.rows('SELECT * FROM cert_cas ORDER BY id')]
    dflt = DF.default_name(store, 'ca')
    pub = _lib('publish')
    for r in rows:
        r['has_key'] = keys.get(int(r['id']), False)
        r['is_default'] = bool(dflt) and str(r['id']) == dflt
        try:
            r['published'] = pub.is_published(store, r['id'])
        except Exception:                               # noqa: BLE001
            r['published'] = False
    return rows


@api('GET', '/api/cas')
def _cas(h, s):
    return {'rows': ca_list(h.store)}


@api('POST', '/api/cas/default', 'fulladmin')
def _ca_default(h, s):
    """{id} - the authority offered first; '' (or 0) for none."""
    b = h.body()
    ref = b.get('id') if 'id' in b else b.get('name')
    got = DF.set_default(h.store, 'ca', '' if ref in (None, 0, '0') else ref, who(s))
    return {'default': got, 'message': ('%s is the default authority now' % got) if got else
            'there is no default authority now'}


@api('GET', '/api/cas/one')
def _ca_one(h, s):
    ca = _lib('ca')
    r = ca_row(h.store, h.arg('id') or h.arg('name'))
    one = ca.ca_get(h.store, r['id'])
    one['has_key'] = bool(r.get('key_sealed'))
    one['cert_pem'] = r.get('cert_pem')
    one['crl_pem'] = r.get('crl_pem')
    one['is_default'] = DF.default_name(h.store, 'ca') == str(r['id'])
    try:
        pki_view = _lib('publish').view(h.store, r['id'])
    except Exception as e:                              # noqa: BLE001
        pki_view = {'error': str(e)}
    issued = ca.ca_issued(h.store, r['id'], limit=h.num('per', 500, 1, 5000),
                          offset=h.num('offset', 0, 0))
    seen = visible_cert_ids(h.store, s)
    if seen is not None:
        # a reader of one team sees its own team's certificates only (1.0.79: every one the
        # CA signed, other teams' names with them)
        rows = issued.get('rows') if isinstance(issued, dict) else issued
        kept = [x for x in rows or [] if x.get('cert_id') in seen]
        if isinstance(issued, dict):
            issued = dict(issued, rows=kept, total=len(kept))
        else:
            issued = kept
    return {'ca': one, 'pki': pki_view, 'issued': issued,
            'children': [ca_row(h.store, c)['name'] for c in one.get('children') or []]}


def visible_cert_ids(store, s):
    """The ids of the certificates a session may see - None when it sees every one (1.0.79)."""
    T = _lib('teams')
    if T.scope(store, s, 'view') is None:
        return None
    sw, sa = T.where(store, s, 'view')
    return {int(r['id']) for r in store.db.rows('SELECT id FROM certs WHERE 1 = 1' + sw, sa)}


def _subject_of(v):
    if isinstance(v, str):
        v = dict(p.split('=', 1) for p in re.split(r'\s*,\s*', v) if '=' in p)
    if not isinstance(v, dict):
        raise ValueError('the subject is {CN, O, OU, C, ST, L} or "CN=..,O=.."')
    return {str(k).strip(): str(x).strip() for k, x in v.items() if str(x or '').strip()}


@api('POST', '/api/cas/create', 'fulladmin')
def _ca_create(h, s):
    b = h.body()
    ca = _lib('ca')
    subject = _subject_of(b.get('subject') or {})
    if not subject.get('CN'):
        raise ValueError('the subject needs a CN (the authority\'s name as people see it)')
    name = S.clean_name(b.get('name'), 'the authority\'s name') if b.get('name') else \
        S.safe_name(subject.get('CN'), _names_in(h.store, 'cert_cas'))
    kt = str(b.get('key_type') or 'ec-384')
    if kt not in schema.KEY_TYPES:
        raise ValueError('the key type is one of %s' % ', '.join(schema.KEY_TYPES))
    parent = b.get('parent_id')
    parent = ca_row(h.store, parent)['id'] if parent not in (None, '', 0, '0') else None
    got = call(ca.ca_create, h.store, name, subject, key_type=kt,
               days=int(b.get('days') or 3650), parent_id=parent,
               path_len=None if b.get('path_len') in (None, '') else int(b['path_len']),
               crl_days=int(b.get('crl_days') or 7), crl_url=_text(b, 'crl_url', 500),
               aia_url=_text(b, 'aia_url', 500), ocsp_url=_text(b, 'ocsp_url', 500),
               name_constraints=_list(b.get('name_constraints'), 'name_constraints'),
               by=who(s))
    ident = _ident(got)
    filled = _published_new(h.store, ident, b, who(s))
    h.store.add_event('certificates', 'authority %s made by %s%s' % (
        name, who(s), (' - its CRL and certificate published on acme (%s)' % filled['crl_url'])
        if filled else ''), who=who(s))
    return {'id': ident, 'published': bool(filled), 'crl_url': (filled or {}).get('crl_url', ''),
            'aia_url': (filled or {}).get('aia_url', '')}


def _published_new(store, ident, b, by):
    """A new authority's publishing: its own switch (published: on unless said
    otherwise) and, with publishing on, acme's own addresses where none were given."""
    pub = _lib('publish')
    if not ident:
        return {}
    if 'published' in b and not _flag(b.get('published'), 1):
        pub.set_published(store, ident, False, by)
        return {}
    return pub.fill_new(store, ident, _text(b, 'crl_url', 500), _text(b, 'aia_url', 500))


def _ident(got):
    if isinstance(got, dict):
        return got.get('id') or got.get('ca_id')
    return got


@api('POST', '/api/cas/import', 'fulladmin')
def _ca_import(h, s):
    """{name, cert_pem | data_b64 (+ filename, password), key_pem | key_b64 (+ key_password)}"""
    b = h.body()
    ca = _lib('ca')
    cert_pem = str(b.get('cert_pem') or '')
    key_pem = str(b.get('key_pem') or '')
    chain = []
    if b.get('data_b64'):
        _out, got = parse_file(_b64(b.get('data_b64')), _text(b, 'filename', 300),
                               _text(b, 'password', 1000))
        if got.get('needs_password'):
            raise ValueError('that password does not open the file' if _text(b, 'password', 1000)
                             else 'the file is locked: give its password')
        cert_pem = got.get('leaf') or ((got.get('certs') or [''])[0])
        key_pem = key_pem or got.get('key') or ''
        chain = list(got.get('chain') or [])
    if b.get('key_b64'):
        kg = _lib('formats').read_any(_b64(b['key_b64'], 'key_b64'), 'key.pem',
                                      _text(b, 'key_password', 1000)) or {}
        key_pem = kg.get('key') or ((kg.get('keys') or [''])[0]) or key_pem
    if not cert_pem:
        raise ValueError('no certificate of the authority was given')
    if not key_pem:
        raise ValueError('no key of the authority was given: without it, it cannot sign')
    name = S.clean_name(b.get('name'), 'the authority\'s name') if b.get('name') else \
        S.safe_name(S.info_of(cert_pem).get('cn') or 'imported CA', _names_in(h.store, 'cert_cas'))
    got = call(ca.ca_import, h.store, name, cert_pem, key_pem, chain_pems=chain,
               password=_text(b, 'key_password', 1000) or None, by=who(s))
    ident = _ident(got)
    filled = _published_new(h.store, ident, b, who(s))
    h.store.add_event('certificates', 'authority %s imported by %s%s' % (
        name, who(s), (' - published on acme (%s)' % filled['crl_url']) if filled else ''),
        who=who(s))
    return {'id': ident, 'published': bool(filled)}


@api('POST', '/api/cas/delete', 'fulladmin')
def _ca_delete(h, s):
    r = ca_row(h.store, h.body().get('id'))
    used = [x['name'] for x in h.store.db.rows("SELECT name, config FROM cert_issuers WHERE "
                                                "kind = 'internal_ca'")
            if str((S.jload(x['config'], {}) or {}).get('ca')) in (str(r['id']), r['name'])]
    if used:
        raise ValueError('the issuer(s) %s sign with %s: change them first' % (
            ', '.join(used), r['name']))
    _lib('ca').ca_delete(h.store, r['id'])
    if DF.forget(h.store, 'ca', r['id']):
        h.store.add_event('certificates', '%s was the default authority: there is none now'
                          % r['name'], 'warn', who=who(s))
    h.store.add_event('certificates', 'authority %s deleted by %s' % (r['name'], who(s)), 'warn',
                      who=who(s))
    return {'message': '%s deleted' % r['name']}


@api('POST', '/api/cas/crl', 'certadmin')
def _ca_crl(h, s):
    r = ca_row(h.store, h.body().get('id'))
    _lib('ca')._split_held()            # a CRL is signed (1.0.19, docs/split-brain.md)
    crl = _lib('ca').ca_crl(h.store, r['id'])
    data = crl.encode('ascii') if isinstance(crl, str) else bytes(crl or b'')
    h.store.add_event('certificates', 'a new CRL of %s made by %s' % (r['name'], who(s)),
                      who=who(s))
    return {'filename': re.sub(r'[^A-Za-z0-9._-]+', '_', r['name']) + '.crl.pem',
            'mime': 'application/x-pem-file', 'crl_pem': data.decode('ascii', 'replace'),
            'data_b64': base64.b64encode(data).decode('ascii')}


CA_KEY_EXPORTS = ('key', 'p12', 'pfx')


@api('POST', '/api/cas/export', 'readonly')
def _ca_export(h, s):
    """{id, format: cert | cert-der | chain | crl | crl-der | p7b | bundle | csr | key | p12,
    password?} - key and p12 for a full administrator only."""
    b = h.body()
    r = ca_row(h.store, b.get('id'))
    fmt = str(b.get('format') or 'cert').lower()
    if fmt in CA_KEY_EXPORTS and not may(s, 'fulladmin'):
        raise E.ApiError(403, 'only a full administrator may take an authority\'s key out')
    if fmt in ('crl', 'crl-pem', 'crl-der', 'bundle') and not may(s, 'certadmin'):
        raise E.ApiError(403, ROLE_WORDS['certadmin'])      # it may make a new CRL
    got = _lib('ca').ca_export(h.store, r['id'], fmt, password=_text(b, 'password', 1000) or None)
    data = got.get('data') or b''
    if isinstance(data, str):
        data = data.encode('utf-8')
    if fmt in CA_KEY_EXPORTS:
        h.store.add_event('certificates', 'the key of authority %s was exported by %s' % (
            r['name'], who(s)), 'warn', who=who(s))
    return {'filename': got.get('filename'), 'mime': got.get('mime'),
            'data_b64': base64.b64encode(data).decode('ascii')}


@api('POST', '/api/cas/sign_csr', 'fulladmin')
def _ca_sign(h, s):
    b = h.body()
    r = ca_row(h.store, b.get('id'))
    csr = str(b.get('csr_pem') or '')
    if 'CERTIFICATE REQUEST' not in csr:
        raise ValueError('csr_pem is a certificate request (PEM)')
    profile = {}
    if _list(b.get('eku'), 'eku'):
        profile['eku'] = _list(b.get('eku'), 'eku')
    got = _lib('ca').ca_sign(h.store, r['id'], csr, int(b.get('days') or r.get('days_default')
                                                       or 397), profile, None, who(s))
    if isinstance(got, dict):
        cert_pem, chain = got.get('cert_pem'), got.get('chain_pems') or []
    else:
        cert_pem, chain = got[0], list(got[1] or [])
    h.store.add_event('certificates', 'authority %s signed a CSR from elsewhere (asked by %s)'
                      % (r['name'], who(s)), who=who(s))
    return {'cert_pem': cert_pem, 'chain_pem': ''.join(chain), 'chain_pems': chain}


@api('POST', '/api/cas/revoke', 'fulladmin')
def _ca_revoke(h, s):
    """{id, serial, reason} - one certificate the authority signed, revoked."""
    b = h.body()
    r = ca_row(h.store, b.get('id'))
    serial = str(b.get('serial') or '').strip()
    if not serial:
        raise ValueError('which serial?')
    reason = str(b.get('reason') or 'unspecified')
    _lib('ca').ca_revoke(h.store, r['id'], serial, reason, who(s))
    h.store.add_event('certificates', 'authority %s revoked serial %s (%s) - %s' % (
        r['name'], serial, reason, who(s)), 'warn', who=who(s))
    return {'message': 'serial %s revoked' % serial}


# ---- publishing on acme (publish.py): the authority's side -------------------------
@api('GET', '/api/cas/pki')
def _ca_pki(h, s):
    r = ca_row(h.store, h.arg('id') or h.arg('name'))
    return {'pki': _lib('publish').view(h.store, r['id'])}


@api('POST', '/api/cas/publish', 'fulladmin')
def _ca_publish(h, s):
    """{id, published} - the authority's CRL and certificate on acme, or not."""
    b = h.body()
    r = ca_row(h.store, b.get('id'))
    pub = _lib('publish')
    yes = pub.set_published(h.store, r['id'], _flag(b.get('published'), 1), who(s))
    return {'published': pub.is_published(h.store, r['id']), 'switch': yes,
            'pki': pub.view(h.store, r['id']),
            'message': '%s %s' % (r['name'], 'published' if yes else 'no longer published')}


@api('POST', '/api/cas/pki_urls', 'fulladmin')
def _ca_pki_urls(h, s):
    """{id} - acme's own addresses put into what the authority signs from now on."""
    r = ca_row(h.store, h.body().get('id'))
    pub = _lib('publish')
    u = pub.use_own_urls(h.store, r['id'], who(s))
    return {'crl_url': u['crl'], 'aia_url': u['cert'], 'pki': pub.view(h.store, r['id']),
            'message': 'what %s signs from now on points at acme' % r['name']}


@api('POST', '/api/cas/pki_check', 'certadmin')
def _ca_pki_check(h, s):
    """{id} - the published CRL and certificate fetched over HTTP and checked."""
    r = ca_row(h.store, h.body().get('id'))
    got = _lib('publish').check(h.store, r['id'])
    got['said'] = got['steps'][-1][1] if got.get('steps') else ''
    return got


# ---- publishing on acme: what anybody may fetch (web/pki.php, no sign-in) --------------
def _pki_public(h, what):
    pub = _lib('publish')
    if not pub.allowed(h.client_ip() if hasattr(h, 'client_ip') else ''):
        raise E.ApiError(429, 'too many requests - try again in a moment')
    try:
        if what == 'index':
            return {'published': pub.index(h.store), 'on': pub.on()}
        fmt = 'pem' if str(h.arg('format') or '').lower() == 'pem' else 'der'
        data, mime, filename = pub.serve(h.store, what, h.arg('ca'), fmt)
    except LookupError:
        raise E.ApiError(404, 'not found')
    return {'mime': mime, 'filename': filename, 'data_b64': base64.b64encode(data).decode('ascii')}


@E.route('GET', '/api/pki/index')
def _pki_index(h):
    return _pki_public(h, 'index')


@E.route('GET', '/api/pki/crl')
def _pki_crl(h):
    return _pki_public(h, 'crl')


@E.route('GET', '/api/pki/cert')
def _pki_cert(h):
    return _pki_public(h, 'cert')


# ---------------------------------------------------------------------------
# The modules
# ---------------------------------------------------------------------------
def options_for(store, source):
    """[[value, words]] for a field's options_from."""
    if source == 'cas':
        return [[r['name'], r['name'] + ('' if r.get('key_sealed') else ' (no key)')]
                for r in store.db.rows('SELECT name, key_sealed FROM cert_cas WHERE '
                                       'COALESCE(disabled, 0) = 0 ORDER BY name')]
    if source == 'tests':
        # the tests a set run through SSH may hold (checks/ssh_relay.py): not another set
        return [[r['name'], '%s (%s)' % (r['name'], r['kind'])]
                for r in store.db.rows('SELECT name, kind FROM cert_tests ORDER BY name')
                if r['kind'] != 'ssh_relay']
    table = {'challenges': 'cert_challenges', 'issuers': 'cert_issuers',
             'targets': 'cert_targets', 'sources': 'cert_issuers',
             'validations': 'cert_challenges'}.get(source)
    if table:
        return [[r['name'], '%s (%s)' % (r['name'], r['kind'])]
                for r in store.db.rows('SELECT name, kind FROM %s ORDER BY name' % table)]
    if source == 'dns_writers':
        # the DNS validations that can write a TXT record that stays (dns_persist.py)
        from acmelib.plugins.challenges import dns_persist
        return [[r['name'], '%s (%s)' % (r['name'], r['kind'])]
                for r in store.db.rows('SELECT name, kind FROM cert_challenges ORDER BY name')
                if dns_persist.can_write(S.row_class('challenge', r))]
    if source == 'certs':
        return [[r['name'], r['name']] for r in store.db.rows('SELECT name FROM certs ORDER BY name')]
    if source == 'ssh_targets':
        # targets a test can go through over SSH (checks/ssh_relay.py): their sign-in
        from acmelib.plugins.targets._common import SshMixin
        return [[r['name'], '%s (%s)' % (r['name'], r['kind'])]
                for r in store.db.rows('SELECT name, kind, config FROM cert_targets ORDER BY name')
                if issubclass(S.row_class('target', r) or object, SshMixin)]
    if source == 'connectors':
        # the connectors a target over SSH can be reached through: those of the targets
        # (targets/ssh_connector.py, 1.0.75), then those of the tests (checks/ssh_relay.py, 1.0.74)
        own = [r['name'] for r in store.db.rows(
            "SELECT name FROM cert_targets WHERE kind = 'ssh_connector' ORDER BY name")]
        tests = [r['name'] for r in store.db.rows(
            "SELECT name FROM cert_tests WHERE kind = 'ssh_relay' ORDER BY name")]
        return [[n, n] for n in own] + [[n, '%s (a connector of the tests)' % n]
                                        for n in tests if n not in own]
    if source == 'test_connectors':
        # the connectors of the tests (checks/ssh_relay.py) a test can go through (1.0.76),
        # then those of the targets (1.0.77): a target's test goes the way its deployment goes
        own = [r['name'] for r in store.db.rows(
            "SELECT name FROM cert_tests WHERE kind = 'ssh_relay' ORDER BY name")]
        tg = [r['name'] for r in store.db.rows(
            "SELECT name FROM cert_targets WHERE kind = 'ssh_connector' ORDER BY name")]
        return [[n, n] for n in own] + [[n, '%s (a connector of the targets)' % n]
                                        for n in tg if n not in own]
    if source == 'key_types':
        return [[k, k] for k in schema.KEY_TYPES]
    return []


def _resolve(store, fields):
    """The fields with the choices of their options_from - an authority's
    field preselecting the default authority."""
    out = []
    dca = None
    for f in fields or []:
        f = dict(f)
        if f.get('options_from'):
            # an empty choice the field offers itself ('none', 'by hand') stays first
            empty = [o for o in (f.get('options') or []) if isinstance(o, (list, tuple)) and
                     o and o[0] == '']
            f['options'] = empty[:1] + options_for(store, f['options_from'])
            if f['options_from'] == 'cas':
                if dca is None:
                    row = DF.default_ca(store)
                    dca = row['name'] if row else ''
                if dca and any(o[0] == dca for o in f['options']):
                    f['default'] = dca
        out.append(f)
    return out


def _names_in(store, table):
    return {str(r['name']) for r in store.db.rows('SELECT name FROM %s' % table)}


# The name a new one of these is offered with, where the module says none.
SUGGESTED = {('challenge', 'dns_builtin'): DF.DNS_OWN, ('challenge', 'http_local'): DF.HTTP_LOCAL}


def plugins_view(store, again=False):
    from acmelib.certs import custom_modules as CM
    CM.keep_current(store, every=0 if again else 5.0)
    reg = S.registry(again)
    d = reg.describe()
    for fam in d:
        for one in d[fam]:
            one['default_name'] = S.safe_name(one.get('default_name') or SUGGESTED.get(
                (fam, one.get('kind'))) or one.get('title') or one.get('kind'))
            one['fields'] = _resolve(store, one.get('fields'))
            if fam in ('issuer', 'challenge'):
                # what one certificate may set itself (store.over_fields)
                pcls = S.row_class(fam, one)
                one['cert_fields'] = [f['key'] for f in S.over_fields(pcls, full=True)]
                # where a file is written: a full administrator's alone (1.0.26)
                one['cert_fields_full'] = S.place_keys(pcls)
            if 'deploy_fields' in one:
                one['deploy_fields'] = _resolve(store, one.get('deploy_fields'))
            for v in one.get('versions') or []:
                # each version's form, its choices resolved as the default one's
                v['fields'] = _resolve(store, v.get('fields'))
                if 'deploy_fields' in v:
                    v['deploy_fields'] = _resolve(store, v.get('deploy_fields'))
    d['broken'] = [{'file': b[0], 'words': b[1]} for b in reg.broken]
    d['shadowed'] = [dict(x) for x in getattr(reg, 'shadowed', [])]      # 1.0.35
    # modules of your own: kept in the database, compared with the other nodes (1.0.32)
    from acmelib.certs import custom_modules as CM
    try:
        d['custom'] = CM.status(store)
    except Exception as e:                              # noqa: BLE001
        d['custom'] = {'error': str(e)}
    try:
        d['marks'] = CM.marks(store)            # tested / works, here and by the release
        d['released'] = CM.released()
    except Exception:                                   # noqa: BLE001
        d['marks'], d['released'] = {}, {}
    return d


@api('GET', '/api/plugins')
def _plugins(h, s):
    again = h.arg('reload') in ('1', 'yes') and may(s, 'fulladmin')
    return plugins_view(h.store, again)


# ---- issuers (sources), challenges (validations), targets: one shape ---------------
def family_rows(store, family, full=False):
    table = S.TABLE_OF[family]
    return [S.plugin_public(store, family, r, full) for r in store.db.rows(
        'SELECT * FROM %s ORDER BY %s' % (table, store.db.name_order()))]


def family_save(store, family, b, by):
    table = S.TABLE_OF[family]
    t = time.time()
    row = S.plugin_row(store, family, _id(b['id'])) if b.get('id') not in (None, '', 0) else None
    if b.get('id') not in (None, '', 0) and not row:
        raise LookupError('there is no such %s' % family)
    name = S.clean_name(b.get('name') if 'name' in b or not row else row['name'],
                        'the name')
    other = store.db.row('SELECT id FROM %s WHERE name = ?' % table, (name,))
    if other and (not row or other['id'] != row['id']):
        raise ValueError('there is one called %s already' % name)
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.given_class(family, kind, b.get('config'), row)
    if cls is None and (not row or kind != row.get('kind')):
        raise ValueError('there is no %s module "%s"' % (family, kind))
    if isinstance(b.get('config'), dict) and S.VERSION_KEY in b['config']:
        # the version of the module it uses (1.0.32): one that is there, or none
        v = str(b['config'].get(S.VERSION_KEY) or '').strip()
        have = S.registry().versions_of(family, kind)
        if v and v not in have:
            raise ValueError('the module %s has no version "%s" - it has: %s' % (
                kind, v, ', '.join(sorted(k or '(plain)' for k in have)) or 'none'))
        b['config'][S.VERSION_KEY] = v
    secrets_ = S.secret_fields(cls)
    given = _dict(b.get('config'), 'config') if 'config' in b else None
    if cls is None and given is not None and row is not None and \
            given != (S.jload(row.get('config'), {}) or {}):
        # Its module did not load (1.0.78): which settings are secrets is not known, so the
        # dots of a kept one were saved over it, and a secret typed in was kept unsealed.
        raise ValueError('the module %s of %s is missing (taken away, or it did not load): its '
                         'settings cannot be changed until it is back - its name, its note and '
                         'switching it on or off can' % (kind, row['name']))
    fields = {'name': name, 'kind': kind, 'updated': t}
    if 'enabled' in b or not row:
        fields['enabled'] = _flag(b.get('enabled'), 1)
    if 'note' in b or not row:
        fields['note'] = _text(b, 'note', 4000)
    if family == 'target' and ('tags' in b or not row):
        fields['tags'] = json.dumps(_tags_of(b))
    made = None
    if row is None:
        fields.update({'config': '{}', 'state': '{}', 'created': t, 'created_by': str(by)[:190]})
        ident = store.db.insert(table, fields)
        row = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (ident,))
        fields = {}
        made = ident
    try:
        return _family_fill(store, family, table, row, name, kind, cls, given, fields,
                            secrets_, by)
    except BaseException:
        if made is not None:
            # A new one refused (1.0.45): not left half made - "there is one called X already"
            # at every try after.
            store.db.run('DELETE FROM %s WHERE id = ?' % table, (made,))
        raise


def _family_fill(store, family, table, row, name, kind, cls, given, fields, secrets_, by):
    old_cfg = S.jload(row.get('config'), {}) or {}
    if given is not None:
        if row.get('kind') != kind:
            old_cfg = {}            # another module: nothing of the old one's kept
        cfg = S.config_seal(given, old_cfg, '%s:%s' % (table, row['id']), secrets_)
        if cls is not None:
            for f in cls.fields or []:
                if f.get('required') and field_shown(f, cfg) and \
                        cfg.get(f['key']) in (None, '') and f.get('default') in (None, ''):
                    raise ValueError('%s: %s is needed' % (name, f.get('label') or f['key']))
        if len(json.dumps(cfg)) > 200000:
            raise ValueError('those settings are too big')
        if family == 'target' and cfg.get('script_body'):
            from acmelib.plugins.targets import _script
            _script.check_body(cfg['script_body'])
        fields['config'] = json.dumps(cfg)
    if fields:
        store.db.update(table, row['id'], fields)
    if row['name'] != name:
        _renamed(store, family, row['name'], name)
    store.add_event('certificates', '%s %s %s by %s' % (
        {'issuer': 'issuer', 'challenge': 'challenge', 'target': 'target', 'check': 'test'}[family], name,
        'saved', by), who=by)
    return row['id']


def _renamed(store, family, old, new):
    """What referred to it by name, made to refer to the new name."""
    db = store.db
    DF.renamed(store, family, old, new)
    # What else names it (1.0.45), as names.migrate() does: the request profiles, the
    # portal's settings, the module's own kept values (an ACME source's account).
    from acmelib.certs import names as NM, reqprofiles as RP
    if family in ('issuer', 'challenge'):
        RP.rename_source(store, family, old, new)
        NM._list_setting(store, 'portal_cert_issuers' if family == 'issuer'
                         else 'portal_cert_challenge', {old: new})
    NM._kv(store, family, old, new)
    if family in ('target', 'check'):
        _via_renamed(store, family, old, new)
    if family == 'issuer':
        db.run('UPDATE certs SET issuer = ? WHERE issuer = ?', (new, old))
    elif family == 'check':
        db.run('UPDATE cert_checks SET test = ? WHERE test = ?', (new, old))
        for r in db.rows("SELECT id, config FROM cert_tests WHERE kind = 'ssh_relay'"):
            cfg = S.jload(r['config'], {}) or {}
            if old in (cfg.get('tests') or []):
                cfg['tests'] = [new if x == old else x for x in cfg['tests']]
                db.update('cert_tests', r['id'], {'config': json.dumps(cfg)})
    elif family == 'target':
        db.run('UPDATE cert_deploys SET target = ? WHERE target = ?', (new, old))
        # the tests run after a deployment on it (1.0.77): they never ran again, silently
        for r in db.rows('SELECT id, after_target FROM cert_checks WHERE after_target LIKE ?',
                         ('%' + old + '%',)):
            got = [new if x == old else x for x in str(r['after_target'] or '').split('\n')]
            if got != str(r['after_target'] or '').split('\n'):
                db.update('cert_checks', r['id'], {'after_target': '\n'.join(got)})
    else:
        db.run('UPDATE certs SET challenge = ? WHERE challenge = ?', (new, old))
        S.over_validation_renamed(store, old, new)
        for r in db.rows('SELECT id, challenge_map FROM certs WHERE challenge_map LIKE ?',
                         ('%' + json.dumps(old) + '%',)):
            cmap = S.jload(r['challenge_map'], {}) or {}
            cmap = {k: (new if v == old else v) for k, v in cmap.items()}
            db.update('certs', r['id'], {'challenge_map': json.dumps(cmap)})


def _via_renamed(store, family, old, new):
    """The targets and tests that go through a connector renamed (1.0.77): they named the old
    one, and every one of them failed "there is no connector called ..."."""
    db = store.db
    for table in ('cert_tests', 'cert_targets'):
        # each names its own family's connector first (a test may go through a target's, 1.0.77)
        if table == 'cert_targets' and family == 'check' and db.row(
                "SELECT 1 AS x FROM cert_targets WHERE name = ? AND kind = 'ssh_connector'", (old,)):
            continue
        if table == 'cert_tests' and family == 'target' and db.row(
                "SELECT 1 AS x FROM cert_tests WHERE name = ? AND kind = 'ssh_relay'", (old,)):
            continue
        for r in db.rows('SELECT id, config FROM %s WHERE config LIKE ?' % table,
                         ('%' + json.dumps(old) + '%',)):
            cfg = S.jload(r['config'], {}) or {}
            if str(cfg.get('via') or '') == old:
                cfg['via'] = new
                db.update(table, r['id'], {'config': json.dumps(cfg)})


def family_uses(store, family, row):
    """Where a module is used (1.0.83), each place with what it does there and whether
    deleting it with "take it off everywhere first" may undo it (`free`): a deployment to a
    target and a test attached to a certificate may; a certificate issued or validated by it,
    and what goes through a connector may not - those are changed there first."""
    db, name, out = store.db, row['name'], []

    def cert(r, said, free, ident=None):
        out.append({'where': 'certificate', 'name': r['name'], 'cert_id': r['cid'],
                    'id': ident, 'said': said, 'free': free})
    if family == 'issuer':
        for r in db.rows('SELECT id AS cid, name FROM certs WHERE issuer = ? ORDER BY name',
                         (name,)):
            cert(r, 'issued by it', False)
    elif family == 'challenge':
        for r in db.rows('SELECT id AS cid, name, challenge, challenge_map FROM certs WHERE '
                         'challenge = ? OR challenge_map LIKE ? ORDER BY name',
                         (name, '%' + json.dumps(name) + '%')):
            if r.get('challenge') == name or name in json.dumps(S.jload(r.get('challenge_map'), {})):
                cert(r, 'validated by it', False)
    elif family == 'check':
        for r in db.rows('SELECT k.id, c.id AS cid, c.name FROM cert_checks k JOIN certs c '
                         'ON c.id = k.cert_id WHERE k.test = ? ORDER BY c.name', (name,)):
            cert(r, 'tested by it', True, r['id'])
        for r in db.rows("SELECT id, name, config FROM cert_tests WHERE kind = 'ssh_relay' "
                         "ORDER BY name"):
            if name in ((S.jload(r.get('config'), {}) or {}).get('tests') or []):
                out.append({'where': 'test', 'name': r['name'], 'id': r['id'],
                            'said': 'in the tests it runs', 'free': True})
    else:
        for r in db.rows('SELECT d.id, c.id AS cid, c.name FROM cert_deploys d JOIN certs c '
                         'ON c.id = d.cert_id WHERE d.target = ? ORDER BY c.name', (name,)):
            cert(r, 'deployed there', True, r['id'])
    if (family == 'target' and row.get('kind') == 'ssh_connector') or \
            (family == 'check' and row.get('kind') == 'ssh_relay'):
        # as via_users counts them: each names its own family's connector first
        tg_own = db.row("SELECT 1 AS x FROM cert_targets WHERE name = ? AND kind = "
                        "'ssh_connector'", (name,))
        ts_own = db.row("SELECT 1 AS x FROM cert_tests WHERE name = ? AND kind = 'ssh_relay'",
                        (name,))
        for table, where in (('cert_targets', 'target'), ('cert_tests', 'test')):
            if family == 'check' and table == 'cert_targets' and tg_own:
                continue
            if family == 'target' and table == 'cert_tests' and ts_own:
                continue
            for r in db.rows('SELECT id, name, config FROM %s WHERE config LIKE ? ORDER BY name'
                             % table, ('%' + json.dumps(name) + '%',)):
                if str((S.jload(r.get('config'), {}) or {}).get('via') or '') == name:
                    out.append({'where': where, 'name': r['name'], 'id': r['id'],
                                'said': 'goes through it', 'free': False})
    if family in ('issuer', 'challenge'):
        key = 'portal_cert_issuers' if family == 'issuer' else 'portal_cert_challenge'
        have = E.CONFIG.get(key) or ''
        have = have if isinstance(have, list) else re.split(r'[\s,;]+', str(have))
        if name in [str(x).strip() for x in have]:
            out.append({'where': 'setting', 'name': 'Settings \u2192 the enrolment pages',
                        'said': 'the portal uses it', 'free': False})
        from acmelib.certs import reqprofiles as RP
        for p in RP.using_source(store, family, name):
            out.append({'where': 'request profile', 'name': p, 'said': 'uses it',
                        'free': False})
    return out


def _uses_said(row, uses):
    held = [u for u in uses if not u['free']] or uses
    names = ['%s %s' % (u['where'], u['name']) for u in held[:8]]
    more = len(held) - len(names)
    return '%s is in use - %s%s: %s' % (
        row['name'], ', '.join(names), (' and %d more' % more) if more > 0 else '',
        'change those first' if held is not uses else
        'take it off there first, or delete it with "take it off everywhere first"')


def _unbind(store, family, row, uses, by):
    """What `free` places hold undone, before the module goes (1.0.83)."""
    from acmelib.certs import checks as C
    for u in uses:
        if family == 'target' and u['where'] == 'certificate':
            if jobs.cert_busy(store, u['cert_id']):
                raise ValueError('a job is working on %s - wait for it to end' % u['name'])
    for u in uses:
        if family == 'target' and u['where'] == 'certificate':
            store.db.run('DELETE FROM cert_deploys WHERE id = ?', (u['id'],))
            C.target_gone(store, u['cert_id'], row['name'])
            store.add_event('certificates', 'the deployment of %s to %s taken off by %s' % (
                u['name'], row['name'], by), who=by)
        elif family == 'check' and u['where'] == 'certificate':
            C.detach(store, u['id'])
            store.add_event('certificates', 'the test %s taken off %s by %s' % (
                row['name'], u['name'], by), who=by)
        elif family == 'check' and u['where'] == 'test':
            r = store.db.row('SELECT config FROM cert_tests WHERE id = ?', (u['id'],))
            cfg = S.jload((r or {}).get('config'), {}) or {}
            cfg['tests'] = [x for x in (cfg.get('tests') or []) if x != row['name']]
            store.db.update('cert_tests', u['id'], {'config': json.dumps(cfg)})
            store.add_event('certificates', 'the test %s taken out of %s by %s' % (
                row['name'], u['name'], by), who=by)


def family_delete(store, family, b, by):
    row = S.plugin_row(store, family, _id(b.get('id')))
    if not row:
        raise LookupError('there is no such %s' % family)
    uses = family_uses(store, family, row)
    force = b.get('force') not in (None, '', 0, '0', False, 'false')
    if uses and (not force or not all(u['free'] for u in uses)):
        raise ValueError(_uses_said(row, uses))
    if family == 'target' and store.db.value(
            "SELECT COUNT(*) FROM cert_jobs WHERE target = ? AND state IN ('queued', 'running') "
            "AND ts > ?", (row['name'], time.time() - 7200), 0):
        raise ValueError('a job is working with %s - wait for it to end' % row['name'])
    if uses:
        _unbind(store, family, row, uses, by)
    store.db.run('DELETE FROM %s WHERE id = ?' % S.TABLE_OF[family], (row['id'],))
    # Its own rows only (1.0.44): LIKE read "_" as any character, and SQLite's ignores
    # case - deleting dc_1 took dc-1's (an aws-acm ARN) with it.
    kv = '%s%s:%s:' % (runtime.KV_PREFIX, family, row['name'])
    for r in store.db.rows('SELECT k FROM meta WHERE k LIKE ?', (kv + '%',)):
        if r['k'].startswith(kv):
            store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
    if DF.forget(store, family, row['name']):
        store.add_event('certificates', '%s was the default %s: there is none now' % (
            row['name'], DF.WORDS[family]), 'warn', who=by)
    store.add_event('certificates', '%s %s deleted by %s' % (family, row['name'], by), 'warn',
                    who=by)
    return row['name']


def persist_cleanup(store, b, by):
    """Before a dns-persist-01 validation is deleted (its "Also remove its records from
    DNS"): what acme wrote taken away, in a job - nothing is deleted when that fails."""
    row = S.plugin_row(store, 'challenge', _id(b.get('id')))
    if not row:
        raise LookupError('there is no such validation')
    if row.get('kind') != 'dns_persist':
        return {}
    used = S.plugin_public(store, 'challenge', row)['used_by']
    if used:
        raise ValueError('%s is in use (%d): change those first' % (row['name'], used))
    got = family_action(store, 'challenge', {'id': row['id'], 'action': 'remove_records'}, by)
    if not got['ok']:
        raise ValueError('its records were not all taken away from DNS (%s) - nothing was '
                         'deleted' % got['said'])
    return {'job_id': got['job_id'], 'cleanup': got['said']}


def _same_value(f, a, b):
    if f.get('type') == 'bool':
        def yes(v):
            return str(v).strip().lower() in ('1', 'true', 'yes', 'on')
        return yes(a) == yes(b)
    if f.get('type') == 'list':
        def items(v):
            v = v if isinstance(v, (list, tuple)) else re.split(r'[\n,]', str(v or ''))
            return [str(x).strip() for x in v if str(x).strip()]
        return items(a) == items(b)
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    return str('' if a is None else a).strip() == str('' if b is None else b).strip()


def saved_only(s, b, what='try'):
    """Settings nobody saved, tried - a full administrator's (1.0.48 for Test; 1.0.78 for
    discovery, catalogs and the SSH key's Try too: any kind with any host made acme connect
    anywhere for a certificate administrator, and what answered was said back). Theirs: the
    module as it is saved - the settings given are dropped."""
    if str(s.get('role') or '') == 'fulladmin' or s.get('cli'):
        return b
    if b.get('id') in (None, '', 0):
        raise E.ApiError(403, 'only a full administrator may %s settings that are not saved - '
                              'save them first, or use the one saved' % what)
    b = dict(b)
    b.pop('config', None)
    b.pop('kind', None)
    return b


def kept_secrets_guard(store, family, b, s, kind=None):
    """A saved module's settings tried changed (Test, Try reaching it, discovery)
    use the secrets it keeps: changed by anybody but a full administrator - who
    alone may save it - those secrets could be sent elsewhere (another API
    address, another host), so that is refused. Tried as saved, or with every
    secret typed in again, it is not."""
    if may(s, 'fulladmin') or b.get('id') in (None, '', 0) or \
            not isinstance(b.get('config'), dict):
        return
    row = S.plugin_row(store, family, _id(b['id']))
    kind = kind or str(b.get('kind') or (row or {}).get('kind') or '')
    if not row or row.get('kind') != kind:
        return
    cls = S.given_class(family, kind, b.get('config'), row)
    if cls is None:
        return
    secrets_ = S.secret_fields(cls)
    given = b['config']
    if not any(given.get(k) in (None, '') or E.is_masked(given.get(k))
               for k in secrets_ if S.plugin_config(family, row).get(k)):
        return                          # every kept secret given again: none of them used
    saved = S.plugin_config(family, row)
    for f in cls.fields or []:
        k = f.get('key')
        if not k or k in secrets_ or f.get('type') == 'sshkey' or k not in given:
            continue
        if not _same_value(f, given[k], saved.get(k, f.get('default'))):
            raise E.ApiError(403, 'settings that are not saved are tried with the secrets '
                                  'kept by a full administrator')


def family_test(store, family, b, by, echo=None):
    """The module tried as saved, or with the settings given over them."""
    table = S.TABLE_OF[family]
    row = S.plugin_row(store, family, _id(b['id'])) if b.get('id') not in (None, '', 0) else None
    if b.get('id') not in (None, '', 0) and not row:
        raise LookupError('there is no such %s' % family)
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.given_class(family, kind, b.get('config'), row)
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (family, kind))
    cfg = S.plugin_config(family, row) if row and row.get('kind') == kind else {}
    for k, v in (_dict(b.get('config'), 'config') or {}).items():
        if k in S.secret_fields(cls) and (v in (None, '') or E.is_masked(v)):
            continue                # "" or the dots shown: the one kept
        cfg[k] = v
    name = (row or {}).get('name') or str(b.get('name') or 'unsaved')

    # settings other than those saved (1.0.51): the form sends all of them, the same ones too
    saved_cfg = S.plugin_config(family, row) if row and row.get('kind') == kind else {}
    secrets_t = set(S.secret_fields(cls))
    fdef = {f.get('key'): f for f in (cls.fields or []) if f.get('key')}
    tried_other = not row or row.get('kind') != kind or any(
        not (k in secrets_t and (v in (None, '') or E.is_masked(v))) and
        not _same_value(fdef.get(k) or {}, v, saved_cfg.get(k, (fdef.get(k) or {}).get('default')))
        for k, v in (_dict(b.get('config'), 'config') or {}).items())

    def fn(job):
        # Settings tried before they are saved (1.0.51): the key of a host only tried is not
        # written into the one saved - a deployment then trusted it, or failed for good.
        if family == 'target' and row and not tried_other:
            ctx = deployer.target_context(store, job, row)
        else:
            ctx = runtime.RunContext(store, job, scope='%s:%s' % (family, name),
                                     on_hostkey=None if (row and not tried_other) else False)
        try:
            job.step('trying %s %s (%s)' % (family, name, kind))
            said = cls(cfg, ctx).test()
            job.step(str(said or 'it works'), 'ok')
            return True, str(said or 'it works')
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'test', fn, target=name if family == 'target' else None, by=by,
                       said='%s %s' % (family, name), echo=echo)
    if row:
        store.db.update(table, row['id'], {'last_ok': time.time(), 'last_error': ''} if job.ok
                        else {'last_error': job.said[:2000]})
    return {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps}


def family_action(store, family, b, by, echo=None):
    """One of a module's actions (Plugin.actions) run on a saved row, in a job of
    its own: {ok, said, job_id, steps}."""
    row = S.plugin_row(store, family, b.get('id') if b.get('id') not in (None, '', 0)
                       else b.get('name'))
    if not row:
        raise LookupError('there is no such %s' % family)
    cls = S.row_class(family, row)
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (family, row.get('kind')))
    key = str(b.get('action') or '').strip()
    act = next((a for a in (cls.actions or []) if a.get('key') == key), None)
    if not act:
        raise ValueError('%s (%s) can do %s' % (row['name'], row['kind'], ', '.join(
            a['key'] for a in cls.actions or []) or 'nothing besides its work'))
    cfg = S.plugin_config(family, row)
    got = {}

    def fn(job):
        if family == 'target':
            ctx = deployer.target_context(store, job, row)
        else:
            ctx = runtime.RunContext(store, job, scope='%s:%s' % (family, row['name']))
        try:
            job.step('%s %s (%s): %s' % (family, row['name'], row['kind'], act.get('label') or key))
            said = cls(cfg, ctx).action(key)
            if isinstance(said, dict):
                # a file to hand over (a config to put in place by hand)
                if said.get('file'):
                    got['file'] = said['file']
                said = said.get('said')
            job.step(str(said or 'done'), 'ok')
            return True, str(said or 'done')
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'action', fn, target=row['name'] if family == 'target' else None,
                       by=by, said='%s %s: %s' % (family, row['name'], key), echo=echo)
    store.add_event('certificates', '%s %s: "%s" run by %s - %s' % (
        family, row['name'], act.get('label') or key, by, 'done' if job.ok else 'failed: %s'
        % job.said), 'info' if job.ok else 'warn', who=by)
    out = {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps,
           'action': key}
    if got.get('file') and job.ok:
        f = got['file']
        out['file'] = {'name': str(f.get('name') or 'file.txt'), 'text': str(f.get('text') or '')}
    return out


def action_role(family, b, store):
    """An action that changes something elsewhere needs a full administrator."""
    row = S.plugin_row(store, family, b.get('id') if b.get('id') not in (None, '', 0)
                       else b.get('name'))
    cls = S.row_class(family, row) if row else None
    act = next((a for a in (getattr(cls, 'actions', None) or [])
                if a.get('key') == str(b.get('action') or '')), None)
    return 'fulladmin' if (act or {}).get('changes', True) else 'certadmin'


def _family_routes(family, path):
    @api('GET', '/api/%s' % path)
    def _rows(h, s):
        DF.ensure(h.store)
        return {'rows': family_rows(h.store, family, may(s, 'fulladmin'))}

    @api('POST', '/api/%s/action' % path, 'certadmin')
    def _action(h, s):
        b = h.body()
        if not may(s, action_role(family, b, h.store)):
            raise E.ApiError(403, ROLE_WORDS['fulladmin'])
        return family_action(h.store, family, b, who(s))

    @api('POST', '/api/%s/save' % path, 'fulladmin')
    def _save(h, s):
        return {'id': family_save(h.store, family, h.body(), who(s))}

    @api('POST', '/api/%s/delete' % path, 'fulladmin')
    def _delete(h, s):
        b = h.body()
        out = {}
        if family == 'challenge' and b.get('cleanup') not in (None, '', 0, '0', False, 'false'):
            out.update(persist_cleanup(h.store, b, who(s)))
        out['message'] = '%s deleted' % family_delete(h.store, family, b, who(s))
        return out

    @api('GET', '/api/%s/uses' % path, 'fulladmin')
    def _uses(h, s):
        row = S.plugin_row(h.store, family, _id(h.arg('id')))
        if not row:
            raise LookupError('there is no such %s' % family)
        uses = family_uses(h.store, family, row)
        return {'name': row['name'], 'uses': uses,
                'free': bool(uses) and all(u['free'] for u in uses)}

    @api('POST', '/api/%s/test' % path, 'certadmin')
    def _test(h, s):
        b = h.body()
        kept_secrets_guard(h.store, family, b, s)
        # Settings nobody saved, tried, are a full administrator's (1.0.48), as saving them is:
        # any kind with any host made acme connect anywhere for a certificate administrator
        # (a scan of the inside, what answered said back). Theirs: the module as it is saved.
        if str(s.get('role') or '') != 'fulladmin' and not s.get('cli'):
            if b.get('id') in (None, '', 0):
                raise E.ApiError(403, 'only a full administrator may try settings that are not '
                                      'saved - save them first, or try the one saved')
            b = {'id': b.get('id')}
        return family_test(h.store, family, b, who(s))

    @api('POST', '/api/%s/default' % path, 'fulladmin')
    def _default(h, s):
        """{name} - made the default; '' for none."""
        b = h.body()
        ref = b.get('name') if 'name' in b else b.get('id')
        got = DF.set_default(h.store, family, '' if ref in (None, 0) else ref, who(s))
        return {'default': got, 'message': ('%s is the default now' % got) if got else
                'there is no default now'}


# ---- HTTP-01 answered by acme (http_local): how it works here -----------------------
@api('GET', '/api/validations/info')
def _validation_info(h, s):
    """?name= (or id=) - the URL the CA fetches, the nodes and the VIP address
    that answer it, port 80 in their firewall, the names that use it and where
    each points (httpinfo.info)."""
    row = S.plugin_row(h.store, 'challenge', h.arg('id') or h.arg('name'))
    if not row:
        raise LookupError('there is no such validation')
    # Of the certificates using it only those this account sees (1.0.51), and no secret
    # setting of the validation in the open.
    T = _lib('teams')
    sc = T.scope(h.store, s, 'view')
    seen = None if sc is None else {r['name'] for r in h.store.db.rows('SELECT name, owner FROM '
                                                                       'certs')
                                    if T.owner_in(sc, r.get('owner'))}
    got = _lib('httpinfo').info(h.store, row, seen)
    cls = S.row_class('challenge', row)
    secret = set(S.secret_fields(cls)) if cls else set()
    for f in got.get('fields') or []:
        if f.get('key') in secret and f.get('value'):
            f['value'] = '••••••••'
    return got


@api('POST', '/api/validations/check', 'certadmin')
def _validation_check(h, s):
    """{id|name, host} - a probe token fetched at http://HOST/.well-known/
    acme-challenge/ from here, in a job."""
    b = h.body()
    row = S.plugin_row(h.store, 'challenge', b.get('id') if b.get('id') not in (None, '', 0)
                       else b.get('name'))
    if not row:
        raise LookupError('there is no such validation')
    host = _text(b, 'host', 253).strip()
    if not host:
        raise ValueError('which name?')
    return _lib('httpinfo').check(h.store, row, host, who(s))


_family_routes('issuer', 'sources')
_family_routes('challenge', 'validations')
_family_routes('target', 'targets')
_family_routes('check', 'tests')


def acme_contact(store, email, by, every=False):
    """The contact e-mail set on the ACME sources that have none (every: on all)."""
    email = str(email or '').strip()
    if email.startswith('mailto:'):
        email = email[7:]
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+\Z', email) or len(email) > 254:
        raise ValueError('%r is not an e-mail address' % email)
    missing = set(DF.contact_missing(store))
    done = []
    for r in store.db.rows("SELECT * FROM cert_issuers WHERE kind = 'acme' ORDER BY name"):
        if not every and r['name'] not in missing:
            continue
        cfg = S.jload(r.get('config'), {}) or {}
        cfg['contacts'] = [email]
        store.db.update('cert_issuers', r['id'], {'config': json.dumps(cfg),
                                                  'updated': time.time()})
        done.append(r['name'])
    if done:
        store.add_event('certificates', 'the contact e-mail of %s set to %s by %s' % (
            ', '.join(done), email, by), who=by)
    return done


@api('POST', '/api/sources/contact', 'fulladmin')
def _sources_contact(h, s):
    b = h.body()
    done = acme_contact(h.store, b.get('email'), who(s), every=_flag(b.get('all')))
    return {'sources': done, 'message': ('set on %s' % ', '.join(done)) if done else
            'every ACME source has a contact e-mail already'}


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------
def deploy_save(store, b, by, full=True):
    """A deployment saved. `full`: by a full administrator - only one may change
    the script written in it (it runs on the target). A new one refused while its
    options are checked is not left behind (1.0.21): every Save that failed made
    another deployment."""
    made = []
    try:
        return _deploy_save_in(store, b, by, full, made)
    except BaseException:
        for ident in made:
            try:
                store.db.run('DELETE FROM cert_deploys WHERE id = ?', (ident,))
            except Exception:                           # noqa: BLE001
                pass
        raise


def _deploy_save_in(store, b, by, full, made):
    t = time.time()
    row = None
    if b.get('id') not in (None, '', 0):
        row = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (_id(b['id']),))
        if not row:
            raise LookupError('there is no such deployment')
    cert = S.cert_need(store, b.get('cert_id') or (row or {}).get('cert_id'))
    target = str(b.get('target') or (row or {}).get('target') or '').strip()
    trow = S.plugin_row(store, 'target', target)
    if not trow:
        raise ValueError('there is no target %s' % target)
    cls = S.row_class('target', trow)
    if getattr(cls, 'connector', False):
        raise ValueError('%s is a connector: certificates go to the targets reached through it' % target)
    if row is not None and not full and row.get('target') != trow['name'] and 'options' not in b:
        # Moved to another target with its options (1.0.51): the commands, the script and where
        # the key goes, written by a full administrator for one server, ran on the one a
        # certificate administrator picked.
        kept = S.jload(row.get('options'), {}) or {}
        fdefs = {f['key']: f.get('default') for f in ((cls.deploy_fields if cls else None) or [])
                 if f.get('key')}
        nothing = (None, '', False, 0, '0', [], 'false')
        # set, and not the module's own default (1.0.51)
        has = lambda k: kept.get(k) not in nothing and str(kept.get(k)) != str(fdefs.get(k))  # noqa: E731
        fills = (dict((cls.deploy_fields and {f['key']: f for f in cls.deploy_fields}.get('preset')
                       or {}).get('fills') or {}) if cls else {})
        preset_keys = set()
        for fill in fills.values():
            if isinstance(fill, dict):
                preset_keys |= _key_lines(fill.get('outputs'))
        if any(has(k) for k in DEPLOY_COMMANDS + ('script_body',)) or \
                (_key_lines(kept.get('outputs')) - preset_keys) or \
                any(has(k) for k in key_options(cls) if k not in (
                    'pfx_password_mode', 'include_key', 'pfx_password')):
            raise E.ApiError(403, 'this deployment runs commands or writes the key where a full '
                                  'administrator set: only one may move it to another target')
    fields = {'cert_id': cert['id'], 'target': trow['name']}
    if row is not None and (int(row.get('cert_id') or 0) != int(cert['id']) or
                            row.get('target') != trow['name']):
        # Moved to another certificate or target (1.0.77): what was deployed is not there - the
        # same version number of another certificate was taken as up to date, never deployed.
        fields.update({'deployed_version': None, 'deployed_fp': None, 'state': 'new',
                       'fails': 0, 'next_try': None, 'last_error': None})
    if 'enabled' in b or not row:
        fields['enabled'] = _flag(b.get('enabled'), 1)
    if 'note' in b or not row:
        fields['note'] = _text(b, 'note', 2000)
    if 'position' in b:
        fields['position'] = int(b.get('position') or 0)
    if row is None:
        fields.update({'options': '{}', 'state': 'new', 'fails': 0, 'created': t,
                       'created_by': str(by)[:190], 'position': fields.get('position', 0)})
        ident = store.db.insert('cert_deploys', fields)
        made.append(ident)
        row = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (ident,))
        fields = {}
    verify_later = False
    if 'options' in b:
        old = S.jload(row.get('options'), {}) or {}
        if row.get('target') != trow['name']:
            old = {}
        given = dict(_dict(b.get('options'), 'options'))
        again = _flag(given.pop('pfx_password_new', None))
        if 'script_body' in given:
            from acmelib.plugins.targets import _script
            _script.check_body(given['script_body'])
            if not full and str(given.get('script_body') or '') != str(old.get('script_body') or ''):
                raise E.ApiError(403, 'only a full administrator may change the script of a '
                                      'deployment (it runs on the target)')
        # The commands run on the target around the files (1.0.19): as the script is,
        # changed by a full administrator only - a certificate administrator keeps them.
        if not full:
            for k in DEPLOY_COMMANDS:
                if k in given and str(given.get(k) or '') != str(old.get(k) or ''):
                    raise E.ApiError(403, 'only a full administrator may change the commands '
                                          'a deployment runs on the target')
        opts = S.config_seal(given, old,
                             'cert_deploys:%s' % row['id'], S.secret_fields(cls, 'deploy_fields'))
        # Where the private key goes and with which password (1.0.48), as the commands are:
        # changed by a full administrator only. A certificate administrator wrote any key to a
        # path of their choosing ("key-pem /var/www/html/k.pem 0644") or as a PFX with a
        # password they chose - and took it, past the export that is a full administrator's.
        # The module's own defaults (its presets) stay theirs to pick.
        if not full:
            _deploy_key_check(cls, given, old)
            sv = str(opts.get('service') or '')
            if sv != str(old.get('service') or '') and re.search(r'[/\\]|\.\.', sv):
                raise E.ApiError(403, 'a service name with a path in it is set by a full '
                                      'administrator only (it goes into the paths of the files)')
        if opts.get('pfx_password_mode') == 'generate' and (
                again or not opts.get('pfx_password') or
                old.get('pfx_password_mode') != 'generate'):
            from acmelib.plugins.targets._common import random_password
            opts['pfx_password'] = E.seal_secret(random_password(24), 'cert_deploys:%s:%s' % (
                row['id'], 'pfx_password'))
        if cls is not None:
            for f in cls.deploy_fields or []:
                if f.get('required') and field_shown(f, opts) and \
                        opts.get(f['key']) in (None, '') and f.get('default') in (None, ''):
                    raise ValueError('%s is needed' % (f.get('label') or f['key']))
                # Of the field's own kind (1.0.45): a number for a file name broke the module
                # inside the deployment ("join() argument must be str").
                v = opts.get(f['key'])
                what = f.get('label') or f['key']
                if v is None or f.get('type') in ('bool', 'catalog'):
                    continue
                if f.get('type') == 'number':
                    if isinstance(v, bool) or (not isinstance(v, (int, float)) and
                                               not re.match(r'^-?\d+(\.\d+)?\Z', str(v).strip() or '0')):
                        raise ValueError('%s is a number' % what)
                elif f.get('type') == 'list':
                    if not isinstance(v, (str, list)) or (isinstance(v, list) and
                                                          not all(isinstance(x, str) for x in v)):
                        raise ValueError('%s is lines of text' % what)
                elif isinstance(v, (int, float)) and not isinstance(v, bool):
                    opts[f['key']] = v = str(v)
                elif not isinstance(v, str):
                    raise ValueError('%s is text' % what)
                if len(json.dumps(v)) > 64000:
                    raise ValueError('%s is too long' % what)
        verify_later = bool(opts.get('verify') or 'verify_sni' in opts)
        if verify_later and not full:
            # a test - a host and port acme connects to - is a full administrator's (1.0.78)
            raise E.ApiError(403, 'only a full administrator may set what is checked after a '
                                  'deployment (it becomes a test: Certificates → Tests)')
        fields['options'] = json.dumps(opts)
        fields['state'] = 'new' if row.get('state') != 'ok' else 'changed'
    moved_from = (row.get('cert_id'), row.get('target')) if row is not None and (
        int(row.get('cert_id') or 0) != int(cert['id']) or row.get('target') != trow['name']) else None
    if fields:
        store.db.update('cert_deploys', row['id'], fields)
    if moved_from and moved_from[0]:
        from acmelib.certs import checks as C
        C.target_gone(store, moved_from[0], moved_from[1])
    if 'options' in b and verify_later:
        # "Check what is served" (as before 1.0.77, the command line's --set verify=...): a
        # test of the target now - made once the deployment is saved where it is (1.0.78: it
        # was made before, against the old target, and lost); what could not be made is kept
        from acmelib.certs import checks as C
        cur = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (row['id'],))
        opts = S.jload(cur.get('options'), {}) or {}
        C.verify_to_tests(store, cur, opts, by)
        store.db.update('cert_deploys', row['id'], {'options': json.dumps(opts)})
    store.add_event('certificates', 'deployment of %s to %s saved by %s' % (
        cert['name'], trow['name'], by), who=by)
    _wake()
    return row['id']


def deploy_rows(store, target='', cert='', full=False):
    """The deployments, of one target or one certificate (or all), each with its
    certificate's name and version."""
    where, args = [], []
    if target:
        trow = S.plugin_row(store, 'target', target)
        if not trow:
            raise LookupError('there is no target %s' % target)
        where.append('d.target = ?')
        args.append(trow['name'])
    if cert:
        c = S.cert_need(store, cert)
        where.append('d.cert_id = ?')
        args.append(c['id'])
    rows = store.db.rows(
        'SELECT d.*, c.name AS cert_name, c.version AS cert_version, c.state AS cert_state, '
        'c.alt_version AS cert_alt_version, c.key_type_alt AS cert_key_type_alt, '
        'c.alt_fingerprint AS cert_alt_fp '
        'FROM cert_deploys d JOIN certs c ON c.id = d.cert_id%s ORDER BY c.name, d.position, d.id'
        % (' WHERE ' + ' AND '.join(where) if where else ''), args)
    out = []
    kinds = {r['name']: r['kind'] for r in store.db.rows('SELECT name, kind FROM cert_targets')}
    for r in rows:
        one = S.deploy_public(store, r, full)
        one['target_kind'] = kinds.get(r['target'])
        gen = S.generation({'version': r.get('cert_version'),
                            'alt_version': r.get('cert_alt_version'),
                            'key_type_alt': r.get('cert_key_type_alt'),
                            'alt_cert_pem': 'x' if r.get('cert_alt_fp') else None})
        one['cert_generation'] = gen
        one['cert_dual'] = bool(r.get('cert_key_type_alt'))
        one['outdated'] = bool(gen and r.get('deployed_version') and
                               int(r['deployed_version']) < gen)
        out.append(one)
    return out


@api('GET', '/api/deploys')
def _deploys(h, s):
    rows = deploy_rows(h.store, h.arg('target').strip(), h.arg('cert').strip() or
                       h.arg('cert_id').strip(), may(s, 'fulladmin'))
    rows = _scoped_rows(h.store, s, {'rows': rows})['rows']
    return {'rows': rows, 'deploys': rows, 'total': len(rows)}


@api('POST', '/api/deploys/save', 'certadmin')
def _deploy_save(h, s):
    return {'id': deploy_save(h.store, h.body(), who(s), full=may(s, 'fulladmin'))}


@api('POST', '/api/deploys/delete', 'certadmin')
def _deploy_delete(h, s):
    row = h.store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (_id(h.body().get('id')),))
    if not row:
        raise LookupError('there is no such deployment')
    if jobs.cert_busy(h.store, row['cert_id']):
        # Not under a job deploying it (1.0.45): it ended "done" for a row no longer there.
        raise ValueError('a job is working on %s - wait for it to end' % row['target'])
    h.store.db.run('DELETE FROM cert_deploys WHERE id = ?', (row['id'],))
    from acmelib.certs import checks as C
    C.target_gone(h.store, row['cert_id'], row['target'])
    h.store.add_event('certificates', 'a deployment to %s deleted by %s' % (row['target'], who(s)),
                      who=who(s))
    return {'message': 'deleted'}


@api('POST', '/api/deploys/run', 'certadmin')
def _deploy_run(h, s):
    row = h.store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (_id(h.body().get('id')),))
    if not row:
        raise LookupError('there is no such deployment')
    return {'job_id': start_deploy(h.store, row['cert_id'], row['id'], who(s))}


# ---------------------------------------------------------------------------
# acme's own DNS server
# ---------------------------------------------------------------------------
RTYPES = ('A', 'AAAA', 'TXT', 'CNAME', 'MX', 'NS', 'CAA', 'SRV', 'PTR')
DNS_SETTINGS = ('dns_server', 'dns_listen', 'dns_port', 'dns_zone', 'dns_ns_names',
                'dns_ns_addresses', 'dns_soa_mail', 'dns_ttl', 'dns_static')


def dns_view(store):
    r = renewer.RENEWER[0]
    rows = store.db.rows('SELECT * FROM dns_records ORDER BY name, rtype, id LIMIT 5000')
    try:
        from acmelib.certs import dnsserver  # noqa: F401
        have = True
    except ImportError:
        have = False
    return {'settings': {k: E.CONFIG.get(k) for k in DNS_SETTINGS},
            'zone': E.CONFIG.get('dns_zone') or '',
            'server': r.dns_state() if r is not None else {'running': None,
                                                           'said': 'not the daemon'},
            'installed': have, 'records': rows, 'rtypes': list(RTYPES)}


@api('GET', '/api/dns')
def _dns(h, s):
    return dns_view(h.store)


def dns_record_save(store, b, by):
    name = str(b.get('name') or '').strip().lower().rstrip('.')
    if not re.match(r'^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]'
                    r'([a-z0-9_-]{0,61}[a-z0-9_])?\Z', name) and name != '@':
        raise ValueError('%r is not a DNS name' % name)
    # the first of the zones (1.0.88: "a.net, b.com" whole was the name of a record at @)
    zone = (re.split(r'[\s,;]+', str(E.CONFIG.get('dns_zone') or '').strip().lower()) or [''])[0]
    zone = zone.rstrip('.')
    if name == '@':
        if not zone:
            raise ValueError('@ is the zone, and no zone is set (dns_zone)')
        name = zone
    rtype = str(b.get('rtype') or b.get('type') or '').upper()
    if rtype not in RTYPES:
        raise ValueError('the type is one of %s' % ', '.join(RTYPES))
    value = str(b.get('value') or '').strip()
    if not value or len(value) > 4000 or re.search(r'[\x00-\x1f]', value):
        raise ValueError('a value of one line is needed')
    if rtype == 'A':
        if not isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address):
            raise ValueError('an A record holds an IPv4 address')
    elif rtype == 'AAAA':
        if not isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address):
            raise ValueError('an AAAA record holds an IPv6 address')
    ttl = int(b.get('ttl') or E.CONFIG.get('dns_ttl') or 60)
    if not 0 <= ttl <= 86400 * 7:
        raise ValueError('ttl: 0 to 604800 seconds')
    expires = b.get('expires')
    expires = float(expires) if expires not in (None, '', 0) else None
    row = {'name': name, 'rtype': rtype, 'value': value, 'ttl': ttl, 'expires': expires,
           'note': _text(b, 'note', 500), 'owner': 'admin:%s' % by}
    if b.get('id') not in (None, '', 0):
        if not store.db.row('SELECT id FROM dns_records WHERE id = ?', (_id(b['id']),)):
            raise LookupError('there is no such record')
        store.db.update('dns_records', _id(b['id']), row)
        ident = _id(b['id'])
    else:
        row['created'] = time.time()
        ident = store.db.insert('dns_records', row)
    store.add_event('certificates', 'DNS record %s %s %s saved by %s' % (name, rtype, value, by),
                    who=by)
    return ident


@api('POST', '/api/dns/record', 'fulladmin')
def _dns_record(h, s):
    return {'id': dns_record_save(h.store, h.body(), who(s))}


@api('POST', '/api/dns/record_delete', 'fulladmin')
def _dns_record_delete(h, s):
    ident = _id(h.body().get('id'))
    row = h.store.db.row('SELECT * FROM dns_records WHERE id = ?', (ident,))
    if not row:
        raise LookupError('there is no such record')
    h.store.db.run('DELETE FROM dns_records WHERE id = ?', (ident,))
    h.store.add_event('certificates', 'DNS record %s %s deleted by %s' % (
        row['name'], row['rtype'], who(s)), who=who(s))
    return {'message': 'deleted'}


# The certificate portal's routes live beside these.
from acmelib.certs import portal  # noqa: E402,F401


# The SSH keys of the modules (fields of the type sshkey): their routes, and drafts kept on save.
from acmelib.certs import api_sshkeys  # noqa: E402,F401
from acmelib.certs import api_readiness  # noqa: E402,F401  (plan, check, dry run: before a certificate)
from acmelib.certs import api_push  # noqa: E402,F401  (acme push: Discover, and what it makes)
from acmelib.certs import api_dnssets  # noqa: E402,F401  (Settings → DNS: the sets of DNS servers)
from acmelib.certs import api_teams  # noqa: E402,F401  (Settings → Owners and teams, the tags)
from acmelib.certs import api_reqprofiles  # noqa: E402,F401  (Settings → Request profiles)
from acmelib.certs import api_deploys  # noqa: E402,F401  (a deployment's files: preview, test)
from acmelib.certs import api_cas  # noqa: E402,F401  (an authority changed: edit, renew, versions)
from acmelib.certs import api_runplan  # noqa: E402,F401  (what happens: a certificate's run plan)
from acmelib.certs import api_catalog  # noqa: E402,F401  (a form's lists: a CA's products)
from acmelib.certs import api_discover  # noqa: E402,F401  (a form filled in from the account)
from acmelib.certs import api_modules  # noqa: E402,F401  (the page Modules: versions, uploads)
from acmelib.certs import api_checks  # noqa: E402,F401  (tests of what the servers serve)
from acmelib.certs import api_onlineimport  # noqa: E402,F401  (Import from a source; a key added later)
from acmelib.certs import api_certview  # noqa: E402,F401  (show a certificate: any file read and described)
from acmelib.certs import listsearch  # noqa: E402,F401  (the search box over the certificates)
from acmelib.certs import isemonsync  # noqa: E402,F401  (Settings → isemon: the first full sync)
