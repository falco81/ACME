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
import re
import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S
from acmelib.certs import jobs, deployer, renewer, runtime, schema
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
             'created_by', 'updated', 'updated_by', 'enabled')


def cert_list(store, search='', state='', issuer='', tag='', owner='', page=1, per=50):
    where, args = [], []
    if search:
        q = '%' + search.lower() + '%'
        where.append('(LOWER(name) LIKE ? OR LOWER(COALESCE(cn, \'\')) LIKE ? OR '
                     'LOWER(COALESCE(names, \'\')) LIKE ? OR LOWER(COALESCE(note, \'\')) LIKE ? '
                     'OR LOWER(COALESCE(serial, \'\')) LIKE ?)')
        args += [q, q, q, q, q]
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
        where.append('tags LIKE ?')
        args.append('%' + json.dumps(tag) + '%')
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
        out.append(one)
    return {'rows': out, 'total': total, 'page': page, 'per': per}


@api('GET', '/api/certs/overview')
def _overview(h, s):
    store = h.store
    t = time.time()
    by_state = renewer.counts(store)
    soon = store.db.rows("SELECT id, name, not_after, state, auto_renew, issuer FROM certs "
                         "WHERE not_after IS NOT NULL AND state NOT IN ('revoked', 'disabled') "
                         "ORDER BY not_after LIMIT 10")
    for r in soon:
        r['days_left'] = S.days_left(r, t)
    weeks = []
    for i in range(12):
        a, b = t + i * 7 * 86400, t + (i + 1) * 7 * 86400
        weeks.append({'from': a, 'to': b, 'n': int(store.db.value(
            'SELECT COUNT(*) FROM certs WHERE not_after >= ? AND not_after < ?', (a, b), 0) or 0)})
    recent = jobs.job_rows(store, per=10)['rows']
    lead = renewer.leader(store)
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    DF.ensure(store)
    di = DF.default_issuer(store)
    dc = DF.default_challenge(store, di) if di else None
    dt, dca = DF.default_target(store), DF.default_ca(store)
    return {'defaults': {'issuer': di['name'] if di else '', 'challenge': dc['name'] if dc else '',
                         'target': dt['name'] if dt else '', 'ca': dca['name'] if dca else '',
                         'ca_id': int(dca['id']) if dca else None},
            'contact_missing': DF.contact_missing(store),
            'by_state': by_state, 'total': sum(by_state.values()), 'soonest': soon,
            'expiring': int(store.db.value('SELECT COUNT(*) FROM certs WHERE not_after > ? AND '
                                           'not_after < ?', (t, t + days * 86400), 0) or 0),
            'expired': int(store.db.value("SELECT COUNT(*) FROM certs WHERE not_after < ? AND "
                                          "state NOT IN ('revoked', 'disabled')", (t,), 0) or 0),
            'deploys_failed': int(store.db.value("SELECT COUNT(*) FROM cert_deploys WHERE "
                                                 "state = 'failed'", (), 0) or 0),
            'weeks': weeks, 'jobs': recent, 'running': len(jobs.RUNNING),
            'leader': lead, 'last_scan': S.jload(store.get_meta('certs:last_scan'), None),
            'alerts': renewer.alerts(store)[:50], 'notify_days': days,
            'states': schema.STATES, 'key_types': list(schema.KEY_TYPES)}


@api('GET', '/api/certs')
def _certs(h, s):
    return cert_list(h.store, h.arg('search').strip(), h.arg('state').strip(),
                     h.arg('issuer').strip(), h.arg('tag').strip(), h.arg('owner').strip(),
                     h.num('page', 1, 1), h.num('per', 50, 1, 1000))


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
    out['due'] = renewer.due_why(row)
    out['busy'] = jobs.cert_busy(store, row['id'])
    return {'cert': out, 'versions': versions, 'deploys': deps, 'jobs': js}


@api('GET', '/api/certs/one')
def _cert_one(h, s):
    return cert_one(h.store, h.arg('id') or h.arg('name'), may(s, 'fulladmin'))


def cert_save(store, b, by):
    t = time.time()
    ident = b.get('id')
    row = S.cert_need(store, _id(ident)) if ident not in (None, '', 0) else None
    name = S.clean_name(b.get('name') if 'name' in b or not row else row['name'],
                        'the certificate\'s name')
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
    if 'profile' in b or not row:
        prof = _dict(b.get('profile'), 'profile')
        if len(json.dumps(prof)) > 20000:
            raise ValueError('the profile is too big')
        fields['profile'] = json.dumps(prof)
    if 'tags' in b or not row:
        fields['tags'] = json.dumps(_list(b.get('tags'), 'tags')[:50])
    if 'note' in b or not row:
        fields['note'] = _text(b, 'note', 4000)
    if 'owner' in b or not row:
        fields['owner'] = _text(b, 'owner', 190).strip()
    if 'enabled' in b:
        fields['enabled'] = _flag(b.get('enabled'), 1)
        if row and not fields['enabled']:
            fields['state'] = 'disabled'
        elif row and row.get('state') == 'disabled':
            fields['state'] = 'ok' if row.get('cert_pem') else 'new'
    fields['updated'], fields['updated_by'] = t, str(by)[:190]
    if row:
        store.db.update('certs', row['id'], fields)
        store.add_event('certificates', 'certificate %s changed by %s' % (name, by), who=by)
        ident = row['id']
    else:
        fields.update({'state': 'new', 'state_at': t, 'version': 0, 'fails': 0, 'source':
                       'issuer' if fields.get('issuer') else 'manual', 'created': t,
                       'created_by': str(by)[:190], 'enabled': fields.get('enabled', 1),
                       'ari': '{}'})
        ident = store.db.insert('certs', fields)
        store.add_event('certificates', 'certificate %s added by %s' % (name, by), who=by)
    _wake()
    return ident


@api('POST', '/api/certs/save', 'certadmin')
def _cert_save(h, s):
    return {'id': cert_save(h.store, h.body(), who(s))}


@api('POST', '/api/certs/delete', 'certadmin')
def _cert_delete(h, s):
    row = S.cert_need(h.store, _id(h.body().get('id')))
    if jobs.cert_busy(h.store, row['id']):
        raise E.ApiError(409, 'a job is working on %s: stop it first' % row['name'])
    db = h.store.db
    db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (row['id'],))
    db.run('DELETE FROM cert_versions WHERE cert_id = ?', (row['id'],))
    db.run('DELETE FROM certs WHERE id = ?', (row['id'],))
    h.store.add_event('certificates', 'certificate %s deleted by %s' % (row['name'], who(s)),
                      'warn', who=who(s))
    return {'message': '%s deleted' % row['name']}


def start_renew(store, ref, force, by):
    row = S.cert_need(store, ref)
    if not row.get('issuer'):
        raise ValueError('%s has no issuer - it was imported or is answered by a CSR; import the '
                         'new certificate instead' % row['name'])
    # Asked by a person, it is renewed whether due or not; `force` also takes a
    # certificate that failed out of its wait - and both are written in the job.
    try:
        return jobs.submit(store, 'renew', renewer.renew_job(row['id'], force, by),
                           cert_id=row['id'], by=by,
                           said='asked by %s%s' % (by, ' (forced)' if force else ''))
    except ValueError as e:
        raise E.ApiError(409, str(e))


@api('POST', '/api/certs/renew', 'certadmin')
def _cert_renew(h, s):
    b = h.body()
    return {'job_id': start_renew(h.store, _id(b.get('id')), _flag(b.get('force')), who(s))}


def start_deploy(store, ref, deploy_id, by):
    row = S.cert_need(store, ref)
    if not row.get('cert_pem'):
        raise ValueError('%s has not been issued yet' % row['name'])
    only = None
    if deploy_id not in (None, '', 0):
        d = store.db.row('SELECT * FROM cert_deploys WHERE id = ? AND cert_id = ?',
                         (_id(deploy_id, 'deploy_id'), row['id']))
        if not d:
            raise LookupError('that deployment is not one of %s' % row['name'])
        only = [d['id']]
    try:
        return jobs.submit(store, 'deploy', deployer.deploy_job(row['id'], only, force=True),
                           cert_id=row['id'], deploy_id=only[0] if only else None, by=by,
                           said='asked by %s' % by)
    except ValueError as e:
        raise E.ApiError(409, str(e))


@api('POST', '/api/certs/deploy', 'certadmin')
def _cert_deploy(h, s):
    b = h.body()
    return {'job_id': start_deploy(h.store, _id(b.get('id')), b.get('deploy_id'), who(s))}


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

    def fn(job):
        return renewer.revoke_cert(job.store, job, row['id'], reason, by)
    try:
        return {'job_id': jobs.submit(h.store, 'revoke', fn, cert_id=row['id'], by=by,
                                      said='reason: %s' % reason)}
    except ValueError as e:
        raise E.ApiError(409, str(e))


def parse_file(data, filename, password):
    """What is in a file: the certificates (each described), a key or not."""
    formats = _lib('formats')
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
                           _text(b, 'password', 1000))
    return out


def cert_import(store, b, by):
    data = _b64(b.get('data_b64'))
    _out, got = parse_file(data, _text(b, 'filename', 300), _text(b, 'password', 1000))
    if got.get('needs_password'):
        raise ValueError('the file is locked: give its password')
    leaf = got.get('leaf') or ((got.get('certs') or [None])[0])
    if not leaf:
        raise ValueError('there is no certificate in that file')
    key = got.get('key')
    if b.get('key_b64'):
        formats = _lib('formats')
        kg = formats.read_any(_b64(b.get('key_b64'), 'key_b64'), _text(b, 'key_filename', 300) or
                              'key.pem', _text(b, 'key_password', 1000) or None) or {}
        if kg.get('needs_password'):
            raise ValueError('the key is locked: give its password (key_password)')
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
    if b.get('id') not in (None, '', 0):
        row = S.cert_need(store, _id(b.get('id')))
        if not key:
            key = S.cert_key(row)       # a new certificate for the key it has (a CSR's answer)
        cid = row['id']
    else:
        name = S.clean_name(b.get('name') or info.get('cn') or (info.get('names') or [''])[0],
                            'the certificate\'s name')
        if store.db.row('SELECT id FROM certs WHERE name = ?', (name,)):
            raise ValueError('there is a certificate called %s already' % name)
        names = list(info.get('names') or ([info['cn']] if info.get('cn') else []))
        cid = store.db.insert('certs', {
            'name': name, 'cn': str(info.get('cn') or (names[0] if names else ''))[:190],
            'names': json.dumps(names), 'key_type': str(info.get('key_type') or '')[:60],
            'issuer': '', 'challenge': '', 'challenge_map': '{}', 'auto_renew': 0,
            'renew_days': None, 'reuse_key': 0, 'profile': '{}', 'source': 'import',
            'state': 'new', 'state_at': t, 'version': 0, 'fails': 0,
            'tags': json.dumps(_list(b.get('tags'), 'tags')[:50]),
            'note': _text(b, 'note', 4000), 'owner': _text(b, 'owner', 190), 'created': t,
            'created_by': str(by)[:190], 'enabled': 1, 'ari': '{}'})
    version = S.save_version(store, cid, leaf, chain, key, 'import', by, info=info)
    store.add_event('certificates', 'certificate %s imported by %s (version %d%s)' % (
        S.cert_need(store, cid)['name'], by, version, '' if key else ', without its key'), who=by)
    return cid, version


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
    if b.get('version') not in (None, '', 0):
        vrow = S.version_row(store, row['id'], int(b['version']))
        if not vrow:
            raise LookupError('%s has no version %s' % (row['name'], b['version']))
    if not (vrow or row).get('cert_pem'):
        raise ValueError('%s has not been issued yet' % row['name'])
    bundle = S.bundle_of(row, vrow)
    if fmt in S.KEY_FORMATS and not getattr(bundle, 'key_pem', None):
        raise ValueError('acme does not have the key of %s' % row['name'])
    data = bundle.as_format(fmt, _text(b, 'password', 1000) or None)
    if isinstance(data, str):
        data = data.encode('utf-8')
    ext, mime = FORMAT_FILES[fmt]
    fname = re.sub(r'[^A-Za-z0-9._-]+', '_', row['name']) + ext
    if fmt in S.KEY_FORMATS:
        store.add_event('certificates', 'the private key of %s was exported (%s) by %s' % (
            row['name'], fmt, who(s)), 'warn', who=who(s))
    return {'filename': fname, 'mime': mime, 'data_b64': base64.b64encode(data).decode('ascii'),
            'format': fmt}


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
    csr = pki.make_csr(key, names, subject=prof.get('subject') or None,
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
    return jobs.job_rows(h.store, cert_id=h.arg('cert_id') or None, kind=h.arg('kind'),
                         ok=ok if ok in ('0', '1') else None, page=h.num('page', 1, 1),
                         per=h.num('per', 50, 1, 500))


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
    return {'ca': one, 'pki': pki_view, 'issued': ca.ca_issued(h.store, r['id'], limit=h.num('per', 500, 1, 5000),
                                              offset=h.num('offset', 0, 0)),
            'children': [ca_row(h.store, c)['name'] for c in one.get('children') or []]}


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
    name = S.clean_name(b.get('name') or subject.get('CN'), 'the authority\'s name')
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
            raise ValueError('the file is locked: give its password')
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
    name = S.clean_name(b.get('name') or S.info_of(cert_pem).get('cn'), 'the authority\'s name')
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
    if fmt in ('crl', 'crl-der', 'bundle') and not may(s, 'certadmin'):
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
    if not pub.allowed():
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
    table = {'challenges': 'cert_challenges', 'issuers': 'cert_issuers',
             'targets': 'cert_targets', 'sources': 'cert_issuers',
             'validations': 'cert_challenges'}.get(source)
    if table:
        return [[r['name'], '%s (%s)' % (r['name'], r['kind'])]
                for r in store.db.rows('SELECT name, kind FROM %s ORDER BY name' % table)]
    if source == 'certs':
        return [[r['name'], r['name']] for r in store.db.rows('SELECT name FROM certs ORDER BY name')]
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
            f['options'] = options_for(store, f['options_from'])
            if f['options_from'] == 'cas':
                if dca is None:
                    row = DF.default_ca(store)
                    dca = row['name'] if row else ''
                if dca and any(o[0] == dca for o in f['options']):
                    f['default'] = dca
        out.append(f)
    return out


def plugins_view(store, again=False):
    reg = S.registry(again)
    d = reg.describe()
    for fam in d:
        for one in d[fam]:
            one['fields'] = _resolve(store, one.get('fields'))
            if 'deploy_fields' in one:
                one['deploy_fields'] = _resolve(store, one.get('deploy_fields'))
    d['broken'] = [{'file': b[0], 'words': b[1]} for b in reg.broken]
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
    cls = S.plugin_class(family, kind)
    if cls is None and (not row or kind != row.get('kind')):
        raise ValueError('there is no %s module "%s"' % (family, kind))
    secrets_ = S.secret_fields(cls)
    given = _dict(b.get('config'), 'config') if 'config' in b else None
    fields = {'name': name, 'kind': kind, 'updated': t}
    if 'enabled' in b or not row:
        fields['enabled'] = _flag(b.get('enabled'), 1)
    if 'note' in b or not row:
        fields['note'] = _text(b, 'note', 4000)
    if family == 'target' and ('tags' in b or not row):
        fields['tags'] = json.dumps(_list(b.get('tags'), 'tags')[:50])
    if row is None:
        fields.update({'config': '{}', 'state': '{}', 'created': t, 'created_by': str(by)[:190]})
        ident = store.db.insert(table, fields)
        row = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (ident,))
        fields = {}
    old_cfg = S.jload(row.get('config'), {}) or {}
    if given is not None:
        if row.get('kind') != kind:
            old_cfg = {}            # another module: nothing of the old one's kept
        cfg = S.config_seal(given, old_cfg, '%s:%s' % (table, row['id']), secrets_)
        if cls is not None:
            for f in cls.fields or []:
                if f.get('required') and cfg.get(f['key']) in (None, '') and \
                        f.get('default') in (None, ''):
                    raise ValueError('%s: %s is needed' % (name, f.get('label') or f['key']))
        if len(json.dumps(cfg)) > 200000:
            raise ValueError('those settings are too big')
        fields['config'] = json.dumps(cfg)
    if fields:
        store.db.update(table, row['id'], fields)
    if row['name'] != name:
        _renamed(store, family, row['name'], name)
    store.add_event('certificates', '%s %s %s by %s' % (
        {'issuer': 'issuer', 'challenge': 'challenge', 'target': 'target'}[family], name,
        'saved', by), who=by)
    return row['id']


def _renamed(store, family, old, new):
    """What referred to it by name, made to refer to the new name."""
    db = store.db
    DF.renamed(store, family, old, new)
    if family == 'issuer':
        db.run('UPDATE certs SET issuer = ? WHERE issuer = ?', (new, old))
    elif family == 'target':
        db.run('UPDATE cert_deploys SET target = ? WHERE target = ?', (new, old))
    else:
        db.run('UPDATE certs SET challenge = ? WHERE challenge = ?', (new, old))
        for r in db.rows('SELECT id, challenge_map FROM certs WHERE challenge_map LIKE ?',
                         ('%' + json.dumps(old) + '%',)):
            cmap = S.jload(r['challenge_map'], {}) or {}
            cmap = {k: (new if v == old else v) for k, v in cmap.items()}
            db.update('certs', r['id'], {'challenge_map': json.dumps(cmap)})


def family_delete(store, family, b, by):
    row = S.plugin_row(store, family, _id(b.get('id')))
    if not row:
        raise LookupError('there is no such %s' % family)
    used = S.plugin_public(store, family, row)['used_by']
    if used:
        raise ValueError('%s is in use (%d): change those first' % (row['name'], used))
    store.db.run('DELETE FROM %s WHERE id = ?' % S.TABLE_OF[family], (row['id'],))
    store.db.run('DELETE FROM meta WHERE k LIKE ?', ('%s%s:%s:%%' % (
        runtime.KV_PREFIX, family, row['name']),))
    if DF.forget(store, family, row['name']):
        store.add_event('certificates', '%s was the default %s: there is none now' % (
            row['name'], DF.WORDS[family]), 'warn', who=by)
    store.add_event('certificates', '%s %s deleted by %s' % (family, row['name'], by), 'warn',
                    who=by)
    return row['name']


def family_test(store, family, b, by, echo=None):
    """The module tried as saved, or with the settings given over them."""
    table = S.TABLE_OF[family]
    row = S.plugin_row(store, family, _id(b['id'])) if b.get('id') not in (None, '', 0) else None
    if b.get('id') not in (None, '', 0) and not row:
        raise LookupError('there is no such %s' % family)
    kind = str(b.get('kind') or (row or {}).get('kind') or '')
    cls = S.plugin_class(family, kind)
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (family, kind))
    cfg = S.plugin_config(family, row) if row and row.get('kind') == kind else {}
    for k, v in (_dict(b.get('config'), 'config') or {}).items():
        if k in S.secret_fields(cls) and (v in (None, '') or E.is_masked(v)):
            continue                # "" or the dots shown: the one kept
        cfg[k] = v
    name = (row or {}).get('name') or str(b.get('name') or 'unsaved')

    def fn(job):
        if family == 'target' and row:
            ctx = deployer.target_context(store, job, row)
        else:
            ctx = runtime.RunContext(store, job, scope='%s:%s' % (family, name))
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
    cls = S.plugin_class(family, row.get('kind'))
    if cls is None:
        raise ValueError('there is no %s module "%s"' % (family, row.get('kind')))
    key = str(b.get('action') or '').strip()
    act = next((a for a in (cls.actions or []) if a.get('key') == key), None)
    if not act:
        raise ValueError('%s (%s) can do %s' % (row['name'], row['kind'], ', '.join(
            a['key'] for a in cls.actions or []) or 'nothing besides its work'))
    cfg = S.plugin_config(family, row)

    def fn(job):
        if family == 'target':
            ctx = deployer.target_context(store, job, row)
        else:
            ctx = runtime.RunContext(store, job, scope='%s:%s' % (family, row['name']))
        try:
            job.step('%s %s (%s): %s' % (family, row['name'], row['kind'], act.get('label') or key))
            said = cls(cfg, ctx).action(key)
            job.step(str(said or 'done'), 'ok')
            return True, str(said or 'done')
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'action', fn, target=row['name'] if family == 'target' else None,
                       by=by, said='%s %s: %s' % (family, row['name'], key), echo=echo)
    store.add_event('certificates', '%s %s: "%s" run by %s - %s' % (
        family, row['name'], act.get('label') or key, by, 'done' if job.ok else 'failed: %s'
        % job.said), 'info' if job.ok else 'warn', who=by)
    return {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps,
            'action': key}


def action_role(family, b, store):
    """An action that changes something elsewhere needs a full administrator."""
    row = S.plugin_row(store, family, b.get('id') if b.get('id') not in (None, '', 0)
                       else b.get('name'))
    cls = S.plugin_class(family, row.get('kind')) if row else None
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
        return {'message': '%s deleted' % family_delete(h.store, family, h.body(), who(s))}

    @api('POST', '/api/%s/test' % path, 'certadmin')
    def _test(h, s):
        return family_test(h.store, family, h.body(), who(s))

    @api('POST', '/api/%s/default' % path, 'fulladmin')
    def _default(h, s):
        """{name} - made the default; '' for none."""
        b = h.body()
        ref = b.get('name') if 'name' in b else b.get('id')
        got = DF.set_default(h.store, family, '' if ref in (None, 0) else ref, who(s))
        return {'default': got, 'message': ('%s is the default now' % got) if got else
                'there is no default now'}


_family_routes('issuer', 'sources')
_family_routes('challenge', 'validations')
_family_routes('target', 'targets')


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
def deploy_save(store, b, by):
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
    cls = S.plugin_class('target', trow['kind'])
    fields = {'cert_id': cert['id'], 'target': trow['name']}
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
        row = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (ident,))
        fields = {}
    if 'options' in b:
        old = S.jload(row.get('options'), {}) or {}
        if row.get('target') != trow['name']:
            old = {}
        opts = S.config_seal(_dict(b.get('options'), 'options'), old,
                             'cert_deploys:%s' % row['id'], S.secret_fields(cls, 'deploy_fields'))
        if cls is not None:
            for f in cls.deploy_fields or []:
                if f.get('required') and opts.get(f['key']) in (None, '') and \
                        f.get('default') in (None, ''):
                    raise ValueError('%s is needed' % (f.get('label') or f['key']))
        fields['options'] = json.dumps(opts)
        fields['state'] = 'new' if row.get('state') != 'ok' else 'changed'
    if fields:
        store.db.update('cert_deploys', row['id'], fields)
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
        'SELECT d.*, c.name AS cert_name, c.version AS cert_version, c.state AS cert_state '
        'FROM cert_deploys d JOIN certs c ON c.id = d.cert_id%s ORDER BY c.name, d.position, d.id'
        % (' WHERE ' + ' AND '.join(where) if where else ''), args)
    out = []
    kinds = {r['name']: r['kind'] for r in store.db.rows('SELECT name, kind FROM cert_targets')}
    for r in rows:
        one = S.deploy_public(store, r, full)
        one['target_kind'] = kinds.get(r['target'])
        one['outdated'] = bool(r.get('cert_version') and r.get('deployed_version') and
                               int(r['deployed_version']) < int(r['cert_version']))
        out.append(one)
    return out


@api('GET', '/api/deploys')
def _deploys(h, s):
    rows = deploy_rows(h.store, h.arg('target').strip(), h.arg('cert').strip() or
                       h.arg('cert_id').strip(), may(s, 'fulladmin'))
    return {'rows': rows, 'deploys': rows, 'total': len(rows)}


@api('POST', '/api/deploys/save', 'certadmin')
def _deploy_save(h, s):
    return {'id': deploy_save(h.store, h.body(), who(s))}


@api('POST', '/api/deploys/delete', 'certadmin')
def _deploy_delete(h, s):
    row = h.store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (_id(h.body().get('id')),))
    if not row:
        raise LookupError('there is no such deployment')
    h.store.db.run('DELETE FROM cert_deploys WHERE id = ?', (row['id'],))
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
    zone = str(E.CONFIG.get('dns_zone') or '').strip().lower().rstrip('.')
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
