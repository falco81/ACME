# -*- coding: utf-8 -*-
"""
Import from a source (Certificates → Import from a source, docs/certificates.md):
the certificates an account already has at a source whose API lists them
(SSLS.cz, SSLmarket, DigiCert CertCentral, acme's own authorities, Vault...)
listed, and those picked brought in - each bound to that source with the
source's own id of it (certs.issuer_ref), so its renewals reissue that very
order. acme gets no private key from a source: the key is added later in the
certificate's window (add_key), or a renewal makes a new one.

    sources(store)                     the sources whose module lists (lists_existing)
    listing(store, name, s)            what the account has there, each marked when
                                       acme has it already - only read, nothing written
    import_job(store, name, items, by) a job: each one fetched, checked, kept
    import_result(store, job_id)       what that job did, one line each
    add_key(store, row, b, by)         the private key of a certificate acme holds none of

A module gives list_existing() and fetch_existing(ref) (acmelib/plugins/base.py,
docs/writing-a-module.md); neither orders, reissues or changes anything.
"""
from __future__ import annotations

import json
import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S
from acmelib.certs import jobs, runtime, schema

RESULT_PREFIX = 'certs:onlineimport:'
RESULT_KEEP = 20
MOST = 2000                     # certificates shown of one account
RENEWABLE = ('reissue', 'order', 'issue', 'none')


# ---------------------------------------------------------------------------
# Which sources can
# ---------------------------------------------------------------------------
def _cls(kind):
    cls = S.plugin_class('issuer', kind)
    return cls if cls is not None and getattr(cls, 'lists_existing', False) else None


def sources(store):
    """[{'name', 'kind', 'title', 'enabled'}] of the sources that can list."""
    out = []
    for r in store.db.rows('SELECT id, name, kind, enabled FROM cert_issuers ORDER BY name'):
        cls = _cls(r.get('kind'))
        if cls is None:
            continue
        out.append({'name': r['name'], 'kind': r['kind'], 'title': cls.title or r['kind'],
                    'enabled': bool(r.get('enabled', 1) in (1, '1', True, None))})
    return out


def _source(store, name):
    irow = S.plugin_row(store, 'issuer', str(name or '').strip())
    if not irow:
        raise LookupError('there is no source %s' % (name or '?'))
    if _cls(irow.get('kind')) is None:
        raise ValueError('the source %s (%s) cannot list the certificates of its account'
                         % (irow['name'], irow.get('kind')))
    return irow


def _instance(store, irow, job=None):
    ctx = runtime.RunContext(store, job, scope='issuer:%s' % irow['name'])
    return S.plugin_instance(store, 'issuer', irow, ctx), ctx


# ---------------------------------------------------------------------------
# What acme has already
# ---------------------------------------------------------------------------
def _serial(v):
    try:
        return S.pki().norm_serial(v) if v not in (None, '') else ''
    except Exception:                                   # noqa: BLE001
        return ''


def known(store, source):
    """{'ref': {ref: cert}, 'serial': {serial: cert}, 'fp': {sha256: cert}, 'id': {id: cert}}
    of every certificate acme keeps (each version, the twins too)."""
    out = {'ref': {}, 'serial': {}, 'fp': {}, 'id': {}}
    certs = {}
    for c in store.db.rows('SELECT id, name, owner, issuer, issuer_ref, serial, fingerprint, '
                           'alt_serial, alt_fingerprint FROM certs'):
        one = {'id': c['id'], 'name': c['name'], 'owner': c.get('owner') or ''}
        certs[c['id']] = one
        out['id'][c['id']] = one
        if c.get('issuer_ref') and (c.get('issuer') or '') == source:
            out['ref'][str(c['issuer_ref'])] = one
        for k in ('serial', 'alt_serial'):
            if _serial(c.get(k)):
                out['serial'][_serial(c.get(k))] = one
        for k in ('fingerprint', 'alt_fingerprint'):
            if c.get(k):
                out['fp'][str(c[k]).upper()] = one
    for v in store.db.rows('SELECT cert_id, serial, fingerprint FROM cert_versions'):
        one = certs.get(v['cert_id'])
        if not one:
            continue
        if _serial(v.get('serial')):
            out['serial'].setdefault(_serial(v.get('serial')), one)
        if v.get('fingerprint'):
            out['fp'].setdefault(str(v['fingerprint']).upper(), one)
    return out


def _match(kn, item, source_has=True):
    """The certificate of acme an item of the list is, or None."""
    ref = str(item.get('ref') or '')
    if ref and ref in kn['ref']:
        return kn['ref'][ref], 'the source\'s id'
    if item.get('acme_cert_id') and kn['id'].get(item['acme_cert_id']):
        return kn['id'][item['acme_cert_id']], 'ordered by acme'
    sn = _serial(item.get('serial'))
    if sn and sn in kn['serial']:
        return kn['serial'][sn], 'its serial'
    fp = str(item.get('fingerprint') or '').replace(':', '').upper()
    if fp and fp in kn['fp']:
        return kn['fp'][fp], 'its fingerprint'
    return None, ''


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------
def _num(v):
    try:
        f = float(v)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


def clean_item(it):
    """One entry of a module's list as the page gets it."""
    names = it.get('names') or []
    if isinstance(names, str):
        names = [n for n in names.replace(',', ' ').split() if n]
    names = [str(n).strip().lower().rstrip('.') for n in names if str(n).strip()]
    cn = str(it.get('cn') or (names[0] if names else '')).strip()
    if cn and cn.lower() not in names and '.' in cn:
        names.insert(0, cn.lower())
    ren = str(it.get('renewable') or 'none')
    out = {'ref': str(it.get('ref') or '').strip()[:190], 'cn': cn[:300], 'names': names[:500],
           'product': str(it.get('product') or '')[:200],
           'status': str(it.get('status') or '')[:200],
           'not_before': _num(it.get('not_before')), 'not_after': _num(it.get('not_after')),
           'paid_until': _num(it.get('paid_until')),
           'serial': _serial(it.get('serial')), 'downloadable': bool(it.get('downloadable')),
           'renewable': ren if ren in RENEWABLE else 'none',
           'note': str(it.get('note') or '')[:500]}
    if it.get('fingerprint'):
        out['fingerprint'] = str(it['fingerprint']).replace(':', '').upper()[:64]
    if it.get('acme_cert_id'):
        try:
            out['acme_cert_id'] = int(it['acme_cert_id'])
        except (TypeError, ValueError):
            pass
    return out


def listing(store, name, s=None):
    """{'source', 'kind', 'title', 'items', 'said', 'steps'} - every certificate the
    account has at the source, each with 'in_acme' ({'id', 'name', 'by'} or None) and
    'importable'. Only read: the module asks its API, nothing is kept."""
    irow = _source(store, name)
    if not irow.get('enabled', 1):
        raise ValueError('the source %s is switched off' % irow['name'])
    inst, ctx = _instance(store, irow)
    try:
        got = inst.list_existing() or []
    finally:
        ctx.tidy()
    kn = known(store, irow['name'])
    teams = None
    if s is not None:
        from acmelib.certs import teams as T
        teams = T
    items, seen = [], set()
    now = time.time()
    for raw in got:
        if not isinstance(raw, dict):
            continue
        it = clean_item(raw)
        if not it['ref'] or it['ref'] in seen:
            continue
        seen.add(it['ref'])
        mine, by = _match(kn, it)
        if mine is not None:
            shown = {'by': by}
            if teams is None or teams.cert_may(store, s, mine, 'view'):
                shown.update(id=mine['id'], name=mine['name'])
            it['in_acme'] = shown
        else:
            it['in_acme'] = None
        it['expired'] = bool(it['not_after'] and it['not_after'] < now)
        it.pop('acme_cert_id', None)
        it['importable'] = bool(it['downloadable'] and mine is None)
        items.append(it)
        if len(items) >= MOST:
            break
    items.sort(key=lambda x: (x['in_acme'] is not None, not x['importable'], x['expired'],
                              x['cn'].lower()))
    n_new = sum(1 for x in items if x['importable'])
    return {'source': irow['name'], 'kind': irow['kind'],
            'title': getattr(type(inst), 'title', '') or irow['kind'],
            'items': items, 'importable': n_new,
            'said': '%d certificates at %s, %d of them can be imported'
                    % (len(items), irow['name'], n_new),
            'steps': [x[2] for x in ctx.steps][-60:]}


# ---------------------------------------------------------------------------
# The import
# ---------------------------------------------------------------------------
def clean_picks(store, items):
    """The certificates asked for: [{'ref', 'owner', 'tags', 'challenge', 'auto_renew',
    'name'}] checked before the job starts."""
    if not isinstance(items, list) or not items:
        raise ValueError('pick at least one certificate to import')
    if len(items) > 500:
        raise ValueError('500 certificates at most in one import')
    out, seen = [], set()
    for it in items:
        if not isinstance(it, dict):
            raise ValueError('each certificate to import is an object')
        ref = str(it.get('ref') or '').strip()
        if not ref or len(ref) > 190:
            raise ValueError('a certificate to import has no id of the source')
        if ref in seen:
            continue
        seen.add(ref)
        tags = it.get('tags') or []
        if isinstance(tags, str):
            tags = [t for t in tags.replace(',', ' ').split() if t]
        if not isinstance(tags, list):
            raise ValueError('the tags are a list')
        ch = str(it.get('challenge') or '').strip()
        if ch:
            crow = S.plugin_row(store, 'challenge', ch)
            if not crow:
                raise ValueError('there is no validation %s' % ch)
            ch = crow['name']
        owner = str(it.get('owner') or '').strip()[:190]
        out.append({'ref': ref, 'owner': owner, 'tags': [str(t)[:60] for t in tags][:50],
                    'challenge': ch, 'auto_renew': 1 if it.get('auto_renew') in
                    (True, 1, '1', 'true', 'on', 'yes') else 0,
                    'name': str(it.get('name') or '').strip()[:120]})
    return out


def import_job(store, name, items, by=''):
    """The job (its id) that imports `items` (clean_picks) from the source."""
    irow = _source(store, name)
    if not irow.get('enabled', 1):
        raise ValueError('the source %s is switched off' % irow['name'])
    picks = clean_picks(store, items)

    def fn(job):
        return run_import(store, job, irow, picks, by)
    return jobs.submit(store, 'online-import', fn, by=by,
                       said='%d certificate(s) from %s' % (len(picks), irow['name']))


def _key_type(info):
    kt = str(info.get('key_type') or '')
    return kt if kt in schema.KEY_TYPES else (kt[:60] or 'ec-256')


def run_import(store, job, irow, picks, by):
    """(ok, words): each certificate fetched from the source, checked and kept."""
    inst, ctx = _instance(store, irow, job)
    results = []
    try:
        kn = known(store, irow['name'])
        job.step('importing %d certificate(s) from %s (%s) - nothing is ordered there'
                 % (len(picks), irow['name'], irow['kind']))
        for p in picks:
            job.check()
            one = {'ref': p['ref'], 'state': 'skipped', 'why': '', 'id': None, 'name': ''}
            results.append(one)
            mine, _by = _match(kn, {'ref': p['ref']})
            if mine is not None:
                one['why'] = 'acme has it already: %s' % mine['name']
                job.step('%s: %s' % (p['ref'], one['why']), 'warn')
                continue
            try:
                got = inst.fetch_existing(p['ref']) or {}
                cid, name, info = _keep(store, irow, p, got, kn, by)
            except jobs.JobStopped:
                raise
            except (base.PluginError, ValueError, LookupError) as e:
                one['state'] = 'failed'
                one['why'] = str(e)
                job.step('%s: not imported - %s' % (p['ref'], e), 'bad')
                continue
            except Exception as e:                      # noqa: BLE001
                one['state'] = 'failed'
                one['why'] = '%s: %s' % (type(e).__name__, e)
                job.step('%s: not imported - %s' % (p['ref'], one['why']), 'bad')
                continue
            if cid is None:
                one['why'] = name
                job.step('%s: %s' % (p['ref'], name), 'warn')
                continue
            one.update(state='imported', id=cid, name=name, cn=info.get('cn') or '',
                       not_after=info.get('not_after'))
            job.step('%s: imported as %s (%s, valid until %s) - without its private key'
                     % (p['ref'], name, ', '.join(info.get('names') or [])[:300],
                        time.strftime('%Y-%m-%d', time.gmtime(info.get('not_after') or 0))),
                     'ok')
    finally:
        ctx.tidy()
        _keep_result(store, job.id, irow['name'], results)
    n_ok = sum(1 for r in results if r['state'] == 'imported')
    n_bad = sum(1 for r in results if r['state'] == 'failed')
    n_skip = len(results) - n_ok - n_bad
    words = '%d imported, %d skipped, %d failed (from %s)' % (n_ok, n_skip, n_bad, irow['name'])
    if n_ok:
        store.add_event('certificates', '%s imported %d certificate(s) from %s' % (
            by or '?', n_ok, irow['name']), who=by)
    return n_bad == 0, words


def _keep(store, irow, p, got, kn, by):
    """(id, name, info) of the certificate made, or (None, why, {}) when it is not."""
    pki = S.pki()
    leaf = str(got.get('cert_pem') or '').strip()
    if not leaf:
        raise base.PluginError('the source gave no certificate for %s' % p['ref'])
    leaf += '\n'
    info = S.info_of(leaf)
    if info.get('is_ca'):
        raise base.PluginError('%s is a certificate authority, not a certificate' % p['ref'])
    mine, _by = _match(kn, {'serial': info.get('serial'), 'fingerprint': info.get('sha256'),
                            'acme_cert_id': got.get('acme_cert_id')})
    if mine is not None:
        return None, 'acme has it already: %s' % mine['name'], {}
    chain = [c if c.endswith('\n') else c + '\n' for c in (got.get('chain_pems') or [])
             if str(c).strip() and str(c).strip() != leaf.strip()]
    try:
        ordered = pki.order_chain(leaf, chain)
        if isinstance(ordered, (list, tuple)) and ordered:
            chain = [c for c in ordered if c.strip() != leaf.strip()]
    except Exception:                                   # noqa: BLE001
        pass
    names = list(info.get('names') or ([info['cn']] if info.get('cn') else []))
    taken = {str(r['name']) for r in store.db.rows('SELECT name FROM certs')}
    if p['name']:
        name = S.clean_name(p['name'], 'the certificate\'s name')
        if name in taken:
            raise ValueError('there is a certificate called %s already' % name)
    else:
        first = info.get('cn') or (names[0] if names else '') or 'imported'
        name = S.safe_name(first.replace('*.', 'wildcard.'), taken)
    ref = str(got.get('ref') or p['ref'])[:190]
    t = time.time()
    cid = store.db.insert('certs', {
        'name': name, 'cn': str(info.get('cn') or (names[0] if names else ''))[:190],
        'names': json.dumps(names), 'key_type': _key_type(info), 'issuer': irow['name'],
        'issuer_ref': ref, 'challenge': p['challenge'], 'challenge_map': '{}',
        'auto_renew': p['auto_renew'], 'renew_days': None, 'reuse_key': 0, 'profile': '{}',
        'source': 'import', 'state': 'new', 'state_at': t, 'version': 0, 'fails': 0,
        'tags': json.dumps(p['tags']), 'note': '', 'owner': p['owner'], 'created': t,
        'created_by': str(by)[:190], 'enabled': 1, 'ari': '{}'})
    S.save_version(store, cid, leaf, chain, None, 'import', by, info=info)
    one = {'id': cid, 'name': name, 'owner': p['owner']}
    kn['ref'][ref] = one
    if info.get('serial'):
        kn['serial'][_serial(info['serial'])] = one
    store.add_event('certificates', 'certificate %s imported from %s (its id there %s) by %s, '
                    'without its key' % (name, irow['name'], ref, by or '?'), who=by)
    return cid, name, info


def _keep_result(store, job_id, source, results):
    try:
        store.set_meta(RESULT_PREFIX + str(job_id), json.dumps(
            {'source': source, 'results': results, 'at': time.time(), 'job': job_id},
            default=str))
        keys = S.jload(store.get_meta(RESULT_PREFIX + 'list'), []) or []
        keys = [k for k in keys if k != job_id] + [job_id]
        for old in keys[:-RESULT_KEEP]:
            store.db.run('DELETE FROM meta WHERE k = ?', (RESULT_PREFIX + str(old),))
        store.set_meta(RESULT_PREFIX + 'list', json.dumps(keys[-RESULT_KEEP:]))
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-onlineimport', 'an import\'s result could not be kept: %s' % e,
                      'warn', every=3600)


def import_result(store, job_id):
    """What the import job `job_id` did, or None (not finished, or long gone)."""
    return S.jload(store.get_meta(RESULT_PREFIX + str(int(job_id))), None)


# ---------------------------------------------------------------------------
# The private key added later
# ---------------------------------------------------------------------------
def _read_key(b, prefix=''):
    """The key given: pasted PEM (key_pem) or a file (key_b64 + key_filename, a PEM,
    PKCS#8, PFX/P12 with key_password). -> PEM or None."""
    from acmelib.certs import formats
    import base64
    text = str(b.get(prefix + 'key_pem') or '').strip()
    pw = str(b.get(prefix + 'key_password') or '') or None
    if len(pw or '') > 1000:
        raise ValueError('the password: 1000 characters at most')
    if text:
        if len(text) > 200000:
            raise ValueError('that is not a key: too long')
        data, fname = text.encode('utf-8'), 'key.pem'
    elif b.get(prefix + 'key_b64'):
        try:
            data = base64.b64decode(str(b.get(prefix + 'key_b64')), validate=False)
        except (ValueError, TypeError):
            raise ValueError('the file is not base64')
        if len(data) > 2000000:
            raise ValueError('the file is too big for a key')
        fname = str(b.get(prefix + 'key_filename') or 'key.pem')[:300]
    else:
        return None
    try:
        got = formats.read_any(data, fname, pw) or {}
    except base.PluginError as e:
        raise ValueError('the key cannot be read: %s' % e)
    except Exception as e:                              # noqa: BLE001
        raise ValueError('the key cannot be read: %s' % e)
    if got.get('needs_password'):
        raise ValueError('the key is locked: give its password')
    key = got.get('key') or ((got.get('keys') or [None])[0])
    if not key:
        raise ValueError('there is no private key in what was given')
    try:
        S.pki().key_info(key)
    except Exception as e:                              # noqa: BLE001
        raise ValueError('the key cannot be read: %s' % e)
    return key


def add_key(store, row, b, by):
    """The private key of a certificate acme holds none of, checked against the
    certificate (pki.key_matches), sealed and kept with its current version - as an
    import with its key keeps it. A dual certificate: the twin's key (alt_*) too.
    -> {'main': bool, 'alt': bool}."""
    pki = S.pki()
    if row.get('csr_given'):
        raise ValueError('%s was issued for a CSR that was sent in: its key stays where the CSR '
                         'was made' % row['name'])
    if not row.get('cert_pem'):
        raise ValueError('%s has no certificate yet' % row['name'])
    key = _read_key(b)
    alt_key = _read_key(b, 'alt_') if row.get('alt_cert_pem') else None
    if not key and not alt_key:
        raise ValueError('give the private key: paste it, or drop its file')
    done = {'main': False, 'alt': False}
    t = time.time()

    def fit(cert_pem, k):
        return bool(pki.key_matches(cert_pem, k))
    if key and not fit(row['cert_pem'], key):
        # One key for the twin only, given in the main box: taken for the twin.
        if row.get('alt_cert_pem') and not alt_key and fit(row['alt_cert_pem'], key):
            key, alt_key = None, key
        else:
            raise ValueError('the key does not belong to the certificate %s (its public key '
                             'is another one)' % row['name'])
    if alt_key and not fit(row['alt_cert_pem'], alt_key):
        raise ValueError('the second key does not belong to the twin of %s' % row['name'])
    if key:
        if row.get('key_sealed'):
            raise ValueError('acme holds the key of %s already' % row['name'])
        ver = int(row.get('version') or 0)
        sealed = E.seal_secret(key, S.key_place(row['id'], ver))
        store.db.update('certs', row['id'], {'key_sealed': sealed, 'updated': t,
                                             'updated_by': str(by)[:190]})
        store.db.run("UPDATE cert_versions SET key_sealed = ? WHERE cert_id = ? AND version = ? "
                     "AND COALESCE(variant, '') = ''", (sealed, row['id'], ver))
        done['main'] = True
    if alt_key:
        if row.get('alt_key_sealed'):
            raise ValueError('acme holds the key of the twin of %s already' % row['name'])
        ver = int(row.get('alt_version') or 0)
        sealed = E.seal_secret(alt_key, S.key_place(row['id'], ver, 'alt'))
        store.db.update('certs', row['id'], {'alt_key_sealed': sealed, 'updated': t,
                                             'updated_by': str(by)[:190]})
        store.db.run("UPDATE cert_versions SET key_sealed = ? WHERE cert_id = ? AND version = ? "
                     "AND variant = 'alt'", (sealed, row['id'], ver))
        done['alt'] = True
    store.add_event('certificates', 'the private key of %s%s was added by %s - it fits the '
                    'certificate' % (row['name'], ' (and its twin)' if done['alt'] and
                                     done['main'] else (' (its twin)' if done['alt'] else ''),
                                     by or '?'), who=by)
    return done
