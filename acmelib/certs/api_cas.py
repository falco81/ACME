# -*- coding: utf-8 -*-
"""
An authority of acme's own changed after it was made (docs/own-ca.md,
"Changing an authority") - the routes the pages and the command line ask:

    POST /api/cas/save         {id, name?, days_default?, crl_days?, crl_url?, aia_url?,
                               ocsp_url?, note?, disabled?, eku?}   what is NOT inside its
                               certificate (fulladmin). crl_url / aia_url 'own': acme's own.
    GET  /api/cas/dependents?id=   the sources, certificates and authorities that rely on it
    POST /api/cas/renew        {id, days?, path_len?, name_constraints?}   its certificate made
                               again with the same key (fulladmin)
    POST /api/cas/install_cert {id, cert_pem | data_b64, chain_pem?}   the certificate a CA
                               elsewhere signed (the first one, or a renewal's answer)
    GET  /api/cas/versions?id= every certificate it has had, newest first

A rename takes what refers to the authority by name along, in one
transaction (as names.py does for names made safe): the settings of every
module whose field lists authorities (internal_ca's "ca"), meta
certs:default_ca, and its address on acme (/pki/<slug>): a slug of the new
name from then on, the old one answering still - certificates signed before
carry it in their CRL distribution point and AIA.

Imported at the end of api.py, as api_sshkeys and api_readiness are.
"""
from __future__ import annotations

import base64
import time

from acmelib.certs import api as A
from acmelib.certs import defaults as DF
from acmelib.certs import names as N
from acmelib.certs import store as S

URL_WORDS = {'crl_url': 'CRL address', 'aia_url': 'CA certificate address (AIA)',
             'ocsp_url': 'OCSP address'}
WORDS = {'name': 'name', 'days_default': 'issues for (days)', 'crl_days': 'CRL valid for (days)',
         'crl_url': 'CRL address', 'aia_url': 'CA certificate address', 'ocsp_url': 'OCSP address',
         'note': 'note', 'disabled': 'switched off', 'eku': 'default key usage'}


def _ca():
    return A._lib('ca')


def _pub():
    return A._lib('publish')


def _day(ts):
    try:
        return time.strftime('%Y-%m-%d', time.gmtime(float(ts)))
    except (TypeError, ValueError):
        return '-'


# ---------------------------------------------------------------------------
# What relies on it
# ---------------------------------------------------------------------------
def dependents(store, ref):
    """{sources: [names], certs: [names], children: [names], is_default} - the
    sources that sign with it (every module field listing authorities), the
    certificates of those sources, the authorities under it."""
    row = A.ca_row(store, ref)
    mine = (str(row['id']), row['name'])
    sources = []
    for r in store.db.rows('SELECT id, name, kind, config FROM cert_issuers ORDER BY name'):
        cls = S.row_class('issuer', r)
        keys = [f['key'] for f in (getattr(cls, 'fields', None) or [])
                if N.OPTIONS_OF.get(f.get('options_from')) == 'ca'] or \
            (['ca'] if r.get('kind') == 'internal_ca' else [])
        cfg = S.jload(r.get('config'), {}) or {}
        for k in keys:
            v = cfg.get(k)
            if str(v) in mine or (isinstance(v, list) and any(str(x) in mine for x in v)):
                sources.append(r['name'])
                break
    certs = []
    if sources:
        marks = ', '.join('?' for _ in sources)
        certs = [r['name'] for r in store.db.rows(
            'SELECT name FROM certs WHERE issuer IN (%s) ORDER BY name' % marks, tuple(sources))]
    children = [r['name'] for r in store.db.rows(
        'SELECT name FROM cert_cas WHERE parent_id = ? ORDER BY name', (int(row['id']),))]
    return {'sources': sources, 'certs': certs, 'children': children,
            'is_default': DF.default_name(store, 'ca') == str(row['id'])}


@A.api('GET', '/api/cas/dependents')
def _ca_dependents(h, s):
    return dependents(h.store, h.arg('id') or h.arg('name'))


# ---------------------------------------------------------------------------
# Editing
# ---------------------------------------------------------------------------
def _changes(b):
    """What the body asks to change, as ca_edit takes it."""
    out = {}
    if 'name' in b and b.get('name') not in (None, ''):
        out['name'] = S.clean_name(b.get('name'), 'the authority\'s name')
    for k in ('days_default', 'crl_days'):
        if b.get(k) not in (None, ''):
            try:
                out[k] = int(b[k])
            except (TypeError, ValueError):
                raise ValueError('%s is a number of days' % k)
    for k in ('crl_url', 'aia_url', 'ocsp_url'):
        if k in b and b.get(k) is not None:
            out[k] = A._text(b, k, 500).strip()
    if 'note' in b and b.get('note') is not None:
        out['note'] = A._text(b, 'note', 2000)
    if 'disabled' in b and b.get('disabled') is not None:
        out['disabled'] = A._flag(b.get('disabled'))
    elif 'enabled' in b and b.get('enabled') is not None:
        out['disabled'] = 0 if A._flag(b.get('enabled'), 1) else 1
    if 'eku' in b and b.get('eku') is not None:
        out['eku'] = A._list(b.get('eku'), 'eku')
    return out


def _words(k, v):
    if k == 'disabled':
        return 'yes' if v else 'no'
    if k == 'eku':
        return ', '.join(v) or 'serverAuth, clientAuth'
    if v in (None, ''):
        return '(none)'
    return str(v)


def ca_save(store, b, by):
    """POST /api/cas/save, for the pages and the command line -> {id, name,
    changed: {field: [old, new]}, warnings: [..], message}."""
    ca = _ca()
    pub = _pub()
    row = dict(A.ca_row(store, b.get('id') if b.get('id') not in (None, '') else b.get('ref')))
    changes = _changes(b)
    # 'own': acme's own address on /pki/ (made of the new name, when it is renamed).
    own = {k for k in ('crl_url', 'aia_url') if str(changes.get(k, '')).lower() == 'own'}
    for k in own:
        changes.pop(k)
    if str(changes.get('ocsp_url', '')).lower() == 'own':
        raise ValueError('acme runs no OCSP responder: give the address of your own, or leave '
                         'it empty')
    old_name = row['name']
    renaming = 'name' in changes and changes['name'] != old_name
    warnings = []
    slugs = None
    try:
        old_urls = pub.urls(store, row)
    except Exception:                                   # noqa: BLE001
        old_urls = {}
    with N._Tx(store.db):
        got, done = ca.ca_edit(store, row['id'], changes, by=by, remake_crl=False)
        if renaming:
            N._configs(store, 'ca', old_name, changes['name'])
            if store.get_meta(DF.META['ca']) == old_name:      # kept by name somewhere old
                store.set_meta(DF.META['ca'], str(int(row['id'])))
            slugs = pub.renamed(store, row['id'])
        got = dict(A.ca_row(store, row['id']))
        new_urls = pub.urls(store, got)
        moved = {}
        for k, part in (('crl_url', 'crl'), ('aia_url', 'cert')):
            if k in own:
                want = new_urls[part]
            elif renaming and k not in changes and old_urls and \
                    (got.get(k) or '') == old_urls.get(part):
                want = new_urls[part]                   # acme's own followed the new name
            else:
                continue
            if (got.get(k) or '') != want:
                moved[k] = want
        if moved:
            _r, more = ca.ca_edit(store, row['id'], moved, by=by, remake_crl=False)
            done.update(more)
    if 'crl_days' in done and got.get('cert_pem') and got.get('key_sealed'):
        try:
            ca.ca_crl(store, row['id'])
        except Exception as e:                          # noqa: BLE001
            warnings.append('its CRL was not made anew: %s' % e)
    got = dict(A.ca_row(store, row['id']))
    name = got['name']
    if any(k in done for k in ('crl_url', 'aia_url', 'ocsp_url')):
        warnings.append('the addresses go into what %s signs from now on - certificates signed '
                        'before keep the ones they carry until they are renewed' % name)
    if slugs and slugs[0] != slugs[1]:
        warnings.append('on acme its CRL and certificate are at /pki/%s.crl and .crt now; the '
                        'old /pki/%s.crl and .crt answer still (certificates signed before '
                        'carry them)' % (slugs[1], slugs[0]))
    if done.get('disabled', (0, 0))[1]:
        dep = dependents(store, row['id'])
        parts = []
        if dep['sources']:
            parts.append('the sources %s' % ', '.join(dep['sources']))
        if dep['certs']:
            parts.append('the certificates %s%s' % (', '.join(dep['certs'][:20]), (
                ' and %d more' % (len(dep['certs']) - 20)) if len(dep['certs']) > 20 else ''))
        if dep['children']:
            parts.append('the authorities under it %s' % ', '.join(dep['children']))
        warnings.append('%s signs nothing now (its CRL is still made and published)%s' % (
            name, ('; it is relied on by %s - their renewals will fail until it is switched on '
                   'or they use another authority' % '; '.join(parts)) if parts else ''))
        if dep['is_default']:
            warnings.append('it is the default authority: it is not offered first while it is '
                            'switched off')
    if done:
        store.add_event('certificates', 'authority %s edited by %s: %s' % (
            name, by, '; '.join('%s %s -> %s' % (WORDS.get(k, k), _words(k, o), _words(k, n))
                                for k, (o, n) in sorted(done.items()))),
            'warn' if done.get('disabled', (0, 0))[1] else 'info', who=by)
    for w in warnings:
        if 'signs nothing' in w or 'relied on' in w:
            store.add_event('certificates', w, 'warn', who=by)
    return {'id': int(got['id']), 'name': name,
            'changed': {k: [o, n] for k, (o, n) in done.items()}, 'warnings': warnings,
            'message': ('%s saved' % name) if done else 'nothing was changed',
            'pki': pub.view(store, got['id'])}


@A.api('POST', '/api/cas/save', 'fulladmin')
def _ca_save(h, s):
    b = h.body()
    if b.get('id') in (None, ''):
        raise ValueError('which authority? (id)')
    return ca_save(h.store, b, A.who(s))


# ---------------------------------------------------------------------------
# Renewing its certificate (the same key)
# ---------------------------------------------------------------------------
def ca_renew(store, b, by):
    ca = _ca()
    row = dict(A.ca_row(store, b.get('id')))
    kw = {}
    if b.get('days') not in (None, ''):
        try:
            kw['days'] = int(b['days'])
        except (TypeError, ValueError):
            raise ValueError('days is a number')
    if 'path_len' in b:
        v = b.get('path_len')
        kw['path_len'] = None if v in (None, '', -1, '-1', 'none') else v
    if 'name_constraints' in b and b.get('name_constraints') is not None:
        v = b['name_constraints']
        kw['name_constraints'] = [x.strip() for x in v.split('\n') if x.strip()] \
            if isinstance(v, str) else A._list(v, 'name_constraints')
    old_end = row.get('not_after')
    root = False
    try:
        root = bool(S.info_of(row['cert_pem']).get('self_signed')) if row.get('cert_pem') else False
    except Exception:                                   # noqa: BLE001
        pass
    got = ca.ca_renew(store, row['id'], by=by, **kw)
    if got.get('pending'):
        store.add_event('certificates', 'authority %s: a request for its renewal with the same '
                        'key made by %s - for the CA above it; install the answer' % (
                            row['name'], by), who=by)
        return dict(got, root=False, message='have the request signed by the CA above %s, '
                    'then install what comes back' % row['name'])
    notes = []
    if root:
        notes.append('a root: give its new certificate to everything that trusts the old one '
                     'before the old one ends on %s - what %s signed verifies against both'
                     % (_day(old_end), row['name']))
    else:
        notes.append('servers send the new certificate of %s in their chain once their own '
                     'certificates are renewed (or deployed again); what it signed stays valid'
                     % row['name'])
    if got.get('capped'):
        notes.append('it ends with the authority above it (%s), before the days asked'
                     % _day(got.get('not_after')))
    store.add_event('certificates', 'authority %s renewed with the same key by %s: valid until %s '
                    '(serial %s, version %s)%s' % (
                        row['name'], by, _day(got.get('not_after')), got.get('serial'),
                        got.get('version'), ('; the chains of %s made anew' % ', '.join(
                            got['children'])) if got.get('children') else ''), who=by)
    return dict(got, root=root, warnings=notes,
                message='%s renewed: valid until %s' % (row['name'], _day(got.get('not_after'))))


@A.api('POST', '/api/cas/renew', 'fulladmin')
def _ca_renew(h, s):
    return ca_renew(h.store, h.body(), A.who(s))


@A.api('POST', '/api/cas/install_cert', 'fulladmin')
def _ca_install(h, s):
    """{id, cert_pem | data_b64 (+ filename), chain_pem?} - what the CA elsewhere signed."""
    b = h.body()
    row = dict(A.ca_row(h.store, b.get('id')))
    data = A._b64(b['data_b64']) if b.get('data_b64') else str(b.get('cert_pem') or '').encode()
    if not data.strip():
        raise ValueError('no certificate was given')
    chain = A._lib('pki').certs_in(str(b['chain_pem'])) if b.get('chain_pem') else []
    renewal = bool(row.get('cert_pem'))
    _ca().ca_install_cert(h.store, row['id'], data, chain, by=A.who(s))
    now = dict(A.ca_row(h.store, row['id']))
    if not renewal:
        _pub().fill_new(h.store, row['id'])
    h.store.add_event('certificates', 'authority %s: its certificate installed by %s - valid '
                      'until %s%s' % (row['name'], A.who(s), _day(now.get('not_after')),
                                      ' (a renewal with the same key)' if renewal else ''),
                      who=A.who(s))
    return {'id': int(row['id']), 'not_after': now.get('not_after'), 'renewal': renewal,
            'message': 'the certificate of %s installed' % row['name']}


@A.api('GET', '/api/cas/versions')
def _ca_versions(h, s):
    row = A.ca_row(h.store, h.arg('id') or h.arg('name'))
    return {'id': int(row['id']), 'name': row['name'],
            'rows': _ca().ca_versions(h.store, row['id'])}


# ---------------------------------------------------------------------------
# The command line: --ca-edit, --ca-renew, --ca-versions (cli.py hands them here)
# ---------------------------------------------------------------------------
CLI_KEYS = ('name', 'days_default', 'crl_days', 'crl_url', 'aia_url', 'ocsp_url', 'note',
            'disabled', 'enabled', 'eku')


def cli_edit(cli, ref):
    r = cli.ca_ref(ref)
    body = {'id': r['id']}
    for k, op, v in cli.sets():
        if k not in CLI_KEYS:
            raise SystemExit('acme: an authority takes --set %s, not %s' % (
                ' '.join(CLI_KEYS), k))
        if op != '=':
            raise SystemExit('acme: --set %s=VALUE' % k)
        body[k] = v
    if len(body) == 1:
        raise SystemExit('acme: --ca-edit CA --set KEY=VALUE (%s)' % ', '.join(CLI_KEYS))
    got = cli.api('POST', '/api/cas/save', body=body)
    if cli.json:
        cli.out(got)
        return 0
    cli.done(got.get('message') or 'saved')
    for k, (o, n) in sorted((got.get('changed') or {}).items()):
        print('  %-18s %s -> %s' % (k, _words(k, o), _words(k, n)))
    for w in got.get('warnings') or []:
        print('  ' + cli.pal.warn('! ' + w))
    return 0


def cli_renew(cli, ref):
    a = cli.args
    r = cli.ca_ref(ref)
    body = {'id': r['id']}
    if a.days not in (None, 825):
        body['days'] = a.days
    if getattr(a, 'path_len', None) is not None:
        body['path_len'] = None if str(a.path_len).lower() in ('', 'none', '-1', '-') else \
            a.path_len
    if getattr(a, 'name_constraints', None) is not None:
        nc = str(a.name_constraints)
        body['name_constraints'] = [] if nc.lower() in ('', 'none', '-') else \
            [x.strip() for x in nc.replace('\n', ',').split(',') if x.strip()]
    got = cli.api('POST', '/api/cas/renew', body=body)
    if cli.json:
        cli.out(got)
        return 0
    if got.get('pending'):
        cli.done(got.get('message'))
        print(got.get('csr_pem') or '')
        print('  then: acme --ca-install-cert %s FILE' % r['name'])
        return 0
    cli.done(got.get('message') or 'renewed')
    cli.kv([('serial', got.get('serial')), ('sha-256', got.get('fingerprint')),
            ('valid', '%s - %s' % (_day(got.get('not_before')), _day(got.get('not_after')))),
            ('path length', 'no limit' if got.get('path_len') is None else got.get('path_len')),
            ('version', got.get('version')),
            ('chains made anew', ', '.join(got.get('children') or []))])
    for w in got.get('warnings') or []:
        print('  ' + cli.pal.warn('! ' + w))
    return 0


def cli_versions(cli, ref):
    r = cli.ca_ref(ref)
    got = cli.api('GET', '/api/cas/versions', args={'id': str(r['id'])})
    if cli.json:
        cli.out(got)
        return 0
    cli.table([[v.get('version'), v.get('serial'), _day(v.get('not_before')),
                _day(v.get('not_after')), v.get('path_len') if v.get('path_len') is not None
                else '-', (v.get('fingerprint') or '')[:23],
                'now' if v.get('current') else ('valid' if v.get('valid') else 'ended'),
                v.get('why') or '', v.get('by_who') or '']
               for v in got.get('rows') or []],
              ['version', 'serial', 'from', 'until', 'path', 'sha-256', 'state', 'why', 'by'])
    return 0


def cli_install(cli, ref, path):
    r = cli.ca_ref(ref)
    data = cli.files.get(path)
    if data is None:
        data = cli._read(path)
    got = cli.api('POST', '/api/cas/install_cert', body={
        'id': r['id'], 'data_b64': base64.b64encode(data).decode('ascii'),
        'filename': path.rsplit('/', 1)[-1]})
    return cli.done(got.get('message') or 'installed', got)
