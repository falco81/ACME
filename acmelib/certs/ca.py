# -*- coding: utf-8 -*-
"""
acme's own certificate authorities: roots, intermediates under them (or
under a CA elsewhere), what they sign, what they revoke, their CRLs.

    ca_create(store, name, subject, key_type='ec-384', days=3650, parent_id=None, path_len=None,
              crl_days=7, crl_url='', aia_url='', ocsp_url='', name_constraints=None, by='') -> id
    ca_import(store, name, cert_pem, key_pem, chain_pems=None, password=None, by='') -> id
    ca_csr(store, name, subject, key_type='ec-384', ...) -> (id, csr_pem)   an intermediate whose
    ca_install_cert(store, ca_id, cert_pem, chain_pems=None, by='')      certificate comes later
    ca_get(store, ca_id) / ca_list(store) / ca_issued(store, ca_id)
    ca_sign(store, ca_id, csr_pem, days, profile=None, cert_id=None, by='')
                                                    -> (cert_pem, chain_pems)
    ca_revoke(store, ca_id, serial, reason, by='') / ca_unrevoke(store, ca_id, serial, by='')
    ca_crl(store, ca_id) -> crl_pem
    ca_delete(store, ca_id)
    ca_export(store, ca_id, what, password=None) -> {filename, mime, data}
    ca_edit(store, ca_id, changes, by='') -> (row, {field: (old, new)})   what is not in its
                                                    certificate: name, days, CRL days, URLs...
    ca_renew(store, ca_id, days=None, path_len=KEEP, name_constraints=None, by='')
                                                    its certificate again, with the same key
    ca_versions(store, ca_id) -> [every certificate it has had, newest first]

`store` is the engine's Storage (only store.db is used: run / rows / row /
value / insert). A CA's key is kept sealed, bound to its row
(E.seal_secret(pem, 'cert_cas:<id>:key')); it is opened only to sign, and
handed to openssl in a directory of our own that is removed at once.

Every signature is made by `openssl ca` with a configuration and an index
written for that one run: what the CA signed is in cert_ca_issued, not in
files - so both nodes of a cluster sign and revoke alike.
"""
from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import time
import zipfile

from acmelib.certs import formats, pki
from acmelib.certs.pki import PkiError

DEFAULT_LEAF_DAYS = 397
BACKDATE_S = 3600           # a certificate begins an hour ago: clocks are not all right

REASONS = ('unspecified', 'keyCompromise', 'CACompromise', 'affiliationChanged', 'superseded',
           'cessationOfOperation', 'certificateHold')
_REASON_ALIAS = {r.lower(): r for r in REASONS}
_REASON_ALIAS.update({'key_compromise': 'keyCompromise', 'ca_compromise': 'CACompromise',
                      'affiliation_changed': 'affiliationChanged',
                      'cessation_of_operation': 'cessationOfOperation',
                      'certificate_hold': 'certificateHold', 'hold': 'certificateHold',
                      '': 'unspecified', 'none': 'unspecified',
                      'privilegewithdrawn': 'unspecified', 'aacompromise': 'unspecified',
                      '0': 'unspecified', '1': 'keyCompromise', '2': 'CACompromise',
                      '3': 'affiliationChanged', '4': 'superseded',
                      '5': 'cessationOfOperation', '6': 'certificateHold'})


def _E():
    from acmelib import engine
    return engine


def _log(words, level='info'):
    try:
        _E().log(words, level)
    except Exception:                                   # noqa: BLE001
        pass


def _bind(ca_id):
    return 'cert_cas:%d:key' % int(ca_id)


def _now():
    return int(time.time())


def _gtime(epoch):
    return time.strftime('%Y%m%d%H%M%SZ', time.gmtime(int(epoch)))


def _index_time(epoch):
    """A time as openssl's index.txt writes it: UTCTime to 2049, then GeneralizedTime."""
    t = time.gmtime(int(epoch))
    return time.strftime('%y%m%d%H%M%SZ' if t.tm_year < 2050 else '%Y%m%d%H%M%SZ', t)


def _j(v, default):
    if v in (None, ''):
        return default
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------
def _row(store, ca_id):
    if isinstance(ca_id, str) and not ca_id.strip().isdigit():
        r = store.db.row('SELECT * FROM cert_cas WHERE name = ?', (ca_id.strip(),))
    else:
        r = store.db.row('SELECT * FROM cert_cas WHERE id = ?', (int(ca_id),))
    if not r:
        raise PkiError('there is no certificate authority %s' % ca_id, retry=False)
    return dict(r)


def _key(row):
    sealed = row.get('key_sealed') or ''
    if not sealed:
        raise PkiError('the authority "%s" has no key here' % row['name'], retry=False)
    key = _E().unseal_secret(sealed, _bind(row['id']))
    if not key:
        raise PkiError('the key of the authority "%s" cannot be opened on this machine (it '
                       'was sealed with another key, or its row was changed)' % row['name'],
                       retry=False)
    return key


def _chain(row):
    return pki.certs_in(row.get('chain_pem') or '')


def _pending(row):
    return not row.get('cert_pem')


def _usable(row, now=None):
    now = now or _now()
    if _pending(row):
        raise PkiError('the authority "%s" waits for its certificate (install the one the '
                       'parent CA signed)' % row['name'], retry=False)
    if row.get('disabled'):
        raise PkiError('the authority "%s" is switched off' % row['name'], retry=False)
    if row.get('not_after') and float(row['not_after']) <= now:
        raise PkiError('the authority "%s" ran out on %s' % (
            row['name'], time.strftime('%Y-%m-%d', time.gmtime(float(row['not_after'])))),
            retry=False)


def _check_name(store, name, but=None):
    name = str(name or '').strip()
    if not name or len(name) > 120 or '\n' in name:
        raise PkiError('an authority needs a name (up to 120 characters)', retry=False)
    r = store.db.row('SELECT id FROM cert_cas WHERE name = ?', (name,))
    if r and (but is None or int(r['id']) != int(but)):
        raise PkiError('there is an authority "%s" already' % name, retry=False)
    return name


def _check_url(u, what):
    u = str(u or '').strip()
    if not u:
        return ''
    if not re.match(r'^(https?|ldap)://[^\s,;"\'\\]+$', u):
        raise PkiError('%s is not a URL acme can put into a certificate: %s' % (what, u),
                       retry=False)
    return u


def _subject(subject):
    if isinstance(subject, str) and '=' not in subject:
        subject = {'CN': subject.strip()}
    pairs = pki.subject_pairs(subject)
    if not pairs:
        raise PkiError('an authority needs a subject (a common name at least)', retry=False)
    return pairs


# ---------------------------------------------------------------------------
# Name constraints
# ---------------------------------------------------------------------------
def nc_normalize(items):
    """['example.com', 'DNS:.corp', '!DNS:bad.example.com', 'IP:10.0.0.0/8',
    'email:example.com', 'excluded;URI:.x'] -> ['permitted;DNS:example.com', ...]
    as openssl's nameConstraints wants them."""
    if isinstance(items, str):
        items = [i for i in re.split(r'[\n,]+', items) if i.strip()]
    out = []
    for raw in items or []:
        s = str(raw).strip()
        if not s:
            continue
        which = 'permitted'
        if s.startswith('!'):
            which, s = 'excluded', s[1:].strip()
        m = re.match(r'^(permitted|excluded)(?:[;:]|\s)\s*(.*)$', s, re.I)
        if m:
            which, s = m.group(1).lower(), m.group(2).strip()
        if ':' in s and s.split(':', 1)[0].upper() in ('DNS', 'IP', 'EMAIL', 'URI'):
            t, v = s.split(':', 1)
            t = {'EMAIL': 'email'}.get(t.upper(), t.upper())
        else:
            t, v = 'DNS', s
        v = v.strip()
        if t == 'IP':
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise PkiError('not a network: %s (write it as 10.0.0.0/8)' % v, retry=False)
            v = '%s/%s' % (net.network_address, net.netmask)
        elif not re.match(r'^[A-Za-z0-9.*@_-]+$', v):
            raise PkiError('a name constraint acme cannot write: %s' % raw, retry=False)
        out.append('%s;%s:%s' % (which, t, v))
    return out


def _nc_allows(nc, typed):
    """Whether (type, value) passes name constraints [which;T:v] (RFC 5280 §4.2.1.10, simply)."""
    t, v = typed
    rules = {'permitted': [], 'excluded': []}
    for item in nc:
        which, rest = item.split(';', 1)
        rt, rv = rest.split(':', 1)
        if rt == t:
            rules[which].append(rv)

    def hit(rv):
        if t == 'DNS':
            name, base = v.lower().lstrip('*.'), rv.lower()
            if base.startswith('.'):
                return name.endswith(base)
            return name == base or name.endswith('.' + base)
        if t == 'IP':
            net = ipaddress.ip_network(rv, strict=False)
            ip = ipaddress.ip_address(v)
            return ip.version == net.version and ip in net
        if t == 'email':
            dom = v.rsplit('@', 1)[-1].lower()
            base = rv.lower()
            if '@' in base:
                return v.lower() == base
            if base.startswith('.'):
                return dom.endswith(base)
            return dom == base
        if t == 'URI':
            host = re.sub(r'^[a-z][a-z0-9+.-]*://([^/:]*).*$', r'\1', v.lower())
            base = rv.lower()
            return host.endswith(base) if base.startswith('.') else host == base
        return False
    if any(hit(rv) for rv in rules['excluded']):
        return False
    if rules['permitted']:
        return any(hit(rv) for rv in rules['permitted'])
    return True


# ---------------------------------------------------------------------------
# Signing with openssl ca
# ---------------------------------------------------------------------------
def _issuer_lines(row):
    """CRL distribution point and AIA of what `row` (the issuer) signs."""
    lines = []
    if row.get('crl_url'):
        lines.append('crlDistributionPoints = URI:%s' % pki._cv(row['crl_url']))
    aia = []
    if row.get('aia_url'):
        aia.append('caIssuers;URI:%s' % pki._cv(row['aia_url']))
    if row.get('ocsp_url'):
        aia.append('OCSP;URI:%s' % pki._cv(row['ocsp_url']))
    if aia:
        lines.append('authorityInfoAccess = ' + ', '.join(aia))
    return lines


def _ca_lines(path_len, nc, ski=None, key_usage=None):
    """The extensions of an authority's certificate. `ski` (hex) keeps a key
    identifier as it was (a renewal of one made elsewhere); `key_usage` the
    key usage it had (keyCertSign and cRLSign always in it)."""
    bc = 'critical, CA:TRUE'
    if path_len not in (None, '') and int(path_len) >= 0:
        bc += ', pathlen:%d' % int(path_len)
    ku = ['keyCertSign', 'cRLSign', 'digitalSignature']
    if key_usage:
        ku = pki._ku_value(key_usage)
        ku += [k for k in ('keyCertSign', 'cRLSign') if k not in ku]
    ski = re.sub(r'[^0-9A-Fa-f]', '', str(ski or ''))
    lines = ['basicConstraints = ' + bc,
             'keyUsage = critical, ' + ', '.join(ku),
             'subjectKeyIdentifier = ' + (ski if ski else 'hash'),
             'authorityKeyIdentifier = keyid:always']
    if nc:
        lines.append('nameConstraints = critical, ' + ', '.join(nc))
    return lines


def _ca_config(d, md, ext_lines, san_lines, crl_days=7):
    cfg = ['[ca]', 'default_ca = d', '', '[d]',
           'database = %s' % os.path.join(d, 'index.txt'),
           'serial = %s' % os.path.join(d, 'serial'),
           'crlnumber = %s' % os.path.join(d, 'crlnumber'),
           'new_certs_dir = %s' % d, 'default_md = %s' % md, 'policy = pol',
           'unique_subject = no', 'email_in_dn = yes', 'copy_extensions = none',
           'default_crl_days = %d' % max(1, int(crl_days or 7)),
           'crl_extensions = crl_ext', '', '[pol]', 'commonName = optional', '',
           '[crl_ext]', 'authorityKeyIdentifier = keyid:always', '',
           '[ext]'] + list(ext_lines) + ['']
    if san_lines:
        cfg += ['[san]'] + list(san_lines) + ['']
    return pki.wfile(d, 'ca.cnf', '\n'.join(cfg) + '\n')


def _openssl_ca_sign(issuer_cert, issuer_key, csr_pem, serial, not_before, not_after,
                     ext_lines, san_lines, subject_pairs=None, selfsign=False):
    issuer_kt = pki.key_info(issuer_key)['key_type']
    with pki.workdir() as d:
        pki.wfile(d, 'index.txt', '')
        pki.wfile(d, 'serial', serial + '\n')
        pki.wfile(d, 'crlnumber', '01\n')
        cfg = _ca_config(d, pki.md_name(issuer_kt), ext_lines, san_lines)
        args = ['ca', '-batch', '-notext', '-preserveDN', '-utf8', '-config', cfg,
                '-in', pki.wfile(d, 'req.csr', csr_pem),
                '-keyfile', pki.wfile(d, 'ca.key', issuer_key),
                '-extfile', cfg, '-extensions', 'ext',
                '-startdate', _gtime(not_before), '-enddate', _gtime(not_after),
                '-out', os.path.join(d, 'out.pem')]
        if selfsign:
            args.append('-selfsign')
        else:
            args += ['-cert', pki.wfile(d, 'ca.pem', issuer_cert)]
        if subject_pairs:
            args += ['-subj', pki._subj_arg(subject_pairs)]
        pki.openssl(args)
        return pki.certs_in(pki.rfile(d, 'out.pem'))[0]


def _csr_for_ca(key_pem, pairs, path_len=None):
    """A request for an intermediate, CA:TRUE asked for in it (AD CS's SubCA wants that)."""
    kt = pki.key_info(key_pem)['key_type']
    bc = 'critical, CA:TRUE' + (', pathlen:%d' % int(path_len) if path_len not in
                               (None, '') else '')
    ext = ['basicConstraints = ' + bc, 'keyUsage = critical, keyCertSign, cRLSign, '
           'digitalSignature']
    with pki.workdir() as d:
        args = ['req', '-new', '-utf8', '-key', pki.wfile(d, 'k.key', key_pem), '-config',
                pki.wfile(d, 'req.cnf', pki.req_config(pairs, ext, []))] + pki.md_args(kt)
        out = pki.openssl(args)
    return [p for lab, p in pki.split_pem(out) if 'REQUEST' in lab][0]


def _new_serial(store, ca_id):
    for _ in range(10):
        s = pki.random_serial()
        if not store.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ? AND '
                              'serial = ?', (int(ca_id), s), 0):
            return s
    raise PkiError('no free serial number (this should not happen)')


def _record(store, ca_id, cert_pem, cert_id=None, by=''):
    i = pki.cert_info(cert_pem)
    store.db.insert('cert_ca_issued', {
        'ca_id': int(ca_id), 'serial': i['serial'], 'subject_dn': i['subject_dn'],
        'names': json.dumps(i['names']), 'not_before': i['not_before'],
        'not_after': i['not_after'], 'fingerprint': i['sha256'],
        'cert_id': int(cert_id) if cert_id not in (None, '') else None, 'revoked': None,
        'reason': '', 'created': _now(), 'by_who': str(by or ''), 'cert_pem': cert_pem})
    store.db.run('UPDATE cert_cas SET serial_next = COALESCE(serial_next, 0) + 1 WHERE id = ?',
                 (int(ca_id),))
    E = _E()
    if E.split_noting():
        # Signed while the two nodes cannot reach each other (1.0.14): for the report - an
        # authority signing on both halves counts its serials and its CRLs two ways.
        name = store.db.value('SELECT name FROM cert_cas WHERE id = ?', (int(ca_id),)) or ca_id
        E.split_took(store, 'sign', name, 'sign:%s' % int(ca_id))


def _split_held():
    """Not signed on both halves of a split cluster (1.0.14, docs/split-brain.md)."""
    held = _E().split_issue_refused()
    if held:
        raise PkiError(held)


def _child_path_len(parent_row, want):
    """The path length an authority under `parent_row` may have (None: unlimited)."""
    if parent_row is None:
        return want
    pinfo = pki.cert_info(parent_row['cert_pem'])
    ppl = pinfo['path_len']
    if ppl is None:
        return want
    if ppl <= 0:
        raise PkiError('the authority "%s" may not have authorities under it (its path '
                       'length is 0)' % parent_row['name'], retry=False)
    if want in (None, ''):
        return ppl - 1
    if int(want) > ppl - 1:
        raise PkiError('under "%s" the path length can be %d at most' % (parent_row['name'],
                                                                        ppl - 1), retry=False)
    return int(want)


# ---------------------------------------------------------------------------
# Making, importing
# ---------------------------------------------------------------------------
def _insert_ca(store, fields, key_pem):
    ident = store.db.insert('cert_cas', dict(fields, key_sealed=''))
    if not ident:
        ident = store.db.value('SELECT id FROM cert_cas WHERE name = ?', (fields['name'],))
    ident = int(ident)
    try:
        sealed = _E().seal_secret(key_pem, _bind(ident))
        store.db.run('UPDATE cert_cas SET key_sealed = ? WHERE id = ?', (sealed, ident))
    except Exception:
        store.db.run('DELETE FROM cert_cas WHERE id = ?', (ident,))
        raise
    return ident


def _cert_fields(cert_pem, chain):
    i = pki.cert_info(cert_pem)
    return {'cert_pem': i['pem'], 'chain_pem': ''.join(chain), 'subject_dn': i['subject_dn'],
            'not_before': i['not_before'], 'not_after': i['not_after'],
            'fingerprint': i['sha256'], 'path_len': i['path_len'], 'key_type': i['key_type']}


def ca_create(store, name, subject, key_type='ec-384', days=3650, parent_id=None, path_len=None,
              crl_days=7, crl_url='', aia_url='', ocsp_url='', name_constraints=None, by=''):
    """A new root (no parent_id) or an intermediate under one of acme's own -> id."""
    name = _check_name(store, name)
    pairs = _subject(subject)
    nc = nc_normalize(name_constraints)
    crl_url = _check_url(crl_url, 'the CRL address')
    aia_url = _check_url(aia_url, 'the CA certificate address (AIA)')
    ocsp_url = _check_url(ocsp_url, 'the OCSP address')
    days = int(days or 3650)
    if days < 1:
        raise PkiError('an authority needs a validity of a day at least', retry=False)
    now = _now()
    key = pki.make_key(key_type)
    parent = None
    if parent_id not in (None, '', 0, '0'):
        _split_held()                   # the parent signs it (1.0.19)
        parent = _row(store, parent_id)
        _usable(parent, now)
        path_len = _child_path_len(parent, path_len)
        # Inside the parent's constraints too.
        pnc = _j(parent.get('name_constraints'), [])
        nc = nc or []
        if pnc and not nc:
            nc = list(pnc)
    csr = _csr_for_ca(key, pairs, path_len)
    lines = _ca_lines(path_len, nc)
    if parent:
        pkey = _key(parent)
        end = min(now + days * 86400, int(float(parent['not_after'])))
        serial = _new_serial(store, parent['id'])
        cert = _openssl_ca_sign(parent['cert_pem'], pkey, csr, serial, now - BACKDATE_S, end,
                                lines + _issuer_lines(parent), [])
        chain = [parent['cert_pem']] + _chain(parent)
    else:
        cert = _openssl_ca_sign('', key, csr, pki.random_serial(), now - BACKDATE_S,
                                now + days * 86400, lines, [], selfsign=True)
        chain = []
    fields = _cert_fields(cert, chain)
    fields.update({
        'name': name, 'parent_id': int(parent['id']) if parent else None, 'serial_next': 0,
        'crl_number': 0, 'crl_pem': '', 'crl_at': None, 'crl_days': int(crl_days or 7),
        'crl_url': crl_url, 'aia_url': aia_url, 'ocsp_url': ocsp_url,
        'days_default': DEFAULT_LEAF_DAYS, 'path_len': path_len,
        'name_constraints': json.dumps(nc), 'profile': json.dumps({}), 'external': 0,
        'disabled': 0, 'note': '', 'created': now, 'created_by': str(by or '')})
    ident = _insert_ca(store, fields, key)
    if parent:
        _record(store, parent['id'], cert, by=by)
    try:
        ca_crl(store, ident)
    except PkiError as e:
        _log('the first CRL of authority %s was not made: %s' % (name, e), 'warn')
    _log('certificate authority "%s" (%d) made%s by %s' % (
        name, ident, ' under "%s"' % parent['name'] if parent else '', by or '-'))
    return ident


def _find_parent(store, cert_pem):
    info = pki.cert_info(cert_pem)
    if info['self_signed']:
        return None
    for r in store.db.rows('SELECT id, cert_pem FROM cert_cas'):
        if not r['cert_pem']:
            continue
        try:
            pi = pki.cert_info(r['cert_pem'])
        except PkiError:
            continue
        if pki._issued_by(info, pi) and pi['sha256'] != info['sha256']:
            return int(r['id'])
    return None


def ca_import(store, name, cert_pem, key_pem, chain_pems=None, password=None, by=''):
    """An authority made elsewhere, with its key -> id."""
    name = _check_name(store, name)
    certs = pki.certs_in(cert_pem) if isinstance(cert_pem, str) else [pki.cert_pem(cert_pem)]
    if not certs:
        raise PkiError('no certificate given for the authority', retry=False)
    key = pki.key_plain(key_pem, password)
    cert = next((c for c in certs if pki.key_matches(c, key)), None)
    if not cert:
        raise PkiError('the private key does not belong to the certificate', retry=False)
    info = pki.cert_info(cert)
    if not info['is_ca']:
        raise PkiError('this is not a CA certificate (basicConstraints CA:TRUE is missing)',
                       retry=False)
    if info['key_usage'] and 'keyCertSign' not in info['key_usage']:
        raise PkiError('this certificate may not sign certificates (keyCertSign is not in '
                       'its key usage)', retry=False)
    chain = pki.order_chain(cert, [c for c in certs if c != cert] + list(chain_pems or []))
    parent_id = _find_parent(store, cert)
    if parent_id and not chain:
        p = _row(store, parent_id)
        chain = [p['cert_pem']] + _chain(p)
    fields = _cert_fields(cert, chain)
    nc = ['%s;%s' % (w, x) for w in ('permitted', 'excluded')
          for x in info['name_constraints'].get(w, [])] if info['name_constraints'] else []
    fields.update({
        'name': name, 'parent_id': parent_id, 'serial_next': 0, 'crl_number': 0, 'crl_pem': '',
        'crl_at': None, 'crl_days': 7, 'crl_url': '', 'aia_url': '', 'ocsp_url': '',
        'days_default': DEFAULT_LEAF_DAYS, 'name_constraints': json.dumps(nc),
        'profile': json.dumps({'imported': True}),
        'external': 0 if (info['self_signed'] or parent_id) else 1, 'disabled': 0,
        'note': '', 'created': _now(), 'created_by': str(by or '')})
    ident = _insert_ca(store, fields, key)
    _log('certificate authority "%s" (%d) imported by %s' % (name, ident, by or '-'))
    return ident


def ca_csr(store, name, subject, key_type='ec-384', path_len=None, crl_days=7, crl_url='',
           aia_url='', ocsp_url='', name_constraints=None, by=''):
    """An intermediate to be signed by a CA elsewhere (AD CS, a corporate root):
    its key made and kept here, its request given out -> (id, csr_pem).
    ca_install_cert() takes the certificate when it comes back."""
    name = _check_name(store, name)
    pairs = _subject(subject)
    key = pki.make_key(key_type)
    csr = _csr_for_ca(key, pairs, path_len)
    nc = nc_normalize(name_constraints)
    fields = {
        'name': name, 'parent_id': None, 'subject_dn': pki.csr_info(csr)['subject_dn'],
        'key_type': pki.key_info(key)['key_type'], 'cert_pem': '', 'chain_pem': '',
        'serial_next': 0, 'crl_number': 0, 'crl_pem': '', 'crl_at': None,
        'crl_days': int(crl_days or 7), 'crl_url': _check_url(crl_url, 'the CRL address'),
        'aia_url': _check_url(aia_url, 'the AIA address'),
        'ocsp_url': _check_url(ocsp_url, 'the OCSP address'),
        'days_default': DEFAULT_LEAF_DAYS, 'path_len': path_len,
        'name_constraints': json.dumps(nc),
        'profile': json.dumps({'pending': True, 'csr_pem': csr}), 'not_before': None,
        'not_after': None, 'fingerprint': '', 'external': 1, 'disabled': 0, 'note': '',
        'created': _now(), 'created_by': str(by or '')}
    ident = _insert_ca(store, fields, key)
    _log('certificate authority "%s" (%d): a request made for a CA elsewhere, by %s'
         % (name, ident, by or '-'))
    return ident, csr


def ca_install_cert(store, ca_id, cert_pem, chain_pems=None, by=''):
    """The certificate of an authority made by ca_csr (or a renewed one for
    the same key), with the chain above it. Accepts PEM, DER or PKCS#7."""
    row = _row(store, ca_id)
    key = _key(row)
    data = cert_pem.encode('utf-8') if isinstance(cert_pem, str) else bytes(cert_pem)
    got = formats.read_any(data, 'ca.crt')
    certs = got['certs'] + [pki.cert_pem(c) for c in (chain_pems or [])]
    cert = next((c for c in certs if pki.key_matches(c, key)), None)
    if not cert:
        raise PkiError('none of these certificates belongs to the key of "%s"' % row['name'],
                       retry=False)
    info = pki.cert_info(cert)
    if not info['is_ca']:
        raise PkiError('the certificate that came back is not a CA certificate (CA:TRUE is '
                       'missing - was it signed with the SubCA template?)', retry=False)
    chain = pki.order_chain(cert, [c for c in certs if c != cert])
    parent_id = _find_parent(store, cert)
    if not chain and parent_id:
        p = _row(store, parent_id)
        chain = [p['cert_pem']] + _chain(p)
    renewal = bool(row.get('cert_pem'))
    if not chain and renewal and _chain(row):
        chain = pki.order_chain(cert, _chain(row))      # a renewal: the CA above is the same
    if renewal:
        old = pki.cert_info(row['cert_pem'])
        if old['subject_dn'] != info['subject_dn']:
            raise PkiError('this certificate is for "%s", the authority is "%s": a renewal keeps '
                           'the subject (for another one, make a new authority)'
                           % (info['subject_dn'], old['subject_dn']), retry=False)
        if old['sha256'] == info['sha256']:
            renewal = False
        else:
            _version_first(store, row, by)
    fields = _cert_fields(cert, chain)
    prof = _j(row.get('profile'), {})
    prof.pop('pending', None)
    prof.pop('csr_pem', None)
    prof.pop('renew_csr_pem', None)
    prof.pop('renew_asked', None)
    fields.update({'profile': json.dumps(prof), 'parent_id': parent_id,
                   'external': 0 if (parent_id or info['self_signed']) else 1})
    if info['name_constraints']:
        fields['name_constraints'] = json.dumps(
            ['%s;%s' % (w, x) for w in ('permitted', 'excluded')
             for x in info['name_constraints'].get(w, [])])
    sets = ', '.join('%s = ?' % k for k in fields)
    store.db.run('UPDATE cert_cas SET %s WHERE id = ?' % sets,
                 tuple(fields.values()) + (int(row['id']),))
    if renewal:
        _version_add(store, row['id'], cert, chain, 'renewed (answer installed)', by)
        _rechain_children(store, row['id'])
    try:
        ca_crl(store, row['id'])
    except PkiError as e:
        _log('the CRL of authority %s was not made: %s' % (row['name'], e), 'warn')
    _log('certificate authority "%s" (%d): its certificate installed by %s'
         % (row['name'], row['id'], by or '-'))
    return int(row['id'])


# ---------------------------------------------------------------------------
# Looking
# ---------------------------------------------------------------------------
_PUBLIC = ('id', 'name', 'parent_id', 'subject_dn', 'key_type', 'cert_pem', 'chain_pem',
           'serial_next', 'crl_number', 'crl_pem', 'crl_at', 'crl_days', 'crl_url', 'aia_url',
           'ocsp_url', 'days_default', 'path_len', 'not_before', 'not_after', 'fingerprint',
           'external', 'disabled', 'note', 'created', 'created_by')


def ca_get(store, ca_id):
    """One authority, its key left out (key_set says whether there is one)."""
    row = _row(store, ca_id)
    out = {k: row.get(k) for k in _PUBLIC}
    out['key_set'] = bool(row.get('key_sealed'))
    out['name_constraints'] = _j(row.get('name_constraints'), [])
    prof = _j(row.get('profile'), {})
    out['pending'] = _pending(row)
    out['csr_pem'] = prof.get('csr_pem', '') if out['pending'] else ''
    out['profile'] = {k: v for k, v in prof.items() if k not in ('csr_pem', 'renew_csr_pem')}
    out['renew_csr_pem'] = prof.get('renew_csr_pem', '')
    out['eku'] = list(prof.get('eku') or [])
    out['versions'] = int(store.db.value('SELECT COUNT(*) FROM cert_ca_versions WHERE ca_id = ?',
                                         (int(row['id']),), 0) or 0)
    out['chain'] = _chain(row)
    out['children'] = [int(r['id']) for r in store.db.rows(
        'SELECT id FROM cert_cas WHERE parent_id = ? ORDER BY id', (int(row['id']),))]
    out['issued'] = int(store.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ?',
                                       (int(row['id']),), 0) or 0)
    out['revoked'] = int(store.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ? '
                                        'AND revoked IS NOT NULL', (int(row['id']),), 0) or 0)
    if not out['pending']:
        i = pki.cert_info(row['cert_pem'])
        out['info'] = {k: v for k, v in i.items() if not isinstance(v, bytes) and k != 'pem'}
        out['root'] = bool(i['self_signed'])
    else:
        out['info'], out['root'] = None, False
    return out


def ca_list(store):
    """Every authority, as a tree: parents before their children, each with
    depth, parent_name, children [ids], issued, revoked, valid (now), pending, root."""
    rows = [dict(r) for r in store.db.rows(
        'SELECT id, name, parent_id, subject_dn, key_type, not_before, not_after, fingerprint, '
        'external, disabled, crl_at, crl_url, path_len, profile, cert_pem, days_default '
        'FROM cert_cas ORDER BY id')]
    counts = {}
    for r in store.db.rows('SELECT ca_id, COUNT(*) AS n, SUM(CASE WHEN revoked IS NOT NULL '
                           'THEN 1 ELSE 0 END) AS r FROM cert_ca_issued GROUP BY ca_id'):
        counts[int(r['ca_id'])] = (int(r['n'] or 0), int(r['r'] or 0))
    byid = {int(r['id']): r for r in rows}
    now = _now()
    for r in rows:
        r['id'] = int(r['id'])
        pid = r.get('parent_id')
        r['parent_id'] = int(pid) if pid not in (None, '') and int(pid) in byid else None
        r['children'] = []
        r['issued'], r['revoked'] = counts.get(r['id'], (0, 0))
        r['pending'] = not r.get('cert_pem')
        r['root'] = False
        if not r['pending']:
            try:
                r['root'] = pki.cert_info(r['cert_pem'])['self_signed']
            except PkiError:
                pass
        r['valid'] = (not r['pending'] and not r.get('disabled') and
                      bool(r.get('not_after')) and float(r['not_after']) > now)
        r.pop('cert_pem', None)
        r.pop('profile', None)
    for r in rows:
        if r['parent_id']:
            byid[r['parent_id']]['children'].append(r['id'])
    out = []

    def walk(r, depth, path):
        if r['id'] in path:
            return
        r['depth'] = depth
        r['parent_name'] = byid[r['parent_id']]['name'] if r['parent_id'] else ''
        out.append(r)
        for c in r['children']:
            walk(byid[c], depth + 1, path | {r['id']})
    for r in rows:
        if not r['parent_id']:
            walk(r, 0, frozenset())
    for r in rows:              # a loop of parents, should one be made by hand
        if r not in out:
            r['depth'], r['parent_name'] = 0, ''
            out.append(r)
    return out


def ca_issued(store, ca_id, limit=500, offset=0):
    """What one authority signed, newest first."""
    row = _row(store, ca_id)
    out = []
    for r in store.db.rows('SELECT * FROM cert_ca_issued WHERE ca_id = ? ORDER BY created DESC, '
                           'id DESC LIMIT %d OFFSET %d' % (int(limit), int(offset)),
                           (int(row['id']),)):
        r = dict(r)
        r['names'] = _j(r.get('names'), [])
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def _as_list(v):
    if v in (None, ''):
        return []
    if isinstance(v, str):
        return [x for x in re.split(r'[\s,]+', v) if x]
    return [str(x) for x in v if str(x).strip()]


def ca_sign(store, ca_id, csr_pem, days, profile=None, cert_id=None, by=''):
    """A certificate for a request -> (cert_pem, chain_pems nearest first, the
    root included).

    profile: eku [names/OIDs] (default serverAuth, clientAuth), key_usage
    [names], must_staple, subject {..} (in place of the request's), names [..]
    (in place of the request's), is_ca + path_len (an intermediate), name_constraints,
    ski + ca_key_usage (an intermediate's renewal: as its certificate had them),
    no_names (no subjectAltName from the request's CN).
    Without an eku the authority's own default (its profile's eku, ca_edit) is taken."""
    _split_held()
    row = _row(store, ca_id)
    now = _now()
    _usable(row, now)
    prof = dict(profile or {})
    if not isinstance(csr_pem, str):
        csr_pem = pki.der_to_pem(bytes(csr_pem), 'CERTIFICATE REQUEST') \
            if b'-----BEGIN' not in csr_pem else csr_pem.decode('ascii')
    ci = pki.csr_info(csr_pem)
    if not pki.csr_verify(csr_pem):
        raise PkiError('the request is not signed by its own key', retry=False)
    names = _as_list(prof.get('names')) if prof.get('names') else list(ci['names'])
    if prof.get('no_names'):
        names = []
    if not ci['san'] and ci['cn'] and not prof.get('names') and names == [ci['cn']]:
        try:
            pki.classify_name(ci['cn'])
        except PkiError:
            names = []          # a CN that is no name (a person, a device)
    subject = None
    if prof.get('subject'):
        subject = pki.subject_pairs(prof['subject'])
    elif not ci['subject_list']:
        subject = pki._subject_for(names, None)
    is_ca = bool(prof.get('is_ca'))
    san, typed = pki.san_lines(names)
    nc = _j(row.get('name_constraints'), [])
    for t in typed:
        if nc and not _nc_allows(nc, t):
            raise PkiError('"%s" is outside what the authority "%s" may sign for (its name '
                           'constraints)' % (t[1], row['name']), retry=False)
    if is_ca:
        pl = _child_path_len(row, prof.get('path_len'))
        lines = _ca_lines(pl, nc_normalize(prof.get('name_constraints')) or nc,
                          ski=prof.get('ski'), key_usage=prof.get('ca_key_usage'))
    else:
        if not san and not (subject or ci['subject_list']):
            raise PkiError('a certificate needs a name or a subject', retry=False)
        kt = ci['key_type']
        ku = pki._ku_value(prof.get('key_usage')) or pki.default_key_usage(kt)
        own = _j(row.get('profile'), {}).get('eku')
        eku = pki._eku_value(prof.get('eku') if prof.get('eku') not in (None, '', [])
                             else (own or ['serverAuth', 'clientAuth']))
        lines = ['basicConstraints = critical, CA:FALSE',
                 'keyUsage = critical, ' + ', '.join(ku),
                 'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always']
        if eku:
            lines.append('extendedKeyUsage = ' + ', '.join(eku))
        if prof.get('must_staple'):
            lines.append('tlsfeature = status_request')
    if san:
        empty_subject = not (subject or ci['subject_list'])
        lines.append('subjectAltName = %s@san' % ('critical, ' if empty_subject else ''))
    lines += _issuer_lines(row)
    days = int(days or row.get('days_default') or DEFAULT_LEAF_DAYS)
    if days < 1:
        raise PkiError('a validity of a day at least', retry=False)
    end = min(now + days * 86400, int(float(row['not_after'])))
    key = _key(row)
    serial = _new_serial(store, row['id'])
    cert = _openssl_ca_sign(row['cert_pem'], key, csr_pem, serial, now - BACKDATE_S, end,
                            lines, san, subject_pairs=subject)
    _record(store, row['id'], cert, cert_id=cert_id, by=by)
    if end < now + days * 86400:
        _log('a certificate of "%s" ends with the authority, before the %d days asked'
             % (row['name'], days), 'warn')
    _log('certificate authority "%s" signed %s (%s) for %s' % (
        row['name'], pki.cert_info(cert)['serial'], ', '.join(names[:5]) or ci['subject_dn'],
        by or '-'))
    return cert, [row['cert_pem']] + _chain(row)


# ---------------------------------------------------------------------------
# Revoking, CRLs
# ---------------------------------------------------------------------------
def norm_reason(reason):
    r = str(reason or '').strip()
    hit = _REASON_ALIAS.get(r.lower()) or _REASON_ALIAS.get(r.lower().replace(' ', '_'))
    if not hit:
        raise PkiError('an unknown reason: %s (one of %s)' % (reason, ', '.join(REASONS)),
                       retry=False)
    return hit


def _issued_row(store, ca_id, serial):
    s = pki.norm_serial(serial)
    r = store.db.row('SELECT * FROM cert_ca_issued WHERE ca_id = ? AND serial = ?',
                     (int(ca_id), s))
    if not r:
        raise PkiError('the authority did not sign a certificate with the serial %s' % s,
                       retry=False)
    return dict(r)


def ca_revoke(store, ca_id, serial, reason='unspecified', by=''):
    """Revoke what an authority signed (by serial), and make its CRL anew."""
    _split_held()
    row = _row(store, ca_id)
    reason = norm_reason(reason)
    r = _issued_row(store, row['id'], serial)
    if r.get('revoked') is not None and r.get('reason') != 'certificateHold':
        return ca_crl(store, row['id'])
    store.db.run('UPDATE cert_ca_issued SET revoked = ?, reason = ? WHERE id = ?',
                 (_now() if r.get('revoked') is None else r['revoked'], reason, r['id']))
    _log('certificate authority "%s": %s revoked (%s) by %s' % (row['name'], r['serial'],
                                                                reason, by or '-'), 'warn')
    return ca_crl(store, row['id'])


def ca_unrevoke(store, ca_id, serial, by=''):
    """Take back a revocation on hold (certificateHold) - the only kind that may be."""
    _split_held()                       # a new CRL signed, as a revocation (1.0.19)
    row = _row(store, ca_id)
    r = _issued_row(store, row['id'], serial)
    if r.get('revoked') is None:
        return ca_crl(store, row['id'])
    if r.get('reason') != 'certificateHold':
        raise PkiError('only a certificate on hold can be taken back (this one: %s)'
                       % r.get('reason'), retry=False)
    store.db.run("UPDATE cert_ca_issued SET revoked = NULL, reason = '' WHERE id = ?", (r['id'],))
    _log('certificate authority "%s": the hold on %s released by %s' % (row['name'],
                                                                        r['serial'], by or '-'))
    return ca_crl(store, row['id'])


def _dn_index(dn):
    # The subject column of index.txt: only shown, never parsed for a CRL.
    return '/' + re.sub(r'[\t\n\r]', ' ', str(dn or 'unknown'))


def ca_crl(store, ca_id):
    """A new CRL of the authority (openssl ca -gencrl, the index made from
    cert_ca_issued), its number one higher; kept in cert_cas -> crl_pem."""
    # Never on both halves of a split cluster (1.0.44), from wherever it is asked - the
    # public /api/pki/crl and an export signed a new one without asking: two CRLs of the
    # same number. The one there is served meanwhile.
    _split_held()
    row = _row(store, ca_id)
    if _pending(row):
        raise PkiError('the authority "%s" has no certificate yet' % row['name'], retry=False)
    key = _key(row)
    kt = pki.key_info(key)['key_type']
    number = int(row.get('crl_number') or 0) + 1
    lines = []
    for r in store.db.rows('SELECT serial, subject_dn, not_after, revoked, reason FROM '
                           'cert_ca_issued WHERE ca_id = ? AND revoked IS NOT NULL ORDER BY id',
                           (int(row['id']),)):
        reason = r.get('reason') or 'unspecified'
        if reason not in REASONS:
            reason = 'unspecified'
        lines.append('R\t%s\t%s,%s\t%s\tunknown\t%s' % (
            _index_time(float(r['not_after'] or 0)), _index_time(float(r['revoked'])), reason,
            pki.norm_serial(r['serial']), _dn_index(r.get('subject_dn'))))
    with pki.workdir() as d:
        pki.wfile(d, 'index.txt', ''.join(ln + '\n' for ln in lines))
        pki.wfile(d, 'index.txt.attr', 'unique_subject = no\n')
        pki.wfile(d, 'serial', '01\n')
        h = '%X' % number
        pki.wfile(d, 'crlnumber', ('0' * (len(h) % 2)) + h + '\n')
        cfg = _ca_config(d, pki.md_name(kt), ['basicConstraints = CA:FALSE'], [],
                         crl_days=row.get('crl_days') or 7)
        pki.openssl(['ca', '-gencrl', '-batch', '-config', cfg,
                     '-keyfile', pki.wfile(d, 'ca.key', key),
                     '-cert', pki.wfile(d, 'ca.pem', row['cert_pem']),
                     '-out', os.path.join(d, 'crl.pem')])
        crl = pki.rfile(d, 'crl.pem').decode('ascii')
    crl = [p for lab, p in pki.split_pem(crl) if lab == 'X509 CRL'][0]
    store.db.run('UPDATE cert_cas SET crl_pem = ?, crl_at = ?, crl_number = ? WHERE id = ?',
                 (crl, _now(), number, int(row['id'])))
    return crl


def crl_due(store, ca_id, margin_s=None):
    """Whether the authority's CRL should be made again: none yet, or past
    half its life (or `margin_s` before its next update)."""
    row = _row(store, ca_id)
    if _pending(row) or not row.get('crl_pem'):
        return not _pending(row)
    try:
        info = pki.crl_info(row['crl_pem'])
    except PkiError:
        return True
    nu = info.get('next_update') or 0
    if margin_s is None:
        margin_s = (nu - info['this_update']) / 2.0
    return _now() >= nu - margin_s


# ---------------------------------------------------------------------------
# Deleting, exporting
# ---------------------------------------------------------------------------
def ca_delete(store, ca_id):
    """An authority away, and its list of what it signed. Not while
    authorities are under it."""
    row = _row(store, ca_id)
    kids = store.db.rows('SELECT name FROM cert_cas WHERE parent_id = ?', (int(row['id']),))
    if kids:
        raise PkiError('the authority "%s" has authorities under it (%s): delete those first'
                       % (row['name'], ', '.join(k['name'] for k in kids)), retry=False)
    store.db.run('DELETE FROM cert_ca_issued WHERE ca_id = ?', (int(row['id']),))
    store.db.run('DELETE FROM cert_ca_versions WHERE ca_id = ?', (int(row['id']),))
    store.db.run('DELETE FROM cert_cas WHERE id = ?', (int(row['id']),))
    _log('certificate authority "%s" (%d) deleted' % (row['name'], row['id']), 'warn')
    return True


def _safe(name):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('_.') or 'ca'


def ca_export(store, ca_id, what, password=None):
    """{filename, mime, data (bytes)} of: cert (PEM), cert-der, chain (the
    certificate and every one above it, PEM), crl (PEM), crl-der, bundle (a
    ZIP: certificate, chain, CRL), key (PKCS#8, encrypted with `password`
    when one is given), p12 (certificate, chain and key; `password`)."""
    row = _row(store, ca_id)
    base = _safe(row['name'])
    what = str(what or 'cert').lower()
    if what == 'csr':
        prof = _j(row.get('profile'), {})
        csr = prof.get('csr_pem') or prof.get('renew_csr_pem')
        if not csr:
            raise PkiError('there is no request waiting for this authority', retry=False)
        return {'filename': base + '.csr', 'mime': 'application/pkcs10', 'data': csr.encode()}
    if _pending(row):
        raise PkiError('the authority "%s" has no certificate yet (export its csr)'
                       % row['name'], retry=False)
    cert = row['cert_pem']
    full = cert + ''.join(_chain(row))
    if what in ('cert', 'cert-pem', 'crt'):
        return {'filename': base + '.crt', 'mime': 'application/x-pem-file',
                'data': cert.encode('ascii')}
    if what in ('cert-der', 'der', 'cer'):
        return {'filename': base + '.cer', 'mime': 'application/pkix-cert',
                'data': pki.pem_to_der(cert)}
    if what in ('chain', 'chain-pem', 'fullchain'):
        return {'filename': base + '-chain.pem', 'mime': 'application/x-pem-file',
                'data': full.encode('ascii')}
    if what in ('crl', 'crl-pem', 'crl-der'):
        crl = row.get('crl_pem') or ''
        if not crl or crl_due(store, row['id']):
            try:
                crl = ca_crl(store, row['id'])
            except PkiError:
                if not crl:                 # split: the one there, while there is one
                    raise
        if what == 'crl-der':
            return {'filename': base + '.crl', 'mime': 'application/pkix-crl',
                    'data': pki.pem_to_der(crl)}
        return {'filename': base + '.crl.pem', 'mime': 'application/x-pem-file',
                'data': crl.encode('ascii')}
    if what == 'p7b':
        from acmelib.certs.bundle import p7b_der
        return {'filename': base + '.p7b', 'mime': 'application/x-pkcs7-certificates',
                'data': p7b_der(pki.certs_in(full))}
    if what == 'bundle':
        crl = row.get('crl_pem') or ''
        if not crl or crl_due(store, row['id']):
            crl = ca_crl(store, row['id'])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr(base + '.crt', cert)
            z.writestr(base + '-chain.pem', full)
            z.writestr(base + '.crl', pki.pem_to_der(crl))
            z.writestr(base + '.crl.pem', crl)
        return {'filename': base + '.zip', 'mime': 'application/zip', 'data': buf.getvalue()}
    if what == 'key':
        key = _key(row)
        data = pki.key_encrypt(key, password) if password else key
        return {'filename': base + '.key', 'mime': 'application/x-pem-file',
                'data': data.encode('ascii')}
    if what in ('p12', 'pfx'):
        if not password:
            raise PkiError('a PKCS#12 of an authority needs a password', retry=False)
        from acmelib.certs.bundle import pkcs12
        return {'filename': base + '.p12', 'mime': 'application/x-pkcs12',
                'data': pkcs12(_key(row), cert, _chain(row), password, row['name'])}
    raise PkiError('an unknown export: %s (cert, cert-der, chain, crl, crl-der, p7b, bundle, '
                   'key, p12, csr)' % what, retry=False)


# ---------------------------------------------------------------------------
# Editing: what is not inside its certificate
# ---------------------------------------------------------------------------
EDITABLE = ('name', 'days_default', 'crl_days', 'crl_url', 'aia_url', 'ocsp_url', 'note',
            'disabled', 'eku')


def ca_edit(store, ca_id, changes, by='', remake_crl=True):
    """Change what an authority keeps beside its certificate -> (row as it is
    now, {field: (old, new)} of what changed).

    name (a safe name, unique - what refers to it is the caller's: api_cas),
    days_default (what it issues for unless asked), crl_days (how long each CRL
    is valid; the CRL is made anew at once, so the half-life refresh follows),
    crl_url / aia_url / ocsp_url (put into what it signs FROM NOW ON), note,
    disabled (it signs nothing; its CRL is still made and published), eku (its
    default extended key usage, where a request says none). Its certificate is
    not touched: for its validity, path length or name constraints, ca_renew."""
    row = _row(store, ca_id)
    unknown = [k for k in changes if k not in EDITABLE]
    if unknown:
        raise PkiError('an authority has no setting %s (it has %s)' % (
            ', '.join(sorted(unknown)), ', '.join(EDITABLE)), retry=False)
    sets, done = {}, {}
    prof = _j(row.get('profile'), {})
    for k, v in changes.items():
        if k == 'name':
            from acmelib.certs import store as S
            v = str(v or '').strip()
            if not S.NAME_RE.match(v):
                raise PkiError('the name of an authority: letters, digits, spaces and . _ @ + - '
                               '(120 at most), starting with a letter or a digit', retry=False)
            v = _check_name(store, v, but=row['id'])
        elif k in ('days_default', 'crl_days'):
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise PkiError('%s is a number of days' % k, retry=False)
            most = 36500 if k == 'days_default' else 365
            if not 1 <= v <= most:
                raise PkiError('%s: 1 to %d days' % (k, most), retry=False)
        elif k in ('crl_url', 'aia_url', 'ocsp_url'):
            v = _check_url(v, {'crl_url': 'the CRL address', 'aia_url': 'the CA certificate '
                               'address (AIA)', 'ocsp_url': 'the OCSP address'}[k])
        elif k == 'note':
            v = str(v or '')
            if len(v) > 2000:
                raise PkiError('a note: 2000 characters at most', retry=False)
        elif k == 'disabled':
            v = 1 if v not in (None, '', 0, '0', False, 'false', 'no', 'off') else 0
        elif k == 'eku':
            v = pki._eku_value(_as_list(v))
            if v != list(prof.get('eku') or []):
                done['eku'] = (list(prof.get('eku') or []), v)
                if v:
                    prof['eku'] = v
                else:
                    prof.pop('eku', None)
                sets['profile'] = json.dumps(prof)
            continue
        old = row.get(k)
        if k in ('days_default', 'crl_days', 'disabled'):
            old = int(old or 0)
        elif old is None:
            old = ''
        if old != v:
            sets[k] = v
            done[k] = (old, v)
    if sets:
        store.db.run('UPDATE cert_cas SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in sets),
                     tuple(sets.values()) + (int(row['id']),))
        _log('certificate authority "%s" (%d) edited by %s: %s' % (
            row['name'], row['id'], by or '-', ', '.join(sorted(done))))
    if remake_crl and 'crl_days' in done and not _pending(row) and row.get('key_sealed'):
        ca_crl(store, row['id'])
    return _row(store, row['id']), done


# ---------------------------------------------------------------------------
# Versions: every certificate it has had
# ---------------------------------------------------------------------------
def _version_row(cert_pem, chain):
    i = pki.cert_info(cert_pem)
    nc = ['%s;%s' % (w, x) for w in ('permitted', 'excluded')
          for x in (i['name_constraints'] or {}).get(w, [])] if i['name_constraints'] else []
    return {'cert_pem': i['pem'], 'chain_pem': ''.join(chain or []), 'serial': i['serial'],
            'fingerprint': i['sha256'], 'not_before': i['not_before'],
            'not_after': i['not_after'], 'path_len': i['path_len'],
            'name_constraints': json.dumps(nc), 'issuer_dn': i['issuer_dn']}


def _version_add(store, ca_id, cert_pem, chain, why, by=''):
    top = store.db.value('SELECT MAX(version) FROM cert_ca_versions WHERE ca_id = ?',
                         (int(ca_id),), 0) or 0
    fields = _version_row(cert_pem, chain)
    fields.update({'ca_id': int(ca_id), 'version': int(top) + 1, 'created': _now(),
                   'why': str(why or '')[:120], 'by_who': str(by or '')})
    store.db.insert('cert_ca_versions', fields)
    return int(top) + 1


def _version_first(store, row, by=''):
    """Before the first renewal: the certificate it has now, as version 1."""
    if not row.get('cert_pem'):
        return
    have = store.db.value('SELECT COUNT(*) FROM cert_ca_versions WHERE ca_id = ? AND '
                          'fingerprint = ?', (int(row['id']), row.get('fingerprint') or
                                              pki.cert_info(row['cert_pem'])['sha256']), 0)
    if not have:
        _version_add(store, row['id'], row['cert_pem'], _chain(row), 'made', row.get(
            'created_by') or by)


def ca_versions(store, ca_id):
    """Every certificate the authority has had, newest first: version, serial,
    fingerprint, not_before, not_after, path_len, name_constraints, issuer_dn,
    created, why, by_who, cert_pem, current (the one it signs with now)."""
    row = _row(store, ca_id)
    out = []
    for r in store.db.rows('SELECT * FROM cert_ca_versions WHERE ca_id = ? ORDER BY version DESC',
                           (int(row['id']),)):
        r = dict(r)
        r['name_constraints'] = _j(r.get('name_constraints'), [])
        r['current'] = r.get('fingerprint') == row.get('fingerprint')
        out.append(r)
    if row.get('cert_pem') and not any(r['current'] for r in out):
        r = _version_row(row['cert_pem'], _chain(row))
        r.update({'version': (out[0]['version'] + 1) if out else 1, 'created': row.get('created'),
                  'why': 'made' if not out else 'installed', 'by_who': row.get('created_by') or '',
                  'current': True, 'id': None, 'ca_id': int(row['id'])})
        r['name_constraints'] = _j(r['name_constraints'], [])
        out.insert(0, r)
    now = _now()
    for r in out:
        r['valid'] = bool(r.get('not_after')) and float(r['not_after']) > now and \
            float(r.get('not_before') or 0) <= now
    return out


def _rechain_children(store, ca_id, seen=None):
    """The authorities under it (and under those) given its certificate as it is
    now in their chains. Their own certificates do not change: the parent's key
    and subject are the same, so they verify against the new one alike.
    Returns the names whose chain was made anew."""
    seen = set(seen or ())
    if int(ca_id) in seen:
        return []
    seen.add(int(ca_id))
    parent = _row(store, ca_id)
    if _pending(parent):
        return []
    chain = [parent['cert_pem']] + _chain(parent)
    done = []
    for r in store.db.rows('SELECT id, name, chain_pem, cert_pem FROM cert_cas WHERE parent_id = ? '
                           'ORDER BY id', (int(parent['id']),)):
        if not r.get('cert_pem') or int(r['id']) in seen:
            continue
        new = ''.join(chain)
        if (r.get('chain_pem') or '') != new:
            store.db.run('UPDATE cert_cas SET chain_pem = ? WHERE id = ?', (new, int(r['id'])))
            done.append(r['name'])
        done += _rechain_children(store, r['id'], seen)
    return done


# ---------------------------------------------------------------------------
# Renewing its certificate with the same key
# ---------------------------------------------------------------------------
KEEP = object()


def _request_same_subject(cert_pem, key_pem, path_len=None):
    """A request with the authority's own key and EXACTLY the subject of its
    certificate (openssl x509 -x509toreq copies the name as it is encoded)."""
    kt = pki.key_info(key_pem)['key_type']
    try:
        with pki.workdir() as d:
            out = pki.openssl(['x509', '-x509toreq', '-in', pki.wfile(d, 'c.pem', cert_pem),
                               '-signkey', pki.wfile(d, 'k.key', key_pem)] + pki.md_args(kt))
        got = [p for lab, p in pki.split_pem(out) if 'REQUEST' in lab]
        if got and pki.csr_info(got[0])['subject_dn'] == pki.cert_info(cert_pem)['subject_dn']:
            return got[0]
    except PkiError:
        pass
    return _csr_for_ca(key_pem, pki.subject_pairs(pki.cert_info(cert_pem)['subject_list']),
                       path_len)


def ca_renew(store, ca_id, days=None, path_len=KEEP, name_constraints=None, by=''):
    """The authority's certificate made again with the SAME key and the same
    subject (so the same key identifier): a new serial and validity, and the
    path length / name constraints asked (else as they were). What it signed
    before stays valid - it verifies against the new certificate alike.

    A root signs itself again; an intermediate under one of acme's authorities
    is signed by it (ca_sign, as an authority); one under a CA elsewhere gets a
    request with its key (kept as renew_csr_pem, exported as 'csr') and the
    answer comes through ca_install_cert. The certificate it had is kept
    (cert_ca_versions), the chains of the authorities under it are made anew,
    and so is its CRL.

    path_len: KEEP (as it is), None or -1 (no limit), a number. name_constraints:
    None (as they are), [] (none), a list (nc_normalize).

    -> {id, pending, csr_pem, version, cert_pem, not_before, not_after, capped,
        children, how ('self' | 'parent' | 'request')}"""
    _split_held()                       # signed, and its CRL made (1.0.19)
    row = _row(store, ca_id)
    if _pending(row):
        raise PkiError('the authority "%s" waits for its first certificate - install that '
                       'first' % row['name'], retry=False)
    key = _key(row)
    info = pki.cert_info(row['cert_pem'])
    now = _now()
    if days in (None, '', 0, '0'):
        days = max(1, int(round((float(info['not_after']) - float(info['not_before'])
                                 - BACKDATE_S) / 86400.0)))
    days = int(days)
    if not 1 <= days <= 36500:
        raise PkiError('a validity of 1 to 36500 days', retry=False)
    if path_len is KEEP:
        pl = info['path_len']
    elif path_len in (None, '', -1, '-1'):
        pl = None
    else:
        try:
            pl = int(path_len)
        except (TypeError, ValueError):
            raise PkiError('the path length is a number (empty: no limit)', retry=False)
        if not 0 <= pl <= 32:
            raise PkiError('the path length is 0 to 32 (empty: no limit)', retry=False)
    if name_constraints is None:
        nc = _j(row.get('name_constraints'), [])
    else:
        nc = nc_normalize(name_constraints)
    ku = [k for k in (info['key_usage'] or []) if k in pki.KEY_USAGE_BITS] or None
    self_signed = bool(info['self_signed'])
    parent = None
    if not self_signed and row.get('parent_id'):
        try:
            parent = _row(store, row['parent_id'])
        except PkiError:
            parent = None
        if parent is not None and (_pending(parent) or not parent.get('key_sealed')):
            parent = None
    csr = _request_same_subject(row['cert_pem'], key, pl)
    out = {'id': int(row['id']), 'pending': False, 'csr_pem': '', 'capped': False,
           'children': []}
    if self_signed:
        end = now + days * 86400
        lines = _ca_lines(pl, nc, ski=info['ski'], key_usage=ku)
        cert = _openssl_ca_sign('', key, csr, pki.random_serial(), now - BACKDATE_S, end, lines,
                                [], selfsign=True)
        chain = []
        out['how'] = 'self'
    elif parent is not None:
        _usable(parent, now)
        pl = _child_path_len(parent, pl)
        pnc = _j(parent.get('name_constraints'), [])
        if pnc and not nc:
            nc = list(pnc)
        prof = {'is_ca': True, 'path_len': pl, 'name_constraints': nc, 'ski': info['ski'],
                'ca_key_usage': ku, 'no_names': True}
        cert, chain = ca_sign(store, parent['id'], csr, days, prof,
                              by=by or 'renewal of %s' % row['name'])
        end = now + days * 86400
        out['capped'] = pki.cert_info(cert)['not_after'] < end - 60
        out['how'] = 'parent'
    else:
        # For a CA elsewhere: CA:TRUE asked for in it (AD CS's SubCA wants that).
        csr = _csr_for_ca(key, pki.subject_pairs(info['subject_list']), pl)
        prof = _j(row.get('profile'), {})
        prof['renew_csr_pem'] = csr
        prof['renew_asked'] = {'days': days, 'path_len': pl, 'name_constraints': nc,
                               'at': now, 'by': str(by or '')}
        store.db.run('UPDATE cert_cas SET profile = ? WHERE id = ?', (json.dumps(prof),
                                                                       int(row['id'])))
        _log('certificate authority "%s" (%d): a request for its renewal with the same key, for '
             'the CA above it, by %s' % (row['name'], row['id'], by or '-'))
        out.update({'pending': True, 'csr_pem': csr, 'how': 'request'})
        return out
    # The new certificate in place, the old one kept.
    new = pki.cert_info(cert)
    if new['pub_sha256'] != info['pub_sha256'] or new['subject_dn'] != info['subject_dn']:
        raise PkiError('the renewed certificate is not for the same key and subject - nothing '
                       'was changed', retry=False)
    _version_first(store, row, by)
    fields = _cert_fields(cert, chain)
    fields['name_constraints'] = json.dumps(nc)
    prof = _j(row.get('profile'), {})
    prof.pop('renew_csr_pem', None)
    prof.pop('renew_asked', None)
    fields['profile'] = json.dumps(prof)
    store.db.run('UPDATE cert_cas SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in fields),
                 tuple(fields.values()) + (int(row['id']),))
    out['version'] = _version_add(store, row['id'], cert, chain, 'renewed', by)
    out['children'] = _rechain_children(store, row['id'])
    try:
        ca_crl(store, row['id'])
    except PkiError as e:
        _log('the CRL of authority %s was not made after its renewal: %s' % (row['name'], e),
             'warn')
    out.update({'cert_pem': new['pem'], 'not_before': new['not_before'],
                'not_after': new['not_after'], 'serial': new['serial'],
                'fingerprint': new['sha256'], 'path_len': new['path_len']})
    _log('certificate authority "%s" (%d) renewed with the same key by %s: until %s' % (
        row['name'], row['id'], by or '-', time.strftime('%Y-%m-%d', time.gmtime(
            new['not_after']))))
    return out
