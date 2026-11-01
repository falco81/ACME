# -*- coding: utf-8 -*-
"""
The certificate manager's tables, read and written: the certificates and
their versions, the issuers, challenges and targets with their settings
(secrets sealed; shown as dots - and their last two characters to a full
administrator - never in clear), the deployments.

Sealing binds every secret to its place:
    a certificate's key        'certs:<id>:key_sealed:<version>'  (the same value
                               in certs and in cert_versions, so it is copied as it is)
    a module's secret setting  '<table>:<id>:<field>'   e.g. 'cert_targets:4:password'
    a deployment's secret      'cert_deploys:<id>:<field>'
    a key waiting for a CSR's answer  'certs:<id>:csr_pending'
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import re
import threading
import time

from acmelib import engine as E
from acmelib.plugins import base

TABLE_OF = {'issuer': 'cert_issuers', 'challenge': 'cert_challenges', 'target': 'cert_targets'}
FAMILY_OF = {v: k for k, v in TABLE_OF.items()}
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,119}\Z')
DNS_RE = re.compile(r'^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*'
                    r'[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.?\Z')
KEY_FORMATS = ('key-pem', 'key-rsa', 'key-der', 'combined-pem', 'pfx', 'p12', 'p12-legacy',
               'jks')
_REG_LOCK = threading.Lock()
_REG_DONE = [False]


def now():
    return time.time()


def jload(text, default=None):
    if text in (None, ''):
        return default
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def jdump(value):
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def epoch(v):
    """A time as epoch seconds, from whatever the PKI library gave."""
    if v in (None, ''):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=datetime.timezone.utc)
        return v.timestamp()
    s = str(v).strip()
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%b %d %H:%M:%S %Y GMT',
                '%Y%m%d%H%M%SZ', '%Y-%m-%dT%H:%M:%S%z'):
        try:
            d = datetime.datetime.strptime(s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=datetime.timezone.utc)
            return d.timestamp()
        except ValueError:
            continue
    try:
        return float(s)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# The modules
# ---------------------------------------------------------------------------
def registry(again=False):
    """The registry of modules, read once (and again when asked)."""
    with _REG_LOCK:
        if again or not _REG_DONE[0]:
            base.REGISTRY.reload()
            _REG_DONE[0] = True
    return base.REGISTRY


def plugin_class(family, kind):
    """The module's class, or None when there is no such module."""
    try:
        return registry().get(family, kind)
    except base.PluginError:
        return None


def secret_fields(cls, attr='fields'):
    """The keys kept sealed: type 'secret', and a 'pem' (or any) field marked
    secret=True - a private key pasted in (the SSH key of a validation)."""
    if cls is None:
        return set()
    return {f['key'] for f in (getattr(cls, attr, None) or [])
            if f.get('type') == 'secret' or f.get('secret')}


SECRET_DOTS = '\u2022' * 8


def secret_view(plain, full=False):
    """A kept secret as it is shown (the engine's rule, secret_shown): to a full
    administrator eight dots and its last two characters, to anybody else eight
    dots, "" when none is set. A PEM key or other text of several lines: the
    last two characters of its body - the BEGIN/END lines, whitespace, '-' and
    '=' left out (those end every key alike and tell nothing)."""
    if plain in (None, ''):
        return ''
    text = str(plain)
    if not full:
        return SECRET_DOTS
    if '-----' in text or '\n' in text:
        text = re.sub(r'-----[A-Z0-9 ]+-----', '', text)
        text = re.sub(r'[\s=-]', '', text)
        if not text:
            return SECRET_DOTS
    return E.secret_shown(text) or SECRET_DOTS


def bool_fields(cls, attr='fields'):
    if cls is None:
        return set()
    return {f['key'] for f in (getattr(cls, attr, None) or []) if f.get('type') == 'bool'}


def config_open(cfg, place, secrets):
    """A module's settings with its secrets opened; `place` is '<table>:<id>'."""
    out = dict(cfg or {})
    for k, v in list(out.items()):
        if isinstance(v, str) and (v.startswith('sealed:') or k in secrets):
            out[k] = E.unseal_secret(v, '%s:%s' % (place, k)) or ''
    return out


def config_seal(new, old, place, secrets):
    """The settings to keep: each secret sealed for its place; a secret given
    as "" (or not at all) keeps the one that is set."""
    out = {}
    old = dict(old or {})
    new = dict(new or {})
    for k, v in new.items():
        if not re.match(r'^[A-Za-z0-9_.-]{1,64}\Z', str(k)):
            raise ValueError('a setting called %r is not one a module has' % k)
        if k in secrets:
            # "" or what the page was shown (dots, its last two): the one kept.
            if v in (None, '') or E.is_masked(v):
                if old.get(k):
                    out[k] = _sealed_kept(old[k], '%s:%s' % (place, k))
                continue
            out[k] = E.seal_secret(str(v), '%s:%s' % (place, k))
        else:
            out[k] = v
    for k in secrets:
        if k not in new and old.get(k):
            out[k] = _sealed_kept(old[k], '%s:%s' % (place, k))
    return out


def _sealed_kept(v, place):
    """A secret kept: sealed already, or - kept in clear before its field was
    marked secret (the SSH key of a validation) - sealed now."""
    if isinstance(v, str) and v and not v.startswith('sealed:'):
        return E.seal_secret(v, place)
    return v


def config_masked(cfg, secrets, place=None, full=False):
    """What a page is shown (secret_view): each secret as dots and its last two
    for a full administrator (`place` '<table>:<id>' opens it), dots for
    anybody else, "" when not set - and which ones are set."""
    out, is_set = {}, []
    for k, v in (cfg or {}).items():
        if k in secrets or (isinstance(v, str) and v.startswith('sealed:')):
            plain = None
            if v and full and place:
                plain = E.unseal_secret(v, '%s:%s' % (place, k))
            out[k] = secret_view(plain, True) if plain else (SECRET_DOTS if v else '')
            if v:
                is_set.append(k)
        else:
            out[k] = v
    return out, sorted(is_set)


# The settings kept as JSON, where secrets sit inside (Export and import of the
# configuration): table -> (column, what their place starts with).
JSON_SECRET_COLS = {'cert_issuers': 'config', 'cert_challenges': 'config',
                    'cert_targets': 'config', 'cert_deploys': 'options'}


def carry_out(table, row, whole):
    """A row as the configuration's file carries it: each sealed value in its
    settings opened (`whole`, a file locked with a passphrase) or eight dots
    (secret_shown last=False) - never sealed for a row of this machine."""
    col = JSON_SECRET_COLS.get(table)
    if not col or not row.get(col):
        return row
    cfg = jload(row.get(col), {})
    if not isinstance(cfg, dict):
        return row
    for k, v in list(cfg.items()):
        if isinstance(v, str) and v.startswith('sealed:'):
            if whole:
                cfg[k] = E.unseal_secret(v, '%s:%s:%s' % (table, row.get('id'), k)) or ''
            else:
                cfg[k] = E.secret_shown(v, last=False)
    return dict(row, **{col: json.dumps(cfg)})


def carry_in(store, table, ident, old):
    """A row put in from such a file: a secret in clear sealed for its place
    here; eight dots (a file without the secrets) - the one kept here stays,
    or none."""
    col = JSON_SECRET_COLS.get(table)
    if not col:
        return
    row = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (ident,))
    if not row:
        return
    if table == 'cert_deploys':
        secrets = deploy_secrets(store, row)
    else:
        fam = FAMILY_OF.get(table)
        secrets = secret_fields(plugin_class(fam, row.get('kind'))) if fam else set()
    cfg = jload(row.get(col), {})
    if not isinstance(cfg, dict):
        return
    had = jload((old or {}).get(col), {}) if old else {}
    had = had if isinstance(had, dict) else {}
    out = dict(cfg)
    for k, v in cfg.items():
        if not isinstance(v, str) or not (k in secrets or v.startswith('sealed:')):
            continue
        place = '%s:%s:%s' % (table, ident, k)
        if v == '' or E.is_masked(v):
            if had.get(k) and E.unseal_secret(had[k], place) is not None:
                out[k] = had[k]
            else:
                out.pop(k, None)
        elif not v.startswith('sealed:'):
            out[k] = E.seal_secret(v, place)
    if out != cfg:
        store.db.update(table, ident, {col: json.dumps(out)})


def plugin_row(store, family, ref):
    """A row of cert_issuers / cert_challenges / cert_targets by id or name."""
    table = TABLE_OF[family]
    if ref in (None, ''):
        return None
    if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
        got = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (int(ref),))
        if got:
            return got
    return store.db.row('SELECT * FROM %s WHERE name = ?' % table, (str(ref),))


def plugin_config(family, row):
    """The row's settings, secrets opened."""
    cls = plugin_class(family, row.get('kind'))
    return config_open(jload(row.get('config'), {}), '%s:%s' % (TABLE_OF[family], row['id']),
                       secret_fields(cls))


def plugin_public(store, family, row, full=False):
    """A row as it is shown; `full`: to a full administrator (its secrets as dots
    and their last two characters - dots alone otherwise)."""
    cls = plugin_class(family, row.get('kind'))
    cfg, is_set = config_masked(jload(row.get('config'), {}), secret_fields(cls),
                                '%s:%s' % (TABLE_OF[family], row['id']), full)
    out = {k: row.get(k) for k in ('id', 'name', 'kind', 'enabled', 'note', 'created',
                                   'created_by', 'updated', 'last_ok', 'last_error')}
    out['config'] = cfg
    out['secret_set'] = is_set
    out['state'] = jload(row.get('state'), {})
    if 'tags' in row:
        out['tags'] = jload(row.get('tags'), [])
    out['title'] = (cls.title or cls.kind) if cls else row.get('kind')
    out['module_missing'] = cls is None
    out['actions'] = [dict(a) for a in (getattr(cls, 'actions', None) or [])] if cls else []
    from acmelib.certs import defaults as DF
    dflt = DF.default_name(store, family)
    out['is_default'] = bool(dflt) and dflt == row.get('name')
    if family == 'issuer':
        out['used_by'] = int(store.db.value('SELECT COUNT(*) FROM certs WHERE issuer = ?',
                                            (row['name'],), 0) or 0)
    elif family == 'challenge':
        out['used_by'] = int(store.db.value(
            "SELECT COUNT(*) FROM certs WHERE challenge = ? OR challenge_map LIKE ?",
            (row['name'], '%' + json.dumps(row['name']) + '%'), 0) or 0)
    else:
        out['used_by'] = int(store.db.value('SELECT COUNT(*) FROM cert_deploys WHERE target = ?',
                                            (row['name'],), 0) or 0)
    return out


def plugin_instance(store, family, row, ctx):
    cls = plugin_class(family, row.get('kind'))
    if cls is None:
        raise base.PluginError('there is no %s module "%s" (it was taken away, or did not load)'
                               % (family, row.get('kind')), retry=False)
    return cls(plugin_config(family, row), ctx)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def clean_names(names):
    """The names of a certificate: DNS names (a wildcard first label allowed)
    and IP addresses, lower case, each once, in the order given."""
    if isinstance(names, str):
        names = [n for n in re.split(r'[\s,;]+', names) if n]
    out = []
    for n in names or []:
        n = str(n).strip().lower().rstrip('.')
        if not n:
            continue
        try:
            n = str(ipaddress.ip_address(n))
        except ValueError:
            if len(n) > 253 or not DNS_RE.match(n):
                raise ValueError('%r is not a DNS name or an address' % n)
            try:
                n = n.encode('idna').decode('ascii') if any(ord(c) > 127 for c in n) else n
            except UnicodeError:
                raise ValueError('%r is not a DNS name' % n)
        if n not in out:
            out.append(n)
    if len(out) > 100:
        raise ValueError('100 names at most in one certificate')
    return out


def safe_name(text, taken=(), most=120, fallback='unnamed'):
    """A name that NAME_RE takes, made from any text - a module's title, a
    certificate's CN, a name kept by an older version: letters with accents
    as their plain letters (Šifrování -> Sifrovani), a possessive 's and
    apostrophes and quotes dropped (Let's -> Lets), brackets, colons, commas, slashes and the
    like as spaces, anything else outside the rule dropped, spaces squeezed,
    starting with a letter or a digit; and, against `taken` (case kept),
    unique: "name 2", "name 3"... Names reach shell commands, files and
    devices: no quotes, no parentheses, ever."""
    import unicodedata
    t = unicodedata.normalize('NFKD', str(text or ''))
    t = ''.join(c for c in t if not unicodedata.combining(c))
    t = t.replace('\u00df', 'ss').replace('\u0141', 'L').replace('\u0142', 'l') \
        .replace('\u00d8', 'O').replace('\u00f8', 'o').replace('\u0110', 'D') \
        .replace('\u0111', 'd').replace('\u00c6', 'AE').replace('\u00e6', 'ae')
    t = re.sub(r"['\u2019\u2018\u02bc`\"\u201c\u201d\u201e]", '', t)
    t = re.sub(r'[()\[\]{}<>:,/\\;|=*?!#$%^&~\s\u2013\u2014]+', ' ', t)
    t = re.sub(r'[^A-Za-z0-9 ._@+-]+', '', t)
    t = re.sub(r' {2,}', ' ', t).strip(' ._@+-')
    t = t[:most].rstrip(' ._@+-') or fallback
    if not re.match(r'^[A-Za-z0-9]', t):
        t = fallback
    have = {str(x) for x in (taken or ())}
    if t not in have:
        return t
    n = 2
    while True:
        tail = ' %d' % n
        cand = t[:most - len(tail)].rstrip() + tail
        if cand not in have:
            return cand
        n += 1


def clean_name(name, what='a name'):
    name = str(name or '').strip()
    if not NAME_RE.match(name):
        raise ValueError('%s: letters, digits, spaces and . _ @ + - (120 at most), starting '
                         'with a letter or a digit' % what)
    return name


def challenge_for(cert, name):
    """The challenge (its name in cert_challenges) that proves `name`: the
    exact name in challenge_map, then a '*.parent' pattern there, then the
    longest suffix there, then the certificate's own `challenge`."""
    cmap = jload(cert.get('challenge_map'), {}) or {}
    cmap = {str(k).lower().rstrip('.'): v for k, v in cmap.items() if v}
    n = str(name).lower().rstrip('.')
    if n in cmap:
        return cmap[n]
    bare = n[2:] if n.startswith('*.') else n
    if '.' in bare:
        parent = bare.split('.', 1)[1]
        if '*.' + parent in cmap and not n.startswith('*.'):
            return cmap['*.' + parent]
    best, best_len = None, -1
    for k, v in cmap.items():
        k2 = k[2:] if k.startswith('*.') else k
        k2 = k2.lstrip('.')
        if bare == k2 or bare.endswith('.' + k2):
            if len(k2) > best_len:
                best, best_len = v, len(k2)
    return best or cert.get('challenge') or None


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
def key_place(cert_id, version):
    return 'certs:%s:key_sealed:%s' % (cert_id, version)


def cert_get(store, ref):
    if ref in (None, ''):
        return None
    if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
        got = store.db.row('SELECT * FROM certs WHERE id = ?', (int(ref),))
        if got:
            return got
    return store.db.row('SELECT * FROM certs WHERE name = ?', (str(ref),))


def cert_need(store, ref):
    got = cert_get(store, ref)
    if not got:
        raise LookupError('there is no certificate %s' % ref)
    return got


def cert_key(row):
    """The certificate's private key (PEM), or None."""
    if not row.get('key_sealed'):
        return None
    return E.unseal_secret(row['key_sealed'], key_place(row['id'], row.get('version') or 0))


def chain_list(text):
    if not text:
        return []
    return ['-----BEGIN CERTIFICATE-----' + p.split('-----END CERTIFICATE-----')[0] +
            '-----END CERTIFICATE-----\n'
            for p in str(text).split('-----BEGIN CERTIFICATE-----')[1:]]


def days_left(row, t=None):
    na = row.get('not_after')
    if not na:
        return None
    return int((float(na) - (t or now())) // 86400)


PUBLIC_SKIP = ('key_sealed', 'csr_pending')
JSON_COLS = {'names': [], 'challenge_map': {}, 'profile': {}, 'ari': {}, 'tags': []}


def cert_public(row, full=False):
    """A certificate as the pages see it: never its key."""
    out = {}
    for k, v in row.items():
        if k in PUBLIC_SKIP:
            continue
        if k in JSON_COLS:
            v = jload(v, JSON_COLS[k])
        if not full and k in ('cert_pem', 'chain_pem'):
            continue
        out[k] = v
    out['has_key'] = bool(row.get('key_sealed'))
    out['csr_waiting'] = bool(row.get('csr_pending'))
    out['days_left'] = days_left(row)
    out['state_words'] = STATES().get(row.get('state') or '', '')
    return out


def STATES():
    from acmelib.certs import schema
    return schema.STATES


def pki():
    from acmelib.certs import pki as _pki
    return _pki


def info_of(cert_pem):
    """pki.cert_info, its times as epoch seconds."""
    info = {k: v for k, v in (pki().cert_info(cert_pem) or {}).items()
            if not isinstance(v, (bytes, bytearray)) and k != 'pem'}
    for k in ('not_before', 'not_after'):
        info[k] = epoch(info.get(k))
    return info


def save_version(store, cert_id, cert_pem, chain_pems, key_pem, why, by, info=None,
                 extra=None):
    """A new certificate for a row of certs: kept in cert_versions, and made
    the current one. Returns the version's number."""
    row = cert_need(store, cert_id)
    info = info or info_of(cert_pem)
    version = int(store.db.value('SELECT MAX(version) FROM cert_versions WHERE cert_id = ?',
                                 (row['id'],), 0) or 0)
    version = max(version, int(row.get('version') or 0)) + 1
    sealed = E.seal_secret(key_pem, key_place(row['id'], version)) if key_pem else None
    chain = ''.join(p if p.endswith('\n') else p + '\n' for p in (chain_pems or []))
    t = now()
    store.db.insert('cert_versions', {
        'cert_id': row['id'], 'version': version, 'cert_pem': cert_pem, 'chain_pem': chain,
        'key_sealed': sealed, 'serial': str(info.get('serial') or '')[:190],
        'fingerprint': str(info.get('sha256') or '')[:190], 'not_before': info.get('not_before'),
        'not_after': info.get('not_after'), 'issuer_dn': info.get('issuer_dn') or '',
        'created': t, 'why': str(why)[:60], 'by_who': str(by or '')[:190], 'revoked': None})
    fields = {
        'cert_pem': cert_pem, 'chain_pem': chain, 'key_sealed': sealed,
        'serial': str(info.get('serial') or '')[:190],
        'fingerprint': str(info.get('sha256') or '')[:190],
        'not_before': info.get('not_before'), 'not_after': info.get('not_after'),
        'issuer_dn': info.get('issuer_dn') or '', 'subject_dn': info.get('subject_dn') or '',
        'version': version, 'state': 'ok' if (info.get('not_after') or 0) > t else 'expired',
        'state_at': t, 'last_ok': t, 'last_error': '', 'fails': 0, 'next_try': None,
        'updated': t, 'updated_by': str(by or '')[:190]}
    if info.get('cn') and not row.get('cn'):
        fields['cn'] = str(info['cn'])[:190]
    if extra:
        fields.update(extra)
    store.db.update('certs', row['id'], fields)
    prune_versions(store, row['id'], version)
    return version


def prune_versions(store, cert_id, current=None):
    keep = max(1, int(E.CONFIG.get('certs_keep_versions') or 10))
    rows = store.db.rows('SELECT id, version FROM cert_versions WHERE cert_id = ? '
                         'ORDER BY version DESC', (cert_id,))
    for r in rows[keep:]:
        if current is not None and r['version'] == current:
            continue
        store.db.run('DELETE FROM cert_versions WHERE id = ?', (r['id'],))


def version_row(store, cert_id, version):
    return store.db.row('SELECT * FROM cert_versions WHERE cert_id = ? AND version = ?',
                        (cert_id, int(version)))


def version_public(r):
    return {k: r.get(k) for k in ('id', 'cert_id', 'version', 'serial', 'fingerprint',
                                  'not_before', 'not_after', 'issuer_dn', 'created', 'why',
                                  'by_who', 'revoked')} | {'has_key': bool(r.get('key_sealed'))}


def bundle_of(row, version_row_=None):
    """The certificate (or one of its versions) as a target gets it."""
    from acmelib.certs import bundle as _bundle
    src = version_row_ or row
    version = src.get('version') or 0
    key = E.unseal_secret(src['key_sealed'], key_place(row['id'], version)) \
        if src.get('key_sealed') else None
    chain = chain_list(src.get('chain_pem'))
    b = _bundle.CertBundle(row['name'], src['cert_pem'], key, chain)
    # What the contract (base.Bundle) promises, where the library left it out.
    for k, v in (('name', row['name']), ('names', jload(row.get('names'), [])),
                 ('serial', src.get('serial')), ('fingerprint', src.get('fingerprint')),
                 ('not_before', src.get('not_before')), ('not_after', src.get('not_after')),
                 ('cert_pem', src['cert_pem']), ('key_pem', key), ('chain_pems', chain),
                 ('version', version)):
        if getattr(b, k, None) in (None, '', []):
            try:
                setattr(b, k, v)
            except AttributeError:
                pass
    if not getattr(b, 'fullchain_pem', None):
        try:
            b.fullchain_pem = src['cert_pem'].rstrip('\n') + '\n' + ''.join(chain)
        except AttributeError:
            pass
    return b


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------
def deploy_secrets(store, row):
    t = plugin_row(store, 'target', row.get('target'))
    cls = plugin_class('target', t.get('kind')) if t else None
    return secret_fields(cls, 'deploy_fields')


def deploy_options(store, row):
    return config_open(jload(row.get('options'), {}), 'cert_deploys:%s' % row['id'],
                       deploy_secrets(store, row))


def deploy_public(store, row, full=False):
    opts, is_set = config_masked(jload(row.get('options'), {}), deploy_secrets(store, row),
                                 'cert_deploys:%s' % row['id'], full)
    out = {k: v for k, v in row.items() if k != 'options'}
    out['options'] = opts
    out['secret_set'] = is_set
    return out


def backoff(fails):
    """How long to wait after the n-th failure in a row: 5 min, doubled each
    time, at most certs_retry_max_h."""
    cap = max(1, int(E.CONFIG.get('certs_retry_max_h') or 6)) * 3600
    return min(cap, 300 * (2 ** max(0, int(fails or 1) - 1)))


def settings_view():
    """The settings as a module may read them: no secret."""
    return {k: v for k, v in E.CONFIG.items() if k not in E.SECRET_KEYS}
