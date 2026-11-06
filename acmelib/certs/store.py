# -*- coding: utf-8 -*-
"""
The certificate manager's tables, read and written: the certificates and
their versions, the issuers, challenges and targets with their settings
(secrets sealed; shown as dots - and their last two characters to a full
administrator - never in clear), the deployments.

Sealing binds every secret to its place:
    a certificate's key        'certs:<id>:key_sealed:<version>'  (the same value
                               in certs and in cert_versions, so it is copied as it is)
    the twin's key (dual)      'certs:<id>:alt_key_sealed:<alt_version>'  (likewise; in
                               cert_versions the row of variant 'alt')
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

TABLE_OF = {'issuer': 'cert_issuers', 'challenge': 'cert_challenges', 'target': 'cert_targets',
            'check': 'cert_tests'}
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


VERSION_KEY = '_version'         # a row's config: the version of its module (1.0.32)


def plugin_class(family, kind, version=None):
    """The module's class, or None when there is no such module. `version`: that
    version of it where it is there (else its default one)."""
    try:
        return registry().get(family, kind, version)
    except base.PluginError:
        return None


def version_of(row_or_cfg):
    """The module version a row (or a config) keeps - None when it says none."""
    if not isinstance(row_or_cfg, dict):
        return None
    cfg = row_or_cfg
    if 'config' in row_or_cfg and 'kind' in row_or_cfg:
        cfg = jload(row_or_cfg.get('config'), {}) if not isinstance(
            row_or_cfg.get('config'), dict) else row_or_cfg.get('config')
    v = (cfg or {}).get(VERSION_KEY) if isinstance(cfg, dict) else None
    return None if v is None else str(v)


def row_class(family, row, kind=None):
    """The class of a saved source, validation or target - the version it keeps."""
    if not row:
        return plugin_class(family, kind) if kind else None
    k = kind or row.get('kind')
    return plugin_class(family, k, version_of(row) if k == row.get('kind') else None)


def given_class(family, kind, cfg=None, row=None):
    """The class for settings sent from a form (saved or not): the version the form
    says (its config's "_version"), else the one the row keeps when it is that kind."""
    if isinstance(cfg, dict) and VERSION_KEY in cfg:
        return plugin_class(family, kind, str(cfg.get(VERSION_KEY) or ''))
    if row and row.get('kind') == kind:
        return row_class(family, row)
    return plugin_class(family, kind)


def version_state(family, row):
    """(version kept, version used, missing): a row whose version is no longer there
    (a module of your own taken away) runs the default one - said on the page."""
    want = version_of(row)
    cls = row_class(family, row)
    used = (cls.module_version or '') if cls else ''
    missing = bool(cls) and want not in (None, '') and want != used
    return want, used, missing


def secret_fields(cls, attr='fields'):
    """The keys kept sealed: type 'secret', and a 'pem' (or any) field marked
    secret=True - a private key pasted in (the SSH key of a validation)."""
    if cls is None:
        return set()
    # every version of the module (1.0.32): a secret of one is sealed whichever is used
    try:
        sibs = list(registry().versions_of(cls.family, cls.kind).values()) or [cls]
    except Exception:                                   # noqa: BLE001
        sibs = [cls]
    if cls not in sibs:
        sibs.append(cls)
    return {f['key'] for c in sibs for f in (getattr(c, attr, None) or [])
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
        secrets = secret_fields(row_class(fam, row)) if fam else set()
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
    if isinstance(ref, int) and not isinstance(ref, bool):
        return store.db.row('SELECT * FROM %s WHERE id = ?' % table, (int(ref),))
    # by its name first (1.0.52): a target named "1" was taken for the one of id 1 - and the
    # certificate and its key went to that one's server
    got = store.db.row('SELECT * FROM %s WHERE name = ?' % table, (str(ref),))
    if got is None and isinstance(ref, str) and ref.isdigit():
        got = store.db.row('SELECT * FROM %s WHERE id = ?' % table, (int(ref),))
    return got


def plugin_config(family, row):
    """The row's settings, secrets opened."""
    cls = row_class(family, row)
    return config_open(jload(row.get('config'), {}), '%s:%s' % (TABLE_OF[family], row['id']),
                       secret_fields(cls))


def plugin_public(store, family, row, full=False):
    """A row as it is shown; `full`: to a full administrator (its secrets as dots
    and their last two characters - dots alone otherwise)."""
    cls = row_class(family, row)
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
    # the version of its module, where it came from (1.0.32)
    want, used, missing = version_state(family, row)
    out['version'] = used
    out['version_kept'] = want
    out['version_missing'] = missing
    out['origin'] = getattr(cls, '_origin', 'builtin') if cls else ''
    out['overrides'] = bool(getattr(cls, '_overrides', '')) if cls else False
    out['actions'] = [dict(a) for a in (getattr(cls, 'actions', None) or [])] if cls else []
    if family == 'challenge' and row.get('kind') == 'dns_persist':
        # what acme wrote in DNS for it (dns_persist.py) - its actions as they apply
        got = jload(store.get_meta('certs:kv:challenge:%s:written' % row['name']), {}) or {}
        out['persist_written'] = len(got.get('v') or []) if isinstance(got, dict) else 0
        has = {'writer': bool(str(cfg.get('writer') or '').strip()),
               'written': out['persist_written'] > 0}
        out['actions'] = [a for a in out['actions'] if not a.get('needs') or has.get(a['needs'])]
    from acmelib.certs import defaults as DF
    dflt = DF.default_name(store, family)
    out['is_default'] = bool(dflt) and dflt == row.get('name')
    if family == 'issuer':
        out['used_by'] = int(store.db.value('SELECT COUNT(*) FROM certs WHERE issuer = ?',
                                            (row['name'],), 0) or 0)
        # A dual certificate (ECDSA beside RSA) can come from it, as its settings are now.
        try:
            out['dual'] = bool(cls and cls.dual_for(cfg))
        except Exception:                               # noqa: BLE001
            out['dual'] = False
    elif family == 'challenge':
        out['used_by'] = int(store.db.value(
            "SELECT COUNT(*) FROM certs WHERE challenge = ? OR challenge_map LIKE ?",
            (row['name'], '%' + json.dumps(row['name']) + '%'), 0) or 0)
    elif family == 'check':
        # attached to certificates, and in the sets of the tests through SSH (1.0.32)
        n = int(store.db.value('SELECT COUNT(*) FROM cert_checks WHERE test = ?',
                               (row['name'],), 0) or 0)
        for r in store.db.rows("SELECT config FROM cert_tests WHERE kind = 'ssh_relay'"):
            if row['name'] in (jload(r.get('config'), {}) or {}).get('tests') or []:
                n += 1
        out['used_by'] = n
    else:
        out['used_by'] = int(store.db.value('SELECT COUNT(*) FROM cert_deploys WHERE target = ?',
                                            (row['name'],), 0) or 0)
    return out


def plugin_instance(store, family, row, ctx, over=None):
    """The module of a row, with its settings - and a certificate's own values of the
    settings it may set itself (`over`, cert_over) over them."""
    cls = row_class(family, row)
    if cls is None:
        raise base.PluginError('there is no %s module "%s" (it was taken away, or did not load)'
                               % (family, row.get('kind')), retry=False)
    return cls(config_over(cls, plugin_config(family, row), over), ctx)


# ---------------------------------------------------------------------------
# A certificate's own settings of its source and validations (1.0.24)
# ---------------------------------------------------------------------------
# profile.over = {'source': {field: value}, 'validation': {validation name: {field:
# value}}} - what one certificate sets itself over the settings of its source and of
# its validations (Add a certificate: "for this certificate"), so one source serves
# certificates of other templates, products, zones... Only what a certificate may set:
# not a secret, not where or as whom the module signs in (OVER_NOT), unless the field
# says `cert: True`; `cert: False` keeps any field out.
OVER_NOT = frozenset((
    'url', 'host', 'hostname', 'port', 'server', 'servers', 'endpoint', 'base_url', 'api_url',
    'api_base', 'directory', 'user', 'username', 'login', 'account', 'account_id', 'auth',
    'domain_user',
    'token', 'api_key', 'key_id', 'client_id', 'client_cert', 'client_key', 'tenant',
    'tenant_id', 'subscription', 'subscription_id', 'region', 'project', 'project_id',
    'verify', 'ca_pem', 'timeout', 'proxy', 'eab_kid', 'eab_hmac', 'contact', 'email_contact',
    'ssh_host', 'ssh_user', 'ssh_port', 'ssh_key', 'ssh_password', 'sandbox', 'test',
    'environment', 'location', 'zone_id_api', 'directory_url', 'account_key', 'contacts',
    'api', 'api_version', 'domain_auth', 'netbios', 'access_key', 'token_url', 'scope',
    'audience', 'api_path', 'role_id', 'approle_mount', 'namespace', 'ca_fingerprint',
    'ca_ident', 'kid', 'given_kid', 'provisioner', 'reference', 'recipient', 'key_in',
    'client_token', 'auth_id', 'user_kind', 'key', 'access_key_id', 'api_user', 'client_ip',
    'user_name', 'customer', 'app_key', 'secret_id', 'tenancy', 'fingerprint', 'global_key',
    'tsig_name', 'tsig_alg', 'ftp_user', 'hostkey', 'trust_first', 'keyfile', 'session_key',
    'hosts', 'team', 'identity', 'subdomain', 'fulldomain', 'flavour', 'nsupdate_server',
    'named_conf', 'pdns_config_dir', 'pdns_api_url', 'wapi_version', 'server_id', 'cloud',
    'partition', 'protocol', 'verify_tls', 'transport', 'resource_group', 'compartment',
    # asked in Add a certificate itself already (Profile: valid for, used for)
    'days', 'eku'))
# Never by a certificate (whatever runs, or is written where): a certificate's manager
# may not set what only a full administrator sets on a module - a command, a script, a
# path or file on a machine, sudo.
OVER_NEVER = re.compile(r'(^|_)(command|commands|path|env|sudo|script|conf|file|files|'
                        r'reload|control|socket|hook|'
                        r'prepare|balancer|computer|rndc|checkzone|writer|style|mode)(_|$)')
# Where a file is written - the web root, a folder, a container, a bucket (1.0.26): a
# certificate's own only when a full administrator sets it (as on the module itself);
# a certificate administrator keeps what was set, and cannot change it.
OVER_PLACES = re.compile(r'(^|_)(webroot|folder|container|bucket)(_|$)')
OVER_TYPES = ('text', 'select', 'bool', 'number', 'list', 'catalog', 'textarea')


def over_fields(cls, full=False):
    """The fields of a module a certificate may set itself - with `full`, also where a
    file is written (OVER_PLACES: a full administrator's)."""
    out = []
    for f in (getattr(cls, 'fields', None) or []) if cls is not None else []:
        if not isinstance(f, dict) or not f.get('key'):
            continue
        mark = f.get('cert')
        if mark is False or f.get('type') == 'secret' or f.get('secret') or \
                OVER_NEVER.search(f['key']):
            continue
        if OVER_PLACES.search(f['key']):
            if full and f.get('type', 'text') in OVER_TYPES:
                out.append(f)
            continue
        if mark is True or (f.get('type', 'text') in OVER_TYPES and f['key'] not in OVER_NOT
                            and not f['key'].startswith('path_')):
            out.append(f)
    return out


def config_over(cls, cfg, over):
    """`cfg` with a certificate's own values over it - only of over_fields."""
    if not over or not isinstance(over, dict):
        return cfg
    keys = {f['key'] for f in over_fields(cls, full=True)}   # checked when saved
    out = dict(cfg or {})
    for k, v in over.items():
        if k in keys:
            out[k] = v
    return out


def cert_over(cert, family, name=''):
    """A certificate's own values for its source ('issuer') or for the validation `name`
    ('challenge'): {} when it sets none."""
    prof = cert.get('profile') if isinstance(cert, dict) else None
    if isinstance(prof, str):
        prof = jload(prof, {})
    over = (prof or {}).get('over') if isinstance(prof, dict) else None
    if not isinstance(over, dict):
        return {}
    if family == 'issuer':
        got = over.get('source')
    else:
        got = (over.get('validation') or {}).get(name) if isinstance(over.get('validation'),
                                                                      dict) else None
    return dict(got) if isinstance(got, dict) else {}


def place_keys(cls):
    """The fields of over_fields(full=True) only a full administrator sets."""
    return [f['key'] for f in over_fields(cls, full=True) if OVER_PLACES.search(f['key'])]


def clean_over(store, over, issuer, challenges, full=False, old=None):
    """profile.over as given, checked: only the fields each module lets a certificate
    set, values of their kind (a choice one of its options), the source's for the
    certificate's source and the validations' for those it uses. -> the clean dict.
    Where a file is written (OVER_PLACES) only `full` (a full administrator) sets; saved
    by anybody else, what `old` (the profile.over before) holds of it is kept as it is."""
    old = old if isinstance(old, dict) else {}
    if over in (None, ''):
        over = {}
    if not isinstance(over, dict):
        raise ValueError('profile.over is an object')
    if not over and (full or not old):
        return {}

    def one(cls, given, what, before):
        if not isinstance(given, dict):
            raise ValueError('the own settings of %s are an object' % what)
        fields = {f['key']: f for f in over_fields(cls, full=True)}
        places = set(place_keys(cls))
        before = before if isinstance(before, dict) else {}
        out = {}
        if not full:
            for k in places:
                if k in given and given[k] != before.get(k):
                    raise ValueError('%s: only a full administrator sets %s of a certificate '
                                     '(where a file is written)' % (
                                         what, (fields.get(k) or {}).get('label') or k))
                if k not in given and k in before:
                    out[k] = before[k]          # kept as a full administrator set it
        for k, v in given.items():
            f = fields.get(k)
            if f is None:
                raise ValueError('%s: a certificate cannot set "%s" itself' % (what, k))
            t = f.get('type', 'text')
            if t == 'bool':
                v = v is True or str(v).strip().lower() in ('1', 'true', 'yes', 'on')
            elif t == 'number':
                try:
                    v = float(v) if '.' in str(v) else int(v)
                except (TypeError, ValueError):
                    raise ValueError('%s: %s is a number' % (what, f.get('label') or k))
            elif t == 'list':
                if isinstance(v, str):
                    v = [x.strip() for x in v.splitlines() if x.strip()]
                if not isinstance(v, list):
                    raise ValueError('%s: %s is a list' % (what, f.get('label') or k))
                v = [str(x)[:1000] for x in v][:200]
            else:
                v = str(v if v is not None else '')
                if len(v) > 4000:
                    raise ValueError('%s: %s is too long' % (what, f.get('label') or k))
                if t == 'select' and f.get('options'):
                    allowed = [str(o[0] if isinstance(o, (list, tuple)) else o)
                               for o in f['options']]
                    if v not in allowed:
                        raise ValueError('%s: %s is one of %s' % (
                            what, f.get('label') or k, ', '.join(allowed)))
            out[k] = v
        return out
    res = {}
    old_src = old.get('source') if isinstance(old.get('source'), dict) else {}
    old_vals = old.get('validation') if isinstance(old.get('validation'), dict) else {}
    src = over.get('source')
    if src or (not full and old_src):
        irow = plugin_row(store, 'issuer', issuer) if issuer else None
        if not irow and src:
            raise ValueError('own settings of a source, but the certificate has none')
        if irow:
            got = one(row_class('issuer', irow), src or {}, irow['name'], old_src)
            if got:
                res['source'] = got
    vals = over.get('validation')
    if vals and not isinstance(vals, dict):
        raise ValueError('the own settings of the validations are an object')
    vals = dict(vals or {})
    if not full:
        for name in old_vals:
            vals.setdefault(name, {})
    keep = {}
    for name, given in vals.items():
        crow = plugin_row(store, 'challenge', name)
        if not crow:
            if name in old_vals and name not in (over.get('validation') or {}):
                continue                # gone since: nothing to keep
            raise ValueError('there is no validation %s' % name)
        if crow['name'] not in challenges:
            continue                    # a validation it no longer uses: dropped
        got = one(row_class('challenge', crow), given, crow['name'],
                  old_vals.get(name))
        if got:
            keep[crow['name']] = got
    if keep:
        res['validation'] = keep
    return res


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def clean_names(names):
    """The names of a certificate: DNS names (a wildcard first label allowed)
    and IP addresses, lower case, each once, in the order given."""
    if isinstance(names, str):
        names = [n for n in re.split(r'[\s,;]+', names) if n]
    if names is not None and not isinstance(names, (list, tuple)):
        raise ValueError('the names are a list of names')     # a number (1.0.45): a traceback
    out = []
    for n in names or []:
        n = str(n).strip().lower().rstrip('.')
        if not n:
            continue
        if '%' in n:
            # An IPv6 zone id takes any character after % (1.0.45): "fd00::5%x.example.com" was an
            # address and passed the portal's domain checks.
            raise ValueError('%r is not a DNS name or an address' % n)
        try:
            n = str(ipaddress.ip_address(n))
        except ValueError:
            if any(ord(c) > 127 for c in n):
                # an international name, in its ASCII form (IDNA): žluťoučký.cz -> xn--...
                star = '*.' if n.startswith('*.') else ''
                if any(c in n for c in '\u00df\u03c2\u200c\u200d'):
                    # ß, ς and the joiners (1.0.51): Python's IDNA (2003) writes faß.de as
                    # fass.de, a CA and a browser (2008) as xn--fa-hia.de - another domain.
                    raise ValueError('%r: ß, ς and the joiners are written two ways in DNS - '
                                     'give the name in its xn-- form' % n)
                try:
                    n = star + (n[len(star):]).encode('idna').decode('ascii')
                except UnicodeError:
                    raise ValueError('%r is not a DNS name' % n)
            if len(n) > 253 or not DNS_RE.match(n):
                raise ValueError('%r is not a DNS name or an address' % n)
        if n not in out:
            out.append(n)
    if len(out) > 100:
        raise ValueError('100 names at most in one certificate')
    return out


SAN_TYPES = ('dns', 'ip', 'email', 'uri')
EMAIL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
                      r"[^@\s]+\Z")
URI_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*:[^\s<>"{}|\\^`]+\Z')


def san_typed(item):
    """('dns' | 'ip' | 'email' | 'uri', value) of one subjectAltName - given as
    {'type', 'value'}, as 'email:x@y' / 'uri:https://...' / 'dns:..' / 'ip:..', or bare
    (an address, an e-mail with @, a URI with ://, else a DNS name) - checked:
    DNS by IDNA, IP v4/v6, an e-mail of RFC 5322's plain form, an absolute URI."""
    if isinstance(item, dict):
        t, v = str(item.get('type') or '').strip().lower(), str(item.get('value') or '').strip()
    else:
        raw = str(item or '').strip()
        m = re.match(r'^(dns|ip|email|uri):(.*)\Z', raw, re.I | re.S)
        if m and not (m.group(1).lower() == 'uri' and raw[4:6] == '//'):
            t, v = m.group(1).lower(), m.group(2).strip()
        else:
            t, v = '', raw
    if not t:
        if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', v) or re.match(r'^(urn|tag|mailto|did|'
                                                                    r'spiffe|ldap|sip):', v, re.I):
            t = 'uri'
        elif '@' in v:
            t = 'email'
        else:
            try:
                ipaddress.ip_address(v.strip('[]'))
                t = 'ip'
            except ValueError:
                t = 'dns'
    if t not in SAN_TYPES:
        raise ValueError('%r: a name is a DNS name, an IP address, an e-mail or a URI' % item)
    if not v:
        raise ValueError('an empty %s name' % t)
    if t == 'ip':
        try:
            return 'ip', str(ipaddress.ip_address(v.strip('[]')))
        except ValueError:
            raise ValueError('%r is not an IP address' % v)
    if t == 'dns':
        got = clean_names([v])
        if not got or ':' in got[0] and '.' not in got[0]:
            raise ValueError('%r is not a DNS name' % v)
        try:
            ipaddress.ip_address(got[0])
            raise ValueError('%r is an IP address, not a DNS name' % v)
        except ValueError as e:
            if 'IP address, not' in str(e):
                raise
        return 'dns', got[0]
    if t == 'email':
        if len(v) > 254 or not EMAIL_RE.match(v):
            raise ValueError('%r is not an e-mail address' % v)
        local, _, dom = v.rpartition('@')
        try:
            dom = clean_names([dom])[0]
        except (ValueError, IndexError):
            raise ValueError('%r is not an e-mail address (its domain)' % v)
        if '.' not in dom and dom != 'localhost':
            raise ValueError('%r is not an e-mail address (its domain has no dot)' % v)
        return 'email', '%s@%s' % (local, dom)
    if len(v) > 2048 or not URI_RE.match(v) or '://' in v and not re.match(
            r'^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]+', v):
        raise ValueError('%r is not an absolute URI (scheme://host/...)' % v)
    return 'uri', v


def clean_sans(items):
    """The subjectAltNames other than DNS names and addresses, checked, each once:
    ['email:it@example.com', 'uri:https://example.com/x'] (what profile.san_other keeps).
    DNS names and addresses given here are refused: they are the certificate's names."""
    if isinstance(items, str):
        items = [x for x in re.split(r'[\n,;]+', items) if x.strip()]
    out = []
    for it in items or []:
        t, v = san_typed(it)
        if t in ('dns', 'ip'):
            raise ValueError('%s is a DNS name or an address: it goes among the names' % v)
        w = '%s:%s' % (t, v)
        if w not in out:
            out.append(w)
    if len(out) > 50:
        raise ValueError('50 e-mail and URI names at most')
    return out


def sans_of(names, profile):
    """Every subjectAltName of a certificate: its names and profile.san_other."""
    other = (profile or {}).get('san_other') or []
    return list(names or []) + [x for x in other if isinstance(x, str)]


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
def key_place(cert_id, version, variant=''):
    """The bind a certificate's key is sealed under; `variant` 'alt': its twin's."""
    return 'certs:%s:%s:%s' % (cert_id, 'alt_key_sealed' if variant == 'alt' else 'key_sealed',
                               version)


def key_family(key_type):
    """'ec' | 'rsa' | 'ed' (or the text itself) of a key type: ec-256 -> ec."""
    kt = str(key_type or '').lower()
    if kt.startswith(('ec', 'ecdsa', 'p-')):
        return 'ec'
    if kt.startswith('rsa'):
        return 'rsa'
    if kt.startswith('ed'):
        return 'ed'
    return kt


def generation(row):
    """The newest version of a certificate, its twin's too: what a deployment that
    is up to date has (cert_deploys.deployed_version)."""
    return max(int(row.get('version') or 0), int(row.get('alt_version') or 0)
               if row.get('key_type_alt') and row.get('alt_cert_pem') else 0)


def is_dual(row):
    """The certificate is dual and its twin has been issued - and not revoked (1.0.48: a revoked
    twin was put on the servers with the new main one, after a revoke and a new one)."""
    return bool(row.get('key_type_alt')) and bool(row.get('alt_cert_pem')) and \
        str(row.get('alt_state') or '') != 'revoked'


def issuer_dual(store, ref):
    """Whether the source (a row of cert_issuers, or its name) gives a twin."""
    irow = ref if isinstance(ref, dict) else plugin_row(store, 'issuer', ref)
    if not irow:
        return False
    cls = row_class('issuer', irow)
    if cls is None:
        return False
    try:
        return bool(cls.dual_for(jload(irow.get('config'), {}) or {}))
    except Exception:                                   # noqa: BLE001
        return False


# The twin's columns in certs, and those of the main certificate they stand for.
ALT_COLS = {'alt_cert_pem': 'cert_pem', 'alt_chain_pem': 'chain_pem',
            'alt_key_sealed': 'key_sealed', 'alt_serial': 'serial',
            'alt_fingerprint': 'fingerprint', 'alt_not_before': 'not_before',
            'alt_not_after': 'not_after', 'alt_issuer_dn': 'issuer_dn', 'alt_ari': 'ari',
            'alt_version': 'version'}
ALT_CLEAR = dict({k: None for k in ALT_COLS}, alt_state='', alt_error='', alt_fails=0,
                 alt_next_try=None)


def alt_view(row):
    """The twin of a row of certs as a row of its own (cert_pem, version...), or None."""
    if not row.get('alt_cert_pem'):
        return None
    out = {main: row.get(alt) for alt, main in ALT_COLS.items()}
    out.update(id=row.get('id'), name=row.get('name'), names=row.get('names'),
               key_type=row.get('key_type_alt'), variant='alt')
    return out


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


def cert_key(row, variant=''):
    """The certificate's private key (PEM), or None; `variant` 'alt': its twin's."""
    if variant == 'alt':
        if not row.get('alt_key_sealed'):
            return None
        return E.unseal_secret(row['alt_key_sealed'],
                               key_place(row['id'], row.get('alt_version') or 0, 'alt'))
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


PUBLIC_SKIP = ('key_sealed', 'csr_pending', 'alt_key_sealed', 'csr_given')
JSON_COLS = {'names': [], 'challenge_map': {}, 'profile': {}, 'ari': {}, 'tags': [],
             'alt_ari': {}}


def cert_public(row, full=False):
    """A certificate as the pages see it: never its key."""
    out = {}
    for k, v in row.items():
        if k in PUBLIC_SKIP:
            continue
        if k in JSON_COLS:
            v = jload(v, JSON_COLS[k])
        if not full and k in ('cert_pem', 'chain_pem', 'alt_cert_pem', 'alt_chain_pem'):
            continue
        out[k] = v
    out['has_key'] = bool(row.get('key_sealed'))
    out['has_alt_key'] = bool(row.get('alt_key_sealed'))
    out['dual'] = bool(row.get('key_type_alt'))
    out['generation'] = generation(row)
    out['alt_days_left'] = days_left({'not_after': row.get('alt_not_after')}) \
        if row.get('alt_not_after') else None
    out['csr_waiting'] = bool(row.get('csr_pending'))
    # Issued for a CSR sent in (a request profile, 1.0.17): acme never had its key.
    out['from_csr'] = bool(row.get('csr_given'))
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
    version = next_version(store, row)
    sealed = E.seal_secret(key_pem, key_place(row['id'], version)) if key_pem else None
    chain = ''.join(p if p.endswith('\n') else p + '\n' for p in (chain_pems or []))
    t = now()
    store.db.insert('cert_versions', {
        'cert_id': row['id'], 'version': version, 'cert_pem': cert_pem, 'chain_pem': chain,
        'key_sealed': sealed, 'serial': str(info.get('serial') or '')[:190],
        'fingerprint': str(info.get('sha256') or '')[:190], 'not_before': info.get('not_before'),
        'not_after': info.get('not_after'), 'issuer_dn': info.get('issuer_dn') or '',
        'created': t, 'why': str(why)[:60], 'by_who': str(by or '')[:190], 'revoked': None,
        'variant': ''})
    fields = {
        'cert_pem': cert_pem, 'chain_pem': chain, 'key_sealed': sealed,
        'serial': str(info.get('serial') or '')[:190],
        'fingerprint': str(info.get('sha256') or '')[:190],
        'not_before': info.get('not_before'), 'not_after': info.get('not_after'),
        'issuer_dn': info.get('issuer_dn') or '', 'subject_dn': info.get('subject_dn') or '',
        'version': version, 'state': 'ok' if (info.get('not_after') or 0) > t else 'expired',
        'state_at': t, 'last_ok': t, 'last_error': '', 'fails': 0, 'next_try': None,
        # the window its CA suggested was the version before's (1.0.51): an import or a CSR's
        # answer kept it, and was renewed at once
        'ari': '{}',
        'updated': t, 'updated_by': str(by or '')[:190]}
    if info.get('cn') and not row.get('cn'):
        fields['cn'] = str(info['cn'])[:190]
    if extra:
        fields.update(extra)
    store.db.update('certs', row['id'], fields)
    prune_versions(store, row['id'], version)
    return version


def next_version(store, row):
    """The number of a certificate's next version - main and twin share one sequence."""
    version = int(store.db.value('SELECT MAX(version) FROM cert_versions WHERE cert_id = ?',
                                 (row['id'],), 0) or 0)
    return max(version, int(row.get('version') or 0), int(row.get('alt_version') or 0)) + 1


def save_alt(store, cert_id, cert_pem, chain_pems, key_pem, why, by, info=None, extra=None):
    """A new twin (the second certificate of a dual one): kept in cert_versions
    (variant 'alt') and made the current twin - the main certificate is left as
    it is. Returns the twin's version number."""
    row = cert_need(store, cert_id)
    info = info or info_of(cert_pem)
    version = next_version(store, row)
    sealed = E.seal_secret(key_pem, key_place(row['id'], version, 'alt')) if key_pem else None
    chain = ''.join(p if p.endswith('\n') else p + '\n' for p in (chain_pems or []))
    t = now()
    store.db.insert('cert_versions', {
        'cert_id': row['id'], 'version': version, 'cert_pem': cert_pem, 'chain_pem': chain,
        'key_sealed': sealed, 'serial': str(info.get('serial') or '')[:190],
        'fingerprint': str(info.get('sha256') or '')[:190], 'not_before': info.get('not_before'),
        'not_after': info.get('not_after'), 'issuer_dn': info.get('issuer_dn') or '',
        'created': t, 'why': str(why)[:60], 'by_who': str(by or '')[:190], 'revoked': None,
        'variant': 'alt'})
    fields = {
        'alt_cert_pem': cert_pem, 'alt_chain_pem': chain, 'alt_key_sealed': sealed,
        'alt_serial': str(info.get('serial') or '')[:190],
        'alt_fingerprint': str(info.get('sha256') or '')[:190],
        'alt_not_before': info.get('not_before'), 'alt_not_after': info.get('not_after'),
        'alt_issuer_dn': info.get('issuer_dn') or '', 'alt_version': version,
        'alt_state': 'ok', 'alt_error': '', 'alt_fails': 0, 'alt_next_try': None,
        'alt_ari': '{}',
        'updated': t, 'updated_by': str(by or '')[:190]}
    if extra:
        fields.update(extra)
    store.db.update('certs', row['id'], fields)
    prune_versions(store, row['id'])
    return version


def alt_failed(store, cert_id, why):
    """The twin did not come: said on the row, tried again after its own wait.
    Returns the wait in seconds."""
    row = cert_need(store, cert_id)
    fails = int(row.get('alt_fails') or 0) + 1
    wait = backoff(fails)
    # A revoked twin stays revoked (1.0.48): "failed" over it made is_dual true again, and the
    # revoked twin went out with the new main one.
    state = 'revoked' if row.get('alt_state') == 'revoked' else 'failed'
    store.db.update('certs', row['id'], {'alt_state': state, 'alt_error': str(why)[:2000],
                                         'alt_fails': fails, 'alt_next_try': now() + wait})
    return wait


def prune_versions(store, cert_id, current=None):
    """The oldest versions beyond certs_keep_versions dropped - the main ones and
    the twin's counted each on their own; the current ones always kept."""
    keep = max(1, int(E.CONFIG.get('certs_keep_versions') or 10))
    row = cert_get(store, cert_id) or {}
    mine = {int(row.get('version') or 0), int(row.get('alt_version') or 0)}
    if current is not None:
        mine.add(int(current))
    rows = store.db.rows('SELECT id, version, variant FROM cert_versions WHERE cert_id = ? '
                         'ORDER BY version DESC', (cert_id,))
    for variant in ('', 'alt'):
        some = [r for r in rows if (r.get('variant') or '') == variant]
        for r in some[keep:]:
            if r['version'] in mine:
                continue
            store.db.run('DELETE FROM cert_versions WHERE id = ?', (r['id'],))


def version_row(store, cert_id, version):
    return store.db.row('SELECT * FROM cert_versions WHERE cert_id = ? AND version = ?',
                        (cert_id, int(version)))


def version_public(r):
    return {k: r.get(k) for k in ('id', 'cert_id', 'version', 'serial', 'fingerprint',
                                  'not_before', 'not_after', 'issuer_dn', 'created', 'why',
                                  'by_who', 'revoked')} | {'has_key': bool(r.get('key_sealed')),
                                                           'variant': r.get('variant') or ''}


def bundle_of(row, version_row_=None, variant=None):
    """The certificate (or one of its versions) as a target gets it. A dual
    certificate's current one carries its twin as b.alt; `variant` 'alt' (or a
    version row of the twin) gives the twin itself, 'main' the main one alone."""
    from acmelib.certs import bundle as _bundle
    if version_row_ is None and variant in ('alt', 'main'):
        if variant == 'alt':
            alt = alt_view(row) if row.get('key_type_alt') or row.get('alt_cert_pem') else None
            if not alt:
                raise LookupError('%s has no twin (no second certificate)' % row['name'])
            return bundle_of(row, alt)
        return bundle_of(dict(row, key_type_alt='', alt_cert_pem=None))
    src = version_row_ or row
    version = src.get('version') or 0
    which = 'alt' if src.get('variant') == 'alt' else ''
    key = E.unseal_secret(src['key_sealed'], key_place(row['id'], version, which)) \
        if src.get('key_sealed') else None
    chain = chain_list(src.get('chain_pem'))
    b = _bundle.CertBundle(row['name'], src['cert_pem'], key, chain)
    b.variant_name = 'alt' if which else 'main'
    if version_row_ is None and is_dual(row):
        b.alt = bundle_of(row, alt_view(row))
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
    cls = row_class('target', t) if t else None
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
    # Its target switched off (1.0.23): said with the deployment, where the certificate is.
    trow = store.db.row('SELECT enabled FROM cert_targets WHERE name = ?', (row.get('target'),))
    out['target_off'] = bool(trow) and not int(trow.get('enabled') if trow.get('enabled')
                                               is not None else 1)
    return out


def backoff(fails):
    """How long to wait after the n-th failure in a row: 5 min, doubled each
    time, at most certs_retry_max_h."""
    cap = max(1, int(E.CONFIG.get('certs_retry_max_h') or 6)) * 3600
    return min(cap, 300 * (2 ** max(0, int(fails or 1) - 1)))


def settings_view():
    """The settings as a module may read them: no secret."""
    return {k: v for k, v in E.CONFIG.items() if k not in E.SECRET_KEYS}
