# -*- coding: utf-8 -*-
"""
Let's Encrypt first: what a new installation starts with, so that the first
certificate needs nothing but its names.

    sources       "LetsEncrypt" (production) and "LetsEncrypt staging", kind acme
    validations   "This server HTTP-01" (http_local), and - once dns_zone is set -
                  "acme DNS server" (dns_builtin)

made the first time the daemon starts (or the command line opens the
database) with no source (no validation) at all. Each is made once only: a
flag in meta (certs:default:<what>) says it was, so one an administrator
deleted is never made again. A new certificate with no issuer said comes from
the default source (meta certs:default_issuer, else "LetsEncrypt") and, when
that is an ACME CA, is proved by the default validation ("This server
HTTP-01"). Every list has a default a person chooses (set_default): the
source, the validation, the target (offered first for a deployment) and the
authority (offered first for an own-CA source and for signing a CSR) - in
meta certs:default_issuer / _challenge / _target / _ca. The ACME account works without a contact e-mail; the pages and
`acme --acme-contact MAIL` ask for one where none is set.
"""
from __future__ import annotations

import json
import time

from acmelib import engine as E
from acmelib.certs import store as S

# Names a shell, a file and a device take (store.NAME_RE): no quotes, no
# brackets. An installation that has the names of before ("Let's Encrypt",
# "This server (HTTP-01)"...) has them renamed to these at its next start
# (names.migrate), with every reference.
LE = 'LetsEncrypt'
LE_STAGING = 'LetsEncrypt staging'
HTTP_LOCAL = 'This server HTTP-01'
DNS_OWN = 'acme DNS server'
FLAG = 'certs:default:'
BY = 'acme (first start)'

SOURCES = [('le', LE, 'acme', {'directory': 'letsencrypt', 'contacts': []},
            "Let's Encrypt, the free public CA: certificates of 90 days, renewed by themselves."),
           ('le_staging', LE_STAGING, 'acme', {'directory': 'letsencrypt-staging',
                                               'contacts': []},
            "Let's Encrypt's staging CA: for trying things out - its certificates are not "
            "trusted.")]
VALIDATIONS = [('http_local', HTTP_LOCAL, 'http_local', {},
                'HTTP-01 answered by this server on port 80: the names must point at acme.')]
DNS_VALIDATION = ('dns_builtin', DNS_OWN, 'dns_builtin', {},
                  'DNS-01 answered by acme\'s own DNS server: delegate _acme-challenge of the '
                  'names to it (wildcards too).')


def _flagged(store, what):
    return bool(store.get_meta(FLAG + what))


def _flag(store, what, words):
    store.set_meta(FLAG + what, json.dumps({'at': time.time(), 'node': E.node_name(),
                                            'said': words}))


def _make(store, table, name, kind, cfg, note):
    if store.db.row('SELECT id FROM %s WHERE name = ?' % table, (name,)):
        return False
    t = time.time()
    try:
        store.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(cfg),
                                'state': '{}', 'enabled': 1, 'note': note, 'created': t,
                                'created_by': BY, 'updated': t})
    except Exception:                                   # noqa: BLE001
        return False            # the other node made it the same moment
    return True


def _empty(store, table):
    return not int(store.db.value('SELECT COUNT(*) FROM %s' % table, (), 0) or 0)


def ensure(store):
    """What a new installation starts with (see the top). Returns the names made.
    Names an older version made unsafe are made safe first (names.migrate)."""
    try:
        from acmelib.certs import names as N
        N.migrate(store)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-names', 'making the names safe: %s' % e, 'warn', every=3600)
    made = []
    try:
        if not _flagged(store, 'sources'):
            if _empty(store, 'cert_issuers') and S.plugin_class('issuer', 'acme'):
                for _k, name, kind, cfg, note in SOURCES:
                    if _make(store, 'cert_issuers', name, kind, cfg, note):
                        made.append(name)
                store.set_meta('certs:default_issuer', LE)
            _flag(store, 'sources', ', '.join(made) or 'there were sources already')
        if not _flagged(store, 'validations'):
            got = []
            if _empty(store, 'cert_challenges') and S.plugin_class('challenge', 'http_local'):
                for _k, name, kind, cfg, note in VALIDATIONS:
                    if _make(store, 'cert_challenges', name, kind, cfg, note):
                        got.append(name)
                store.set_meta('certs:default_challenge', HTTP_LOCAL)
            made += got
            _flag(store, 'validations', ', '.join(got) or 'there were validations already')
        if not _flagged(store, 'dns') and str(E.CONFIG.get('dns_zone') or '').strip():
            _k, name, kind, cfg, note = DNS_VALIDATION
            if not store.db.row("SELECT id FROM cert_challenges WHERE kind = 'dns_builtin'") and \
                    S.plugin_class('challenge', kind) and \
                    _make(store, 'cert_challenges', name, kind, cfg, note):
                made.append(name)
            _flag(store, 'dns', name if name in made else 'there was one already')
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-defaults', 'the sources and validations a new installation starts '
                      'with could not be made: %s' % e, 'warn', every=3600)
        return made
    if made:
        store.add_event('certificates', 'ready to go: %s made (Let\'s Encrypt first)'
                        % ', '.join(made))
    return made


# ---------------------------------------------------------------------------
# The default of each list (Sources, Validation, Targets, Authorities)
# ---------------------------------------------------------------------------
# meta holds the name (an authority: its id). Never set (an installation from
# before, or one that had sources already): the source falls back to
# "LetsEncrypt" and the validation to "This server HTTP-01" where they are there.
# Set to '' by a person: there is none, and nothing is taken in its place.
META = {'issuer': 'certs:default_issuer', 'challenge': 'certs:default_challenge',
        'target': 'certs:default_target', 'ca': 'certs:default_ca'}
FALLBACK = {'issuer': LE, 'challenge': HTTP_LOCAL}
WORDS = {'issuer': 'source', 'challenge': 'validation', 'target': 'target',
         'ca': 'authority'}


def default_name(store, what):
    """The name (an authority: the id, as text) of the default, or '' - only
    of a row that is there."""
    raw = store.get_meta(META[what])
    if raw is None:
        raw = FALLBACK.get(what, '')
    raw = str(raw or '')
    if not raw:
        return ''
    if what == 'ca':
        try:
            ok = store.db.value('SELECT id FROM cert_cas WHERE id = ?', (int(raw),))
        except (TypeError, ValueError):
            ok = None
        return str(ok) if ok else ''
    return raw if S.plugin_row(store, what, raw) else ''


def _ca_usable(row):
    if not row:
        return 'there is no such authority'
    if row.get('disabled'):
        return 'the authority %s is switched off' % row['name']
    if not row.get('cert_pem'):
        return 'the authority %s has no certificate yet: it signs nothing' % row['name']
    if not row.get('key_sealed'):
        return 'the authority %s has no key here: it cannot sign' % row['name']
    try:
        if row.get('not_after') and float(row['not_after']) < time.time():
            return 'the authority %s has run out' % row['name']
    except (TypeError, ValueError):
        pass
    return ''


def set_default(store, what, ref, by):
    """The default made `ref` (a name; an authority: its id or name), or none
    with ''. Refused for a row that is not there or is switched off. Written
    to the events. Returns the name made the default ('' for none)."""
    ref = '' if ref is None else str(ref).strip()
    word = WORDS[what]
    if not ref:
        was = default_name(store, what)
        store.set_meta(META[what], '')
        store.add_event('certificates', 'no default %s any more%s (by %s)' % (
            word, (' - it was %s' % _shown(store, what, was)) if was else '', by), who=by)
        return ''
    if what == 'ca':
        row = None
        if ref.isdigit():
            row = store.db.row('SELECT * FROM cert_cas WHERE id = ?', (int(ref),))
        if not row:
            row = store.db.row('SELECT * FROM cert_cas WHERE name = ?', (ref,))
        if not row:
            raise LookupError('there is no authority %s' % ref)
        why = _ca_usable(row)
        if why:
            raise ValueError('%s - it cannot be the default' % why)
        store.set_meta(META[what], str(int(row['id'])))
        name = row['name']
    else:
        row = S.plugin_row(store, what, ref)
        if not row:
            raise LookupError('there is no %s %s' % (word, ref))
        if row.get('enabled') is not None and not int(row['enabled']):
            raise ValueError('the %s %s is switched off - it cannot be the default' % (
                word, row['name']))
        store.set_meta(META[what], row['name'])
        name = row['name']
    store.add_event('certificates', '%s is now the default %s (by %s)' % (name, word, by),
                    who=by)
    return name


def _shown(store, what, value):
    if what == 'ca' and str(value).isdigit():
        return str(store.db.value('SELECT name FROM cert_cas WHERE id = ?', (int(value),))
                   or value)
    return value


def forget(store, what, name_or_id):
    """A row deleted: no longer the default (nothing is put in its place)."""
    raw = store.get_meta(META[what])
    if raw is None and what in FALLBACK and str(name_or_id) == FALLBACK[what]:
        store.set_meta(META[what], '')
        return True
    if raw is not None and str(raw) == str(name_or_id) and raw != '':
        store.set_meta(META[what], '')
        return True
    return False


def renamed(store, what, old, new):
    """A row renamed: the default follows it."""
    raw = store.get_meta(META[what])
    if (raw is not None and raw == old) or (raw is None and FALLBACK.get(what) == old):
        store.set_meta(META[what], new)


def default_issuer(store):
    """The source a new certificate comes from when none is said, or None."""
    name = default_name(store, 'issuer')
    if name:
        row = S.plugin_row(store, 'issuer', name)
        if row and row.get('enabled', 1):
            return row
    return None


def default_challenge(store, issuer_row=None):
    """The validation of a new ACME certificate when none is said, or None."""
    if issuer_row is not None:
        cls = S.plugin_class('issuer', issuer_row.get('kind'))
        if cls is None or not getattr(cls, 'needs_challenge', False):
            return None
    name = default_name(store, 'challenge')
    if name:
        row = S.plugin_row(store, 'challenge', name)
        if row and row.get('enabled', 1):
            return row
    return None


def default_target(store):
    """The target a new deployment is offered first, or None."""
    name = default_name(store, 'target')
    if name:
        row = S.plugin_row(store, 'target', name)
        if row and row.get('enabled', 1):
            return row
    return None


def default_ca(store):
    """The authority offered first (a new own-CA source, signing a CSR), or None."""
    ident = default_name(store, 'ca')
    if ident:
        row = store.db.row('SELECT * FROM cert_cas WHERE id = ?', (int(ident),))
        if row and not _ca_usable(row):
            return row
    return None


def contact_missing(store):
    """The ACME sources with no contact e-mail (asked for on the pages and the CLI)."""
    out = []
    for r in store.db.rows("SELECT id, name, config, enabled FROM cert_issuers WHERE kind = 'acme' "
                           "ORDER BY name"):
        cfg = S.jload(r.get('config'), {}) or {}
        c = cfg.get('contacts')
        if not c or (isinstance(c, list) and not [x for x in c if str(x).strip()]):
            out.append(r['name'])
    return out
