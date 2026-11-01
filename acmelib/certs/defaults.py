# -*- coding: utf-8 -*-
"""
Let's Encrypt first: what a new installation starts with, so that the first
certificate needs nothing but its names.

    sources       "Let's Encrypt" (production) and "Let's Encrypt (staging)", kind acme
    validations   "This server (HTTP-01)" (http_local), and - once dns_zone is set -
                  "acme's DNS server" (dns_builtin)

made the first time the daemon starts (or the command line opens the
database) with no source (no validation) at all. Each is made once only: a
flag in meta (certs:default:<what>) says it was, so one an administrator
deleted is never made again. A new certificate with no issuer said comes from
the default source (meta certs:default_issuer, else "Let's Encrypt") and, when
that is an ACME CA, is proved by the default validation ("This server
(HTTP-01)"). The ACME account works without a contact e-mail; the pages and
`acme --acme-contact MAIL` ask for one where none is set.
"""
from __future__ import annotations

import json
import time

from acmelib import engine as E
from acmelib.certs import store as S

LE = "Let's Encrypt"
LE_STAGING = "Let's Encrypt (staging)"
HTTP_LOCAL = 'This server (HTTP-01)'
DNS_OWN = "acme's DNS server"
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
    """What a new installation starts with (see the top). Returns the names made."""
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


def default_issuer(store):
    """The source a new certificate comes from when none is said, or None."""
    for name in (store.get_meta('certs:default_issuer'), LE):
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
    for name in (store.get_meta('certs:default_challenge'), HTTP_LOCAL):
        if name:
            row = S.plugin_row(store, 'challenge', name)
            if row and row.get('enabled', 1):
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
