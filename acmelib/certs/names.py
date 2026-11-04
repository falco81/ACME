# -*- coding: utf-8 -*-
"""
Names that are safe: every source, validation, target, authority and
certificate is called by a name store.NAME_RE takes (letters, digits, spaces
and . _ @ + -, starting with a letter or a digit) - names reach shell
commands, files and devices, so never a quote or a bracket.

An older version made "Let's Encrypt", "Let's Encrypt (staging)", "This
server (HTTP-01)" and "acme's DNS server" itself, and took names like them
from a file's CN. migrate(store) - run at every start, before the first
start's defaults (defaults.ensure), and by the command line - renames each
such row to a safe name (the preferred new name of the four, else
store.safe_name(old), unique in its table) and, in the same transaction,
every place that refers to it by name:

    a source        certs.issuer, meta certs:default_issuer, the setting
                    portal_cert_issuers, its module's kept values (meta certs:kv:issuer:NAME:...)
    a validation    certs.challenge, the values of certs.challenge_map, meta
                    certs:default_challenge, the setting portal_cert_challenge, its kept values
    a target        cert_deploys.target, meta certs:default_target, its kept values
    an authority    the settings of the modules that name it (internal_ca's "ca" - every
                    field with options_from 'cas')
    any of them     the settings of every module whose field names that family
                    (options_from sources / issuers, validations / challenges, targets,
                    cas, certs) and holds the old name

One event says what was renamed. Nothing is done when every name is safe.
"""
from __future__ import annotations

import json

from acmelib import engine as E
from acmelib.certs import store as S

PREFERRED = {"Let's Encrypt": 'LetsEncrypt',
             "Let's Encrypt (staging)": 'LetsEncrypt staging',
             'This server (HTTP-01)': 'This server HTTP-01',
             "acme's DNS server": 'acme DNS server'}
TABLES = (('cert_issuers', 'issuer'), ('cert_challenges', 'challenge'),
          ('cert_targets', 'target'), ('cert_cas', 'ca'), ('certs', 'cert'))
WORDS = {'issuer': 'source', 'challenge': 'validation', 'target': 'target', 'ca': 'authority',
         'cert': 'certificate'}
# options_from of a module's field -> the family whose names it holds
OPTIONS_OF = {'sources': 'issuer', 'issuers': 'issuer', 'validations': 'challenge',
              'challenges': 'challenge', 'targets': 'target', 'cas': 'ca', 'certs': 'cert',
              'dns_writers': 'challenge'}
KV_PREFIX = 'certs:kv:'


def bad_names(store):
    """[(table, family, id, name)] of every row whose name is not safe."""
    out = []
    for table, fam in TABLES:
        for r in store.db.rows('SELECT id, name FROM %s ORDER BY id' % table):
            if not S.NAME_RE.match(str(r['name'] or '')):
                out.append((table, fam, int(r['id']), str(r['name'] or '')))
    return out


class _Tx(object):
    """One transaction on the main connection, as a copy put back takes it."""
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.lock = self.db.lock
        self.lock.acquire()
        try:
            if self.db.conn is None:
                self.db.connect()
            self.db.run('START TRANSACTION' if self.db.engine == 'mariadb' else 'BEGIN')
            self.db.in_tx = True
        except BaseException:
            self.lock.release()
            raise
        return self

    def __exit__(self, kind, value, tb):
        try:
            self.db.in_tx = False
            if kind is None:
                self.db.run('COMMIT')
            else:
                try:
                    self.db.run('ROLLBACK')
                except Exception:                       # noqa: BLE001
                    pass
        finally:
            self.lock.release()
        return False


def _new_name(old, taken):
    want = PREFERRED.get(old)
    if want and want not in taken:
        return want
    return S.safe_name(old, taken)


def _list_setting(store, key, renames):
    """A setting holding names, comma between them: each one renamed."""
    raw = E.CONFIG.get(key)
    saved = store.settings_saved()
    if key in saved:
        raw = saved[key]
    if not raw or not isinstance(raw, str):
        return False
    items = [x.strip() for x in raw.split(',')]
    new = [renames.get(x, x) for x in items]
    if new == items:
        return False
    value = ', '.join(x for x in new if x)
    store.save_setting(key, value, 'acme (names made safe)')
    E.CONFIG[key] = value
    return True


def _configs(store, fam, old, new):
    """Every module's settings whose field names a row of `fam` and holds `old`."""
    changed = 0
    for table, family in (('cert_issuers', 'issuer'), ('cert_challenges', 'challenge'),
                          ('cert_targets', 'target')):
        for r in store.db.rows('SELECT id, kind, config FROM %s' % table):
            cls = S.row_class(family, r)
            keys = [f['key'] for f in (getattr(cls, 'fields', None) or [])
                    if OPTIONS_OF.get(f.get('options_from')) == fam]
            if not keys:
                continue
            cfg = S.jload(r.get('config'), {}) or {}
            hit = False
            for k in keys:
                v = cfg.get(k)
                if v == old:
                    cfg[k] = new
                    hit = True
                elif isinstance(v, list) and old in v:
                    cfg[k] = [new if x == old else x for x in v]
                    hit = True
            if hit:
                store.db.update(table, r['id'], {'config': json.dumps(cfg)})
                changed += 1
    return changed


def _kv(store, fam, old, new):
    for r in store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?',
                           ('%s%s:%s:%%' % (KV_PREFIX, fam, old),)):
        if not r['k'].startswith('%s%s:%s:' % (KV_PREFIX, fam, old)):
            continue                    # LIKE's "_" and case: another one's (1.0.44)
        tail = r['k'][len('%s%s:%s:' % (KV_PREFIX, fam, old)):]
        store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
        store.set_meta('%s%s:%s:%s' % (KV_PREFIX, fam, new, tail), r['v'])


def _references(store, fam, old, new):
    db = store.db
    if fam == 'issuer':
        db.run('UPDATE certs SET issuer = ? WHERE issuer = ?', (new, old))
    elif fam == 'challenge':
        db.run('UPDATE certs SET challenge = ? WHERE challenge = ?', (new, old))
        for r in db.rows('SELECT id, challenge_map FROM certs WHERE challenge_map LIKE ?',
                         ('%' + json.dumps(old)[1:-1] + '%',)):
            cmap = S.jload(r['challenge_map'], {}) or {}
            if old in cmap.values():
                cmap = {k: (new if v == old else v) for k, v in cmap.items()}
                db.update('certs', r['id'], {'challenge_map': json.dumps(cmap)})
    elif fam == 'target':
        db.run('UPDATE cert_deploys SET target = ? WHERE target = ?', (new, old))
    meta = {'issuer': 'certs:default_issuer', 'challenge': 'certs:default_challenge',
            'target': 'certs:default_target'}.get(fam)
    if meta and store.get_meta(meta) == old:
        store.set_meta(meta, new)
    if fam in ('issuer', 'challenge', 'target'):
        _kv(store, fam, old, new)
    _configs(store, fam, old, new)


def migrate(store, by='acme (names made safe)'):
    """Every unsafe name made safe, with what refers to it. Returns
    [(family, old, new)]. Never raises: a failure is logged and nothing of
    it is kept (one transaction)."""
    try:
        todo = bad_names(store)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-names', 'the names could not be looked at: %s' % e, 'warn',
                      every=3600)
        return []
    if not todo:
        return []
    done = []
    try:
        with _Tx(store.db):
            renames = {}
            for table, fam, ident, old in todo:
                taken = {str(r['name']) for r in store.db.rows('SELECT name FROM %s' % table)}
                taken.discard(old)
                new = _new_name(old, taken)
                store.db.run('UPDATE %s SET name = ? WHERE id = ?' % table, (new, ident))
                _references(store, fam, old, new)
                renames.setdefault(fam, {})[old] = new
                done.append((fam, old, new))
            if renames.get('issuer'):
                _list_setting(store, 'portal_cert_issuers', renames['issuer'])
            if renames.get('challenge'):
                _list_setting(store, 'portal_cert_challenge', renames['challenge'])
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-names', 'the unsafe names could not be renamed: %s' % e, 'warn',
                      every=3600)
        return []
    store.add_event('certificates', 'names made safe (letters, digits, spaces and . _ @ + - '
                    'only - no quotes, no brackets): %s' % '; '.join(
                        '%s "%s" is now "%s"' % (WORDS[f], o, n) for f, o, n in done), 'warn',
                    who=by)
    return done


def check_now(store):
    """For the tests and the command line: what migrate() would rename."""
    out = []
    for table, fam, _i, old in bad_names(store):
        taken = {str(r['name']) for r in store.db.rows('SELECT name FROM %s' % table)}
        taken.discard(old)
        out.append((fam, old, _new_name(old, taken)))
    return out

