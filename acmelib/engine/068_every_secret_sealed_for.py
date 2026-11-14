# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Every secret sealed for its place (1.0.102)
# ---------------------------------------------------------------------------
# A secret is sealed with the key of this installation and, since otp 1.0.13x, for the place it
# is kept in (sealed:2:, its bind): opened anywhere else it gives nothing. The settings and the
# directories' passwords were still sealed without a place, and a value never sealed was given
# back as it was - so somebody who could write the database without holding secrets.key (what
# the guard against writes is for) copied the sealed proxy password into a module's secret
# field pointed at a server of their own, or wrote a key they knew, in clear, over a
# certificate's. Once, at the first start where every node of the cluster runs 1.0.102, every
# secret kept here is sealed again for its place - the settings for their names, the
# directories' passwords for their rows, the columns of SCHEMA and the modules' own - and
# marked done (in the database and in this node's file); from then on a value sealed without
# a place, or in clear, is refused wherever a place is asked for. A backup or a copy put back
# (older ones hold the old forms) is sealed so again at once.


def _seal_again(value, bind):
    """(the value sealed for `bind`, how it was: 'v1' or 'clear'), or (None, 'lost') for one
    that does not open with the key here, or (None, '') for one that needs nothing."""
    if not isinstance(value, str) or not value or value.startswith(SEALED2):
        return None, ''
    if value.startswith(SEALED):
        plain = unseal_secret(value)
        if plain is None:
            return None, 'lost'
        return seal_secret(plain, bind), 'v1'
    return seal_secret(value, bind), 'clear'


def _seal_bound_note(store):
    """The mark that it is done: in the database (signed with the guard on) and this node's."""
    try:
        if not store.get_meta(SEAL_BOUND_MARK):
            store.set_meta(SEAL_BOUND_MARK, json.dumps({'at': time.time(), 'node': node_name(),
                                                        'version': __version__}))
    except Exception as e:                              # noqa: BLE001
        log('the mark that every secret is sealed for its place could not be written into the '
            'database: %s' % e, 'warn')
    try:
        path = seal_bound_path()
        if not path.exists():
            write_replacing(path, '%s %s\n' % (__version__, time.strftime('%Y-%m-%d %H:%M:%S')),
                            0o600)
    except Exception as e:                              # noqa: BLE001
        log('the mark that every secret is sealed for its place could not be written to %s: %s'
            % (seal_bound_path(), e), 'warn')
    seal_bound_forget()


def seal_bind_all(store, force=False, why='the upgrade to 1.0.102'):
    """Every secret kept here sealed for its place, once: {what: how many} - None where it is
    done already (or cannot be done yet: a node of the cluster still on an older version, no
    key). `force` (a backup or copy put back): again, whatever the marks say."""
    db = store.db
    if not force and seal_bound(db, fresh=True):
        _seal_bound_note(store)                     # the other mark too (a node of a cluster)
        return None
    # Not while a node of the cluster runs an older version: it opens the settings sealed
    # without a place only. A node that did it already does it again after a copy put back.
    if not (force and seal_bound_path().exists()) and not cluster_runs_at_least(store, '1.0.102'):
        return None                                 # tried again at the next tick
    if not sealing_key():
        return None
    said = collections.Counter()

    def count(how, what):
        if how:
            said['%s %s' % (what, how)] += 1
    # With the guard on, only what acme signed - not what was written past it; a copy put back
    # is taken whole (it is signed as this node's word just after).
    guard = dbguard_on() and not force
    # The settings, for their names.
    for r in db.rows('SELECT k, v, by_who FROM settings'):
        base = str(r['k']).split('@', 1)[0]
        if base not in SEALED_KEYS:
            continue
        try:
            value = json.loads(r['v'])
        except (TypeError, ValueError):
            continue
        if not isinstance(value, str) or not value or value.startswith(SEALED2):
            continue
        if guard and dbguard_setting_kept(r['k']) and not dbguard_ok(db, 's', r['k'], r['v'],
                                                                      quiet=True):
            count('refused (not signed)', 'setting')
            continue
        new, how = _seal_again(value, setting_bind(base))
        count(how, 'setting')
        if new:
            store.save_setting(r['k'], new, by=r.get('by_who') or '')
    # The directories' passwords, for their rows.
    for r in db.rows('SELECT id, name, bind_pw FROM directories'):
        if guard and not dbguard_directory_ok(db, r['name']):
            if r.get('bind_pw') and not str(r['bind_pw']).startswith(SEALED2):
                count('refused (not signed)', 'directory password')
            continue
        new, how = _seal_again(r.get('bind_pw'), seal_bind('directories', r, 'bind_pw'))
        count(how, 'directory password')
        if new:
            db.update('directories', r['id'], {'bind_pw': new})
            if guard:
                dbguard_directory_sign(db, r['name'])
    try:
        store._dirs = None
    except Exception:                                   # noqa: BLE001
        pass
    # The columns of SCHEMA ending in _sealed, each under its bind (the modules' own too).
    tables = set(db.tables())
    for table, col in sealed_columns():
        if table in ('settings', 'directories') or table not in tables:
            continue
        rows = db.rows("SELECT * FROM %s WHERE %s IS NOT NULL AND %s <> '' AND %s NOT LIKE "
                       "'sealed:2:%%'" % (table, col, col, col))
        for r in rows:
            new, how = _seal_again(r.get(col), seal_bind(table, r, col))
            count(how, '%s.%s' % (table, col))
            if new:
                db.update(table, r['id'], {col: new})
    # What a module keeps inside a column of its own (its settings as JSON, its state).
    for fn in HOOKS.get('seal_bind_all', []):
        try:
            for k, n in (fn(store) or {}).items():
                said[k] += n
        except Exception as e:                          # noqa: BLE001
            log('a module\'s secrets could not be sealed for their places: %s' % e, 'warn')
            return None                                 # not marked: tried again
    _seal_bound_note(store)
    done = {k: n for k, n in said.items() if n}
    if done:
        lost = sum(n for k, n in done.items() if k.endswith(' lost'))
        log('every secret is sealed for its place now (%s): %s' % (
            why, ', '.join('%s %d' % kv for kv in sorted(done.items()))),
            'warn' if lost else 'info')
        try:
            store.add_event('security', 'the secrets kept here are sealed for their places now '
                            '(%s): %s' % (why, ', '.join('%s %d' % kv for kv in
                                                         sorted(done.items()))),
                            'warn' if lost else 'info')
        except Exception:                               # noqa: BLE001
            pass
    return done
