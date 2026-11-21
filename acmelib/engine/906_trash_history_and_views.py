# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The trash, the history of every object and the saved views (1.0.138)
# ---------------------------------------------------------------------------
# acmelib/certs/history.py, docs/history-and-trash.md. Three tables of their own -
# made, given new columns, backed up and replicated between the nodes as every other
# (SCHEMA); the history is a log (LOG_TABLES): a copy put back without its logs leaves
# it as it is here. Two settings on Settings → Trash and history.

_HT_SCHEMA = [
    # Every change of a setting of an object (a target, a deployment, a team...): who, when,
    # from where, through which route, its settings before (was_v) and after (now_v) - a secret
    # as it was kept, sealed (only "changed" is ever shown). No column is a word MariaDB keeps.
    ('obj_history', '''CREATE TABLE IF NOT EXISTS obj_history (
        id {ID}, ts {N}, otable {K}, otype {K}, oid {I}, oname {K}, action {K}, who {K},
        ip {K}, via {K}, note {T}, owner {K}, was_v {B}, now_v {B}, fields {T},
        batch {K})'''),
    # What was deleted, kept for history_trash_days: the row as it was (row_v: its secrets sealed
    # as they were; a certificate without its key and certificates), what went with it under it.
    ('obj_trash', '''CREATE TABLE IF NOT EXISTS obj_trash (
        id {ID}, ts {N}, otable {K}, otype {K}, oid {I}, oname {K}, owner {K}, who {K},
        ip {K}, via {K}, parent {I}, batch {K}, row_v {B}, meta {B}, detail {T},
        expires {N})'''),
    # A table's filters, sort and columns under a name: one person's, a team's or everybody's.
    ('saved_views', '''CREATE TABLE IF NOT EXISTS saved_views (
        id {ID}, tbl {K} NOT NULL, name {K} NOT NULL, scope {K}, team {K}, owner_user {K},
        state {B}, created {N}, created_by {K}, updated {N}, updated_by {K})'''),
]
for _ht_name, _ht_ddl in _HT_SCHEMA:
    if _ht_name not in TABLES:
        SCHEMA.append((_ht_name, _ht_ddl))
        TABLES.append(_ht_name)
for _ht_ix in ('CREATE INDEX IF NOT EXISTS obj_history_obj ON obj_history (otable, oid, ts)',
               'CREATE INDEX IF NOT EXISTS obj_history_ts ON obj_history (ts)',
               'CREATE INDEX IF NOT EXISTS obj_trash_ts ON obj_trash (ts)',
               'CREATE INDEX IF NOT EXISTS saved_views_tbl ON saved_views (tbl)'):
    if _ht_ix not in INDEXES:
        INDEXES.append(_ht_ix)
del _ht_name, _ht_ddl, _ht_ix
if 'obj_history' not in LOG_TABLES:
    LOG_TABLES.append('obj_history')

for _ht_k, _ht_v in {'history_trash_days': 30, 'history_keep_days': 365}.items():
    DEFAULTS.setdefault(_ht_k, _ht_v)
    CONFIG.setdefault(_ht_k, _ht_v)
    FILE_CONFIG.setdefault(_ht_k, _ht_v)
del _ht_k, _ht_v
NAMES.update({'history_trash_days': 'Keep what was deleted (days)',
              'history_keep_days': 'Keep the history of changes (days)'})
SAYS.update({
    'history_trash_days': 'A target, deployment, test, source, validation, request profile, '
                          'owner, role, tag, DNS set or certificate deleted on the pages goes '
                          'to the trash below for this many days and can be restored - its '
                          'secrets sealed as they were. 0: nothing is kept, deleted is gone '
                          '(as before).',
    'history_keep_days': 'Every change of those objects is written down - who, when, from '
                         'where and what changed (a secret only as "changed") - and kept this '
                         'many days; each object\'s History shows it and restores a version. '
                         '0: no history is written.',
})
TUNABLE.update({'history_trash_days': (0, 3650), 'history_keep_days': (0, 3650)})
PANES['trash'] = ['history_trash_days', 'history_keep_days']


@hook('daemon_start')
def history_daemon_start(daemon):
    _importlib.import_module('acmelib.certs.api_history')     # its routes
    _importlib.import_module('acmelib.certs.history').start(daemon)


@hook('daemon_stop')
def history_daemon_stop(daemon):
    if 'acmelib.certs.history' in sys.modules:
        sys.modules['acmelib.certs.history'].stop(daemon)
