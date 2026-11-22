# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Periodic reports and the teams' digests (1.0.140, docs/reports.md, docs/teams.md)
# ---------------------------------------------------------------------------
# Their tables into SCHEMA (made on SQLite, MariaDB and PostgreSQL alike, in every backup and
# replicated as every other table), the definitions into the configuration's export, and their
# command line. The work itself is in acmelib/certs/reports.py and digest.py, imported only
# when it is needed; nothing is made or sent until a report is defined or a team's digest is
# switched on.

_RP_SCHEMA = [
    # Settings → Reports: one report defined - its kind, scope (teams: JSON names, [] every
    # team), formats (JSON ["csv", "pdf"]), schedule (JSON {every off|weekly|monthly, day,
    # hour, since}), recipients (addresses), language, how many runs are kept, its options.
    ('cert_reports', '''CREATE TABLE IF NOT EXISTS cert_reports (
        id {ID}, name {K} NOT NULL UNIQUE, kind {K}, teams {T}, formats {T}, schedule {T},
        recipients {T}, lang {K}, keep {I}, options {T}, enabled {I}, note {T}, created {N},
        created_by {K}, updated {N}, updated_by {K}, last_run {N}, last_ok {N},
        last_said {T})'''),
    # One run of a report: when, by whom, how many rows, whether it was mailed and to whom,
    # and its files (JSON [{format, filename, mime, size, data_b64}]) - the newest `keep`.
    ('cert_report_runs', '''CREATE TABLE IF NOT EXISTS cert_report_runs (
        id {ID}, report {K}, report_id {I}, ts {N}, by_who {K}, kind {K}, rows {I}, ok {I},
        said {T}, sent_to {T}, took_ms {I}, scope {T}, files {B})'''),
]
for _rp_name, _rp_ddl in _RP_SCHEMA:
    if _rp_name not in TABLES:
        SCHEMA.append((_rp_name, _rp_ddl))
        TABLES.append(_rp_name)
_RP_IX = 'CREATE INDEX IF NOT EXISTS cert_report_runs_r ON cert_report_runs (report_id, ts)'
if _RP_IX not in INDEXES:
    INDEXES.append(_RP_IX)
del _rp_name, _rp_ddl, _RP_IX

# The definitions are configuration (Export and import of the configuration); the runs are
# what happened - kept in the database's backups and replicated, not in that file.
if 'cert_reports' not in CERT_CARRY_TABLES:
    CERT_CARRY_TABLES.append('cert_reports')
# A run's files come by themselves, also while a backup's copy is made.
if 'cert_report_runs' not in RB_GROWING:
    RB_GROWING.append('cert_report_runs')


@_certs_hook('cli_args')
def reports_cli_args(parser):
    certs_mod('reports_cli').add_args(parser)


@_certs_hook('cli_run')
def reports_cli_run(args):
    return certs_mod('reports_cli').run(args)
