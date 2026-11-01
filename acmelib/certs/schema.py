# -*- coding: utf-8 -*-
"""
The tables of the certificate manager, in the engine's own notation:
{ID} the row's number, {K} a short text that is looked up by (a name, a state),
{T} text, {B} a big text (PEM, JSON), {N} a number of seconds (epoch, REAL),
{I} an integer. The engine makes them on SQLite, MariaDB and PostgreSQL alike,
adds a column a later version declares, backs them up, exports them and
replicates them between the nodes of a cluster.

JSON is kept as text. A secret is kept sealed (engine seal_secret, bound to
'<table>:<id>:<field>'), never in the clear.
"""

SCHEMA = [
    # A certificate acme keeps - one row however often it is renewed.
    ('certs', '''CREATE TABLE IF NOT EXISTS certs (
        id {ID}, name {K} NOT NULL UNIQUE, cn {K}, names {T}, key_type {K},
        issuer {K}, challenge {K}, challenge_map {T}, auto_renew {I}, renew_days {I},
        reuse_key {I}, profile {T}, cert_pem {B}, chain_pem {B}, key_sealed {B},
        serial {K}, fingerprint {K}, not_before {N}, not_after {N}, issuer_dn {T},
        subject_dn {T}, source {K}, state {K}, state_at {N}, last_try {N}, last_ok {N},
        last_error {T}, next_try {N}, fails {I}, ari {T}, version {I}, tags {T},
        note {T}, owner {K}, created {N}, created_by {K}, updated {N}, updated_by {K},
        csr_pending {B}, enabled {I})'''),
    # Every certificate one of them has had, the current one too.
    ('cert_versions', '''CREATE TABLE IF NOT EXISTS cert_versions (
        id {ID}, cert_id {I} NOT NULL, version {I}, cert_pem {B}, chain_pem {B},
        key_sealed {B}, serial {K}, fingerprint {K}, not_before {N}, not_after {N},
        issuer_dn {T}, created {N}, why {K}, by_who {K}, revoked {N}, UNIQUE (cert_id, version))'''),
    # A certificate authority of acme's own.
    ('cert_cas', '''CREATE TABLE IF NOT EXISTS cert_cas (
        id {ID}, name {K} NOT NULL UNIQUE, parent_id {I}, subject_dn {T}, key_type {K},
        cert_pem {B}, chain_pem {B}, key_sealed {B}, serial_next {I}, crl_number {I},
        crl_pem {B}, crl_at {N}, crl_days {I}, crl_url {T}, aia_url {T}, ocsp_url {T},
        days_default {I}, path_len {I}, name_constraints {T}, profile {T},
        not_before {N}, not_after {N}, fingerprint {K}, external {I}, disabled {I},
        note {T}, created {N}, created_by {K})'''),
    # What one of acme's authorities signed - for its CRL and its list.
    ('cert_ca_issued', '''CREATE TABLE IF NOT EXISTS cert_ca_issued (
        id {ID}, ca_id {I} NOT NULL, serial {K} NOT NULL, subject_dn {T}, names {T},
        not_before {N}, not_after {N}, fingerprint {K}, cert_id {I}, revoked {N},
        reason {K}, created {N}, by_who {K}, UNIQUE (ca_id, serial))'''),
    # Where certificates come from (a module of acmelib/plugins/issuers).
    ('cert_issuers', '''CREATE TABLE IF NOT EXISTS cert_issuers (
        id {ID}, name {K} NOT NULL UNIQUE, kind {K}, config {B}, state {B}, enabled {I},
        note {T}, created {N}, created_by {K}, updated {N}, last_ok {N}, last_error {T})'''),
    # How names are proved (acmelib/plugins/challenges).
    ('cert_challenges', '''CREATE TABLE IF NOT EXISTS cert_challenges (
        id {ID}, name {K} NOT NULL UNIQUE, kind {K}, config {B}, state {B}, enabled {I},
        note {T}, created {N}, created_by {K}, updated {N}, last_ok {N}, last_error {T})'''),
    # Where certificates go (acmelib/plugins/targets).
    ('cert_targets', '''CREATE TABLE IF NOT EXISTS cert_targets (
        id {ID}, name {K} NOT NULL UNIQUE, kind {K}, config {B}, state {B}, enabled {I},
        note {T}, created {N}, created_by {K}, updated {N}, last_ok {N}, last_error {T},
        tags {T})'''),
    # One certificate on one target.
    ('cert_deploys', '''CREATE TABLE IF NOT EXISTS cert_deploys (
        id {ID}, cert_id {I} NOT NULL, target {K} NOT NULL, options {B}, enabled {I},
        position {I}, state {K}, deployed_version {I}, deployed_fp {K}, last_try {N},
        last_ok {N}, last_error {T}, fails {I}, next_try {N}, note {T}, created {N},
        created_by {K})'''),
    # One piece of work, every step of it.
    ('cert_jobs', '''CREATE TABLE IF NOT EXISTS cert_jobs (
        id {ID}, ts {N}, kind {K}, cert_id {I}, deploy_id {I}, target {K}, node {K},
        state {K}, ok {I}, finished {N}, took_ms {I}, steps {B}, by_who {K}, said {T},
        version {I})'''),
    # What acme's own DNS server answers.
    ('dns_records', '''CREATE TABLE IF NOT EXISTS dns_records (
        id {ID}, name {K} NOT NULL, rtype {K} NOT NULL, value {T}, ttl {I}, expires {N},
        created {N}, owner {K}, note {T})'''),
]

INDEXES = [
    'CREATE INDEX IF NOT EXISTS certs_not_after ON certs (not_after)',
    'CREATE INDEX IF NOT EXISTS certs_state ON certs (state, next_try)',
    'CREATE INDEX IF NOT EXISTS cert_versions_cert ON cert_versions (cert_id, version)',
    'CREATE INDEX IF NOT EXISTS cert_deploys_cert ON cert_deploys (cert_id)',
    'CREATE INDEX IF NOT EXISTS cert_deploys_target ON cert_deploys (target)',
    'CREATE INDEX IF NOT EXISTS cert_jobs_ts ON cert_jobs (ts)',
    'CREATE INDEX IF NOT EXISTS cert_jobs_cert ON cert_jobs (cert_id, ts)',
    'CREATE INDEX IF NOT EXISTS cert_ca_issued_ca ON cert_ca_issued (ca_id, serial)',
    'CREATE INDEX IF NOT EXISTS dns_records_name ON dns_records (name, rtype)',
]

# The states of a certificate.
STATES = {
    'new': 'not issued yet',
    'ok': 'valid',
    'due': 'due for renewal',
    'renewing': 'being renewed',
    'failed': 'the last renewal failed',
    'expired': 'expired',
    'pending': 'waiting for a certificate from outside (a CSR given out)',
    'revoked': 'revoked',
    'disabled': 'switched off',
}

KEY_TYPES = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096', 'ed25519')
