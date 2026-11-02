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
        csr_pending {B}, enabled {I}, key_type_alt {K}, alt_cert_pem {B}, alt_chain_pem {B},
        alt_key_sealed {B}, alt_serial {K}, alt_fingerprint {K}, alt_not_before {N},
        alt_not_after {N}, alt_issuer_dn {T}, alt_ari {T}, alt_version {I}, alt_state {K},
        alt_error {T}, alt_fails {I}, alt_next_try {N}, csr_given {B}, issuer_ref {T}, setup_due {I})'''),
    # Every certificate one of them has had, the current one too. A dual
    # certificate's twin (key_type_alt) has rows of its own, variant 'alt',
    # numbered in the same sequence as the main ones (variant '').
    ('cert_versions', '''CREATE TABLE IF NOT EXISTS cert_versions (
        id {ID}, cert_id {I} NOT NULL, version {I}, cert_pem {B}, chain_pem {B},
        key_sealed {B}, serial {K}, fingerprint {K}, not_before {N}, not_after {N},
        issuer_dn {T}, created {N}, why {K}, by_who {K}, variant {K}, revoked {N},
        UNIQUE (cert_id, version))'''),
    # A certificate authority of acme's own.
    ('cert_cas', '''CREATE TABLE IF NOT EXISTS cert_cas (
        id {ID}, name {K} NOT NULL UNIQUE, parent_id {I}, subject_dn {T}, key_type {K},
        cert_pem {B}, chain_pem {B}, key_sealed {B}, serial_next {I}, crl_number {I},
        crl_pem {B}, crl_at {N}, crl_days {I}, crl_url {T}, aia_url {T}, ocsp_url {T},
        days_default {I}, path_len {I}, name_constraints {T}, profile {T},
        not_before {N}, not_after {N}, fingerprint {K}, external {I}, disabled {I},
        note {T}, created {N}, created_by {K})'''),
    # What one of acme's authorities signed - for its CRL and its list; the certificate
    # itself (cert_pem) since 1.0.21, for Import from a source.
    ('cert_ca_issued', '''CREATE TABLE IF NOT EXISTS cert_ca_issued (
        id {ID}, ca_id {I} NOT NULL, serial {K} NOT NULL, subject_dn {T}, names {T},
        not_before {N}, not_after {N}, fingerprint {K}, cert_id {I}, revoked {N},
        reason {K}, created {N}, by_who {K}, cert_pem {B}, UNIQUE (ca_id, serial))'''),
    # Every certificate one of acme's authorities has had (its renewals with
    # the same key: same subject, same key identifier) - the current one too,
    # once it was renewed. No key here: the key is the authority's, in cert_cas.
    ('cert_ca_versions', '''CREATE TABLE IF NOT EXISTS cert_ca_versions (
        id {ID}, ca_id {I} NOT NULL, version {I}, cert_pem {B}, chain_pem {B}, serial {K},
        fingerprint {K}, not_before {N}, not_after {N}, path_len {I}, name_constraints {T},
        issuer_dn {T}, created {N}, why {K}, by_who {K}, UNIQUE (ca_id, version))'''),
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
    # Settings → DNS (acmelib/certs/dnssets.py): named sets of DNS servers, one
    # address a line in `servers`; protocol udp | tcp | dot. "The system's" is
    # built in and kept nowhere.
    ('dns_sets', '''CREATE TABLE IF NOT EXISTS dns_sets (
        id {ID}, name {K} NOT NULL UNIQUE, servers {T}, protocol {K}, tls_name {K},
        timeout_s {N}, note {T}, created {N}, created_by {K}, updated {N},
        updated_by {K})'''),
    # Which set a function of acme asks (validation, public, apis, targets, acme,
    # mail); a function not listed asks its default.
    ('dns_set_uses', '''CREATE TABLE IF NOT EXISTS dns_set_uses (
        id {ID}, purpose {K} NOT NULL UNIQUE, set_name {K}, updated {N}, updated_by {K})'''),
    # Settings → Owners and teams (acmelib/certs/teams.py, docs/teams.md): who a
    # certificate belongs to (certs.owner is a name of these), its members
    # (JSON [{who, rights}]: local:NAME, a directory user, group:NAME or a DN;
    # rights view | request | manage | approve) and whom to tell.
    ('cert_teams', '''CREATE TABLE IF NOT EXISTS cert_teams (
        id {ID}, name {K} NOT NULL UNIQUE, kind {K}, members {B}, contact_mail {T},
        contact_phone {K}, note {T}, created {N}, created_by {K}, updated {N},
        updated_by {K})'''),
    # The tags certificates and targets pick from (their `tags`: JSON names of these).
    ('cert_tags', '''CREATE TABLE IF NOT EXISTS cert_tags (
        id {ID}, name {K} NOT NULL UNIQUE, colour {K}, description {T}, created {N},
        created_by {K}, updated {N}, updated_by {K})'''),
    # Settings → Request profiles (acmelib/certs/reqprofiles.py, docs/request-profiles.md):
    # what may be asked for on the portal, everything but the names set beforehand -
    # the source, the validation, the names allowed, the key or a CSR, the subject,
    # renewal, approval, owner, tags and who may use it (config: JSON).
    ('cert_req_profiles', '''CREATE TABLE IF NOT EXISTS cert_req_profiles (
        id {ID}, name {K} NOT NULL UNIQUE, description {T}, enabled {I}, config {B},
        created {N}, created_by {K}, updated {N}, updated_by {K})'''),
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
    'CREATE INDEX IF NOT EXISTS cert_ca_versions_ca ON cert_ca_versions (ca_id, version)',
    'CREATE INDEX IF NOT EXISTS dns_records_name ON dns_records (name, rtype)',
]

# A dual certificate (docs/certificates.md "Dual certificates"): the main key
# type and a twin of the same names with another kind of key - ECDSA beside
# RSA - kept in the alt_* columns of the same row of certs. alt_version is the
# twin's version (in cert_versions, variant 'alt'), alt_state '' | 'ok' |
# 'failed' with alt_error, alt_fails and alt_next_try for its own retries;
# its key is sealed under 'certs:<id>:alt_key_sealed:<alt_version>'.
VARIANTS = ('main', 'alt')

# issuer_ref: the source's own id of a certificate imported from it (Certificates →
# Import from a source, acmelib/certs/onlineimport.py) - its order, its certificate ID
# - handed to the source at every renewal (CertRequest.ref), so that very order is
# reissued; kept up to date from what the source says it used (Issued.info['ref']).
# setup_due: 1 for a certificate imported from a source whose set-up (its validation,
# profile, renewal, targets - the steps of Add a certificate) has not been gone through
# yet; the wizard's Save (setup_done) clears it.

# The states of a certificate.
STATES = {
    'new': 'not issued yet',
    'held': 'added, not issued - Issue now issues it',
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
