# How acme is put together

```
                       ┌──────────────────────────── acme daemon (user acme) ───────────────────────────┐
 browser ─HTTPS─▶ nginx│  engine (acmelib/engine)          certificate manager (acmelib/certs)           │
            │          │  settings · database · sealing    store · PKI (openssl) · own CAs               │
            ▼          │  cluster (HA, VIP) · mail · SMS   scheduler: renew ▶ deploy, one node at a time │
  php-fpm "acme" ─────▶│  backups · firewall · network     jobs (every step written down)                │
  (relays only)        │  time · updates · API · CLI       DNS server (UDP/TCP 53) for DNS-01            │
                       │  console · alerts · SIEM · SNMP   modules (acmelib/plugins):                    │
                       │                                     issuers     ACME/Let's Encrypt, own CA,     │
                       │                                                 self-signed, MS AD CS, SCEP     │
                       │                                     challenges  DNS-01 (own DNS, RFC 2136,      │
                       │                                                 Cloudflare, …), HTTP-01 (here,  │
                       │                                                 nginx over SSH)                 │
                       │                                     targets     Linux over SSH, F5, NetScaler,  │
                       │                                                 MikroTik, FortiGate, …          │
                       └─────────────────────────────────────────────────────────────────────────────────┘
```

## The layout

| Where | What |
|---|---|
| `acme.py` | the launcher - `acme` on the command line, `acme --daemon` for systemd |
| `acmelib/__init__.py` | the version, in one place |
| `acmelib/engine/NNN_*.py` | the platform, in numbered parts run in order into one namespace (`acmelib/engine/__init__.py`) - each part sees every other's names, as when they were one file. `tools/lint-engine.py` checks them that way. |
| `acmelib/engine/900_certificates.py` | the glue: the certificate manager's tables, settings, API routes, command line and console put into the engine through `HOOKS` |
| `acmelib/certs/` | the certificate manager, a package of ordinary modules |
| `acmelib/plugins/base.py` | the contract of a module: `Issuer`, `Challenge`, `Target`, `Context`, the `Registry` |
| `acmelib/plugins/{issuers,challenges,targets}/*.py` | the modules, one file each, found by themselves |
| `/etc/acme/plugins/{issuers,challenges,targets}/*.py` | your own modules, kept across upgrades; one with the same `kind` wins over the built-in |
| `acmelib/vendor/` | colorama, carried so nothing comes from pip |
| `web/` | the pages (PHP 8.3) - they relay to the API and decide nothing |
| `deploy/` | systemd, nginx, php-fpm, logrotate, the upgrade helper, the MIB |
| `tools/release.py` | builds a release: `release/acme-X.Y.Z.tar.gz`, the last ten kept |

## The engine's hooks

`HOOKS` (in `acmelib/engine/000_start.py`) is where a module plugs in without
the engine knowing it: `daemon_start(daemon)`, `daemon_stop(daemon)`,
`cli_args(parser)`, `cli_run(args) -> exit code | None`,
`console_main(console) -> [(key, words, fn)]`, `status(store, pal) -> [lines]`,
`alerts(store)`, `report(store, since)`, `metrics(store) -> [(name, help, type,
samples)]`, `snmp(store) -> [(oid under ACME-MIB, kind, value)]`,
`event_fields(kind, words, level) -> {field: value}` (what an event is about,
for isemon and the SIEM; or said with `event_with(**fields)` around
`store.add_event`), `carry_tables()`, `firewall`.
API endpoints are added with `@route('GET', '/api/...')` anywhere.

## The certificate manager

### Tables (added to the engine's `SCHEMA`, so SQLite, MariaDB and PostgreSQL alike, in every backup, export and replication)

| Table | One row is |
|---|---|
| `certs` | a certificate acme keeps: its names, key type, issuer, challenges, renewal policy, the current certificate, chain and sealed key, its state |
| `cert_versions` | every certificate a row of `certs` has had (renewals, imports) |
| `cert_cas` | a certificate authority of acme's own (root or intermediate): sealed key, serial counter, CRL |
| `cert_ca_issued` | what one of those CAs signed (serial, subject, revoked) - for its CRL |
| `cert_issuers` | a source of certificates: kind (`acme`, `internal_ca`, `selfsigned`, `ms_adcs`, `scep`, …) and its settings (secrets sealed) |
| `cert_challenges` | a way of proving names: kind (`dns_builtin`, `rfc2136`, `cloudflare`, `http_local`, `http_ssh`, …) and its settings |
| `cert_targets` | a place certificates go: kind (`ssh`, `f5`, `netscaler`, `mikrotik`, `fortigate`, …), its address, how acme signs in (sealed) |
| `cert_deploys` | one certificate on one target, with the options there (paths, formats, profile, commands) and how it went |
| `cert_jobs` | one piece of work - an issue, a renewal, a deployment, a test - with every step |
| `dns_records` | the records acme's own DNS server answers with (the `_acme-challenge` TXT records, and your own) |

### What happens

1. Every few minutes the node that leads (the one holding the VIP address in a
   cluster, else the only node - a lease row in `meta` makes sure only one does)
   looks for certificates due: past `renew_days` before the end, or inside the
   window the CA suggests (ARI), or failed and past their backoff.
2. A job renews each one: a new key (unless the key is kept), a CSR, the
   issuer asked; for ACME every name proved by its challenge (DNS-01 or
   HTTP-01), waited for, cleaned up.
3. The new certificate becomes the current one (the old one is kept in
   `cert_versions`), and every enabled deployment of it is run: the target's
   module puts it in place in the formats asked and makes the service take
   it, then checks what is served.
4. Every step is in the job (`acme --job ID`, the Jobs tab); a failure is an
   event, an alert by mail/SMS, a line to syslog/SIEM and isemon.

### Roles

`readonly` looks; `certadmin` adds, imports, renews, deploys and exports
certificates (no private keys); `fulladmin` does everything: the authorities,
the issuers, the challenges, the targets, the settings, private keys out.

## The API of the certificate manager

All JSON, through the pages' relay (`/admin/api.php` → `127.0.0.1:9861`), with the
session of the person. A secret field is never sent back: `config` holds `""`
there and `secret_set` says which are set; saving `""` keeps what is set.

| | |
|---|---|
| `GET /api/certs/overview` | counts by state, what runs out soonest, recent jobs, expiry by week |
| `GET /api/certs` `?search= &state= &issuer= &tag= &page= &per=` | `{rows, total}` |
| `GET /api/certs/one?id=` | `{cert, versions, deploys, jobs}` |
| `POST /api/certs/save` | `{id?, name, names[], key_type, issuer, challenge, challenge_map{}, auto_renew, renew_days, reuse_key, profile{}, tags[], note, owner}` → `{id}` |
| `POST /api/certs/delete` | `{id}` |
| `POST /api/certs/renew` | `{id, force}` → `{job_id}` |
| `POST /api/certs/deploy` | `{id, deploy_id?}` → `{job_id}` |
| `POST /api/certs/revoke` | `{id, reason}` → `{job_id}` |
| `POST /api/certs/parse` | `{data_b64, filename, password}` → what is in a file, nothing kept |
| `POST /api/certs/import` | `{name, data_b64, filename, password, key_b64?, key_password?, tags[], note}` → `{id}` |
| `POST /api/certs/export` | `{id, format, password?, version?}` → `{filename, mime, data_b64}` |
| `POST /api/certs/csr` | `{id}` → a CSR for an issuer acme does not speak to: `{csr_pem}`; `POST /api/certs/csr_answer {id, data_b64}` takes the certificate back |
| `GET /api/certs/jobs` `?cert_id= &kind= &ok= &page=` | `{rows, total}` |
| `GET /api/certs/job?id=` | one job, every step; `POST /api/certs/job_stop {id}` |
| `GET /api/cas` · `GET /api/cas/one?id=` | the authorities; one with what it signed |
| `POST /api/cas/create` | `{name, subject{CN,O,OU,C,ST,L}, key_type, days, parent_id?, path_len, crl_days, crl_url, aia_url, name_constraints[]}` |
| `POST /api/cas/import` · `/api/cas/delete` · `/api/cas/crl` · `/api/cas/export` | `{..}` |
| `POST /api/cas/sign_csr` | `{id, csr_pem, days, eku[]}` → a certificate for a CSR from elsewhere |
| `GET /api/plugins` | `{issuer:[…], challenge:[…], target:[…], broken:[…]}` - each with `fields` (and `deploy_fields`) |
| `GET /api/sources` · `POST /api/sources/save` · `/delete` · `/test` · `/action` | the issuers (`cert_issuers`); each row says `actions` and `is_default` |
| `GET /api/validations` · `POST /api/validations/save` · `/delete` · `/test` · `/action` | the challenges (`cert_challenges`) |
| `GET /api/targets` · `POST /api/targets/save` · `/delete` · `/test` · `/action` | the targets |
| `POST /api/{sources,validations,targets}/action` | `{id, action}` - one of the module's `actions`, in a job: `{ok, said, job_id, steps}` |
| `POST /api/sources/contact` | `{email, all?}` - the contact e-mail of the ACME sources that have none |
| `GET /api/deploys` `?target= &cert=` | the deployments (of a target, of a certificate), each with `cert_name`, `cert_version`, `outdated` |
| `POST /api/deploys/save` · `/delete` · `/run` | `{id?, cert_id, target, options{}, enabled}` |
| `GET /api/dns` · `POST /api/dns/record` · `/api/dns/record_delete` | acme's own DNS server: its zone, its records, whether it listens |
