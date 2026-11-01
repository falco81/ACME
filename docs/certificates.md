# Certificates: how acme keeps, renews and deploys them

acme keeps a database of certificates. It renews each one by itself from
the place it came from (Let's Encrypt or another ACME CA, one of acme's own
authorities, self-signed, Microsoft AD CS, SCEP), then puts every new
certificate on the servers and appliances that use it. A certificate
imported from a file is kept and deployed too, but nothing renews it: acme
does not know where it came from.

The code is in `acmelib/certs/`. The engine part `acmelib/engine/900_certificates.py`
plugs it into the engine. The modules (issuers, challenges, targets) are in
`acmelib/plugins/` (see `acmelib/plugins/base.py`).

## The pieces

| | |
|---|---|
| **certificate** (`certs`) | its names, key type, issuer, challenge(s), renewal policy, the current certificate, its chain and its key (sealed), its state |
| **version** (`cert_versions`) | every certificate a row has had: each issue, renewal, import or CSR answer. `certs_keep_versions` of them are kept |
| **source / issuer** (`cert_issuers`) | where certificates come from: a module (`acme`, `internal_ca`, `selfsigned`, `ms_adcs`, `scep`, ...) and its settings |
| **validation / challenge** (`cert_challenges`) | how a name is proved to an ACME CA: DNS-01 (acme's own DNS server, RFC 2136, Cloudflare, ...) or HTTP-01 (this server's port 80, web servers over SSH) |
| **target** (`cert_targets`) | a place certificates go: a Linux server over SSH, F5, NetScaler, MikroTik, FortiGate, ... and how acme signs in |
| **deployment** (`cert_deploys`) | one certificate on one target, with the options there (paths, formats, profile, commands after) |
| **job** (`cert_jobs`) | one piece of work (an issue or renewal, a deployment, a revocation, a test), with every step it took |

### States of a certificate

`new` (not issued yet) → `renewing` → `ok`. Then `failed` (the last renewal
failed, so it waits and tries again), `expired`, `pending` (a CSR was given
out and its answer is awaited), `revoked`, or `disabled` (switched off).

## Secrets

A module's setting of type `secret` (a password, an API token, a key) is
sealed with the installation's key (`E.seal_secret`). It is bound to its
place, `<table>:<id>:<field>`, so a value copied to another row does not
open. A certificate's private key is bound to `certs:<id>:key_sealed:<version>`,
and a key waiting for a CSR's answer to `certs:<id>:csr_pending`.

A secret is never sent back to a page. `config` holds `""` in its place,
and `secret_set` lists which secrets are set. Saving `""` keeps the one
that is set. The same goes for the secret options of a deployment
(`deploy_fields`).

## Renewing

The renewer is a thread of the daemon. Every `certs_check_min` minutes the
node that leads looks for what is due:

* `auto_renew` is on, and `not_after - renew_days × 86400 <= now`.
  `renew_days` is the certificate's own value, else `certs_renew_days` (30).
* Or the time is inside the renewal window the CA suggests (ACME ARI,
  RFC 9773, from the issuer's `renewal_window()`). This is asked at most
  every 6 hours. acme picks a moment at random inside the window and keeps
  it in `certs.ari`.
* Or it has never been issued (`new`).
* Or the last renewal failed and its wait is over. The wait is 5 minutes,
  then twice as long each time, at most `certs_retry_max_h` (6 h).

Each certificate that is due gets a job:

1. A new key of the certificate's key type, unless `reuse_key` is on and it
   has one already.
2. A CSR (`pki.make_csr`), with the profile's subject, `must_staple` and `eku`.
3. For an issuer that needs every name proved (ACME), each name gets a
   challenge. acme tries these in order:
   * the exact name in `challenge_map`
   * a `*.parent` pattern there
   * the longest suffix there
   * the certificate's own `challenge`

   What a challenge puts in place (DNS records in acme's own server, HTTP-01
   answers on port 80) is taken away at the end of the job, whether it
   worked or not.
4. `Issuer.issue(CertRequest)` is called. The chain is put in order, and acme
   checks that the key fits the certificate.
5. The new certificate becomes the current version (the old one stays in
   `cert_versions`), and the certificate's state becomes `ok`.
6. Every enabled deployment of it is run (see below).

When a renewal fails, the certificate becomes `failed` with `last_error`
and `next_try` set. The failure is recorded as an event and sent as a
notification.

Asked by a person (the page, `acme --renew NAME`), a certificate is renewed
whether it is due or not.

## Deploying

For each deployment, the target's module is handed a `Bundle` (the
certificate in every format a device may want: PEM, DER, PKCS#8/PKCS#1,
chain, fullchain, combined, P7B, PFX/P12, legacy P12, JKS) and the
deployment's options, with its secrets opened. The module:

1. puts the certificate in place;
2. makes the service take it (reload, profile update, ...);
3. is asked `verify()`: is the new certificate what is served now?

`False` counts as a failure. `None` means the module cannot tell.

A deployment started by a person (the page, `acme --deploy`, the console)
passes `options['force'] = True`, so a target that skips an unchanged
fingerprint puts it in place anyway. The deployments run after a renewal,
and those the renewer tries again, are not forced.

A failed deployment gets `state = failed`, `fails` increased and `next_try`
set with the same doubling wait. The renewer tries it again then. The
renewer also runs a deployment that has never been given the current
version (one added after the renewal, or one whose options changed).

### SSH (for target modules)

`ctx.ssh(conn)` runs the `ssh` and `scp` programs of OpenSSH. The server's
host key is always checked:

* `conn['hostkey']` holds the key as known_hosts line(s). Any shape works:
  `host type key`, `[host]:port type key`, a hashed line, or a bare
  `type key`.
* With no host key and `trust_first` on, the first key the server shows
  (`ssh-keyscan`) is taken. acme writes it into the target's config
  (`hostkey`) and records it as a warning in the job and the events. From
  then on, that key is checked.
* With no host key and no `trust_first`, the connection is refused. The
  error shows the fingerprint the server presents, so it can be checked and
  pasted in.

A password or a key's passphrase goes through `SSH_ASKPASS`, never on a
command line. All commands of one session share one connection
(ControlMaster).

`s.put(data, path, mode, owner)` writes the file with `cat` into a
temporary file beside the target path, sets its mode and owner, then moves
it into place, so the file is replaced whole or not at all. With
`via='scp'` (for devices without a POSIX shell, such as MikroTik and
Windows), the file goes by scp straight to the path, with no temporary
file, chmod or chown.

## Jobs

Jobs run in a pool of `certs_parallel` threads (4). At most one job works
on a certificate at a time. While a job runs, its steps
(`[[epoch, level, words], ...]`, where `level` is `info`, `ok`, `warn`,
`bad` or `debug`) are written into its row: at most a second late, and at
once for `ok`, `warn` and `bad`. So a job can be followed live from the
Jobs page or with `acme --job ID` on either node.

Stopping a job (`POST /api/certs/job_stop`, the page) sets a flag. The
module sees it through `ctx.cancelled()` and gives up at its next step. A
job that runs on the other node is asked to stop through `meta`
(`certs:stop:<id>`). Jobs left running when the daemon stopped are marked
failed at its next start. Jobs older than `certs_keep_jobs_days` (90) are
deleted.

## Who may do what

| role | may |
|---|---|
| `readonly` | look at everything: certificates, versions, deployments, jobs, authorities, sources, validations, targets, the DNS records, the modules |
| `certadmin` | also add, change, delete, import, renew, deploy, revoke and export certificates (without their private key), give out CSRs and take their answers, add and run deployments, try sources, validations and targets, stop jobs, make a CRL |
| `fulladmin` | everything: the authorities, the sources, the validations, the targets, acme's DNS server, the settings, and private keys out (key formats, PFX, JKS, combined PEM, an authority's key) |

The role `tokenadmin` (from the engine acme came from) counts as `certadmin`
until it is renamed.

## Two nodes (HA)

Both nodes serve the pages, the API and acme's DNS server from the same
database (shared or replicated). Only one node renews and deploys at a
time. A lease in `meta` (`certs:leader` = `{node, until, vip}`) says which:

* The leader renews the lease every 30 s. It runs out after 90 s.
* A node takes the lease when it is free or has run out.
* The node that holds the VIP address takes it over from a node that does
  not.

If the leader dies, the other node takes over within about 90 seconds.
`acme --status` shows which node leads (the `renewed by` line), and so does
`GET /api/certs/overview` (`leader`).

## Telling people

Every issue, renewal, deployment, failure and expiry is an event (kind
`certificates`), so it also goes to syslog, the SIEM and isemon. A failed
renewal, a failed deployment, an expired certificate, and one that ends
within `certs_notify_days` without being renewed by itself all send a mail
to `certs_notify_mail` and an SMS to `certs_notify_sms`, each at most every
6 hours. The same things are alerts (the `alerts` hook) and lines in the
weekly report. Prometheus gets `acme_certs{state}`,
`acme_cert_expiry_seconds{name}`, `acme_cert_deploys_failed`,
`acme_cert_jobs_failed_24h` and `acme_cert_leader`.

## acme's own DNS server

With `dns_server` on, every node answers DNS for `dns_zone`. It serves the
`_acme-challenge` TXT records that DNS-01 challenges put in `dns_records`,
plus your own records (`dns_static`, or the DNS page). It is started again
when one of the `dns_*` settings changes. Delegate `_acme-challenge.<name>`
(or a whole zone) to the nodes with NS records.

## The certificate portal

With `portal_cert` on, people signed in on the enrolment pages:

* see the certificates whose `owner` is them;
* can download the certificate, its chain or both (never the key);
* can ask for a certificate for names under `portal_cert_suffixes`, from
  one of `portal_cert_issuers`, up to `portal_cert_max` certificates each.
  acme issues it with a job and renews it by itself.

## Settings

| key | default | |
|---|---|---|
| `certs_renew_days` | 30 | renew this many days before the end |
| `certs_check_min` | 5 | look for what is due every N minutes |
| `certs_parallel` | 4 | jobs at once |
| `certs_retry_max_h` | 6 | the longest wait before trying again |
| `certs_notify_days` | 14 | warn this many days before the end |
| `certs_notify_mail`, `certs_notify_sms` | | who is told |
| `certs_keep_versions` | 10 | old certificates kept, each |
| `certs_keep_jobs_days` | 90 | jobs kept |
| `portal_cert`, `portal_cert_suffixes`, `portal_cert_issuers`, `portal_cert_max` | 0, '', '', 10 | the certificate portal |
| `dns_server`, `dns_listen`, `dns_port`, `dns_zone`, `dns_ns_names`, `dns_ns_addresses`, `dns_soa_mail`, `dns_ttl`, `dns_static` | 0, `0.0.0.0,::`, 53, ..., 60 | acme's own DNS server |

On the settings pages these are in the panes `certs` and `dnssrv`.
