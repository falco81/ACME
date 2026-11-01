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
| **source / issuer** (`cert_issuers`) | where certificates come from: a module (`acme`, `internal_ca`, `selfsigned`, `ms_adcs`, `scep`, `sslmarket`, ...) and its settings |
| **validation / challenge** (`cert_challenges`) | how a name is proved to an ACME CA: DNS-01 (acme's own DNS server, RFC 2136, Cloudflare, ...) or HTTP-01 (this server's port 80, web servers over SSH) |
| **target** (`cert_targets`) | a place certificates go: a Linux server over SSH, F5, NetScaler, MikroTik, FortiGate, ... and how acme signs in |
| **deployment** (`cert_deploys`) | one certificate on one target, with the options there (paths, formats, profile, commands after) |
| **job** (`cert_jobs`) | one piece of work (an issue or renewal, a deployment, a revocation, a test), with every step it took |

### Let's Encrypt first

A new installation starts ready for Let's Encrypt. The first time the daemon
starts (or the command line opens the database) with no source at all, it
makes the sources **LetsEncrypt** (production) and **LetsEncrypt
staging** (module `acme`); with no validation at all, **This server
HTTP-01** (`http_local`); and once `dns_zone` is set, **acme DNS server**
(`dns_builtin`). Each is made once: a flag in `meta` (`certs:default:sources`,
`:validations`, `:dns`) says so, and one an administrator deleted is never
made again.

A new certificate with no issuer said comes from the default source (`meta
certs:default_issuer`, "LetsEncrypt"), and one from an ACME CA with no
validation said is proved by the default validation (`certs:default_challenge`,
"This server HTTP-01"); the lists mark them (`is_default`, `*` on the
command line). An ACME account works without a contact e-mail; where an ACME
source has none, the Sources page and `acme --certs` / `--sources` ask for one
(`acme --acme-contact MAIL`, `POST /api/sources/contact {email}`).

### The default of each list

Every list - **Sources**, **Validation**, **Targets**, **Authorities** - has
one entry a full administrator makes the default: the star in its row, or
*Make it the default* in its popup (pressed on the default: *No default*).
The list marks it with the green *default* tag (`is_default` on its row,
`*` on the command line and in the console). What it is used for:

| list | the default is | kept in `meta` |
|---|---|---|
| Sources | where a new certificate comes from when none is said; preselected in the new certificate's wizard | `certs:default_issuer` (a name) |
| Validation | how a new certificate from an ACME CA is proved when nothing else is said; preselected in the wizard | `certs:default_challenge` (a name) |
| Targets | offered first - and ticked - in the wizard's *Deployments* step, and preselected in a new deployment | `certs:default_target` (a name) |
| Authorities | preselected in a new source of the kind *own certificate authority* (every field with `options_from: 'cas'` gets it as its `default` in `GET /api/plugins`), as the parent of a new intermediate, and for *Sign a CSR* | `certs:default_ca` (an id) |

`POST /api/sources/default`, `/api/validations/default`, `/api/targets/default`
`{name}` and `POST /api/cas/default {id}` set it (`''`: no default),
`acme --source-default NAME` (`--validation-default`, `--target-default`,
`--ca-default`; `none` for no default) the same. One that is switched off,
an authority that cannot sign (no certificate yet, no key, off, run out),
and one that is not there are refused. Each change is an event. Renamed, it
stays the default; deleted, there is none (an event says so) - nothing is
taken in its place. An installation that never set one keeps "LetsEncrypt" and
"This server HTTP-01" where they are there.

### Names

Every source, validation, target, authority and certificate has a name of
letters, digits, spaces and `. _ @ + -`, starting with a letter or a digit
(120 at most; `store.NAME_RE`) - names reach shell commands, files and
devices, so never a quote or a bracket. The pages say what a name box would
refuse as it is typed (and keep *Save* off meanwhile). Every name acme
suggests is made so (`store.safe_name`, `safeName` on the pages): a module's
`default_name`, else its title; a certificate's first name (a wildcard as
`wildcard.`); an authority's or an imported certificate's CN - letters with
accents as plain letters (`Šifrování` → `Sifrovani`), apostrophes and quotes
dropped, brackets, colons, commas and slashes as spaces, unique in its list
(`name 2`, `name 3`...).

An installation from before had names that are not safe ("Let's Encrypt",
"Let's Encrypt (staging)", "This server (HTTP-01)", "acme's DNS server", and
names taken from a CN). At its next start (`names.migrate`, before the first
start's defaults) each is renamed - the four to "LetsEncrypt", "LetsEncrypt
staging", "This server HTTP-01", "acme DNS server", the rest to their safe
name - in one transaction with every place that refers to it: the
certificates' source, validation and per-name validations, the deployments'
target, the defaults, the settings `portal_cert_issuers` and
`portal_cert_challenge`, the values a module keeps, and every module setting
that names it (an own-CA source's authority). One event says what was
renamed.
`GET /api/certs/overview` says all four (`defaults`).

### Always current

The pages keep what they asked of the daemon - the lists, the modules with
the choices of their fields (the authorities, sources, validations and
targets inside a select), the authorities - only until something changes:
after every request that changes something (a save, a delete, a default,
an import, an approval, an action) all of it is asked anew, and so is what a
tab shows when it is opened and what a popup that offers choices (the
wizard, the deployment editor, a module's form, the authority pickers) is
opened with. What is made in one tab is offered in every other at once,
without reloading the page (`test/fresh_lists_page.js`).

### HTTP-01 answered by acme ("This server")

A validation of the kind `http_local` says, in its popup and on its row,
how it works on this installation (`GET /api/validations/info?name=`,
`acme --validation-show NAME`): the URL the CA fetches -
`http://NAME/.well-known/acme-challenge/<token>`, port 80, plain HTTP; the
path and the port are fixed by the ACME standard (RFC 8555) -, which
machines answer it now (every node with its address, and the VIP address
with its name when it is on), port 80 in each node's firewall, and every
name of the certificates that use it with what it resolves to: ✔ one of
acme's addresses, or ✘ *points elsewhere* - then set its DNS to the VIP
address, or put a proxy there that forwards `/.well-known/acme-challenge/` to
acme. What can be set is the module's own: *Check before the CA is asked*
and the address *Test* tries. *Check a name* (`POST /api/validations/check
{id, host}`, `acme --validation-check NAME HOST`) puts a probe token in place
(`meta acme:chal:<token>`, taken away after) and fetches it at that name from
the daemon, step by step in a job. Behind NAT a router may not loop back to
its own public address (hairpin NAT): the check fails here although the CA
from outside is answered.

While a validation of this kind is switched on, the firewall lets port 80
in from anywhere even when *Who may reach the pages* keeps the pages to
some networks (as for the engine's own ACME and for `/pki/`).

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

A secret is never sent back to a page in clear - the rule of the whole
appliance (and of otp): a full administrator is shown eight dots and its
last two characters (`••••••••et`), so "the one I set" can be told from
another; a certificate administrator or a reader eight dots only; `""`
when none is set. `secret_set` lists which secrets are set. Saving `""`, or
the value as it was shown (anything that starts with a dot), keeps the one
that is set. The same goes for the secret options of a deployment
(`deploy_fields`), the command line (`--target-show` and the others: root
on the box, so dots and the last two) and the console.

A private key or another secret of several lines (an SSH key pasted into a
validation or a target - a `pem` field marked `secret=True`, or a `secret`
with `multiline=True` - the JSON of a service account, acme-dns accounts) is
sealed the same way. Its last two characters would be the dashes of
`-----END ... KEY-----`, which every key ends with alike: what is shown is
the last two characters of its body instead, the BEGIN/END lines, spaces,
`-` and `=` left out. A key kept in clear by a version before this one is
sealed the next time its row is saved.

In the configuration's export without the secrets, a module's secrets are
eight dots (put back, the ones kept here stay); with the secrets (locked with
the passphrase) they are opened, and sealed again for their row when imported.

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
   Before the first certificate, and after a renewal that failed on its
   validation, what those challenges need is checked first; the CA is not
   asked while something is missing (see *Before the first certificate*
   below, `certs_precheck`).
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


## Before the first certificate: what acme checks and tells you

Let's Encrypt counts failed validations (five an hour for one account and
name) and then refuses the name for a while. So acme does not try blindly:

* **Before the first certificate** of a certificate (it has no version yet),
  and **after a renewal that failed on its validation** (the CA did not
  accept the proof, it was not seen in time - kept in `meta
  certs:validation_failed:<id>` until a renewal works), the renewer first
  checks what each name's validation needs (`readiness.check()`, read-only:
  DNS asked at the zones' own name servers, a provider's API read, a probe
  acme answers fetched).
* While something **blocks** - the CNAME `_acme-challenge.www.firma.cz.
  CNAME www.firma.cz.acme.example.net.` is missing, the name points
  elsewhere, the zone is not at the DNS provider, the credentials are
  refused - **the CA is not asked**. The certificate becomes `failed`, its
  `last_error` says what to do (*the CA was not asked - the validation is not
  ready: Create in the DNS of firma.cz: _acme-challenge.shop.firma.cz. CNAME
  shop.firma.cz.acme.example.net.*), and the job's steps hold the whole guide:
  each step ✔/✘ with where, what was found, what to do and the exact record.
  It is tried again after the usual wait (5 minutes, doubled), checked again
  each time, so once the record is there the certificate comes by itself.
* What cannot be told from here (whether the internet reaches acme's DNS
  server, a step that did not finish in 45 s) does not block: the CA is asked.
* `certs_precheck` (on) switches this off; a renewal of a certificate that
  has one is not checked unless its last one failed on validation.

The same check, for any names, before a certificate is even made:
`acme --check-names a,b,c [--issuer X] [--challenge Y]`, `acme --cert-check
NAME` for one acme keeps, and `acme --dry-run NAME|names` to try the
validation for real with no CA (a job, kind `dry-run`). The names may come
from different domains: they are grouped by zone, each with its own
validation (`challenge_map`) and acme's suggestions of which validation would
do (a DNS provider holding the zone, acme's own DNS server, HTTP-01 here or
on the web servers). What each kind checks: [validation.md](validation.md#before-the-first-certificate-what-acme-checks-and-tells-you).

For the pages (and anything else) the functions are in
`acmelib/certs/readiness.py`:

| | |
|---|---|
| `plan(store, names, issuer=None, challenge=None, challenge_map=None, cert=None)` | `{groups: [{domain, names, validation, kind, suggested: [{validation, kind, why}], guide: {steps, ok}}], issuer, issuer_needs_validation, ok, blocking: [{domain, name, validation, key, what, said, fix, record}], complete, took_ms}` - at most 60 s |
| `check(...)` | the same, suggestions only for a group that blocks - at most 45 s (the renewer's) |
| `dry_run(store, names, ..., by='', cert_id=None)` | a job id; `dry_run_result(store, job_id)` what it found, in the same shape |

A step: `{key, what, where, record: {name, type, value, ttl} or null, done:
true|false|null, said, fix, blocking, name}`.

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
`certificates`), so it also goes to syslog, the SIEM and isemon - with fields
of their own beside the words: `action` (`issued`, `renewed`, `renew`,
`deployed`, `deploy`, `expired`, `expiring`, `revoked`, ...), `result` (`ok`,
`failed`, `expired`, `warn`), `cert`, `names`, `serial`, `not_after` (ISO
8601, UTC), `issuer`, and for a deployment `target`, `target_kind` and
`version`. isemon gets them as `key=value` before `msg=` on the `acme-certs`
line; the SIEM as fields of its JSON, CEF or RFC 5424 structured data.

A failed renewal, a failed deployment, an expired certificate, and one that
ends within `certs_notify_days` without being renewed by itself (or whose
renewal keeps failing) all send a mail to `certs_notify_mail` and an SMS to
`certs_notify_sms`, each at most every 6 hours. With `certs_notify_ok` on, a
renewal and a deployment that went well are told too. The words are those of
**Settings → Message texts** (group *Certificates*, in Czech and English,
the language of `alerts_lang`, else `mail_lang`), edited there as every other
text; the placeholders are `{cert}` `{names}` `{left}` `{not_after}`
`{issuer}` `{serial}` `{version}` `{error}` `{retry}` `{target}` `{node}`
`{site}`:

| message | sent when |
|---|---|
| `cert_expiring` (+ `_sms`) | it ends within `certs_notify_days` and nothing renews it |
| `cert_expired` (+ `_sms`) | it has run out (once) |
| `cert_renew_failed` (+ `_sms`) | a renewal failed |
| `cert_deploy_failed` (+ `_sms`) | a deployment failed |
| `cert_renewed` (+ `_sms`) | it was renewed (with `certs_notify_ok`) |
| `cert_deployed` (+ `_sms`) | a deployment went well (with `certs_notify_ok`) |
| `cert_portal_issued`, `cert_portal_declined` | to the person who asked on the enrolment pages (`{name}`, `{reason}`) |

The same things are alerts (the `alerts` hook) and lines in the weekly
report.

### Monitoring

Prometheus (`https://NODE/metrics`, the `metrics` hook) gets
`acme_certs{state}`, `acme_cert_state{name,state}`,
`acme_cert_not_after_timestamp_seconds{name,cn,issuer}`,
`acme_cert_expiry_seconds{name}`, `acme_cert_expiring`,
`acme_cert_renewals_total{result}` and `acme_cert_deployments_total{result}`
(of the jobs kept), `acme_cert_jobs_24h{kind,result}`,
`acme_cert_jobs_failed_24h`, `acme_cert_deploys{state}`,
`acme_cert_deploys_failed`, `acme_cert_last_job_timestamp_seconds{kind,result}`,
`acme_cert_last_scan_timestamp_seconds{node}`, `acme_cert_leader{node}` (this
node: 1 or 0), `acme_cert_leader_info{node}` (who leads) and, with acme's DNS
server on, `acme_dns_up`, `acme_dns_queries_total{proto}`,
`acme_dns_answers_total{rcode}` and `acme_dns_records`.

SNMP (ACME-MIB, `deploy/ACME-MIB.txt`; the `snmp` hook) has
`acmeManagedCertTable` (`acmeCertificates.2`: index = the certificate's id,
name, CN, notAfter, daysLeft, state, issuer, state as a number, renewed by
itself, deployments failed) and `acmeManagedCounts` (`acmeCertificates.3`:
total, ok, failed, expired, expiring, deployments failed, this node leads,
jobs failed in 24 h, DNS queries, waiting). Every Prometheus sample is in
`acmeMetricTable` as well.

## The certificate of acme's own pages

The target module `appliance` - *This acme server (its pages)* - makes a
certificate of the manager the certificate of acme's own pages, as
**Settings → Certificates and TLS** would take one uploaded: the profile of a
node or of the VIP address (`meta web:tls:<node|vip>`), its TLS settings
kept, the engine's own ACME (*Automatic certificates*) told to leave it.
Every node puts its own into nginx within seconds; the VIP's is served by the
node that holds the address. A deployment says which pages (`where`):
`auto` (every node, and the VIP address in a cluster that has one), `nodes`,
`this`, `vip`, or the ones named (`names`); the certificate has to hold the
VIP address's name. As every deployment it runs again after each renewal -
so the pages of every node are renewed with it.

```
acme --target-add pages --kind appliance
acme --cert-add pages --names acme.example.com,acme1.example.com,acme2.example.com
acme --deploy-add pages pages --set where=auto
```

## A module's actions

A module may offer things to do besides its work (`actions` in
`acmelib/plugins/base.py`): a button on its row on the pages, an item in the
console, `acme --validation-action NAME KEY` (and `--source-action`,
`--target-action`), `POST /api/validations/action {id, action}` (and
`/api/sources/action`, `/api/targets/action`). Each runs in a job of its own,
its steps written down. One that changes something elsewhere (`changes`, the
default) is for a full administrator. `http_ssh` has **prepare** (*Prepare
the hosts*, docs/validation.md).

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
  one of `portal_cert_issuers`, up to `portal_cert_max` requests each.
  acme issues it at once (`portal_cert_auto`) or after an administrator
  approves it (state `pending-approval`; `POST /api/certs/approve`), and
  renews it by itself.

The whole of it - group ownership, PFX downloads (`portal_cert_keys`), the
approval and the mails - is in [certificate-portal.md](certificate-portal.md).

## Settings

| key | default | |
|---|---|---|
| `certs_renew_days` | 30 | renew this many days before the end |
| `certs_check_min` | 5 | look for what is due every N minutes |
| `certs_parallel` | 4 | jobs at once |
| `certs_retry_max_h` | 6 | the longest wait before trying again |
| `certs_notify_days` | 14 | warn this many days before the end |
| `certs_notify_mail`, `certs_notify_sms` | | who is told |
| `certs_notify_ok` | 0 | tell renewals and deployments that went well too |
| `certs_keep_versions` | 10 | old certificates kept, each |
| `certs_keep_jobs_days` | 90 | jobs kept |
| `certs_precheck` | 1 | before the first certificate (and after a failed validation) check the validation first; the CA is not asked while something blocks |
| `certs_dry_run_s` | 120 | how long a dry run waits for its test value to be seen |
| `pki_publish` | 1 | the CRLs and certificates of acme's own authorities served at `/pki/` on port 80 (docs/own-ca.md) |
| `pki_base_url` | '' | where: `http://NAME/pki/`; empty: the VIP address's name when it is on, else this server's |
| `portal_cert`, `portal_cert_suffixes`, `portal_cert_issuers`, `portal_cert_challenge`, `portal_cert_max`, `portal_cert_auto`, `portal_cert_keys` | 0, '', '', '', 10, 0, 0 | the certificate portal |
| `dns_server`, `dns_listen`, `dns_port`, `dns_zone`, `dns_ns_names`, `dns_ns_addresses`, `dns_soa_mail`, `dns_ttl`, `dns_static` | 0, `0.0.0.0,::`, 53, ..., 60 | acme's own DNS server |

On the settings pages these are in the panes `certs` and `dnssrv`; the
`portal_cert*` ones are on the portal's pane (`portal`).
