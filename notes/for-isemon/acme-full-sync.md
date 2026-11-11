# acme → isemon: the first full sync (acme 1.0.71) - what isemon needs to read

For the developers of **isemon**. acme can now send isemon everything it holds of its
certificates at once: Settings → isemon → *First full sync…*, or `acme --isemon-sync [DAYS]`.
The lines arrive, as `/var/log/remote/acme/acme-jobs.log` shows (687 records after one sync),
but isemon's *acme* page still says **0 certificates · 0 targets**. isemon builds that page
from the live `acme-certs` lines only and does not read the `kind=sync` lines yet. This is what
to add.

## 1. Where the lines come from

* **File and program:** the same file and program as the job lines,
  `/var/log/remote/<host>/acme-jobs.log` from program `acme-jobs`. `11-acme.conf` already files
  them there, so nothing changes in rsyslog.
* **Format:** RFC 3164 syslog, then `key=value` pairs, the same as every acme line. A value
  with a space or a quote is in double quotes, with `\"` and `\\` escaped inside. `msg` is
  always last. A line never breaks.
* **Telling them apart:** the sync lines are `kind=sync`. The other lines of the same file are
  `kind=job` / `kind=check`, the live detail.
* **One sync:** every line of one sync carries the same `sync=<12 hex>`. A new sync gets a new
  id, and a sync can be run again at any time.
* **`node`:** the acme node that sent it. `who` is the person or `command line`.

```
Nov 11 15:21:53 acme acme-jobs[1007]: level=info kind=sync node=acme1 who=admin certificates=45 checks=4 days=365 deployments=12 event=begin sources=5 sync=183b020fc4e1 targets=12 msg="the first full sync of acme begins"
```

## 2. The events of a sync, in the order they come

| `event=` | what | key fields |
|---|---|---|
| `begin` | the sync starts | `sync`, the counts: `certificates deployments checks targets sources`, `days` (history asked for, 0 = none) |
| `object` | one thing as it is **now** (`object=` says which) | see 3 |
| `history` | one past event of the certificates, oldest first | `at` (ISO 8601 UTC), `event_node`, `by`, `level`; the event's words in `msg` |
| `job` | one past job (an order, renewal, deployment, test run, import...) | `job` (id), `job_kind`, `cert`, `cert_id`, `deploy_id`, `target`, `at`, `state`, `ok` (1/0), `finished`, `took_ms`, `by`, `job_node`, `version`, `steps` (count); its result in `msg` |
| `job_step` | each kept step of that job, right after it | `job`, `job_kind`, `cert`, `cert_id`, `seq` (1..n), `at`, `level`; the step in `msg` |
| `end` | the sync is complete | `lines` (all of this sync incl. begin/end), `events`, `jobs`, `took_ms` |

The objects come first (sources, validations, targets, tests, authorities, certificates,
deployments, checks), then the history and the jobs, then `end`.

**Time:** each `history`, `job` and `job_step` line carries the syslog stamp of when it
happened, not of when it was sent. The RFC 3164 stamp has no year, so **use `at=`** (full UTC)
for these. A line from last December would otherwise land in the future. In the file these
lines sit *after* newer live lines, so the file is not in time order.

## 3. The objects (`event=object`)

Every value of a date is ISO 8601 UTC (`2027-12-03T16:27:45Z`). A key is left out when it has
no value.

### `object=certificate` - one per certificate (the main table of the *acme* page)

| key | meaning |
|---|---|
| `cert_id` | acme's id - **the key to upsert by** (`cert` can be renamed) |
| `cert` | its name in acme |
| `names` | the DNS names, comma separated; `cn` the common name |
| `cert_state` | `ok`, `new`, `failed`, `held`, `pending`, `pending-approval`, `declined`, `revoked`, `revoke-failed`, `disabled`, `deleting` |
| `enabled` | 1/0 |
| `issuer` | the source's name in acme, or **`by hand`** (imported, renewed by importing) |
| `source` | `issuer`, `import`, `manual`, `portal`, `csr` |
| `challenge` | the validation |
| `key_type`, `key_type_alt` | `ec-256`, `rsa-2048`...; `_alt` set for a dual certificate (ECDSA + RSA) |
| `version`, `serial`, `fingerprint` (SHA-256, hex), `issuer_dn` | the certificate in use |
| `not_before`, `not_after`, `days_left` | its validity; `days_left` is whole days, negative = run out |
| `auto_renew` (1/0), `renew_days` | renewed by itself, so many days before the end |
| `last_ok`, `last_try`, `next_try`, `fails`, `last_error` | the renewal |
| `owner`, `tags` (comma separated), `note`, `eku` | |
| `alt_not_after`, `alt_state` | the twin of a dual certificate |
| `created`, `created_by` | |

```
level=info kind=sync node=acme1 who=admin auto_renew=1 cert=intranet.example.com cert_id=1 cert_state=ok cn=intranet.example.com days_left=387 enabled=1 event=object fails=0 fingerprint=753AE7B6... issuer="Interni CA" issuer_dn="CN=Example Issuing CA,O=Example s.r.o.,C=CZ" key_type=ec-256 last_ok=2026-11-01T16:27:45Z names="intranet.example.com,www.intranet.example.com" not_after=2027-12-03T16:27:45Z not_before=2026-11-01T15:27:45Z object=certificate serial=762B931B... source=issuer sync=183b020fc4e1 version=1 msg="certificate intranet.example.com"
```

### `object=deployment` - one certificate on one target

`cert`, `cert_id`, `deploy_id` (**key**), `target`, `deploy_state` (`ok`, `failed`, `pending`,
`disabled`...), `enabled`, `deployed_version`, `deployed_fp` (the fingerprint put there; it
equals the certificate's `fingerprint` when the target has the current one), `last_ok`,
`last_try`, `fails`, `last_error`.

### `object=check` - a test attached to a certificate

`cert`, `cert_id`, `check_id` (**key**), `test`, `enabled`, `state` (`ok`, `warn`, `old`,
`other`, `answer`, `unreachable`, `not run`), `last_at`, `last_ok`, `fails`, `after` (which
deployments run it: `any`, `-` for none, or the targets comma separated). The last result is in
`msg`.

### `object=target | source | validation | test` - the modules

`name` (**key** within its `object`), `module_kind` (`ssh`, `f5`, `acme`, `internal_ca`,
`http01`...), `enabled`, `last_ok`, `last_error`, `note`, `tags`.

### `object=authority` - acme's own CAs

`name` (**key**), `subject`, `key_type`, `not_before`, `not_after`, `fingerprint`, `external`,
`enabled`, `crl_at`.

## 4. What isemon should do

1. **Read `kind=sync` lines** of `acme-jobs.log` (per host folder, as now).
2. **Collect a sync by its id.** Keep the objects of a `sync` until its `end` arrives.
3. **On `end`, replace the state** of that host with what the sync said:
   * certificates by `cert_id`, deployments by `deploy_id`, checks by `check_id`, the modules by
     (`object`, `name`);
   * what is not in the sync is **gone** from acme (deleted). Drop it or mark it removed, but
     only on a complete sync: `end` received, and the object counts matching `begin`'s.
   * A sync without its `end` (acme restarted mid-way) is not applied. Its objects can still
     be upserted, but nothing is dropped.
4. **After a sync, keep the state current from the live lines** as today:
   * `acme-certs` lines with `action=` `issued`, `renewed`, `deployed`, `failed`, `expired`,
     `revoked`... and `cert`, `serial`, `not_after`, `target`, `version`;
   * the `acme-jobs` lines `kind=job event=end` and `kind=check event=result`.

   A later live line wins over the sync for the same certificate, compared by line time.
5. **Merge the history without doubles.** The same history comes again with every sync, and
   overlaps the live lines isemon already has. Key them so:
   * `event=history`: (`at`, hash of `msg`). The live `acme-certs` line of the same event has
     the same words, but `at` must be taken from its syslog time (to the second).
   * `event=job`: `job`. The live job lines carry the same `job` id.
   * `event=job_step`: (`job`, `seq`).
6. **Fill the page from it:**
   * the counters: certificates, run out within N days (`not_after`), run out, failing
     (`cert_state=failed` or a deployment `deploy_state=failed`), issued and renewed / deployed
     in the period (the history and jobs);
   * the *Certificates* table: one row per `object=certificate`, with its deployments and
     checks;
   * *When they run out*: the `not_after` of every certificate;
   * the *Jobs* and *Checks* tabs: from `event=job` / `job_step` and the `object=check` rows.
7. **Header line:** "N certificates · M targets · nodes ... · last full sync <time> (<id>)", the
   time of the `end` line.

## 5. Things to know

* **Nothing secret** is in these lines: no module settings, no keys. Every value went through
  acme's redaction. Words like `[hidden]` mean something was taken out (an SSH host key
  fingerprint, a token).
* **Truncation:** a line longer than `isemon_max_bytes` (default 1800) ends `...TRUNCATED`.
  That can happen to a long `msg` of a job step, never to the key fields before it.
* **A pair of acme nodes (HA):** the sync is sent by the node it was pressed on (its `node`).
  Both nodes hold the same database, so one sync describes the whole cluster.
* **Pacing:** acme sends the sync at the pace the receiver takes it, at most half its queue at
  a time. A few thousand lines in seconds is normal.
* **Testing:** `acme --isemon-sync 0` sends only the objects (about 100 lines on a small
  installation). `acme --isemon-sync 30` adds 30 days of history. Every field is also
  described in acme's `docs/isemon.md`, under *The first full sync*.

## 6. Example of one complete sync (shortened)

```
... kind=sync event=begin sync=183b020fc4e1 certificates=45 deployments=12 checks=4 targets=12 sources=5 days=0 msg="the first full sync of acme begins"
... kind=sync event=object object=source name=LetsEncrypt module_kind=acme enabled=1 sync=183b020fc4e1 msg="source LetsEncrypt"
... kind=sync event=object object=target name=web01-nginx module_kind=local enabled=1 last_ok=2026-11-02T02:44:10Z sync=183b020fc4e1 msg="target web01-nginx"
... kind=sync event=object object=authority name="Example Root CA" key_type=ec-384 not_after=2046-10-27T16:27:33Z ... msg="authority Example Root CA"
... kind=sync event=object object=certificate cert=intranet.example.com cert_id=1 cert_state=ok not_after=2027-12-03T16:27:45Z days_left=387 ... msg="certificate intranet.example.com"
... kind=sync event=object object=deployment cert=intranet.example.com cert_id=1 deploy_id=1 target=web01-nginx deploy_state=ok deployed_version=1 ... msg="deployment intranet.example.com on web01-nginx"
... kind=sync event=object object=check cert=intranet.example.com cert_id=1 check_id=1 test=web-intranet state=unreachable after=- ... msg="127.0.0.1:8443 cannot be reached: Connection refused"
Nov  1 16:27:24 ... kind=sync event=history at=2026-11-01T16:27:24Z event_node=acme1 sync=... msg="..."
Nov  1 16:27:45 ... kind=sync event=job job=1 job_kind=renew cert=intranet.example.com cert_id=1 at=2026-11-01T16:27:45Z state=ok ok=1 took_ms=102 steps=5 version=1 sync=... msg="version 1, valid until 2027-12-03; nothing to deploy"
Nov  1 16:27:45 ... kind=sync event=job_step job=1 job_kind=renew seq=1 at=2026-11-01T16:27:45Z sync=... msg="issuing intranet.example.com ..."
... kind=sync event=end sync=183b020fc4e1 lines=95 events=0 jobs=0 took_ms=31 msg="the first full sync of acme is done"
```
