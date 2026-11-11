# Sending acme's logs to isemon

isemon receives what happens to the certificates over syslog, into
`/var/log/remote/<host>/`. acme sends it as it happens; on the isemon side
only a rule that files the lines is needed.

## What acme sends

What happens to the certificates - an order, a renewal, a deployment, a
failure, one running out - one event a line, program `acme-certs` (facility
`daemon`), key=value fields:

```
<29>Oct 22 15:31:02 acme1 acme-certs[812]: level=warn kind=certificates node=acme1 who="acme" msg="www.example.cz: the renewal failed - ..."
```

A value with a space or a quote in it is in quotes, its quotes and
backslashes escaped; a line never breaks. What a line is about has fields of
its own before `msg` - `action` (issued, renewed, renew, deployed, deploy,
expired, expiring, revoked...), `result` (ok, failed, expired, warn), `cert`,
`names`, `serial`, `not_after` (UTC, ISO 8601), `issuer`, and for a
deployment `target`, `target_kind`, `version`:

```
<29>Nov  1 10:27:04 acme1 acme-certs[812]: level=info kind=certificates node=acme1 who=acme action=deployed cert=www issuer="Let's Encrypt" names="www.example.cz,example.cz" not_after=2027-01-30T10:26:48Z result=ok serial=04A19C552E0B target=f5-prague target_kind=f5 version=7 msg="www (version 7) deployed to f5-prague"
```

The SIEM (Settings → Syslog / SIEM) gets the same fields in its JSON, CEF or
RFC 5424 structured data.

Optionally every other event of acme (a setting changed, a sign-in, a node
gone), the same way as program `acme` - with `isemon_events` on.

A TCP/TLS receiver that cannot be reached is tried again after 15 s, then
longer, up to 5 min; the lines meanwhile are held - the last 5 000 of each
receiver (1.0.44) - and sent in their order, with their own time, once it
answers (before, they were lost). Only beyond that are the oldest given up,
counted as missed.

The very same `acme-certs` lines are written to
`/var/log/acme/acme-certs.log` whether or not they are sent (`ship_files`).

### The certificates' work in detail (`isemon_detail`, 1.0.44)

On by default: every job of the certificates step by step, program `acme-jobs`,
for isemon's analytics - an order or a renewal (and its validations), a
deployment, the tests, an import from a source, a revocation, a dry run:

- `kind=job event=start|step|debug|http|validation|end` - every line carries
  the job (`job`, `job_kind`), its certificate (`cert`, `cert_id`, `names`,
  `issuer`, `issuer_kind`, `key_type`, `version`, `serial`, `fingerprint`,
  `not_before`, `not_after`, `cert_state`, `challenge`, `owner`), its target
  (`target`, `target_kind`, `deploy_id`) and `t_ms` since it began; a step
  `seq` and, said by a module, `module_kind` / `module` (`issuer`,
  `challenge`, `target`); a module's HTTPS request `method host port path
  query_keys status ms bytes` (no query values); a validation `name
  challenge_type via state ms`; the end `state ok took_ms steps
  result_version`;
- `kind=check event=result` - every test's result: `check_id test test_kind
  cert names state ok ms fails before went endpoint` and what it found,
  `d_<key>` a value.

Nothing secret is ever sent: `detail_redact()` takes out of every line (and of
the `acme-certs` and `acme` lines too) a PEM block, a password, token, key or
secret given as key=value or in a header, a URL's user and the values of its
secret query parameters, a JWS, and any long mixed-case blob. The same lines go
to `/var/log/acme/acme-jobs.log` with `ship_files`. The rule on the isemon side
(`deploy/isemon/11-acme.conf`) files them as `acme-jobs.log`.

### The first full sync (1.0.71)

Settings → isemon → **First full sync…**, or `acme --isemon-sync [DAYS]`, sends isemon
everything acme holds of its certificates once, so isemon starts from what is here and not
only from what happens next. The lines are program `acme-jobs`, `kind=sync`, so isemon's
rule files them as `acme-jobs.log`. Every line carries `sync=<id>`, which is the same for one
sync and new for each:

- `event=begin` - how many of each there are (`certificates deployments checks targets
  sources days`).
- `event=object` - one object a line, as it is now:
  - `object=certificate`: `cert cert_id names cn cert_state enabled issuer` (`by hand` when
    it has no source) `source challenge key_type key_type_alt version serial fingerprint
    issuer_dn not_before not_after days_left auto_renew renew_days last_ok last_try
    next_try fails last_error owner tags note eku alt_not_after alt_state created
    created_by`;
  - `object=deployment`: `cert cert_id deploy_id target deploy_state enabled
    deployed_version deployed_fp last_ok last_try fails last_error`;
  - `object=check`, a test attached: `cert check_id test enabled state last_at last_ok
    fails after` (the targets whose deployment runs it: `any`, or `-` for none). Its last
    result is in `msg`;
  - `object=source | validation | target | test`: `name module_kind enabled last_ok
    last_error note tags`;
  - `object=authority`: `name subject key_type not_before not_after fingerprint external
    enabled crl_at`.
- `event=history` - the certificates' events of the last DAYS days, oldest first, each with
  its own time (the syslog stamp, and `at` in ISO 8601 UTC), `by`, `event_node`, and the event
  in `msg`.
- `event=job` - each job of those days: `job job_kind cert cert_id deploy_id target at state
  ok finished took_ms by job_node version steps`, its result in `msg`. After it,
  `event=job_step` - each step it kept: `job seq at` and the level and words of the step.
- `event=end` - `lines events jobs took_ms`.

History is 365 days by default; 0 sends only what there is now, 3650 all that is kept. Never a
module's settings or a key, and every value goes through `detail_redact()`, as the live
lines do. The sending is paced: the shipper's queue is never filled past half, so no live line
is dropped for the sync. Only one sync runs at a time, from the node it was pressed on. The
pages show how far it got.

## On the acme server

Settings → isemon, or:

```bash
acme --set isemon=1 \
    --set isemon_targets=isemon.example.local:514/tcp \
    --set isemon_hostname=acme
acme --isemon-test
```

- `isemon_targets` — `host`, `host:port`, `/udp`, `/tcp` or `/tls` after it;
  several, separated by commas. TCP is the better choice: UDP loses lines
  when the network does.
- `isemon_hostname` — the host name on every line, which is the folder isemon
  files them under. isemon reads `/var/log/remote/acme` by default, so `acme`
  needs nothing changed there. Empty: the machine's own short name.
- `isemon_events` — every other event of acme as well, as `acme` lines.
- `isemon_max_bytes` — a longer line is cut with `...TRUNCATED`.
- `acme --isemon-sync [DAYS]` — the first full sync (above) from the command line.

## On the isemon server

1. A rule in `/etc/rsyslog.d/` that files the programs `acme-certs` (and
   `acme`, if you send those) into the folder named after the host, as the
   file named after the program -
   `/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log`, readable by the group
   `isemon`. `deploy/isemon/11-acme.conf` in this package is the template.
2. Over TCP, open 514/tcp and load `imtcp` if it is not loaded. Over UDP, a
   line longer than 2048 bytes needs `$MaxMessageSize` raised as the very
   first line of `/etc/rsyslog.conf`.
3. `rsyslogd -N1 && systemctl restart rsyslog`

Then `acme --isemon-test` on the acme server, and
`tail /var/log/remote/acme/acme-certs.log` on the isemon server after the
next renewal or deployment (the test line is an `acme` line).

## When nothing arrives

- **acme's side:** `acme --status` shows how many lines went to each target and
  the last error; Settings → isemon shows the same.
- **the network:** `tcpdump -n port 514` on the isemon server.
- **rsyslog:** a line that arrives but lands elsewhere is usually a rule
  higher up that matched first — `11-acme.conf` must come before a catch-all.
- **permissions:** the folder and files must be readable by the group
  `isemon`; the rule creates them so.

## Encrypted (TLS)

Settings → isemon → *Encrypted sending (TLS)*: the lines over TLS on 6514/tcp,
isemon's certificate checked, mutual TLS if wanted - and what to do on the isemon
machine: [isemon-tls.md](isemon-tls.md).
