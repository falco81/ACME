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
backslashes escaped; a line never breaks.

Optionally every other event of acme (a setting changed, a sign-in, a node
gone), the same way as program `acme` - with `isemon_events` on.

The very same `acme-certs` lines are written to
`/var/log/acme/acme-certs.log` whether or not they are sent (`ship_files`).

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
