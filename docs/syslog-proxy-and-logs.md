# Syslog and SIEM, the proxy, the disks and the logs (1.0.166)

All three are in *Settings*, for a full administrator, and the same for every
node of a cluster. None of them is on the way of a sign-in.

## Syslog and SIEM

*Settings → Syslog and SIEM*, off until switched on. Each node sends, as they
happen:

- every event of the Events page (`siem_events`), and
- every RADIUS Access-Request with its result (`siem_signins`): the user, the
  realm, the client, the NAS and source address, Calling-Station-Id, the
  device, let in / refused / asked for a code, the reason, how long it took.
  The password and the code typed are never sent.

Where to: up to 8 servers, `tls://siem.example.cz:6514`, `tcp://host:514` or
`udp://host:514`. TCP and TLS use octet counting (RFC 5425 / 6587); TLS checks
the server's certificate against the system's CAs, or the one given in
`siem_ca`.

The message, after an RFC 5424 header (`<PRI>1 time host acme pid type`):

| `siem_format` | what follows the header |
|---|---|
| `json` | one JSON object: `type`, `event` (`signin-accept`, `signin-reject`, `event`...), `user`, `client`, `result`, `reason`, `message`, `node`... |
| `cef` | `CEF:0|acme|acme|VERSION|event|text|severity|key=value ...` |
| `rfc5424` | structured data `[acme@32473 key="value" ...]` and the text |

The facility is `siem_facility` (13, log audit, by default). Severity: 3 for
an error, 4 for a warning or a refused sign-in, 6 for the rest.

Each node has a queue (20 000 lines) and a thread of its own. A sign-in only
puts a line in the queue; a server that is down is tried again after 30 s,
and a full queue drops lines and counts them. The page shows per node what
was sent to each server, what failed and why, what waits and what was dropped;
*Send a test line* sends one from the node the page asks, at once.

## Proxy

*Settings → Proxy*, off until switched on: `proxy_url` is `http://host:port`;
the user name and the password (kept sealed, like the other passwords) are
fields of their own. Through it go:

- the look for new versions and their download (Upgrades),
- the HTTP SMS gateway and the telephone gateway (`proxy_sms`),
- dnf or apt, on every node (`proxy_os`): the proxy is handed to the root
  helper in its request and to the update in `/run/acme-osup-proxy.json`
  (root only, 0600) as `https_proxy`/`http_proxy` - never on a command line.

Mail, Active Directory, the database, syslog and the other node never go
through it. `proxy_no` lists what is reached straight: a name, `.example.cz`
for every name under it, an address or a net (`10.0.0.0/8`). *Try it* asks
an address through the proxy and says what came back - a 407 means the user
name or the password is missing or wrong.

## Disks and logs

*Settings → Disks and logs* shows each node's file systems, how much its
system journal, `/var/log/acme` and acme's data take, and whether the node has
put the settings in:

- `logs_journal_mb`, `logs_journal_days`: `SystemMaxUse=` and
  `MaxRetentionSec=` in `/etc/systemd/journald.conf.d/00-acme.conf`
  (systemd-journald restarted only when the file changed); both 0 removes the
  file - the system's own limits again.
- `logs_keep`, `logs_max_mb`: `rotate` and `maxsize` of `/etc/logrotate.d/acme`,
  nothing else in it changed.

Each node puts them in itself through its root helper (`logs.ask`), within a
minute of a change, and reads the sizes again every 6 hours; *Put in and look
again* asks every node now.
