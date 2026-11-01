# Sending acme's logs to isemon

isemon already reads a token server: a totpcgi server and the FreeRADIUS in
front of it, whose lines arrive over syslog into `/var/log/remote/<host>/`.
acme writes exactly those lines, so isemon needs no new code — only the rule
that files them, and its ACME settings switched on.

## What acme sends

Every check of a code, as the token server's own line (facility `auth`,
program `totp.cgi`):

```
<37>Oct 22 16:33:01 acme totp.cgi[4711]: Failure: user=falco@dpmo.cz, mode=PAM_SM_AUTH, host=127.0.0.1, rid=192.9.212.1:23, message=Not a valid token
<37>Oct 22 16:34:12 acme totp.cgi[4711]: Success: user=falco@dpmo.cz, mode=PAM_SM_AUTH, host=127.0.0.1, rid=192.9.212.1:24, message=Valid token used
```

The messages are totpcgi's own, word for word: `Valid token used`, `Valid
token within window size used`, `Scratch-token used`, `Not a valid token`,
`Token has already been used once`, `Rate-limit reached, please try again
later`, `No token is enrolled for this account`.

Every RADIUS packet behind it, as a `radius-detail` line (facility `local5`) —
the request, the answer and accounting, with `Totp-Request-Id` tying the
packet to the check of the code (`rid=` above), the way the detail
forwarding in isemon's `docs/acme-radius-detail/` does it:

```
<173>Oct 22 16:33:01 acme radius-detail[4711]: nas=192.9.212.1 id=… file=auth-detail-20261022 ts=[Thu Oct 22 16:33:01 2026] Packet-Type = Access-Request, User-Name = "falco", Calling-Station-Id = "203.0.113.7", …, Totp-Request-Id = "192.9.212.1:23"
```

Optionally its own events (a token made, a setting changed), program `acme`.
isemon does not read those.

The very same lines are written to `/var/log/acme/totp.cgi.log` and
`/var/log/acme/radius-detail.log` whether or not they are sent.

## On the acme server

Settings → isemon, or:

```bash
acme --set isemon=1 \
    --set isemon_targets=isemon.example.local:514/tcp \
    --set isemon_hostname=acme \
    --set isemon_detail=1
acme --isemon-test
```

- `isemon_targets` — `host`, `host:port`, `/udp` or `/tcp` after it; several,
  separated by commas. TCP is the better choice: a detail line is long and
  UDP loses lines when the network does.
- `isemon_hostname` — the host name on every line, which is the folder isemon
  files them under. isemon reads `/var/log/remote/acme` and
  `/var/log/remote/acmesec` by default, so `acme` (and `acmesec` for a second
  server) need nothing changed there.
- `isemon_max_bytes` — a longer line is cut with `...TRUNCATED`.

## On the isemon server

1. Copy `deploy/isemon/11-acme.conf` from this package to `/etc/rsyslog.d/`.
2. For UDP, raise the message size: `$MaxMessageSize 8192` as the very first
   line of `/etc/rsyslog.conf`. Over TCP, open 514/tcp and load `imtcp` if it
   is not loaded.
3. `rsyslogd -N1 && systemctl restart rsyslog`
4. isemon → Settings → *The ACME logs*: switched on, the folder `acme` in its
   paths, and *RADIUS detail* switched on.

Then `acme --isemon-test` on the acme server, and
`tail /var/log/remote/acme/totp.cgi.log` on the isemon server.

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
