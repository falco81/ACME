# How acme is put together

```
  VPN (ASA) ──UDP 1812/1813──▶ ┌──────────────────────────── acme.py (user acme) ──┐
                               │ RADIUS server ─▶ decision ─▶ tokens (TOTP)      │
  browser ──HTTPS──▶ nginx     │                    │                            │
             │                 │                    └──▶ directories (LDAP/AD) ──┼──▶ domain controllers
             ▼                 │ JSON API 127.0.0.1:9861 (token in /run/acme)     │
   php-fpm pool "acme"  ───────▶│ storage: SQLite / MariaDB / PostgreSQL          │
   (user acme-www, relays only) │ shipper: totp.cgi + radius-detail syslog ───────┼──▶ isemon
                               └─────────────────────────────────────────────────┘
```

**One daemon does everything.** `acme.py` is a single file using the Python
standard library: the RADIUS server (its own packet code, RFC 2865/2866/
2869/3579/5997), TOTP/HOTP, the QR codes (its own encoder, drawn as SVG for
the pages and as half-blocks for the terminal), an LDAP client (read only:
it refuses to write), the database layer, the syslog shipper, the JSON API and
the command line. Run with no arguments it is the daemon; with arguments it
is the command line, which works on the same database.

**The pages hold no logic.** `index.php` (enrolment) and `admin/index.php`
(administration) relay each request to the daemon's API on 127.0.0.1 with the
API token from `/run/acme/api-token` and the person's session, and draw what
comes back. Every check — who may do what, the password, the rate limits —
is the daemon's. A PHP that is broken into reaches a JSON API and nothing
else.

**A RADIUS request, step by step:**

1. The packet comes from a client (by address, the narrowest range wins);
   from anywhere else it is dropped unanswered. The Message-Authenticator is
   checked; a repeat within the duplicate window gets the same answer again.
2. The client's realm is added to a name without one (FreeRADIUS's hints).
3. The realm is chosen by what follows the @ (then empty, then `*`).
4. The password is split as the realm says: the code alone, or the directory
   password followed by the code.
5. The code is checked against the token: rate limit, window, reuse, recovery
   codes — with totpcgi's messages.
6. The person is looked up in the realm's directory: found, not disabled, not
   expired, the password (when asked), a member of one of the groups (nested
   when allowed).
7. Access-Accept with the realm's and the group's reply lines, or
   Access-Reject with the reason as Reply-Message; signed with a
   Message-Authenticator.
8. Every step, with how long it took, is kept with the request (the Log
   tab, `acme --request ID`), and the lines go to isemon.

**Settings** are layered as in isemon: the built-in defaults, then
`/etc/acme/config.json`, then what was saved on the pages (in the
database). A change takes effect when it is saved — nothing restarts.
