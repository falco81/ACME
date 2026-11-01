# How acme works

```
                                ┌──────────────── acme daemon (user acme) ────────────────┐
  browser ──HTTPS──▶ nginx      │ certificates: renew ▶ prove the names ▶ deploy          │──▶ CAs (Let's Encrypt,
             │                  │   (issuers, challenges, targets - modules)              │    own CA, AD CS, SCEP)
             ▼                  │ DNS server (UDP/TCP 53) for DNS-01                      │──▶ targets (SSH, F5, …)
   php-fpm pool "acme" ────────▶│ JSON API 127.0.0.1:9861 (token in /run/acme)            │
   (user acme-www, relays only) │ directories (LDAP/AD) for the sign-ins ─────────────────┼──▶ domain controllers
                                │ storage: SQLite / MariaDB / PostgreSQL                  │
                                │ shipper: acme-certs lines ──────────────────────────────┼──▶ isemon, SIEM
                                └─────────────────────────────────────────────────────────┘
```

The parts, the tables and the API are in [architecture.md](architecture.md);
what the certificate manager does is in [certificates.md](certificates.md).

**One daemon does everything.** `acme.py` with `acmelib/` uses the Python
standard library and `openssl`: the certificate manager and its modules, the
ACME client, acme's own CAs, the DNS server for DNS-01, an LDAP client (read
only: it refuses to write), the database layer, the cluster, mail and SMS,
the syslog shipper, the JSON API and the command line. Run with no arguments
it is the daemon; with arguments it is the command line, which works on the
same database.

**The pages hold no logic.** `index.php` (the enrolment pages - the
certificate portal) and `admin/index.php` (administration) relay each request
to the daemon's API on 127.0.0.1 with the API token from `/run/acme/api-token`
and the person's session, and draw what comes back. Every check — who may do
what, the password, the second step, the rate limits — is the daemon's. A PHP
that is broken into reaches a JSON API and nothing else.

**A renewal, step by step:**

1. Every few minutes the node that leads (in a cluster the one holding the
   VIP address, else the only node) looks for certificates due: within
   `renew_days` of the end, inside the window the CA suggests (ARI), or failed
   and past their backoff.
2. A job is made for each: a new key (unless the key is kept) and a CSR.
3. The issuer is asked. For ACME every name is proved by its challenge -
   a TXT record (acme's own DNS server, RFC 2136, a DNS provider's API) or a
   file over HTTP-01 - waited for, and cleaned up afterwards.
4. The new certificate becomes the current one; the old one is kept.
5. Every enabled deployment of it is run: the target's module puts it in
   place in the formats asked, makes the service take it, and checks what is
   served.
6. Every step, with how long it took, is kept with the job (the Jobs tab,
   `acme --job ID`). A failure is an event, an alert by mail or SMS, and a
   line to syslog/SIEM and isemon.

**Settings** are layered as in isemon: the built-in defaults, then
`/etc/acme/config.json`, then what was saved on the pages (in the
database). A change takes effect when it is saved — nothing restarts.
