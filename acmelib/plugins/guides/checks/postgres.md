# PostgreSQL - setup for acme

The **PostgreSQL** test connects to a PostgreSQL server on port `5432` and sends the 8-byte *SSLRequest*; the server answers one byte - `S` (TLS follows) or `N` (SSL is off) - and on `S` acme makes the TLS handshake, as `psql` or a driver with `sslmode=require` would. It does not sign in, so `pg_hba.conf` and passwords play no part. The certificate served is compared with the one acme keeps. Any supported PostgreSQL version (and compatible servers: pgBouncer with `client_tls_*`, Patroni nodes).

## What you need

- A PostgreSQL server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `5432`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up PostgreSQL

1. Put the certificate (with the **intermediates after it** in the same file) and its key where PostgreSQL reads them, and switch SSL on in `postgresql.conf`:

   ```text
   ssl = on
   ssl_cert_file = '/var/lib/pgsql/data/server.crt'
   ssl_key_file = '/var/lib/pgsql/data/server.key'
   ```

2. The key must belong to the server's user and not be readable by others:

   ```sh
   chown postgres:postgres /var/lib/pgsql/data/server.{crt,key}
   chmod 0600 /var/lib/pgsql/data/server.key
   ```

3. Reload after each deployment (PostgreSQL 10+ takes new certificate files on reload; the target's reload command):

   ```sh
   sudo -u postgres psql -c 'SELECT pg_reload_conf();'
   ```

4. `listen_addresses` must include the address acme connects to (not only `localhost`), and TCP `5432` must be allowed from acme:

   ```sh
   firewall-cmd --permanent --add-service=postgresql && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **PostgreSQL**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `5432` |
| Name asked for (SNI) | empty: the certificate's first name; `-`: no SNI sent (servers that pick no certificate by name) |
| Name the certificate must hold | empty: the SNI; set it when you connect by IP but the certificate holds a DNS name |
| The certificate expected | *the version deployed now* (default); *any version* only when an older one is not a fault |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* or *both* for a server with a dual (RSA + ECDSA) certificate - needs TLS 1.2 on the server |
| Check the chain sent | on - the server must send the intermediates |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (advanced) | normally empty |
| Time limit (s) (advanced) | `15`; raise it for a slow server |
| Fail when not trusted here (advanced) | on for a public CA; off for a certificate of your own CA unless its root is trusted by acme's machine |
| Through a connector (advanced) | *directly*, or a *Connector over SSH* when only another network reaches the server |

## Check it

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects and sends the SSLRequest and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -starttls postgres -connect db.example.com:5432 -servername db.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls postgres` needs OpenSSL 1.1.1 or newer.) On the server: `psql -c 'SHOW ssl;'` says `on`.

## Common problems

| Problem | Fix |
|---|---|
| `SSL is off on the PostgreSQL server (it answered N ...)` | `ssl = off` (or the files failed to load - see the server log): set `ssl = on` and reload |
| `refused the SSLRequest (an error message ...)` | a server too old for SSL, or something else on the port |
| **an old version** | the server was not reloaded after the deployment (`SELECT pg_reload_conf();`) |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
