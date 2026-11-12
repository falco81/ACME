# MySQL / MariaDB - setup for acme

The **MySQL / MariaDB** test connects to the database server on port `3306`, reads its greeting (the Initial Handshake Packet) and checks it offers TLS (`CLIENT_SSL`), answers with an *SSLRequest* packet - no user, no password - and makes the TLS handshake, as the `mysql` client or a driver would. The certificate served is compared with the one acme keeps. MySQL 5.7 / 8.x and MariaDB 10.x / 11.x.

## What you need

- A MySQL or MariaDB server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `3306`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up MySQL / MariaDB

1. Put the certificate, its key and the CA chain where the server reads them, in `[mysqld]` (`/etc/my.cnf.d/server.cnf` or `/etc/mysql/my.cnf`):

   ```text
   [mysqld]
   ssl_cert = /etc/mysql/tls/fullchain.pem
   ssl_key  = /etc/mysql/tls/privkey.pem
   ssl_ca   = /etc/mysql/tls/chain.pem
   ```

   The files must be readable by the `mysql` user.
2. Load the new files after each deployment (the target's reload command) - without a restart:

   ```sh
   mysql -e 'ALTER INSTANCE RELOAD TLS;'   # MySQL 8.0.16+
   mariadb -e 'FLUSH SSL;'                 # MariaDB 10.4+
   ```

   Older versions: restart the service.
3. `bind-address` must include the address acme connects to; allow TCP `3306` from acme:

   ```sh
   firewall-cmd --permanent --add-service=mysql && firewall-cmd --reload
   ```

4. MySQL's `max_connect_errors` counts handshakes that never sign in: if acme's IP gets *blocked because of many connection errors*, raise it or run `FLUSH HOSTS` (MySQL 8: `TRUNCATE performance_schema.host_cache`).

## Fill in acme

Certificates → **Tests** → *Add a test* → **MySQL / MariaDB**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `3306` |
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
openssl s_client -starttls mysql -connect db.example.com:3306 -servername db.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls mysql` needs OpenSSL 1.1.1 or newer.) On the server: `mysql -e "SHOW VARIABLES LIKE '%ssl%';"`.

## Common problems

| Problem | Fix |
|---|---|
| `the MySQL server does not offer TLS (... without CLIENT_SSL ...)` | no certificate set, or `have_ssl` is `DISABLED` (the files could not be read - see the error log) |
| `the MySQL server refused the connection (error 1130 / 1129 ...)` | 1130: acme's host is not allowed to connect at all; 1129: blocked after many connection errors - `FLUSH HOSTS`, raise `max_connect_errors` |
| **an old version** | the new files were not loaded: `ALTER INSTANCE RELOAD TLS` / `FLUSH SSL`, or a restart |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
