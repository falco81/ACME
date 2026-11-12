# TLS server (any port) - setup for acme

The **TLS (any port)** test connects to any port that speaks TLS at once - a web server, a reverse proxy, LDAPS, MQTT over TLS, an API, SQL Server with TDS 8.0 strict - and makes the TLS handshake with the certificate's name as SNI. Nothing is sent after the handshake. The certificate served is compared with the one acme keeps. For a web site with an HTTP request use **HTTPS**; for protocols that start in plain text use their own test (SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL, SQL Server, RDP).

## What you need

- A server that speaks TLS at once on its port with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `443` (or the service's own port).
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the server

1. Configure the server with the certificate, its key and the **full chain** (the leaf followed by the intermediates):

   nginx:

   ```text
   ssl_certificate     /etc/nginx/tls/fullchain.pem;
   ssl_certificate_key /etc/nginx/tls/privkey.pem;
   ```

   Apache httpd 2.4.8+: `SSLCertificateFile` (the full chain) and `SSLCertificateKeyFile`. IIS: the site's **Bindings → https → SSL certificate** (with *Require Server Name Indication* for SNI sites). HAProxy: `bind :443 ssl crt /etc/haproxy/certs/`.
2. Reload the server after each deployment (the target's reload command): `systemctl reload nginx`.
3. Every virtual host of the certificate's names must answer with SNI; a server behind a load balancer: test each node by its IP in *Connect to*.
4. Allow TCP `443` from acme (or its connector):

   ```sh
   firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **TLS (any port)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `443` - or the service's own port |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects with TLS at once and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| a plain-text greeting / `the TLS handshake failed` (wrong version number) | the port does not speak TLS at once: it is plain HTTP or a STARTTLS protocol - use that protocol's test |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
