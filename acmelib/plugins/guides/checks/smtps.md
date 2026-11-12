# SMTP server over TLS (SMTPS) - setup for acme

The **SMTPS** test connects to a mail server's port for SMTP over TLS at once (implicit TLS, RFC 8314 - port `465`, *submissions*) and makes the TLS handshake straight away, as a mail program would. Nothing is sent after the handshake; no mail and no password. The certificate served is compared with the one acme keeps. For port 25/587 with STARTTLS use the **SMTP (STARTTLS)** test.

## What you need

- An SMTP server with a TLS-at-once listener with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `465`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the mail server

1. Switch the implicit-TLS listener on, with the certificate, its key and the **full chain**:

   Postfix (`/etc/postfix/master.cf`, then the cert/key in `main.cf` as `smtpd_tls_cert_file` / `smtpd_tls_key_file`):

   ```text
   submissions inet n - n - - smtpd
     -o smtpd_tls_wrappermode=yes
     -o smtpd_sasl_auth_enable=yes
   ```

   Exim: `tls_on_connect_ports = 465` and `daemon_smtp_ports = 25 : 465 : 587`. Exchange: `Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services SMTP`.
2. Reload the service after each deployment (the target's reload command): `systemctl reload postfix`.
3. Allow TCP `465` from acme's address:

   ```sh
   firewall-cmd --permanent --add-service=smtps && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **SMTPS**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `465` |
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
openssl s_client -connect mail.example.com:465 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| `the TLS handshake failed` right away, or a `220` text | the port speaks plain SMTP (STARTTLS), not TLS at once: use the SMTP (STARTTLS) test, or switch on `smtpd_tls_wrappermode` |
| `... does not answer` | the submissions listener is not enabled in `master.cf`, or the port is closed |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
