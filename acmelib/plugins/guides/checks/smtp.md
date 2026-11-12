# SMTP server (STARTTLS) - setup for acme

The **SMTP (STARTTLS)** test connects to a mail server as another mail server (or a mail program) would: it reads the `220` greeting, sends `EHLO acme-check.<name>`, looks for `STARTTLS` among the extensions, sends `STARTTLS`, waits for `220` and makes the TLS handshake on the same connection. No mail is sent and no password is used. The certificate served is compared with the one acme keeps. Works with any SMTP server - Postfix, Exim, Sendmail, Microsoft Exchange, appliances. For SMTP over TLS at once (port 465) use the **SMTPS** test.

## What you need

- An SMTP server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `25` (or `587` for submission).
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the mail server

1. Give the server the certificate and its key with the **full chain**, and offer STARTTLS:

   Postfix (`/etc/postfix/main.cf`):

   ```sh
   postconf -e 'smtpd_tls_cert_file = /etc/postfix/tls/fullchain.pem' \
               'smtpd_tls_key_file = /etc/postfix/tls/privkey.pem' \
               'smtpd_tls_security_level = may'
   systemctl reload postfix
   ```

   Exim: `tls_certificate`, `tls_privatekey` and `tls_advertise_hosts = *`. Exchange (Exchange Management Shell):

   ```powershell
   Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services SMTP
   ```

2. Make the deployment reload the service (the target's reload/restart command) - a running Postfix or Exim keeps the old certificate until reloaded.
3. Allow TCP `25` (and/or `587`) from acme's address in the host firewall and any network firewall:

   ```sh
   firewall-cmd --permanent --add-service=smtp && firewall-cmd --reload
   ```

4. Anti-spam or rate limits (postscreen, greylisting, `smtpd_client_connection_rate_limit`) must not drop acme's connection before EHLO - whitelist acme's IP where they do.

## Fill in acme

Certificates → **Tests** → *Add a test* → **SMTP (STARTTLS)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `25` (`587` for submission: mail programs sending with a password) |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects and runs EHLO and STARTTLS and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -starttls smtp -connect mail.example.com:25 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| `the server does not offer STARTTLS` | TLS is off or no certificate is set (Postfix: `smtpd_tls_security_level = may`, the cert/key files); some firewalls (SMTP inspection) strip STARTTLS - switch that off |
| `the SMTP server does not take mail now` | the greeting was not `220` (e.g. `554` - acme's IP is blocked or postscreen rejects it): whitelist acme |
| `the SMTP server refused EHLO` / `refused STARTTLS` | see the server's mail log for why; check `smtpd_helo_restrictions` and TLS settings |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
