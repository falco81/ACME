# POP3 server over TLS (POP3S) - setup for acme

The **POP3S** test connects to a mailbox server's TLS port (`995`) and makes the TLS handshake at once, as a mail program would. It does not sign in. The certificate served is compared with the one acme keeps. For port 110 with STLS use the **POP3 (STLS)** test.

## What you need

- A POP3 server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `995`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the mail server

1. Give the server the certificate, its key and the **full chain**, and switch TLS on with the POP3S listener on port `995`:

   Dovecot 2.3 (`/etc/dovecot/conf.d/10-ssl.conf`; Dovecot 2.4 names them `ssl_server_cert_file` / `ssl_server_key_file`):

   ```text
   ssl = yes
   ssl_cert = </etc/dovecot/tls/fullchain.pem
   ssl_key = </etc/dovecot/tls/privkey.pem
   ```

   Then `systemctl reload dovecot`. Exchange: `Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services POP` and restart the Exchange POP services.

2. Make the deployment reload the service (the target's reload command) - Dovecot keeps the old certificate until reloaded.
3. Allow TCP `995` from acme's address:

   ```sh
   firewall-cmd --permanent --add-service=pop3s && firewall-cmd --reload
   ```
4. fail2ban or similar must not ban acme: it connects without signing in, every few hours when tests run by themselves.

## Fill in acme

Certificates → **Tests** → *Add a test* → **POP3S**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `995` |
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
openssl s_client -connect mail.example.com:995 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| a plain greeting, or `the TLS handshake failed` at once | the port speaks plain POP3: use the POP3 (STLS) test, or enable the TLS listener (Dovecot: `inet_listener pop3s { port = 995; ssl = yes }`) |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
