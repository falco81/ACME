# FTP server (AUTH TLS, explicit FTPS) - setup for acme

The **FTP (AUTH TLS)** test connects to an FTP server on port `21` as an FTP program would: it reads the `220` greeting, sends `AUTH TLS` and makes the TLS handshake on the same connection (explicit FTPS, RFC 4217). It does not sign in and opens no data connection. The certificate served is compared with the one acme keeps. Works with vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, IIS FTP. For FTPS at once on port 990 use the **FTPS** test.

## What you need

- An FTP server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `21`.
- The DNS name FTP clients use, held by the certificate; acme sends it as SNI.

## Set up the FTP server

1. Give the FTP server the certificate, its key and the **full chain**, and switch TLS on:

   vsftpd (`/etc/vsftpd/vsftpd.conf`):

   ```text
   ssl_enable=YES
   rsa_cert_file=/etc/vsftpd/tls/fullchain.pem
   rsa_private_key_file=/etc/vsftpd/tls/privkey.pem
   ```

   ProFTPD (mod_tls): `TLSEngine on`, `TLSRSACertificateFile`, `TLSRSACertificateKeyFile`, `TLSCertificateChainFile`. IIS FTP: the site's **FTP SSL Settings** → the certificate (it must be in the Local Computer\Personal store).
2. Restart the service after each deployment (the target's reload command): `systemctl restart vsftpd`.
3. Allow TCP `21` from acme's address (the test opens no data connection, so passive ports do not matter for it):

   ```sh
   firewall-cmd --permanent --add-port=21/tcp && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **FTP (AUTH TLS)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `21` |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects and sends AUTH TLS and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -starttls ftp -connect ftp.example.com:21 -servername ftp.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| `AUTH TLS` refused (`500`/`502`/`534`) | TLS is not switched on in the FTP server (`ssl_enable=YES`, `TLSEngine on`) |
| the greeting is not `220` | the server refuses acme's address (`tcp_wrappers`, a max-clients limit): allow acme |
| an FTP-aware firewall in between | some firewalls (FTP inspection / ALG) break AUTH TLS: switch inspection off for this server |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
