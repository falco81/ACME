# FTP server over TLS (implicit FTPS) - setup for acme

The **FTPS** test connects to an FTP server's implicit-TLS port (`990`) and makes the TLS handshake at once, as an FTP program set to *implicit FTPS* would. It does not sign in. The certificate served is compared with the one acme keeps. For FTP on port 21 with AUTH TLS (explicit FTPS, the more common one) use the **FTP (AUTH TLS)** test.

## What you need

- An FTP server with an implicit-TLS listener with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `990`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the FTP server

1. Give the FTP server the certificate, its key and the **full chain**, and switch TLS on:

   vsftpd (`/etc/vsftpd/vsftpd.conf`):

   ```text
   ssl_enable=YES
   rsa_cert_file=/etc/vsftpd/tls/fullchain.pem
   rsa_private_key_file=/etc/vsftpd/tls/privkey.pem
   implicit_ssl=YES
   listen_port=990
   ```

   ProFTPD (mod_tls): `TLSEngine on`, `TLSRSACertificateFile`, `TLSRSACertificateKeyFile`, `TLSCertificateChainFile` and `TLSOptions UseImplicitSSL` on a `<VirtualHost>` with `Port 990`. IIS FTP: the site's **FTP SSL Settings** → the certificate (it must be in the Local Computer\Personal store).
2. Restart the service after each deployment (the target's reload command): `systemctl restart vsftpd`.
3. Allow TCP `990` from acme's address (the test opens no data connection, so passive ports do not matter for it):

   ```sh
   firewall-cmd --permanent --add-port=990/tcp && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **FTPS**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `990` |
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
openssl s_client -connect ftp.example.com:990 -servername ftp.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| a `220` text, or `the TLS handshake failed` at once | the port speaks plain FTP: use the FTP (AUTH TLS) test, or enable implicit TLS (`implicit_ssl=YES`) |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
