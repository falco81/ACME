# LDAP server (StartTLS) - setup for acme

The **LDAP (StartTLS)** test connects to a directory server on port `389` and sends the StartTLS extended request (OID `1.3.6.1.4.1.1466.20037`) as message 1; on result `0` (success) it makes the TLS handshake on the same connection. It does not bind (no user, no password). The certificate served is compared with the one acme keeps. Works with OpenLDAP, 389 Directory Server / Red Hat DS / FreeIPA, Active Directory domain controllers. For LDAP over TLS at once (port 636) use the **LDAPS** test.

## What you need

- A directory server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `389`.
- The DNS name directory clients use, held by the certificate; acme sends it as SNI.

## Set up the directory server

1. Give the directory server the certificate, its key and the **full chain**:

   OpenLDAP (`cn=config`):

   ```sh
   ldapmodify -Y EXTERNAL -H ldapi:/// <<'EOF'
   dn: cn=config
   replace: olcTLSCertificateFile
   olcTLSCertificateFile: /etc/openldap/tls/cert.pem
   -
   replace: olcTLSCertificateKeyFile
   olcTLSCertificateKeyFile: /etc/openldap/tls/privkey.pem
   -
   replace: olcTLSCACertificateFile
   olcTLSCACertificateFile: /etc/openldap/tls/chain.pem
   EOF
   ```

   389 Directory Server: `dsconf <instance> security certificate add` and `dsconf <instance> security set --tls-port 636`.

   **Active Directory domain controller**: the certificate (with its key, *Server Authentication* EKU and the DC's FQDN) in the **Local Computer\Personal** store (or `NTDS\Personal`); the DC picks it up for StartTLS without a restart in most cases - if not, restart the DC or use `renewServerCertificate` (rootDSE modify).
2. The key file must be readable by the server's user (`ldap` on RHEL/Alma).
3. Allow TCP `389` from acme's address:

   ```sh
   firewall-cmd --permanent --add-service=ldap && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **LDAP (StartTLS)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `389` |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects and asks for StartTLS and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -starttls ldap -connect ldap.example.com:389 -servername ldap.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls ldap` needs OpenSSL 1.1.1 or newer.) `ldapwhoami -ZZ -H ldap://ldap.example.com -x` checks StartTLS as a client would.

## Common problems

| Problem | Fix |
|---|---|
| `the LDAP server refused StartTLS (it said: unavailable (52) / protocolError (2))` | no certificate is configured for TLS, or the key cannot be read by the server's user |
| `Notice of Disconnection` | the server closed the session at once - see its log; often a TLS configuration error at start-up |
| AD: **another certificate** | the DC chose another certificate of its store (it takes one with Server Authentication and its FQDN): remove the old one, or put acme's in `NTDS\Personal`, which wins |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
