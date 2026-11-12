# Microsoft SQL Server - setup for acme

The **Microsoft SQL Server** test connects to SQL Server on port `1433`, sends a TDS *PRELOGIN* packet asking for encryption, reads the server's PRELOGIN answer and makes the TLS handshake carried inside TDS packets - as SQL Server Management Studio or a driver with *Encrypt* would. It does not sign in. The certificate served is compared with the one acme keeps. SQL Server 2016 - 2022 (and 2025) on Windows or Linux. A server set to TDS 8.0 *strict* encryption speaks TLS at once: test it with the **TLS (any port)** test on port 1433.

## What you need

- SQL Server with a certificate chosen for the instance - normally the one acme deploys to the Windows certificate store (Local Computer\Personal) or, on Linux, to the files `mssql-conf` points at.
- Network access **from acme** (or its connector) to TCP `1433` - or the instance's own static port; a named instance on a dynamic port cannot be found through SQL Browser (UDP 1434) by this test, so give it a static port.
- The DNS name clients use, held by the certificate.

## Set up SQL Server

1. Windows: the certificate (with its key, *Server Authentication* EKU, the server's FQDN) in **Local Computer\Personal**. Grant the SQL Server service account read access to the key (certlm.msc → the certificate → All Tasks → Manage Private Keys → add `NT Service\MSSQLSERVER` or the instance's service account → Read).
2. Choose it for the instance: **SQL Server Configuration Manager → SQL Server Network Configuration → Protocols for <instance> → Properties → Certificate** (SQL Server 2019+ also: Import / the thumbprint). Or set the thumbprint (lower case, no spaces) in the registry value `Certificate` under `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance id>\MSSQLServer\SuperSocketNetLib` - that is what a Windows target can update on each deployment.
3. **Restart the SQL Server service** - SQL Server loads its certificate only at start:

   ```powershell
   Restart-Service -Name MSSQLSERVER -Force
   ```

   Linux: `mssql-conf set network.tlscert /etc/ssl/certs/mssql.pem`, `mssql-conf set network.tlskey /etc/ssl/private/mssql.key`, `systemctl restart mssql-server`.
4. TCP/IP must be enabled for the instance (Protocols → TCP/IP → Enabled) and TCP `1433` allowed from acme:

   ```powershell
   New-NetFirewallRule -DisplayName 'SQL Server 1433' -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress <acme IP> -Action Allow
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **Microsoft SQL Server**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `1433` |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects, sends PRELOGIN and runs TLS inside TDS and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

There is no `openssl s_client` mode for TDS. On the server, the SQL Server error log says at start which certificate was loaded:

```powershell
Select-String -Path 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG' -Pattern 'certificate'
```

It should say `The certificate [Cert Hash(sha1) "<thumbprint>"] was successfully loaded for encryption.` - compare the hash with the certificate's SHA-1 in acme.

## Common problems

| Problem | Fix |
|---|---|
| **another certificate** (a self-signed one, `CN=SSL_Self_Signed_Fallback`) | no certificate is chosen for the instance, or the service account cannot read its key - SQL Server falls back to its own; fix the key permissions and restart |
| **an old version** | SQL Server was not restarted after the deployment |
| `the SQL Server does not do encryption (ENCRYPT_NOT_SUP ...)` | encryption is unavailable on that instance: choose a certificate for it |
| `the server does not speak TDS` | the port is not SQL Server's (a named instance on another port), or TDS 8.0 strict: use the TLS test |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
