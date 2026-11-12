# Remote Desktop (RDP) - setup for acme

The **RDP (Remote Desktop)** test connects to a Remote Desktop server on port `3389`, sends the X.224 Connection Request asking for TLS and CredSSP (NLA), reads the Connection Confirm and makes the TLS handshake on the same connection - the certificate *Remote Desktop Connection* would get. It does not sign in (CredSSP is not needed: the certificate is seen in the TLS handshake). The certificate served is compared with the one acme keeps. Windows Server 2012 R2 - 2025 and Windows 10/11, or another RDP server (xrdp). An RD Gateway or RD Web is HTTPS: use the **HTTPS** test for it.

## What you need

- Remote Desktop enabled, with the certificate acme deploys (Local Computer\Personal on Windows) chosen as the RDP listener's certificate - a Windows target can set it on each deployment.
- The security layer must be **TLS** or **Negotiate**, not *RDP Security Layer* (standard RDP security has no certificate to test).
- Network access **from acme** (or its connector) to TCP `3389`.

## Set up Remote Desktop

1. Import the certificate (with its key, *Server Authentication* EKU, the server's FQDN) into **Local Computer\Personal**, and give `NETWORK SERVICE` read access to its key (certlm.msc → All Tasks → Manage Private Keys).
2. Point the RDP listener at it by thumbprint:

   ```powershell
   $tp = '<thumbprint>'
   $ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
   Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash = $tp}
   ```

   No restart is needed - new connections get the new certificate. (Group Policy can also choose it: *Remote Desktop Session Host → Security → Server authentication certificate template* - a policy wins over the setting above.)
3. Security layer: Group Policy **Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → Require use of specific security layer for remote (RDP) connections** = *SSL* or *Negotiate* (or not configured).
4. Allow TCP `3389` from acme:

   ```powershell
   Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
   ```

   xrdp: `certificate=` and `key_file=` in `/etc/xrdp/xrdp.ini`, `security_layer=tls` or `negotiate`, then `systemctl restart xrdp`.

## Fill in acme

Certificates → **Tests** → *Add a test* → **RDP (Remote Desktop)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `3389` |
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

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects and runs the RDP negotiation and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

On the server, the thumbprint the listener uses:

```powershell
(Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash
```

It must equal the certificate's SHA-1 thumbprint shown in acme (`openssl s_client` has no RDP mode).

## Common problems

| Problem | Fix |
|---|---|
| `the RDP server uses standard RDP security - no TLS` | the security layer is *RDP Security Layer*: set *SSL* or *Negotiate* |
| `the RDP server refused TLS: ...` | the reason is said (e.g. `SSL_CERT_NOT_ON_SERVER` - the certificate chosen is missing or its key unreadable) |
| **another certificate** (`CN=<computer name>`, self-signed) | the listener still uses its own self-signed certificate: set `SSLCertificateSHA1Hash`, check `NETWORK SERVICE` can read the key; a GPO template may override it |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
