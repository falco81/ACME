# SQL Server Reporting Services / Power BI Report Server - setup for acme

acme signs in to the report server over **OpenSSH** and runs PowerShell. It uploads the certificate as a PFX (one-time random password), imports it into **LocalMachine\My** (friendly name `acme-<name>-<date>-<serial>`), deletes the PFX and then, through the report server's **WMI provider** (`root\Microsoft\SqlServer\ReportServer\RS_<instance>\v<version>\Admin`, class `MSReportServer_ConfigurationSetting`):

1. lists the HTTPS bindings (`ListSSLCertificateBindings`) - the web service and the web portal, each IP and port;
2. for each one not on the new certificate: `RemoveSSLCertificateBindings` (the old hash), then `CreateSSLCertificateBinding` with the new hash **in small letters** (the method fails otherwise); if the new one is refused, the old binding is created again;
3. removes older acme certificates beyond *keep* that nothing uses (HTTP.sys bindings are checked - SSRS's are there). **The binding is removed before the old certificate** - an SSRS binding left on a deleted certificate cannot be removed through WMI any more.

acme replaces bindings, it does not make the first one: choose the HTTPS certificate once in **Report Server Configuration Manager** (*Web Service URL → HTTPS Certificate*, *Web Portal URL → Advanced → Multiple HTTPS Identities*). The change recycles the report server's application domains (seconds).

## Which versions

**SSRS 2016, 2017, 2019, 2022** and **Power BI Report Server** (on-premises reporting of SQL Server 2025) - the same WMI methods; acme finds the instance and its newest `v<NN>` namespace by itself. One module, no versions.

## What you need

- SSH from acme to the server, **TCP 22**.
- An account in the local **Administrators** group with an **elevated** SSH session - the WMI class is "only accessible with administrative privileges".
- A certificate (Server Authentication) whose name is the URL's host name; SSRS does not use client certificates.
- IIS on the same machine shares HTTP.sys: keep each IP:port managed by one tool.

## Set up the server

1. OpenSSH Server and acme's key (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. The instance and the bindings acme will see:

   ```powershell
   Get-WmiObject -Namespace 'root\Microsoft\SqlServer\ReportServer' -Class __Namespace | Select-Object Name
   $rs = Get-WmiObject -Namespace 'root\Microsoft\SqlServer\ReportServer\RS_SSRS\v16\Admin' -Class MSReportServer_ConfigurationSetting
   $b = $rs.ListSSLCertificateBindings(1033); $b.Application; $b.CertificateHash; $b.IPAddress; $b.Port
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | the report server, `22` |
| User / The SSH key | `Administrator` or e.g. `CORP\acme-rs` (local Administrators) |
| Report server instance (deploy) | `SSRS`, `PBIRS`, `MSSQLSERVER`...; empty when there is only one |
| HTTPS port to check (deploy) | `443` (default) - acme tests `<address>:<port>` with the deployment; `0`: no test |
| PKCS#12 kind (advanced) | *3DES* (any Windows); *AES-256* on 2019 and later |
| Previous versions to keep (advanced) | default 1 |

## Check it

```sh
openssl s_client -connect reports.example.com:443 -servername reports.example.com </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
netsh http show sslcert ipport=0.0.0.0:443
```

Report Server Configuration Manager → *Web Service URL* and *Web Portal URL* show the certificate; open `https://reports.example.com/Reports`.

## Common problems

| Problem | Fix |
|---|---|
| `no report server ... is on this server` | SSRS / PBIRS not installed, or the WMI provider not registered |
| `there are several instances` | name one in *Report server instance* |
| `there is no HTTPS binding yet` | set HTTPS up once in Report Server Configuration Manager |
| `... could not be removed` | the old certificate was deleted while still bound: remove the HTTP.sys binding with `netsh http delete sslcert ipport=0.0.0.0:443`, then bind once in the Configuration Manager |

*Uncertain*: the out-parameter names of `ListSSLCertificateBindings` (`IPAddress` - acme also takes `IPAddresses`) and the application names (acme uses the ones the list gives, not fixed names); no service restart is done (the binding change recycles the application domains).

Sources: Microsoft Learn - *Configure TLS connections on a native mode report server*, WMI provider methods `ListSSLCertificateBindings`, `CreateSSLCertificateBinding`, `RemoveSSLCertificateBinding(s)`, *Access the Reporting Services WMI provider*.
