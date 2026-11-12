# WSUS (Windows Server Update Services) - setup for acme

acme signs in to the WSUS server over **OpenSSH** and runs PowerShell. It uploads the certificate as a PFX (one-time random password), imports it into **LocalMachine\My** (friendly name `acme-<name>-<date>-<serial>`), deletes the PFX and then:

1. puts it on the **https binding of the IIS site "WSUS Administration"** (port **8531**) - `Remove-IISSiteBinding` and `New-IISSiteBinding -CertificateThumbPrint` (module IISAdministration); if the new one is refused, the old one is bound again; a missing https binding is created (`*:8531:`);
2. when asked, sets **Require SSL** on the five WSUS web services (`SimpleAuthWebService`, `DSSAuthWebService`, `ServerSyncWebService`, `APIremoting30`, `ClientWebService`) - never on `Content`, `Inventory`, `ReportingWebService` or `SelfUpdate` (the update payload goes over HTTP, signed);
3. runs **`WsusUtil.exe configuressl <FQDN>`** (every time, only when the binding changed, or never);
4. removes older acme certificates beyond *keep* that nothing uses (IIS / HTTP.sys bindings, RDP, SQL Server, WinRM are checked).

The binding takes effect at once, without restarting IIS. Also for WSUS as the **software update point** of Configuration Manager.

## Which versions

WSUS role on **Windows Server 2016, 2019, 2022 and 2025** - the same commands on all (WSUS is "no longer actively developed"; TLS 1.3 only on 2022/2025, from Windows itself). One module, no versions.

## What you need

- SSH from acme to the server, **TCP 22**; WSUS installed and its IIS site present.
- An account in the local **Administrators** group with an **elevated** SSH session (the built-in Administrator, a domain admin, or a local admin with `LocalAccountTokenFilterPolicy=1`). *WSUS Administrators* alone is enough for `wsusutil` but not for importing into `LocalMachine\My` or changing IIS - acme needs local Administrators.
- A certificate whose name is the **FQDN** clients use (Server Authentication). Clients and downstream servers must trust its CA.
- Ports: HTTP **8530** (content), HTTPS **8531** (metadata) - if you changed them, HTTP must stay HTTPS minus one.

## Set up the server

1. OpenSSH Server (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   New-NetFirewallRule -Name acme-sshd -DisplayName 'OpenSSH for acme' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress <acme-IP> -Action Allow
   ```

2. acme's public key for an administrator goes to `administrators_authorized_keys`, readable by Administrators and SYSTEM only:

   ```powershell
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

3. Check the site and its port:

   ```powershell
   Import-Module IISAdministration
   Get-IISSiteBinding -Name 'WSUS Administration'
   Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup' | Select-Object PortNumber, UsingSSL
   ```

4. Clients (GPO *Specify intranet Microsoft update service location*) point at `https://wsus01.corp.example.com:8531`. For a Configuration Manager SUP tick *Require SSL communication to the WSUS server* in the role's properties (check `WCM.log` for `WSUS_CONFIG_SUCCESS`); in a hierarchy go from the bottom up.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | the WSUS server, `22` |
| User / The SSH key | `Administrator` or e.g. `CORP\acme-wsus` (local Administrators) |
| IIS site of WSUS (deploy) | `WSUS Administration` (default) |
| HTTPS port (deploy) | `8531` (default); `443` if WSUS uses 80/443 |
| Server name for clients (deploy) | the FQDN for `wsusutil configuressl`, e.g. `wsus01.corp.example.com`; empty: the certificate's first name |
| Run wsusutil configuressl (deploy) | *every time* (default), *when the binding changed*, or *never* |
| Require SSL on the WSUS web services (deploy) | on for the first deployment (or set it once in IIS Manager) |
| PKCS#12 kind (advanced) | *3DES* (any Windows); *AES-256* on 2019 and later |
| Previous versions to keep (advanced) | default 1 |

With each deployment acme makes a TLS test of `<server name>:<HTTPS port>`.

## Check it

```sh
openssl s_client -connect wsus01.corp.example.com:8531 -servername wsus01.corp.example.com -showcerts </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
Get-IISSiteBinding -Name 'WSUS Administration'
netsh http show sslcert ipport=0.0.0.0:8531
Invoke-WebRequest https://wsus01.corp.example.com:8531/ClientWebService/client.asmx -UseBasicParsing
```

In the WSUS console: *Connect to Server*, port 8531, *Use Secure Sockets Layer (SSL)*. On clients: `Get-WindowsUpdateLog`.

## Common problems

| Problem | Fix |
|---|---|
| `the service WsusService is not on this server` | WSUS is not installed here, or this is another server |
| `there is no IIS site WSUS Administration` | the site has another name - put it in *IIS site of WSUS* |
| clients fail with `0x80072F8F` | clients do not trust the CA, or the name differs from the certificate; check the GPO URL (FQDN + 8531) |
| `Content` downloads break | *Require SSL* was set on `Content` by hand - take it off; acme never sets it there |
| wsusutil prints another port | the HTTP/HTTPS ports must be neighbours (8530/8531 or 80/443) |

*Uncertain*: whether `wsusutil configuressl` is needed after a plain rebind - Microsoft names it for a change of name, TLS setting or port, so acme runs it every time by default (harmless); *Require SSL* is set through `Set-WebConfigurationProperty ... sslFlags` - the documents show it in IIS Manager.

Sources: Microsoft Learn - *Secure WSUS with SSL* (WSUS deployment, step 2.5), *WsusUtil.exe*, *IISAdministration* cmdlets (`New-IISSiteBinding`, `Remove-IISSiteBinding`), Configuration Manager *software update point* TLS.
