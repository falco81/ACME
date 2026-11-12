# Office Online Server - setup for acme

acme signs in to an Office Online Server (OOS) over **OpenSSH** and runs PowerShell. It uploads the certificate as a PFX (one-time random password), imports it into **LocalMachine\My** with an **exportable** key (OOS requires it) and the friendly name `acme-<name>-<date>-<serial>` - unique, as OOS requires - deletes the PFX and then:

1. reads the farm (`Get-OfficeWebAppsFarm`); a farm with **SSL offloading** is refused (the certificate belongs on the load balancer);
2. checks the friendly name is on exactly one certificate;
3. `Set-OfficeWebAppsFarm -CertificateName <friendly name> -Force` - the farm-wide setting; acme does **not** bind the certificate in IIS itself (OOS makes its binding; a manual one is lost at a restart);
4. when asked, schedules a **restart of this server** in a minute (`shutdown /r /t 60`) - the farm takes the certificate after its servers restart; the tests after the deployment then wait up to ~6 minutes;
5. removes older acme certificates beyond *keep*, never the one the farm names.

## Which versions

Office Online Server (the current release, Desktop Experience) on **Windows Server 2016 (Nov 2018 update or later), 2019 (Jul 2021 patch or later) and 2022 (Nov 2021 patch or later)** - one module, no versions. Used by SharePoint Server (2016, 2019, SE) and Exchange.

## What you need

- SSH from acme to **each** OOS server, **TCP 22** - one acme target per server, all deploying the same certificate (the friendly name is the same on each).
- An account in the local **Administrators** group with an **elevated** SSH session (the OfficeWebApps module and `LocalMachine\My` need it).
- A certificate from a CA the SharePoint/Exchange servers and the browsers trust, with the **farm's FQDN** (internal and external URL) in its SAN; no special EKU.

## Set up the server

1. OpenSSH Server and acme's key (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. The farm exists already (made once, with any certificate):

   ```powershell
   Import-Module OfficeWebApps
   Get-OfficeWebAppsFarm | Format-List InternalURL, ExternalURL, CertificateName, SSLOffloaded
   ```

3. With several servers: deploy to them **one at a time** with *Restart this server* on, or restart them yourself in turn behind the load balancer.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | the OOS server, `22` |
| User / The SSH key | `Administrator` or e.g. `CORP\acme-oos` (local Administrators) |
| Restart this server after the change (deploy) | off (default): restart in a maintenance window; on: in a minute |
| HTTPS port to check (deploy) | `443` (default); `0`: no test |
| PKCS#12 kind (advanced) | *3DES* (any Windows); *AES-256* on 2019 and later |
| Previous versions to keep (advanced) | default 1 |

## Check it

```sh
openssl s_client -connect oos.example.com:443 -servername oos.example.com </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
Get-OfficeWebAppsFarm | Format-List CertificateName
Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -like 'acme-*' | Format-List FriendlyName, Thumbprint, NotAfter
```

Open `https://oos.example.com/hosting/discovery`.

## Common problems

| Problem | Fix |
|---|---|
| `the OfficeWebApps module is not here` | Office Online Server is not installed on this server |
| `this server is in no Office Online Server farm` | create the farm once (`New-OfficeWebAppsFarm`) |
| `the farm is SSL offloaded` | put the certificate on the load balancer instead |
| `the friendly name ... is on 2 certificates` | remove the duplicate from `LocalMachine\My` |
| the old certificate still served | the servers have not restarted yet |

*Uncertain*: `-Force` on `Set-OfficeWebAppsFarm` (to run without a prompt) - the example in the documents has none; that the setting needs the restart of every server of the farm comes from the cmdlet reference.

Sources: Microsoft Learn - *Plan Office Online Server* (certificate requirements), *Deploy Office Online Server*, `Set-OfficeWebAppsFarm`, `New-OfficeWebAppsFarm`.
