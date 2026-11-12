# System Center Operations Manager (certificate) - setup for acme

Operations Manager authenticates a **gateway**, a **management server** or an **agent** outside a trusted domain (workgroup, DMZ) with a certificate, both ways, on **TCP 5723**. acme signs in to that machine over **OpenSSH** and runs PowerShell:

1. uploads the certificate as a PFX (one-time random password) and imports it with **`certutil -f -p <pw> -importPFX My <pfx> AT_KEYEXCHANGE`** - the key goes into a **legacy CSP as AT_KEYEXCHANGE** (KeySpec 1), as Operations Manager needs (a KSP/CNG key does not work); the PFX is deleted whatever happens; friendly name `acme-<name>-<date>-<serial>`;
2. checks the certificate has **Server Authentication and Client Authentication** and the key is `Exchange` - before anything is switched;
3. runs **`MOMCertImport.exe /SubjectName <subject>`**, then reads back `ChannelCertificateSerialNumber` (`HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\MachineSettings`) to make sure it took **this** certificate;
4. restarts the **Microsoft Monitoring Agent** (`HealthService`, a short gap in monitoring of this machine) - when asked;
5. removes older acme certificates beyond *keep*, never the one Operations Manager uses.

The certificate must be **RSA** (acme refuses an ECDSA one before anything is done) with both EKUs - **most public CAs no longer issue Client Authentication**: use your own CA (ACME from AD CS, step-ca...) with an *Operations Manager* template.

## Which versions

**Operations Manager 2019, 2022 and 2025** - `MOMCertImport` and the certificate requirements are the same. One module, no versions.

## What you need

- SSH from acme to the gateway / management server / agent, **TCP 22**.
- An account in the local **Administrators** group with an **elevated** SSH session (MOMCertImport and `LocalMachine\My` need it).
- `MOMCertImport.exe` on the machine: from the installation media `SupportTools\amd64` (copy it, e.g. to `C:\Tools`); on a gateway it is in `%ProgramFiles%\System Center Operations Manager\Gateway`.
- Subject `CN=<FQDN>` of the machine; the root CA in `LocalMachine\Root` on both sides; only **one** certificate with that subject besides acme's own (MOMCertImport picks by subject).

## Set up the machine

1. OpenSSH Server and acme's key (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. The CA's root, once (outside the domain):

   ```powershell
   Import-Certificate -FilePath C:\Certs\root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

3. A template on the CA (AD CS): duplicate *Computer*, *Legacy Cryptographic Service Provider* (*Microsoft RSA SChannel Cryptographic Provider*), 2048 bits or more, EKU Server + Client Authentication, Subject *Supply in the request*.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | the gateway / management server / agent, `22` |
| User / The SSH key | `Administrator` or e.g. `DMZ\acme-scom` (local Administrators) |
| MOMCertImport.exe (deploy) | e.g. `C:\Tools\MOMCertImport.exe`; empty on a gateway |
| Restart the Microsoft Monitoring Agent (deploy) | on (default) |
| PKCS#12 kind (advanced) | *3DES* (any Windows); *AES-256* on 2019 and later |
| Previous versions to keep (advanced) | default 1 |

No TLS test is made with the deployment: 5723 is Operations Manager's own mutually authenticated channel.

## Check it

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\MachineSettings' | Select-Object ChannelCertificateSerialNumber
certutil -v -store My <thumbprint> | Select-String 'KeySpec|Provider'
Get-WinEvent -LogName 'Operations Manager' -MaxEvents 50 | Where-Object Id -in 20053,20049,20050,20052,20066,20069,20077
Test-NetConnection ms01.example.com -Port 5723
```

Event **20053** says the certificate was loaded.

## Common problems

| Problem | Fix |
|---|---|
| `needs an RSA key` | issue the certificate with an RSA key |
| `needs both Server Authentication and Client Authentication` | a template with both EKUs |
| `the key is not in a legacy CSP as AT_KEYEXCHANGE` | the import did not convert it - check `certutil -v -store My <thumbprint>`; re-deploy with *force* |
| `MOMCertImport.exe is not at ...` | copy it from the media and give its path |
| `MOMCertImport took another certificate with the subject ...` | remove the other (non-acme) certificates of that subject from `LocalMachine\My` |
| events 20049 / 20050 / 20052 | the other side does not trust the CA, or the name differs |

*Uncertain*: how MOMCertImport chooses among several certificates of one subject (acme checks the serial it wrote and fails plainly); the byte order of `ChannelCertificateSerialNumber` (acme takes both); whether MOMCertImport restarts the HealthService by itself (acme restarts it when asked).

Sources: Microsoft Learn - *Obtain a certificate for use with Windows Servers and Operations Manager*, *Install an Operations Manager gateway server* (MOMCertImport), `certutil -importPFX ... AT_KEYEXCHANGE`.
