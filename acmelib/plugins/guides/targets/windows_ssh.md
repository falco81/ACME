# Windows server (OpenSSH + PowerShell) - setup for acme

acme signs in to Windows over **OpenSSH** and runs PowerShell. It uploads the certificate
as a PFX (one-time random password) to `C:/Windows/Temp`, imports it into
**LocalMachine\My** (friendly name `acme-<name>-<date>-<serial>`), deletes the PFX, and
then, as you ask:

- **IIS bindings** - `site | host name | port [| ip]`: an SNI binding with a host name,
  missing https bindings are created;
- **Remote Desktop listener** - the RDP-tcp certificate, NETWORK SERVICE given read on the
  key;
- **Exchange services** - `Enable-ExchangeCertificate -Services ...`;
- **Roles on the server** - RDS, RD Gateway, AD FS, WAP, SQL Server, LDAPS, WinRM HTTPS,
  SSTP, IIS Central Certificate Store, IIS FTP, Exchange, Skype for Business, SharePoint SE,
  Windows Admin Center (each with its own switch and fields);
- optional **files** (PEM, PFX, JKS... anywhere) and a **PowerShell script** after them.

Old acme certificates of the same name beyond *Previous versions to keep* are removed
unless something still uses them.

For Windows Server 2016 and later (2019+ recommended) and Windows 10/11 with the OpenSSH
Server feature.

## What you need

- SSH from acme to the server, **TCP 22**.
- An account in the local **Administrators** group whose SSH session is **elevated**
  (the built-in Administrator, a domain admin, or a local admin with
  `LocalAccountTokenFilterPolicy=1`).
- The roles you want to use already installed (IIS, RDS, AD FS...).

## Set up Windows

1. Install and start the OpenSSH Server (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   New-NetFirewallRule -Name acme-sshd -DisplayName 'OpenSSH for acme' -Direction Inbound `
     -Protocol TCP -LocalPort 22 -RemoteAddress <acme-IP> -Action Allow
   ```

2. Put acme's public key in place. For an **administrator** account Windows reads
   `C:\ProgramData\ssh\administrators_authorized_keys` (not the user's own file), and the
   file must be readable only by Administrators and SYSTEM:

   ```powershell
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

   Make the key in acme (target → *The SSH key* → *Make a key*; *How to set it up on
   Windows* shows the same commands).
3. A **local** administrator other than the built-in one gets a filtered (not elevated)
   token over SSH. Either use a domain admin / the built-in Administrator, or:

   ```powershell
   New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
     -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force
   ```

4. Note the IIS site names (`Get-Website`) and which roles you want acme to update.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | The server, `22` |
| User | `Administrator` (default) or e.g. `EXAMPLE\acme-admin` |
| Sign in with / The SSH key | *a private key* (or a password - needed for an RDS role with a remote broker or a UNC CCS path) |
| Folder for uploads (advanced) | `C:/Windows/Temp` (default) |
| IIS bindings (deploy) | e.g. `Default Web Site \| www.example.com \| 443` |
| Remote Desktop listener (deploy) | On to use it for RDP |
| Exchange services (deploy, advanced) | e.g. `IIS,SMTP`; empty: not Exchange |
| PKCS#12 kind (advanced) | *3DES (any Windows)*; *AES-256* for Server 2019 and later |
| Key exportable (advanced) | Off (default) |
| PowerShell after (advanced) | Your own lines; `$thumb` is the new thumbprint |
| Roles on the server | Switch on the roles you need and fill their fields |
| Files / script after them (advanced) | Only if something needs the certificate as files |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `www.example.com:443`, `rdp.example.com:3389` |

## Check it

- Press **Try** on the target: acme signs in, checks the session is elevated and lists the
  roles it finds: `signed in as Administrator on Microsoft Windows Server 2022 ..., PowerShell 5.1 ...`.
- On the server:

  ```powershell
  Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -like 'acme-*' | Format-List FriendlyName, Thumbprint, NotAfter
  Get-WebBinding -Protocol https
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Permission denied (publickey)` for an admin | The key must be in `administrators_authorized_keys` with the `icacls` rights above. |
| `signed in as ..., but not as an administrator (elevated)` | Use the built-in Administrator or a domain admin, or set `LocalAccountTokenFilterPolicy=1`. |
| PFX import fails on older Windows | Choose *PKCS#12 kind* 3DES. |
| `IIS line N has no site` | Each line needs `site \| host \| port`. |
| RDS / CCS role: access denied on the broker or share | Key sign-in has no network credentials (second hop): sign in with a password, or run it on the broker / use a local folder. |
| Old certificate not removed | Still used by a binding or service - expected; it goes once unused. |
