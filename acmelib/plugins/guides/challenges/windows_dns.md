# Windows DNS Server - setup for acme

acme proves names by DNS-01 in a zone of a **Windows Server DNS server**. Windows DNS has no REST API, so acme signs in over **OpenSSH for Windows** and runs the PowerShell DnsServer cmdlets: `Add-DnsServerResourceRecord -Txt` only when the name lacks our value, and `Remove-DnsServerResourceRecord -RecordData VALUE -Force` only when it has it - **always with `-RecordData`**, so other TXT records at the name stay. Windows raises the zone's serial itself; an AD-integrated zone reaches the other domain controllers by replication, and acme waits until every name server has the value.

For Windows Server 2016 and later (OpenSSH Server built in from 2019; installable on 2016), DNS Server role with the `DnsServer` PowerShell module.

## What you need

- SSH (TCP 22) from acme to the DNS server - or to a management machine with the **DNS Server Tools** (RSAT) that reaches it.
- A dedicated (domain) account for acme allowed to change the zone.

## Set up Windows

1. Install and start OpenSSH Server (PowerShell as administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service sshd -StartupType Automatic; Start-Service sshd
   New-NetFirewallRule -Name sshd-acme -DisplayName 'OpenSSH (acme)' -Protocol TCP -LocalPort 22 -RemoteAddress 203.0.113.10 -Action Allow
   ```

2. Create the account (domain example) and allow it to change DNS - membership in **DnsAdmins** is the usual way; tighter: give it *Write* / *Create all child objects* on the zone only (DNS Manager → the zone → **Properties → Security**):

   ```powershell
   New-ADUser -Name acme-dns -AccountPassword (Read-Host -AsSecureString) -Enabled $true
   Add-ADGroupMember -Identity DnsAdmins -Members acme-dns
   ```

3. Put acme's public SSH key in the account's `C:\Users\acme-dns\.ssh\authorized_keys` (for an account in **Administrators**: `C:\ProgramData\ssh\administrators_authorized_keys`, readable only by Administrators and SYSTEM).
4. Pin the host key in acme:

   ```sh
   ssh-keyscan -t ed25519 dc1.example.com
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Windows DNS server | `dc1.example.com:22` - the machine acme signs in to |
| User | `acme-dns` (or `EXAMPLE\acme-dns` / `acme-dns@example.com` as sshd expects) |
| Signs in with / The SSH key | a private key (made here) |
| Host keys | the `ssh-keyscan` line; or *Trust the first key seen* |
| Zone | the zone **exactly as DNS Manager shows it**; empty: the longest of *Zones there*, else by SOA |
| Zones there | filled from *Test*'s list |
| DNS server for the cmdlets | empty = the machine signed in to; a DNS server name when signing in to a management host |
| TTL (s) | 60 (advanced) |

## Check it

- In acme press **Test**: it runs `Get-DnsServerZone` and lists the zones; nothing is changed. A **dry run** of the certificate adds a test record and removes it.
- On the server:

```powershell
Get-DnsServerResourceRecord -ZoneName example.com -Name _acme-challenge.www -RRType Txt
```

## Common problems

| Problem | Fix |
|---|---|
| SSH "Permission denied (publickey)" | Key in the wrong file (administrators use `administrators_authorized_keys`) or wrong file permissions. |
| "Access denied" from the cmdlet | The account is not in DnsAdmins / has no rights on the zone. |
| "zone … not found" | *Zone* is not written as DNS Manager shows it, or *DNS server for the cmdlets* is needed. |
| CA sees the record late | AD replication to the other DCs takes time - give the ACME issuer a longer wait. |
