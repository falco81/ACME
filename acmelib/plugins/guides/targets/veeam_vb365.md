# Veeam Backup for Microsoft 365 - setup for acme

acme sets the certificates of Veeam Backup for Microsoft 365 **v8** with VB365's own cmdlets, signed in to the VB365 server over OpenSSH. It uploads a one-time PKCS#12 (the cmdlets take a PFX file and its password), runs what you ticked, and deletes the file:

```powershell
Set-VBORestAPISettings -EnableService -HTTPSPort 4443 -CertificateFilePath <pfx> -CertificatePassword <SecureString>
Set-VBOSecuritySettings -CertificateFilePath <pfx> -CertificatePassword <SecureString> -Force
Set-VBOOperatorAuthenticationSettings -EnableAuthentication -CertificateFilePath <pfx> -CertificatePassword <SecureString>
Set-VBOTenantAuthenticationSettings -EnableAuthentication -CertificateFilePath <pfx> -CertificatePassword <SecureString>
```

| acme option | Certificate | Who uses it |
|---|---|---|
| REST API certificate (on) | REST API, HTTPS port 4443 | Restore Portal, Veeam Service Provider Console, Veeam ONE, scripts |
| Server certificate (workgroup backup proxies) | the server certificate | Windows backup proxies in a workgroup (VB365 tells them by itself) |
| Restore operator authentication certificate | restore operator authentication | restore operators |
| Tenant authentication certificate | tenant authentication | service providers' tenants |

The **Restore Portal** certificate is not set by acme: it must be the one uploaded to its Microsoft Entra application - change it there first (*Backup Applications Manager*), then in VB365.

## Which versions

Veeam Backup for Microsoft 365 **8.x** (the vendor guide: build 8.6.0.5011). One module.

## What you need

- **OpenSSH Server** on the VB365 server, port 22 open from acme:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
```

- An account with the VB365 role **Veeam Backup Administrator** (members of the local *Administrators* group have it by default) that is a local administrator. With MFA on, use a service account with MFA turned off (*Disabling MFA for Service Accounts*):

```powershell
New-LocalUser -Name svc-vb365 -Password (Read-Host -AsSecureString "Password") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-vb365
```

- A certificate for the name the REST API / Restore Portal is reached by (a public CA is fine - VB365 sets no CA requirement for it).
- The REST API on another machine: run acme against the **VB365 server** (the cmdlets do not run on the separate REST machine); if a new self-signed operator certificate is made, import it on the REST machine into *Trusted Root*.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | the VB365 server, `22`, `svc-vb365` |
| Sign in with / The SSH key / Password | a key made in acme or the password |
| REST API certificate (deployment) | on |
| REST API HTTPS port (deployment) | `4443` - the Restore Portal's address uses the same port |
| Server certificate (workgroup backup proxies) | on when you have such proxies |
| Restore operator / Tenant authentication certificate (advanced) | as you use them |
| Check what is served | acme checks `<server>:4443` by itself when the REST API certificate is on |

## Check it

```powershell
Import-Module Veeam.Archiver.PowerShell
Get-VBORestAPISettings
Get-VBOSecuritySettings
```

```sh
openssl s_client -connect vb365.example.com:4443 -servername vb365.example.com </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Then sign in to the Restore Portal as an operator, and look at the VB365 integration in VSPC / Veeam ONE.

## Common problems

| What you see | Why | What to do |
|---|---|---|
| `Import-Module Veeam.Archiver.PowerShell` fails | the console / PowerShell module is not on that machine | run against the VB365 server itself |
| the Restore Portal stops working after a port change | its address keeps the old port | set the same port in the portal's address |
| Veeam ONE / VSPC lose the connection | they trusted the old REST API certificate | trust the CA, or accept the new certificate there |
| *nothing to set* | no certificate ticked | tick at least one |

Sources: VB365 8 User Guide *Veeam Backup for Microsoft 365 Certificates*, *REST API Settings*, *Security Settings*; PowerShell `Set-VBORestAPISettings`, `Set-VBOSecuritySettings`, `Set-VBOOperatorAuthenticationSettings`, `Set-VBOTenantAuthenticationSettings`.
