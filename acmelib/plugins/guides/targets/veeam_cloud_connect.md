# Veeam Cloud Connect - setup for acme

acme replaces the **Cloud Connect TLS certificate** on the service provider's backup server - the certificate the cloud gateways show tenants. It is separate from the backup server certificate and, unlike it, **may be a usual web server certificate of a public CA** (Let's Encrypt, a commercial CA), a **wildcard** or one with several FQDNs. Over OpenSSH acme runs PowerShell on the provider's backup server:

1. reads the certificate used now (`Get-VBRCloudGatewayCertificate`); the same one already: nothing is changed;
2. imports the certificate from a one-time PKCS#12 into `Cert:\LocalMachine\My` (the file is deleted right after) and its CA certificates into *Intermediate Certification Authorities* / *Trusted Root Certification Authorities* - Veeam refuses a certificate whose chain the server does not trust;
3. `$c = Get-VBRCloudGatewayCertificate -FromStore | Where-Object Thumbprint -eq …` and `Add-VBRCloudGatewayCertificate -Certificate $c`;
4. deletes older acme certificates beyond *keep* (never the one used now or before), and says the new **thumbprint** in the job.

## Which versions

Veeam Backup & Replication **12.3** and **13.0 - 13.1** (the cmdlets and the steps are the same). One module.

## What you need

- A certificate covering **every cloud gateway's DNS name** - with `*.provider.com` a gateway whose name does not end in `.provider.com` is not used.
- **OpenSSH Server** on the provider's backup server, port 22 open from acme:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
```

- An account that is a **local administrator** (the machine store) and has the VBR role **Backup Administrator**; marked as a *service account* in *Users & Roles* when MFA is on (PowerShell does not do MFA):

```powershell
New-LocalUser -Name svc-veeam -Password (Read-Host -AsSecureString "Password") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-veeam
```

- The **Veeam Cloud Connect Service** account (Local System by default) must read the private key without a password - a key imported into the machine store is readable by Local System; if you run the service as another account, give it *Manage Private Keys → Read*.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | the provider's backup server, `22`, `svc-veeam` |
| Sign in with / The SSH key / Password | a key made in acme or the password |
| Folder for uploads (advanced) | `C:/Windows/Temp` |
| Add the CA certificates to the machine's stores (deployment, advanced) | on |
| Previous versions to keep (advanced) | `1` |

Cloud Connect speaks Veeam's own protocol on the gateways (port 6180 by default): a plain TLS check of it may not see the certificate, so acme attaches no test - look in the console (below).

## Tenants

- A certificate of a CA the tenants trust (a public CA, or your CA in their *Trusted Root*): usually nothing to do.
- A self-signed or private CA certificate: send tenants the new thumbprint (the job says it) over a safe channel; they set it:

```powershell
$sp = Get-VBRCloudProvider -Name "cloudgw.provider.com"
Set-VBRCloudProvider -CloudProvider $sp -VerifyCertificate -CertificateThumbprint "<new thumbprint>"
Rescan-VBREntity -AllCloudProviders
```

Do it in a maintenance window - tenants' jobs may fail while the certificate is switched.

## Check it

```powershell
Get-VBRCloudGatewayCertificate | Format-List *
```

In the console: *Cloud Connect > Manage Certificates* → *Keep the existing certificate* shows the name, expiry, thumbprint and serial. On a tenant: a rescan of the provider and a job to the cloud repository.

## Common problems

| What you see | Why | What to do |
|---|---|---|
| *-FromStore does not offer …* | the chain is not trusted on the server, or the service cannot read the key | keep *Add the CA certificates…* on; check the key's permissions |
| a gateway is not used | the certificate does not cover its DNS name | add the name to the certificate |
| tenants fail with a certificate error | they verify the old thumbprint | `Set-VBRCloudProvider -VerifyCertificate -CertificateThumbprint` |
| *not as an administrator* | the SSH session is not elevated | an account in *Administrators* |

Sources: Veeam Cloud Connect 13 *TLS Certificates* (types, rights, import, what you do next); PowerShell `Get-VBRCloudGatewayCertificate`, `Add-VBRCloudGatewayCertificate` (13 and 12.x), `Set-VBRCloudProvider`.
