# Veeam Backup & Replication (VBR 13.0 - 13.1) - setup for acme

acme replaces the **backup server certificate** of Veeam Backup & Replication on **Windows** - the TLS certificate components, agents, plug-ins and consoles trust the backup server by; in **v13** also the certificate of the **web UI and REST API** (443, 9419). It signs in to the server over **OpenSSH** and runs PowerShell there:

1. reads the version and the certificate used now (`Get-VBRBackupServerCertificate`); the same one already: nothing is changed;
2. imports the certificate from a one-time PKCS#12 into `Cert:\LocalMachine\My` (the file is deleted right after), names it `acme-<name>-<date>-<serial>`, and puts its CA certificates into *Intermediate Certification Authorities* / *Trusted Root Certification Authorities*;
3. `Get-VBRBackupServerCertificate -FromStore | Where-Object Thumbprint -eq …` and `Add-VBRBackupServerCertificate -Certificate $c` - with `-Force` on v13 (12.3 has no such parameter);
4. on **12.3** also moves the REST API's http.sys binding: `netsh http delete sslcert ipport=0.0.0.0:9419`, then `netsh http add sslcert ipport=0.0.0.0:9419 certhash=<thumbprint> appid={284175c4-aa3e-4c6f-a2dd-5a4c80552eb9} certstorename=MY`;
5. restarts the services you list (none by default), deletes older acme certificates beyond *keep* (never the one used now or before).

## Which versions

Module version **VBR 13.0 - 13.1** (`13`): Veeam Backup & Replication **13.0.x and 13.1** on Windows (the vendor guide: 13.1.2.57). It calls

```powershell
Add-VBRBackupServerCertificate -Certificate $c -Force
```

and no netsh: in v13 the **web UI (443)** and the **REST API (443, 9419)** use the backup server certificate by themselves (v13.1 also as the default SAML service provider certificate). acme reads the version first: a 12.x server is refused before anything is changed (choose *VBR 12.3*); a newer one is a warning. On a Linux backup server (Veeam Software Appliance) there is no SSH and PowerShell for this - see its own documentation.

## The certificate Veeam takes - read this before issuing

Veeam takes **only** a certificate of an **internal CA** made like a subordinate CA certificate - a usual web server certificate (and any of a **public CA**, so Let's Encrypt) is refused, and acme says so before changing anything:

- **Basic Constraints**: Subject Type = **CA**, **Path Length Constraint = 0** (an AD CS template duplicated from *Subordinate Certification Authority*, on *Extensions* → *Basic Constraints*: *Make this extension critical* and *Do not allow subject to issue certificates to other CAs*);
- Key Usage: Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing;
- Subject = the server's FQDN (`CN=vbr01.example.local`); SAN = the FQDN **and** the NetBIOS name (`DNS:vbr01.example.local, DNS:vbr01`);
- **RSA 2048** or more, key type *Exchange* (a legacy CSP) - **not ECC, not CNG**;
- the issuing CA's CRL reachable from the server over HTTP; its root in *Trusted Root* (acme puts the chain it has there).

acme's source for this is your internal CA (Microsoft AD CS, a private CA in acme) with such a profile. *Deploy a certificate that is not a CA one* (advanced) turns acme's check off - Veeam will still refuse it.

## What you need on the server

- **OpenSSH Server** on Windows (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`, `Start-Service sshd`, `Set-Service sshd -StartupType Automatic`), port 22 open from acme.
- An account that is a **local administrator** (the certificate store, netsh) and has the VBR role **Backup Administrator** (*Users and Roles*). PowerShell does not do MFA: mark it in *Users & Roles > Security > Edit* as **This is a service account (disables two-factor authentication)**.

```powershell
New-LocalUser -Name svc-veeam -Password (Read-Host -AsSecureString "Password") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-veeam
```

Then in the Veeam console: *Main menu > Users and Roles > Add* → `.\svc-veeam`, role *Veeam Backup Administrator*, tick *This is a service account*.

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **VBR 13.0 - 13.1** |
| Address / SSH port / User | the VBR server, `22`, `svc-veeam` |
| Sign in with / The SSH key / Password | a key made in acme (`administrators_authorized_keys` for an administrator) or the password |
| Folder for uploads (advanced) | `C:/Windows/Temp` - the PKCS#12 lies there for seconds |
| Restart these services (deployment) | empty, or `VeeamBackupSvc` (and the AHV service of the Nutanix plug-in) - **a restart stops running jobs** |
| Previous versions to keep (advanced) | `1` |
| Check what is served | acme checks `<server>:443` by itself |

## After the change (Veeam's own steps)

Veeam says the backup service must restart (running jobs are stopped) - list it in *Restart these services* or restart it in a window. Then: restart every **console** (accept the new certificate); restart the **Veeam AHV Service** (Nutanix plug-in); go through *Edit* of RHV and CDP proxies and the *I/O filter Management* of CDP clusters; **rescan agents before** the change, and export a new install package for pre-installed agents. v13.1 SAML: download the new SP certificate / metadata for the IdP. Scripts that pin the REST API's thumbprint need the new one.

## Check it

```powershell
Get-VBRBackupServerCertificate | Format-List *
netsh http show sslcert ipport=0.0.0.0:9419
```

```sh
openssl s_client -connect vbr01.example.local:443 -servername vbr01.example.local </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage
curl -s -H "x-api-version: 1.3-rev1" https://vbr01.example.local/api/v1/serverCertificate
```

## Common problems

| What you see | Why | What to do |
|---|---|---|
| *would refuse this certificate: no Basic Constraints CA* | a usual leaf certificate | issue it from a Subordinate-CA-like template (above) |
| *-FromStore does not offer …* | no private key Veeam can use (CNG, ECC) or an untrusted chain | RSA in a legacy CSP; the CA in *Trusted Root* |
| *the module version ... is for ...* | the server runs another VBR | choose the version named in the message |
| plug-ins stop talking (AHV, Proxmox, cloud) after 13.0.1 | KB4687: a certificate without Basic Constraints | as above |
| *not as an administrator* | the SSH session is not elevated | an account in *Administrators* |
| a 12.3 REST client still sees the old certificate | the 9419 binding was not moved | turn on *Move the REST API binding* |

Sources: VBR 13 User Guide *Backup Server Certificate*, *Using Certificate Signed by Internal CA*; PowerShell reference `Add-VBRBackupServerCertificate`, `Get-VBRBackupServerCertificate` (13 and the 12.x archive); REST API 12.x *TLS Certificate* (netsh); Veeam KB4687.
