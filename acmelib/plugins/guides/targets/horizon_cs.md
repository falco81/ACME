# Omnissa Horizon Connection Server - setup for acme

acme gives a Horizon 8 Connection Server its **Machine Identity** certificate - the TLS certificate of the server, HTML Access and the Blast Secure Gateway - the way the Horizon documents do it by hand, over **OpenSSH and PowerShell**:

1. uploads a PKCS#12 (scp) and imports it into **Local Computer → Personal** with an **exportable key** (`Import-PfxCertificate -Exportable`) - Horizon refuses a key that cannot be exported ("No qualifying certificates in keystore");
2. imports the intermediates into **Intermediate Certification Authorities** (`Cert:\LocalMachine\CA`);
3. takes the friendly name **`vdm`** off the certificate that had it (renamed `acme-was-vdm-...`, not deleted) and gives `vdm` to the new one - only one certificate may have it;
4. **restarts the Connection Server service** (`wsbroker`, *Omnissa Horizon Connection Server*) and waits until it runs - **ongoing provisioning and Blast sessions are interrupted**;
5. deletes older certificates **acme imported** beyond *keep* (never the one with `vdm`, never one acme did not import).

The REST API's `import-certificate` is not used: it cannot restart the service, which Horizon needs to take the certificate.

## Which Horizon this guide is for

Horizon 8 **2212 - 2609** (the same steps). Each Connection Server of a pod has its own Machine Identity: one target each, deployed one after another (drain the server on the load balancer first). `vdm.ec` (an ECDSA Machine Identity) from 2312.

## Set up the Connection Server

1. **OpenSSH Server** on the Windows server (Settings → Optional features, or):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd; Set-Service sshd -StartupType Automatic
   New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Protocol TCP -LocalPort 22 -Action Allow
   ```

2. **An account that is a local administrator** of the server (importing into the machine store, renaming, restarting the service are outside Horizon's roles) - a domain account such as `CORP\svc-hzn-cert` in the local *Administrators* group:

   ```powershell
   Add-LocalGroupMember -Group Administrators -Member 'CORP\svc-hzn-cert'
   ```

   With a key: put acme's public key (the key card in acme: *How to set it up*) into `C:\ProgramData\ssh\administrators_authorized_keys` for an administrator.

3. **The root CA** in *Trusted Root Certification Authorities* of every Connection Server (a public CA's root usually is):

   ```powershell
   Import-Certificate -FilePath C:\certs\root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

4. **UAG in front**: if the certificate changes its CA or thumbprint, update *Horizon Settings → Connection Server URL Thumbprints* on each UAG - otherwise the service is lost.

## The certificate

- CN/SAN: the FQDN clients use (the server's, or the load balancer's).
- **EKU Server Authentication only** - a certificate with Client Authentication issued after 15 March 2026 is not trusted by browsers and HTML Access.
- RSA (friendly name `vdm`); ECDSA with `vdm.ec` on 2312 and later.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the Connection Server's FQDN, e.g. `cs01.example.local` |
| SSH port / User | `22`, `CORP\svc-hzn-cert` (or `Administrator`) |
| Sign in with / The SSH key / Password | a key (made in acme) or the password |
| Folder for uploads (advanced) | `C:/Windows/Temp` - the PKCS#12 is deleted at once |
| Friendly name (deploy) | `vdm`; `vdm.ec` for an ECDSA certificate |
| Restart the Connection Server service (deploy) | on - off only when you restart it yourself in a window |
| Intermediates into the machine's CA store (deploy, advanced) | on |
| Previous versions to keep (advanced) | `1` |
| Check what is served | empty: acme checks `<address>:443` |

## Check it

*Try* signs in, checks the account is an administrator and says the service and the current `vdm` certificate. After a deployment:

```sh
openssl s_client -connect cs01.example.local:443 -servername cs01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext extendedKeyUsage
```

On the server:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'vdm' | Select-Object Subject, NotAfter, Thumbprint, HasPrivateKey
```

Horizon Console: the dashboard (*System Health → Connection Servers*: "SSL Certificate: Valid").

## Common problems

| Problem | Fix |
|---|---|
| `not as an administrator (elevated)` | The account is not in the local *Administrators* group. |
| `there is no Horizon Connection Server service` | Not a Connection Server (or a renamed service) - check `Get-Service wsbroker`. |
| "No qualifying certificates in keystore", the server red | The key is not exportable, or two certificates have `vdm` - acme imports with an exportable key and moves the name; check none else has it. |
| Red health: revocation | The server cannot reach the CA's CRL/OCSP - allow it, or set `CertificateRevocationCheckType` (HKLM\Software\Omnissa\Horizon\Security). |
| Clients through UAG fail after the change | Update the Connection Server thumbprint on the UAGs. |
