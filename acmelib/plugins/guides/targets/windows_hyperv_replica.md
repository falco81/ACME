# Hyper-V Replica (certificate authentication) - setup for acme

acme signs in to a Hyper-V host over **OpenSSH** and runs PowerShell. It uploads the certificate as a PFX (one-time random password), imports it into **LocalMachine\My** (friendly name `acme-<name>-<date>-<serial>`), deletes the PFX and then, as you ask:

- **Replica server** (this host receives replication): `Set-VMReplicationServer -CertificateThumbprint <new> -Force` - only when replication is enabled with certificate-based (HTTPS) authentication;
- **primary VMs** of this host that replicate with a certificate (all, or the ones you list): first `Test-VMReplicationConnection ... -AuthenticationType Certificate -CertificateThumbprint <new>` against **each** replica server - a failure stops everything before any change - then `Set-VMReplication -VMName <vm> -CertificateThumbprint <new>`;
- removes older acme certificates beyond *keep*, never one the Replica server or a VM still uses.

Before anything is switched, acme checks the certificate has **both Server Authentication (1.3.6.1.5.5.7.3.1) and Client Authentication (1.3.6.1.5.5.7.3.2)** - Hyper-V Replica authenticates both ways with it. **Most public CAs no longer issue Client Authentication**: use your own CA (ACME from AD CS, step-ca...) with a template that gives both.

The change applies without restarting Hyper-V; a replication cycle running at the moment may fail once and is repeated.

## Which versions

Hyper-V on **Windows Server 2016, 2019, 2022 and 2025** - the same cmdlets on all (TLS 1.3 on 2022/2025; RSA 2048 or more enforced on 2025). One module, no versions.

## What you need

- SSH from acme to **every** host (primary and replica) - one acme target per host, each deploying the same or its own certificate.
- An account in the local **Administrators** group with an **elevated** SSH session. *Hyper-V Administrators* is not enough: importing into `LocalMachine\My` needs local Administrators.
- The certificate: name = the host's **FQDN** (CN or SAN); on a cluster also the **Hyper-V Replica Broker** FQDN on each node; chain trusted on both sides (root in `LocalMachine\Root`, the CRL reachable from the other site).
- Replication set up once with certificate authentication (Hyper-V Manager, *Hyper-V Settings → Replication Configuration → Use certificate-based authentication (HTTPS)*), port **443** by default.

## Set up the host

1. OpenSSH Server and acme's key (PowerShell as Administrator):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. Replica server, once (acme then only changes the certificate):

   ```powershell
   Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Certificate -CertificateThumbprint '<THUMBPRINT>' -CertificateAuthenticationPort 443 -ReplicationAllowedFromAnyServer $true -DefaultStorageLocation 'D:\Replica'
   Enable-NetFirewallRule -DisplayName 'Hyper-V Replica HTTPS Listener (TCP-In)'
   ```

3. A primary VM, once:

   ```powershell
   Enable-VMReplication -VMName 'VM01' -ReplicaServerName 'hvrep01.example.com' -ReplicaServerPort 443 -AuthenticationType Certificate -CertificateThumbprint '<THUMBPRINT>'
   Start-VMInitialReplication -VMName 'VM01'
   ```

Renew in this order: put the new certificate on **every** host of both sides first (acme's deployments to the replica side, then the primary side - the primary's test needs the replica to trust it), then the VMs switch.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port | the Hyper-V host, `22` |
| User / The SSH key | `Administrator` or e.g. `CORP\acme-hv` (local Administrators) |
| This host receives replication (deploy) | on for a Replica server |
| Primary VMs of this host (deploy) | on for a primary host |
| Only these VMs (deploy) | empty: every primary VM using a certificate; or VM names, one a line |
| Test each replica server first (deploy) | on (default) |
| PKCS#12 kind (advanced) | *3DES* (any Windows); *AES-256* on 2019 and later |
| Previous versions to keep (advanced) | default 1 |

No TLS test is made with the deployment: the replication listener wants a client certificate.

## Check it

```powershell
Get-VMReplicationServer | Format-List *
Get-VMReplication | Format-Table VMName, State, Health, ReplicaServer, ReplicaPort, AuthenticationType
Measure-VMReplication
Test-VMReplicationConnection -ReplicaServerName hvrep01.example.com -ReplicaServerPort 443 -AuthenticationType Certificate -CertificateThumbprint <THUMBPRINT>
```

```sh
openssl s_client -connect hvrep01.example.com:443 -showcerts </dev/null
```

(the handshake may end with an error - the listener asks for a client certificate - but the server certificate is shown).

## Common problems

| Problem | Fix |
|---|---|
| `needs both Server Authentication and Client Authentication` | issue the certificate from a template with both EKUs |
| `this host is not a Replica server` | enable it once (step 2) or turn off *This host receives replication* |
| `allows Kerberos only` | choose certificate-based authentication once |
| `... does not take the new certificate, nothing changed` | the replica side does not trust the new certificate yet (CA, CRL) - deploy to the replica first |
| Health *Critical* after an expiry | `Resume-VMReplication -VMName <vm>` (maybe a resynchronisation) |

*Uncertain*: one SAN certificate for the node and the broker FQDN instead of two certificates (common practice, the documents describe two); the property names `CertificateThumbprint`, `AuthenticationType`, `ReplicaPort` on `Get-VMReplication` objects follow the cmdlet parameters; a broker's certificate is set in Failover Cluster Manager (*Replication Settings*), acme sets the node's.

Sources: Microsoft Learn - *Hyper-V Replica overview*, *Enable Hyper-V Replica on a single host / a failover cluster*, cmdlets `Set-VMReplicationServer`, `Set-VMReplication`, `Test-VMReplicationConnection`.
