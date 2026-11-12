# Hyper-V Replica (ověřování certifikátem) - nastavení pro acme

acme se k hostiteli Hyper-V přihlásí přes **OpenSSH** a spouští PowerShell. Nahraje certifikát jako PFX (s jednorázovým náhodným heslem), naimportuje ho do **LocalMachine\My** (popisné jméno `acme-<jméno>-<datum>-<sériové číslo>`), PFX smaže a potom podle zadání:

- **replikační server** (tento hostitel replikaci přijímá): `Set-VMReplicationServer -CertificateThumbprint <nový> -Force` - jen když je replikace zapnutá s ověřováním certifikátem (HTTPS);
- **primární VM** tohoto hostitele, které replikují s certifikátem (všechny, nebo ty, které vyjmenujete): nejdřív `Test-VMReplicationConnection ... -AuthenticationType Certificate -CertificateThumbprint <nový>` proti **každému** replikačnímu serveru - selhání vše zastaví dřív, než se cokoli změní - potom `Set-VMReplication -VMName <vm> -CertificateThumbprint <nový>`;
- odstraní starší certifikáty acme nad počet *keep*, nikdy ne ten, který replikační server nebo některá VM ještě používá.

Než se cokoli přepne, acme ověří, že certifikát má **Server Authentication (1.3.6.1.5.5.7.3.1) i Client Authentication (1.3.6.1.5.5.7.3.2)** - Hyper-V Replica jím ověřuje obě strany. **Většina veřejných CA už Client Authentication nevydává**: použijte vlastní CA (ACME z AD CS, step-ca...) se šablonou, která dá obě.

Změna platí bez restartu Hyper-V; právě běžící cyklus replikace může jednou selhat a zopakuje se.

## Pro které verze

Hyper-V na **Windows Serveru 2016, 2019, 2022 a 2025** - všude stejné cmdlety (TLS 1.3 na 2022/2025; na 2025 je vynucen RSA klíč aspoň 2048 bitů). Jeden modul, bez verzí.

## Co potřebujete

- SSH z acme na **každého** hostitele (primárního i replikačního) - pro každého hostitele jeden cíl v acme, každý nasazuje stejný nebo vlastní certifikát.
- Účet v místní skupině **Administrators** s **elevovanou** relací SSH. *Hyper-V Administrators* nestačí: import do `LocalMachine\My` vyžaduje místní Administrators.
- Certifikát: jméno = **FQDN** hostitele (CN nebo SAN); v clusteru na každém uzlu i FQDN **Hyper-V Replica Brokera**; řetězec důvěryhodný na obou stranách (kořen v `LocalMachine\Root`, CRL dostupné z druhé lokality).
- Replikace jednou nastavená s ověřováním certifikátem (Hyper-V Manager, *Hyper-V Settings → Replication Configuration → Use certificate-based authentication (HTTPS)*), výchozí port **443**.

## Nastavení hostitele

1. OpenSSH Server a klíč acme (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. Replikační server, jednou (acme pak mění jen certifikát):

   ```powershell
   Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Certificate -CertificateThumbprint '<THUMBPRINT>' -CertificateAuthenticationPort 443 -ReplicationAllowedFromAnyServer $true -DefaultStorageLocation 'D:\Replica'
   Enable-NetFirewallRule -DisplayName 'Hyper-V Replica HTTPS Listener (TCP-In)'
   ```

3. Primární VM, jednou:

   ```powershell
   Enable-VMReplication -VMName 'VM01' -ReplicaServerName 'hvrep01.example.com' -ReplicaServerPort 443 -AuthenticationType Certificate -CertificateThumbprint '<THUMBPRINT>'
   Start-VMInitialReplication -VMName 'VM01'
   ```

Obnovujte v tomto pořadí: nový certifikát nejdřív na **všechny** hostitele obou stran (nasazení acme na replikační stranu, pak na primární - test primární strany potřebuje, aby mu replika důvěřovala), teprve potom se přepnou VM.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Address / SSH port | hostitel Hyper-V, `22` |
| User / The SSH key | `Administrator` nebo např. `CORP\acme-hv` (místní Administrators) |
| This host receives replication (nasazení) | zapnout u replikačního serveru |
| Primary VMs of this host (nasazení) | zapnout u primárního hostitele |
| Only these VMs (nasazení) | prázdné: všechny primární VM s certifikátem; nebo jména VM, jedno na řádek |
| Test each replica server first (nasazení) | zapnuto (výchozí) |
| PKCS#12 kind (rozšířené) | *3DES* (jakákoli Windows); *AES-256* na 2019 a novějších |
| Previous versions to keep (rozšířené) | výchozí 1 |

Test TLS se s nasazením nevytváří: posluchač replikace chce klientský certifikát.

## Ověření

```powershell
Get-VMReplicationServer | Format-List *
Get-VMReplication | Format-Table VMName, State, Health, ReplicaServer, ReplicaPort, AuthenticationType
Measure-VMReplication
Test-VMReplicationConnection -ReplicaServerName hvrep01.example.com -ReplicaServerPort 443 -AuthenticationType Certificate -CertificateThumbprint <THUMBPRINT>
```

```sh
openssl s_client -connect hvrep01.example.com:443 -showcerts </dev/null
```

(handshake může skončit chybou - posluchač žádá klientský certifikát - ale certifikát serveru se vypíše).

## Časté problémy

| Problém | Řešení |
|---|---|
| `needs both Server Authentication and Client Authentication` | vystavte certifikát ze šablony s oběma EKU |
| `this host is not a Replica server` | jednou ho zapněte (krok 2), nebo vypněte *This host receives replication* |
| `allows Kerberos only` | jednou zvolte ověřování certifikátem |
| `... does not take the new certificate, nothing changed` | replikační strana novému certifikátu zatím nedůvěřuje (CA, CRL) - nasaďte nejdřív na repliku |
| Health *Critical* po vypršení | `Resume-VMReplication -VMName <vm>` (případně resynchronizace) |

*Nejisté*: jeden certifikát se SAN pro uzel i FQDN brokera místo dvou certifikátů (běžná praxe, dokumentace popisuje dva); názvy vlastností `CertificateThumbprint`, `AuthenticationType`, `ReplicaPort` na objektech `Get-VMReplication` odpovídají parametrům cmdletů; certifikát brokera se nastavuje ve Failover Cluster Manageru (*Replication Settings*), acme nastavuje certifikát uzlu.

Zdroje: Microsoft Learn - *Hyper-V Replica overview*, *Enable Hyper-V Replica on a single host / a failover cluster*, cmdlety `Set-VMReplicationServer`, `Set-VMReplication`, `Test-VMReplicationConnection`.
