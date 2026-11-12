# System Center Operations Manager (certifikát) - nastavení pro acme

Operations Manager ověřuje **bránu** (gateway), **management server** nebo **agenta** mimo důvěryhodnou doménu (pracovní skupina, DMZ) certifikátem, oboustranně, na **TCP 5723**. acme se k takovému stroji přihlásí přes **OpenSSH** a spouští PowerShell:

1. nahraje certifikát jako PFX (s jednorázovým náhodným heslem) a naimportuje ho příkazem **`certutil -f -p <heslo> -importPFX My <pfx> AT_KEYEXCHANGE`** - klíč se uloží do **starého CSP jako AT_KEYEXCHANGE** (KeySpec 1), jak Operations Manager potřebuje (klíč v KSP/CNG nefunguje); PFX se smaže v každém případě; popisné jméno `acme-<jméno>-<datum>-<sériové číslo>`;
2. ověří, že certifikát má **Server Authentication i Client Authentication** a klíč je `Exchange` - dřív, než se cokoli přepne;
3. spustí **`MOMCertImport.exe /SubjectName <subjekt>`** a pak přečte zpět `ChannelCertificateSerialNumber` (`HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\MachineSettings`), aby měl jistotu, že vzal **tento** certifikát;
4. restartuje **Microsoft Monitoring Agent** (`HealthService`, krátký výpadek monitorování tohoto stroje) - když o to požádáte;
5. odstraní starší certifikáty acme nad počet *keep*, nikdy ne ten, který Operations Manager používá.

Certifikát musí mít klíč **RSA** (certifikát ECDSA acme odmítne dřív, než cokoli udělá) a obě EKU - **většina veřejných CA už Client Authentication nevydává**: použijte vlastní CA (ACME z AD CS, step-ca...) se šablonou *Operations Manager*.

## Pro které verze

**Operations Manager 2019, 2022 a 2025** - `MOMCertImport` i požadavky na certifikát jsou stejné. Jeden modul, bez verzí.

## Co potřebujete

- SSH z acme na bránu / management server / agenta, **TCP 22**.
- Účet v místní skupině **Administrators** s **elevovanou** relací SSH (vyžaduje to MOMCertImport i `LocalMachine\My`).
- `MOMCertImport.exe` na stroji: z instalačního média `SupportTools\amd64` (zkopírujte ho např. do `C:\Tools`); na bráně je v `%ProgramFiles%\System Center Operations Manager\Gateway`.
- Subjekt `CN=<FQDN>` stroje; kořenová CA v `LocalMachine\Root` na obou stranách; kromě certifikátů acme jen **jeden** certifikát s tímto subjektem (MOMCertImport vybírá podle subjektu).

## Nastavení stroje

1. OpenSSH Server a klíč acme (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. Kořen CA, jednou (mimo doménu):

   ```powershell
   Import-Certificate -FilePath C:\Certs\root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

3. Šablona na CA (AD CS): duplikát *Computer*, *Legacy Cryptographic Service Provider* (*Microsoft RSA SChannel Cryptographic Provider*), aspoň 2048 bitů, EKU Server + Client Authentication, Subject *Supply in the request*.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Address / SSH port | brána / management server / agent, `22` |
| User / The SSH key | `Administrator` nebo např. `DMZ\acme-scom` (místní Administrators) |
| MOMCertImport.exe (nasazení) | např. `C:\Tools\MOMCertImport.exe`; na bráně prázdné |
| Restart the Microsoft Monitoring Agent (nasazení) | zapnuto (výchozí) |
| PKCS#12 kind (rozšířené) | *3DES* (jakákoli Windows); *AES-256* na 2019 a novějších |
| Previous versions to keep (rozšířené) | výchozí 1 |

Test TLS se s nasazením nevytváří: 5723 je vlastní oboustranně ověřovaný kanál Operations Manageru.

## Ověření

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\MachineSettings' | Select-Object ChannelCertificateSerialNumber
certutil -v -store My <thumbprint> | Select-String 'KeySpec|Provider'
Get-WinEvent -LogName 'Operations Manager' -MaxEvents 50 | Where-Object Id -in 20053,20049,20050,20052,20066,20069,20077
Test-NetConnection ms01.example.com -Port 5723
```

Událost **20053** říká, že se certifikát načetl.

## Časté problémy

| Problém | Řešení |
|---|---|
| `needs an RSA key` | vystavte certifikát s klíčem RSA |
| `needs both Server Authentication and Client Authentication` | šablona s oběma EKU |
| `the key is not in a legacy CSP as AT_KEYEXCHANGE` | import ho nepřevedl - zkontrolujte `certutil -v -store My <thumbprint>`; nasaďte znovu s *force* |
| `MOMCertImport.exe is not at ...` | zkopírujte ho z média a zadejte jeho cestu |
| `MOMCertImport took another certificate with the subject ...` | odstraňte z `LocalMachine\My` ostatní certifikáty (mimo acme) s tímto subjektem |
| události 20049 / 20050 / 20052 | druhá strana nedůvěřuje CA, nebo nesedí jméno |

*Nejisté*: jak MOMCertImport vybírá mezi více certifikáty se stejným subjektem (acme kontroluje sériové číslo, které zapsal, a srozumitelně selže); pořadí bajtů v `ChannelCertificateSerialNumber` (acme bere obě); zda MOMCertImport restartuje HealthService sám (acme ho restartuje, když o to požádáte).

Zdroje: Microsoft Learn - *Obtain a certificate for use with Windows Servers and Operations Manager*, *Install an Operations Manager gateway server* (MOMCertImport), `certutil -importPFX ... AT_KEYEXCHANGE`.
