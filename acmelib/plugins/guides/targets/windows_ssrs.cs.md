# SQL Server Reporting Services / Power BI Report Server - nastavení pro acme

acme se k serveru sestav přihlásí přes **OpenSSH** a spouští PowerShell. Nahraje certifikát jako PFX (s jednorázovým náhodným heslem), naimportuje ho do **LocalMachine\My** (popisné jméno `acme-<jméno>-<datum>-<sériové číslo>`), PFX smaže a potom přes **poskytovatele WMI** serveru sestav (`root\Microsoft\SqlServer\ReportServer\RS_<instance>\v<verze>\Admin`, třída `MSReportServer_ConfigurationSetting`):

1. vypíše vazby HTTPS (`ListSSLCertificateBindings`) - webovou službu i webový portál, každou IP a port;
2. u každé, která ještě nemá nový certifikát: `RemoveSSLCertificateBindings` (starý otisk), potom `CreateSSLCertificateBinding` s novým otiskem **malými písmeny** (jinak metoda selže); když nový certifikát odmítne, vytvoří znovu starou vazbu;
3. odstraní starší certifikáty acme nad počet *keep*, které nic nepoužívá (kontroluje vazby HTTP.sys - tam jsou i vazby SSRS). **Vazba se ruší dřív než starý certifikát** - vazbu SSRS ponechanou na smazaném certifikátu už přes WMI odstranit nejde.

acme vazby nahrazuje, první nevytváří: certifikát HTTPS jednou zvolte v **Report Server Configuration Manageru** (*Web Service URL → HTTPS Certificate*, *Web Portal URL → Advanced → Multiple HTTPS Identities*). Změna recykluje aplikační domény serveru sestav (sekundy).

## Pro které verze

**SSRS 2016, 2017, 2019, 2022** a **Power BI Report Server** (reporting SQL Serveru 2025 na vlastních serverech) - stejné metody WMI; instanci a její nejnovější jmenný prostor `v<NN>` acme najde sám. Jeden modul, bez verzí.

## Co potřebujete

- SSH z acme na server, **TCP 22**.
- Účet v místní skupině **Administrators** s **elevovanou** relací SSH - třída WMI je „přístupná jen s právy správce“.
- Certifikát (Server Authentication) se jménem hostitele z URL; SSRS klientské certifikáty nepoužívá.
- IIS na stejném stroji sdílí HTTP.sys: každou IP:port spravujte jedním nástrojem.

## Nastavení serveru

1. OpenSSH Server a klíč acme (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. Instance a vazby, které acme uvidí:

   ```powershell
   Get-WmiObject -Namespace 'root\Microsoft\SqlServer\ReportServer' -Class __Namespace | Select-Object Name
   $rs = Get-WmiObject -Namespace 'root\Microsoft\SqlServer\ReportServer\RS_SSRS\v16\Admin' -Class MSReportServer_ConfigurationSetting
   $b = $rs.ListSSLCertificateBindings(1033); $b.Application; $b.CertificateHash; $b.IPAddress; $b.Port
   ```

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Address / SSH port | server sestav, `22` |
| User / The SSH key | `Administrator` nebo např. `CORP\acme-rs` (místní Administrators) |
| Report server instance (nasazení) | `SSRS`, `PBIRS`, `MSSQLSERVER`...; prázdné, když je jen jedna |
| HTTPS port to check (nasazení) | `443` (výchozí) - acme s nasazením testuje `<adresa>:<port>`; `0`: bez testu |
| PKCS#12 kind (rozšířené) | *3DES* (jakákoli Windows); *AES-256* na 2019 a novějších |
| Previous versions to keep (rozšířené) | výchozí 1 |

## Ověření

```sh
openssl s_client -connect reports.example.com:443 -servername reports.example.com </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
netsh http show sslcert ipport=0.0.0.0:443
```

Report Server Configuration Manager → *Web Service URL* a *Web Portal URL* ukazují certifikát; otevřete `https://reports.example.com/Reports`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `no report server ... is on this server` | SSRS / PBIRS není nainstalovaný, nebo není registrovaný poskytovatel WMI |
| `there are several instances` | zadejte jednu do *Report server instance* |
| `there is no HTTPS binding yet` | HTTPS jednou nastavte v Report Server Configuration Manageru |
| `... could not be removed` | starý certifikát byl smazán, když byl ještě navázaný: odstraňte vazbu HTTP.sys příkazem `netsh http delete sslcert ipport=0.0.0.0:443` a jednou navažte v Configuration Manageru |

*Nejisté*: názvy výstupních parametrů `ListSSLCertificateBindings` (`IPAddress` - acme bere i `IPAddresses`) a názvy aplikací (acme používá ty, které vrátí výpis, ne pevné názvy); služba se nerestartuje (změna vazby recykluje aplikační domény).

Zdroje: Microsoft Learn - *Configure TLS connections on a native mode report server*, metody poskytovatele WMI `ListSSLCertificateBindings`, `CreateSSLCertificateBinding`, `RemoveSSLCertificateBinding(s)`, *Access the Reporting Services WMI provider*.
