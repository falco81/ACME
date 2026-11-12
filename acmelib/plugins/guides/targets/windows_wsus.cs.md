# WSUS (Windows Server Update Services) - nastavení pro acme

acme se k serveru WSUS přihlásí přes **OpenSSH** a spouští PowerShell. Nahraje certifikát jako PFX (s jednorázovým náhodným heslem), naimportuje ho do **LocalMachine\My** (popisné jméno `acme-<jméno>-<datum>-<sériové číslo>`), PFX smaže a potom:

1. dá ho na **vazbu https webu IIS „WSUS Administration“** (port **8531**) - `Remove-IISSiteBinding` a `New-IISSiteBinding -CertificateThumbPrint` (modul IISAdministration); když nový certifikát vazba odmítne, vrátí na ni starý; chybějící vazbu https vytvoří (`*:8531:`);
2. na požádání zapne **Require SSL** na pěti webových službách WSUS (`SimpleAuthWebService`, `DSSAuthWebService`, `ServerSyncWebService`, `APIremoting30`, `ClientWebService`) - nikdy na `Content`, `Inventory`, `ReportingWebService` ani `SelfUpdate` (obsah aktualizací jde po HTTP, je podepsaný);
3. spustí **`WsusUtil.exe configuressl <FQDN>`** (pokaždé, jen když se vazba změnila, nebo nikdy);
4. odstraní starší certifikáty acme nad počet *keep*, které nic nepoužívá (kontroluje vazby IIS / HTTP.sys, RDP, SQL Server, WinRM).

Vazba platí hned, IIS se nerestartuje. Platí i pro WSUS jako **software update point** Configuration Manageru.

## Pro které verze

Role WSUS na **Windows Serveru 2016, 2019, 2022 a 2025** - všude stejné příkazy (WSUS se „dál aktivně nevyvíjí“; TLS 1.3 jen na 2022/2025, daný samotnými Windows). Jeden modul, bez verzí.

## Co potřebujete

- SSH z acme na server, **TCP 22**; nainstalovaný WSUS a jeho web v IIS.
- Účet v místní skupině **Administrators** s **elevovanou** relací SSH (vestavěný Administrator, doménový správce, nebo místní správce s `LocalAccountTokenFilterPolicy=1`). Samotná skupina *WSUS Administrators* stačí na `wsusutil`, ale ne na import do `LocalMachine\My` a změny IIS - acme potřebuje místní Administrators.
- Certifikát se jménem **FQDN**, které používají klienti (Server Authentication). Klienti a podřízené servery musí jeho CA důvěřovat.
- Porty: HTTP **8530** (obsah), HTTPS **8531** (metadata) - pokud jste je změnili, HTTP musí zůstat HTTPS mínus jedna.

## Nastavení serveru

1. OpenSSH Server (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   New-NetFirewallRule -Name acme-sshd -DisplayName 'OpenSSH for acme' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress <IP-acme> -Action Allow
   ```

2. Veřejný klíč acme pro správce patří do `administrators_authorized_keys`, který smí číst jen Administrators a SYSTEM:

   ```powershell
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

3. Ověřte web a jeho port:

   ```powershell
   Import-Module IISAdministration
   Get-IISSiteBinding -Name 'WSUS Administration'
   Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup' | Select-Object PortNumber, UsingSSL
   ```

4. Klienti (GPO *Specify intranet Microsoft update service location*) míří na `https://wsus01.corp.example.com:8531`. U SUP Configuration Manageru zaškrtněte ve vlastnostech role *Require SSL communication to the WSUS server* (v `WCM.log` hledejte `WSUS_CONFIG_SUCCESS`); v hierarchii postupujte odspodu nahoru.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Address / SSH port | server WSUS, `22` |
| User / The SSH key | `Administrator` nebo např. `CORP\acme-wsus` (místní Administrators) |
| IIS site of WSUS (nasazení) | `WSUS Administration` (výchozí) |
| HTTPS port (nasazení) | `8531` (výchozí); `443`, když WSUS používá 80/443 |
| Server name for clients (nasazení) | FQDN pro `wsusutil configuressl`, např. `wsus01.corp.example.com`; prázdné: první jméno certifikátu |
| Run wsusutil configuressl (nasazení) | *every time* (výchozí), *when the binding changed*, nebo *never* |
| Require SSL on the WSUS web services (nasazení) | zapnout pro první nasazení (nebo nastavit jednou v IIS Manageru) |
| PKCS#12 kind (rozšířené) | *3DES* (jakákoli Windows); *AES-256* na 2019 a novějších |
| Previous versions to keep (rozšířené) | výchozí 1 |

S každým nasazením acme vytvoří test TLS na `<jméno serveru>:<port HTTPS>`.

## Ověření

```sh
openssl s_client -connect wsus01.corp.example.com:8531 -servername wsus01.corp.example.com -showcerts </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
Get-IISSiteBinding -Name 'WSUS Administration'
netsh http show sslcert ipport=0.0.0.0:8531
Invoke-WebRequest https://wsus01.corp.example.com:8531/ClientWebService/client.asmx -UseBasicParsing
```

V konzoli WSUS: *Connect to Server*, port 8531, *Use Secure Sockets Layer (SSL)*. Na klientech: `Get-WindowsUpdateLog`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the service WsusService is not on this server` | WSUS tu není nainstalovaný, nebo jde o jiný server |
| `there is no IIS site WSUS Administration` | web se jmenuje jinak - zadejte ho do *IIS site of WSUS* |
| klienti hlásí `0x80072F8F` | klienti nedůvěřují CA, nebo se jméno liší od certifikátu; zkontrolujte URL v GPO (FQDN + 8531) |
| přestane fungovat stahování `Content` | na `Content` někdo ručně nastavil *Require SSL* - vypněte ho; acme ho tam nikdy nenastavuje |
| wsusutil vypíše jiný port | porty HTTP/HTTPS musí být sousední (8530/8531 nebo 80/443) |

*Nejisté*: zda je `wsusutil configuressl` nutný i po pouhé výměně certifikátu na vazbě - Microsoft ho uvádí při změně jména, nastavení TLS nebo portu, proto ho acme ve výchozím stavu spouští pokaždé (neškodí); *Require SSL* nastavuje acme přes `Set-WebConfigurationProperty ... sslFlags` - dokumentace ho ukazuje v IIS Manageru.

Zdroje: Microsoft Learn - *Secure WSUS with SSL* (nasazení WSUS, krok 2.5), *WsusUtil.exe*, cmdlety *IISAdministration* (`New-IISSiteBinding`, `Remove-IISSiteBinding`), TLS pro *software update point* Configuration Manageru.
