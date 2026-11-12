# Windows server (OpenSSH + PowerShell) - nastavení pro acme

acme se k Windows přihlásí přes **OpenSSH** a spouští PowerShell. Nahraje certifikát jako
PFX (s jednorázovým náhodným heslem) do `C:/Windows/Temp`, naimportuje ho do
**LocalMachine\My** (popisné jméno `acme-<jméno>-<datum>-<sériové číslo>`), PFX smaže a
pak podle zadání:

- **IIS bindings** - `site | host name | port [| ip]`: s host name vznikne vazba SNI,
  chybějící vazby https se vytvoří;
- **Remote Desktop listener** - certifikát RDP-tcp, NETWORK SERVICE dostane právo čtení
  klíče;
- **Exchange services** - `Enable-ExchangeCertificate -Services ...`;
- **Roles on the server** - RDS, RD Gateway, AD FS, WAP, SQL Server, LDAPS, WinRM HTTPS,
  SSTP, IIS Central Certificate Store, IIS FTP, Exchange, Skype for Business, SharePoint SE,
  Windows Admin Center (každá s vlastním přepínačem a poli);
- volitelně **soubory** (PEM, PFX, JKS... kamkoli) a **skript PowerShellu** po nich.

Staré certifikáty acme stejného jména nad počet *Previous versions to keep* se odstraní,
pokud je nic nepoužívá.

Pro Windows Server 2016 a novější (doporučeno 2019+) a Windows 10/11 s funkcí OpenSSH
Server.

## Co potřebujete

- SSH z acme na server, **TCP 22**.
- Účet v místní skupině **Administrators**, jehož relace SSH je **elevovaná**
  (vestavěný Administrator, doménový správce, nebo místní správce s
  `LocalAccountTokenFilterPolicy=1`).
- Role, které chcete použít, už nainstalované (IIS, RDS, AD FS...).

## Nastavení Windows

1. Nainstalujte a spusťte OpenSSH Server (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   New-NetFirewallRule -Name acme-sshd -DisplayName 'OpenSSH for acme' -Direction Inbound `
     -Protocol TCP -LocalPort 22 -RemoteAddress <IP-acme> -Action Allow
   ```

2. Vložte veřejný klíč acme. U účtu **správce** čte Windows
   `C:\ProgramData\ssh\administrators_authorized_keys` (ne soubor uživatele) a soubor smí
   číst jen Administrators a SYSTEM:

   ```powershell
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

   Klíč vytvořte v acme (cíl → *The SSH key* → *Make a key*; *How to set it up on
   Windows* ukáže tytéž příkazy).
3. **Místní** správce jiný než vestavěný dostane přes SSH filtrovaný (neelevovaný) token.
   Buď použijte doménového správce / vestavěného Administratora, nebo:

   ```powershell
   New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
     -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force
   ```

4. Poznamenejte si jména webů IIS (`Get-Website`) a role, které má acme aktualizovat.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / SSH port | Server, `22` |
| User | `Administrator` (výchozí) nebo např. `EXAMPLE\acme-admin` |
| Sign in with / The SSH key | *a private key* (nebo heslo - nutné pro roli RDS se vzdáleným brokerem nebo cestu CCS přes UNC) |
| Folder for uploads (pokročilé) | `C:/Windows/Temp` (výchozí) |
| IIS bindings (nasazení) | např. `Default Web Site \| www.example.com \| 443` |
| Remote Desktop listener (nasazení) | Zapnout pro RDP |
| Exchange services (nasazení, pokročilé) | např. `IIS,SMTP`; prázdné: není Exchange |
| PKCS#12 kind (pokročilé) | *3DES (any Windows)*; *AES-256* pro Server 2019 a novější |
| Key exportable (pokročilé) | Vypnuto (výchozí) |
| PowerShell after (pokročilé) | Vlastní řádky; `$thumb` je nový otisk |
| Roles on the server | Zapněte potřebné role a vyplňte jejich pole |
| Files / skript po nich (pokročilé) | Jen pokud něco potřebuje certifikát jako soubory |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `www.example.com:443`, `rdp.example.com:3389` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, ověří, že relace je elevovaná, a vypíše
  nalezené role: `signed in as Administrator on Microsoft Windows Server 2022 ..., PowerShell 5.1 ...`.
- Na serveru:

  ```powershell
  Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -like 'acme-*' | Format-List FriendlyName, Thumbprint, NotAfter
  Get-WebBinding -Protocol https
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Permission denied (publickey)` u správce | Klíč musí být v `administrators_authorized_keys` s právy `icacls` jako výše. |
| `signed in as ..., but not as an administrator (elevated)` | Použijte vestavěného Administratora nebo doménového správce, nebo nastavte `LocalAccountTokenFilterPolicy=1`. |
| Import PFX na starších Windows selže | Zvolte *PKCS#12 kind* 3DES. |
| `IIS line N has no site` | Každý řádek potřebuje `site \| host \| port`. |
| Role RDS / CCS: přístup na broker nebo sdílení odepřen | Přihlášení klíčem nemá síťová pověření (second hop): přihlaste se heslem, nebo spouštějte na brokeru / použijte místní složku. |
| Starý certifikát se neodstranil | Ještě ho používá vazba nebo služba - očekávané; zmizí, až nebude používán. |
