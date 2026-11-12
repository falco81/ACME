# Office Online Server - nastavení pro acme

acme se k Office Online Serveru (OOS) přihlásí přes **OpenSSH** a spouští PowerShell. Nahraje certifikát jako PFX (s jednorázovým náhodným heslem), naimportuje ho do **LocalMachine\My** s **exportovatelným** klíčem (OOS to vyžaduje) a s popisným jménem `acme-<jméno>-<datum>-<sériové číslo>` - jedinečným, jak OOS vyžaduje - PFX smaže a potom:

1. přečte farmu (`Get-OfficeWebAppsFarm`); farmu s **SSL offloadingem** odmítne (certifikát patří na load balancer);
2. ověří, že popisné jméno má právě jeden certifikát;
3. `Set-OfficeWebAppsFarm -CertificateName <popisné jméno> -Force` - nastavení pro celou farmu; acme certifikát v IIS **sám neváže** (vazbu udělá OOS; ruční vazba se při restartu ztratí);
4. na požádání naplánuje **restart tohoto serveru** za minutu (`shutdown /r /t 60`) - farma převezme certifikát po restartu svých serverů; testy po nasazení pak čekají až asi 6 minut;
5. odstraní starší certifikáty acme nad počet *keep*, nikdy ne ten, který farma uvádí.

## Pro které verze

Office Online Server (aktuální vydání, Desktop Experience) na **Windows Serveru 2016 (aktualizace z listopadu 2018 a novější), 2019 (oprava z července 2021 a novější) a 2022 (oprava z listopadu 2021 a novější)** - jeden modul, bez verzí. Používají ho SharePoint Server (2016, 2019, SE) a Exchange.

## Co potřebujete

- SSH z acme na **každý** server OOS, **TCP 22** - pro každý server jeden cíl v acme, všechny nasazují stejný certifikát (popisné jméno je na každém stejné).
- Účet v místní skupině **Administrators** s **elevovanou** relací SSH (vyžaduje to modul OfficeWebApps i `LocalMachine\My`).
- Certifikát od CA, které důvěřují servery SharePointu/Exchange i prohlížeče, s **FQDN farmy** (interní i externí URL) v SAN; žádné zvláštní EKU.

## Nastavení serveru

1. OpenSSH Server a klíč acme (PowerShell jako správce):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAA... acme'
   icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
   ```

2. Farma už existuje (vytvořená jednou, s libovolným certifikátem):

   ```powershell
   Import-Module OfficeWebApps
   Get-OfficeWebAppsFarm | Format-List InternalURL, ExternalURL, CertificateName, SSLOffloaded
   ```

3. Při více serverech: nasazujte na ně **po jednom** se zapnutým *Restart this server*, nebo je za load balancerem postupně restartujte sami.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Address / SSH port | server OOS, `22` |
| User / The SSH key | `Administrator` nebo např. `CORP\acme-oos` (místní Administrators) |
| Restart this server after the change (nasazení) | vypnuto (výchozí): restartujte v servisním okně; zapnuto: za minutu |
| HTTPS port to check (nasazení) | `443` (výchozí); `0`: bez testu |
| PKCS#12 kind (rozšířené) | *3DES* (jakákoli Windows); *AES-256* na 2019 a novějších |
| Previous versions to keep (rozšířené) | výchozí 1 |

## Ověření

```sh
openssl s_client -connect oos.example.com:443 -servername oos.example.com </dev/null | openssl x509 -noout -subject -enddate
```

```powershell
Get-OfficeWebAppsFarm | Format-List CertificateName
Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -like 'acme-*' | Format-List FriendlyName, Thumbprint, NotAfter
```

Otevřete `https://oos.example.com/hosting/discovery`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the OfficeWebApps module is not here` | na tomto serveru není Office Online Server nainstalovaný |
| `this server is in no Office Online Server farm` | jednou vytvořte farmu (`New-OfficeWebAppsFarm`) |
| `the farm is SSL offloaded` | dejte certifikát místo toho na load balancer |
| `the friendly name ... is on 2 certificates` | odstraňte duplikát z `LocalMachine\My` |
| server nabízí pořád starý certifikát | servery se ještě nerestartovaly |

*Nejisté*: `-Force` u `Set-OfficeWebAppsFarm` (aby běžel bez dotazu) - příklad v dokumentaci ho nemá; že nastavení vyžaduje restart všech serverů farmy, uvádí reference cmdletu.

Zdroje: Microsoft Learn - *Plan Office Online Server* (požadavky na certifikát), *Deploy Office Online Server*, `Set-OfficeWebAppsFarm`, `New-OfficeWebAppsFarm`.
