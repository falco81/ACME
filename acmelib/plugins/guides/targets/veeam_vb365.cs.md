# Veeam Backup for Microsoft 365 - nastavení pro acme

acme nastavuje certifikáty Veeam Backup for Microsoft 365 **v8** vlastními cmdlety VB365, přihlášený na server VB365 přes OpenSSH. Nahraje jednorázový PKCS#12 (cmdlety berou soubor PFX a jeho heslo), spustí to, co jste zaškrtli, a soubor smaže:

```powershell
Set-VBORestAPISettings -EnableService -HTTPSPort 4443 -CertificateFilePath <pfx> -CertificatePassword <SecureString>
Set-VBOSecuritySettings -CertificateFilePath <pfx> -CertificatePassword <SecureString> -Force
Set-VBOOperatorAuthenticationSettings -EnableAuthentication -CertificateFilePath <pfx> -CertificatePassword <SecureString>
Set-VBOTenantAuthenticationSettings -EnableAuthentication -CertificateFilePath <pfx> -CertificatePassword <SecureString>
```

| Volba v acme | Certifikát | Kdo ho používá |
|---|---|---|
| Certifikát REST API (zapnuto) | REST API, HTTPS port 4443 | Restore Portal, Veeam Service Provider Console, Veeam ONE, skripty |
| Certifikát serveru (backup proxy ve workgroup) | certifikát serveru | Windows backup proxy ve workgroup (VB365 jim to oznámí sám) |
| Certifikát ověřování restore operátorů | ověřování restore operátorů | restore operátoři |
| Certifikát ověřování tenantů | ověřování tenantů | tenanti poskytovatelů služeb |

Certifikát **Restore Portalu** acme nenastavuje: musí to být ten nahraný k jeho aplikaci v Microsoft Entra – změňte ho nejdřív tam (*Backup Applications Manager*), pak ve VB365.

## Pro které verze

Veeam Backup for Microsoft 365 **8.x** (návod výrobce: build 8.6.0.5011). Jeden modul.

## Co potřebujete

- **OpenSSH Server** na serveru VB365, port 22 otevřený z acme:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
```

- Účet s rolí VB365 **Veeam Backup Administrator** (členové místní skupiny *Administrators* ji mají ve výchozím stavu), který je lokálním administrátorem. Při zapnutém MFA použijte servisní účet s vypnutým MFA (*Disabling MFA for Service Accounts*):

```powershell
New-LocalUser -Name svc-vb365 -Password (Read-Host -AsSecureString "Heslo") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-vb365
```

- Certifikát na jméno, pod kterým se chodí na REST API / Restore Portal (veřejná CA je v pořádku – VB365 na něj žádný požadavek na CA neklade).
- REST API na jiném stroji: spouštějte acme proti **serveru VB365** (cmdlety na samostatném REST stroji neběží); když vznikne nový self-signed certifikát operátorů, naimportujte ho na REST stroji do *Trusted Root*.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / SSH port / Uživatel | server VB365, `22`, `svc-vb365` |
| Přihlásit se přes / SSH klíč / Heslo | klíč vytvořený v acme nebo heslo |
| Certifikát REST API (nasazení) | zapnuto |
| HTTPS port REST API (nasazení) | `4443` – adresa Restore Portalu používá stejný port |
| Certifikát serveru (backup proxy ve workgroup) | zapnout, když takové proxy máte |
| Certifikát ověřování restore operátorů / tenantů (pokročilé) | podle toho, co používáte |
| Zkontrolovat, co se servíruje | acme sám kontroluje `<server>:4443`, když je zapnutý certifikát REST API |

## Ověření

```powershell
Import-Module Veeam.Archiver.PowerShell
Get-VBORestAPISettings
Get-VBOSecuritySettings
```

```sh
openssl s_client -connect vb365.example.com:4443 -servername vb365.example.com </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Pak se přihlaste do Restore Portalu jako operátor a podívejte se na integraci VB365 ve VSPC / Veeam ONE.

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| `Import-Module Veeam.Archiver.PowerShell` selže | konzole / modul PowerShellu na tom stroji není | spouštějte proti samotnému serveru VB365 |
| Restore Portal po změně portu nefunguje | jeho adresa má starý port | nastavte stejný port v adrese portálu |
| Veeam ONE / VSPC ztratí spojení | důvěřovaly starému certifikátu REST API | ať důvěřují CA, nebo tam nový certifikát přijměte |
| *nothing to set* | není zaškrtnutý žádný certifikát | zaškrtněte aspoň jeden |

Zdroje: VB365 8 User Guide *Veeam Backup for Microsoft 365 Certificates*, *REST API Settings*, *Security Settings*; PowerShell `Set-VBORestAPISettings`, `Set-VBOSecuritySettings`, `Set-VBOOperatorAuthenticationSettings`, `Set-VBOTenantAuthenticationSettings`.
