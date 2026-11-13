# Veeam Cloud Connect - nastavení pro acme

acme vymění **TLS certifikát Cloud Connect** na backup serveru poskytovatele služby – certifikát, který cloud gateway ukazují tenantům. Je oddělený od certifikátu backup serveru a na rozdíl od něj **může být běžný certifikát webového serveru od veřejné CA** (Let's Encrypt, komerční CA), **wildcard** nebo certifikát s více FQDN. acme přes OpenSSH spustí PowerShell na backup serveru poskytovatele:

1. přečte právě používaný certifikát (`Get-VBRCloudGatewayCertificate`); když je to už tentýž, nic nemění;
2. naimportuje certifikát z jednorázového PKCS#12 do `Cert:\LocalMachine\My` (soubor hned smaže) a jeho certifikáty CA do *Intermediate Certification Authorities* / *Trusted Root Certification Authorities* – Veeam odmítne certifikát, jehož řetězci server nedůvěřuje;
3. `$c = Get-VBRCloudGatewayCertificate -FromStore | Where-Object Thumbprint -eq …` a `Add-VBRCloudGatewayCertificate -Certificate $c`;
4. smaže starší certifikáty acme nad počet *ponechat* (nikdy ten, který se používá nebo používal) a v úloze uvede nový **otisk (thumbprint)**.

## Pro které verze

Veeam Backup & Replication **12.3** a **13.0 – 13.1** (cmdlety i postup jsou stejné). Jeden modul.

## Co potřebujete

- Certifikát pokrývající **DNS jméno každé cloud gateway** – s `*.provider.com` se gateway, jejíž jméno nekončí na `.provider.com`, nepoužije.
- **OpenSSH Server** na backup serveru poskytovatele, port 22 otevřený z acme:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
```

- Účet, který je **lokálním administrátorem** (úložiště počítače) a má roli VBR **Backup Administrator**; při zapnutém MFA označený v *Users & Roles* jako *service account* (PowerShell MFA neumí):

```powershell
New-LocalUser -Name svc-veeam -Password (Read-Host -AsSecureString "Heslo") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-veeam
```

- Účet služby **Veeam Cloud Connect Service** (ve výchozím stavu Local System) musí číst soukromý klíč bez hesla – klíč naimportovaný do úložiště počítače Local System číst může; pokud služba běží pod jiným účtem, dejte mu *Manage Private Keys → Read*.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / SSH port / Uživatel | backup server poskytovatele, `22`, `svc-veeam` |
| Přihlásit se přes / SSH klíč / Heslo | klíč vytvořený v acme nebo heslo |
| Složka pro nahrávání (pokročilé) | `C:/Windows/Temp` |
| Přidat certifikáty CA do úložišť počítače (nasazení, pokročilé) | zapnuto |
| Kolik předchozích verzí ponechat (pokročilé) | `1` |

Cloud Connect mluví na gateway vlastním protokolem Veeamu (ve výchozím stavu port 6180): obyčejná kontrola TLS na něm certifikát vidět nemusí, proto acme žádný test nepřipojí – podívejte se do konzole (níže).

## Tenanti

- Certifikát od CA, které tenanti důvěřují (veřejná CA, nebo vaše CA v jejich *Trusted Root*): obvykle není co dělat.
- Self-signed certifikát nebo certifikát privátní CA: pošlete tenantům nový otisk (úloha ho uvádí) bezpečnou cestou; nastaví si ho:

```powershell
$sp = Get-VBRCloudProvider -Name "cloudgw.provider.com"
Set-VBRCloudProvider -CloudProvider $sp -VerifyCertificate -CertificateThumbprint "<nový otisk>"
Rescan-VBREntity -AllCloudProviders
```

Dělejte to v servisním okně – úlohy tenantů mohou během přepnutí certifikátu selhat.

## Ověření

```powershell
Get-VBRCloudGatewayCertificate | Format-List *
```

V konzoli: *Cloud Connect > Manage Certificates* → *Keep the existing certificate* ukáže jméno, platnost, otisk a sériové číslo. U tenanta: rescan poskytovatele a úloha do cloud repository.

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| *-FromStore does not offer …* | serveru chybí důvěra v řetězec, nebo služba nepřečte klíč | nechte *Přidat certifikáty CA…* zapnuté; zkontrolujte práva ke klíči |
| gateway se nepoužívá | certifikát nepokrývá její DNS jméno | přidejte jméno do certifikátu |
| tenantům selhává certifikát | ověřují starý otisk | `Set-VBRCloudProvider -VerifyCertificate -CertificateThumbprint` |
| *not as an administrator* | relace SSH není se zvýšenými právy | účet ve skupině *Administrators* |

Zdroje: Veeam Cloud Connect 13 *TLS Certificates* (typy, práva, import, co dál); PowerShell `Get-VBRCloudGatewayCertificate`, `Add-VBRCloudGatewayCertificate` (13 a 12.x), `Set-VBRCloudProvider`.
