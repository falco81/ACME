# Huawei / xFusion iBMC - nastavení pro acme

acme naimportuje **HTTPS certifikát iBMC Huawei nebo xFusion** (FusionServer, TaiShan) jako
**vlastní certifikát** („custom certificate“) - soubor PKCS#12 s jednorázovým heslem - přes
Redfish iBMC:

```text
POST /redfish/v1/SessionService/Sessions                       -> X-Auth-Token
POST /redfish/v1/UpdateService/FirmwareInventory               multipart "imgfile" -> /tmp/web/acme-….pfx
POST /redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HttpsCert.ImportCustomCertificate
     {"Type": "URI", "Content": "/tmp/web/acme-….pfx", "Password": "…"}   -> iBMC.1.0.CertImportOK
POST /redfish/v1/Managers/1/Actions/Manager.Reset {"ResetType": "ForceRestart"}
```

Huawei: po `CertImportOK` je třeba „restartovat iBMC“, aby se certifikát projevil - acme to ve
výchozím stavu udělá. **Restartuje se jen iBMC; server běží dál.** Soubor v `/tmp/web` je
dočasný (po importu nebo restartu zmizí).

**Které verze:** iBMC V2/V3 (Huawei FusionServer V5/V6, TaiShan 200, xFusion FusionServer na
stejné linii iBMC), stojanové servery (Manager ID `1`) i servery s vysokou hustotou a blade
(`BladeN`). **Méně jisté:** portál Huawei ukazuje stránky API jen ve výňatcích - název
`Password` pro heslo PKCS#12 a cesty v nejnovějším firmwaru xFusion nejsou ověřené z celé
stránky. Stiskněte **Vyzkoušet**: řekne, zda iBMC nabízí `HttpsCert.ImportCustomCertificate`.

## Co potřebujete

- Z acme na iBMC: **TCP 443**, zapnutý Redfish (**Services** ve webovém rozhraní iBMC).
- Uživatele iBMC s rolí **Administrator** - nebo vlastní roli (`CustomRole1…4`) s právem
  bezpečnostní konfigurace.

## Nastavení iBMC

1. Vytvořte uživatele pro acme. Přes Redfish:

   ```sh
   curl -k -u Administrator:'<heslo-admina>' -X POST https://ibmc.example.local/redfish/v1/AccountService/Accounts \
     -H "Content-Type: application/json" \
     -d '{"UserName": "svc-cert", "Password": "<silné-heslo>", "RoleId": "Administrator"}'
   ```

   Nebo modulem PowerShell od Huawei:

   ```text
   $s = Connect-iBMC -Address ibmc.example.local -Credential (Get-Credential) -TrustCert
   Add-iBMCUser -Session $s -Username svc-cert -Password (Read-Host -AsSecureString) -Role Administrator
   Disconnect-iBMC -Session $s
   ```
2. Ověřte, co iBMC nabízí (jen čtení):

   ```sh
   curl -k -u svc-cert:'<heslo>' https://ibmc.example.local/redfish/v1/Managers/1/SecurityService/HttpsCert
   ```

   V `Actions` má být `#HttpsCert.ImportCustomCertificate`.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP iBMC, např. `ibmc.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-cert` z kroku 1 |
| Ověřovat certifikát zařízení | Při prvním nasazení vypnuto, potom zapnuto |
| ID manageru (rozšířené) | `1` u stojanového serveru; `Blade1`, `Blade2`… u serveru s vysokou hustotou nebo blade |
| Potom restartovat iBMC (nasazení) | Zapnuto (certifikát platí až po restartu) |
| Zkontrolovat, co se servíruje | Prázdné: acme po restartu zkontroluje adresu iBMC |

## Ověření

- **Vyzkoušet** přečte `SecurityService/HttpsCert` (právě servírovaný certifikát) - nic nemění.
- Po restartu:

  ```sh
  openssl s_client -connect ibmc.example.local:443 -servername ibmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo; příliš mnoho otevřených relací - počkejte. |
| `403` při nahrání nebo importu | Uživatel nemá právo bezpečnostní konfigurace. |
| `404` při importu | iBMC nemá `HttpsCert.ImportCustomCertificate` (starý firmware, jiné ID manageru) - zkontrolujte *ID manageru*, aktualizujte iBMC, nebo naimportujte `.pfx` ve webovém rozhraní (SSL certifikát, *Customize*). |
| Certifikát odmítnut | Od iBMC V360 se odmítají certifikáty s MD5; použijte RSA 2048+ nebo ECDSA. |
| Stále se servíruje starý certifikát | *Potom restartovat iBMC* bylo vypnuté - restartujte iBMC. |
