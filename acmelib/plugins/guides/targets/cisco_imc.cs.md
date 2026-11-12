# Cisco IMC (UCS C-Series, samostatný) - nastavení pro acme

acme vloží **HTTPS certifikát samostatného Cisco IMC** jako **External Certificate** s vlastním
soukromým klíčem přes **XML API** IMC (`https://<imc>/nuova`):

```text
aaaLogin                                          -> cookie relace
uploadExternalCertificate  sys/cert-mgmt/external-cert-upload    adminAction=content-cert-upload
uploadExternalPrivateKey   sys/cert-mgmt/external-pvt-key-upload adminAction=content-cert-upload
certificateManagement      sys/cert-mgmt                         adminAction=activate-external-cert
aaaLogout
```

Je to cesta Cisca pro klíč vytvořený mimo IMC (běžné *Upload Server Certificate* bere jen
certifikát k CSR, kterou vytvořilo samo IMC). **Aktivace přeruší všechna spojení HTTPS a SSH
a restartuje služby IMC** - naplánujte ji; server a jeho operační systém běží dál.

**Které verze:** Cisco IMC 4.x (M5/M6) a 6.0 (M7, M8) - stejné objekty XML. Servery spravované
Intersightem (IMM) nebo UCS Managerem nemají místní konfiguraci IMC: použijte tam Certificate
Management Policy.

**Klíče:** RSA **2048 nebo 4096** (od M5 i 8192); soubory nejvýše 8 KB. Zvolte typ klíče RSA.
Certifikát musí být serverový (EKU serverAuth).

## Co potřebujete

- Z acme na IMC: **TCP 443**; zapnuté XML API (**Admin → Communication Services → XML API**).
- Uživatele IMC s rolí **admin** - Cisco: „Admin privileges for all certificate tasks“; užší
  role neexistuje.
- Správný čas na IMC („Set Cisco IMC to the current time before certificate tasks“).

## Nastavení IMC

1. Vytvořte uživatele pro acme (CLI přes SSH; slot 5 je příklad - vezměte volný):

   ```text
   Server# scope user 5
   Server /user # set enabled yes
   Server /user # set name svc-cert
   Server /user # set role admin
   Server /user # set password
   Please enter password:
   Please confirm password:
   Server /user* # commit
   ```
2. Ověřte, že ho XML API pustí dovnitř:

   ```sh
   curl -k https://cimc.example.local/nuova -d "<aaaLogin inName='svc-cert' inPassword='<heslo>'/>"
   ```

   Odpověď obsahuje `outCookie="…"`; odhlaste se příkazem
   `<aaaLogout cookie='<cookie>' inCookie='<cookie>'/>`.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP IMC, např. `cimc.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-cert` z kroku 1 |
| Ověřovat certifikát zařízení | Při prvním nasazení vypnuto (IMC má self-signed certifikát), potom zapnuto |
| Poslat s certifikátem i řetězec (nasazení) | Vypnuto (jen certifikát); zapněte, potřebují-li klienti mezilehlý certifikát od IMC |
| Zkontrolovat, co se servíruje | Prázdné: acme zkontroluje adresu IMC, až se služby vrátí |

## Ověření

- **Vyzkoušet** se přihlásí a přečte `sys/cert-mgmt/curr-cert` (současný certifikát) - nic
  nemění.
- Po nasazení:

  ```sh
  openssl s_client -connect cimc.example.local:443 -servername cimc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `signing in: … error 551` | Špatný uživatel nebo heslo, nebo je XML API vypnuté. |
| Odmítnuto při nahrání | Uživatel nemá roli `admin`; klíč není RSA; certifikát není serverový. |
| `Key does not match` | Klíč a certifikát nepatří k sobě - nasaďte znovu (vynuceně). |
| Během nasazení se přerušila spojení | Očekávané: aktivace restartuje webové a SSH služby IMC. |
| Server spravovaný Intersightem | Použijte Certificate Management Policy v Intersightu (`certificatemanagement.Imc`); IMC místní změny odmítne. |
