# Supermicro BMC (nahrání certifikátu SSL) - nastavení pro acme

acme nahraje **HTTPS certifikát BMC Supermicro** (webové rozhraní a Redfish ho sdílejí) vlastní
akcí Redfish od Supermicra - **bez licence** (v seznamu API Supermicra je označena „Standard“):

```text
POST /redfish/v1/UpdateService/Oem/Supermicro/SSLCert/Actions/SmcSSLCert.Upload
     multipart/form-data: cert_file = certifikát (+ řetězec), key_file = soukromý klíč (PEM)
```

Přihlásí se relací Redfish (nebo HTTP Basic), nahraje oba soubory a na přání BMC resetuje
voláním `Manager.Reset` `GracefulRestart` („BMC cold reset“). Webový server BMC se po nahrání
restartuje sám; **server a jeho operační systém zůstanou nedotčené**.

**Které verze:** firmware BMC X12/H12, X13/H13 a X14/H14 (Supermicro Redfish User's Guide 4.0,
1.22.2 a 1.23.2) - všude stejné volání. **X11 a starší**: použijte webové rozhraní
(**Configuration → SSL Certificate**). Gen 15 přejmenovává některé cesty OEM - po aktualizaci
ověřte.

**S licencí SFT-DCMS-SINGLE** funguje i standardní cesta: cíl *Server management (Redfish)*
s volbou **Poslat jako: PEM** (`ReplaceCertificate` Supermicra bere jen `PEM`). Bez licence
standardní `CertificateService` odpoví chybou licence - použijte tento cíl.

## Co potřebujete

- Z acme na BMC: **TCP 443**.
- Uživatele BMC s rolí **Administrator** (užší roli pro certifikáty Supermicro nemá; změna
  certifikátu je `ConfigureManager`).
- Klíč RSA nebo ECDSA: nahrávání bere soubory PEM; vlastní CSR Supermicra nabízí jen RSA - **RSA
  2048 nebo 3072** je bezpečná volba.

## Nastavení BMC

1. Vytvořte pro acme samostatný účet (Redfish; BMC s pevnými sloty účtů místo toho přijme
   `PATCH` volného slotu `/redfish/v1/AccountService/Accounts/<n>`):

   ```sh
   curl -k -u ADMIN:'<heslo-admina>' -X POST https://bmc.example.local/redfish/v1/AccountService/Accounts \
     -H "Content-Type: application/json" \
     -d '{"UserName": "svc-cert", "Password": "<silné-heslo>", "RoleId": "Administrator", "Enabled": true}'
   ```

   Nebo ve webovém rozhraní (menu se liší podle generace BMC): seznam uživatelů v nabídce
   **Configuration**, oprávnění *Administrator*.
2. Omezte, odkud se smí přihlásit: **Configuration → IP Access Control** (přidejte server acme).
3. Ověřte, že akce existuje (jen čte):

   ```sh
   curl -k -u svc-cert:'<heslo>' https://bmc.example.local/redfish/v1/UpdateService/Oem/Supermicro/SSLCert
   ```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP BMC, např. `bmc.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-cert` z kroku 1 |
| Basic autentizace místo relace (rozšířené) | Jen pro BMC, kterému nefungují relace |
| Ověřovat certifikát zařízení | Při prvním nasazení vypnuto (BMC má self-signed certifikát „IPMI“), potom zapnuto |
| Poslat s certifikátem i řetězec (nasazení) | Zapnuto: `cert_file` obsahuje certifikát i mezilehlé certifikáty |
| Potom resetovat BMC (nasazení) | Vypnuto; zapněte jen tehdy, když BMC po nahrání dál servíruje starý certifikát |
| Zkontrolovat, co se servíruje | Prázdné: acme zkontroluje vlastní adresu BMC |

## Ověření

- **Vyzkoušet** se přihlásí, přečte manager a `Oem/Supermicro/SSLCert` - nic nemění.
- Z libovolného stroje:

  ```sh
  openssl s_client -connect bmc.example.local:443 -servername bmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný uživatel nebo heslo, případně zakázaný účet. |
| `403` | Účet nemá roli *Administrator*. |
| `no SmcSSLCert.Upload` (404/405) | X11 nebo starý firmware: aktualizujte firmware BMC, nebo nahrajte certifikát ve webovém rozhraní (**Configuration → SSL Certificate**). |
| Nahrání je odmítnuto | Klíč musí být nešifrovaný PEM (acme ho tak posílá); zkuste vypnout *Poslat s certifikátem i řetězec*; použijte klíč RSA. |
| Stále se servíruje starý certifikát | Zapněte *Potom resetovat BMC*. |
| Aktualizace firmwaru vrátila starý certifikát | `sum … UpdateBmc --overwrite_ssl` ho přepíše - nasaďte znovu (vynuceně). |
