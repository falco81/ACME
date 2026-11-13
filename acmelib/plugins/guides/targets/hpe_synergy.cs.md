# HPE Synergy Composer / OneView - klíč vytváří zařízení - nastavení pro acme

Tento cíl je pro certifikáty, jejichž **klíč zůstává na zařízení**: acme si při každém vydání
a obnově vyžádá od HPE OneView (na Synergy Composeru nebo ve VM OneView) **nový klíč a CSR**,
nechá CSR podepsat zdrojem certifikátu a podepsaný certifikát hned vrátí zpět. acme žádný klíč
nedrží. Jeden cíl (přihlášení do OneView) obslouží dva druhy certifikátů - každé nasazení
říká který:

- **appliance** - HTTPS certifikát samotného Composeru / OneView (GUI, REST API a HPE SSO
  certifikát, který OneView předává spravovaným iLO a rámům).
  `POST /rest/certificates/https/certificaterequest`, potom `PUT` podepsaného certifikátu.
  Appliance vytváří **RSA 2048**, pro CNSA **RSA 3072** (typ klíče `rsa-3072`).
- **modul správy enclosure** - pozice **Frame Link Module** rámu Synergy nebo **Onboard
  Administrator** c7000; ty žádný klíč nepřijmou, jen certifikát ke svému CSR:
  `POST /rest/enclosures/{id}/https/certificaterequest?bayNumber=N`, potom `PUT`.
  **Jen jedno jméno** (common name - CSR enclosure v OneView jiná jména nenese).

Verze: HPE OneView for Synergy a OneView **9.x - 11.x** (REST API 6600 - 9200); acme posílá
verzi API, kterou appliance uvede. Chcete-li na appliance dát klíč z acme, použijte cíl
**HPE OneView / Synergy Composer**.

## Co je potřeba

- Z acme na adresu appliance Composeru (ne vlastní IP modulu Composer): **TCP 443**.
- Účet OneView s rolí **Infrastructure administrator** (bez scope) - certifikát appliance
  i certifikáty enclosure jsou nastavení appliance.
- Zdroj, který podepisuje CSR vytvořený jinde - ACME CA (validace DNS-01), vlastní autorita
  acme, komerční CA. Ne *Self-signed*, CMP ani SCEP.

## Nastavení OneView

1. Servisní účet (jako administrátor, `$OVAUTH` je relace z `POST /rest/login-sessions`):

   ```sh
   curl -k -X POST "https://composer.example.local/rest/users" \
     -H "X-API-Version: 9200" -H "Auth: $OVAUTH" -H "Content-Type: application/json" \
     -d '{"type":"UserAndPermissions","userName":"svc-acme","password":"<heslo>","enabled":true,
          "permissions":[{"roleName":"Infrastructure administrator"}]}'
   ```

   Nebo v GUI: **Settings → Users and Groups → Add**, role *Infrastructure administrator*.
   Funguje i adresářový (LDAP / AD) účet s touto rolí - v acme uveďte jeho přihlašovací doménu.
2. Nic se nezapíná: REST API běží vždy na 443.
3. Jména appliance: její FQDN (a IP, pokud se na ni uživatelé připojují přes IP) - všechna
   jdou do alternativních jmen CSR. U rámu: DNS jméno, přes které je pozice Frame Link Module
   dostupná.

## Vyplnění v acme

Cíl (**Cíle → Přidat → HPE Synergy Composer / OneView - klíč vytváří zařízení**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | FQDN appliance, např. `composer.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-acme` z kroku 1 |
| Přihlašovací doména | `LOCAL`, nebo přihlašovací doména adresáře |
| Země (C), Kraj (ST), Město (L), Organizace (O) | Co nese každý CSR (OneView je vyžaduje); přednost má vlastní subjekt certifikátu (jeho profil) |
| Útvar (OU), E-mail v CSR | Nepovinné |
| Ověřovat certifikát zařízení | Vypnuto, dokud má appliance self-signed certifikát |

Potom každý certifikát: **Přidat certifikát → Klíč → Klíč vytváří zařízení → vyberte tento
cíl**. acme samo vytvoří nasazení na cíl; nastavte jeho volby:

| Volba | Appliance | Enclosure |
|---|---|---|
| Certifikát pro | *appliance* | *modul správy enclosure* |
| Enclosure | - | její název v OneView (`Frame1`) nebo `/rest/enclosures/<id>` |
| Pozice | - | `1` nebo `2` (pozice Frame Link Module / OA) |
| Vložit mezilehlé certifikáty do trust storu | zapnuto (HPE chce vydávající CA v trust storu předem) | - |
| Zkontrolovat, co se servíruje | - | `flm1.example.local:443` - adresu modulu acme nezná |

Z příkazové řádky:

```sh
acme --cert-add composer --names composer.example.local,10.0.0.20 --key-type rsa-2048 --issuer "Own CA" --csr-from synergy
acme --renew composer
```

## Ověření

- **Test** u cíle se přihlásí, přečte certifikát appliance a vypíše enclosure - nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže *klíč a CSR vytváří zařízení*, vydání a potom
  úlohu importu. Appliance znovu načte webové služby (relace se odpojí, servery ani datová
  cesta se nemění):

  ```sh
  openssl s_client -connect composer.example.local:443 -servername composer.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -k -s "https://composer.example.local/rest/certificates/https" -H "X-API-Version: 9200" -H "Auth: $OVAUTH"
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel, heslo nebo přihlašovací doména. |
| `403` u CSR nebo importu | Účet není *Infrastructure administrator* (nebo má scope). |
| `OneView chce v každém CSR ...` | Vyplňte u cíle Zemi, Kraj, Město a Organizaci. |
| `CSR enclosure má jedno jméno` | Dejte certifikátu rámu jedno DNS jméno. |
| `OneView nemá žádnou enclosure s názvem ...` | Použijte název ze stránky **Enclosures** nebo URI enclosure. |
| Úloha importu skončí `invalid certificate` | Vydávající CA není v trust storu (nechte *Vložit mezilehlé certifikáty do trust storu* zapnuté), nebo mezitím vznikl jiný CSR (ručně v GUI) - **Obnovit teď** vytvoří nový. |
| Jen RSA | Appliance vytváří jen klíče RSA: typ klíče `rsa-2048` (`rsa-3072` pro CNSA). |
| Nasazení pozdržena | Zařízení si nechá starý certifikát; další vydání si vyžádá nový klíč a CSR. |

Volání pro enclosure dokumentuje SDK HPE pro Onboard Administrator; na Frame Link Module rámu
Synergy jde o stejné volání OneView (acme ho na rámu nezkoušelo) - vyzkoušejte ho nejdřív na
jedné pozici.
