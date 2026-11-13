# HPE Aruba Networking ClearPass Policy Manager - nastavení pro acme

acme vymění **serverové certifikáty jednoho serveru ClearPass** - HTTPS(RSA), HTTPS(ECC), RADIUS (EAP), RadSec - přes REST API ClearPassu. ClearPass přijme serverový certifikát jen **z URL, ze které si ho stáhne** (`pkcs12_file_url`), proto acme potřebuje váš **přestupní webový server**: zapíše na něj PKCS#12 přes SSH pod náhodným jménem, nechá ClearPass soubor stáhnout a hned ho zase smaže.

```text
POST /api/oauth                       {"grant_type": "client_credentials", "client_id", "client_secret"}
GET  /api/cluster/server              UUID serveru uvedeného v acme
POST /api/cert-trust-list             {"cert_file": <CA z řetězce, PEM>, "enabled": true, "cert_usage": [...]}
(ssh) <adresář>/acme-<náhodné>.p12    na přestupním webovém serveru
PUT  /api/server-cert/name/<server_uuid>/<HTTPS(RSA)|HTTPS(ECC)|RADIUS|RadSec>
     {"pkcs12_file_url": "<jeho URL>/acme-<náhodné>.p12", "pkcs12_passphrase": "<jednorázové>"}
(ssh) rm -f <adresář>/acme-<náhodné>.p12
```

## Pro který ClearPass

**ClearPass 6.12 - 6.14** (reference API 6.14.1, SDK Aruby `pyclearpass`). Modul má jedinou verzi.

## Co se v ClearPassu stane

| Služba | Dopad změny |
|---|---|
| HTTPS(RSA) / HTTPS(ECC) | webový server daného serveru se restartuje: administrace, portály Guest/Onboard a API jsou na okamžik nedostupné. HTTPS(ECC) potřebuje certifikát ECDSA. |
| RADIUS | služba RADIUS se restartuje: ověřování se na okamžik zastaví (NAD přejdou na jiný RADIUS server). **Supplicanty musí věřit nové CA a jménu** - jinak PEAP/EAP-TLS selže; novou CA nejdřív rozdistribuujte klientům (GPO/MDM). |
| RadSec | klienti RadSec (AP, gatewaye) se připojí znovu s novým certifikátem |

Řetězec musí být v **Certificate Trust List** dřív, než se certifikát importuje - acme tam každou CA řetězce nejdřív přidá (již přítomnou ClearPass odmítne a zůstane). Certifikáty jsou **pro každý server zvlášť**: jeden cíl na server clusteru (nejdřív subscribery, publisher nakonec); pro RADIUS dejte všem serverům stejný certifikát, aby klienti při roamingu mezi nimi nepoznali rozdíl.

## Nastavení ClearPassu

1. **Profil operátora s přístupem k API**: *Administration → Operator Logins → Profiles* - zkopírujte některý, ponechte **API Services: Allow API Access** a v Policy Manager / Platform jen **Certificates** (čtení, zápis) a **Server Configuration** (čtení) - *nejisté*: přesné názvy těchto práv; vestavěný *Super Administrator* funguje, ale není to nejmenší oprávnění.
2. **Klient API**: *Administration → API Services → API Clients → Create API Client* (v modulu Guest) - *Client ID* `acme`, *Operating Mode* ClearPass REST API, *Operator Profile* z kroku 1, *Grant Type* **Client credentials**, platnost tokenu např. 8 hodin. Tajný klíč klienta si zkopírujte (zobrazí se jen jednou).
3. **Přestupní webový server**: libovolný server HTTPS (nebo HTTP), na který ClearPass dosáhne, s adresářem, který servíruje a do kterého acme smí zapisovat přes SSH, např.:

```sh
sudo useradd -m acme
sudo install -d -o acme -g www-data -m 0755 /var/www/cppm-drop
# pak veřejný klíč SSH z karty klíče u cíle vložte do ~acme/.ssh/authorized_keys
```

   K adresáři pusťte jen adresy ClearPassu (`allow` / `deny` webového serveru); u HTTPS musí ClearPass jeho certifikátu věřit. Soubor tam leží pár sekund, pod náhodným jménem o 32 znacích, chráněný jednorázovým heslem.

4. Token si vyzkoušejte ze stroje acme:

```sh
curl -s -X POST https://cppm.example.com/api/oauth -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"acme","client_secret":"<tajny-klic>"}'
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | publisher (nebo přímo server), např. `cppm.example.com` / `443` |
| ID klienta API / Tajný klíč klienta | z kroku 2 |
| Server | server, jehož certifikáty to jsou: jméno, FQDN, IP adresa nebo UUID serveru (*Administration → Server Manager → Server Configuration*) |
| Přestupní webový server, SSH port, Uživatel SSH, Přihlásit se přes, SSH klíč / Heslo SSH | server z kroku 3 a jak se na něj acme přihlásí |
| Adresář / Jeho URL | např. `/var/www/cppm-drop` a `https://files.example.com/cppm-drop` |
| Použít pro (nasazení) | po řádcích: `HTTPS(RSA)`, `HTTPS(ECC)`, `RADIUS`, `RadSec` |
| Přidat CA do trust listu / Použití v trust listu (rozšířené) | zapnuto; `EAP` a `Others` (nebo podle toho, k čemu CA používáte) |

## Ověření

```sh
openssl s_client -connect cppm01.example.com:443 -servername cppm01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect cppm01.example.com:2083 -showcerts </dev/null | openssl x509 -noout -subject -dates
curl -s -H "Authorization: Bearer $TOKEN" https://cppm.example.com/api/server-cert/name/<server_uuid>/RADIUS
```

V GUI: *Administration → Certificates → Certificate Store*. RADIUS: zkušební ověření v *Monitoring → Live Monitoring → Access Tracker*.

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| `401` / `invalid_client` při přihlášení | špatné ID nebo tajný klíč klienta, špatný grant type | krok 2 |
| `403` | profil operátora nemá přístup k API nebo právo na certifikáty | krok 1 |
| *ClearPass has no server ...* | jméno není mezi servery z `/api/cluster/server` | jméno, FQDN, IP nebo UUID, které vypíše |
| `422` / chyba řetězce při výměně | řetězec CA není důvěryhodný nebo klíč nesedí | trust list (*Administration → Certificates → Trust List*), použití |
| ClearPass soubor nestáhne | nedosáhne na přestupní URL nebo nevěří jejímu certifikátu | URL ze sítě ClearPassu; jeho CA do trust listu |
| *the staged file ... stays* | acme ho nemohl smazat | hned ho smažte ručně |

*Nejisté*: zda `cert_file` v trust listu je přímo PEM (reference říká jen „Certificate trust list file“); restarty po importu nebyly v dokumentech, které průvodce mohl číst.

Zdroje: reference API ClearPass Policy Manager 6.14.1 (`PUT /server-cert/name/{server_uuid}/{service_name}`, `POST /cert-trust-list`, `POST /oauth`), vývojářská dokumentace (konfigurace ClearPassu, OAuth2), `pyclearpass` od Aruby (`api_platformcertificates.py`, `common.py`).
