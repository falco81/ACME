# Barracuda Web Application Firewall - nastavení pro acme

acme se přihlásí do **REST API** WAF (`POST /restapi/<v>/login` vrátí token), a protože
obsah certifikátu nelze měnit na místě, **nahraje certifikát pod novým jménem s datem**
(`acme-<jméno>-<datum>-<sériové číslo>`, soukromý klíč neexportovatelný). U každé služby
načte **SSL security** a zapíše ji zpět s `certificate` (nebo `ecdsa-certificate`)
nastaveným na nové jméno; starší jméno acme mezi SNI certifikáty domén se také nahradí.
Starší certifikáty acme nad počet *ponechat* smaže, pokud je žádná služba nepoužívá. Na
konci se odhlásí.

Pro Barracuda WAF v hardwarové, virtuální i cloudové edici s REST API v3 / v3.1 / v3.2
(firmware 9.x a novější; v3.2 ověřeno proti firmwaru 11.0, v3.1 proti 12.2).

## Co potřebujete

- Správcovskou adresu WAF, port REST API **8443** (HTTPS) dostupný z acme.
- Služby (webové aplikace) už nastavené s HTTPS; jejich jména.
- Správcovský účet, který smí používat API.

## Nastavení Barracuda WAF

1. Ověřte, že je povolena správa přes HTTPS: **BASIC → Administration** (*Web Interface
   HTTPS/SSL Configuration*) - REST API běží na portu 8443.
2. Je-li přístup ke správě omezen (**BASIC → Administration → Administrator IP/Range**),
   přidejte IP adresu serveru acme.
3. Vytvořte pro acme samostatného správce: **ADVANCED → Admin Access Control** (správa
   podle rolí). Jeho role potřebuje zápis do **Certificates** (BASIC → Certificates) a do
   **Services** (BASIC → Services, nastavení SSL služeb, které má měnit). Přesné názvy
   objektů rolí se liší podle firmwaru - ověřte je; vestavěný `admin` funguje, ale má
   víc práv, než je třeba.
4. Poznamenejte si jména služeb (**BASIC → Services**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Správcovská IP nebo jméno, např. `waf.example.local` |
| HTTPS port | `8443` |
| User | Správce z kroku 3 (výchozí `admin`) |
| Password | Jeho heslo |
| API version (pokročilé) | `v3.2` (výchozí), `v3.1` nebo `v3` - podle firmwaru |
| Check the device's certificate | Zapnuto; vypnout jen dokud má WAF self-signed certifikát |
| CA certificate (pokročilé) | CA správcovského certifikátu WAF, pokud není veřejná |
| Service (nasazení) | Služba vybraná ze seznamu (*Load the list*) nebo napsaná |
| More services (nasazení) | Jedna na řádek, např. `www-https` |
| As (nasazení) | `the certificate of the service`, `the ECDSA certificate of the service` nebo `an SNI domain certificate only` |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | VIP služby, např. `www.example.com:443` |

Akce **List the services** vypíše služby a certifikáty, které jejich SSL security
používá - nic nemění.

## Ověření

- **Try**: `signed in to the WAF ... (API v3.2); N services, M certificates`.
- Na WAF: **BASIC → Certificates** obsahuje `acme-...`; **Edit → SSL** služby ho ukazuje
  jako její certifikát.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 při přihlášení | Chybný uživatel nebo heslo, nebo účet nesmí používat API |
| Spojení na 8443 odmítnuto | Správa HTTPS / REST API nedostupná - ověřte port a rozsah IP správců |
| 404 na `certificates/signed-certificate` | Starší firmware: nastavte *API version* na `v3` |
| Služba nenalezena | Chybné jméno - použijte *List the services* |
| Nahrání odmítnuto (typ klíče) | EC certifikát patří do *the ECDSA certificate of the service* |
| Starší certifikát se nesmazal | Ještě ho používá služba; smaže se při dalším běhu |
