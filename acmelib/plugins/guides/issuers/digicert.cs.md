# DigiCert CertCentral (API) - nastavení pro acme

Zdroj **DigiCert CertCentral (API)** získává komerční certifikáty **DigiCert, GeoTrust, Thawte a RapidSSL** přes CertCentral Services API v2 (hlavička `X-DC-DEVKEY`). acme certifikát se svým CSR **znovu vydá** (reissue) uvnitř již zaplacené objednávky (`/order/certificate/{order}/reissue` - zdarma), nebo - jen když je zapnuté *Allow new orders (paid)* - vytvoří novou objednávku (`/order/certificate/{product}`, nákup; když objednávka končí, renewal objednávku). Ověření domény (DCV): acme získá náhodnou hodnotu DigiCertu, **TXT/CNAME záznam nebo soubor** umístí pomocí validace certifikátu, požádá DigiCert o okamžitou kontrolu (`check-dcv`) a po vydání ho odstraní; nebo DigiCert pošle schvalovací e-mail. **Soukromý klíč nikdy neopustí acme.** *Import from a source* vypíše objednávky. Kde stačí čisté DV nebo OV již ověřené organizace, je zdroj ACME s předvolbou *DigiCert (EAB)* plně automatický a jednodušší; tento zdroj je pro OV/EV objednávky zvolené organizace, víceleté plány, produkt zvolený podle jména a DCV e-mailem. Žádné IP adresy.

## Co potřebujete

- Účet CertCentral (US nebo Europe) se zůstatkem nebo platební metodou a uživatele, jehož role smí žádat o certifikáty a znovu je vydávat.
- **API klíč** tohoto uživatele.
- Pro OV/EV: **organizaci** ověřenou v CertCentral (její ID).
- Objednávku k opakovanému použití (víceletý plán), nebo svolení, aby acme nakupovalo.
- Validaci v acme, která umí umístit důkaz DCV (DNS poskytovatel pro TXT/CNAME, HTTP pro soubor) - nebo člověka pro DCV e-mailem.
- Přístup HTTPS **z acme** na `www.digicert.com` (nebo `certcentral.digicert.eu`) port 443, přímo nebo přes Nastavení → Proxy.

## Nastavení CertCentral

1. Uživatel pro acme (nebo váš vlastní): **Account → Users** - role, která smí objednávat a znovu vydávat (např. *Manager* nebo *Administrator*; ověřte, co role ve vašem účtu dovolují).
2. **Automation → API Keys → Add API Key**: jméno `acme`, uživatel a v *API key restrictions* omezení, které stále dovolí objednávat a znovu vydávat (např. *Orders, Domains, Organizations* - ne *View Only*). Zkopírujte klíč (zobrazí se jednou).
3. OV/EV: **Certificates → Organizations** - ověřená organizace (OV/EV); její **ID** patří do acme (nebo použijte v acme akci *List the organizations*).
4. Domény: předběžné ověření v **Certificates → Domains** dovolí acme přeskočit DCV, dokud platí (*Skip domains validated already*).
5. Záznamy CAA, pokud jsou: `0 issue "digicert.com"`.

Ověření klíče:

```sh
curl -s -H "X-DC-DEVKEY: $DIGICERT_KEY" https://www.digicert.com/services/v2/user/me
```

## Vyplnění v acme

Zdroje → **Přidat** → **DigiCert CertCentral (API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| CertCentral | *CertCentral* (US), *CertCentral Europe*, nebo *Another address* + API address |
| API key | z kroku 2 |
| Order to reuse | již zakoupená objednávka (např. `12345678`) - znovu vydá uvnitř, zdarma; prázdné: objednávka, kterou acme vytvořilo naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Product of a new order / Product name_id | např. *DigiCert Basic OV* (`ssl_basic`); *List the products* ukáže, co smí účet objednat |
| Organization ID | pro OV/EV (*List the organizations*) |
| Order validity (years) | 1-3 (víceletý plán, uvnitř se znovu vydává, jak každý certifikát končí) |
| Payment of a new order (pokročilé) | *Account balance*, *Credit card on file*, nebo jak nastavuje účet |
| Domain validation (DCV) | *DNS TXT record* (výchozí), *DNS CNAME record*, *HTTP file* (bez wildcardů), *E-mail* |
| Label of the DNS TXT record / Shape of the DNS CNAME record / DCV for (pokročilé) | `_dnsauth`; `_dnsauth.DOMAIN → RANDOM.dcv.digicert.com`; každé jméno nebo registrovaná doména |
| Skip domains validated already (pokročilé) | zapnuto |
| Čekání, Ask again every (pokročilé), Path: ... (pokročilé) | `600` / `300` / `15`; cesty API není třeba měnit |
| Allow a second (paid) order for a dual certificate (pokročilé) | vypnuto, pokud nechcete dvojice ECDSA + RSA, každou placenou |

## Ověření

- Zdroje → zdroj → **Test** (Try it), pak akce **List the products**, **List the organizations**, **List the validated domains** - vše jen čte.
- V CertCentral: **Certificates → Orders** ukáže nové vydání a stav jeho DCV.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `invalid_api_key` | špatný klíč, nebo špatný CertCentral (US vs Europe) |
| `403` / přístup odepřen | omezení klíče nebo role uživatele nedovoluje objednávat / znovu vydávat |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Objednávka OV/EV odmítnuta | nastavte *Organization ID* ověřené organizace |
| DCV čeká | záznam ještě nebyl vidět (acme požádá DigiCert o novou kontrolu); u e-mailu musí někdo schválit |
| Wildcard s HTTP souborem odmítnut | pro wildcardy použijte DNS DCV |
| Produkt nebere wildcard | úloha to odmítne před objednáním - zvolte produkt, který ho bere |
