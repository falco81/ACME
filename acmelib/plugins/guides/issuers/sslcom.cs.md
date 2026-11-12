# SSL.com (SWS API) - nastavení pro acme

Zdroj **SSL.com (SWS API)** získává certifikáty od SSL.com přes jeho API SSL Web Services (SWS) (`sws.sslpki.com`): acme certifikát se svým CSR **překlíčuje** (rekey) uvnitř již zakoupené objednávky nebo voucheru (`PUT /certificate/{ref}`), nebo - jen když je zapnuté *Allow new orders (paid)* - objedná nový (`POST /certificates`, nákup). Soubor **ověření domény (DCV)**, kterým SSL.com odpoví, umístí HTTP validace certifikátu (`/.well-known/pki-validation/`), nebo SSL.com napíše schvalovateli e-mail; acme čte objednávku, dokud není certifikát vydán. **Soukromý klíč nikdy neopustí acme.** Odvolání podle sériového čísla je součástí; *Import from a source* vypíše objednávky účtu. Metoda DCV přes DNS se nenabízí (její hodnota není zdokumentována). Pro SSL.com přes ACME (EAB) použijte předvolby *SSL.com* zdroje ACME. Žádné IP adresy.

## Co potřebujete

- Účet SSL.com s **API údaji** (account key + secret key) a prostředky nebo již zakoupenými objednávkami/vouchery.
- Přístup HTTPS **z acme** na `sws.sslpki.com` (sandbox: `sws-test.sslpki.com`, samostatný účet) port 443.
- Pro HTTP DCV: HTTP validaci v acme, která umí umístit soubor na `http://<jméno>/.well-known/pki-validation/` (port 80 z internetu; bez wildcardů). Pro DCV e-mailem: člověka, který čte schvalovací schránku.

## Nastavení SSL.com

1. Přihlaste se do dashboardu SSL.com → **API credentials** (vývojářská / API stránka účtu): zkopírujte **account_key** a **secret_key** (podle potřeby je vygenerujte znovu). Na stejné stránce jsou údaje pro ACME - zde nejsou potřeba.
2. Kupte certifikáty, které bude acme překlíčovávat, a poznamenejte si **referenci objednávky** každého (např. `co-ac1ecm200`), nebo účet nabijte a rozhodněte, zda smí acme nakupovat.
3. Pro sandbox si založte účet na `sandbox.ssl.com` - má vlastní klíče.
4. Záznamy CAA, pokud jsou: `0 issue "ssl.com"`.

Ověření údajů:

```sh
curl -s "https://sws.sslpki.com/certificates?account_key=$AK&secret_key=$SK&per_page=1"
```

## Vyplnění v acme

Zdroje → **Přidat** → **SSL.com (SWS API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Account key / Secret key | z kroku 1 |
| Environment | *Production* nebo *Sandbox* |
| Order to reuse | reference objednávky (nebo voucheru) - překlíčuje se s žádostí acme; prázdné: ta, kterou acme vytvořilo naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Product of a new order | *Load the list* nebo kód (např. `106` Basic; více jmen berou jen 100, 102 a 107) |
| Period of a new order (days) | `365` (až `1826`; 30/90 pro Free SSL) |
| Server software (code) (pokročilé) | `1` (OTHER) |
| Domain validation (DCV) | *HTTP file* (výchozí) nebo *E-mail* + *Approver mailbox* |
| Contact: first name / last name / e-mail / phone / country | kontakt objednávky (povinný) |
| API address, čekání (pokročilé) | prázdné; `600` / `300` / `30` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte objednávky - nic nekupuje.
- V dashboardu objednávka ukáže stav ověření a vydaný certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / neplatné údaje | špatný account_key / secret_key, nebo produkční klíče na sandboxu (či naopak) |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Certifikát s více jmény odmítnut | produkt bere jedno jméno - zvolte 100, 102 nebo 107 |
| Soubor DCV nenalezen | port 80 jména není dosažitelný z internetu, nebo přesměrovává jinam - zkontrolujte `/.well-known/pki-validation/` |
| Wildcard odmítnut | HTTP DCV wildcardy ověřit neumí - použijte e-mail, nebo zdroj ACME |
| Čeká na ověření | DCV e-mailem: někdo musí schválit; OV/EV: prověrka u SSL.com |
