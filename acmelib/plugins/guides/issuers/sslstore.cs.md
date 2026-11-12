# The SSL Store (REST API) - nastavení pro acme

Zdroj **The SSL Store (REST API)** získává certifikáty přes REST API The SSL Store (TheSSLStore.com, prodejce Sectiga, DigiCertu a dalších značek): acme certifikát se svým CSR **znovu vydá** uvnitř již zakoupené objednávky (zdarma), nebo - jen když je zapnuté *Allow new orders (paid)* - vytvoří novou objednávku (nákup). Záznam nebo soubor **ověření domény (DCV)**, kterým objednávka odpoví (DNS CNAME, nebo HTTP soubor v `/.well-known/pki-validation/`), umístí validace certifikátu, nebo CA napíše schvalovateli e-mail; acme certifikát stáhne, jakmile je objednávka hotová. **Soukromý klíč nikdy neopustí acme.** Odvolání je součástí; *Import from a source* vypíše objednávky účtu. Každé volání nese **partner code** a **auth token**. Žádné IP adresy.

## Co potřebujete

- Partnerský (resellerský) účet The SSL Store s **přístupem k API**, jeho **partner code** a **auth token**.
- Prostředky na nové objednávky, nebo již zakoupené objednávky (jejich *TheSSLStoreOrderID*).
- Přístup HTTPS **z acme** na `api.thesslstore.com` (Evropa: `api.thesslstore.eu`; sandbox: `sandbox-wbapi.thesslstore.com`) port 443.
- Validaci v acme, která umí umístit důkaz DCV (DNS pro CNAME, HTTP pro soubor), nebo člověka pro e-mail.

## Nastavení The SSL Store

1. Přihlaste se do účtu The SSL Store → **API Settings**: poznamenejte si **partner code**, vytvořte pro acme **auth token**. Kde stránka nabízí seznam povolených IP, přidejte veřejnou IP acme.
2. Sandboxový účet má vlastní partner code a token a jen fiktivní produkty - použijte ho pro první test.
3. Poznamenejte si ID objednávek (`TSSL-...`), ve kterých bude acme znovu vydávat, nebo účet nabijte a rozhodněte, zda smí acme nakupovat.
4. Záznamy CAA, pokud jsou: povolte CA produktu (např. `sectigo.com`, `digicert.com`).

Ověření údajů:

```sh
curl -s https://api.thesslstore.com/rest/health/validate -H 'Content-Type: application/json' \
  -d '{"PartnerCode":"<code>","AuthToken":"<token>"}'
```

## Vyplnění v acme

Zdroje → **Přidat** → **The SSL Store (REST API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Partner code / Auth token | z kroku 1 |
| Environment | *Live*, *Live, Europe* nebo *Sandbox* |
| Order to reuse | `TSSL-9876543` - znovu vydá uvnitř; prázdné: objednávka, kterou acme vytvořilo naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Product of a new order | *Load the list* (`product/query`) nebo kód, např. `positivessl` |
| Validity of a new order (months) | `12` (jedna z dob produktu) |
| Server licences, Web server type (pokročilé) | `1`, `Other` |
| Domain validation (DCV) | *DNS CNAME record* (výchozí), *HTTP file* (bez wildcardů), nebo *E-mail* + *Approver mailbox* |
| Contact: first name / last name / phone (jen číslice) / e-mail / title | kontakt objednávky (povinný) |
| API address, čekání (pokročilé) | prázdné; `600` / `300` / `60` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `health/validate` - zkontroluje partner code a token.
- V portálu The SSL Store objednávka ukáže stav DCV a stav (*Active* po vydání).

## Časté problémy

| Problém | Řešení |
|---|---|
| `isError: true` - autentizace | špatný partner code / token, nebo sandboxové údaje na live (či naopak) |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Nedostatek prostředků | nabijte účet |
| DCV čeká | CNAME / soubor ještě nebyl vidět; The SSL Store obnovuje detaily objednávky každých 5 minut - zvyšte čekání |
| Wildcard s HTTP DCV odmítnut | použijte DNS (CNAME) |
| Telefon odmítnut | jen číslice (např. `420123456789`) |
