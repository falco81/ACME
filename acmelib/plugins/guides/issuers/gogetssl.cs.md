# GoGetSSL (resellerské API) - nastavení pro acme

Zdroj **GoGetSSL (reseller API)** získává certifikáty zakoupené přes resellerské API GoGetSSL: acme **znovu vydá uvnitř již zakoupené objednávky** (zdarma), nebo - jen když je zapnuté *Allow new orders (paid)* - vytvoří novou objednávku (nákup) se svým CSR, záznam nebo soubor **ověření domény (DCV)** umístí pomocí validace certifikátu (DNS CNAME nebo HTTP soubor v `/.well-known/pki-validation/`), nebo nechá CA napsat schvalovateli e-mail, a pak certifikát stáhne. **Soukromý klíč nikdy neopustí acme.** API **nemá odvolání**: akce *Cancel the order to reuse* požádá GoGetSSL o zrušení (a vrácení peněz) objednávky, které GoGetSSL posoudí za 2-48 hodin. *Import from a source* vypíše objednávky účtu. Žádné IP adresy. (Vlastní ACME adresář GoGetSSL se nepodařilo potvrdit.)

## Co potřebujete

- Resellerský účet GoGetSSL s **přístupem k API**, jeho **login** do klientské zóny a **API heslo**.
- Zůstatek na účtu pro nové objednávky, nebo již zakoupené objednávky k novému vydání.
- Přístup HTTPS **z acme** na `my.gogetssl.com` port 443.
- Validaci v acme, která umí umístit důkaz DCV (DNS pro CNAME, HTTP pro soubor), nebo člověka pro e-mail.

## Nastavení GoGetSSL

1. Přihlaste se do klientské zóny GoGetSSL → **Reseller Modules → API settings**: zapněte přístup k API a nastavte **API heslo** (oddělené od hesla účtu). Kde to stránka nabízí, přidejte veřejnou IP acme mezi povolené adresy API.
2. Poznamenejte si **ID objednávky** certifikátu, který smí acme znovu vydávat (např. `1332864`), nebo dobijte zůstatek a rozhodněte, zda smí acme nakupovat.
3. Pro produkty OV/EV připravte údaje organizace, které produkt potřebuje (`org_name`, `org_division`, `org_addressline1`, ... jak je API GoGetSSL žádá) - patří do *More fields of a new order*.
4. Záznamy CAA, pokud jsou: povolte CA kupovaného produktu (např. `sectigo.com`, `digicert.com`).

## Vyplnění v acme

Zdroje → **Přidat** → **GoGetSSL (reseller API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| User | login do klientské zóny |
| API password | z kroku 1 |
| Order to reuse | již zakoupená objednávka; prázdné: objednávka, kterou acme vytvořilo naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Product of a new order | *Load the list* (`/products/ssl`) nebo ID produktu |
| Period of a new order (months) | `12` (až 60) |
| Server licences (pokročilé) | `1` (`-1` neomezeně) |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (bez wildcardů), nebo *E-mail* + *Approver mailbox* |
| Contact: first name / last name / phone / title / e-mail | kontakt objednávky (povinný) |
| More fields of a new order (pokročilé) | řádky `name=value`, např. `org_name=Example s.r.o.` |
| API address, čekání (pokročilé) | výchozí; `600` / `300` / `20` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte účet - nic neobjednává.
- V klientské zóně: **Orders** ukáže objednávku, stav DCV a certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba autentizace | špatný login nebo API heslo (ne heslo účtu), nebo není zapnutý přístup k API / IP acme není povolená |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Nedostatečný zůstatek | dobijte účet |
| DCV čeká | CNAME / soubor ještě nebyl vidět - zvyšte čekání; u e-mailu musí někdo schválit |
| Wildcard s HTTP DCV odmítnut | použijte DNS DCV |
| Objednávka OV/EV odmítnuta kvůli chybějícím polím | doplňte je do *More fields of a new order* |
| Certifikát je třeba odvolat | v API není: *Cancel the order to reuse*, nebo podpora GoGetSSL |
