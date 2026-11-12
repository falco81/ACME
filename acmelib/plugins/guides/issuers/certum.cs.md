# Certum (partnerské API) - nastavení pro acme

Zdroj **Certum (partner API)** získává certifikáty od Certum (Asseco) přes jeho SOAP **partnerské API** (`gs.certum.pl/service/PartnerApi`): acme objedná se svým CSR - jen když je zapnuté *Allow new orders (paid)* - nebo **znovu vydá uvnitř již zakoupené objednávky** (zdarma, v rámci platnosti produktu), záznam nebo soubor **ověření domény (DCV)** umístí pomocí validace certifikátu (TXT nebo CNAME na `_certum.<doména>` nebo na samotné doméně, nebo soubor `/.well-known/pki-validation/certum.txt`) a certifikát vyzvedne. Odvolání je součástí; *Import from a source* vypíše objednávky účtu. **Soukromý klíč nikdy neopustí acme.** Pro ACME od Certumu (ACME produkt, kid + HMAC) použijte místo toho předvolbu *Certum* zdroje ACME. Žádné IP adresy.

## Co potřebujete

- **Partnerský účet** API Certumu (dohodnutý s Certumem), jeho **partnerský login** a heslo a **zákazníka**, pro kterého jsou certifikáty.
- Veřejnou **IP adresu** acme **zaregistrovanou** u partnerského účtu - API odpovídá jen registrovaným adresám.
- Produkty k objednání, nebo již zakoupené objednávky k novému vydání.
- Přístup HTTPS **z acme** na `gs.certum.pl` (test: `gs.test.certum.pl`) port 443.
- Validaci v acme, která umí umístit důkaz DCV (DNS pro TXT/CNAME, HTTP pro soubor).

## Nastavení Certumu

1. Dohodněte s Certumem přístup k API (partnerský / resellerský program): dostanete **partnerský login** (SSO účet) a heslo a podle potřeby přístup do testovacího prostředí.
2. Sdělte Certumu **veřejné IP adresy**, ze kterých acme odchází (adresu proxy, používá-li acme Nastavení → Proxy), aby je pro API zaregistroval.
3. Poznamenejte si **zákazníka** (jeho ID nebo login SimplySign), pro kterého se certifikáty objednávají.
4. Kupte objednávky, ve kterých bude acme znovu vydávat (poznamenejte si ID objednávky), nebo rozhodněte, zda smí acme kupovat nové.
5. Pro produkty OV/EV: v acme jsou potřeba údaje žadatele a DIČ organizace.
6. Záznamy CAA, pokud jsou: `0 issue "certum.pl"`.

## Vyplnění v acme

Zdroje → **Přidat** → **Certum (partner API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Certum | *Production (gs.certum.pl)* nebo *Test* |
| Partner login / Password | z kroku 1 |
| Customer | ID zákazníka nebo login SimplySign - ne partnerský login |
| Product of a new order | *Load the list* (getProductList), nebo kód produktu |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Order to reuse | ID objednávky Certumu; prázdné: objednávka, kterou acme vytvořilo naposledy |
| Domain validation (DCV) | TXT na `_certum.DOMAIN` (výchozí), TXT na doméně, CNAME na `_certum.DOMAIN` nebo na doméně, nebo HTTP soubor (bez wildcardů) |
| Requestor (OV/EV), Tax identification number (OV/EV) (pokročilé) | řádky `email=`, `firstName=`, `lastName=`, `phone=`; DIČ |
| Language, Orders listed (days back), API address, čekání (pokročilé) | `en`, `825`, prázdné, `600` / `300` / `20` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte produkty - nic neobjednává.
- V partnerském panelu Certumu objednávka ukáže stav DCV a certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| API neodpovídá / přístup odepřen | veřejná IP acme není u partnerského účtu zaregistrovaná |
| Chyba autentizace | špatný partnerský login nebo heslo, nebo testovací vs produkční prostředí |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Zákazník nenalezen | *Customer* musí být ID zákazníka nebo login SimplySign |
| DCV neověřeno | záznam ještě nebyl vidět - zvyšte čekání; zkontrolujte `_certum.<doména>` ve veřejném DNS |
| Wildcard s HTTP souborem odmítnut | pro wildcardy použijte DNS DCV |
| Objednávka OV/EV odmítnuta | vyplňte *Requestor* a *Tax identification number* |
