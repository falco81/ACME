# GlobalSign MSSL (GCC API) - nastavení pro acme

Zdroj **GlobalSign MSSL (GCC API)** získává certifikáty účtu GlobalSign **Managed SSL** v GlobalSign Certificate Center (GCC) přes jeho SOAP API. MSSL ověřuje **domény**, ne certifikáty: jména musí patřit do domény schválené v **MSSL profilu** účtu - acme ji tam najde (`GetDomains`), nebo s metodou DNS doménu samo přidá a ověří (`AddDomainToProfile`, TXT záznam umístěný validací certifikátu, `VerifyMsslDomain`). CSR se pak **znovu vydá uvnitř již zakoupené objednávky** (`ReIssue`, zdarma), nebo - jen když je zapnuté *Allow new orders (paid)* - objedná (`PVOrder` - nákup). acme čte objednávku, dokud není vydána; odvolání je `RevokeMSSLOrder`; *Import from a source* vypíše objednávky účtu. **Soukromý klíč nikdy neopustí acme.** Žádné IP adresy. Pro GlobalSign Atlas použijte zdroj `globalsign_atlas`.

## Co potřebujete

- Účet GCC s **MSSL** a přístupem k API zapnutým GlobalSignem, a **API uživatele** s heslem.
- **MSSL profil** s prověřenou organizací a schválenými doménami (nebo DNS validaci v acme, která umí zapisovat TXT záznamy do zóny domény).
- Objednávku k opakovanému použití (nebo peníze / kredit na nové objednávky, pokud je povolíte).
- Přístup HTTPS **z acme** na `system.globalsign.com:443` (test: `test-gcc.globalsign.com`), přímo nebo přes Nastavení → Proxy.

## Nastavení GCC

1. Požádejte GlobalSign (svého account managera nebo podporu) o **zapnutí přístupu k API** pro MSSL účet. Nastaví **API uživatele** - uživatelské jméno pro API, oddělené od přihlášení do portálu - a mohou ho omezit na veřejnou IP adresu acme. Testovací účet na `test-gcc.globalsign.com` je k dispozici na vyžádání.
2. V GCC **MSSL → Manage Domains & Profiles**: poznamenejte si **ID MSSL profilu** (např. `01_SSL_1234`) a ověřte, že domény vašich certifikátů jsou **schválené** (schválená doména pokrývá svá jména 199 dní, pak se prověřuje znovu).
3. Pro dosud neschválené domény je buď schvalte v GCC (přidat doménu → ověření DNS / e-mailem / HTTP), nebo je nechte přidat acme přes DNS: dejte certifikátům validaci DNS-01, která umí zapisovat do zóny domény.
4. Poznamenejte si číslo existující **objednávky**, jejíž certifikát smí acme znovu vydat (např. `CE20261103123456`), nebo rozhodněte, zda smí acme kupovat nové objednávky.

## Vyplnění v acme

Zdroje → **Přidat** → **GlobalSign MSSL (GCC API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| API user / Password | z kroku 1 |
| Environment | *Production* nebo *Test* |
| MSSL profile | *Load the list* (GetMSSLProfiles), nebo napište ID |
| Domain validation (DCV) | *approved in the profile already*, nebo *DNS TXT record* (acme doménu přidá a ověří) |
| Domain to add | s DNS: např. `example.com`; prázdné: každé jméno bez `*.` a `www.` |
| Order to reuse | již zakoupená objednávka - znovu vydaná s žádostí acme; prázdné: ta, kterou acme vytvořilo naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí kupovat - jinak se zastaví se slovy, že by byl potřeba nákup |
| Product of a new order / Validity of a new order | např. `PV_SHA2`, `6 months` - jen pro nové objednávky |
| Contact: first name / last name / phone / e-mail | kontakt objednávky (API ho vyžaduje) |
| Orders listed (days back), Wait for the certificate, Wait for the DCV record, Ask again every (pokročilé) | `400`, `300`, `300`, `20` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte profily - nic neobjednává.
- V GCC: **MSSL → Order history** ukáže znovu vydanou objednávku a její stav.

## Časté problémy

| Problém | Řešení |
|---|---|
| `-1` s chybou autentizace | špatný API uživatel/heslo, přístup k API není zapnutý, nebo IP acme není povolená |
| Doména jména není schválená | schvalte ji v profilu, nebo přepněte DCV na *DNS TXT record* s DNS validací |
| *a purchase would be needed* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| Ověření domény selže | TXT záznam nebyl včas vidět ve veřejném DNS - zvyšte čekání na DCV |
| IP adresa odmítnuta | MSSL zde pro IP adresy nevydává |
| Objednávka zůstává ve stavu 2 (kontrola phishingu) | GlobalSign ji prověřuje; acme se zeptá znovu při dalším pokusu |
