# SSLS.cz - nastavení pro acme

Zdroj **SSLS.cz (AlpiroSSL, Sectigo, Certum…)** získává komerční certifikáty (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, DigiCert, Thawte, RapidSSL) od SSLS.cz - českého obchodu s certifikáty společnosti ZONER a.s. - přes jeho API *SAPI v2* (`https://api.ssls.cz/v2/{method}/`, POST formuláře s **tokenem**). acme certifikát **znovu vydá** uvnitř jeho předplatného se svým CSR (`quickReissue` - zdarma), dokud běží, nebo - jen když je zapnuté *Allow new orders (paid)* - **koupí** novou objednávku či obnovení (`newOrder`). Záznam nebo soubor **DCV**, který CA chce (CNAME pro AlpiroSSL/Sectigo/PositiveSSL, TXT pro Certum, nebo soubor v `/.well-known/pki-validation/`), umístí validace certifikátu a po vydání ho odstraní; nebo CA napíše schvalovateli e-mail. acme se ptá `certStatus` a stahuje přes `getCert`. **Soukromý klíč nikdy neopustí acme.** API nemá metodu pro odvolání. API dovoluje nejvýš **60 požadavků za minutu a 2000 za hodinu** - nad to se zablokuje na 15 minut, pak déle.

## Co potřebujete

- Účet na www.ssls.cz se **zapnutým API**, **tokenem** a povolenými veřejnými **IPv4 adresami** acme.
- Kredit na účtu pro nové objednávky, nebo již zakoupené certifikáty k novému vydání (jejich *SSLS ID*).
- Přístup HTTPS **z acme** na `api.ssls.cz` port 443.
- Validaci v acme, která umí umístit důkaz DCV: DNS modul, který zapisuje záznamy **CNAME** (rodina Sectigo) nebo TXT (Certum), nebo HTTP na portu 80 pro soubor (bez přesměrování) - nebo člověka pro e-mail.

## Nastavení SSLS.cz

1. Na www.ssls.cz: **Můj účet → API nastavení** - zapněte API, **vygenerujte token** a zadejte **IPv4 adresy**, ze kterých se API smí používat, oddělené mezerami: veřejnou adresu, ze které acme odchází do internetu (za NATem adresu routeru; u clusteru obou uzlů). **Token držte v tajnosti** - vše, co se s ním objedná, se platí z kreditu účtu.
2. Prohlédněte si již zakoupené certifikáty (**Můj účet**) a poznamenejte si *SSLS ID* toho, který smí acme znovu vydávat, nebo rozhodněte, zda smí acme nakupovat.
3. Pro OV, EV a každý produkt Certum připravte údaje organizace (název, město, ulice, PSČ; Certum OV/EV: povinné IČO a e-mail).
4. Záznamy CAA, pokud jsou: povolte CA produktu (`sectigo.com`, `certum.pl`, `digicert.com` ...).

## Vyplnění v acme

Zdroje → **Přidat** → **SSLS.cz (AlpiroSSL, Sectigo, Certum…)**.

| Pole v acme | Co do něj zadat |
|---|---|
| API token | z kroku 1 |
| Product | *Load the list* (`allProducts`) - vyplní *Validation* a *Authority of the product* a *The product needs the organisation's details* |
| Subscription (years) | 1-5 (certifikát žije nejvýš 200 dní - delší předplatné obslouží bezplatná znovuvydání) |
| Domain validation (DCV) | *DNS*, *FILE* nebo *E-mail* + *Approver mailbox* |
| Contact: first name / last name / e-mail / phone / country | telefon **ve tvaru `00420123456789`** (00 místo +, jen číslice) |
| The product needs the organisation's details, Organisation ... | pro OV, EV a Certum |
| At a renewal | *Reissue inside the subscription while it runs* (výchozí) nebo *Always a new order (paid)* |
| Allow new orders (paid) | **ve výchozím stavu vypnuto** |
| Certificate to reuse (SSLS ID) / for the twin | již zakoupený certifikát; ID ukáže *List the certificates* |
| Product code typed, Server type, A new order for a certificate that had one, DNS record the CA asks for, Label of the DNS TXT record, Reissue while the subscription runs at least, More order fields, čekání (pokročilé) | podle potřeby; výchozí hodnoty většinou sedí |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `allProducts` se stavem účtu - zda jsou token a adresa vpuštěny, produkty, kredit. Nic se neobjedná.
- Na www.ssls.cz certifikát ukáže svůj stav a DCV.

## Časté problémy

| Problém | Řešení |
|---|---|
| *SSLS.cz refuses the API token* (`1002 Invalid token`) | vygenerujte token znovu a vložte ho |
| *SSLS.cz does not allow the API from this server's address* | přidejte veřejnou IPv4 acme v API nastavení |
| *nothing ordered: a new order would be a purchase* | nastavte *Certificate to reuse*, nebo zapněte *Allow new orders (paid)* |
| API zablokované na 15 minut / hodinu | příliš mnoho požadavků z jiných nástrojů se stejným tokenem; acme samo drží limity - počkejte |
| CNAME se nevytvoří | validace certifikátu neumí zapisovat CNAME - zvolte DNS modul, který to umí, nebo ho vytvořte ručně, jak říká úloha |
| FILE DCV selže | CA stahuje přes čisté http bez přesměrování - port 80 musí soubor obsloužit přímo |
| Certifikát Certum se nikdy znovu nevydá | očekávané: Certum je vždy nová objednávka |
