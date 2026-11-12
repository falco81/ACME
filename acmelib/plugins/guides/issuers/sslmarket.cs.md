# SSLmarket (objednávky a znovuvydání) - nastavení pro acme

Zdroj **SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)** získává komerční certifikáty (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo) přes REST API SSLmarketu - prodejce provozovaného společností ZONER a.s. za SSLmarket.cz, .sk, .com, .de, .at, .ch, .hu a .co.uk (`https://www.sslmarket.<tld>/api`, hlavička `X-Auth-Token`). acme certifikát se svým CSR **znovu vydá** uvnitř objednávky, která ještě běží (`POST /certificate/order_id/{ID}/reissue` - zdarma), doplní svou žádost do objednávky zakoupené, ale ještě nevydané, nebo - jen když je zapnuté *Allow new orders (paid)* - **koupí** novou objednávku (`POST /order/certificate/{PRODUCT_CODE}`). Řetězec **DCV** objednávky umístí validace certifikátu (DNS TXT záznam, nebo soubor v `/.well-known/pki-validation/`), nebo CA napíše na `admin@`, `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@`. Objednávky OV/EV čekající u CA se vyzvednou při dalších pokusech. **Soukromý klíč nikdy neopustí acme.** *Import from a source* vypíše objednávky účtu. Pro plně automatické DigiCert DV/OV přes ACME použijte místo toho zdroj **SSLmarket ACME**.

## Co potřebujete

- Zákaznický účet u SSLmarketu se zapnutým **přístupem přes API** a jeho **API klíčem** - patří právnímu účtu: vše, co se s ním objedná, se platí z kreditu toho účtu.
- Již zakoupené objednávky k novému vydání, nebo kredit / fakturaci pro nové objednávky.
- Přístup HTTPS **z acme** na `www.sslmarket.<tld>` port 443.
- Validaci v acme, která umí umístit důkaz DCV: DNS modul pro TXT (vlastní DNS server acme odpovídá jen na jména `_acme-challenge`), *HTTP over SSH* pro soubor - nebo člověka pro e-mail.
- **Veřejný sandbox neexistuje** - zkoušejte přes *Try it* a levný DV produkt.

## Nastavení SSLmarketu

1. Přihlaste se do **Zákaznické administrace** → **Nastavení účtu** → **Přístup k účtu přes API** → zapněte; zobrazí se tam **API klíč**. **Držte ho v tajnosti** - kdokoli s ním může na váš účet kupovat certifikáty.
2. Podívejte se do **Objednávky**: poznamenejte si objednávku, ve které smí acme znovu vydávat (její ID), nebo ji kupte v administraci (acme do ní doplní žádost).
3. Než povolíte placené objednávky, zkontrolujte produkty a ceny; poznamenejte si **kód produktu** (*Load the products* v acme je ukáže).
4. Připravte údaje **vlastníka** (jméno, adresa, země, telefon ve tvaru `+420.123456789` - u OV/EV jako v obchodním rejstříku), **kontaktu** a případně **fakturační** údaje - jsou povinné pro každou novou objednávku.
5. Záznamy CAA, pokud jsou: povolte CA produktu (`digicert.com`, `sectigo.com`).

Ověření klíče:

```sh
curl -s -H "X-Auth-Token: $SSLMARKET_KEY" https://www.sslmarket.cz/api/product/list
```

## Vyplnění v acme

Zdroje → **Přidat** → **SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)**. *Find the settings from the account* doplní produkty, objednávky, vlastníka a kontakt z účtu (jen čte).

| Pole v acme | Co do něj zadat |
|---|---|
| SSLmarket / API address | obchod vašeho účtu (SSLmarket.cz ...); *Another address* jen pro testovací systém, který vám SSLmarket dal |
| API key | z kroku 1 |
| Product code / Order term (years) | např. kód DV produktu; roky nové objednávky (certifikát žije nejvýš 200 dní - delší objednávky obslouží bezplatná znovuvydání) |
| Domain validation (DCV) | *DNS* (TXT), *FILE* (HTTP soubor) nebo *Email* |
| Owner ..., Owner's phone | povinné pro nové objednávky; telefon ve tvaru `+420.123456789` |
| Contact: title / first name / last name / e-mail / phone | kontakt organizace a technický kontakt |
| Invoice: ... | prázdné: údaje vlastníka a kontaktu |
| At a renewal | *Reissue inside the order while it runs* (výchozí) nebo *Always a new order (paid)* |
| Allow new orders (paid) | **ve výchozím stavu vypnuto** |
| Order to reuse / Order to reuse for the twin | již zakoupená objednávka (pro duální certifikát jedna na každý typ klíče) |
| Reissue while the order runs at least (days) | `30` |
| Discount voucher, More order fields, Label of the DNS TXT record, čekání (pokročilé) | podle potřeby; TXT label `_dnsauth` |
| Allow a second (paid) order for a dual certificate (pokročilé) | vypnuto, pokud nechcete dvojice ECDSA + RSA, každou jako vlastní objednávku |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `GET /product/list` - nic se neobjedná.
- V administraci: **Objednávky** ukáže znovuvydání a certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` | špatný API klíč, vypnutý přístup přes API, nebo špatný obchod (.cz vs .sk ...) |
| *nothing ordered: ... a new order would be a purchase* | nastavte *Order to reuse*, nebo zapněte *Allow new orders (paid)* |
| `SSLmarket refused the order (400): ...` | zpráva jmenuje pole: údaje vlastníka / kontaktu, formát telefonu, roky produktu |
| Záznam DCV se nevytvoří | validace ho neumí zapsat (CNAME, nebo TXT u vlastního DNS serveru acme) - vytvořte ho ručně, jak říká úloha, nebo použijte jinou validaci |
| OV/EV čeká dny | očekávané: CA ověřuje organizaci; acme se podívá znovu později |
| Odvolání | přes API jen DigiCert Client Premium; TLS certifikáty odvolávejte v administraci |
