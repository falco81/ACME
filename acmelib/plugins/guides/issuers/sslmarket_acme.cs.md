# SSLmarket ACME (DigiCert) - nastavení pro acme

Zdroj **SSLmarket ACME (DigiCert, EAB made through the API)** vytvoří u SSLmarketu přes jeho REST API **ACME klíč** (`POST /acme` s ACME produktem, jménem klíče, platností certifikátu a - u OV/EV - organizací) a uschová si z odpovědi URL ACME adresáře a EAB (key id + HMAC). Od té chvíle se každý certifikát objednává přes **ACME** u DigiCertu, každé jméno se prokazuje přes DNS-01 nebo HTTP-01 jako u Let's Encrypt a obnovuje se v okně ARI určeném CA - žádné objednávky a žádné DCV SSLmarketu. **Soukromý klíč nikdy neopustí acme.** Akce: *Load the ACME keys*, *Load the organisations*, *Make an ACME key*, *Revoke the ACME key*. Totéž udělá obyčejný zdroj ACME s *DigiCert (EAB)*, když do něj vložíte ručně vytvořený klíč.

## Co potřebujete

- Zákaznický účet u SSLmarketu (.cz, .sk, .com, .de, .at, .ch, .hu, .co.uk) s **přístupem přes API** a jeho **API klíčem**; kredit nebo fakturaci pro ACME produkt.
- **ACME produkt** účtu (jeho kód); pro OV/EV **organizaci** ověřenou u SSLmarketu.
- Přístup HTTPS **z acme** na `www.sslmarket.<tld>` a na ACME server DigiCertu (`acme.digicert.com` nebo regionální v URL adresáře), port 443.
- Validaci pro jména: DNS-01 (API DNS poskytovatele) nebo HTTP-01 (port 80 dosažitelný z internetu).

## Nastavení SSLmarketu

1. **Zákaznická administrace** → **Nastavení účtu** → **Přístup k účtu přes API** → zapněte a zkopírujte **API klíč**. Držte ho v tajnosti.
2. Zvolte ACME produkt (jeho *kód produktu*) - vypíše je *Find the settings from the account* v acme - a zkontrolujte jeho cenu.
3. OV/EV: organizace musí být u SSLmarketu ověřená; *Load the organisations* ukáže její id a ověření.
4. Klíč vytvořený dříve v administraci: SSLmarket ukáže jeho EAB **jen při vytvoření klíče** - tehdy si zkopírujte EAB key id a HMAC; URL adresáře acme najde podle jména klíče.
5. Záznamy CAA, pokud jsou: `0 issue "digicert.com"`.

## Vyplnění v acme

Zdroje → **Přidat** → **SSLmarket ACME (DigiCert, EAB made through the API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| SSLmarket / API address | obchod vašeho účtu |
| API key | z kroku 1 |
| ACME product code | ACME produkt |
| Name of the ACME key | např. `acme-prod` - jak se klíč u SSLmarketu jmenuje |
| Certificate validity (days) | 1-199 |
| Organisation | id organizace pro OV/EV (*Load the organisations*) |
| Make the ACME key when there is none | zapnuto - první certifikát ho vytvoří; vypnuto: úloha to místo toho oznámí |
| EAB key id / EAB HMAC of a key made elsewhere (pokročilé) | pro klíč vytvořený v administraci |

Změna produktu, jména, platnosti nebo organizace znamená jiný ACME klíč. Běžná nastavení ACME (kontakty, klíč účtu, čekání) jsou ta ze zdroje ACME.

## Ověření

- Zdroje → zdroj → **Test** (Try it), pak **Load the ACME keys** - klíč, jeho produkt, platnost a stav.
- Vydejte certifikát: úloha ukáže kroky ACME (objednávka, důkazy DNS-01/HTTP-01, finalize).

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` od SSLmarketu | špatný API klíč, vypnutý přístup přes API, nebo špatný obchod |
| *a key by that name of which acme has no EAB* | acme vytvoří nový klíč (nebo, je-li vytváření vypnuté, to oznámí) - vložte EAB existujícího klíče, nebo použijte jiné jméno |
| ACME server odmítne EAB | klíč byl u SSLmarketu odvolán, nebo je HMAC špatně zkopírovaný |
| OV/EV odmítnuto | nastavte *Organisation* na ověřenou organizaci |
| Selhání výzev | jako u každé ACME CA: TXT záznam není vidět (DNS-01), port 80 nedosažitelný (HTTP-01), CAA nepovoluje DigiCert |
| Klíč má přestat fungovat | *Revoke the ACME key* - certifikáty jím vydané zůstávají platné |
