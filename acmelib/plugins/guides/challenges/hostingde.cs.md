# hosting.de / http.net - nastavení pro acme

acme prokazuje jména přes DNS-01 u hosting.de (a http.net, stejná platforma): přes JSON DNS API hosting.de přidá záznam TXT `_acme-challenge.JMÉNO` pomocí `zoneUpdate` (`recordsToAdd`) a poté odebere přesně svou hodnotu (`recordsToDelete`). Ostatní hodnoty u jména zůstanou.

## Co potřebujete

- Zónu hostovanou v DNS hosting.de (nebo http.net).
- Odchozí HTTPS z acme na `secure.hosting.de` (nebo `partner.http.net`), port 443.

## Nastavení hosting.de

1. Přihlaste se do ovládacího panelu hosting.de → **Profile → API keys → New API key** (v německém rozhraní *Profil → API-Keys*).
2. Pojmenujte ho `acme` a dejte mu jen práva DNS: **list zones**, **list records** a **edit zones** (přesné popisky najdete v části DNS seznamu práv).
3. Je-li to nabízeno, omezte klíč na veřejnou adresu acme.
4. Zkopírujte klíč.

Pro **http.net** postupujte stejně v partnerském panelu http.net.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč |
| Zone | např. `example.de`; prázdné = nejdelší zóna viditelná klíči, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `120` |
| API address | (pokročilé) Výchozí `https://secure.hosting.de/api/dns/v1/json`; http.net: `https://partner.http.net/api/dns/v1/json` |

## Kontrola

- **Test** v acme vypíše zóny, které klíč vidí - nebo při vyplněné *Zone* přečte jen konfiguraci této zóny. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -X POST https://secure.hosting.de/api/dns/v1/json/zoneConfigsFind \
    -H 'Content-Type: application/json' \
    -d "{\"authToken\":\"$KEY\",\"filter\":{\"field\":\"zoneName\",\"value\":\"example.de\"}}"
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `status: error` s kódem autentizace | Špatný klíč, nebo pro něj není povolená adresa acme. |
| Chyba práv u `zoneUpdate` | Dejte klíči *edit zones*. |
| Test nevypíše všechny zóny | Vyplňte *Zone* - Test se pak ptá jen na tu zónu. |
| Hlášení „already exists“ | Hodnota z dřívějšího běhu tam stále je; acme to bere jako hotové. |
