# Simply.com - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **Simply.com** (dříve UnoEuro), přes jeho REST API v2 (`https://api.simply.com/2`). Vypíše produkty (domény), načte DNS záznamy, pro každou hodnotu přidá jeden TXT záznam (`POST /my/products/{object}/dns/records/`) a ten smaže podle id. Ostatní hodnoty na jméně zůstanou.

Přihlašuje se **číslem účtu + API klíčem** (basic autentizace), nebo u novějších klíčů **samotným API klíčem** (bearer token).

## Co potřebujete

- Doménu u Simply.com, která používá jmenné servery Simply.com.
- HTTPS (TCP 443) z acme na `api.simply.com`.

## Nastavení Simply.com

1. Přihlaste se do **ovládacího panelu** Simply.com.
2. Jděte do **Account → API**.
3. Poznamenejte si zobrazené **číslo účtu** (`S123456`) a vytvořte / zobrazte **API klíč**.
4. Nabízí-li stránka novější typ klíče, který funguje samostatně (bearer klíč), můžete ho použít bez čísla účtu.

**Pozor:** API klíč působí na celý účet Simply.com (všechny produkty) - mějte ho jen v acme.

Volitelná kontrola:

```sh
curl -u 'S123456:APIKEY' https://api.simply.com/2/my/products/
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Account number | `S123456`; prázdné, je-li klíč bearer klíčem použitým samostatně |
| API key | API klíč |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 120 (pokročilé) |
| API address | `https://api.simply.com/2` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény účtu; nic nemění.
- Po objednávce: ovládací panel → doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / „Unauthorized“ | Číslo účtu a klíč k sobě nepatří, nebo byl samostatný bearer klíč poslán s číslem účtu (nechte ho prázdné) - či naopak. |
| Doména nenalezena | Doména je v jiném účtu Simply.com nebo používá jiné jmenné servery. |
| CA záznam ještě nevidí | Nechte *Wait until it is seen by* na jmenných serverech zóny. |
