# Njalla - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Njally, přes JSON-RPC API Njally (`https://njal.la/api/1/`, hlavička `Authorization: Njalla <token>`). Volá `list-domains`, `list-records`, `add-record` (jeden TXT záznam pro každou hodnotu) a `remove-record` podle id záznamu. Ostatní hodnoty na stejném jménu zůstanou.

## Co potřebujete

- Doménu u Njally, která používá DNS Njally.
- HTTPS (TCP 443) z acme na `njal.la`.
- Nejlépe: veřejnou IP adresu, ze které acme volá, pro omezení tokenu.

## Nastavení Njally

1. Přihlaste se na `njal.la`.
2. Jděte do **Settings → API access → Add token**.
3. Dejte mu komentář, např. `acme`, a nabízí-li to stránka, omezte ho na adresu, ze které acme volá.
4. Token zkopírujte.

**Pozor:** token Njally platí pro všechny domény účtu - mějte ho jen v acme a kde to jde, omezte ho na adresu.

Volitelná kontrola:

```sh
curl -H 'Authorization: Njalla TOKEN' -H 'Content-Type: application/json' \
  -d '{"method":"list-domains","params":{}}' https://njal.la/api/1/
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API token | token |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 60 (pokročilé) |
| API address | `https://njal.la/api/1/` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény účtu; nic nemění.
- Po objednávce: Njalla → **Domains →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| „Permission denied“ / neplatný token | Token je špatný nebo smazaný, nebo volání přichází z adresy, kterou token nepovoluje. |
| Doména nenalezena | Doména je v jiném účtu Njally nebo používá jiné jmenné servery. |
| `{error: {code, message}}` při přidání | acme ukáže zprávu Njally - zkontrolujte doménu a TTL. |
