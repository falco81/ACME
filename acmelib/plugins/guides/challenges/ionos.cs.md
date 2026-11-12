# IONOS (Hosting API) - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně u IONOS přes **IONOS Hosting DNS API** (`https://api.hosting.ionos.com/dns/v1`). Vypíše zóny, pro každou hodnotu přidá jeden TXT záznam na `_acme-challenge.JMÉNO` a potom ho smaže podle id; ostatní hodnoty zůstanou.

Jde o API pro domény v hostingových/doménových smlouvách IONOS. **IONOS Cloud DNS (DCD) je jiné API** a s tímto modulem nefunguje.

## Co potřebujete

- Doménu ve smlouvě IONOS, jejíž DNS je u IONOS.
- HTTPS (TCP 443) z acme na `api.hosting.ionos.com`.
- Přístup na vývojářský portál IONOS s přihlášením ke smlouvě.

## Nastavení IONOS

1. Otevřete `developer.hosting.ionos.com` a přihlaste se účtem IONOS.
2. Jděte do **Get started → API keys → Create** (německy *API-Keys → Erstellen*).
3. Dejte klíči popis, např. `acme`.
4. Zkopírujte obě části: **public prefix** a **secret**. Secret se zobrazí jen jednou.

Klíče IONOS nejsou omezené na DNS: klíč mějte jen v acme.

Volitelná kontrola ze shellu (prefix a secret spojené tečkou):

```sh
curl -H 'X-API-Key: PREFIX.SECRET' https://api.hosting.ionos.com/dns/v1/zones
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Public prefix | veřejný prefix klíče |
| Secret | secret klíče |
| Zone | prázdné (nejdelší zóna účtu, do které jméno patří), nebo zóna |
| TTL (s) | výchozí 60 (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše zóny účtu; žádný záznam nemění.
- Po objednávce v ovládacím panelu IONOS: **Domains & SSL →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unauthorized` | Prefix nebo secret je špatně či prohozený - acme posílá `prefix.secret`. |
| Zóna nenalezena | Doména používá jiné jmenné servery, nebo jde o zónu IONOS Cloud (DCD) - na ty tento modul nedosáhne. |
| CA záznam nevidí | Jmenným serverům IONOS to může trvat několik minut; nechte *Wait until it is seen by* na jmenných serverech zóny. |
