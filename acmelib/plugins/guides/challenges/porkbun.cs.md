# Porkbun - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Porkbunu, přes **API v3** Porkbunu (`https://api.porkbun.com/api/json/v3`, každé volání je POST s API klíčem a tajemstvím v těle JSON). Ověří klíče (`/ping`), vypíše domény (`/domain/listAll`), načte TXT záznamy na jménu (`/dns/retrieveByNameType/...`), pro každou hodnotu vytvoří jeden záznam (`/dns/create/{domain}`) a smaže ho podle id (`/dns/delete/{domain}/{id}`). Ostatní hodnoty na jméně zůstanou.

## Co potřebujete

- Doménu registrovanou u Porkbunu, která používá jmenné servery Porkbunu.
- HTTPS (TCP 443) z acme na `api.porkbun.com`.

## Nastavení Porkbunu

1. Přihlaste se na `porkbun.com`.
2. **Account → API Access → Create API Key**; pojmenujte ho `acme`.
3. Zkopírujte **API key** (`pk1_…`) a **secret API key** (`sk1_…`) - tajemství se zobrazí jen jednou.
4. **U každé domény**, kterou smí acme měnit: **Domain Management →** doména → **Details → API Access** → **zapnout**. Bez toho Porkbun odmítne s „domain is not opted in to API access“.

Vypnutý API Access u všech ostatních domén je způsob, jak klíč omezit - klíč funguje jen na doménách s ním zapnutým.

Volitelná kontrola:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"apikey":"pk1_…","secretapikey":"sk1_…"}' https://api.porkbun.com/api/json/v3/ping
# {"status":"SUCCESS","yourIp":"203.0.113.10"}
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key | `pk1_…` |
| Secret API key | `sk1_…` |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 600 (obvyklé minimum Porkbunu; pokročilé) |
| API address | `https://api.porkbun.com/api/json/v3` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: pingne Porkbun (a ukáže adresu, ze které acme volá) a vypíše domény; nic nemění.
- Po objednávce: **Domain Management →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| „Invalid API key“ | Klíč nebo tajemství je špatně, prohozené, nebo byl klíč smazán. |
| „Domain is not opted in to API access“ | Zapněte u domény **API Access**. |
| TTL odmítnuto | Nechte *TTL (s)* na 600 nebo víc (minimum vašeho účtu). |
| Doména není ve výpisu | Je v jiném účtu Porkbun nebo používá jiné jmenné servery. |
