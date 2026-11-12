# Scaleway - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS zóně Scaleway, přes **Domains and DNS API v2beta1** (`https://api.scaleway.com/domain/v2beta1`, hlavička `X-Auth-Token` se secret key API klíče). Vypíše DNS zóny, načte TXT záznamy na jménu a přidá či smaže jen svou hodnotu přes `PATCH .../dns-zones/{zone}/records` (`add` / `delete` podle id). Zónu, která je subdoménou (`dev.example.com`), najde jako takovou.

## Co potřebujete

- Zónu ve **Scaleway Domains and DNS** (jmenné servery Scaleway) ve známém projektu.
- HTTPS (TCP 443) z acme na `api.scaleway.com`.
- Práva IAM v organizaci Scaleway vytvořit aplikaci a policy.

## Nastavení Scaleway

1. Přihlaste se na `console.scaleway.com`.
2. **IAM → Applications → Create application**, název `acme`.
3. **IAM → Policies → Create policy**:
   - *Principal*: aplikace `acme`.
   - *Rule*: rozsah **Access to resources** → **projekt**, ve kterém je DNS zóna.
   - *Permission sets*: **DomainsDNSFullAccess** (sady oprávnění pro DNS, jak je Scaleway pojmenovává; nic dalšího).
4. Otevřete aplikaci → **API keys → Generate an API key**. Zkopírujte **secret key** (zobrazí se jen jednou); access key acme nepotřebuje.

Volitelná kontrola:

```sh
curl -H 'X-Auth-Token: SECRET_KEY' 'https://api.scaleway.com/domain/v2beta1/dns-zones?page_size=100'
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Secret key | secret key API klíče |
| Zone | prázdné (nejdelší zóna, kterou klíč vidí a do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše DNS zóny, které klíč vidí; nic nemění.
- Po objednávce: konzole → **Domains and DNS →** doména → **DNS zones →** zóna → **Records**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` „authentication is denied“ | Špatný secret key, nebo byl vložen access key. |
| `403` „insufficient permissions“ | Policy chybí, má rozsah na jiný projekt, nebo jí chybí sada oprávnění pro DNS. |
| Zóna nenalezena | Zóna je v jiném projektu nebo organizaci - upravte projekt v policy. |
