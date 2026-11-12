# Vercel DNS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně, která používá **Vercel DNS**, přes REST API Vercelu (`https://api.vercel.com`, bearer token; `?teamId=…` pro domény týmu). Vypíše domény (`/v5/domains`), načte záznamy (`/v4/domains/{domain}/records`), pro každou hodnotu přidá jeden TXT záznam (`POST /v2/domains/{domain}/records`) a ten smaže podle id. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu ve vašem účtu nebo týmu na Vercelu se jmennými servery Vercelu (`ns1.vercel-dns.com`, `ns2.vercel-dns.com`).
- HTTPS (TCP 443) z acme na `api.vercel.com`.

## Nastavení Vercelu

1. Přihlaste se na `vercel.com`.
2. **Account Settings → Tokens → Create**:
   - název `acme`;
   - **Scope**: **tým**, kterému domény patří (nebo váš osobní účet);
   - platnost podle potřeby (token s platností je nutné v acme včas vyměnit).
3. Token zkopírujte - zobrazí se jednou.
4. U domén týmu zkopírujte **Team ID**: tým → **Settings → General → Team ID** (`team_…`).

**Pozor:** token Vercelu má ve svém rozsahu vaše plná práva (projekty, nasazení, domény) - Vercel nemá token jen pro DNS. Omezte ho na jediný tým s doménami.

Volitelná kontrola:

```sh
curl -H 'Authorization: Bearer TOKEN' 'https://api.vercel.com/v5/domains?teamId=team_…'
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Access token | token |
| Team ID | `team_…` pro domény týmu; prázdné pro vaše vlastní |
| Domain | prázdné (nejdelší doména, kterou token vidí a do které jméno patří), nebo doména |
| TTL (s) | 60 (pokročilé) |
| API address | `https://api.vercel.com` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény, které token vidí; nic nemění.
- Po objednávce: tým → **Domains →** doména → **DNS Records**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` „forbidden“ / „not_authorized“ | Token má rozsah na jiný tým, nebo chybí / je špatně *Team ID*. |
| Doména nenalezena | Doména používá jiné jmenné servery (ne Vercel DNS), nebo patří jinému týmu. |
| `401` po čase | Token vypršel - vytvořte nový. |
