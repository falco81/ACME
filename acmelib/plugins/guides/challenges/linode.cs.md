# Linode (Akamai Cloud) - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně DNS Manageru Linode (dnes Akamai Cloud), přes API v4 (`https://api.linode.com/v4/domains`). Vypíše domény, pro každou hodnotu přidá jeden TXT záznam na `_acme-challenge.JMÉNO` a potom ho smaže podle id. Ostatní hodnoty na stejném jménu zůstanou.

## Co potřebujete

- Doménu v části **Domains** vašeho účtu Linode / Akamai Cloud a u registrátora nastavené jmenné servery Linode (`ns1.linode.com` … `ns5.linode.com`).
- HTTPS (TCP 443) z acme na `api.linode.com`.

## Nastavení Linode

1. Přihlaste se na `cloud.linode.com`.
2. Klikněte na své uživatelské jméno (vpravo nahoře) → **API Tokens** → **Create a Personal Access Token**.
3. *Label* `acme`; *Expiry* podle potřeby (token s expirací je nutné v acme včas vyměnit).
4. **Domains** nastavte na **Read/Write** a všechny ostatní scopes na **No Access**.
5. **Create Token** a token zkopírujte - zobrazí se jen jednou.

Volitelná kontrola:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.linode.com/v4/domains
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Personal access token | token z kroku 5 |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 300 (Linode zaokrouhluje na známé hodnoty, nejméně 300; pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény, které token vidí; žádný záznam nemění.
- Po objednávce: **Domains →** doména: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.linode.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Invalid Token` | Token je špatný nebo vypršel - vytvořte nový. |
| `403` / „Unauthorized“ při vytváření | Token má Domains jen *Read Only* - potřebuje **Read/Write**. |
| Doména nenalezena | Doména je v jiném účtu Linode nebo není přidána v Domains. |
| CA záznam nevidí | Jmenné servery Linode se aktualizují po několika minutách; nechte kontrolu propagace zapnutou. |
