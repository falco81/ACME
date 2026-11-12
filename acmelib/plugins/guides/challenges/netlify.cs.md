# Netlify DNS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně hostované na **Netlify DNS**, přes Netlify API v1 (`https://api.netlify.com/api/v1`) s osobním přístupovým tokenem. Vypíše DNS zóny (`dns_zones`), pro každou hodnotu přidá jeden TXT záznam (`POST .../dns_zones/{id}/dns_records`) a potom ho smaže podle id. Ostatní hodnoty na stejném jménu zůstanou.

## Co potřebujete

- Doménu přidanou do Netlify jako **DNS zónu** (Netlify DNS) a u registrátora nastavené jmenné servery Netlify (`dns1.p0X.nsone.net` …, jak je Netlify ukazuje).
- HTTPS (TCP 443) z acme na `api.netlify.com`.

## Nastavení Netlify

1. Přihlaste se na `app.netlify.com` jako uživatel, který smí spravovat domény týmu.
2. **User settings → Applications → Personal access tokens → New access token**.
3. Popis `acme`; zvolte platnost (nebo žádnou - token s platností je nutné v acme včas vyměnit).
4. **Generate token** a token zkopírujte - zobrazí se jen jednou.

**Pozor:** osobní přístupový token Netlify má plná práva vašeho uživatele (weby, nasazení, DNS) - Netlify nemá scope jen pro DNS. Zvažte vyhrazeného uživatele Netlify, který je členem jen týmu s doménou.

Volitelná kontrola:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.netlify.com/api/v1/dns_zones
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Personal access token | token |
| Zone | prázdné (nejdelší zóna účtu, do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| API address | `https://api.netlify.com/api/v1` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše DNS zóny, které token vidí; nic nemění.
- Po objednávce: **Domains →** doména → **DNS records**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unauthorized` | Token je špatný, zrušený nebo vypršel. |
| Zóna nenalezena | Doména je jen vlastní doménou webu, ne zónou Netlify DNS - přidejte ji v **Domains → Add or register domain** a použijte Netlify DNS. |
| Záznam vytvořen, ale CA ho nevidí | Registrátor stále ukazuje na jiné jmenné servery. |
