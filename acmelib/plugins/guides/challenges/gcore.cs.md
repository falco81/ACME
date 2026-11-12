# Gcore DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v Gcore Managed DNS: přes Gcore DNS API v2 (`api.gcore.com/dns`) přečte sadu záznamů TXT `_acme-challenge.JMÉNO`, přidá svou hodnotu a sadu zapíše zpět (`POST`/`PUT`); při úklidu odebere jen svou hodnotu (nebo sadu smaže, byla-li jeho hodnota poslední). Přihlašuje se **trvalým API tokenem**.

## Co potřebujete

- Zónu v Gcore Managed DNS, s doménou delegovanou na jmenné servery Gcore.
- Odchozí HTTPS z acme na `api.gcore.com` (port 443).

## Nastavení Gcore

1. Portál Gcore → **Profile → API tokens → Create token**.
2. Pojmenujte ho `acme`, nastavte **expiration** (nebo žádnou - pak ho obměňujte sami).
3. Zvolte **roli**, která smí upravovat zóny DNS, ale co nejméně dalšího. Má-li váš účet uživatele s omezenými rolemi, vytvořte pro acme samostatného uživatele jen s přístupem k DNS a token vytvořte jako on.
4. Zkopírujte token (zobrazí se jen jednou).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Trvalý token |
| Zone | např. `example.com`; prázdné = nejdelší zóna účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `120` |
| API address | (pokročilé) Výchozí `https://api.gcore.com/dns` |

## Kontrola

- **Test** v acme vypíše zóny, které token vidí. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: APIKey $TOKEN" 'https://api.gcore.com/dns/v2/zones?limit=10'
  curl -s -H "Authorization: APIKey $TOKEN" \
    https://api.gcore.com/dns/v2/zones/example.com/_acme-challenge.example.com/TXT
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný nebo prošlý token. |
| `403` | Role tokenu nesmí upravovat zóny DNS. |
| Výpis zón selže | acme se pak ptá zónu po zóně - vyplněním *Zone* to přeskočíte. |
| CA záznam nevidí | Ověřte, že doména používá jmenné servery Gcore; zvyšte *Wait at least (seconds)*. |
