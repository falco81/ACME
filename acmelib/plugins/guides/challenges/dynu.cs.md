# Dynu - nastavení pro acme

acme prokazuje jména přes DNS-01 u Dynu: přes Dynu API v2 (`api.dynu.com`) přidá do domény záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Přihlašuje se klíčem API účtu.

## Co potřebujete

- Doménu (nebo jméno dynamického DNS Dynu) ve vašem účtu Dynu, s DNS obsluhovaným Dynu.
- Odchozí HTTPS z acme na `api.dynu.com` (port 443).

## Nastavení Dynu

1. Přihlaste se na `dynu.com` → **Control Panel → API Credentials**.
2. Zkopírujte **API key** (případně ho tam vygenerujte/resetujte). Klíč jedná za celý účet; Dynu nemá klíč omezený na jednu doménu.
3. Pokud klíč později resetujete, aktualizujte ho v acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč API |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| API address | (pokročilé) Výchozí `https://api.dynu.com/v2` |

## Kontrola

- **Test** v acme vypíše domény účtu. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "API-Key: $KEY" -H 'Accept: application/json' https://api.dynu.com/v2/dns
  dig +short TXT _acme-challenge.example.com @ns1.dynu.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný nebo resetovaný klíč API. |
| Doména se nenajde | Není v tomto účtu Dynu; vyplňte přesně *Domain*. |
| CA záznam nevidí | Ověřte, že doména používá jmenné servery Dynu; zvyšte *Wait at least (seconds)*. |
