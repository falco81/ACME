# Domeneshop - nastavení pro acme

acme prokazuje jména přes DNS-01 u Domeneshop (domene.shop, Norsko): přes Domeneshop API v0 přidá do DNS domény záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Přihlašuje se tokenem a secretem API (HTTP basic autentizace).

## Co potřebujete

- Doménu u Domeneshop, která používá DNS službu Domeneshop.
- Odchozí HTTPS z acme na `api.domeneshop.no` (port 443).

## Nastavení Domeneshop

1. Přihlaste se na `domene.shop` → **My page → API access** (`https://domene.shop/admin?view=api`).
2. Vytvořte nové přihlašovací údaje API. Získáte **token** a **secret** - zkopírujte oba; secret se zobrazí jen jednou.
3. Údaje API Domeneshop jednají za celý účet; nelze je omezit na jednu doménu. Pokud uniknou, smažte je v *API access*.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token |
| API secret | Secret |
| Domain | např. `example.no`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` (nejméně 60) |
| API address | (pokročilé) Výchozí `https://api.domeneshop.no/v0` |

## Kontrola

- **Test** v acme vypíše domény účtu. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "$TOKEN:$SECRET" https://api.domeneshop.no/v0/domains
  dig +short TXT _acme-challenge.example.no @ns1.hyp.net
  ```

  (použijte jeden ze jmenných serverů domény z `dig NS example.no`).

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný token nebo secret, nebo byly údaje smazány. |
| Doména se nenajde | Je v jiném účtu, nebo její DNS není u Domeneshop. |
| CA záznam nevidí | Ověřte, že doména používá jmenné servery Domeneshop; zvyšte *Wait at least (seconds)*. |
