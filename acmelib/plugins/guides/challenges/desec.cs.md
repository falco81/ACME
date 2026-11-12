# deSEC - nastavení pro acme

acme prokazuje jména přes DNS-01 u deSEC.io (i pro jména `dedyn.io`): přes REST API deSEC přečte sadu TXT u `_acme-challenge.JMÉNO`, přidá svou hodnotu a sadu zapíše zpět (`PATCH .../rrsets/`); při úklidu odebere jen svou hodnotu. Protože jmenné servery deSEC jsou anycast, čeká acme po tom, co je oba mají, ještě chvíli navíc. Pro ověření u komerční CA umí zapsat i CNAME.

## Co potřebujete

- Doménu (nebo jméno `dedyn.io`) ve vašem účtu deSEC.
- Odchozí HTTPS z acme na `desec.io` (port 443).
- Trpělivost s TTL: **deSEC nepřijme TTL pod minimálním TTL domény** (u většiny účtů 3600 s).

## Nastavení deSEC

1. Přihlaste se na `desec.io` → **Token management → +** (vytvořit token). Zkopírujte hodnotu tokenu (zobrazí se jen jednou).
2. Token omezte (doporučeno):
   - **Allowed subnets**: veřejná adresa acme (např. `203.0.113.10/32`).
   - Volitelně **max age / max unused period**.
3. Přidejte **token policies**, aby token mohl zapisovat jen záznamy pro ověření. Výchozí politika (bez domény, subname a typu) se zápisem **vypnutým** a jedna pro každou doménu:

   | Domain | Subname | Type | Write |
   |---|---|---|---|
   | (výchozí) | (libovolné) | (libovolný) | ne |
   | `example.com` | `_acme-challenge` | `TXT` | ano |

   Přidejte řádek pro každé používané `_acme-challenge.SUB` (např. `_acme-challenge.www`). Token přesto musí smět číst seznam domén.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token |
| Domain | např. `example.dedyn.io`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `3600`; nižší hodnota se zvýší na minimum domény |
| Wait after it is seen (seconds) | (pokročilé) Výchozí `60` - čas navíc pro anycastové jmenné servery |
| API address | (pokročilé) Výchozí `https://desec.io/api/v1` |

## Kontrola

- **Test** v acme vypíše domény (nebo přečte zadanou doménu a její minimální TTL). Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: Token $TOKEN" https://desec.io/api/v1/domains/
  dig +short TXT _acme-challenge.example.dedyn.io @ns1.desec.io
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` při zápisu | Žádná token policy nepovoluje `TXT` u daného subname - přidejte pro něj řádek. |
| `403` / `401` u všeho | Špatný token, nebo adresa acme není mezi povolenými podsítěmi tokenu. |
| `429 Too Many Requests` | deSEC omezuje rychlost; acme počká - jen to trvá déle. |
| CA nic nevidí | Dejte tomu víc času: zvyšte *Wait after it is seen (seconds)*. |
