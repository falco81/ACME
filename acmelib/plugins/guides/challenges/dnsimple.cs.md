# DNSimple - nastavení pro acme

acme prokazuje jména přes DNS-01 u DNSimple: přes DNSimple API v2 přidá do zóny záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Přihlašuje se přístupovým tokenem API - nejlépe **tokenem účtu** (account token), který zná svůj účet.

## Co potřebujete

- Zónu v účtu DNSimple (hostované DNS pro doménu aktivní).
- Odchozí HTTPS z acme na `api.dnsimple.com` (port 443) - nebo `api.sandbox.dnsimple.com` pro sandbox.

## Nastavení DNSimple

1. Přihlaste se na `dnsimple.com` a přepněte se na účet se zónou.
2. **Account → Access tokens → New access token** (přístupový token *účtu*, ne token uživatele).
3. Pojmenujte ho např. `acme` a zkopírujte token (zobrazí se jen jednou).
4. Tokeny účtu DNSimple nelze omezit na jednotlivé zóny: chcete-li omezit, kam token dosáhne, držte zóny spravované acme v samostatném účtu DNSimple.
5. Token **uživatele** (User settings → Access tokens) vidí všechny účty uživatele - pak si poznamenejte i **Account ID** (číslo v adrese účtu, `dnsimple.com/a/<ID>/…`).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API access token | Token |
| Account ID | (pokročilé) Prázdné pro token účtu; číslo účtu pro token uživatele |
| Zone | např. `example.com`; prázdné = nejdelší zóna účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| Endpoint | (pokročilé) `api.dnsimple.com`, nebo sandbox |

## Kontrola

- **Test** v acme vypíše zóny účtu. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://api.dnsimple.com/v2/whoami
  dig +short TXT _acme-challenge.example.com @ns1.dnsimple.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Authentication failed` | Špatný nebo zrušený token; token ze sandboxu použitý v produkci (nebo naopak). |
| Účet je neznámý | Token uživatele: vyplňte *Account ID*. |
| `402` / `403` | Tarif účtu nezahrnuje přístup k API, nebo DNS zóny není aktivní. |
| Zóna se nenajde | Je v jiném účtu; vyplňte přesně *Zone*. |
