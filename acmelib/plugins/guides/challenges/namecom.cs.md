# Name.com - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Name.com, přes **API v4** Name.com (`https://api.name.com/v4`) s basic autentizací (uživatelské jméno + API token). Vypíše domény, pro každou hodnotu přidá jeden TXT záznam (`POST /v4/domains/{domain}/records`) a potom ho smaže podle id. Ostatní hodnoty na stejném jménu zůstanou.

Name.com ohlásil novější „Core API“; dokud v4 odpovídá, modul ho používá. Až bude v4 ukončeno, adresa patří do *API address* (a volání se pak mohou lišit).

## Co potřebujete

- Doménu u Name.com, která používá jmenné servery Name.com.
- HTTPS (TCP 443) z acme na `api.name.com`.

## Nastavení Name.com

1. Přihlaste se na `name.com`.
2. **Account → Settings → Security → API access** (API Token Management).
3. Zapněte přístup k API a **vytvořte produkční token** (např. `acme`). *Testovací* token funguje jen proti `api.dev.name.com` s uživatelským jménem končícím na `-test`.
4. Token zkopírujte - zobrazí se jednou. Uživatelské jméno je jméno vašeho účtu.
5. Má-li účet zapnuté dvoufázové ověření, může Name.com chtít přístup k API jednou potvrdit - postupujte podle stránky.

Tokeny Name.com nejsou omezené na DNS: token mějte jen v acme.

Volitelná kontrola:

```sh
curl -u 'USERNAME:TOKEN' https://api.name.com/v4/domains
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| User name | uživatelské jméno účtu Name.com |
| API token | produkční token |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 300 (méně Name.com nepřijme; pokročilé) |
| API address | `https://api.name.com/v4` (pokročilé; `https://api.dev.name.com/v4` pro testovací API) |

## Ověření

- V acme stiskněte **Test**: vypíše domény účtu; nic nemění.
- Po objednávce: **My Domains →** doména → **Manage DNS Records**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unauthorized` | Špatné uživatelské jméno nebo token, nebo testovací token proti produkci. |
| `403` „Permission Denied“ | Přístup k API je pro účet vypnutý nebo ještě nepotvrzený. |
| Doména nenalezena | Doména je v jiném účtu nebo používá jiné jmenné servery. |
| TTL odmítnuto | Nechte *TTL (s)* na 300 nebo víc. |
