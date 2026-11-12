# Websupport - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **Websupportu** (websupport.sk / websupport.cz), přes REST API v1 (`https://rest.websupport.sk/v1/user/self/zone/...`). Každý požadavek je podepsaný HMAC-SHA1 s API tajemstvím nad `METHOD PATH UNIXTIME`, poslaný jako basic autentizace `KEY:SIGNATURE` s hlavičkou `Date`. acme vypíše zóny, načte záznamy, pro každou hodnotu přidá jeden TXT záznam a ten smaže podle id. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu u Websupportu, která používá DNS Websupportu.
- HTTPS (TCP 443) z acme na `rest.websupport.sk`.
- **Správné hodiny** acme (NTP) - podpis obsahuje čas.

## Nastavení Websupportu

1. Přihlaste se na `admin.websupport.sk` (nebo `admin.websupport.cz`).
2. Klikněte na své jméno → **Security and login → API access → Generate new access** (v českém/slovenském UI *Zabezpečení a přihlášení → API přístup*).
3. Nabízí-li to stránka, **omezte přístup na IP adresu**, ze které acme volá.
4. Zkopírujte **identifikátor** (API key) a **tajemství** (secret) - tajemství se zobrazí jen jednou.

**Pozor:** API klíč působí na celý účet Websupport (nejen DNS) - mějte ho jen v acme a omezte ho na IP.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key | identifikátor |
| API secret | tajemství |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména, např. `example.sk` |
| TTL (s) | 600 (pokročilé) |
| API address | `https://rest.websupport.sk` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše zóny účtu; nic nemění.
- Po objednávce: administrace → doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.sk @ns1.websupport.sk
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Klíč a tajemství k sobě nepatří, nebo hodiny acme jdou špatně (zkontrolujte NTP). |
| `403` | Adresa acme není pro klíč povolena. |
| Zóna nenalezena | Doména používá jiné jmenné servery nebo je v jiném účtu Websupport. |
| v1 už neodpovídá | Websupport má vedle něj API v2; *API address* měňte jen tehdy, oznámí-li to Websupport. |
