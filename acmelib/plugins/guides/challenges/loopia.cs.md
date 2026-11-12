# Loopia - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Loopie (Švédsko; také Loopia Srbsko a Norsko), přes **LoopiaAPI** (XML-RPC na `https://api.loopia.se/RPCSERV`). Volá `getDomains`, `getZoneRecords`, `addSubdomain` a `addZoneRecord`, aby přidal jeden TXT záznam pro každou hodnotu, pak `removeZoneRecord` (jen naše) a `removeSubdomain`, jakmile v subdoméně `_acme-challenge` nezůstane žádný záznam.

## Co potřebujete

- Doménu u Loopie, která používá jmenné servery Loopie.
- HTTPS (TCP 443) z acme na `api.loopia.se` (`api.loopia.rs` pro Loopia Srbsko).
- Přístup do zákaznické zóny Loopie.

## Nastavení Loopie

1. Přihlaste se do **zákaznické zóny Loopie** (Kundzon).
2. Jděte do **Account settings → LoopiaAPI** a vytvořte nového API uživatele. Jeho jméno končí na `@loopiaapi` (např. `acme@loopiaapi`); nastavte dlouhé náhodné heslo.
3. Povolte tomuto API uživateli přesně tyto funkce:
   - `getDomains`
   - `getZoneRecords`
   - `addSubdomain`
   - `addZoneRecord`
   - `removeZoneRecord`
   - `removeSubdomain`
4. Všechny ostatní funkce nechte vypnuté (žádné objednávky, platby ani převody domén).

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API user | `acme@loopiaapi` |
| API password | jeho heslo |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 300 (méně Loopia nepřijme; pokročilé) |
| API address | `https://api.loopia.se/RPCSERV`; `https://api.loopia.rs/RPCSERV` pro Loopia Srbsko (pokročilé) |

## Ověření

- V acme stiskněte **Test**: zavolá `getDomains` a vypíše domény; nic nemění.
- Po objednávce: zákaznická zóna → doména → **DNS editor**: subdoména `_acme-challenge` s TXT záznamem se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.se @ns1.loopia.se
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AUTH_ERROR` | Špatný API uživatel nebo heslo, nebo funkce není API uživateli povolena - zaškrtněte ji v LoopiaAPI. |
| `RATE_LIMITED` | Příliš mnoho volání; acme počká a zkusí znovu - nepoužívejte stejného API uživatele v mnoha validacích najednou. |
| `BAD_INDATA` | Doména nebo jméno není v účtu; zkontrolujte *Domain*. |
| CA záznam nevidí včas | Jmenným serverům Loopie to může trvat mnoho minut: nechte *Wait until it is seen by* na jmenných serverech zóny a dejte vydavateli dost času na čekání. |
