# ClouDNS - nastavení pro acme

acme prokazuje jména přes DNS-01 u ClouDNS: přes HTTP API ClouDNS (`api.cloudns.net`) přidá záznam TXT `_acme-challenge.JMÉNO` (`add-record.json`) a poté smaže jen svůj vlastní záznam (`delete-record.json`). Přihlašuje se jako API uživatel nebo, lépe, API **sub-user** omezený na zóny, které smí acme měnit.

## Co potřebujete

- Zónu hostovanou u ClouDNS, v tarifu s přístupem k API.
- Odchozí HTTPS z acme na `api.cloudns.net` (port 443); veřejnou IP adresu acme, protože **API odpovídá jen z adres, které API uživatel povolí**.

## Nastavení ClouDNS

1. Přihlaste se na `cloudns.net` → **API & Resellers**.
2. Nejlépe: **API sub-users → Add new sub-user**: nastavte heslo a **allowed IP** = veřejná adresa acme. Pak sub-userovi přidělte jen zóny, které smí acme měnit (delegace zón sub-usera / *Add zone* v jeho nastavení).
3. Nebo: **API users → Add new user** (hlavní API uživatel, `auth-id`) s povolenou IP acme - tento uživatel může měnit všechny zóny účtu.
4. Poznamenejte si **ID** (sub-)uživatele a jeho heslo.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Signs in as | `an API sub-user (sub-auth-id)` nebo `the main API user (auth-id)` |
| Auth ID | ID (sub-)uživatele, např. `1234` |
| Auth password | Jeho heslo |
| Zone | např. `example.com`; prázdné = nejdelší zóna účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60`; ClouDNS zná jen 60, 300, 900, 1800, 3600 … - jiná hodnota se zvýší na nejbližší vyšší |

## Kontrola

- **Test** v acme se přihlásí (`login.json`) a vypíše zóny. Nic nemění.
- Pomocí curl (sub-user):

  ```sh
  curl -s -d 'sub-auth-id=1234' -d "auth-password=$PASS" https://api.cloudns.net/dns/login.json
  dig +short TXT _acme-challenge.example.com @ns1.cloudns.net
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Invalid authentication, incorrect auth-id or auth-password` | Špatné ID/heslo, nebo *Signs in as* neodpovídá (sub-user vs. hlavní uživatel). |
| Přihlášení z acme odmítnuto | Veřejná IP acme není mezi povolenými IP uživatele. |
| Zóna není v seznamu | Sub-user tu zónu nemá přidělenou. |
| CA záznam nevidí | Zvyšte *Wait at least (seconds)*; ověřte, že `dig NS example.com` vede na ClouDNS. |
