# Openprovider - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS zóně u Openprovideru, přes jeho REST API (`https://api.openprovider.eu/v1beta`). Přihlásí se (`POST /v1beta/auth/login`, bearer token držený několik hodin), vypíše zóny, načte TXT záznamy zóny a přidá či odebere jen svou hodnotu přes `PUT /v1beta/dns/zones/{zone}` (`records: {add: […]}` / `{remove: […]}`). Ostatní hodnoty na jméně zůstanou.

Funguje s Openprovider DNS i s Premium DNS (Sectigo).

## Co potřebujete

- Zónu v DNS Openprovideru (standardní nebo Premium DNS).
- HTTPS (TCP 443) z acme na `api.openprovider.eu`.
- Veřejnou IP adresu, ze které acme volá.

## Nastavení Openprovideru

1. Přihlaste se do ovládacího panelu Openprovideru (`cp.openprovider.eu`).
2. Vytvořte pro acme vyhrazeného uživatele: **Account → Users** (kontakty s přihlášením) → přidejte uživatele `acme` s dlouhým náhodným heslem.
3. Povolte tomuto uživateli **přístup k API** a omezte ho na IP adresu acme (nastavení API access / IP whitelist uživatele nebo účtu).
4. Pokud by dvoufázové přihlášení blokovalo přihlášení přes API, nechte ho u tohoto uživatele vypnuté (ověřte v nastavení Openprovideru: API se přihlašuje jen jménem a heslem).

**Pozor:** uživatelé Openprovideru nejsou omezeni na DNS - tento uživatel může jednat za resellerský účet. Heslo mějte jen v acme a omezení na IP přísné.

Volitelná kontrola:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"acme","password":"HESLO"}' https://api.openprovider.eu/v1beta/auth/login
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| User name | uživatel acme |
| Password | jeho heslo |
| DNS | `Openprovider DNS`, nebo `Premium DNS (Sectigo)` pro zóny tam |
| Zone | prázdné (nejdelší zóna účtu, do které jméno patří), nebo zóna |
| TTL (s) | 600 (pokročilé) |
| API address | `https://api.openprovider.eu` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše zóny; nic nemění.
- Po objednávce: ovládací panel → **DNS management → DNS zones →** zóna: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo, nepovolený přístup k API, nebo adresa acme není na whitelistu. |
| Zóna nenalezena | Zóna je v druhém *DNS* (standardní vs. Premium) - změňte *DNS*. |
| PUT odmítnut | Uživatel nemá právo měnit DNS zóny tohoto účtu. |
