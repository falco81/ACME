# UltraDNS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v **primární zóně u UltraDNS** (Vercara, nyní DigiCert), přes její REST API (`https://api.ultradns.com`). Přihlásí se uživatelským jménem a heslem (`POST /v1/authorization/token`, `grant_type=password`) a bearer token drží po dobu jeho platnosti, vypíše zóny (`GET /v3/zones`), načte TXT RRset na `_acme-challenge.JMÉNO`, přidá či odebere svou hodnotu a RRset zapíše zpět (`POST` pro vytvoření, `PUT` pro změnu, `DELETE`, byla-li naše hodnota poslední). Ostatní hodnoty na jménu se zapíší zpět tak, jak byly načteny.

## Co potřebujete

- Zónu jako **primární** zónu v UltraDNS.
- HTTPS (TCP 443) z acme na `api.ultradns.com`.
- Správce účtu UltraDNS, který může vytvářet uživatele a nastavovat oprávnění.

## Nastavení UltraDNS

1. Přihlaste se do portálu UltraDNS (`portal.ultradns.com`) jako správce účtu.
2. **Accounts → Users → Add User**: vlastní uživatel pro acme (např. `acme-dns01`), dlouhé náhodné heslo. Druhý faktor u tohoto uživatele nezapínejte, pokud by blokoval přihlášení přes API (API používá jen jméno a heslo).
3. Vytvořte skupinu jen s právy, která acme potřebuje, a dejte do ní uživatele: **Accounts → Groups** → skupina s oprávněními na **záznamy** (vytvořit / změnit / smazat) v zónách, které smí acme měnit, a se čtením těchto zón. Nedávejte práva na účet, uživatele ani vytváření zón.
4. Nabízí-li váš účet omezení podle IP, omezte uživatele na adresu acme.

Volitelná kontrola:

```sh
curl -s -d 'grant_type=password&username=acme-dns01&password=HESLO' \
  https://api.ultradns.com/v1/authorization/token
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| User name | uživatel pro acme |
| Password | jeho heslo |
| Zone | prázdné (nejdelší zóna, kterou uživatel vidí a do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| API address | `https://api.ultradns.com` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše zóny, které uživatel vidí; nic nemění.
- Po objednávce: portál → **Zones →** zóna → záznamy: TXT RRset na `_acme-challenge…` dostane hodnotu acme a zase ji ztratí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / „invalid_grant“ při přihlášení | Špatné jméno nebo heslo, zamčený uživatel, nebo vyžadovaný druhý faktor. |
| Chyba 60001 „invalid token“ | Token vypršel - acme se přihlásí znovu sám; opakuje-li se to, zkontrolujte heslo. |
| `403` u POST/PUT | Skupině uživatele chybí vytvoření/změna/smazání záznamů v té zóně. |
| Zóna nenalezena | Jde o sekundární nebo alias zónu, nebo ji uživatel nevidí. |
