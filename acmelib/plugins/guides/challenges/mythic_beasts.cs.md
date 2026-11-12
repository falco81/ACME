# Mythic Beasts - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně hostované u Mythic Beasts (Velká Británie), přes jejich **DNS API v2** (`https://api.mythic-beasts.com/dns/v2`). Pomocí ID a tajemství API klíče získá krátkodobý token z `https://auth.mythic-beasts.com/login` (OAuth2 client credentials), vypíše zóny, přidá TXT hodnotu na `_acme-challenge.JMÉNO` a potom odebere přesně tuto hodnotu (`DELETE .../TXT?data=HODNOTA`), takže ostatní hodnoty na jméně zůstanou.

## Co potřebujete

- Doménu, jejíž DNS hostuje Mythic Beasts.
- HTTPS (TCP 443) z acme na `auth.mythic-beasts.com` a `api.mythic-beasts.com`.

## Nastavení Mythic Beasts

1. Přihlaste se do **ovládacího panelu** Mythic Beasts.
2. Otevřete **API keys** a vytvořte nový klíč, např. `acme`.
3. Dejte klíči přístup **DNS API** k zónám, které smí acme měnit. Úžeji (doporučeno) ho omezte na
   - záznamy, jejichž host odpovídá `_acme-challenge` (a `_acme-challenge.*` pro jména pod vrcholem zóny),
   - typ záznamu **TXT**.
4. Uložte a zkopírujte **key ID** a **secret** - secret se zobrazí jen jednou.

Volitelná kontrola:

```sh
curl -u 'KEYID:SECRET' -d grant_type=client_credentials https://auth.mythic-beasts.com/login
# {"access_token":"...","expires_in":...}
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key ID | ID klíče |
| API secret | secret |
| Zone | prázdné (nejdelší zóna, kterou klíč vidí a do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| API address / Sign-in address | ponechte výchozí (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše zóny, které klíč vidí; nic nemění.
- Po objednávce: ovládací panel → **DNS** → zóna: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.co.uk @ns1.mythic-beasts.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatné key ID nebo secret, nebo byl klíč smazán. |
| `403` u záznamu | Oprávnění klíče nepokrývá tuto zónu, host nebo typ - rozšiřte ho (TXT na `_acme-challenge…`). |
| Zóna není ve výpisu | Klíč k zóně nemá přístup, nebo je zóna v jiném účtu. |
