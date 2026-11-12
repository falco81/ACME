# Technitium DNS Server - nastavení pro acme

acme prokazuje jména metodou DNS-01 v primární zóně **Technitium DNS Serveru**, přes jeho HTTP API (formulářové POSTy s API tokenem): `/api/zones/list`, `/api/zones/records/get`, `/api/zones/records/add` (typ TXT) a `/api/zones/records/delete` s hodnotou - odebere se jen hodnota acme; ostatní TXT hodnoty na jménu zůstanou.

## Co potřebujete

- Technitium DNS Server (verzi s API tokeny a oprávněními na zóny), který je pro zónu autoritativní (je tam zónou typu **Primary**).
- HTTP(S) z acme na webovou konzoli: `http://HOST:5380` nebo `https://HOST:53443`.

## Nastavení Technitia

1. Přihlaste se do webové konzole jako administrátor.
2. **Administration → Users → Add User**: uživatel `acme`, dlouhé náhodné heslo. Nedávejte ho do skupiny *Administrators*.
3. Dejte mu **Modify** na zóny, které smí acme měnit: **Zones →** zóna → **Permissions** (nebo **Administration → Permissions → Zones**) → přidejte uživatele `acme` s *View* a *Modify*.
4. Vytvořte pro tohoto uživatele token: **Administration → Sessions → Create Token** → uživatel `acme`, název tokenu `acme`. (Nebo se přihlaste jako `acme` a použijte *váš uživatel* → **Create API Token**.) Token zkopírujte - zobrazí se jednou.
5. Přístup na port konzole omezte na acme a své administrátory (firewall) a dejte přednost HTTPS (**Settings → Web Service → Enable HTTPS**).

Volitelná kontrola:

```sh
curl -s 'https://dns.example.local:53443/api/zones/list?token=TOKEN'
# {"response":{"zones":[...]},"status":"ok"}
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Server address | `https://dns.example.local:53443` (nebo `http://HOST:5380`) |
| API token | token |
| Zone | prázdné (nejdelší primární zóna serveru, do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| Check the server's certificate | zapnuto; vypněte jen u self-signed certifikátu konzole (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše zóny, které token vidí; nic nemění.
- Po objednávce: webová konzole → **Zones →** zóna: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @dns.example.local
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `invalid-token` | Token je špatný nebo smazaný - vytvořte nový. |
| „Access was denied“ při přidání | Uživatel nemá na zóně **Modify**. |
| Zóna nenalezena | Jde o sekundární/stub/forwarder zónu - acme zapisuje jen do primárních zón. |
| Chyba certifikátu | Self-signed certifikát konzole: nasaďte řádný, nebo kontrolu vypněte. |
