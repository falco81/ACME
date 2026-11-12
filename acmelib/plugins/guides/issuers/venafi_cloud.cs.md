# CyberArk Certificate Manager SaaS (Venafi Cloud) - nastavení pro acme

Zdroj **CyberArk Certificate Manager SaaS (Venafi Cloud)** získává certifikáty z CyberArk Certificate Manager, SaaS (Venafi as a Service / TLS Protect Cloud / Venafi Control Plane) přes jeho REST API: s **API klíčem** (hlavička `tppl-api-key`) acme najde **aplikaci** (`outagedetection/v1/applications/name/<app>`), pošle své CSR pro aplikaci a **issuing template** (`outagedetection/v1/certificaterequests`), počká, až je žádost `ISSUED`, a stáhne certifikát s řetězcem. Obnovení se žádá jako obnovení téhož certifikátu (`existingCertificateId`), takže služba zachová jeho historii. **Soukromý klíč nikdy neopustí acme.** *Import from a source* vyhledá certifikáty aplikace. **Odvolání se nenabízí** (služba ho dělá přes GraphQL) - odvolávejte ve webovém rozhraní.

## Co potřebujete

- Tenant v jednom regionu (US, EU, AU, UK, SG, CA) - jeho API host musí být dosažitelný **z acme** přes HTTPS (např. `api.venafi.cloud`, `api.eu.venafi.cloud`).
- **Aplikaci** s přiřazeným **issuing template** (s jeho API aliasem) a uživatele acme mezi **vlastníky** aplikace.
- **API klíč** uživatele.

## Nastavení služby

1. **Issuing template** (Policies → Issuing Templates): šablona na vaší CA (např. připojená Microsoft/DigiCert/vestavěná CA), která povoluje jména (omezení domén), typy klíčů, které acme používá (velikosti RSA / ECDSA), a platnost. Její generování klíčů musí povolit **CSR dodané žadatelem** (ne jen *Venafi-generated*).
2. **Aplikace** (Applications → New): např. `Storefront`; **Owners**: uživatel (nebo tým), za kterého acme jedná; **Issuing templates**: přidejte šablonu a poznamenejte si její **API alias** (např. `Default`).
3. **Uživatel pro acme** - nejlépe vyhrazený servisní uživatel / člen týmu s rolí *Resource Owner*, ne administrátor.
4. **API klíč**: přihlášeni jako tento uživatel, **vaše jméno → Preferences → API Keys** → zkopírujte (nebo vygenerujte) klíč. Patří uživateli: jeho práva jsou práva uživatele.

Ověření klíče:

```sh
curl -s -H "tppl-api-key: $VENAFI_KEY" https://api.venafi.cloud/v1/useraccounts
```

## Vyplnění v acme

Zdroje → **Přidat** → **CyberArk Certificate Manager SaaS (Venafi Cloud)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Region | region tenantu (US, EU, AU, UK, SG, CA) nebo *Another address* |
| API address | jen s *Another address* |
| API key | z kroku 4 |
| Application | `Storefront` - přesně jméno |
| Issuing template | *Load the list* (šablony aplikace podle API aliasu) a vyberte jednu |
| Issuing template typed (API alias) (pokročilé) | např. `Default`, kde seznam nejde načíst |
| Validity (days) | `0`: jak říká šablona; vlastní dny certifikátu mají přednost |
| Renew the same certificate (pokročilé) | zapnuto |
| Wait for the certificate (s) / Ask again every (s) (pokročilé) | `180` / `5` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `v1/useraccounts` - uživatel a firma.
- Po vydání: **Inventory → Certificates** ho ukáže pod aplikací.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | špatný API klíč, nebo špatný region (klíč funguje jen na API hostu svého tenantu) |
| Aplikace nenalezena | jméno se liší, nebo uživatel acme není mezi jejími vlastníky |
| Šablona nenalezena / nepovolena | šablona není přiřazena aplikaci; použijte její API alias |
| Žádost `FAILED` | viz zpráva: jméno mimo domény šablony, nepovolený typ klíče nebo platnost, selhávající konektor CA |
| CSR dodané uživatelem odmítnuto | povolte v issuing template CSR od žadatele |
| Je potřeba odvolání | proveďte ho ve webovém rozhraní - tento zdroj ho nenabízí |
