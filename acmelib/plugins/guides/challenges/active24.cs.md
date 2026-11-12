# Active24 - nastavení pro acme

acme prokazuje jména přes DNS-01 u Active24: do DNS domény přidá záznam TXT `_acme-challenge.JMÉNO` přes **REST API v2** Active24 (`rest.active24.cz`, české a slovenské Active24 na platformě Websupport) a poté smaže jen svůj vlastní záznam. Staré Active24 API (`api.active24.com`, token) lze stále vybrat, ale podle Active24 od přechodu na novou platformu nefunguje.

## Co potřebujete

- Doménu, jejíž DNS je u Active24 (služba DNS domény v administraci).
- Přístup do administrace Active24 pro vygenerování klíče API.
- Odchozí HTTPS z acme na `rest.active24.cz` (port 443).

## Nastavení Active24

1. Přihlaste se do administrace Active24.
2. Přejděte na **(vaše jméno) → Zabezpečení a přihlášení → Přístup přes API → Vygenerovat nový přístup** (v anglické administraci *Security and login → API access → Generate new access*).
3. Zkopírujte **identifikátor** (klíč API) a **secret**. Secret se zobrazí jen jednou - bezpečně ho uložte.
4. Pokud administrace umožňuje přístup omezit (podle IP adresy nebo služby), povolte veřejnou IP adresu acme a službu DNS domény. Klíč jedná za váš účet, proto pokud to jde, použijte samostatného uživatele účtu.
5. Volitelně si poznamenejte **ID služby** domény - číslo v adrese stránky domény v administraci. acme ho obvykle najde v seznamu služeb; vyplňte ho, když ne.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API | `REST API v2 - rest.active24.cz` (to, které funguje) |
| API key | Identifikátor z *Přístup přes API* |
| API secret | Secret z *Přístup přes API* |
| API token | Jen pro staré *Active24 API* (`api.active24.com`) |
| Domain | Doména, např. `example.cz`; prázdné = nejdelší doména účtu, ve které jméno leží |
| Service ID | (pokročilé) Číslo služby domény; prázdné = najde se v seznamu služeb |
| TTL (s) | (pokročilé) Výchozí `600` |
| API address | (pokročilé) Prázdné = `https://rest.active24.cz` |

## Kontrola

- **Test** v acme se zeptá na `/v2/check` (jsou klíč a secret přijaty?) a pak vypíše domény - nebo při vyplněném *Service ID* přečte záznamy TXT té služby. Nikdy nic nemění.
- Po běhu ověřte záznam na autoritativních jmenných serverech:

  ```sh
  dig +short NS example.cz
  dig +short TXT _acme-challenge.example.cz @<jeden z těchto serverů>
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Active24 did not take the API key and secret (/v2/check: not verified)` | Špatný klíč nebo secret, nebo nesedí čas serveru (požadavky se podepisují časem) - zkontrolujte NTP na stroji s acme. |
| Doména se nenajde | Vyplňte přesně *Domain*, a pokud to nepomůže, i její *Service ID*. |
| `401` se starým API | Platforma `api.active24.com` už nefunguje - přepněte *API* na REST API v2 s klíčem a secretem. |
| CA záznam nevidí | Jmenné servery Active24 bývají pomalé; zvyšte *Wait at least (seconds)*. |
