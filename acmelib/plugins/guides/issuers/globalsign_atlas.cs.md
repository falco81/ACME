# GlobalSign Atlas (HVCA) - nastavení pro acme

Zdroj **GlobalSign Atlas (HVCA)** získává veřejně důvěryhodné certifikáty z GlobalSign Atlas přes jeho HVCA (High Volume CA) API. Každé volání jde přes TLS s **mTLS klientským certifikátem** účtu; acme se přihlásí **API klíčem a tajemstvím** (`POST /login`), pošle `POST /certificates` se subjektem, SAN a svým CSR, pak čte `GET /certificates/<serial>`, dokud není vydán, a `GET /trustchain` pro řetězec. **Soukromý klíč nikdy neopustí acme.** Odvolání je `PATCH /certificates/<serial>`; *Import from a source* čte `/stats/issued` po 30 dnech. Jména musí být **ověřené domény** účtu - jiná Atlas odmítne. Duální (RSA + ECDSA) certifikát je druhá, placená objednávka, jen je-li povolena.

## Co potřebujete

- Účet GlobalSign Atlas s HVCA API (validační politika pro serverové TLS certifikáty).
- API URL účtu (např. `https://emea.api.hvca.globalsign.com:8443/v2`), **API klíč**, **API tajemství** a **mTLS certifikát s klíčem**.
- Domény daných jmen ověřené v Atlasu.
- Přístup HTTPS **z acme** na host API na portu `8443`, přímo nebo přes Nastavení → Proxy.

## Nastavení Atlasu

1. V portálu Atlas **API credentials** → vytvořte údaje pro acme: API klíč a tajemství a vygenerujte **mTLS certifikát** (s klíčem, nebo z vašeho CSR). Stáhněte certifikát a uschovejte klíč - oba patří do acme. Poznamenejte si API URL zobrazenou u účtu.
2. **Domains** → přidejte a **ověřte** každou doménu, pro kterou bude acme vydávat (DNS TXT, HTTP nebo e-mailem, jak Atlas nabízí). Wildcardy a subdomény pokrývá ověřená doména podle pravidel Atlasu.
3. Prohlédněte si **validační politiku** účtu (která pole subjektu jsou povinná nebo povolená, např. `organization`, `country`, maximální platnost) - *More of the subject* v acme musí dodat, co vyžaduje.
4. Kde to Atlas nabízí, omezte API údaje na zdrojovou IP acme.

Ověření mTLS spojení a údajů:

```sh
curl --cert atlas-mtls.pem --key atlas-mtls.key -H 'Content-Type: application/json' \
  -d '{"api_key":"<key>","api_secret":"<secret>"}' https://emea.api.hvca.globalsign.com:8443/v2/login
```

## Vyplnění v acme

Zdroje → **Přidat** → **GlobalSign Atlas (HVCA)**.

| Pole v acme | Co do něj zadat |
|---|---|
| API address | jak ji dal GlobalSign, s `/v2` (výchozí `https://emea.api.hvca.globalsign.com:8443/v2`) |
| API key / API secret | z kroku 1 |
| mTLS certificate / mTLS certificate's key | klientský certifikát účtu a jeho klíč (PEM) |
| Validity (days) | `0`: nejdelší, kterou politika dovolí; vlastní dny certifikátu mají přednost |
| More of the subject (pokročilé) | řádky `key=value`, které politika chce, např. `organization=Example s.r.o.`, `country=CZ` |
| Wait for the certificate (s) (pokročilé) | `60` |
| CA certificate of the API's TLS / Check the API's TLS certificate (pokročilé) | obvykle prázdné / zapnuto |
| Allow a second (paid) order for a dual certificate (pokročilé) | vypnuto, pokud nechcete dvojice ECDSA + RSA, každou placenou |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte validační politiku - nic neobjednává.
- V portálu Atlas se certifikát objeví mezi vydanými certifikáty účtu.

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba TLS handshaku před přihlášením | mTLS certifikát nebo klíč je špatný, vypršel, nebo nepatří účtu |
| `401` na `/login` | špatný API klíč / tajemství |
| Jméno odmítnuto | doména není v Atlasu ověřená (Domains) |
| Pole subjektu odmítnuto nebo chybí | upravte *More of the subject* podle validační politiky |
| Platnost odmítnuta | delší, než politika dovolí - použijte `0` |
| Certifikát není hotový | Atlas ho ještě vytváří (202/404); acme se zeptá znovu; zvyšte čekání |
