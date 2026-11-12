# CyberArk Certificate Manager Self-Hosted (Venafi TPP) - nastavení pro acme

Zdroj **CyberArk Certificate Manager Self-Hosted (Venafi TPP)** získává certifikáty z Venafi Trust Protection Platform (nyní CyberArk Certificate Manager, Self-Hosted) přes jeho REST API **WebSDK**: acme se přihlásí (`vedauth/authorize/oauth`, nebo tokenem vytvořeným v platformě), pošle své CSR do **policy složky** (`vedsdk/certificates/request`), vyzvedne certifikát, když ho CA platformy vydá (`vedsdk/certificates/retrieve`), obnovuje tentýž objekt certifikátu na místě (`vedsdk/certificates/renew`) a odvolává podle otisku. **Soukromý klíč nikdy neopustí acme.** *Import from a source* vypíše certifikáty složky; seznam složek pochází z `config/findobjectsofclass` (může potřebovat scope `configuration` - jinak složku napište). Žádost čekající na schválení se vyžádá znovu při dalším pokusu.

## Co potřebujete

- Adresu platformy dosažitelnou **z acme** přes HTTPS (`443`), s WebSDK.
- **API integraci** (aplikaci) - výchozí `vcert-sdk` - se scope `certificate:manage,revoke`, kterou smí používat uživatel acme.
- Uživatele pro acme s právy na policy složce (níže), nebo pro něj vytvořený přístupový token.
- Policy složku, jejíž politika povoluje **CSR dodané uživatelem**, s CA šablonou.

## Nastavení platformy

1. **API integrace** (Venafi Configuration Console / Aperture → **Platform → API → Integrations**, podle verze): použijte nebo vytvořte integraci s Application ID `vcert-sdk`, scopes **certificate: manage, revoke** (přidejte **configuration**, chcete-li *Load the list* složek) a přidejte uživatele acme do jejích *Allowed identities*. Poznamenejte si platnost tokenu / nastavení obnovy.
2. **Uživatel** pro acme (lokální nebo z AD), např. `svc-acme`.
3. **Policy složka**, např. `\VED\Policy\DevOps\Web servers`: v **Permissions** složky dejte `svc-acme` **View, Read, Write, Create** (a **Revoke** pro odvolání). S dědičností na objekty pod ní.
4. V politice složky (záložka **Certificate**): **CA Template**; *CSR Generation* musí povolit **User Provided CSR** (ne zamčené na *Service Generated*); povolené algoritmy a velikosti klíčů, které acme používá; whitelist domén zahrnující vaše jména.
5. Používá-li složka **schvalování** (workflow), acme čeká a ptá se znovu při dalších pokusech - schvalovatel musí schválit.

Ověření přihlášení:

```sh
curl -s https://tpp.example.local/vedauth/authorize/oauth -H 'Content-Type: application/json' \
  -d '{"client_id":"vcert-sdk","username":"svc-acme","password":"<password>","scope":"certificate:manage,revoke"}'
```

## Vyplnění v acme

Zdroje → **Přidat** → **CyberArk Certificate Manager Self-Hosted (Venafi TPP)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Platform address | `https://tpp.example.local` |
| Signing in | *User and password (an OAuth token made by acme)* nebo *An access token made in the platform* |
| User / Password | `svc-acme` a jeho heslo |
| Access token | token pro integraci s `certificate:manage,revoke` - vyměňte ho, než skončí |
| Policy folder | *Load the list* a vyberte složku |
| Policy folder typed (pokročilé) | `DevOps\Web servers` (pod `\VED\Policy`), kde seznam nejde načíst |
| CA template (CADN) (pokročilé) | prázdné: šablona složky |
| Name of the certificate object (pokročilé) | jak ho pojmenuje platforma (CN), nebo první jméno |
| Renew the same certificate object (pokročilé) | zapnuto |
| API application (client_id) / Scope of the token (pokročilé) | `vcert-sdk` / `certificate:manage,revoke` |
| Wait for the certificate (s) / Ask again every (s) (pokročilé) | `120` / `5` |
| CA certificate of the platform's TLS / Check the platform's TLS certificate (pokročilé) | pro privátní TLS certifikát |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `Identity/Self` - uživatel, kterým acme je.
- Po vydání: objekt certifikátu ve složce (strom Policy / inventář Aperture) s jeho historií.

## Časté problémy

| Problém | Řešení |
|---|---|
| `invalid_grant` / `unauthorized_client` | uživatel nesmí používat integraci `vcert-sdk`, nebo scope není povolen |
| `401` s přístupovým tokenem | token vypršel - vytvořte nový |
| `... does not have permission` při žádosti | View/Read/Write/Create na složce pro uživatele |
| `Load the list` odmítnuto | token nemá scope `configuration` - napište složku |
| *CSR ... not allowed* / *Service Generated* | povolte v politice složky CSR dodané uživatelem |
| Čeká a nikdy se nevydá | schvalování ve workflow, nebo selhává CA ze šablony - viz log objektu |
