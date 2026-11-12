# ZeroSSL (REST API) - nastavení pro acme

Zdroj **ZeroSSL (REST API)** získává certifikáty od ZeroSSL přes jeho REST API (`https://api.zerossl.com`), ne ACME: acme vytvoří certifikát s vlastním CSR (`POST /certificates`), důkaz **ověření domény (DCV)** umístí pomocí validace certifikátu - DNS CNAME (`CNAME_CSR_HASH`), HTTP soubor v `/.well-known/pki-validation/` (`HTTP_CSR_HASH`) - nebo nechá ZeroSSL poslat schvalovací e-mail, požádá ZeroSSL o ověření, počká na stav `issued` a stáhne certifikát s CA bundle. **Soukromý klíč nikdy neopustí acme.** Odvolání je `POST /certificates/{id}/revoke`; *Import from a source* vypíše certifikáty účtu. Pro ZeroSSL přes ACME (bezplatné 90denní certifikáty s EAB) použijte místo toho předvolbu *ZeroSSL* zdroje ACME; tento zdroj je pro tarif účtu, jak ho ukazuje dashboard: roční certifikáty, kde je tarif prodává, DCV e-mailem. Žádné IP adresy.

## Co potřebujete

- Účet ZeroSSL s **tarifem**, který certifikáty pokryje (počet certifikátů, více domén, wildcard, roční).
- **API access key** účtu.
- Přístup HTTPS **z acme** na `api.zerossl.com:443`, přímo nebo přes Nastavení → Proxy.
- Validaci v acme, která umí umístit důkaz DCV: DNS poskytovatele (záznamy CNAME) nebo HTTP (port 80 každého jména dosažitelný z internetu; bez wildcardů) - nebo člověka, který čte schvalovací schránku (e-mail).
- Záznamy `CAA`, pokud je doména má, povolující `sectigo.com` (ZeroSSL vydává z CA Sectiga).

## Nastavení ZeroSSL

1. Přihlaste se do dashboardu ZeroSSL → **Developer** → zkopírujte **API access key** (*Reset key* vytvoří nový a starý zneplatní).
2. Zkontrolujte tarif (**Billing / Plans**): bezplatné tarify mají malou kvótu 90denních certifikátů a žádné multi-domain/wildcard; zvolte tarif, který vyhovuje.
3. Pro DCV e-mailem ověřte, že pro každou doménu existuje schvalovací adresa (`admin@`, `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@`).
4. Kde se používá CAA, povolte CA v DNS:

   ```text
   example.com.  CAA 0 issue "sectigo.com"
   ```

Ověření klíče:

```sh
curl -s -H "Authorization: ApiKey $ZEROSSL_KEY" 'https://api.zerossl.com/certificates?limit=1'
```

## Vyplnění v acme

Zdroje → **Přidat** → **ZeroSSL (REST API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| API key | z kroku 1 |
| How the API key is sent | *In the header Authorization: ApiKey* (výchozí); parametr `access_key` jen pro starší účet, který ho stále chce |
| Validity | `90 days`; *Annual - 200* jen tam, kde tarif prodává roční certifikáty |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (bez wildcardů) nebo *E-mail* |
| Approver mailbox | s e-mailem: `admin@` ... nebo první, kterou ZeroSSL nabídne |
| API address (pokročilé) | `https://api.zerossl.com` |
| Wait for the certificate / Wait for the DCV record to be visible / Ask again every (s) (pokročilé) | `600` / `300` / `15` |

Validace certifikátu musí umět umístit zvolený důkaz: DNS validace pro CNAME, HTTP validace pro soubor.

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte účet - nic neobjednává.
- V dashboardu certifikát přechází *Draft → Pending validation → Issued*.

## Časté problémy

| Problém | Řešení |
|---|---|
| `invalid_access_key` / `missing_access_key` | špatný klíč, nebo se klíč posílá jinak - přepněte *How the API key is sent* |
| `domain_control_validation_failed` | CNAME / soubor ještě nebyl vidět; acme ověří znovu při dalším pokusu - zkontrolujte záznam ve veřejném DNS |
| Chyba kvóty nebo tarifu (`certificate_limit_reached`, ...) | limit tarifu - povyšte tarif nebo odstraňte koncepty |
| Wildcard s HTTP DCV odmítnut | pro wildcardy použijte CNAME (DNS) |
| Chyba CAA | povolte `sectigo.com` v CAA |
| Ověření e-mailem nikdy neskončí | nikdo e-mail neschválil - zkontrolujte schvalovací schránku |
