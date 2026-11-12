# Google Cloud CA Service - nastavení pro acme

Zdroj **Google Cloud CA Service** nechá vydávat certifikáty z CA poolu služby Google Cloud Certificate Authority Service (`privateca`, privátní CA): `POST .../locations/<l>/caPools/<pool>/certificates?certificateId=...` s CSR vytvořeným acme a dobou platnosti - **soukromý klíč nikdy neopustí acme**. Odvolání je `.../certificates/<id>:revoke`. *Try it* čte pool a `:fetchCaCerts`; seznam šablon pochází z `certificateTemplates`; *Import from a source* používá `certificates.list`. acme se přihlašuje **klíčem servisního účtu** (JSON), scope `cloud-platform`.

## Co potřebujete

- Projekt Google Cloud se zapnutým CA Service API (`privateca.googleapis.com`), **CA pool** a v něm zapnutou CA.
- Servisní účet pro acme s rolemi níže **na poolu** a jeho JSON klíč.
- Přístup HTTPS **z acme** na `privateca.googleapis.com` a `oauth2.googleapis.com` (port 443), přímo nebo přes Nastavení → Proxy.

## Nastavení Google Cloud

1. Servisní účet:

   ```sh
   gcloud iam service-accounts create acme-cas --project=p1 --display-name="acme"
   ```

2. Role na CA poolu (ne na celém projektu):

   ```sh
   SA=acme-cas@p1.iam.gserviceaccount.com
   gcloud privateca pools add-iam-policy-binding tls-pool --location=europe-west3 --project=p1 \
     --member="serviceAccount:$SA" --role=roles/privateca.certificateRequester
   # pro odvolání (a čtení certifikátů poolu pro Import):
   gcloud privateca pools add-iam-policy-binding tls-pool --location=europe-west3 --project=p1 \
     --member="serviceAccount:$SA" --role=roles/privateca.certificateManager
   ```

   *CA Service Certificate Requester* vydává; *CA Service Certificate Manager* navíc odvolává. Se **šablonou certifikátu** udělte na šablonu i *CA Service Template User* (`roles/privateca.templateUser`). Pokud *Try it* nebo *Load the list* odmítne přístup, přidejte pro čtení *CA Service Auditor* (`roles/privateca.auditor`).
3. Klíč: **IAM & Admin → Service accounts → acme-cas → Keys → Add key → Create new key → JSON**, nebo

   ```sh
   gcloud iam service-accounts keys create acme-cas.json --iam-account=$SA
   ```

   Pokud vaše organizace klíče zakazuje (`iam.disableServiceAccountKeyCreation`), je pro tento účet potřeba výjimka.
4. Politika vydávání poolu rozhoduje, co se podepíše (povolené SAN, typy klíčů, maximální platnost).

## Vyplnění v acme

Zdroje → **Přidat** → **Google Cloud CA Service**.

| Pole v acme | Co do něj zadat |
|---|---|
| Service account key (JSON) | celý JSON soubor z kroku 3 |
| Project ID | `p1`; prázdné: projekt servisního účtu |
| Location | např. `europe-west3` |
| CA pool | např. `tls-pool` |
| CA in the pool (pokročilé) | id CA, ze které se vydává; prázdné: vybere Google |
| Certificate template (pokročilé) | její plné jméno `projects/P/locations/L/certificateTemplates/T` - *Load the list*; vlastní šablona certifikátu má přednost |
| Validity (days) | `90` (výchozí); vlastní dny certifikátu mají přednost; politika poolu ji může omezit |

## Ověření

- Zdroje → zdroj → **Test** (Try it): pool a jeho certifikáty CA.
- Se stejnou identitou:

```sh
gcloud auth activate-service-account --key-file=acme-cas.json
gcloud privateca pools describe tls-pool --location=europe-west3 --project=p1
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403 PERMISSION_DENIED` při vytvoření | na tom poolu chybí role (nebo oprávnění používat šablonu) |
| `403` při odvolání | udělte *CA Service Certificate Manager* |
| `invalid_grant` při přihlášení | klíč byl smazán/zakázán, nebo jdou hodiny acme špatně |
| `FAILED_PRECONDITION` | v poolu není zapnutá CA, nebo zadané id CA není zapnuté |
| Jméno nebo platnost odmítnuty | nepovoluje to politika vydávání poolu nebo šablona |
| API není zapnuté | `gcloud services enable privateca.googleapis.com --project=p1` |
