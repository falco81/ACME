# Google Cloud Certificate Manager - nastavení pro acme

acme vkládá certifikát do Google Cloud Certificate Manager jako **self-managed certifikát**. První nasazení ho vytvoří (ID `acme-<jméno certifikátu>` nebo zadané); každé obnovení ho **aktualizuje na místě** (`PATCH …?updateMask=selfManaged`), takže certificate mapy a load balancery, které na něj ukazují, převezmou nový certifikát bez jakékoli změny z vaší strany. acme se přihlašuje klíčem service accountu (JSON) a čeká, než Google dokončí dlouhotrvající operaci.

## Co potřebujete

- Projekt Google Cloud se zapnutým **Certificate Manager API** (`certificatemanager.googleapis.com`).
- Load balancer, který používá certifikáty z Certificate Manageru (přes certificate mapu u globálních externích load balancerů, nebo přímo u regionálních).
- Service account s rolí **Certificate Manager Editor** (`roles/certificatemanager.editor`) na projektu a jeho JSON klíč.
- Přístup HTTPS z acme na `oauth2.googleapis.com` a `certificatemanager.googleapis.com` (port 443), přímo nebo přes proxy acme.

## Nastavení Google Cloud

Pomocí CLI `gcloud` (nebo totéž v konzoli: **IAM & Admin → Service accounts**):

```sh
PROJECT=my-project
gcloud services enable certificatemanager.googleapis.com --project "$PROJECT"

gcloud iam service-accounts create acme-certs --project "$PROJECT" \
    --display-name "acme certificate deployment"

gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:acme-certs@$PROJECT.iam.gserviceaccount.com" \
    --role roles/certificatemanager.editor

gcloud iam service-accounts keys create acme-certs.json \
    --iam-account "acme-certs@$PROJECT.iam.gserviceaccount.com"
```

**Soubor s klíčem držte v tajnosti**: vložte ho do acme a lokální kopii smažte. (Pokud vaše organizace klíče service accountů zakazuje, acme tento cíl použít nemůže.)

Po prvním nasazení certifikát jednou připojte k load balanceru, např. u globálního externího load balanceru s certificate mapou:

```sh
gcloud certificate-manager maps entries create www-entry --map my-map \
    --hostname www.example.com --certificates acme-www-example-com --project "$PROJECT"
```

Obnovení pak aktualizují tentýž certifikát; nic jiného se měnit nemusí.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Service account key (JSON) | celý soubor JSON s klíčem |
| Project ID | prázdné: projekt service accountu; nebo jiný projekt, kde má účet roli |
| Location | `global` pro globální externí load balancery; region (např. `europe-west3`) pro regionální |
| Through the proxy (pokročilé) | zapnuto, když acme dosáhne na Google jen přes Nastavení → Proxy |
| Timeout (s) (pokročilé) | 30 stačí |
| Certificate ID (nasazení) | `a-z`, `0-9` a `-`, začíná písmenem, nejvýš 63 znaků; prázdné: `acme-<jméno certifikátu>` |
| Description (nasazení, pokročilé) | popis certifikátu v Googlu (výchozí `kept by acme`) |
| Check what is served | `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme vypíše certifikáty projektu a lokace (`signed in to Certificate Manager (…), N certificates`).
- V Google Cloud:

```sh
gcloud certificate-manager certificates describe acme-www-example-com \
    --location global --project "$PROJECT" --format "value(expireTime,sanDnsnames)"
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 403 `PERMISSION_DENIED` | service account nemá `roles/certificatemanager.editor` na tom projektu, nebo API není zapnuté |
| `no project: set the Project ID` | klíč nemá `project_id`; vyplňte *Project ID* |
| `… is not a certificate ID` | jen malá písmena, číslice a `-`, na začátku písmeno |
| `the names differ from those of …` | Google při aktualizaci na místě chce stejné SAN; pro jiná jména použijte nové *Certificate ID* a změňte map entry |
| `Google has not finished after two minutes` | operace ještě běží; zkontrolujte ji v konzoli, další běh pokračuje |
| Load balancer podává starý certifikát | certifikát není připojen (map entry / target proxy); nebo je špatná lokace (`global` vs. region) |
