# Google Cloud Certificate Manager - setup for acme

acme puts the certificate into Google Cloud Certificate Manager as a **self-managed certificate**. The first deployment creates it (ID `acme-<certificate name>` or the one you give); every renewal **updates it in place** (`PATCH …?updateMask=selfManaged`), so the certificate maps and load balancers that point at it take the new certificate without any change on your side. acme signs in with a service account key (JSON) and waits for Google's long-running operation to finish.

## What you need

- A Google Cloud project with the **Certificate Manager API** (`certificatemanager.googleapis.com`) enabled.
- A load balancer that uses Certificate Manager certificates (through a certificate map for global external load balancers, or directly for regional ones).
- A service account with the role **Certificate Manager Editor** (`roles/certificatemanager.editor`) on the project, and a JSON key of it.
- HTTPS access from acme to `oauth2.googleapis.com` and `certificatemanager.googleapis.com` (port 443), directly or through acme's proxy.

## Set up Google Cloud

With the `gcloud` CLI (or the same in the console: **IAM & Admin → Service accounts**):

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

**Keep the key file secret**: paste it into acme and delete the local copy. (If your organisation forbids service account keys, acme cannot use this target.)

After the first deployment, attach the certificate once to your load balancer, e.g. for a global external load balancer with a certificate map:

```sh
gcloud certificate-manager maps entries create www-entry --map my-map \
    --hostname www.example.com --certificates acme-www-example-com --project "$PROJECT"
```

Renewals then update the same certificate; nothing else has to change.

## Fill in acme

| acme field | What to put there |
|---|---|
| Service account key (JSON) | the whole JSON key file |
| Project ID | empty: the project of the service account; or another project where the account has the role |
| Location | `global` for global external load balancers; a region (e.g. `europe-west3`) for regional ones |
| Through the proxy (advanced) | on when acme reaches Google only through Settings → Proxy |
| Timeout (s) (advanced) | 30 is fine |
| Certificate ID (deployment) | `a-z`, `0-9` and `-`, starting with a letter, at most 63; empty: `acme-<certificate name>` |
| Description (deployment, advanced) | the certificate's description in Google (default `kept by acme`) |
| Check what is served | `www.example.com:443`, one a line |

## Check it

- **Test** in acme lists the certificates of the project and location (`signed in to Certificate Manager (…), N certificates`).
- In Google Cloud:

```sh
gcloud certificate-manager certificates describe acme-www-example-com \
    --location global --project "$PROJECT" --format "value(expireTime,sanDnsnames)"
```

## Common problems

| Problem | Fix |
|---|---|
| 403 `PERMISSION_DENIED` | the service account lacks `roles/certificatemanager.editor` on that project, or the API is not enabled |
| `no project: set the Project ID` | the key has no `project_id`; fill in *Project ID* |
| `… is not a certificate ID` | use only lowercase letters, digits and `-`, starting with a letter |
| `the names differ from those of …` | Google asks for the same SANs on an in-place update; for other names use a new *Certificate ID* and change the map entry |
| `Google has not finished after two minutes` | the operation is still running; check it in the console, the next run continues |
| The load balancer still serves the old certificate | the certificate is not attached (map entry / target proxy); or the location is wrong (`global` vs a region) |
