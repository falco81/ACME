# Google Cloud CA Service - setup for acme

The **Google Cloud CA Service** source has certificates issued by a CA pool of Google Cloud Certificate Authority Service (`privateca`, private CAs): `POST .../locations/<l>/caPools/<pool>/certificates?certificateId=...` with the CSR acme made and the lifetime - **the private key never leaves acme**. Revocation is `.../certificates/<id>:revoke`. *Try it* reads the pool and `:fetchCaCerts`; the template list comes from `certificateTemplates`; *Import from a source* uses `certificates.list`. acme signs in with a **service account key** (JSON), scope `cloud-platform`.

## What you need

- A Google Cloud project with the CA Service API (`privateca.googleapis.com`) enabled, a **CA pool** and an enabled CA in it.
- A service account for acme with the roles below **on the pool**, and a JSON key of it.
- HTTPS access **from acme** to `privateca.googleapis.com` and `oauth2.googleapis.com` (port 443), directly or through Settings → Proxy.

## Set up Google Cloud

1. The service account:

   ```sh
   gcloud iam service-accounts create acme-cas --project=p1 --display-name="acme"
   ```

2. Roles on the CA pool (not on the whole project):

   ```sh
   SA=acme-cas@p1.iam.gserviceaccount.com
   gcloud privateca pools add-iam-policy-binding tls-pool --location=europe-west3 --project=p1 \
     --member="serviceAccount:$SA" --role=roles/privateca.certificateRequester
   # to revoke (and read the pool's certificates for Import):
   gcloud privateca pools add-iam-policy-binding tls-pool --location=europe-west3 --project=p1 \
     --member="serviceAccount:$SA" --role=roles/privateca.certificateManager
   ```

   *CA Service Certificate Requester* issues; *CA Service Certificate Manager* also revokes. With a **certificate template**, also grant *CA Service Template User* (`roles/privateca.templateUser`) on the template. If *Try it* or *Load the list* is refused, add *CA Service Auditor* (`roles/privateca.auditor`) for reading.
3. The key: **IAM & Admin → Service accounts → acme-cas → Keys → Add key → Create new key → JSON**, or

   ```sh
   gcloud iam service-accounts keys create acme-cas.json --iam-account=$SA
   ```

   If your organization forbids keys (`iam.disableServiceAccountKeyCreation`), an exception is needed for this account.
4. The pool's issuance policy decides what is signed (allowed SANs, key types, maximum lifetime).

## Fill in acme

Sources → **Add** → **Google Cloud CA Service**.

| acme field | What to put there |
|---|---|
| Service account key (JSON) | the whole JSON file from step 3 |
| Project ID | `p1`; empty: the service account's project |
| Location | e.g. `europe-west3` |
| CA pool | e.g. `tls-pool` |
| CA in the pool (advanced) | a CA id to issue from; empty: Google chooses |
| Certificate template (advanced) | its full name `projects/P/locations/L/certificateTemplates/T` - *Load the list*; a certificate's own template wins |
| Validity (days) | `90` (default); a certificate's own days win; the pool's policy may cap it |

## Check it

- Sources → the source → **Test** (Try it): the pool and its CA certificates.
- With the same identity:

```sh
gcloud auth activate-service-account --key-file=acme-cas.json
gcloud privateca pools describe tls-pool --location=europe-west3 --project=p1
```

## Common problems

| Problem | Fix |
|---|---|
| `403 PERMISSION_DENIED` on create | the role is missing on that pool (or the template use permission) |
| `403` on revoke | grant *CA Service Certificate Manager* |
| `invalid_grant` when signing in | the key was deleted/disabled, or acme's clock is off |
| `FAILED_PRECONDITION` | no enabled CA in the pool, or the CA id given is not enabled |
| Name or lifetime refused | the pool's issuance policy or the template does not allow it |
| API not enabled | `gcloud services enable privateca.googleapis.com --project=p1` |
