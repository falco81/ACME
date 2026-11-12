# Google Cloud DNS - setup for acme

acme proves names by DNS-01 in a Google Cloud DNS **public** managed zone: it signs in as a service account (a JSON key, a JWT signed RS256 by openssl), reads the TXT record set `_acme-challenge.NAME`, and submits one atomic change that replaces the set with its value added (or, on cleanup, taken away). If someone changes the set meanwhile, the change fails rather than losing their value. Private zones are not used.

## What you need

- A public managed zone in Cloud DNS, with the domain delegated to its Google name servers.
- A Google Cloud project where you can create a service account and grant roles.
- Outbound HTTPS from acme to `oauth2.googleapis.com` and `dns.googleapis.com` (port 443).
- `openssl` on the acme machine (it signs the token request).

## Set up Google Cloud

1. **IAM & Admin → Service accounts → Create service account**: e.g. `acme-dns01`.
2. Grant it the role **DNS Administrator** (`roles/dns.admin`) on the project. For least access, create a custom role instead with: `dns.managedZones.list`, `dns.resourceRecordSets.list`, `dns.changes.create`, `dns.changes.get`, `dns.resourceRecordSets.create`, `dns.resourceRecordSets.update`, `dns.resourceRecordSets.delete`.
3. The service account → **Keys → Add key → Create new key → JSON**. Keep the downloaded file safe - it is the credential.
4. With gcloud:

   ```sh
   gcloud iam service-accounts create acme-dns01 --project my-project
   gcloud projects add-iam-policy-binding my-project \
     --member serviceAccount:acme-dns01@my-project.iam.gserviceaccount.com --role roles/dns.admin
   gcloud iam service-accounts keys create acme-dns01.json \
     --iam-account acme-dns01@my-project.iam.gserviceaccount.com
   ```

   (If your organization blocks key creation by policy, an admin must allow it for this account.)

## Fill in acme

| acme field | What to put there |
|---|---|
| Service account key (JSON) | The whole JSON key file, pasted |
| Project ID | The project of the zone; empty = the service account's project |
| Managed zone | The zone's **name** in Cloud DNS (e.g. `example-com`), not the domain; empty = found by the domain |
| TTL (s) | (advanced) Default `60` |

## Check it

- **Test** in acme signs in and lists the managed zones of the project. It changes nothing.
- With gcloud:

  ```sh
  gcloud dns managed-zones list --project my-project
  gcloud dns record-sets list --zone example-com --name _acme-challenge.example.com. --type TXT
  ```

## Common problems

| Problem | Fix |
|---|---|
| `invalid_grant` / JWT errors | The key was deleted or the acme machine's clock is off. |
| `403 Forbidden` | The service account lacks the role on that project, or *Project ID* points elsewhere. |
| No zone found | The zone is private, or in another project - set *Project ID* / *Managed zone*. |
| The change fails now and then | Another tool changed the same record set meanwhile; the next try reads it again. |
