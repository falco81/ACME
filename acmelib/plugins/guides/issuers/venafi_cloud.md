# CyberArk Certificate Manager SaaS (Venafi Cloud) - setup for acme

The **CyberArk Certificate Manager SaaS (Venafi Cloud)** source gets certificates from CyberArk Certificate Manager, SaaS (Venafi as a Service / TLS Protect Cloud / Venafi Control Plane) through its REST API: with the **API key** (header `tppl-api-key`) acme finds the **application** (`outagedetection/v1/applications/name/<app>`), sends its CSR for the application and an **issuing template** (`outagedetection/v1/certificaterequests`), waits until the request is `ISSUED` and downloads the certificate with its chain. A renewal is asked as a renewal of the same certificate (`existingCertificateId`), so the service keeps its history. **The private key never leaves acme.** *Import from a source* searches the application's certificates. **Revocation is not offered** (the service does it through GraphQL) - revoke in the web interface.

## What you need

- A tenant in one region (US, EU, AU, UK, SG, CA) - its API host must be reachable **from acme** over HTTPS (e.g. `api.venafi.cloud`, `api.eu.venafi.cloud`).
- An **application** with an **issuing template** assigned (with its API alias), and the acme user among the application's **owners**.
- The user's **API key**.

## Set up the service

1. **Issuing template** (Policies → Issuing Templates): a template on your CA (e.g. a connected Microsoft/DigiCert/built-in CA) that allows the names (domain restrictions), the key types acme uses (RSA / ECDSA sizes), and the validity. Its key generation must allow a **CSR provided by the requester** (not only *Venafi-generated*).
2. **Application** (Applications → New): e.g. `Storefront`; **Owners**: the user (or team) acme acts as; **Issuing templates**: add the template and note its **API alias** (e.g. `Default`).
3. **A user for acme** - preferably a dedicated service user / team member with the *Resource Owner* role, not an administrator.
4. **API key**: signed in as that user, **your name → Preferences → API Keys** → copy (or generate) the key. It belongs to the user: its rights are the user's.

Check the key:

```sh
curl -s -H "tppl-api-key: $VENAFI_KEY" https://api.venafi.cloud/v1/useraccounts
```

## Fill in acme

Sources → **Add** → **CyberArk Certificate Manager SaaS (Venafi Cloud)**.

| acme field | What to put there |
|---|---|
| Region | the tenant's region (US, EU, AU, UK, SG, CA) or *Another address* |
| API address | only with *Another address* |
| API key | from step 4 |
| Application | `Storefront` - the name exactly |
| Issuing template | *Load the list* (the application's templates by API alias) and pick one |
| Issuing template typed (API alias) (advanced) | e.g. `Default`, where the list cannot be loaded |
| Validity (days) | `0`: as the template says; a certificate's own days win |
| Renew the same certificate (advanced) | on |
| Wait for the certificate (s) / Ask again every (s) (advanced) | `180` / `5` |

## Check it

- Sources → the source → **Test** (Try it): `v1/useraccounts` - the user and the company.
- After issuing: **Inventory → Certificates** shows it under the application.

## Common problems

| Problem | Fix |
|---|---|
| `401` | wrong API key, or the wrong region (a key works only on its tenant's API host) |
| Application not found | the name differs, or the acme user is not among its owners |
| Template not found / not allowed | the template is not assigned to the application; use its API alias |
| Request `FAILED` | see the message: a name outside the template's domains, a key type or validity not allowed, the CA connector failing |
| A user-provided CSR refused | allow CSRs from the requester in the issuing template |
| Revocation needed | do it in the web interface - not offered by this source |
