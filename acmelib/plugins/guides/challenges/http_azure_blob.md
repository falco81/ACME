# Azure Blob Storage (HTTP-01) - setup for acme

acme proves names by HTTP-01 by uploading the token file `.well-known/acme-challenge/TOKEN` to an Azure Storage container that serves the name - a **static website** (`$web` container) or a container behind Azure Front Door / CDN - and deletes it afterwards. The CA then fetches `http://NAME/.well-known/acme-challenge/TOKEN`. **Not for wildcards** (they need DNS-01).

## What you need

- A storage account whose blob container serves the site of the name (static website enabled, or a CDN / Front Door origin pointing at the container).
- The name pointing (CNAME / A) at that website or CDN, answering on **port 80** to the internet.
- Outbound HTTPS from acme to `ACCOUNT.blob.core.windows.net` (port 443).

## Set up Azure Storage

1. For a static website: Storage account → **Data management → Static website → Enabled**; this creates the `$web` container. Add the custom domain (via Front Door / CDN or the storage account's *Networking → Custom domain*).
2. Create the credential, the smaller choice first:
   - **SAS token** (recommended): the container `$web` → **Shared access tokens** → permissions **Read, Write, Create, Delete**, an expiry date (remember to renew), allowed IP = acme's public address, protocol HTTPS only → **Generate SAS token and URL** → copy the **token** (the part after `?`). An account SAS works too: service *Blob*, resource type *Object*, the same permissions.
   - Or the **account key**: Storage account → **Security + networking → Access keys** → key1 or key2 (full access to the account - avoid if you can).
3. Behind Azure Front Door or CDN: make sure `/.well-known/acme-challenge/*` is passed through over **HTTP** (no forced HTTPS redirect that breaks, and **no caching** for that path).
4. If the storage account's firewall is on (*Networking → Selected networks*), add acme's public address.

## Fill in acme

| acme field | What to put there |
|---|---|
| Storage account | The account name, e.g. `mysite` |
| Container | `$web` for a static website, or the container's name |
| Signs in with | `a SAS token` or `the account key (Shared Key)` |
| SAS token | The token (the part after `?`) |
| Account key | key1 or key2 (base64) |
| Folder in the container | Where the site's root is inside the container; empty = its root |
| Blob endpoint | (advanced) Empty = `https://ACCOUNT.blob.core.windows.net`; another Azure cloud: its own |
| Check before the CA is asked | `http://NAME/` (default), the address below, or no check |
| Address the folder is served at | (advanced) e.g. the static website's own address `https://mysite.z6.web.core.windows.net/` |

## Check it

- **Test** in acme uploads a probe file, reads it back and deletes it.
- From any machine on the internet, during a run (or with a file you put there):

  ```sh
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403 AuthorizationPermissionMismatch` | The SAS lacks Write/Create/Delete, or it expired. |
| `403 AuthorizationFailure` | The storage firewall blocks acme's address. |
| The probe works but the CA gets 404 | *Folder in the container* is wrong, or the name does not point at this container / CDN. |
| The CA gets an old answer | The CDN caches `/.well-known/acme-challenge/*` - exclude it from caching. |
