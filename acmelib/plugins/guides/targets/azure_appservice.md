# Azure App Service - setup for acme

acme talks to **Azure Resource Manager** (`api-version=2023-12-01`) with the token of an
app registration. It uploads the certificate as a PKCS#12 (with a one-time password) as a
certificate of the resource group under a dated name, in the web app's region and App
Service plan (`PUT .../Microsoft.Web/certificates/<name>`), then binds each **custom
hostname** of the web app - those you list, or every one the certificate covers (not
`*.azurewebsites.net`) - to it with **SNI SSL**. Older acme certificates of the resource
group beyond *keep* are deleted; Azure refuses one still bound, and it stays.

For Azure App Service web apps (production slot; deployment slots are not handled) on a
plan that supports custom TLS certificates (Basic and higher), in Azure, Azure China or
Azure US Government.

## What you need

- Subscription ID, resource group and name of the web app.
- The custom hostnames already **added and verified** on the app (acme binds, it does not
  add hostnames).
- Outbound HTTPS from acme to `login.microsoftonline.com` and `management.azure.com`.

## Set up Azure

1. **Microsoft Entra ID → App registrations → New registration** (e.g.
   `acme-appservice`). Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret**; copy the value (shown once).
3. Assign roles to the app registration (**Access control (IAM) → Add role assignment**):
   - **Website Contributor** on the web app(s),
   - **Web Plan Contributor** on their App Service plan,
   - or simply **Contributor** on the resource group.

   ```sh
   az role assignment create --assignee <client-id> --role "Website Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>
   az role assignment create --assignee <client-id> --role "Web Plan Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/serverfarms/<plan>
   ```

   Certificates are created in the resource group, so if uploading fails with 403, use
   *Contributor* on the resource group.

## Fill in acme

| acme field | What to put there |
|---|---|
| Subscription ID | The subscription's GUID |
| Resource group | The resource group of the web apps (their certificates are kept there) |
| Tenant (directory) ID | From step 1 |
| Client (application) ID | From step 1 |
| Client secret | From step 2 |
| Cloud (advanced) | Azure, Azure China (21Vianet) or Azure US Government |
| Web app (deploy) | The App Service web app's name, e.g. `app-www` |
| Hostnames (deploy) | One a line; empty: each custom hostname the certificate covers |
| PKCS#12 kind (deploy, advanced) | `3DES` (as App Service documents it, default) or `AES-256` |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `www.example.com:443` |

**Discover** (the form) lists the resource groups that hold App Service certificates.

## Check it

- **Try**: `signed in to Azure; N App Service certificates in <rg>`.
- In Azure (**web app → Certificates / Custom domains**) or:

  ```sh
  az webapp config hostname list -g <rg> --webapp-name <app> -o table
  az webapp config ssl list -g <rg> -o table
  ```

## Common problems

| Problem | Fix |
|---|---|
| `AADSTS7000215` / invalid client secret | Wrong or expired secret |
| 403 on `certificates/<name>` | Missing *Web Plan Contributor* / *Contributor* on the resource group |
| 403 on `hostNameBindings` | Missing *Website Contributor* on the web app |
| Hostname not bound | It is not a custom hostname of the app, or the certificate does not cover it |
| Older certificate not deleted | Still bound somewhere; it stays until unbound |
| Plan does not support SSL | Scale the plan to Basic or higher |
