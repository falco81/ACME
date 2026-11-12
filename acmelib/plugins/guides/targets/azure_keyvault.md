# Azure Key Vault - setup for acme

acme imports the key and the full chain as a **new version of one Key Vault certificate**
(`POST https://<vault>.vault.azure.net/certificates/<name>/import?api-version=7.4`).
Whatever uses the certificate **without a version** - Application Gateway, App Service
(Key Vault references; syncs within 24 h or on *Sync*), Front Door, API Management - takes
the new one by itself. When the vault's current version already has the same SHA-1
thumbprint (`x5t`), nothing is imported. Old versions stay in the vault's history.

For Azure Key Vault (standard or premium) in Azure, Azure China or Azure US Government.

## What you need

- The vault's name or URL.
- Outbound HTTPS from acme to `login.microsoftonline.com` and
  `<vault>.vault.azure.net` (or the China / US Government equivalents).
- If the vault has a **firewall** (Networking → Firewalls and virtual networks): the acme
  server's public IP allowed.

## Set up Azure Key Vault

1. **Microsoft Entra ID → App registrations → New registration** (e.g. `acme-keyvault`).
   Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret**; copy the value (shown once).
3. Grant access on the vault - depending on its **permission model** (Access
   configuration):
   - **Azure RBAC**: **Access control (IAM) → Add role assignment → Key Vault
     Certificates Officer** for the app registration.

     ```sh
     az role assignment create --assignee <client-id> --role "Key Vault Certificates Officer" \
       --scope $(az keyvault show -n kv-firma --query id -o tsv)
     ```

   - **Vault access policy**: **Access policies → Create**, *Certificate permissions*:
     **Get, List, Import** - nothing else.

     ```sh
     az keyvault set-policy -n kv-firma --spn <client-id> --certificate-permissions get list import
     ```
4. Vault firewall: add the acme server's IP address (Networking → Firewall).

## Fill in acme

| acme field | What to put there |
|---|---|
| Key Vault | Its name (`kv-firma`) or URL (`https://kv-firma.vault.azure.net`) |
| Tenant (directory) ID | From step 1 |
| Client (application) ID | From step 1 |
| Client secret | From step 2 |
| Cloud (advanced) | Azure, Azure China (21Vianet) or Azure US Government |
| Certificate name in the vault (deploy) | Letters, digits and `-`, e.g. `www-example-com`; empty: `acme-<the certificate's name>` |
| Kept in the vault as (deploy) | `PEM` (default) or `PKCS#12` - **Application Gateway takes only PKCS#12** |
| Check what is served | The service that uses it, e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in to https://kv-firma.vault.azure.net, N certificates seen`.
- In Azure:

  ```sh
  az keyvault certificate show --vault-name kv-firma -n www-example-com --query "{x5t:x5t, expires:attributes.expires}"
  az keyvault certificate list-versions --vault-name kv-firma -n www-example-com -o table
  ```

## Common problems

| Problem | Fix |
|---|---|
| `AADSTS7000215` / invalid client secret | Wrong or expired secret |
| 403 `Forbidden` | Missing role / access policy (*Import*, *Get*, *List*) |
| 403 `ForbiddenByFirewall` | Add acme's IP to the vault's firewall |
| Application Gateway does not take it | Set *Kept in the vault as* to PKCS#12 |
| Services keep the old certificate | They reference a fixed version; reference it without a version (App Service: *Sync*) |
| Name refused | Only letters, digits and `-` are allowed |
