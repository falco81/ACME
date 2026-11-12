# Azure Application Gateway - setup for acme

acme talks to **Azure Resource Manager** (`api-version=2026-03-01`) with the token of an
app registration (Microsoft Entra, client credentials). The gateway's certificates and
listeners have no API calls of their own, so acme **reads the whole gateway, changes it
and PUTs it back**, then waits until `provisioningState` is no longer `Updating`:

- **Uploaded** (default): the PKCS#12 with its chain goes into `sslCertificates` under a
  dated name (`acme-<name>-<date>-<serial>`), or - with *Name on the gateway* - replaces
  that one certificate in place.
- **From Key Vault**: an entry pointing at a Key Vault secret **without a version**; the
  gateway takes each new version itself. acme then only changes the gateway's tags
  (`PATCH {"tags"}`) so it looks in the vault at once instead of within four hours.

The listeners you name (and every listener that used an older acme certificate of this
one) are switched to the new certificate; older acme certificates no listener uses are
taken out in the same PUT.

For Application Gateway v2 (Standard_v2 / WAF_v2) in Azure, Azure China or Azure US
Government.

## What you need

- Subscription ID, resource group and name of the gateway; its HTTPS (or TLS) listeners.
- Outbound HTTPS from acme to `login.microsoftonline.com` and `management.azure.com`
  (or the China / US Government equivalents).
- For *From Key Vault*: an `azure_keyvault` deployment of the same certificate (run it
  **first**, with *Kept in the vault as* = PKCS#12) and a **user-assigned managed
  identity** on the gateway allowed to read the vault's secrets.

## Set up Azure

1. **Microsoft Entra ID → App registrations → New registration** (e.g. `acme-appgw`).
   Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret**; copy the value (shown once).
3. On the gateway: **Access control (IAM) → Add role assignment → Network Contributor**
   for the app registration. With the Azure CLI:

   ```sh
   az role assignment create --assignee <client-id> --role "Network Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/applicationGateways/<gw>
   ```

   A PUT of the gateway also checks the linked resources; if it fails with
   `LinkedAuthorizationFailed`, grant *Network Contributor* on the gateway's subnet /
   virtual network and public IP too (or on the resource group).
4. Key Vault only: give the app registration **Managed Identity Operator** on the
   gateway's managed identity, and the identity **Key Vault Secrets User** on the vault
   (or an access policy *Secrets: Get*).
5. If the vault has a firewall, allow trusted Microsoft services (the gateway) through it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Subscription ID | The subscription's GUID |
| Resource group | The resource group of the application gateways |
| Tenant (directory) ID | From step 1 |
| Client (application) ID | From step 1 |
| Client secret | From step 2 |
| Cloud (advanced) | Azure, Azure China (21Vianet) or Azure US Government |
| Application gateway (deploy) | The gateway's name, e.g. `agw-www` |
| Listener (deploy) | An HTTPS/TLS listener, picked from the list (*Load the list*) or typed |
| More listeners (deploy) | One a line; none: the listeners that used an older acme certificate are switched |
| The certificate goes (deploy) | `uploaded (PKCS#12 with its chain)` or `from Key Vault` |
| Key Vault secret ID (deploy) | `https://kv-firma.vault.azure.net/secrets/acme-www-example-com/` - **without a version** |
| Name on the gateway (deploy) | Empty: a new dated name each time; set: that one certificate, replaced in place |
| PKCS#12 kind (deploy, advanced) | `3DES` (default) or `AES-256` |
| Wait for the gateway (s) (deploy, advanced) | Default 1800 - a gateway update can take many minutes |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in to Azure; N application gateways in <rg>: ...`.
- In Azure:

  ```sh
  az network application-gateway ssl-cert list -g <rg> --gateway-name <gw> -o table
  az network application-gateway show -g <rg> -n <gw> --query provisioningState
  ```

## Common problems

| Problem | Fix |
|---|---|
| `AADSTS7000215` / invalid client secret | Wrong or expired client secret - make a new one |
| 403 `AuthorizationFailed` | The app registration lacks *Network Contributor* on the gateway |
| `LinkedAuthorizationFailed` | Grant rights on the subnet / public IP / managed identity the gateway uses |
| Waiting times out | The gateway is still `Updating`; raise *Wait for the gateway* |
| Key Vault certificate not taken | The gateway's identity cannot read the secret, the secret ID has a version, or the vault's firewall blocks it |
| EC key refused | Application Gateway may not take EC keys - use an RSA certificate |
