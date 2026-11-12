# Azure DNS - setup for acme

acme proves names by DNS-01 in an Azure DNS zone: it signs in as an app registration (service principal) with a client secret, reads the TXT record set `_acme-challenge.NAME` through the Azure Resource Manager API (api-version 2018-05-01), adds its value and writes the set back with the etag it read (so a change made meanwhile is not lost); cleanup takes only its value away. Public Azure, Azure China and Azure US Government are supported. Azure **Private** DNS zones are not.

## What you need

- A public DNS zone in Azure DNS (`Microsoft.Network/dnsZones`).
- Rights in Microsoft Entra ID to create an app registration, and Owner or User Access Administrator on the zone (or its resource group) to assign a role.
- Outbound HTTPS from acme to `login.microsoftonline.com` and `management.azure.com` (or the China / US Government equivalents), port 443.

## Set up Azure

1. Microsoft Entra ID → **App registrations → New registration**: e.g. `acme-dns01`, single tenant. Note the **Application (client) ID** and **Directory (tenant) ID**.
2. The app → **Certificates & secrets → Client secrets → New client secret**. Copy its **Value** (not the Secret ID) - shown only once. Note when it expires.
3. The DNS zone (or its resource group) → **Access control (IAM) → Add role assignment** → role **DNS Zone Contributor** → members: the app. Assign it on the zone itself for the least access.
4. Or with the Azure CLI, in one step:

   ```sh
   az ad sp create-for-rbac --name acme-dns01 \
     --role "DNS Zone Contributor" \
     --scopes /subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/example.com
   ```

   It prints `appId` (client ID), `password` (client secret) and `tenant`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Tenant (directory) ID | The Directory (tenant) ID |
| Client (application) ID | The app's Application (client) ID |
| Client secret | The secret's Value |
| Subscription ID | The subscription the zone is in |
| Resource group | The zone's resource group; empty = every zone of the subscription is looked through (needs read access on them) |
| Zone | e.g. `example.com`; empty = the longest zone the name is in |
| TTL (s) | (advanced) Default `60` |
| Cloud | (advanced) Azure, Azure China (21Vianet) or Azure US Government |

## Check it

- **Test** in acme signs in and lists the DNS zones the app can see. It changes nothing.
- With the Azure CLI:

  ```sh
  az login --service-principal -u <client-id> -p <secret> --tenant <tenant-id>
  az network dns zone list -o table
  az network dns record-set txt show -g <rg> -z example.com -n _acme-challenge
  ```

## Common problems

| Problem | Fix |
|---|---|
| `AADSTS7000215` invalid client secret | You copied the Secret ID instead of its Value, or the secret expired - create a new one. |
| `AuthorizationFailed` | The role assignment is missing or on another scope; role assignments can take a few minutes to apply. |
| `the zone ... is not in the subscription/resource group` | Wrong *Subscription ID* or *Resource group*. |
| No zone found with an empty *Resource group* | The role is only on one zone - set *Resource group* and *Zone*. |
