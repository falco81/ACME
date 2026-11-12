# Azure Key Vault - nastavení pro acme

acme naimportuje klíč a celý řetězec jako **novou verzi jednoho certifikátu v Key Vault**
(`POST https://<vault>.vault.azure.net/certificates/<name>/import?api-version=7.4`).
Cokoli, co certifikát používá **bez verze** - Application Gateway, App Service (Key Vault
reference; synchronizace do 24 h nebo přes *Sync*), Front Door, API Management - si nový
převezme samo. Má-li aktuální verze v trezoru stejný SHA-1 otisk (`x5t`), nic se
neimportuje. Staré verze zůstávají v historii trezoru.

Pro Azure Key Vault (standard i premium) v Azure, Azure China nebo Azure US Government.

## Co potřebujete

- Jméno nebo URL trezoru.
- Odchozí HTTPS z acme na `login.microsoftonline.com` a `<vault>.vault.azure.net` (nebo
  ekvivalenty pro China / US Government).
- Má-li trezor **firewall** (Networking → Firewalls and virtual networks): povolenou
  veřejnou IP serveru acme.

## Nastavení Azure Key Vault

1. **Microsoft Entra ID → App registrations → New registration** (např. `acme-keyvault`).
   Poznamenejte si **Application (client) ID** a **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret**; zkopírujte hodnotu (zobrazí se jen
   jednou).
3. Udělte přístup k trezoru - podle jeho **modelu oprávnění** (Access configuration):
   - **Azure RBAC**: **Access control (IAM) → Add role assignment → Key Vault
     Certificates Officer** pro registraci aplikace.

     ```sh
     az role assignment create --assignee <client-id> --role "Key Vault Certificates Officer" \
       --scope $(az keyvault show -n kv-firma --query id -o tsv)
     ```

   - **Vault access policy**: **Access policies → Create**, *Certificate permissions*:
     **Get, List, Import** - nic víc.

     ```sh
     az keyvault set-policy -n kv-firma --spn <client-id> --certificate-permissions get list import
     ```
4. Firewall trezoru: přidejte IP adresu serveru acme (Networking → Firewall).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Key Vault | Jméno (`kv-firma`) nebo URL (`https://kv-firma.vault.azure.net`) |
| Tenant (directory) ID | Z kroku 1 |
| Client (application) ID | Z kroku 1 |
| Client secret | Z kroku 2 |
| Cloud (pokročilé) | Azure, Azure China (21Vianet) nebo Azure US Government |
| Certificate name in the vault (nasazení) | Písmena, číslice a `-`, např. `www-example-com`; prázdné: `acme-<jméno certifikátu>` |
| Kept in the vault as (nasazení) | `PEM` (výchozí) nebo `PKCS#12` - **Application Gateway bere jen PKCS#12** |
| Check what is served | Služba, která ho používá, např. `www.example.com:443` |

## Ověření

- **Try**: `signed in to https://kv-firma.vault.azure.net, N certificates seen`.
- V Azure:

  ```sh
  az keyvault certificate show --vault-name kv-firma -n www-example-com --query "{x5t:x5t, expires:attributes.expires}"
  az keyvault certificate list-versions --vault-name kv-firma -n www-example-com -o table
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AADSTS7000215` / neplatný client secret | Chybný nebo prošlý secret |
| 403 `Forbidden` | Chybí role / access policy (*Import*, *Get*, *List*) |
| 403 `ForbiddenByFirewall` | Přidejte IP acme do firewallu trezoru |
| Application Gateway ho nepřevezme | Nastavte *Kept in the vault as* na PKCS#12 |
| Služby drží starý certifikát | Odkazují na pevnou verzi; odkazujte bez verze (App Service: *Sync*) |
| Jméno odmítnuto | Povolena jsou jen písmena, číslice a `-` |
