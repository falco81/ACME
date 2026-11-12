# Azure App Service - nastavení pro acme

acme komunikuje s **Azure Resource Manager** (`api-version=2023-12-01`) pomocí tokenu
registrace aplikace. Nahraje certifikát jako PKCS#12 (s jednorázovým heslem) jako
certifikát skupiny prostředků pod jménem s datem, v regionu a App Service plánu webové
aplikace (`PUT .../Microsoft.Web/certificates/<name>`), a pak k němu přes **SNI SSL**
přiváže každé **vlastní jméno hostitele** aplikace - zadaná, nebo všechna, která
certifikát pokrývá (ne `*.azurewebsites.net`). Starší certifikáty acme ve skupině nad počet
*ponechat* smaže; Azure nesmaže certifikát, který je ještě navázaný.

Pro webové aplikace Azure App Service (produkční slot; deployment sloty se neobsluhují) na
plánu, který podporuje vlastní TLS certifikáty (Basic a vyšší), v Azure, Azure China nebo
Azure US Government.

## Co potřebujete

- ID předplatného, skupinu prostředků a jméno webové aplikace.
- Vlastní jména hostitelů už v aplikaci **přidaná a ověřená** (acme je jen navazuje,
  nepřidává).
- Odchozí HTTPS z acme na `login.microsoftonline.com` a `management.azure.com`.

## Nastavení Azure

1. **Microsoft Entra ID → App registrations → New registration** (např.
   `acme-appservice`). Poznamenejte si **Application (client) ID** a **Directory (tenant)
   ID**.
2. **Certificates & secrets → New client secret**; zkopírujte hodnotu (zobrazí se jen
   jednou).
3. Přiřaďte registraci aplikace role (**Access control (IAM) → Add role assignment**):
   - **Website Contributor** na webové aplikace,
   - **Web Plan Contributor** na jejich App Service plán,
   - nebo jednoduše **Contributor** na skupinu prostředků.

   ```sh
   az role assignment create --assignee <client-id> --role "Website Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>
   az role assignment create --assignee <client-id> --role "Web Plan Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/serverfarms/<plan>
   ```

   Certifikáty vznikají ve skupině prostředků; selže-li nahrání s 403, použijte
   *Contributor* na skupinu prostředků.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Subscription ID | GUID předplatného |
| Resource group | Skupina prostředků webových aplikací (ukládají se do ní i certifikáty) |
| Tenant (directory) ID | Z kroku 1 |
| Client (application) ID | Z kroku 1 |
| Client secret | Z kroku 2 |
| Cloud (pokročilé) | Azure, Azure China (21Vianet) nebo Azure US Government |
| Web app (nasazení) | Jméno webové aplikace, např. `app-www` |
| Hostnames (nasazení) | Jedno na řádek; prázdné: každé vlastní jméno, které certifikát pokrývá |
| PKCS#12 kind (nasazení, pokročilé) | `3DES` (jak to App Service dokumentuje, výchozí) nebo `AES-256` |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `www.example.com:443` |

**Discover** (ve formuláři) vypíše skupiny prostředků, ve kterých jsou certifikáty App
Service.

## Ověření

- **Try**: `signed in to Azure; N App Service certificates in <rg>`.
- V Azure (**web app → Certificates / Custom domains**) nebo:

  ```sh
  az webapp config hostname list -g <rg> --webapp-name <app> -o table
  az webapp config ssl list -g <rg> -o table
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AADSTS7000215` / neplatný client secret | Chybný nebo prošlý secret |
| 403 na `certificates/<name>` | Chybí *Web Plan Contributor* / *Contributor* na skupině prostředků |
| 403 na `hostNameBindings` | Chybí *Website Contributor* na webové aplikaci |
| Jméno hostitele se nenavázalo | Není to vlastní jméno aplikace, nebo ho certifikát nepokrývá |
| Starší certifikát se nesmazal | Je ještě někde navázaný; zůstane, dokud se neuvolní |
| Plán nepodporuje SSL | Zvyšte plán na Basic nebo vyšší |
