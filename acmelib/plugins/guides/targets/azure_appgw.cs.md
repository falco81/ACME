# Azure Application Gateway - nastavení pro acme

acme komunikuje s **Azure Resource Manager** (`api-version=2026-03-01`) pomocí tokenu
registrace aplikace (Microsoft Entra, client credentials). Certifikáty a listenery brány
nemají vlastní volání API, proto acme **načte celou bránu, změní ji a pošle ji zpět
(PUT)** a pak čeká, dokud `provisioningState` není jiný než `Updating`:

- **Nahrání** (výchozí): PKCS#12 s řetězcem se uloží do `sslCertificates` pod jménem s
  datem (`acme-<jméno>-<datum>-<sériové číslo>`), nebo - s *Name on the gateway* - nahradí
  obsah tohoto jednoho certifikátu.
- **Z Key Vault**: položka odkazující na secret v Key Vault **bez verze**; brána si každou
  novou verzi vezme sama. acme pak jen změní tagy brány (`PATCH {"tags"}`), aby se do
  trezoru podívala hned, a ne až do čtyř hodin.

Zadané listenery (a každý listener, který používal starší certifikát acme téhož
certifikátu) se přepnou na nový certifikát; starší certifikáty acme, které žádný listener
nepoužívá, se odeberou ve stejném PUT.

Pro Application Gateway v2 (Standard_v2 / WAF_v2) v Azure, Azure China a Azure US
Government.

## Co potřebujete

- ID předplatného, skupinu prostředků a jméno brány; její HTTPS (nebo TLS) listenery.
- Odchozí HTTPS z acme na `login.microsoftonline.com` a `management.azure.com` (nebo
  ekvivalenty pro China / US Government).
- Pro *Z Key Vault*: nasazení `azure_keyvault` téhož certifikátu (spusťte ho **jako
  první**, s *Kept in the vault as* = PKCS#12) a na bráně **user-assigned managed
  identity**, která smí číst secrety trezoru.

## Nastavení Azure

1. **Microsoft Entra ID → App registrations → New registration** (např. `acme-appgw`).
   Poznamenejte si **Application (client) ID** a **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret**; zkopírujte hodnotu (zobrazí se jen
   jednou).
3. Na bráně: **Access control (IAM) → Add role assignment → Network Contributor** pro
   registraci aplikace. S Azure CLI:

   ```sh
   az role assignment create --assignee <client-id> --role "Network Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/applicationGateways/<gw>
   ```

   PUT brány kontroluje i propojené prostředky; selže-li s `LinkedAuthorizationFailed`,
   dejte *Network Contributor* i na podsíť / virtuální síť a veřejnou IP brány (nebo na
   celou skupinu prostředků).
4. Jen Key Vault: dejte registraci aplikace roli **Managed Identity Operator** na managed
   identity brány a identitě roli **Key Vault Secrets User** na trezoru (nebo access
   policy *Secrets: Get*).
5. Má-li trezor firewall, povolte v něm důvěryhodné služby Microsoftu (bránu).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Subscription ID | GUID předplatného |
| Resource group | Skupina prostředků aplikačních bran |
| Tenant (directory) ID | Z kroku 1 |
| Client (application) ID | Z kroku 1 |
| Client secret | Z kroku 2 |
| Cloud (pokročilé) | Azure, Azure China (21Vianet) nebo Azure US Government |
| Application gateway (nasazení) | Jméno brány, např. `agw-www` |
| Listener (nasazení) | HTTPS/TLS listener vybraný ze seznamu (*Load the list*) nebo napsaný |
| More listeners (nasazení) | Jeden na řádek; žádný: přepnou se listenery se starším certifikátem acme |
| The certificate goes (nasazení) | `uploaded (PKCS#12 with its chain)` nebo `from Key Vault` |
| Key Vault secret ID (nasazení) | `https://kv-firma.vault.azure.net/secrets/acme-www-example-com/` - **bez verze** |
| Name on the gateway (nasazení) | Prázdné: pokaždé nové jméno s datem; vyplněné: ten jeden certifikát, nahrazený na místě |
| PKCS#12 kind (nasazení, pokročilé) | `3DES` (výchozí) nebo `AES-256` |
| Wait for the gateway (s) (nasazení, pokročilé) | Výchozí 1800 - aktualizace brány může trvat mnoho minut |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try**: `signed in to Azure; N application gateways in <rg>: ...`.
- V Azure:

  ```sh
  az network application-gateway ssl-cert list -g <rg> --gateway-name <gw> -o table
  az network application-gateway show -g <rg> -n <gw> --query provisioningState
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AADSTS7000215` / neplatný client secret | Chybný nebo prošlý secret - vytvořte nový |
| 403 `AuthorizationFailed` | Registrace aplikace nemá *Network Contributor* na bráně |
| `LinkedAuthorizationFailed` | Dejte práva na podsíť / veřejnou IP / managed identity, které brána používá |
| Vypršelo čekání | Brána je stále `Updating`; zvyšte *Wait for the gateway* |
| Certifikát z Key Vault se nepřevezme | Identita brány nesmí číst secret, ID secretu obsahuje verzi, nebo blokuje firewall trezoru |
| EC klíč odmítnut | Application Gateway nemusí brát EC klíče - použijte RSA certifikát |
