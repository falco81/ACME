# Azure DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v zóně Azure DNS: přihlásí se jako registrace aplikace (service principal) s tajným klíčem klienta, přes Azure Resource Manager API (api-version 2018-05-01) přečte sadu záznamů TXT `_acme-challenge.JMÉNO`, přidá svou hodnotu a sadu zapíše zpět s přečteným etagem (aby se neztratila změna provedená mezitím); při úklidu odebere jen svou hodnotu. Podporuje veřejný Azure, Azure China a Azure US Government. Zóny Azure **Private** DNS podporované nejsou.

## Co potřebujete

- Veřejnou zónu DNS v Azure DNS (`Microsoft.Network/dnsZones`).
- Práva v Microsoft Entra ID k vytvoření registrace aplikace a roli Owner nebo User Access Administrator na zóně (nebo její skupině prostředků) pro přiřazení role.
- Odchozí HTTPS z acme na `login.microsoftonline.com` a `management.azure.com` (nebo obdoby pro China / US Government), port 443.

## Nastavení Azure

1. Microsoft Entra ID → **App registrations → New registration**: např. `acme-dns01`, jeden tenant. Poznamenejte si **Application (client) ID** a **Directory (tenant) ID**.
2. Aplikace → **Certificates & secrets → Client secrets → New client secret**. Zkopírujte jeho **Value** (ne Secret ID) - zobrazí se jen jednou. Poznamenejte si datum vypršení.
3. Zóna DNS (nebo její skupina prostředků) → **Access control (IAM) → Add role assignment** → role **DNS Zone Contributor** → členové: aplikace. Pro nejmenší přístup ji přiřaďte přímo na zónu.
4. Nebo jedním krokem v Azure CLI:

   ```sh
   az ad sp create-for-rbac --name acme-dns01 \
     --role "DNS Zone Contributor" \
     --scopes /subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/example.com
   ```

   Vypíše `appId` (ID klienta), `password` (tajný klíč klienta) a `tenant`.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Tenant (directory) ID | Directory (tenant) ID |
| Client (application) ID | Application (client) ID aplikace |
| Client secret | Value tajného klíče |
| Subscription ID | Předplatné, ve kterém je zóna |
| Resource group | Skupina prostředků zóny; prázdné = projdou se všechny zóny předplatného (vyžaduje na ně právo čtení) |
| Zone | např. `example.com`; prázdné = nejdelší zóna, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| Cloud | (pokročilé) Azure, Azure China (21Vianet) nebo Azure US Government |

## Kontrola

- **Test** v acme se přihlásí a vypíše zóny DNS, které aplikace vidí. Nic nemění.
- V Azure CLI:

  ```sh
  az login --service-principal -u <client-id> -p <secret> --tenant <tenant-id>
  az network dns zone list -o table
  az network dns record-set txt show -g <rg> -z example.com -n _acme-challenge
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AADSTS7000215` neplatný tajný klíč | Zkopírovali jste Secret ID místo Value, nebo klíč vypršel - vytvořte nový. |
| `AuthorizationFailed` | Přiřazení role chybí nebo je na jiném rozsahu; projevení přiřazení může trvat několik minut. |
| `the zone ... is not in the subscription/resource group` | Špatné *Subscription ID* nebo *Resource group*. |
| S prázdnou *Resource group* se zóna nenajde | Role je jen na jedné zóně - vyplňte *Resource group* a *Zone*. |
