# Keyfactor Command - nastavení pro acme

Zdroj **Keyfactor Command** získává certifikáty přes REST API Keyfactor Command (`/KeyfactorAPI`): acme zažádá se svým CSR, **šablonou** a **CA** (`POST Enrollment/CSR`) a certifikát s řetězcem si vezme z odpovědi; odvolání je `POST Certificates/Revoke`; seznamy šablon a CA pocházejí z `GET Enrollment/CSR/Context/My` (s čím smí uživatel žádat); *Import from a source* čte `GET Certificates` a `Certificates/Download`. **Soukromý klíč nikdy neopustí acme.** Přihlášení je HTTP Basic (`DOMAIN\user`) nebo OAuth 2.0 klient (client credentials u poskytovatele identit, kterému Command důvěřuje). Šablona, která v Commandu vyžaduje schválení, nechá žádost čekat tam - acme to oznámí a samo se znovu neptá.

## Co potřebujete

- Keyfactor Command dosažitelný **z acme** přes HTTPS (`443`), s API (`/KeyfactorAPI`).
- CA známou Commandu (např. CA AD CS nebo EJBCA přes jeho gateway) a **šablonu** zapnutou pro **CSR enrollment**.
- Uživatele (nebo OAuth klienta) pro acme v **security role** Commandu s minimálními oprávněními níže.

## Nastavení Commandu

1. **Šablona** (Management Portal → **Locations → Certificate Templates**, *Edit*): zapněte ji pro **CSR Enrollment**; *Template Regular Expressions* / povolené velikosti klíčů podle vaší politiky. Pro automatická obnovení nechte *requires approval* vypnuté. Šablona musí také na straně CA povolit enrollment Commandu (např. AD CS: servisní účet Commandu má na šabloně Enroll a šablona je publikovaná).
2. **Security role** (**System Settings → Security Roles**, *Add*): např. `acme-enroll`, s oprávněními (jména podle Command 10/11 - ověřte seznam své verze):
   - *Certificate Enrollment*: **Enroll CSR**
   - *Certificates*: **Read** (pro výpis a stažení pro *Import from a source*), **Revoke** (pro odvolání)
   - ve starších verzích také *API*: **Read**
   Kde to vaše verze umožňuje, omezte ji na kolekce / CA, které acme potřebuje.
3. **Identita**: přidejte do role uživatele z AD (např. `EXAMPLE\svc-acme`) - nebo s poskytovatelem identit (Keyfactor Identity Provider, Entra ID, Keycloak...) identitu OAuth klienta (**Security Identities → Add**).
4. OAuth: v poskytovateli identit vytvořte pro acme důvěrného klienta (grant client credentials); poznamenejte si **token endpoint**, client ID, secret a scopes / audience, které Command vyžaduje.

Ověření API:

```sh
curl -s -u 'EXAMPLE\svc-acme' -H 'x-keyfactor-api-version: 1' -H 'x-keyfactor-requested-with: APIClient' \
  https://keyfactor.example.local/KeyfactorAPI/Enrollment/CSR/Context/My
```

## Vyplnění v acme

Zdroje → **Přidat** → **Keyfactor Command**.

| Pole v acme | Co do něj zadat |
|---|---|
| Command address | `https://keyfactor.example.local` |
| Signing in | *User and password (HTTP Basic)* nebo *OAuth client (client ID and secret)* |
| Domain of the user / User / Password | `EXAMPLE`, `svc-acme`, jeho heslo (posílá se jako `DOMAIN\user`) |
| Token address / Client ID / Client secret | pro OAuth, např. `https://idp.example.local/realms/Keyfactor/protocol/openid-connect/token` |
| Scopes / Audience (pokročilé) | když je poskytovatel identit chce |
| Template | *Load the list* - CSR šablony, které smí uživatel použít |
| Certificate authority | CA šablony, jak ji Command jmenuje (`HOST\CA name`); nastaví se sama, je-li jen jedna |
| Template typed / Certificate authority typed (pokročilé) | jen kde seznamy nejde načíst |
| Which certificates to list (pokročilé) | dotaz Commandu pro *Import from a source*, např. `IssuedCN -contains "example.com"` |
| API path (pokročilé) | `KeyfactorAPI` |
| CA certificate of Command's TLS / Check Command's TLS certificate (pokročilé) | pro privátní TLS certifikát |

## Ověření

- Zdroje → zdroj → **Test** (Try it): šablony a CA, se kterými smí uživatel žádat.
- Po vydání: Management Portal → **Certificates → Certificate Search** ho ukáže se šablonou a žadatelem.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | špatný uživatel / doména / heslo, nebo je OAuth token odmítnut (klient, scope, audience) |
| `403` / *does not have permission* | roli chybí *Enroll CSR* (nebo Read / Revoke), nebo identita není v roli |
| Šablona chybí v seznamu | není zapnutá pro CSR enrollment, nebo ji uživatel nesmí použít |
| *waiting for approval* | šablona vyžaduje schválení - schvalte v Commandu, nebo použijte šablonu bez něj |
| Jméno nebo klíč odmítnut | regulární výrazy šablony nebo pravidla velikosti klíče |
| CA odmítne (`Denied`) | oprávnění šablony na straně CA pro enrollment účet Commandu |
