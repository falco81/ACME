# Hostinger - nastavení pro acme

acme prokazuje jména přes DNS-01 v zóně DNS domény u Hostingeru: přes Hostinger API (`developers.hostinger.com`) přidá svou hodnotu do sady TXT `_acme-challenge.JMÉNO` (`PUT` s `overwrite: false`) a při úklidu sadu zapíše zpět bez ní (`overwrite: true`) - nebo sadu smaže, byla-li jeho hodnota poslední.

## Co potřebujete

- Doménu používající DNS Hostingeru (ve vašem portfoliu domén u Hostingeru).
- Odchozí HTTPS z acme na `developers.hostinger.com` (port 443).

## Nastavení Hostingeru

1. Přihlaste se do **hPanel → Account → API** (nabídka účtu → *API*).
2. **New token**: pojmenujte ho `acme`, zvolte **platnost** (nezapomeňte ho obnovit).
3. Nabízí-li hPanel výběr prostředků, dejte tokenu jen domény, které acme potřebuje.
4. Zkopírujte token (zobrazí se jen jednou).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `300` |
| API address | (pokročilé) Výchozí `https://developers.hostinger.com` |

## Kontrola

- **Test** v acme vypíše domény portfolia - nebo při vyplněné *Domain* spočítá sady záznamů zóny. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://developers.hostinger.com/api/dns/v1/zones/example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný nebo prošlý token. |
| Doména se nenajde | Její DNS není u Hostingeru, nebo je v jiném účtu; vyplňte *Domain*. |
| `422` při zápisu | Zkontrolujte TTL (nejméně 60) a že je zóna DNS domény aktivní. |
| CA záznam nevidí | Ověřte, že doména používá jmenné servery Hostingeru; zvyšte *Wait at least (seconds)*. |
