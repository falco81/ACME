# DigitalOcean - nastavení pro acme

acme prokazuje jména přes DNS-01 v doméně DigitalOcean (Networking → Domains): přes DigitalOcean API v2 přidá záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Přihlašuje se osobním přístupovým tokenem.

## Co potřebujete

- Doménu přidanou v **Networking → Domains** a delegovanou na `ns1/ns2/ns3.digitalocean.com`.
- Odchozí HTTPS z acme na `api.digitalocean.com` (port 443).

## Nastavení DigitalOcean

1. Ovládací panel → **API → Tokens → Generate New Token**.
2. Pojmenujte ho např. `acme`, zvolte **expiration** a v rozsazích (scopes) vyberte **Custom Scopes** → **domain**: `read`, `create`, `delete` (nebo **Full Access** / *Write*, což je víc, než je třeba).
3. Máte-li více týmů, vytvořte token v týmu, kterému doména patří.
4. Zkopírujte token (zobrazí se jen jednou).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Personal access token | Token (`dop_v1_…`) |
| Domain | např. `example.com`; prázdné = najde se podle jména |
| TTL (s) | (pokročilé) Výchozí `60`; DigitalOcean přijme 30 a více |

## Kontrola

- **Test** v acme vypíše domény, které token vidí. Nic nemění.
- Pomocí `doctl` nebo curl:

  ```sh
  doctl compute domain records list example.com
  curl -s -H "Authorization: Bearer $DO_TOKEN" https://api.digitalocean.com/v2/domains
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unable to authenticate you` | Špatný nebo prošlý token. |
| `403` při přidání záznamu | Token nemá `domain:create` / `domain:delete` (token jen pro čtení). |
| Doména se nenajde | Patří jinému týmu; nebo vyplňte přesně *Domain*. |
| CA záznam nevidí | Doména není delegovaná na jmenné servery DigitalOcean. |
