# Cloudflare - nastavení pro acme

acme prokazuje jména přes DNS-01 u Cloudflare: přes Cloudflare API v4 přidá do zóny záznam TXT `_acme-challenge.JMÉNO` (s komentářem `acme DNS-01`) a poté smaže jen svůj vlastní záznam. Pro ověření u komerční CA umí zapsat i CNAME (nikdy přes proxy). Přihlašuje se omezeným **API tokenem** - ne Global API Key.

## Co potřebujete

- Zónu aktivní u Cloudflare (v libovolném tarifu).
- Přístup do rozhraní Cloudflare pro vytvoření API tokenu.
- Odchozí HTTPS z acme na `api.cloudflare.com` (port 443).

## Nastavení Cloudflare

1. Rozhraní → **My Profile → API Tokens → Create Token**.
2. Použijte šablonu **Edit zone DNS**, nebo vlastní token s těmito oprávněními:
   - **Zone → DNS → Edit**
   - **Zone → Zone → Read** (aby acme našlo zónu podle jména; není třeba, vyplníte-li *Zone ID*)
3. **Zone Resources**: *Include → Specific zone → example.com* (zopakujte pro každou zónu, kterou smí acme měnit). Nepoužívejte *All zones*.
4. Volitelně: **Client IP Address Filtering** - *Is in* veřejná adresa acme.
5. Volitelně: **TTL** (datum vypršení) tokenu - nezapomeňte ho obnovit.
6. **Continue to summary → Create Token** a zkopírujte token (zobrazí se jen jednou). Cloudflare ukáže příkaz `curl` k jeho ověření.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token |
| Zone ID | (pokročilé) ID zóny (stránka Overview → API, pravý sloupec); prázdné = najde se podle jména |
| TTL (s) | (pokročilé) Výchozí `60`; `1` je „auto“ Cloudflare |
| API address | (pokročilé) Výchozí `https://api.cloudflare.com/client/v4` |

## Kontrola

- **Test** v acme vypíše zóny, které token vidí (nebo přečte zónu zadanou v *Zone ID*). Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify
  curl -s -H "Authorization: Bearer $CF_TOKEN" 'https://api.cloudflare.com/client/v4/zones?name=example.com'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the token works but sees no zone` | Přidejte pro zónu **Zone:Read** a **DNS:Edit** v *Zone Resources*. |
| `Authentication error (10000)` | Špatný nebo prošlý token; nebo adresa acme není v IP filtru tokenu. |
| `Cloudflare has no zone for NAME that this token may see` | Zóna je v jiném účtu nebo není v tokenu zahrnuta - případně vyplňte *Zone ID*. |
| CA záznam nevidí | Jmenné servery domény nejsou Cloudflare (částečné/CNAME nastavení): zkontrolujte `dig NS example.com`. |
