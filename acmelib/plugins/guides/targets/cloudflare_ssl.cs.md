# Cloudflare custom certificate - nastavení pro acme

acme nahraje certifikát jako **custom certificate** zóny Cloudflare (`POST
/zones/<id>/custom_certificates`) a při každé obnově ho **nahradí** (`PATCH
.../custom_certificates/<id>`); Cloudflare ho na okraji sítě vymění bez výpadku. U
`sni_custom` vrátí PATCH **nové id** a předchozí smaže; acme si nové id uchová pro další
obnovu. Certifikát, který acme ještě nezná, najde podle jeho jmen.

Pro zóny s tarifem **Business nebo Enterprise**, nebo s doplňkem **Advanced Certificate
Manager** - jinak vlastní certifikáty k dispozici nejsou.

## Co potřebujete

- Zónu Cloudflare s dostupnými vlastními certifikáty (viz výše).
- Odchozí HTTPS z acme na `api.cloudflare.com` (TCP 443), přímo nebo přes proxy.
- **API token** (ne Global API Key) omezený na tuto zónu.

## Nastavení Cloudflare

1. **My Profile → API Tokens → Create Token → Create Custom Token**.
2. Oprávnění:
   - **Zone → SSL and Certificates → Edit**
   - **Zone → Zone → Read** (jen pokud zónu zadáváte jménem)
3. **Zone Resources → Include → Specific zone →** vaše zóna (např. `example.com`).
4. Volitelně **Client IP Address Filtering**: povolte jen veřejnou IP serveru acme.
5. Vytvořte a zkopírujte token (zobrazí se jen jednou). Otestujte ho:

   ```sh
   curl -s -H "Authorization: Bearer <token>" https://api.cloudflare.com/client/v4/user/tokens/verify
   ```

6. ID zóny je na stránce **Overview** zóny (pravý sloupec, *API → Zone ID*).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token z kroku 5 |
| Zone | Jméno zóny (`example.com`) nebo její ID (32 hex znaků) |
| Through the proxy (pokročilé) | Výchozí zapnuto: ven přes Settings → Proxy |
| Chain (nasazení) | `as acme gives it (force)` (výchozí), `ubiquitous` nebo `optimal` |
| Served to (nasazení, pokročilé) | `clients with SNI (sni_custom)` (výchozí) nebo `every client (legacy_custom)` |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try**: `signed in: zone example.com (Business plan), N custom certificates`.
- V Cloudflare: **SSL/TLS → Edge Certificates** ukazuje vlastní certifikát a jeho
  platnost.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 403 / `Authentication error` | Token nemá *SSL and Certificates → Edit*, nebo není pro tuto zónu |
| Zóna podle jména nenalezena | Přidejte *Zone → Zone → Read*, nebo zadejte ID zóny |
| Vlastní certifikáty nejsou povoleny | Zóna je na Free/Pro bez Advanced Certificate Manager |
| Stále se servíruje certifikát Cloudflare | Univerzální/pokročilé certifikáty mohou mít u některých jmen přednost - viz Edge Certificates |
| Chyby `Chain` při nahrání | Zkuste `ubiquitous`, ať řetězec sestaví Cloudflare |
| Blokováno filtrem IP | Přidejte aktuální veřejnou IP acme do filtru tokenu |
