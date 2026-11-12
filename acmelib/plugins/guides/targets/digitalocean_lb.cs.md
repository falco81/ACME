# DigitalOcean Load Balancer - nastavení pro acme

acme nahraje certifikát do DigitalOcean jako **custom certificate** pod jménem s datem
(`POST /v2/certificates`), pak načte každý zadaný load balancer a pošle ho zpět celý
(`PUT /v2/load_balancers/<id>` - DigitalOcean load balancer nahrazuje jako celek) s jeho
**HTTPS forwarding rules** (`https`, `http2`, `http3`; ne TLS passthrough; všemi, nebo
jen těmi se zadanými vstupními porty) nasměrovanými na nový certifikát. Starší certifikáty
acme nad počet *ponechat* smaže; používaný DigitalOcean odmítne smazat a zůstane.

Pro (regionální) Load Balancery DigitalOcean přes veřejné API v2.

## Co potřebujete

- Tým v DigitalOcean a load balancery (jméno nebo ID) s již nastavenými HTTPS pravidly
  přesměrování (acme pravidla nevytváří).
- Odchozí HTTPS z acme na `api.digitalocean.com` (TCP 443), přímo nebo přes proxy.

## Nastavení DigitalOcean

1. **API → Tokens → Generate New Token** (Personal access tokens).
2. Pojmenujte ho `acme`, zvolte platnost a **Custom Scopes**:
   - **certificate**: `create`, `read`, `delete`
   - **load_balancer**: `read`, `update`
   Nic dalšího není potřeba.
3. Zkopírujte token (zobrazí se jen jednou). Otestujte ho:

   ```sh
   curl -s -H "Authorization: Bearer <token>" "https://api.digitalocean.com/v2/load_balancers?per_page=200" | head
   ```

   nebo přes `doctl`:

   ```sh
   doctl auth init --access-token <token>
   doctl compute load-balancer list
   ```

4. Poznamenejte si jména nebo ID load balancerů (**Networking → Load Balancers**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token z kroku 3 |
| Through the proxy (pokročilé) | Výchozí zapnuto: ven přes Settings → Proxy |
| Load balancers (nasazení) | Jeden na řádek: jméno nebo ID load balanceru, např. `lb-www` |
| Entry ports (nasazení) | Jeden na řádek, např. `443`; prázdné: každé HTTPS pravidlo, které není TLS passthrough |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `www.example.com:443` |

Akce **List the load balancers** vypíše load balancery a jejich HTTPS pravidla - nic
nemění.

## Ověření

- **Try**: `signed in to DigitalOcean; N load balancers`.
- V DigitalOcean nebo přes `doctl`:

  ```sh
  doctl compute certificate list
  doctl compute load-balancer get <id> --format Name,ForwardingRules
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 `Unable to authenticate you` | Chybný nebo prošlý token |
| 403 u certifikátů nebo load balancerů | Chybí scope (certificate create/read/delete, load_balancer read/update) |
| Load balancer nenalezen | Chybné jméno nebo ID - použijte *List the load balancers* |
| Žádné pravidlo se nezměnilo | Pravidla jsou TLS passthrough nebo na jiných portech - ověřte *Entry ports* |
| Starší certifikát se nesmazal | Load balancer ho ještě používá; smaže se později |
| Nahrazen certifikát Let's Encrypt od DigitalOcean | Očekávané: pravidlo teď používá vlastní certifikát acme |
