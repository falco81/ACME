# Cloudflare Origin CA - nastavení pro acme

Zdroj **Cloudflare Origin CA** získává certifikáty pro server za proxy Cloudflare (*origin*) od Origin CA společnosti Cloudflare: důvěřuje jim **jen edge Cloudflare, ne prohlížeče**. acme pošle své CSR s hostnames, druhem (`origin-ecc` / `origin-rsa`) a platností (`POST /client/v4/certificates`); certifikát přijde okamžitě a acme nad něj přidá kořen Origin CA. **Soukromý klíč nikdy neopustí acme.** Odvolání je `DELETE /client/v4/certificates/{id}`; *Try it* ověří API token; *Import from a source* vypíše Origin CA certifikáty zóny. Zdarma, až na 15 let. Žádné IP adresy; wildcardy povoleny.

## Co potřebujete

- Účet Cloudflare se zónami daných jmen (Cloudflare odmítá jména mimo zóny účtu).
- **API token** omezený na tyto zóny (doporučeno), nebo **Origin CA Key** účtu.
- Přístup HTTPS **z acme** na `api.cloudflare.com` a `developers.cloudflare.com` (kořen) na portu 443, přímo nebo přes Nastavení → Proxy.
- V Cloudflare režim SSL/TLS zóny **Full (strict)**, aby edge kontroloval certifikát originu.

## Nastavení Cloudflare

1. **My Profile → API Tokens → Create Token → Create Custom Token**:
   - Permissions: **Zone → SSL and Certificates → Edit**; přidejte **Zone → Zone → Read**, aby acme mohlo vypsat zóny (pro *Import from a source*).
   - Zone Resources: **Include → Specific zone** (každá zóna, pro kterou acme vydává) - nebo všechny zóny účtu.
   - Client IP Address Filtering (volitelné): veřejná IP acme.
   - TTL: podle vaší politiky - token obnovte, než skončí.
2. Zkopírujte token (zobrazí se jednou).
3. Nebo starší způsob: **My Profile → API Tokens → Origin CA Key → View** - umí vydávat pro všechny zóny uživatele, proto dejte přednost tokenu.
4. V každé zóně: **SSL/TLS → Overview → Full (strict)**, jakmile origin posílá Origin CA certifikát.

Ověření tokenu:

```sh
curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify
```

## Vyplnění v acme

Zdroje → **Přidat** → **Cloudflare Origin CA**.

| Pole v acme | Co do něj zadat |
|---|---|
| Signing in | *API token (Zone - SSL and Certificates - Edit)* nebo *Origin CA Key* |
| API token / Origin CA Key | z kroku 2 / 3 |
| Validity | `90 days` (výchozí); 7 dní - 15 let |
| Kind of the certificate (pokročilé) | *as the key* (ECDSA → `origin-ecc`, RSA → `origin-rsa`) |
| Zone (for importing) | jen pro *Import from a source* - *Load the list*, vyberte zónu |
| Zone ID typed (pokročilé) | ID zóny z její stránky Overview, kde seznam nejde načíst (Origin CA Key) |
| Put the Origin CA root above the certificate (pokročilé) | zapnuto |
| API address (pokročilé) | `https://api.cloudflare.com/client/v4` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): token se ověří.
- Po vydání v Cloudflare: **SSL/TLS → Origin Server** certifikát vypíše. Ze strany originu (mimo proxy):

```sh
openssl s_client -connect <origin IP>:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -enddate     # vydavatel: CloudFlare Origin ... CA
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Authentication error` / `10000` | token nemá *SSL and Certificates → Edit* na té zóně, nebo vypršel |
| Hostname odmítnut | není v zóně účtu (nebo v zóně, kterou token zahrnuje) |
| Prohlížeče při přímém přístupu na origin hlásí *nedůvěryhodný* | očekávané: Origin CA důvěřuje jen proxy Cloudflare - nechte záznam proxovaný (oranžový mráček) |
| Cloudflare `526 Invalid SSL certificate` | origin posílá jiný certifikát, nebo v něm hostname není |
| IP adresa odmítnuta | Origin CA pro IP adresy nevydává |
| `Load the list` zón je prázdné | přidejte tokenu *Zone → Zone → Read*, nebo zadejte Zone ID |
