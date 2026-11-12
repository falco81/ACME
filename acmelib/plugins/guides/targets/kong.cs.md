# Kong Gateway - nastavení pro acme

acme nasazuje certifikáty na Kong Gateway přes **Kong Admin API**. Každé obnovení přidá **nový objekt certifikátu** (`POST /certificates`, celý řetězec a klíč, štítky `acme`, `acme-<jméno>`, `acme-fp-…`, `acme-at-…`) a pak na něj nasměruje každé **SNI** (`PUT /snis/<jméno>` - SNI, které ještě neexistuje, se vytvoří). Starší objekty certifikátu od acme, které už žádné SNI nepoužívá, se mažou. Duální certifikát (ECDSA + RSA se stejnými jmény) jde do jednoho objektu jako `cert` / `cert_alt` a Kong každému klientovi podá ten druh, který podporuje.

Pro Kong Gateway (OSS nebo Enterprise) s databází. **Kong v režimu DB-less nelze přes Admin API měnit** a Kong Konnect (hostovaná řídicí rovina) se nepokrývá.

## Co potřebujete

- Kong Gateway 2.x / 3.x běžící s databází (PostgreSQL), aby Admin API mohlo zapisovat.
- Síťový přístup z acme na Admin API (např. `http://kong:8001` nebo `https://kong:8444`).
- U Kong Gateway Enterprise s RBAC: token RBAC uživatele, který smí ve workspace měnit certifikáty a SNI.

## Nastavení Kongu

1. Zpřístupněte Admin API **jen** ze serveru acme. V `kong.conf` (nebo `KONG_ADMIN_LISTEN`), např.:

```text
admin_listen = 10.0.0.5:8001, 10.0.0.5:8444 ssl
```

   a ve firewallu povolte port 8001/8444 jen z acme (a pro vaše správce). **Otevřené Admin API bez RBAC dovolí komukoli Kong překonfigurovat.** Když je acme na jiném stroji, dejte přednost HTTPS listeneru (8444).

2. Kong Gateway Enterprise s RBAC: vytvořte roli omezenou na certifikáty a SNI a uživatele pro acme (jako super-admin, ve workspace, které acme používá):

```sh
ADMIN=https://kong.example.local:8444; H="Kong-Admin-Token: $SUPER_TOKEN"
curl -s -X POST $ADMIN/rbac/roles -H "$H" -d name=acme-certs
for ep in /certificates /certificates/* /snis /snis/*; do
  curl -s -X POST $ADMIN/rbac/roles/acme-certs/endpoints -H "$H" \
       -d endpoint="$ep" -d actions=read,create,update,delete -d workspace=default
done
curl -s -X POST $ADMIN/rbac/users -H "$H" -d name=acme -d user_token="$ACME_TOKEN"
curl -s -X POST $ADMIN/rbac/users/acme/roles -H "$H" -d roles=acme-certs
```

   Seznam endpointů ověřte v dokumentaci RBAC své verze Kongu; acme pro **Test** čte i `GET /`.

3. Kong OSS nemá RBAC: token nechte prázdný a Admin API chraňte jen sítí.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Admin API | adresa Admin API se schématem a portem, např. `http://kong.example.local:8001` |
| Admin token | Enterprise s RBAC: token uživatele acme (`Kong-Admin-Token`); bez RBAC prázdné |
| Workspace (pokročilé) | Enterprise: workspace; prázdné: výchozí |
| Check the device's certificate | u Admin API na `https://`: zapnuto, pokud nemá self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu Admin API, když není veřejná |
| SNIs (nasazení) | jména serverů, jedno na řádek (`www.example.com`, `*.example.com`); prázdné: jména certifikátu |
| Previous versions to keep | kolik starších objektů certifikátu od acme zůstane |
| Check what is served | adresa proxy se jménem, např. `www.example.com:443`, jedna na řádek |

## Ověření

- **Test** v acme přečte verzi (`GET /`) a jeden certifikát (`Kong 3.x at …`).
- Na Admin API:

```sh
curl -s http://kong.example.local:8001/snis/www.example.com
curl -s "http://kong.example.local:8001/certificates?tags=acme"
```

- Na proxy: `openssl s_client -connect kong.example.local:8443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate`

## Časté problémy

| Problém | Řešení |
|---|---|
| `… (Kong runs without a database: its Admin API cannot change anything)` | Kong DB-less: změňte místo toho deklarativní konfiguraci, nebo provozujte Kong s databází |
| `… does not answer as a Kong Admin API` | adresa je port proxy (8000/8443), ne Admin API (8001/8444) |
| 401 / 403 | Enterprise RBAC: chybí nebo je špatný token, nebo role nemá `/certificates` či `/snis` |
| 404 u každého volání | špatný *Workspace* |
| `no SNI to point at the certificate` | vyplňte *SNIs*, nebo certifikát nemá jména, která Kong přijme |
| `the older certificate … stays: SNIs still use it` | nějaké SNI, které není v *SNIs*, na něj stále ukazuje; doplňte ho nebo ho přesuňte ručně |
