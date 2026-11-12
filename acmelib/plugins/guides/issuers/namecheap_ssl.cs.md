# Namecheap SSL (API) - nastavení pro acme

Zdroj **Namecheap SSL (API)** získává SSL certifikáty zakoupené u Namecheap přes jeho API (`namecheap.ssl.*`): již zakoupený certifikát se **aktivuje** s CSR od acme (`namecheap.ssl.activate`), nebo se aktivní certifikát **znovu vydá** (zdarma); nový se kupuje (`namecheap.ssl.create`) jen když je zapnuté *Allow new orders (paid)*. CNAME nebo soubor **ověření domény (DCV)**, kterým Namecheap odpoví, umístí validace certifikátu, nebo CA napíše schvalovateli e-mail; certifikát se přečte přes `getInfo`, jakmile je aktivní. **Soukromý klíč nikdy neopustí acme.** *Import from a source* vypíše certifikáty účtu; odvolání je možné jen u nahrazených certifikátů (jak to API Namecheapu dovoluje). Žádné TXT DCV, žádné IP adresy.

## Co potřebujete

- Účet Namecheap se zapnutým **přístupem k API** (Namecheap ho dává účtům, které splní jeho podmínky - zůstatek, počet domén nebo útrata; viz stránka API access Namecheapu).
- **API uživatele**, **API klíč** a veřejnou **IPv4 adresu** acme **na seznamu povolených** pro API.
- Již zakoupené certifikáty (jejich *CertificateID*), nebo zůstatek na nové.
- Přístup HTTPS **z acme** na `api.namecheap.com` (sandbox: `api.sandbox.namecheap.com`) port 443.
- Validaci v acme, která umí umístit důkaz DCV (DNS pro CNAME, HTTP pro soubor), nebo člověka pro e-mail.

## Nastavení Namecheapu

1. **Profile → Tools → Business & Dev Tools → Namecheap API Access → Manage**: přepněte přístup k API na **ON** (přijměte podmínky); zkopírujte **API klíč**.
2. **Whitelisted IPs → Edit → Add IP**: veřejná IPv4 acme (adresa proxy, pokud acme odchází přes Nastavení → Proxy). Přijímá se jen IPv4.
3. Kupte certifikáty, které bude acme aktivovat / znovu vydávat (**Account → Product List → SSL Certificates**), a poznamenejte si *CertificateID* každého, nebo rozhodněte, zda smí acme nakupovat.
4. Pro test je **sandbox** (`www.sandbox.namecheap.com`) samostatný účet s vlastním API klíčem a seznamem povolených IP.

Ověření ze sítě acme:

```sh
curl -s "https://api.namecheap.com/xml.response?ApiUser=$U&ApiKey=$K&UserName=$U&ClientIp=198.51.100.7&Command=namecheap.ssl.getList"
```

## Vyplnění v acme

Zdroje → **Přidat** → **Namecheap SSL (API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Namecheap | *Production* nebo *Sandbox* |
| API user / API key | uživatelské jméno účtu a klíč z kroku 1 |
| User name (pokročilé) | prázdné: API uživatel |
| Client IP | IPv4, ze které acme volá - na seznamu povolených |
| Certificate to reuse | *CertificateID*: nový se aktivuje, aktivní se znovu vydá; prázdné: ten, který mělo acme naposledy |
| Allow new orders (paid) | **vypnuto**, pokud acme nesmí nakupovat |
| Type of a new certificate / Years | např. `PositiveSSL`, `1 year` - jen pro nové nákupy |
| Administrator e-mail | kam Namecheap pošle certifikát (povinné) |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (bez wildcardů), nebo *E-mail* + *Approver mailbox* |
| Web server type, More fields of the activation (pokročilé) | např. `nginx`; řádky `Name=value`, které chce aktivace OV/EV |
| API address, čekání (pokročilé) | prázdné; `600` / `300` / `20` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a vypíše certifikáty - nic nekupuje.
- V Namecheapu: **Product List → SSL Certificates** ukáže stav (*Active*, *Pending*).

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba `1011150` / *Invalid request IP* | IP acme není na seznamu povolených, nebo se *Client IP* liší od adresy, ze které acme skutečně volá |
| Neplatný API klíč / přístup k API vypnutý | zapněte přístup k API; zkopírujte klíč znovu |
| *a purchase would be needed* | nastavte *Certificate to reuse*, nebo zapněte *Allow new orders (paid)* |
| DCV čeká | CNAME / soubor ještě nebyl vidět - zvyšte čekání; e-mail vyžaduje schválení |
| Wildcard s HTTP DCV odmítnut | použijte DNS (CNAME) |
| Odvolání odmítnuto | API Namecheapu odvolává jen nahrazené certifikáty - obraťte se na podporu Namecheapu |
