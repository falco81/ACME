# Palo Alto Networks PAN-OS - nastavení pro acme

acme komunikuje s **XML API** firewallu (`/api/`). Naimportuje certifikát s klíčem jako
pár klíčů PKCS#12 pod jménem `acme-<jméno>-<datum>-<sériové číslo>` (sdílený, nebo ve
virtuálním systému), každý mezilehlý certifikát jako certifikát `acme-ca-<id>`, nasměruje
zadané **SSL/TLS service profiles** (portál/brána GlobalProtect, správcovské GUI...) na
nový certifikát, smaže starší certifikáty acme nad počet *Previous versions to keep*
(ten, na který se něco odkazuje, zůstane), pak provede **commit** a počká na dokončení
úlohy commitu.

Pro firewally PAN-OS (hardware i VM-Series). **Panorama podporovaná není**: pro každý
firewall založte v acme samostatný cíl.

## Co potřebujete

- Firewall PAN-OS se správcovským rozhraním dostupným z acme přes **HTTPS, TCP 443** (nebo
  váš správcovský port).
- SSL/TLS service profiles, které mají certifikát používat, už existují (acme jim nastaví
  certifikát, nevytváří je).
- U firewallů s více vsys: jméno virtuálního systému (např. `vsys1`), pokud certifikát
  nemá být sdílený.

## Nastavení PAN-OS

1. Vytvořte roli správce: **Device → Admin Roles → Add**, např. `acme-api`:
   - záložka **XML API**: zapněte **Configuration**, **Import**, **Commit** a **Operational
     Requests**; ostatní nechte vypnuté.
   - záložka **Web UI**: zapněte **Device → Certificate Management** (a vypněte, co acme
     nepotřebuje).
   - **Command Line**: None.
2. Vytvořte správce: **Device → Administrators → Add**, např. `acme`, *Administrator Type*
   **Role Based**, profil `acme-api`, silné heslo.
3. Proveďte commit.
4. Buď nechte acme přihlašovat jménem a heslem (samo zavolá `type=keygen`), nebo jednou
   vygenerujte klíč API a dejte acme jen klíč:

   ```sh
   curl -k -X POST 'https://pa.example.local/api/?type=keygen' \
        --data-urlencode 'user=acme' --data-urlencode 'password=<heslo>'
   ```

   `<key>` v odpovědi je klíč API.
5. Má-li správcovské rozhraní **Permitted IP Addresses** (*Device → Setup → Interfaces →
   Management*), přidejte IP adresu serveru acme.
6. Poznamenejte si jména SSL/TLS service profiles (**Device → Certificate Management →
   SSL/TLS Service Profile**).

**Na způsobu commitu záleží**: se jménem a heslem acme commituje jen změny svého správce
(partial commit). S klíčem API pošle úplný commit - projdou i rozpracované změny jiných
správců. Pokud to nechcete, zvolte *do not commit*.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Správcovské jméno nebo IP, např. `pa.example.local` |
| HTTPS port | `443` |
| Sign in with | *an API key* nebo *user and password* |
| API key | Klíč z kroku 4 |
| User / Password | Správce `acme` z kroku 2 |
| Virtual system (pokročilé) | Prázdné pro sdílený (*Device → Certificates*, shared), nebo např. `vsys1` |
| Check the device's certificate | Zapnuto; vypnout jen dokud má firewall self-signed certifikát |
| CA certificate (pokročilé) | CA správcovského certifikátu, pokud není veřejná |
| SSL/TLS service profiles (nasazení) | Jeden na řádek, např. `gp-portal-profile`, `mgmt-ssl` |
| Commit (nasazení) | *commit acme's own changes only* (výchozí), *commit everything pending*, nebo *do not commit* |
| PKCS#12 kind (nasazení, pokročilé) | *3DES (any PAN-OS)*; *AES-256* jen pro novější PAN-OS, který ho přijme |
| Wait for the commit (s) (pokročilé) | Výchozí `600` |
| Previous versions to keep (pokročilé) | Výchozí 2, `-1` ponechá vše |
| Check what is served | např. `gp.example.com:443` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, přečte `type=version` a odpoví
  `signed in to <hostname>, <model> PAN-OS x.y.z`.
- Na firewallu po nasazení:

  ```text
  show config running xpath shared/certificate
  show jobs all
  ```

  a v **Device → Certificate Management → Certificates** je `acme-...`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `PAN-OS said Invalid credentials` / kód 403 | Špatný klíč nebo heslo, nebo role nemá výše uvedená práva XML API. |
| Import odmítnut | Role nemá XML API *Import*; nebo starší PAN-OS nepřečte PKCS#12 s AES-256 - použijte *3DES*. |
| `the commit failed: ...` | Přečtěte zobrazené podrobnosti úlohy; vadná rozpracovaná změna jiného správce shodí úplný commit - použijte partial commit (jméno + heslo). |
| `the commit ... has not finished in 600s` | Vytížený firewall: zvyšte *Wait for the commit (s)*. |
| `the old ... stays (still used?)` | Odkazuje na něj ještě profil nebo služba; smaže se později, až nebude používán. |
| Zařízení spravované Panoramou certifikát přepíše | Panorama podporovaná není: spravujte tyto certifikáty lokálně nebo mimo acme. |
