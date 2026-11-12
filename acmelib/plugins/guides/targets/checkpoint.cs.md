# Check Point (Management API) - nastavení pro acme

acme se přihlásí k Security Management Serveru (nebo k doméně Multi-Domain Serveru) přes
**Management API** (`/web_api/login`, uživatel a heslo, nebo API klíč). Naimportuje
certifikát jako **server certificate** (PKCS#12, base64) pod jménem s datem - nebo do
jednoho zadaného objektu, nahrazený na místě - a podle zadání:

- nasměruje na něj příchozí pravidla **HTTPS Inspection** (`set-https-rule`),
- dá ho **portálům** brány nebo clusteru (Gaia platform portal, UserCheck, captive portal
  Identity Awareness, SAML portál VPN),
- smaže starší objekty acme, které `where-used` najde nepoužité,
- **publikuje** session a je-li zadán balíček politik, **nainstaluje** jeho politiku
  Access Control. Při chybě před publikací se session zahodí. acme se vždy odhlásí.

Pro R80.40 a novější (Management API v1.6+; SAML portál potřebuje v2.1 / R82.10).

## Co potřebujete

- Adresu management serveru, **HTTPS 443** dostupné z acme (na Gaia serveru, který je
  zároveň bránou, nebo při jiném portu použijte ten port).
- Zapnuté Management API, které přijímá volání z IP acme.
- Administrátora s oprávněními uvedenými níže.

## Nastavení Check Point

1. Povolte volání API z acme: **SmartConsole → Manage & Settings → Blades → Management API
   → Advanced Settings → Accept API calls from**: *All IP addresses that can be used for
   GUI clients* (a přidejte IP acme mezi GUI clients / Trusted Clients) nebo *All IP
   addresses*. **Publish** a pak na management serveru (expert mode):

   ```sh
   api restart
   api status
   ```

2. Vytvořte profil oprávnění (**Manage & Settings → Permissions & Administrators →
   Permission Profiles → New**), typ *Customized*, se zápisem (*Edit*) na to, co nasazení
   používá:
   - objekty **Gateways** (server certificates jsou objekty; portály jsou nastavení brány),
   - politiku **HTTPS Inspection** (jen pokud nasměrováváte pravidla),
   - **Install Policy** (jen pokud acme instaluje balíček).
   Názvy položek oprávnění se mezi verzemi liší - ověřte je na své.
3. Vytvořte administrátora (**Permissions & Administrators → Administrators → New**) s
   tímto profilem; *Authentication Method*: **API Key** (doporučeno) nebo *Check Point
   Password*. Přes `mgmt_cli` na serveru:

   ```sh
   mgmt_cli -r true add administrator name "acme" permissions-profile "acme-certs" authentication-method "api key"
   mgmt_cli -r true add api-key admin-name "acme"
   mgmt_cli -r true publish
   ```

   Druhý příkaz jednou vypíše API klíč - zkopírujte ho do acme.
4. Poznamenejte si jména: vrstva a pravidla HTTPS Inspection, objekt brány/clusteru,
   balíček politik.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | Management server, např. `mgmt.example.local` / `443` |
| Sign in with | `a user and password` nebo `an API key` |
| User / Password | Administrátor (při přihlášení heslem) |
| API key | Klíč z kroku 3 |
| Domain (pokročilé) | Multi-Domain Server: jméno nebo UID domény; prázdné: výchozí |
| API version (pokročilé) | Prázdné: nejnovější; potřeba `v1.6` nebo novější |
| Check the device's certificate / CA certificate | Jako u každého HTTPS zařízení |
| Server certificate object (nasazení) | Prázdné: pokaždé nový objekt s datem; jméno: ten jeden objekt, nahrazený na místě |
| HTTPS Inspection rule / More HTTPS Inspection rules / HTTPS Inspection layer (nasazení) | Příchozí pravidlo (pravidla) a jejich vrstva, např. `Default Layer` |
| Gateway or cluster (portals) / It is (nasazení) | Objekt brány a zda jde o bránu, nebo cluster |
| Gaia platform portal / UserCheck portal / Identity Awareness captive portal / SAML portal of the VPN (nasazení) | Které portály certifikát dostanou |
| Install the policy package / Install on (nasazení) | Balíček k instalaci po publikaci a jeho brány (prázdné: jeho cíle) |
| PKCS#12 encryption (nasazení, pokročilé) | `3DES` (všechny verze) nebo `AES-256` |
| Wait for publish and install (s) (nasazení, pokročilé) | Výchozí 900 |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try** se přihlásí jen pro čtení: `signed in to ..., Management API 1.9; N server certificates`.
- **List the server certificates** je vypíše i s pravidly HTTPS - jen pro čtení.
- Na serveru:

  ```sh
  mgmt_cli -r true show server-certificates --format json
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení 403 / "API server not accessible from this IP" | Povolte IP acme v *Accept API calls from*, publikujte a `api restart` |
| `wrong credentials` / neplatný API klíč | Chybný klíč, nebo je administrátor zamčený |
| Chyby oprávnění při add / set / publish | Profil nemá zápis na objekty nebo HTTPS Inspection |
| Instalace selže | Profil nemá *Install Policy*, nebo chybný balíček/cíle - viz SmartConsole → Tasks |
| Objekt zamčen jinou session | Někdo má na stejném objektu nepublikované změny - publikujte je nebo zahoďte |
| Publikace trvá příliš dlouho | Zvyšte *Wait for publish and install* |
