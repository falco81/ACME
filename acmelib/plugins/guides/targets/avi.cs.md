# VMware Avi Load Balancer (NSX ALB) - nastavení pro acme

acme se přihlásí do **REST API Avi Controlleru** (`POST /login`), jednou přidá mezilehlé
certifikáty jako CA certifikáty (`acme-ca-<id>`, Avi z nich sestaví řetězec), přidá
certifikát jako SSL klíč a certifikát pod jménem s datem, nasměruje na něj zadané virtuální
služby místo starší položky acme (`PATCH /api/virtualservice/<uuid>`) a - je-li zapnuto -
z něj udělá certifikát vlastního portálu Controlleru. Starší certifikáty acme nad počet
*ponechat* smaže (Avi nesmaže certifikát, který se používá). Na konci se odhlásí. Duální
certifikát (EC + RSA) dá virtuální službě jeden od každého druhu.

Pro Controllery Avi Vantage / NSX Advanced Load Balancer / VMware Avi Load Balancer s REST
API (verze s hlavičkou `X-Avi-Version`, např. 20.x, 21.x, 22.x a novější).

## Co potřebujete

- Správcovskou adresu Controlleru (IP clusteru nebo uzel), **HTTPS, TCP 443**, dostupnou z
  acme.
- **Lokálního** nebo vzdáleného (LDAP/TACACS+) uživatele Controlleru, který se může
  přihlásit heslem.
- Jména virtuálních služeb, které mají certifikát používat, a jejich tenant.

## Nastavení Avi Controlleru

1. Vytvořte pro acme roli: **Administration → Accounts → Roles → Create** (ve starších
   verzích *Administration → User Credentials/Roles*). Dejte jí **Write** na:
   - **Templates → Security → SSL/TLS Certificates** (`sslkeyandcertificate`),
   - **Applications → Virtual Services** (`virtualservice`),
   - jen pro *Controller portal certificate*: **Administration → System Configuration**
     (`systemconfiguration`).
   Vše ostatní může být **No Access**. Názvy oprávnění se mezi verzemi mírně liší -
   ověřte je na své.
2. Vytvořte uživatele: **Administration → Accounts → Users → Create**, silné heslo, roli z
   kroku 1 a **tenant** virtuálních služeb (např. `admin`).
3. Pokud omezujete přístup ke správě (**Administration → Settings → Access Settings**,
   povolené IP), přidejte adresu serveru acme.
4. Poznamenejte si jména virtuálních služeb (**Applications → Virtual Services**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | IP / DNS jméno clusteru Controlleru, např. `avi-controller.example.local` |
| HTTPS port | `443` |
| User | Uživatel z kroku 2 (výchozí `admin` - lépe samostatný) |
| Password | Jeho heslo |
| Tenant | Tenant virtuálních služeb a certifikátů (výchozí `admin`) |
| API version (pokročilé) | Prázdné: vlastní verze Controlleru; vyplňte (např. `22.1.3`), pokud ji acme nepřečte |
| Check the device's certificate | Zapnuto; vypnout jen dokud má Controller self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu Controlleru, pokud není veřejná |
| Virtual services (nasazení) | Jedna na řádek, např. `vs-www` |
| Controller portal certificate (nasazení) | Zapnuto: i pro webové rozhraní a API Controlleru - použijte na to samostatné nasazení |
| Add the intermediates as CA certificates (nasazení, pokročilé) | Zapnuto (Avi hledá řetězec mezi svými CA certifikáty) |
| Previous versions to keep (pokročilé) | Výchozí 1; `-1` ponechá vše |
| Check what is served | Jméno a port VIP, např. `www.example.com:443` |

**Discover** (ve formuláři) se přihlásí a nabídne verzi Controlleru jako *API version*.

## Ověření

- **Try**: `signed in to ..., (Avi 22.1.3), tenant admin; N certificates`.
- Na Controlleru: **Templates → Security → SSL/TLS Certificates** ukazuje
  `acme-<jméno>-<datum>-<sériové číslo>` a **SSL Settings** virtuální služby na něj odkazují.
- Z příkazové řádky:

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the Controller gave no session on signing in` | Chybný uživatel/heslo, nebo se uživatel nesmí přihlásit do API |
| 403 při přidání certifikátu nebo úpravě virtuální služby | Role nemá Write na SSL/TLS Certificates nebo Virtual Services, nebo chybný tenant |
| Virtuální služba nenalezena | Chybné jméno nebo chybný *Tenant* |
| Chyby verze (`X-Avi-Version`) | Nastavte *API version* na verzi Controlleru |
| Starší certifikát se nesmazal | Avi nesmaže používaný certifikát; smaže se později |
| Změna portálu odmítnuta | Role potřebuje Write na System Configuration |
