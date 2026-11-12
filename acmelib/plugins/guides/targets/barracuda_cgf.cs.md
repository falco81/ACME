# Barracuda CloudGen Firewall - nastavení pro acme

acme mluví s **REST API** firewallu CloudGen (samostatný box) nebo **Firewall Control Center** (HTTPS, port 8443) a certifikát s řetězcem a klíčem naimportuje **na místo do jedné položky Certificate Store**:

```text
PUT /rest/config/v1/box/store/certificates/<položka>
{"action": "import", "certificates": "<certifikát + mezilehlé, PEM>", "key": "<PEM>", "comment": "acme ..."}
```

Služby, které položku používají (SSL VPN / CudaLaunch, příchozí TLS Inspection, Access Control Service, Mail Security…), na ni odkazují jménem, takže ji drží dál - Barracuda: *„References to this key and certificate will be updated automatically“*. acme pak položku přečte zpět a ověří, že obsahuje nový certifikát (podle otisku SHA-256). Nic se nemaže: položka je jedna a obnovuje se na místě.

## Pro které verze

CloudGen Firewall / Control Center **10.0 a 10.5** (stejná volání; Swagger *Box configuration - 10.5 / 10.0* a *CC Configuration - 10.5*). **9.0** má jen `GET /rest/config/v1/box/certificates` (pouze čtení): acme to oznámí a nic nemění - na 9.0 certifikát naimportujte ve Firewall Admin.

Firewall spravovaný z Control Center **nemá vlastní úložiště**: nasměrujte acme na Control Center a zvolte jeho globální úložiště, úložiště rozsahu (range) nebo clusteru (range / cluster potřebuje *Own certificate store Settings: Yes*).

## 1. Zapněte REST API

*CONFIGURATION > Configuration Tree > Box > Infrastructure Services > REST API Service* → **Lock**:

- **Enable HTTPS interface**: ano, **HTTPS Port** 8443 (výchozí);
- **Bind to Management IPs**: ano (jinak poslouchá jen na loopbacku);
- **New Key** / **Ex/import**: certifikát samotného REST rozhraní - jeho CN musí odpovídat jménu, které používá acme (např. `cgf1.example.local` pro `https://cgf1.example.local:8443`); tento certifikát lze změnit jen ve Firewall Admin, ne přes REST;
- **Send Changes** → **Activate**.

Ve firewallových pravidlech povolte TCP 8443 z adresy acme. HTTP rozhraní (8080) poslouchá jen na 127.0.0.1 - acme používá HTTPS.

## 2. Účet pro acme

**Samostatný box**: *Box > Administrators* → **Lock** → **+** - role **Manager** (zápis do konfigurace včetně Certificate Store; jemnější role nejsou), *System Level Access* **No OS Login**, *Authentication Level* Password, *Peer IP Restriction* = adresa acme. Totéž přes REST (s tokenem stávajícího administrátora):

```sh
curl -s -X POST "https://cgf1.example.local:8443/rest/config/v1/box/admins" \
  -H "X-API-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"svc-acme","fullName":"acme certificates","password":"<heslo>","roles":["Manager"],
       "systemLevelAccess":"noOsLogin","authenticationLevel":"password","peerIpRestriction":["192.0.2.10"]}'
```

**API token** pro něj (*REST API Service* → **Access Tokens** → **+** → Name → **Generate new token** → Admin name `svc-acme`, Time to live nejvýš 365 dní), nebo přes REST:

```sh
curl -s -X POST "https://cgf1.example.local:8443/rest/config/v1/box/admins/svc-acme/tokens" \
  -H "X-API-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"name":"acme","ttl":365}'
```

Token platí nejvýš rok - nastavte si připomínku jeho obnovy.

**Control Center**: *Multi-Range > Global Settings > Administrative Roles* → **Lock** → role s **Access to REST API** a **Write Access** → **Send Changes** → **Activate**; *ADMINS* → **+ New Admin** (Authentication Level Password, ACL s adresou acme), *Administrator Scopes*: nejmenší rozsah (Global, range nebo cluster), *Configuration Level* ≤ 2 (zápis), role výše, *Shell Level* **No**. acme se přihlašuje jménem a heslem tohoto administrátora (HTTP basic) nebo tokenem.

## 3. Položka Certificate Store

Použijte položku, na kterou už vaše služby odkazují (např. `vpn-portal` zvolenou jako *External-Certificate* SSL VPN). S volbou *Vytvořit položku, když neexistuje* (výchozí zapnuto) acme chybějící položku založí jako self-signed zástupce a hned přes ni naimportuje certifikát; službu pak na ni **jednou** nasměrujte ve Firewall Admin (výběr položky pro službu v REST API není) a dejte **Activate**.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | box nebo Control Center, `8443` |
| Přihlásit se přes | *API token (X-API-Token)* nebo *administrátora a heslo* |
| API token / Uživatel, Heslo | z kroku 2 |
| Certificate Store | *tohoto firewallu (samostatný box)*, nebo *Control Center: globální / rozsah (range) / cluster* |
| Range / Cluster | např. `1` a `prague` (jako v `/rest/cc/v1/config/ranges/1/clusters/prague/...`) |
| Ověřovat certifikát zařízení | zapnuto, s *Certifikátem CA*, když je certifikát REST rozhraní od privátní CA |
| Položka Certificate Store (nasazení) | jméno položky, např. `vpn-portal` |
| Klíč jako (nasazení, pokročilé) | PKCS#8; *tradiční (BEGIN RSA / EC PRIVATE KEY)* jen když ho box odmítne |
| Zkontrolovat, co se servíruje (nasazení) | kde ho služba ukazuje, např. `vpn.example.com:443` |

## Co potom

- **SSL VPN / CudaLaunch**: Barracuda službu restartuje jen při změně jejího nastavení. Pokud portál ukazuje starý certifikát, restartujte ji ve Firewall Admin: *VPN-Service > SSL-VPN* → **Enable SSL VPN** = no → **Activate** → yes → **Activate** (krátké přerušení relací SSL VPN).
- **Příchozí TLS Inspection**: serverový certifikát tam musí být ten, který má skutečný server - nasaďte stejný certifikát na oba.
- **HA**: cluster konfiguraci synchronizuje; měňte ji na Control Center nebo primárním uzlu.
- Box spravovaný z Control Center odmítne změny provedené přímo na boxu - použijte úložiště Control Center.

## Ověřte to

```sh
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -s "https://cgf1.example.local:8443/rest/config/v1/box/store/certificates/vpn-portal" \
  -H "X-API-Token: $TOKEN"
```

Ve Firewall Admin: sloupce Certificate Store **Expires**, **Has Key**, **Referenced by**; dvojklik → Certification Path.

## Časté problémy

| Odpověď | Význam | Řešení |
|---|---|---|
| *no Certificate Store endpoints ... 10.0 or later* | box s verzí 9.0 | upgrade, nebo import ve Firewall Admin |
| `401` / `403` | token vypršel nebo je špatný, administrátor bez role Manager / zápisu do REST, omezení Peer IP | nový token; role; adresa acme |
| `404` na úložišti range / clusteru | špatný range nebo cluster, nebo tam není vlastní úložiště | zkontrolujte jména; *Own certificate store Settings: Yes* |
| *does not hold the new certificate after the import* | změna čeká na aktivaci (*neověřeno*: zda se změny úložiště aktivují hned) | **Activate** ve Firewall Admin a nasaďte znovu |
| odmítnutý klíč | šifrovaný klíč nebo neobvyklý formát | *Klíč jako: tradiční* |

*Neověřeno* (z návodu výrobce): zda je změna úložiště aktivní bez Activate, zda `PUT ... action=import` umí založit chybějící položku (acme ji zakládá napřed), kde přesně je v odpovědi otisk.
