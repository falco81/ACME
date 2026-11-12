# HPE OneView / Synergy Composer - nastavení pro acme

acme vymění **HTTPS certifikát appliance** - webové rozhraní, REST API a HPE SSO do
spravovaných iLO a OA - na VM appliance HPE OneView nebo na HPE Synergy Composeru (HPE
OneView for Synergy) za vlastní klíč a certifikát. Přes REST API:

1. přečte verzi API, kterou appliance bere (`GET /rest/version`, `currentVersion`; acme
   posílá nejvýš `9200` = OneView 11.50, nejnovější, proti které byl modul ověřen), a
   přihlásí se (`POST /rest/login-sessions`, `sessionID` v hlavičce `Auth`);
2. vloží každou mezilehlou CA do trust storu appliance (`POST /rest/certificates/ca`,
   alias `acme-<id>`; už vloženou přeskočí) - HPE chce vydávající CA mít v trust storu
   **před** importem certifikátu appliance;
3. nahraje klíč a certifikát jako **PKCS#12** s jednorázovým heslem
   (`PUT /rest/certificates/https/pkcs12`, multipart `file`, hlavička `Password`) a počká
   na úlohu importu (`/rest/tasks/<id>`);
4. odhlásí se.

Appliance potom **znovu načte webové služby**: přihlášené relace GUI a API se přeruší (VM se
nerestartuje, spravovaných serverů se to nedotkne) a v téže úloze se nový SSO certifikát
rozešle do spravovaných iLO/OA.

**Jen klíče RSA** - HPE: „only RSA certificates are supported for the appliance
certificate“ (2048; 3072 v bezpečnostním režimu CNSA). Certifikát ECDSA acme odmítne dřív,
než cokoli změní.

## Pro které verze

Jeden modul pro **HPE OneView 9.x, 10.x a 11.x** (REST API 6600 - 9200) na VM appliance i
na **Synergy Composer / Composer2 / Composer3**: volání `/rest/certificates` jsou ve všech
stejná (SDK HPE žádnou změnu neuvádějí). Na starší appliance acme upozorní, ale neodmítne
ji. HPE Compute Ops Management pro tyto certifikáty API nemá - certifikát iLO se mění přímo
na iLO (verze *HPE iLO* cíle Redfish).

## Co potřebujete

- Síťový přístup z acme na appliance: **TCP 443**, (virtuální) IP nebo FQDN appliance - u
  páru Composerů adresu appliance, ne vlastní adresu modulu.
- Uživatele OneView s rolí **Infrastructure administrator** bez omezení scope (certifikát
  appliance a trust store jsou nastavení appliance).
- Název hostitele a DNS appliance (*Settings → Appliance → Network*) odpovídající
  certifikátu a NTP.

## Nastavení OneView

Vytvořte lokální servisní účet (jako administrátor; `9200` je OneView 11.50 - použijte to,
co vrátí `GET /rest/version`):

```sh
OV=https://oneview.example.com
AUTH=$(curl -sk -X POST "$OV/rest/login-sessions" -H "X-API-Version: 9200" \
  -H "Content-Type: application/json" \
  -d '{"userName":"administrator","password":"<heslo-admina>","authLoginDomain":"LOCAL","loginMsgAck":true}' \
  | jq -r .sessionID)

curl -sk -X POST "$OV/rest/users" -H "X-API-Version: 9200" -H "Auth: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"type": "UserAndPermissions", "userName": "svc-acme", "fullName": "acme certificate manager",
       "password": "<silne-heslo>", "enabled": true, "emailAddress": "pki@example.com",
       "permissions": [{"roleName": "Infrastructure administrator"}]}'
```

V GUI: *Settings → Users and Groups → Add user*, role *Infrastructure administrator*.
Funguje i adresářový účet: v acme pak zadejte jeho přihlašovací doménu.

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa | FQDN appliance, např. `oneview.example.com` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-acme` z předchozího kroku |
| Přihlašovací doména | `LOCAL`, nebo název adresářové přihlašovací domény |
| Verze API (pokročilé) | prázdné: co řekne appliance (nejvýš 9200); nebo např. `7600` |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má appliance self-signed certifikát |
| Certifikát CA (pokročilé) | CA současného certifikátu appliance, není-li veřejná |
| Vložit mezilehlé certifikáty do trust storu (nasazení) | zapnuto (doporučuje HPE) |
| Čekat na úlohu importu (s) (nasazení, pokročilé) | `300` |
| Zkontrolovat, co se servíruje (nasazení) | prázdné: acme kontroluje vlastní adresu appliance |

Certifikát: typ klíče **RSA**; v certifikátu FQDN appliance (a jména/IP, pod kterými k ní
přistupují uživatelé a spravovaná zařízení).

## Kontrola

```sh
openssl s_client -connect oneview.example.com:443 -servername oneview.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sk "https://oneview.example.com/rest/certificates/https" -H "X-API-Version: 9200" -H "Auth: $AUTH" | jq .
curl -sk "https://oneview.example.com/rest/certificates/ca" -H "X-API-Version: 9200" -H "Auth: $AUTH" \
  -H "If-Req-CertDetails: true" | jq '.members[].certificateDetails | {aliasName, commonName, validUntil}'
```

PowerShell (`HPEOneView.1000`): `Get-OVApplianceCertificateStatus`,
`Get-OVApplianceTrustedCertificate`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | špatný uživatel, heslo nebo přihlašovací doména |
| `403` | uživatel není *Infrastructure administrator*, nebo má omezený scope |
| `400` kvůli `X-API-Version` | nastavte *Verze API* na verzi, kterou appliance bere (`GET /rest/version`) |
| *only an RSA certificate* | zvolte pro certifikát typ klíče RSA |
| úloha importu skončí „invalid certificate“ | v trust storu chybí vydávající CA - nechte zapnuté vkládání mezilehlých certifikátů, nebo kořenovou CA přidejte ručně |
| *the end of the certificate import could not be read* | webové služby se znovu načetly, zatímco se acme ptalo; zda se to povedlo, ukáže test toho, co se servíruje |
| spravovaná zařízení po změně CA nedůvěryhodná | trust store musí dál obsahovat CA certifikátů spravovaných zařízení |

*Nejisté*: nejmenší potřebnou roli pro certifikát appliance HPE neuvádí (předpoklad:
Infrastructure administrator); hlavičky `Password` / `uploadfilename` při nahrání PKCS#12
pocházejí z PowerShell modulu HPE, ne z API reference.

Zdroje: HPE POSH-HPEOneView 10.00 (`Install-OVApplianceCertificate`,
`Add-OVApplianceTrustedCertificate`, `Get-OVApplianceCertificateStatus`), HPE
oneview-python (`/rest/login-sessions`, `endpoints-support.md`, verze API), HPE
oneview-ansible-collection 11.5.0.
