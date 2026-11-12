# Dell iDRAC9 6.00.02+ / iDRAC10 (Redfish, Dell OEM) - nastavení pro acme

Tato verze cíle Redfish nahraje klíč a certifikát z acme do **Dell iDRAC** tak, jak Dell
dokumentuje pro klíč vytvořený jinde: přes vlastní službu iDRAC `DelliDRACCardService` -
nejdřív `UploadSSLKey` (klíč), potom `ImportSSLCertificate` s `CertificateType: Server`
(certifikát). Je to redfishová obdoba `racadm sslkeyupload -t 1` + `racadm sslcertupload -t 1`.
iDRAC pak **restartuje jen svůj webový server** (GUI, Redfish a vzdálený RACADM jsou na pár
desítek sekund nedostupné); server ani jeho operační systém to neovlivní.

## Pro které iDRAC tento návod je

Verze modulu **„Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM)“** (`6.00.02`):

| Řadič | Firmware | Tato verze |
|---|---|---|
| iDRAC10 (PowerEdge 17G) | 1.xx (ověřeno 1.10 - 1.30) | ano |
| iDRAC9 (14G, 15G, 16G) | 6.00.02.00 - 7.xx (ověřeno 7.00 - 7.20) | ano |
| iDRAC9 | starší než 6.00.02.00 | **odmítne** - použijte základní verzi s volbou *Potom restartovat řadič*, nebo aktualizujte firmware |
| jiný řadič než Dell iDRAC (iLO, XCC, BMC) | - | **odmítne** - použijte základní verzi |

acme přečte `FirmwareVersion` manageru (`/redfish/v1/Managers/iDRAC.Embedded.1`) a když
nesedí, odmítne dřív, než cokoli změní. Novější firmware, než jaký byl ověřen, pokračuje
s varováním.

Proč ne základní verze: Dell dokumentuje `CertificateService.ReplaceCertificate` na iDRAC jen
pro certifikát z **CSR, které vytvořil sám iDRAC** (samotný certifikát, `PEM`). Základní
verze posílá klíč uvnitř `CertificateString` - podle DMTF, což Dell pro iDRAC nedokumentuje.
Od iDRAC9 6.00.02 a na iDRAC10 není potřeba reset.

## Co potřebujete

- HTTPS z acme na iDRAC: **TCP 443** (nebo port z `iDRAC.WebServer.HttpsPort`).
- Zapnutý Redfish (výchozí stav):

  ```sh
  racadm set iDRAC.Redfish.Enable 1
  ```

- Libovolnou licenci iDRAC (ruční nahrání licenci nepotřebuje; jen automatická registrace
  vyžaduje Datacenter).
- Typ klíče, který iDRAC přijme: **RSA 2048 nebo 4096** na iDRAC9; na iDRAC10 raději
  **RSA 3072 nebo 4096** (iDRAC10 sám klíče 2048 bitů nevytváří; zda nahraný klíč 2048 bitů
  odmítne, není zdokumentováno). ECDSA zdokumentováno není.

## Účet (nejmenší oprávnění)

Dell: certifikát webového serveru vyžaduje **Login to iDRAC** + **Configure iDRAC**.
Předdefinovaná role *Operator* má obojí; nejmenší je vlastní role jen s těmito dvěma.

iDRAC9 přes RACADM (slot 5 jako příklad - použijte volný):

```sh
racadm set iDRAC.Users.5.UserName acme
racadm set iDRAC.Users.5.Password '<silne-heslo>'
racadm set iDRAC.Users.5.Privilege 0x3
racadm set iDRAC.Users.5.IpmiLanPrivilege 15
racadm set iDRAC.Users.5.Enable 1
```

`0x3` = Login (0x1) + Configure iDRAC (0x2) - na svém firmwaru ověřte příkazem
`racadm help iDRAC.Users.Privilege`. Přes Redfish s předdefinovanou rolí Operator:

```sh
curl -k -u admin:'<heslo-admina>' -X PATCH https://idrac.example.local/redfish/v1/AccountService/Accounts/5 \
  -H 'Content-Type: application/json' \
  -d '{"UserName":"acme","Password":"<silne-heslo>","RoleId":"Operator","Enabled":true}'
```

iDRAC10 už nemá roli *None*: v GUI (**iDRAC Settings → Users → Local Users → Add**) zvolte
**vlastní roli** (custom role) a zaškrtněte jen *Login* a *Configure iDRAC*.

## Co acme volá

```text
POST /redfish/v1/SessionService/Sessions                     {UserName, Password} -> X-Auth-Token
GET  /redfish/v1/Managers/iDRAC.Embedded.1                   FirmwareVersion
GET  /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService
POST .../DelliDRACCardService/Actions/DelliDRACCardService.UploadSSLKey         {"SSLKeyString": "<klíč PEM>"}
POST .../DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate {"CertificateType": "Server", "SSLCertificateFile": "<certifikát PEM>"}
POST /redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset {"ResetType": "GracefulRestart"}   (jen na požádání)
```

## Vyplňte v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM)** |
| Adresa / Port HTTPS | jméno nebo adresa iDRAC, `443` |
| Uživatel / Heslo | účet výše |
| Basic autentizace místo relace (rozšířené) | vypnuto; zapněte jen při plných relacích |
| Ověřovat certifikát zařízení | při prvním nasazení přes self-signed certifikát vypnuto (nebo vyplňte *Certifikát CA*), potom zapnuto |
| Poslat jako (nasazení) | *PEMchain*: certifikát s mezilehlými; *PEM*: jen certifikát |
| URI certifikátu (nasazení) | tato verze nepoužívá |
| Potom restartovat řadič (nasazení) | vypnuto - od 6.00.02 / na iDRAC10 není potřeba; zapněte jen tehdy, když zůstane servírován starý certifikát |

## Ověření

```sh
openssl s_client -connect idrac.example.local:443 -servername idrac.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
racadm -r idrac.example.local -u acme -p '<heslo>' sslcertview -t 1
```

*Vyzkoušet* u cíle vypíše model, firmware a `iDRAC9` / `iDRAC10`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `runs firmware 5.x ... needs iDRAC9 6.00.02` | Aktualizujte firmware iDRAC, nebo použijte základní verzi s volbou *Potom restartovat řadič*. |
| `offers no DelliDRACCardService.UploadSSLKey` | Firmware ji nemá - aktualizujte ho. |
| `403` u UploadSSLKey | Účtu chybí *Configure iDRAC*. |
| Import odmítnut | Klíč nesedí k certifikátu nebo není RSA; na iDRAC10 zkuste RSA 3072/4096; zkuste *Poslat jako* `PEM`. |
| Webový server nedostupný po aktualizaci firmwaru (iDRAC9 7.00 - 7.10.30) | Dell KB 000220891: přes SSH `racadm sslresetcfg`, pak nasaďte znovu. |
| Stále je servírován starý certifikát | Počkejte minutu (webový server se restartuje); jinak zapněte *Potom restartovat řadič*. |
