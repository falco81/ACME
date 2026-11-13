# HPE Aruba Networking Central (AOS 10) - nastavení pro acme

Gatewaye a AP s AOS 10 nemají vlastní konfiguraci: jejich certifikáty jsou v **úložišti certifikátů Aruba Central** a odkazuje na ně profil (captive portál gatewaye, ukončení 802.1X, WebUI gatewaye, VPN). acme tam drží **jedno jméno**: první nasazení nahraje certifikát jako PKCS#12 pod tímto jménem, každá obnova ho **nahradí pod stejným jménem** - profily na něj dál odkazují a Central nový certifikát rozešle zařízením. Totéž platí pro Instant AP a switche CX spravované z Central.

```text
POST /oauth2/token?client_id=...&client_secret=...&grant_type=refresh_token&refresh_token=...
GET  /configuration/v1/certificates?limit=20&offset=0&q=<jméno>
POST /configuration/v1/certificates          poprvé
PUT  /configuration/v1/non_msp/certificate   při každé obnově
     {"cert_name", "cert_type": "SERVER_CERT", "cert_format": "PKCS12",
      "passphrase": <base64 jednorázového hesla>, "cert_data": <base64 PKCS#12>}
```

## Pro který Central

**Classic Central** (API Gateway, `apigw-...central.arubanetworks.com`). **New Central** (HPE GreenLake) zatím v oficiálním přehledu API pro úložiště certifikátů nemá - na něj tento modul není. **Mobility Conductory a kontrolery AOS 8** se takto nespravují: průvodce nenašel zdokumentované API, které by na ně nahrálo soubor certifikátu (jen CLI `crypto pki-import` po zkopírování souboru do flash) - acme pro ně modul nemá.

## Nastavení Central

1. Role pro API: *Account Home → Global Settings → Users and Roles* - role s **Network Operations: Modify** (zápis do konfigurace), bez správy *Account Home*. Uživatel jen se čtením dostane `403 No write access to upload certificates`. *Nejisté*: názvy menu jsou z obecné znalosti průvodce.
2. Klient API a token: *Organization → Platform Integration → REST API*: vytvořte pro tohoto uživatele systémovou aplikaci a token. Poznamenejte si **client ID**, **client secret**, **refresh token** tokenu a URL **API gateway** z té stránky (např. `https://apigw-prod2.central.arubanetworks.com` pro US-2, `https://eu-apigw.central.arubanetworks.com` pro EU-1).
3. V konfiguraci skupiny jednou certifikát pojmenujte (captive portál, serverový certifikát 802.1X...) - po prvním nasazení, jménem, které zadáte do acme.

Refresh token se obnovením **spotřebuje**: acme si ponechá nový, který Central vrátí (ve svém stavu, sdíleném v clusteru). Když acme hlásí odmítnuté obnovení (token se obnovil jinde, nebo acme neběželo déle, než refresh token platí), vytvořte nový token a jeho refresh token vložte do cíle.

Ručně zkoušejte obnovení jen s tokenem, který acme nepoužívá:

```sh
curl -s -X POST "https://apigw-prod2.central.arubanetworks.com/oauth2/token?client_id=<id>&client_secret=<secret>&grant_type=refresh_token&refresh_token=<refresh>"
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| API gateway | URL z kroku 2 |
| ID klienta / Tajný klíč klienta | klienta API |
| Refresh token | refresh token tokenu z kroku 2 |
| Jméno v Central (nasazení) | jméno, které používají profily, např. `captive-portal` |

## Ověření

```sh
curl -s -H "Authorization: Bearer <access token>" "https://apigw-prod2.central.arubanetworks.com/configuration/v1/certificates?limit=20&offset=0&q=captive-portal"
openssl s_client -connect <ip-captive-portalu>:443 -servername captive.example.com </dev/null | openssl x509 -noout -subject -dates
```

V Central: úložiště certifikátů (*Organization → Network Structure → Certificates*), datum vypršení. Na gatewayi (*Tools → Console*):

```text
show crypto-local pki ServerCert
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| *Central refused the token refresh* | refresh token je spotřebovaný nebo prošlý | nový token; jeho refresh token do cíle |
| `403` | role nesmí zapisovat konfiguraci | Network Operations: Modify |
| `400` při nahrazení | znovu stejný certifikát (Central odmítne stejný kontrolní součet), nebo jiný typ téhož jména | *vynutit* jen s novým certifikátem; jiné jméno |
| *... is a CA_CERT, not a server certificate* | jméno patří jinému druhu certifikátu | jiné jméno |
| `429` | omezení rychlosti Central | acme počká samo |

Zákazníci účtu MSP se aktualizují jiným voláním (`msp_update_certificate`) - acme ho nepoužívá.

*Nejisté*: tvar odpovědi seznamu (`items` s `cert_name`); restart služby na gatewayi po rozeslání není v dokumentaci.

Zdroje: reference API Aruba Central (Configuration → Certificates: upload, get, delete, update for non-MSP customers), `pycentral` od Aruby (`base.py`: obnovení tokenu).
