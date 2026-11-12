# HPE Alletra 5000/6000, Nimble Storage (NimbleOS) - nastavení pro acme

acme vymění **vlastní (custom) certifikát skupiny** - používaný webovým rozhraním HTTPS
(port 443) a/nebo REST API (port 5392) - přes REST API NimbleOS:

1. přihlásí se: `POST /v1/tokens` `{"data": {"username", "password", "app_name": "acme"}}`,
   `session_token` v hlavičce `X-Auth-Token`;
2. naimportuje klíč, certifikát a řetězec jako **PKCS#12** (base64, jednorázové heslo):
   `POST /v1/certificates/actions/import`
   `{"data": {"name": "custom", "input": "<base64>", "pkcs12": true, "password": "...", "force": true}}`;
3. začne ho používat: `POST /v1/certificates/actions/use`
   `{"data": {"name": "custom", "https": true, "apis": true}}`;
4. odhlásí se (`DELETE /v1/tokens/<id>`).

Webový server GUI a/nebo REST API se potom **znovu načtou**: jejich relace se přeruší.
**Datové cesty hostitelů (iSCSI/FC) se to netýká**, kontrolery se nerestartují.

> **Nejdřív ověřte názvy akcí.** Veřejná SDK HPE uvádějí pole objektu `certificates`
> (`name`, `input`, `pkcs12`, `password`, `force`, `https`, `apis`, `reload_https`,
> `reload_apis`) a konvenci URL `/v1/<objekt>/actions/<akce>`, ale REST API Reference
> NimbleOS (na HPE InfoSight, za přihlášením) se přečíst nepodařilo - názvy `import` a
> `use` jsou předpoklad acme. Jsou to nastavení nasazení (*Více*): pokud je vaše verze
> NimbleOS jmenuje jinak, zadejte tam její cesty. Špatný název vrátí 404 a acme to oznámí;
> nic se přitom nezmění.

## Pro které verze

Jeden modul pro **NimbleOS 5.x a 6.x** (HPE Alletra 5000/6000, Nimble AF/HF): SDK u
objektu certificates žádný rozdíl neukazují. Není pro HPE Alletra 9000 / Alletra Storage
MP B10000 (jiný systém: jejich CLI vytváří klíč na poli a klíč z acme nepřijme).

## Co potřebujete

- Síťový přístup z acme na management IP skupiny: **TCP 5392** (REST API, standardně
  zapnuté) - a 443 pro kontrolu GUI.
- Uživatele NimbleOS s rolí **administrator** (zda stačí *poweruser*, není
  zdokumentováno).
- NTP na skupině.

## Nastavení pole

Vytvořte uživatele - v GUI (*Administration → Users and Groups*), přes Ansible
(`hpe.nimble`):

```text
- name: acme service account
  hpe.nimble.hpe_nimble_user:
    host: "{{ nimble_host }}"
    username: "{{ admin_user }}"
    password: "{{ admin_pass }}"
    name: svc-acme
    user_password: "<silne-heslo>"
    role: administrator
    description: "acme certificate manager"
    state: present
```

nebo přes REST API:

```sh
TOKEN=$(curl -sk -X POST "https://nimble.example.com:5392/v1/tokens" -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"<heslo-admina>"}}' | jq -r .data.session_token)
curl -sk -X POST "https://nimble.example.com:5392/v1/users" -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"name":"svc-acme","password":"<silne-heslo>","role":"administrator"}}'
```

Podívejte se na certifikáty skupiny (`custom` je ten, který acme vyměňuje):

```sh
curl -sk "https://nimble.example.com:5392/v1/certificates/detail" -H "X-Auth-Token: $TOKEN" \
  | jq '.data[] | {name, trusted, subject}'
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa | management FQDN nebo IP skupiny, např. `nimble.example.com` |
| Port HTTPS | `5392` (REST API) |
| Uživatel / Heslo | `svc-acme` z předchozího kroku |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má skupina self-signed certifikát |
| Certifikát CA (pokročilé) | CA současného certifikátu skupiny, není-li veřejná |
| Použít pro webové rozhraní HTTPS (443) (nasazení) | zapnuto |
| Použít pro REST API (5392) (nasazení) | zapnuto - klienti, kteří si pamatují starý certifikát, musí přijmout nový |
| Název certifikátu (nasazení, pokročilé) | `custom` |
| Akce importu / Akce použití (nasazení, pokročilé) | `/v1/certificates/actions/import`, `/v1/certificates/actions/use` - nebo co uvádí REST reference vaší verze NimbleOS |
| Zkontrolovat, co se servíruje (nasazení) | prázdné: acme kontroluje 443 a/nebo 5392 té adresy |

Certifikát: obsahuje management FQDN a IP skupiny (a ty, přes které se připojují klienti).

## Kontrola

```sh
openssl s_client -connect nimble.example.com:443 -servername nimble.example.com </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect nimble.example.com:5392 -servername nimble.example.com </dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | špatné jméno nebo heslo |
| `403` | uživatel nemá roli *administrator* |
| *the group has no action ...* | vaše verze NimbleOS akci jmenuje jinak - najděte ji v REST API Reference (InfoSight) a nastavte *Akce importu* / *Akce použití* |
| přestane fungovat plugin vCenter / VASA provider | vCenter si pamatuje otisk starého certifikátu - zaregistrujte je znovu |
| PowerShell Toolkit skupinu odmítá | znovu `Connect-NSGroup -ImportServerCertificate` (Windows) |

Zdroje: HPE nimble-python-sdk (`restclient.py`: port 5392, `v1/tokens`, `X-Auth-Token`,
`/{object}/actions/{action}`), HPE nimble-golang-sdk (`certificate.go`, `ns_cert_data.go`,
`ns_user_roles.go`), HPE nimble-ansible-modules 1.1.4.
