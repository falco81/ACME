# Dell Unisphere for PowerMax (certifikát Solutions Enabler) - nastavení pro acme

**Co tento cíl dělá - a co ne.** Unisphere for PowerMax 10.x **nemá API pro svůj vlastní
certifikát HTTPS** (port 8443): Dell ho dokumentuje jen v GUI (**Settings → Security → Server
Certificates**: *Replace With Self-Signed Certificate*, *Generate CSR*, *Upload Certificates*),
z CSR, které si Unisphere vytvoří sám - klíč ho nikdy neopustí, takže acme tam svůj certifikát
dát nemůže. Ten vyměňte ručně.

API má **serverový certifikát Solutions Enabler (SYMAPI)** uzlů embedded management (eMGMT),
`Semgmt0` a `Semgmt1`: vlastní klíč, certifikát a trust file. acme je naimportuje přes
Serviceability REST API Unisphere, uzel po uzlu:

```text
GET  /univmax/restapi/version                     -> api_version (např. 101 = Unisphere 10.1)
POST /univmax/restapi/<api>/serviceability/symmetrix/<pole>/application/solutions_enabler/custom_certificate/import
     multipart/form-data: node_name=Semgmt0, keyfile=<klíč PEM>, certfile=<certifikát + mezilehlé>, trustfile=<certifikáty CA>
```

> **Nejisté.** Tato volání pocházejí z oficiálního Python SDK Dellu **PyU4V**
> (`serviceability.import_custom_certificate`); referenční příručku REST API Unisphere se
> přečíst nepodařilo. Nejdřív to vyzkoušejte na jednom uzlu (*Uzly správy*: `Semgmt0`).

## Pro který Unisphere

**Unisphere for PowerMax 10.0 - 10.4** s embedded management (PowerMaxOS 10). Unisphere 9.x
(REST API 9x) acme odmítne dřív, než cokoli změní; novější pokračuje s varováním.

## Účet

Bezpečnostní operace vyžadují **Administrator** nebo **SecurityAdmin** (StorageAdmin je dělat
nesmí); nejmenší je SecurityAdmin. Unisphere: **Settings → Users and Groups → Authorized Users
& Groups → Add** - lokální uživatel `acme`, role *SecurityAdmin*, rozsah pole.

## Trust file

SE server ověřuje **certifikáty svých klientů** podle certifikátů CA v trust file. Když
necháte *Důvěryhodné certifikáty CA* prázdné, acme tam dá mezilehlé certifikáty svého
certifikátu: to je správně, pokud certifikáty vašich SE klientů vydává stejná CA. Jinak do
*Důvěryhodné certifikáty CA* vložte certifikát(y) CA klientů (PEM). Návrat k self-signed
certifikátu Dellu:

```sh
curl -k -u admin:'<heslo>' -X POST "https://unisphere.example.local:8443/univmax/restapi/101/serviceability/symmetrix/000120000123/application/solutions_enabler/self_signed_certificate" \
  -H 'Content-Type: application/json' -d '{"node_name":"Semgmt0"}'
```

## Vyplňte v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | adresa Unisphere, `8443` |
| Uživatel / Heslo | účet `acme` |
| ID pole | dvanáctimístné Symmetrix ID, např. `000120000123` |
| Ověřovat certifikát zařízení | zapnuto, když je vlastní certifikát Unisphere důvěryhodný (nebo vyplňte *Certifikát CA*) |
| Uzly správy (nasazení) | `Semgmt0` a `Semgmt1`, každý na řádek |
| Důvěryhodné certifikáty CA (nasazení, rozšířené) | prázdné, nebo certifikáty CA klientů SE |

## Ověření

*Vyzkoušet* u cíle se přihlásí, přečte verzi REST API a embedded management pole. Na klientovi
Solutions Enabler:

```sh
openssl s_client -connect semgmt0.example.local:2707 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Vlastní certifikát Unisphere (acme ho nemění):

```sh
openssl s_client -connect unisphere.example.local:8443 -servername unisphere.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `acme needs Unisphere for PowerMax 10.0` | Unisphere 9.x - nepodporováno. |
| `401` / `403` | Špatné heslo, nebo účet není SecurityAdmin / Administrator. |
| `404` při importu | Nejde o embedded management, špatné ID pole, nebo se cesta ve vaší verzi liší - použijte GUI. |
| Klienti SE server odmítají | Trust file nebo důvěra na klientech: musí důvěřovat CA z acme. |
