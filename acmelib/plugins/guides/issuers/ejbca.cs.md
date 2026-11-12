# EJBCA (REST API) - nastavení pro acme

Zdroj **EJBCA (REST API)** nechá vydávat certifikáty EJBCA (Keyfactor; Community nebo Enterprise) přes jeho REST rozhraní pro správu certifikátů: `POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll` s CSR vytvořeným acme, certifikačním profilem, profilem koncové entity, CA, jménem entity a enrollment kódem - **soukromý klíč nikdy neopustí acme**. Odvolání je `PUT .../v1/certificate/<issuer DN>/<serial>/revoke`; *Try it* čte `/v1/certificate/status` a `/v1/ca`; *Import from a source* používá `/v1/certificate/search`. acme se přihlašuje **klientským certifikátem administrátora** (vzájemné TLS). Seznamy profilů koncových entit a jejich certifikačních profilů pocházejí z `/v2/endentity/...`, pravděpodobně jen v EJBCA Enterprise - na Community jména napište ručně.

## Co potřebujete

- EJBCA dosažitelné **z acme** přes HTTPS (veřejný webový port, obvykle `443` nebo `8443`) s autentizací klientským certifikátem.
- Zapnutý protokol REST.
- CA, **profil koncové entity** a **certifikační profil** pro TLS servery.
- Administrátorský certifikát (a klíč) pro acme v roli s minimálními právy níže.

## Nastavení EJBCA

1. **System Configuration → Protocol Configuration**: zapněte **REST Certificate Management** (a **REST Certificate Management V2** pro seznamy a vyhledávání na Enterprise).
2. Profily: **Certificate Profile** (např. `SERVER`: algoritmy klíčů RSA/ECDSA, jak je acme používá, Server Authentication, platnost) a **End Entity Profile** (např. `TLS_SERVERS`: CN subjektu, SAN typu DNS Name - tolik, kolik vaše certifikáty mají, dostupná CA a certifikační profil).
3. Vydejte pro acme administrátorský certifikát: **RA Web → Make New Request** (nebo koncová entita s profilem pro client-auth), stáhněte ho s klíčem jako PEM.
4. **Roles and Access Rules → Add** roli `acme-rest`; *Members*: shoda s certifikátem acme (*X509: CN, Common name* = jeho CN, vydávající CA). Přístupová pravidla (Advanced mode), minimální sada:
   - `/ra_functionality/create_end_entity`, `/ra_functionality/edit_end_entity`, `/ra_functionality/view_end_entity`
   - `/ra_functionality/revoke_end_entity` (pro odvolání)
   - `/endentityprofilesrules/TLS_SERVERS/create_end_entity`, `.../edit_end_entity`, `.../view_end_entity`, `.../revoke_end_entity`
   - `/ca/IssuingCA`
   - `/administrator`
5. Řetězec CA: **CA Functions → CA certificate** - pro kontrolu, a TLS kořen pro *CA certificate of EJBCA's TLS*, je-li potřeba.

Ověření z příkazové řádky v síti acme:

```sh
curl --cert acme-admin.pem --key acme-admin.key \
  https://ejbca.example.local/ejbca/ejbca-rest-api/v1/ca
```

## Vyplnění v acme

Zdroje → **Přidat** → **EJBCA (REST API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| EJBCA address | `https://ejbca.example.local` (`/ejbca/ejbca-rest-api` se doplní) |
| Administrator's client certificate / Client certificate's key | PEM z kroku 3, za ním řetězec |
| CA | např. `IssuingCA` - *Load the list* čte `/v1/ca` |
| End entity profile | např. `TLS_SERVERS` (seznam: Enterprise; na Community napište ručně) |
| Certificate profile | např. `SERVER` (výchozí); vlastní profil certifikátu má přednost |
| End entity name | `{cn}` (výchozí) - první jméno; `{id}` id v acme |
| Enrollment code | prázdné: pro každou žádost se vytvoří nový |
| E-mail, Account binding ID (pokročilé) | kde je profil koncové entity vyžaduje |
| CA certificate of EJBCA's TLS / Check EJBCA's TLS certificate (pokročilé) | pro privátní TLS certifikát |

## Ověření

- Zdroje → zdroj → **Test** (Try it): stav a CA, které administrátor vidí.
- Po vydání: **RA Web → Search → End Entities** ukáže koncovou entitu (`{cn}`) a její certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `Not authorized to resource` | roli chybí některé pravidlo výše, nebo shoda členů neodpovídá certifikátu acme |
| TLS handshake selže | EJBCA nedůvěřuje vydavateli administrátorského certifikátu acme, nebo se klientský certifikát neposílá (reverzní proxy bez předání client-auth) |
| `REST ... is not enabled` / 403 | zapněte REST Certificate Management v Protocol Configuration |
| `Load the list` hlásí, že volání neexistuje | EJBCA Community: napište jména profilů ručně |
| Jméno nebo klíč odmítnut | profil entity / certifikační profil nepovoluje tento počet SAN, jméno nebo algoritmus klíče |
| `202` - čeká na schválení | je nastaven profil schvalování: schvalte v EJBCA; acme se zeptá znovu při dalším pokusu |
