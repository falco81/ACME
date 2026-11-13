# Komponenta VMware Cloud Foundation 9.1 přes VCF Operations – nastavení pro acme

Správa flotily ve VCF Operations přijme **jen certifikát podepsaný pro CSR, který sama
vytvořila**: import páruje certifikát s CSR ve svém úložišti klíčů (`400`, když leaf
neodpovídá žádnému CSR) – privátní klíč vytvořený jinde naimportovat nelze. Proto **klíč
vytváří VCF**: při každém vydání a obnově se acme přihlásí do VCF Operations, najde TLS
certifikát komponenty (`POST .../certificate-management/certificates/query`), nechá VCF
vytvořit nový klíč a CSR (`POST .../certificate-management/csrs`, workflow), přečte CSR
(`GET .../csrs?certificateId=`), nechá ho podepsat zdrojem certifikátu a hned poté nechá VCF
nahradit certifikát podepsaným i s řetězcem (`PUT .../certificate-management/certificates/{id}`
s `caType` `EXTERNAL_CA` – API akce *Replace with imported certificate*). Klíč VCF nikdy
neopustí; acme žádný nemá.

**Verze:** VCF **9.1 a 9.1.1** (API VCF Operations *Fleet Certificate Management*); acme přečte
verzi VCF Operations a starší odmítne dřív, než cokoli změní. Pro VCF 5.2 (nebo SDDC Manager
API ve VCF 9.x) zvolte základní verzi tohoto cíle. **Jeden cíl = jedna komponenta**: vCenter,
NSX Manager, hostitel ESX, SDDC Manager, komponenta VCF management (VCF Operations, VCF
Automation, Operations for logs / networks, Fleet Management, Identity Broker) – cokoli, co
ukazuje *Fleet management → Certificates*.

## Co je potřeba

- Z acme do VCF Operations: **TCP 443**; a na komponentu port 443 pro test toho, co se
  servíruje.
- Uživatel VCF Operations s rolí **Administrator** (nebo vlastní role s oprávněními pro
  certifikáty flotily – VMware je nejmenuje; vypíšete je přes
  `GET /suite-api/api/auth/privileges`).
- Zdroj, který podepíše CSR vytvořený jinde – ACME CA (DNS-01 pro FQDN komponenty), vlastní
  autorita acme, komerční CA. Jen **RSA** (2048, 3072, 4096); VCF 9.1 kontroluje SAN přísně:
  FQDN v něm musí být, žádná krátká jména.
- **Kořenový certifikát CA** zdroje: řetězec jde leaf → mezilehlý → kořen.
- Certifikát ještě nesmí být prošlý – prošlý VCF vyměnit neumí (KB 445742).

## Nastavení VCF Operations

1. Uživatel pro acme s rolí Administrator: *VCF Operations → Administration → Control Panel →
   Access Control → Users → Add*, nebo ho importujte ze zdroje Identity Broker / LDAP.
   Ověřte, že se přihlásí do API:

   ```sh
   curl -sk -X POST https://vcf-ops.example.local/suite-api/api/auth/token/acquire \
     -H 'Content-Type: application/json' -H 'Accept: application/json' \
     -d '{"username":"svc-vcf-certs","password":"<heslo>","authSource":"<zdroj>"}'
   ```

2. Najděte certifikát komponenty (jeho ID je v acme volitelné – najde se podle FQDN):

   ```sh
   TOKEN=<token z kroku 1>
   curl -sk -X POST 'https://vcf-ops.example.local/suite-api/api/fleet-management/certificate-management/certificates/query?page=0&pageSize=50' \
     -H "Authorization: OpsToken $TOKEN" -H 'Content-Type: application/json' \
     -d '{"applianceFqdn":"vc01.example.local","category":"TLS_CERT"}' | jq '.vcfCertificateModels[]|{certificateResourceKey,issuedTo,appliance,type,status}'
   ```

3. Nic se nezapíná. CA nastavená pro flotilu (Microsoft / OpenSSL) není potřeba; u této
   komponenty **vypněte automatickou obnovu** (auto-renewal), aby VCF nenahradil certifikát
   z acme certifikátem své CA.

## Vyplňte v acme

Cíl (**Cíle → Přidat → VMware Cloud Foundation component**, verze **9.1**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | VCF Operations, např. `vcf-ops.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Účet z kroku 1 |
| Zdroj ověření | Zdroj uživatele (Identity Broker / LDAP); u lokálního uživatele prázdné |
| FQDN komponenty | Komponenta, např. `vc01.example.local` (prázdné: první jméno certifikátu) |
| ID certifikátu | Prázdné (najde se podle FQDN); ID z kroku 2, když VCF ukazuje víc certifikátů |
| Země, Kraj, Město, Organizace, Útvar | Co VCF dá do každého CSR (kraj celým názvem); vlastní subjekt certifikátu (z profilu) má přednost |
| Čekat na úlohy VCF (minuty) | `60` |

*Typ komponenty* a *Doména (workload domain)* platí jen pro SDDC Manager. Pak certifikát:
**Přidat certifikát → Klíč → Klíč vytváří zařízení → zvolte tento cíl** (nebo v okně cíle
**Vytvořit jeho certifikát**). Jména: nejdřív FQDN komponenty, pak ostatní (IP adresy jdou do
IP jmen CSR). Typ klíče RSA. Do možností nasazení vložte **Kořenový certifikát CA** (pro
Let's Encrypt ISRG Root X1). Z příkazové řádky:

```sh
acme --cert-add vc01 --names vc01.example.local --key-type rsa-3072 --issuer "Let's Encrypt" --csr-from vc01-ops
acme --renew vc01
```

## Ověření

- **Test** cíle se přihlásí, řekne verzi VCF Operations a ID nalezeného certifikátu – nic
  nemění.
- **Obnovit teď**: úloha ukáže workflow CSR, vydání a workflow výměny. Pak:

  ```sh
  openssl s_client -connect vc01.example.local:443 -servername vc01.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -H "Authorization: OpsToken $TOKEN" https://vcf-ops.example.local/suite-api/api/workflows/requests/<requestId> | jq .state
  ```

- V UI: *Fleet management → Certificates* – VCF načítá certifikáty každých 6 hodin, nový se
  tam může ukázat později než na komponentě.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel, heslo nebo *Zdroj ověření*. |
| `has no fleet certificate management API` | VCF Operations starší než 9.1: použijte základní verzi (SDDC Manager API). |
| `lists no TLS certificate of ...` | FQDN se liší od toho ve VCF: viz krok 2, nebo vyplňte *ID certifikátu*. |
| `lists 2 TLS certificates` | Vyplňte v cíli *ID certifikátu*. |
| `400` při výměně | Leaf neodpovídá žádnému CSR ve VCF (mezitím vznikl novější CSR: **Obnovit teď**), nebo je řetězec neúplný (vložte kořen). |
| Workflow selhalo | Podívejte se na požadavek ve VCF Operations (*Fleet management → Tasks*); prošlý certifikát vyžaduje vcf-cert-tool (KB 445742). |
| VCF nahradil certifikát z acme | U komponenty je zapnutá automatická obnova – vypněte ji. |
