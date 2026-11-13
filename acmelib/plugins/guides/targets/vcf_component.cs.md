# Komponenta VMware Cloud Foundation přes SDDC Manager – nastavení pro acme

SDDC Manager přijme **jen certifikát podepsaný pro CSR, který sám vytvořil** – jeho workflow
páruje každý certifikát s CSR uloženým v lockeru („leaf certificate doesn't match any CSR
stored in the locker“); privátní klíč vytvořený jinde naimportovat nelze. Proto **klíč
vytváří VCF**: při každém vydání a obnově acme nechá SDDC Manager vytvořit pro komponentu nový
klíč a CSR (`PUT /v1/domains/{id}/csrs`), přečte ho (`GET /v1/domains/{id}/csrs`), nechá ho
podepsat zdrojem certifikátu a hned poté nechá SDDC Manager podepsaný certifikát s řetězcem
ověřit a nainstalovat (`PUT /v1/domains/{id}/resource-certificates/validations`, pak
`PUT /v1/domains/{id}/resource-certificates`). SDDC Manager ho na komponentě použije
a restartuje její služby (předtím udělá snapshot komponenty a po úspěchu ho smaže). Klíč VCF
nikdy neopustí; acme žádný nemá.

**Verze:** tato verze je pro **SDDC Manager API v1** – VCF **5.2.x** a VCF 9.0 – 9.1.1, kde
SDDC Manager API stále je. Pro VCF **9.1 / 9.1.1** přes VCF Operations (Fleet management →
Certificates) zvolte verzi **9.1** tohoto cíle. **Jeden cíl = jedna komponenta**: vCenter,
NSX Manager (VIP a uzly v SAN), samotný SDDC Manager, komponenta Aria / VCF management. VCF 5.2
certifikáty ESXi nespravuje. (Druh *VMware SDDC Manager (úložiště důvěry)* je něco jiného:
jen přidává certifikáty CA do úložiště důvěry SDDC Manageru.)

## Co je potřeba

- Z acme na SDDC Manager: **TCP 443**; a na komponentu port 443 pro test toho, co se
  servíruje.
- Uživatel SDDC Manageru s rolí **ADMIN** (nebo **OPERATOR** – VIEWER jen čte; přesná matice
  rolí není zveřejněná).
- Zdroj, který podepíše CSR vytvořený jinde – ACME CA (DNS-01 pro FQDN komponenty), vlastní
  autorita acme, komerční CA. Jen klíče **RSA** (2048, 3072, 4096). Bez wildcardu.
- **Kořenový certifikát CA** zdroje: SDDC Manager chce řetězec až ke kořeni.
- Okno údržby: služby vCenteru se restartují (minuty); nespouštějte současně jiné workflow
  SDDC Manageru.
- Certifikát ještě nesmí být prošlý – prošlý VCF vyměnit neumí (KB 445742).

## Nastavení SDDC Manageru

1. Servisní účet z vCenter SSO (Active Directory) s rolí ADMIN – v UI SDDC Manageru
   *Administration → Single Sign On → + User or Group*, nebo přes API:

   ```sh
   TOKEN=$(curl -sk -X POST https://sddc-manager.example.local/v1/tokens -H 'Content-Type: application/json' \
     -d '{"username":"administrator@vsphere.local","password":"<heslo>"}' | jq -r .accessToken)
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/roles | jq '.elements[]|{id,name}'
   curl -sk -X POST https://sddc-manager.example.local/v1/users -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '[{"name":"svc-vcf-certs@corp.local","type":"USER","domain":"corp.local","role":{"id":"<id role ADMIN>"}}]'
   ```

2. Zjistěte doménu a komponentu tak, jak je zná SDDC Manager:

   ```sh
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains | jq '.elements[]|{id,name}'
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains/<id-domény>/resource-certificates | jq
   ```

3. Nic dalšího se nezapíná – API běží. CA Microsoft ani OpenSSL v SDDC Manageru není potřeba
   (CSR podepíše zdroj v acme).

## Vyplňte v acme

Cíl (**Cíle → Přidat → VMware Cloud Foundation component**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | SDDC Manager, např. `sddc-manager.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Účet z kroku 1 (`svc-vcf-certs@corp.local`) |
| FQDN komponenty | Komponenta, např. `vc01.example.local` (prázdné: první jméno certifikátu) |
| Typ komponenty | `vCenter`, `NSX Manager (NSX-T)`, `SDDC Manager`, … (typ prostředku SDDC Manageru) |
| Doména (workload domain) | Její název nebo ID, např. `sddcm-mgmt-domain` (prázdné: jediná) |
| Země, Kraj, Město, Organizace, Útvar | Co SDDC Manager dá do každého CSR (kraj celým názvem); vlastní subjekt certifikátu (z profilu) má přednost |
| Čekat na úlohy VCF (minuty) | `60` |
| Ověřovat certifikát zařízení | Zapnuto, pokud je vlastní certifikát SDDC Manageru od CA, které acme věří (jinak vložte CA) |

Pak certifikát: **Přidat certifikát → Klíč → Klíč vytváří zařízení → zvolte tento cíl**
(nebo v okně cíle **Vytvořit jeho certifikát**). Jména: nejdřív FQDN komponenty (VCF ho chce
v SAN), pak ostatní (u NSX VIP a každý uzel). Typ klíče RSA 2048 / 3072 / 4096. Do možností
nasazení vložte **Kořenový certifikát CA** (pro Let's Encrypt ISRG Root X1). Z příkazové řádky:

```sh
acme --cert-add vc01 --names vc01.example.local --key-type rsa-3072 --issuer "Let's Encrypt" --csr-from vc01-vcf
acme --renew vc01
```

## Ověření

- **Test** cíle se přihlásí a řekne verzi SDDC Manageru a doménu – nic nemění.
- **Obnovit teď**: úloha ukáže úlohu CSR, vydání, validaci a úlohu instalace. Pak:

  ```sh
  openssl s_client -connect vc01.example.local:443 -servername vc01.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains/<id-domény>/resource-certificates | jq
  ```

- V UI: *Inventory → Workload Domains → doména → Certificates*.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` | Špatný uživatel nebo heslo, nebo role VIEWER. |
| `give the workload domain` / `no workload domain` | Vyplňte v cíli název nebo ID domény z `/v1/domains`. |
| `lists none for ...` | FQDN nebo typ není ten, který zná SDDC Manager: porovnejte s `/resource-certificates`. |
| `the validation of the certificate failed` | Neúplný řetězec (vložte kořen), jména bez FQDN, nebo SDDC Manager mezitím vytvořil novější CSR: **Obnovit teď**. |
| `making the CSR failed` / instalace selhala | Podívejte se na úlohu v UI (*Tasks*) a do `/var/log/vmware/vcf/operationsmanager/operationmanager.log`; výměna u vCenteru selže, když má SSO účet SDDC Manageru jen čtení (KB 316107). |
| Jiné produkty komponentě přestanou věřit | Vztahy důvěry jinde (compute manager v NSX, SRM, zálohování) může být nutné obnovit (KB 445742). |
| Nasazení pozdržena | Komponenta si ponechá starý certifikát; další vydání požádá SDDC Manager o nový klíč a CSR. |
