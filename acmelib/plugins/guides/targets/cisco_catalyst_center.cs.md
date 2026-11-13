# Cisco Catalyst Center (DNA Center) - nastavení pro acme

acme vymění **systémový certifikát** Catalyst Center (*Controller*: jeho GUI, severní Intent API, PnP, telemetrie) a/nebo certifikát **Disaster Recovery** (*ipsec*) přes Intent API:

```text
POST /dna/system/api/v1/auth/token                                   (HTTP basic) -> Token
POST /dna/intent/api/v1/certificate?listOfUsers=server               certFileUpload + pkFileUpload
POST /dna/intent/api/v1/certificate-p12?listOfUsers=server&p12Password=...   p12FileUpload
GET  /dna/intent/api/v1/task/<taskId>                                 dokud odpovídá
```

Certifikát jde s řetězcem v jednom souboru PEM v pořadí řetězce (serverový certifikát, pak podřízená CA, pak kořenová), klíč ve druhém - nebo, když zvolíte *PKCS#12*, vše v jednom PKCS#12 s jednorázovým heslem.

## Pro které verze

Catalyst Center **2.3.7.x, 3.1.x a 3.3.x** - všude stejná dvě volání (Cisco SDK `dnacentersdk` pro 3.1.6.0 a moduly Ansible `authentication_import_certificate[_p12]` od 2.3.7.6). Modul má jedinou verzi.

## Co se v Catalyst Center stane

- Certifikát nahradí ten, který určuje *Použití*: **Controller** (`server`), **Disaster Recovery** (`ipsec`) nebo oba.
- Catalyst Center pak restartuje své webové služby: **všichni jsou odhlášeni**, GUI a API jsou asi **2 minuty** nedostupné. Naplánujte to mimo pracovní dobu.
- **Zařízení a integrace věří Catalyst Center podle tohoto certifikátu** (PnP, telemetrie/Assurance, NETCONF callbacky, ISE pxGrid/ERS, ITSM, IPAM, vaše skripty): před prvním přechodem na certifikát nové CA zajistěte, aby jí věřily. Se zapnutou *device controllability* Catalyst Center zařízení obvykle aktualizuje sám.
- Disaster Recovery: měňte na obou lokalitách současně.

## Nastavení Catalyst Center

1. Uživatel pro acme: **System → Users & Roles → User Management → Add**. Výměna systémového certifikátu je systémové nastavení: **SUPER-ADMIN-ROLE**. NETWORK-ADMIN-ROLE nestačí („no access to system-related functions“). Nejméně je vlastní role (**System → Users & Roles → Role Based Access Control → Create a New Role**) jen s *System → System Management* a *Platform → APIs* - *nejisté*: přesné názvy oprávnění v dostupné dokumentaci nebyly.
2. Na 2.3.x zapněte REST API: **Platform → Manage → Bundles → Catalyst Center REST API → Enable** (na 3.x podle dokumentace není potřeba).
3. Certifikát: RSA nebo ECDSA, nejméně 2048 bitů; v SAN všechna jména, která klienti používají (FQDN Catalyst Center; v praxi i VIP clusteru a `pnpserver.<doména>` pro PnP); použití klíče pro **ověření serveru i klienta** (požadavek Cisca pro jeho CSR).

Přihlášení si vyzkoušejte ze stroje acme:

```sh
curl -s -u acme -X POST https://catalyst.example.com/dna/system/api/v1/auth/token
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | `catalyst.example.com` / `443` |
| Uživatel / Heslo | uživatel z kroku 1 |
| Ověřovat certifikát zařízení | zapnuto (u soukromé CA vyplňte *Certifikát CA*); vypnuto jen dokud má vlastní self-signed |
| Použití (nasazení) | *Controller* (GUI, API, PnP), *Disaster Recovery*, nebo obojí |
| Nahrát jako (rozšířené) | řetězec PEM + klíč (výchozí) nebo PKCS#12 |
| Čekat na import (s) (rozšířené) | jak dlouho acme sleduje úlohu importu |

acme nemůže přečíst, jaký systémový certifikát Catalyst Center má (žádné volání ho nevypíše): stejný certifikát nepošle dvakrát, protože si pamatuje, co poslal; volba *vynutit* ho pošle znovu.

## Ověření

```sh
openssl s_client -connect catalyst.example.com:443 -servername catalyst.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

V GUI: **System → Settings → Certificates → System Certificates → Action → View**. Na každém uzlu clusteru (maglev shell):

```sh
sudo maglev-config certs info
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| `401` při přihlášení | špatný uživatel nebo heslo | uživatel z kroku 1 |
| `403` při importu | role nesmí měnit systémová nastavení | SUPER-ADMIN-ROLE nebo role z kroku 1 |
| *Catalyst Center refused the certificate: ...* | úloha importu selhala (špatné pořadí řetězce, krátký klíč, klíč nepatří k certifikátu) | přečtěte důvod; RSA/ECDSA 2048+ |
| *the task ... cannot be read any more* | očekávané: Catalyst Center se restartuje a acme odhlásí | test servírovaného certifikátu řekne, zda ho převzal |
| zařízení po změně přestanou hlásit | nevěří nové CA | přidejte CA do trustpoolu zařízení (nebo to nechte na device controllability) |

*Nejisté*: tvar odpovědi importu (`response.taskId`) a úlohy (`isError`, `failureReason`, `endTime`) jsou obvyklé tvary Intent API; zda nešifrovaný klíč potřebuje `pkPassword` (acme ho neposílá).

Zdroje: Cisco Catalyst Center Administrator Guide 3.3.x (Manage Certificates, Certificate and Private Key Support, About user roles), Intent API *Import Certificate*, Cisco `dnacentersdk` 3.1.6.0 `authentication_management.py`, kolekce Ansible `cisco.catalystcenter`.
