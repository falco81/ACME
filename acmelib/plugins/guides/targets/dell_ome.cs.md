# Dell OpenManage Enterprise - nastavení pro acme

OpenManage Enterprise (OME) přijme **jen certifikát podepsaný k CSR, který si samo vytvořilo** -
uživatelská příručka Dellu: *CSR generujte jen v samotné appliance OpenManage Enterprise*;
soukromý klíč ani PKCS#12 nahrát nejde. Proto **klíč vytváří OME**: při každém vystavení
a obnovení acme požádá OME přes jeho REST API o nový klíč a CSR
(`ApplicationService.GenerateCSR`), nechá CSR podepsat zdrojem certifikátu a hned certifikát
nahraje (`ApplicationService.UploadCertChain` nebo `UploadCertificate`). Klíč OME nikdy
neopustí; acme žádný nemá. Je to certifikát webového rozhraní a REST API OME
(`https://<ome>/api`).

**Tato verze** je pro **jakékoli OME 3.x a 4.x** (ověřeno proti OME 4.6): acme přečte verzi
(`GET /api/ApplicationService/Info`) a od OME 3.10 nahraje certifikát **s mezilehlými
certifikáty**, před 3.10 certifikát **samotný** (nahrání řetězce tam není). Chcete-li volání
pevně dané, zvolte verzi **`3.10`** (OME 3.10 - 4.x) nebo **`3.0`** (OME 3.0 - 3.9) - zařízení
s jinou verzí odmítnou dřív, než cokoli změní.

## Co potřebujete

- Z acme do OME: **TCP 443** (nebo port z *Application Settings → Network → Web Server*).
- Účet OME pro acme jen s tím, co certifikáty potřebují (níže).
- Zdroj, který podepíše CSR vytvořený jinde - ACME CA (Let's Encrypt s ověřením DNS-01 pro
  jméno appliance), vlastní autoritu acme, komerční CA. Ne *Self-signed*. Certifikát musí mít
  EKU *Server Authentication* a podpis SHA-256 nebo silnější (nikde v řetězci SHA-1).
- Jména: nejdřív FQDN OME (je to common name, v OME *Distinguished Name*) a jeho IP adresa,
  pokud se k němu servery připojují přes IP (aktualizace ovladačů Windows). **Nejvýš 4 jména**
  a **žádný wildcard** - OME nepřijme ani jedno.
- Klíč: OME vytvoří klíč **RSA 2048** (volbu nenabízí) - dejte certifikátu tento typ klíče.

## Nastavení OME

1. Role jen s oprávněním **Appliance Management** (OME 4.x: *Application Settings → Users →
   Roles → Create*, zaškrtnout jen *Appliance Management*) a uživatel s ní - nebo role
   **Administrator** (Device Manager a Viewer se k certifikátům nedostanou). Přes REST API jako
   správce:

   ```sh
   OME=ome.example.local
   TOKEN=$(curl -sk -D - -o /dev/null -X POST https://$OME/api/SessionService/Sessions \
     -H 'Content-Type: application/json' \
     -d '{"UserName":"admin","Password":"<heslo správce>","SessionType":"API"}' \
     | awk -F': ' 'tolower($1)=="x-auth-token"{print $2}' | tr -d '\r')
   curl -sk -H "X-Auth-Token: $TOKEN" https://$OME/api/AccountService/Roles
   curl -sk -X POST https://$OME/api/AccountService/Accounts \
     -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"UserName":"svc-cert","Password":"<heslo>","RoleId":"<id role>","Enabled":true,"UserTypeId":1,"DirectoryServiceId":0,"Locked":false,"Description":"certifikáty acme"}'
   ```

2. REST API je zapnuté vždy (`https://<ome>/api`) - není co zapínat.
3. Nastavte správně DNS jméno OME a NTP: jména certifikátu musí být ta, přes která se k OME
   přistupuje.

## Vyplnění v acme

Cíl (**Cíle → Přidat → Dell OpenManage Enterprise**):

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP OME, např. `ome.example.local` |
| Port HTTPS | `443` (nebo port webového serveru OME) |
| Uživatel / Heslo | Účet z kroku 1 (`svc-cert`) |
| Země, Kraj, Město, Název firmy, Oddělení, E-mail v CSR | Co OME dává do každého CSR (žádá všechna); přednost má vlastní subjekt certifikátu (jeho profil) |
| Ověřovat certifikát zařízení | Při prvním vystavení vypnuto (OME má ještě self-signed certifikát), potom zapnuto |

Pak certifikát: **Přidat certifikát** → v kroku **Klíč** zvolte **Klíč vytváří zařízení** →
vyberte tento cíl (nebo v okně cíle **Vytvořit jeho certifikát**). Jména: FQDN OME (a jeho IP
adresa). Typ klíče: RSA 2048. Nasazení do OME si acme vytvoří samo; proběhne hned po každém
vystavení. Z příkazové řádky:

```sh
acme --cert-add ome --names ome.example.local --issuer "Let's Encrypt" --key-type rsa-2048 --csr-from ome
acme --renew ome
```

Volby nasazení: **Nahrát řetězec** (zapnuto: certifikát a mezilehlé certifikáty; vypnuto:
certifikát samotný) a **Kořenový certifikát CA** (přidá se na konec řetězce - Dell doporučuje
celý řetězec včetně kořene; nejvýš 10 certifikátů).

## Ověření

- **Test** u cíle se přihlásí a řekne verzi OME a jak se certifikát nahraje - nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže *klíč a CSR vytváří zařízení*, vystavení
  a nahrání. OME restartuje webový server a na pár sekund je nedostupné; testy po nasazení na
  něj počkají.

  ```sh
  openssl s_client -connect ome.example.local:443 -servername ome.example.local -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  V OME: **Application Settings → Security → Certificates** ukáže *Issued To*, *Issued By*
  a platnost.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo, případně je účet vypnutý nebo zamčený. |
| `403` u GenerateCSR nebo nahrání | Roli chybí *Appliance Management* - přidejte ho, nebo dejte roli Administrator. |
| `takes no wildcard` / `at most 4 names` | Dejte certifikátu vlastní jména OME, nejvýš čtyři. |
| `asks for ... in every CSR` | Vyplňte u cíle všechna pole CSR (OME chce všechna). |
| Nahrání odmítnuto | OME od vystavení certifikátu vytvořilo novější CSR (ručně vytvořené v GUI zahodí klíč, pro který je certifikát acme) - **Obnovit teď** vystaví nový. Odmítnut je i řetězec podepsaný SHA-1 nebo řetězec nahraný jako jediný certifikát. |
| `runs OpenManage Enterprise X - the module version ... is for ...` | Zvolte verzi, kterou zpráva jmenuje, nebo verzi bez čísla. |
| Integrace (OMEVV ve vCenter, ServiceNow, skripty) přestanou OME věřit | Musí důvěřovat nové CA; OMEVV může chtít certifikát OME znovu potvrdit. |
| Nasazení pozdržena | OME si nechá starý certifikát; další vystavení si řekne o nový klíč a CSR. |
