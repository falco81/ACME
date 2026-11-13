# Cisco Unified Communications Manager (CUCM 14 / 15) – nastavení pro acme

CUCM přijme **jen certifikát podepsaný pro CSR, který sám vytvořil**: Cisco Unified OS
Administration nahrává pro `tomcat` / `CallManager` certifikát nebo řetězec, nikdy privátní
klíč – klíč vzniká vždy na CUCM při *Generate CSR*. Proto **klíč vytváří CUCM**: při každém
vydání a obnově se acme přihlásí do **platformového CLI přes SSH**, nechá CUCM vytvořit nový
klíč a CSR (`set csr gen tomcat`), přečte ho (`show csr own tomcat/tomcat.csr`), nechá CSR
podepsat zdrojem certifikátu a hned poté naimportuje certifikáty CA (`set cert import trust
tomcat-trust`) a certifikát (`set cert import own tomcat tomcat-trust/<CA>.pem`) a restartuje
služby dané jednotky. Klíč CUCM nikdy neopustí; acme žádný nemá.

**Verze:** CUCM 14 a 15 se všemi SU (CLI je stejné). Jeden cíl = jeden **uzel** a jedna
**jednotka**: `tomcat` (webová administrace, AXL, UDS, přihlášení Jabberu, SAML SP),
`tomcat-ECDSA`, `CallManager` (SIP / SCCP TLS) nebo `CallManager-ECDSA`. Cisco pro tyto
certifikáty nedokumentuje REST API, na kterém by acme mohlo stavět, a **multi-server (SAN)**
certifikát se od 14SU2 nahrává jen v GUI OS Administration – každý uzel dostane vlastní cíl.

## Co je potřeba

- Z acme na každý uzel: **TCP 22** (SSH do platformového CLI) a TCP 8443 pro test toho, co
  se servíruje.
- **Platformový (OS) účet** s **úrovní oprávnění 1** – aplikační uživatel CM Administration
  se do CLI nepřihlásí.
- Zdroj, který podepíše CSR vytvořený jinde – ACME CA (s ověřením DNS-01 pro jméno uzlu),
  vlastní autorita acme, komerční CA. Ne *Self-signed*, CMP ani SCEP. Kořen a mezilehlé
  certifikáty CA musí být v `tomcat-trust` – to udělá acme.
- Okno údržby: restart Cisco Tomcat na minuty zastaví web, AXL a přihlášení Jabberu na uzlu;
  restart Cisco CallManager znovu zaregistruje jeho telefony.

## Nastavení CUCM

1. Přihlaste se do CLI jako platformový administrátor (účet z instalace, úroveň 4) a vytvořte
   účet pro acme – úroveň **1** stačí na `set csr gen`, `set cert import` i `show cert`
   (CLI reference Cisco):

   ```text
   admin: set account name svc-cert
   Please enter the privilege level :1
   Allow this user to be able to modify the system? (yes/no) : no
   Please enter the password : ********
   ```

   Jednou se přihlaste jako `svc-cert` (`ssh svc-cert@cucm-pub.example.local`) a změňte heslo,
   pokud o to CUCM požádá – dřív, než účet použije acme.
2. Podívejte se, co CUCM dává do CSR – certifikát v acme musí mít **přesně tato jména**
   (CLI CUCM od acme žádná jména nepřebírá):

   ```text
   admin: set csr gen tomcat
   admin: show csr own tomcat/tomcat.csr
   ```

   ```sh
   openssl req -noout -text -in tomcat.csr | grep -A1 'Subject Alternative Name'
   ```

   Obvykle FQDN uzlu (a nadřazená doména, pokud ji CUCM přidá). Alternativní jméno hostitele
   se nastaví jednou příkazem `set web-security` (viz CLI reference Cisco – změní obsah všech
   dalších CSR). Bez wildcardu; nejvýš 4096 bitů.
3. Připravte si kořenovou (a mezilehlou) CA svého zdroje – acme je naimportuje do
   `tomcat-trust` před certifikátem. Pro Let's Encrypt vložte do *Kořenový certifikát CA*
   v možnostech nasazení **ISRG Root X1**.

## Vyplňte v acme

Cíl (**Cíle → Přidat → Cisco Unified Communications Manager (CUCM)**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | Uzel, např. `cucm-pub.example.local` |
| SSH port | `22` |
| Uživatel | Platformový účet `svc-cert` |
| Přihlásit se přes / Heslo | *heslo* a heslo účtu |
| Klíč serveru | Řádek known_hosts uzlu (nebo *Věřit prvnímu viděnému klíči serveru*) |
| Certifikát | `tomcat` (nebo `tomcat-ECDSA`, `CallManager`, `CallManager-ECDSA`) |
| Čas na příkaz CLI (s) | `600` – CLI CUCM startuje pomalu, restart trvá minuty |

Pak certifikát: **Přidat certifikát → Klíč → Klíč vytváří zařízení → zvolte tento cíl**
(nebo v okně cíle **Vytvořit jeho certifikát**). Jména: přesně ta z kroku 2. Typ klíče:
**RSA 2048** pro `tomcat` / `CallManager`, **EC** pro jednotky `-ECDSA`. Nasazení na CUCM
vytvoří acme samo; běží hned po každém vydání. Z příkazové řádky:

```sh
acme --cert-add cucm-pub --names cucm-pub.example.local --key-type rsa-2048 --issuer "Let's Encrypt" --csr-from cucm-pub
acme --renew cucm-pub
```

Možnosti nasazení:

| Možnost | Význam |
|---|---|
| Restartovat služby | Zapnuto: `utils service restart Cisco Tomcat` a `Cisco Tftp` (tomcat), `Cisco CallManager` a `Cisco CTIManager` (CallManager). Vypnuto: restartujete sami; do té doby CUCM servíruje starý certifikát |
| Kořenový certifikát CA | Kořen, kterým řetězec končí; importuje se do `<jednotka>-trust` spolu s mezilehlými |
| Soubor CA v úložišti důvěry | Prázdné: vydavatel nalezený v `show cert list trust`; jinak např. `tomcat-trust/Example_Issuing_CA.pem` |

## Ověření

- **Test** cíle se přihlásí a řekne verzi CUCM a zda jednotka existuje – nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže CSR vytvořený CUCM, vydání, importy a
  restarty. Pak:

  ```sh
  openssl s_client -connect cucm-pub.example.local:8443 -servername cucm-pub.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  ```text
  admin: show cert list own
  admin: show cert own tomcat/tomcat.pem
  admin: utils service list
  ```

- Potom udělejte **zálohu DRS** – obnova musí obsahovat nové certifikáty.

## Časté problémy

| Problém | Řešení |
|---|---|
| `CUCM puts ... into its CSR` | Jména certifikátu se liší od jmen CUCM: dejte mu přesně jména z `show csr own` (krok 2). |
| `CUCM makes RSA keys for tomcat` | Pro `tomcat` / `CallManager` zvolte RSA 2048, pro jednotky `-ECDSA` EC. |
| `Permission denied` při SSH | Účet není platformový, nebo čeká na první změnu hesla – přihlaste se jednou ručně. |
| `Executed command unsuccessfully` u `set cert import own` | V `<jednotka>-trust` chybí CA nebo má jiný název souboru – podívejte se do `show cert list trust` a vyplňte *Soubor CA v úložišti důvěry*; nebo CUCM mezitím vytvořil novější CSR (další *Generate CSR*): **Obnovit teď**. |
| Telefony dostávají starý certifikát | Neproběhl restart Cisco TFTP (zapněte *Restartovat služby*, nebo ho restartujte). |
| Mixed mode po certifikátu CallManager | Aktualizujte soubor CTL: `utils ctl update CTLFile`. |
| SAML SSO po certifikátu tomcat nefunguje | Znovu nahrajte metadata SP do IdP (vypnout / zapnout SSO). |
| Nasazení pozdržena | CUCM si ponechá starý certifikát; další vydání ho požádá o nový klíč a CSR. |
