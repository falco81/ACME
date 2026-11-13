# Lenovo XClarity Controller 3 (XCC3) - nastavení pro acme

XCC přijme **jen certifikát podepsaný k CSR, který si samo vytvořilo** - dokumentace Lenova to
říká pro XCC3, XCC2, XCC i IMM2: soukromý klíč do něj nahrát nejde. Proto **klíč vytváří
zařízení**: při každém vystavení a obnovení acme požádá XCC přes Redfish o nový klíč a CSR
(`CertificateService.GenerateCSR`), nechá CSR podepsat zdrojem certifikátu a hned certifikát
vrátí (`CertificateService.ReplaceCertificate`). Klíč XCC nikdy neopustí; acme žádný nemá.
Je to certifikát webového rozhraní XCC, Redfishe a jeho LDAP klienta (sdílejí ho).

**Tato verze** je pro **XCC3** (ThinkSystem V4): acme žádá typ klíče certifikátu - ECDSA P-256
(výchozí v XCC) nebo P-384, RSA 2048, 3072 nebo 4096. Pro XCC a XCC2 (ThinkSystem V1-V3)
zvolte verzi **`xcc2`** tohoto cíle.

## Co potřebujete

- Z acme do XCC: **TCP 443** (HTTPS, Redfish).
- Účet XCC pro acme jen s tím, co certifikáty potřebují (níže).
- Zdroj, který podepíše CSR vytvořený jinde - ACME CA (Let's Encrypt s ověřením DNS-01 nebo
  HTTP-01 pro jméno XCC), vlastní autoritu acme, komerční CA. Ne *Self-signed*, CMP ani SCEP.

## Nastavení XCC

1. Role jen s **Configuration - Networking and BMC Security** (`nsc`) a uživatel s ní, omezený
   na Redfish - v CLI XCC (SSH):

   ```text
   system> roles -3 -n CertAdmin -p custom:nsc
   system> users -3 -n svccert -p '<heslo>' -r CertAdmin -ai redfish
   ```

   Nebo přes Redfish (XCC3):

   ```sh
   curl -k -u USERID:'<heslo správce>' -X POST https://xcc.example.local/redfish/v1/AccountService/Roles \
     -H 'Content-Type: application/json' \
     -d '{"RoleId":"CertAdmin","OemPrivileges":["Configuration_NetworkingAndSecurity"]}'
   curl -k -u USERID:'<heslo správce>' -X PATCH https://xcc.example.local/redfish/v1/AccountService/Accounts/3 \
     -H 'Content-Type: application/json' -H 'If-Match: *' \
     -d '{"UserName":"svccert","Password":"<heslo>","RoleId":"CertAdmin","Enabled":true}'
   ```

   Ve webovém rozhraní: **BMC Configuration → User/LDAP → Create a role** (jen *Networking and
   BMC Security*), pak uživatel s touto rolí.
2. HTTPS (port 443) musí být zapnuté - výchozí stav. Nic dalšího se nezapíná.
3. Jméno, které acme dá do certifikátu (jeho první jméno, common name), má být jméno, kterým se
   na XCC chodí; chodí-li se na něj adresou IP, přidejte ji jako další jméno.

## Vyplnění v acme

Cíl (**Cíle → Přidat → Lenovo XClarity Controller**):

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP XCC, např. `xcc01.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Účet z kroku 1 (`svccert`) |
| Země (C), Kraj (ST), Město (L), Organizace (O) | Co XCC dá do každého CSR (vyžaduje je); vlastní subjekt certifikátu (jeho profil) má přednost |
| Útvar (OU), E-mail v CSR | Nepovinné |
| Ověřovat certifikát zařízení | Při prvním vystavení vypnuto (XCC má ještě svůj self-signed certifikát), potom zapnuto |

Pak certifikát: **Přidat certifikát**, v kroku *Klíč* zvolte **Klíč vytváří zařízení** a tento
cíl - nebo v okně cíle **Vytvořit jeho certifikát**. Jména: jméno XCC (a adresa). Typ klíče:
některý, který XCC umí. Nasazení na XCC acme vytvoří samo; běží hned po každém vystavení.
Z příkazové řádky:

```sh
acme --cert-add xcc01 --names xcc01.example.local --issuer "Let's Encrypt" --csr-from xcc01
acme --renew xcc01
```

Volby nasazení: *Poslat i mezilehlé certifikáty* (vypnuto: jen certifikát, jak ho importuje
Lenovo) a *URI certifikátu* (prázdné: první certifikát HTTPS).

## Ověření

- **Test** u cíle se přihlásí a řekne, zda XCC nabízí `GenerateCSR` - nic nemění.
- **Obnovit teď** u certifikátu: úloha napíše *klíč a CSR vytváří zařízení*, vystavení a import.
  XCC začne nový certifikát podávat **do zhruba 15 minut**, bez restartu (testy po nasazení
  čekají tak dlouho):

  ```sh
  openssl s_client -connect xcc01.example.local:443 -servername xcc01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -u svccert:'<heslo>' https://xcc01.example.local/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo, nebo účet nemá povolený Redfish (`-ai redfish`). |
| `403` u GenerateCSR nebo ReplaceCertificate | Role nemá *Networking and BMC Security* (`nsc`). |
| `offers no CertificateService.GenerateCSR` | XCC / XCC2 se starším firmwarem: zvolte verzi `xcc2` (vlastní bezpečnostní služba Lenova). |
| `the XCC asks for Country, ...` | Vyplňte u cíle Zemi, Kraj, Město a Organizaci. |
| `the CSR ... does not name ...` | XCC vynechalo jméno ze svého CSR - dejte certifikátu jen jména, která XCC vezme. |
| Import odmítnut (`does not match`) | XCC mezitím vytvořilo novější CSR (další GenerateCSR, ručně nebo z webového rozhraní) - **Obnovit teď** vystaví nový ke klíči, který teď drží. |
| Pořád se podává starý certifikát | Počkejte až 15 minut; XCC přepne samo. |
| Nasazení pozdržena | XCC si ponechá starý certifikát; další vystavení ho požádá o nový klíč a CSR. |
