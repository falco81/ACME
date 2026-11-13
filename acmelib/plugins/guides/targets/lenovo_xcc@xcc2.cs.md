# Lenovo XClarity Controller a XCC2 (ThinkSystem V1-V3) - nastavení pro acme

XCC přijme **jen certifikát podepsaný k CSR, který si samo vytvořilo** - soukromý klíč do něj
nahrát nejde (dokumentace Lenova). Proto **klíč vytváří zařízení**: při každém vystavení
a obnovení acme požádá XCC přes Redfish o nový klíč a CSR, nechá CSR podepsat zdrojem
certifikátu a hned certifikát vrátí. Klíč XCC nikdy neopustí; acme žádný nemá. Je to
certifikát webového rozhraní XCC, Redfishe a jeho LDAP klienta.

**Tato verze** je pro **XCC a XCC2** (ThinkSystem V1, V2, V3):

| | |
|---|---|
| Klíč | XCC / XCC2 typ klíče nenabízí: acme žádný nežádá a typ klíče certifikátu je **RSA 2048** |
| CSR | `CertificateService.GenerateCSR`, má-li ho firmware (novější firmware XCC/XCC2, stejná URI jako XCC3); jinak vlastní služba Lenova: `LenovoSecurityService.GenerateCSR` a `DownloadCSR` |
| Import | `CertificateService.ReplaceCertificate` (`CertificateType` `PEM`); jinak `LenovoSecurityService.ImportCertificate` (certifikát jako DER) |
| Jména | Přes vlastní službu Lenova má CSR **jedno jméno hostitele** (žádná další) - takový certifikát smí mít jen jedno jméno |

Pro XCC3 (ThinkSystem V4) použijte prostou verzi tohoto cíle (libovolný typ klíče).

## Co potřebujete

- Z acme do XCC: **TCP 443** (HTTPS, Redfish).
- Účet XCC pro acme jen s tím, co certifikáty potřebují (níže).
- Zdroj, který podepíše CSR vytvořený jinde - ACME CA, vlastní autoritu acme, komerční CA. Ne
  *Self-signed*, CMP ani SCEP.

## Nastavení XCC

1. Role jen s **Configuration - Networking and BMC Security** (`nsc`) a uživatel s ní, v CLI
   XCC (SSH):

   ```text
   system> roles -3 -n CertAdmin -p custom:nsc
   system> users -3 -n svccert -p '<heslo>' -r CertAdmin -ai redfish
   ```

   Nebo ve webovém rozhraní: **BMC Configuration → User/LDAP**: role jen s *Networking and BMC
   Security*, uživatel s touto rolí.
2. HTTPS (port 443) musí být zapnuté - výchozí stav.
3. První jméno certifikátu (common name) má být jméno, kterým se na XCC chodí.

## Vyplnění v acme

Cíl (**Cíle → Přidat → Lenovo XClarity Controller**, verze **xcc2**):

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP XCC, např. `xcc01.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Účet z kroku 1 (`svccert`) |
| Země (C), Kraj (ST), Město (L), Organizace (O) | Co XCC dá do každého CSR (vyžaduje je); vlastní subjekt certifikátu (jeho profil) má přednost |
| Útvar (OU), E-mail v CSR | Nepovinné |
| Ověřovat certifikát zařízení | Při prvním vystavení vypnuto (XCC má ještě svůj self-signed certifikát), potom zapnuto |

Pak certifikát: **Přidat certifikát**, v kroku *Klíč* zvolte **Klíč vytváří zařízení** a tento
cíl (typ klíče RSA 2048) - nebo v okně cíle **Vytvořit jeho certifikát**. Nasazení na XCC acme
vytvoří samo; běží hned po každém vystavení.

```sh
acme --cert-add xcc01 --names xcc01.example.local --issuer "Let's Encrypt" --key-type rsa-2048 --csr-from xcc01
acme --renew xcc01
```

## Ověření

- **Test** u cíle se přihlásí a řekne, jakou cestou se CSR vytváří (standardní `GenerateCSR`,
  nebo vlastní služba Lenova) - nic nemění.
- **Obnovit teď** u certifikátu; XCC začne nový certifikát podávat **do zhruba 15 minut**, bez
  restartu:

  ```sh
  openssl s_client -connect xcc01.example.local:443 -servername xcc01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo, nebo účet nemá povolený Redfish. |
| `403` | Role nemá *Networking and BMC Security* (`nsc`). |
| `makes rsa-2048 keys only` | Nastavte certifikátu typ klíče RSA 2048. |
| `takes one host name` | Vlastní služba Lenova zná jedno jméno: dejte certifikátu jedno jméno, nebo aktualizujte firmware XCC (standardní GenerateCSR vezme víc jmen). |
| Import odmítnut | XCC mezitím vytvořilo novější CSR (další GenerateCSR) - **Obnovit teď** vystaví certifikát ke klíči, který teď drží. |
| Pořád se podává starý certifikát | Počkejte až 15 minut. |
