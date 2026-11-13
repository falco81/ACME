# HPE iLO 5 / 6 / 7 - klíč vytváří iLO - nastavení pro acme

S tímto cílem si **klíč** HTTPS certifikátu **vytváří iLO** a klíč **iLO nikdy neopustí** -
vlastní postup HPE „Generate CSR and Import an SSL Certificate“. Při každém vydání a obnově si
acme přes Redfish vyžádá od iLO nový klíč a CSR (`HpeHttpsCert.GenerateCSR` - iLO na to
potřebuje několik minut, zhruba do 10), nechá CSR podepsat zdrojem certifikátu a podepsaný
certifikát naimportuje (`HpeHttpsCert.ImportCertificate`); iLO se pak samo resetuje
(1-3 minuty - server ani jeho OS se nemění).

Kdy ho zvolit místo **Správa serverů (Redfish)**, verze *HPE iLO* (ta dává na iLO klíč z acme):

- iLO 5 starší než **2.78** nebo iLO 6 starší než **1.30** - klíč zvenčí nepřijmou;
- iLO 6 mimo bezpečnostní stav **Production**, iLO 7 mimo **SecureStandard** (HighSecurity,
  FIPS, CNSA...) - klíč RSA zvenčí nepřijmou;
- zásada, že klíč řadiče správy ho nesmí opustit.

Verze: iLO 5, iLO 6 a iLO 7, jakýkoli firmware (iLO 4 odmítne).

## Co iLO dá do svého CSR

- **Jedno jméno hostitele** - common name - a pokud má certifikát i IP adresy, **vlastní IP
  adresy** iLO (`IncludeIP`). Jiná alternativní jména iLO nebere, takže dejte certifikátu
  FQDN iLO a případně jeho adresy - nic dalšího. acme CSR zkontroluje a slovy řekne, když
  jmenuje něco jiného.
- **Klíč**: na iLO 6 1.70+ a iLO 7 1.17+ acme nastaví `KeyType` - `rsa-2048` (RSA) nebo
  `ec-384` (ECDSA P-384). iLO bez `KeyType` vytváří RSA ve stavu *Production* a ECDSA P-384
  ve stavech *HighSecurity*, *FIPS*, *CNSA*, *SuiteB* - takový typ klíče certifikátu zvolte.

## Co je potřeba

- Z acme na iLO: **TCP 443** (Redfish).
- Jméno hostitele a doména iLO nastavené na jeho FQDN (**iLO Dedicated Network Port →
  General**) před prvním CSR.
- Zdroj, který podepisuje CSR vytvořený jinde - ACME CA (validace DNS-01 pro jméno iLO),
  vlastní autorita acme, komerční CA. Ne *Self-signed*, CMP ani SCEP.
- Na iLO nesmí být zapnutý SCEP / automatická registrace - blokuje ruční import.

## Nastavení iLO

1. Účet jen s oprávněními **Login** a **Configure iLO Settings** (relace administrátora
   v `$TOKEN`):

   ```sh
   curl -k -X POST "https://ilo01.example.local/redfish/v1/AccountService/Accounts/" \
     -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"UserName":"svc-cert","Password":"<heslo>",
          "Oem":{"Hpe":{"LoginName":"svc-cert","Privileges":{"LoginPriv":true,"iLOConfigPriv":true,
          "RemoteConsolePriv":false,"UserConfigPriv":false,"VirtualMediaPriv":false,
          "VirtualPowerAndResetPriv":false,"HostBIOSConfigPriv":false,"HostNICConfigPriv":false,
          "HostStorageConfigPriv":false,"SystemRecoveryConfigPriv":false}}}}'
   ```

   Nebo ve webovém rozhraní: **Administration → User Administration → New**, jen *Login*
   a *Configure iLO Settings*.
2. Nic se nezapíná: Redfish běží vždy na 443.

## Vyplnění v acme

Cíl (**Cíle → Přidat → HPE iLO 5 / 6 / 7 - klíč vytváří iLO**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | FQDN iLO, např. `ilo01.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc-cert` z kroku 1 |
| Země (C), Kraj (ST), Město (L), Organizace (O), Útvar (OU) | Co iLO chce v každém CSR; přednost má vlastní subjekt certifikátu (jeho profil) |
| Čekat na CSR nejvýše (s) | `900` - iLO vytvoří CSR zhruba do 10 minut |
| Ověřovat certifikát zařízení | Vypnuto, dokud má iLO self-signed certifikát |

Potom certifikát: **Přidat certifikát → Klíč → Klíč vytváří zařízení → vyberte tento cíl**
(nebo **Vytvořit jeho certifikát** v okně cíle). Jeho jména: FQDN iLO (a jeho IP adresy).
Typ klíče: `rsa-2048` nebo `ec-384`, viz výše. acme samo vytvoří nasazení na iLO; spustí se
hned po každém vydání.

```sh
acme --cert-add ilo01 --names ilo01.example.local --key-type ec-384 --issuer "Let's Encrypt" --csr-from ilo01
acme --renew ilo01
```

## Ověření

- **Test** u cíle se přihlásí a řekne generaci iLO, firmware, bezpečnostní stav a typ klíče,
  který vytváří - nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže *klíč a CSR vytváří zařízení* (několik minut),
  vydání a import; iLO se resetuje a testy po něm počkají:

  ```sh
  openssl s_client -connect ilo01.example.local:443 -servername ilo01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -u svc-cert:'<heslo>' "https://ilo01.example.local/redfish/v1/Managers/1/SecurityService/HttpsCert/" | jq .X509CertificateInformation
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo. |
| `403` u GenerateCSR, PATCH nebo importu | Účtu chybí *Configure iLO Settings*. |
| `iLO dá do svého CSR jedno jméno hostitele` | Dejte certifikátu jedno DNS jméno (a jen adresy iLO). |
| `CSR ... jmenuje ..., které certifikát nechce` | iLO přidalo jméno (své IP nebo krátké jméno hostitele) - přidejte ho do certifikátu, nebo IP adresy vynechte. |
| `vytváří jen klíče ECDSA` / `jen klíče RSA` | Rozhoduje bezpečnostní stav iLO (bez `KeyType`): zvolte uvedený typ klíče. |
| `za 900 s nevytvořilo nový CSR` | iLO ještě pracuje - **Obnovit teď** zkuste později; dokud CSR vytváří, další nespustí. |
| iLO po resetu servíruje self-signed certifikát | Mezitím vznikl jiný CSR (ručně) nebo se před importem změnilo jméno hostitele - **Obnovit teď** vytvoří nový. |
| Zapnutý SCEP | Vypněte na iLO automatickou registraci certifikátu; blokuje import. |
