# HPE iLO 5 / 6 / 7 (Redfish, HpeHttpsCert) - nastavení pro acme

acme nahraje na iLO certifikát **i jeho soukromý klíč** tak, jak to popisuje HPE: přihlásí
se do Redfish relací (`POST /redfish/v1/SessionService/Sessions/`, `X-Auth-Token`), přečte
firmware manageru a bezpečnostní stav, nastaví typ klíče certifikátu iLO
(`PATCH .../SecurityService/HttpsCert/ {"KeyType": "RSA" | "ECDSA"}`), pokud je jiný,
a pošle certifikát následovaný klíčem akcí `HpeHttpsCert.ImportCertificate` (tzv.
*sideload*). **iLO se potom samo restartuje** - webové rozhraní, Redfish, vzdálená konzole
a virtuální média jsou 1-3 minuty nedostupné; **server ani jeho operační systém se
nerestartují**. Test toho, co se servíruje, na to počká.

## Pro které iLO je tato verze

Verze modulu **„HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7“** (`ilo`):

| iLO | Firmware | Typ klíče (`KeyType`) | Klíč RSA jen v bezpečnostním stavu |
|---|---|---|---|
| iLO 5 (Gen10, Gen10 Plus) | 2.78 a novější | neexistuje - nic se nenastavuje | (nedokumentováno - nekontroluje se) |
| iLO 6 (Gen11) | 1.30 a novější | od 1.70 - nastaví se podle klíče | **Production** |
| iLO 7 (Gen12) | libovolný (ověřeno do 1.25) | od 1.17 - nastaví se podle klíče | **SecureStandard** |

Volání jsou na všech třech stejná, proto je to jedna verze. acme **odmítne dřív, než cokoli
změní**: iLO 4, iLO 5 starší než 2.78, iLO 6 starší než 1.30, řadič, který není iLO (pro
ty zvolte prostou verzi *Redfish*), a klíč RSA na iLO 6/7 v jiném bezpečnostním stavu
(HighSecurity, FIPS, CNSA: použijte typ klíče ECDSA - vlastní CSR iLO jsou tam ECDSA P-384).

Proč ne prostá verze Redfish: HPE dává certifikát webového serveru iLO jen přes vlastní
prostředek `HpeHttpsCert`; iLO 6 pro něj nemá akci DMTF `ReplaceCertificate`.

## Co potřebujete

- Síťový přístup z acme na iLO: **TCP 443** (Redfish je v iLO vždy zapnutý).
- Účet iLO s oprávněními **Login** a **Configure iLO Settings** (`LoginPriv`,
  `iLOConfigPriv`). Role *Operator* **nestačí** (nemá `iLOConfigPriv`).
- Název hostitele a doménu iLO nastavené na jméno v certifikátu (*iLO Dedicated Network
  Port → General*) a nastavené NTP.
- Vypnutou automatickou registraci certifikátu (SCEP, iLO 5/6): když je zapnutá, iLO ruční
  import blokuje.

## Nastavení iLO

Vytvořte servisní účet jen s Login + Configure iLO Settings. Přes iLOrest (oprávnění
1 = Login, 4 = Configure iLO Settings):

```sh
ilorest login ilo01.example.com -u Administrator -p '<heslo-admina>'
ilorest iloaccounts add acme "acme certificate manager" '<silne-heslo>' --addprivs 1,4
ilorest logout
```

Nebo přes Redfish (pozor: v Redfish je `UserName` přihlašovací jméno a `Oem.Hpe.LoginName`
zobrazované jméno - ve webovém rozhraní je to naopak):

```sh
curl -k -X POST "https://ilo01.example.com/redfish/v1/AccountService/Accounts/" \
  -u 'Administrator:<heslo-admina>' -H "Content-Type: application/json" \
  -d '{"UserName": "acme", "Password": "<silne-heslo>",
       "Oem": {"Hpe": {"LoginName": "acme certificate manager",
                       "Privileges": {"LoginPriv": true, "iLOConfigPriv": true}}}}'
```

iLO roli dopočítává při čtení: účet s `iLOConfigPriv` se **zobrazí jako „Administrator“**,
i když má jen tato dvě oprávnění - je to zdokumentované chování, ne chyba.

Kontrola firmwaru a bezpečnostního stavu:

```sh
curl -sk -u acme:'<heslo>' https://ilo01.example.com/redfish/v1/Managers/1/ | jq .FirmwareVersion
curl -sk -u acme:'<heslo>' https://ilo01.example.com/redfish/v1/Managers/1/SecurityService/ | jq .SecurityState
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7** |
| Adresa | jméno nebo IP iLO, např. `ilo01.example.com` |
| Port HTTPS | `443` |
| Uživatel / Heslo | účet `acme` z předchozího kroku |
| Basic autentizace místo relace (pokročilé) | vypnuto (jen když relace nefungují) |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má iLO svůj self-signed certifikát (typicky před prvním nasazením) |
| Certifikát CA (pokročilé) | CA současného certifikátu iLO, není-li veřejná |
| Zkontrolovat, co se servíruje (nasazení) | prázdné: acme kontroluje vlastní adresu iLO |

Samotný certifikát: typ klíče **ECDSA** funguje ve všech bezpečnostních stavech; **RSA**
(2048, 3072, 4096) jen ve stavu *Production* (iLO 6) / *SecureStandard* (iLO 7). Jméno,
pod kterým se k iLO přistupuje, musí být v certifikátu.

## Kontrola

- Stiskněte na cíli **Vyzkoušet**: `signed in to ...: iLO 6 firmware 1.62, security state
  Production, certificate CN=..., until ...`.
- Po nasazení (počkejte na restart iLO):

```sh
openssl s_client -connect ilo01.example.com:443 -servername ilo01.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sk -u acme:'<heslo>' "https://ilo01.example.com/redfish/v1/Managers/1/SecurityService/HttpsCert/" \
  | jq .X509CertificateInformation
```

*Security Log* v iLO (Information → Security Log) zaznamenává každý import i jeho chyby.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | špatné jméno nebo heslo, nebo je účet vypnutý |
| `403` při importu | účtu chybí *Configure iLO Settings* (`iLOConfigPriv`) |
| `400 ImportCertificateFailed` | nesedí typ klíče (acme nastavuje `KeyType` předem - viz Security Log), nebo je klíč RSA ve vyšším bezpečnostním stavu |
| *it takes a private key from 2.78 / 1.30* | aktualizujte firmware iLO |
| *is not an HPE iLO* | řadič není iLO: zvolte prostou verzi *Redfish* |
| *takes an RSA key only in Production / SecureStandard* | zvolte pro certifikát typ klíče ECDSA, nebo změňte bezpečnostní stav (změna maže bezpečnostní obsah) |
| import odmítnut při zapnutém SCEP | vypněte automatickou registraci certifikátu (iLO 5/6) |
| test toho, co se servíruje, zprvu selže | iLO se po importu restartuje (1-3 minuty); test acme čeká až pět minut |
| OneView hlásí nedůvěryhodný certifikát iLO | vložte vydávající CA do trust storu OneView (`/rest/certificates/ca`) - viz cíl *HPE OneView* |

*Nejisté*: na iLO 5 je sideload zdokumentován „přes iLOrest“ (který posílá právě tuto akci)
a zda iLO 5 omezuje klíče RSA podle bezpečnostního stavu, dokumentace neuvádí; zda iLO
přijme za certifikátem i mezilehlé certifikáty, také neuvádí - acme posílá certifikát a
klíč, jako příklad HPE.

Zdroje: HPE iLO security service (Redfish supplement), iLO 5 SSL certificate
(ilo-rest-api-docs), resource definitions iLO 6 1.74 a iLO 7 1.23 (`HpeHttpsCert`,
`KeyType`), changelog iLO 7 a *Adapting from iLO 6*, *Managing iLO users*.
