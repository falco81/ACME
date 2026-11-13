# Lenovo XClarity Administrator - nastavení pro acme

XClarity Administrator (LXCA) přijme **jen certifikát podepsaný k CSR, který si sám vytvořil** -
referenční příručka REST API Lenova: nahraný certifikát *musí vzniknout z žádosti o podpis
certifikátu*; soukromý klíč ani PKCS#12 nahrát nejde. Proto **klíč vytváří LXCA**: při každém
vystavení a obnovení acme požádá LXCA přes jeho REST API o nový klíč a CSR
(`POST /certificateSigningRequest`), nechá CSR podepsat zdrojem certifikátu, přidá certifikáty CA
do úložiště důvěryhodných certifikátů LXCA a hned certifikát nahraje
(`POST /serverCertificate/tmp`). Klíč LXCA nikdy neopustí; acme žádný nemá. Je to certifikát
webového rozhraní a REST API LXCA - a ten, kterým se LXCA prokazuje spravovaným zařízením
a XClarity Orchestratoru.

**Tato verze** je pro **LXCA 3.x a 4.x** (ověřeno proti LXCA 4.3) - volání jsou stejná. LXCA
4.0 a novější po nahrání restartuje webový server a ukončí všechny relace. XClarity Orchestrator
a XClarity One tento cíl nepokrývá: Lenovo jejich serverový certifikát dokumentuje jen v jejich
webovém rozhraní.

## Co potřebujete

- Z acme do LXCA: **TCP 443** (HTTPS, REST API s Basic autentizací).
- Účet LXCA pro acme ve skupině rolí **LXC-SECURITY-ADMIN** (níže).
- Zdroj, který podepíše CSR vytvořený jinde - obvykle vlastní autorita acme nebo firemní CA:
  LXCA chce **obě EKU, Server Authentication i Client Authentication** (certifikátem se
  prokazuje i svým zařízením), Key Usage *Digital Signature, Key Encipherment, Key Agreement*,
  SHA-256 nebo SHA-384. Veřejné ACME CA už klientskou autentizaci nevydávají. Ne *Self-signed*.
- Jména: nejdřív jméno, přes které se LXCA připojuje k zařízením (common name), jeho FQDN a IP
  adresa (IP se do CSR dá jako IP adresa).
- Klíč: LXCA vytvoří klíč **RSA** o **2048** nebo **3072** bitech podle svého kryptografického
  režimu (žádné ECDSA) - dejte certifikátu jeden z těchto typů klíče; acme ho vybrat nemůže.
- **Před první výměnou:** spravovaná zařízení online a důvěryhodná (*Hardware → Servers /
  Chassis*, žádné *Offline* ani *Untrusted*), jejich firmware aktuální.

## Nastavení LXCA

1. Místní uživatel ve skupině rolí **LXC-SECURITY-ADMIN** (*Administration → Security → Users
   and Groups → Local Users → Create*), nebo vlastní role vytvořená z `lxc-security-admin`
   (*Administration → Security → Roles → Create*). Přes REST API jako supervisor:

   ```sh
   curl -k -u admin:'<heslo správce>' -X POST https://lxca.example.local/userAccounts \
     -H 'Content-Type: application/json' \
     -d '{"userName":"svc-cert","userPw":"<heslo>","description":"certifikáty acme","groups":["LXC-SECURITY-ADMIN"],"PasswordChangeFirstAccess":false}'
   ```

2. REST API je zapnuté vždy - není co zapínat.
3. Je-li CA pro LXCA nová, acme před nahráním přidá její kořenový a mezilehlé certifikáty do
   **Trusted Certificates** (volba nasazení, výchozí zapnutá); LXCA pak CA rozešle spravovaným
   zařízením v úloze.

## Vyplnění v acme

Cíl (**Cíle → Přidat → Lenovo XClarity Administrator**):

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP LXCA, např. `lxca.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Účet z kroku 1 (`svc-cert`) |
| Země, Kraj, Město, Organizace | Co LXCA dává do každého CSR (žádá je); přednost má vlastní subjekt certifikátu (jeho profil) |
| Útvar | Nepovinné |
| Ověřovat certifikát zařízení | Při prvním vystavení vypnuto (LXCA má ještě vlastní certifikát), potom zapnuto |

Pak certifikát: **Přidat certifikát** → v kroku **Klíč** zvolte **Klíč vytváří zařízení** →
vyberte tento cíl (nebo v okně cíle **Vytvořit jeho certifikát**). Jména: FQDN LXCA a jeho IP
adresa. Typ klíče: RSA 2048 (nebo RSA 3072 v režimu NIST strict). Nasazení do LXCA si acme
vytvoří samo; proběhne hned po každém vystavení. Z příkazové řádky:

```sh
acme --cert-add lxca --names lxca.example.local,10.0.0.60 --issuer "Internal CA" --key-type rsa-2048 --csr-from lxca
acme --renew lxca
```

Volby nasazení: **Přidat certifikáty CA do úložiště důvěryhodných** (zapnuto: kořenový a každý
mezilehlý certifikát jdou nejdřív do *Trusted Certificates*, jak Lenovo žádá) a **Kořenový
certifikát CA** - kořen, kterým řetězec končí, když ho řetězec nenese: LXCA chce celý řetězec
včetně kořene.

## Ověření

- **Test** u cíle se přihlásí a přečte serverový certifikát - nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže *klíč a CSR vytváří zařízení*, vystavení, úložiště
  důvěryhodných certifikátů a nahrání. LXCA restartuje webový server (v prohlížeči se přihlaste
  znovu); testy po nasazení na něj počkají.

  ```sh
  openssl s_client -connect lxca.example.local:443 -servername lxca.example.local -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -k -u svc-cert:'<heslo>' https://lxca.example.local/serverCertificate/details
  curl -k -u svc-cert:'<heslo>' https://lxca.example.local/trustedCertificates/details
  ```

  V LXCA: *Hardware → Servers* - žádné zařízení *Offline* ani *Untrusted*.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný uživatel nebo heslo. |
| `403` | Účet není v LXC-SECURITY-ADMIN (ani LXC-SUPERVISOR). |
| `LXCA makes RSA keys only` | Dejte certifikátu typ klíče RSA 2048 nebo 3072. |
| `LXCA did not take the certificate` | Není podepsaný k poslednímu CSR LXCA (ručně vytvořené CSR klíč zahodí) - **Obnovit teď**; nebo chybí EKU *Client Authentication*, případně je použito ECDSA / RSA-PSS / SHA-1. |
| `no root CA certificate` (varování) | Zadejte kořen ve volbě nasazení *Kořenový certifikát CA*. |
| Zařízení po výměně *Untrusted* / *Offline* | Úloha s CA u nich selhala: opravte je a v LXCA instalaci dokončete (*Administration → Security → Server Certificate*). |
| XClarity Orchestrator nad LXCA přestane fungovat | Certifikát LXCA potřebuje obě EKU a Orchestrator musí nové CA důvěřovat. |
| Nasazení pozdržena | LXCA si nechá starý certifikát; další vystavení si řekne o nový klíč a CSR. |
