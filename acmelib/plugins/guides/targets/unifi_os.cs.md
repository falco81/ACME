# UniFi OS console - nastavení pro acme

acme se přihlásí ke konzoli (`POST /api/auth/login`) a použije její vlastní API pro
certifikáty - to, které stojí za **Settings → Control Plane → Console → Certificates**:
přidá certifikát (celý řetězec + klíč) pod jménem s datem
`acme-<jméno>-<datum>-<sériové číslo>` (`/api/userCertificates`), nastaví ho jako
**aktivní** (`PUT /api/userCertificates/<id>/status`) a smaže starší certifikáty acme nad
počet *Previous versions to keep*. Na disk konzole se nic nezapisuje; konzole si webový
server znovu načte sama.

Pro konzole UniFi OS s podporou vlastních certifikátů (**UniFi OS 4.2 a novější**, podle
hlášení funguje na 4.x i 5.x): UDM, UDM Pro / SE, UCG, UDR, Cloud Key Gen2+ a UniFi OS
Server. API je vlastní API konzole (to, které používá acme.sh), ne zdokumentované veřejné
API. Pro samostatně hostovanou aplikaci UniFi Network použijte místo toho cíl *Linux / Unix
server* s předvolbou *UniFi Network*.

## Co potřebujete

- UniFi OS 4.2 nebo novější.
- Síťový přístup z acme na konzoli: **TCP 443**.
- **Lokálního** správce konzole **bez dvoufázového přihlášení** (účet UI.com / SSO s 2FA
  použít nelze).

## Nastavení konzole

1. Vytvořte lokálního správce pro acme: **UniFi OS → Settings → Admins & Users → Create New
   Admin** (znění se mezi verzemi liší): zvolte **Restrict to Local Access Only**,
   uživatelské jméno `acme`, silné heslo.
2. Dejte mu roli, která smí měnit nastavení konzole (certifikáty jsou nastavením konzole -
   plný správce / Super Admin; omezená role může být odmítnuta - ověřte přes **Try**).
   Oprávnění k aplikacím (Network, Protect...) nepotřebuje.
3. Ověřte, že acme dosáhne na port HTTPS konzole (firewall / pravidla provozu ve
   správcovské síti).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP konzole, např. `unifi.example.local` |
| HTTPS port | `443` |
| User | `acme` (výchozí) - lokální správce |
| Password | Jeho heslo |
| Check the device's certificate | Zapnuto; vypnout jen dokud má konzole self-signed certifikát (typicky před prvním nasazením) |
| CA certificate (pokročilé) | CA současného certifikátu konzole, pokud není veřejná |
| Previous versions to keep (pokročilé) | Výchozí 1, `-1` ponechá vše |
| Check what is served | Prázdné: acme ověří vlastní adresu konzole |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí a vypíše přidané certifikáty:
  `signed in to ...; N certificates added there`.
- V konzoli: **Settings → Control Plane → Console → Certificates** ukazuje `acme-...` jako
  aktivní.
- Z libovolného počítače:

  ```sh
  openssl s_client -connect unifi.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` při přihlášení | Špatné heslo, účet je UI.com/SSO, nebo má dvoufázové přihlášení - použijte lokálního správce. |
| `the console gave no session cookie` | Nejde o konzoli UniFi OS (např. starší Cloud Key nebo samotná aplikace Network). |
| `404` na `/api/userCertificates` | UniFi OS starší než 4.2 - aktualizujte. |
| `403` při přidání | Role správce nesmí měnit nastavení konzole. |
| Stále se ukazuje starý certifikát | Konzole potřebuje pár sekund na načtení; kontrola acme to zkouší opakovaně. |
