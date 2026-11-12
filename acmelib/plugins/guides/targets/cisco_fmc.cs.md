# Cisco Secure Firewall Management Center (FMC) - nastavení pro acme

acme se přihlásí do **REST API FMC** (`POST /api/fmc_platform/v1/auth/generatetoken`,
HTTP basic) a naimportuje certifikát a klíč jako **nový objekt Internal Certificate** se
jménem s datem (změna na místě není spolehlivá). V každé zadané **decryption policy**
přepne na nový objekt každé pravidlo (*Decrypt - Known Key*), které odkazuje na starší
objekt acme tohoto certifikátu. Pokud se pravidla změnila a je zapnuto *Deploy to the
devices*, pošle acme požadavek na nasazení pro zařízení se změnami. Starší objekty acme,
které žádné pravidlo neuvádí, smaže.

Pro FMC 7.4 a novější (tělo Internal Certificate podle Terraform provideru Cisco),
on-premises i virtuální. Identitní certifikáty RA VPN (certificate enrolments) se
neobsluhují.

## Co potřebujete

- Správcovskou adresu FMC, **HTTPS 443** dostupné z acme.
- Zapnuté REST API (výchozí).
- **Samostatný účet jen pro API**: přihlásí-li se týž účet do webového rozhraní, relace
  API ho odhlásí (a naopak).
- Decryption policies, jejichž pravidla Known Key mají certifikát používat.

## Nastavení FMC

1. Ověřte, že je zapnuto **System (ozubené kolo) → Configuration → REST API Preferences →
   Enable REST API**.
2. Vytvořte uživatelskou roli (nebo použijte *Administrator*): **System → Users → User
   Roles → Create User Role**, s právem úprav na:
   - **Object Manager** (Internal Certificates / PKI objekty),
   - **Policies → Access Control → SSL / Decryption Policy** (modify),
   - **Deploy Configuration to Devices** (jen pokud acme nasazuje).
   Názvy nabídek se mezi verzemi FMC liší - ověřte je na své.
3. Vytvořte uživatele: **System → Users → Users → Create User**, např. `api-acme`, silné
   heslo, role z kroku 2, v doméně politik. Používejte ho **jen pro acme**.
4. **Poprvé**: starší objekt acme ještě neexistuje - po prvním nasazení otevřete
   decryption policy a v pravidlech Known Key jednou vyberte nový objekt `acme-...`. Další
   obnovy je přepnou samy.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | FMC, např. `fmc.example.local` / `443` |
| User | Účet jen pro API (výchozí `api-acme`) |
| Password | Jeho heslo |
| Domain UUID (pokročilé) | Prázdné: doména, kterou vrátí přihlášení (`DOMAIN_UUID`) |
| Check the device's certificate / CA certificate | Vypnout jen dokud má FMC self-signed certifikát |
| Decryption policy (nasazení) | Vybraná ze seznamu (*Load the list*) |
| More decryption policies (nasazení) | Jedna na řádek: jména nebo ID |
| Deploy to the devices (nasazení) | Zapnuto: po změně požadavek na nasazení |
| Only these devices (nasazení) | Jedno na řádek: jména zařízení; prázdné: každé zařízení se změnami |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | Server za firewallem, např. `www.example.com:443` |

Akce **List the internal certificates** vypíše objekty Internal Certificate a decryption
policies - jen pro čtení.

## Ověření

- **Try**: `signed in to the FMC ... (domain ...); N internal certificates`.
- Na FMC: **Objects → Object Management → PKI → Internal Certs** ukazuje `acme-...`;
  **Deploy → Deployment History** ukazuje nasazení.

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 na generatetoken | Chybný uživatel/heslo, nebo je REST API vypnuté |
| Webová relace (nebo acme) se náhle odhlásí | Stejný účet se používá v prohlížeči - dejte acme vlastní |
| 403 na objektech nebo pravidlech | Role nemá práva Object Manager nebo úprav decryption policy |
| Pravidla se nepřepnula | Žádné pravidlo ještě neodkazuje na starší objekt acme - vyberte nový objekt jednou ručně |
| Nasazení nezačalo | *Deploy to the devices* vypnuto, nebo chybí právo nasazovat |
| Starší objekt se nesmazal | Ještě ho uvádí nějaké pravidlo |
