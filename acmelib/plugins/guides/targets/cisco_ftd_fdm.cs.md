# Cisco Secure Firewall Threat Defense (FDM) - nastavení pro acme

Pro FTD spravované **lokálně přes Firepower Device Manager**. (FTD spravované z FMC
používá místo toho cíl *Cisco Secure Firewall Management Center*.)

acme si vezme token z **REST API FDM** (`POST /api/fdm/latest/fdm/token`,
`grant_type: password`), nahraje certifikát a klíč jako **nový Internal Certificate** se
jménem s datem, mezilehlé certifikáty jednou přidá jako External CA Certificates
`acme-ca-<id>` a pak na něj přepne:

- **správcovské webové rozhraní** (vlastní HTTPS a API FDM) - výchozí zapnuto,
- nastavení brány **remote access VPN** - je-li zapnuto,

poté změnu **nasadí** a čeká, dokud není `DEPLOYED` (před nasazením není nic aktivní).
Starší objekty acme, které nic neuvádí, smaže.

Pro FTD 6.x / 7.x s lokální správou (FDM) a REST API (reference v6 pro FTD 7.2).

## Co potřebujete

- Přístup HTTPS z acme na správcovskou adresu zařízení (TCP 443) - management rozhraní
  nebo datové rozhraní s povoleným HTTPS přístupem ke správě.
- Účet **admin** zařízení: FDM přijímá API jen od něj.
- Žádné rozpracované, nenasazené změny jiných správců v FDM v době nasazení acme (byly by
  nasazeny také).

## Nastavení FDM

1. V FDM: **Device → System Settings → Management Access**. Na záložce *Management
   Interface* povolte HTTPS z adresy serveru acme (nebo přidejte pravidlo na záložce *Data
   Interfaces* pro rozhraní, kam acme přistupuje).
2. Použijte účet **admin** (lokální). Dejte mu silné heslo; acme ho uchovává zapečetěné.
3. Pro **Remote access VPN**: RA VPN už musí být nastavena (**Device → Remote Access
   VPN**); acme jen vymění její serverový certifikát.
4. Čekající změny jednou nasaďte sami, aby první nasazení acme neslo jen jeho změnu.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | Správcovská adresa FTD, `443` |
| User | `admin` (FDM přijímá API jen od něj) |
| Password | Jeho heslo |
| Check the device's certificate | Zapnuto, ale viz níže: po přepnutí zařízení servíruje nový certifikát |
| CA certificate (pokročilé) | CA nového certifikátu (např. kořen ACME CA), jakmile ho FDM používá |
| The management web interface (nasazení) | Zapnuto: vlastní HTTPS FDM (webové rozhraní a API) používá certifikát |
| Remote access VPN (nasazení) | Zapnuto: serverový certifikát nastavení brány RA VPN |
| Deploy the change (nasazení) | Zapnuto - bez nasazení není na zařízení nic aktivní |
| Wait for the deployment (s) (nasazení, pokročilé) | Výchozí 900 |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. `ftd.example.com:443` nebo jméno VPN |

## Ověření

- **Try**: `signed in to FDM ...; N internal certificates, the web interface uses <name>`.
- V FDM: **Objects → Certificates** obsahuje `acme-...`; **Deployment** (vpravo nahoře)
  ukazuje historii nasazení.

  ```sh
  openssl s_client -connect ftd.example.com:443 -servername ftd.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 400/401 na tokenu | Chybné heslo, nebo to není účet admin |
| Vypršení spojení | Přístup HTTPS ke správě nepovoluje adresu acme |
| Chyba TLS po prvním nasazení | FDM teď servíruje nový certifikát: vložte jeho CA do *CA certificate* |
| Nasazení vyprší nebo selže | Viz historie nasazení v FDM; zvyšte *Wait for the deployment* |
| Nasazeny i cizí čekající změny | Před během acme je v FDM nasaďte nebo zahoďte |
| Zařízení je spravované z FMC | Použijte cíl FMC |
