# Juniper SRX - nastavení pro acme

acme nasazuje certifikáty na Juniper SRX (Junos OS) přes **Junos REST API** (`https://<srx>:3443`, HTTP basic autentizace, stejná XML RPC jako v CLI). Každé obnovení:

1. zapíše certifikát (s řetězcem, nebo samotný) a klíč do `/var/tmp/<id>.crt` / `.key` (práva 0600);
2. načte je do PKI pod **novým certificate id** `acme-<label>-<datum>-<sériové číslo>` (nejvýš 32 znaků);
3. oba soubory znovu zapíše **prázdné**, aby v `/var/tmp` nezůstal žádný klíč;
4. přepne vybrané služby na nové id v **jedné zamčené a commitnuté změně**: J-Web / web management, samotné REST API, SSL termination profily, SSL proxy profily, IKE policy;
5. odstraní starší id od acme (`clear security pki local-certificate` a pár klíčů) nad rámec *keep*.

Chassis cluster / multinode HA (PKI druhého uzlu) se neřeší.

## Co potřebujete

- SRX s verzí Junos, která má REST API (`system services rest`), např. Junos 15.1X49 a novější; ověřeno podle modelů Junos 23.4.
- Přístup HTTPS z acme na port REST API SRX (v tomto návodu 3443).
- Lokálního uživatele Junos s login class, která povoluje operace **configure**, **maintenance** a **security** (PKI).

## Nastavení SRX

1. Vytvořte pro acme login class a uživatele (konfigurační režim):

```text
set system login class acme-certs permissions [ configure maintenance security ]
set system login user acme class acme-certs authentication plain-text-password
```

   Třídu můžete dále zúžit pomocí `allow-configuration-regexps` na příkazy, které acme nastavuje (`system services web-management https pki-local-certificate`, `system services rest https server-certificate`, `services ssl termination profile`, `services ssl proxy profile`, `security ike policy`) - vyzkoušejte to tlačítkem **Test** v acme a prvním nasazením.

2. Zapněte REST API přes HTTPS, omezené na server acme. HTTPS potřebuje certifikát; na novém zařízení nejdřív vygenerujte self-signed (provozní režim):

```text
request security pki generate-key-pair certificate-id rest-self size 2048
request security pki local-certificate generate-self-signed certificate-id rest-self domain-name srx.example.local subject "CN=srx.example.local"
```

   a pak (konfigurační režim):

```text
set system services rest https port 3443
set system services rest https server-certificate rest-self
set system services rest control allowed-sources 192.0.2.10
commit
```

   (`192.0.2.10` = server acme.) Pokud to tam omezujete, povolte port REST také v host-inbound traffic zóny, ze které acme přichází.

3. Ověřte, že SSL profily / IKE policy, které má acme přepínat, existují (acme mění jen jejich certifikát).

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | správcová adresa SRX |
| HTTPS port | 3443 (`rest https port`) |
| User / Password | uživatel z kroku 1 |
| Check the device's certificate | vypnuto, dokud REST API používá self-signed `rest-self` (nebo zadejte jeho CA); zapnuto, jakmile používá certifikát od acme |
| CA certificate (pokročilé) | CA certifikátu REST API |
| J-Web / web management (HTTPS) | zapnuto: `web-management https pki-local-certificate` dostane nové id |
| The REST API itself | zapnuto: i REST API, se kterým acme mluví, použije nový certifikát |
| SSL termination profiles | jména profilů, jedno na řádek |
| SSL proxy profiles | jména profilů, jedno na řádek |
| IKE policies | jména policy, jedno na řádek (z každé se smaže starší id od acme) |
| The certificate file holds (pokročilé) | certifikát a jeho řetězec (výchozí), nebo jen certifikát |
| Previous versions to keep | kolik starších id od acme zůstane v PKI |
| Check what is served | `srx.example.local:443` (J-Web) apod., jeden na řádek |

## Ověření

- **Test** v acme se přihlásí a přečte verzi softwaru (`get-software-information`).
- Na SRX:

```text
show security pki local-certificate
show configuration system services web-management
show system commit
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 při Testu | špatný uživatel/heslo, nebo IP acme není v `rest control allowed-sources` |
| Spojení odmítnuto / timeout | REST přes HTTPS není zapnuté, špatný port, nebo ho blokuje host-inbound traffic |
| `…: Junos said … permission denied` | login class nemá `security`, `maintenance` nebo `configure` (nebo allow-regexp) |
| `… (the candidate configuration may hold acme's lines …)` | commit selhal: na SRX v konfiguračním režimu spusťte `rollback 0`, odstraňte příčinu (viz zprávu) a nasaďte znovu |
| `… is not a Junos name` | jméno profilu/policy obsahuje znaky, které Junos nepřijímá |
| `nothing is switched to … (no service asked)` | v nasazení vyberte aspoň jednu službu |
| Načtení selže u klíče ECDSA | ověřte, že vaše verze Junos tento typ klíče pro danou službu přijímá; jinak použijte RSA |
