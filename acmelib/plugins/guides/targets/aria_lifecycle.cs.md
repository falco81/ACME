# VMware Aria Suite Lifecycle (certifikáty produktů) - nastavení pro acme

acme dá certifikát **produktům Aria přes Aria Suite Lifecycle 8.18** - to je zdokumentovaná cesta pro Aria Operations (jeho webový certifikát se jinak nastavuje jen v Admin UI), Aria Operations for Logs (jen v jeho UI), Aria Automation / Orchestrator a Workspace ONE Access. *Replace Certificate* v Suite Lifecycle navíc zajistí, že nový certifikát ostatní produkty znovu přijmou (*Retrust*), a umí udělat snapshot.

1. `GET /lcm/locker/api/v2/certificates` - je už v Lockeru (stejný alias)? pak se znovu neimportuje;
2. `POST /lcm/locker/api/v2/certificates/import` s `alias` (`acme-<jméno>-<datum>-<sériové číslo>`), `certificateChain` (koncový → mezilehlé → kořen), `privateKey`, `passphrase` "";
3. pro každý řádek produktu: `POST .../environments/<env>/products/<produkt>/certificates/<vmid>/pre-validate`, pak `PUT .../environments/<env>/products/<produkt>/certificates/<vmid>` - vznikne požadavek (request);
4. `GET /lcm/request/api/v2/requests/<requestId>` každých 30 s, dokud není `COMPLETED` (požadavek `FAILED` nasazení zastaví);
5. starší certifikáty acme nad *ponechat* smaže z Lockeru (ten, který se ještě používá, Suite Lifecycle odmítne a zůstane).

Autentizace: základní HTTP (`admin@local`, nebo Certificate Administrator).

## Pro které verze je tento návod

Aria Suite Lifecycle **8.18** (Aria Suite 8.18, samostatně i ve VCF 5.x). Ve **VCF 9** jsou produkty komponentami správy VCF, které spravuje VCF Operations (*Fleet management → Certificates*) a ten přijme jen certifikáty k vlastním CSR - na to tento cíl není.

## Nastavení Suite Lifecycle

1. **Uživatel**: `admin@local`, nebo - s nejmenšími právy - uživatel z Workspace ONE Access (např. AD `svc-aria-cert`) **jen** s rolí **Certificate Administrator**: *Lifecycle Operations → User Management → ADD USER/GROUP → uživatel → Next → Certificate Administrator → Next → Submit* (uživatel, který už má jinou roli, ji dostat nemůže).
2. **ID prostředí a produktů**: *Lifecycle Operations → Environments → prostředí → View Details* - ID prostředí je v adrese; produkty jsou `vrops` (Aria Operations), `vra` (Automation), `vrli` (Operations for Logs), `vidm` (Workspace ONE Access, prostředí `globalenvironment`), `vro` ... Nebo:

   ```sh
   curl -sk -u 'admin@local:<heslo>' https://lcm.example.local/lcm/lcops/api/v2/environments
   ```

3. **Snapshoty**: *Opt-in for Snapshot* je v průvodci v UI; přes API je před prvním během udělejte sami (cluster Operations for Logs: snapshoty bez paměti).
4. **Load balancery** před produktem Suite Lifecycle neaktualizuje (KB 424473) - změňte je sami.

## Certifikát

- RSA 2048 nebo 4096; SAN s FQDN všech uzlů **a** load balanceru (Aria Automation i IP uzlů, žádný wildcard - KB 325876, KB 420444).
- Operations for Logs: CA musí povolit i účel *SSL Client* (KB 442507).
- Locker odmítne certifikát, kterému zbývá méně než 15 dní.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FQDN Suite Lifecycle, `443` |
| Uživatel / Heslo | `admin@local` (nebo Certificate Administrator) a jeho heslo |
| Produkty (nasazení) | jeden na řádek: `<ID prostředí> <ID produktu>`, např. `8a2b...e1 vrops`; prázdné: jen do Lockeru |
| Kořenový certifikát CA (nasazení, pokročilé) | kořen, když jím řetězec nekončí |
| Nejdřív předběžně ověřit (nasazení, pokročilé) | zapnuto |
| Čekat na každý požadavek (minut) (nasazení, pokročilé) | `60`; `0`: požadavek spustit a pokračovat |
| Kolik předchozích verzí ponechat (pokročilé) | `1` |
| Zkontrolovat, co se servíruje | adresa produktu, např. `vrops.example.local:443` |

## Kontrola

*Vyzkoušet* vypíše Locker. Požadavky: *Lifecycle Operations → Requests*; certifikát produktu:

```sh
curl -sk -u 'admin@local:<heslo>' https://lcm.example.local/lcm/lcops/api/v2/environments/<env>/products/vrops/certificates
openssl s_client -connect vrops.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

## Vlastní certifikát Suite Lifecycle

Jsou to dva soubory a nginx (techdocs 8.18 „Replace your custom Lifecycle certificate") - použijte cíl **SSH** v acme s těmito soubory a tímto příkazem:

```text
cert-pem /opt/vmware/vlcm/cert/server.crt 0644
key-pem  /opt/vmware/vlcm/cert/server.key 0600
```

```sh
systemctl restart nginx
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| „Failed to parse private key" (KB 408525) | Klíč chybí nebo je šifrovaný - acme ho posílá nešifrovaný; ověřte, že ho nic nezměnilo. |
| Validace řetězce selže (KB 430787) | Vyplňte *Kořenový certifikát CA*: řetězec musí být úplný a ve správném pořadí. |
| Požadavek FAILED (LCMCOMMON80066, LCMVRLISYSTEM45038 ...) | Přečtěte ho v *Requests*; u Operations for Logs často pomůže nový certifikát v Lockeru (KB 411526). |
| Expirovaný certifikát nejde vyměnit (KB 411526) | Nejdřív ručně dejte platný (Aria Operations: KB 326393). |
| `the product line ... is "<environment id> <product id>"` | Na řádku dvě slova. |
