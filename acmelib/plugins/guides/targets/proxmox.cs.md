# Proxmox VE - nastavení pro acme

acme přes API Proxmox VE nahraje certifikát (celý řetězec + klíč) jako **vlastní
certifikát webového rozhraní každého uzlu** (pveproxy, port 8006):
`POST /api2/json/nodes/<node>/certificates/custom` s `force=1` a `restart=1`. Udělá to pro
každý zadaný uzel, nebo pro všechny uzly clusteru, není-li zadán žádný, a přeskočí uzel,
jehož `pveproxy-ssl.pem` už má stejný otisk.

Pro Proxmox VE 6 a novější (API tokeny). Proxmox Backup Server má vlastní cíl
(`proxmox_backup`).

## Co potřebujete

- Síťový přístup z acme na API uzlu: **TCP 8006**.
- Uživatele a **API token** s `Sys.Modify` (a `Sys.Audit` pro výpis uzlů) na `/nodes`.
- **Vlastní ACME Proxmoxu musí být vypnuté** na uzlech, které spravuje acme: obě zapisují
  stejné soubory (`pveproxy-ssl.pem`). Odstraňte domény ACME uzlu (*Node → System →
  Certificates → ACME*), nebo tam tento cíl nepoužívejte.

## Nastavení Proxmox VE

1. Vytvořte uživatele, roli jen s potřebnými oprávněními a token (na libovolném uzlu, jako
   root):

   ```sh
   pveum user add acme@pve --comment "acme certificate deployment"
   pveum role add AcmeCert --privs "Sys.Audit Sys.Modify"
   pveum acl modify /nodes --users acme@pve --roles AcmeCert
   pveum user token add acme@pve deploy --privsep 1
   pveum acl modify /nodes --tokens 'acme@pve!deploy' --roles AcmeCert
   ```

   Příkaz pro token vypíše tajemství **jen jednou** - zkopírujte si ho.
   (Jednodušší, ale širší: role `PVESysAdmin` na `/`.)
2. V GUI je totéž v **Datacenter → Permissions → Users / Roles / API Tokens / Add → User
   Permission / API Token Permission**. Se zapnutou *Privilege Separation* potřebuje token
   vlastní záznam oprávnění, jako výše.
3. Je-li zapnutý firewall Proxmoxu, povolte TCP 8006 ze serveru acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP jednoho uzlu, např. `pve1.example.local` |
| HTTPS port | `8006` |
| API token ID | `acme@pve!deploy` |
| API token secret | Tajemství vypsané při vytvoření tokenu |
| Check the device's certificate | Zapnuto; vypnout jen dokud má uzel self-signed certifikát (nebo vložte CA clusteru `/etc/pve/pve-root-ca.pem` do *CA certificate*) |
| Nodes (nasazení) | Jeden na řádek; prázdné = všechny uzly clusteru |
| Restart pveproxy (nasazení) | Zapnuto (výchozí), aby se nový certifikát hned použil |
| Check what is served | např. `pve1.example.local:8006`, `pve2.example.local:8006` |

**Všechny uzly dostanou stejný certifikát**: jeho jména musí pokrýt všechny zadané uzly
(nebo použijte pro každý uzel vlastní cíl s vlastním certifikátem).

## Ověření

- Na cíli stiskněte **Try**: acme přečte verzi a uzly a odpoví
  `signed in to ..., Proxmox VE x.y, nodes pve1, pve2`.
- Na uzlu:

  ```sh
  pvenode cert info
  openssl s_client -connect pve1.example.local:8006 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný formát ID tokenu (`user@realm!tokenid`) nebo tajemství. |
| `403 Permission check failed (/nodes/..., Sys.Modify)` | Token (s oddělením oprávnění) nebo uživatel nemá roli na `/nodes`. |
| Vypíší se jen některé uzly | Chybí `Sys.Audit` na `/nodes` - nebo uzly zadejte sami. |
| Certifikát se po pár dnech vrátí | Přepsalo ho vlastní ACME Proxmoxu: odstraňte jeho domény ACME. |
| Nesouhlasí jméno na uzlu | Certifikát neobsahuje jméno tohoto uzlu. |
