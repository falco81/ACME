# Proxmox Backup Server - nastavení pro acme

acme přes API PBS nahraje certifikát (celý řetězec + klíč) jako **vlastní certifikát
webového rozhraní a API PBS** (`proxy.pem` / `proxy.key`):
`POST https://<pbs>:8007/api2/json/nodes/<node>/certificates/custom` s API tokenem
(`Authorization: PBSAPIToken=<user@realm!id>:<secret>`). PBS si proxy znovu načte sám.
Pokud PBS už používá certifikát se stejným otiskem, nic se nenahrává.

**Připnuté otisky**: úložiště Proxmox VE a vzdálené PBS (remotes), které mají otisk PBS
připnutý, mu po změně přestanou věřit. Úloha ukáže nový otisk - doplňte ho tam, nebo je
nechte věřit CA.

Pro Proxmox Backup Server 2.x a novější.

## Co potřebujete

- Síťový přístup z acme na PBS: **TCP 8007**.
- Uživatele a API token s **`Sys.Modify` na `/system/certificates`**.
- **Vlastní ACME PBS nesmí certifikát spravovat** (zapisuje stejné soubory).

## Nastavení Proxmox Backup Server

1. Vytvořte uživatele a token a přidělte oprávnění (jako root na PBS). Oprávnění tokenu je
   omezeno tím, co má uživatel, proto je přidělte oběma:

   ```sh
   proxmox-backup-manager user create acme@pbs --comment "acme certificate deployment"
   proxmox-backup-manager user generate-token acme@pbs deploy
   proxmox-backup-manager acl update /system/certificates Admin --auth-id acme@pbs
   proxmox-backup-manager acl update /system/certificates Admin --auth-id 'acme@pbs!deploy'
   ```

   `generate-token` vypíše tajemství **jen jednou**. PBS nemá vlastní role; `Admin` je
   vestavěná role se `Sys.Modify` a cesta ACL ji omezuje jen na certifikáty.
2. V GUI je totéž v **Configuration → Access Control → User Management / API Token /
   Permissions**.
3. Je-li před PBS firewall, povolte TCP 8007 ze serveru acme.
4. Odstraňte případné vlastní domény ACME v PBS (**Certificates → ACME**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP PBS, např. `pbs.example.local` |
| HTTPS port | `8007` |
| API token ID | `acme@pbs!deploy` |
| API token secret | Tajemství vypsané příkazem `generate-token` |
| Check the device's certificate | Zapnuto; vypnout jen dokud má PBS self-signed certifikát |
| CA certificate (pokročilé) | CA současného certifikátu PBS, pokud není veřejná |
| Node (nasazení, pokročilé) | `localhost` (výchozí) |
| Check what is served | např. `pbs.example.local:8007` |

## Po prvním nasazení: připnuté otisky

V Proxmox VE potřebuje úložiště PBS s připnutým otiskem ten nový (je v úloze acme, nebo v
PBS: **Dashboard → Show Fingerprint**):

```sh
pvesm set <storage-id> --fingerprint <AA:BB:...>
```

S veřejně důvěryhodným certifikátem můžete otisk místo toho smazat, aby se věřilo CA.

## Ověření

- Na cíli stiskněte **Try**: acme přečte současný certifikát a odpoví
  `signed in to PBS ...; its certificate: <subjekt>, until <datum>`.
- Na PBS:

  ```sh
  proxmox-backup-manager cert info
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | ID tokenu musí být `user@realm!tokenid`; špatné tajemství. |
| `403 ... Sys.Modify` | Chybí ACL na `/system/certificates` pro uživatele nebo token. |
| Zálohy z Proxmox VE po obnovení selhávají (otisk) | Doplňte nový otisk do úložiště (viz výše). |
| Certifikát později nahradí jiný | Vlastní ACME PBS je stále nastavené - odstraňte ho. |
