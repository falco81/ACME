# VMware SDDC Manager (úložiště důvěry) - nastavení pro acme

acme přidá **certifikáty CA** svého certifikátu - mezilehlé a kořen - do **úložiště důvěry SDDC Manageru**, aby VMware Cloud Foundation dál důvěřovala komponentě (vCenter, NSX Manager, ESX), které acme certifikát dalo přímo cílem `vcenter`, `nsx_manager` nebo `esxi`. Samotný certifikát do SDDC Manageru nejde:

- `POST /v1/tokens` (`username`, `password`) → token typu bearer;
- `GET /v1/sddc-manager/trusted-certificates` - certifikát CA, který tam už je, se nepřidá znovu;
- `POST /v1/sddc-manager/trusted-certificates` s `certificate` (PEM) a `certificateUsageType` `TRUSTED_FOR_OUTBOUND`.

**Proč ne samotný certifikát:** SDDC Manager (VCF 5.2) ani VCF Operations (*Fleet management → Certificates*, VCF 9) nepřijmou soukromý klíč vytvořený jinde: instalují jen certifikáty podepsané k CSR, které samy vygenerovaly („leaf certificate doesn't match any CSR stored in the locker"). Certifikát vyměněný přímo na komponentě je podporovaný - VCF ho pak ukazuje jako *externally managed* - a musí být v tomto úložišti důvěry, „jinak UI hlásí chyby a workflowy selhávají".

## Pro kterou VCF je tento návod

VCF **5.2** a **9.0 - 9.1.1** - API v1 SDDC Manageru ve VCF 9 zůstává (stejná volání, jeden modul).

## Nastavení SDDC Manageru

1. Uživatel s rolí **ADMIN** v SDDC Manageru (*Administration → Single Sign On*, uživatel nebo skupina AD ze SSO vCenteru): matice rolí pro operace s certifikáty není zveřejněná; VIEWER jen čte. Např. `svc-vcf-certs@corp.local` ve skupině s rolí ADMIN.
2. Vyzkoušejte přihlášení:

   ```sh
   curl -s -X POST https://sddc-manager.example.local/v1/tokens -H "Content-Type: application/json" \
     -d '{"username": "svc-vcf-certs@corp.local", "password": "<heslo>"}'
   ```

3. **Po přidání certifikátu restartujte služby SDDC Manageru** (KB 316056) - acme to neumí (potřebuje root po `su -`), řekne to v úloze:

   ```sh
   ssh vcf@sddc-manager.example.local
   su -
   /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh
   ```

   Kořen se mění zřídka: když už CA důvěřuje, obnovy nic nepřidají a restart nepotřebují.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FQDN SDDC Manageru, `443` |
| Uživatel / Heslo | uživatel s rolí ADMIN a jeho heslo |
| Kořenový certifikát CA (nasazení) | kořen (pro Let's Encrypt ISRG Root X1); prázdné: poslední certifikát řetězce, je-li kořenem |
| I mezilehlé certifikáty (nasazení) | zapnuto |
| Důvěřovat pro (nasazení) | odchozí - SDDC Manager se připojuje ke komponentám |

Certifikát nasaďte na cíl SDDC Manageru i na cíl komponenty (např. `vcenter`) v nasazeních téhož certifikátu - důvěru nejdřív.

## Kontrola

*Vyzkoušet* se přihlásí a spočítá důvěryhodné certifikáty.

```sh
curl -s -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/sddc-manager/trusted-certificates
```

V UI: *Inventory → Workload Domains → doména → Certificates* - stav komponenty.

## Časté potíže

| Potíž | Řešení |
|---|---|
| `401` při přihlášení | Špatný uživatel nebo heslo; SDDC Manager musí uživatele znát. |
| `403` při přidání | Uživatel nemá roli ADMIN. |
| `nothing to add` | Řetězec nemá mezilehlé certifikáty a kořen chybí: vložte kořenový certifikát CA. |
| Workflowy po přidání dál selhávají | Služby nebyly restartovány (KB 316056). |
| VCF Operations ukazuje certifikát komponenty jako *External CA* | U certifikátu vyměněného na komponentě očekávané; automatická obnova pro něj zůstane vypnutá. |
