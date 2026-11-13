# VMware NSX Manager (vlastní certifikát) - nastavení pro acme

acme dá certifikát **samotnému NSX Manageru** - UI/API uzlů manageru a virtuální IP clusteru - přes **NSX Manager API** (MP API, základní autentizace HTTP). Pro virtuální servery load balanceru použijte druhý cíl, *VMware NSX load balancer (Policy API)* (`nsx`).

1. `GET /api/v1/trust-management/certificates` - je už importovaný (stejné jméno)? pak znovu ne;
2. `POST /api/v1/trust-management/certificates?action=import` s `display_name` (`acme-<jméno>-<datum>-<sériové číslo>`), `pem_encoded` (koncový → mezilehlé → kořen, bez prázdných řádků) a `private_key` - certifikát platformy, **ne** servisní certifikát;
3. `GET .../certificates/<id>?action=validate&usage=SERVER` - cokoli jiného než `"status": "OK"` ho zastaví dřív, než se použije;
4. `POST .../certificates/<id>?action=apply_certificate&service_type=API&node_id=<uuid>` pro každý uvedený uzel, pak `...&service_type=MGMT_CLUSTER` pro virtuální IP;
5. starší certifikáty acme nad *ponechat* smaže - jen ty, jejichž `used_by` je prázdné.

Použití certifikátu restartuje službu HTTPS uzlu (desítky sekund; stránku v prohlížeči je třeba obnovit). acme jde jeden po druhém a zkusí to znovu, dokud se webová služba uzlu nevrátí.

## Pro které NSX je tento návod

NSX **4.2.x a 9.0 / 9.1** (VCF 9) - stejná volání (jeden modul). Od 4.2 je certifikát API uzlů a VIP standardně jeden sdílený: dejte ho oběma (SAN pak musí obsahovat VIP i každý uzel). Ve **VCF 9** spravuje certifikáty NSX VCF Operations (*Fleet management → Certificates → VCF Instances*): certifikát vyměněný zde se ukáže jako externě spravovaný a kořen musí být v úložišti důvěry SDDC Manageru (cíl `sddc_manager`).

## Nastavení NSX

1. Uživatel s právem spravovat certifikáty. Matice RBAC dává plný přístup k *System → Certificates* rolím **Enterprise Admin** a **Security Admin** (`security_engineer`); dokumentace pro použití certifikátu uvádí „admin privileges" - zkuste Security Admin, jinak Enterprise Admin. Lokální uživatel (NSX 4.1.1+):

   ```sh
   curl -k -u 'admin:<heslo>' -X POST "https://nsx-mgr01.example.local/api/v1/node/users?action=create_user" \
     -H "Content-Type: application/json" \
     -d '{"username": "svc-acme", "full_name": "acme certificates", "password": "<silné heslo>", "password_change_frequency": 90}'
   curl -k -u 'admin:<heslo>' -X POST "https://nsx-mgr01.example.local/api/v1/aaa/role-bindings" \
     -H "Content-Type: application/json" \
     -d '{"name": "svc-acme", "type": "local_user", "roles_for_paths": [{"path": "/", "roles": [{"role": "security_engineer"}]}]}'
   ```

   Uživatel nebo skupina z LDAP: *System → User Management → User Role Assignment → Add → Role Assignment for LDAP*, role *Security Admin*. Ve VCF 9 se na lokální účty uplatní politika hesel z VCF Operations.

2. Pro virtuální IP: VIP musí být nastavená (*System → Appliances → Set Virtual IP*) - bez ní NSX certifikát od CA na `MGMT_CLUSTER` odmítne.
3. UUID uzlů: *System → Appliances → NSX Manager → View Details*, nebo na uzlu jako `admin`:

   ```text
   get cluster status
   ```

4. Nasměrujte acme na **vlastní adresu uzlu**, ne na VIP (VIP se během výměny může přesunout).

## Certifikát

- CN/SAN: FQDN (a IP) VIP **a** každého uzlu, když je sdílený; Basic Constraints `CA:FALSE`.
- RSA 2048 a více (bere i EC); každý certifikát řetězce s podporovaným podpisem (žádné SHA-1, KB 380830).
- Soukromý klíč jde s ním (KB 400892).

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | uzel manageru, např. `nsx-mgr01.example.local`, `443` |
| Uživatel / Heslo | `svc-acme` (nebo `admin`) a jeho heslo |
| Virtuální IP clusteru (MGMT_CLUSTER) (nasazení) | zapnuto, aby certifikát dostala VIP |
| Uzly manageru (API) (nasazení) | jedno UUID uzlu na řádek - uzly, jejichž vlastní UI/API ho dostane |
| Kořenový certifikát CA (nasazení, pokročilé) | kořen, když jím řetězec nekončí |
| Kolik předchozích verzí ponechat (pokročilé) | `1` - starší certifikáty acme, které se ještě používají, se nikdy nesmažou |
| Zkontrolovat, co se servíruje | `nsx.example.local:443` (VIP) a uzly |

## Kontrola

*Vyzkoušet* vypíše počet certifikátů. Po nasazení:

```sh
for n in nsx-mgr01 nsx-mgr02 nsx-mgr03; do echo | openssl s_client -connect $n.example.local:443 2>/dev/null | openssl x509 -noout -subject -enddate; done
```

Na uzlu (NSX CLI): `get certificate api` a `get certificate cluster`; v UI *System → Certificates* (sloupec *Used By*).

## Časté potíže

| Potíž | Řešení |
|---|---|
| validace hlásí, že řetězec neověří (KB 415779) | Vyplňte *Kořenový certifikát CA*, nebo kořen naimportujte v NSX jako certifikát CA. |
| „Certificate data is missing the private key" (KB 400892) | Certifikát importovaný bez klíče - acme ho posílá vždy; ručně vytvořený se stejným jménem smažte. |
| V UI chybí *Apply Certificate* (KB 416689) | Byl importován jako servisní certifikát (Policy API) - import acme přes MP API jím není. |
| `403` při použití | Security Admin na této verzi nestačí: použijte Enterprise Admin. |
| VIP odmítnuta | Cluster nemá nastavenou virtuální IP. |
| Federace: GM ztratí LM | Aktualizujte thumbprint Local Manageru na Global Manageru (*System → Location Manager*). |
| VCF: „Private key does not match" ve VCF Operations (KB 449554) | VCF očekává jeden certifikát na komponentu - po změně spusťte inventory sync. |
