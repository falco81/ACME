# VMware ESXi 8.0 U3 - 9.1 přes vCenter - nastavení pro acme

acme vymění **certifikát machine SSL hostitele** (port 443 - hostd/rhttpproxy, ten vidí vCenter i Host Client) **přes vSphere Web Services API vCenteru** (VI JSON API) - bez SSH, bez režimu údržby, bez restartu:

1. `GET /sdk/vim25/<release>/ServiceInstance/ServiceInstance/content` (bez přihlášení), `POST .../SessionManager/<id>/Login`;
2. přečte hostitele (`HostSystem/<host-id>/summary`: jeho verzi ESX) - **ESXi starší než 8.0 U3 odmítne dřív, než cokoli změní**;
3. přidá mezilehlé certifikáty a kořen mezi **důvěryhodné kořeny vCenteru** (`POST /api/vcenter/certificate-management/vcenter/trusted-root-chains`) - bez nich vCenter hostitele odpojí nebo vrátí certifikát VMCA;
4. `HostCertificateManager.ProvisionServerPrivateKey` (klíč), `InstallServerCertificate` (certifikát), `NotifyAffectedServices` (otevřená spojení dožijí se starým certifikátem, nová dostanou nový).

## Pro které ESXi je tento návod

| Verze modulu | ESXi | Jak |
|---|---|---|
| základní - *VMware ESXi host (SSH)* | libovolné | `rui.crt` / `rui.key` přes SSH, restart hostd a vpxa, uložení `/sbin/auto-backup.sh` |
| **ESXi 8.0 U3 - 9.1 (přes vCenter)** (`8.0.3`) | 8.0 U3, 9.0, 9.1 | tento návod - `ProvisionServerPrivateKey` a `NotifyAffectedServices` jsou od API 8.0.3.0 |

Novější ESX než 9.1 se použije s varováním. Samostatný hostitel (bez vCenteru) - použijte základní verzi přes SSH.

## Nastavení vCenteru

### 1. Režim certifikátů `custom`

vCenter nesmí certifikát hostitele obnovovat přes VMCA a přepsat ten od acme: *vSphere Client → vCenter → Configure → Settings → Advanced Settings → Edit Settings*, filtr `vpxd.certmgmt`, nastavte **`vpxd.certmgmt.mode` = `custom`** (rozlišuje velikost písmen), *Save*, a na vCenteru:

```sh
service-control --restart vpxd
```

### 2. Uživatel s nejmenšími právy

Privilegium je **Certificates → Manage Certificates** (`Certificate.Manage`) na objektu vCenter s propagací. acme navíc přidává řetězec mezi důvěryhodné kořeny: k tomu je třeba **Certificate Management → Manage** a **Administer** (`CertificateManagement.Manage`, `CertificateManagement.Administer`) - nebo volbu *Přidat řetězec mezi důvěryhodné kořeny vCenteru* vypněte a kořen přidejte jednou sami.

PowerCLI (uživatele SSO `svc-esxcert` nejdřív založte: *Administration → Single Sign On → Users and Groups → Add*):

```powershell
Connect-VIServer -Server vcenter.example.local -User administrator@vsphere.local
$priv = Get-VIPrivilege -Id 'Certificate.Manage','CertificateManagement.Manage','CertificateManagement.Administer'
$role = New-VIRole -Name 'acme ESX certificates' -Privilege $priv
New-VIPermission -Entity (Get-Folder -NoRecursion) -Principal 'VSPHERE.LOCAL\svc-esxcert' -Role $role -Propagate:$true
```

### 3. ID hostitele

acme hostitele označuje ID spravovaného objektu (`host-12`): je v adrese vSphere Clientu, když je hostitel vybraný, nebo:

```powershell
(Get-VMHost esx01.example.local).ExtensionData.MoRef.Value
```

### 4. Kořenový certifikát CA

Let's Encrypt a většina veřejných CA kořen neposílá: stáhněte ho (pro Let's Encrypt ISRG Root X1) a vložte do *Kořenový certifikát CA*. Nebo ho jednou přidejte sami:

```sh
/usr/lib/vmware-vmafd/bin/dir-cli trustedcert publish --cert /tmp/root.pem --login administrator@vsphere.local
```

## Certifikát

- **Jen RSA**, 2048 - 8192 bitů (jiný klíč acme odmítne dřív, než cokoli pošle); při FIPS 2048 nebo 3072.
- **FQDN hostitele v SAN** - jméno, pod kterým je ve vCenteru; žádný wildcard.
- Key usage Digital Signature a Key Encipherment; v řetězci žádné SHA-1 ani RSASSA-PSS.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **ESXi 8.0 U3 - 9.1 (přes vCenter)** |
| Adresa vCenteru / Port HTTPS | FQDN vCenteru, `443` |
| Uživatel / Heslo | `svc-esxcert@vsphere.local` a jeho heslo |
| Hostitel ESX (ID spravovaného objektu) | `host-12` |
| Jméno hostitele ESX | `esx01.example.local` - kde acme kontroluje servírovaný certifikát; prázdné: jméno, které má vCenter |
| Vydání API (pokročilé) | `8.0.3.0` (vCenter ho poskytuje od 8.0 U3, i 9.x) |
| Kořenový certifikát CA (nasazení) | kořenový PEM, když jím řetězec nekončí |
| Přidat řetězec mezi důvěryhodné kořeny vCenteru (nasazení) | zapnuto |
| Oznámit změnu službám hostitele (nasazení, pokročilé) | zapnuto |

## Kontrola

*Vyzkoušet* se přihlásí, přečte verzi hostitele a jeho správce certifikátů. Po nasazení:

```sh
openssl s_client -connect esx01.example.local:443 -servername esx01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Ve vSphere Clientu: *hostitel → Configure → System → Certificate*.

## Časté potíže

| Potíž | Řešení |
|---|---|
| `the host runs VMware ESXi 8.0.2` | Starší než 8.0 U3: zvolte základní verzi cíle (SSH). |
| `500` / HostConfigFault při instalaci | Certifikát nesedí ke klíči nebo je odmítnut (SAN, algoritmus). acme posílá klíč jako první; ověřte, že SAN obsahuje FQDN hostitele. |
| Hostitel se po změně odpojí | Kořen/mezilehlé nejsou v TRUSTED_ROOTS vCenteru: vyplňte *Kořenový certifikát CA* a nechte volbu řetězce zapnutou. |
| vCenter vrátí certifikát VMCA (KB 454050) | `vpxd.certmgmt.mode` není `custom`. |
| Úloha prošla, ale servíruje se starý certifikát | Hostitele ve vCenteru odpojte (Disconnect) a znovu připojte (Connect) (KB 410036). |
| `404` na `/sdk/vim25/8.0.3.0/...` | vCenter je starší než 8.0 U3 - aktualizujte ho, nebo použijte základní verzi. |
