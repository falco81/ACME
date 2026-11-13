# VMware vCenter 8.0 U2 - 9.1 - nastavení pro acme

acme vymění **certifikát machine SSL vCenteru** (rhttpproxy na 443 - vSphere Client, API) přes **vSphere Automation REST API**:

1. přečte verzi vCenteru (`GET /sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`, bez přihlášení) - **jinou verzi než 8.0 U2 - 9.1 odmítne dřív, než cokoli změní**;
2. `POST /api/session` (základní autentizace), `GET /api/vcenter/certificate-management/vcenter/tls` - je-li tam už stejný certifikát, nic nedělá;
3. přidá mezilehlé certifikáty a kořen mezi **důvěryhodné kořenové řetězce** (`POST .../vcenter/trusted-root-chains`);
4. `PUT /api/vcenter/certificate-management/vcenter/tls` s `cert` (koncový certifikát), `key` a `root_cert`.

**Od vCenteru 8.0 U2 se služby nerestartují** a otevřené relace zůstávají (KB 403973, VCF 9.1 Programming Guide) - stačí obnovit stránku v prohlížeči; acme kontroluje servírovaný certifikát hned. Na vCenteru 7.0 - 8.0 U1 použijte základní verzi (*VMware vCenter Server*), která na restart služeb počká.

## Pro který vCenter je tento návod

| Verze modulu | vCenter | Po změně |
|---|---|---|
| základní - *VMware vCenter Server* | 7.0 - 9.1 | čeká jako na restart (20 pokusů po 15 s) |
| **vCenter 8.0 U2 - 9.1** (`8.0.2`) | 8.0 U2, 8.0 U3, 9.0, 9.1 | bez restartu, kontrola hned (6 pokusů po 10 s); jen klíče RSA, jiné odmítne před odesláním |

Volání jsou v obou stejná; vCenter novější než 9.1 se použije s varováním. Ve **VCF 9** spravuje certifikáty vCenteru VCF Operations (*Fleet management → Certificates*): výměnou zde ho VCF ukáže jako *externally managed* - přidejte kořen i do úložiště důvěry SDDC Manageru (cíl `sddc_manager`).

## Nastavení vCenteru

1. Uživatel SSO: *Administration → Single Sign On → Users and Groups → Users → vsphere.local → Add*, např. `svc-certmgmt`. Nebo na appliance:

   ```sh
   /usr/lib/vmware-vmafd/bin/dir-cli user create --account svc-certmgmt --user-password '<heslo>' --first-name svc --last-name certmgmt --login administrator@vsphere.local
   ```

2. Role: *Administration → Access Control → Roles → New* `CertMgmt-Operator` s privilegii skupiny **Certificate Management** **Manage** a **Administer** (`CertificateManagement.Manage` pro důvěryhodné kořeny, `CertificateManagement.Administer` pro `PUT .../tls`).
3. *Administration → Access Control → Global Permissions → Add*: `svc-certmgmt@vsphere.local`, tato role, *Propagate to children*.
4. Vyzkoušejte: přihlášení i čtení certifikátu musí vrátit 200:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-certmgmt@vsphere.local:<heslo>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/certificate-management/vcenter/tls
   ```

Pokud vlastní role nestačí, použijte člena *Administrators* (nebo *CAAdmins*) domény `vsphere.local`.

## Certifikát

- **RSA**, 2048 - 8192 bitů (FIPS: 2048 nebo 3072) - ECDSA se pro machine SSL nepoužívá.
- SAN musí obsahovat **FQDN vCenteru (jeho PNID)**; žádný wildcard.
- Key usage Digital Signature, Key Encipherment; EKU prázdné nebo Server Authentication.
- Nikde v řetězci RSASSA-PSS (`SHA256withRSAandMGF1` odmítnou prechecky 9.0, KB 418126).

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **vCenter 8.0 U2 - 9.1** |
| Adresa / Port HTTPS | FQDN vCenteru, `443` |
| Uživatel / Heslo | `svc-certmgmt@vsphere.local` a jeho heslo |
| Ověřovat certifikát zařízení | zapnuto; dokud má vCenter certifikát VMCA, vložte kořen VMCA do *Certifikát CA* (z `https://<vcenter>/certs/download.zip`) |
| Kořenový certifikát CA (nasazení) | kořenový PEM (pro Let's Encrypt ISRG Root X1); prázdné: poslední certifikát řetězce |
| Přidat řetězec mezi důvěryhodné kořeny (nasazení) | zapnuto |

## Kontrola

*Vyzkoušet* se přihlásí, přečte certifikát a řekne verzi vCenteru. Po nasazení:

```sh
openssl s_client -connect vcenter.example.local:443 -servername vcenter.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Na appliance:

```sh
/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT --text | grep -E "Subject:|Not After"
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| `this vCenter runs 8.0.1` | Zvolte základní verzi cíle (počká na restart). |
| `the vCenter version cannot be read` | vCenter starší než 8.0 U1 nebo zablokované `/sdk`: acme pokračuje jako pro 8.0 U2 - pro starší vCenter zvolte základní verzi. |
| `400` AlreadyExists | Stejný thumbprint už tam je - acme to bere jako hotové. |
| `400` neplatný certifikát / algoritmus podpisu | Není RSA, chybí FQDN v SAN, nebo RSASSA-PSS (KB 418126). |
| `404` NotFound u `PUT .../tls` | vCenter chce klíč: acme ho posílá - zkontrolujte práva uživatele. |
| NSX, SRM, Horizon, Aria přestaly důvěřovat | Aktualizujte tam thumbprint/kořen vCenteru (KB 318946). |
