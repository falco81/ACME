# VMware vSphere Supervisor na vCenteru 9.0 - nastavení pro acme

Verze modulu **vCenter 9.0** (`9.0`): acme vymění certifikát **Kubernetes API endpointu Supervisoru** s vlastním klíčem přes API vCenteru 9.0:

```text
POST  /api/session                                            (základní autentizace)
GET   /api/vcenter/namespace-management/clusters/<cluster>     je už nasazený?
PATCH /api/vcenter/namespace-management/clusters/<cluster>
      {"tls_endpoint_certificate": "<koncový, mezilehlé, kořen>",
       "tls_endpoint_private_key": "<klíč>"}
DELETE /api/session
```

`tls_endpoint_private_key` existuje od API 9.0 (předtím jen certifikát k CSR, které vytvořil Supervisor). Nejdřív se přečte verze vCenteru (`/sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`): **jiný vCenter než 9.0.x se odmítne dřív, než se cokoli změní**, a hláška řekne, kterou verzi zvolit. Výchozímu NSX ingressu se tímto způsobem na 9.0 klíč dát nedá - acme tuto volbu odmítne; použijte vCenter 9.1.

| Verze modulu | vCenter | Volání |
|---|---|---|
| libovolná verze (zjistí ji) | 9.0 - 9.1 | podle verze |
| **vCenter 9.0** | 9.0.x | `clusters/<cluster>` - tento návod |
| vCenter 9.1 a novější 9.x | 9.1, 9.1.1 | `supervisors/<id>/certificates` |

## Nastavení vCenteru

1. Uživatel s **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*): *Administration → Access Control → Roles → New*, pak *Global Permissions → Add* (nebo oprávnění na clusteru) např. pro `svc-wcp-cert@vsphere.local`.
2. **ID clusteru**, na kterém Supervisor běží (`domain-c8`): v adrese clusteru ve vSphere Clientu, nebo PowerCLI:

   ```powershell
   (Get-Cluster 'Cluster01').ExtensionData.MoRef.Value
   ```

3. Vyzkoušejte čtení, které modul dělá:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<heslo>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/clusters/domain-c8
   ```

## Certifikát

FQDN Supervisoru a virtuální IP v SAN, celý řetězec (koncový → mezilehlé → kořen).

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **vCenter 9.0** |
| Adresa / Port HTTPS | FQDN vCenteru, `443` |
| Uživatel / Heslo | `svc-wcp-cert@vsphere.local` a jeho heslo |
| Supervisor | ID clusteru, `domain-c8` |
| API endpoint | FQDN nebo VIP Supervisoru |
| Který certifikát (nasazení) | Kubernetes API endpoint |
| Kořenový certifikát CA (nasazení) | kořenový PEM, když jím řetězec nekončí |

## Kontrola

```sh
echo | openssl s_client -connect supervisor.example.local:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| `this vCenter runs 9.1.0 ... choose the version "vCenter 9.1 and later 9.x"` | vCenter byl aktualizován: změňte verzi modulu (nebo zvolte *libovolná verze*). |
| `the vCenter version cannot be read` | `/sdk` není dosažitelné: acme pokračuje s voláními 9.0. |
| `vCenter has no Supervisor` | Špatné ID clusteru. |
| `403` | Chybí `Namespaces.Manage`. |
