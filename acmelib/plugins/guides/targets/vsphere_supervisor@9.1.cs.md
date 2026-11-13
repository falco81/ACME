# VMware vSphere Supervisor na vCenteru 9.1 - nastavení pro acme

Verze modulu **vCenter 9.1 a novější 9.x** (`9.1`): acme vymění certifikát **Kubernetes API endpointu Supervisoru** nebo jeho **výchozího NSX ingressu** s vlastním klíčem přes Supervisors API vCenteru 9.1:

```text
POST  /api/session                                                       (základní autentizace)
GET   /api/vcenter/namespace-management/supervisors/<id>/certificates    je už nasazený?
PATCH /api/vcenter/namespace-management/supervisors/<id>/certificates
      {"endpoint": "KUBERNETES_API_SERVER" | "DEFAULT_NSX_INGRESS",
       "tls_endpoint_certificate": "<koncový, mezilehlé, kořen>",
       "tls_endpoint_private_key": "<klíč>"}
DELETE /api/session
```

(Starší `PATCH .../clusters/<cluster>` s `tls_endpoint_certificate` je ve 9.1 zastaralý.) Nejdřív se přečte verze vCenteru: **vCenter starší než 9.1 se odmítne dřív, než se cokoli změní**; novější hlavní verze než 9.x pokračuje s varováním.

| Verze modulu | vCenter | Volání |
|---|---|---|
| jakákoli verze (zjistí ji) | 9.0 - 9.1 | podle verze |
| vCenter 9.0 | 9.0.x | `clusters/<cluster>` |
| **vCenter 9.1 a novější 9.x** | 9.1, 9.1.1 | `supervisors/<id>/certificates` - tento návod |

*Nejisté*: referenční stránka se jmény endpointů přečtena nebyla - `KUBERNETES_API_SERVER` a `DEFAULT_NSX_INGRESS` jsou jména typů CSR; `400`, které jmenuje toto pole, znamená jiné jméno.

## Nastavení vCenteru

1. Uživatel s **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*) - *Administration → Access Control → Roles → New*, pak *Global Permissions → Add* např. pro `svc-wcp-cert@vsphere.local`.
2. **ID Supervisoru**:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<heslo>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/supervisors/summaries
   ```

3. Výchozí NSX ingress jen u Supervisoru s NSX; jeho jména vCenter nedoplní - musí být v certifikátu acme.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **vCenter 9.1 a novější 9.x** |
| Adresa / Port HTTPS | FQDN vCenteru, `443` |
| Uživatel / Heslo | `svc-wcp-cert@vsphere.local` a jeho heslo |
| Supervisor | jeho ID, např. `domain-c8` |
| API endpoint | FQDN nebo VIP Supervisoru - kde se testuje certifikát API endpointu; certifikát ingressu se tam netestuje (test se pro něj nevytvoří - přidejte si test jména ingressu v Certifikáty → Testy) |
| Který certifikát (nasazení) | Kubernetes API endpoint, nebo výchozí NSX ingress - každý jedním nasazením |
| Kořenový certifikát CA (nasazení) | kořenový PEM, když jím řetězec nekončí |

## Kontrola

```sh
echo | openssl s_client -connect supervisor.example.local:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "vmware-api-session-id: $TOKEN" "https://vcenter.example.local/api/vcenter/namespace-management/supervisors/domain-c8/certificates"
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| `this vCenter runs 9.0.2 ... choose the version "vCenter 9.0"` | Změňte verzi modulu (nebo zvolte *jakákoli verze*). |
| `vCenter has no Supervisor` | Použijte ID Supervisoru ze `supervisors/summaries`. |
| `400` kvůli `endpoint` | Jméno endpointu se v tomto buildu liší - dejte nám vědět; mezitím použijte vSphere Client. |
| `403` | Chybí `Namespaces.Manage`. |
