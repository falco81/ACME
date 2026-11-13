# VMware vSphere Supervisor (API endpoint) - nastavení pro acme

acme vymění certifikát **Kubernetes API endpointu Supervisoru** - nginx na virtuální IP, který vidí `kubectl vsphere login`, VCF Consumption CLI i prohlížeče - nebo jeho **výchozího NSX ingressu**, s vlastním klíčem acme, přes **vSphere Automation API vCenteru**:

1. přečte verzi vCenteru (`GET /sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`, bez přihlášení);
2. `POST /api/session` (základní autentizace);
3. **vCenter 9.1 a novější**: `PATCH /api/vcenter/namespace-management/supervisors/<id>/certificates` s `endpoint` (`KUBERNETES_API_SERVER` nebo `DEFAULT_NSX_INGRESS`), `tls_endpoint_certificate` (koncový → mezilehlé → kořen) a `tls_endpoint_private_key`;
   **vCenter 9.0**: `PATCH /api/vcenter/namespace-management/clusters/<cluster>` s `tls_endpoint_certificate` a `tls_endpoint_private_key` (jen API endpoint);
4. `DELETE /api/session`.

Je-li certifikát už nasazený (nejdřív se přečte přes `GET`), nic nedělá. Tokeny v kubeconfig zůstávají; klienti, kteří nové CA nedůvěřují, se musí přihlásit znovu.

## Pro který vCenter je tento návod

| Verze modulu | vCenter | Volání |
|---|---|---|
| **libovolná verze (zjistí ji)** | 9.0 - 9.1 | podle verze, kterou vCenter řekne; neznámá: volání 9.1, pak 9.0 |
| vCenter 9.0 | 9.0.x | `clusters/<cluster>` |
| vCenter 9.1 a novější 9.x | 9.1, 9.1.1 | `supervisors/<id>/certificates` |

**Před 9.0** (vSphere 8.0 U3) API bere jen certifikát k CSR, které vytvořil Supervisor - žádný klíč vytvořený jinde: acme to odmítne dřív, než cokoli změní; vyměňte ho ve vSphere Clientu (*Supervisor Management → Supervisors → Configure → Certificates → Generate CSR / Replace Certificate*).

## Nastavení vCenteru

1. Uživatel s **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*) na vCenteru nebo na clusteru Supervisoru (ke čtení `System.Read`, ten má každá role): *Administration → Access Control → Roles → New* `acme Supervisor certificates` s tímto privilegiem; *Global Permissions → Add* (nebo na clusteru) pro `svc-wcp-cert@vsphere.local`.
2. ID Supervisoru (`domain-c8` ...): v adrese vSphere Clientu v *Supervisor Management → Supervisors*, nebo

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<heslo>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/supervisors/summaries
   ```

   Na vCenteru 9.0 je to ID clusteru, na kterém Supervisor běží.
3. Supervisor ve stavu **Running**, všechny uzly Ready, NTP synchronizované.
4. Přidali jste control plane FQDN (`--master-dns-name`)? Certifikát se sám znovu nevytvoří - nová jména musí být v certifikátu acme.

## Certifikát

- CN/SAN: FQDN Supervisoru a jeho **virtuální IP** (IP v SAN - zvolte CA, která ji vydá, nebo používejte jen FQDN a připojujte se přes něj).
- Celý řetězec, koncový první, kořen poslední (potřebuje ho poskytovatel identit).
- Certifikát NSX ingressu (`DEFAULT_NSX_INGRESS`, vCenter 9.1): jména ingressu - vCenter je nedoplní.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **libovolná verze (zjistí ji)** - nebo ta pro váš vCenter |
| Adresa / Port HTTPS | FQDN vCenteru, `443` |
| Uživatel / Heslo | `svc-wcp-cert@vsphere.local` a jeho heslo |
| Supervisor | `domain-c8` (9.1: ID Supervisoru; 9.0: ID jeho clusteru) |
| API endpoint | `supervisor.example.local` (nebo VIP) - kde acme po nasazení testuje certifikát API endpointu; certifikát NSX ingressu se tam netestuje (test se pro něj nevytvoří - přidejte si test jména ingressu v Certifikáty → Testy) |
| Který certifikát (nasazení) | Kubernetes API endpoint; výchozí NSX ingress na vCenteru 9.1 |
| Kořenový certifikát CA (nasazení) | kořenový PEM, když jím řetězec nekončí |

## Kontrola

*Vyzkoušet* se přihlásí a přečte Supervisor (řekne, která volání odpověděla). Po nasazení:

```sh
echo | openssl s_client -connect supervisor.example.local:443 -servername supervisor.example.local 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "vmware-api-session-id: $TOKEN" "https://vcenter.example.local/api/vcenter/namespace-management/supervisors/domain-c8/certificates"
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| `this vCenter runs 8.0.3` | Před 9.0 API klíč nebere: CSR a Replace ve vSphere Clientu. |
| `vCenter has no Supervisor "domain-c8"` | ID: 9.1 chce ID Supervisoru, 9.0 ID jeho clusteru. |
| `400` u PATCH | V SAN chybí FQDN/VIP, řetězec je neúplný, nebo tento vCenter nezná jméno endpointu (`KUBERNETES_API_SERVER` / `DEFAULT_NSX_INGRESS`). |
| `403` | Uživatel nemá `Namespaces.Manage`. |
| `kubectl vsphere login` certifikát odmítá | Stanice CA nedůvěřuje: nainstalujte tam její kořen. |
