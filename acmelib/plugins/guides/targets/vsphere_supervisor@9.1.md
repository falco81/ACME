# VMware vSphere Supervisor on vCenter 9.1 - setup for acme

Module version **vCenter 9.1 and later 9.x** (`9.1`): acme replaces the certificate of the **Supervisor's Kubernetes API endpoint** or of its **default NSX ingress** with its own key through the Supervisors API of vCenter 9.1:

```text
POST  /api/session                                                       (basic auth)
GET   /api/vcenter/namespace-management/supervisors/<id>/certificates    there already?
PATCH /api/vcenter/namespace-management/supervisors/<id>/certificates
      {"endpoint": "KUBERNETES_API_SERVER" | "DEFAULT_NSX_INGRESS",
       "tls_endpoint_certificate": "<leaf, intermediates, root>",
       "tls_endpoint_private_key": "<key>"}
DELETE /api/session
```

(The older `PATCH .../clusters/<cluster>` with `tls_endpoint_certificate` is deprecated in 9.1.) vCenter's version is read first: **a vCenter older than 9.1 is refused before anything changes**; a newer major than 9.x goes on with a warning.

| Module version | vCenter | Calls |
|---|---|---|
| any version (detects it) | 9.0 - 9.1 | by the version |
| vCenter 9.0 | 9.0.x | `clusters/<cluster>` |
| **vCenter 9.1 and later 9.x** | 9.1, 9.1.1 | `supervisors/<id>/certificates` - this guide |

*Uncertain*: the reference page of the endpoint names was not read - `KUBERNETES_API_SERVER` and `DEFAULT_NSX_INGRESS` are those of the CSR types; a `400` naming the field means another name.

## Set up vCenter

1. A user with **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*) - *Administration → Access Control → Roles → New*, then *Global Permissions → Add* for e.g. `svc-wcp-cert@vsphere.local`.
2. The **Supervisor's id**:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<password>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/supervisors/summaries
   ```

3. The default NSX ingress only with a Supervisor on NSX; its names are not filled in by vCenter - they must be in acme's certificate.

## Fill in acme

| acme field | What to put there |
|---|---|
| Version of the module | **vCenter 9.1 and later 9.x** |
| Address / HTTPS port | vCenter's FQDN, `443` |
| User / Password | `svc-wcp-cert@vsphere.local` and its password |
| Supervisor | its id, e.g. `domain-c8` |
| API endpoint | the Supervisor's FQDN or VIP - where the API endpoint's certificate is tested; the ingress's certificate is not tested there (no test is made for it - add one for the ingress's name in Certificates → Tests) |
| Which certificate (deploy) | the Kubernetes API endpoint, or the default NSX ingress - one deployment each |
| Root CA certificate (deploy) | the root PEM, when the chain does not end in it |

## Check it

```sh
echo | openssl s_client -connect supervisor.example.local:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "vmware-api-session-id: $TOKEN" "https://vcenter.example.local/api/vcenter/namespace-management/supervisors/domain-c8/certificates"
```

## Common problems

| Problem | Fix |
|---|---|
| `this vCenter runs 9.0.2 ... choose the version "vCenter 9.0"` | Change the module version (or take *any version*). |
| `vCenter has no Supervisor` | Use the Supervisor's id from `supervisors/summaries`. |
| `400` about `endpoint` | The endpoint name differs on this build - tell us; meanwhile use the vSphere Client. |
| `403` | No `Namespaces.Manage`. |
