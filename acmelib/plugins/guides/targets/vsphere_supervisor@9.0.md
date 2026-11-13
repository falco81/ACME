# VMware vSphere Supervisor on vCenter 9.0 - setup for acme

Module version **vCenter 9.0** (`9.0`): acme replaces the certificate of the **Supervisor's Kubernetes API endpoint** with its own key through vCenter 9.0's API:

```text
POST  /api/session                                            (basic auth)
GET   /api/vcenter/namespace-management/clusters/<cluster>     there already?
PATCH /api/vcenter/namespace-management/clusters/<cluster>
      {"tls_endpoint_certificate": "<leaf, intermediates, root>",
       "tls_endpoint_private_key": "<key>"}
DELETE /api/session
```

`tls_endpoint_private_key` exists from API 9.0 (before it only a certificate for a CSR the Supervisor made). vCenter's version is read first (`/sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`): **another vCenter than 9.0.x is refused before anything changes**, the words name the version to choose. The default NSX ingress cannot be given a key this way on 9.0 - acme refuses that choice; use vCenter 9.1.

| Module version | vCenter | Calls |
|---|---|---|
| any version (detects it) | 9.0 - 9.1 | by the version |
| **vCenter 9.0** | 9.0.x | `clusters/<cluster>` - this guide |
| vCenter 9.1 and later 9.x | 9.1, 9.1.1 | `supervisors/<id>/certificates` |

## Set up vCenter

1. A user with **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*): *Administration → Access Control → Roles → New*, then *Global Permissions → Add* (or a permission on the cluster) for e.g. `svc-wcp-cert@vsphere.local`.
2. The **cluster's id** the Supervisor runs on (`domain-c8`): the vSphere Client's address of the cluster, or PowerCLI:

   ```powershell
   (Get-Cluster 'Cluster01').ExtensionData.MoRef.Value
   ```

3. Try the read the module makes:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<password>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/clusters/domain-c8
   ```

## The certificate

The Supervisor's FQDN(s) and virtual IP in the SAN, the whole chain (leaf → intermediates → root).

## Fill in acme

| acme field | What to put there |
|---|---|
| Version of the module | **vCenter 9.0** |
| Address / HTTPS port | vCenter's FQDN, `443` |
| User / Password | `svc-wcp-cert@vsphere.local` and its password |
| Supervisor | the cluster's id, `domain-c8` |
| API endpoint | the Supervisor's FQDN or VIP - where acme tests the certificate served |
| Which certificate (deploy) | the Kubernetes API endpoint |
| Root CA certificate (deploy) | the root PEM, when the chain does not end in it |

## Check it

```sh
echo | openssl s_client -connect supervisor.example.local:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

## Common problems

| Problem | Fix |
|---|---|
| `this vCenter runs 9.1.0 ... choose the version "vCenter 9.1 and later 9.x"` | vCenter was updated: change the module version (or take *any version*). |
| `the vCenter version cannot be read` | `/sdk` not reachable: acme goes on with 9.0's calls. |
| `vCenter has no Supervisor` | The cluster's id is wrong. |
| `403` | No `Namespaces.Manage`. |
