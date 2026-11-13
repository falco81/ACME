# VMware vSphere Supervisor (API endpoint) - setup for acme

acme replaces the certificate of a **Supervisor's Kubernetes API endpoint** - the virtual IP's nginx that `kubectl vsphere login`, the VCF Consumption CLI and browsers see - or of its **default NSX ingress**, with acme's own key, through **vCenter's vSphere Automation API**:

1. reads vCenter's version (`GET /sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`, no sign-in);
2. `POST /api/session` (basic auth);
3. **vCenter 9.1 and later**: `PATCH /api/vcenter/namespace-management/supervisors/<id>/certificates` with `endpoint` (`KUBERNETES_API_SERVER` or `DEFAULT_NSX_INGRESS`), `tls_endpoint_certificate` (leaf → intermediates → root) and `tls_endpoint_private_key`;
   **vCenter 9.0**: `PATCH /api/vcenter/namespace-management/clusters/<cluster>` with `tls_endpoint_certificate` and `tls_endpoint_private_key` (the API endpoint only);
4. `DELETE /api/session`.

The certificate is there already (read first with `GET`): nothing done. Kubeconfig tokens stay; clients that do not trust the new CA must log in again.

## Which vCenter this guide is for

| Module version | vCenter | Calls |
|---|---|---|
| **any version (detects it)** | 9.0 - 9.1 | by the version vCenter says; not known: 9.1's, then 9.0's |
| vCenter 9.0 | 9.0.x | `clusters/<cluster>` |
| vCenter 9.1 and later 9.x | 9.1, 9.1.1 | `supervisors/<id>/certificates` |

**Before 9.0** (vSphere 8.0 U3) the API takes only a certificate for a CSR the Supervisor made - no key made elsewhere: acme refuses it before changing anything; replace it in the vSphere Client (*Supervisor Management → Supervisors → Configure → Certificates → Generate CSR / Replace Certificate*).

## Set up vCenter

1. A user with **`Namespaces.Manage`** (*Namespaces → Modify cluster-wide configuration*) on the vCenter or the Supervisor's cluster (reading needs `System.Read`, in every role): *Administration → Access Control → Roles → New* `acme Supervisor certificates` with that privilege; *Global Permissions → Add* (or on the cluster) for `svc-wcp-cert@vsphere.local`.
2. The Supervisor's id (`domain-c8` ...): in the vSphere Client's address of *Supervisor Management → Supervisors*, or

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-wcp-cert@vsphere.local:<password>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/namespace-management/supervisors/summaries
   ```

   On vCenter 9.0 it is the id of the cluster the Supervisor runs on.
3. The Supervisor **Running**, every node Ready, NTP in sync.
4. Added FQDNs to the control plane (`--master-dns-name`)? The certificate is not made again by itself - the new names must be in acme's certificate.

## The certificate

- CN/SAN: the Supervisor's FQDN(s) and its **virtual IP** (an IP SAN - choose a CA that issues one, or use the FQDN only and connect by it).
- The whole chain, leaf first, root last (an identity provider needs it).
- The NSX ingress certificate (`DEFAULT_NSX_INGRESS`, vCenter 9.1): the ingress's names - not filled in by vCenter.

## Fill in acme

| acme field | What to put there |
|---|---|
| Version of the module | **any version (detects it)** - or the one for your vCenter |
| Address / HTTPS port | vCenter's FQDN, `443` |
| User / Password | `svc-wcp-cert@vsphere.local` and its password |
| Supervisor | `domain-c8` (9.1: the Supervisor's id; 9.0: its cluster's id) |
| API endpoint | `supervisor.example.local` (or the VIP) - where acme tests the API endpoint's certificate after a deployment; the NSX ingress's certificate is not tested there (no test is made for it - add one for the ingress's name in Certificates → Tests) |
| Which certificate (deploy) | the Kubernetes API endpoint; the default NSX ingress on vCenter 9.1 |
| Root CA certificate (deploy) | the root PEM, when the chain does not end in it |

## Check it

*Try* signs in and reads the Supervisor (it says which calls answered). After a deployment:

```sh
echo | openssl s_client -connect supervisor.example.local:443 -servername supervisor.example.local 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "vmware-api-session-id: $TOKEN" "https://vcenter.example.local/api/vcenter/namespace-management/supervisors/domain-c8/certificates"
```

## Common problems

| Problem | Fix |
|---|---|
| `this vCenter runs 8.0.3` | The API takes no key before 9.0: CSR and Replace in the vSphere Client. |
| `vCenter has no Supervisor "domain-c8"` | The id: 9.1 wants the Supervisor's, 9.0 its cluster's. |
| `400` on the PATCH | The SAN lacks the FQDN/VIP, the chain is incomplete, or the endpoint name is not one this vCenter knows (`KUBERNETES_API_SERVER` / `DEFAULT_NSX_INGRESS`). |
| `403` | The user lacks `Namespaces.Manage`. |
| `kubectl vsphere login` refuses the certificate | The workstation does not trust the CA: install its root there. |
