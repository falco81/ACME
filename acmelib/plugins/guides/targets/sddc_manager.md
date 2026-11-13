# VMware SDDC Manager (trust store) - setup for acme

acme adds the **CA certificates** of its certificate - the intermediates and the root - to **SDDC Manager's trust store**, so VMware Cloud Foundation keeps trusting a component (vCenter, NSX Manager, ESX) acme gave the certificate to directly with the `vcenter`, `nsx_manager` or `esxi` target. The certificate itself does not go to SDDC Manager:

- `POST /v1/tokens` (`username`, `password`) → a bearer token;
- `GET /v1/sddc-manager/trusted-certificates` - a CA certificate there already is not added again;
- `POST /v1/sddc-manager/trusted-certificates` with `certificate` (PEM) and `certificateUsageType` `TRUSTED_FOR_OUTBOUND`.

**Why not the certificate itself:** neither SDDC Manager (VCF 5.2) nor VCF Operations (*Fleet management → Certificates*, VCF 9) takes a private key made elsewhere: they install only certificates signed for a CSR they generated ("leaf certificate doesn't match any CSR stored in the locker"). A certificate replaced on the component is supported - VCF then shows it as *externally managed* - and must be in this trust store, "otherwise the UI shows errors and workflows fail".

## Which VCF this guide is for

VCF **5.2** and **9.0 - 9.1.1** - the SDDC Manager API v1 stays in VCF 9 (the same calls, one module).

## Set up SDDC Manager

1. A user with the role **ADMIN** in SDDC Manager (*Administration → Single Sign On*, an AD user or group from vCenter SSO): the role matrix for certificate operations is not published; VIEWER is read-only. E.g. `svc-vcf-certs@corp.local` in a group with ADMIN.
2. Try the sign-in:

   ```sh
   curl -s -X POST https://sddc-manager.example.local/v1/tokens -H "Content-Type: application/json" \
     -d '{"username": "svc-vcf-certs@corp.local", "password": "<password>"}'
   ```

3. **After acme added a certificate, restart SDDC Manager's services** (KB 316056) - acme cannot (it needs root after `su -`), it says so in the job:

   ```sh
   ssh vcf@sddc-manager.example.local
   su -
   /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh
   ```

   The root changes rarely: once the CA is trusted, renewals add nothing and need no restart.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | SDDC Manager's FQDN, `443` |
| User / Password | the ADMIN user and its password |
| Root CA certificate (deploy) | the root (ISRG Root X1 for Let's Encrypt); empty: the last certificate of the chain when it is a root |
| The intermediates too (deploy) | on |
| Trusted for (deploy) | outbound - SDDC Manager connecting to the components |

Deploy the certificate to SDDC Manager's target and to the component's target (e.g. `vcenter`) in the same certificate's deployments - the trust first.

## Check it

*Try* signs in and counts the trusted certificates.

```sh
curl -s -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/sddc-manager/trusted-certificates
```

In the UI: *Inventory → Workload Domains → the domain → Certificates* - the component's status.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password; the user must be known to SDDC Manager. |
| `403` on adding | The user is not an ADMIN. |
| `nothing to add` | The chain has no intermediates and no root: paste the root CA certificate. |
| Workflows still fail after adding | The services were not restarted (KB 316056). |
| VCF Operations shows the component's certificate as *External CA* | Expected for a certificate replaced on the component; auto-renewal stays off for it. |
