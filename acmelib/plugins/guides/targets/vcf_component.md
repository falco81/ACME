# VMware Cloud Foundation component through SDDC Manager - setup for acme

SDDC Manager takes **only a certificate signed for a CSR it made itself** - its certificate
workflow pairs every certificate with a CSR in its locker ("leaf certificate doesn't match any
CSR stored in the locker"); no private key made elsewhere can be imported. So **VCF makes the
key**: at every issue and renewal acme has SDDC Manager make a new key and CSR for the
component (`PUT /v1/domains/{id}/csrs`), reads it (`GET /v1/domains/{id}/csrs`), has it signed
by the certificate's source and right away has SDDC Manager validate and install the signed
certificate with its chain (`PUT /v1/domains/{id}/resource-certificates/validations`, then
`PUT /v1/domains/{id}/resource-certificates`). SDDC Manager applies it on the component and
restarts its services (it snapshots the component first and deletes the snapshot after). The
key never leaves VCF; acme holds none.

**Versions:** this version is for the **SDDC Manager API v1** - VCF **5.2.x**, and VCF 9.0 -
9.1.1 where the SDDC Manager API is still there. For VCF **9.1 / 9.1.1** through VCF
Operations (Fleet management → Certificates) choose the version **9.1** of this target.
**One component a target**: a vCenter, an NSX Manager (the VIP and the nodes in the SAN), SDDC
Manager itself, an Aria / VCF management component. VCF 5.2 does not manage ESXi certificates.
(The kind *VMware SDDC Manager (trust store)* is something else: it only adds CA certificates
to SDDC Manager's trust store.)

## What you need

- From acme to SDDC Manager: **TCP 443**; and to the component on 443 for the test of what is
  served.
- An SDDC Manager user with the role **ADMIN** (or **OPERATOR** - VIEWER is read-only; the
  exact role matrix is not published).
- A source that signs a CSR made elsewhere - an ACME CA (DNS-01 for the component's FQDN), acme's
  own authority, a commercial CA. **RSA** keys only (2048, 3072, 4096). No wildcard.
- The **root CA certificate** of the source: SDDC Manager wants the chain up to the root.
- A maintenance window: a vCenter's services restart (minutes); do not run other SDDC Manager
  workflows at the same time.
- The certificate must not be expired yet - VCF cannot replace an expired one (KB 445742).

## Set up SDDC Manager

1. A service account from vCenter SSO (Active Directory) with the role ADMIN - in the SDDC
   Manager UI *Administration → Single Sign On → + User or Group*, or over the API:

   ```sh
   TOKEN=$(curl -sk -X POST https://sddc-manager.example.local/v1/tokens -H 'Content-Type: application/json' \
     -d '{"username":"administrator@vsphere.local","password":"<password>"}' | jq -r .accessToken)
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/roles | jq '.elements[]|{id,name}'
   curl -sk -X POST https://sddc-manager.example.local/v1/users -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '[{"name":"svc-vcf-certs@corp.local","type":"USER","domain":"corp.local","role":{"id":"<ADMIN role id>"}}]'
   ```

2. Find the workload domain and the component as SDDC Manager knows them:

   ```sh
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains | jq '.elements[]|{id,name}'
   curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains/<domain-id>/resource-certificates | jq
   ```

3. Nothing to switch on - the API is on. A Microsoft or OpenSSL CA configured in SDDC Manager
   is not needed (acme's source signs the CSR).

## Fill in acme

The target (**Targets → Add → VMware Cloud Foundation component**):

| acme field | What to put there |
|---|---|
| Address | SDDC Manager, e.g. `sddc-manager.example.local` |
| HTTPS port | `443` |
| User / Password | The account from step 1 (`svc-vcf-certs@corp.local`) |
| Component FQDN | The component, e.g. `vc01.example.local` (empty: the certificate's first name) |
| Component type | `vCenter`, `NSX Manager (NSX-T)`, `SDDC Manager`, ... (SDDC Manager's resource type) |
| Workload domain | Its name or ID, e.g. `sddcm-mgmt-domain` (empty: the only one) |
| Country, State, City, Organization, Unit | What SDDC Manager puts in every CSR (the state in full); the certificate's own subject (its profile) wins |
| Wait for VCF's tasks (minutes) | `60` |
| Check the device's certificate | On when SDDC Manager's own certificate is from a CA acme trusts (else paste the CA) |

Then the certificate: **Add a certificate → Key → Key made by the device → pick this
target** (or, in the target's window, **Make its certificate**). Its names: the component's
FQDN first (VCF wants it in the SAN), then the others (for NSX: the VIP and every node). Key
type RSA 2048 / 3072 / 4096. In the deployment's options paste the **Root CA certificate**
(ISRG Root X1 for Let's Encrypt). From the command line:

```sh
acme --cert-add vc01 --names vc01.example.local --key-type rsa-3072 --issuer "Let's Encrypt" --csr-from vc01-vcf
acme --renew vc01
```

## Check it

- **Test** on the target signs in and says SDDC Manager's version and the domain - nothing is
  changed.
- **Renew now**: the job shows the CSR task, the issue, the validation and the install task.
  Then:

  ```sh
  openssl s_client -connect vc01.example.local:443 -servername vc01.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -H "Authorization: Bearer $TOKEN" https://sddc-manager.example.local/v1/domains/<domain-id>/resource-certificates | jq
  ```

- In the UI: *Inventory → Workload Domains → the domain → Certificates*.

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` | Wrong user or password, or a VIEWER role. |
| `give the workload domain` / `no workload domain` | Put the domain's name or ID from `/v1/domains` on the target. |
| `lists none for ...` | The FQDN or type is not the one SDDC Manager knows: compare with `/resource-certificates`. |
| `the validation of the certificate failed` | The chain is incomplete (paste the root), the names miss the FQDN, or SDDC Manager made a newer CSR since: **Renew now**. |
| `making the CSR failed` / install failed | Look at the task in the UI (*Tasks*) and `/var/log/vmware/vcf/operationsmanager/operationmanager.log`; vCenter replacement fails when the SSO account SDDC Manager uses is read-only (KB 316107). |
| Other products stop trusting the component | Trust relations elsewhere (NSX compute manager, SRM, backup) may need a refresh (KB 445742). |
| Deployments held | The component keeps its old certificate; the next issue asks SDDC Manager for a new key and CSR. |
