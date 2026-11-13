# VMware Cloud Foundation 9.1 component through VCF Operations - setup for acme

VCF Operations fleet management takes **only a certificate signed for a CSR it made itself**:
its import pairs the certificate with the CSR in its keystore (a `400` when the leaf matches no
CSR) - no private key made elsewhere can be imported. So **VCF makes the key**: at every issue
and renewal acme signs in to VCF Operations, finds the component's TLS certificate
(`POST .../certificate-management/certificates/query`), has VCF make a new key and CSR
(`POST .../certificate-management/csrs`, a workflow), reads the CSR (`GET .../csrs?certificateId=`),
has it signed by the certificate's source and right away has VCF replace the certificate with
the signed one and its chain (`PUT .../certificate-management/certificates/{id}` with
`caType` `EXTERNAL_CA` - the API of *Replace with imported certificate*). The key never leaves
VCF; acme holds none.

**Versions:** VCF **9.1 and 9.1.1** (the VCF Operations API *Fleet Certificate Management*);
acme reads VCF Operations' version and refuses an older one before changing anything. For VCF
5.2 (or the SDDC Manager API of VCF 9.x) choose the plain version of this target. **One
component a target**: a vCenter, NSX Manager, ESX host, SDDC Manager, a VCF management
component (VCF Operations, VCF Automation, Operations for logs / networks, Fleet Management,
Identity Broker) - whatever *Fleet management → Certificates* lists.

## What you need

- From acme to VCF Operations: **TCP 443**; and to the component on 443 for the test of what
  is served.
- A VCF Operations user with the role **Administrator** (or a role of your own with the fleet
  certificate privileges - VMware does not name them; list them with
  `GET /suite-api/api/auth/privileges`).
- A source that signs a CSR made elsewhere - an ACME CA (DNS-01 for the component's FQDN), acme's
  own authority, a commercial CA. **RSA** only (2048, 3072, 4096); VCF 9.1 checks the SAN
  strictly: the FQDN must be there, no short names.
- The **root CA certificate** of the source: the chain goes leaf → intermediate → root.
- The certificate must not be expired yet - VCF cannot replace an expired one (KB 445742).

## Set up VCF Operations

1. A user for acme with the role Administrator: *VCF Operations → Administration → Control
   Panel → Access Control → Users → Add*, or import it from the Identity Broker / LDAP source.
   Check that it signs in to the API:

   ```sh
   curl -sk -X POST https://vcf-ops.example.local/suite-api/api/auth/token/acquire \
     -H 'Content-Type: application/json' -H 'Accept: application/json' \
     -d '{"username":"svc-vcf-certs","password":"<password>","authSource":"<source>"}'
   ```

2. Find the component's certificate (its ID is optional in acme - the FQDN finds it):

   ```sh
   TOKEN=<token from step 1>
   curl -sk -X POST 'https://vcf-ops.example.local/suite-api/api/fleet-management/certificate-management/certificates/query?page=0&pageSize=50' \
     -H "Authorization: OpsToken $TOKEN" -H 'Content-Type: application/json' \
     -d '{"applianceFqdn":"vc01.example.local","category":"TLS_CERT"}' | jq '.vcfCertificateModels[]|{certificateResourceKey,issuedTo,appliance,type,status}'
   ```

3. Nothing to switch on. A CA configured for the fleet (Microsoft / OpenSSL) is not needed;
   switch **auto-renewal off** for this component, so VCF does not replace acme's certificate
   with one of its CA.

## Fill in acme

The target (**Targets → Add → VMware Cloud Foundation component**, version **9.1**):

| acme field | What to put there |
|---|---|
| Address | VCF Operations, e.g. `vcf-ops.example.local` |
| HTTPS port | `443` |
| User / Password | The account from step 1 |
| Authentication source | The source of the user (Identity Broker / LDAP); empty for a local user |
| Component FQDN | The component, e.g. `vc01.example.local` (empty: the certificate's first name) |
| Certificate ID | Empty (found by the FQDN); the ID from step 2 when VCF lists more than one |
| Country, State, City, Organization, Unit | What VCF puts in every CSR (the state in full); the certificate's own subject (its profile) wins |
| Wait for VCF's tasks (minutes) | `60` |

*Component type* and *Workload domain* are for SDDC Manager only. Then the certificate:
**Add a certificate → Key → Key made by the device → pick this target** (or, in the target's
window, **Make its certificate**). Its names: the component's FQDN first, then the others (IP
addresses go to the CSR's IP names). Key type RSA. In the deployment's options paste the
**Root CA certificate** (ISRG Root X1 for Let's Encrypt). From the command line:

```sh
acme --cert-add vc01 --names vc01.example.local --key-type rsa-3072 --issuer "Let's Encrypt" --csr-from vc01-ops
acme --renew vc01
```

## Check it

- **Test** on the target signs in, says VCF Operations' version and the certificate ID it
  finds - nothing is changed.
- **Renew now**: the job shows the CSR workflow, the issue and the replace workflow. Then:

  ```sh
  openssl s_client -connect vc01.example.local:443 -servername vc01.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -H "Authorization: OpsToken $TOKEN" https://vcf-ops.example.local/suite-api/api/workflows/requests/<requestId> | jq .state
  ```

- In the UI: *Fleet management → Certificates* - VCF reads the certificates every 6 hours, a
  new one may show later there than on the component.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user, password or *Authentication source*. |
| `has no fleet certificate management API` | VCF Operations older than 9.1: use the plain version (SDDC Manager API). |
| `lists no TLS certificate of ...` | The FQDN differs from VCF's: look at step 2, or give the *Certificate ID*. |
| `lists 2 TLS certificates` | Give the *Certificate ID* on the target. |
| `400` on the replace | The leaf matches no CSR in VCF (a newer CSR was made since: **Renew now**), or the chain is incomplete (paste the root). |
| The workflow failed | Look at the request in VCF Operations (*Fleet management → Tasks*); an expired certificate needs the vcf-cert-tool (KB 445742). |
| acme's certificate replaced by VCF | Auto-renewal is on for the component - switch it off. |
