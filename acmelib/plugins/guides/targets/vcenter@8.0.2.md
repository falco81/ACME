# VMware vCenter 8.0 U2 - 9.1 - setup for acme

acme replaces vCenter's **machine SSL certificate** (rhttpproxy on 443 - the vSphere Client, the API) through the **vSphere Automation REST API**:

1. reads vCenter's version (`GET /sdk/vim25/8.0.1.0/ServiceInstance/ServiceInstance/content`, no sign-in) - **another version than 8.0 U2 - 9.1 is refused before anything changes**;
2. `POST /api/session` (basic auth), `GET /api/vcenter/certificate-management/vcenter/tls` - the same certificate there already: nothing done;
3. adds the intermediates and the root to the **trusted root chains** (`POST .../vcenter/trusted-root-chains`);
4. `PUT /api/vcenter/certificate-management/vcenter/tls` with `cert` (the leaf), `key` and `root_cert`.

**From vCenter 8.0 U2 the services are not restarted** and open sessions stay (KB 403973, VCF 9.1 Programming Guide) - a refresh of the browser is enough; acme checks the served certificate at once. On vCenter 7.0 - 8.0 U1 use the plain version (*VMware vCenter Server*), which waits for the restart of the services.

## Which vCenter this guide is for

| Module version | vCenter | After the change |
|---|---|---|
| plain - *VMware vCenter Server* | 7.0 - 9.1 | waits as for a restart (20 tries, 15 s apart) |
| **vCenter 8.0 U2 - 9.1** (`8.0.2`) | 8.0 U2, 8.0 U3, 9.0, 9.1 | no restart, checked at once (6 tries, 10 s apart); RSA keys only, refused before sending |

The calls are the same in both; a vCenter newer than 9.1 is used with a warning. In **VCF 9** vCenter's certificates are managed by VCF Operations (*Fleet management → Certificates*): replacing it here makes VCF show it as *externally managed* - add the root to SDDC Manager's trust store too (the `sddc_manager` target).

## Set up vCenter

1. An SSO user: *Administration → Single Sign On → Users and Groups → Users → vsphere.local → Add*, e.g. `svc-certmgmt`. Or on the appliance:

   ```sh
   /usr/lib/vmware-vmafd/bin/dir-cli user create --account svc-certmgmt --user-password '<password>' --first-name svc --last-name certmgmt --login administrator@vsphere.local
   ```

2. A role: *Administration → Access Control → Roles → New* `CertMgmt-Operator` with the **Certificate Management** privileges **Manage** and **Administer** (`CertificateManagement.Manage` for the trusted roots, `CertificateManagement.Administer` for `PUT .../tls`).
3. *Administration → Access Control → Global Permissions → Add*: `svc-certmgmt@vsphere.local`, the role, *Propagate to children*.
4. Try it: the sign-in and the read of the certificate must answer 200:

   ```sh
   TOKEN=$(curl -s -X POST -u 'svc-certmgmt@vsphere.local:<password>' https://vcenter.example.local/api/session | tr -d '"')
   curl -s -H "vmware-api-session-id: $TOKEN" https://vcenter.example.local/api/vcenter/certificate-management/vcenter/tls
   ```

If a custom role is refused, use a member of *Administrators* (or *CAAdmins*) of `vsphere.local`.

## The certificate

- **RSA**, 2048 - 8192 bits (FIPS: 2048 or 3072) - ECDSA is not used for the machine SSL certificate.
- The SAN must hold **vCenter's FQDN (its PNID)**; no wildcard.
- Key usage Digital Signature, Key Encipherment; EKU empty or Server Authentication.
- No RSASSA-PSS anywhere in the chain (`SHA256withRSAandMGF1` is refused by 9.0's prechecks, KB 418126).

## Fill in acme

| acme field | What to put there |
|---|---|
| Version of the module | **vCenter 8.0 U2 - 9.1** |
| Address / HTTPS port | vCenter's FQDN, `443` |
| User / Password | `svc-certmgmt@vsphere.local` and its password |
| Check the device's certificate | on; while vCenter still has its VMCA certificate, put the VMCA root into *CA certificate* (from `https://<vcenter>/certs/download.zip`) |
| Root CA certificate (deploy) | the root PEM (ISRG Root X1 for Let's Encrypt); empty: the last certificate of the chain |
| Add the chain to the trusted roots (deploy) | on |

## Check it

*Try* signs in, reads the certificate and says the vCenter version. After a deployment:

```sh
openssl s_client -connect vcenter.example.local:443 -servername vcenter.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

On the appliance:

```sh
/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT --text | grep -E "Subject:|Not After"
```

## Common problems

| Problem | Fix |
|---|---|
| `this vCenter runs 8.0.1` | Choose the plain version of the target (it waits for the restart). |
| `the vCenter version cannot be read` | vCenter older than 8.0 U1, or `/sdk` blocked: acme goes on as for 8.0 U2 - choose the plain version for an older vCenter. |
| `400` AlreadyExists | The same thumbprint is there - acme takes it as done. |
| `400` invalid certificate / signature algorithm | Not RSA, no FQDN in the SAN, or RSASSA-PSS (KB 418126). |
| `404` NotFound on `PUT .../tls` | vCenter wants the key: acme sends it - check the user's rights. |
| NSX, SRM, Horizon, Aria lost trust | Update the vCenter thumbprint/root there (KB 318946). |
