# Server management controllers (Redfish) - setup for acme

acme replaces the **HTTPS certificate of a server's management controller** (Dell iDRAC,
HPE iLO, Lenovo XClarity Controller, Supermicro and AMI MegaRAC BMCs) through standard
Redfish. It signs in with a session (`POST` to the session service, `X-Auth-Token`; or
basic authentication), finds the first manager's `NetworkProtocol/HTTPS/Certificates`
member (or the *Certificate URI* you give) and calls
`CertificateService.ReplaceCertificate` with the key and certificate in one PEM string
(`PEMchain`: key + full chain, or `PEM`: key + certificate). If the collection is empty it
`POST`s the certificate to it. With *Restart the controller afterwards* it sends
`Manager.Reset` `GracefulRestart` - **only the controller restarts, not the server**.

**Which controllers take a private key this way varies.** Reported to work: AMI MegaRAC
(ASUS, Lenovo, Supermicro), Dell iDRAC9 firmware 5.x and later, HPE iLO 5 2.42 and later.
**HPE iLO 6 offers only GenerateCSR** and does not take a key - acme says so. Older iDRACs
need `racadm sslkeyupload`, not this target. Lenovo XCC2 takes `PEM` only.
Use an **RSA 2048** key type for the certificate.

## What you need

- Network access from acme to the controller's HTTPS: **TCP 443**.
- Redfish enabled on the controller.
- A controller user with the **Configure Manager** privilege (iDRAC: *Configure*; iLO:
  *Configure iLO Settings*).

## Set up the controller

1. Enable Redfish if it is off.
   - iDRAC: **iDRAC Settings → Services → Redfish → Enabled**, or:

     ```text
     racadm set iDRAC.Redfish.Enable 1
     ```
   - iLO: Redfish is part of the iLO RESTful API and is on by default.
2. Create a dedicated user for acme with only *Login* and *Configure* rights:
   - iDRAC: **iDRAC Settings → Users → Local Users → Add**, role custom with *Login* and
     *Configure*. With racadm (slot 3 as an example - use a free slot):

     ```text
     racadm set iDRAC.Users.3.UserName acme
     racadm set iDRAC.Users.3.Password <strong-password>
     racadm set iDRAC.Users.3.Privilege 0x3
     racadm set iDRAC.Users.3.Enable 1
     ```

     (`0x3` = Login + Configure iDRAC.)
   - iLO: **Administration → User Administration → New**, privileges *Login* and
     *Configure iLO Settings*.
   - XCC / Supermicro / MegaRAC: a user with a role that may change the BMC's
     configuration/security settings (check your vendor's role list).
3. If the controller has an IP allow-list (iDRAC *IP Blocking / IP Range*, iLO *Access
   Settings*), include the acme server.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The controller's name or IP, e.g. `idrac.example.local` |
| HTTPS port | `443` |
| User / Password | The acme user from step 2 |
| Basic authentication instead of a session (advanced) | Only for a controller whose sessions do not work |
| Check the device's certificate | On; off only while the controller has its self-signed certificate (typical for the first deployment) |
| CA certificate (advanced) | The CA of the controller's current certificate, if not public |
| Send as (deploy) | *PEMchain* (default); *PEM* for a controller that refuses it (Lenovo XCC2) |
| Certificate URI (deploy, advanced) | Empty: the first HTTPS certificate of the first manager. Or e.g. `/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates/SecurityCertificate.1` |
| Restart the controller afterwards (deploy) | On for iDRAC (it serves the new certificate only after a reset) |
| Check what is served | Empty: acme checks the controller's own address |

## Check it

- Press **Try** on the target: acme signs in and reads the manager, answering
  `signed in to ...: <vendor> <model>, firmware x, Redfish y`.
- From any machine:

  ```sh
  curl -sk -u acme:'<password>' https://idrac.example.local/redfish/v1/CertificateService
  openssl s_client -connect idrac.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

  The first should list `#CertificateService.ReplaceCertificate` under `Actions`.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user/password, user disabled, or Redfish off. |
| `403` on replacing | The user lacks *Configure* / *Configure iLO Settings*. |
| `offers no CertificateService.ReplaceCertificate` | HPE iLO 6: it takes only certificates for its own CSR - not supported. |
| Certificate refused | Try *Send as* `PEM`; use an RSA 2048 key; older firmware may not accept a key at all - update it. |
| Old certificate still served | Set *Restart the controller afterwards* (iDRAC); the check waits for the restart. |
| Session limit reached | Too many open sessions on the controller; wait, or use basic authentication. |
