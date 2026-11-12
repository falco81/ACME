# Dell iDRAC9 6.00.02+ / iDRAC10 (Redfish, Dell OEM) - setup for acme

This version of the Redfish target puts acme's key and certificate on a **Dell iDRAC** the
way Dell documents for a key made elsewhere: through the iDRAC's own Redfish service
`DelliDRACCardService` - first `UploadSSLKey` (the key), then `ImportSSLCertificate` with
`CertificateType: Server` (the certificate). It is the Redfish twin of
`racadm sslkeyupload -t 1` + `racadm sslcertupload -t 1`. The iDRAC then **restarts only its
web server** (GUI, Redfish and remote RACADM are gone for a few tens of seconds); the server
and its operating system are not touched.

## Which iDRAC this guide is for

Module version **"Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM)"** (`6.00.02`):

| Controller | Firmware | This version |
|---|---|---|
| iDRAC10 (PowerEdge 17G) | 1.xx (1.10 - 1.30 checked) | yes |
| iDRAC9 (14G, 15G, 16G) | 6.00.02.00 - 7.xx (7.00 - 7.20 checked) | yes |
| iDRAC9 | older than 6.00.02.00 | **refused** - use the plain version with *Restart the controller afterwards*, or update the firmware |
| not a Dell iDRAC (iLO, XCC, BMC) | - | **refused** - use the plain version |

acme reads the manager's `FirmwareVersion` (`/redfish/v1/Managers/iDRAC.Embedded.1`) and
refuses before changing anything when it does not fit. A newer firmware than checked goes
on with a warning.

Why not the plain version: Dell documents `CertificateService.ReplaceCertificate` on the
iDRAC only for a certificate of a **CSR the iDRAC made itself** (the certificate alone,
`PEM`). The plain version puts the key inside `CertificateString` - the DMTF way, which Dell
does not document for the iDRAC. No reset is needed from iDRAC9 6.00.02 and on iDRAC10.

## What you need

- HTTPS from acme to the iDRAC: **TCP 443** (or the port set in `iDRAC.WebServer.HttpsPort`).
- Redfish enabled (it is by default):

  ```sh
  racadm set iDRAC.Redfish.Enable 1
  ```

- Any iDRAC licence (the manual upload is not licensed; only automatic enrollment needs
  Datacenter).
- A key type the iDRAC takes: **RSA 2048 or 4096** on iDRAC9; on iDRAC10 prefer
  **RSA 3072 or 4096** (iDRAC10 makes no 2048-bit keys itself; whether it refuses an uploaded
  2048-bit key is not documented). ECDSA is not documented.

## The account (least privileges)

Dell: the web server certificate needs **Login to iDRAC** + **Configure iDRAC**. The
predefined *Operator* role has both; a custom role with only these two is the least.

iDRAC9 with RACADM (slot 5 as an example - use a free one):

```sh
racadm set iDRAC.Users.5.UserName acme
racadm set iDRAC.Users.5.Password '<strong-password>'
racadm set iDRAC.Users.5.Privilege 0x3
racadm set iDRAC.Users.5.IpmiLanPrivilege 15
racadm set iDRAC.Users.5.Enable 1
```

`0x3` = Login (0x1) + Configure iDRAC (0x2) - check it with `racadm help iDRAC.Users.Privilege`
on your firmware. Through Redfish with the predefined Operator role:

```sh
curl -k -u admin:'<admin-password>' -X PATCH https://idrac.example.local/redfish/v1/AccountService/Accounts/5 \
  -H 'Content-Type: application/json' \
  -d '{"UserName":"acme","Password":"<strong-password>","RoleId":"Operator","Enabled":true}'
```

iDRAC10 has no role *None* any more: in the GUI (**iDRAC Settings → Users → Local Users →
Add**) choose a **custom role** and tick only *Login* and *Configure iDRAC*.

## What acme calls

```text
POST /redfish/v1/SessionService/Sessions                     {UserName, Password} -> X-Auth-Token
GET  /redfish/v1/Managers/iDRAC.Embedded.1                   FirmwareVersion
GET  /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService
POST .../DelliDRACCardService/Actions/DelliDRACCardService.UploadSSLKey         {"SSLKeyString": "<key PEM>"}
POST .../DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate {"CertificateType": "Server", "SSLCertificateFile": "<certificate PEM>"}
POST /redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset {"ResetType": "GracefulRestart"}   (only when asked)
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM)** |
| Address / HTTPS port | the iDRAC's name or address, `443` |
| User / Password | the account above |
| Basic authentication instead of a session (advanced) | off; on only when sessions are full |
| Check the device's certificate | off for the first deployment over the self-signed certificate (or give *CA certificate*), then on |
| Send as (deploy) | *PEMchain*: the certificate with its intermediates; *PEM*: the certificate alone |
| Certificate URI (deploy) | not used by this version |
| Restart the controller afterwards (deploy) | off - not needed from 6.00.02 / on iDRAC10; on only if the old certificate stays served |

## Check it

```sh
openssl s_client -connect idrac.example.local:443 -servername idrac.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
racadm -r idrac.example.local -u acme -p '<password>' sslcertview -t 1
```

*Try* on the target says the model, the firmware and `iDRAC9` / `iDRAC10`.

## Common problems

| Problem | Fix |
|---|---|
| `runs firmware 5.x ... needs iDRAC9 6.00.02` | Update the iDRAC firmware, or use the plain version with *Restart the controller afterwards*. |
| `offers no DelliDRACCardService.UploadSSLKey` | The firmware lacks it - update it. |
| `403` on UploadSSLKey | The account lacks *Configure iDRAC*. |
| Import refused | The key does not match, or the key type is not RSA; on iDRAC10 try RSA 3072/4096; try *Send as* `PEM`. |
| Web server unavailable after a firmware update (iDRAC9 7.00 - 7.10.30) | Dell KB 000220891: over SSH `racadm sslresetcfg`, then deploy again. |
| The old certificate is still served | Wait a minute (the web server restarts); otherwise set *Restart the controller afterwards*. |
