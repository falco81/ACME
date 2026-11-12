# Huawei / xFusion iBMC - setup for acme

acme imports the **HTTPS certificate of a Huawei or xFusion iBMC** (FusionServer, TaiShan) as a
**custom certificate** - a PKCS#12 file with a one-time password - through the iBMC's Redfish:

```text
POST /redfish/v1/SessionService/Sessions                       -> X-Auth-Token
POST /redfish/v1/UpdateService/FirmwareInventory               multipart "imgfile" -> /tmp/web/acme-….pfx
POST /redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HttpsCert.ImportCustomCertificate
     {"Type": "URI", "Content": "/tmp/web/acme-….pfx", "Password": "…"}   -> iBMC.1.0.CertImportOK
POST /redfish/v1/Managers/1/Actions/Manager.Reset {"ResetType": "ForceRestart"}
```

Huawei: after `CertImportOK` "restart the iBMC" for the certificate to take effect - acme does
it by default. **Only the iBMC restarts; the server keeps running.** The file in `/tmp/web` is
temporary (gone after the import or the restart).

**Which versions:** iBMC V2/V3 (Huawei FusionServer V5/V6, TaiShan 200, xFusion FusionServer
on the same iBMC line), rack servers (Manager ID `1`) and high-density / blade servers
(`BladeN`). **Less certain:** Huawei's portal shows the API pages only in excerpts - the name
`Password` of the PKCS#12 password and the paths on the newest xFusion firmware are not
confirmed from a full page. Press **Try**: it says whether the iBMC lists
`HttpsCert.ImportCustomCertificate`.

## What you need

- From acme to the iBMC: **TCP 443**, Redfish enabled (**Services** in the iBMC web interface).
- An iBMC user with the role **Administrator** - or a custom role (`CustomRole1…4`) with the
  security configuration right.

## Set up the iBMC

1. Create a user for acme. With Redfish:

   ```sh
   curl -k -u Administrator:'<admin-password>' -X POST https://ibmc.example.local/redfish/v1/AccountService/Accounts \
     -H "Content-Type: application/json" \
     -d '{"UserName": "svc-cert", "Password": "<strong-password>", "RoleId": "Administrator"}'
   ```

   Or with Huawei's PowerShell module:

   ```text
   $s = Connect-iBMC -Address ibmc.example.local -Credential (Get-Credential) -TrustCert
   Add-iBMCUser -Session $s -Username svc-cert -Password (Read-Host -AsSecureString) -Role Administrator
   Disconnect-iBMC -Session $s
   ```
2. Check what the iBMC offers (read only):

   ```sh
   curl -k -u svc-cert:'<password>' https://ibmc.example.local/redfish/v1/Managers/1/SecurityService/HttpsCert
   ```

   `Actions` should list `#HttpsCert.ImportCustomCertificate`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The iBMC's name or IP, e.g. `ibmc.example.local` |
| HTTPS port | `443` |
| User / Password | `svc-cert` from step 1 |
| Check the device's certificate | Off for the first deployment, then on |
| Manager ID (advanced) | `1` on a rack server; `Blade1`, `Blade2`… on a high-density or blade server |
| Restart the iBMC afterwards (deploy) | On (the certificate takes effect only after a restart) |
| Check what is served | Empty: acme checks the iBMC's address after the restart |

## Check it

- **Try** reads `SecurityService/HttpsCert` (the certificate served now) - nothing is changed.
- After the restart:

  ```sh
  openssl s_client -connect ibmc.example.local:443 -servername ibmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password; too many sessions open - wait. |
| `403` on the upload or import | The user lacks the security configuration right. |
| `404` on the import | The iBMC has no `HttpsCert.ImportCustomCertificate` (old firmware, other Manager ID) - check the *Manager ID*, update the iBMC, or import a `.pfx` in the web interface (SSL certificate, *Customize*). |
| Refused certificate | Since iBMC V360 MD5 certificates are refused; use RSA 2048+ or ECDSA. |
| Old certificate still served | *Restart the iBMC afterwards* was off - restart the iBMC. |
