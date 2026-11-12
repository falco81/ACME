# Supermicro BMC (SSL certificate upload) - setup for acme

acme uploads the **HTTPS certificate of a Supermicro BMC** (web interface and Redfish share it)
with Supermicro's own Redfish action - **no licence needed** (Supermicro's list of APIs marks it
"Standard"):

```text
POST /redfish/v1/UpdateService/Oem/Supermicro/SSLCert/Actions/SmcSSLCert.Upload
     multipart/form-data: cert_file = certificate (+ chain), key_file = private key (PEM)
```

It signs in with a Redfish session (or HTTP Basic), uploads both files, and - when asked -
resets the BMC with `Manager.Reset` `GracefulRestart` ("BMC cold reset"). The BMC restarts its
web server after the upload by itself; **the server and its operating system are not touched**.

**Which versions:** X12/H12, X13/H13 and X14/H14 BMC firmware (Supermicro Redfish User's Guide
4.0, 1.22.2 and 1.23.2) - the same call everywhere. **X11 and older**: use the web interface
(**Configuration → SSL Certificate**). Gen 15 renames some OEM paths - check after an upgrade.

**With the SFT-DCMS-SINGLE licence** the standard way works too: the target *Server management
(Redfish)* with **Send as: PEM** (Supermicro's `ReplaceCertificate` takes `PEM` only). Without
the licence the standard `CertificateService` answers with a licence error - use this target.

## What you need

- From acme to the BMC: **TCP 443**.
- A BMC user with the role **Administrator** (Supermicro has no narrower role for certificates;
  changing the certificate is `ConfigureManager`).
- RSA or ECDSA key: the upload takes PEM files; Supermicro's own CSR offers RSA only - **RSA 2048
  or 3072** is the safe choice.

## Set up the BMC

1. Create a separate account for acme (Redfish; a BMC with fixed account slots takes a `PATCH`
   of a free slot `/redfish/v1/AccountService/Accounts/<n>` instead):

   ```sh
   curl -k -u ADMIN:'<admin-password>' -X POST https://bmc.example.local/redfish/v1/AccountService/Accounts \
     -H "Content-Type: application/json" \
     -d '{"UserName": "svc-cert", "Password": "<strong-password>", "RoleId": "Administrator", "Enabled": true}'
   ```

   Or in the web interface (the menu differs by BMC generation): the user list under
   **Configuration**, privilege *Administrator*.
2. Limit where it may sign in from: **Configuration → IP Access Control** (add the acme
   server).
3. Check that the action is there (it reads only):

   ```sh
   curl -k -u svc-cert:'<password>' https://bmc.example.local/redfish/v1/UpdateService/Oem/Supermicro/SSLCert
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The BMC's name or IP, e.g. `bmc.example.local` |
| HTTPS port | `443` |
| User / Password | `svc-cert` from step 1 |
| Basic authentication instead of a session (advanced) | Only for a BMC whose sessions do not work |
| Check the device's certificate | Off for the first deployment (the BMC has its self-signed "IPMI" certificate), then on |
| Send the chain with the certificate (deploy) | On: `cert_file` holds the certificate and the intermediates |
| Reset the BMC afterwards (deploy) | Off; on only if the BMC keeps serving the old certificate after an upload |
| Check what is served | Empty: acme checks the BMC's own address |

## Check it

- **Try** signs in, reads the manager and `Oem/Supermicro/SSLCert` - nothing is changed.
- From any machine:

  ```sh
  openssl s_client -connect bmc.example.local:443 -servername bmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong user or password, or the account is disabled. |
| `403` | The account is not *Administrator*. |
| `no SmcSSLCert.Upload` (404/405) | X11 or old firmware: update the BMC firmware, or upload in the web interface (**Configuration → SSL Certificate**). |
| The upload is refused | Send the key unencrypted PEM (acme does), try *Send the chain with the certificate* off, use an RSA key. |
| Old certificate still served | Turn on *Reset the BMC afterwards*. |
| A firmware update put the old certificate back | `sum … UpdateBmc --overwrite_ssl` overwrites it - deploy again (force). |
