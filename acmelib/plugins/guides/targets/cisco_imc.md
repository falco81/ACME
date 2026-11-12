# Cisco IMC (UCS C-Series, standalone) - setup for acme

acme puts the **HTTPS certificate of a standalone Cisco IMC** in as an **External Certificate**
with its own private key, through the IMC **XML API** (`https://<imc>/nuova`):

```text
aaaLogin                                          -> session cookie
uploadExternalCertificate  sys/cert-mgmt/external-cert-upload    adminAction=content-cert-upload
uploadExternalPrivateKey   sys/cert-mgmt/external-pvt-key-upload adminAction=content-cert-upload
certificateManagement      sys/cert-mgmt                         adminAction=activate-external-cert
aaaLogout
```

This is Cisco's way for a key made outside the IMC (the plain *Upload Server Certificate* takes
only a certificate for a CSR the IMC made itself). **Activating it drops all HTTPS and SSH
sessions and restarts the IMC's services** - plan it; the server and its operating system keep
running.

**Which versions:** Cisco IMC 4.x (M5/M6) and 6.0 (M7, M8) - the same XML objects. Servers
managed by Intersight (IMM) or UCS Manager have no local IMC configuration: use a Certificate
Management Policy there instead.

**Keys:** RSA **2048 or 4096** (8192 on M5 and later); files up to 8 KB. Choose an RSA key type.
The certificate must be a server certificate (EKU serverAuth).

## What you need

- From acme to the IMC: **TCP 443**; the XML API enabled (**Admin → Communication Services →
  XML API**).
- An IMC user with the role **admin** - Cisco: "Admin privileges for all certificate tasks";
  there is no narrower role.
- The IMC's clock right ("Set Cisco IMC to the current time before certificate tasks").

## Set up the IMC

1. Create a user for acme (CLI over SSH; slot 5 as an example - take a free one):

   ```text
   Server# scope user 5
   Server /user # set enabled yes
   Server /user # set name svc-cert
   Server /user # set role admin
   Server /user # set password
   Please enter password:
   Please confirm password:
   Server /user* # commit
   ```
2. Check that the XML API lets it in:

   ```sh
   curl -k https://cimc.example.local/nuova -d "<aaaLogin inName='svc-cert' inPassword='<password>'/>"
   ```

   The answer holds `outCookie="…"`; sign out again with
   `<aaaLogout cookie='<cookie>' inCookie='<cookie>'/>`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The IMC's name or IP, e.g. `cimc.example.local` |
| HTTPS port | `443` |
| User / Password | `svc-cert` from step 1 |
| Check the device's certificate | Off for the first deployment (the IMC has its self-signed certificate), then on |
| Send the chain with the certificate (deploy) | Off (the certificate alone); on if your clients need the intermediate from the IMC |
| Check what is served | Empty: acme checks the IMC's address after the services are back |

## Check it

- **Try** signs in and reads `sys/cert-mgmt/curr-cert` (the current certificate) - nothing is
  changed.
- After the deployment:

  ```sh
  openssl s_client -connect cimc.example.local:443 -servername cimc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `signing in: … error 551` | Wrong user or password, or the XML API is off. |
| Refused on upload | The user is not `admin`; the key is not RSA; the certificate is not a server certificate. |
| `Key does not match` | The key and the certificate are not a pair - deploy again (force). |
| Sessions dropped during the deployment | Expected: the activation restarts the IMC's web and SSH services. |
| Intersight-managed server | Use Intersight's Certificate Management Policy (`certificatemanagement.Imc`); the IMC refuses local changes. |
