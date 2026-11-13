# Dell OpenManage Enterprise 3.10 - 4.x - setup for acme

OpenManage Enterprise (OME) takes **only a certificate signed for a CSR it made itself** -
Dell's user guide: *generate the CSR only from within the OpenManage Enterprise appliance*; no
private key and no PKCS#12 can be uploaded. So **OME makes the key**: at every issue and renewal
acme asks it for a new key and CSR over its REST API
(`ApplicationService.GenerateCSR`), has the CSR signed by the certificate's source and uploads
the certificate right away (`ApplicationService.UploadCertChain`, or `UploadCertificate`). The
key never leaves OME; acme holds none. It is the certificate of OME's web interface and REST
API (`https://<ome>/api`).

**This version** is for **OME 3.10 - 4.x** (checked against OME 4.6):

| | |
|---|---|
| Version check | acme reads the version (`GET /api/ApplicationService/Info`) and refuses an appliance older than 3.10 before anything is asked of it |
| CSR | `POST /api/ApplicationService/Actions/ApplicationService.GenerateCSR` - the names in `San` |
| Upload | `ApplicationService.UploadCertChain`: the certificate and its intermediates (and the root, when given), PEM, `application/octet-stream`; with *Upload the chain* off, `UploadCertificate` with the certificate alone |

For OME 3.0 - 3.9 choose the version **`3.0`**; the plain version reads the version and acts
by it.

## What you need

- From acme to OME: **TCP 443** (or the port of *Application Settings → Network → Web
  Server*).
- An OME account for acme with only what certificates need (below).
- A source that signs a CSR made elsewhere - an ACME CA (Let's Encrypt with a DNS-01
  validation for the appliance's name), acme's own authority, a commercial CA. Not
  *Self-signed*. The certificate must have the EKU *Server Authentication* and be signed with
  SHA-256 or stronger (no SHA-1 anywhere in the chain).
- The names: OME's FQDN first (it is the common name, *Distinguished Name* in OME), and its IP
  address if servers reach it by IP (Windows driver updates). **At most 4 names** and **no
  wildcard** - OME takes neither.
- The key: OME makes an **RSA 2048** key (it offers no choice) - give the certificate that key
  type.

## Set up OME

1. A role with only **Appliance Management** (OME 4.x: *Application Settings → Users → Roles →
   Create*, tick *Appliance Management* only) and a user with it - or the role
   **Administrator** (Device Manager and Viewer cannot reach the certificates). Over the REST
   API, as an administrator:

   ```sh
   OME=ome.example.local
   TOKEN=$(curl -sk -D - -o /dev/null -X POST https://$OME/api/SessionService/Sessions \
     -H 'Content-Type: application/json' \
     -d '{"UserName":"admin","Password":"<admin password>","SessionType":"API"}' \
     | awk -F': ' 'tolower($1)=="x-auth-token"{print $2}' | tr -d '\r')
   curl -sk -H "X-Auth-Token: $TOKEN" https://$OME/api/AccountService/Roles
   curl -sk -X POST https://$OME/api/AccountService/Accounts \
     -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"UserName":"svc-cert","Password":"<password>","RoleId":"<role id>","Enabled":true,"UserTypeId":1,"DirectoryServiceId":0,"Locked":false,"Description":"acme certificates"}'
   ```

2. The REST API is always on (`https://<ome>/api`) - nothing to switch on.
3. Set OME's DNS name and NTP right: the certificate's names must be the names it is reached by.

## Fill in acme

The target (**Targets → Add → Dell OpenManage Enterprise**):

| acme field | What to put there |
|---|---|
| Address | OME's name or IP, e.g. `ome.example.local` |
| HTTPS port | `443` (or OME's web server port) |
| User / Password | The account from step 1 (`svc-cert`) |
| Country, State, City, Business name, Department name, E-mail in the CSR | What OME puts in every CSR (it asks for all of them); the certificate's own subject (its profile) wins |
| Check the device's certificate | Off for the first issue (OME still has its self-signed certificate), on afterwards |

Then the certificate: **Add a certificate** → in the step **Key** choose **Key made by the
device** → pick this target (or, in the target's window, **Make its certificate**). Its names:
OME's FQDN (and its IP address). Key type: RSA 2048. acme makes the deployment to OME by
itself; it runs right after each issue. From the command line:

```sh
acme --cert-add ome --names ome.example.local --issuer "Let's Encrypt" --key-type rsa-2048 --csr-from ome
acme --renew ome
```

The deployment's options: **Upload the chain** (on: the certificate and its intermediates;
off: the certificate alone) and **Root CA certificate** (added at the end of the chain - Dell
advises the whole chain, root included; up to 10 certificates).

## Check it

- **Test** on the target signs in and says the OME version and how the certificate will be
  uploaded - nothing is changed.
- **Renew now** on the certificate: the job says *the key and the CSR are made by the device*,
  the issue and the upload. OME restarts its web server and is unreachable for a few seconds;
  the tests after the deployment wait for it.

  ```sh
  openssl s_client -connect ome.example.local:443 -servername ome.example.local -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  In OME: **Application Settings → Security → Certificates** shows *Issued To*, *Issued By*
  and the dates.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password, or the account is disabled or locked. |
| `403` on GenerateCSR or the upload | The role lacks *Appliance Management* - give it, or the role Administrator. |
| `takes no wildcard` / `at most 4 names` | Give the certificate OME's own names, four at most. |
| `asks for ... in every CSR` | Fill in every CSR field on the target (OME wants all of them). |
| The upload refused | OME made a newer CSR since this certificate was issued (one made by hand in the GUI drops the key acme's certificate is for) - **Renew now** issues a new one. A chain signed with SHA-1, or one uploaded as a single certificate, is refused too. |
| `runs OpenManage Enterprise 3.9` (or older) - the module version ... is for ...` | Choose the version the message names, or the plain one. |
| Integrations (OMEVV in vCenter, ServiceNow, scripts) stop trusting OME | They must trust the new CA; OMEVV may ask to accept OME's certificate again. |
| Deployments held | OME keeps its old certificate; the next issue asks it for a new key and CSR. |
