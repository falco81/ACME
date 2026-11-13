# Lenovo XClarity Controller 3 (XCC3) - setup for acme

The XCC takes **only a certificate signed for a CSR it made itself** - Lenovo's documents say
so for XCC3, XCC2, XCC and IMM2: no private key can be imported. So the **XCC makes the key**:
at every issue and renewal acme asks it for a new key and CSR over Redfish
(`CertificateService.GenerateCSR`), has the CSR signed by the certificate's source and puts
the certificate back right away (`CertificateService.ReplaceCertificate`). The key never
leaves the XCC; acme holds none. The certificate is the one of the XCC's web interface,
Redfish and its LDAP client (they share it).

**This version** is for **XCC3** (ThinkSystem V4): acme asks for the key type of the
certificate - ECDSA P-256 (the XCC's default) or P-384, RSA 2048, 3072 or 4096. For XCC and
XCC2 (ThinkSystem V1-V3) choose the version **`xcc2`** of this target.

## What you need

- From acme to the XCC: **TCP 443** (HTTPS, Redfish).
- An XCC account for acme with only what certificates need (below).
- A source that signs a CSR made elsewhere - an ACME CA (Let's Encrypt with a DNS-01 or
  HTTP-01 validation for the XCC's name), acme's own authority, a commercial CA. Not
  *Self-signed*, CMP or SCEP.

## Set up the XCC

1. A role with only **Configuration - Networking and BMC Security** (`nsc`) and a user with it,
   limited to Redfish - in the XCC's CLI (SSH):

   ```text
   system> roles -3 -n CertAdmin -p custom:nsc
   system> users -3 -n svccert -p '<password>' -r CertAdmin -ai redfish
   ```

   Or over Redfish (XCC3):

   ```sh
   curl -k -u USERID:'<admin password>' -X POST https://xcc.example.local/redfish/v1/AccountService/Roles \
     -H 'Content-Type: application/json' \
     -d '{"RoleId":"CertAdmin","OemPrivileges":["Configuration_NetworkingAndSecurity"]}'
   curl -k -u USERID:'<admin password>' -X PATCH https://xcc.example.local/redfish/v1/AccountService/Accounts/3 \
     -H 'Content-Type: application/json' -H 'If-Match: *' \
     -d '{"UserName":"svccert","Password":"<password>","RoleId":"CertAdmin","Enabled":true}'
   ```

   In the web interface: **BMC Configuration → User/LDAP → Create a role** (only *Networking
   and BMC Security*), then a user with that role.
2. HTTPS (port 443) must be on - it is by default. Nothing else to switch on.
3. The name acme puts in the certificate (its first name, the common name) should be the name
   the XCC is reached by; give the XCC's IP address as another name if it is reached by it.

## Fill in acme

The target (**Targets → Add → Lenovo XClarity Controller**):

| acme field | What to put there |
|---|---|
| Address | The XCC's name or IP, e.g. `xcc01.example.local` |
| HTTPS port | `443` |
| User / Password | The account from step 1 (`svccert`) |
| Country, State, City, Organization | What the XCC puts in every CSR (it asks for them); the certificate's own subject (its profile) wins |
| Unit, E-mail in the CSR | Optional |
| Check the device's certificate | Off for the first issue (the XCC still has its self-signed certificate), on afterwards |

Then the certificate: **Add a certificate**, in the step *Key* choose **Key made by the device**
and this target - or, in the target's window, **Make its certificate**. Its names: the XCC's
name (and address). The key type: one the XCC makes. acme makes the deployment to the XCC by
itself; it runs right after each issue. From the command line:

```sh
acme --cert-add xcc01 --names xcc01.example.local --issuer "Let's Encrypt" --csr-from xcc01
acme --renew xcc01
```

The deployment's options: *Send the intermediates too* (off: the certificate alone, as Lenovo
imports it) and the *Certificate URI* (empty: the first HTTPS certificate).

## Check it

- **Test** on the target signs in and says whether the XCC offers `GenerateCSR` - nothing is
  changed.
- **Renew now** on the certificate: the job says *the key and the CSR are made by the device*,
  the issue, and the import. The XCC serves the new certificate **within about 15 minutes**,
  without a restart (the tests after the deployment wait that long):

  ```sh
  openssl s_client -connect xcc01.example.local:443 -servername xcc01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -u svccert:'<password>' https://xcc01.example.local/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password, or the account is not allowed Redfish (`-ai redfish`). |
| `403` on GenerateCSR or ReplaceCertificate | The role lacks *Networking and BMC Security* (`nsc`). |
| `offers no CertificateService.GenerateCSR` | An XCC / XCC2 with older firmware: choose the version `xcc2` (Lenovo's own security service). |
| `the XCC asks for Country, ...` | Fill in Country, State, City and Organization on the target. |
| `the CSR ... does not name ...` | The XCC left a name out of its CSR - give the certificate only the names the XCC takes. |
| The import refused (`does not match`) | The XCC made a newer CSR since this certificate was issued (another GenerateCSR, by hand or from the web interface) - **Renew now** issues a new one for the key it holds now. |
| Old certificate still served | Wait up to 15 minutes; the XCC switches by itself. |
| Deployments held | The XCC keeps its old certificate; the next issue asks it for a new key and CSR. |
