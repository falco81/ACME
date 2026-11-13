# Lenovo XClarity Controller and XCC2 (ThinkSystem V1-V3) - setup for acme

The XCC takes **only a certificate signed for a CSR it made itself** - no private key can be
imported (Lenovo's documents). So the **XCC makes the key**: at every issue and renewal acme
asks it for a new key and CSR over Redfish, has the CSR signed by the certificate's source and
puts the certificate back right away. The key never leaves the XCC; acme holds none. The
certificate is the one of the XCC's web interface, Redfish and its LDAP client.

**This version** is for **XCC and XCC2** (ThinkSystem V1, V2, V3):

| | |
|---|---|
| Key | The XCC / XCC2 offer no key type: acme asks for none, and the certificate's key type is **RSA 2048** |
| CSR | `CertificateService.GenerateCSR` where the firmware has it (newer XCC/XCC2 firmware, the same URIs as XCC3); else Lenovo's own security service: `LenovoSecurityService.GenerateCSR` and `DownloadCSR` |
| Import | `CertificateService.ReplaceCertificate` (`CertificateType` `PEM`); else `LenovoSecurityService.ImportCertificate` (the certificate as DER) |
| Names | Through Lenovo's own service the CSR has **one host name** (no other names) - give such a certificate one name |

For XCC3 (ThinkSystem V4) use the plain version of this target (any key type).

## What you need

- From acme to the XCC: **TCP 443** (HTTPS, Redfish).
- An XCC account for acme with only what certificates need (below).
- A source that signs a CSR made elsewhere - an ACME CA, acme's own authority, a commercial
  CA. Not *Self-signed*, CMP or SCEP.

## Set up the XCC

1. A role with only **Configuration - Networking and BMC Security** (`nsc`) and a user with it,
   in the XCC's CLI (SSH):

   ```text
   system> roles -3 -n CertAdmin -p custom:nsc
   system> users -3 -n svccert -p '<password>' -r CertAdmin -ai redfish
   ```

   Or in the web interface: **BMC Configuration → User/LDAP**: a role with only *Networking and
   BMC Security*, a user with that role.
2. HTTPS (port 443) must be on - it is by default.
3. The certificate's first name (its common name) should be the name the XCC is reached by.

## Fill in acme

The target (**Targets → Add → Lenovo XClarity Controller**, version **xcc2**):

| acme field | What to put there |
|---|---|
| Address | The XCC's name or IP, e.g. `xcc01.example.local` |
| HTTPS port | `443` |
| User / Password | The account from step 1 (`svccert`) |
| Country, State, City, Organization | What the XCC puts in every CSR (it asks for them); the certificate's own subject (its profile) wins |
| Unit, E-mail in the CSR | Optional |
| Check the device's certificate | Off for the first issue (the XCC still has its self-signed certificate), on afterwards |

Then the certificate: **Add a certificate**, in the step *Key* choose **Key made by the device**
and this target (the key type RSA 2048) - or, in the target's window, **Make its certificate**.
acme makes the deployment to the XCC by itself; it runs right after each issue.

```sh
acme --cert-add xcc01 --names xcc01.example.local --issuer "Let's Encrypt" --key-type rsa-2048 --csr-from xcc01
acme --renew xcc01
```

## Check it

- **Test** on the target signs in and says which way the CSR is made (the standard
  `GenerateCSR` or Lenovo's own service) - nothing is changed.
- **Renew now** on the certificate; the XCC serves the new certificate **within about 15
  minutes**, without a restart:

  ```sh
  openssl s_client -connect xcc01.example.local:443 -servername xcc01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password, or the account is not allowed Redfish. |
| `403` | The role lacks *Networking and BMC Security* (`nsc`). |
| `makes rsa-2048 keys only` | Set the certificate's key type to RSA 2048. |
| `takes one host name` | Lenovo's own service names one host: give the certificate one name, or update the XCC firmware (the standard GenerateCSR takes more names). |
| The import refused | The XCC made a newer CSR since (another GenerateCSR) - **Renew now** issues one for the key it holds now. |
| Old certificate still served | Wait up to 15 minutes. |
