# HPE iLO 5 / 6 / 7 - key made by the iLO - setup for acme

With this target the **iLO makes the key** of its HTTPS certificate and the key **never leaves
the iLO** - HPE's own way, "Generate CSR and Import an SSL Certificate". At every issue and
renewal acme asks the iLO over Redfish for a new key and CSR (`HpeHttpsCert.GenerateCSR` -
the iLO takes a few minutes, up to about 10), has the CSR signed by the certificate's source,
and imports the signed certificate (`HpeHttpsCert.ImportCertificate`); the iLO then resets
itself (1-3 minutes - the server and its OS are not touched).

When to choose it rather than **Server management (Redfish)**, version *HPE iLO* (which puts
acme's key on the iLO):

- an iLO 5 older than **2.78** or an iLO 6 older than **1.30** - they take no key from outside;
- an iLO 6 not in the security state **Production**, an iLO 7 not in **SecureStandard**
  (HighSecurity, FIPS, CNSA...) - they take no RSA key from outside;
- a policy that a management controller's key must stay on it.

Versions: iLO 5, iLO 6 and iLO 7, any firmware (iLO 4 is refused).

## What the iLO puts into its CSR

- **One host name** - the common name - and, when the certificate has IP addresses too, the
  iLO's **own IP addresses** (`IncludeIP`). The iLO takes no other alternative names, so give
  the certificate the iLO's FQDN and, if you want, its addresses - nothing else. acme checks
  the CSR and says it in words when it names something else.
- **The key**: on iLO 6 1.70+ and iLO 7 1.17+ acme sets `KeyType` - `rsa-2048` (RSA) or
  `ec-384` (ECDSA P-384). An iLO without `KeyType` makes RSA in *Production* and ECDSA P-384 in
  *HighSecurity*, *FIPS*, *CNSA*, *SuiteB* - choose that key type for the certificate.

## What you need

- From acme to the iLO: **TCP 443** (Redfish).
- The iLO's host name and domain set to its FQDN (**iLO Dedicated Network Port → General**)
  before the first CSR.
- A source that signs a CSR made elsewhere - an ACME CA (DNS-01 validation for the iLO's
  name), acme's own authority, a commercial CA. Not *Self-signed*, CMP or SCEP.
- No SCEP / automatic enrollment on the iLO - it blocks a manual import.

## Set up the iLO

1. An account with only **Login** and **Configure iLO Settings** (an administrator's session
   in `$TOKEN`):

   ```sh
   curl -k -X POST "https://ilo01.example.local/redfish/v1/AccountService/Accounts/" \
     -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
     -d '{"UserName":"svc-cert","Password":"<password>",
          "Oem":{"Hpe":{"LoginName":"svc-cert","Privileges":{"LoginPriv":true,"iLOConfigPriv":true,
          "RemoteConsolePriv":false,"UserConfigPriv":false,"VirtualMediaPriv":false,
          "VirtualPowerAndResetPriv":false,"HostBIOSConfigPriv":false,"HostNICConfigPriv":false,
          "HostStorageConfigPriv":false,"SystemRecoveryConfigPriv":false}}}}'
   ```

   Or in the web interface: **Administration → User Administration → New**, only *Login* and
   *Configure iLO Settings*.
2. Nothing to switch on: Redfish is always there on 443.

## Fill in acme

The target (**Targets → Add → HPE iLO 5 / 6 / 7 - key made by the iLO**):

| acme field | What to put there |
|---|---|
| Address | The iLO's FQDN, e.g. `ilo01.example.local` |
| HTTPS port | `443` |
| User / Password | `svc-cert` from step 1 |
| Country (C), State or region (ST), City (L), Organization (O), Unit (OU) | What the iLO asks for in every CSR; the certificate's own subject (its profile) wins |
| Wait for the CSR at most (s) | `900` - the iLO makes the CSR in up to about 10 minutes |
| Check the device's certificate | Off while the iLO still has its self-signed certificate |

Then the certificate: **Add a certificate → Key → Key made by the device → pick this
target** (or **Make its certificate** in the target's window). Its names: the iLO's FQDN (and
its IP addresses). Its key type: `rsa-2048` or `ec-384`, as above. acme makes the deployment
to the iLO; it runs right after each issue.

```sh
acme --cert-add ilo01 --names ilo01.example.local --key-type ec-384 --issuer "Let's Encrypt" --csr-from ilo01
acme --renew ilo01
```

## Check it

- **Test** on the target signs in and says the iLO generation, firmware, security state and
  the key type it makes - nothing is changed.
- **Renew now** on the certificate: the job says *the key and the CSR are made by the device*
  (a few minutes), the issue and the import; the iLO resets and the tests after it wait:

  ```sh
  openssl s_client -connect ilo01.example.local:443 -servername ilo01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -sk -u svc-cert:'<password>' "https://ilo01.example.local/redfish/v1/Managers/1/SecurityService/HttpsCert/" | jq .X509CertificateInformation
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user or password. |
| `403` on GenerateCSR, PATCH or import | The account lacks *Configure iLO Settings*. |
| `the iLO puts one host name into its CSR` | Give the certificate one DNS name (and the iLO's addresses only). |
| `the CSR ... names ..., which the certificate does not ask for` | The iLO added a name (its IPs, or its short host name) - add it to the certificate, or leave the IP addresses out. |
| `makes ECDSA keys only` / `RSA keys only` | The iLO's security state decides (no `KeyType`): choose the key type said. |
| `made no new CSR in 900 s` | The iLO is still busy - **Renew now** again later; it does not start a second CSR while one is being made. |
| The iLO serves its self-signed certificate after the reset | Another CSR was made since (by hand) or the host name changed before the import - **Renew now** makes a new one. |
| SCEP on | Switch the iLO's automatic certificate enrollment off; it blocks the import. |
