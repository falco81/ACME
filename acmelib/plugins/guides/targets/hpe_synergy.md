# HPE Synergy Composer / OneView - key made by the device - setup for acme

This target is for certificates whose **key stays on the device**: acme asks HPE OneView (on
a Synergy Composer, or the OneView VM) for a **new key and CSR** at every issue and renewal,
has the CSR signed by the certificate's source and puts the signed certificate back right
away. acme holds no key. One target (the sign-in to OneView) serves two kinds of
certificate - each deployment says which:

- **the appliance** - the HTTPS certificate of the Composer / OneView itself (GUI, REST API,
  and the HPE SSO certificate OneView passes on to the managed iLOs and frames).
  `POST /rest/certificates/https/certificaterequest`, then `PUT` of the signed certificate.
  The appliance makes **RSA 2048**, or **RSA 3072** for CNSA (key type `rsa-3072`).
- **an enclosure's management module** - a Synergy frame's **Frame Link Module** bay or a
  c7000's **Onboard Administrator** bay, which take no key at all, only a certificate for their
  own CSR: `POST /rest/enclosures/{id}/https/certificaterequest?bayNumber=N`, then `PUT`.
  **One name** only (the common name - OneView's enclosure CSR carries no other names: acme puts
  the certificate's name there, whatever the profile's CN), **RSA 2048** only (the enclosure's
  CSR asks for no key size), bay `1` or `2`.

Versions: HPE OneView for Synergy and OneView **9.x - 11.x** (REST API 6600 - 9200); acme sends
the API version the appliance says it takes. To put a key of acme's on the appliance instead,
use the target **HPE OneView / Synergy Composer**.

## What you need

- From acme to the Composer's appliance address (not a Composer module's own IP): **TCP 443**.
- A OneView account with the role **Infrastructure administrator** (no scope) - the appliance
  certificate and the enclosures' certificates are appliance settings.
- A source that signs a CSR made elsewhere - an ACME CA (DNS-01 validation for the names),
  acme's own authority, a commercial CA. Not *Self-signed*, CMP or SCEP.

## Set up OneView

1. A service account (as an administrator, `$OVAUTH` the session of `POST /rest/login-sessions`):

   ```sh
   curl -k -X POST "https://composer.example.local/rest/users" \
     -H "X-API-Version: 9200" -H "Auth: $OVAUTH" -H "Content-Type: application/json" \
     -d '{"type":"UserAndPermissions","userName":"svc-acme","password":"<password>","enabled":true,
          "permissions":[{"roleName":"Infrastructure administrator"}]}'
   ```

   Or in the GUI: **Settings → Users and Groups → Add**, role *Infrastructure administrator*.
   A directory (LDAP / AD) account with that role works too - give its login domain in acme.
2. Nothing to switch on: the REST API is always there on 443.
3. The appliance's names: its FQDN (and the IP if users reach it by it) - all go into the CSR's
   alternative names. For a frame: the DNS name the Frame Link Module bay is reached by.

## Fill in acme

The target (**Targets → Add → HPE Synergy Composer / OneView - key made by the device**):

| acme field | What to put there |
|---|---|
| Address | The appliance's FQDN, e.g. `composer.example.local` |
| HTTPS port | `443` |
| User / Password | `svc-acme` from step 1 |
| Login domain | `LOCAL`, or the directory's login domain |
| Country (C), State or region (ST), City (L), Organization (O) | What every CSR carries (OneView asks for them); the certificate's own subject (its profile) wins |
| Unit (OU), E-mail in the CSR | Optional |
| Check the device's certificate | Off while the appliance still has its self-signed certificate |

Then each certificate: **Add a certificate → Key → Key made by the device → pick this
target**. acme makes its deployment to the target; set the deployment's options:

| Option | Appliance | Enclosure |
|---|---|---|
| Certificate of | *the appliance* | *an enclosure's management module* |
| Enclosure | - | its name in OneView (`Frame1`) or `/rest/enclosures/<id>` |
| Bay | - | `1` or `2` (the Frame Link Module / OA bay) |
| Put the intermediates into the trust store | on (HPE wants the issuing CA there first) | - |
| Check what is served | - | `flm1.example.local:443` - acme cannot know the module's address |

From the command line:

```sh
acme --cert-add composer --names composer.example.local,10.0.0.20 --key-type rsa-2048 --issuer "Own CA" --csr-from synergy
acme --renew composer
```

## Check it

- **Test** on the target signs in, reads the appliance certificate and lists the enclosures -
  nothing is changed.
- **Renew now** on the certificate: the job says *the key and the CSR are made by the device*,
  the issue, then the import task. The appliance reloads its web services (sessions are cut,
  servers and the data path are not touched):

  ```sh
  openssl s_client -connect composer.example.local:443 -servername composer.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -k -s "https://composer.example.local/rest/certificates/https" -H "X-API-Version: 9200" -H "Auth: $OVAUTH"
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user, password or login domain. |
| `403` on the CSR or the import | The account is not *Infrastructure administrator* (or is scoped). |
| `OneView asks for country, ...` | Fill in Country, State, City and Organization on the target. |
| `an enclosure's CSR has one name` | Give the frame's certificate one DNS name. |
| `OneView has no enclosure named ...` | Use the name shown in **Enclosures**, or the enclosure's URI. |
| The import task ends `invalid certificate` | The issuing CA is not in the trust store (leave *Put the intermediates into the trust store* on), or another CSR was made since (by hand in the GUI) - **Renew now** makes a new one. |
| Only RSA | The appliance makes RSA keys only: key type `rsa-2048` (`rsa-3072` for CNSA). |
| `an enclosure's management module makes RSA 2048 keys only` | Choose key type `rsa-2048` for an enclosure's certificate - refused before the bay is asked. |
| `the bay is 1 or 2` | Give the bay of the Frame Link Module / Onboard Administrator: `1` or `2`. |
| Deployments held | The device keeps its old certificate; the next issue asks for a new key and CSR. |

The enclosure call is documented by HPE's SDK for the Onboard Administrator; on a Synergy
frame's Frame Link Module it is OneView's same call (not tried on a frame by acme) - try it
on one bay first.
