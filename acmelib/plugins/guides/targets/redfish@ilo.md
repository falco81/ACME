# HPE iLO 5 / 6 / 7 (Redfish, HpeHttpsCert) - setup for acme

acme puts the certificate **and its private key** on the iLO the way HPE documents it: it
signs in to Redfish with a session (`POST /redfish/v1/SessionService/Sessions/`,
`X-Auth-Token`), reads the manager's firmware and the security state, sets the key type
of the iLO certificate (`PATCH .../SecurityService/HttpsCert/ {"KeyType": "RSA" | "ECDSA"}`)
when it says another, and posts the certificate followed by the key to
`HpeHttpsCert.ImportCertificate` (the *sideload*). **The iLO then resets itself** - web
GUI, Redfish, remote console and virtual media are away for 1-3 minutes; **the server and
its operating system are not touched**. acme's test of what is served waits for it.

## Which iLO this version is for

Module version **"HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7"** (`ilo`):

| iLO | Firmware | Key type (`KeyType`) | An RSA key only in the security state |
|---|---|---|---|
| iLO 5 (Gen10, Gen10 Plus) | 2.78 and later | not there - nothing set | (not documented - not checked) |
| iLO 6 (Gen11) | 1.30 and later | 1.70 and later - set to match | **Production** |
| iLO 7 (Gen12) | any (checked to 1.25) | 1.17 and later - set to match | **SecureStandard** |

The calls are the same on all three, so this is one version. acme refuses **before
changing anything** on an iLO 4, an iLO 5 older than 2.78, an iLO 6 older than 1.30, a
controller that is not an iLO (choose the plain *Redfish* version for those), and an RSA
key on an iLO 6/7 in another security state (HighSecurity, FIPS, CNSA: use an ECDSA key
type - iLO's own CSRs there are ECDSA P-384).

Why not the plain Redfish version: HPE gives the iLO web server certificate only through
its own `HpeHttpsCert` resource; iLO 6 has no DMTF `ReplaceCertificate` for it.

## What you need

- Network access from acme to the iLO: **TCP 443** (Redfish is always on in iLO).
- An iLO account with **Login** and **Configure iLO Settings** (`LoginPriv`,
  `iLOConfigPriv`). The role *Operator* is **not** enough (it lacks `iLOConfigPriv`).
- The iLO host name and domain set to the name in the certificate (*iLO Dedicated
  Network Port → General*), and NTP set.
- Automatic certificate enrollment (SCEP, iLO 5/6) **off**: while it is on, iLO blocks a
  manual import.

## Set up the iLO

Create a service account with only Login + Configure iLO Settings. With iLOrest
(privilege 1 = Login, 4 = Configure iLO Settings):

```sh
ilorest login ilo01.example.com -u Administrator -p '<admin-password>'
ilorest iloaccounts add acme "acme certificate manager" '<strong-password>' --addprivs 1,4
ilorest logout
```

Or with Redfish (note: in Redfish `UserName` is the login name and `Oem.Hpe.LoginName`
the display name - the other way round than in the web GUI):

```sh
curl -k -X POST "https://ilo01.example.com/redfish/v1/AccountService/Accounts/" \
  -u 'Administrator:<admin-password>' -H "Content-Type: application/json" \
  -d '{"UserName": "acme", "Password": "<strong-password>",
       "Oem": {"Hpe": {"LoginName": "acme certificate manager",
                       "Privileges": {"LoginPriv": true, "iLOConfigPriv": true}}}}'
```

iLO computes the role when it is read: an account with `iLOConfigPriv` is **shown as
"Administrator"** although it has only these two privileges - that is documented, not an
error.

Check the firmware and the security state:

```sh
curl -sk -u acme:'<password>' https://ilo01.example.com/redfish/v1/Managers/1/ | jq .FirmwareVersion
curl -sk -u acme:'<password>' https://ilo01.example.com/redfish/v1/Managers/1/SecurityService/ | jq .SecurityState
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7** |
| Address | the iLO's name or IP, e.g. `ilo01.example.com` |
| HTTPS port | `443` |
| User / Password | the `acme` account from above |
| Basic authentication instead of a session (advanced) | off (only when sessions do not work) |
| Check the device's certificate | on; off only while the iLO still has its self-signed certificate (typical before the first deployment) |
| CA certificate (advanced) | the CA of the iLO's current certificate, if not public |
| Check what is served (deploy) | empty: acme checks the iLO's own address |

The certificate itself: an **ECDSA** key type works in every security state; **RSA**
(2048, 3072, 4096) only in *Production* (iLO 6) / *SecureStandard* (iLO 7). The name
the iLO is reached by must be in the certificate.

## Check it

- Press **Try** on the target: `signed in to ...: iLO 6 firmware 1.62, security state
  Production, certificate CN=..., until ...`.
- After a deployment (wait for the reset):

```sh
openssl s_client -connect ilo01.example.com:443 -servername ilo01.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sk -u acme:'<password>' "https://ilo01.example.com/redfish/v1/Managers/1/SecurityService/HttpsCert/" \
  | jq .X509CertificateInformation
```

The iLO *Security Log* (Information → Security Log) records each import and its errors.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | wrong user or password, or the account is disabled |
| `403` on the import | the account lacks *Configure iLO Settings* (`iLOConfigPriv`) |
| `400 ImportCertificateFailed` | the key type does not match (acme sets `KeyType` first - see the Security Log), or the key is RSA in a high security state |
| *it takes a private key from 2.78 / 1.30* | update the iLO firmware |
| *is not an HPE iLO* | the controller is not an iLO: choose the plain *Redfish* version |
| *takes an RSA key only in Production / SecureStandard* | choose an ECDSA key type for the certificate, or change the security state (a change wipes the security content) |
| import refused while SCEP is on | turn automatic certificate enrollment off (iLO 5/6) |
| the test of what is served fails at first | the iLO resets after the import (1-3 minutes); acme's test waits up to five minutes |
| OneView says the iLO certificate is not trusted | put the issuing CA into OneView's trust store (`/rest/certificates/ca`) - see the *HPE OneView* target |

*Uncertain*: on iLO 5 the sideload is documented "through iLOrest" (which posts this very
action) and whether iLO 5 limits RSA keys by security state is not documented; whether
iLO accepts the intermediates after the certificate is not documented - acme sends the
certificate and the key, as HPE's example does.

Sources: HPE iLO security service (Redfish supplement), iLO 5 SSL certificate
(ilo-rest-api-docs), iLO 6 1.74 and iLO 7 1.23 resource definitions (`HpeHttpsCert`,
`KeyType`), iLO 7 changelog and *Adapting from iLO 6*, *Managing iLO users*.
