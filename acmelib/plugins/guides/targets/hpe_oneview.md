# HPE OneView / Synergy Composer - setup for acme

acme replaces the **appliance's HTTPS certificate** - the web GUI, the REST API and the HPE
SSO into the managed iLOs and OAs - of an HPE OneView VM appliance or an HPE Synergy
Composer (HPE OneView for Synergy) with its own key and certificate. Through the REST API
it:

1. reads the API version the appliance takes (`GET /rest/version`, `currentVersion`; acme
   sends at most `9200` = OneView 11.50, the newest it was checked against) and signs in
   (`POST /rest/login-sessions`, the `sessionID` in the `Auth` header);
2. puts each intermediate CA into the appliance's trust store
   (`POST /rest/certificates/ca`, alias `acme-<id>`; one there already is skipped) - HPE
   wants the issuing CA there **before** the appliance certificate;
3. uploads the key and certificate as **PKCS#12** with a one-time password
   (`PUT /rest/certificates/https/pkcs12`, multipart `file`, header `Password`) and waits
   for the import task (`/rest/tasks/<id>`);
4. signs out.

The appliance then **reloads its web services**: signed-in GUI and API sessions are cut
(the VM is not restarted, the managed servers are not touched) and the new SSO
certificate goes to the managed iLOs/OAs within the same task.

**RSA keys only** - HPE: "only RSA certificates are supported for the appliance
certificate" (2048; 3072 in the CNSA security mode). acme refuses an ECDSA certificate
before changing anything.

## Which versions

One module for **HPE OneView 9.x, 10.x and 11.x** (REST API 6600 - 9200) on the VM
appliance and on **Synergy Composer / Composer2 / Composer3**: the `/rest/certificates`
calls are the same in all of them (HPE's SDKs list no change). An older appliance is
warned about, not refused. HPE Compute Ops Management has no API for these certificates -
change an iLO's certificate on the iLO (the *HPE iLO* version of the Redfish target).

## What you need

- Network access from acme to the appliance: **TCP 443**, the appliance's (virtual) IP
  or FQDN - on a Composer pair the appliance address, not a module's own.
- A OneView user with the role **Infrastructure administrator** and no scope (the
  appliance certificate and the trust store are appliance settings).
- The appliance's host name and DNS (*Settings → Appliance → Network*) matching the
  certificate, and NTP.

## Set up OneView

Create a local service account (as an administrator; `9200` is OneView 11.50 - use what
`GET /rest/version` says):

```sh
OV=https://oneview.example.com
AUTH=$(curl -sk -X POST "$OV/rest/login-sessions" -H "X-API-Version: 9200" \
  -H "Content-Type: application/json" \
  -d '{"userName":"administrator","password":"<admin-password>","authLoginDomain":"LOCAL","loginMsgAck":true}' \
  | jq -r .sessionID)

curl -sk -X POST "$OV/rest/users" -H "X-API-Version: 9200" -H "Auth: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"type": "UserAndPermissions", "userName": "svc-acme", "fullName": "acme certificate manager",
       "password": "<strong-password>", "enabled": true, "emailAddress": "pki@example.com",
       "permissions": [{"roleName": "Infrastructure administrator"}]}'
```

In the GUI: *Settings → Users and Groups → Add user*, role *Infrastructure administrator*.
A directory account works too: give its login domain in acme.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the appliance's FQDN, e.g. `oneview.example.com` |
| HTTPS port | `443` |
| User / Password | `svc-acme` from above |
| Login domain | `LOCAL`, or the name of the directory login domain |
| API version (advanced) | empty: what the appliance says (at most 9200); or e.g. `7600` |
| Check the device's certificate | on; off only while the appliance still has its self-signed certificate |
| CA certificate (advanced) | the CA of the appliance's current certificate, if not public |
| Put the intermediates into the trust store (deploy) | on (recommended by HPE) |
| Wait for the import task (s) (deploy, advanced) | `300` |
| Check what is served (deploy) | empty: acme checks the appliance's own address |

The certificate: an **RSA** key type; the appliance's FQDN (and the names/IPs users and
the managed devices reach it by) in the certificate.

## Check it

```sh
openssl s_client -connect oneview.example.com:443 -servername oneview.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sk "https://oneview.example.com/rest/certificates/https" -H "X-API-Version: 9200" -H "Auth: $AUTH" | jq .
curl -sk "https://oneview.example.com/rest/certificates/ca" -H "X-API-Version: 9200" -H "Auth: $AUTH" \
  -H "If-Req-CertDetails: true" | jq '.members[].certificateDetails | {aliasName, commonName, validUntil}'
```

PowerShell (`HPEOneView.1000`): `Get-OVApplianceCertificateStatus`,
`Get-OVApplianceTrustedCertificate`.

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | wrong user, password or login domain |
| `403` | the user is not an *Infrastructure administrator*, or has a scope |
| `400` on `X-API-Version` | set *API version* to one the appliance takes (`GET /rest/version`) |
| *only an RSA certificate* | choose an RSA key type for the certificate |
| the import task ends with "invalid certificate" | the issuing CA is missing from the trust store - leave *Put the intermediates into the trust store* on, or add the root CA by hand |
| *the end of the certificate import could not be read* | the web services reloaded while acme was asking; the test of what is served tells whether it worked |
| managed devices untrusted after a CA change | the trust store must keep the CAs of the managed devices' certificates |

*Uncertain*: the least role for the appliance certificate is not stated by HPE
(Infrastructure administrator assumed); the `Password` / `uploadfilename` headers of the
PKCS#12 upload come from HPE's PowerShell module, not from the API reference.

Sources: HPE POSH-HPEOneView 10.00 (`Install-OVApplianceCertificate`,
`Add-OVApplianceTrustedCertificate`, `Get-OVApplianceCertificateStatus`), HPE
oneview-python (`/rest/login-sessions`, `endpoints-support.md`, API versions), HPE
oneview-ansible-collection 11.5.0.
