# HPE Aruba Networking AOS-CX switch - setup for acme

acme installs the certificate and its key on the switch through the **AOS-CX REST API** under a dated name (`acme-<name>-<date>-<serial>`, at most 32 characters), adds each CA of the chain as a **trust anchor profile** (`acme-ca-<id>`, once), points the applications you list at it (`https-server` - the WebUI and REST API - by default), saves the configuration and deletes older acme certificates no application uses.

```text
POST   /rest/latest/login?username=...&password=...        the session cookie
POST   /rest/latest/system/pki_ta_profiles                  {"name", "certificate", "revocation_check_mode": "disabled"}
PUT    /rest/latest/certificates/<name>                     {"certificate": key + certificate + chain}
PATCH  /rest/latest/system                                  {"certificate_association": {"https-server": "<name>", ...}}
GET    /rest/latest/system?attributes=certificate_association_status
PUT    /rest/latest/fullconfigs/startup-config?from=/rest/latest/fullconfigs/running-config
DELETE /rest/latest/certificates/<older>
POST   /rest/latest/logout
```

## Which AOS-CX

**AOS-CX 10.13 - 10.18** (REST API reference v10.18; `/rest/latest` exists from 10.09). One module version.

## What acme changes

| acme option | AOS-CX | Effect |
|---|---|---|
| (always) | `crypto pki ta-profile acme-ca-<id>` | the CAs of the chain - a leaf certificate cannot be installed without the trust anchor of its issuer |
| (always) | `crypto pki certificate acme-...` | the certificate and its key |
| Use it for (deploy) | `crypto pki application <app> certificate acme-...` | `https-server`: the WebUI/REST HTTPS server takes it at once - open sessions may be cut (acme signs in again); `syslog-client`, `radsec-client`, `captive-portal`...: at the next TLS connection |
| Save the configuration | `write memory` (REST: startup-config from running-config) | kept over a reload |

The others in the association stay as they are; an application whose certificate is invalid falls back to the switch's self-signed one - acme reads `certificate_association_status` and fails when it is not `as_configured`.

## Set up the switch

```text
configure terminal
https-server vrf mgmt
https-server rest access-mode read-write
ntp server 192.0.2.123 iburst
ntp enable
user acme group administrators password plaintext <a-strong-password>
end
write memory
```

- REST writes of the PKI need the group **administrators** (a user group with CLI rules does not limit the REST API as far as the documents say - *uncertain*).
- `https-server rest access-mode read-write` is needed for any change over REST.
- The clock must be right (NTP).
- The REST login sends the password in the URL (that is how AOS-CX takes it) - acme sends it only over HTTPS and signs out at the end; keep proxies between acme and the switch from logging URLs.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | `sw01.example.com` / `443` |
| User / Password | `acme` and its password |
| REST API version (advanced) | `latest`, or one the switch lists at `/rest` (e.g. `v10.13`) |
| Check the device's certificate | on once the switch serves a certificate of your CA; off only while it has its self-signed `local-cert` |
| Use it for (deploy) | one a line: `https-server`, `syslog-client`, `captive-portal`, `radsec-client`, `hsc`, `gnmi`, `est-client`, `dot1x-supplicant` |
| Save the configuration (deploy) | on |
| Previous versions to keep (advanced) | `1` |

## Check it

On the switch:

```text
show crypto pki certificate
show crypto pki application
show crypto pki ta-profile
```

From acme's machine:

```sh
openssl s_client -connect sw01.example.com:443 -servername sw01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| `401` at signing in | wrong user or password, or too many REST sessions | the account; old sessions time out |
| `403` | the user may not write over REST | group `administrators`; `https-server rest access-mode read-write` |
| `404` at installing | this AOS-CX does not install a certificate under a new name this way | *uncertain point* - report the switch's version; install it once by hand (`crypto pki certificate <name>` / `import terminal`) |
| *... does not use ...: the switch says configured_cert_invalid* | the switch does not take the certificate (chain, key type) | the trust anchors; RSA 2048+ or ECDSA P-256/384 |

*Uncertain* (the guide marks them): whether `PUT /certificates/<name>` takes a key for a name the switch made no CSR for (the reference: the certificate "may contain a private key if it was generated outside of the switch"); whether `PATCH /system` takes `certificate_association` alone (acme sends the whole association); saving through `fullconfigs` is AOS-CX's usual call, not in the guide.

Sources: AOS-CX REST API reference v10.18 (`PUT /certificates/{name}`, `POST /system/pki_ta_profiles`, `GET /system` - `certificate_association`, `login`), AOS-CX API versioning.
