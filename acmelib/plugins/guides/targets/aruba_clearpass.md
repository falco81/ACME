# HPE Aruba Networking ClearPass Policy Manager - setup for acme

acme replaces the **server certificates of one ClearPass server** - HTTPS(RSA), HTTPS(ECC), RADIUS (EAP), RadSec - through the ClearPass REST API. ClearPass takes a server certificate only **from a URL it downloads it from** (`pkcs12_file_url`), so acme needs a **staging web server** of yours: it writes the PKCS#12 there over SSH under a random name, has ClearPass fetch it, and deletes it again at once.

```text
POST /api/oauth                       {"grant_type": "client_credentials", "client_id", "client_secret"}
GET  /api/cluster/server              the server UUID of the server named in acme
POST /api/cert-trust-list             {"cert_file": <a CA of the chain, PEM>, "enabled": true, "cert_usage": [...]}
(ssh) <directory>/acme-<random>.p12   on the staging web server
PUT  /api/server-cert/name/<server_uuid>/<HTTPS(RSA)|HTTPS(ECC)|RADIUS|RadSec>
     {"pkcs12_file_url": "<its URL>/acme-<random>.p12", "pkcs12_passphrase": "<one-time>"}
(ssh) rm -f <directory>/acme-<random>.p12
```

## Which ClearPass

**ClearPass 6.12 - 6.14** (API reference 6.14.1, Aruba's SDK `pyclearpass`). One module version.

## What happens on ClearPass

| Service | Effect of the change |
|---|---|
| HTTPS(RSA) / HTTPS(ECC) | the web server of that server restarts: the admin pages, Guest/Onboard portals and the API are away for a moment. HTTPS(ECC) needs an ECDSA certificate. |
| RADIUS | the RADIUS service restarts: authentications pause for a moment (NADs fail over to another RADIUS server). **Supplicants must trust the new CA and name** - else PEAP/EAP-TLS fails; push a new CA to the clients (GPO/MDM) first. |
| RadSec | RadSec clients (APs, gateways) connect again with the new certificate |

The chain must be in the **Certificate Trust List** before the import - acme adds each CA of the chain there first (one there already is refused and left). Certificates are **per server**: one target per server of the cluster (subscribers first, the publisher last); for RADIUS give every server the same certificate, so clients roaming between them see no change.

## Set up ClearPass

1. **An operator profile with API access**: *Administration → Operator Logins → Profiles* - copy one, keep **API Services: Allow API Access**, and in Policy Manager / Platform only **Certificates** (read, write) and **Server Configuration** (read) - *uncertain*: the exact names of these rights; the built-in *Super Administrator* works but is not least privilege.
2. **An API client**: *Administration → API Services → API Clients → Create API Client* (in the Guest module) - *Client ID* `acme`, *Operating Mode* ClearPass REST API, *Operator Profile* of step 1, *Grant Type* **Client credentials**, an access token lifetime of e.g. 8 hours. Copy the client secret (it is shown once).
3. **The staging web server**: any HTTPS (or HTTP) server ClearPass reaches, with a directory it serves and acme may write to over SSH, e.g.:

```sh
sudo useradd -m acme
sudo install -d -o acme -g www-data -m 0755 /var/www/cppm-drop
# then put acme's SSH public key (the key card of the target) into ~acme/.ssh/authorized_keys
```

   Let only ClearPass's addresses reach that directory (an `allow` / `deny` of the web server); with HTTPS ClearPass must trust its certificate. The file lives there for a few seconds, under a 32-character random name, protected by a one-time passphrase.

4. Try the token from acme's machine:

```sh
curl -s -X POST https://cppm.example.com/api/oauth -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"acme","client_secret":"<secret>"}'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the publisher (or the server itself), e.g. `cppm.example.com` / `443` |
| API client ID / Client secret | from step 2 |
| Server | the server whose certificates these are: its name, FQDN, IP address or server UUID (*Administration → Server Manager → Server Configuration*) |
| Staging web server, SSH port, SSH user, Sign in with, The SSH key / SSH password | the server of step 3 and how acme signs in to it |
| Directory / Its URL | e.g. `/var/www/cppm-drop` and `https://files.example.com/cppm-drop` |
| Use it for (deploy) | one a line: `HTTPS(RSA)`, `HTTPS(ECC)`, `RADIUS`, `RadSec` |
| Add the CAs to the trust list / Trust list usage (advanced) | on; `EAP` and `Others` (or as you use the CA) |

## Check it

```sh
openssl s_client -connect cppm01.example.com:443 -servername cppm01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect cppm01.example.com:2083 -showcerts </dev/null | openssl x509 -noout -subject -dates
curl -s -H "Authorization: Bearer $TOKEN" https://cppm.example.com/api/server-cert/name/<server_uuid>/RADIUS
```

In the GUI: *Administration → Certificates → Certificate Store*. RADIUS: a test authentication in *Monitoring → Live Monitoring → Access Tracker*.

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| `401` / `invalid_client` at signing in | wrong client ID or secret, wrong grant type | step 2 |
| `403` | the operator profile has no API access or no right to the certificates | step 1 |
| *ClearPass has no server ...* | the name is not one of `/api/cluster/server` | the name, FQDN, IP or UUID it lists |
| `422` / a chain error at the replacement | the CA chain is not trusted, or the key does not fit | the trust list (*Administration → Certificates → Trust List*), the usage |
| ClearPass cannot download the file | it does not reach the staging URL or does not trust its certificate | the URL from ClearPass's network; its CA into the trust list |
| *the staged file ... stays* | acme could not delete it | delete it by hand at once |

*Uncertain*: whether `cert_file` of the trust list is the PEM itself (the reference says only "Certificate trust list file"); the restarts after an import were not in the documents the guide could read.

Sources: ClearPass Policy Manager API reference 6.14.1 (`PUT /server-cert/name/{server_uuid}/{service_name}`, `POST /cert-trust-list`, `POST /oauth`), the developer docs (ClearPass configuration, OAuth2), Aruba's `pyclearpass` (`api_platformcertificates.py`, `common.py`).
