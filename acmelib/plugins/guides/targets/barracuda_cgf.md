# Barracuda CloudGen Firewall - setup for acme

acme talks to the **REST API** of a CloudGen Firewall (stand-alone box) or of a **Firewall Control Center** (HTTPS, port 8443) and imports the certificate, its chain and its key into **one Certificate Store entry, in place**:

```text
PUT /rest/config/v1/box/store/certificates/<entry>
{"action": "import", "certificates": "<leaf + intermediates, PEM>", "key": "<PEM>", "comment": "acme ..."}
```

The services that use the entry (SSL VPN / CudaLaunch, TLS Inspection inbound, Access Control Service, Mail Security...) refer to it by its name, so they keep it - Barracuda: *"References to this key and certificate will be updated automatically"*. acme then reads the entry back and checks that it holds the new certificate (by its SHA-256 fingerprint). Nothing is deleted: there is one entry, renewed in place.

## Which versions

CloudGen Firewall / Control Center **10.0 and 10.5** (the same calls; the Swagger *Box configuration - 10.5 / 10.0* and *CC Configuration - 10.5*). **9.0** has only `GET /rest/config/v1/box/certificates` (read-only): acme says so and changes nothing - on 9.0 import the certificate in Firewall Admin.

A firewall managed by a Control Center **has no store of its own**: point acme at the Control Center and choose its global, range or cluster store (a range / cluster needs *Own certificate store Settings: Yes*).

## 1. Turn on the REST API

*CONFIGURATION > Configuration Tree > Box > Infrastructure Services > REST API Service* → **Lock**:

- **Enable HTTPS interface**: yes, **HTTPS Port** 8443 (default);
- **Bind to Management IPs**: yes (otherwise it listens on the loopback only);
- **New Key** / **Ex/import**: the certificate of the REST interface itself - its CN must be the name acme uses (e.g. `cgf1.example.local` for `https://cgf1.example.local:8443`); this certificate can be changed only in Firewall Admin, not over REST;
- **Send Changes** → **Activate**.

Allow TCP 8443 from acme's address in the firewall rules. The HTTP interface (8080) listens on 127.0.0.1 only - acme uses HTTPS.

## 2. The account acme uses

**Stand-alone box**: *Box > Administrators* → **Lock** → **+** - role **Manager** (writing into the configuration, the Certificate Store too; the roles are not finer than that), *System Level Access* **No OS Login**, *Authentication Level* Password, *Peer IP Restriction* = acme's address. The same over REST (with an existing admin's token):

```sh
curl -s -X POST "https://cgf1.example.local:8443/rest/config/v1/box/admins" \
  -H "X-API-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"svc-acme","fullName":"acme certificates","password":"<password>","roles":["Manager"],
       "systemLevelAccess":"noOsLogin","authenticationLevel":"password","peerIpRestriction":["192.0.2.10"]}'
```

The **API token** for it (*REST API Service* → **Access Tokens** → **+** → Name → **Generate new token** → Admin name `svc-acme`, Time to live up to 365 days), or over REST:

```sh
curl -s -X POST "https://cgf1.example.local:8443/rest/config/v1/box/admins/svc-acme/tokens" \
  -H "X-API-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"name":"acme","ttl":365}'
```

The token lives a year at most - put a reminder for renewing it.

**Control Center**: *Multi-Range > Global Settings > Administrative Roles* → **Lock** → a role with **Access to REST API** and **Write Access** → **Send Changes** → **Activate**; *ADMINS* → **+ New Admin** (Authentication Level Password, an ACL with acme's address), *Administrator Scopes*: the smallest scope (Global, the range or the cluster), *Configuration Level* ≤ 2 (write), the role above, *Shell Level* **No**. acme signs in with this admin's name and password (HTTP basic), or a token.

## 3. The Certificate Store entry

Use the entry your services already point at (e.g. `vpn-portal` selected as the SSL VPN *External-Certificate*). With *Make the entry when it is not there* (on by default) acme creates a missing entry as a self-signed placeholder and imports over it at once; then point the service at it **once** in Firewall Admin (selecting an entry for a service is not in the REST API) and **Activate**.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the box or the Control Center, `8443` |
| Sign in with | *an API token* (X-API-Token) or *an administrator and password* |
| API token / User, Password | from step 2 |
| Certificate Store | *of this firewall*, or *Control Center: global / a range / a cluster* |
| Range / Cluster | e.g. `1` and `prague` (as in `/rest/cc/v1/config/ranges/1/clusters/prague/...`) |
| Check the device's certificate | on, with *CA certificate* when the REST interface's certificate is from a private CA |
| Certificate Store entry (deploy) | the entry name, e.g. `vpn-portal` |
| Key as (deploy, advanced) | PKCS#8; *traditional* only if the box refuses it |
| Check what is served (deploy) | where a service shows it, e.g. `vpn.example.com:443` |

## What then

- **SSL VPN / CudaLaunch**: Barracuda restarts the service only when its settings change. If the portal still shows the old certificate, restart it in Firewall Admin: *VPN-Service > SSL-VPN* → **Enable SSL VPN** = no → **Activate** → yes → **Activate** (short break of the SSL VPN sessions).
- **TLS Inspection inbound**: the server certificate there must be the one the real server has - deploy the same certificate to both.
- **HA**: a cluster synchronises the configuration; change it on the Control Center or the primary.
- A box managed by a Control Center refuses changes made on the box itself - use the Control Center store.

## Check it

```sh
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -s "https://cgf1.example.local:8443/rest/config/v1/box/store/certificates/vpn-portal" \
  -H "X-API-Token: $TOKEN"
```

In Firewall Admin: the Certificate Store columns **Expires**, **Has Key**, **Referenced by**; double-click → Certification Path.

## Common problems

| Answer | Meaning | Fix |
|---|---|---|
| *no Certificate Store endpoints ... 10.0 or later* | a 9.0 box | upgrade, or import in Firewall Admin |
| `401` / `403` | token expired or wrong, admin without Manager role / REST write access, peer IP restriction | a new token; the role; acme's address |
| `404` on the store of a range / cluster | wrong range or cluster, or no own store there | check the names; *Own certificate store Settings: Yes* |
| *does not hold the new certificate after the import* | the change waits to be activated (*unverified*: whether store changes are activated at once) | **Activate** in Firewall Admin and deploy again |
| refused key | an encrypted key or an unusual format | *Key as: traditional* |

*Unverified* (from the vendor guide): whether a store change is active without Activate, whether `PUT ... action=import` can make a missing entry (acme makes it first), the place of the fingerprint in the answer.
