# Check Point (Management API) - setup for acme

acme signs in to the Security Management Server (or a Multi-Domain Server domain) through
the **Management API** (`/web_api/login`, user and password or an API key). It imports
the certificate as a **server certificate** (PKCS#12, base64) under a dated name - or into
one object you name, replaced in place - then, as you ask:

- points **HTTPS Inspection** inbound rules at it (`set-https-rule`),
- gives it to the **portals** of a gateway or cluster (Gaia platform portal, UserCheck,
  Identity Awareness captive portal, SAML portal of the VPN),
- deletes older acme objects `where-used` finds unused,
- **publishes** the session and, when a policy package is set, **installs** its Access
  Control policy. On a failure before publishing the session is discarded. acme always
  logs out.

For R80.40 and later (Management API v1.6+; the SAML portal needs v2.1 / R82.10).

## What you need

- The management server's address, **HTTPS 443** reachable from acme (on a Gaia server
  that also runs a gateway or with a non-default port, use that port).
- The Management API enabled and accepting calls from acme's IP.
- An administrator with the permissions below.

## Set up Check Point

1. Allow API calls from acme: **SmartConsole → Manage & Settings → Blades → Management API
   → Advanced Settings → Accept API calls from**: *All IP addresses that can be used for
   GUI clients* (and add acme's IP to the GUI clients / Trusted Clients) or *All IP
   addresses*. **Publish**, then on the management server (expert mode):

   ```sh
   api restart
   api status
   ```

2. Create a permission profile (**Manage & Settings → Permissions & Administrators →
   Permission Profiles → New**), type *Customized*, with write (*Edit*) on what the
   deployments use:
   - **Gateways** objects (server certificates are objects; the portals are gateway
     settings),
   - **HTTPS Inspection** policy (only if you point rules),
   - **Install Policy** (only if acme installs a package).
   Names of the permission items differ between versions - check them on yours.
3. Create the administrator (**Permissions & Administrators → Administrators → New**)
   with that profile; *Authentication Method*: **API Key** (recommended) or *Check Point
   Password*. With `mgmt_cli` on the server:

   ```sh
   mgmt_cli -r true add administrator name "acme" permissions-profile "acme-certs" authentication-method "api key"
   mgmt_cli -r true add api-key admin-name "acme"
   mgmt_cli -r true publish
   ```

   The second command prints the API key once - copy it into acme.
4. Note the names: HTTPS Inspection layer and rules, gateway/cluster object, policy
   package.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | Management server, e.g. `mgmt.example.local` / `443` |
| Sign in with | `a user and password` or `an API key` |
| User / Password | The administrator (password way) |
| API key | The key from step 3 |
| Domain (advanced) | Multi-Domain Server: the domain name or UID; empty: the default |
| API version (advanced) | Empty: the newest; `v1.6` or later needed |
| Check the device's certificate / CA certificate | As for every HTTPS device |
| Server certificate object (deploy) | Empty: a new dated object each time; a name: that one object, replaced in place |
| HTTPS Inspection rule / More HTTPS Inspection rules / HTTPS Inspection layer (deploy) | The inbound rule(s) and their layer, e.g. `Default Layer` |
| Gateway or cluster (portals) / It is (deploy) | The gateway object and whether it is a gateway or cluster |
| Gaia platform portal / UserCheck portal / Identity Awareness captive portal / SAML portal of the VPN (deploy) | Which portals get the certificate |
| Install the policy package / Install on (deploy) | The package to install after publishing, and its gateways (empty: its targets) |
| PKCS#12 encryption (deploy, advanced) | `3DES` (every version) or `AES-256` |
| Wait for publish and install (s) (deploy, advanced) | Default 900 |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try** signs in read-only: `signed in to ..., Management API 1.9; N server certificates`.
- **List the server certificates** lists them and the HTTPS rules - read-only.
- On the server:

  ```sh
  mgmt_cli -r true show server-certificates --format json
  ```

## Common problems

| Problem | Fix |
|---|---|
| Login 403 / "API server not accessible from this IP" | Allow acme's IP in *Accept API calls from*, publish and `api restart` |
| `wrong credentials` / invalid API key | Wrong key or the administrator is locked |
| Permission errors on add / set / publish | The permission profile lacks write on objects or HTTPS Inspection |
| Install fails | The profile lacks *Install Policy*, or the package/targets are wrong - see SmartConsole → Tasks |
| Object locked by another session | Someone has unpublished changes on the same object - publish or discard them |
| Publish waits too long | Raise *Wait for publish and install* |
