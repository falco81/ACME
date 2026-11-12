# Palo Alto Networks PAN-OS - setup for acme

acme talks to the firewall's **XML API** (`/api/`). It imports the certificate and key as a
PKCS#12 key pair named `acme-<name>-<date>-<serial>` (shared, or in a virtual system),
imports each intermediate as a certificate `acme-ca-<id>`, points the listed **SSL/TLS
service profiles** (GlobalProtect portal/gateway, admin GUI...) at the new certificate,
deletes older acme certificates beyond *Previous versions to keep* (one still referenced
stays), then **commits** and waits for the commit job to finish.

For PAN-OS firewalls (hardware and VM-Series). **Panorama is not supported**: point a
separate acme target at each firewall.

## What you need

- A PAN-OS firewall with the management interface reachable from acme over **HTTPS, TCP
  443** (or your management port).
- The SSL/TLS service profiles that should use the certificate already exist (acme sets
  their certificate, it does not create them).
- For multi-vsys firewalls: the name of the virtual system (e.g. `vsys1`), unless the
  certificate should be shared.

## Set up PAN-OS

1. Create an admin role: **Device → Admin Roles → Add**, e.g. `acme-api`:
   - **XML API** tab: enable **Configuration**, **Import**, **Commit** and **Operational
     Requests**; leave the rest disabled.
   - **Web UI** tab: enable **Device → Certificate Management** (and disable what acme
     does not need).
   - **Command Line**: None.
2. Create the admin: **Device → Administrators → Add**, e.g. `acme`, *Administrator Type*
   **Role Based**, profile `acme-api`, a strong password.
3. Commit.
4. Either let acme sign in with user and password (it calls `type=keygen` itself), or
   generate an API key once and give acme only the key:

   ```sh
   curl -k -X POST 'https://pa.example.local/api/?type=keygen' \
        --data-urlencode 'user=acme' --data-urlencode 'password=<password>'
   ```

   The `<key>` in the answer is the API key.
5. If the management interface has **Permitted IP Addresses** (*Device → Setup →
   Interfaces → Management*), add the acme server's IP.
6. Note the names of the SSL/TLS service profiles (**Device → Certificate Management →
   SSL/TLS Service Profile**).

**Commit mode matters**: with user and password acme commits only its own admin's changes
(partial commit). With an API key it sends a full commit - other admins' pending changes
go in too. Choose *do not commit* if that is not wanted.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Management name or IP, e.g. `pa.example.local` |
| HTTPS port | `443` |
| Sign in with | *an API key* or *user and password* |
| API key | The key from step 4 |
| User / Password | The `acme` admin from step 2 |
| Virtual system (advanced) | Empty for shared (*Device → Certificates*, shared), or e.g. `vsys1` |
| Check the device's certificate | On; off only while the firewall has its self-signed certificate |
| CA certificate (advanced) | The CA of the management certificate, if not a public one |
| SSL/TLS service profiles (deploy) | One a line, e.g. `gp-portal-profile`, `mgmt-ssl` |
| Commit (deploy) | *commit acme's own changes only* (default), *commit everything pending*, or *do not commit* |
| PKCS#12 kind (deploy, advanced) | *3DES (any PAN-OS)*; *AES-256* only for newer PAN-OS that accepts it |
| Wait for the commit (s) (advanced) | Default `600` |
| Previous versions to keep (advanced) | Default 2, `-1` keeps all |
| Check what is served | e.g. `gp.example.com:443` |

## Check it

- Press **Try** on the target: acme signs in and reads `type=version`, answering
  `signed in to <hostname>, <model> PAN-OS x.y.z`.
- On the firewall after a deployment:

  ```text
  show config running xpath shared/certificate
  show jobs all
  ```

  and **Device → Certificate Management → Certificates** lists `acme-...`.

## Common problems

| Problem | Fix |
|---|---|
| `PAN-OS said Invalid credentials` / code 403 | Wrong key or password, or the role lacks the XML API rights above. |
| Import refused | Role lacks XML API *Import*; or an older PAN-OS does not read the AES-256 PKCS#12 - use *3DES*. |
| `the commit failed: ...` | Read the job details shown; another admin's broken pending change makes a full commit fail - use partial commit (user + password). |
| `the commit ... has not finished in 600s` | Busy firewall: raise *Wait for the commit (s)*. |
| `the old ... stays (still used?)` | A profile or service still references it; it is deleted later once unreferenced. |
| Panorama-managed device overrides the certificate | Panorama is not supported: manage these certificates locally or outside acme. |
