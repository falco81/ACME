# Cisco Secure Firewall Threat Defense (FDM) - setup for acme

For an FTD managed **locally by its Firepower Device Manager**. (An FTD managed by an FMC
uses the *Cisco Secure Firewall Management Center* target instead.)

acme takes a token from the **FDM REST API** (`POST /api/fdm/latest/fdm/token`,
`grant_type: password`), uploads the certificate and key as a **new Internal
Certificate** of a dated name, adds the intermediates once as External CA Certificates
`acme-ca-<id>`, then switches:

- **the management web interface** (FDM's own HTTPS and API) to it - on by default,
- **remote access VPN** gateway settings - when asked,

then **deploys** the change and waits until it is `DEPLOYED` (nothing is active before a
deployment). Older acme objects nothing names are deleted.

For FTD 6.x / 7.x with local management (FDM) and the REST API (reference v6 for FTD 7.2).

## What you need

- HTTPS access from acme to the device's management address (TCP 443) - the management
  interface or a data interface with HTTPS management access.
- The device's **admin** account: FDM takes the API only from it.
- No unfinished, undeployed changes of others in FDM when acme deploys (they would be
  deployed too).

## Set up FDM

1. In FDM: **Device → System Settings → Management Access**. On the *Management Interface*
   tab allow HTTPS from the acme server's address (or add a rule on the *Data Interfaces*
   tab for the interface acme reaches).
2. Use the **admin** account (local). Give it a strong password; acme keeps it sealed.
3. For **Remote access VPN**: the RA VPN must already be configured (**Device → Remote
   Access VPN**); acme only replaces its server certificate.
4. Deploy any pending changes yourself once, so acme's first deployment carries only its
   own change.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | The FTD management address, `443` |
| User | `admin` (FDM takes the API only from it) |
| Password | Its password |
| Check the device's certificate | On, but see below: after the switch the device serves the new certificate |
| CA certificate (advanced) | The CA of the new certificate (e.g. the ACME CA's root) once FDM uses it |
| The management web interface (deploy) | On: FDM's own HTTPS (web interface and API) uses the certificate |
| Remote access VPN (deploy) | On: the server certificate of the RA VPN gateway settings |
| Deploy the change (deploy) | On - nothing is active on the device before a deployment |
| Wait for the deployment (s) (deploy, advanced) | Default 900 |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `ftd.example.com:443` or the VPN name |

## Check it

- **Try**: `signed in to FDM ...; N internal certificates, the web interface uses <name>`.
- In FDM: **Objects → Certificates** lists `acme-...`; **Deployment** (top right) shows
  the deployment history.

  ```sh
  openssl s_client -connect ftd.example.com:443 -servername ftd.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| 400/401 on the token | Wrong password, or not the admin account |
| Connection timeout | HTTPS management access does not allow acme's address |
| TLS error after the first deployment | FDM now serves the new certificate: put its CA in *CA certificate* |
| Deployment times out or fails | See FDM's deployment history; raise *Wait for the deployment* |
| Others' pending changes deployed | Deploy or discard them in FDM before acme runs |
| The device is managed by an FMC | Use the FMC target |
