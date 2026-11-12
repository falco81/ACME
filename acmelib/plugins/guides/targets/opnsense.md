# OPNsense - setup for acme

acme signs in to the OPNsense API with an API key and secret, adds the intermediate
certificates as CAs (`/api/trust/ca/add`, named `acme-ca-<id>`), imports the certificate
and its key into **System → Trust → Certificates** as `acme-<name>-<date>-<serial>`
(`/api/trust/cert/add`, `action: import`) and deletes older acme certificates beyond
*Previous versions to keep* (one still in use stays). With *Replace in place* it writes
each renewal into the older acme certificate instead (`/api/trust/cert/set/<uuid>`), so
services you pointed at it keep it. The web GUI certificate is not in the API: with *Web
GUI certificate* acme sets it over **SSH as root** with a small PHP script and runs
`configctl webgui restart`.

For OPNsense **24.7 or later** (the trust API).

## What you need

- OPNsense 24.7 or newer.
- Network access from acme to the web GUI / API: **TCP 443** (or the port the GUI uses).
- Only for *Web GUI certificate*: SSH from acme, **TCP 22**, as `root`.

## Set up OPNsense

1. Create a dedicated user: **System → Access → Users → +**, e.g. `acme`. No shell, no
   group with full admin rights needed.
2. Give it only the privileges it needs: on the user (or a group), **Effective
   Privileges** → add **System: Certificate Manager** and, on releases that list it,
   **System: Trust**. Save.
3. Make an API key: edit the user → **API keys → +**. OPNsense downloads a file with
   `key=` and `secret=` - keep it, the secret is not shown again.
4. If you restrict GUI access (**System → Settings → Administration → Listen
   Interfaces**, firewall rules on the management interface), allow the acme server's IP
   to the GUI port.
5. Only for *Web GUI certificate*: **System → Settings → Administration → Secure Shell**
   → *Enable Secure Shell*, *Permit root user login*; then put acme's public key on root:
   **System → Access → Users → root → Authorized keys**. Prefer key sign-in over a
   password.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Name or IP of the OPNsense web GUI, e.g. `opnsense.example.local` |
| HTTPS port | `443`, or the GUI's port |
| API key | `key` from the downloaded file |
| API secret | `secret` from the downloaded file |
| Check the device's certificate | On; off only while OPNsense still has its self-signed certificate |
| CA certificate (advanced) | The CA of the GUI's current certificate, if not a public one |
| SSH port / User / Sign in with / The SSH key (advanced) | Only for the web GUI: `22`, `root`, the key whose public half is on root |
| Web GUI certificate (deploy) | On to make the web GUI use the new certificate (needs SSH) |
| Replace in place (deploy, advanced) | On if services (HAProxy, OpenVPN, captive portal...) point at the acme certificate and should keep it |
| Previous versions to keep (advanced) | Older acme certificates kept (default 2, `-1` keeps all) |
| Check what is served | e.g. `opnsense.example.local:443` |

## Check it

- Press **Try** on the target: acme reads the version (`/api/core/firmware/info`) and the
  certificate list; it answers `signed in to ..., OPNsense x.y, N certificates`.
- After a deployment, the certificate is in **System → Trust → Certificates**, the
  intermediates in **System → Trust → Authorities**.
- On the box (SSH) the GUI's certificate reference:

  ```sh
  grep -A3 '<webgui>' /conf/config.xml | grep ssl-certref
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` on Try | Wrong key or secret, or the user lacks *System: Certificate Manager* / *System: Trust*. If only the version read is refused, check which privilege covers `core/firmware` on your release. |
| `404` on `/api/trust/...` | OPNsense older than 24.7 - update. |
| TLS error | The GUI still has its self-signed certificate: add its CA under *CA certificate* or switch *Check the device's certificate* off until the first deployment. |
| `the web GUI is set over SSH` | *Web GUI certificate* is on but the SSH sign-in is empty. |
| `the old ... stays (still used?)` | A service still uses the older certificate ("Item in use by"); move the service or use *Replace in place*. |
| Service still serves the old certificate after *Replace in place* | Services read it again only when restarted - restart them in OPNsense. |
