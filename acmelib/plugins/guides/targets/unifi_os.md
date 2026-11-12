# UniFi OS console - setup for acme

acme signs in to the console (`POST /api/auth/login`) and uses its own certificate API -
the one behind **Settings → Control Plane → Console → Certificates**: it adds the
certificate (full chain + key) under a dated name `acme-<name>-<date>-<serial>`
(`/api/userCertificates`), makes it the **active** certificate
(`PUT /api/userCertificates/<id>/status`), and deletes older acme certificates beyond
*Previous versions to keep*. Nothing is written on the console's disk; the console reloads
its web server itself.

For UniFi OS consoles with custom certificate support (**UniFi OS 4.2 and later**,
reported working on 4.x and 5.x): UDM, UDM Pro / SE, UCG, UDR, Cloud Key Gen2+ and UniFi OS
Server. The API is the console's own (what acme.sh uses), not a documented public API.
For a self-hosted UniFi Network application use the *Linux / Unix server* target with the
*UniFi Network* preset instead.

## What you need

- UniFi OS 4.2 or later.
- Network access from acme to the console: **TCP 443**.
- A **local** console admin **without two-factor sign-in** (a UI.com / SSO account with
  2FA cannot be used).

## Set up the console

1. Create a local admin for acme: **UniFi OS → Settings → Admins & Users → Create New
   Admin** (wording varies by version): choose **Restrict to Local Access Only**, user name
   `acme`, a strong password.
2. Give it a role that may change the console's settings (certificates are a console
   setting - a full admin / Super Admin role; a restricted role may be refused - check with
   **Try**). It needs no application (Network, Protect...) permissions.
3. Make sure acme can reach the console's HTTPS port (firewall / traffic rules on the
   management network).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The console's name or IP, e.g. `unifi.example.local` |
| HTTPS port | `443` |
| User | `acme` (default) - the local admin |
| Password | Its password |
| Check the device's certificate | On; off only while the console has its self-signed certificate (typical before the first deployment) |
| CA certificate (advanced) | The CA of the console's current certificate, if not public |
| Previous versions to keep (advanced) | Default 1, `-1` keeps all |
| Check what is served | Empty: acme checks the console's own address |

## Check it

- Press **Try** on the target: acme signs in and lists the added certificates:
  `signed in to ...; N certificates added there`.
- In the console: **Settings → Control Plane → Console → Certificates** shows `acme-...` as
  active.
- From any machine:

  ```sh
  openssl s_client -connect unifi.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` on signing in | Wrong password, the account is a UI.com/SSO one, or it has two-factor sign-in - use a local admin. |
| `the console gave no session cookie` | Not a UniFi OS console (e.g. an older Cloud Key or the Network application alone). |
| `404` on `/api/userCertificates` | UniFi OS older than 4.2 - update. |
| `403` when adding | The admin's role cannot change console settings. |
| Old certificate still served | The console needs a few seconds to reload; acme's check retries. |
