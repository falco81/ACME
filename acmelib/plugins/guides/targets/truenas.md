# TrueNAS - setup for acme

acme signs in to TrueNAS over SSH and uses the middleware client (`midclt`, or the
middleware's Python client) on the machine itself - so it works on releases whose REST API
is deprecated or removed. It imports the certificate under a dated name
(`certificate.create`, `CERTIFICATE_CREATE_IMPORTED`), makes it the **web interface
certificate** (`system.general.update` `ui_certificate`, then `system.general.ui_restart`)
and, when asked, the **FTP certificate** (`ftp.update` `ssltls_certificate`), and deletes
older acme certificates beyond *Previous versions to keep* (one still in use stays). The
private key never appears on a command line.

For TrueNAS SCALE / Community Edition (24.04 and later) and TrueNAS CORE.

## What you need

- SSH from acme to TrueNAS, **TCP 22**.
- `root`, or an admin user with sudo - `truenas_admin` on SCALE 24.04 and later (root
  sign-in is off there by default).

## Set up TrueNAS

1. Turn on SSH: **System → Services → SSH** → enable and *Start Automatically*. In its
   settings leave *Allow Password Authentication* off if you use a key (recommended).
2. Put acme's public key on the admin user: **Credentials → Users → truenas_admin → Edit
   → Authorized Keys** (CORE: **Accounts → Users → Edit → SSH Public Key**). Make the key in
   acme first (target → *The SSH key* → *Make a key*).
3. Let the user run sudo without a password - acme runs its steps as `sudo -n sh -c ...`:
   on the user's edit page tick **Allow all sudo commands with no password** (or add `sh` to
   *Allowed sudo commands with no password*). **This amounts to root.** (Or sign in as
   `root` and leave *Use sudo* off.)
4. If the TrueNAS web interface is behind a firewall/allow-list, the SSH port must be
   reachable from acme too.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The NAS name or IP |
| SSH port | `22` |
| User | `truenas_admin` (default) or `root` |
| Sign in with / The SSH key | *a private key* - the key from step 2 |
| Use sudo / sudo password | On for `truenas_admin`; password empty with "no password" sudo |
| Host key (advanced) | A `known_hosts` line, or empty with *Trust the first host key seen* |
| Web interface certificate (deploy) | On (default) |
| FTP certificate (deploy) | On if FTP with TLS should use it |
| Previous versions to keep (advanced) | Default 1, `-1` keeps all |
| Check what is served | Empty: acme checks the web interface on port 443 |

## Check it

- Press **Try** on the target: acme runs `midclt call system.version` and lists the
  certificates: `signed in: TrueNAS-..., N certificates`.
- On TrueNAS (shell):

  ```sh
  sudo midclt call system.general.config | python3 -m json.tool | grep -A3 ui_certificate
  ```

- In the web interface: **Credentials → Certificates** lists `acme-...`; **System →
  General Settings → GUI** shows it.

## Common problems

| Problem | Fix |
|---|---|
| `Permission denied (publickey)` | Key not in the user's *Authorized Keys*, or SSH service settings. |
| `sudo: a password is required` / midclt refused | Tick *Allow all sudo commands with no password*, or fill in *sudo password*. |
| `midclt: command not found` | Not a TrueNAS shell, or the PATH lacks it - use sudo/root. |
| `TrueNAS does not list ... after importing it` | Import failed silently - check *Credentials → Certificates* and the middleware log `/var/log/middlewared.log`. |
| `the old ... stays (still used?)` | Another service (S3, WebDAV, apps) still uses it; switch it and it goes next time. |
| Web interface briefly unreachable | Expected: it restarts after the change. |
