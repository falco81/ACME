# pfSense - setup for acme

pfSense CE has no official REST API, so acme works **over SSH**: it runs a PHP script with
pfSense's own functions (`cert_import()`) that adds the certificate (full chain + key) to
the certificate manager as `acme-<name>-<date>-<serial>`, makes the web GUI use it (and
runs `/etc/rc.restart_webgui`), removes older acme certificates beyond *Previous versions
to keep* that nothing uses (checked with pfSense's `cert_in_use()` where it exists), and
saves with `write_config()` - one configuration revision per renewal. *Force* on a
certificate already there edits it in place, so services pointing at it keep it.

For pfSense CE and pfSense Plus with SSH access.

## What you need

- SSH from acme to pfSense, **TCP 22** (or your SSH port).
- An account that can run PHP with pfSense's configuration: `admin` (default) or `root`.
- acme's SSH key (made in acme on the target's *The SSH key* field, or your own).

## Set up pfSense

1. Enable SSH: **System → Advanced → Admin Access → Secure Shell** → tick *Enable Secure
   Shell*. Set *SSHd Key Only* to **Public Key Only** if you use key sign-in (recommended).
   Save.
2. Add acme's public key to the account: **System → User Manager → Users → admin (edit)**
   → *Authorized SSH Keys* → paste the public key → Save.
3. Allow the acme server through the firewall to the SSH port on the interface acme comes
   in on (**Firewall → Rules → <interface>**: pass TCP from the acme IP to *This Firewall*,
   port 22). Restrict it to that IP.
4. Optional: check PHP is at the default path:

   ```sh
   ls -l /usr/local/bin/php
   ```

**Note**: the account must be `admin` or `root` (or one with equivalent shell
privileges) - the script writes the configuration directly. A restricted user cannot do it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Name or IP of pfSense |
| SSH port | `22` |
| User | `admin` (default) or `root` |
| Sign in with | *a private key* (recommended) or *a password* |
| The SSH key | The key whose public half you added in step 2 |
| Password | Only with password sign-in |
| Host key (advanced) | A `known_hosts` line, or leave empty with *Trust the first host key seen* |
| Through a connector (advanced) | A connector server, if pfSense is reachable only from another network |
| PHP (advanced) | `/usr/local/bin/php` |
| Timeout (s) (advanced) | `60` |
| Web GUI certificate (deploy) | On (default): the web GUI uses the new certificate |
| Previous versions to keep (advanced) | Default 2, `-1` keeps all |
| Check what is served | e.g. `pfsense.example.local:443` |

## Check it

- Press **Try** on the target: acme signs in over SSH, runs PHP and answers
  `signed in to ..., pfSense <version>`.
- In pfSense: **System → Cert. Manager → Certificates** lists `acme-...`;
  **System → Advanced → Admin Access → SSL/TLS Certificate** shows it for the GUI.
- **Diagnostics → Backup & Restore → Config History** has an entry
  `acme: certificate acme-...`.

## Common problems

| Problem | Fix |
|---|---|
| SSH sign-in refused | Public key not on the account, or *SSHd Key Only* and password sign-in mixed up; firewall rule missing. |
| You get the console menu / script does nothing | Use `admin` or `root`; check *PHP* path. |
| `the PHP script on pfSense failed` | Read the output shown; an unusual pfSense version may lack the functions - check `/etc/inc/certs.inc`. |
| `the old ... is still used: kept` | OpenVPN, IPsec, the captive portal or a package uses it; move it to the new certificate, it is removed next time. |
| GUI briefly unreachable | Expected: the web GUI restarts after the change. |
