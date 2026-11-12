# HestiaCP - setup for acme

acme installs the certificate on HestiaCP web domains over **SSH**, using Hestia's own documented commands. For each web domain of the given Hestia user it writes the certificate, key and chain into a fresh private folder (`mktemp -d`) as `<domain>.crt`, `<domain>.key` and `<domain>.ca`, then runs `v-change-web-domain-sslcert` (SSL already on) or `v-add-web-domain-ssl` (SSL off), and removes the folder. Hestia restarts the web server itself. If Hestia's own Let's Encrypt is on for the domain, acme first turns it off with `v-delete-web-domain-ssl` (otherwise Hestia's cron would put its own certificate back) - **this also turns "force SSL" off**, and acme says so in the job.

Hestia's REST API is not used: its SSL commands only take a folder on the server, which the API cannot write safely.

## What you need

- A HestiaCP server (1.x) with its commands in `/usr/local/hestia/bin` (the default).
- SSH access from acme to the server (port 22, or the port you set).
- **root**, or a user with **sudo** - Hestia's `v-*` commands must run as root.

## Set up HestiaCP

1. Decide the SSH user:
   - `root` with an SSH key (simplest; set `PermitRootLogin prohibit-password` in `/etc/ssh/sshd_config` so only keys are accepted), or
   - a dedicated user with sudo:

```sh
sudo useradd -m -s /bin/bash acme
echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme
sudo chmod 440 /etc/sudoers.d/acme
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# put the public SSH key from acme into /home/acme/.ssh/authorized_keys (mode 600, owner acme)
```

   **acme runs its commands as `sudo sh -c '…'`, so a sudo rule limited to single `v-*` commands does not work - the user effectively gets root.** Protect its key accordingly and, where possible, allow SSH only from the acme server (firewall, or `AllowUsers acme@<acme-ip>` in sshd_config).
2. If Hestia's firewall is on, allow SSH from the acme server: **Server (gear icon) → Firewall**.
3. Note the Hestia user that owns the web domains (e.g. `admin`) and the domain names exactly as Hestia lists them (**Web** tab).
4. For domains using Hestia's Let's Encrypt: decide whether acme should take them over (it turns Hestia's Let's Encrypt off) - and turn **Enable SSL redirection / force SSL** on again afterwards if you used it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the Hestia server |
| SSH port | 22 (or your SSH port) |
| User | `root` or the sudo user |
| Sign in with / The SSH key / Password | the key made in acme (its public half in `authorized_keys`), or a password |
| Host key (advanced) | the server's `known_hosts` line; empty with *Trust the first host key seen* |
| Use sudo / sudo password | on for a non-root user; the password empty when sudo is NOPASSWD |
| Hestia's commands (advanced) | `/usr/local/hestia/bin` |
| Hestia user (deployment) | the user the web domains belong to, e.g. `admin` |
| Web domains (deployment) | the web domains of that user, one a line |
| Restart the web server | on (Hestia restarts/reloads the web server after the change) |
| Check what is served | `example.com:443`, one a line |

## Check it

- **Test** in acme runs `v-list-users json` and reports how many Hestia users answer. The key's *Try* button runs `id -un; ls /usr/local/hestia/bin/v-list-users`.
- On the server:

```sh
sudo /usr/local/hestia/bin/v-list-web-domain-ssl admin example.com
```

   shows the subject, issuer and dates of the installed certificate. In the panel: **Web → (domain) → Edit → SSL**.

## Common problems

| Problem | Fix |
|---|---|
| `… failed (exit …): sudo: a password is required` | give the *sudo password*, or make the sudo rule NOPASSWD |
| `v-list-users … not found` | Hestia's commands are elsewhere: set *Hestia's commands* |
| `"…" is not a Hestia user` / domain not found | user and domain must be exactly as in Hestia |
| Error from `v-add-web-domain-ssl` / `v-change-web-domain-sslcert` | Hestia refused the certificate - the key does not match, or the chain is wrong; see the job's detail |
| `… now has NO SSL: Hestia's own Let's Encrypt was turned off …` | turn Let's Encrypt on again in Hestia, or deploy again after fixing the cause |
| Site no longer redirects to HTTPS | acme took over a Let's Encrypt domain: turn *force SSL* on again in Hestia |
