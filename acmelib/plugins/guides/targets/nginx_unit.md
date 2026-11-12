# NGINX Unit - setup for acme

acme signs in to the Unit server over **SSH** and talks to Unit's **control API** through its control socket with `curl` on that machine. It uploads the certificate bundle (full chain + key) as `PUT /certificates/acme-<name>-<date>-<serial>`, points each listener you name at it (`PUT /config/listeners/<listener>/tls/certificate`; in a list of certificates only the older acme one is replaced) and deletes older acme bundles. Unit takes the new certificate at once - **no restart, no dropped connection**. A bundle still in use is refused by Unit and stays.

## What you need

- NGINX Unit (1.x) on Linux, with its control socket (`/var/run/control.unit.sock`, or `/run/unit/control.sock` on some systems - see `unitd --help` / the `--control` option).
- `curl` on the Unit server.
- SSH access from acme (port 22) with a user who may use the control socket: root, or a user with sudo.
- The listeners already defined in Unit's configuration.

## Set up the Unit server

1. Install curl if missing (`sudo apt install curl` / `sudo dnf install curl`).
2. Find the control socket:

```sh
ps -o args= -C unitd | head -1        # look for --control
ls -l /var/run/control.unit.sock /run/unit/control.sock 2>/dev/null
```

3. Create a user for acme with sudo (the control socket is root-only by default):

```sh
sudo useradd -m -s /bin/bash acme
echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme && sudo chmod 440 /etc/sudoers.d/acme
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# put the public SSH key from acme into /home/acme/.ssh/authorized_keys (mode 600, owner acme)
```

   **acme runs its commands as `sudo sh -c '…'`, so a sudo rule limited to `curl` does not work - and full access to the control socket is equivalent to root anyway.** Alternatively use `root` with an SSH key only.

4. Make sure the listener exists and is meant for TLS, e.g. in Unit's config:

```json
"listeners": { "*:443": { "pass": "routes", "tls": { "certificate": "initial" } } }
```

   If the listener has no `tls` section yet, upload any certificate once by hand (`curl -X PUT --data-binary @bundle.pem --unix-socket … http://localhost/certificates/initial`) and add `tls` as above; acme then replaces it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the Unit server |
| SSH port | 22 |
| User | `acme` (or root) |
| Sign in with / The SSH key / Password | the key made in acme (its public half in `authorized_keys`), or a password |
| Host key (advanced) | the server's `known_hosts` line; empty with *Trust the first host key seen* |
| Use sudo / sudo password | on for a non-root user; the password empty when sudo is NOPASSWD |
| Control socket | `/var/run/control.unit.sock` (or what step 2 showed) |
| Timeout (s) (advanced) | 30 |
| Listeners (deployment) | one a line, exactly as in Unit's config, e.g. `*:443` |
| Previous versions to keep | older acme bundles kept |
| Check what is served | `www.example.com:443`, one a line |

## Check it

- **Test** in acme signs in and lists the certificate bundles (`signed in; Unit answers, N certificate bundles`).
- On the server:

```sh
sudo curl -s --unix-socket /var/run/control.unit.sock http://localhost/certificates | head -40
sudo curl -s --unix-socket /var/run/control.unit.sock http://localhost/config/listeners
```

## Common problems

| Problem | Fix |
|---|---|
| `the control socket … cannot be reached` | wrong socket path, curl missing, or no rights (turn on *Use sudo*) |
| `sudo: a password is required` | give the *sudo password* or make the rule NOPASSWD |
| `Unit has no listener "…"` | the listener name must match the config exactly (`*:443`, `127.0.0.1:8443`) |
| `Unit said 400 - …` on upload | the bundle was refused (e.g. key does not match); see the message |
| `Unit said 404/400` pointing a listener | the listener has no `tls` section yet - see step 4 |
| `the old bundle … stays (still used?)` | another listener still uses it; add it to *Listeners* or change it by hand |
