# Linux / Unix server (SSH) - setup for acme

acme signs in to the server over SSH and writes the certificate as **files** - in the
formats and places you list (PEM, full chain, key, combined PEM, DER, PKCS#7, PKCS#12, JKS).
Each file is uploaded to a temporary folder first, then moved over the old one atomically
(the old one kept as a copy). Then it runs your *Test command* (e.g. `nginx -t`) and
*Reload / restart* (e.g. `systemctl reload nginx`); if either fails, **the previous files
are put back** and the service reloaded with them. Presets fill the files and commands for
nginx, Apache, HAProxy, Postfix, Dovecot, Exim, Proxmox VE, Proxmox Backup Server, Tomcat,
Docker, Kubernetes, Webmin, Cockpit, vsftpd, OpenLDAP, Grafana, Plex, MySQL/MariaDB and
UniFi Network.

For any Linux or Unix system with an OpenSSH server and a POSIX `sh` (also BSDs and
appliances with a normal shell).

## What you need

- SSH from acme to the server, **TCP 22** (or your port). If only another network reaches
  it, a **connector** (*Targets → Connector over SSH*) can relay.
- An account that can write the target files and run the reload: `root`, or a user with
  `sudo`.
- `sh`, `mkdir`, `cp`, `mv`, `chmod`, `chown` on the server (standard).

## Set up the server

1. Create a dedicated account (recommended over signing in as root):

   ```sh
   sudo useradd -m -s /bin/sh acme
   ```

2. Put acme's public key on it. Make the key in acme (target → *The SSH key* → *Make a
   key*; *How to set it up* shows the exact commands), then on the server:

   ```sh
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<acme-IP>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

   `from="<acme-IP>"` lets the key work only from the acme server.
3. If the account is not root, allow sudo without a password. acme runs its steps as
   `sudo -n sh -c '...'`, so the rule must allow `sh`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **This is effectively root** for that account - protect the key accordingly. (Or fill in
   *sudo password* and drop `NOPASSWD`.)
4. Make sure the service's configuration points at the paths you will list in *Files*
   (e.g. nginx `ssl_certificate /etc/nginx/ssl/<name>.crt;`).
5. Allow TCP 22 from the acme server in the host firewall, if any.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The server's name or IP |
| SSH port | `22` |
| User | `acme` (or `root`) |
| Sign in with / The SSH key | *a private key* - the key from step 2 |
| Host key (advanced) | A `known_hosts` line, or leave empty with *Trust the first host key seen* |
| Through a connector (advanced) | A connector, when the server is reachable only from another network |
| Use sudo / sudo password | On for a non-root account; password empty with `NOPASSWD` |
| Folder for uploads (advanced) | `/tmp` (default) - files are put there before being moved |
| Service (deploy) | A preset, e.g. *nginx*, or *Custom* |
| Files (deploy) | One a line: `format path [mode] [owner[:group]]`, e.g. `fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root` |
| PKCS#12 / keystore password, Keystore alias | Only for `pfx`, `p12`, `jks` files (a `jks` needs 6+ characters) |
| Keep a copy of a file replaced | On (default) - the copy is used to roll back |
| Test command | e.g. `nginx -t` |
| Reload / restart | e.g. `systemctl reload nginx` |
| Before writing / After reloading (advanced) | Optional extra commands |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- Press **Try** on the target: acme signs in, runs `id -un; uname -sr` and, with sudo,
  checks that `sudo` gives root: `signed in as acme on Linux ...; sudo works`.
- On the server after a deployment:

  ```sh
  ls -l /etc/nginx/ssl/
  openssl x509 -in /etc/nginx/ssl/<name>.crt -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Permission denied (publickey)` | Key not in `~acme/.ssh/authorized_keys`, wrong permissions (700/600), or `from=` does not match acme's IP. |
| Host key changed | The server was reinstalled: put the new `known_hosts` line into *Host key*. |
| `signed in, but sudo does not work` | No `NOPASSWD` rule for `sh`, or `requiretty` set; fill in *sudo password* or fix the sudoers line. |
| `no files to write` | Choose a *Service* preset or fill in *Files*. |
| Test failed, files put back | Read the test output in the job; the service config points elsewhere or the key/cert pair is wrong for the format. |
| Service serves the old certificate | The reload command does not reload that service, or the config points at other paths. |
