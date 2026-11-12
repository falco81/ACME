# HAProxy - setup for acme

acme signs in to the HAProxy server over SSH, writes the certificate (key + full chain in one PEM) to its file, and swaps it into the **running** HAProxy through the Runtime API on the stats socket (`set ssl cert` + `commit ssl cert`, sent with `socat`) - **no reload, no dropped connection**. A certificate file HAProxy does not know yet is created with `new ssl cert` and added to a crt-list. When the Runtime API cannot be used, acme can run a reload command of yours instead. For HAProxy 2.2 and later.

## What you need

- HAProxy **2.2 or later** on Linux, with a stats socket at **level admin**.
- `socat` installed on the HAProxy server.
- SSH access from acme to the server (port 22) with a user that may write the certificate file and use the socket (root, sudo, or group rights as below).

## Set up HAProxy

1. Install socat:

```sh
sudo apt install socat        # Debian / Ubuntu
sudo dnf install socat        # RHEL / Fedora
```

2. Give HAProxy an admin-level stats socket in the `global` section of `/etc/haproxy/haproxy.cfg` (most packages have one already):

```text
global
    stats socket /run/haproxy/admin.sock mode 660 level admin user haproxy group haproxy
```

3. Name the certificate file in a `bind` line (or in a crt-list), e.g.:

```text
frontend https
    bind :443 ssl crt /etc/haproxy/certs/www.example.com.pem
```

   If the file does not exist yet, create it once (e.g. a copy of the current certificate), or use a crt-list and fill in *crt-list for a new certificate*.

4. Create a user for acme and let it reach the socket and the certificate folder without sudo:

```sh
sudo useradd -m -s /bin/bash acme
sudo usermod -aG haproxy acme
sudo chgrp haproxy /etc/haproxy/certs && sudo chmod 2770 /etc/haproxy/certs
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# put the public SSH key from acme into /home/acme/.ssh/authorized_keys (mode 600, owner acme)
sudo systemctl reload haproxy
```

   Or use root / a sudo user and turn on *Use sudo*. **The certificate file holds the private key: keep it readable only by HAProxy and acme (acme writes it with mode 600).** If the file belongs to root and HAProxy reads it as root at start, group rights are not needed for HAProxy itself.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the HAProxy server |
| SSH port | 22 |
| User | `acme` (or root / a sudo user) |
| Sign in with / The SSH key / Password | the key made in acme (its public half in `authorized_keys`), or a password |
| Host key (advanced) | the server's `known_hosts` line; empty with *Trust the first host key seen* |
| Use sudo / sudo password | on only when the user needs sudo to write the file and use the socket |
| Stats socket | `/run/haproxy/admin.sock` (as in haproxy.cfg); `ipv4@host:port` for a TCP socket |
| Certificate file (deployment) | the absolute PEM path as haproxy.cfg or the crt-list names it |
| crt-list for a new certificate (advanced) | a crt-list file to add a certificate HAProxy does not know yet; empty: it must be known |
| Reload when the Runtime API cannot (advanced) | e.g. `systemctl reload haproxy` (needs rights for it); empty: fail instead |
| Leave a file alone when it is the same (SHA-256) | on: an unchanged file is not rewritten |
| Keep a copy of a file replaced | copies go to `.acme-backup/` beside it (a crt folder is loaded whole) |
| Check what is served | `www.example.com:443`, one a line |

## Check it

- **Test** in acme signs in, checks `socat` is there and asks the socket `show info` (`signed in; HAProxy 2.x answers on …`).
- On the server:

```sh
echo "show ssl cert /etc/haproxy/certs/www.example.com.pem" | socat stdio /run/haproxy/admin.sock
```

   shows the serial and the dates of the certificate HAProxy serves now.

## Common problems

| Problem | Fix |
|---|---|
| `socat is not on the machine` | install socat (step 1) |
| `the Runtime API cannot be reached on …` | wrong socket path, the socket is not `level admin`, or the user may not open it (group/sudo) |
| `HAProxy does not know …` | name the file in haproxy.cfg (`crt`) and reload once, or give a crt-list |
| `set ssl cert … ` refused | HAProxy older than 2.2, or the file path differs from the one HAProxy loaded (it must be the very same path) |
| `the certificate file must be an absolute path …` | use an absolute path without spaces or shell characters |
| After a restart HAProxy serves an old certificate | a new certificate added through the Runtime API must also be in the crt-list file on disk |
