# strongSwan (IPsec VPN) - setup for acme

acme signs in to the VPN server over SSH and writes the certificate, the intermediates and
the key where strongSwan reads its credentials, then loads them **without dropping a
tunnel**:

| Configured with | Files | Load command |
|---|---|---|
| `swanctl.conf` (vici) | `<folder>/x509/<name>.crt`, `<folder>/x509ca/acme-ca-<id>.crt`, `<folder>/private/<name>.key` | `swanctl --load-creds` |
| `ipsec.conf` (stroke) | `<folder>/ipsec.d/certs/...`, `ipsec.d/cacerts/...`, `ipsec.d/private/...` | `ipsec rereadall` |

If the load command fails, the previous files are put back. Copies of replaced files go to
`.acme-backup/` beside them by default (`swanctl --load-creds` reads its folders whole).

For strongSwan 5.x and 6.x on Linux.

## What you need

- SSH from acme to the VPN server, **TCP 22**.
- `root`, or a user with `sudo` (the files are under `/etc` and the key is private).
- The connection already configured to use the certificate file by name (below).

## Set up the server

1. Create an account and put acme's public key on it (as for the *Linux / Unix server*
   target; *The SSH key → How to set it up* in acme shows the commands):

   ```sh
   sudo useradd -m -s /bin/sh acme
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<acme-IP>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

2. If not root, allow sudo without a password. acme runs its steps as `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **This amounts to root** for that account.
3. Point the connection at the file acme writes (`<name>` = the certificate's name, or the
   *File name* you set in acme):
   - `swanctl.conf`:

     ```text
     connections {
       rw {
         local { certs = vpn.example.com.crt  ... }
       }
     }
     ```
   - `ipsec.conf`: `leftcert=vpn.example.com.crt`

   The key is found by itself. Reload the configuration once (`swanctl --load-all` or
   `ipsec reload`).
4. Find the folder: `/etc/swanctl` on most distributions, `/etc/strongswan/swanctl` on
   RHEL/Fedora; for stroke `/etc` (holding `ipsec.d`).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | The VPN server, `22`, `acme` (or `root`) |
| Sign in with / The SSH key | *a private key* - the key from step 1 |
| Use sudo / sudo password | On for a non-root account; password empty with `NOPASSWD` |
| Configured with (deploy) | *swanctl.conf (vici)* or *ipsec.conf (stroke)* |
| Folder (deploy) | `/etc/swanctl` (or `/etc/strongswan/swanctl`); `/etc` for stroke |
| File name (deploy, advanced) | `<this>.crt` / `<this>.key`; empty: the certificate's name |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Defaults are fine |

## Check it

- Press **Try** on the target: acme signs in and reads `swanctl --version` (or
  `ipsec version`); `strongSwan not found on the PATH` means the commands are missing for
  that user.
- On the server:

  ```sh
  sudo swanctl --list-certs
  sudo openssl x509 -in /etc/swanctl/x509/vpn.example.com.crt -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `strongSwan not found on the PATH` | Commands in `/usr/sbin` not on the user's PATH; use sudo or root. |
| `"swanctl --load-creds" failed, the previous files are back` | Read the error; charon not running, or wrong *Configured with*. |
| Clients still see the old certificate | The connection's `certs =` / `leftcert=` names another file - match *File name*. |
| `the folder must be an absolute path` | Give e.g. `/etc/swanctl`, no shell characters. |
