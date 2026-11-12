# Caddy - setup for acme

acme signs in to the Caddy machine over **SSH** and does one of two things:

- **admin API** (default): with `curl` on the machine it calls Caddy's admin API
  (`localhost:2019`) and replaces the entries of `apps.tls.certificates.load_pem` tagged
  `acme-<name>` (`PATCH`, or `POST` when there are none yet). No file, no reload. For
  Caddy run from **JSON config** or with `--resume` - a Caddyfile reload loses it.
- **files + reload**: it writes the certificate and key to the paths your Caddyfile's
  `tls` line names, then runs `caddy reload` (the old files are put back if the reload
  fails).

For Caddy 2.x on Linux.

## What you need

- SSH access from acme to the machine (TCP 22 by default).
- `curl` installed on the machine.
- Caddy's **admin endpoint enabled** (the default `localhost:2019`; not `admin off`) -
  **Try** reads it in both ways.
- For *files + reload*: a user who may write the certificate files and run the reload
  (root, or a user with sudo).

## Set up the Caddy machine

1. Create a user for acme and put acme's public SSH key in its `~/.ssh/authorized_keys`
   (acme makes the key: the *The SSH key* field).

   ```sh
   sudo useradd -m -s /bin/bash acme
   sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' | sudo tee /home/acme/.ssh/authorized_keys
   ```

2. For **admin API**: nothing more - check that the admin API answers locally:

   ```sh
   curl -s http://localhost:2019/config/apps/tls/certificates
   ```

3. For **files + reload**: name the files in the Caddyfile and let acme write them and
   reload Caddy. With a non-root user, allow just what is needed through sudo, e.g.
   `/etc/sudoers.d/acme`:

   ```text
   www.example.com {
       tls /etc/caddy/certs/www.example.com.crt /etc/caddy/certs/www.example.com.key
   }
   ```

   ```sh
   sudo install -d -m 750 -o caddy -g caddy /etc/caddy/certs
   echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme   # narrow it if you can
   ```

   acme writes the files through sudo, sets their owner and runs the reload command; a
   narrower sudoers rule must still allow writing the files and running `caddy reload`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The machine's name or IP |
| SSH port / User | `22` / `acme` (or `root`) |
| Sign in with / The SSH key / Password | A key made in acme (recommended) or a password |
| Use sudo / sudo password | On when the user is not root (empty password: NOPASSWD) |
| Admin API on the machine | Caddy's `admin` address, default `localhost:2019` |
| How (deploy) | `admin API: load_pem, no reload (JSON config)` or `files + reload (Caddyfile)` |
| Certificate file / Key file (deploy) | The paths of the `tls` line, e.g. `/etc/caddy/certs/{name}.crt` |
| Owner of the files (deploy) | Default `caddy:caddy` |
| Reload (deploy) | Default `caddy reload --config /etc/caddy/Caddyfile` |
| Leave a file alone when it is the same / Keep a copy of a file replaced | File handling options of the files way |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in; Caddy's admin API answers, N certificates loaded through it`.
- On the machine:

  ```sh
  curl -s http://localhost:2019/config/apps/tls/certificates | head
  journalctl -u caddy --since "10 min ago"
  ```

## Common problems

| Problem | Fix |
|---|---|
| curl not found | Install `curl` on the machine |
| Connection refused on `localhost:2019` | The admin API is off or on another address - fix *Admin API on the machine* |
| Certificate gone after `caddy reload` | You run a Caddyfile: use *files + reload* instead of the admin API |
| Permission denied writing files | Turn on *Use sudo* or give the user rights on the directory |
| Reload fails | Check the Caddyfile (`caddy validate --config /etc/caddy/Caddyfile`); acme restored the old files |
| Host key changed | Update *Host key* if the server was reinstalled |
