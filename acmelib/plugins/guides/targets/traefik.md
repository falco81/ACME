# Traefik Proxy (file provider) - setup for acme

acme signs in to the Traefik host over SSH and writes:

- the certificate (full chain) and key as `acme-<name>-<date>-<serial>.crt` / `.key` in
  *Folder for the certificates*;
- a dynamic configuration file `acme-<name>.yml` in the **file provider's folder**, listing
  them under `tls.certificates` (and as `tls.stores.default.defaultCertificate` when
  asked).

Traefik watches that folder and picks the new certificate up **without a restart**. Older
certificate files beyond *Previous versions to keep* are deleted.

For Traefik Proxy v2 and v3, installed on the host or in a container.

## What you need

- SSH from acme to the Traefik host, **TCP 22**.
- `root`, or a user with `sudo`, able to write both folders.
- Traefik started with a **file provider watching a folder**.

## Set up Traefik and the host

1. Enable the file provider with `watch` in Traefik's static configuration, e.g.
   `/etc/traefik/traefik.yml`:

   ```text
   providers:
     file:
       directory: /etc/traefik/dynamic
       watch: true
   ```

   or as arguments: `--providers.file.directory=/etc/traefik/dynamic --providers.file.watch=true`.
   Restart Traefik once after adding it.
2. Create the folders:

   ```sh
   sudo mkdir -p /etc/traefik/certs /etc/traefik/dynamic
   ```

3. **Traefik in Docker**: mount both folders (as folders, not single files) into the
   container, e.g. `-v /etc/traefik/certs:/certs:ro -v /etc/traefik/dynamic:/etc/traefik/dynamic:ro`,
   and set *The certificates' folder as Traefik sees it* to `/certs` in acme.
4. Create an account for acme and put acme's public key on it (*The SSH key → How to set
   it up* in acme shows the commands); if it is not root, allow sudo without a password -
   acme runs its steps as `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **This amounts to root** for that account. Alternatively make the account own the two
   folders and leave *Use sudo* off.
5. Your routers need `tls: {}` (or `tls=true` labels) - Traefik then picks the certificate
   whose names match the request.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | The Traefik host, `22`, `acme` (or `root`) |
| Sign in with / The SSH key | *a private key* |
| Use sudo / sudo password | On for a non-root account; password empty with `NOPASSWD` |
| Folder for the certificates (deploy) | `/etc/traefik/certs` |
| Folder of the file provider (deploy) | `/etc/traefik/dynamic` - the `providers.file.directory` |
| The certificates' folder as Traefik sees it (advanced) | For a container, e.g. `/certs`; empty: the same path |
| Also the default certificate (deploy) | On to serve it when no other certificate matches |
| Previous versions to keep (advanced) | Default 1, `-1` keeps all |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- Press **Try** on the target: acme signs in and looks for `traefik version` or a Traefik
  container: `signed in as acme; Version: 3.x ...`.
- On the host:

  ```sh
  cat /etc/traefik/dynamic/acme-*.yml
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

- Traefik's log at DEBUG level shows the file provider reloading the configuration.

## Common problems

| Problem | Fix |
|---|---|
| Traefik still serves its default certificate | File provider not watching that folder (`watch: true`), or the router has no `tls`. |
| `... is not an absolute path without spaces` | Use absolute paths, no spaces or shell characters. |
| Error in Traefik log: file not found | Traefik in a container sees another path: set *The certificates' folder as Traefik sees it*. |
| Changes not seen in Docker | A single file is mounted instead of the folder - mount the folder. |
| Permission denied writing | Turn on *Use sudo*, or give the account the two folders. |
