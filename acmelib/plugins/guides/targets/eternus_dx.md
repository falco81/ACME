# Fujitsu ETERNUS DX / AF (Web GUI certificate) - setup for acme

acme registers the **SSL certificate of ETERNUS Web GUI** on an ETERNUS DX / AF storage system -
the **RESTful API (port 5665) shares it**. The ETERNUS CLI takes the key and certificate only
from a file server, so acme:

1. puts `acme-<serial>.key` and `acme-<serial>.crt` on your **FTPS (or FTP) server**,
2. signs in to the array's CLI over **SSH** and runs

   ```text
   CLI> import ssl-certificate -port maintenance -server <file server> -user <ftp user> -cert-filename acme-<serial>.crt -key-filename acme-<serial>.key
   Password :            (acme answers with the file server's password)
   ```

3. deletes both files from the file server again (the key does not stay there),
4. when asked, restarts SMI-S on the new certificate (`set smi-s -function disable`, then
   `set smi-s -function enable -ssl-certificate shared-with-webgui`).

After the registration the array's **HTTP/HTTPS stops for a few minutes** (Web GUI and RESTful
API; logged-in users are cut off). **Data access (FC / iSCSI / SAS) is not touched.**

**Which versions:** checked against the ETERNUS DX S6 manuals (CLI C140-0003-06ENZ3, Web GUI
C140-0005-06ENZ3, RESTful API C140-0052-03ENZ3); ETERNUS AF on the same firmware line. DX S5 /
AF S3 / AF S2 use the same commands but FTP only - choose *File transfer: FTP on DX S5 / AF S3*
there. The
RESTful API has no certificate endpoint, hence the CLI.

**Keys:** RSA 1024 / 2048 / 4096, PEM; no PKCS#12. Use **RSA 2048 or 4096**.

## What you need

- From acme to the array: **TCP 22** (SSH on the MNT or RMT port, allowed in **Setup
  Firewall**).
- A file server both reach: acme puts files there, the array fetches them through its MNT, RMT
  or FST LAN port. S6 uses **FTPS (explicit)**, passive mode, and does not check the server's
  certificate.
- A user on the file server for this (a folder of its own).
- An ETERNUS user with the policy **Storage Management** (default roles that have it: *Admin*,
  *Maintainer*).

## Set up the array

1. Create a role with only *Status Display* (1) and *Storage Management* (10), and a user for acme
   (CLI over SSH as an administrator):

   ```text
   CLI> create role -name CertAdmin -policy 1,10
   CLI> create user -name svc-cert -role CertAdmin -function enable
   Password:
   Confirm Password:
   CLI> show users
   ```

   Add *Security Setting* (13) only if the account should also change TLS versions.
2. Optional - sign in with a key instead of a password: the CLI command `import ssh-public-key`
   registers one public key per account (its parameters: the CLI User's Guide, chapter
   "SSH/SSL Security Configuration"). Take the public key from the key card of the target.
3. On the file server, create the user `stage` with a home (or folder) it may write to and
   delete from, reachable from both acme and the array's LAN port.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The array's management address, e.g. `dx.example.local` |
| SSH port / User | `22` / `svc-cert` |
| Sign in with / The SSH key / Password | The key from step 2, or the password |
| LAN port of the array to the file server | *MNT* (default), *RMT* or *FST* - the port that reaches the file server |
| File server / File server port | e.g. `ftp.example.local` / `21` |
| File transfer | *FTPS, explicit TLS* for S6 (default); *FTP on S6* sends `-disable-ftps yes`; *FTP on DX S5 / AF S3 / AF S2* sends no FTPS option (those know FTP only) |
| File server user / File server password | `stage` and its password (the CLI asks for it; it is never shown) |
| Folder on the file server (advanced) | Empty (the user's home) or e.g. `eternus` |
| Check the file server's certificate (advanced) | acme's own FTPS connection - off for a self-signed file server |
| HTTPS port of the Web GUI (advanced) | `443` |
| Send the chain with the certificate (deploy) | Off (the certificate alone - the manual does not say the array takes a chain); try it on once if clients need the intermediate |
| Restart SMI-S on the new certificate (deploy) | On only where SMI-S is on and shares the Web GUI certificate |
| Check what is served | Empty: the Web GUI; add `dx.example.local:5665` for the RESTful API |

## Check it

- **Try** logs in to the file server (lists the folder) and runs `show ssl-version` on the
  array - nothing is changed.
- After a few minutes:

  ```sh
  openssl s_client -connect dx.example.local:443 -servername dx.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
  openssl s_client -connect dx.example.local:5665 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
  ```

  and in the CLI `show events`: there must be no `Network service startup error. service=GUI` (or
  `service=Restful API`).

## Common problems

| Problem | Fix |
|---|---|
| `the ETERNUS CLI said Error: …` | Read the error: wrong file server user or password, the array cannot reach the file server through that LAN port, FTPS not offered by the file server (choose an FTP *File transfer*), or a key and certificate that are no pair. |
| `Network service startup error. service=GUI` in the events | The pair was refused: deploy again (force) - acme registers over SSH, which works while HTTPS is down; or `create ssl-certificate` restores a self-signed one. |
| The chain is refused | Turn *Send the chain with the certificate* off. |
| SMI-S still serves the old certificate | Turn on *Restart SMI-S on the new certificate*, or `set smi-s -function disable` / `enable` by hand. |
| `takes RSA keys only` | Change the certificate's key type to RSA. |
| An older array rejects `-disable-ftps` | Choose *File transfer: FTP on DX S5 / AF S3 / AF S2*. |
