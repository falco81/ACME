# Proxmox Backup Server - setup for acme

acme uploads the certificate (full chain + key) as the **custom certificate of the PBS web
interface and API** (`proxy.pem` / `proxy.key`) through the PBS API:
`POST https://<pbs>:8007/api2/json/nodes/<node>/certificates/custom` with an API token
(`Authorization: PBSAPIToken=<user@realm!id>:<secret>`). PBS reloads its proxy by itself.
If PBS already serves the same fingerprint, nothing is uploaded.

**Pinned fingerprints**: Proxmox VE storages and PBS remotes that pin the PBS fingerprint
stop trusting it after the change. The job shows the new fingerprint - update them, or
make them trust the CA instead.

For Proxmox Backup Server 2.x and later.

## What you need

- Network access from acme to PBS: **TCP 8007**.
- A user and an API token with **`Sys.Modify` on `/system/certificates`**.
- **PBS's own ACME must not manage the certificate** (it writes the same files).

## Set up Proxmox Backup Server

1. Create a user and a token, and grant the permission (as root on PBS). Token permissions
   are limited to what the user has, so grant it to both:

   ```sh
   proxmox-backup-manager user create acme@pbs --comment "acme certificate deployment"
   proxmox-backup-manager user generate-token acme@pbs deploy
   proxmox-backup-manager acl update /system/certificates Admin --auth-id acme@pbs
   proxmox-backup-manager acl update /system/certificates Admin --auth-id 'acme@pbs!deploy'
   ```

   `generate-token` prints the secret **once**. PBS has no custom roles; `Admin` is the
   built-in role with `Sys.Modify`, and the ACL path limits it to the certificates.
2. In the GUI the same is **Configuration → Access Control → User Management / API Token /
   Permissions**.
3. If a firewall is in front of PBS, allow TCP 8007 from the acme server.
4. Remove PBS's own ACME domains, if any (**Certificates → ACME**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | PBS name or IP, e.g. `pbs.example.local` |
| HTTPS port | `8007` |
| API token ID | `acme@pbs!deploy` |
| API token secret | The secret printed by `generate-token` |
| Check the device's certificate | On; off only while PBS has its self-signed certificate |
| CA certificate (advanced) | The CA of PBS's current certificate, if not public |
| Node (deploy, advanced) | `localhost` (default) |
| Check what is served | e.g. `pbs.example.local:8007` |

## After the first deployment: pinned fingerprints

On Proxmox VE, a PBS storage that pins the fingerprint needs the new one (shown in the
acme job, or in PBS: **Dashboard → Show Fingerprint**):

```sh
pvesm set <storage-id> --fingerprint <AA:BB:...>
```

With a publicly trusted certificate you can instead clear the fingerprint so the CA is
trusted.

## Check it

- Press **Try** on the target: acme reads the current certificate and answers
  `signed in to PBS ...; its certificate: <subject>, until <date>`.
- On PBS:

  ```sh
  proxmox-backup-manager cert info
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Token ID must be `user@realm!tokenid`; wrong secret. |
| `403 ... Sys.Modify` | ACL missing on `/system/certificates` for the user or the token. |
| Proxmox VE backups fail after renewal (fingerprint) | Put the new fingerprint into the storage (above). |
| Certificate replaced by another later | PBS's own ACME is still set - remove it. |
