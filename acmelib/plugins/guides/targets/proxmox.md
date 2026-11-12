# Proxmox VE - setup for acme

acme uploads the certificate (full chain + key) as the **custom certificate of each node's
web interface** (pveproxy, port 8006) through the Proxmox VE API:
`POST /api2/json/nodes/<node>/certificates/custom` with `force=1` and `restart=1`. It does
this for each node listed, or for every node of the cluster when none is listed, and skips
a node whose `pveproxy-ssl.pem` already has the same fingerprint.

For Proxmox VE 6 and later (API tokens). Proxmox Backup Server has its own target
(`proxmox_backup`).

## What you need

- Network access from acme to a node's API: **TCP 8006**.
- A user and an **API token** with `Sys.Modify` (and `Sys.Audit` to list nodes) on `/nodes`.
- **Proxmox's own ACME must be off** on the nodes acme manages: both write the same files
  (`pveproxy-ssl.pem`). Remove the node's ACME domains (*Node → System → Certificates →
  ACME*) or do not use this target there.

## Set up Proxmox VE

1. Create a user, a role with just the privileges needed, and a token (on any node, as
   root):

   ```sh
   pveum user add acme@pve --comment "acme certificate deployment"
   pveum role add AcmeCert --privs "Sys.Audit Sys.Modify"
   pveum acl modify /nodes --users acme@pve --roles AcmeCert
   pveum user token add acme@pve deploy --privsep 1
   pveum acl modify /nodes --tokens 'acme@pve!deploy' --roles AcmeCert
   ```

   The token command prints the secret **once** - copy it.
   (Simpler but broader: role `PVESysAdmin` on `/`.)
2. In the GUI the same is **Datacenter → Permissions → Users / Roles / API Tokens /
   Add → User Permission / API Token Permission**. With *Privilege Separation* on, the
   token needs its own permission entry, as above.
3. If the Proxmox firewall is on, allow TCP 8006 from the acme server.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | One node's name or IP, e.g. `pve1.example.local` |
| HTTPS port | `8006` |
| API token ID | `acme@pve!deploy` |
| API token secret | The secret printed when the token was made |
| Check the device's certificate | On; off only while the node has its self-signed certificate (or put the cluster CA `/etc/pve/pve-root-ca.pem` into *CA certificate*) |
| Nodes (deploy) | One a line; empty = every node of the cluster |
| Restart pveproxy (deploy) | On (default) so the new certificate is served at once |
| Check what is served | e.g. `pve1.example.local:8006`, `pve2.example.local:8006` |

**Every node gets the same certificate**: its names must cover all the nodes listed (or
use one target per node, each with its own certificate).

## Check it

- Press **Try** on the target: acme reads the version and the nodes, answering
  `signed in to ..., Proxmox VE x.y, nodes pve1, pve2`.
- On a node:

  ```sh
  pvenode cert info
  openssl s_client -connect pve1.example.local:8006 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong token ID format (`user@realm!tokenid`) or secret. |
| `403 Permission check failed (/nodes/..., Sys.Modify)` | The token (with privilege separation) or the user lacks the role on `/nodes`. |
| Only some nodes listed | `Sys.Audit` missing on `/nodes` - or list the nodes yourself. |
| The certificate goes back after some days | Proxmox's own ACME renewed over it: remove its ACME domains. |
| Name mismatch on a node | The certificate does not contain that node's name. |
