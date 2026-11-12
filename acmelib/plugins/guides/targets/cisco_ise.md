# Cisco ISE - setup for acme

acme uses the **ISE OpenAPI** (basic authentication). It imports the intermediates as
**trusted certificates** (`/api/v1/certs/trusted-certificate/import`), then the certificate
as a **system certificate** of one node under a dated friendly name
(`/api/v1/certs/system-certificate/import`) for the roles you list - Admin, EAP, RADIUS
DTLS, pxGrid, SAML, Portal, ISE messaging. The private key goes encrypted with a one-time
password. Older acme system certificates of the node beyond *keep* are deleted.

**The Admin role restarts the application server of that node (several minutes of
outage of its web pages and services).**

For ISE 3.1 and later.

## What you need

- HTTPS (TCP 443) from acme to **each node** that gets the certificate: the import goes to
  the node the request is sent to, so **one target per node**, its *Address* being that
  node itself.
- An administrator with the **ERS Admin** role (or Super Admin).
- A **new private key on each renewal**: ISE cannot import two certificates with the same
  key (it replaces the one there) - do not renew this certificate with its old key.

## Set up Cisco ISE

1. Turn on the API: **Administration → System → Settings → API Settings → API Service
   Settings**: enable **Open API** (and ERS for the primary/secondary nodes as offered).
   Save.
2. Create the admin: **Administration → System → Admin Access → Administrators → Admin
   Users → Add**, e.g. `acme`, a strong password, admin group **ERS Admin**.
3. Note each node's hostname as ISE lists it: **Administration → System → Deployment**.
4. Plan the roles: EAP and RADIUS DTLS move to the new certificate; if you include
   `admin`, schedule the deployment in a maintenance window.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | **This node's** address, e.g. `ise01.example.local` / `443` |
| User | The admin with ERS Admin (default `acme`) |
| Password | Its password |
| Node hostname | The node's hostname as ISE lists it, e.g. `ise01` |
| Check the device's certificate / CA certificate | Its admin certificate's CA when not public |
| Use it for (deploy) | One a line: `admin`, `eap`, `radius`, `pxgrid`, `saml`, `portal`, `ims` (default `eap` and `portal`) |
| Portal group tag (deploy, advanced) | Default `Default Portal Certificate Group` |
| Import the intermediates as trusted (deploy, advanced) | On |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. the portal `guest.example.com:8443` |

## Check it

- **Try**: `signed in to ...; node ise01 has N system certificates`.
- In ISE: **Administration → System → Certificates → System Certificates** shows the
  `acme-...` friendly name and its roles on the node.

## Common problems

| Problem | Fix |
|---|---|
| 401 | Wrong user/password, or the admin is not in ERS Admin |
| 404 / API not answering | Open API is off - turn it on in API Settings |
| Imported on the wrong node | *Address* must be the node itself, *Node hostname* its name |
| Import refused: same private key | Renew with a new key |
| Node unreachable for minutes | The Admin role restarts its services - expected |
| EAP clients complain | Clients must trust the new chain - check the supplicant's trusted CAs |
