# VMware vCenter Server - setup for acme

acme uses the vSphere Automation REST API: it signs in (`POST /api/session`, basic auth),
adds the intermediates and the root to vCenter's **trusted root chains**
(`/api/vcenter/certificate-management/vcenter/trusted-root-chains`), then **replaces the
machine SSL certificate** - the one the vSphere Client uses
(`PUT /api/vcenter/certificate-management/vcenter/tls` with `cert`, `key`, `root_cert`).
**vCenter then restarts its services: the vSphere Client is unavailable for several
minutes.** acme's check of what is served waits for it (20 tries, 15 s apart). If vCenter
already has this certificate, nothing is done.

For vCenter Server 7.0 and later (8.x included). ESXi hosts have their own target (`esxi`).

## What you need

- Network access from acme to vCenter: **TCP 443**.
- An SSO user with the privilege **CertificateManagement.Administer**
  (members of *Administrators* in `vsphere.local` have it).
- For Let's Encrypt and other chains that do not include the root: the **root CA
  certificate** in PEM (ISRG Root X1 for Let's Encrypt).
- A maintenance window: each renewal restarts vCenter's services.

## Set up vCenter

1. Create a dedicated SSO user: **vSphere Client → Administration → Single Sign On → Users
   and Groups → Users** → domain `vsphere.local` → **Add**, e.g. `acme`.
2. Give it the certificate privilege, either:
   - **Administration → Access Control → Roles → New**: a role with only
     **Certificate Management → Create/Delete (Admins priv)** (`CertificateManagement.Administer`);
     then **Administration → Access Control → Global Permissions → Add**: user
     `acme@vsphere.local`, that role, *Propagate to children*; or
   - simply add it to the group **Administrators** (broader).

   If replacing is still refused with only the role, use a member of *Administrators* as
   Broadcom's documentation describes.
3. Download the root CA certificate the chain ends in (for Let's Encrypt: ISRG Root X1 from
   letsencrypt.org) - acme puts it into *Root CA certificate*.
4. If vCenter uses a custom CA mode or VMCA policies, check that it accepts a custom
   machine SSL certificate (**Administration → Certificates → Certificate Management**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | vCenter's FQDN, e.g. `vcenter.example.local` |
| HTTPS port | `443` |
| User | `acme@vsphere.local` (default `administrator@vsphere.local`) |
| Password | Its password |
| Check the device's certificate | On; put the VMCA root into *CA certificate* while vCenter still has a VMCA certificate |
| CA certificate (advanced) | VMCA root (download from `https://<vcenter>/certs/download.zip`) |
| Root CA certificate (deploy) | The root PEM (ISRG Root X1 for Let's Encrypt); empty: the last certificate of the chain |
| Add the chain to the trusted roots (deploy) | On (default) - vCenter accepts a certificate only if it trusts the issuers |
| Check what is served | Empty: acme checks vCenter's own address |

**The certificate must contain vCenter's FQDN** (the Primary Network Identifier) and use an
RSA key (2048 or more).

## Check it

- Press **Try** on the target: acme signs in and reads the current certificate:
  `signed in to ...; its certificate: <subject>, valid to <date>`.
- After a deployment (once the services are back): **Administration → Certificates →
  Certificate Management → Machine SSL Certificate** shows the new one; or

  ```sh
  openssl s_client -connect vcenter.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong user/password; use the `user@vsphere.local` form. |
| `403` / Unauthorized on replacing | The user lacks `CertificateManagement.Administer`; add it to *Administrators*. |
| `400` about the chain / not trusted | Give *Root CA certificate* and keep *Add the chain to the trusted roots* on. |
| `400` invalid certificate | Key not RSA, or the certificate lacks the vCenter FQDN. |
| Check fails right after deploying | Services are still restarting; acme retries for about 5 minutes. |
