# Targets - where certificates go

A **target** is a place acme puts certificates: a server, an appliance, a
secret store. It holds *how acme signs in* (its `fields`: address, user, key,
token - secrets sealed). A **deployment** is one certificate on one target,
with *what to do there* (its `deploy_fields`: files, profiles, services,
commands). After a renewal every enabled deployment of the certificate runs.

Every module here works the same way:

- **`test`** signs in and reads something harmless (a version, a list) -
  nothing is changed.
- **`deploy`** puts the certificate in place and makes the service take it,
  then returns a short line for the job. Each step is written down in the job.
- **The same certificate again is a no-op.** When the fingerprint already
  deployed there with the same options is still on the device, nothing is
  sent; *Deploy (force)* does it again anyway.
- **Names on a device** are `acme-<name>-<YYYYMMDD>-<serial>` (the date the
  certificate starts), so renewals do not overwrite in use objects, and the
  old ones can be found. **Previous versions to keep** (`keep`, default 1-2)
  says how many older ones stay; older ones are deleted unless still in use
  (`-1` keeps all). Intermediates are kept as `acme-ca-<id>` / `acme-chain-<id>`,
  added once and reused.
- **Check what is served** (`verify`, `host:port` one a line, optional SNI
  name): after deploying acme makes a TLS handshake there and compares the
  SHA-256 fingerprint of the certificate served with the new one (the trust
  is not checked - only *which* certificate it is). A few tries a few seconds
  apart, as services take a moment to reload.
- **Check the device's certificate** (`verify_tls`) is on by default; paste
  the CA of the management interface in *CA certificate* when it is a private
  one, or turn the check off for a device still on its factory certificate.
  *Through the proxy* is off for devices (they are usually inside), on for
  the webhook.

| Kind | Title | Vendor |
|---|---|---|
| `ssh` | Linux / Unix server (SSH) | Linux / Unix |
| `local` | This machine (files) | acme |
| `appliance` | This acme server (its pages) | acme |
| `windows_ssh` | Windows server (OpenSSH + PowerShell) | Microsoft |
| `f5` | F5 BIG-IP | F5 |
| `netscaler` | NetScaler / Citrix ADC | Citrix |
| `mikrotik` | MikroTik RouterOS | MikroTik |
| `fortigate` | FortiGate | Fortinet |
| `paloalto` | Palo Alto Networks (PAN-OS) | Palo Alto Networks |
| `opnsense` | OPNsense | Deciso |
| `pfsense` | pfSense | Netgate |
| `proxmox` | Proxmox VE (API) | Proxmox |
| `synology` | Synology DSM | Synology |
| `kubernetes` | Kubernetes TLS secret | Kubernetes |
| `webhook` | Webhook | Generic |
| `vault` | HashiCorp Vault (KV v2) | HashiCorp |
| `aws_acm` | AWS Certificate Manager (ACM) | Amazon |
| `azure_keyvault` | Azure Key Vault | Microsoft |
| `gcp_certmanager` | Google Cloud Certificate Manager | Google |
| `cloudflare_ssl` | Cloudflare custom certificate | Cloudflare |
| `vcenter` | VMware vCenter Server | VMware |
| `esxi` | VMware ESXi host (SSH) | VMware |
| `redfish` | Server management (Redfish: iDRAC, iLO, XCC, BMC) | Redfish (Dell, HPE, Lenovo, Supermicro) |
| `sophos` | Sophos Firewall (SFOS / XG) | Sophos |
| `kemp` | Kemp / Progress LoadMaster | Progress Kemp |
| `cisco_ise` | Cisco ISE | Cisco |
| `haproxy` | HAProxy (Runtime API, no reload) | HAProxy |
| `traefik` | Traefik Proxy (file provider) | Traefik Labs |
| `caddy` | Caddy | Caddy |
| `nginx_unit` | NGINX Unit | NGINX |
| `zimbra` | Zimbra Collaboration | Zimbra |
| `truenas` | TrueNAS (midclt over SSH) | iXsystems |
| `docker_swarm` | Docker Swarm secrets | Docker |
| `strongswan` | strongSwan (IPsec VPN) | strongSwan |
| `fritzbox` | AVM FRITZ!Box | AVM |
| `unifi_os` | UniFi OS console (UDM, UCG, Cloud Key) | Ubiquiti |

**A dual certificate** (ECDSA and RSA of the same names, see
[certificates.md](certificates.md#dual-certificates-ecdsa--rsa)): the targets
that can serve both put both in place - `ssh` and `local` (the `@variant`
outputs, the presets of nginx, Apache, HAProxy, Postfix, Dovecot and Exim),
`f5`, `appliance`, `kubernetes`, `vault`, `webhook`. Every other target holds
one certificate at a time and gets the deployment option **Which certificate**
(`variant`: `auto` = the RSA one, which every client can use - the default;
`main`, `alt`, `rsa`, `ec`). *Check what is served* asks for each variant the
target has: a TLS 1.2 handshake offering only ECDSA, then only RSA.

Your own module goes in `/etc/acme/plugins/targets/` - see
[writing-a-module.md](writing-a-module.md).

---

## `ssh` - Linux / Unix server

Writes the certificate as files, in any formats, in any places; tests the
configuration; reloads the service; puts the previous files back when the
test or the reload fails.

**Sign-in**: address, port, user, the SSH key or a password, the host key (a
`known_hosts` line, or *trust the first* one seen), and *Use sudo* (with the
sudo password, or none for `NOPASSWD`).

**The SSH key** is the key card isemon has for its firewalls, the same on every
module that signs in over SSH (Linux, Windows OpenSSH, MikroTik, pfSense,
OPNsense, and the validations HTTP-01 and DNS over SSH): *Right now*, *Signing
in with*, the key's fingerprint and when it was made; **Make a key** (Ed25519,
or RSA 4096 for something old such as RouterOS 6) - made on acme, kept sealed,
never shown back; **Use my own** (pasted or read from a file, OpenSSH or PEM;
its passphrase asked for and checked, kept sealed beside it); **Download it**
(the private half, to a full administrator, written into Events); **Forget it**;
**Try reaching it** (a real sign-in that runs `id -un; uname -n` - `whoami` on
Windows, `/system identity print` on RouterOS - and changes nothing, step by
step); and **How to set it up on ...** with the exact commands for that kind of
machine: `~/.ssh/authorized_keys` with `from="acme's addresses"` in front of the
key (and the sudoers line for an account that is not root), Windows'
`administrators_authorized_keys` and its `icacls`, RouterOS' `/user ssh-keys
import`, the *Authorized keys* of a pfSense / OPNsense user. A key made in a new
target's form is kept for that form and becomes the target's when it is saved.
A key pasted before there was this card goes on working and shows as *your own
key*. On the command line: `acme --target-key NAME make|show|public|own
FILE|private|forget|try`.

**Files** - one a line, `format path [mode] [owner[:group]]`:

```
fullchain-pem  /etc/nginx/ssl/{name}.crt   0644  root:root
key-pem        /etc/nginx/ssl/{name}.key   0600  root:root
pfx            /opt/app/keystore.p12       0640  app:app
```

- formats: `cert-pem` `fullchain-pem` `chain-pem` `key-pem` (PKCS#8)
  `key-rsa` (traditional) `combined-pem` (key + fullchain, HAProxy) `cert-der`
  `key-der` `p7b` `pfx`/`p12` (AES) `p12-legacy` (3DES) `jks`; short names work
  too (`cert`, `key`, `chain`, `fullchain`, `combined`).
- the mode is octal; without one keys get `0600`, the rest `0644`. Without an
  owner the file belongs to whoever writes it (root with sudo).
- in paths and commands: `{name}` the certificate's name made safe
  (`*.example.com` → `wildcard.example.com`), `{cn}`, `{service}`, `{date}`.
- paths must be absolute, without `..` or shell characters; up to 20 files.
- *PKCS#12 / keystore password* is used for `pfx`, `p12`, `p12-legacy`, `jks`
  (a `jks` needs one of 6 characters or more); *Keystore alias* defaults to
  the name.

**How it is written**: each file is uploaded to `/tmp` (*Folder for uploads*)
first; then in one script, through sudo when asked: `mkdir -p` the folder,
the old file copied to `<path>.bak`, the new one copied to `<path>.acme-new`
beside it, `chmod`, `chown`, and `mv -f` over the old one (a rename: atomic,
nothing ever reads half a file). Then:

1. *Before writing* commands (one failing stops everything, nothing written);
2. the files, as above;
3. *Test command* (e.g. `nginx -t`) - when it fails every file is put back
   from its copy (a file that was not there before is removed) and the
   deployment fails with what the test said;
4. *Reload / restart* (e.g. `systemctl reload nginx`) - when it fails the
   files are put back and the reload commands run again with the old ones;
5. *After reloading* - a failure is only a warning.

*Keep the previous files as .bak* off: the copies are removed after success.
When every PEM file there already holds exactly the new content (compared by
`sha256sum`), nothing is done.

**Service presets** fill whatever you leave empty (what you set wins); the
field carries the values in `fills` so the page can show them:

| Preset | Files | Test | Reload | Checked on |
|---|---|---|---|---|
| nginx | fullchain + key in `/etc/nginx/ssl/` | `nginx -t` | `systemctl reload nginx` | 443 |
| Apache httpd | cert, chain, key in `/etc/ssl/acme/` | `apachectl -t` | reload apache2 / httpd | 443 |
| HAProxy | combined PEM in `/etc/haproxy/certs/` | `haproxy -c` | `systemctl reload haproxy` | 443 |
| Postfix | `/etc/postfix/ssl/` | `postfix check` | `postfix reload` | 465 |
| Dovecot | `/etc/dovecot/ssl/` | `doveconf -n` | reload dovecot | 993 |
| Exim | `/etc/exim4/`, group Debian-exim | `exim -bV` | restart exim4 | 465 |
| Proxmox VE | `/etc/pve/local/pveproxy-ssl.{pem,key}` | | restart pveproxy | 8006 |
| Proxmox Backup Server | `/etc/proxmox-backup/proxy.{pem,key}` | | reload proxmox-backup-proxy | 8007 |
| Tomcat / Java | `jks` keystore | | restart `{service}` (tomcat) | 8443 |
| Docker volume | `/srv/docker/certs/{name}/` | | `docker restart {service}` | 443 |
| Kubernetes (kubectl) | temp files | | `kubectl create secret tls {service} … \| kubectl apply -f -` | |
| Webmin | `/etc/webmin/miniserv.pem` (combined) | | restart webmin | 10000 |
| Cockpit | `/etc/cockpit/ws-certs.d/90-acme.*` | | restart cockpit | 9090 |
| vsftpd | combined PEM | | restart vsftpd | |
| OpenLDAP | cert, chain, key, group openldap | | restart slapd | 636 |
| Grafana | `/etc/grafana/`, group grafana | | restart grafana-server | 3000 |
| Plex | PKCS#12 (set the password in Plex too) | | restart plexmediaserver | 32400 |
| MySQL / MariaDB | `/etc/mysql/ssl/` | | restart `{service}` | |
| UniFi Network | `jks` keystore, alias unifi | | restart unifi | 8443 |

The paths in your configuration must point at these files (e.g.
`ssl_certificate /etc/nginx/ssl/www.example.com.crt;`) - acme does not edit
configuration files.

**Rights**: either sign in as root (key only, `PermitRootLogin
prohibit-password`), or as a user with sudo for exactly what it runs, e.g.
`/etc/sudoers.d/acme`:

```
acme ALL=(root) NOPASSWD: /bin/sh -c *
```

(every command and write is one `sh -c` script, so this is what sudo sees;
tighten it with a restricted shell if your policy needs it). Without sudo the
user must be able to write the folders and run the commands itself.

**Example**: target `web1` (host `web1.example.com`, user `acme`, key, sudo
on); deployment preset *nginx*, verify `web1.example.com:443` → the files
`/etc/nginx/ssl/www.example.com.{crt,key}`, `nginx -t`, `systemctl reload
nginx`, and the served certificate compared.

**Dual certificate.** An output line names one of the two by a suffix:
`fullchain-pem@rsa`, `key-pem@ec`, `@main`, `@alt` (`{alt}` in a path is the
twin's kind, `rsa` or `ec`); a line for a variant the certificate does not
have is left out. The presets write the twin's files beside the main ones by
themselves (also when the page filled the preset's lines in):

| Preset | Files of a dual certificate | The service told of both |
|---|---|---|
| nginx | `{name}.crt` `{name}.key` + `{name}.rsa.crt` `{name}.rsa.key` | `ssl_certificate` and `ssl_certificate_key` twice, one pair each |
| Apache | `{name}.crt` `.chain.crt` `.key` + `{name}.rsa.crt` (with its chain) `{name}.rsa.key` | a second `SSLCertificateFile` / `SSLCertificateKeyFile` pair (2.4.8+) |
| HAProxy | `{name}.pem.ecdsa` + `{name}.pem.rsa` (instead of `{name}.pem`) | `crt /etc/haproxy/certs/{name}.pem` loads the bundle (remove an old `{name}.pem` from a crt directory) |
| Postfix | `{name}.crt` `{name}.key` + `{name}.rsa.crt` `{name}.rsa.key` | `smtpd_tls_chain_files = {name}.key, {name}.crt, {name}.rsa.key, {name}.rsa.crt` |
| Dovecot | + `{name}.rsa.crt` `{name}.rsa.key` | `ssl_alt_cert` / `ssl_alt_key` |
| Exim | + `{name}.rsa.crt` `{name}.rsa.key` | `tls_certificate` / `tls_privatekey` as lists of two |

(An RSA main certificate with an ECDSA twin: `.ec.` instead of `.rsa.`.) The
other presets write the main one only - add `@alt` lines for more.


## `local` - this machine

Writes files under one folder of the acme server only (*Folder*, default
`/etc/acme/out`), for something else to pick up (a backup job, a container
volume). The *Files* lines are as for `ssh` but the paths are inside that
folder (`fullchain-pem {name}/fullchain.pem`); a path leading outside it -
`..`, an absolute path elsewhere, or a link - is refused. Each file is
written to a temporary file in the same folder and renamed into place.

*Then run* runs one command - only one listed, exactly, in the target's
*Commands allowed* (set by a full admin); it is run without a shell, as the
acme user, with a plain `PATH`.

**Rights**: the acme user must be able to write the folder:
`install -d -o acme -g acme -m 0750 /etc/acme/out`.

**Dual certificate:** as `ssh` - `format@rsa` / `format@ec` (`@main`, `@alt`)
lines, `{alt}` the twin's kind.


## `appliance` - this acme server (its pages)

The certificate becomes the one of acme's own pages, as **Settings →
Certificates and TLS** would take it uploaded (its TLS settings - protocols,
ciphers, DH, HSTS - stay as they are; the engine's own ACME no longer renews
those pages). The target has no settings; a deployment says *Which pages*
(`where`):

| `where` | |
|---|---|
| `auto` (default) | every node's own pages, and the VIP address's in a cluster that has one |
| `nodes` | every node's own pages |
| `this` | the pages of the node that deploys |
| `vip` | the VIP address's only |
| `list` | the nodes (or `vip`) named in *Nodes* (`names`) |

Every node puts its own into nginx within seconds (it is kept in the
database, so the other node of a cluster takes it as well); the VIP's is
served by whichever node holds the address. *The certificate must hold the
names* (on by default) refuses a certificate without the VIP address's name.
A renewal deploys it again by itself - so the pages are renewed on every
node. `verify` compares what each of those pages holds with the new one.

```
acme --target-add pages --kind appliance
acme --deploy-add acme-pages pages --set where=auto
```

**Dual certificate:** the twin becomes the second certificate of the pages
(the engine's "alt", 1.0.196) on every node / the VIP - nginx gives each
client the one it takes; the check compares both.


## `windows_ssh` - Windows over OpenSSH

Imports a PFX into **LocalMachine\My** (friendly name
`acme-<name>-<date>-<serial>`), then as asked:

- **IIS bindings** - `site | host name | port [| ip]`, one a line: an https
  binding with a host name is an SNI binding (`SslFlags 1`); missing bindings
  are made; the certificate is set with `AddSslCertificate`.
- **Remote Desktop listener** - `Win32_TSGeneralSetting.SSLCertificateSHA1Hash`
  of `RDP-tcp`, NETWORK SERVICE given read on the key.
- **Exchange services** - `Enable-ExchangeCertificate -Services IIS,SMTP …`.
- *PowerShell after* - your own lines, `$thumb` holding the thumbprint.
- old acme certificates of the same name beyond *keep* are removed, unless an
  IIS binding still uses them.

The PFX is 3DES (any Windows) or AES (Server 2019+), with a one-time random
password; it is uploaded to `C:/Windows/Temp` and deleted after the import.
Everything runs as one `powershell -EncodedCommand` script.

**Rights**: the OpenSSH Server feature; an account in Administrators (the
test checks the session is elevated: for a local administrator other than
the built-in one, set `LocalAccountTokenFilterPolicy=1` or use a domain
admin). Key sign-in for administrators goes in
`C:\ProgramData\ssh\administrators_authorized_keys`.

**Example**: IIS `Default Web Site | www.example.com | 443`, RDP on, verify
`www.example.com:443` and `rdp.example.com:3389`.

## `f5` - F5 BIG-IP

Over iControl REST:

1. signs in at `/mgmt/shared/authn/login` (login provider `tmos`, or yours)
   and uses the token (`X-F5-Auth-Token`), deleted at the end;
2. uploads the key and the certificate to `/mgmt/shared/file-transfer/uploads/`
   (in 512 KiB `Content-Range` chunks), installs them as `sys crypto key` /
   `sys crypto cert` `/<partition>/acme-<name>-<date>-<serial>` with
   `from-local-file`, and removes the uploaded files;
3. installs the chain once as its own certificate `acme-chain-<id>`;
4. in each listed **client-ssl profile**, replaces the cert-key-chain entry
   that held the older acme certificate (else the `default` entry, else the
   first) - other entries (an RSA next to an EC one) are kept; *Make missing
   profiles* creates one from `/Common/clientssl`;
5. deletes older acme certificates and keys beyond *keep* (one still used by a
   profile is refused by the BIG-IP and stays, with a warning);
6. `save sys config`, and with *Sync to device group* `config-sync to-group`.

**Rights**: a user with the role *Certificate Manager* can manage keys and
certificates but not profiles; for profiles and saving use *Administrator* on
the partition (or *Resource Administrator*). REST must be allowed for the
user (`tmsh modify auth user acme partition-access … shell none` is fine).

**Example**: partition `Common`, profiles `/Common/www_clientssl`,
`/Common/api_clientssl`, device group `dg-failover`, verify `vip.example.com:443`.

**Dual certificate:** both are installed - the twin as
`acme-<name>-<kind>-<date>-<serial>` (e.g. `acme-www.example.com-rsa-...`) -
and each client-ssl profile gets two cert-key-chain entries: the main one in
the entry of acme's (or `default`), the twin in one of its own (`acme-rsa` /
`acme-ec`), found again by its name on the next renewal. A profile may hold
one certificate of each kind: take away an entry of the twin's kind that is
not acme's.


## `netscaler` - NetScaler / Citrix ADC

Over NITRO:

1. `login` (session cookie `NITRO_AUTH_TOKEN`), `logout` at the end;
2. uploads `acme-<name>-<date>-<serial>.crt` and `.key` to `/nsconfig/ssl`
   (`systemfile`, base64);
3. the **certkey** (default `acme-<name>`, kept across renewals): `update`
   with `nodomaincheck` when it exists - bindings stay - else `add`;
4. each intermediate as a certkey `acme-ca-<id>`, and `link` from the
   certificate up the chain (unlinking an old link first);
5. binds the certkey to each listed SSL virtual server (`name sni` for an SNI
   certificate) when not bound yet;
6. `save ns config`, and deletes older acme files beyond *keep*.

An HA pair syncs the files and configuration by itself.
*Key as* traditional (`BEGIN RSA PRIVATE KEY`) works on every release for
RSA keys; EC keys always go as PKCS#8 (NetScaler 12.1 and later).

**Rights**: a system user with a command policy allowing `systemfile`,
`ssl certKey`, `ssl vserver` binding and `save ns config` - or the built-in
`superuser` policy.

**Example**: certkey `www`, vservers `vs_www_ssl` and `vs_portal sni`.

## `mikrotik` - MikroTik RouterOS

- **REST (RouterOS 7)**: the fullchain and key are put on the router over
  SSH (SCP/SFTP - REST cannot upload files), imported with
  `/certificate/import`, found again by their fingerprint and named
  `acme-<name>-<date>-<serial>`; the uploaded files are deleted. Then
  `/ip/service` `www-ssl` / `api-ssl` get `certificate=…` (www-ssl last, as
  acme talks through it), and `sstp` / `ovpn` servers when listed.
- **SSH only (RouterOS 6)**: the same with CLI commands (`/certificate
  import`, the imported `<file>_0` renamed, `/ip service set`).
- older acme certificates beyond *keep* are removed unless a service uses them.

**Rights**: a user in a group with `read, write, api, rest-api, ssh, ftp`
(`ftp` is what lets SCP/SFTP write files). REST needs `www-ssl` enabled; the
first time it still has a self-signed certificate - paste it as *CA
certificate* or turn *Check the device's certificate* off for that first run.

**Example**: services `www-ssl`, `api-ssl`, `sstp`; verify `router.example.com:443`.

## `fortigate` - FortiGate

FortiOS REST API with an API token (`Authorization: Bearer`):

1. imports the certificate as `acme-<name>-<date>-<serial>` (35 characters at
   most) through `monitor/vpn-certificate/local/import` - PKCS#12 with a
   one-time password (or certificate + key PEM), in *global* scope (every
   VDOM and the admin GUI) or the VDOM;
2. imports the intermediates as CA certificates (an existing one is skipped);
3. as asked: `system global admin-server-cert`, `vpn ssl settings servercert`,
   `firewall ssl-ssh-profile <name> server-cert` and `firewall vip <name>
   ssl-certificate` (both shapes FortiOS versions use are tried);
4. deletes older acme certificates beyond *keep* (one still referenced stays).

`vdom` (target, or per deployment) is sent as `?vdom=`.

**Rights**: a *REST API Admin* with an admin profile giving read-write to
*System → Certificates* (`vpngrp`/`sysgrp` certificate parts), plus
*Firewall* for profiles/VIPs and *VPN* for SSL VPN; trusted hosts set to the
acme servers' addresses. For `admin-server-cert` the profile needs
`super_admin` or *System → Settings* write.

**Example**: admin GUI on, SSL VPN on, VIPs `web-https`, verify
`vpn.example.com:443` and `fw.example.com:8443`.

## `paloalto` - Palo Alto Networks (PAN-OS)

Over the XML API: an API key (or user + password → `type=keygen`), sent as
`X-PAN-KEY`:

1. imports the key pair as PKCS#12 (`type=import&category=keypair`) named
   `acme-<name>-<date>-<serial>` (shared, or in the virtual system set);
2. imports each intermediate as a certificate `acme-ca-<id>`;
3. sets `certificate` of each listed **SSL/TLS service profile** (what
   GlobalProtect portals/gateways and the admin GUI use);
4. deletes older acme certificates beyond *keep* (still referenced: stays);
5. commits - by default a partial commit of the acme admin's changes only
   (with user + password; with an API key a full commit), or everything, or
   not - and polls the job until it is `FIN` (fails with the job's details
   when its result is not `OK`).

**Rights**: an admin role with XML API *Configuration*, *Import*, *Commit*
and *Operational requests*; on the web side *Device → Certificate Management*.

**Example**: profiles `gp-portal-profile`, `mgmt-ssl`; commit acme's own;
verify `gp.example.com:443`.

## `opnsense` - OPNsense

Through the API (key + secret, Basic auth): the intermediates are added as
CAs (`/api/trust/ca/add`), the certificate imported with
`/api/trust/cert/add` (`action: import`) as `acme-<name>-<date>-<serial>`,
older ones beyond *keep* deleted. *Web GUI certificate* sets
`system/webgui/ssl-certref` with a small PHP script over SSH (the SSH fields
of the target, as root) and runs `configctl webgui restart`.

**Rights**: a user with an API key and the privileges *System: Certificate
Manager* (and *System: Trust* on newer releases); root over SSH for the web
GUI. OPNsense 24.7 or later (the trust API).

## `pfsense` - pfSense

Over SSH as root (or `admin`): a PHP script using pfSense's own
`cert_import()` adds the certificate (fullchain + key) to the certificate
manager as `acme-<name>-<date>-<serial>`, sets the web GUI to it
(`/etc/rc.restart_webgui`), removes older ones beyond *keep* that nothing
uses, and `write_config()` - one configuration revision per renewal.

**Rights**: SSH enabled (*System → Advanced → Secure Shell*), key sign-in
for root/admin.

## `proxmox` - Proxmox VE

`POST /api2/json/nodes/<node>/certificates/custom` with the fullchain, the
key, `force=1` and `restart=1` for each node listed (none listed: every node
of the cluster), skipping a node whose `pveproxy-ssl.pem` already has the
fingerprint. The API token: `Authorization: PVEAPIToken=user@realm!id=secret`.

**Rights**: a token (privilege separation on) with `Sys.Modify` on `/nodes`
(e.g. role *PVESysAdmin* on `/`), and `Sys.Audit` for listing nodes.

**Example**: token `acme@pve!deploy`, nodes empty, verify `pve1:8006`, `pve2:8006`.
(The `ssh` preset *Proxmox VE* does the same over SSH.)

## `synology` - Synology DSM

Signs in through `SYNO.API.Auth` (session `Certificate`), imports with
`SYNO.Core.Certificate` `import` (key, certificate, intermediates) - replacing
the certificate with the same description, so the services assigned to it
keep it - and can make it the default. A certificate that is the default
stays the default.

**Rights**: a user in the *administrators* group without 2-step verification
(make one only for acme).

## `kubernetes` - Kubernetes TLS secret

Makes (`POST`) or updates (merge `PATCH`) a `kubernetes.io/tls` secret
(`tls.crt` the fullchain, `tls.key`, optionally `ca.crt`), labelled
`app.kubernetes.io/managed-by: acme`; unchanged when `tls.crt` is the same.
*Restart these deployments* does a rollout restart (the
`kubectl.kubernetes.io/restartedAt` annotation).

**Rights**: a service account token with a Role in the namespace:

```yaml
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, create, patch]
- apiGroups: [apps]
  resources: [deployments]
  verbs: [patch]
```

and the API server's CA in *CA certificate*.

**Dual certificate:** the twin goes into the same secret as `tls-rsa.crt` /
`tls-rsa.key` (or `tls-ec.*`); an ingress reads `tls.crt` / `tls.key`, the
main one.


## `webhook` - a URL

`POST`s the certificate as JSON:

```json
{"event": "certificate.deployed", "name": "www", "names": ["www.example.com"],
 "serial": "…", "fingerprint": "…", "not_before": 1793491200, "not_after": 1801267200,
 "cert_pem": "…", "chain_pem": "…", "fullchain_pem": "…"}
```

(`key_pem` too only when the *target* says *Send the private key*), or as
`multipart/form-data` with the formats listed as files. Headers:
`X-Acme-Event`, `X-Acme-Timestamp`, and with a signing secret
`X-Acme-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>` -
check it, and that the timestamp is recent, on the receiving side. *Test*
sends `{"event": "ping"}`. Any 2xx is success.

**Dual certificate:** the JSON gets `key_type` and `alt` - the twin's
`key_type`, `serial`, `fingerprint`, `not_before`, `not_after`, `cert_pem`,
`chain_pem`, `fullchain_pem` (and `key_pem` where keys are sent); a multipart
body gets each file again as `fmt@alt`.


## `vault` - HashiCorp Vault KV v2

Writes `<mount>/data/<path>` (default `secret/data/acme/{name}`) with
`certificate`, `chain`, `fullchain`, `private_key` (unless turned off),
`fingerprint`, `serial`, `names`, `not_before`, `not_after` - a new version
only when the fingerprint there differs. Signs in with a token or AppRole;
Enterprise namespaces through `X-Vault-Namespace`.

**Rights**: a policy like

```hcl
path "secret/data/acme/*" { capabilities = ["create", "update", "read"] }
```

---

The modules below were added from what other certificate tools deploy to
(acme.sh's deploy hooks, Certify The Web's deployment tasks, certimate's
deployers) and from the vendors' own API documentation; each module's file
names its sources at the top. Where a vendor documents a thing only loosely,
the section says so under **Uncertain**.

**Dual certificate:** the twin in the same secret: `alt_certificate`,
`alt_chain`, `alt_fullchain`, `alt_fingerprint`, `alt_serial`,
`alt_not_after`, `alt_key_type`, `alt_private_key` (with the key),
`key_type` and `dual_fingerprint`.


## `aws_acm` - AWS Certificate Manager

Imports the certificate into ACM (`CertificateManager.ImportCertificate`,
JSON 1.1, signed with Signature Version 4) and on every renewal **re-imports
it into the same ARN** - so the ALB/NLB listeners, CloudFront distributions
and API Gateway domains that use it take the new one by themselves, nothing
else is touched. The ARN is the one given, or the one acme got on the first
import (kept per region and certificate). Unchanged: `DescribeCertificate`
shows the same serial. Tags are set on the first import only (ACM refuses
them on a re-import).

**Rights**: an IAM user (or temporary STS credentials) with
`acm:ImportCertificate`, `acm:DescribeCertificate`, `acm:ListCertificates`,
`acm:AddTagsToCertificate`. CloudFront takes certificates only from
`us-east-1`.

**Example**: region `eu-central-1`, ARN empty (first import makes it), tags
`Owner=it`. Source: <https://docs.aws.amazon.com/acm/latest/APIReference/API_ImportCertificate.html>,
<https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html>.

## `azure_keyvault` - Azure Key Vault

Imports the key and full chain (PEM, `application/x-pem-file`) as a **new
version** of one Key Vault certificate (`POST
https://<vault>.vault.azure.net/certificates/<name>/import?api-version=7.4`).
Whatever uses the certificate without a version - Application Gateway,
App Service (Key Vault reference; it syncs within 24 h or on *Sync*), Front
Door, API Management - takes it. Unchanged: the vault's current version has
the same SHA-1 thumbprint (`x5t`). Old versions stay in the vault (Key
Vault's own history; disable or purge them there if you wish).

**Rights**: an app registration (client secret; OAuth2 client credentials,
scope `https://vault.azure.net/.default`) with the role *Key Vault
Certificates Officer* on the vault (RBAC), or access policy *Certificates:
Get, List, Import*. Azure China and US Government are under *Cloud*.

**Example**: vault `kv-firma`, name `www-example-com`. Source:
<https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/import-certificate/import-certificate>.

## `gcp_certmanager` - Google Cloud Certificate Manager

Makes a **self-managed certificate** (`POST
.../projects/<p>/locations/<l>/certificates?certificateId=<id>`) and on each
renewal updates it in place (`PATCH ...?updateMask=selfManaged`), so the
certificate maps and load balancers pointing at it take the new one; the
long-running operation is waited for. Unchanged: its `pemCertificate` is
this certificate. The token comes from a service account key (a JWT signed
RS256 by openssl, as for Google Cloud DNS).

**Rights**: the role *Certificate Manager Editor*
(`roles/certificatemanager.editor`) on the project. Location `global` for
global load balancers, a region for regional ones.

Source: <https://cloud.google.com/certificate-manager/docs/reference/certificate-manager/rest/v1/projects.locations.certificates>.
**Uncertain**: the vendor page says an update is taken by every load
balancer using the certificate; acme does not check each one.

## `cloudflare_ssl` - Cloudflare custom certificate

Uploads the certificate as a **custom certificate** of a zone (`POST
/zones/<id>/custom_certificates`, `bundle_method` force / ubiquitous /
optimal, `sni_custom` or `legacy_custom`) and on each renewal replaces it in
place (`PATCH .../custom_certificates/<id>`: same id, swapped on Cloudflare's
edge without a gap). The id is remembered; a certificate acme does not know
yet is found by its names (exactly the same hosts).

**Rights**: an API token with *Zone → SSL and Certificates → Edit* (and *Zone
→ Zone → Read* to find the zone by name). Custom certificates need a
Business or Enterprise zone, or Advanced Certificate Manager.

Source: <https://developers.cloudflare.com/api/resources/custom_certificates/methods/create/>.

## `vcenter` - VMware vCenter Server

vCenter 7.0 and later, vSphere Automation REST API: signs in (`POST
/api/session`, basic auth → `vmware-api-session-id`), adds the intermediates
and the root to the **trusted root chains**, then **replaces the machine SSL
certificate** (`PUT /api/vcenter/certificate-management/vcenter/tls` with
`cert`, `key`, `root_cert`). vCenter restarts its services - the vSphere
Client is away for several minutes; the check of what is served waits for it
(20 tries, 15 s apart). Unchanged: the TLS info's thumbprint is this
certificate's.

**Rights**: a user with *CertificateManagement.Administer* (Administrators of
vsphere.local). Let's Encrypt's chain has no root: give *Root CA certificate*
(ISRG Root X1).

Source: <https://developer.broadcom.com/xapis/vsphere-automation-api/latest/vcenter/certificate_management-vcenter/tls>.
**Uncertain**: whether `cert` should hold the leaf alone (sent so, as the
SDK sample does) or the leaf with its intermediates.

## `esxi` - VMware ESXi host

Over SSH: `/etc/vmware/ssl/rui.crt` (full chain) and `rui.key` written
(atomically, the previous ones as `.acme-prev`), then `/etc/init.d/hostd
restart && /etc/init.d/vpxa restart` (or `services.sh restart`); when that
fails the old files are put back and the services restarted again.
Unchanged: both files already hold exactly this (`sha256sum`).

**Rights**: root with SSH on (*Host → Actions → Services → Enable Secure
Shell*). A host in vCenter's default VMCA mode gets its certificate renewed
by vCenter: set `vpxd.certmgmt.mode` to `custom` first. Choose an RSA key for
ESXi before 8.0.

Source: <https://knowledge.broadcom.com/external/article?legacyId=2113926>.

## `redfish` - server management controllers (iDRAC, iLO, XCC, BMC)

Standard Redfish: signs in with a session (`X-Auth-Token`; or basic auth),
finds the first manager's `NetworkProtocol/HTTPS/Certificates` member (or
the *Certificate URI* given), and calls
`CertificateService.ReplaceCertificate` with key + full chain
(`CertificateType: PEMchain`, or key + certificate as `PEM`). *Restart the
controller* sends `Manager.Reset` `GracefulRestart` (the server itself is not
touched). Unchanged: the controller already serves this certificate.

**Rights**: a controller user with *Configure Manager* (iDRAC: *Configure*;
iLO: *Configure iLO Settings*).

Sources: <https://www.dmtf.org/sites/default/files/standards/documents/DSP2046_2023.3.html>,
<https://github.com/acmesh-official/acme.sh/blob/master/deploy/redfish.sh>.
**Uncertain**: which controllers take a private key this way - reported for
AMI MegaRAC (ASUS, Lenovo, Supermicro), "should" for iDRAC9 5.x+ and iLO 5
2.42+; HPE iLO mostly wants its own CSR and older iDRACs `racadm
sslkeyupload`. Use an RSA 2048 key.

## `sophos` - Sophos Firewall (SFOS / XG)

XML API (`https://<fw>:4444/webconsole/APIController`, multipart `reqxml` +
the file): uploads the certificate as PKCS#12 (3DES, a one-time password)
under a dated name (`UploadCertificate`; SFOS refuses to replace one in
use), points each listed **firewall (WAF) rule** at it (the rule read, its
`<Certificate>` set, written back with `operation="update"`), then removes
older acme certificates beyond *keep* (one still used stays).

**Rights**: *Administration → Device access → API* on, acme's address among
the allowed ones; an administrator whose profile may change *Certificates*
and *Firewall rules*.

Source: <https://docs.sophos.com/nsg/sophos-firewall/21.0/api/index.html>.
**Uncertain**: the part name of the file (`file`, as the community's working
examples) and that the WAF rule's certificate is found as `<Certificate>`
anywhere in the rule (SFOS 18-21).

## `kemp` - Kemp / Progress LoadMaster

REST API in its JSON form (`POST /accessv2`, LoadMaster 7.2.50+; API key, or
`apiuser`/`apipass`): `addcert` (full chain + key, base64) under a dated
name, `addintermediate` for the chain (one already there is fine), `modvs
… CertFile=` for each listed virtual service (`address:port[:tcp]`),
`delcert` for older acme ones beyond *keep*.

**Rights**: *System Configuration → Remote Access → Enable API Interface*; an
API key or a user with *Certificate Creation* and *Virtual Services*.

Source: <https://docs.progress.com/bundle/loadmaster-technical-note-restful-api-programmer-guide-ga/page/Introduction.html>.
**Uncertain**: `addintermediate` and the shape of `listcert`'s answer are
taken from the APIv1 descriptions.

## `cisco_ise` - Cisco ISE

ISE 3.1+ OpenAPI, basic auth: the intermediates imported as **trusted
certificates** (`/api/v1/certs/trusted-certificate/import`), then the
certificate as a **system certificate** under a dated friendly name
(`/api/v1/certs/system-certificate/import`) for the roles listed - `admin`,
`eap`, `radius`, `pxgrid`, `saml`, `portal` (with its portal group tag),
`ims`; the key goes encrypted (PKCS#8 AES-256 by openssl) with a one-time
password. Older acme certificates of the node beyond *keep* are deleted. The
*Admin* role restarts the node's application server (minutes).

**Rights**: Open API on (*Administration → System → Settings → API
Settings*), an admin with *ERS Admin* (or *Super Admin*).

Source: <https://developer.cisco.com/docs/identity-services-engine/latest/certificates-openapi/>.
**Uncertain**: the import goes to the node acme speaks to - set *Address*
and *Node hostname* to the same node, one target per node.

## `haproxy` - HAProxy (Runtime API, no reload)

Over SSH: the PEM (key + full chain) written to *Certificate file*, then
swapped into the running HAProxy on its stats socket (`socat`): `set ssl
cert <file> <<` with the PEM, `commit ssl cert <file>` - no reload, no
dropped connection. A file HAProxy does not know yet is made with `new ssl
cert` and added with `add ssl crt-list` (put it in the crt-list file as well
for the next restart). *Reload when the Runtime API cannot* runs your
command instead. Unchanged: the file holds this and `show ssl cert` shows
its serial.

**Rights**: a user who may write the file and the socket (root or sudo);
`stats socket /run/haproxy/admin.sock mode 660 level admin`; `socat`;
HAProxy 2.2+.

Source: <https://docs.haproxy.org/2.8/management.html#9.3-set%20ssl%20cert>.

## `traefik` - Traefik Proxy (file provider)

Over SSH: `acme-<name>-<date>-<serial>.crt/.key` in *Folder for the
certificates* and `acme-<name>.yml` in the file provider's folder with
`tls.certificates` (and `tls.stores.default.defaultCertificate` when asked);
Traefik watches the folder and takes it without a restart. *The
certificates' folder as Traefik sees it* is for Traefik in a container.
Older certificate files beyond *keep* are deleted.

**Rights**: write access to both folders (root or sudo); Traefik with
`--providers.file.directory=/etc/traefik/dynamic --providers.file.watch=true`.

Source: <https://doc.traefik.io/traefik/https/tls/#user-defined>.

## `caddy` - Caddy

Over SSH, curl on the machine to Caddy's admin API (`localhost:2019`):
*admin API* replaces the entries of `apps.tls.certificates.load_pem` tagged
`acme-<name>` (`PATCH`, or `POST` when there are none) - no file, no reload;
for Caddy run from JSON or with `--resume` (a Caddyfile reload loses it).
*files + reload* writes the files the Caddyfile's `tls` line names and runs
`caddy reload --config /etc/caddy/Caddyfile`; the old files are put back if
the reload fails.

**Rights**: SSH; curl; for files, write access (root or sudo).

Source: <https://caddyserver.com/docs/api>,
<https://caddyserver.com/docs/json/apps/tls/certificates/load_pem/>.

## `nginx_unit` - NGINX Unit

Over SSH, curl to the control socket: the bundle (full chain + key) uploaded
as `PUT /certificates/acme-<name>-<date>-<serial>`, each listed listener's
`tls/certificate` pointed at it (in a list, the older acme one replaced),
older acme bundles deleted (one still used is refused by Unit and stays).

**Rights**: access to the control socket (root or sudo); curl.

Source: <https://unit.nginx.org/certificates/>.

## `zimbra` - Zimbra Collaboration

Over SSH, as zimbra (`su - zimbra -c`): the key put in
`/opt/zimbra/ssl/zimbra/commercial/commercial.key`, the certificate and the
chain **up to the root** checked with `zmcertmgr verifycrt comm` (the old key
is put back when it fails), deployed with `zmcertmgr deploycrt comm`, then
`zmcontrol restart` (or proxy, mailbox and MTA only). Let's Encrypt's chain
has no root: give *Root CA certificate* (ISRG Root X1 / X2).

**Rights**: root (or sudo) on every Zimbra server - one target each.

Source: <https://wiki.zimbra.com/wiki/Installing_a_LetsEncrypt_SSL_Certificate>.

## `truenas` - TrueNAS

Over SSH with `midclt` (the middleware client - it works on releases whose
REST API is deprecated or gone): `certificate.create` (imported, a dated name
with `_` for dots), `system.general.update` *ui_certificate* and
`system.general.ui_restart`, `ftp.update` when asked, `certificate.delete`
for older acme ones beyond *keep* (one in use stays).

**Rights**: root or an admin with sudo (`truenas_admin`); SSH on.

Source: <https://api.truenas.com/v25.04/api_methods_certificate.create.html>.
**Uncertain**: TrueNAS 26 changes some of `midclt`'s output; acme reads the
last line as JSON.

## `docker_swarm` - Docker Swarm secrets

Over SSH on a manager: `docker secret create acme-<name>-<date>-<serial>.crt`
(full chain) and `.key`, each listed service rolled onto them (`docker
service update --secret-rm <old> --secret-add
source=<new>,target=tls.crt,mode=0444`), older acme secrets removed (one
still used stays).

**Rights**: docker group (or root / sudo) on a manager node.

Source: <https://docs.docker.com/engine/swarm/secrets/#example-rotate-a-secret>.

## `strongswan` - strongSwan (IPsec VPN)

Over SSH: `x509/<name>.crt`, `x509ca/acme-ca-<id>.crt`, `private/<name>.key`
under `/etc/swanctl` (or `ipsec.d/…` for the stroke configuration), then
`swanctl --load-creds` (or `ipsec rereadall`) - no tunnel dropped; the old
files are put back when that fails.

**Rights**: root or sudo.

Source: <https://docs.strongswan.org/docs/latest/swanctl/swanctlDir.html>.

## `fritzbox` - AVM FRITZ!Box

Signs in through `login_sid.lua` (PBKDF2 challenge of FRITZ!OS 7.24+, or the
old MD5 one) and posts key + full chain to `/cgi-bin/firmwarecfg`
(`BoxCertImportFile`), as the box's own page does; the certificate is then
used for its pages, MyFRITZ! and VPN. Unchanged: the box already serves it.

**Rights**: a FRITZ!Box user with *FRITZ!Box settings*, without the button
confirmation for settings changes.

Source: <https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_english_2021-05-03.pdf>.
**Uncertain**: the box answers the upload with a page; it counts as done when
the page speaks of the SSL certificate without an error. Older FRITZ!OS
takes RSA keys only.

## `unifi_os` - UniFi OS console

The console's own certificate API (`/api/auth/login`, `/api/userCertificates`):
the certificate added under a dated name, made active (`PUT
…/<id>/status {"active": true}`), older acme ones deleted. For UDM, UCG,
UDR, Cloud Key Gen2+ and UniFi OS Server; nothing is written on the disk.
(The `ssh` preset *UniFi Network* is for the self-hosted Network
application.)

**Rights**: a local console admin without two-factor sign-in.

Source: <https://github.com/acmesh-official/acme.sh/blob/master/deploy/unifios.sh>.
**Uncertain**: Ubiquiti documents the page, not the API; it is what acme.sh's
hook uses (UniFi OS 4.x, 5.x).
