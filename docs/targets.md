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
