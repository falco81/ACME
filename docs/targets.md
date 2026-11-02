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
| `acme_push` | An application of ours (acme push: otp, isemon, zigmon, acme) | acme |
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
| `webglobe` | Webglobe hosting | Webglobe |
| `kong` | Kong Gateway | Kong |
| `nginx_proxy_manager` | Nginx Proxy Manager | Nginx Proxy Manager |
| `avi` | VMware Avi Load Balancer (NSX ALB) | VMware |
| `a10` | A10 Thunder (ACOS aXAPI) | A10 Networks |
| `hetzner_lb` | Hetzner Cloud Load Balancer | Hetzner |
| `digitalocean_lb` | DigitalOcean Load Balancer | DigitalOcean |
| `azure_appservice` | Azure App Service | Microsoft |
| `bunny` | bunny.net CDN (pull zone hostnames) | bunny.net |
| `fastly` | Fastly TLS (your own certificate) | Fastly |
| `nutanix` | Nutanix cluster (Prism Central v4 API) | Nutanix |

**A dual certificate** (ECDSA and RSA of the same names, see
[certificates.md](certificates.md#dual-certificates-ecdsa--rsa)): the targets
that can serve both put both in place - `ssh` and `local` (the `@variant`
outputs, the presets of nginx, Apache, HAProxy, Postfix, Dovecot and Exim),
`f5`, `kong` (`cert_alt`), `avi` (one of each kind), `appliance`,
`kubernetes`, `vault`, `webhook`. Every other target holds
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
| HAProxy | `{name}.ecdsa.pem` + `{name}.rsa.pem` (instead of `{name}.pem`) | `crt /etc/haproxy/certs/` - the folder: HAProxy loads every file in it and gives each client the ECDSA or the RSA one of the same name - or a crt-list naming both. Not `crt {name}.pem` with `.ecdsa` / `.rsa` beside it: that multi-certificate bundle is gone since HAProxy 2.3 |
| Postfix | `{name}.crt` `{name}.key` + `{name}.rsa.crt` `{name}.rsa.key` | `smtpd_tls_chain_files = {name}.key, {name}.crt, {name}.rsa.key, {name}.rsa.crt` |
| Dovecot | + `{name}.rsa.crt` `{name}.rsa.key` | `ssl_alt_cert` / `ssl_alt_key` |
| Exim | + `{name}.rsa.crt` `{name}.rsa.key` | `tls_certificate` / `tls_privatekey` as lists of two |

(An RSA main certificate with an ECDSA twin: `.ec.` instead of `.rsa.`.) The
other presets write the main one only - add `@alt` lines for more.

**Files no longer written are taken away.** acme remembers, per deployment,
the files it wrote. When the set changes - the certificate becomes dual (the
HAProxy preset then writes `{name}.ecdsa.pem` and `{name}.rsa.pem` instead of
`{name}.pem`), stops being dual (the twin's `.rsa.` files), or the outputs are
edited - the files it wrote before and not now are moved aside before the
test, removed once the reload worked, and put back when the test or the
reload fails. Only files acme itself wrote for that deployment, never any
other file (a link is left alone).


## Files and the script after them

`ssh`, `local` and `windows_ssh` write the certificate as **files** and can run
a **script after them**. The deployment's popup draws both as a designer; what
it keeps is the deployment's options, the same the command line sets
(`acme --deploy-add CERT TARGET --set outputs=...`).

**Files** (`outputs`, one a line: `format path [mode] [owner[:group]]`).
*Quick layouts* fill the rows in one click - one PEM with everything,
certificate + chain + key apart, full chain + key (nginx), PKCS#12 with a
password, a Java keystore, DER files, PKCS#12 3DES for Windows - and the
service presets (nginx, Apache, HAProxy, Postfix, Dovecot, Tomcat...) fill the
commands too. Each row: the format in words, the path (click `{name}` `{cn}`
`{service}` `{date}` `{alt}` to put a placeholder in), the mode and the owner
(not on Windows; `local` paths are inside its folder). *As text* shows the same
rows as the lines kept. A path must be absolute (`/...`, `C:/...`), without
`..`, spaces, quotes or `$ ; & | < >`; a key anybody may read (`0644`) is said.

**The password** of `pfx`, `p12`, `p12-legacy` and `jks` files
(`pfx_password_mode`): `none`; `fixed` - the one typed (`pfx_password`, sealed;
empty: none, or the preset's); `generate` - acme makes a random one of 24
characters when the deployment is saved (or first run), keeps it sealed with
the deployment, the same on every renewal; a full administrator sees it as
every secret, *Make a new one* replaces it (`pfx_password_new=1`). The script
gets it as `ACME_PASSWORD`.

**After the files** (`script_mode`):

| `script_mode` | What runs |
|---|---|
| empty | the target's default - the same fields in the target's settings (a full administrator sets them there) |
| `none` | nothing |
| `path` | `script_path` with `script_args`, a command already on the machine: `/usr/local/bin/reload-certs.sh {name}` |
| `inline` | `script_body` run by `script_interp` (`bash`, `sh`, `python3`; `powershell` on Windows) |

A script written here (`inline`, 64 KiB at most, only a full administrator may
change it) is uploaded on every deployment into the target's upload folder
(`tmp_dir`) under a name of its own, made executable (`chmod 700`), run -
through sudo when the target uses sudo - and deleted. Its variables travel in
a file of mode 0600 beside it that the wrapper reads and deletes before the
script starts: never on a command line. What it prints goes into the job; an
exit code other than 0 fails the deployment and puts the previous files back.
The order: *before writing* · the files · *test* · **the script** · *reload* ·
*after*. On `local` (acme's own machine) a script written here runs only when
the target's *Scripts written in a deployment may run here* (`allow_scripts`)
is on, and one on the machine only when it is among *Commands allowed*; it runs
as acme, without a shell, with a small `PATH`.

| Variable | What it is |
|---|---|
| `ACME_CERT_NAME` | the certificate's name in acme |
| `ACME_CN` | its first name |
| `ACME_NAMES` | every name, separated by spaces |
| `ACME_NOT_AFTER` | when it ends, UTC ISO 8601 (`2027-01-30T12:00:00Z`) |
| `ACME_FINGERPRINT`, `ACME_SERIAL` | SHA-256 fingerprint, serial (hex) |
| `ACME_VERSION`, `ACME_KEY_TYPE` | its version in acme, the kind of key |
| `ACME_FILES` | the files written, one a line |
| `ACME_FILE_<FORMAT>` | the path of the file of that format: `ACME_FILE_KEY_PEM`, `ACME_FILE_FULLCHAIN_PEM`, `ACME_FILE_PFX`...; `_2` for a second of the same format; a dual certificate's `_ALT`, and `_RSA` / `_EC` by its kind |
| `ACME_ALT_FINGERPRINT`, `ACME_ALT_KEY_TYPE` | a dual certificate's twin |
| `ACME_PASSWORD` | the password of the PKCS#12 / keystore files, when they have one |
| `ACME_SERVICE` | the deployment's *Service* (`{service}`) |
| `ACME_TARGET`, `ACME_HOST`, `ACME_DEPLOY_ID` | the target's name, the address reached, the deployment |
| `ACME_THUMBPRINT` | Windows: the SHA-1 thumbprint of the certificate imported |
| `ACME_DRY_RUN` | `1` on a test, else `0` |
| `ACME_TEST_DIR` | on a test: the temporary folder the files are in |

```bash
#!/bin/bash
# the key and the certificate copied to two more applications
set -euo pipefail
for dir in /opt/app1/tls /opt/app2/tls; do
  [ "$ACME_DRY_RUN" = 1 ] && { echo "test: would copy to $dir"; continue; }
  install -D -m 0644 "$ACME_FILE_FULLCHAIN_PEM" "$dir/cert.pem"
  install -D -m 0600 "$ACME_FILE_KEY_PEM" "$dir/key.pem"
done
systemctl restart app1 app2
```

```powershell
# Windows: a service restarted (its name: "Service" of the deployment)
if ($env:ACME_DRY_RUN -eq '1') { (Get-Service $env:ACME_SERVICE).Status; exit 0 }
Restart-Service -Name $env:ACME_SERVICE -Force
```

**Beside the designer** the popup shows what it will really be, worked out by
the module as a deployment does, without the network
(`POST /api/deploys/preview {cert_id, target, options}` -> `files`, `env`,
`problems`): each file with its path filled in for this certificate (a dual
one's twin too), its format, mode and owner and size, what is wrong, and every
variable the script gets with its value (the password as dots) - click one to
put it into the script. On Windows, with roles chosen, the PowerShell that will
run for them too.

**Test** (`POST /api/deploys/dry_run`, a certificate administrator; a script
other than the one saved only a full administrator) signs in, makes the files
and writes them into a temporary folder on the target (not their places; the
folders where they go are looked at), runs the script there with
`ACME_DRY_RUN=1` and the `ACME_FILE_*` of the copies, and deletes the folder.
The commands before, test, reload and after are not run, and on Windows the
machine store and the bindings are not touched - but the script **is** run:
it must change nothing when `ACME_DRY_RUN` is `1` (the examples do so).

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


## `acme_push` - an application of ours (otp, isemon, zigmon, another acme)

The certificate put on another application of the same family through its
own **Settings → Certificates and TLS → Certificates from acme** - each
node's pages, the VIP address's, a server in front, a broker - over HTTPS
to its administration pages, with every request signed (Ed25519) and the
private key sealed to the application (X25519 + HKDF-SHA256 + AES-256-GCM).
The whole protocol, for the applications to implement their side:
[acme-push-protocol.md](acme-push-protocol.md).

| Field | |
|---|---|
| `url` | the application's administration as opened in a browser: `https://otp.example.com/admin/`, `https://isemon.example.com/` |
| `pair_code` | the one-time code the application shows (*Pair with an acme*, 15 minutes); Try pairs the two, after that it is not needed |
| `verify_tls`, `ca_pem`, `timeout` | as everywhere |

**Try** says hello, pairs where a code is given, and asks the inventory -
nothing is changed. Not paired and no code: it says how, with this acme's
key to paste there instead. **Discover** (a button of the target, and
Certificates → the target's row) lists the application's slots - the names
each must hold, what it has now, who keeps it - and makes the certificates
and deployments for those not covered: one for each slot, or one for all
(every node's name and the VIP address's).

A deployment says **Slots** (`slots`, one a line): `auto` (default: each
slot whose names the certificate holds), `nodes`, `vip`, `this`, or slot ids
from Discover (`node:otp1`, `vip`, `front`, `broker`). The application
refuses a certificate without a slot's names unless it allows other names
and *The certificate must hold the slot's names* is off. Pushed twice, it
answers *already there*. After the push acme makes a TLS handshake to each
slot's name (SNI) until the new certificate is served (`verify_served`; or
`verify` host:port lines instead).

```
acme --target-add otp --kind acme_push --set url=https://otp.example.com/admin/ --set pair_code=ABCD-EFGH-JKMN-PQRS
acme --deploy-add otp.example.com otp --set slots=auto
```

**Dual certificate:** the twin goes with it (`alt`), the application's
second certificate of the same pages.

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

### Windows roles

These are under *Roles on the server* in a `windows_ssh` deployment (`role_*` switches, the
code is in `acmelib/plugins/targets/_win_roles.py`). Each role has its own switch, and its
fields show only when the switch is on. The certificate is imported once into
**LocalMachine\My** as described above (IIS, RDP and the Exchange services field come with
that import). After it:

1. **read on the key** for the accounts in *Read on the key for* (`key_read`, one a line;
   `icacls` on the key file by SID; CNG and CAPI keys, RSA and ECDSA);
2. each role that is on, **one PowerShell run each**, in the order of the table. A role first
   checks that its module, service or snap-in is there and says plainly when it is not
   installed. It then compares before it changes anything, so running it again does nothing,
   and it reports what it did as job steps. If a role fails, it shows as a bad step and the
   other roles still run. The deployment then fails as a whole, it is tried again later, and
   the old certificates are kept;
3. when every role worked, the old acme certificates beyond *keep* are removed, except those
   still in use. "In use" means an IIS binding, any http.sys binding (`netsh http show
   sslcert`: AD FS, WAP, SSTP, RD Gateway, older WAC), the RDP listener, a SQL Server
   instance, or a WinRM listener. When a role is on, the import itself removes nothing;
4. the files and the script after them (see above), then the TLS checks of *verify*.

The roles that need a PFX (RDS, SharePoint) get a second upload with a one-time password.
CCS gets one locked with the store's password. Both are deleted at the end, whatever
happened. A run that would not fit `cmd.exe`'s 8191-character line is uploaded as a `.ps1`
that deletes itself as soon as it starts.

**Test** (of the target): signs in, checks the session is elevated, and lists in one
PowerShell run, without changing anything, which roles this server has. **Test** of a
deployment (`dry_run`): checks that the roles switched on are installed, and writes each
role's PowerShell into the job steps without running it. **Preview** (`POST
/api/deploys/preview`) returns `roles: {on, script}`, the whole script with the passwords
as `********`, and refuses impossible settings (`problems`).

| Role (`role_…`) | What acme does | Fields | Notes / uncertain |
|---|---|---|---|
| `rds` - Remote Desktop Services via the Connection Broker | `Get-RDCertificate` per role, then for those that differ `Set-RDCertificate -Role RDGateway\|RDWebAccess\|RDPublishing\|RDRedirector -ImportPath <pfx> -Password … -ConnectionBroker <fqdn> -Force` | the four roles (switches, all on), `rds_broker` (empty: this server's FQDN) | Run on the broker, or on a server that can reach it. With a remote broker and SSH **key** sign-in, the session has no network credentials (second hop) and the broker cannot be asked: sign in with a password, or run it on the broker. |
| `rdgw` - RD Gateway (standalone) | `Import-Module RemoteDesktopServices`; `RDS:\GatewayServer\SSLCertificate\Thumbprint` set when it differs; NETWORK SERVICE given read on the key; `Restart-Service TSGateway` | `rdgw_restart` | A restart drops open gateway sessions. |
| `adfs` - AD FS | `Set-AdfsSslCertificate -Thumbprint`; `Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint` (switch); read on the key for the `adfssrv` service account (from Win32_Service, works for a gMSA); `Restart-Service adfssrv` with its dependants | `adfs_service_comm`, `adfs_grant`, `adfs_restart` | `Set-AdfsCertificate` works on the primary server of a WID farm only: on a secondary server, turn Service-Communications off. Every farm server needs its own deployment for the SSL part. |
| `wap` - Web Application Proxy | `Set-WebApplicationProxySslCertificate -Thumbprint`; published applications whose `ExternalCertificateThumbprint` was an old one (the previous WAP certificate, or an older acme certificate of the same name) get `Set-WebApplicationProxyApplication -ExternalCertificateThumbprint <new>` | `wap_apps` | The property names on the objects that `Get-WebApplicationProxySslCertificate` returns (`CertificateHash`) are from memory. |
| `sql` - SQL Server | instance → id from `…\Instance Names\SQL`; `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<id>\MSSQLServer\SuperSocketNetLib` `Certificate` = thumbprint in lower case; read on the key for the service account (`MSSQLSERVER` / `MSSQL$<inst>`, from Win32_Service); `ForceEncryption` 1/0 (optional); restart of the service, and the running services that depend on it (SQL Agent) are started again | `sql_instance` (MSSQLSERVER), `sql_force` (keep/on/off), `sql_restart` | The certificate must hold the server's FQDN. Failover-cluster instances are not handled (each node, and the virtual name, need their own). |
| `ldaps` - LDAPS on a domain controller | copies the certificate's registry key into the NTDS service store (`HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates`; older acme ones removed from there), or only LocalMachine\My; then `ldifde -i -f` with `dn:` / `changetype: modify` / `add: renewServerCertificate` / `renewServerCertificate: 1` / `-` (no restart); `host:636` added to the TLS check | `ldaps_store` (ntds / my), `ldaps_verify` | Copying the registry key is the usual scripted way into a service store (the MMC way is manual). With LocalMachine\My only, the DC picks one of the suitable certificates itself, which may not be the newest. |
| `winrm` - WinRM HTTPS | every listener with `Transport=HTTPS`: `WSMan:\localhost\Listener\<name>\CertificateThumbprint` set; with none, either an error or (option) `New-Item WSMan:\localhost\Listener -Transport HTTPS -Address * -HostName <name> -CertificateThumbPrint`; firewall rule `acme-WinRM-HTTPS-In` TCP 5986 (option); `Restart-Service WinRM` when changed | `winrm_create`, `winrm_hostname` (empty: the certificate's first name that is not a wildcard), `winrm_firewall` | It runs over SSH, so restarting WinRM cuts nothing of its own. |
| `sstp` - RRAS SSTP VPN | `Set-RemoteAccess -SslCertificate (the certificate)`; `Restart-Service RemoteAccess` | `sstp_restart` | Some builds may want RemoteAccess stopped before `Set-RemoteAccess`. Not tested on every version. |
| `ccs` - IIS Central Certificate Store | a PFX locked with the store's password, written as `<host>.pfx`, or `_.<domain>.pfx` for `*.<domain>` (the CCS naming), for every name or only the first; an existing file with the same certificate is left alone (`Get-PfxData`); no binding | `ccs_path` (UNC or local), `ccs_password` (secret), `ccs_names` | A UNC path is reached as the SSH user. With key sign-in there are no network credentials: use a local folder or a share the computer account may write. |
| `ftp` - IIS FTP over TLS | `Microsoft.Web.Administration`: `ftpServer/security/ssl` `serverCertHash` (and `serverCertStoreName=My`) of a site, or of `siteDefaults` when no site is given | `ftp_site`, `ftp_restart` | Whether FTP picks it up without a restart of `ftpsvc` is not sure: turn the restart on if it does not. |
| `exchange` - Exchange (extended) | snap-in loaded when needed; `Get-ExchangeCertificate` first; `Enable-ExchangeCertificate -Thumbprint -Services IIS,SMTP,… -Force -Confirm:$false` (the default SMTP certificate replaced without the prompt; no `-DoNotRequireSsl`); IMAP4/POP3 (front end and back end) restarted when chosen and changed; old acme Exchange certificates whose `Services` are `None` removed (switch), the others kept with a warning | `ex_iis`, `ex_smtp`, `ex_imap`, `ex_pop`, `ex_um`, `ex_umcr`, `ex_remove_old`, `ex_restart` | UM and UMCallRouter exist only up to Exchange 2016. The older *Exchange services* text field still works next to this. |
| `lync` - Skype for Business / Lync | `Import-Module SkypeForBusiness` (or `Lync`); `Set-CsCertificate -Type Default\|WebServicesInternal\|WebServicesExternal -Thumbprint` for the types whose `Get-CsCertificate` differs; optional `Stop-/Start-CsWindowsService` | `cs_default`, `cs_internal`, `cs_external`, `cs_restart` | Public CAs no longer put *Client Authentication* in server certificates (Let's Encrypt from 2026). The Default certificate (server-to-server MTLS) usually needs it, so for Default use a CA that still issues it. OAuth certificates are not touched. |
| `sharepoint` - SharePoint Server SE (**beta**) | snap-in; `Get-SPCertificate` by thumbprint, else `Import-SPCertificate -Path <pfx> -Password … -Exportable`; `Set-SPWebApplication -Identity <url> -Zone <zone> -Port <port> -SecureSocketsLayer -Certificate <cert> [-HostHeader … -UseServerNameIndication]` | `sp_url`, `sp_zone`, `sp_port` (443), `sp_host` | Subscription Edition only (certificate management). Best effort, not tried on a farm: parameter sets may differ by version. |
| `wac` - Windows Admin Center | service `WindowsAdminCenter` (2410 and later): module `Microsoft.WindowsAdminCenter.Configuration` (from the module path, or under `Program Files\WindowsAdminCenter\PowerShellModules`), `Set-WACCertificateSubjectName -SubjectName <CN without "CN="> [-Thumbprint, when the cmdlet has it]`, `Set-WACCertificateAcl -SubjectName …` (when there), `Restart-Service WindowsAdminCenter`. Service `ServerManagementGateway` (older): when `netsh http show sslcert` for its port does not show the thumbprint, `msiexec /i <msi> /qn SME_PORT=<port> SME_THUMBPRINT=<thumb> SSL_CERTIFICATE_OPTION=installed` | `wac_msi` (older versions only), `wac_port` (empty: `SmePort` from the registry, else 443) | **Uncertain**: the 2410+ cmdlets and their parameters are from memory and from reports that differ (the service is said to be `WindowsAdminCenter` and, by some, `wacs`). Look at the job's steps after the first run. |

**Example**: on an AD FS server, *Role: AD FS* on (all its switches), verify
`sts.example.com:443`. On a domain controller, *Role: LDAPS* on: the TLS check on
`<host>:636` is added by itself.

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

## `webglobe` - Webglobe hosting

Stores the certificate as the **own SSL certificate** of a domain hosted at
Webglobe, through the Webglobe API: signed in as the Webglobe validation does
(`POST /auth/login` with the login and an API key → a JWT), the domain found
by its name (`GET /domains`, else `GET /domains/{name}`; or give its ID), the
certificate, key and chain (PEM, the chain apart) first checked by Webglobe
(`POST /{domainId}/ssl/validate`, deployment option *Let Webglobe check it
first*), then stored (`POST /{domainId}/ssl/own-certificate`). *Redirect
http to https* sets `POST /{domainId}/ssl/httpsRedirect` when it is on or
off, and leaves it otherwise. *Test* signs in, finds the domain and reads its
certificates (`GET /{domainId}/ssl`) - it changes nothing.

**Rights**: a login of the account (best a sub-account that sees only the
hosted domain) and an API key of it (*My account → API keys*) that allows
acme's public IP address. Webglobe takes its customers' own certificates
**only with its paid support**; without it the API answers code 3 (access to
the module denied), said so.

Source: the Webglobe API's OpenAPI description, <https://api.webglobe.com/>
(a copy in `test/fixtures/webglobe-openapi.yaml`). **Uncertain**: whether a
new own certificate replaces the one stored before or is kept beside it
(acme deletes nothing; older ones can be removed in the administration);
the answer of `own-certificate` is described twice (an `id`, or the checked
certificate's data) - both are read.

## `kong` - Kong Gateway

The Kong **Admin API** (`http://<kong>:8001`; Kong Gateway Enterprise: the
*Workspace* and an RBAC *Admin token*, sent as `Kong-Admin-Token`). Each
renewal adds a **new certificate object** (`POST /certificates`, the full
chain and the key, tagged `acme`, `acme-<name>`, `acme-fp-<fingerprint>` and
`acme-at-<date>-<serial>`), then points each **SNI** at it (`PUT
/snis/<name>` `{"certificate": {"id"}}` - an upsert, so an SNI that is not
there yet is made). *SNIs* empty: the names of the certificate (wildcards
too, Kong takes `*.example.com`). Older acme certificates of this name beyond
*keep* are deleted (`DELETE /certificates/<id>`) - never one an SNI still
uses. A **dual certificate** goes into one object: the twin as `cert_alt` /
`key_alt`, and Kong serves each client the kind it takes. *Test* reads the
version (`GET /`) and one certificate. Kong without a database (DB-less) has
an Admin API that cannot change anything - acme says so.

Sources (Kong's own code, the Admin API's definition):
<https://github.com/Kong/kong/blob/master/kong/db/schema/entities/certificates.lua>,
<https://github.com/Kong/kong/blob/master/kong/db/schema/entities/snis.lua>,
<https://github.com/Kong/kong/blob/master/kong/api/routes/certificates.lua>,
<https://github.com/Kong/kong/blob/master/kong/api/endpoints.lua> (the `tags`
filter). **Uncertain**: Kong's documentation site was not reachable from here,
so its pages were not read; Kong Konnect (the hosted control plane) is not
covered - only a Kong Admin API.

## `hetzner_lb` - Hetzner Cloud Load Balancer

The Hetzner Cloud API (`https://api.hetzner.cloud/v1`, a project's API token
with *Read & Write*, `Authorization: Bearer`). The certificate is uploaded as
type `uploaded` under a dated name (`POST /certificates` - full chain and
key, label `managed-by=acme`); each listed **load balancer** (its name or ID)
is read (`GET /load_balancers/<id>` or `?name=`) and each of its **HTTPS
services** - all of them, or those of the *Listen ports* listed - gets it
(`POST /load_balancers/<id>/actions/update_service` `{"listen_port", "http":
{"certificates": [...]}}`, the action waited for at `GET
/load_balancers/actions/<id>`). A service holds several certificates (chosen
by SNI): only the older acme one of this certificate is taken out, others
stay - unless *Replace every certificate of the service*. Older acme
certificates beyond *keep* that no load balancer uses are deleted. The action
**List the load balancers** shows them, their HTTPS services and the
certificates on each - it changes nothing.

Sources (Hetzner's official Go library, which the `hcloud` CLI is built on):
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/certificate.go>,
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/schema/certificate.go>,
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/load_balancer.go>,
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/schema/load_balancer.go>,
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/action.go>,
<https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/client.go>.
**Uncertain**: docs.hetzner.cloud was not reachable from here; the calls are
those of the library.

## `digitalocean_lb` - DigitalOcean Load Balancer

The DigitalOcean API (`https://api.digitalocean.com`, a personal access token
with the *certificate* and *load_balancer* scopes). The certificate is
uploaded as a `custom` certificate under a dated name (`POST
/v2/certificates` - `leaf_certificate`, `certificate_chain`, `private_key`);
each listed **load balancer** (name or ID) is read and sent back whole with
its **HTTPS forwarding rules** (`https`, `http2`, `http3`; not TLS
passthrough; all, or those of the *Entry ports* listed) pointed at it (`PUT
/v2/load_balancers/<id>` - DigitalOcean replaces a load balancer as a whole,
so acme sends exactly what the official library's `AsRequest()` sends: the
same settings, the region as its slug). Older acme certificates beyond *keep*
are deleted; one still used is refused by DigitalOcean and stays. **List the
load balancers** shows them and their HTTPS rules - it changes nothing.

Sources (DigitalOcean's official Go library, which `doctl` is built on):
<https://github.com/digitalocean/godo/blob/main/certificates.go>,
<https://github.com/digitalocean/godo/blob/main/load_balancers.go>,
<https://github.com/digitalocean/godo/blob/main/godo.go>. **Uncertain**:
docs.digitalocean.com was not reachable from here.

## `avi` - VMware Avi Load Balancer (NSX ALB)

The Avi Controller's REST API: `POST /login` (a local or remote user; the
session and the CSRF token come back as two cookies), then each call with
`X-CSRFToken`, `Referer`, `X-Avi-Tenant` (*Tenant*) and `X-Avi-Version` (the
Controller's own, or *API version*). The intermediates are added once as CA
certificates (`acme-ca-<id>`, type `SSL_CERTIFICATE_TYPE_CA` - Avi builds the
chain from its CA certificates), the certificate as an SSL key and
certificate under a dated name (`POST /api/sslkeyandcertificate`, type
`SSL_CERTIFICATE_TYPE_VIRTUALSERVICE`); each listed **virtual service** gets
it in place of the older acme one (`PATCH /api/virtualservice/<uuid>`
`{"replace": {"ssl_key_and_certificate_refs": [...]}}`). *Controller portal
certificate* instead makes it a `SSL_CERTIFICATE_TYPE_SYSTEM` certificate
(named `acme-<name>-portal-…`) and sets it as the portal's
(`portal_configuration.sslkeyandcertificate_refs` of `/api/systemconfiguration`,
the rest of the portal configuration sent back as it was) - one deployment
for the portal, another for virtual services. A **dual certificate**: both
are added (the twin as `acme-<name>-<kind>-…`) and a virtual service gets one
of each kind. Older acme ones beyond *keep* are deleted; Avi refuses one in
use, and it stays. acme signs out at the end (`POST /logout`).

Sources (VMware's official Avi SDK and its object model):
<https://github.com/vmware/alb-sdk/blob/eng/python/avi/sdk/avi_api.py>,
<https://github.com/vmware/alb-sdk/blob/eng/python/avi/sdk/utils/ansible_utils.py>
(the `replace` patch), <https://github.com/vmware/alb-sdk/blob/eng/go/models/s_s_l_key_and_certificate.go>,
<https://github.com/vmware/alb-sdk/blob/eng/go/models/s_s_l_certificate.go>,
<https://github.com/vmware/alb-sdk/blob/eng/go/models/virtual_service.go>,
<https://github.com/vmware/alb-sdk/blob/eng/go/models/portal_configuration.go>.
**Uncertain**: the field of the Controller version in the login answer
(`version.Version`; set *API version* when acme cannot read it).

## `bunny` - bunny.net CDN (pull zone hostnames)

The bunny.net API (`https://api.bunny.net`, the account's API key as the
`AccessKey` header). The **pull zone** is found by its ID (`GET
/pullzone/<id>`) or its name (`GET /pullzone?search=`), and each **custom
hostname** - those listed, or every one the certificate covers - gets the
certificate (`POST /pullzone/<id>/addCertificate` `{"Hostname",
"Certificate", "CertificateKey"}`, the full chain and the key base64). bunny
keeps one certificate a hostname: the new one takes the place of the one
before, and nothing is left to clean up. **List the pull zones** shows them
and their hostnames - it changes nothing.

Sources (bunny.net's official Terraform provider):
<https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/pullzone_hostname.go>,
<https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/pullzone.go>,
<https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/client.go>.
**Uncertain**: docs.bunny.net was not reachable from here; *Try it* and the
list ask `GET /pullzone?search=` with nothing searched for.

## `fastly` - Fastly TLS (your own certificate)

The Fastly API (`https://api.fastly.com`, a token as `Fastly-Key`, JSON:API
bodies). The new key is uploaded under a dated name (`POST
/tls/private_keys`), then the certificate acme put on Fastly before - found
by its name, or the one given as *Fastly certificate ID* - is **replaced in
place** (`PATCH /tls/certificates/<id>` with the full chain), so its
activations (the domains it serves, on which TLS configuration) stay. The
first time there is none: a new certificate is added (`POST
/tls/certificates`) and acme says to **activate it once** in Fastly; every
renewal after that replaces it. Older acme keys no certificate uses any more
(`GET /tls/private_keys?filter[in_use]=false`) are deleted beyond *keep*.

Sources (Fastly's official Go client, which the Fastly CLI and Terraform
provider use): <https://github.com/fastly/go-fastly/blob/main/fastly/tls_custom_certificate.go>,
<https://github.com/fastly/go-fastly/blob/main/fastly/tls_private_keys.go>,
<https://github.com/fastly/go-fastly/blob/main/fastly/client.go>.
**Uncertain**: activations are not made by acme (the first one is yours);
developer.fastly.com was not reachable from here.

## `nginx_proxy_manager` - Nginx Proxy Manager

Its API (`http://<npm>:81/api`): a token from `POST /api/tokens` (an NPM
user's e-mail and password; a user with two-factor sign-in cannot be used),
the certificate added as a **custom certificate** under a dated name (`POST
/api/nginx/certificates` `{"provider": "other"}`), its files uploaded (`POST
…/<id>/upload`: certificate, key, intermediates), then each listed **proxy
host** (a domain name it serves, or its ID), redirection host and 404 host
pointed at it (`PUT /api/nginx/proxy-hosts/<id>` `{"certificate_id"}` - NPM
writes the host's nginx configuration and reloads nginx). *Also the hosts
that use the older one* (on by default) moves every host that used an older
acme certificate of this name too. Older acme certificates beyond *keep* are
deleted only when no host uses them; Let's Encrypt certificates NPM made
itself are never touched.

Sources (the project's own code):
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/routes/nginx/certificates.js>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/certificate.js>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/routes/tokens.js>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/token.js>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/proxy-host.js>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/schema/paths/nginx/certificates/post.json>,
<https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/schema/paths/nginx/proxy-hosts/hostID/put.json>.

## `a10` - A10 Thunder (ACOS aXAPI)

aXAPI v3: `POST /axapi/v3/auth` (then `Authorization: A10 <signature>`), the
*Partition* made active when it is not `shared`. The certificate and its key
are imported as SSL files under a dated name (`POST /axapi/v3/file/ssl-cert`
and `/file/ssl-key`, multipart: a `json` part `{"ssl-cert": {"file",
"action": "import", "certificate-type": "pem", "file-handle"}}` and the
`file`), the intermediates once as one chain file `acme-ca-<id>`; each listed
**client-SSL template** gets them (`POST
/axapi/v3/slb/template/client-ssl/<name>/certificate` `{"certificate":
{"cert", "key", "chain-cert"}}`); *Write the configuration* (on) does `write
memory`. Older acme files beyond *keep* are deleted (`POST /axapi/v3/pki/delete`
`{"delete": {"cert-name"}}` and `{"private-key"}`); ACOS refuses one in use
and it stays. acme signs off at the end.

Sources (A10's official Ansible collection, generated from the aXAPI schema):
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/auth.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/client.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/axapi_client.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_file_ssl_cert.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_file_ssl_key.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_slb_template_client_ssl_certificate.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_write_memory.py>,
<https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_pki_delete.py>.
**Uncertain**: the shape of the file list (`GET /axapi/v3/file/ssl-cert/oper`,
`file-list[].file`) is taken from the module's `oper` description; ACOS 4.1
and later (the `certificate` object of a client-SSL template).

## `nutanix` - Nutanix cluster (Prism Central v4 API)

Replaces the **SSL certificate of a cluster** - its Prism web console and API
- through Prism Central's v4 API (HTTP basic sign-in of a Prism Central
user, port 9440). The cluster is its `extId` or its name; *Clusters of Prism
Central* → *Load the list* asks `GET /api/clustermgmt/<v>/config/clusters`
and fills the extId in (it can always be typed). The certificate's ETag is
read (`GET …/clusters/<extId>/ssl-certificate`), then the certificate, key
and chain are sent base64 with the key's algorithm (`PUT …/ssl-certificate`,
`If-Match` and a new `NTNX-Request-Id`; `ECDSA_256`, `ECDSA_384`,
`ECDSA_521`, `RSA_2048`, `RSA_4096` - taken from the key, or chosen in *Key
algorithm*; an RSA 3072 key is refused, Nutanix has no such one), and the
task it starts is waited for (`GET /api/prism/<v>/config/tasks/<extId>` until
`SUCCEEDED`). The web console restarts with the new certificate; *Check what
is served* (port 9440 by default) then sees it. *API version* (`v4.3` by
default) is the version of the clustermgmt and prism APIs Prism Central
serves.

Sources (Nutanix's official v4 Go client and Terraform provider):
<https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/api/ssl_certificate_api.go>,
<https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/api/clusters_api.go>,
<https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/models/clustermgmt/v4/config/config_model.go>,
<https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/prism-go-client/api/tasks_api.go>,
<https://github.com/nutanix/terraform-provider-nutanix/blob/dadc2b20bd0a96f6358104a555f89a3e0b3638ca/nutanix/services/clustersv2/resource_nutanix_ssl_certificate_v2.go>,
<https://github.com/nutanix/terraform-provider-nutanix/blob/dadc2b20bd0a96f6358104a555f89a3e0b3638ca/website/docs/r/ssl_certificate_v2.html.markdown>.
**Uncertain**: the older v4 versions (`v4.0`-`v4.2`) were not checked for
the ssl-certificate call; the key goes as PKCS#8 PEM (`BEGIN PRIVATE KEY`).

## `azure_appservice` - Azure App Service

Azure Resource Manager (`https://management.azure.com`, `api-version=2023-12-01`;
an app registration's client secret, as `azure_keyvault`). The certificate is
uploaded as a PKCS#12 (3DES by default, a one-time password) to the resource
group under a dated name, in the web app's region and App Service plan (`PUT
…/Microsoft.Web/certificates/<name>` `{"location", "properties": {"pfxBlob",
"password", "serverFarmId"}}`), then each **custom hostname** of the *Web
app* - those listed, or every one the certificate covers (not
`*.azurewebsites.net`) - is bound to it with SNI SSL (`PUT
…/sites/<app>/hostNameBindings/<host>` `{"properties": {"sslState":
"SniEnabled", "thumbprint"}}`); one bound to it already is left alone. Older
acme certificates of the resource group beyond *keep* are deleted; Azure
refuses one still bound, and it stays.

**Rights**: *Website Contributor* on the web apps and *Web Plan Contributor*
on their plan (or *Contributor* on the resource group).

Sources (Microsoft's official REST API specification):
<https://github.com/Azure/azure-rest-api-specs/blob/main/specification/web/resource-manager/Microsoft.Web/AppService/stable/2023-12-01/Certificates.json>,
<https://github.com/Azure/azure-rest-api-specs/blob/main/specification/web/resource-manager/Microsoft.Web/AppService/stable/2023-12-01/WebApps.json>.
**Uncertain**: deployment slots are not handled (only the production app);
learn.microsoft.com was not reachable from here.
