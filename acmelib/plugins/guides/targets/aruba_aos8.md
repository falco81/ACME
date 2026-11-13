# HPE Aruba Networking ArubaOS 8 (Mobility Conductor, controllers) - setup for acme

acme signs in to the controller over **SSH** and sends CLI lines in an SSH shell session. AOS 8 takes a certificate file only from its own **flash**, and nothing - not its REST API, not the CLI - lets acme hand the file over directly. So acme puts the file on a **staging server** (a Linux server it reaches over SSH) and has the controller fetch it with `copy tftp:` (or `copy scp:`). Then:

1. `crypto pki-import pfx ServerCert acme-<name>-<date>-<serial> <file> <one-time password>` - the certificate with its key (PKCS#12); the CAs of the chain as `IntermediateCA` / `TrustedCA` named `acme-ca-<id>`, once;
2. `web-server profile` → `switch-cert` (WebUI management) and optionally `captive-portal-cert`;
3. `write memory`;
4. the file is deleted from the staging server and from flash right away; older acme `ServerCert`s beyond *keep* that nothing references are removed (`no crypto-local pki ServerCert`).

> **Unverified**: the HPE techdocs could not be opened in full while this module was written. The commands come from the AOS 8 CLI Bank pages (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`) as seen in excerpts, and from the vendor guide. Not checked on a device: lines sent to a shell session without a terminal, the answer to the password `copy scp:` asks, `delete filename`, the layout of `show crypto-local pki`, whether the controller serves the chain from the PKCS#12. Try it on one controller first and watch the job's steps.

## Which AOS 8 this guide is for

Module version **"any version (detects it)"** - the only one: **ArubaOS 8.6 - 8.13** (Mobility Conductor, Mobility Controller, also a standalone controller). No document read shows a difference in these commands between 8.10, 8.12 and 8.13. acme reads `show version`: **AOS 6** (other `web-server` commands) and **AOS 10** (configured from Central - use the target `aruba_central`) are refused before anything is changed; newer than 8.13 is warned.

## What acme changes on the controller

| acme option | AOS 8 CLI | Effect |
|---|---|---|
| (always) | `copy tftp: <stage> <file> flash: <file>`, `crypto pki-import pfx ServerCert <name> <file> <pw>`, `delete filename <file>` | a new server certificate; the file is gone from flash afterwards |
| Import the chain | `crypto pki-import pem IntermediateCA` / `TrustedCA acme-ca-<id> <file>` | each CA once, kept for the next certificates |
| Configuration node (Conductor) | `cd <node>`, `crypto-local pki ServerCert <name> <file>` | the certificate known at that node of the hierarchy |
| WebUI management certificate | `web-server profile`, `no switch-cert`, `switch-cert <name>` | **the web server restarts**: WebUI and REST API sessions on 4343 are cut for a moment |
| Captive portal certificate | `web-server profile`, `no captive-portal-cert`, `captive-portal-cert <name>` | new guest sign-ins get the new certificate |
| Save the configuration | `write memory` | without it the change is gone after a reload |
| Previous versions to keep | `no crypto-local pki ServerCert <old>` | only acme's own, only with reference count 0 |

## Set up the controller

### 1. An account for acme

Importing certificates and changing `web-server profile` needs the **root** management role (AOS 8 has no role for certificates only). On the Conductor or the controller:

```text
configure terminal
mgmt-user acme root
write memory
```

`mgmt-user` asks for the password twice. Better: an account from TACACS+ / RADIUS (ClearPass) with the root role, audited, and management reachable only from acme's address. Sign in with a **password** in acme (SSH key sign-in on AOS 8 was not checked for this module). If the account lands in the non-privileged prompt (`>`), fill in *Enable password*.

### 2. The staging server

Any Linux server the controller reaches. With **TFTP** (the default):

```sh
sudo apt-get install tftpd-hpa
sudo useradd -m -s /bin/bash acme
sudo passwd acme
sudo chown acme /srv/tftp
sudo systemctl enable --now tftpd-hpa
```

- the controller must reach UDP **69** of the server (and the replies); acme must reach its SSH port;
- the file (with the private key, encrypted with a one-time password) lies there only for the seconds of the copy and is readable by the TFTP server; acme deletes it right after.

With **SCP** (`copy scp:`) the controller signs in to the staging server itself, with the staging user's password (set *Sign in with* of the staging server to a password); the file stays the user's own (mode 600). The folder can be any one the user may write to, e.g. `/home/acme/stage`.

### 3. Mobility Conductor

On a Conductor, the WebUI certificate is set in the `web-server profile` of the node where it is used (`/md`, `/md/branch`, `/mm/mynode`). Fill in *Configuration node*: acme runs `cd <node>` and `crypto-local pki ServerCert <name> <file>` there. A standalone controller needs neither. In a cluster, a member may keep its own setting (a node-level override) - check `show web-server profile` on each.

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **any version (detects it)** |
| Address | the management address of the controller, e.g. `mcr01.example.com` |
| SSH port / User | `22` / `acme` |
| Sign in with, Password | a password (step 1) |
| Host key (advanced) | the controller's known_hosts line; empty with *Trust the first host key seen* takes the first one |
| Enable password (advanced) | only when the account lands in `>` mode |
| Configuration node (advanced) | Conductor: `/md/branch` or `/mm/mynode`; standalone: empty |
| WebUI port (advanced) | `4343` |
| PKCS#12 encryption (advanced) | 3DES with a SHA-1 MAC |
| The controller fetches the file with | TFTP from the staging server (or SCP) |
| Staging server | the address acme signs in to over SSH, e.g. `tftp.example.com` |
| Its address for the controller | the address the controller reaches it at (empty: the same) |
| Folder on the staging server | `/srv/tftp` (the TFTP root) |
| SSH port / User / Sign in with (staging server) | `22` / `acme` / a key of acme or a password (SCP: a password) |
| WebUI management certificate (switch-cert) (deploy) | on |
| Captive portal certificate (captive-portal-cert) (deploy) | as needed; *Captive portal name* for the test |
| Import the chain (IntermediateCA, TrustedCA) (deploy) | on |
| Save the configuration (write memory) (deploy) | on |
| Previous versions to keep (advanced) | `1` |

## Check it

On the controller:

```text
show crypto-local pki ServerCert
show crypto-local pki IntermediateCA
show web-server profile
```

From acme's machine:

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| *the device said "Error: ... not found in path /md/..."* | the certificate is not known at that node | fill in *Configuration node*, or import on the node where the profile is |
| *copying ... to flash: ...* | the controller could not fetch the file | UDP 69 to the staging server, the TFTP root = *Folder on the staging server*; SCP: the password |
| *Expecting string of length 1 to 31* | a name too long | acme's names fit 31 characters; a name of your own (*object_name*) must too |
| *... is not there after the import* | the import said nothing but did not take it | `show crypto-local pki ServerCert`; try *PKCS#12 encryption* 3DES |
| *runs ArubaOS 10 ...* | an AOS 10 gateway | target `aruba_central` |
| the test of what is served fails right after | the web server is restarting | it waits by itself |
| WebUI shows only the server certificate, no chain | the chain is not served | keep *Import the chain* on |

Sources: AOS 8 CLI Bank (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`), AOS 8 User Guide (Managing Certificates, Configuring Certificate Authentication for WebUI Access, SCP server support), AOS 8 REST API reference (no certificate upload), the vendor guide `aos8-aos10-central.md`.
