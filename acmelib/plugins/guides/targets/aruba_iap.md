# HPE Aruba Networking Instant AP (AOS 8) - setup for acme

acme signs in over **SSH** to the **virtual controller** of an Instant AP cluster (certificates are imported only on the conductor AP and go to every member) and sends CLI lines in an SSH shell session. The AP takes a certificate only from a server it fetches it from, so acme puts the file on a **staging server** (a Linux server it reaches over SSH, served by TFTP or another URL), lets the AP fetch it and deletes it right after. What the AP is told depends on its version:

| Module version | Instant | What acme sends |
|---|---|---|
| any version (detects it) | 8.3 - 8.13 | by `show version`: 8.7 and later the way of 8.7, before it the way of 8.3; unknown: 8.7 (warned) |
| Instant 8.3 - 8.6 | 8.3 - 8.6 | `copy tftp <stage> <file> uiserver cert <pw> format pem` (WebUI), `... cpserver ...` (captive portal) - a PEM with the key encrypted by a one-time password, the certificate and the chain |
| Instant 8.7 - 8.13 | 8.7 - 8.13 | `crypto pki-import format pfx cert-type ServerCert url <url> certname <name> psk <pw>`, then `wlan cert-assignment-profile` / `pki-cert-assign application ui` (and `captive-portal`) `cert-type ServerCert certname <name>`, `commit apply` |

From Instant 8.7.0.0 a certificate takes effect only when it is assigned to an application - that is why the versions differ. AOS 10 APs (configured in Central) are refused: use the target `aruba_central`. An Instant cluster managed by Central: also `aruba_central` - a change made on the virtual controller is overwritten by Central.

> **Unverified**: the HPE techdocs could not be opened in full while this module was written; the commands are from the Instant CLI Bank pages (`crypto pki-import`, `wlan cert-assignment-profile`, `copy`) and the Instant 8.x user guide as seen in excerpts. Not checked on a device: the keyword form of `crypto pki-import` (the CLI Bank's example has a typo) and which URL schemes the AP fetches from (its example is FTP) - so the command is the advanced field *Import command (Instant 8.7 and later)* and the URL the field *URL the AP fetches it from*; `commit apply` after the assignment; lines sent to a shell session without a terminal. acme does not remove older certificates from the AP (`crypto pki-remove` by hand).

## Set up the AP

### 1. An account for acme

Instant has one local administrator (`admin`) with full rights, or administrators from RADIUS / TACACS+ with the role *admin*. acme needs the full one: the import and `commit apply` are configuration.

```text
configure terminal
mgmt-user admin <a-strong-password>
exit
commit apply
```

Sign in with a **password** in acme. SSH must be on (Instant: *System > Admin > SSH*, or the default).

### 2. The staging server

Any Linux server the AP reaches. With **TFTP**:

```sh
sudo apt-get install tftpd-hpa
sudo useradd -m -s /bin/bash acme
sudo passwd acme
sudo chown acme /srv/tftp
sudo systemctl enable --now tftpd-hpa
```

The AP must reach UDP **69** of the server. The file (the private key encrypted with a one-time password) lies there only for the seconds of the fetch. For FTP, set *URL the AP fetches it from* to e.g. `ftp://user:password@{addr}/{dir}/{file}` and point *Folder on the staging server* at the FTP user's folder.

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **any version (detects it)** (or the one for your Instant) |
| Address | the virtual controller's address, e.g. `iap.example.com` |
| SSH port / User | `22` / `admin` |
| Sign in with, Password | a password |
| Host key (advanced) | the AP's known_hosts line; empty with *Trust the first host key seen* takes the first one |
| WebUI port (advanced) | `4343` |
| Import command (Instant 8.7 and later) (advanced) | leave it, unless your Instant says another syntax |
| Staging server | the address acme signs in to over SSH |
| Its address for the AP | the address the AP reaches it at (empty: the same) |
| Folder on the staging server | `/srv/tftp` (the TFTP root) |
| SSH port / User / Sign in with (staging server) | `22` / `acme` / a key of acme or a password |
| URL the AP fetches it from (advanced) | `tftp://{addr}/{file}` |
| WebUI certificate (deploy) | on |
| Captive portal certificate (deploy) | as needed; *Captive portal name* for the test |

## Check it

On the AP:

```text
show cert assignment
show version
```

From acme's machine:

```sh
openssl s_client -connect iap.example.com:4343 -servername iap.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| *the device said "% Invalid input ..."* at the import | this Instant has another syntax | correct *Import command*; or choose *Instant 8.3 - 8.6* when it is older than 8.7 |
| *Validate certificate date failed* / *Cert file check fail* | the AP's clock (a known Instant 8.3 bug compares local time with GMT) | NTP and the time zone on the AP |
| *show cert assignment does not name ...* | the assignment did not take | `show cert assignment`, `commit apply` by hand |
| *runs AOS 10 ...* | an AOS 10 AP | target `aruba_central` |
| *the module version ... is for Instant ...* | the AP runs another Instant | choose the version named in the message |

Sources: Instant CLI Bank (`crypto pki-import`, `crypto pki-remove`, `wlan cert-assignment-profile`, `copy`), Instant 8.x user guide (Authentication Certificates, Uploading Certificates), the vendor guide `aos8-aos10-central.md`.
