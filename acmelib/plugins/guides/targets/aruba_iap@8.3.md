# HPE Aruba Networking Instant AP (AOS 8) (Instant 8.3 - 8.6) - setup for acme

acme signs in over **SSH** to the **virtual controller** of an Instant AP cluster running **Instant 8.3 - 8.6** and sends CLI lines in an SSH shell session. It puts a **PEM** - the private key encrypted with a one-time password, the certificate and its chain - on a **staging server** (a Linux server it reaches over SSH, whose folder a TFTP server serves) and has the AP load it:

```text
copy tftp <staging server> acme-<serial>.pem uiserver cert <one-time password> format pem
copy tftp <staging server> acme-<serial>.pem cpserver cert <one-time password> format pem
```

The first is the WebUI certificate (4343), the second the captive portal's (only when chosen). The certificate takes effect at once - these versions have no certificate assignment profile and no `commit apply` is needed. The file is deleted from the staging server right after.

Module version **Instant 8.3 - 8.6**: an AP that says another version (`show version`) is refused before anything is changed - Instant 8.7 and later want the import and assignment of *Instant 8.7 - 8.13*.

> **Unverified**: the `copy tftp ... uiserver|cpserver cert <password> format pem` words are from the Instant CLI Bank / 8.3 user guide as seen in excerpts (older Instant said `ui` / `cp`); only TFTP is used (the *URL the AP fetches it from* field is not used by this version); not checked on a device. acme does not remove older certificates.

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
| Module version | **Instant 8.3 - 8.6** |
| Address | the virtual controller's address, e.g. `iap.example.com` |
| SSH port / User | `22` / `admin` |
| Sign in with, Password | a password |
| Host key (advanced) | the AP's known_hosts line; empty with *Trust the first host key seen* takes the first one |
| WebUI port (advanced) | `4343` |
| Staging server | the address acme signs in to over SSH |
| Its address for the AP | the address the AP reaches it at (empty: the same) |
| Folder on the staging server | `/srv/tftp` (the TFTP root) |
| SSH port / User / Sign in with (staging server) | `22` / `acme` / a key of acme or a password |
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
