# HPE Aruba Networking Instant AP (AOS 8) (Instant 8.7 - 8.13) - setup for acme

acme signs in over **SSH** to the **virtual controller** of an Instant AP cluster running **Instant 8.7 - 8.13** and sends CLI lines in an SSH shell session. It puts a **PKCS#12** (key, certificate, chain; a one-time password) on a **staging server** (a Linux server it reaches over SSH, served by TFTP or another URL), has the AP import it and assigns it - from Instant 8.7.0.0 a certificate takes effect only when assigned to an application:

```text
crypto pki-import format pfx cert-type ServerCert url tftp://<staging server>/acme-<serial>.pfx certname acme-<name>-<date>-<serial> psk <one-time password>
configure terminal
wlan cert-assignment-profile
pki-cert-assign application ui cert-type ServerCert certname acme-<name>-<date>-<serial>
pki-cert-assign application captive-portal cert-type ServerCert certname acme-<name>-<date>-<serial>
exit
exit
commit apply
```

`captive-portal` only when chosen. Then `show cert assignment` must name the new certificate (else a warning). The file is deleted from the staging server right after the import.

Module version **Instant 8.7 - 8.13**: an AP that says another version (`show version`) is refused before anything is changed - before 8.7 choose *Instant 8.3 - 8.6*.

> **Unverified**: the keyword form of `crypto pki-import` (format / cert-type / url / certname / psk) and the URL schemes the AP fetches from are from the Instant CLI Bank as seen in excerpts (its example uses FTP and has a typo) - the command is the advanced field *Import command (Instant 8.7 and later)* (`{format}` `{url}` `{name}` `{psk}`) and the URL the field *URL the AP fetches it from*, so both can be corrected; `commit apply` after the assignment; not checked on a device. acme does not remove older certificates (`crypto pki-remove` by hand).

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
| Module version | **Instant 8.7 - 8.13** |
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
