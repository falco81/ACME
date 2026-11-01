# acme

Certificates kept, renewed and put in place by themselves - an appliance for
one server or a cluster of two.

acme orders and renews certificates - from Let's Encrypt and any other ACME CA,
from certificate authorities of its own, from Microsoft AD CS or by SCEP - and
answers the CA's validation itself: with its own DNS server (DNS-01, UDP and
TCP 53), through your DNS provider's API, or on port 80 (HTTP-01). Every new
certificate is put where it is used - Linux and Windows servers over SSH, F5,
NetScaler, FortiGate, MikroTik, Palo Alto, Kubernetes, Vault and more - in the
format that place wants, and the service there is made to take it. Every step
of every renewal and deployment is written down, and what fails is said: by
mail, SMS, syslog/SIEM and isemon.

```
    acme --status                    what it is doing, in one screen
    acme --certs                     every certificate it keeps
    acme --cert NAME                 one: its versions, deployments, jobs
    acme --renew NAME | all          now, the steps as they come
    acme --deploy NAME               every deployment of it, now
    acme --jobs   /   acme --job ID  what was done, every step
    acme --console                   the menus, on the server's own screen
    acme --help                      all of it
```

The daemon itself is `acme --daemon` (systemd starts it). The pages are
`https://<host>/admin/`.

## What is in it

| | |
|---|---|
| issuers | ACME (RFC 8555; Let's Encrypt, ZeroSSL, step-ca, ...; EAB, profiles, ARI - RFC 9773), acme's own CAs (root and intermediate, CRLs, name constraints), self-signed, Microsoft AD CS, SCEP |
| challenges | DNS-01: acme's own DNS server, RFC 2136, Cloudflare, Route 53, Azure, Google Cloud, Hetzner, OVH, DigitalOcean, PowerDNS, deSEC, Gandi, Linode, Vultr, Porkbun, Namecheap, GoDaddy, DNSimple, NS1, bunny.net, ClouDNS, INWX, TransIP, netcup, IONOS, Scaleway, Exoscale, Infoblox, Technitium, Hurricane Electric, WEDOS, Active24, Websupport, acme-dns, a script, by hand ([validation.md](docs/validation.md)); HTTP-01: here (nginx → `acme.php`), or on another web server over SSH |
| targets | Linux and Windows over SSH, F5 BIG-IP, NetScaler, FortiGate, MikroTik, Palo Alto, pfSense, OPNsense, Proxmox, Synology, Kubernetes, HashiCorp Vault, a webhook, this machine |
| your own | modules in `/etc/acme/plugins/{issuers,challenges,targets}/` - kept across upgrades ([docs/architecture.md](docs/architecture.md)) |
| the platform | SQLite, MariaDB or PostgreSQL; secrets sealed; two nodes with a VIP address, one renewing at a time; backups (also to another machine); the firewall, the network and the time from the pages; Prometheus and SNMPv3; the console at root's login |

Built on **Python 3.14** and **PHP 8.3**. The standard library, nothing from pip
(a driver only for MariaDB or PostgreSQL); openssl and the OpenSSH client from
the system.

## The layout

```
acme.py              the launcher: `acme`, and `acme --daemon` for systemd
acmelib/             everything acme is made of (version: acmelib/__init__.py)
  engine/NNN_*.py      the platform, in numbered parts
  certs/               the certificate manager
  plugins/             the issuers, challenges and targets
web/                 the pages (PHP 8.3) - they relay to the API, decide nothing
deploy/              systemd, nginx, php-fpm, logrotate, root's helpers, release keys
tools/release.py     builds a signed release into release/
release/             the last ten releases, index.json, LATEST
```

This repository is the unpacked release: `sudo ./install.sh` works from a
clone as it does from `acme-X.Y.Z.tar.gz` (only the release is signed).

## Where to read on

- [INSTALL.md](INSTALL.md) - installing it
- [docs/architecture.md](docs/architecture.md) - how it is put together, the tables, the API
- [docs/acme-issuers.md](docs/acme-issuers.md), [docs/targets.md](docs/targets.md), [docs/ms-adcs.md](docs/ms-adcs.md), [docs/scep.md](docs/scep.md) - where certificates come from and go to
- [docs/operations.md](docs/operations.md) - the runbook: installing, PostgreSQL, the cluster, a node down or lost, upgrades
- [docs/upgrades.md](docs/upgrades.md) - upgrades, from the command line and the pages, and going back
- [docs/releasing.md](docs/releasing.md) - making a release
- [docs/high-availability.md](docs/high-availability.md) - two servers
- [docs/firewall.md](docs/firewall.md) - the firewall (port 53 for the DNS server, 80 for HTTP-01)
- [docs/tls-and-vip.md](docs/tls-and-vip.md) - the pages' own certificate, TLS, the VIP address
- [docs/backup-and-recovery.md](docs/backup-and-recovery.md), [docs/remote-backups.md](docs/remote-backups.md) - backups
- [docs/monitoring.md](docs/monitoring.md) - Prometheus and SNMPv3
- [docs/php2shell.md](docs/php2shell.md) - PHP and php2shell (CVE-2026-109618 / CVE-2026-109619)
- [CHANGELOG.md](CHANGELOG.md) - what changed, version by version

acme is built on the engine of otp 1.0.209.

## Checking it

```
python3 tools/lint-engine.py          # the engine's parts, read as one
python3 test/checks.py
```
