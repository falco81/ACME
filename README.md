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
| issuers | ACME (RFC 8555; Let's Encrypt, ZeroSSL, step-ca, ...; EAB, profiles, ARI - RFC 9773), acme's own CAs (root and intermediate, CRLs, name constraints), self-signed, Microsoft AD CS, SCEP, SSLmarket (commercial DigiCert / Sectigo / GeoTrust certificates: orders, free reissues, DCV by the challenge modules; and SSLmarket ACME - an ACME key with EAB made through its API); EST (RFC 7030), CMP (RFC 4210 / 9480, by openssl cmp), HashiCorp Vault PKI, EJBCA REST, step-ca (JWK provisioner), AWS Private CA, Google Cloud CA Service, FreeIPA / Red Hat IdM, GlobalSign Atlas, DigiCert CertCentral API ([docs/sources.md](docs/sources.md)); ACME presets for Actalis, Certum, Sectigo |
| challenges | DNS-01: acme's own DNS server, RFC 2136, Cloudflare, Route 53, Azure, Google Cloud, Hetzner, OVH, DigitalOcean, PowerDNS, deSEC, Gandi, Linode, Vultr, Porkbun, Namecheap, GoDaddy, DNSimple, NS1, bunny.net, ClouDNS, INWX, TransIP, netcup, IONOS, Scaleway, Exoscale, Infoblox, Technitium, Hurricane Electric, WEDOS, Active24, Websupport, Subreg.cz, CZECHIA.COM, Loopia, Simply.com, hosting.de, Domeneshop, GleSYS, Mythic Beasts, Infomaniak, Alibaba Cloud, Tencent DNSPod, Oracle Cloud, Akamai Edge DNS, DNS Made Easy, Gcore, Netlify, Vercel, Name.com, NameSilo, Dynu, Njalla, DreamHost, Duck DNS, Webglobe, acme-dns, a script, by hand ([validation.md](docs/validation.md)); HTTP-01: here (nginx → `acme.php`), on another web server over SSH, or uploaded over FTP(S)/SFTP, to S3, Azure Blob or WebDAV |
| targets | Linux and Windows over SSH, F5 BIG-IP, NetScaler, FortiGate, MikroTik, Palo Alto, pfSense, OPNsense, Proxmox, Synology, Kubernetes, HashiCorp Vault, a webhook, this machine; clouds: AWS Certificate Manager, Azure Key Vault, Google Cloud Certificate Manager, Cloudflare custom certificate; VMware vCenter Server and VMware ESXi host, server management (Redfish: iDRAC, iLO, XCC, BMC); Sophos Firewall, Kemp / Progress LoadMaster, Cisco ISE; HAProxy (Runtime API, no reload), Traefik Proxy, Caddy, NGINX Unit; Zimbra Collaboration, TrueNAS, Docker Swarm secrets, strongSwan, AVM FRITZ!Box, UniFi OS console; Webglobe hosting; gateways, CDNs and cloud load balancers: Kong Gateway, Nginx Proxy Manager, VMware Avi Load Balancer (NSX ALB), A10 Thunder (aXAPI), Hetzner Cloud Load Balancer, DigitalOcean Load Balancer, Azure App Service, bunny.net CDN, Fastly TLS; Nutanix cluster (Prism Central v4 API); Omnissa Unified Access Gateway (UAG); firewalls, load balancers and hosting panels from the vendors' API documents: Check Point (Management API), VMware NSX load balancer, Barracuda Web Application Firewall, FortiWeb, FortiADC, Cisco Secure Firewall Management Center (FMC), cPanel / WHM, DirectAdmin, Plesk (certificate repository), Cisco Secure Firewall Threat Defense (FDM), Cisco Secure Firewall ASA (HTTP interface), Juniper SRX, Azure Application Gateway, ISPConfig, HestiaCP, Virtualmin, froxlor, Proxmox Backup Server; from the vendors' guides (1.0.96): HPE OneView / Synergy, HPE Alletra / Nimble, HPE iLO 5/6/7, Dell iDRAC9/10, PowerScale, PowerStore, Unity, Unisphere for PowerMax, Fujitsu iRMC, ISM, ETERNUS DX, Supermicro BMC, Cisco IMC, Huawei iBMC, VMware NSX Manager, SDDC Manager, Aria Suite Lifecycle, Aria Automation, Cloud Director, Live Site Recovery / vSphere Replication, vSphere Supervisor, Omnissa Horizon Connection Server, Cisco IOS XE, Catalyst 9800, NX-OS, Catalyst Center, HPE Aruba AOS-CX, ClearPass, Central, ArubaOS 8 and Instant AP, Barracuda CloudGen Firewall, Infoblox NIOS, FortiManager, Windows WSUS / Hyper-V Replica / Reporting Services / Operations Manager / Office Online Server, NetApp ONTAP, Pure Storage, QNAP, Cockpit, Veeam Backup & Replication / Cloud Connect / Microsoft 365; devices that make their own key (the key made by the device, renewed through its CSR): Lenovo XClarity Controller and XClarity Administrator, Dell OpenManage Enterprise, HPE Synergy, HPE iLO (its own key), HPE Alletra MP, Cisco CUCM, VMware VCF component certificates; our own applications - otp, isemon, zigmon, another acme - over acme push, with Discover ([docs/targets.md](docs/targets.md), [docs/acme-push-protocol.md](docs/acme-push-protocol.md)) |
| your own | modules in `/etc/acme/plugins/{issuers,challenges,targets}/` - kept across upgrades ([docs/architecture.md](docs/architecture.md)) |
| the platform | SQLite, MariaDB or PostgreSQL; secrets sealed; two nodes with a VIP address, one renewing at a time; backups (also to another machine); the firewall, the network and the time from the pages; Prometheus and SNMPv3; the console at root's login |
| signing in | the administration and the certificate portal against Active Directory, a second step (an app, mail, SMS, Face ID / passkeys), and **with Windows (Kerberos SSO)** - each part by its own switches, NTLM never taken, the keytab put in once for the cluster ([docs/kerberos-sso.md](docs/kerberos-sso.md)), and **with a certificate** - a smart card, a YubiKey, on a port of its own, CRL and the KB5014754 SID checked ([docs/certificate-sign-in.md](docs/certificate-sign-in.md)) |

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
- [docs/acme-issuers.md](docs/acme-issuers.md), [docs/targets.md](docs/targets.md), [docs/ms-adcs.md](docs/ms-adcs.md), [docs/scep.md](docs/scep.md), [docs/sslmarket.md](docs/sslmarket.md), [docs/ssls.md](docs/ssls.md), [docs/sources.md](docs/sources.md) - where certificates come from and go to
- [docs/operations.md](docs/operations.md) - the runbook: installing, PostgreSQL, the cluster, a node down or lost, upgrades
- [docs/upgrades.md](docs/upgrades.md) - upgrades, from the command line and the pages, and going back
- [docs/releasing.md](docs/releasing.md) - making a release
- [docs/high-availability.md](docs/high-availability.md) - two servers
- [docs/firewall.md](docs/firewall.md) - the firewall (port 53 for the DNS server, 80 for HTTP-01)
- [docs/local-users.md](docs/local-users.md), [docs/ssh-keys.md](docs/ssh-keys.md), [docs/console.md](docs/console.md) - the users of the machines, their SSH keys, the console at login
- [docs/kerberos-sso.md](docs/kerberos-sso.md) - signing in with Windows (Kerberos SSO) to the administration and to the certificate portal, each by itself
- [docs/certificate-sign-in.md](docs/certificate-sign-in.md) - signing in with a certificate (a smart card, a YubiKey) to the administration and to the certificate portal, each by itself
- [docs/ssh-with-a-code.md](docs/ssh-with-a-code.md) - SSH to the nodes with a code from acme (pam_radius, SSH tokens by an app, mail or SMS)
- [docs/dns-sets.md](docs/dns-sets.md) - Settings → DNS: named sets of DNS servers, and which one each function asks
- [docs/teams.md](docs/teams.md) - Settings → Owners and teams: who certificates belong to, what each member may do, the tags; who sees what
- [docs/tls-and-vip.md](docs/tls-and-vip.md) - the pages' own certificate, TLS, the VIP address
- [docs/active-directory-2025.md](docs/active-directory-2025.md) - Active Directory on Windows Server 2025: what acme does with it, what its check warns of
- [docs/trusted-roots.md](docs/trusted-roots.md) - the system's trusted roots: certificate authorities of your own added to the trust of every node's operating system, beside the distribution's list
- [docs/acme-push-protocol.md](docs/acme-push-protocol.md) - acme push: how acme puts certificates on our other applications (the protocol, for their side), and Certificates from acme here
- [docs/backup-and-recovery.md](docs/backup-and-recovery.md), [docs/remote-backups.md](docs/remote-backups.md) - backups
- [docs/monitoring.md](docs/monitoring.md) - Prometheus and SNMPv3
- [docs/performance-meter.md](docs/performance-meter.md) - how busy the node is, in the header of the pages (off unless chosen)
- [docs/things-to-do-by-hand.md](docs/things-to-do-by-hand.md) - what waits for a person (a command after an update, SELinux switched off): in Settings → Upgrades until done, and how a release adds one
- [docs/php2shell.md](docs/php2shell.md) - PHP and php2shell (CVE-2026-109618 / CVE-2026-109619)
- [CHANGELOG.md](CHANGELOG.md) - what changed, version by version

acme is built on the engine of otp 1.0.209.

## Checking it

```
python3 tools/lint-engine.py          # the engine's parts, read as one
python3 test/checks.py
```
