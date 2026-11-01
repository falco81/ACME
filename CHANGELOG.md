# Changes in acme

Newest first. Each version's section is what the pages show before an
upgrade (and, going back, what is given up), so it says what changed for
the people who run acme - one `## X.Y.Z - date` heading per version.

## 1.0.9 - 2026-11-01

- **Columns of a list no longer jump** when it is drawn again - a switch in a
  row, the auto refresh, "2 min ago" become "3 min ago": the widths it had
  first are kept (as shares, so a window made wider or narrower still fits);
  a long word that does not fit is laid out once more before the page is
  painted. A layout set by hand (the columns editor) comes first.
- **Add and issue now** shows the job already issuing a new certificate (the
  look starts it as soon as it is saved) instead of "a job is working"; the
  popup closes whatever the issuing says. "Renew now" on a certificate being
  worked on shows that job too.
- HTTP-01 over SSH guide: a CNAME to the name that has the public address is
  suggested, or a redirect of /.well-known/acme-challenge/ from another web
  server; a name acme's own block adds by itself is not a thing to set up.

## 1.0.8 - 2026-11-01

- **acme-dns: Register an account** from the validation's form - one, or one a
  name into "Accounts by name" (an acme-dns account keeps two TXT values), with
  the CNAMEs to put into your DNS; nothing saved until Save.
- SSLmarket: the DCV records of an order that waited across the upgrade to
  1.0.5 are taken away too.
- Tests: the HA and database move suites run against real PostgreSQL and
  MariaDB again; the SSLmarket suite runs all its tests.

## 1.0.7 - 2026-11-01

- **The QR code of the second factor is right again.** 1.0.6 drew it wrong:
  a helper of acme push had the name of the QR code's own (the engine's parts
  share one namespace), so an authenticator app could not read a new QR code.
  Every name is defined once now, and the engine's lint and a test say so.
- A second `db_trouble` (the words for an unreachable PostgreSQL when joining
  a cluster) renamed `ha_db_trouble` - it had taken the place of the one that
  tells a database error.
- docs/acme-push-protocol.md: **additive only** - every existing way of
  managing certificates in an application stays as it is; acme push is off by
  default and only one more way in.

## 1.0.6 - 2026-11-01

- **acme push - certificates for our other applications** (otp, isemon,
  zigmon and acme itself): a target that pairs with the application once
  (a one-time code shown there, Settings → Certificates and TLS →
  "Certificates from acme"), then installs each certificate and its renewals
  with signed requests, the private key sealed to the application.
  **Discover** reads the application's certificate slots (each node, the VIP
  address, zigmon's front server and broker) and makes the certificates and
  deployments for those not covered. The receiving side is in the engine;
  docs/acme-push-protocol.md is the specification for the other projects.
- HTTP-01 over SSH **behind NAT**: the guide never suggests a private address
  (the public one, from a name it knows); "Public addresses (NAT, load
  balancer)"; port 80 checked with the name; a name nginx does not answer said
  as such; the name validated added to acme's own block.
- Settings → DNS: **Public is built in** - always there, changed, never deleted.

## 1.0.5 - 2026-11-01

- **HTTP-01 on web servers over SSH where nginx answers port 80 already**:
  "Prepare the hosts" puts one line, `include
  /etc/nginx/snippets/acme-challenge.conf;`, at the top of each port-80 server
  block - nothing else in them changes (a certbot redirect to HTTPS goes on as
  before). Every file is checked unchanged since it was read, copied to
  /var/backups/acme-nginx/, and put back when nginx -t fails. With names
  given and no block answering them, acme's own block listens for those
  names only (not the default server). "I put it in myself": "Download the
  nginx config" gives the file and the line, and Prepare only checks.
- "Set nginx up by itself" (before Test and every validation) and "Open port
  80 in their firewall" (firewalld, ufw); a port 80 closed by the firewall is
  said as such ("No route to host" while SSH works).
- The check before the CA is asked can be made **at other addresses** - a load
  balancer, the public IP, NAT; https:// too - with the certificate's name as
  Host and SNI; "Name for Test".
- **Try reaching it fills in the host keys** of the form (every form with an SSH
  key); a different key pinned already is shown with a warning and "Replace
  with the key seen", never replaced by itself. Kept by Save.
- **Webglobe**: DNS-01 validation (login + API key; only the record it made is
  taken away) and a target uploading your own certificate to a hosted domain.
- The nginx config for HTTP-01 printed by `acme --validation-action NAME
  nginx_files`.
- Settings → DNS: a function's set waits for Save on the bar (Put back undoes
  it); Test of a set opens over its form and gives the form back as it was.
- High security: a refused exception switch turns back instead of an error.

## 1.0.4 - 2026-11-01

- **Renewal by itself switched on and off** from the list of certificates and
  from a certificate - nothing is revoked, it stays valid and deployed.
- **Revoking**: a dual certificate's both keys (ECDSA and RSA) are revoked, the
  dialog says so; "Issue a new one at once" gives a new certificate with a new
  key in the same job, deployed where the revoked one was. A revoked one has
  "Issue a new one". The old "Switch renewal off" switch did nothing - gone.
- **dns-persist-01**: one TXT record at `_validation-persist.DOMAIN`, set once,
  for any certificate of the domain (subdomains and wildcards with
  `policy=wildcard`). acme writes the exact record for each ACME account,
  checks it, and uses it as soon as the CA offers it (Google Trust Services
  does; Let's Encrypt has announced it) - a fallback validation until then.
- **What fits together is checked before the CA is asked**: names, source,
  validation, key type and twin, in one place - the wizard greys out what does
  not fit and says why; a public CA refuses single labels, .local/.test and
  private addresses.
- **SAN editor**: typed SANs (DNS, IP, e-mail, URI), the CN apart with "CN is
  also a SAN", many pasted at once.
- **DigiCert, GeoTrust, Thawte, RapidSSL** products, with domain validation by
  TXT, CNAME, HTTP file or e-mail placed by the validation; SSLmarket uses the
  same.
- **Settings → DNS**: named sets of DNS servers (UDP, TCP, DNS over TLS) given
  to validation, public checks, APIs, targets, ACME and mail; the system's by
  default.
- **Own authorities edited** without removing them: settings, the name (the old
  /pki/ addresses still served), the certificate renewed with the same key, its
  history. A switched-off authority still publishes its CRL.
- Name constraints written as "permitted DNS:…" are read too.
- SSLmarket reworked after its API description, and SSLmarket ACME.
- The authorities' tree drawn with joined lines; "until" of a CRL translated.

## 1.0.3 - 2026-11-01

- **The pages after an upgrade are the new ones**: they said otp's version
  (1.0.209) for every acme release, so browsers kept core.js and admin.js from
  before - the default buttons without their star, errors of old scripts on
  new pages after F5. Every script and stylesheet is keyed by its own file now,
  and a release keeps the pages' version equal to acme's.
- acme's own DNS server answering on the VIP only: the validation's Test and
  its wait ask the VIP, not 127.0.0.1 where the server does not listen then.
- The SQLite file's setting is on The database pane, not under every pane; a
  test keeps every setting on a pane of its own.
- A button after words on the same line keeps its gap ("… is there" [every
  step]).

## 1.0.2 - 2026-11-01

- **Validation that tells you what to do, and tests itself.** For every name of
  a certificate acme says what has to be in place and where - the exact CNAME,
  NS or TXT record with Copy buttons, where an HTTP-01 name must point - and
  checks it live. "Dry run" puts a real test record or file in place, sees it
  from outside and takes it away, without asking the CA. Names are grouped by
  domain, with a validation suggested for each (a certificate may span many
  domains, each proved its own way). Before a first certificate - and after a
  failed validation - the CA is not asked while something is missing.
- **More sources**: EST, CMPv2, HashiCorp Vault PKI, EJBCA, step-ca, AWS Private
  CA, Google CAS, FreeIPA, GlobalSign Atlas, DigiCert CertCentral, SSLmarket.cz;
  Actalis, Certum, Sectigo and DigiCert (EAB) among the ACME CAs. A paid order
  is never placed without "Allow new orders (paid)".
- **More validations** (deSEC, WEDOS, Active24, Websupport, Subreg/Gransy,
  CZECHIA.COM and some 45 more DNS providers), HTTP-01 by FTP/FTPS/SFTP, S3,
  Azure Blob and WebDAV.
- **More targets**: AWS ACM, Azure Key Vault, Google Certificate Manager,
  Cloudflare, vCenter, ESXi, Redfish (iDRAC, iLO, XCC), Sophos, Kemp, Cisco
  ISE, HAProxy (runtime API), Traefik, Caddy, NGINX Unit, Zimbra, TrueNAS,
  Docker Swarm, strongSwan, FRITZ!Box, UniFi OS.
- **Dual certificates**: ECDSA and RSA under one certificate, renewed in one
  job (the second ACME order needs no second validation) and deployed together
  where the target serves both (nginx, Apache, HAProxy, Postfix, F5, acme's own
  pages...), the variant chosen for the others.
- **acme's DNS server**: answers on the VIP address, the nodes, or both (and
  from the address it was asked at); the firewall lets it in by itself when it
  is switched on.
- **CRLs on acme**: every authority of acme's own publishes its CRL and its
  certificate over HTTP at /pki/ on every node and the VIP, refreshed by
  itself; new authorities put those URLs in what they sign.
- **The SSH key card of isemon** wherever acme signs in over SSH: make a key
  here, use your own, download, forget, try reaching it, how to set it up.
- **The database move wizard**: target, connection, checks, what happens, the
  move live, done - SQLite, MariaDB and PostgreSQL in every direction; not on a
  node of a cluster.
- A default in every list (sources, validations, targets, authorities); the
  lists are current without reloading; names made safe everywhere (the
  defaults of 1.0.0/1.0.1 are renamed with every reference to them).
- The overview as in otp: the certificates' tiles first, then the server's,
  each opening what it counts.
- Fixed: backups checked "not good" after an upgrade from the pages and with
  keys of authorities (the backups themselves were whole); the configuration's
  export left the authorities' and certificates' keys out; the encrypted link
  between the databases could not be switched on (otp's version floor).

## 1.0.1 - 2026-11-01

- **High availability: joining does everything by itself, on both sides.**
  - The node a bundle is made for is let through the firewall of the first
    node at once (for a day, until it has joined; a firewall change on trial
    never takes it back), and the joining node opens its own firewall to the
    first one before it reaches the database or copies anything - acme's own
    chain (ACME-IN) and firewalld alike, each opening checked and said
    truthfully ("does NOT let ..." with the command, when it did not work).
  - The bundle made on the pages prepares PostgreSQL on the first node as
    `acme --ha-setup` does: it listens on the node's address, the joining
    node is in pg_hba.conf, PostgreSQL is restarted - each step shown.
  - A node's PostgreSQL lets in its own address too: the replicated join
    stopped half way on "no pg_hba.conf entry for host <own address>".
  - Every failure of a join is named with its fix: connection refused (not
    listening there), timed out / no route (a firewall), pg_hba, password,
    name. "Check from here" tries it before joining. A half-done join is said
    to be one, and running it again finishes it cleanly.
  - Shared mode writes `ha_mode` on both nodes (they ran as two single
    servers on one database).
  - `--ha-status` and the page saw the outgoing replication as missing while
    both directions ran (the slots were looked for under otp's names); the
    cluster counted as unhealthy for /healthz?check=all and the alerts.
  - The Make the bundle and Join a cluster popups redrawn: a drop zone and
    what the bundle holds, the passphrase checked as typed, live steps.
- **Secrets as otp shows them, everywhere**: a stored password is dots and
  its last two characters to a full administrator, dots only to everybody
  else, and only dots while it is typed - the certificate manager's sources,
  validations, targets and deployments included. The SSH keys of validations
  and the acme-dns accounts are sealed now; the configuration export carries
  module secrets only when it is locked with a password.
- **Czech everywhere**: every tab, settings pane, popup and module form of
  the certificate manager, the job steps and the errors.
- No browser dialogs: the contact e-mail of the ACME sources is asked in
  acme's own popup.
- As in otp: "The enrolment pages" keeps its name; the balancer's health
  check offers "+ DNS server listening" (`/healthz?check=dns`) where otp
  offered RADIUS; the certificate manager's retention is on The database.

## 1.0.0 - 2026-11-01

The first version of **acme**: certificates kept, renewed and put in place by
themselves.

acme is built on the engine of **otp 1.0.209** (the one-time password server):
its platform - settings, the database (SQLite, MariaDB, PostgreSQL), sealed
secrets, the two-node cluster with its VIP address, mail and SMS, backups, the
firewall, the network, time, upgrades, the API, the command line and the
console - taken over, renamed `otp` → `acme` everywhere, and the single
`otp.py` split into a package. RADIUS, the tokens and the enrolment of otp
are not part of acme.

- **The certificate manager** (`acmelib/certs`): certificates kept with every
  version they had, renewed before they run out (or when the CA says so, ARI),
  deployed to every place they are used, one node at a time in a cluster, every
  step of every job written down.
- **Issuers**: ACME (Let's Encrypt and any ACME CA), acme's own certificate
  authorities (root and intermediate, CRLs), self-signed, Microsoft AD CS,
  SCEP.
- **Challenges**: DNS-01 with acme's own DNS server (UDP and TCP 53), RFC 2136,
  and the APIs of Cloudflare, Route 53, Azure, Google Cloud, Hetzner, OVH,
  DigitalOcean, PowerDNS and others; HTTP-01 here (nginx → `acme.php` on
  port 80) or on another web server over SSH.
- **Targets**: Linux and Windows over SSH, F5, NetScaler, MikroTik, FortiGate,
  Palo Alto, pfSense, OPNsense, Proxmox, Synology, Kubernetes, Vault, a
  webhook, and more - and your own modules in `/etc/acme/plugins/`.
- **The layout**: `acme.py` (the launcher) and `acmelib/` (the engine in
  numbered parts, the certificate manager, the modules, colorama carried
  along).
- **Python 3.14 and PHP 8.3** from the start: install.sh installs or requires
  `python3.14` (AppStream on EL, the deadsnakes PPA on Ubuntu) and PHP-FPM
  8.3, and refuses an older Python unless `--python PATH` says otherwise.
- **The installed tree**: `/usr/local/lib/acme/versions/X.Y.Z-STAMP/`, compiled,
  with `current` switched to a new one in a single step on an upgrade and the
  one before kept as `previous` (`acme_upgrade.py --previous` puts it back).
- **Releases**: `tools/release.py` builds `release/acme-X.Y.Z.tar.gz` - the
  tree with a MANIFEST of SHA-256 sums signed with Ed25519 by acme's own release
  key (`deploy/release-keys/acme-release-1.pub`; otp's key is not trusted) -
  keeps the last ten, and writes `release/index.json` and `release/LATEST`,
  which the servers read for new versions (`upgrade_url`).
