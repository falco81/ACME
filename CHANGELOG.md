# Changes in acme

Newest first. Each version's section is what the pages show before an
upgrade (and, going back, what is given up), so it says what changed for
the people who run acme - one `## X.Y.Z - date` heading per version.

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
