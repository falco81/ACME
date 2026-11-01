# acme — installing it

Certificates kept, renewed and put in place by themselves. A Python 3.14
program (`acme.py` and `acmelib/`), PHP 8.3 pages that only relay to it, nginx
in front.

---

## The short version

```bash
tar xzf acme-X.Y.Z.tar.gz
cd acme-X.Y.Z
sudo ./install.sh --server-name acme.example.local
```

It asks a handful of questions, installs everything, makes the first account
and prints its password. Then `https://acme.example.local/admin/`.

To see what it would do without doing it:

```bash
sudo ./install.sh --dry-run
```

The release is signed (`MANIFEST`, `MANIFEST.sig`); to check one by hand before
installing it, with the key from a tree you already trust:

```bash
ACME_RELEASE_KEYS=/usr/local/lib/acme/release-keys \
    python3 -I acme-X.Y.Z/deploy/acme_upgrade.py --inspect acme-X.Y.Z.tar.gz
```

A clone of the repository installs the same way (`sudo ./install.sh` in it) -
only it is not signed.

---

## What it needs

- AlmaLinux, Rocky or RHEL 9 or 10; Ubuntu 24.04; Debian 13 or newer. On
  Debian and Ubuntu the installer does less by itself.
- **Python 3.14** or newer. install.sh takes `python3.14` from where the
  distribution has it, and installs it when it is missing:
  - EL9 / EL10: `dnf install python3.14` (AppStream), with
    `python3.14-psycopg2` / `python3.14-PyMySQL` for a database server;
  - Ubuntu: its own `python3.14` where it has one, else the **deadsnakes PPA**
    (`ppa:deadsnakes/ppa`: `python3.14`, `python3.14-venv`);
  - Debian: its own `python3` once that is 3.14.

  Where none can be found or installed it stops and says how to get one;
  `--python /path/to/python3` runs acme on another one instead (an older one
  only at your own risk). The choice is the link `/usr/local/lib/acme/python`,
  which the service and the `acme` command start - kept for later upgrades.
  The database driver comes from the distribution for that Python where it has
  one, else into a virtual environment of acme's own (`/usr/local/lib/acme/venv`,
  with the system's packages visible) from PyPI.
- **PHP-FPM 8.3** or newer for the pages: EL9 `dnf module enable php:8.3` (or
  `--remi`, Remi's `php:remi-8.3`), EL10 and Ubuntu 24.04 have 8.3 of their
  own; Debian 12 needs packages.sury.org. Fixed for php2shell (below).
- nginx; `openssl`; the OpenSSH client (`ssh`, for targets and HTTP-01 over
  SSH, and backups over SFTP/SCP) - install.sh installs what is missing.
- chrony for the clock: install.sh installs and enables it (and stops
  systemd-timesyncd), on a fresh install and every `--upgrade`.
- Open into the server: **TCP 443** (the pages) and **TCP 80** (the CAs'
  HTTP-01 challenges - everything else on 80 goes to HTTPS). install.sh opens
  them in firewalld or ufw where one runs.
  **UDP and TCP 53** only when acme's own DNS server is switched on (DNS-01):
  Settings → Firewall and access opens it then (iptables/ip6tables) - see
  [docs/firewall.md](docs/firewall.md). The CA must reach it: delegate
  `_acme-challenge.<name>` (NS or CNAME) to this server.
- Out of the server: HTTPS to the CAs and the DNS providers' APIs, SSH (or the
  API port) to the targets.

---

## What it installs, and where

| What | Where |
|---|---|
| the program | `/usr/local/lib/acme/versions/X.Y.Z-STAMP/` - the whole tree (`acme.py`, `acmelib/`, `web/`, `deploy/`, `docs/`, `install.sh`, `MANIFEST`), root's, compiled |
| the one that runs | `/usr/local/lib/acme/current` → that tree, switched in one step on an upgrade; `previous` → the one before, kept for going back |
| stable names | `/usr/local/lib/acme/acme.py`, `acme_upgrade.py`, `acme_web.py`, `deploy/`, `docs/`, `CHANGELOG.md` … - links into `current/` |
| the command | `/usr/local/bin/acme` (on `/usr/local/lib/acme/python`, from `current/`) |
| your own modules | `/etc/acme/plugins/{issuers,challenges,targets}/*.py` - root's, kept across upgrades |
| what it is set up with | `/etc/acme/config.json` — only the database settings (`db_*`) need be here; everything saved on the pages lives in the database |
| everything it records | `/var/lib/acme/acme.db` (SQLite), or MariaDB / PostgreSQL |
| the sealing key | `/var/lib/acme/secrets.key` — **keep it with every copy of the database** (private keys and passwords are sealed with it) |
| copies | `/var/lib/acme/backups/` — one a day, each with the key beside it |
| its own log | `/var/log/acme/acme.log` |
| the API token the pages use | `/run/acme/api-token` (group `acme-web`) |
| the pages | `/var/www/acme/` (administration `/admin/`, HTTP-01 `acme.php`) |
| the services | `acme.service` (user `acme`, `CAP_NET_BIND_SERVICE` for port 53), `acme-upgrade.path/.service`, `acme-web.path/.service` |
| nginx | `/etc/nginx/conf.d/acme.conf`, its certificate in `/etc/nginx/certs/` |
| PHP-FPM | the pool `acme.conf` (user `acme-www`, socket `/run/php-fpm/acme.sock` or `/run/php/acme.sock`) and `99-php2shell.ini` |
| rotation | `/etc/logrotate.d/acme` |
| the release keys | `/usr/local/lib/acme/release-keys/*.pub` - what an upgrade from the pages must be signed by |

Accounts: `acme` runs the daemon; `acme-www` runs PHP; the group `acme-web`
may read the API token. Nothing runs as root after the start but the two
helpers systemd starts when the pages ask (upgrades; TLS, the network, the
firewall).

### HTTP-01 for other names

The CA asks `http://NAME/.well-known/acme-challenge/…` for every name on the
certificate, and nginx sends that to `acme.php` in the server block on port
80. For names other than `--server-name`, that block has to be nginx's default
on port 80: put `default_server` on its `listen 80` lines (and take it off any
other, e.g. remove Debian's `/etc/nginx/sites-enabled/default`), or list the
names in its `server_name`. In a cluster, either node may answer: the answer
is in the database.

---

## Every option

```
--server-name HOST        the pages' hostname (default acme.example.local)
--admin-allow CIDR[,..]   who may reach the administration pages
--portal-allow CIDR[,..]  who may reach the portal page at / (both default to RFC 1918)
--admin-user NAME         the first account (admin)
--admin-password PASS     its password (otherwise one is made and printed)
--cert FILE --key FILE    the pages' TLS certificate and key (otherwise a self-signed one)
--isemon HOST[:PORT][/tcp] send the logs to isemon
--isemon-hostname NAME    the host name isemon files them under (default acme)
--site-name NAME          what to call this installation on the pages
--with-db ENGINE          the Python driver for mariadb, postgres or both
--python PATH             run acme on this Python rather than python3.14
--php-stream X.Y          the AppStream PHP stream for a machine with no PHP yet (default 8.3)
--remi                    PHP 8.3 from Remi's repository instead
--no-php-update           leave PHP as it is (it is still checked)
--no-web                  the daemon only (no HTTP-01 on this machine then)
--no-db-restart           the pages may not restart a PostgreSQL here after tuning it
--db-restart              they may again
--upgrade                 replace the program and pages, fix PHP, restart; keep the rest
--rewrite-nginx           write the nginx file afresh (otherwise one that is there is kept)
--uninstall               remove the service and the pages; keep the data (always asks)
--dry-run                 print what would happen
--yes                     never ask
```

---

## PHP and php2shell

The pages are PHP, so the PHP running them must not have php2shell
(CVE-2026-109618 / CVE-2026-109619, remote code execution through a crafted
multipart request, fixed upstream on 21 October 2026 in 8.3.36, 8.4.27 and
8.5.12). The installer:

1. leaves a PHP that is installed, 8.3 or newer and fixed exactly as it is —
   nothing installed, no stream switched, nothing restarted; newer builds come
   with `dnf upgrade` / `apt upgrade`. A PHP that is installed but not fixed
   only has its own packages upgraded; one older than 8.3 is moved to the
   stream `php:8.3` once you say so (never during an upgrade from the pages);
   a machine with no PHP gets `php:8.3` (`--php-stream`) on EL9, `php8.3-fpm`
   on Ubuntu 24.04;
2. checks the result by its version and, when a distribution backported the
   fix under an old number, by the changelog of php-fpm;
3. offers PHP 8.3 from Remi's repository if AppStream has no fixed build yet;
4. adds a guard whatever happens: `99-php2shell.ini` and the pool switch off
   what the attack needs, and nginx refuses every multipart request (none of
   acme's pages sends one);
5. reloads php-fpm only when acme's pool or the guard file changed.

More in [docs/php2shell.md](docs/php2shell.md).

---

## After installing

```bash
acme --status                    # everything at once
acme --check                     # the configuration, the database, the ports
acme --plugins                   # the issuers, challenges and targets it found
```

1. Sign in to `https://<host>/admin/` with the first account and change its
   password (the account menu, top right).
2. **Issuers**: Let's Encrypt (its staging first, to try), your own CA, AD CS…
3. **Challenges**: HTTP-01 here, DNS-01 with acme's own DNS server (switch it
   on, open 53 in Settings → Firewall and access, delegate
   `_acme-challenge.<name>` to this server) or your DNS provider's API.
4. **Targets**: where certificates go, and how acme signs in there (an SSH key
   is made for you to put on the target); *Test* says what works.
5. **Certificates → New**: the names, the issuer, the challenge, the
   deployments. *Renew now* shows every step.
6. Alerts: Settings → Mail / SMS / Alerts, and isemon / SIEM.

---

## Upgrading, going back, uninstalling

```bash
sudo ./install.sh --upgrade      # from the new version's folder: the new tree, PHP fixed, restarted
sudo /usr/bin/python3 -I /usr/local/lib/acme/acme_upgrade.py --previous   # the tree before, back
sudo ./install.sh --uninstall    # service and pages gone; /var/lib/acme and /etc/acme kept
```

An upgrade puts the new tree in beside the one running, compiles it, and then
switches `/usr/local/lib/acme/current` to it in one step: whatever happens, what
runs is one whole version. The tree before stays as `previous`.

From the pages, node by node in a cluster, from the web, and going back to an
older version: [docs/upgrades.md](docs/upgrades.md). Making a release:
[docs/releasing.md](docs/releasing.md). Every procedure step by step:
[docs/operations.md](docs/operations.md).
