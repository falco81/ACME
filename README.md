# acme

A one-time password server for a VPN.

A Cisco ASA (or anything else that speaks RADIUS) asks it whether a person
may in. acme answers RADIUS itself, checks the six-digit code from the
person's phone (TOTP, RFC 6238), looks the person up in Active Directory,
checks their groups, and sends back Access-Accept with whatever the VPN
should be told - a Class, a group policy - or Access-Reject with the reason.

People make their own token on a web page: they sign in with their directory
password, scan a QR code, keep their recovery codes and prove it worked with
a code. Administrators look after everything else on pages of their own.

It is the replacement for a totpcgi + totpcgi-provisioning + FreeRADIUS 2 +
Perl handler server, and it brings such a server over whole - every token
keeps working, nobody enrols again. It writes its logs in the very shape that
server wrote them, so isemon reads it with what it already has.

One Python file, the standard library, and PHP pages that only relay to it.
No FreeRADIUS, no totpcgi, no qrencode, no pip packages (a driver only for
MariaDB or PostgreSQL, if you choose one of those).

```
    acme --status                    what it is doing, in one screen
    acme --log                       the RADIUS requests, newest first
    acme --rejects                   ...only the refused ones, with the reason
    acme --request 42                one request, every attribute and every step
    acme --acme-log                   every check of a code
    acme --tokens                    everybody who has a token
    acme --enroll novak@example.cz   a token, with the QR code in the terminal
    acme --radtest novak 123456      ask it the way radtest does, from here
    acme --directory-user AD novak   what the directory says about somebody
    acme --isemon-test               a line to isemon, to see that it arrives
```

`acme` is the same command, for those who type the server's name - and `acme` with nothing
after it says what it is doing. The daemon itself is `acme --daemon` (systemd starts it).

And the real thing, from anywhere a client is allowed:

```
    radtest falco 135830 acme.example.local 1812 testing123
```

## What is in it

| | |
|---|---|
| RADIUS | RFC 2865/2866, Status-Server (RFC 5997), Message-Authenticator on every answer and, per client, required on every request (BlastRADIUS, CVE-2024-3596); duplicate detection; accounting written down |
| codes | TOTP/HOTP (RFC 6238/4226), SHA-1/256/512, 6-8 digits, a window for clock drift that is recorded per token, a code used once only, a pause after wrong codes, recovery codes kept as hashes |
| realms | what comes after the @: which directory, how the name is looked up (UPN / sAMAccountName), which groups let in (nested groups too), whether the password is the code, the directory password then the code, or the directory password alone, and what goes back - per group |
| Active Directory | LDAPS / StartTLS / plain, several domain controllers in order, its own CA certificate, a read-only service account, disabled and expired accounts refused, a check that says which step failed |
| enrolment | the user's own pages: sign in, scan, recovery codes, confirm with a code, replace a lost phone with the password and a code from the old token or a recovery code |
| administration | overview, tokens, every RADIUS request with every step of its decision, every check of a code, a radtest from the page, events, and every setting - the same pages as isemon |
| isemon | `totp.cgi` and `radius-detail` syslog lines exactly as totpcgi and FreeRADIUS wrote them, over UDP or TCP, and the same lines in files here |
| mail | a new token's QR code (and, if asked, its recovery codes) mailed to its owner in Czech or English - through your mail server (STARTTLS/SMTPS/none; PLAIN, LOGIN, CRAM-MD5, XOAUTH2 or no sign-in) or straight to the recipient's MX; its own CA certificates |
| export | tokens out as totpcgi .totp files - all, a search, or one - for totpcgi or another acme |
| databases | SQLite (a file here), MariaDB, PostgreSQL; the token keys sealed with a key kept beside the database |
| languages | English and Czech, chosen per person; isemon's language files and engine |

## Where to read on

- [docs/high-availability.md](docs/high-availability.md) - two servers, both answering
- [docs/operations.md](docs/operations.md) - the runbook: installing, PostgreSQL, the cluster, a node down or lost, upgrades
- [docs/realms-and-suffixes.md](docs/realms-and-suffixes.md) - one person, several domain suffixes (example.local and example.cz): one realm with other suffixes, one token
- [docs/codes-by-mail-and-sms.md](docs/codes-by-mail-and-sms.md) - codes sent by e-mail or SMS after the directory password, the VPN's second window (RADIUS Challenge/Response, Cisco ASA/FTD), enrolling with them beside the app
- [docs/backup-and-recovery.md](docs/backup-and-recovery.md) - backing up the whole installation and getting it back: a wrong change, damaged data, a lost server or cluster, installing from nothing
- [docs/remote-backups.md](docs/remote-backups.md) - backups of everything to another machine (FTP, FTPS, SFTP, SCP, SMB, a folder), locked, on a schedule, and putting one back on a machine installed from nothing
- [docs/network-and-power.md](docs/network-and-power.md) - each node's IP address, gateway, DNS, host name and IPv6 from the pages, and restarting or switching off one node or both
- [docs/console.md](docs/console.md) - the acme console: menus, the live log and live RADIUS requests, at root's login
- [docs/admin-second-step.md](docs/admin-second-step.md) - a code after the password for the administration pages: app, e-mail or SMS, reset
- [docs/time.md](docs/time.md) - the clock of each node (chrony): how far off, its sources, the time servers for the whole cluster, the time zone
- [docs/renaming-and-readdressing.md](docs/renaming-and-readdressing.md) - a node renamed or given a new address: putting the cluster right, from the pages or the command line
- [docs/tls-and-vip.md](docs/tls-and-vip.md) - certificates, TLS, the VIP address, the firewall
- [docs/load-balancers.md](docs/load-balancers.md) - HAProxy, nginx, Apache, F5, NetScaler, LVS, with real health checks
- [docs/sign-in-protection.md](docs/sign-in-protection.md) - guessing from one place blocked (RADIUS), and network and firewall changes that go back by themselves unless kept
- [docs/firewall.md](docs/firewall.md) - the firewall (iptables / ip6tables) and who may reach which pages, from Settings
- [docs/reply-attributes.md](docs/reply-attributes.md) - what an Access-Accept can carry, product by product (Cisco ASA, FortiGate, Palo Alto, NetScaler, F5, Horizon UAG and more)

Installing it: [INSTALL.md](INSTALL.md).
Bringing the old totpcgi + FreeRADIUS server over: [docs/migration-from-totpcgi.md](docs/migration-from-totpcgi.md).
Mailing tokens out: [docs/mail.md](docs/mail.md).
Sending the logs to isemon: [docs/isemon.md](docs/isemon.md).
Syslog and SIEM, the proxy, the disks and the logs: [docs/syslog-proxy-and-logs.md](docs/syslog-proxy-and-logs.md).
High security: [docs/high-security.md](docs/high-security.md).
Automatic certificates (ACME, HTTP-01 and DNS-01): [docs/acme.md](docs/acme.md).
Encryption to the database server, every node: [docs/database-tls.md](docs/database-tls.md).
isemon over TLS, and what to do on the isemon machine: [docs/isemon-tls.md](docs/isemon-tls.md).
Prometheus metrics and SNMPv3 of every node: [docs/monitoring.md](docs/monitoring.md).
SSH to the nodes with a code from acme (pam_radius): [docs/ssh-with-a-code.md](docs/ssh-with-a-code.md).
The database, and moving into MariaDB or PostgreSQL: [docs/the-database.md](docs/the-database.md).
PHP and php2shell (CVE-2026-109618 / CVE-2026-109619): [docs/php2shell.md](docs/php2shell.md).
The pages in another language: [docs/languages.md](docs/languages.md).
How it is put together: [docs/how-it-works.md](docs/how-it-works.md).

## Checking it

```
python3 test/checks.py                        # the RFC vectors, RADIUS packets, QR codes
test/engines.sh BACKUP.json.gz sqlite mariadb postgres
python3 test/mockldap.py                      # a pretend Active Directory on 127.0.0.1:3899
```
