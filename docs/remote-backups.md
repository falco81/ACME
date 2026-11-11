# Backups to another machine

*Settings → Backups* sends a backup of everything to another machine - on a
schedule, or now - and puts one back. One backup brings any loss back: one
server or a cluster of two, onto a machine installed from nothing.

## What is in a backup

One file, `acme-backup-SITE-NODE-YYYYMMDD-HHMMSS.tar.gz.enc`:

| File inside | What |
|---|---|
| `acme-copy.json.gz` | the whole database, in a shape SQLite, MariaDB and PostgreSQL all take: the certificates with their versions and sealed private keys, acme's own CAs, the issuers, challenges, targets and deployments, the jobs, the DNS server's records, the directories, accounts, every setting (the cluster's and each node's own), the certificates and private keys of the pages, the VIP address, the firewall and who may reach which page, the message texts, the cluster's authority for the link between the databases, the logs |
| `secrets.key` | the key that opens the private keys and every other sealed secret |
| `config.json` | this machine's `/etc/acme/config.json`: which database it opens, its node name, its place in a cluster |
| `files/` | files config.json names outside the database (the authority of a database on another machine) |
| `manifest.json` | what it is, where and when it was made, and the SHA-256 of every file above |
| `RESTORE.md` | the exact steps to put this backup back, filled in with what it is |

Beside it, **not** locked, go `...tar.gz.enc.sha256` (to check the file) and
`...-RESTORE.md` (the same steps, readable before anything is opened). Neither
holds a secret.

What is not in it, because it is made from the database or belongs to the
operating system: nginx, keepalived and firewall files, PostgreSQL itself,
the program. They come back by themselves once the database is back.

## Locked with a password

*The password of the backups* (on the same page) locks every backup:
`openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256`. It is opened by
acme (`acme --restore-bundle`, or *Put one back…* on the pages), or with
openssl alone on any machine:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 \
    -in acme-backup-....tar.gz.enc -out acme-backup-....tar.gz
```

The password is kept in the database, sealed - so it is inside every backup
too, which helps nobody who does not have it. **Keep it in a password vault,
apart from the backups.** *Make a strong one* makes a random one and shows it
once. **Without a password nothing is sent** (1.0.136): an unlocked backup
would hand every private key to whoever can read the destination, so a
scheduled or a by-hand run stops with "the backups have no password", and
*Download one made now* is refused too.

## Where they go

*Add a destination* - as many as you like (up to 20); every one switched on
gets every backup.

| Kind | What it needs | Signing in | Checked |
|---|---|---|---|
| A folder | a path on this machine (an NFS, CIFS or other mount); the `acme` account must write there | - | - |
| FTP | server, port 21, folder | account and password - **unencrypted on the way** (the file itself is locked) | - |
| FTPS | server, port 21 (explicit, AUTH TLS) or 990 (implicit), folder | account and password; a client certificate if the server wants one | the server's certificate: against the system's authorities, an authority of your own, a pinned fingerprint, or (not safe) not at all |
| SFTP | server, port 22, folder | an SSH key made here or your own (with its passphrase), an SSH certificate if the server wants one, or a password | the server's host key, trusted once |
| SCP | as SFTP; needs a shell on the server (`ls`, `mv`, `rm` through ssh) | as SFTP | as SFTP |
| SMB | server, port 445, share, folder in it | account, password, domain | SMB2 at least; SMB3 encryption required (on by default) |

SFTP and SCP use OpenSSH's own `sftp`, `scp` and `ssh` (`openssh-clients`), SMB
`smbclient` (`samba-client`); `install.sh` installs both, and the page says when
one is missing. A file is written under a temporary name and renamed when it
is whole, so a half-sent backup is never taken for one.

### SSH keys

*Make a key* makes an ed25519 pair here; the private half is kept in the
database, sealed, and never leaves the machine unless you *Download it* (written
into Events). The public half is shown with the line to run on the server:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-ed25519 AAAA… acme-backup@acme1' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
```

*Use my own* takes a private key you have (OpenSSH or PEM, with its passphrase
if it has one). Restricting the key on the server is a good idea, e.g. an
SFTP-only account in a chroot.

### The server's host key

The first *Try reaching it* shows the server's fingerprint. Compare it with the
server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on it) and
*Trust it*. From then on a server answering with another key is refused - if it
was reinstalled on purpose, *Forget it* and trust the new one.

### FTPS certificates

- **Against an authority of my own**: paste the certificate of the authority
  that signed the server's.
- **Pinned**: exactly this certificate - *Try reaching it* shows the server's
  SHA-256 fingerprint and *Pin this certificate* takes it. A renewed server
  certificate has to be pinned again.
- **Client certificate**: *Make one* (EC P-256, five years) and give the server's
  administrator the certificate shown (*Download it*), or *Use my own* - PEM
  (certificate and key) or a PFX/PKCS#12 file with its password.
- The data connection resumes the TLS session of the control connection, as
  vsftpd, ProFTPD and FileZilla Server require.

## When, and how many

| Setting | |
|---|---|
| *Backups to the destinations on a schedule* | on: each node sends its backup at the time below |
| *At* | `HH:MM`, this machine's clock |
| *How often* | daily, or weekly on *On (1 Monday - 7 Sunday)* |
| *Backups kept at each destination* | this node's newest N stay at each destination; older ones are taken away after each backup (with their .sha256 and RESTORE.md). The newest is never taken away |
| *And none older than (days)* | older ones go too; 0: only the count |

In a cluster **each node sends its own** (its config.json is its own); the file
names carry the node's name, and each node takes away only its own old ones.
Either node's newest backup holds the whole cluster's data.

*Back up now* sends one at once; *Download one here* makes one and saves it on
the computer you are sitting at. *What was sent* lists every backup with where
it went, how long it took and what each destination said; Events has it too.
*Clear the list* empties it, and the bin on a line takes that line off. Only the
list changes: the backups stay at the destinations (*Backups there* deletes
them).

On the command line:

```bash
acme --rbackup-status            # the destinations and the last backups
acme --rbackup-now               # one now, to every destination switched on
```

## Putting one back

**On the pages**: *Backups there* on a destination lists its backups -
*Download*, *Put this back…*, *Delete*. Or *Put one back…* at the top sends a file
from your computer. Before anything is replaced a copy of the database as it is
is made (*Settings → The database → Copies*). The sessions are the backup's too:
you sign in again afterwards, with an account the backup has. In a cluster it
goes over to the other node by replication.

**On a machine installed from nothing** (the server is lost):

```bash
tar xzf acme-VERSION.tar.gz && cd acme-VERSION && ./install.sh
acme --restore-bundle acme-backup-....tar.gz.enc               # what is in it
acme --restore-bundle acme-backup-....tar.gz.enc --yes         # put it back
systemctl restart acme
```

The password is asked for, or comes from `--passphrase-file FILE` or
`ACME_BACKUP_PASSWORD`. The database, the key of the sealed secrets and the node's name
come back; the new machine keeps its own database connection (`--keep-node-name`
keeps its own name too). The backup goes into SQLite after a plain install;
PostgreSQL can be chosen afterwards (*Settings → The database*).

**A cluster**: one node lost and the other alive - do not put a backup back:
install the lost node and join it (`acme --ha-bundle` / `acme --ha-join`), it copies
everything from the living one. Both lost - put the newest backup back on one new
machine as above, move it to PostgreSQL, and build the pair again
(`acme --ha-setup`, `acme --ha-join` - high-availability.md). The VIP address, the
firewall, the certificates and the encrypted link between the databases come
back by themselves from the database.

Every backup's own `RESTORE.md` has these steps with its own names, version and
cluster in them. *How to put it back* at the top of *Settings → Backups* shows the same
file as a backup made now would carry it, and *Download RESTORE.md* saves it -
keep it with the password, apart from the backups.

## Troubleshooting

| What it says | What to do |
|---|---|
| *the acme account may not write into ...*, *Read-only file system* | a folder destination: `chown acme /mnt/backup/acme` (or give the acme group write) - and, since the service runs sandboxed (`ProtectSystem=strict`, `ProtectHome=yes`: only `/var/lib/acme`, `/var/log/acme` and `/etc/acme` are writable), let it write there: `systemctl edit acme`, add `[Service]` and `ReadWritePaths=/mnt/backup/acme`, then `systemctl restart acme`. The same for a *This machine* target writing outside `/etc/acme` |
| *the server's certificate is not trusted* | FTPS: the server's certificate is not from an authority this machine trusts - give its authority, or pin it |
| *the server shows another host key than the one trusted* | SFTP/SCP: reinstalled on purpose? *Forget it*, *Try reaching it*, compare, trust. Otherwise somebody is in between |
| *the server did not let the account in* | the public key is not in `authorized_keys` yet, or the password is wrong |
| *the server did not take the account and password (NT_STATUS_LOGON_FAILURE)* | SMB: account, password or domain |
| *... is not on this machine* | `dnf install openssh-clients` or `dnf install samba-client` |
| *the password does not open it* | the backup was locked with another password than the one set now: type that one when putting it back |

## Trying a backup (1.0.168)

*Try the newest* (and the setting *Try the backups*: only by hand, after every
backup - the one just sent - or once a week) fetches the newest backup of this
node from the first destination switched on into a folder of its own, and:

- opens it with the password of the backups and checks every file against
  the SHA-256 its manifest has;
- reads the copy of the database to its last line, counts its tables, rows
  and accounts, and compares them with the manifest;
- checks that a full administrator can sign in after it;
- tries the sealed secrets in it (a sample of 50) against the key in it -
  each must carry that key's tag;
- reads config.json;
- reads the newest nightly copy on this machine through as well.

Nothing is put back and the database in use is not touched. Each try is
listed under *Backups tried* with every check, is an event, and one that fails
is an alert (*A backup that failed or did not come*).
