# Backup and recovery

This guide covers backing up a whole acme installation, and getting it back
after anything from one wrong click to the loss of every machine, for one
server and for a cluster of two. It ends with installing from nothing.

The other guides go deeper on single steps:
[operations.md](operations.md) (the runbook),
[high-availability.md](high-availability.md) (how the cluster works),
[the-database.md](the-database.md) and [upgrades.md](upgrades.md).

Contents

1. [What there is to keep](#1-what-there-is-to-keep)
2. [The backup plan](#2-the-backup-plan)
3. [Before any recovery](#3-before-any-recovery)
4. [Which case is yours](#4-which-case-is-yours)
5. [One server: recovery](#5-one-server-recovery)
6. [A cluster of two: recovery](#6-a-cluster-of-two-recovery)
7. [Installing from nothing](#7-installing-from-nothing)
8. [After every recovery: the checks](#8-after-every-recovery-the-checks)
9. [Reference](#9-reference)

---

## 1. What there is to keep

Everything acme knows is in **its database** and in **one key file**. What
sits on the disk elsewhere is either made from the database or belongs to
the machine.

| What | Where | In a copy of the database? | How it comes back |
|---|---|---|---|
| Certificates, their versions and private keys, acme's own CAs and what they signed | database, tables `certs`, `cert_versions`, `cert_cas`, … (keys sealed with the key) | yes | with the copy **and** the key |
| Issuers, challenges, targets (their passwords and API tokens sealed), deployments, jobs, the DNS server's records | database | yes | with the copy **and** the key |
| Settings (the cluster's and each node's own) | database | yes | with the copy |
| Directories (passwords, CAs) | database | yes | with the copy |
| Accounts of the administration pages | database | yes | with the copy |
| Certificates and private keys of the pages and of the VIP address, TLS settings | database (keys sealed) | yes | with the copy; nginx is rewritten from it within seconds |
| The VIP address, who may reach which page, the firewall, the mail server's CAs | database | yes | with the copy; keepalived, nginx and iptables are rewritten from it within seconds |
| The link between the two databases: the cluster's authority (key sealed) and what each node wants | database | yes | with the copy; each node gives its PostgreSQL a certificate again by itself within ten minutes (1.0.104) |
| PostgreSQL's certificate of each node, `/etc/pki/acme/ha-ca.pem`, `hostssl` lines in pg_hba.conf | the operating system | no - made from the database | by each node itself, through its root helper (1.0.104) |
| Events | database | yes | with the copy |
| Modules of your own: uploaded on Settings → Modules | database (`meta`, `module-file:…`); each node writes them into `/var/lib/acme/plugins-uploaded/` | yes | with the copy - every node writes them back by itself |
| Modules of your own: files in `/etc/acme/plugins` | the disk of each node; their text kept in the database too (`custom-modules:<node>`) | yes (1.0.32), and in `plugins/` of a full backup | a full backup puts them back; from a copy: `acme --plugins-sync NODE` (root) |
| **The key of the sealed secrets** | `/var/lib/acme/secrets.key` | beside each kept copy (`acme-….key`); **inside** every copy downloaded from the pages | with the copy, or by hand |
| The machine's own file: which database it opens, its node name, its place in a cluster | `/etc/acme/config.json` | **to read only** (from 1.0.63; the database password left out) | written by `install.sh`, `acme --set`, `--ha-setup`, `--ha-join` |
| nginx, php-fpm, keepalived, iptables files | `/etc/nginx/conf.d/acme.conf`, `/etc/sysconfig/iptables`, ... | no - made from the database | by `install.sh` and by acme itself |
| The program | `/usr/local/lib/acme`, `/var/www/acme` | no | `install.sh` from the package |
| PostgreSQL itself, replication between the nodes | the operating system | no | `install.sh`, `--ha-setup`, `--ha-join` |

**Backups to another machine** (1.0.109) put all of it - the database, the key
and config.json, locked with a password, with the steps to put it back - on
FTP, FTPS, SFTP, SCP, a Windows/Samba share or a mounted folder, on a schedule:
[remote-backups.md](remote-backups.md). That is the backup to rely on; the
copies below stay on this machine.

**One copy of the database plus the key is the whole installation.** Put
back on a freshly installed machine, that machine is the old one again -
certificates and their keys, issuers, targets, accounts, the pages'
certificates, firewall and all.

What is made from the database is checked against it, not only written once
(1.0.104): nginx's certificate is compared with the saved one and put in again
when it differs or is missing, and each node of a cluster looks every ten
minutes - and at once after a copy is put back - whether its PostgreSQL answers
with a certificate of the cluster's authority, whether `/etc/pki/acme/ha-ca.pem`
holds it and whether its link is on verify-full. Anything not right is made
again by itself. A copy from before the link was encrypted (no authority in
it) makes one node create a new authority and both take it. Putting a copy
back keeps the authority the cluster has now - it is the one the running
servers' certificates come from.

### Copies and dumps

Two kinds of backup are made every night at `backup_at` (03:30). They are
**not** the same:

| | **Copy** (`/var/lib/acme/backups/acme-*.json.gz`) | **Dump** (`/var/lib/acme/dumps/`) |
|---|---|---|
| Made by | acme | the database's own program: `pg_dump`, `mariadb-dump`, SQLite's backup |
| Goes back into | SQLite, MariaDB **or** PostgreSQL | only the engine it came from |
| In a cluster | put back on one node, replication carries it to the other | refused while replication runs |
| The key of the sealed secrets | beside it as `acme-….key`; inside a downloaded copy | not in it |
| Where it was made (config.json) | in it, to read (1.0.63) | no |
| Read without acme | no | yes, with the engine's own tools |
| Kept | the last `backup_keep` (14) | the same number |

**Back up with the copies.** The dumps are a second, independent line, for
the day somebody has to look into the data with PostgreSQL's or MariaDB's own
tools.

### The key of the sealed secrets

`/var/lib/acme/secrets.key` seals the private keys of the certificates and of
acme's own CAs, the passwords and API tokens of the issuers, challenges and
targets, and the other secrets kept in the database. **Without it a copy is
worthless** - for an attacker, and for you: no private key opens, every
certificate has to be issued anew with a new key, and acme's own CAs - with
everything they signed - have to be made again. Both nodes of a
cluster use the same key. It does not change on its own; keep one copy of it
apart from the database copies (a password vault, a sealed envelope), and the
problem of the key is solved for good.

---

## 2. The backup plan

What acme does by itself:

- a **copy** every night at `backup_at` (Settings → The database), the last
  `backup_keep` kept, each with its key beside it;
- a **dump** every night at the same time;
- in a cluster **each node** does both, on its own disk. Each node's copy holds
  the whole cluster's data, so the copies of one node are enough.

What you add - three things:

1. **Get the copies off the machine.** Every night, after `backup_at`, take
   the newest copy **and its `.key`** to another machine. For example, from a
   backup server:

   ```bash
   # pulls the newest copy and its key (run after 03:30)
   ssh root@acme1 'ls -t /var/lib/acme/backups/acme-*.json.gz | head -1' | while read f; do
       scp "root@acme1:$f" "root@acme1:${f%.json.gz}.key" /srv/backup/acme/
   done
   ```

   Or by hand on the pages: *Settings → The database → Download it* (a copy
   made now), *Download one* (a dump made now), or *Download* beside a kept
   copy or dump. Each asks first (1.0.123):

   - **With the key** - one file, `NAME.with-key.tar`, holding the copy or the
     dump and the key that opens its secrets, **locked with a passphrase** you
     give there (10 characters at least; scrypt and HMAC, the lock of the
     cluster's bundle). The passphrase is not kept anywhere: lost, the key in
     the file is lost with it. Keep the file and the passphrase apart.
   - **Without the key** - the copy or the dump alone. It opens no secret on
     another machine: the key is the `.key` file beside it in
     `/var/lib/acme/backups/` or `/var/lib/acme/dumps/` (or `secrets.key`).

   Every download is an event; one with the key a warning.

   ```
   NAME.with-key.tar
     acme-db.json          what it is: the file's name, size, sha256, node, version
     NAME                 the copy (.json.gz) or the dump (.pgc, .sql.gz, .sqlite3)
     secrets.key.locked   the key, locked with the passphrase
   ```

2. **Keep the key apart, once.** Copy `/var/lib/acme/secrets.key` into a
   password vault. It is 64 hexadecimal characters.

3. **Try a restore now and then** (every few months, and after big changes):
   put the newest copy back on a test machine as in
   [section 5.3](#53-the-server-is-lost) and run the checks of
   [section 8](#8-after-every-recovery-the-checks). A backup that was never
   put back is a hope, not a backup.

Optional:

- **The configuration as text** for version control or to carry a setup to
  another installation: `acme --export-config /root/acme-config.json`
  (without secrets) or `--with-secrets` (the passwords and private keys in
  the clear). Not a substitute for the copies: the jobs, the events and the
  older versions of the certificates are not in it.
- **A copy before every risky change** (an upgrade, a big import, a move of the
  database): `acme --backup`, or *Make a copy now* on the pages.

What to **not** rely on:

- **Snapshots of a virtual machine in a cluster.** Reverting one node to a
  snapshot leaves it behind what the other node already counted as delivered;
  it never catches up and must be rebuilt
  ([section 6.3](#63-one-nodes-database-is-broken-or-behind)). A snapshot of
  a single server is fine as an extra.
- **The dumps alone**: no key in them.

---

## 3. Before any recovery

1. **Stop the damage from spreading.** In a cluster a wrong change goes to the
   other node within a second; there is no "other node to take it from".
   If the database is being damaged right now (a script deleting things),
   stop acme on both nodes: `systemctl stop acme`.
2. **Keep what is there now**, broken or not - it may hold the last hours that
   no copy has: `acme --backup` (if the database still opens), and
   `cp -a /var/lib/acme /root/acme-state-$(date +%F-%H%M)`.
3. **Look at the copy you are about to put back**:

   ```bash
   acme --backup-info /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz
   ```

   It says when it was made, by which version, on which machine (node name,
   database, place in the cluster, its `config.json`), and how many rows of
   each table it holds - certificates, accounts, events. The pages show the same before
   anything is put back.
4. **Pick the right copy.** The newest file in `/var/lib/acme/backups/` is not
   always the one you want: a restore and a rebuild first make a safety copy
   of what they replace, named like any other. *Events* (kind *backups*) says
   which copy was made why; `acme --backup-info` shows its contents.
5. **Know what you lose.** Putting a copy back replaces everything: what was
   recorded after the copy was made (certificates renewed since, changed settings, events) is
   only in the safety copy that the restore makes first
   (`/var/lib/acme/backups/`, named in the message).
6. **People are signed out** of the pages: the sign-ins came with the copy.

---

## 4. Which case is yours

| What happened | One server | Cluster |
|---|---|---|
| A wrong setting, target, issuer or directory - acme still works | [5.1](#51-a-wrong-change) | [6.1](#61-a-wrong-change) |
| Certificates, targets or accounts deleted or damaged by mistake | [5.2](#52-data-deleted-or-damaged) | [6.2](#62-data-deleted-or-damaged-on-both-nodes) |
| The database will not open, or is corrupt | [5.2](#52-data-deleted-or-damaged) | [6.3](#63-one-nodes-database-is-broken-or-behind) |
| A node was reverted to a snapshot, or was away too long ("lost") | - | [6.3](#63-one-nodes-database-is-broken-or-behind) |
| Both nodes ran apart (split network) | - | [6.4](#64-both-nodes-ran-apart-split-network) |
| The machine is gone (disk, VM, reinstalled) | [5.3](#53-the-server-is-lost) | one node: [6.5](#65-one-node-is-lost) · both: [6.6](#66-both-nodes-are-lost) |
| The key of the sealed secrets is lost | [5.4](#54-the-key-of-the-sealed-secrets-is-lost) | [6.7](#67-the-key-is-lost-on-one-node) |
| An upgrade went wrong | [5.5](#55-an-upgrade-went-wrong) | [5.5](#55-an-upgrade-went-wrong) |
| Nobody can sign in to the pages | [5.6](#56-nobody-can-sign-in-to-the-pages) | [5.6](#56-nobody-can-sign-in-to-the-pages) |
| Moving to a new machine or another database engine | [5.7](#57-moving-to-new-hardware-or-another-engine) | [6.5](#65-one-node-is-lost), one node at a time |

---

## 5. One server: recovery

### 5.1 A wrong change

The pages record every change in *Events* (who, what, when). Most mistakes are
fixed by changing it back.

For a whole configuration gone wrong - many settings, issuers or targets - put
an exported configuration back. It replaces the configuration and **leaves the
jobs and events alone**:

```bash
acme --import-config /root/acme-config.json --yes            # add to what is here
acme --import-config /root/acme-config.json --yes --replace  # exactly the file
```

On the pages: *Settings → Export and import → Import a file…*, then *Add to
what is here* or *Exactly the file*. Without an exported file, take the
configuration out of a copy: put the copy back on a test machine
([section 5.3](#53-the-server-is-lost)), `acme --export-config FILE
--with-secrets` there, and import that file here.

### 5.2 Data deleted or damaged

Certificates deleted, accounts lost, the database corrupt or no longer opening:
put the newest good copy back. Everything returns as it was when the copy was
made.

**The database still opens:**

```bash
acme --backup                     # what is there now, kept anyway
acme --backup-info /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz
acme --restore /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz --yes
```

On the pages: *Settings → The database → What is in it*: *Restore* beside a
kept copy, or *Restore from this file* for one you upload. The key beside the
copy (or inside a downloaded one) is put in place by itself. A
`….with-key.tar` sent there asks for its passphrase, and the copy or dump and
its key are put back together - the file is kept on the server for an hour
meanwhile, and taken away once it is back.

**The database does not open:**

- *SQLite*: move the broken file aside; acme makes an empty one when it next
  opens it, and the copy goes into that:

  ```bash
  systemctl stop acme
  mv /var/lib/acme/acme.db /root/acme.db.broken
  rm -f /var/lib/acme/acme.db-wal /var/lib/acme/acme.db-shm
  acme --restore /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz --yes
  systemctl start acme
  ```

- *PostgreSQL / MariaDB*: make the database again, empty (as when it was set
  up - [operations.md section 3](operations.md#3-postgresql-16-on-almalinux-9)),
  then put the copy into it:

  ```bash
  systemctl stop acme
  sudo -u postgres psql -c 'DROP DATABASE acme' -c "CREATE DATABASE acme OWNER acme ENCODING 'UTF8' TEMPLATE template0"
  acme --restore /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz --yes
  systemctl start acme
  ```

- *From a dump* instead of a copy (same engine only): the same command with the
  dump file, `acme --restore /var/lib/acme/dumps/acme-postgres-….pgc --yes`.
  The key is not in a dump: the one in `/var/lib/acme/secrets.key` stays, and
  acme says loudly if the secrets do not open with it
  ([section 5.4](#54-the-key-of-the-sealed-secrets-is-lost)).

Then [section 8](#8-after-every-recovery-the-checks).

### 5.3 The server is lost

The disk died, the machine was deleted or must be reinstalled. You need a
copy and its key from **off the machine** ([section 2](#2-the-backup-plan)).

1. A new machine with the **same name and address** if you can (DNS, the NS
   records of acme's own DNS server and the targets' allow lists then need no
   change). AlmaLinux 9.
2. Install acme - [section 7.1](#71-one-server). With PostgreSQL or MariaDB, set
   the database up first as it was (`acme --backup-info` on the copy shows what
   it was: engine, host, port, database name).
3. Put the copy back, with its key beside it:

   ```bash
   cp /media/backup/acme-YYYYMMDD-HHMMSS.json.gz /media/backup/acme-YYYYMMDD-HHMMSS.key /root/
   acme --restore /root/acme-YYYYMMDD-HHMMSS.json.gz --yes
   ```

   It says "the key that opens the sealed secrets came with it and is in use now".
   A downloaded copy with its key (`….with-key.tar`) carries the key inside,
   locked: *Restore from this file* on the pages asks for its passphrase, and
   no `.key` file is needed.
4. The node name: if the old machine had `node_name` set (see its `config.json`
   in `acme --backup-info`), set the same, so its certificate and its own
   settings, which are kept under that name, apply:
   `acme --set node_name=acme1` and `systemctl restart acme`.
5. Within a few seconds acme puts the restored certificates, TLS settings, the
   page access lists and the firewall into nginx and iptables by itself.
   Check with `acme --web-status`.
6. [Section 8](#8-after-every-recovery-the-checks).

A copy with no full administrator in it (an installation that was used only
from the command line) is put back too, and acme says so; make an account
afterwards: `acme --add-user admin --role fulladmin`.

### 5.4 The key of the sealed secrets is lost

Symptoms: renewals and deployments fail with "cannot be opened", the pages say
the key is missing, `acme --check` complains about `/var/lib/acme/secrets.key`.

1. **Find it.** It is beside every kept copy (`/var/lib/acme/backups/acme-*.key`,
   all the same as long as it was never changed), inside every copy downloaded
   from the pages, in your vault, and on the other node of a cluster.
2. **Put it back**, as the service's own:

   ```bash
   systemctl stop acme
   install -m 0600 -o acme -g acme /root/acme-YYYYMMDD-HHMMSS.key /var/lib/acme/secrets.key
   systemctl start acme
   acme --check
   ```

   Or put a downloaded copy back ([section 5.2](#52-data-deleted-or-damaged)):
   its key comes with it.
3. **Lost everywhere** - no copy of it anywhere: the sealed secrets cannot be
   opened by anybody, ever. acme starts with a new key. Certificates, issuers,
   targets, directories and settings are not lost, but their secrets that were
   sealed have to be given again where acme says "cannot be opened": the
   passwords and API tokens of the issuers, challenges, targets and
   directories, the ACME accounts' keys (register again), the pages' own
   private keys. Every certificate is renewed with a new key (*Renew it now*,
   or `acme --renew all --force`); a CA of acme's own is made again, and what
   it signed is signed again by the new one.

### 5.5 An upgrade went wrong

`install.sh --upgrade` and the upgrades from the pages put the node back into
service by themselves if the new version does not start. If the new version
starts but misbehaves:

1. Put the older package back from its folder: `./install.sh --upgrade` (the
   command line takes an older version; the pages do not).
2. If the newer version changed the database, put back the copy made before
   the upgrade ([section 5.2](#52-data-deleted-or-damaged)). Every upgrade made
   from the pages and every `install.sh --upgrade` is a good moment for
   `acme --backup` first.

Upgrades go from any older version straight to the newest; see
[upgrades.md](upgrades.md).

### 5.6 Nobody can sign in to the pages

```bash
acme --users
acme --passwd admin                        # a new password for an account
acme --add-user rescue --role fulladmin    # or a new account
acme --set-role someone --role fulladmin
```

If the pages themselves are refused (403) from where you are, the page access
lists or the firewall shut you out. The machine itself is always let in, and so
is SSH unless you turned that rule off: reach the pages through an SSH tunnel,
then put the lists right under *Settings → Firewall → Who may reach the pages*.

```bash
ssh -L 8443:127.0.0.1:443 root@acme1        # then open https://localhost:8443/admin/
```

### 5.7 Moving to new hardware or another engine

A copy goes into SQLite, MariaDB or PostgreSQL alike. On the new machine:
install ([section 7.1](#71-one-server)), set the database up as wanted, and
put the newest copy back as in [section 5.3](#53-the-server-is-lost). For a
move between engines on the same machine see
[operations.md section 4](operations.md#4-moving-from-sqlite-to-postgresql)
and [section 16](operations.md#16-back-from-postgresql-to-sqlite).

---

## 6. A cluster of two: recovery

Two things make a cluster different:

- **A change reaches the other node within a second** - a wrong one too.
  Replication is protection against a lost machine, not against a mistake.
- **A copy put back on one node goes to the other node by itself.** Never put
  a copy back on both.

Below, `acme1` and `acme2` are the two nodes.

### 6.1 A wrong change

As on one server ([5.1](#51-a-wrong-change)), on **either** node: the fix
replicates. An imported configuration (`acme --import-config`) replicates too,
including each node's own settings and certificates.

### 6.2 Data deleted or damaged on both nodes

Certificates or targets deleted, a mass change - replicated to both nodes. Put the copy back on
**one** node:

```bash
# on acme1
acme --backup
acme --backup-info /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz
acme --restore /var/lib/acme/backups/acme-YYYYMMDD-HHMMSS.json.gz --yes
```

Or on the pages of one node: *Settings → The database → What is in it →
Restore*. The rows go over to acme2 by replication; after a minute:

```bash
acme --ha-status          # both directions running
acme --ha-compare         # "both nodes hold the same rows"
```

Notes:

- Only a **copy** goes back in a cluster. A dump is refused while replication
  runs: to use one, leave the cluster ([operations.md section 13](operations.md#13-leaving-the-cluster-back-to-one-server)),
  put it back on one node, and build the pair again.
- A copy sealed with **another key** than the cluster's is refused: the other
  node could not open its secrets. A copy of this cluster always has the right
  key. A copy from another installation goes in as in
  [section 6.6](#66-both-nodes-are-lost).
- A large database takes a while (about 45 s for 600 000 rows); the pages
  of the other node go on answering meanwhile.

### 6.3 One node's database is broken or behind

The database of one node does not open, is corrupt, the node was reverted to
a snapshot, or `acme --ha-status` says *lost - rebuild the other node*. The
other node is fine. **Rebuild the broken node from the good one** - no copy
needed:

```bash
# on the broken node
acme --maintenance on --why "rebuild"
acme --ha-resync --yes
acme --maintenance off
```

Or on its pages: *Settings → High availability → Rebuild this node from the
other…*. It keeps a copy of what was there, empties the node's tables, copies
every row from the good node and sets both directions of replication up again.
If PostgreSQL itself on that node is beyond repair, treat the node as lost
([section 6.5](#65-one-node-is-lost)).

### 6.4 Both nodes ran apart (split network)

Both answered and wrote while they could not see each other. Pick the node
that holds the truth (usually the one that led - renewed and deployed - during
the split; Events says which), and rebuild the
other from it:

```bash
# on the node whose data is given up
acme --ha-resync --yes
```

What only the rebuilt node recorded during the split is in its safety copy,
not in the cluster. See [operations.md section 10](operations.md#10-split-network-both-nodes-ran-alone).

### 6.5 One node is lost

A dead disk, a deleted VM, a node to be reinstalled. The survivor answers alone
meanwhile. Here acme1 is lost, acme2 survives (the same with the roles
swapped).

1. **On acme2** - leave the cluster, keeping everything:

   ```bash
   acme --backup
   acme --ha-standalone --yes
   ```

2. **The new acme1** - install it ([section 7.1](#71-one-server), with
   `--with-db postgres`), same acme version as acme2.
3. **On acme2** - make it the first node of a new pair:

   ```bash
   acme --ha-setup --ha-peer ADDRESS-OF-ACME1 --node-name acme2
   ```

   Write down the passphrase it prints once; the bundle is
   `/root/acme-join-acme2.json`.
4. **On acme1** - join:

   ```bash
   scp root@ADDRESS-OF-ACME2:/root/acme-join-acme2.json /root/
   acme --ha-join /root/acme-join-acme2.json --node-name acme1
   ```

   Every row comes from acme2, and so does the key. With the **same name** as
   before, acme1 gets back its own certificate and its own settings, which are
   kept in the database under its name. With a new name:
   `acme --ha-forget OLD-NAME` on either node.
5. `acme --ha-status ; acme --ha-compare`, and [section 8](#8-after-every-recovery-the-checks).

Details: [operations.md section 11](operations.md#11-a-node-is-lost-for-good).

### 6.6 Both nodes are lost

Fire, ransomware, a site gone. You need a copy and its key from **off the
machines**. You build one server from the copy, then the second node from it.

1. **acme1**: install it with PostgreSQL ([section 7.1](#71-one-server) and
   [operations.md section 3](operations.md#3-postgresql-16-on-almalinux-9)).
   Point acme at the database:

   ```bash
   acme --set db_engine=postgres --set db_host=127.0.0.1 --set db_port=5432 \
       --set db_name=acme --set db_user=acme --set db_password=- --yes   # the password asked for
   ```

2. **Put the copy back** on acme1, key beside it (or a downloaded copy):

   ```bash
   acme --backup-info /root/acme-YYYYMMDD-HHMMSS.json.gz    # which node made it, its config.json
   acme --restore /root/acme-YYYYMMDD-HHMMSS.json.gz --yes
   acme --set node_name=acme1 && systemctl restart acme       # the name it had
   ```

   acme1 is now a single server with everything of the cluster: the
   certificates, issuers, targets, accounts, both nodes' own certificates and own settings, the web
   address, the firewall.
3. **Build the pair** as in [operations.md section 5](operations.md#5-building-a-cluster-of-two):

   ```bash
   # on acme1
   acme --ha-setup --ha-peer ADDRESS-OF-ACME2 --node-name acme1
   # on acme2: install.sh --with-db postgres, then
   acme --ha-join /root/acme-join-acme1.json --node-name acme2
   ```

   The VIP address, kept in the copy, comes back by itself once there are two
   nodes; each node takes its certificate from the database.
4. `acme --ha-status ; acme --ha-compare`, and [section 8](#8-after-every-recovery-the-checks).

Without a copy but with an exported configuration (`--export-config
--with-secrets`): install, `acme --import-config FILE --yes`, build the pair -
the configuration and the current certificates come back; the jobs, events and
older versions do not.

### 6.7 The key is lost on one node

The other node still has it. Make a bundle there and join again:

```bash
# on the node that has the key
acme --ha-bundle /root/b.json        # prints a passphrase once
# on the node without it
acme --ha-join /root/b.json
```

Both nodes lost the key: as on one server ([5.4](#54-the-key-of-the-sealed-secrets-is-lost)),
then copy the key file to both nodes (`/var/lib/acme/secrets.key`, owner `acme`,
mode 0600) and restart acme on both.

---

## 7. Installing from nothing

### 7.1 One server

AlmaLinux 9 (or Rocky, RHEL 9; Debian/Ubuntu work too), the package unpacked:

```bash
tar xzf acme-X.Y.Z.tar.gz && cd acme-X.Y.Z
./install.sh --server-name acme.example.cz \
             --admin-allow 10.0.0.0/8 --portal-allow 10.0.0.0/8 \
             --with-db postgres --yes          # --with-db only for PostgreSQL / MariaDB
```

It installs the program, the service, nginx and PHP, a self-signed
certificate and the first administrator (the password is printed). acme
starts on SQLite; for PostgreSQL see
[operations.md sections 3 and 4](operations.md#3-postgresql-16-on-almalinux-9).

Then either put a copy back ([section 5.3](#53-the-server-is-lost)), import a
configuration ([section 5.1](#51-a-wrong-change)), or set it up anew:
directories on the pages (*Settings*), the pages' own certificate under
*Settings → Certificates and TLS*, then the issuers, challenges, targets and
certificates ([certificates.md](certificates.md)). Then **plan the backups** ([section 2](#2-the-backup-plan))
and keep the key.

### 7.2 A cluster of two

1. acme1 as in 7.1, with PostgreSQL ([operations.md section 3](operations.md#3-postgresql-16-on-almalinux-9),
   [section 4](operations.md#4-moving-from-sqlite-to-postgresql)).
2. `acme --ha-setup --ha-peer ADDRESS-OF-ACME2 --node-name acme1` on acme1.
3. acme2: `./install.sh --with-db postgres ...` and
   `acme --ha-join /root/acme-join-acme1.json --node-name acme2`.
4. In front of the pair: the VIP address (*Settings → High availability*) or a
   load balancer ([load-balancers.md](load-balancers.md)); both nodes allowed
   in by the targets (either may be the one that deploys).
5. Backups: each node makes its own copies; take those of one node off the
   machines every night ([section 2](#2-the-backup-plan)).

Full walk-through: [operations.md section 5](operations.md#5-building-a-cluster-of-two).

---

## 8. After every recovery: the checks

```bash
acme --status                   # the version, the database, the counts
acme --check                    # every part: the key, the copies, PHP, the directories
acme --certs | tail -1          # as many certificates as expected
acme --targets                  # where certificates go
acme --target-test NAME         # one target reached and signed in to, nothing changed
acme --web-status               # certificates, days left, where the VIP address is
# a cluster:
acme --ha-status                # both directions running, little or nothing behind
acme --ha-compare               # "both nodes hold the same rows"
```

And by hand:

- sign in to the pages with an administrator account;
- one certificate renewed and deployed (*Renew it now*), its job gone
  through - it proves the key, the issuer, the challenge and the target;
- *Events*: the restore is written down, with the name of the safety copy.

---

## 9. Reference

| Command | What it does |
|---|---|
| `acme --backup` | a copy now, into `/var/lib/acme/backups/`, key beside it |
| `acme --backup-info FILE` | what a copy holds and the machine it was made on |
| `acme --restore FILE --yes` | put a copy or a dump back (a safety copy first) |
| `acme --export-config FILE [--with-secrets]` | the configuration as JSON - with the current certificates, without the jobs and events |
| `acme --import-config FILE --yes [--replace]` | put a configuration back |
| `acme --ha-resync --yes` | rebuild this node from the other |
| `acme --ha-standalone --yes` | leave the cluster, keeping everything |
| `acme --ha-setup --ha-peer ADDR --node-name N` | the first node of a pair |
| `acme --ha-join FILE --node-name N` | the second node joins |
| `acme --ha-bundle FILE` | a new join bundle (with the key) |
| `acme --maintenance on/off` | take a node out of service and back |

| Where | What |
|---|---|
| `/var/lib/acme/secrets.key` | the key of the sealed secrets |
| `/var/lib/acme/backups/` | copies (`acme-*.json.gz`) and their keys (`acme-*.key`) |
| `/var/lib/acme/dumps/` | the engine's own dumps |
| `/var/lib/acme/acme.db` | the database, on SQLite |
| `/etc/acme/config.json` | the machine's own file |
| `/var/log/acme/acme.log` | the service's log |

On the pages: *Settings → The database* (copies, dumps, restore, download),
*Settings → Export and import* (the configuration), *Settings → High
availability* (the cluster, rebuild).
