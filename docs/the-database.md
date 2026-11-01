# The database

Everything acme keeps is in one database: the certificates and every version
of them, its own certificate authorities and what they signed, the sources
(issuers), the validations (challenges), the targets and the deployments,
every job with its steps, the records of acme's own DNS server, the settings
saved on the pages, the accounts, the sign-ins and every event.

| Engine | When | Needs |
|---|---|---|
| SQLite — a file, `/var/lib/acme/acme.db` | the default; one server | nothing |
| MariaDB / MySQL | a database server you already run | `python3-PyMySQL` (`--with-db mariadb`) |
| PostgreSQL (16 or later for two nodes) | a database server you already run; two acme servers ([high-availability.md](high-availability.md)) | `python3-psycopg2` (`--with-db postgres`) |

The database's own address cannot live in the database, so `db_engine`,
`db_host`, `db_port`, `db_name`, `db_user`, `db_password` and `db_timeout_s`
are kept in `/etc/acme/config.json` - and so are the node's name and its place
in a cluster (`node_name`, `ha_mode`, `ha_slot`, `ha_peer`, `ha_peer_port`,
`ha_address`). Everything else saved on the pages lives in the database and
wins over that file.

The tables are made by acme itself, on every engine from the same
declarations (the certificate manager's are in `acmelib/certs/schema.py`). A
column a later version adds is added at start. The types:

| | SQLite | MariaDB | PostgreSQL |
|---|---|---|---|
| a row's number | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGINT AUTO_INCREMENT` | `BIGSERIAL` |
| a name looked up by (unique) | `TEXT` | `VARCHAR(190)` compared byte for byte (`utf8mb4_bin`); `meta`'s keys 255 | `TEXT` |
| a big text - a PEM, a job's steps, JSON | `TEXT` | `MEDIUMTEXT` (16 MB) | `TEXT` |
| a moment (epoch seconds) | `REAL` | `DOUBLE` | `DOUBLE PRECISION` |

On MariaDB a name is therefore at most 190 characters, and `Web` and `web`
(or `novák` and `novak`) are two names, as on the other engines.

## The key of the secrets

The private keys of the certificates and of acme's own authorities, the
passwords and keys of the targets, the sources and the validations, the
passwords of the directories and the secrets among the settings are sealed
with `/var/lib/acme/secrets.key`, each bound to its row. A copy of the
database without that key is a copy whose secrets cannot be opened: every
backup is written with the key beside it (`acme-YYYYMMDD-HHMMSS.key`), and a
copy carried to another machine needs it in `/var/lib/acme/` there. The two
nodes of a cluster have the same key (it travels in the join bundle).

## Copies

One a day at `backup_at` (03:30), the last `backup_keep` (14) kept, in
`/var/lib/acme/backups/` — gzip'd JSON lines, the same for every engine, so a
copy from SQLite goes into PostgreSQL or MariaDB and the other way round. Every
table is in it, the certificate manager's too.

```bash
acme --backup                                        # one now
acme --restore /var/lib/acme/backups/acme-….json.gz --yes
```

A copy put back keeps the rows' numbers, and the numbering goes on past them.

## Moving to another engine

On the pages: *Settings → The database → Move to another database…*, a wizard
with Next and Back (what was typed is kept going back):

1. **Where to** - the database in use (its engine, size and the rows of each
   table) and the one to move to: SQLite (a file on this machine), MariaDB or
   PostgreSQL, each with a word on what it is for (two nodes need PostgreSQL)
   and whether its driver is installed - if not, the exact package for acme's
   Python (`dnf install python3.14-psycopg2`, `python3-PyMySQL`, … as
   `install.sh` puts them in).
2. **Connection** - for a server: its address, port (empty: 3306 / 5432), the
   database, the account and its password (dots only), TLS (off, `require`,
   `verify-full` with the authority's PEM file chosen on the page, kept as
   `/var/lib/acme/db-move-ca.pem`). With the server on this machine, *Make the
   database and the account for me* does it as root through the root helper
   (`acme_web.py --dbmake`: PostgreSQL as `postgres`, MariaDB as root over its
   socket - no administrator's password typed) and makes the account a password
   if none was typed. On another machine the wizard shows the SQL to run there,
   with Copy, or uses an administrator account of that server given for that
   one connection. For SQLite: the file (empty: `/var/lib/acme/acme.db`; any
   full path ending in `.db` in a folder acme may write - `db_path` in
   config.json).
3. **Check** - each a row with ✔ / ! / ✘ and what to do: another database
   than the one in use, room for the copy made first, the driver, reached as
   that account (a refused connection, a wrong password, pg_hba.conf, a missing
   database, a name that does not resolve, TLS - each said in plain words),
   the engine's version (PostgreSQL before 16: fine alone, not for two nodes),
   encrypted or not, what the account may do there (CREATE TABLE, CREATE INDEX,
   INSERT, UPDATE, SELECT, DELETE, ALTER, DROP - tried on a table of its own),
   empty or not, the characters (MariaDB utf8mb4, the names `utf8mb4_bin`;
   PostgreSQL UTF8) and the room on a disk of this machine. A database that
   holds acme already - a copy left by an earlier move, the way back - is
   refused until *throw away what of acme is in it, and move over it* is
   switched on; another installation's database is never mixed in.
4. **What happens** - from and to, the rows to copy, about how long, and the
   order below; switched on *I have read this* before *Move it now*.
5. **Moving** - one job (the daemon's one long job at a time), each step with
   what it said and each table with the rows copied of all:
   a copy of everything here, first (`/var/lib/acme/backups/`, its key beside
   it) → the tables made there → every row copied, as one transaction → the
   rows of every table counted against the copy, and every sealed secret there
   opened with the key, each under the bind it was sealed with (the certificate
   manager's too) → config.json switched to it → acme started again on it
   (systemd starts it, `Restart=always`) → asked whether it answers there.
   Meanwhile the pages answer and renewals and deployments wait. *Cancel the
   move* stops it at any step until config.json is switched; nothing here is
   changed then. The state of the move is kept in `/var/lib/acme/db-move.json`,
   so the page follows it through the restart and reads its end from the
   daemon that answers on the new database.
6. **Done** - what it runs on now, what was done, where the copy is, and
   *Move back…*: the old database is left exactly as it was, so going back is
   the same wizard the other way (it is thrown away and filled again with what
   is here now).

On the command line, the same steps:

```bash
ACME_DB_PASSWORD=… acme --db-move postgres --db-host 127.0.0.1 --db-name acme --db-user acme --db-check
ACME_DB_PASSWORD=… acme --db-move postgres --db-host 127.0.0.1 --db-name acme --db-user acme --yes
acme --db-move sqlite --db-path /var/lib/acme/acme.db --db-overwrite --yes     # back to the file
```

(`--db-tls-mode require|verify-full` and `--ca FILE` for TLS; `--db-check`
only checks; it restarts acme with systemctl at the end.)

**Not on a node of a cluster.** With `ha_mode` set in config.json, or another
node heard on this database a moment ago, the wizard does not start - the
page says why and how - and the API (409) and `acme --db-move` refuse too:
moving the database of one node would break the replication (or take the
shared database away from the other node). Take the cluster apart first
(*Settings → High availability → Switch it off…*, then
`acme --ha-standalone --yes` on each node), move, then build the cluster again
(*Make the bundle…*). A node whose config.json still says `ha_mode` though no
other node has been heard from for an hour is refused as well, and told to
leave the cluster mode with `acme --ha-standalone --yes`.

By hand, make the database and its account first:

```sql
-- MariaDB
CREATE DATABASE acme CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'acme'@'localhost' IDENTIFIED BY '…';
GRANT ALL ON acme.* TO 'acme'@'localhost';
```

```bash
# PostgreSQL
sudo -u postgres psql -c "CREATE USER acme PASSWORD '…'"
sudo -u postgres psql -c "CREATE DATABASE acme OWNER acme ENCODING 'UTF8' TEMPLATE template0"
```

then, without the wizard:

```bash
acme --backup
systemctl stop acme
# /etc/acme/config.json:
#   {"db_engine": "postgres", "db_host": "127.0.0.1", "db_port": 5432,
#    "db_name": "acme", "db_user": "acme", "db_password": "…"}
acme --restore /var/lib/acme/backups/<the copy just made> --yes
systemctl start acme
acme --status
```

## Tested

`test/engines.sh BACKUP` puts a copy back into each engine and reads it back
there: the accounts, the certificates, a certificate's sealed key exported,
the authority signing a renewal with its sealed key, a target's sealed
password tried, acme's DNS records and the jobs; then a directory and an
account made, the daemon started and asked, the configuration exported and
imported, the events read, a copy made; last, the move from SQLite into
PostgreSQL and on into MariaDB by the pages' own steps. A copy with
certificates in it is made by `python3 test/test_ha.py --make-backup DIR`.

`test/test_db_move.py` moves one populated installation by the wizard's own
questions around all six directions - SQLite → MariaDB → PostgreSQL (TLS,
`verify-full`) → MariaDB (over the older copy) → SQLite (another file) →
PostgreSQL → SQLite - and after each counts every table on the new database
against the old one, opens every sealed secret there, starts the daemon again
on it and renews a certificate; it also cancels a move half-way, moves by
`acme --db-move`, and checks the refusal on a node of a cluster (the API's
409 and the command line). It needs the servers on this machine and root (the
wizard makes its own database `acmemv` there) and is skipped without them.

`test/test_ha.py` tries the same in Python, and more: the types and limits
above on MariaDB (a 130 KB PEM, the 190-character unique names), the lease of
the certificate manager on each engine, and both layouts of two nodes. Each
part is skipped when its database server is not there (`ACME_TEST_PG_PORT`,
`ACME_TEST_PG2_PORT`, `ACME_TEST_MY_PORT`; database `acme`, account `acme`,
password `optpw`).

## How long things are kept

`retain_events_days` (365; 0 keeps for ever) for the events,
`certs_keep_jobs_days` (90) for the jobs and `certs_keep_versions` (10) for the
old certificates of each one. The tidying runs every hour, or `acme --tidy`.
