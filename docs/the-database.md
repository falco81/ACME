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

On the pages: *Settings → The database*, then *Try it → Set it up → Carry
everything across → Start using it*. *Carry everything across* makes a copy
of what is here and loads it into the other database (which must be empty);
*Start using it* writes the new address into config.json and starts the daemon
again on it. Nothing is taken out of the old database, so going back is the
same steps the other way.

By hand, make the database and its account first:

```sql
-- MariaDB
CREATE DATABASE acme CHARACTER SET utf8mb4;
CREATE USER 'acme'@'localhost' IDENTIFIED BY '…';
GRANT ALL ON acme.* TO 'acme'@'localhost';
```

```bash
# PostgreSQL
sudo -u postgres psql -c "CREATE USER acme PASSWORD '…'"
sudo -u postgres psql -c "CREATE DATABASE acme OWNER acme"
```

then:

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
