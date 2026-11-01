# The database

Everything acme keeps is in one database: the certificates with their
versions and sealed keys, acme's own CAs, the issuers, challenges, targets and
deployments, every job, the DNS server's records, the directories, the settings
saved on the pages, the accounts, every event ([architecture.md](architecture.md)
lists the tables).

| Engine | When | Needs |
|---|---|---|
| SQLite — a file, `/var/lib/acme/acme.db` | the default; one server | nothing |
| MariaDB / MySQL | a database server you already run, or two acme servers on one database | `python3-PyMySQL` (`--with-db mariadb`) |
| PostgreSQL | the same | `python3-psycopg2` (`--with-db postgres`) |

The database's own address cannot live in the database, so `db_engine`,
`db_host`, `db_port`, `db_name`, `db_user`, `db_password` and `db_timeout_s`
are kept in `/etc/acme/config.json`. Everything else saved on the pages
lives in the database and wins over that file.

## The key of the sealed secrets

The private keys of the certificates and the CAs, the passwords and API
tokens of the issuers, challenges and targets, and the passwords of the
directories are sealed with `/var/lib/acme/secrets.key`. A copy of the
database without that key is a copy whose secrets cannot be opened: every
backup is written with the key beside it (`acme-YYYYMMDD-HHMMSS.key`), and a
copy carried to another machine needs it in `/var/lib/acme/` there.

## Copies

One a day at `backup_at` (03:30), the last `backup_keep` (14) kept, in
`/var/lib/acme/backups/` — gzip'd JSON lines, the same for every engine, so a
copy from SQLite goes into PostgreSQL and the other way round.

```bash
acme --backup                                        # one now
acme --restore /var/lib/acme/backups/acme-….json.gz --yes
```

## Moving to MariaDB

```sql
CREATE DATABASE acme CHARACTER SET utf8mb4;
CREATE USER 'acme'@'localhost' IDENTIFIED BY '…';
GRANT ALL ON acme.* TO 'acme'@'localhost';
```

## Moving to PostgreSQL

```bash
sudo -u postgres psql -c "CREATE USER acme PASSWORD '…'"
sudo -u postgres psql -c "CREATE DATABASE acme OWNER acme"
```

## Then, for either

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

The tables are made by acme itself. `test/engines.sh` runs the whole flow on
each engine.

## How long things are kept

`retain_events_days` (365); 0 keeps for ever. The tidying runs every hour, or `acme --tidy`.
