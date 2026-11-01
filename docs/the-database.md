# The database

Everything acme keeps is in one database: the tokens, the clients, the realms,
the directories, the settings saved on the pages, the accounts, every RADIUS
request, every check of a code, every event.

| Engine | When | Needs |
|---|---|---|
| SQLite — a file, `/var/lib/acme/acme.db` | the default; one server | nothing |
| MariaDB / MySQL | a database server you already run, or two acme servers on one database | `python3-PyMySQL` (`--with-db mariadb`) |
| PostgreSQL | the same | `python3-psycopg2` (`--with-db postgres`) |

The database's own address cannot live in the database, so `db_engine`,
`db_host`, `db_port`, `db_name`, `db_user`, `db_password` and `db_timeout_s`
are kept in `/etc/acme/config.json`. Everything else saved on the pages
lives in the database and wins over that file.

## The key of the tokens

The key of every token, the shared secrets of the clients and the passwords
of the directories are sealed with `/var/lib/acme/secrets.key`. A copy of the
database without that key is a copy whose tokens cannot be opened: every
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

The tables are made by acme itself. `test/engines.sh` runs the whole flow —
restore, a client, a realm, a token, real RADIUS packets, the logs read back,
a copy — on each engine.

## How long things are kept

`retain_radius_days` (180), `retain_acme_days` (180), `retain_events_days`
(365); 0 keeps for ever. The tidying runs every hour, or `acme --tidy`.
