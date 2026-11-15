# The database on a server of its own (acme-db-agent, 1.0.113)

Until 1.0.113 acme looked after its database only when it ran **on the same
machine**: the root helper (`acme_web.py`, started by `acme-web.path`) gave
PostgreSQL its certificate, changed `pg_hba.conf`, switched `ssl` on, read the
replication's log; `acme --ha-setup` / `--ha-join` set `wal_level`,
`listen_addresses`, made the account able to replicate, published the tables and
restarted PostgreSQL as root. A database elsewhere was the server
administrator's: acme only connected to it.

From 1.0.113 a database server of its own can be looked after **exactly the same
way**, by a small agent installed on it - **acme-db-agent**. Nothing changes for
an installation that does not use one: without the agent's file on a node
(`/var/lib/acme/db-agent/agent.json`), every path is the one it was, nothing new
runs, nothing new is asked or said.

```
 layout A - one node                     layout B - two nodes, replicated
 ┌────────┐  HTTPS 9443 (mTLS, signed)   ┌────────┐ VRRP VIP ┌────────┐
 │ acme   │ ───────────────► agent       │ acme1  │◄────────►│ acme2  │
 │ node   │                  │           └───┬────┘          └───┬────┘
 │        │  PostgreSQL 5432 ▼           agent│+5432          agent│+5432
 │        │ ───────────────► DB server       ▼                    ▼
 └────────┘  (TLS verify-full)            ┌──────┐ logical repl. ┌──────┐
                                          │ db1  │◄─────────────►│ db2  │
                                          └──────┘ TLS verify-full└─────┘
```

- **Layout A - one acme server, one database server.** Everything acme does to a
  database on its own machine - the certificate from acme's own authority and its
  renewal, the settings and the restart (*Settings → The database → The server's
  own settings*), the database and its account made for a move, the moves,
  backups and putting one back, the meter in the header - it does to the server
  of its own through its agent. PostgreSQL and MariaDB.
- **Layout B - high availability, replicated.** Two acme servers with everything
  they have today (the VIP address with keepalived, the leader, the split
  handling, the clocks), **each on its own database server**: acme1 → db1, acme2 →
  db2. db1 and db2 replicate both ways (PostgreSQL's logical replication), set up,
  encrypted (verify-full, `hostssl`) and watched by acme as today. **PostgreSQL 16
  or later only**, as today - MariaDB has no replicated layout.
- *Shared* (both nodes on one PostgreSQL, `--ha-shared`, possibly with
  `--ha-db-host`) is unchanged: that server stays the administrator's.

## What touched "the database server is this machine"

Every operation that assumed it, and how it is done with an agent:

| Where | What | Kind | With an agent |
|---|---|---|---|
| `acme_web.py` pgtls `server` (link TLS, Database → TLS) | key/cert into PG's data folder, `/etc/pki/acme/ha-ca.pem`, `ALTER SYSTEM SET ssl…`, reload, TLS probe on 127.0.0.1 | root on the DB machine | agent `pgtls` (the same code) |
| pgtls `hba` / `hba_off` / `peer` | `pg_hba.conf` host ⇄ hostssl, a node's new address | root (file) | agent `pgtls`, for the other DB server **and** the other acme node |
| pgtls `server_off` | `ALTER SYSTEM RESET`, files away | root | agent `pgtls` |
| pgtls `ha_open` (shared pair from the pages) | listen, `pg_hba.conf`, restart | root | agent `pgtls` (shared stays unmanaged unless the first node has an agent) |
| `acme_web.py --dbmake` (Move → "make it for me") | role and database as postgres / MariaDB root over the socket | root (local socket) | agent `dbmake` (+ `pg_hba.conf` / `'user'@'node'` for the acme nodes) |
| `acme_web.py` pglog | PostgreSQL's log lines about replication | reads local files | agent `pglog` |
| `--ha-setup` / `--ha-join`: `pg_prepare_local` | `wal_level`, `listen_addresses`, `max_slot_wal_keep_size`, role REPLICATION, `pg_create_subscription`, database, `pg_hba.conf` | SQL as superuser + file | agent `pg_prepare` |
| `pg_publication` | `CREATE PUBLICATION … FOR ALL TABLES` | superuser SQL | agent `pg_publication` |
| `pg_restart_local`, tuning's restart | systemctl / pg_ctlcluster | root | agent `pg_restart` (`my_restart`) |
| `pg_install_local` | dnf/apt PostgreSQL | root, packages | `install.sh --db-server postgres` on the DB server; acme says so |
| `firewall_peer` | firewalld rich rule for 5432 | root | agent `fw_allow` |
| `pg_local_running` | `SELECT 1` as postgres | local socket | agent `status` |
| `hatls_own_cert` | TLS probe of 127.0.0.1 | network | probes the DB server's address |
| tuning `tune_machine` | /proc of this machine | reads local state | agent `status` facts |
| meter `/api/load` | /proc of this machine | reads local state | agent `load`, `dbservers` rows |
| `HA_CA_FILE` exists / readable | the authority file | local file | written on the acme node too (the daemon's verify-full) |
| sequences, subscriptions, slots, rebuild, pause/resume, readdress (subscription), compare, backups (`pg_dump`), restore, moves, db_guard, schema upgrade | SQL | works remotely already | unchanged |
| `--ha-standalone`, `--ha-resync` | stop/start acme, SQL | local acme only | unchanged |

## The agent

`deploy/acme_db_agent.py` (standard library and `openssl` only), installed by
`install.sh --db-server postgres|mariadb` or `install.sh --db-agent` into
`/usr/local/lib/acme-db-agent/` with `acme_pg_ops.py` and `acme_web.py`, run by
`acme-db-agent.service`. Its configuration, root's (0600):

```json
/etc/acme-db-agent/agent.json
{"listen": "0.0.0.0", "port": 9443, "engine": "postgres", "pg_port": 5432,
 "user": "acme-db-agent", "state": "/var/lib/acme-db-agent",
 "log": "/var/log/acme-db-agent/audit.log", "ha_ca": "/etc/pki/acme/ha-ca.pem",
 "advertise": "", "names": [], "rate": 20, "burst": 60,
 "pg_restart_cmd": null, "my_port": 3306, "my_socket": null, "my_cnf_dir": null,
 "my_tls_dir": "/etc/acme-db-agent/mariadb", "my_restart_cmd": null}
```

Beside it: `boot.crt/key` (self-signed, until a node joined), `server.crt/key`
(from acme's authority), `ca.pem` (the authorities client certificates are checked
against), `clients.json` (each node: certificate fingerprint, signing key),
`join.json` (one-time codes, hashed).

### Two processes: root does only the closed set

- The **network side** runs as `acme-db-agent` (or `nobody`): it binds the port,
  terminates TLS, checks the client certificate, rate-limits (a token bucket per
  address, failed tries cost more), and hands each request to root over a socket
  pair. It gives root up right after binding (`setgroups([])`, `setgid`,
  `setuid`, `PR_SET_NO_NEW_PRIVS`; it dies with root, `PR_SET_PDEATHSIG`).
- The **root side** checks every request **again** - the certificate's
  fingerprint is one enrolled, the HMAC signature, the time (±120 s), the nonce
  never seen - and only then runs **one operation of a closed set**
  (`acme_pg_ops.OPS`). It writes the audit log (`audit.log`, JSON lines: time,
  node, address, operation, `do`, what was said - never a password or a key).
- No shell, no file named by a request, SQL only as `postgres` (`runuser`) or
  MariaDB's root over its socket.

### The protocol

HTTPS (TLS 1.2+) on its own port (9443).

| Path | Who | Body | Answer |
|---|---|---|---|
| `GET /v1/hello` | anyone | - | `{"agent": "acme-db-agent", "version"}` |
| `POST /v1/enroll/begin` | a node with a join code | `{secret, node}` | `{csr, names, version, engine, pg_port, my_port}` |
| `POST /v1/enroll/finish` | the same | `{secret, node, cert, ca, client_cert, sign_key}` | `{said, facts}` - the code is used up |
| `POST /v1/op` | an enrolled node | `{op, args}` | `{ok, said, ...}` |

Every `/v1/op` request carries a client certificate from acme's authority, and

```
X-Acme-Node: NODE   X-Acme-Time: 1794761625.456   X-Acme-Nonce: 32 hex
X-Acme-Sign: hex HMAC-SHA256(sign_key, "acme-db-agent/1\nPOST\n/v1/op\nNODE\nTIME\nNONCE\n" + sha256hex(body))
```

The answer is signed back: `X-Acme-Sign: HMAC(sign_key, "reply\nNONCE\n" + sha256(body))`.
The node pins the agent's certificate by its SHA-256 fingerprint **and** checks it
against acme's authority.

### Joining (enrollment)

1. On the database server: `install.sh --db-server …` prints a **join code**, or
   `acme_db_agent.py --new-code [--minutes 60]` makes one. It is
   `ADBA1.` + base64url of `{h: address, p: port, s: secret, f: SHA-256 of the
   agent's certificate, e: engine}`; valid an hour, five wrong tries void it.
2. On the acme node (root): `acme --db-agent-join CODE [--db-agent HOST:PORT]
   [--db-agent-db-host HOST]` (or *Join* on the page: `POST /api/db-agent
   {action: join, code}`). The node connects, **pins the fingerprint of the
   code** (nobody in between can pose as the agent), sends the secret, gets a
   certificate request (the agent's key never leaves its server), issues the
   agent's server certificate (its names and the address the node used) and its
   own client certificate (clientAuth, CN `acme-NODE`) from acme's authority,
   makes a signing key, and sends all of it. The agent checks both certificates
   against the authority and that the server certificate is for the key it asked
   with, then starts its network side again with them.
3. The node keeps `/var/lib/acme/db-agent/`: `agent.json` (`db_admin:
   "agent:HOST:PORT"`, pins, engine, ports, the other acme node's address in
   layout B), `client.crt/key`, `ca.pem`, `sign.key` (0600, the daemon's - not
   sealed with `secrets.key`, which a join or a backup put back replaces).
4. Several nodes may join one agent (a code each).

`acme --db-agent-forget --yes` goes back to `db_admin` local (the file is kept
as `agent.json.forgotten`); `acme_db_agent.py --forget NODE` on the server
takes a node's certificate away.

### The operations (the closed set)

| Verb | Arguments (checked) | What it does |
|---|---|---|
| `status` | - | facts: host, CPUs, RAM, load, uptime; engine, version, running, ssl, wal_level, connections, the data folder's disk; the agent's version, certificate end, the nodes it knows |
| `load` | `db` (a plain name) | the meter: `cpu`, `mem_used`, `mem_total`, `swap_used`, `disk_rd`, `disk_wr`, `net_rx`, `net_tx` (B/s), `load`, `cores` - as a node's `server_load()` - and `db: {running, version, started, connections, repl_behind, size, disk}` |
| `pgtls` | the root helper's pgtls request (`do` ∈ server, hba, peer, hba_off, server_off, ha_open; db, user, peer(s), cert, key, trust) - `acme_web.pgtls_checked`, the port is the agent's own | the root helper's own functions |
| `pg_prepare` | db, user (plain, not the server's own), password (8-128 printable, no `'` `\`), peers (≤ 8 plain addresses) | wal_level logical, listen `*`, max_slot_wal_keep_size 16GB, the role (REPLICATION, pg_create_subscription; refused if it is a superuser/createrole), the database (UTF-8), pg_hba lines in front - the file kept beside, put back when PostgreSQL does not read it; says whether a restart is needed |
| `pg_allow` | db, user, peers | pg_hba lines only |
| `pg_publication` | db | `acme_pub` FOR ALL TABLES (insert, update, delete) |
| `pg_restart`, `pg_reload` | - | systemd unit / pg_ctlcluster (the root helper's), or `pg_restart_cmd` from the agent's configuration; waited for |
| `pglog` | - | the root helper's pglog |
| `dbmake` | name, user, password, peers | the root helper's dbmake; pg_hba (or MariaDB `'user'@'peer'`) for the nodes |
| `fw_allow` | peers, `agent` | firewalld rich rules for the database port (and the agent's) from those addresses |
| `my_tls` | cert, key, trust | MariaDB: files (mysql's to read), `zz-acme-tls.cnf`, restart the first time, `FLUSH SSL` after; checked `@@have_ssl`, put back otherwise |
| `my_restart` | - | the mariadb service or `my_restart_cmd` |
| `agent_csr`, `agent_cert` | cert, ca | the agent's own certificate renewed (a new key each time) |
| `trust` | ca, client_cert_new | the authorities replaced, a node's next client certificate announced (never one that would lock the asking node out) |
| `clients` | drop | the nodes it knows; one taken away |

Anything else: *"… is not something this agent does"*. PostgreSQL verbs on a
MariaDB agent and the other way round are refused.

## How acme decides: `db_admin`

Per node, in `/var/lib/acme/db-agent/agent.json` - never in `config.json` nor the
database, so nothing of it moves with a backup or to the other node:

- `local` (no file - every installation until now): the root helper, unchanged.
- `agent:HOST:PORT`: each place in the table above asks the agent instead:
  `pgtls_send` → `db_agent_pgtls_send` (its answer written to the same
  `pgtls.json`, so the link's steps, Database → TLS and a new address read it as
  ever), `pg_prepare_local`, `pg_publication`, `pg_restart_local`,
  `pg_local_running`, `pg_install_local`, `firewall_peer`, `db_make_here`,
  `repl_errors`' log, `hatls_own_cert`, `hatls_names` (+ the DB server's
  address), `dbtls_kind` (a PostgreSQL with an agent counts as *local* or
  *replicated*), tuning's facts and restart.

## Layout B step by step (replicated, each node its own server)

1. Two database servers: `install.sh --db-server postgres --acme-node ACME1
   --acme-node ACME2` on each (PostgreSQL 16, wal_level logical, the agent).
2. acme1: `acme --db-agent-join CODE-OF-DB1`, then move its database onto db1
   (*Settings → The database → Move*, or `acme --db-move postgres --db-host DB1`).
3. acme1: `acme --ha-setup --ha-peer DB2 --ha-peer-node ACME2 --node-name acme1`.
   `--ha-peer` is the **other database server**, `--ha-peer-node` the other acme
   node; `ha_address` is db1 by default. The agent of db1 prepares it (pg_hba for
   db2, acme2 and acme1), restarts it, publishes the tables, opens its firewall.
4. acme2: `acme --db-agent-join CODE-OF-DB2`, then `acme --ha-join BUNDLE
   --node-name acme2`: db2 prepared by its agent, every row copied from db1, both
   subscriptions; `config.json` gets `db_host` = db2.
5. *High availability → Repair* (or `acme --ha-tls-repair`): each node issues its
   server's certificate, its agent puts it in; verify-full; `hostssl` for the other
   server and the other node. The authorities are written on each server
   (`/etc/pki/acme/ha-ca.pem`, read by its replication workers) and on each node
   (the daemon's own checks).
6. VIP (keepalived), the leader, split handling, clocks: unchanged - they are the
   nodes' own.

Renewals (45 days before), the authority's roll, the ten-minute check of the
link, a rebuild (`acme --ha-resync`, *Rebuild this node*), pause/resume, stop,
readdress: as today, the root parts through the agents.

## Watching

- Every node with an agent looks at it every 30 s (`dbagent:node:NODE` in `meta`,
  replicated): answering, facts, the agent's version and certificate. An event
  when it stops / starts answering; an **alert** (`dbagent:NODE`, bad) after 90 s
  away, `dbserver:NODE` when the agent answers but the database does not, a warn
  14 days before the agent's certificate ends (renewed by itself 45 days before).
- Prometheus: `acme_db_agent_up{node,host}`, `acme_db_server_up{node}`.
- `acme --status` has a line; `acme --db-agent-status [--json]`.
- The meter: `/api/load` → `dbservers: [...]`.

## The pages (data for them)

- `GET /api/db-agent` (readonly): `{db_admin, node, host, port, db_host, engine,
  joined_at, joined_by, peer_node, agent_cert_end, client_cert_end, state: {ok,
  down_since, fails, at}, servers: [...], applies: {...}}`.
- `POST /api/db-agent` (fulladmin): `{action: join, code, address?, db_host?}`,
  `look`, `renew`, `restart`, `mariadb_tls`, `forget`.
- `servers` / `dbservers` entries, shape of a node's dot with `kind: "db"`:
  `{kind: "db", name: "db:NODE", node, me, alive, stale, ok, said, down_since, at,
  host, port, db_host, engine, db_admin, agent_cert_end, client_cert_end,
  facts: {host, fqdn, cpus, ram, avail, load, uptime, virtual, engine, running,
  version, ssl, wal_level, started, connections, disk: {total, free}},
  agent: {version, port, engine, pg_port, cert_end, cert_fp, boot, clients, uid}}`.
- Added only with an agent: `GET /api/ha` → `db_admin`, `dbservers`; `GET
  /api/dbtls` → `db_admin`, `dbservers`; `GET /api/load` → `dbservers` (each
  `{kind: "db", name, node, host, age, cpu, mem_used, mem_total, swap_used,
  disk_rd, disk_wr, net_rx, net_tx, load, cores, over_s, db: {...}}`).

Which cards draw the database servers beside the nodes (`applies`):

| Card | Database servers? |
|---|---|
| The database → TLS (certificate, renewal) | yes |
| High availability → the link, replication, errors (log) | yes |
| The database → the server's own settings, restart | yes |
| Firewall - the database's port | yes (the agent's `fw_allow`) |
| The meter in the header | yes |
| nginx / web TLS, VIP, sshd, sign-in, SELinux, NTP, password policy, logs, OS updates, db_guard | no - the acme nodes' own (the DB server's OS is its administrator's) |

## Installing a database server

`install.sh` on the database server (never on the acme node; nothing of acme is
installed), `--dry-run` and running it again are safe:

```
./install.sh --db-server postgres --acme-node 192.0.2.11 --acme-node 192.0.2.12
./install.sh --db-server mariadb  --acme-node 192.0.2.11
./install.sh --db-agent                       # the agent alone, for a server you installed
./install.sh --db-agent --uninstall           # the agent away; the database stays
   [--db-agent-port 9443] [--db-name acme] [--db-user acme] [--db-password PASS]
```

PostgreSQL 16: EL 9 the `postgresql:16` AppStream module, EL 10 AppStream's 16,
else PGDG (`pgdg-redhat-repo`); Debian 12 / Ubuntu 22.04 PGDG's apt repository,
Ubuntu 24.04 its own `postgresql-16`. Initialised UTF-8 with scram-sha-256,
enabled and started, `listen_addresses = '*'`, `wal_level = logical`,
`max_slot_wal_keep_size = 16GB`, the account (REPLICATION,
`pg_create_subscription`, password made up and shown once unless given), the
database, `pg_hba.conf` for the nodes given, firewalld for the nodes given
(database port and agent port), the agent, a join code. MariaDB: the
distribution's server, secured (no anonymous accounts, no test database, root
only locally), the database (utf8mb4_bin) and the account at localhost,
127.0.0.1 and each node, listening on the network. TLS comes from acme once a
node joined.

## Security notes

- The join code is a secret for an hour; it carries the agent's certificate
  fingerprint, so the first connection is pinned too.
- A stolen client certificate is not enough without the signing key, and a
  captured request cannot be replayed (nonce, ±120 s).
- The root side never trusts the network side: every check is made again there.
- systemd hardening: `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`,
  `ReadWritePaths` limited to the agent's and the database's folders.
- An alternative without root at all (a dedicated account with sudo for exactly
  `systemctl restart postgresql`, files owned by postgres) is possible for
  PostgreSQL alone; it was not taken because `pg_hba.conf` and the firewall need
  root anyway and the closed set is the same - documented as an open point.

## Out of scope

- MariaDB replication (Galera, primary/replica): no; replicated HA stays
  PostgreSQL 16+.
- Physical backups (`pg_basebackup`) on the DB server: acme's backups stay
  `pg_dump` / its own portable copy over the network; a rebuild copies through the
  subscription.
- Packages on the DB server from acme (`pg_install_local` with an agent says to
  run `install.sh --db-server`).
- The shared layout's server.
