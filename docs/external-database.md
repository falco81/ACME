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

Beside it: `agent.crt/key` - the certificate the agent answers **every** node with, made by
the agent itself (no authority stands behind it: each node pins its SHA-256 fingerprint);
`agent-next.crt/key` while its next one is announced; `clients.json` (each node: its client
certificate's fingerprint - and the next one while it renews -, its signing key, the
authorities that issued its certificate, which of the agent's certificates it pins);
`join.json` (one-time codes: an id, the secret hashed, the tries, the begun joins' tokens
hashed); `enroll.key` (1.0.115: root's own RSA key pair, 3072 bits, made once - a joining node
seals the code's secret and its signing key to it). Each node's entry also says when it was
last heard from (`seen`, an hour at most off; a node enrolled by an agent before 1.0.115 has
none - it counts as heard from when the upgraded agent first starts, not as gone 30 days after
it joined), and which authority signed its certificate (`issuers`, checked with that
authority's key; `issuers_seen`, every one that signed a certificate it was let in with - at its
join, a renewal put in use, a `trust` - kept, 1.0.115). In `state` (`/var/lib/acme-db-agent`):
`nonces.json`, the nonces of the last four minutes, so a request captured cannot be replayed
after a restart either; `server-cert.json` (1.0.115), which node - and which authorities - put
the database server's certificate in (`issuers`: the ones that signed the client certificate
it asked with).

The account the network side runs as (`user`, `acme-db-agent`) is made by `install.sh`; the
agent refuses to start that side as `root` or `nobody` (another service's account), and when
the account is missing.

### Two processes: root does only the closed set, and holds every key

- The **network side** is a program of its own, started afresh by root for each
  start of that side (`acme_db_agent.py --network-side FD LFD`, never a `fork()` - a
  copy of root's memory), with the socket pair to root (`FD`) as its only link and
  the listening socket (`LFD`) - root binds the port once and gives the same socket
  to each side it starts. Root gives it the fingerprints enrolled and the
  authorities TLS needs to ask for the nodes' certificates - **no signing key**. It
  loads the agent's certificate, gives root up at once (`setgroups([])`, `setgid`,
  `setuid` to `acme-db-agent`, `PR_SET_NO_NEW_PRIVS`; it dies with root,
  `PR_SET_PDEATHSIG` - set again after `setuid`, which clears it, and ended at once
  when root is already gone),
  terminates TLS, turns away a request without an enrolled certificate (401/403),
  rate-limits (a token bucket per address; failures - no certificate, not
  enrolled, a bad signature, a wrong join code, a failed handshake - cost more and
  **do** block the address for a while: `fail_rate`, `fail_burst` in agent.json),
  and hands each request **as it came** to root: method, path, the `X-Acme-*`
  headers, the body and the client's certificate (DER). It writes back the answer
  root made, signature included. It never sees a signing key nor a join code's
  secret (1.0.115): at enrollment the node seals both to root's own key (RSA-OAEP,
  SHA-256), whose fingerprint is in the join code - this side passes the sealed
  bytes on and could not put another key in (the node checks it against the code).
  Several requests go to root at once, each with an id of its own (1.0.115): one
  node's long operation (a restart, a certificate - up to 240 s) does not hold
  another node's `status` or `load` (16 at most at once; more are answered 503 for a
  moment). When it starts again (its next certificate, a node joined or left, new
  authorities) it takes the nodes let in now at once, goes on answering everybody
  while what root still works on is answered (up to 300 s), then stops taking
  connections and is started again: the listening socket is root's, given to each
  side started, so connections wait in its queue for a second or so - none refused,
  never 503 to everything meanwhile (1.0.115). The side ends only once the
  connections it took are answered (a slow client's included). An answer from root
  without the request's id (a root started before 1.0.115, its program upgraded
  under it) ends the side at once - every request waiting is answered 503 - instead
  of leaving them waiting 900 s; restart the agent after an upgrade
  (`install.sh --db-agent` does).
- The **root side** works the fingerprint out of the certificate itself, checks
  it is enrolled (and for the node the request names), the HMAC signature, the
  time (±120 s), the nonce never seen (kept across a restart) - and only then runs
  **one operation of a closed set** (`acme_pg_ops.OPS`), and signs the answer.
  It writes the audit log (`audit.log`, JSON lines: time, node, address,
  operation, `do`, what was said, `ok` - refusals too: no certificate, not
  enrolled, a bad signature, a replay, a wrong join code, a failed operation;
  never a password, a key, a signature or a code). An operation that changes the
  server runs one at a time; `status` and `load` are answered beside it, and while
  it runs `status` says so (`agent.busy`: `{op, node, since}` - *busy with
  pg_restart for acme1*). A stop or restart of the service (SIGTERM) waits for the
  operation under way (300 s at most - `TimeoutStopSec=360`, `KillMode=mixed`: the
  root side ends the network side itself) and begins no new one (*the agent is
  stopping*); `status` and `load` are answered meanwhile (1.0.115: it was cut off).
- No shell, no file named by a request, SQL only as `postgres` (`runuser`) or
  MariaDB's root over its socket.

### The protocol

HTTPS (TLS 1.2+) on its own port (9443).

| Path | Who | Body | Answer |
|---|---|---|---|
| `GET /v1/hello` | anyone | - | `{"agent": "acme-db-agent", "version", "code"}` |
| `GET /v1/enroll/key` | anyone | - | `{pub, fp}`: root's public key the join is sealed to (the node checks `fp` against the code's `k`) |
| `POST /v1/enroll/begin` | a node with a join code | `{code_id, node, seal}` - `seal`: base64 of RSA-OAEP(`acme-db-agent-seal/1\nbegin\nCODE_ID\nNODE\nSECRET`) | `{token, names, version, code, engine, pg_port, my_port, cert_fp, cert_next_fp}` |
| `POST /v1/enroll/finish` | the same | `{code_id, token, node, client_cert, ca, seal}` - `seal`: RSA-OAEP(`…\nfinish\nCODE_ID\nNODE\nSECRET\nSIGN_KEY\nSHA-256 of client_cert`) | `{said, facts}` - the code is used up |
| `POST /v1/op` | an enrolled node | `{op, args}` | `{ok, said, ...}` |

A join without `seal` (acme before 1.0.115) is refused: *this agent takes a join only sealed to
its own key*. A seal that does not open, or names another node or code, counts as a wrong code.

Every `/v1/op` request carries the node's client certificate (from acme's authority; the
agent lets it in by its fingerprint), and

```
X-Acme-Node: NODE   X-Acme-Time: 1794761625.456   X-Acme-Nonce: 32 hex
X-Acme-Sign: hex HMAC-SHA256(sign_key, "acme-db-agent/1\nPOST\n/v1/op\nNODE\nTIME\nNONCE\n" + sha256hex(body))
```

The answer is signed back (by root): `X-Acme-Sign: hex HMAC-SHA256(sign_key, "reply\nNONCE\n" +
SHA-256(body))`, the body's SHA-256 here being its **32 raw bytes** (`digest()`), not the hex
text the request's signature takes. The node pins the agent's certificate by its SHA-256 fingerprint - the one in
the join code, then the ones the agent's signed answers announce. An answer with
`agent_restart` means the agent starts its network side again (a node joined or was taken
away, the authorities of a node, its next certificate in use): the node waits for it.

### The agent's certificate: one for every node, renewed by the agent

The agent makes its certificate itself (825 days) and answers every node with it: a second
node joining, or a node joining again, changes nothing for the others. 60 days before it
ends the agent makes the next one (`acme --db-agent-renew` asks for it at once, op
`agent_renew`) and announces it in the answer to `status` (`agent.cert_next_fp`), which is
signed with each node's key: each node pins it beside the one in use and says so in its next
`status` (`args.pins`). Once **every** node joined has it pinned, the agent puts it in use and
starts its network side again; the nodes then pin only it. A node that leaves tells the agent
(`leave`: on `acme --db-agent-forget`, a move off the server, joining another agent,
`acme --db-agent-leave`) and is off the list. One not heard from for **30 days** (gone
without a word) is not waited for (1.0.115) - it is listed as such: `stale` in
`acme_db_agent.py --status`, *Not heard from* on the card, a line in `acme --status` and
`acme --db-agent-status`; `acme_db_agent.py --forget NODE` takes it away for good. And
whatever is left: 7 days before the end the next one is put in use anyway (that node would
have to join again). The alert on a node (`dbagent:cert:NODE`) follows it: within 14 days of
the end only when no next certificate is announced, or the switch 7 days before the end did
not happen (*… switches by itself 7 days before the end …, and that did not happen*).

### Joining (enrollment)

1. On the database server: `install.sh --db-server …` prints a **join code**, or
   `acme_db_agent.py --new-code [--minutes 60]` makes one. It is
   `ADBA1.` + base64url of `{h: address, p: port, s: secret, i: the code's id,
   f: SHA-256 of the agent's certificate, e: engine, k: SHA-256 of root's public
   key the join is sealed to (1.0.115; a code without it - an older agent - is
   refused by the node: upgrade the agent)}`; valid an hour. A wrong
   secret counts against the address it came from (ten in an hour, and that
   address is refused for the hour) - and against the code only when its id was
   right (five such tries void it): a stranger guessing burns nobody's code.
2. On the acme node (root): `acme --db-agent-join -` and the code pasted on its
   standard input (or `ACME_DB_AGENT_CODE=…` in its environment) `[--db-agent
   HOST:PORT] [--db-agent-db-host HOST]` - never the code on the command line,
   where every account sees it in `ps`. Or *Join* on the page (`POST
   /api/db-agent {action: join, code}`: the code in the body). The node connects,
   **pins the fingerprint of the code** (nobody in between can pose as the
   agent), fetches root's public key and checks it is the code's (`k`), sends the
   secret **sealed to it** and gets a **token** for this join (a second begin
   with the same code - somebody else who saw it - gets its own token and cannot
   finish this one), issues its own client certificate (clientAuth, CN
   `acme-NODE`) from acme's authority, makes a signing key, and sends them with
   the authorities that issued the certificate and the token - the key, the secret
   and the certificate's fingerprint sealed to root's key, so the agent's network
   side never sees them. The agent checks the
   certificate against those authorities, keeps its fingerprint, the key and the
   authorities **for this node only**, and starts its network side again.
3. The node keeps `/var/lib/acme/db-agent/`: `agent.json` (`db_admin:
   "agent:HOST:PORT"`, pins, engine, ports, the other acme node's address in
   layout B), `client.crt/key`, `client-ca.pem` (the authorities it gave the
   agent), `sign.key` (0600, the daemon's - not sealed with `secrets.key`, which a
   join or a backup put back replaces). It then asks the agent to open its
   firewall (the database's port and the agent's) to this node's address - the one
   it reaches the database server from (1.0.115: the source address of the route
   to it, not the one it reaches the outside with; a node with another network for
   its database is let in by that one - the same for `dbmake` and `pg_prepare`).
4. Several nodes may join one agent (a code each): each is let in by its own
   certificate's fingerprint, the agent's certificate is the same for all. Each node
   keeps its own authorities (renewed by itself, never another's) - but **one database
   server serves one cluster's authority** (1.0.115): the server's certificate (`pgtls`
   `server`, MariaDB's `my_tls`) and `/etc/pki/acme/ha-ca.pem` are put in by one node, and
   the agent remembers whose (and its authorities). Which authority a node is of is the one
   that **signed the client certificate it asks with** (checked with that authority's key,
   1.0.115) - never the list of authorities it gave at its join or with `trust`, where a
   node may put any authority's certificate (it was taken: a node listing the owner's
   authority beside its own replaced the certificate). A node of the same authority (the other
   node of that cluster, the same node renewing) may replace it; a node of another authority
   (another cluster) is refused, the refusal says whose it is (*the certificate of this
   database server is acme1's, from another authority …*) - two clusters do not share one
   database server's TLS, each would break the other's verify-full. Once the node that put it
   in is gone (left, forgotten there, or not heard from for 30 days), another may. With no
   owner recorded (the first certificate put in - also the first one after the upgrade from
   an agent before 1.0.115, which kept none) the node putting it in becomes its owner: the
   agent cannot tell then whether another live node's certificate is in use (take care with
   two clusters on one server at that upgrade - one database server serves one cluster).
   **A cluster's authority rolled** (a new one made, the old one trusted beside it until it
   ends): each node tells its agent its cluster's authorities again (`trust`, no new
   certificate) whenever they change - the daemon looks every 30 s, and `--ha-join` does it at
   its end -, so the other node's certificate renewed under the new authority is still the
   owner's cluster's. A node let in before with a certificate of the owner's authority
   (`issuers_seen`) is of the owner's cluster too. What a node lists for itself counts only for
   itself: a node listing another cluster's authority still cannot take its certificate over.
   A name is one authority's too (1.0.115): a join under the name of a node of another
   authority heard from in the last 30 days is refused (*a node named acme1 of another
   authority … is joined here already*) - it would have taken that node's place; the node
   itself joining again (an authority it was let in with, or one it listed) may. A node that
   joined its agent standalone and then a cluster (`--ha-join`, layout B) tells the agent the
   cluster's authority at the end of the join; one whose agent was not told (it did not
   answer) and joins again from the same address is told *its authority changed* and how to
   go on: `acme_db_agent.py --forget NODE` on the database server, then join again.
5. **One agent a node.** A node joined to an agent that joins another one (another
   `HOST:PORT`) lets the first go: its `agent.json` is put aside as
   `agent.json.replaced` and nothing of it (pins, `peer_node`, certificate ends) is taken
   over. When the node's database is still on the first one's server, the join says so
   (*NOTE: this node's database is still on …*): until the database is moved onto the new
   server nothing of the old one is looked after (its certificate is not renewed). Refused
   while the node is one of a cluster whose database is on the first agent's server.

With firewalld on the database server and no `--acme-node` given to `install.sh`,
the join itself cannot reach the agent's port: `install.sh` prints the exact lines,
for each node, on the database server:

```
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="ACME-NODE-ADDRESS" port port="9443" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="ACME-NODE-ADDRESS" port port="5432" protocol="tcp" accept'
firewall-cmd --reload
```

(the database's port is opened by the agent too, once the node joined - and again
by `dbmake` when the node makes its database there).

`acme --db-agent-forget --yes` (or *Forget the agent…* on the card) goes back to `db_admin`
local (the file is kept as `agent.json.forgotten`) and tells the agent this node leaves it
(`leave`, 1.0.115 - it takes only the node asking off its list; one that does not answer keeps
it until `acme_db_agent.py --forget NODE` there). **Refused in layout B** while this node's
database is on the agent's server (1.0.115, as joining another agent is: *this node is one of
a cluster and its database is on …: the agent is not let go - take the cluster apart first*),
and the card has no *Forget* then: forgotten, the other node's address fell back to `ha_peer`
- the other database server - for the VIP address, the firewall and the clocks. Only layout B
is refused: two nodes of a cluster on one database server (a shared pair) may forget it.
`install.sh --uninstall` on a node **keeps the join** (1.0.115), as it keeps
`/var/lib/acme`: acme installed again goes on with the agent. A node going away for good
leaves first: `acme --db-agent-leave --yes` (as Forget, refused in layout B - take the cluster
apart first), or `acme_db_agent.py --forget NODE` on the server takes a node's certificate
away.

### The operations (the closed set)

| Verb | Arguments (checked) | What it does |
|---|---|---|
| `status` | - | facts: host, CPUs, RAM, load, uptime; engine, version, running, ssl, wal_level, connections, the data folder's disk; the agent's version, certificate end, the nodes it knows |
| `load` | `db` (a plain name) | the meter: `cpu`, `mem_used`, `mem_total`, `swap_used`, `disk_rd`, `disk_wr`, `net_rx`, `net_tx` (B/s), `load`, `cores` - as a node's `server_load()` - and `db: {running, version, started, connections, repl_behind, size, disk}` |
| `pgtls` | the root helper's pgtls request (`do` ∈ server, hba, peer, hba_off, server_off, ha_open; db, user, peer(s), cert, key, trust) - `acme_web.pgtls_checked`, the port is the agent's own | the root helper's own functions |
| `pg_prepare` | db, user (plain, not the server's own), password (8-128 printable, no `'` `\`), peers (≤ 8 plain addresses) | wal_level logical, listen `*`, max_slot_wal_keep_size 16GB, the role (REPLICATION, pg_create_subscription; refused if it is a superuser/createrole), the database (UTF-8), pg_hba lines in front - the file kept beside, put back when PostgreSQL does not read it; says whether PostgreSQL has to start again (`pg_restart_needed`) |
| `pg_allow` | db, user, peers | pg_hba lines only |
| `my_allow` | db, user, password, peers | MariaDB: the account at those addresses, every right on that database (a node's new address) |
| `pg_publication` | db | `acme_pub` FOR ALL TABLES (insert, update, delete) |
| `pg_restart`, `pg_reload` | - | systemd unit / pg_ctlcluster (the root helper's), or `pg_restart_cmd` from the agent's configuration; waited for |
| `pglog` | - | the root helper's pglog |
| `dbmake` | name, user, password, peers | the root helper's dbmake; pg_hba (or MariaDB `'user'@'peer'`) for the nodes |
| `fw_allow` | peers, `agent` | firewalld rich rules for the database port (and the agent's) from those addresses |
| `my_tls` | cert, key, trust | MariaDB: files (mysql's to read), `zz-acme-tls.cnf`, restart the first time, `FLUSH SSL` after; checked `@@have_ssl`, put back otherwise |
| `my_restart` | - | the mariadb service or `my_restart_cmd` |
| `agent_renew` | - | the agent's next certificate made now (a new key) and announced; put in use once every node took it in |
| `trust` | ca, client_cert_new | the authorities of **the asking node's** certificates replaced - never another node's - and its next client certificate announced; refused when empty, or when the certificate it asks with now would not pass with them |
| `clients` | drop (only the asking node itself) | the nodes it knows (`stale`: not heard from for 30 days); a node takes only itself away (1.0.115 - any node took any other away), another is taken away on the server (`acme_db_agent.py --forget`) |
| `leave` | - | the asking node taken off the list (forgotten, moved off, joined another agent, uninstalled) |

Anything else: *"… is not something this agent does"*. PostgreSQL verbs on a
MariaDB agent and the other way round are refused.

## How acme decides: `db_admin`

Per node, in `/var/lib/acme/db-agent/agent.json` - never in `config.json` nor the
database, so nothing of it moves with a backup or to the other node:

- `local` (no file - every installation until now): the root helper, unchanged.
- `agent:HOST:PORT` **and this node's database is the one on the agent's server**
  (`db_agent_here()`: config.json's engine, address and port are the agent's database
  server's - or an `--ha-join` is putting it there): each place in the table above asks
  the agent instead. A node that joined an agent but still has its database on this
  machine (not moved yet) or on a server no agent looks after is looked after exactly as
  without an agent:
  `pgtls_send` → `db_agent_pgtls_send` (its answer written to the same
  `pgtls.json`, so the link's steps, Database → TLS and a new address read it as
  ever), `pg_prepare_local`, `pg_publication`, `pg_restart_local`,
  `pg_local_running`, `pg_install_local`, `firewall_peer`, `db_make_here`,
  `repl_errors`' log, `hatls_own_cert`, `hatls_names` (+ the DB server's
  address), `dbtls_kind` (a PostgreSQL with an agent counts as *local* or
  *replicated*), tuning's facts and restart.

## Moving between engines (1.0.113)

The move (*Settings → The database → Move to another database…*, `acme --db-move ENGINE`)
works between every pair - SQLite, PostgreSQL and MariaDB, on this machine, on a server no
agent looks after, or on an agent's server (tested in `test/test_external_db.py`,
`EngineMoves`). What the agents add, and the rule behind it: **a node has one database agent,
and it is the agent of the server its database is on.**

| From → to | What to do | `db_admin` afterwards |
|---|---|---|
| this machine / SQLite → an agent's server | join its agent (*Connect a database server…*), then move (*Move the database onto it…*, or `acme --db-move ENGINE --db-host H --db-port P --db-make`) | `agent:` that agent |
| agent A's server → agent B's server (PostgreSQL → MariaDB and back, or two PostgreSQLs) | join agent B first - it takes A's place (`agent.json.replaced`, said); then move | `agent:` B |
| an agent's server → this machine's PostgreSQL / MariaDB, SQLite, or a server no agent looks after | move | `local` - the agent let go by the move |
| a node of a cluster (shared or replicated, with agents or not) | refused, as for a local replicated pair: take the cluster apart first | unchanged |

- **"Make it for me"** - the database and its account made before the move: on this
  machine by the root helper, on the server of this node's agent by the agent (`dbmake`:
  the database, the account with its password - made up when none is given -, `pg_hba.conf`
  or `'user'@'node'` for this node, the firewall). The wizard offers *Make the database and
  the account for me* for both (step 2); the command line has `--db-make` (the password from
  `ACME_DB_PASSWORD`, else made up and written to `config.json` at the end; the account in use
  on the same server keeps its own). Elsewhere it is refused and the SQL to run there is shown
  (the password never printed). A target that is not the agent's server is said
  (*note: … is not the server of this node's database agent*).
- **The encryption is the server's own.** `db_tls` / `db_tls_ca` are not carried to another
  database server (another engine, address or port) by `acme --db-move` - verify-full against
  the old server's authority asked of a MariaDB without TLS yet, or of a PostgreSQL whose
  certificate another authority signed, was wrong either way. Off unless `--db-tls-mode` (and
  `--ca`) are given; the wizard asks it in step 2. After a move onto an agent's server acme says
  the next step: *Database → Encryption* (`--db-tls-apply server`, then `connect`), for MariaDB
  first `acme --db-agent-mariadb-tls`. A MariaDB connection asked for TLS (`require`,
  `verify-ca`, `verify-full`) by a server that does not offer it is refused, never used in the
  clear (PyMySQL went on without TLS).
- **What described the old server is left behind**: the moved database does not get the old
  server's rows - `dbtls:server:NODE` (its certificate from acme's authority, renewed and
  alerted on), `dbagent:node:NODE`, `load:db:NODE`. The new server's are written as they come.
  The database left behind is not touched.
- **Off the agent's server**: once `config.json` is switched the move lets the agent go
  (`agent.json` → `agent.json.forgotten`, as `acme --db-agent-forget`), says so (the switch
  step, `acme --db-move`'s last line, the wizard's last step) and writes an event. From then
  on nothing is asked of the agent (no look every 30 s, no renewal, no alert), the card
  *Database server* and the dots, rows and meter of database servers are gone - the pages are
  as for a database on this machine. The agent is told the node leaves it (`leave`, 1.0.115);
  one that does not answer keeps this node's certificate until `acme_db_agent.py --forget
  NODE` on its server (the move says which). Moving
  back means joining it again (a new code); the wizard's *Move back…* says so.
- **High availability**: `--db-move`, the wizard and its *make it for me* are refused on a node
  of a cluster as before; with each node's database on a server of its own the refusal says
  so (*each node's database on a server of its own …: moving it - to another engine, another
  server or back onto this machine - would break the replication*), with the way out (switch
  the replication off, `acme --ha-standalone`, then move, then build the cluster again).

## Layout B step by step (replicated, each node its own server)

1. Two database servers: `install.sh --db-server postgres --acme-node ACME1
   --acme-node ACME2` on each (PostgreSQL 16, wal_level logical, the agent).
2. acme1: `acme --db-agent-join -` (the code of db1 pasted), then move its database onto db1
   (*Settings → The database → Move*, or `acme --db-move postgres --db-host DB1`).
3. acme1: `acme --ha-setup --ha-peer DB2 --ha-peer-node ACME2 --node-name acme1`.
   `--ha-peer` is the **other database server**, `--ha-peer-node` the other acme
   node; `ha_address` is db1 by default. The agent of db1 prepares it (pg_hba for
   db2, acme2 and acme1), restarts it, publishes the tables, opens its firewall.
4. acme2: `acme --db-agent-join -` (the code of db2), then `acme --ha-join BUNDLE
   --node-name acme2`: db2 prepared by its agent, every row copied from db1, both
   subscriptions; `config.json` gets `db_host` = db2.
5. *High availability → Repair* (or `acme --ha-tls-repair`): each node issues its
   server's certificate, its agent puts it in; verify-full; `hostssl` for the other
   server and the other node. The authorities are written on each server
   (`/etc/pki/acme/ha-ca.pem`, read by its replication workers) and on each node
   (the daemon's own checks).
6. VIP (keepalived), the leader, split handling, clocks: unchanged - they are the
   nodes' own. In this layout `ha_peer` is the other **database server**: what is the
   nodes' own takes the other acme node (`--ha-peer-node`, kept as `peer_node` in
   agent.json) - the clocks' peers (chrony), the addresses the firewall always lets
   in, the VIP address's other node, the split's look at the other machine. The
   database server only for the database (subscriptions, pg_hba, the link's TLS).
   And `ha_address` is **this node's database server** here: what means *this node*
   takes the node's own address (1.0.115 - keepalived was told db1 as its own
   `unicast_src_ip`, and the other node's firewall let db1 in instead of acme1):
   `node_address` in agent.json, kept at `--ha-setup` / `--ha-join` (the address this
   node reaches the other node from; for a cluster made before 1.0.115, worked out the
   same way each time). The network job moving this node to another address updates it
   (1.0.115), and one this machine no longer has is not used: the address toward the other
   node now (the route's source) is - keepalived's own address, the address the other node's
   firewall always lets in, the bundle's `node`. The clocks: the other database
   server's clock is another machine's - measured, it is said as *the database server
   of acme2*, never taken for the other node's (the heartbeats are not corrected by it).

Renewals (45 days before), the authority's roll, the ten-minute check of the
link, a rebuild (`acme --ha-resync`, *Rebuild this node*), pause/resume, stop,
readdress: as today, the root parts through the agents.

A node's **own** address changed (*Settings → Network*, the network job): before the
network is switched, its agent lets the new address into the database (`pg_allow`, or
`my_allow` for MariaDB) and through the firewall (`fw_allow`); the job stops - nothing of
the network changed - when the agent cannot. The other node is told (`dbagent:addr:NODE` in
the replicated database): its agent lets the new address into its server too, and its
`peer_node` follows. The old address's lines stay (the network may still go back).
With `db_guard` on (1.0.135) that row is signed: one written into the database past acme is
not acted on (see [High security](high-security.md)).

## Watching

- Every node with an agent looks at it every 30 s (`dbagent:node:NODE` in `meta`,
  replicated): answering, facts, the agent's version and certificate. An event
  when it stops / starts answering; an **alert** (`dbagent:NODE`, bad) after 90 s
  away, `dbserver:NODE` when the agent answers but the database does not, a warn
  within 14 days of the agent's certificate's end only when the agent did not do what
  it does by itself (the next one made 60 days before, switched to 7 days before the
  end at the latest: no next one announced, or the switch not done),
  `dbagent:client:NODE` 14 days before the node's own client certificate ends
  (renewed by itself 45 days before; ended, the agent no longer lets it in), and
  `dbagent:version:NODE` when the agent's program is not the one this acme ships.
- Prometheus: `acme_db_agent_up{node,host}`, `acme_db_server_up{node}`.
- `acme --status` has a line; `acme --db-agent-status [--json]`.
- The meter: `/api/load` → `dbservers: [...]`.

## The pages (data for them)

- `GET /api/db-agent` (readonly): `{db_admin, node, host, port, db_host, engine,
  joined_at, joined_by, peer_node, forget_refused, agent_cert_end, client_cert_end,
  state: {ok, down_since, fails, at}, servers: [...], applies: {...}}` - `forget_refused`
  (1.0.115): why the agent may not be let go now (layout B), '' when it may.
- `POST /api/db-agent` (fulladmin): `{action: join, code, address?, db_host?}`,
  `look`, `renew`, `restart`, `mariadb_tls`, `forget` (409 with `forget_refused`'s words;
  answers `left`: whether the agent took the node off its list).
- `servers` / `dbservers` entries, shape of a node's dot with `kind: "db"`:
  `{kind: "db", name: "db:NODE", node, me, alive, stale, ok, said, down_since, at,
  host, port, db_host, engine, db_admin, agent_cert_end, client_cert_end,
  facts: {host, fqdn, cpus, ram, avail, load, uptime, virtual, engine, running,
  version, ssl, wal_level, started, connections, disk: {total, free}},
  agent: {version, code, port, engine, pg_port, cert_end, cert_fp, cert_next_fp, busy,
  stale_days, force_days, clients: [{name, addr, at, seen, stale, cert_end, next_taken}],
  uid}, version_skew: null | {agent, acme, how}}`.
- Added only with an agent: `GET /api/ha` → `db_admin`, `dbservers`; `GET
  /api/dbtls` → `db_admin`, `dbservers`; `GET /api/load` → `dbservers` (each
  `{kind: "db", name, node, host, age, cpu, mem_used, mem_total, swap_used,
  disk_rd, disk_wr, net_rx, net_tx, load, cores, over_s, server, db: {...}}`; `server` is the
  database server's own short host name, from its agent's facts).
- `GET /api/db-agent`, with *Show this machine's database as a database server* on
  (`db_local_card`, 1.0.115) and no agent on this node, also says `local: [...]` - one entry for
  each node of the cluster whose database is PostgreSQL or MariaDB on its own machine:
  `{kind: "db", name: "db:NODE", node, me, ok, stale, at, host, port, engine, cert_end, cert_by:
  "dbtls" | "link" | "", facts: {host, engine, cpus, ram, avail, virtual, load, uptime, running,
  version, ssl, wal_level, started, connections, disk: {total, free}, said}, restart?: {may,
  unit, waiting}}` (`restart` only on this node's own, only while settings wait for a restart).
  Each node writes its own into `meta` (`dblocal:node:NODE`, every 30 s, `ACME_DBLOCAL_EVERY`)
  from what it reads anyway - its own connection as acme's account, `/proc`, the row of the
  certificate acme gave its PostgreSQL - and the other node reads it there, as every node's rows
  travel (replicated, or the one database of a shared pair). No password or secret is in it.
  Off, the key is not there and nothing is read or written for it; `POST look` then looks at
  this node's own (with an agent, as before).
- `GET /api/db-agent` also says, for the card and its wizard (1.0.113): `where`
  (`{kind: agent | here | file | unmanaged, engine, host, port, name}` - this node's database
  on the agent's server, still on this machine, the file, or on a server no agent looks
  after), `ha_mode`, and `addresses` (this node's own, for `install.sh --acme-node`).

Which cards draw the database servers beside the nodes (`applies`):

| Card | Database servers? |
|---|---|
| The database → TLS (certificate, renewal) | yes |
| High availability → the link, replication, errors (log) | yes |
| The database → the server's own settings, restart | yes |
| Firewall - the database's port | yes (the agent's `fw_allow`) |
| The meter in the header | yes |
| nginx / web TLS, VIP, sshd, sign-in, SELinux, NTP, password policy, logs, OS updates, db_guard | no - the acme nodes' own (the DB server's OS is its administrator's) |

### What the pages show (1.0.113)

Nothing of this is drawn without an agent: Settings → The database, High availability, the
firewall and the header are exactly as before for a database on this machine (a page test,
`test/extdb_page.js`, compares their DOM before and after every new piece is asked to draw) -
unless *Show this machine's database as a database server* is switched on (1.0.115, below), and
then only the card of Settings → The database.

- **Settings → The database → Database server** (a card above *Encryption to the database
  server*), shown with an agent, or for a database on a server elsewhere that no agent looks
  after (never for a shared pair). It says where this node's database is - on the agent's
  server, still on this machine (joined, not moved yet: *Move it onto the database server…*
  opens the move wizard filled in with the server), or on another server - and draws a tile
  for each database server the cluster knows: its name, whose it is, the engine and its
  version, the address and the agent's (`host:port`, its version), running and for how long,
  TLS, the connections, the data's disk and the RAM as bars, the processors and the load, up
  for, the agent's certificate and this node's client certificate (red under 14 days), when it
  was last heard from, and what the agent said when it does not answer. A state pill (answers
  · 3 s ago / its agent does not answer / its database does not run / not heard from lately).
  Actions (full administrator): *Look now*, *Renew the certificates*, *Restart the
  database…* (asked first), for MariaDB *Turn TLS on* / *Give MariaDB a new certificate*,
  *Forget the agent…* (danger, asked first).
- **This machine's database as a database server** (1.0.115, opt-in: Settings → The database →
  *Show this machine's database as a database server*, off by default). PostgreSQL or MariaDB on
  the acme node's own machine (localhost, 127.0.0.1, ::1 or a socket; not SQLite, not with an
  agent) gets the same card, *Database server*, above *Encryption to the database server*: a
  tile for each node's own server (each node its own PostgreSQL: acme1 and acme2; a shared pair:
  its one server, seen from both nodes) with the same look and what is known without an agent -
  the engine and its version, the address (`host:port`), running and for how long, TLS and the
  end of the certificate acme gave it, the connections, the data's disk and the RAM as bars, the
  processors and the load, up for, when last heard from; the state pill (answers · 3 s ago / its
  database does not run / not heard from lately). No agent's rows (its address, version and
  certificate, the node's client certificate), no join code, no *Forget*, no pills on other
  cards, no rows in the header's meter or on High availability, no alerts. Actions (full
  administrator), only those acme has for a database here: *Look now*; *Renew the certificate*
  where acme gave PostgreSQL its certificate - the link's between the databases (the same steps as
  High availability's *Renew the certificates*, asked first) or else Encryption to the database
  server's (the same step as that card's *Renew the certificate*); *Restart the database…* only while settings of the
  server's own wait for a restart and install.sh let acme restart it (the same question and
  restart as *The server's own settings*). Off: the pane is exactly as before (the page tests
  `test/extdb_page.js` and `test/localdb_page.js` compare / check it).
- **Connect a database server…** - from that card, or from the move wizard's first step for a
  database on this machine: three steps in one popup that keeps its size. 1. what to run on
  the database server, as root, with copy buttons and this node's own addresses filled in
  (`./install.sh --db-server postgres|mariadb --acme-node ADDRESS`, `--db-agent` for a server
  installed already, `acme_db_agent.py --new-code`); 2. the join code, read as it is pasted
  (`ADBA1.`, the agent's address and engine and the first characters of the certificate's
  fingerprint said, never the secret), the agent's address if this node reaches it otherwise,
  and *Use it as this node's database* with the database's address (`db_host`); 3. the join,
  step by step, and the server's tile - with *Move the database onto it…* when this node's
  database is not there yet.
- **The dots of the database servers** - a violet-edged pill on the heading of each card in
  the table above: a dot and a name per database server (its own short host name where that
  tells it from the other, else `db · NODE`), green / amber (not heard from lately) / red (its
  agent does not answer, or its database does not run); pointed at, each server's address,
  state, what its agent said and when it was heard from, and what of the card is done on it
  (`applies`). On Database → TLS each database server also has a row in the list (TLS on or
  not, its agent answering); on the firewall a tile each (*its port opened by its agent to the
  nodes*). The cards outside the table get none, and the cluster's own pill (each node's
  settings in effect) is unchanged.
- **High availability**: under the nodes, *The database servers* - each server's dot and name,
  its node, address, engine and version, the direction it sends in (`db1 → db2`) and its state
  (this node's slot: taken / waiting / lost; the other's: this node's subscription running /
  paused), what waits to go over, the link's TLS (verify-full, its certificate's end, failed),
  and its agent (answers · when, or what it said). The Replication card carries the pill. In
  *Making it two, step by step*, with an agent on PostgreSQL: *Each node's database on a
  server of its own* - the other database server, the other acme node and the names typed in,
  the commands filled in from them (`acme --ha-setup --ha-peer DB2 --ha-peer-node ACME2
  --node-name acme1`, `install.sh --db-server postgres --acme-node ...` on the other server,
  `acme --db-agent-join` and `acme --ha-join` on the second node).
- **The meter in the header**: a row per database server after the nodes', in the look chosen
  (graphs, pills, line, rings), named with a small cylinder; pointed at, its panel says the
  database - version, running for how long, connections, what waits to go over to the other
  server, the size of acme's database, the data's disk, TLS - and the machine in numbers, with
  the graph of what was pointed at. A server whose agent does not answer is dimmed and said
  so. No rows without `dbservers`; this node's row is named as soon as there are (the same
  reading, so nothing moves afterwards). Under 700 px the meter is not shown, as before.
- **Alerts** (Alerts and reports): `dbagent:NODE` *The database agent of NODE does not answer*
  (since when, what was said, that acme can neither renew nor change the server meanwhile and
  where to look), `dbserver:NODE` *The database server of NODE is down*, `dbagent:cert:NODE`
  *The certificate of the database agent of NODE ends soon* (and where to renew it) - in the
  mail's language (the alert hook takes `lang`), translated on the pages.
- The MariaDB's certificate given by acme is renewed by the node's agent thread 45 days
  before it ends, as a PostgreSQL's is.

## Upgrading the agent

The agent is not upgraded with acme: after an upgrade of acme, run the new version's
`./install.sh --db-agent` on each database server (its configuration, its keys and the nodes
it knows are kept; the service starts again; **no join code** is printed - only a new install
or `--new-code` prints one, 1.0.115: a code is a key to the agent, and the nodes stay joined).

What is compared (1.0.115) is the agent's **program**, not acme's release number: the agent
says `code`, the SHA-256 of its `acme_db_agent.py`, `acme_pg_ops.py` and `acme_web.py` (a
SHA-256 of each, in that order, hashed - the root helper's functions it runs are its program
too, 1.0.115; install.sh copies the three unchanged), and each node hashes the three files it
ships (`deploy/`) the same way. The same
program says nothing whatever the numbers - an acme release that did not change the agent
asks for no upgrade, and nothing is bumped by hand at a release (the agent's version is only
said: the release `install.sh` wrote beside it, `/usr/local/lib/acme-db-agent/release`, or
acme's own tree around it). Another program is said by what to do, on the database server's
card, in `acme --db-agent-status` and `acme --status`, and as an alert
(`dbagent:version:NODE`, `version_skew: {agent, acme, how}`):

- `older` - the agent came with an older acme: upgrade it (`./install.sh --db-agent`).
- `newer` - it came with a newer acme than this node's: upgrade acme on this node (or put the
  agent of this version back).
- `other` - the same release, another program (changed there by hand, another build): put it
  back with `./install.sh --db-agent`.

An agent before 1.0.115 says no `code`: its version is compared (older is said).

## Installing a database server

`install.sh` on the database server (never on the acme node; nothing of acme is
installed), `--dry-run` and running it again are safe:

```
./install.sh --db-server postgres --acme-node 192.0.2.11 --acme-node 192.0.2.12
./install.sh --db-server mariadb  --acme-node 192.0.2.11
./install.sh --db-agent                       # the agent alone, for a server you installed
./install.sh --db-agent --new-code            # ...an upgrade, and a join code all the same
./install.sh --db-agent --uninstall           # the agent away; the database stays
   [--db-agent-port 9443] [--db-name acme] [--db-user acme] [--db-password-file FILE]
```

The account's password: made up and shown once when the account is new, or the first line of
`--db-password-file FILE` (`--db-password PASS` works too, but a command line is seen by every
account on the machine - install.sh warns). The statements holding it are fed to `psql` /
`mariadb` on their standard input, never as arguments, PostgreSQL told not to log them even
when they fail (`log_min_error_statement = panic`), and `--dry-run` does not print it.
`pg_hba.conf` - in a folder of the postgres account - is written by the agent's own link-safe
code (`acme_pg_ops.hba_add`): written beside it and renamed over it, never through a link.

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
  fingerprint, so the first connection is pinned too. It is read from standard
  input (or `ACME_DB_AGENT_CODE`), never put on a command line. Wrong codes count
  per address (and per code only with its id right); a finish needs the token of
  its own begin.
- The agent is known by the fingerprint of the certificate it made itself - the
  same for every node; renewed with an overlap announced in signed answers, so no
  node is ever locked out by another's join or by a renewal.
- A node is let in by its client certificate's fingerprint (each node's own list
  entry); the authorities stored with it only let TLS ask for it, and a node can
  change only its own (`trust` refuses an empty set and one its current
  certificate would not pass).
- A stolen client certificate is not enough without the signing key, and a
  captured request cannot be replayed (nonce, ±120 s, the nonces kept across a
  restart).
- The root side never trusts the network side: it gets the request as it came
  and the client's certificate, and works out everything itself - the
  fingerprint, the signature, the time, the nonce - and signs the answer. The
  network side is started afresh as a program of its own and never holds a
  signing key - **not even at enrollment** (1.0.115; before, the finish carried it
  in clear through that side, which could keep it and ask root as that node): the
  code's secret and the node's signing key are sealed to root's own key, pinned by
  the join code, so a network side taken over can neither sign as a node nor finish
  a join of its own with a code it saw. Failures from an address block it for a
  while.
- A node of one authority cannot replace (or take out) the database server's
  certificate another authority's node put in (1.0.115) - the authority is the one that
  signed its client certificate, not one it lists -, cannot join under the name of
  another authority's node, and takes only itself off the agent's list.
- An operation of one node no longer holds the others' looks (1.0.115): a long one
  (a restart, a certificate) does not make every other node see the agent as dead.
- systemd hardening (`acme-db-agent.service`): `ProtectSystem=strict` - the whole
  file system read-only but `ReadWritePaths`: the agent's own folders,
  `/etc/pki/acme` (made by install.sh), PostgreSQL's (`/var/lib/pgsql`,
  `/var/lib/postgresql`, `/etc/postgresql`, `/var/log/postgresql`, its sockets) and
  MariaDB's configuration (`/etc/my.cnf.d`, `/etc/mysql`); firewalld and systemd
  are asked over D-Bus. A folder that is missing when the agent starts (another
  layout) is left out: a write there fails until it is added (`systemctl edit
  acme-db-agent`, `ReadWritePaths=`). `ProtectHome`, `PrivateTmp`,
  `PrivateDevices`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  AF_NETLINK`, a `CapabilityBoundingSet` of what root needs (SETUID, SETGID, CHOWN,
  FOWNER, DAC_OVERRIDE, DAC_READ_SEARCH, KILL, AUDIT_WRITE, SYS_RESOURCE,
  NET_BIND_SERVICE). Not `NoNewPrivileges` for root (runuser, systemctl); the
  network side sets it on itself.
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
