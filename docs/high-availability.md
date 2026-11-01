# Two servers, both answering (high availability, active/active)

Two acme servers can run side by side, both answering. A load balancer in front
of them can send any request to either one, round robin and without sticky
sessions. There are two ways to lay the database out:

- **Replicated (from 1.0.14, the usual way)** - each node has **its own
  PostgreSQL** (16 or later) and the two replicate to each other both ways.
  Either node goes on alone while the other is down, and catches up by itself
  when it is back. A node that was away too long, or was reinstalled, is
  rebuilt from the live one with one command.
- **Shared (1.0.13)** - both nodes open **one PostgreSQL**: on node 1, on its
  own server, or a PostgreSQL cluster's address.

```
              ┌─────────────── load balancer ───────────────┐
 HTTPS :443   │  round robin, no stickiness, GET /healthz   │
              └──────────────┬──────────────────┬───────────┘
                             │                  │
                       ┌─────┴─────┐      ┌─────┴─────┐
  CAs, targets ◄────── │  node 1   │      │  node 2   │  (the one that leads
  (the leader only)    │ PostgreSQL│ ◄──► │ PostgreSQL│   renews and deploys)
                       └───────────┘      └───────────┘
                     logical replication, both ways (replicated)
```

## Why either node can answer any request

- **Settings, directories, certificates, issuers, challenges, targets and
  deployments** are kept in the database. A change made on one node is picked up by the other within five
  seconds.
- **A sign-in to the pages** is a row in the database. So is the "Edit the
  columns" switch that belongs to it. The next page can therefore come from
  the other node.
- **The renewals and deployments** are done by one node at a time, the
  leader - see [Who renews and deploys](#who-renews-and-deploys). A job's
  steps are in the database, so either node's pages show it.
- **acme's DNS server** answers from the database on both nodes: a DNS-01
  record put in by the leader is answered by both (each reads the records
  again at most every `dns_cache` seconds). Name both nodes in the NS
  records that delegate `_acme-challenge` (or the zone) to acme.
- **A code of the administration's second step is used up** by a single
  conditional `UPDATE`. If both nodes are asked for the same code at the same
  moment, only one of them accepts it.
- **The nightly dump** is made by one node only: whichever claims the day
  first.
- **A job's progress** (a move, an erase, giving the disk back) is kept in the
  database, so its bar keeps moving whichever node the page asks.
- **The key that seals the secrets** (the private keys, the passwords) is the
  same file on both nodes. It is
  carried to the second node once, inside a bundle locked with a passphrase.

Each node writes a heartbeat every fifteen seconds. *Settings → High
availability* and `acme --ha-status` list the nodes and when each was last heard
from. In a cluster, the page header shows which node answered it.

## Building it - replicated (each node its own PostgreSQL)

1. **On the first node, move the database to PostgreSQL** if it is not there
   yet: *Settings → The database → Move to another database…* (or
   `acme --db-move postgres`). It has to be PostgreSQL 16 or later on this
   machine.
2. **On the first node**, as root:

   ```
   acme --ha-setup --ha-peer 192.0.2.12 --node-name acme1
   ```

   This:
   - sets `wal_level = logical`, `listen_addresses = '*'` and
     `max_slot_wal_keep_size = 16GB`, and restarts PostgreSQL after asking,
   - adds a `pg_hba.conf` line for the second node (this database, this
     account, `scram-sha-256`) and opens TCP 5432 in firewalld for that one
     address,
   - publishes every table (`acme_pub`) and gives the database account the
     right to replicate,
   - numbers this node's new rows odd (the second node's will be even, so the
     two never hand out the same id),
   - writes `/root/acme-join-acme1.json` and prints the passphrase, once.
3. **On the second node**, as root:

   ```
   ./install.sh --with-db postgres --yes
   scp root@acme1:/root/acme-join-acme1.json /root/
   acme --ha-join /root/acme-join-acme1.json --node-name acme2
   ```

   It installs PostgreSQL there if it is missing, prepares it the same way,
   copies every row from the first node, and sets both directions up. The
   bundle also carries the key that opens the sealed secrets. The pages of a fresh
   node cannot do this step, because it needs root.
4. **On both nodes**, give the load balancer's address (see below):
   `acme --trusted-proxy 192.0.2.10/32`.

`acme --ha-status` (or *Settings → High availability*) then shows both nodes and
both directions of the replication.

## Watching it and stepping in

*Settings → High availability → Replication* and `acme --ha-status` show, for
each direction (coming in, going out): whether it runs, when the other side was
last heard from, how much is waiting to go over, and any errors.

| Pages                               | Command line                   | What it does |
|-------------------------------------|--------------------------------|--------------|
| *Pause it…*                         | `acme --ha-pause [both\|in\|out]` | Stops sending. Both nodes keep answering from their own database. What is written meanwhile waits (up to 16 GB) and goes over after resuming. |
| *Resume it*                         | `acme --ha-resume [both\|in\|out]`| Carries on from where it stopped. |
| *Read the tables again*             | -                              | Re-reads the list of published tables (after an upgrade that added one). |
| *Rebuild this node from the other…* | `acme --ha-resync`              | Makes a copy of this node's database, empties it, copies every row from the other node and sets both directions up afresh. |
| *Switch it off…*                    | `acme --ha-stop`                | Removes both subscriptions and their slots. Each node goes on alone; joining them again is a rebuild. |

The same guide, with the commands, is on the pages: *Settings → High
availability → Making it two, step by step* and *Looking after it from the
command line*.

## The link between the two databases: encrypted and checked (1.0.104)

Replication and every question one node asks the other's PostgreSQL go over
the network. *Settings → High availability → Replication* says how that link
is protected; when it is not encrypted and checked, the bar has a **Repair**
button. It works on a running cluster, without stopping anything:

1. The cluster gets an authority of its own (kept in the database, its key
   sealed with the cluster's key) and each node a certificate from it, for
   every name and address the other node reaches it by.
2. Each node's root helper puts the certificate into its PostgreSQL (data
   folder, `acme-ha.key` / `acme-ha.crt`), the authority into
   `/etc/pki/acme/ha-ca.pem`, switches `ssl` on with `ALTER SYSTEM` and reloads -
   PostgreSQL is not restarted. It then asks the server over TLS whether it
   answers with that certificate.
3. When both servers do, each node tries the other with `sslmode=verify-full`
   and only then moves its link over: `ha_tls` and `ha_tls_ca` in its
   config.json, and its subscription's connection (`ALTER SUBSCRIPTION ...
   CONNECTION`). Replication carries on from where it was.
4. When both links are on it, each PostgreSQL lets the other node in over TLS
   only: its line in pg_hba.conf goes from `host` to `hostssl` (the file as it
   was is kept beside it as `pg_hba.conf.acme-before-tls`).

The bar shows each node's step. A step that does not work stops there and
says why; nothing in use was changed by it - press *Repair again* once it is
put right. The daemon's own connection to its local PostgreSQL (127.0.0.1) is
left as it is; *Database → TLS* is about a database on another machine.

**It looks after itself.** Each node renews its certificate 45 days before it
ends (they last two years); the authority (twenty years) is replaced two years
before it ends, the old one trusted beside the new one until it runs out. Every
ten minutes, at start and after a copy of the database is put back, each node
checks that its PostgreSQL answers with a certificate of the cluster's
authority, that `/etc/pki/acme/ha-ca.pem` is there and that its link is on
verify-full, and goes through the steps again by itself when not - a node
reinstalled or joined again, a PostgreSQL set up anew, a certificate that ran
out while the machine was off. If a certificate did run out and replication
stopped, *Repair* still works: the other node is told over an encrypted but
unchecked connection, only to start the same steps.

Both nodes must run 1.0.104 or later, with `acme-web.path` (the root helper)
running - `install.sh --upgrade` puts it in.

**Switching it off.** *Switch TLS off…* in the green bar, or
`acme --ha-tls-off --yes`: the same steps the other way round - both
databases let the other node in without TLS too, both links go back to
*Database → TLS*, then the cluster's certificates leave both PostgreSQLs
(`ALTER SYSTEM RESET ssl, ssl_cert_file, ssl_key_file`, so `ssl` is again
what postgresql.conf says) and `/etc/pki/acme/ha-ca.pem` is removed. Nothing
is put back by itself until *Repair* is pressed again.

On the command line: `acme --ha-tls` shows how the link is protected, each
node's step and when its certificate ends; `acme --ha-tls-repair` does what
the button does (and starts stuck steps again). A node renamed or given a new
address: [renaming-and-readdressing.md](renaming-and-readdressing.md).

## Who renews and deploys

Both nodes answer the pages, the API and DNS, but only one renews and deploys
the certificates at a time: the **leader**. `acme --status` (the `renewed by`
line), `GET /api/certs/overview` (`leader`) and the Prometheus gauge
`acme_cert_leader` say which, and an event says when a node took over. A
renewal or a deployment asked by hand runs on the node it was asked of.

- **Shared** (one database): the lease row `certs:leader` in `meta`
  (`{node, until, vip}`) decides. The leader renews it every 30 s; it runs out
  90 s after it was last renewed. It is taken and kept with one conditional
  statement (`INSERT` of a key that is not there, `UPDATE … WHERE v = <what
  was read>`), so of two nodes asking at the same moment exactly one wins. The
  node holding the VIP address takes the lease over from one that does not;
  any node takes it once it ran out. If the leader dies, the other leads
  within about two minutes (90 s for the lease, up to 30 s for its next look).
- **Replicated** (a database each): a lease row cannot decide, because each
  node reads its own copy of it, and a copy may be late or - while replication
  is paused or broken - not come at all: both would see the other's lease run
  out and both would lead, renewing the same certificate twice (two orders at
  the CA, and the same version made on both). So each node decides by a rule
  both reach on their own:
  1. the node that holds the VIP address leads;
  2. else the first by name of the nodes alive. A node is alive while its
     heartbeat (every 15 s) is younger than 45 s - and a node that sorts first
     but looks stale here is asked in **its own** PostgreSQL before it is
     given up (alive there while its heartbeat is younger than 120 s). So a
     paused or broken replication does not make two leaders: the second node
     still reaches the first one's database and sees it alive.

  Only the leader writes the lease row, which then only says who leads. A
  node that should lead waits while the row names another node and has not
  run out (that one lets it go at its next look and removes the row), so the
  two do not overlap when the first node comes back. If the leader dies (its
  daemon or its machine), the other leads within three to four minutes: 120 s
  until its heartbeat is stale in its own database, its lease run out in the
  copy here, up to 30 s for the next look.
- **On either**, a node trusts its own lead for 60 s after it last renewed it,
  so one that cannot reach its database stops before another may start.

It needs **the clocks of both nodes to agree** (chrony/NTP): the lease's end
and the heartbeats are times written by one node and read by the other.

## When a node is lost

- **Down for a while** (a reboot, a network cut, hours or days): nothing to do.
  The live node keeps what the other one misses in its replication slot, up to
  16 GB of changes. When the node is back, it catches up by itself.
- **Down for longer than that**, its slot is dropped by PostgreSQL. The status
  then says *lost - rebuild the other node*. Rebuild the node that came back:
  `acme --ha-resync` on it (or the button on its pages).
- **Reinstalled from scratch**: install acme, then `acme --ha-join` with a new
  bundle made on the live node (`acme --ha-bundle FILE`, or *Make the bundle…*
  on its pages). It joins the same way the second node did the first time,
  and takes the same slot number.

**Rebuild the node that was away, never the one that kept working.** A
rebuild replaces everything on the node where it runs. What was written there
and never reached the other node survives only in the safety copy the rebuild
makes first.

## Building it - shared (both nodes open one PostgreSQL)

1. **Move the database to PostgreSQL first**, as in step 1 above.
2. **On the first node**, as root:

   ```
   acme --ha-setup --ha-shared --ha-peer 192.0.2.12 --node-name acme1
   ```

   If PostgreSQL runs on this machine, this command:
   - makes it listen on the network,
   - adds a `pg_hba.conf` line for the second node (this database, this
     account, `scram-sha-256`),
   - opens TCP 5432 in firewalld for that one address,
   - and restarts PostgreSQL after asking.

   It then writes `/root/acme-join-acme1.json` and prints the passphrase, once,
   and `"ha_mode": "shared"` into this node's config.json. For a PostgreSQL
   elsewhere, give its address as the second node will reach it:
   `--ha-db-host`.
3. **On the second node**: install acme, copy the bundle over and run
   `acme --ha-join /root/acme-join-acme1.json --node-name acme2`. Instead of the
   last command you can press *Join a cluster…* on the second node's own
   pages. It writes the database, `"ha_mode": "shared"` and the node's name
   into its config.json. From then on, sign in with the cluster's accounts.
4. **On both nodes**: `acme --trusted-proxy 192.0.2.10/32`.

## The load balancer

Two ways for the pages: the built-in **VIP address** (one address,
active/standby, keepalived - [tls-and-vip.md](tls-and-vip.md)), or a **load
balancer of your own** - HAProxy, nginx, Apache, F5, NetScaler, LVS, with
health checks that really look at each node: [load-balancers.md](load-balancers.md).
Step-by-step procedures for every situation (a node down, lost, rebuilt,
leaving the cluster): [operations.md](operations.md).

- **HTTPS**: round robin to both nodes on 443. No stickiness is needed. For the
  health check use `GET /healthz`: it answers `200 ok NODE` while the node and
  its database work, and `503` when they do not.

  The nodes must see the address of whoever is signing in, not the
  balancer's: every sign-in limit and allow list is per address, and behind
  a balancer that hides it everybody shares one - five wrong passwords from
  anybody lock out everybody for a quarter of an hour. So either end TLS on
  the balancer and pass `X-Forwarded-For` (`mode http`, `option forwardfor`),
  or pass TLS through with the PROXY protocol. `mode tcp` alone carries no
  address at all, and `acme --trusted-proxy` then has nothing to read.

  Ending TLS on the balancer (the nodes keep their own certificate behind it):

  ```
  frontend acme_https
      bind :443 ssl crt /etc/haproxy/acme.pem
      mode http
      option forwardfor
      default_backend acme_nodes

  backend acme_nodes
      mode http
      balance roundrobin
      option httpchk GET /healthz
      http-check expect status 200
      server acme1 192.0.2.11:443 check ssl verify none
      server acme2 192.0.2.12:443 check ssl verify none
  ```

  Passing TLS through, with the PROXY protocol:

  ```
  frontend acme_https
      bind :443
      mode tcp
      default_backend acme_nodes

  backend acme_nodes
      mode tcp
      balance roundrobin
      option httpchk GET /healthz
      http-check expect status 200
      server acme1 192.0.2.11:443 send-proxy-v2 check check-ssl verify none
      server acme2 192.0.2.12:443 send-proxy-v2 check check-ssl verify none
  ```

  and on both nodes, in `/etc/nginx/conf.d/acme.conf`: `listen 443 ssl
  proxy_protocol;` (in place of `listen 443 ssl;`), `set_real_ip_from
  192.0.2.10;` and `real_ip_header proxy_protocol;`. With send-proxy the
  health check needs `check-send-proxy` as well, or it is refused by nginx.

## What it does not do

- **Replicated: a code is used up on one node, and the other learns of it a
  moment later** - normally well under a second. An administrator's code asked
  on both nodes in that moment, or on both halves of a split network, can be
  accepted twice. An app code lives 30 seconds at most, so the risk is small,
  but it is there. The shared layout does not have it.
- **Replicated: cut in two, both nodes may lead.** With the network between
  them cut (each answering, neither reaching the other's PostgreSQL), each
  takes the other for dead and leads, and a certificate may be renewed and
  deployed twice - a CA's rate limits count both. Without a third machine a
  cut cannot be told from a dead node; the VIP address (keepalived) has the
  same limit. A paused or broken replication alone does not do this.
- **Replicated: a renewal by hand on the node that does not lead**, while
  the leader renews the same certificate, makes the same version on both;
  the same one of the two is kept on both, the other node's certificate
  lost. Renew a certificate by hand on the leader, or one node at a time.
- **Replicated: the same row changed on both nodes at the same moment.** A row
  made on both nodes under the same name (a certificate, a target, a source,
  an account, a meta key, a setting) or the same key of several columns (a
  certificate's version, an authority's serial) does not stop the
  replication: the same one of the two is kept on both. A setting changed on
  both keeps the later change on both. Anything else (a certificate's
  options, a target's address) ends up as whichever change arrived last on
  each node - change those on one node at a time. New rows never collide on
  their numbers: one node numbers odd, the other even.
- **Replicated: send a person's requests to one node** where the balancer
  can (sticky by source address): a sign-in or a certificate added on one node
  reaches the other a moment later, and the next page asked of the other
  node in that moment does not know it yet.
- **Shared: it does not make PostgreSQL highly available.** If the database runs
  on node 1, node 1 is the one machine that must stay up. Use the replicated
  layout, or a PostgreSQL cluster (Patroni, or a managed one) given with
  `--ha-db-host`.
- **Copies and dumps stay on the node that made them.** Each node lists the
  ones on its own disk. In the replicated layout each node makes its own
  nightly dump. Restoring a dump is refused while replication runs: switch it
  off, restore on one node, rebuild the other from it.
- **Upgrade both nodes to the same version** - one at a time, each taken out
  of service first: *Settings → Upgrades* does it by itself, or by hand with
  `acme --maintenance on` and `install.sh --upgrade` on each node in turn.
  [upgrades.md](upgrades.md) says how, and how to upgrade the operating
  system. The node list shows any mismatch.

## Tested

`test/test_ha.py` sets both layouts up on one machine with the wizards above
(two daemons with their own folders, ports and names; the VIP address off):
one PostgreSQL for *shared*, two PostgreSQL clusters (5432 and 5433, two nodes
on one machine: the second's `db_port` set before the join, the first given
`--ha-peer-port 5433 --ha-address 127.0.0.1`) for *replicated*. It checks
that one node leads and both say so, that four certificates made on either
node are renewed once each, by the leader, and seen on both, that both DNS
servers answer the same TXT record, that one node numbers odd and the other
even, that with replication paused both ways the second node still does not
lead (a certificate made there waits for the first), and that the other node
takes over when the leader is killed. Each part is skipped when its
PostgreSQL is not there.
