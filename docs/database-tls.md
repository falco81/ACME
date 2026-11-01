# Encryption to the database server (1.0.170)

*Settings → The database → Encryption to the database server*, for a full
administrator: the daemon's own connection to its database - on every node -
encrypted and checked, on the running installation. RADIUS answers all the time.

## What it does, by where the database is

| The database | What the wizard does |
|---|---|
| a file (SQLite), a Unix socket | nothing - nothing goes over a network |
| PostgreSQL on the same machine, no cluster | gives PostgreSQL a certificate from acme's own authority (`localhost`, `127.0.0.1`, `::1`, the machine's names and addresses), `ALTER SYSTEM SET ssl = on` and a reload - no restart; then the connection moves to `verify-full` with that authority |
| two nodes replicating | each node's PostgreSQL has the cluster's certificate once the link between the databases is encrypted (*High availability → Repair*); each node's connection moves to `verify-full` with the cluster's authority |
| a server elsewhere, or a node's PostgreSQL another node shares | its certificate is the server's administrator's: the wizard takes its authority (PEM), the system's (a public CA), or acme's own when that server is a node's PostgreSQL given one here; `verify-full`, `verify-ca` or `require` |

MariaDB elsewhere works as a server elsewhere (its authority, or the system's).

## How it moves, safely

The wizard goes in phases, each asked of every node and finished on all of them
before the next:

1. *Try it on every node* - a connection of its own with the new settings, on
   each node; nothing changes.
2. The certificates of the PostgreSQLs on the nodes (only where PostgreSQL is on
   the same machine and not replicated).
3. Every node's connection: tried apart once more, then `config.json` written
   and the daemon's connections made again - **put back at once if the first
   statement on the new one does not go**. A node where it does not go stays as
   it was and the wizard stops there.

Off is the other way round: every connection back to no TLS, then acme's
certificates out of the PostgreSQLs (`ALTER SYSTEM RESET`, ssl as
`postgresql.conf` says).

## By itself afterwards

- The certificate of a PostgreSQL on the same machine is renewed 45 days before
  it ends, and made again when the machine's names or addresses change (a new
  address, a node renamed). The connections go on: PostgreSQL takes the new
  certificate with a reload (`pg_reload_conf()`), never a restart - the
  connections open keep going, new ones get the new certificate, RADIUS does not
  notice. In a cluster whose link between the databases has its TLS on, the
  certificate is the link's and is renewed with it (45 days before it ends, the
  cluster's authority two years before), the same way. A database server
  elsewhere (*remote*) renews its certificate as its administrator does it -
  acme only checks it.
- A connection on the same machine that stops working because of its TLS - the
  certificate gone, PostgreSQL set up again, `ssl` switched off by hand - is moved
  back to no TLS within seconds, said in the events and on the card, so RADIUS
  goes on. It never leaves the machine. Under high security (`db:tls` not an
  exception) it is not moved back, only said.
- In a cluster, the link's TLS (*High availability → Switch TLS off*) cannot be
  switched off while the daemons' connections check with its certificate - switch
  this off first.

## High security

`db:tls` asks for `verify-ca` or `verify-full` to a database over a network: under
high security `require` is not offered and switching off is refused unless
`db:tls` is an exception.

## By hand

The same settings are `db_tls` (`require`, `verify-ca`, `verify-full`) and
`db_tls_ca` (the authority file) in `/etc/acme/config.json`. The authority given in
the wizard is kept as `/var/lib/acme/db-ca.pem`; acme's own (and the cluster's) as
`/etc/pki/acme/ha-ca.pem`.
