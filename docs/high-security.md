# High security (1.0.168)

*Settings → High security*, for a full administrator, off by default. On, it
switches off every way of doing something less safely, on every node.

## Switching it on

Switching it on first looks over everything - the settings, the directories,
the backup destinations, the TLS of the pages, who may
reach the administration, and the SSH server as each node's sshd says it is.
What stands against it is listed in a window, each with what to set and a
link to where; it is refused (the daemon too, HTTP 409 with the list) until
the list is empty. The same list is on the page itself, with *Look again*.

## What stands against it

| Where | Refused |
|---|---|
| Active Directory | plain LDAP; the certificate not checked; old, weak TLS |
| Mail | to the server unencrypted or only if offered (`smtp_security` none, starttls-if); the certificate not checked; direct delivery unencrypted where the recipient's server offers no TLS |
| SMS | the HTTP gateway over `http://`; the telephone gateway without HTTPS or without checking its certificate |
| Database, cluster | MariaDB/PostgreSQL over the network without `verify-ca`/`verify-full`; the replication likewise |
| Backups | plain FTP; FTPS not checking the certificate; SMB not encrypted |
| Syslog | UDP or TCP servers (only `tls://`); the certificate not checked; isemon over plain syslog, or its certificate not checked |
| The pages | TLS other than *standard* (ECDHE, AEAD) or *modern* (TLS 1.3); the administration reachable from everybody |
| SSH | passwords (or keyboard-interactive); root with a password; more than 4 tries |
| Accounts | no second step for the administration, or one by mail or SMS; the administrators' app codes taken more than one step either side; sign-ins lasting over 8 hours or idle over 30 minutes |
| The enrolment pages | anyone in the directory may sign in |
| Other | debugging; a private key or the configuration exported not locked; a proxy without a password |

While it is on, each of these is refused wherever it is changed - the pages,
the API, `acme --set` - and greyed out on the pages, with why.

## Exceptions (1.0.169)

Every rule has a switch on its right: *Exception*. A rule made an exception
stops nothing and is not enforced while high security is on - the rest stay.
While high security is on, an exception is taken back only once the rule is kept
(else high security would stand against itself). Each change is an event. The
rules kept are listed too, folded, each with its switch.

## The security check

What is not as it should be now - the firewall off, no backup going to another
machine or none tried, a backup that cannot be put back, security updates or a
restart waiting, certificates running out - is listed apart, and never stops
high security.

Switching it off is always possible, and written down as every setting is.

## The guard against writes to the database (1.0.40)

*Settings → High security → Guard against writes to the database* (`db_guard`;
a switch, off by default - as until now; taken over from otp 1.0.231-1.0.236).

Worth it with a cluster or a database on another machine; with SQLite on this
machine (only root and acme can write it) it adds little. Nothing else is to be
set: switch it on, on every node.

What a node does as root follows rows of the database: the firewall, sshd and
root's `authorized_keys`, the network and the host name, a restart or a power-off,
the system's updates and the proxy they go through, chrony's servers, nginx's
certificates, keepalived's VIP, the TLS of the link between the databases - and so
do the accounts and the sign-ins of these pages, through which all of it is asked
for. Anybody who can write the database - its server, a `db_password` found out, a
copy of the database put back - could write those rows, and the node did as they
said.

Since 1.0.40 every such row is signed when acme writes it: an HMAC under a key
worked out from `secrets.key`, which is in no database (both nodes of a cluster have
it). The signature is a row of its own beside it (`sig:<kind>:<hash>:<node>` in `meta`; each
node writes only its own, so replication never meets the same row from both sides);
versions before 1.0.40 leave those rows alone. With `db_guard` **on**, a node:

| Row | Not signed, or an older one put back |
|-----|--------------------------------------|
| a sign-in to these pages (`sessions`) | not taken - "not signed in" |
| an account (`accounts`: name, role, password, source, switched off, DN) | cannot sign in |
| the directory administrators sign in against | not asked |
| a setting that reaches root, or who may sign in (firewall ports, proxy, updates, restarts, logs, the HTTP-01 challenge here, SNMP, mail and SMS, the administrators' groups and second step, high security, the balancers) | its last good value stays (else config.json and the default) |
| a row of `meta` that root acts on (`web:vip`, `web:tls:*`, `web:access`, `fw:conf`, `ntp:conf`, `net:*`, `power:plan`, `host:sshkeys:want:*`, `host:sshd:conf`, `host:osup:plan`, `hatls:*`, `readdress:*`, `console:want:*`, `upgrade:plan`, `ask:want:*`, `adm2fa:*` ...) | read as not there - nothing is done |
| another node's heartbeat | its address not let through the firewall, not into nginx's lists, not taken for the VIP's or chrony's peer |

Each node remembers, in its own file (`/var/lib/acme/guard.json`, not in the
database), the newest signature it has seen of each row: a row taken from an
older copy - signature and all - is older, and refused. What is refused is written
in the log and in Events, and listed in the security check.

The certificates, their renewals, deployments and tests are **never** held up by it:
nothing of the guard is asked on their way.

**Switching it on** writes `db_guard` into this node's `config.json` - never into
the database, so nobody who can write the database can switch it off - and signs
what the database holds at that moment as acme's word. It is switched off only on
the node itself (its pages, or `acme --set db_guard=0` as root). In a cluster switch
it on on every node, once all of them run 1.0.40 or later (it refuses while one
does not). From 1.0.88 a node that joins (or comes back to) a cluster whose other live node has the guard on switches it on by itself - unless somebody switched it off on that node (then it stays off). A copy put back on purpose, a configuration imported, the database moved
and a node renamed are signed again by acme afterwards - they work as before.

**From the command line**: `acme --set db_guard=1` on each node, as root. The
running service takes it at once - nothing to reload or restart.

**`acme --guard-status`** says whether it is on on this node, and lists every row
that reaches root not as acme wrote it - what it does not act on.

**Another node's heartbeat** is a row and its signature, written in one
transaction. The address a node had in its last signed heartbeat is still taken for
three minutes while a newer one waits for its signature; a heartbeat with another
address is not.

**Going back** to a version before 1.0.40 is refused while the guard is on on any
node: switch it off on every node first.

**`systemctl reload acme`** (as otp 1.0.232): systemd gives the service's `/run/acme`
back to `acme:acme` before it sends the reload. The pages (the `acme-web` group) could
then not read the API token: `/healthz` said *503 - the pages cannot read the daemon's
API token* and the VIP address left the node until acme was restarted. The daemon now
gives `/run/acme` and the token back to `acme-web` the moment the reload arrives, and
checks it every 5 seconds (said in the log when it had to).

Not against the other node of a cluster: it holds the same key, and root on it is
root of the cluster's database anyway.

## SELinux

Under the settings, a card for each node says how SELinux stands there - the mode, acme's
module, the labels, booleans and ports acme needs, what was refused - with the steps to make it
ready, enforcing, or permissive again. Where SELinux is on, the security check lists what keeps
a node from being protected as it should; where it is disabled, it says nothing. See
[selinux.md](selinux.md).
