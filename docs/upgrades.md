# Upgrades and maintenance

Two ways to put in a new version. Both stay: use whichever suits you.

| | Command line | The pages |
|---|---|---|
| Where | on each node, as root | *Settings → Upgrades*, as a full administrator |
| How | `./install.sh --upgrade` | send the `.tar.gz`, press *Upgrade* |
| One server | out of service for a minute or two | the same |
| A cluster | node by node, by hand | every node in turn, by itself |

## From any version

Any older version - back to the first `opt` 1.0.0 - is upgraded straight to
this one, on SQLite, MariaDB and PostgreSQL: the tables are brought up to date
when the new version starts (columns added, nothing taken away), `opt` is
renamed to `acme` by install.sh, and copies made by any older version go back
into this one. Tested from every release 1.0.0 - 1.0.61 on SQLite and from
releases across that range on MariaDB and PostgreSQL (1.0.62). In a cluster the nodes are upgraded one after the other; while
one is new and the other old, what the new one writes into a table that gained
a column waits in its replication until the other is upgraded too, and then
goes over - nothing is lost.

## Maintenance

A node **in maintenance** answers no RADIUS request and its `/healthz` says
`503 maintenance`, so the VPN and the load balancer take it for down and use
the other node. Its pages go on working, so it can be looked at and brought
back.

```
acme --maintenance on --why "new disk"     # out of service
acme --maintenance status                  # which (exit 3 while in maintenance)
acme --maintenance off                     # back in service
acme --maintenance on --node acme2          # another node of the cluster
```

With the VIP address on ([tls-and-vip.md](tls-and-vip.md)), a node in
maintenance also gives the address up to the other node.

On the pages: *Settings → Upgrades → The nodes*, or the *Maintenance and
upgrades* card on the Overview. With a single server, maintenance means
nobody can sign in to the VPN.

## On the command line

```
tar xzf acme-X.Y.Z.tar.gz && cd acme-X.Y.Z
sudo ./install.sh --upgrade
```

From 1.0.37 on, `install.sh --upgrade` takes the node out of service before it
touches anything (and waits 20 s in a cluster, for the balancer and the VPN to
notice), and puts it back once the new version answers. A node that was in
maintenance already stays in it. In a cluster, upgrade one node, check it
(`acme --check`, `acme --ha-status`), then the other.

## From the pages

*Settings → Upgrades*:

1. **Send the package** - the `acme-X.Y.Z.tar.gz` as released. It is checked at
   once (below) and kept in the database, so every node of a cluster has it.
2. **Upgrade.** One server: it is put in and restarted. A cluster: one node at
   a time - the others first, the node the page came from last:
   1. the node goes into maintenance, and waits 20 s for the balancer;
   2. the package is handed to root (see below), which runs its
      `install.sh --upgrade`;
   3. the node comes back as the new version, checks that its database opens
      and RADIUS listens, reads the list of replicated tables again, and leaves
      maintenance;
   4. only then the next node begins.

   A node that fails stops the upgrade there, goes back into service as it
   runs, and the page shows what `install.sh` said. *Stop it* leaves the nodes
   not yet begun as they are.

`acme --upgrade-status` shows the same on the command line, and
`acme --upgrade-cancel` stops it.

### From the web (1.0.123)

*Settings → Upgrades → From the web* looks once a day (and when *Look now*
is pressed) at `upgrade_url` for `acme-X.Y.Z.tar.gz` packages:

| `upgrade_url` | how it is read |
|---|---|
| `https://github.com/OWNER/REPO/tree/BRANCH/FOLDER` (the default: `https://github.com/falco81/ACME/tree/main/release`, which keeps the last ten versions) | GitHub's API lists the folder; the packages come from `raw.githubusercontent.com`. When the API refuses (60 questions an hour without an account), the folder's own page is read for the names. |
| a web page or a folder listing (nginx, Apache autoindex) | every link to an `acme-X.Y.Z.tar.gz` |
| one package's address | that package |

HTTPS only. A proxy, if the server needs one, comes from `https_proxy` in the
service's environment (`systemctl edit acme`: `Environment=https_proxy=…`).
The node needs to reach the address (and `api.github.com`,
`raw.githubusercontent.com` for GitHub) - Settings → Firewall and access lets
everything out.

The newest one newer than what runs here is offered: **Upgrade to X now**
fetches it, checks it exactly as a package sent by hand (below - the signature
of a release key this server trusts, every file in it), keeps it in the
database and begins the upgrade; **Only fetch it** stops before the upgrade.
With more than one version there newer than this one (1.0.142), a list beside
the buttons lets you choose which to go to - the newest is chosen, and the
buttons follow the choice; with only one, the page is as before. An older one
than what runs here is never offered, nor taken.
Nothing is ever put in by itself. `upgrade_check` off stops the daily look;
*Look now* still asks.

*Hide this* takes a finished upgrade off the page.

On the command line (and in `acme --console` → Upgrades):

```bash
acme --upgrade-check              # what is at upgrade_url, and whether it is newer
acme --upgrade-online             # the newest: fetched, checked, every node upgraded
acme --upgrade-online 1.0.140 --yes
acme --upgrade-follow             # follow one going on, with its progress bars
```

### What makes it safe

The service runs as `acme`, which may not write a byte of the program. The
pages therefore never install anything themselves:

- The node lays the package and a request down in `/var/lib/acme/upgrade/`.
  systemd sees the request (`acme-upgrade.path`) and starts
  `acme-upgrade.service`, which runs `/usr/local/lib/acme/acme_upgrade.py` **as
  root**. It is the only thing that unit can do.
- Root copies the package to a folder of its own before reading it, so it
  cannot be changed under the check, and checks it again from the start:
  - **signed**: `MANIFEST` lists the SHA-256 of every file and `MANIFEST.sig`
    is its Ed25519 signature, by one of the keys in
    `/usr/local/lib/acme/release-keys/` - root's alone, put there only by
    `install.sh`;
  - every file is the one signed, and nothing else is in it: no link, no
    device, no path outside its one folder;
  - it is not older than what is installed (going back is done on the command
    line).
- Then it runs the package's own `install.sh --upgrade --yes`, exactly as
  somebody would by hand, and writes what it said to
  `/var/lib/acme/upgrade/last.log`.

A package that was changed, or signed by a key the server does not know, is
refused - put it in on the command line if you trust it. The first version
with this (1.0.37) has to be put in on the command line once: that installs the
units and the key.

## Going back to an older version (1.0.143)

Only to a version it is safe to go back to, and never by putting a database
back: the tables stay as they are - whatever their size - and the older
program runs on them. Every column a newer version added is one an older one
leaves alone (they are all added NULL).

**How far back.** Each version says the oldest one it may go back to
(`DOWNGRADE_FLOOR` in acme.py): one that reads what it writes into the
database and config.json the same, and has every security fix that matters.
Going back is refused below the highest of these

- of any version that ran on this database, on any node - each node keeps its
  own in the database (`downgrade:floor:NODE`), so a version that ran once
  still counts after going back from it;
- of any version installed on this machine - install.sh keeps it in
  `/usr/local/lib/acme/downgrade-floor`, root's alone. The acme account cannot
  lower it, so nobody who has only the pages (or the acme account) can take the
  server back to a version with a hole a later one fixed. An older version's
  install.sh leaves it as it is.

**The package against the database.** Fetched or given, the older package is
checked like an upgrade's (signed, every file) and then against this
database: a column the database has as NOT NULL with no default that the
older version does not know would make every row it writes there fail - such
a version is refused, naming the column.

**Then** it goes the road of an upgrade: one node at a time, each in
maintenance while it is done, checked and brought back. Root's helper puts an
older version in only when going back is asked for as such, and never below
its floor file.

- The pages, once *Settings → Upgrades → Offer going back to an older
  version* (`upgrade_downgrade`, off by default) is on: *Going back to an older
  version* - *Show the versions to go back to* lists the older versions at
  `upgrade_url`, each with what stands in its way and *What changed* (what
  came in it, and folded what going back to it gives up); *Go back to X*
  (asked twice). Off, the pages offer nothing of it and the API refuses it.
- The command line:

  ```bash
  acme --downgrade-check                  # the older versions there, and which are safe
  acme --downgrade 1.0.140                # from upgrade_url, every node, followed here
  acme --downgrade /root/acme-1.0.140.tar.gz
  ```

- The console: *Upgrades → Go back to an older version (only a safe one)*.
  *Upgrade this node from a package file* refuses an older package and points
  here.

What came in the newer versions is gone until you upgrade again; settings
that only a newer version knows stay in the database and are used again then.

## A cluster: what goes where

Settings, clients, realms, directories, tokens and accounts are the cluster's
and replicate. A few settings belong to one machine and each node has its own
(*Settings → High availability → Each node's own settings*): the address RADIUS
listens on, the port the pages ask the daemon on, the name it greets mail
servers with, the name isemon files it under, and the debug switches. The
database address and the cluster's wiring are in each node's
`/etc/acme/config.json` and never replicate. Maintenance, heartbeats and the
upgrade's progress are kept per node.

A new version may add a column. Between the upgrade of the first node and the
second, the older one takes nothing from the newer (the change waits in the
newer one's replication slot) and catches up as soon as it is upgraded - which
is why the upgrade goes straight on to the next node.

## The operating system

- **Ordinary updates** (`dnf upgrade`, a new kernel, a minor PostgreSQL):
  node by node - `acme --maintenance on`, update, reboot,
  `acme --ha-status` shows both directions running, `acme --maintenance off`,
  then the other node. The live node keeps what the other misses (up to 16 GB).
- **A new major release** (AlmaLinux 9 → 10, PostgreSQL 16 → 17): do not
  upgrade in place - `pg_upgrade` does not carry the replication slots. Make a
  bundle on the live node (`acme --ha-bundle FILE`), reinstall the other node
  from scratch, `acme --ha-join FILE` on it; then the same the other way round.
