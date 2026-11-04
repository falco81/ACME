# Upgrades and maintenance

Two ways to put in a new version. Both stay: use whichever suits you.

| | Command line | The pages |
|---|---|---|
| Where | on each node, as root | *Settings → Upgrades*, as a full administrator |
| How | `./install.sh --upgrade` | send the `.tar.gz`, press *Upgrade* |
| One server | out of service for a minute or two | the same |
| A cluster | node by node, by hand | every node in turn, by itself |

## What an upgrade changes on the machine

The program is a tree - `acme.py`, `acmelib/`, `web/`, `deploy/`, `docs/`,
`install.sh`, `MANIFEST` - and every version gets a tree of its own:

```
/usr/local/lib/acme/
    versions/1.0.1-20261201101500/   the new one: copied, root's, compiled
    versions/1.0.0-20261101093700/   the one before
    current  -> versions/1.0.1-…     what runs
    previous -> versions/1.0.0-…     kept for going back
    acme.py, acme_upgrade.py, acme_web.py, deploy, docs, CHANGELOG.md -> current/…
    python, venv/, release-keys/, downgrade-floor, db-drivers, python-choice
```

`install.sh --upgrade` makes the new tree under a name of its own, compiles
it, and only then switches `current` to it - one `rename(2)` of a link - and
restarts the service. Cut off at any moment, the machine runs one whole
version: the old one until the switch, the new one after it; a half-copied
tree is a `.new-…` folder nobody runs, cleared by the next install. The tree
that ran before becomes `previous`; older ones are deleted. The pages
(`/var/www/acme`) are copied whole beside the old ones and put in their place
the same way.

**When the new one does not run (1.0.44).** After the restart the service must
stay up, the same run, for 15 s (systemd's `NRestarts` unchanged) - a version
that dies at once and is started again every 5 s is no longer taken for one
that runs. Should the upgrade stop after the switch (that check, the pages, PHP,
nginx), `current` goes back to the tree that ran before, its pages are put back,
and the service is started again on it; the new tree is marked `.failed` and is
never made `previous` by a later try - which made the failed tree `previous`
and deleted the last one that ran. Only one install.sh runs at a time (a lock
in `/run`), and `install.sh --upgrade` refuses to take this node out while the
other node of a cluster is not in service (`ACME_FORCE_UPGRADE=1` when that is
meant).

The database is brought up to date when the new version starts (columns and
tables added, nothing taken away). In a cluster the nodes are upgraded one
after the other; while one is new and the other old, what the new one writes
into a table that gained a column waits in its replication until the other
is upgraded too, and then goes over - nothing is lost.

### The tree before, back

```bash
sudo /usr/bin/python3 -I /usr/local/lib/acme/acme_upgrade.py --previous
```

checks the previous tree as root checks a package - its `MANIFEST.sig` by a
release key this machine trusts, every file listed in its `MANIFEST` the one
signed (a tree put in from a git checkout has none: `--unsigned` takes it
anyway), not below the machine's floor for going back - and then runs its own
`install.sh --upgrade --yes`, which makes it `current` again without copying
it (and the newer one `previous`). Going back on the database is the same as
below: only to a version that reads what the newer one wrote.

## Maintenance

A node **in maintenance** starts no renewal or deployment and its `/healthz`
says `503 maintenance`, so the load balancer (and the VIP address) go to the
other node. Its pages go on working, so it can be looked at and brought back.

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
nothing is renewed or deployed meanwhile.

## On the command line

```
tar xzf acme-X.Y.Z.tar.gz && cd acme-X.Y.Z
sudo ./install.sh --upgrade
```

`install.sh --upgrade` takes the node out of service before it touches
anything (and waits 20 s in a cluster, for the balancer to notice), and puts
it back once the new version answers. A node that was in
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
   3. the node comes back as the new version, checks that its database opens,
      reads the list of replicated tables again, and leaves maintenance;
   4. only then the next node begins.

   A node that fails stops the upgrade there, goes back into service as it
   runs, and the page shows what `install.sh` said. *Stop it* leaves the nodes
   not yet begun as they are.

`acme --upgrade-status` shows the same on the command line, and
`acme --upgrade-cancel` stops it.

### From the web

*Settings → Upgrades → From the web* looks once a day (and when *Look now*
is pressed) at `upgrade_url` for `acme-X.Y.Z.tar.gz` packages:

| `upgrade_url` | how it is read |
|---|---|
| `https://github.com/OWNER/REPO/tree/BRANCH/FOLDER` (the default: `https://github.com/falco81/ACME/tree/main/release`, which keeps the last ten versions) | the folder's `index.json` (written by `tools/release.py`: name, version, size, sha256, date, download address of each) from `raw.githubusercontent.com` - of the branch's newest commit, asked of GitHub's API first (`/repos/OWNER/REPO/commits/BRANCH`): the branch's own address is kept 5 minutes by GitHub, and just after a release said the version before it; without the API, the branch's address; where there is none, GitHub's API lists the folder, and when that refuses (60 questions an hour without an account), the folder's own page is read for the names. The packages come from `raw.githubusercontent.com`. |
| an `index.json` (or any JSON list of `{name, download_url, size, sha256}`) | its entries |
| a web page or a folder listing (nginx, Apache autoindex) | every link to an `acme-X.Y.Z.tar.gz` |
| one package's address | that package |

HTTPS only. A proxy, if the server needs one, comes from `https_proxy` in the
service's environment (`systemctl edit acme`: `Environment=https_proxy=…`).
The node needs to reach the address (and, for GitHub,
`api.github.com` and `raw.githubusercontent.com`) - Settings → Firewall and access lets
everything out. A package whose index gave its `sha256` must have that one,
before anything else is looked at. How a release gets there:
[releasing.md](releasing.md).

The newest one newer than what runs here is offered: **Upgrade to X now**
fetches it, checks it exactly as a package sent by hand (below - the signature
of a release key this server trusts, every file in it), keeps it in the
database and begins the upgrade; **Only fetch it** stops before the upgrade.
With more than one version there newer than this one, a list beside
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
acme --upgrade-online 1.0.2 --yes
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
  - its version is the one in `acmelib/__init__.py`, and its folder is named
    after it (`acme-X.Y.Z/`).
- Then it runs the package's own `install.sh --upgrade --yes`, exactly as
  somebody would by hand - which puts the new tree in beside the old one and
  switches to it (above) - and writes what it said to
  `/var/lib/acme/upgrade/last.log`.

A package that was changed, or signed by a key the server does not know, is
refused - put it in on the command line if you trust it. The keys trusted are
exactly those of the version installed (`deploy/release-keys/*.pub`, acme's
own - the key of otp, which acme was made from, is not one of them).

## Going back to an older version

Only to a version it is safe to go back to, and never by putting a database
back: the tables stay as they are - whatever their size - and the older
program runs on them. Every column a newer version added is one an older one
leaves alone (they are all added NULL).

**How far back.** Each version says the oldest one it may go back to
(`DOWNGRADE_FLOOR` in `acmelib/engine/000_start.py`): one that reads what it writes into the
database and config.json the same, and has every security fix that matters.
Going back is refused below the highest of these

- of any version that ran on this database, on any node - each node keeps its
  own in the database (`downgrade:floor:NODE`), so a version that ran once
  still counts after going back from it;
- of any version installed on this machine - install.sh keeps it in
  `/usr/local/lib/acme/downgrade-floor` (beside `versions/`, not in a tree),
  root's alone (1.0.44 raised the floor to 1.0.44: its root helper shuts holes
  the older ones have). The acme account cannot
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
  acme --downgrade 1.0.1                  # from upgrade_url, every node, followed here
  acme --downgrade /root/acme-1.0.1.tar.gz
  ```

- The console: *Upgrades → Go back to an older version (only a safe one)*.
  *Upgrade this node from a package file* refuses an older package and points
  here.

What came in the newer versions is gone until you upgrade again; settings
that only a newer version knows stay in the database and are used again then.

## A cluster: what goes where

Settings, certificates, authorities, issuers, challenges, targets and accounts are the cluster's
and replicate. A few settings belong to one machine and each node has its own
(*Settings → High availability → Each node's own settings*): the port the
pages ask the daemon on, the name it greets mail servers with, the name isemon
files it under, and the debug switches. The
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
