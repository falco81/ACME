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

### The pages during an upgrade

An upgrade restarts the very things that serve the pages - the API, then
nginx and PHP. Since 1.0.120 the pages stay with it instead of turning red:

- **A band under the header**, on every page and for everybody signed in:
  *acme is being upgraded to X* (going back: *acme is being taken back to
  X*), from which version, who asked, how long so far, a bar, and the step -
  *acmeB: The pages · step 7 of 9*. In a cluster **every node has a row**:
  its step, how far, what happened, when. The pill in the header says *in
  maintenance*, the cards *maintenance* and *upgrading*.
- **No red while it is expected**: no "not answering" bar, no red messages.
  While the API restarts the band says *not answering for 7 s, asked again
  every two seconds*; while nginx and PHP restart too, it says so.
- **The end**: once every node is done the page loads itself again - once,
  onto the new pages. With changes not saved it does not: the band offers
  *Load it again*. A failure is a red band with the reason and a link to
  *Settings → Upgrades*, with × to hide it; a stopped upgrade says which nodes
  stay as they were.
- **Signed out meanwhile** (or the page loaded while the API is away): the
  sign-in page shows the band itself and loads itself again once the API
  answers. Nobody is signed out by the upgrade.
- `acme --upgrade-follow` (and *Upgrades → Follow the upgrade* of the console)
  shows the same *step N of M*; it also follows an `install.sh --upgrade`
  typed in on this node.

**Where it comes from.** Root writes how far it is into
`/var/www/acme/.upgrade.json` - `acme_upgrade.py` when it takes the request
(step 1, checking the package), then `install.sh --upgrade` at each of its
steps, and how it ended (`failed` from its exit trap also when it is stopped
by Ctrl-C, a hang-up or TERM, so a stopped run is never left "running"). The
file is root's (0644, the folder is root's), written whole and renamed into
place, goes over with the pages when they are put in, and holds nothing
secret (who asked is shown only to a page with a session). nginx never serves
it (`location ~ /\. { deny all; }`); PHP reads it from disk (within its
`open_basedir`, labelled for the web server like the pages, so SELinux needs
nothing new). It is believed for 30 min after its last word while it says
`running`, 10 min once `done` or `failed`; anything else in it, or a time to
come, is as if there were none.

PHP uses it three ways: while the API does not answer, every request of the
pages gets `503 {"upgrading": {...}}` instead of "not answering";
`?api=upgrade-state` answers without the API at all; and the status the pages
ask every few seconds carries it, with the version of the pages on that
node's disk.

**A cluster and the VIP address.** The file is per node - each node's root
writes its own - while the upgrade of the cluster is the plan in the database,
which the API of *whichever node answers* serves. Behind the VIP address the
answering node changes during the upgrade: the node the page came from goes
last, so when it goes into maintenance the address moves to the other node,
which already runs the new version. The band always draws the cluster's plan;
the answering node's file only fills in that node's own row (and is the whole
of it only while no API answers, or on a single server). A node's own file
saying `done` never ends the upgrade: the page loads the new pages only when
the API says the plan is over - every node done, or failed, or stopped with no
node at its turn - and never while a node is still to go. It also loads once
when the pages on the answering node's disk are another version than the page
itself while nothing is going on (an old page must not stay on a new API).
Each of these happens once per upgrade in a tab (no loops, whichever node
answers next). The session is the cluster's: the node that takes over knows
it, and a 401 from a node that is just starting is asked again before
anybody is signed out (1.0.73).

`/healthz` keeps its status codes exactly - what keepalived, the balancers and
the other node read is unchanged (keepalived itself decides by
`/run/acme/vip-state`, not by `/healthz`). Only its words gain the reason
after the first one: `maintenance: being upgraded`, `down: the daemon is not
answering (maintenance: being upgraded)` - no version, no node name.

While an upgrade runs, the alerts *a node is not heard from* and *the nodes
run different versions* wait (the failure of the upgrade is an alert of its
own), and the checks of *what waits for a person* are not made on a node until
root has written that its part ended - the new daemon starts before
`install.sh` has finished.

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
  root's alone (1.0.102 raised the floor to 1.0.102: it and 1.0.101 shut holes
  of the root helper, the approvals and the seals the older ones have; every
  version with an entry marked `(security)` in CHANGELOG.md raises it to
  itself, [releasing.md](releasing.md)). The acme account cannot
  lower it, so nobody who has only the pages (or the acme account) can take the
  server back to a version with a hole a later one fixed. An older version's
  install.sh leaves it as it is.

**What is in use here** (1.0.138). Below 1.0.138 going back is also refused
while a request profile stands on a base profile (an older version reads it
without what it inherits and stops offering it - let it stand alone first)
or a team has governance switched on (separation of duties, temporary roles,
access reviews, team channels - an older version would drop them without a
word, "never approve your own request" among them). Each is named; with
neither in use, going back is as before.

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
