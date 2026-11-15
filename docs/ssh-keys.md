# SSH keys on the pages

*Settings → SSH keys* (full administrators): the keys that may sign in to each node over SSH,
read from every node, a column a node.

## Root (1.0.158)

The lines of `/root/.ssh/authorized_keys` of every node, a column a node: each key's type,
fingerprint and comment, *with options* where the line has some, *made here* for one made on
these pages before 1.0.108. Each is exported by its public half (a `.pub` file). What sshd
makes of root is said above the list (`PermitRootLogin no`, root not in `AllowUsers`, no keys
taken at all), and a node built again on another machine says the fingerprints root had there
before that are not on it now.

### Root's keys are only shown (1.0.108)

Root's keys are not made, added or taken away on the pages: no *A key for root* card, no
*Add a key*, no taking away in the list - a note says where they are changed instead. Change
them **on the server itself, as root**: `/root/.ssh/authorized_keys` of each node (an editor,
`ssh-copy-id root@node` from your machine, or `ssh-keygen` there). acme reads the file again
when the pane is opened, and with the refresh button.

It is held on the server too, not only by the page:

- `POST /api/sshkeys` answers **403** (*root's SSH keys are only shown on the pages - change
  them on the server itself, in /root/.ssh/authorized_keys*) for `add`, `drop`, `uk_make` for
  root, and the old `rk_make`, `rk_given`, `rk_again`. A body without `user` is root's.
- The command line has no option of its own for root's keys; `acme --api POST /api/sshkeys
  ...` is the same route and is refused the same way. root on the server needs no acme to
  change its own file.
- The daemon writes no ask for a change of root's keys, and one it finds in the database (from
  a version before, from the other node, written there past acme) is marked done with the
  refusal - never handed to the root helper.
- **Each node's root helper** (`acme_web.py`) refuses an add or a removal for root whatever
  carries it: an ask laid in `/var/lib/acme/web` by itself, a row of the database signed by
  acme or not, `db_guard` on or off. It has no code left that writes root's file; it only
  reads it.

So the `acme` account - a fault in the daemon or a plugin, anybody who can write the database
- can no longer put a key into root's `authorized_keys` on any node. The keys of root made on
the pages before stay where they are (they are root's file's lines now) and are no longer put
on again on a node built again on another machine: its page says their fingerprints, to put
them back on the server itself.

### Who can add a key of a user with sudo (1.0.101)

A key of a member of wheel/sudo is root with a password, so the root helper does not add one
just because a file asks it to:

- **`db_guard` on** (*Settings → High security → Guard against writes to the database*): the
  helper adds such a key only when the ask carries the row of the database it comes from
  (`host:sshkeys:want:*`) with acme's signature of it. The helper checks that signature
  itself, with the key acme works out from `secrets.key`. The row must hold that very ask:
  its id, *add*, the user, the same key line, and not more than an hour old. An ask laid in
  `/var/lib/acme/web` by itself, or one whose row somebody wrote straight into the
  database, is refused (*db_guard is on: ...*) and nothing is added. A `config.json` that
  cannot be read counts as on. Each signed ask is done only once. Taking a key away needs no
  signature, and neither do the keys of a user without sudo.
- **`db_guard` off** (the default): the `acme` account can add a key of such a user - as it can
  ask the other things root does for it (the firewall, sshd, the network, the updates).
  Switch the guard on, on every node, wherever that matters.

Even with the guard on, it is defence in depth, not a wall between `acme` and root: `acme`
holds `secrets.key` (it seals every secret with it) and may write `config.json`. Code that
runs as `acme` can still sign an ask, or switch the guard off. What the guard stops is an
ask that did not come through acme's own signed rows: anybody who can only write the
database, or only drop a file into the helper's folder. See
[High security](high-security.md) (*What the acme account can do as root*).

## Every user who may sign in (1.0.240)

*Whose keys* picks root or a normal user of the nodes: UID_MIN to UID_MAX of
`/etc/login.defs` (1000 to 60000), with a login shell (not `nologin` or `false`). Local users
(`/etc/passwd`); directory users of sssd appear when the machine lists them.

Their own `~/.ssh/authorized_keys`: listed, a key added (a line of your own - its public line,
a `.pub` file, or a private key of which only the public half is used - onto the nodes you tick),
exported, taken away - on the nodes where the user is.

*A key for USER* (1.0.108: as root's card was until then) makes a fresh pair here - Ed25519, or
RSA 4096 where something old needs RSA. In a cluster, *The key for* picks **the same key on
every node** the user is on, or **only on** one node (a node the user is not on cannot be
picked). Its private half is shown once, to download or copy, and kept nowhere; its public half
goes into `~USER/.ssh/authorized_keys` of those nodes. A key there before stays until it is
taken away in the list. On the API: `{"action": "uk_make", "user": "USER", "scope": "all"}` or
`"scope": "NODE"` (without `scope`, the `nodes` given, as before).

The file is read and written **as that user** - by a child of the root helper that has their
UID, GID and groups: `~/.ssh` made 0700 and the file 0600, theirs; a link put there (to
`/etc/shadow`, to `/root/.ssh`) is refused and never followed, so nothing in a user's own home
can make root write anywhere else. A name that is not such a user (a system account, one with
`nologin`, `../root`) is refused. Every change is in Events, with the user's name.
