# SSH keys on the pages

*Settings → SSH keys* (full administrators): the keys that may sign in to each node over SSH,
read from every node, a column a node.

## Root (1.0.158)

The lines of `/root/.ssh/authorized_keys`. A key made here (Ed25519, or RSA 4096) has its
private half shown once and kept nowhere; one of your own is put on by its public half - on
every node or on one. Taking away the last key root signs in with is said first.

## Every user who may sign in (1.0.240)

*Whose keys* picks root or a normal user of the nodes: UID_MIN to UID_MAX of
`/etc/login.defs` (1000 to 60000), with a login shell (not `nologin` or `false`). Local users
(`/etc/passwd`); directory users of sssd appear when the machine lists them.

Their own `~/.ssh/authorized_keys`, as for root: listed, a key added (a line of your own, or
made here - its private half shown once to hand over), exported, taken away - on the nodes
where the user is.

The file is read and written **as that user** - by a child of the root helper that has their
UID, GID and groups: `~/.ssh` made 0700 and the file 0600, theirs; a link put there (to
`/etc/shadow`, to `/root/.ssh`) is refused and never followed, so nothing in a user's own home
can make root write anywhere else. A name that is not such a user (a system account, one with
`nologin`, `../root`) is refused. Every change is in Events, with the user's name.
