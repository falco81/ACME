# Local users of the machines - 1.0.243

*Settings → Local users* (full admin only): the users of each node's own system - who may sign in to
the machine itself, over SSH or at its console. They are not the accounts of these pages (*Accounts*).

In a cluster every change goes to **every node at once**, or to the nodes you tick; a standalone server
has the one node. Each node's root helper (`acme_web.py`, `acme-web.path`) does it with the system's own
tools - `useradd`, `usermod`, `chpasswd -e`, `chage`, `gpasswd`, `userdel` - exactly as an administrator
would at the console.

## What is shown

One row a user, a column a node: whether the user is there, locked there, or there with another UID.
Above the list, the accounts with no shell (often a package's) are hidden until *Also the N accounts
with no shell* is ticked. A user's pencil opens the facts node by node - UID, home folder, shell,
groups, the password (none / set on a day / to be changed at the next sign-in), locked or not, sudo.

**root** is first and **shown only**: its password, its shell and whether it may sign in are changed
on the machine itself, never from these pages - the API refuses any change of it. Accounts of the
system (outside `UID_MIN`..`UID_MAX` of `/etc/login.defs`) and the services' own (acme, acme-web, postgres, mysql,
nginx, sshd…) are neither shown nor changed.

## What can be done

| | |
|---|---|
| **Add a user** | name, full name, shell (from `/etc/shells`), a password (or none: SSH keys only), *to be changed at the first sign-in*, sudo; the same UID on every node - the lowest of the normal range no node uses |
| **Make it on more nodes** | a user on one node only made on the others too, with its UID |
| **Name and shell** | the full name (GECOS) and the shell |
| **Password** | a new one, typed twice; *to be changed at the next sign-in* if wanted |
| **Give / take sudo** | membership of `wheel` (RHEL) or `sudo` (Debian, Ubuntu) - root with their own password |
| **Lock / unlock** | locked: the password put out of use *and* the account expired - no SSH key lets them in either; nothing of theirs is taken away |
| **Take the user away** | `userdel`, with the home folder or without; refused while they are signed in or run something |

The SSH keys of a user are in *SSH keys* (*Whose keys*) once the user is there; who may sign in over
SSH at all is in *SSH server and notices*.

## The password

Typed on one node's page, it never leaves that node as itself: the node makes its hash (SHA-512 crypt,
`openssl passwd -6` from standard input), seals it with the cluster's key, and asks that of each node.
Each node's root helper hands it to `chpasswd -e` on its standard input - never on a command line, never
in a log. Once a node said it is done, the sealed hash is taken out of the asking row (after 15 minutes
in any case); Events say who changed which user on which nodes, never the password.

## The password policy (1.0.43, as otp 1.0.245)

The card **Password policy** under the users: one policy for every local user of the cluster, put in
by each node into its system's own files - so it holds however a password is changed (`passwd`, a
password run out at sign-in, these pages). **Off by default**: each node as its system has it, nothing
written; switched off again, every file is put back as it was.

| Rule | Where each node puts it |
|---|---|
| characters at least, kinds, the same character in a row, characters not in the old one, no word of the dictionary, not the user's name (`retry = 3`) | `/etc/security/pwquality.conf.d/50-acme.conf` (a drop-in; `pwquality.conf` itself untouched) |
| the last N passwords not taken again | `/etc/security/pwhistory.conf`, acme's lines between marks |
| locked after N wrong, for how long, counted within | `/etc/security/faillock.conf`, acme's lines between marks - `even_deny_root` never: root is never locked |
| good for, warned before, the least days between two changes | `/etc/login.defs` (`PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`); what it had is kept in it, commented between acme's marks (`# acme-was: …`) |

The marks: `# ---- acme: Settings -> Local users -> Password policy (from here) ----` and
`# ---- acme: (to here) ----`; the rest of each file stays as it was, a link is refused, a file is written
only if its text changes. With **authselect** (RHEL), `with-pwhistory` and `with-faillock` are switched
on where needed - and off again, only those acme switched on (kept in `/var/lib/acme/pwpolicy-orig.json`).
*Also for the users there now* puts the days (`chage -M -m -W`) on every normal user with a password;
users with no password (a key only) are left without - sshd's account step would ask them for a new one.
acme 1.0.42's own file `pwquality.conf.d/90-acme.conf` is taken out, and its settings taken over once.

A password typed on these pages is checked first - by `pwscore` where it is there, otherwise by the rules
set here (length, kinds, repeats, the name). Each node's light says *as set here*, *being put in…*,
*refused* (pointed at: why) or *not answering*; *In effect on the nodes* shows what each has, read from its
files and PAM.

**A user's own aging**: their popup has *Password aging* (good for, warned before, the least days between
two changes; *The password runs out on …*), saved on the nodes chosen. A user made with no password gets no
aging; given a password later, the policy's. Adding a user with sudo and no password is refused (sudo asks
for their own password), and the popup says when a user may use sudo but has none.

With SSH keys, acme's codes and sudo: a password that runs out is to be changed at the next sign-in over SSH
too, with a key or a code (sshd asks PAM's account step); acme's SSH code is no password - never counted for
the lockout, never kept out by it; sudo (and `acme --console` of a normal user through it) asks for the
user's own password, so the policy is the one for it.

## The guard of root's actions

The rows a change is asked in (`host:users:want:…`) are among those the guard signs
(*High security → the guard of root's actions*): with it on, a row written straight into the database -
a user with sudo, say - is done by no node. The row of the policy (`host:pwpolicy:conf`) is signed too: a
row the guard refuses changes nothing - each node keeps the policy it has put in.

## Command line and console

```
acme --local-users                                   # the users of each node
acme --local-user add jnovak --local-full-name "Jan Novák" --local-must-change   # the password is asked
acme --local-user password jnovak                    # asked at the terminal, twice
acme --local-user sudo-on jnovak                     # sudo-off
acme --local-user lock jnovak                        # unlock
acme --local-user drop-home jnovak                   # drop: the home folder kept
acme --local-user lock jnovak --local-nodes acme2     # one node only
acme --local-user aging jnovak --local-max-days 90 --local-min-days 1 --local-warn-days 7
acme --local-policy                                  # as set, and as in effect on each node
acme --local-policy-set managed=1 minlen=14 minclass=3 max_days=90 deny=5 existing=1
acme --local-policy-set managed=0                    # as each system has it
```

In `acme --console`: *The pages' certificates, updates, restarts, tests → Local users of the nodes*, *Add a local
user*, *A new password for a local user*, *Lock, unlock, sudo or take away a local user*, *The password
policy of local users: how it stands*, *Set the password policy of local users*.
