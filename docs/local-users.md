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

## The guard of root's actions

The rows a change is asked in (`host:users:want:…`) are among those the guard signs
(*High security → the guard of root's actions*): with it on, a row written straight into the database -
a user with sudo, say - is done by no node.

## Command line and console

```
acme --local-users                                   # the users of each node
acme --local-user add jnovak --local-full-name "Jan Novák" --local-must-change   # the password is asked
acme --local-user password jnovak                    # asked at the terminal, twice
acme --local-user sudo-on jnovak                     # sudo-off
acme --local-user lock jnovak                        # unlock
acme --local-user drop-home jnovak                   # drop: the home folder kept
acme --local-user lock jnovak --local-nodes acme2     # one node only
```

In `acme --console`: *The pages' certificates, updates, restarts, tests → Local users of the nodes*, *Add a local
user*, *A new password for a local user*, *Lock, unlock, sudo or take away a local user*.
