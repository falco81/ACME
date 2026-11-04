# The acme console

`acme --console` - the whole of acme by its menus, on the server's own screen or
over SSH. With `acme --console-at-login on` (what install.sh sets the first
time) it opens by itself when **root** signs in; **q** leaves it for the
ordinary shell, exactly as it was before, and `acme --console` opens it again.

It opens on the **live log** (every line); Esc goes to the main menu.

```
 acme 1.0.135  acme1   service active    node acme1 | 2 of 2 nodes, replication ok | VIP 192.0.2.10 on acme2

  Main menu

     c  Certificates: renewing, deploying, authorities, DNS
     1  Status and checks
     2  Live log
     3  Accounts of the administration
     4  Settings
     5  Directories (Active Directory, LDAP)
     6  Cluster, VIP address and maintenance
     7  Backups
     8  Upgrades
     9  The service
    10  The pages' certificates, updates, restarts, tests
    11  Encryption, sending out, time, network, high security

 Up/Down move   Enter choose   Esc back   ! shell   q leave
```

- **The bar at the top**: the version, the machine, whether the service runs,
  this node, the cluster and replication, **which node holds the VIP address
  (VRRP VIP)** - `VIP off` when it is switched off; a red line under the bar
  when no node holds it, or two do. Too narrow a window shortens it, or puts
  it on the line under it; asked again every 20 s without holding
  anything up. Maintenance, a daemon not answering and the problems of
  `acme --status` are on the lines under it.
- **The menus** are a text screen: arrows (or j/k) move, Enter or → chooses,
  Esc, ← or Backspace goes back, a number jumps to its item (`1` `1` is 11),
  Home/End and PgUp/PgDn, `!` a shell, `q` leaves. Only what changed is
  written, so nothing blinks; made bigger or smaller (PuTTY too), the screen
  is drawn again to its size.
- **Nothing is typed at a bare prompt.** Every question is a window over the
  menu: its fields one under the other - Up/Down (Tab) move between them, a
  choice (a key type, a role, on / off) is changed with Left/Right, a
  password shows only stars, the field's help is under them - and Enter checks
  them all before anything is run (a needed one left empty, a number out of
  its limits, an address that is none, two passwords not the same, a file
  that is not there: it says which, and the window stays). Esc closes it.
  Anything that cannot be undone (delete, put a copy back, switch off, a
  restart, an upgrade) asks Yes / No first - No unless chosen.
- **Lists**: certificates, jobs, targets, accounts, directories and the
  backups kept here are lists to scroll - arrows, PgUp/PgDn, Home/End, a
  scroll bar on the right, `/` to keep only the rows with some words - and
  Enter on one offers what can be done with it:
  - a certificate: show it all, renew it now, deploy it now, export it into a
    file;
  - a job: every step, live; a target: try it;
  - an account: set its password, change its role, switch it off / on, reset
    its second step, show it, delete it;
  - a directory: try it (and look somebody up), show it, change it, delete it;
  - a backup: what is in it, put it back.
- Every action is the `acme …` command its window shows in its title, run as
  it would be typed - the console can do nothing the command line cannot. A
  short answer comes in a window; a long one on a screen of its own to scroll
  (arrows, PgUp/PgDn, Home/End, a scroll bar; Esc, q or Enter back).
- **Settings → Browse and change**: every setting in its group, Enter opens a
  window with its help, what it is now and as it comes, and what it may be;
  checked as the daemon checks it before it is saved. **Change one by its
  key** opens the same window for a key typed.
- **Cluster**: maintenance of this node (on / off, why), the VIP address moved
  to a node picked from the list (the one holding it marked), replication
  paused / resumed. **Upgrades → from the web**: what is newer at
  upgrade_url, a version picked, Yes, then every node upgraded one at a time
  with its progress bars.
- **Certificates** (`c`): everything the Certificates pages do - the
  certificates (browse: show, renew, deploy, its deployments, change, export,
  a CSR and its answer, revoke, delete; add one; renew every one due now),
  the jobs (followed live, stopped), the live log of the certificates, the
  sources, validations and targets (show, add, change, rename, switch off,
  try, a module's actions such as *Prepare the hosts*, delete), the
  deployments (add, run, change, switch off, take away), acme's own
  authorities (show, new root, new intermediate, import, CRL, export, sign a
  CSR, revoke, delete), acme's own DNS server (its records) and the modules
  (what each takes). A module's form is drawn from its fields: a choice for a
  select or an on/off, a secret as stars - handed over in the environment,
  never on a command line - and a PEM read from a file. Each item runs the
  `acme` option of [command-line.md](command-line.md) it says.
- **Directories**: a directory added or changed in a form (its servers, where
  to look, the account it reads with, LDAPS / StartTLS; its password asked,
  shown as stars).
- **The pages' certificates, updates, restarts, tests** (1.0.187) - what the
  pages do, for a server without them (installed `--no-web`) or with them
  down: the pages' own certificates by ACME and one ordered now, followed; the
  updates of the system looked for, put in one node at a time, or stopped; a
  machine restarted, the service kept on the others; a test mail or SMS; who
  is locked out, and a lockout forgotten on every node.
- **Encryption, sending out, time, network, high security** (1.0.188): the
  encryption to the database server and to isemon looked at and tried, a
  test line to isemon and to the syslog servers, the proxy tried, SNMPv3
  asked, and the rest of those pages.

## The live views

The live log (`/var/log/acme/acme.log`), a job followed live and the
journal (`journalctl -u acme -f`) are screens of their own:

- The newest line at the bottom, followed as it comes (`following`).
  Up/PgUp/Home scroll back - the view then stays where it is (`PAUSED, 12 new
  below`) - and Down/PgDn to the end, End or Enter follow again. Left/Right
  move sideways along long lines. A scroll bar on the right says where you
  are; the last 20 000 lines are kept.
- **Whatever is typed is a grep**, as `grep -i`: the lines with it, in any
  case, stay; the hits are marked. A regular expression works
  (`failed|locked`, `www.*renew`); text that is not one is taken as it is.
  Backspace takes a character back, Ctrl+U all of them; Esc clears it, and
  Esc again goes back to the menu.
- Coloured (colorama): the time dim, the level by how bad, what it is about in
  cyan, addresses in magenta, accepted / signed in green, rejected / failed /
  wrong in red, a warning line yellow and an error line red.
- Colour with colorama when it is installed (install.sh installs it); without
  a colour terminal, or with `--no-color`, plain text. English.
- `ACME_CONSOLE_START=menu acme --console` opens on the menu instead.

## At login

`/etc/profile.d/zz-acme-console.sh` opens it for root in an interactive login
shell only - never for a command run over SSH (`ssh acme1 uptime`), scp or
sftp, a script, a shell opened from the console itself (`!`), or when
`ACME_NO_CONSOLE=1` is set (`ssh -t acme1 ACME_NO_CONSOLE=1 bash -l`).

```bash
acme --console-at-login off      # root lands in the shell; acme --console still works
acme --console-at-login on
acme --console-at-login status
```

The choice is `/etc/acme-console-login` (`on` / `off`); an upgrade leaves it as
it is. `install.sh --uninstall` takes the profile script away.

On the pages (1.0.141): **Settings → About → The console at login**, a switch
for each node of the cluster (full administrators). The node's own root helper
writes `/etc/acme-console-login`; each node says within a minute how the file is,
so a change made with `acme --console-at-login` shows there too. Every switch is
in Events.

### For normal users too (1.0.240)

The console can open at login for normal users of the machine as well (UID 1000 and up,
a login shell) - the ones named, or every one:

```bash
acme --console-users "alice bob"   # these two
acme --console-users '*'           # every normal user
acme --console-users none          # root only, as before
```

On the pages: **Settings → About → The console at login**, beside each node's switch:
*normal users: nobody / every one / these…*.

It runs **through sudo, with the user's own password** - the console does what only root may,
so only who may become root with sudo gets it (the `wheel` group, or a sudoers rule of their
own). Anybody else named is told so in one line and keeps the ordinary shell: nobody gets more
than they already have. Changes made from such a console are in Events as
`command line (sudo alice)`.

The file gets a second line: `users: alice bob` (or `users: *`); root's own switch (`on` /
`off`) is the first line, as before, and either is changed without the other.
