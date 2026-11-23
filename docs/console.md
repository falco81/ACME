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
     o  Owners and teams: the tree, members, roles, limits, access
     p  Reports and team digests: periodic reports, digests by mail
     h  History, trash, request profiles, the agent fleet
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
  authorities (show, new root, new intermediate, import, change it - its
  name, days, CRL / CA certificate / OCSP addresses, key usages, note, switched
  off, `acme --ca-edit` -, CRL, export, sign a CSR, revoke, release a hold,
  renew, its versions, delete), acme's own DNS server (its records) and the modules
  (what each takes). Since 1.0.77 also: **Tests** (`t`: add, change, try, run,
  its SSH key, delete), a certificate's **tests** (attach, run, after which
  deployment, switched off for that certificate, take off), **Run the tests**
  (`r`) with a report by mail and / or SMS, **import** (`i`) a certificate or a
  new version of one, a **self-signed** one (`s`), a certificate switched off
  and on, **Change the source** (by hand ↔ an authority, keeping its
  deployments and tests; the first certificate then or at the next renewal),
  and **the SSH key** of a target, validation or test (make, the public half,
  your own, try, forget). A connector is not offered as a place to deploy to;
  *Renew it now* and the validation's checks are not offered for a certificate
  by hand. A module's form is drawn from its fields: a choice for a select or
  an on/off (a value set that is not offered now - a CA switched off - stays
  as it is, marked so), a secret and an SSH key as stars - handed over in the
  environment, never on a command line - a PEM read from a file, and a value
  of several lines shown on one line with ⏎ between them. The fields under
  *More* that depend on a main one (a DNS server's flavour) are asked too.
  Since 1.0.140 also: **Find anything** (`f`, `acme --find`: a certificate by
  its name, a SAN or its serial, a deployment, a target, an agent, a source,
  an authority, a profile, a team, an account, an event; Enter shows it),
  **the expiry calendar** (`y`: what runs out week by week, optionally of one
  team, `acme --calendar`; a file for a calendar program, `acme
  --calendar-ics`; who has a link to subscribe, and taking one back) and
  **request profiles from a template** (`p`: the templates with their
  compliance; Enter asks the name, the domains and the source and makes the
  profile, `acme --profile-from-template`).
  Since 1.0.141 also: on a certificate **What happens** (everything a renewal
  would do, step by step, nothing done - `acme --run-plan NAME`), on a
  deployment **Preview** (the files it writes, what its script is given -
  `acme --deploy-preview ID`) and **Test it** (the files into a temporary
  folder on the target, nothing put in place - `acme --deploy-dry-run ID`),
  and **Show what a file holds** (`v`: a certificate, a chain, a CSR, a CRL,
  a key, PFX - `acme --inspect FILE [--password]`).
  Each item runs the `acme` option of [command-line.md](command-line.md) it
  says.
- **Target agents** (`c` → *Target agents*, 1.0.140 too): **Where keys are made**
  (`7`) - every certificate deployed to a server with an agent, its key made on
  the server or acme's, which could switch and why the others cannot; Enter on
  one that could switch offers *At its next renewal* or *Now* (`acme
  --agent-keys-switch CERT [--now]`), on one waiting for its renewal *Take the
  switch back* (`--agent-keys-cancel`); **The CAs acme knows** (`8`, `acme
  --agent-cas`: what `allow issuer sha256=...` names). A target's agent menu has
  **What it checks of what it deploys** (`acme --agent-guard NAME`: its `allow
  issuer`, `allow names`, `require key local` and each deployment there judged).
- **Directories**: a directory added or changed in a form (its servers, where
  to look, the account it reads with, LDAPS / StartTLS; its password asked,
  shown as stars; whether its certificate is checked, old weak certificates,
  its CA from a file). The port is kept only when it was changed: from LDAPS
  to StartTLS it becomes 389 by itself.
- **Keys**: an item's own letter chooses it (`c`, `k`, `t`...), as a number
  does; Ctrl+C anywhere goes back, as Esc - it no longer ends the console. A
  list whose command failed says what went wrong instead of "none yet".
- **The pages' certificates, updates, restarts, tests** (1.0.187) - what the
  pages do, for a server without them (installed `--no-web`) or with them
  down: the pages' own certificates by ACME and one ordered now, followed; the
  updates of the system looked for, put in one node at a time, or stopped; a
  machine restarted, the service kept on the others; a test mail or SMS; who
  is locked out, and a lockout forgotten on every node.
- **Encryption, sending out, time, network, high security** (1.0.188): the
  encryption to the database server and to isemon looked at and tried, a
  test line to isemon and to the syslog servers, the proxy tried, SNMPv3
  asked, and the rest of those pages; isemon's **first full sync** (1.0.77).

- **History, trash, request profiles, the agent fleet** (`h`, 1.0.140 - what the pages got in
  1.0.138): the latest changes (Enter: the whole history of that object, or that version again),
  the trash (bring it back, under another name, delete it for good), the request profiles (show,
  versions, compare a version with now, restore one, a dry run for some names, end it with a
  successor or take that back, delete), their compliance check, the agent fleet, the
  certificates found on the servers that acme does not manage (Enter: take over), the drift of
  the agents from their templates, an update in rings (plan, start, go on, stop) and the keys of
  the agents - `acme --history`, `--trash...`, `--profile-...`, `--fleet...`
  ([command-line.md](command-line.md)). A target's agent menu has **Watching it** (the audit
  chain, anomalies, what it serves, its keys; switched on and off in a form), *Read and check its
  audit chain now*, *Ask what its services serve now*, *Looked at* and *Change its keys now*
  (`acme --target-agent NAME watch|watch-set|audit-verify|served|ack|rotate`). Since 1.0.141
  **Groups of agents** (`h` → `g`): Enter on one changes it in a form - its agents, the template
  they follow, the canary ring - shows an update in rings with it first, or deletes it; *+ a new
  group* makes one (`acme --fleet-group-save NAME --fleet-members A,B --fleet-template REF|-
  --fleet-canary yes|no`, `--fleet-group-del`, `--fleet-rollout plan GROUP`).
- **Owners and teams** (`o`) has, since 1.0.140, the teams' health (`7`), the requests for a
  temporary role to decide (`8`: approve, or decline with why), the access reviews open now
  (`9`), *Who may do what, and why* (`w`), the team templates (`m`: Enter on one makes a
  new team from it or deletes it - `--team-from-template`, `--team-template-del`), *Who can do
  one thing in a team or on a certificate* (`n`, `--who-can`) and *Teams from a CSV file* (`i`:
  each row said first, then made - `--teams-import-csv`); a team's own menu its
  health, its governance, its access reviews (show, open one, confirm or take out a member),
  its requests for a temporary role (Enter ends one), *Try its channels now* and *Save it as a
  team template* (with its members or without - `--team-template-save`) - `acme --team-health`,
  `--team-gov`, `--reviews`, `--review-open`, `--review-answer`, `--elevations`,
  `--elevation-approve`, `--who-may`, `--team-templates`, `--team-notify-test`. Since 1.0.141
  a team's governance is changed there too (*Change its governance*), each part in a form of
  its own: access reviews (how
  often, the days to answer, reported or taken out), temporary roles (which roles, for how many
  hours), separation of duties (no self-approval, pairs nobody holds both of: `Requester +
  Approver; cert.key + cert.revoke`) and its channels (the team's, its manager's and on-call
  addresses, the days before the end, where a failed deployment goes, whether requests and
  reviews are told) - each on or off (`acme --team-gov-set TEAM JSON`; the webhooks stay sealed:
  `acme --api POST /api/teams/hooks -`).

- **Reports and team digests** (`p`, 1.0.140): the reports (show, run now, run and mail,
  their runs, save a run's CSV or PDF on this machine, change - with the runs kept, the days
  ahead and a paused schedule - delete; add one) and each team's digest (show, set - with the
  teams below and the language - preview, mail a preview to an address, send now) -
  `acme --reports`, `--report-...`, `--team-digest...` ([command-line.md](command-line.md)).

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
