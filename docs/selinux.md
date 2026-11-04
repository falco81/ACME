# SELinux

*Settings → High security → SELinux* (as otp 1.0.233), a card for each node; on the server
`acme --selinux-check` (as root). **Nothing changes unless somebody asks:** a machine
where SELinux is disabled stays disabled, and acme runs on it exactly as before.

## What acme needs of it

With SELinux enforcing (RHEL, Rocky, AlmaLinux - the *targeted* policy), the daemon,
its root helper and the upgrade run unconfined, as every service started from
`/usr/local` does. Confined are the programs around them, and these need a few
things the system's policy does not say by itself:

| What | Why | How |
|---|---|---|
| `/run/acme` and the API token labelled `httpd_var_run_t` | the pages (php-fpm, `httpd_t`) read the token; systemd makes `/run/acme` as `var_run_t`, which `httpd_t` may not read | acme's module **`acme_server`** (`/usr/local/lib/acme/acme_server.cil`): file labels only, no rule of its own - for `/run/acme` and `/var/run/acme` both (as otp 1.0.234), as the policy reads one as the other (`file_contexts.subs_dist`: `/run` ↔ `/var/run`) |
| `httpd_can_network_connect` on | the pages ask the daemon on `127.0.0.1:9861` (`api_port`) | a boolean |
| sshd's port as `ssh_port_t` | sshd on a port other than 22 | `semanage port` |
| PostgreSQL's port as `postgresql_port_t` | a local PostgreSQL on a port other than 5432 | `semanage port` |
| systemd may change the owner of what is in `/run/acme` | before every command of the unit (`systemctl reload acme` too) systemd hands `/run/acme` back to the service's account - seen on a node as `init_t → httpd_var_run_t file { setattr }` | a rule of `acme_server` (as otp 1.0.237): owner and mode only, nothing read or written |
| `/var/www/acme`, `/usr/libexec/keepalived/acme-vip-check` | the pages; keepalived's check, which may run unconfined from there | the system's own labels (`restorecon`) |

`install.sh` and every upgrade copy the module beside the program, and put it into the
policy where SELinux is on (only when it changed - `semodule` takes its time), and say so
when the policy still does not label `/run/acme` for the pages (`matchpathcon /run/acme`).
Where SELinux is disabled they do nothing more. `--uninstall` takes the module out; the mode,
the booleans and the ports are the machine's and stay as they are.

## The card

Per node: the mode now and after the next restart, acme's module, the labels of its files,
the booleans and ports above, and **what SELinux refused since the machine started**
(`ausearch -m AVC,USER_AVC -ts boot`, for the web server, keepalived, sshd, chronyd,
PostgreSQL, rsyslog, logrotate and anything with acme in it). acme's own DNS server for
DNS-01 (port 53) is the daemon itself, unconfined: SELinux has nothing to say about it, grouped and counted.
Looked at two minutes after acme starts and every half hour after that, and at once with
*Look again*; `semanage`, `semodule -l` and `ausearch` run at the lowest CPU and disk
priority (as otp 1.0.234). **What was refused before acme's needs were last put in no longer
counts** (as otp 1.0.234): *Put in what acme needs*, when it changes anything, starts the count
again - no second restart is needed after the first permissive start. *Switch to
enforcing* never starts it again. **What the policy loaded now allows no longer counts either**
(as otp 1.0.238): every kind refused is put to `audit2why`; one it says *would be allowed by active
policy* - a newer `acme_server` from an upgrade, a boolean switched on since - is shown as allowed
now and not counted, without the button pressed again. **auditd** must run: without it nothing is written down,
and enforcing is refused.

The steps, each asked of that node only and done by its root helper:

1. **Make it ready (permissive)** - from *disabled*: `SELINUX=permissive` in
   `/etc/selinux/config`, every file labelled at the next start (`/.autorelabel`),
   `selinux=0` taken off the kernel's command line (`grubby`) where it is there, acme's
   module put in. **The machine is not restarted**: restart it when it suits
   (*Settings → Restart and power off*), one node at a time - the labelling takes a few
   minutes before it answers. It comes up permissive: nothing is refused, what would be
   is written down. On a permissive node the same button (*Put in what acme needs*) puts
   in the module, the booleans and the ports and labels acme's files again.
2. Let it run a day or two as it is used - sign-ins, the pages, renewals and deployments,
   a failover, an upgrade, a backup - then *Look again*.
3. **Switch to enforcing** - only from permissive, and only once nothing acme needs is
   missing **and nothing was refused since the start**: `setenforce 1` and
   `SELINUX=enforcing`. Refused otherwise, with what is missing.
4. **Back to permissive** - at once (`setenforce 0`) and after a restart.

Every step is written in Events with who asked; the security check lists what keeps a
node where SELinux is on from being protected as it should (on a disabled node it says
nothing, as before). With the guard against writes to the database on, a step written
straight into the database is not done.

## The report, for acme's module (as otp 1.0.236)

*Download the report (all nodes)* on the card asks every node to gather what SELinux says there,
and gives one file with a folder of each node in it; on the server `acme --selinux-report` makes
the same for that node (`/root/acme-selinux-report-NODE-DATE.tar.gz`). Nothing is changed to
make it. In it: what SELinux refused since the start (raw and readable, `audit2why`, and
`audit2allow`'s suggestion - a hint, never loaded), the card's state, the labels of acme's files
and what the policy says they should be, the domains the programs run in, the ports and the
booleans, the system's and the policy's versions, and what acme uses on the node (switches and
ports - no password, key or token). The audit log holds the command lines of the programs
something was refused to: acme never puts a secret on one, other programs may - look through
`avc*.txt` before sending it on. From the pages a node's report is kept sealed in the database
an hour, so that whichever node answers gives every node's.

Sent to whoever writes acme, it becomes rules of `acme_server` - labels, booleans and ports first,
a narrow `allow` only where nothing else does - so that a new installation needs less of it.

## The tools

On RHEL, Rocky and AlmaLinux every install and upgrade puts in what is missing of
`policycoreutils`, `libselinux-utils`, `policycoreutils-python-utils`, `audit` and
`selinux-policy-targeted` (as otp 1.0.236) - with SELinux disabled too, the mode is not touched - and
starts auditd where SELinux is on. Without a repository it says what is missing and goes on.

## On the server

```bash
acme --selinux-check            # how it stands; exit 1 when something is missing
```
```bash
acme --selinux-check --json
```
```bash
acme --selinux prepare          # check | prepare | apply | enforce | permissive - asked first
```
```bash
acme --selinux-report           # the report of this node, as a file
```
The console (`acme --console`) has the same in *Encryption, sending out, time, network, high
security*.

Something refused that acme did not foresee: `ausearch -m AVC -ts boot | audit2why`
says why, and `audit2allow -M acme-local` makes a local module of it - send the
output of `acme --selinux-check` so it can go into `acme_server`.
