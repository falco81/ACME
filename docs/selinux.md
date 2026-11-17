# SELinux

*Settings → SELinux* (since 1.0.120, as fake-igd's kit; before that a card under *High security*,
as otp 1.0.233); on the server `sudo acme --selinux look`. **Nothing changes unless somebody asks:**
a machine where SELinux is disabled stays disabled, and acme runs on it exactly as before.

**SELinux is each machine's own.** In a cluster every node has its own mode, its own module, its
own refusals and its own fixes. The card shows one node at a time - a pill for each node at the top,
with a dot (green: enforcing and nothing left; amber: something to do; red: not heard from; grey:
disabled) - and whatever is asked on it is asked of the node shown and done by that node's root
helper only. Nothing of it is a setting: no switch is replicated to the other node, and an id found
on one node is refused on the other.

## Who is who (what SELinux sees of acme)

| Who | Domain | What it needs |
|---|---|---|
| nginx, php-fpm (the pages, the agents' port, the certificate sign-in port) | `httpd_t` (confined) | read the pages (`httpd_sys_content_t`); read the API token in `/run/acme` (labelled `httpd_var_run_t` by acme's module); connect to the daemon on `127.0.0.1:api_port` (boolean `httpd_can_network_connect`); listen on 80, 443 and the certificate's / agents' ports (`http_port_t`) |
| the daemon (`acme.service`, `NoNewPrivileges=yes`), its root helper (`acme-web.service`), the upgrade, the database agent | `unconfined_service_t` | nothing for themselves - their own listeners (the API, the DNS server for DNS-01, the SNMP agent, the gate for SSH with a code) need no port type. But every tool the daemon runs **that has a domain of its own** - `ssh`/`sftp`/`scp` (`ssh_t`), `ssh-keygen` (`ssh_keygen_t`), `ping` (`ping_t`), `ip` (`ifconfig_t`), `hostname` (`hostname_t`), `chronyc` (`chronyc_t`) - needs `process2 { nnp_transition nosuid_transition }` because of `NoNewPrivileges` |
| systemd (`RuntimeDirectory=acme`) | `init_t` | set owner and mode in `/run/acme` |
| sshd (the console, on its own port) | `sshd_t` | the port labelled `ssh_port_t`; with *SSH with a code* `authlogin_radius` and the gate's UDP port as `radius_port_t` |
| keepalived (the cluster's VIP address, VRRP) and its check `/usr/libexec/keepalived/acme-vip-check` | `keepalived_t`, the check in `keepalived_unconfined_script_t` | the check labelled `keepalived_unconfined_script_exec_t` (the system's policy and acme's module both say so): run in `keepalived_t` instead, it could not read `/run/acme/vip-state` and the address would leave a node that may hold it |
| PostgreSQL (the replication between the nodes) | `postgresql_t` | the other node's port as `postgresql_port_t` when it is not 5432; reading `/etc/pki/acme/ha-ca.pem` (`cert_t`) for the encrypted link - a rule of acme's module; its own certificate of the link (`acme-ha.crt`, `acme-ha.key`) is in its data folder, labelled as the rest of it by `restorecon` |
| chronyd, logrotate, rsyslog/journald | their own | only where they touch acme's files |

## acme's module - `acme_server`

`/usr/local/lib/acme/acme_server.cil` (CIL), put in with `semodule -i`, taken away with
`semodule -r acme_server`. Labels first, a narrow rule only where no label or boolean does it,
**each rule in an `(optional …)` block of its own** - a policy without one of the types still takes
the rest:

- `/run/acme` and `/var/run/acme` (both spellings: the policy reads one as the other through
  `file_contexts.subs_dist`) as `httpd_var_run_t`;
- `/usr/libexec/keepalived/acme-vip-check` as `keepalived_unconfined_script_exec_t` (optional);
- `init_t` may change owner and mode in `/run/acme` (nothing read, nothing written);
- `postgresql_t` may read `cert_t` (the authorities of the link between the databases);
- `unconfined_service_t` may go to `ssh_t`, `ssh_keygen_t`, `ping_t`, `ifconfig_t`, `hostname_t`,
  `chronyc_t` under NoNewPrivileges (`process2 { nnp_transition nosuid_transition }`), each in a
  block of its own.

Checked with `secilc` against the reference policy (Debian's / Ubuntu's `selinux-policy-default`
2.20240202, its modules turned into CIL with `/usr/libexec/selinux/hll/pp`), once as it is (the
RHEL-only types `unconfined_service_t` and `keepalived_*` missing: those blocks are left out, the
rest goes in) and once with a stub declaring them (every block in). `test/test_selinux_findings.py`
does it when given `ACME_SECILC` and `ACME_REFPOLICY_CIL` (and `ACME_SECILC_LD` for the library
path).

## The installer

`install.sh` - a fresh install and every upgrade, with the pages or without (`--no-web`):

1. puts in what is missing of `policycoreutils libselinux-utils policycoreutils-python-utils audit
   selinux-policy-targeted` (RHEL, Rocky, AlmaLinux; offline: said, not fatal) and starts `auditd`
   where SELinux is on - without it nothing refused is written down. **It never changes the mode.**
2. copies the module beside the program and puts it into the policy **only when it differs** from
   the copy last put in (`acme_server.cil.in-policy`, written only after `semodule -i` went
   through): an upgrade without a change does not reload the policy;
3. `setsebool -P httpd_can_network_connect 1`, `restorecon -R` of `/run/acme`, the pages and
   `/usr/libexec/keepalived`; says so when `matchpathcon /run/acme` still does not say
   `httpd_var_run_t`;
4. `--uninstall`: `semodule -r acme_local` and `semodule -r acme_server`, and root's notes of the
   card (`/var/lib/acme-net/selinux-*.json`, `acme_local.cil`) go; the mode, the booleans and the
   ports labelled are the machine's and stay.

## The card - Settings → SELinux

### The checks

A dot a line, as the node found it: acme's module in the policy; the labels of `/run/acme`, the API
token, the pages and keepalived's check; `httpd_can_network_connect` (and `authlogin_radius` with
*SSH with a code*); the ports acme needs labelled (sshd's when not 22, PostgreSQL's and MariaDB's own
when not the usual, the other node's PostgreSQL, the gate's UDP port); how much was refused since
the machine started; auditd running; the mode now and after the next restart
(`/etc/selinux/config`, `selinux=0` on the kernel's command line).

### What SELinux refuses - *Look again* is a full analysis

The node's root helper reads every `AVC`, `USER_AVC` and `SELINUX_ERR` since the machine started
(`ausearch -ts boot`) **with the records of its event** - SYSCALL (the program, its file), PATH and
CWD (the whole path), PROCTITLE - with the strings hex-encoded by the audit system decoded (only
`proctitle name path comm exe cwd`, never a port), groups them by *(source type, target type, class,
permissions, program, path or port)*, puts each group to `audit2why`, and sorts it into one kind:

| Kind | Meaning | Put right by |
|---|---|---|
| allowed now | the policy loaded now allows it (a newer module, a boolean since) | - (not counted, not shown) |
| **A boolean** | audit2why names a boolean | `setsebool -P NAME 1` - never one that allows far more (`*exec*`, `unconfined`, `*manage_all*`, `*read_all*`, `ptrace`, `deny_*`, `nsswitch`, `nis_enabled`, `use_nfs`, …) |
| **A label** | the file is not labelled as `matchpathcon` says | `restorecon -R -v FOLDER` (or the file) - only acme's paths |
| **A port** | a confined program acme works with (nginx, sshd, PostgreSQL, chronyd…) binds or connects to one of acme's ports, which has no type of its own | `semanage port -a -t TYPE -p PROTO PORT` (`http_port_t`, `ssh_port_t`, `postgresql_port_t`, `ntp_port_t`…) - never a port another service's type has |
| **A rule of acme's** | nothing of the policy allows it, and it is safe to allow exactly that | one rule in acme's **local module** `acme_local`: `(optional acme_local_ID (allow SRC TGT (CLASS (PERMS))))` |
| **Not for a button** | acme's, but too much to allow from a page | shown in red with *why* - a security-sensitive target (`shadow_t`, `security_t`, the policy, `kernel_t`, keys, audit, `sudo`, home…), running or changing far more (`execute`, `entrypoint`, `exec*`, `transition`, `ptrace`, `relabel*`, capabilities such as `sys_admin`, `dac_override`), classes of the kernel's or the policy's own (`security`, `system`, `service`, `key`, `bpf`…), writes to the types of the whole system (`etc_t`, `usr_t`, `bin_t`, `var_t`, `var_log_t`, `tmp_t`…), `default_t`/`unlabeled_t`, a boolean that allows too much, another service's port, an SELinux error, a constraint |
| **Not acme's** | another program of the machine | shown in grey, never put right here |
| *Put right just now* | put right on this card or with `acme --selinux fix` | green, until the next look an hour later; refused again after that, it comes back |

A finding's **id** is a hash of what was refused (12 hex): the same refusal has the same id at every
look - of that node.

**Whose refusal it is.** acme's own programs (`unconfined_service_t` whose file or command line is
acme's: `/usr/local/lib/acme…`, `acme.py`, `acme_web.py`, `acme-vip-check`, a thread named `acme-…`);
the tools the daemon runs (`ssh_t`, `ssh_keygen_t`, `ping_t`, `ifconfig_t`, `hostname_t`,
`chronyc_t`) when they touch acme or acme's paths; and the confined services acme works with
(`httpd_t`, `sshd_t`, `init_t`, `logrotate_t`, `keepalived_t`, `postgresql_t`, `chronyd_t`,
`syslogd_t`…) **only where the path or the port is acme's**:

- paths: `/usr/local/lib/acme`, `/var/lib/acme`, `/var/lib/acme-net`, `/etc/acme`, `/var/www/acme`,
  `/run/acme` (and `/run/acme-*`), `/var/log/acme`, `/etc/pki/acme`, `/etc/nginx/certs`, nginx's
  `conf.d/acme*.conf`, `/etc/php-fpm.d/acme.conf`, `/etc/ssh/sshd_config.d/00-acme.conf`,
  `/etc/keepalived/keepalived.conf` and its systemd drop-in, `/usr/libexec/keepalived/acme-vip-check`,
  `/etc/logrotate.d/acme`, `/etc/rsyslog.d/10-acme-*`, `/etc/sysctl.d/90-acme*`, the unit files,
  PostgreSQL's `acme-ha.*` in its data folder, the database agent's folders;
- ports: the API port, the console's SSH port, the agents' port and the certificate sign-in port
  (read by root from the nginx and sshd files acme wrote), 80 and 443, acme's SNMP agent, the DNS
  server, the gate for SSH with a code, the database's and the other node's PostgreSQL port.

### Put in what is selected

Every finding that can be put right comes ticked; each kind has *select all*; the button counts.
**The page sends only the ids.** The node's daemon passes them to its root helper - the request
holds `do`, `ids` and who asked, nothing else (anything more is refused, by the API and by root) -
and root finds them again in that machine's audit log and works out every fix itself. A confirm
lists **exactly** what root will do. Root runs `setsebool -P`, `restorecon`, `semanage port -a`,
writes `acme_local` again from its list (`/var/lib/acme-net/selinux-local.json`) and loads it
(`semodule -i`, the copy kept as `.in-policy`) - **under enforcing too**, nothing has to be switched
off. Every step goes into Events; the node looks again at once, and what was put right is noted
with its time: a refusal of it from before no longer counts, one from after comes back.

*acme's local rules* lists each rule of `acme_local` with who put it in and when, and **Take it
away**; the last one takes the module out of the policy (`semodule -r acme_local`).

### The steps (per node)

| Now | Button | Root does |
|---|---|---|
| disabled | **Make it ready (permissive)** | `SELINUX=permissive` in `/etc/selinux/config`, `/.autorelabel`, `selinux=0` taken off the kernel's command line (`grubby`), acme's module in; **never restarts the machine** |
| permissive | **Put in what acme needs** | the module, the labels, the booleans and the ports above |
| permissive, something fixable or not for a button left (or anything acme needs missing, auditd not running) | *Switch to enforcing* **locked**; "Not ready for enforcing yet" says how many | - |
| permissive, nothing left | **Switch to enforcing** | `setenforce 1`, `SELINUX=enforcing` |
| enforcing | **Back to permissive** | `setenforce 0`, `SELINUX=permissive` - refused while *high security* is on |

What is not acme's never locks enforcing. **In a cluster: one node at a time.** A step asked
while another node is in the middle of one is still taken (as before), with a warning in the log; the confirms say it: do one node, then look at the
cluster - *High availability*: both nodes answer, the replication runs, the VIP address holds (a
refused `keepalived_t` or `postgresql_t` shows on that node's card at once) - and only then the
other node. Restart a node made ready when it suits, one at a time: the labelling takes minutes.

Let it run a day or two as it is used - sign-ins, the pages, renewals and deployments, backups, a
failover, an upgrade - then look again: refusals appear only when the thing is done.

When acme's needs were last put in is kept in root's folder (`/var/lib/acme-net/selinux-applied`):
what was refused before that no longer counts. Looked at two minutes after acme starts and every
half hour after that, and at once with *Look again* (the refresh of the node pill: every node);
`semanage`, `semodule -l` and `ausearch` run at the lowest CPU and disk priority.

A read-only account sees the card, every node, every finding - without a button or a tick. No
command line of any program is on the card (another program's might hold a secret): the program's
name and file only.

## The report

*Download the report* gives the report of the node shown (`acme-selinux-report-NODE-DATE.tar.gz`);
`sudo acme --selinux report [FILE]` (or `--selinux-report`) makes the same for the machine it runs
on. Nothing is changed to make it.

| File | What |
|---|---|
| `check.json` | the card: mode, module, labels, booleans, ports, the findings sorted, acme's local rules |
| `acme.json` | what acme uses on the node (switches and ports - no password, key or token) |
| `avc-raw.txt`, `avc.txt` | every refusal since the start, raw and `ausearch -i` - **of the whole machine** |
| `audit2why.txt`, `audit2allow.te` | why; what would allow it (a hint, never loaded) |
| `labels.txt` | acme's files, their labels and what `matchpathcon` says |
| `processes.txt`, `ports.txt`, `booleans.txt`, `modules.txt` | acme's part of them (`modules.txt` with `acme_server` and `acme_local`) |
| `system.txt` | os-release, kernel, `sestatus -v`, the packages, the kernel's command line, the config, auditd |
| `os/processes.txt` | **every** process with its domain |
| `os/booleans.txt` | **every** boolean (`getsebool -a`) |
| `os/ports.txt` | **every** port type (`semanage port -l`) |
| `os/modules.txt` | **every** module (`semodule -lfull`) |
| `os/local-changes.txt` | what was changed on this machine: `semanage boolean/port/fcontext/login/user/module/permissive -l -C` |
| `os/semanage-export.txt` | `semanage export` |
| `os/listening.txt` | `ss -lntupZ` |

No password, key or token of acme is in it. The audit log and `os/processes.txt` hold the command
lines of other programs - look through them before sending the file on. From the pages a node's
report is kept sealed in the database an hour, so that whichever node answers gives it.

## On the server

```bash
sudo acme --selinux check                    # the checks and the mode (as --selinux-check)
sudo acme --selinux look                     # what SELinux refuses, grouped and coloured, with ids and fixes
sudo acme --selinux fix ID...                # lists exactly what root will do, asks (--yes)
sudo acme --selinux fix --all                # everything that can be put right
sudo acme --selinux rules                    # acme's local rules
sudo acme --selinux rules --take-away ID
sudo acme --selinux prepare | apply | enforce | permissive   # the steps, asked first unless --yes
sudo acme --selinux report [FILE]            # the report of this machine (as --selinux-report)
```

Each works on the machine it runs on (in a cluster: that node), writes what root did into Events
and has the node look again, so the card shows it at once. `acme --selinux-check [--json]` and
`acme --selinux-report [FILE]` work as before. The console (`acme --console`, *Encryption, sending
out, time, network, high security*) has the same: how it stands, a step, the report, what it
refuses, put right what can be (asked first), acme's local rules.

## Alerts and "To be done by hand"

*To be done by hand* (each node its own): **"SELinux refuses acme something - N can be put right on
the card"** (and how many are not for a button), with `sudo acme --selinux look`; it goes by itself
once nothing is left. The alert *SELinux refusing* (off by default) says the same, and the security
check lists it. SNMP and Prometheus (`acme_selinux_mode`, the denials) are as before: the count is
of acme's refusals still open.
