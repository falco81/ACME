# The network of a node, restarting and switching off

*Settings → Network* and *Settings → Restart and power off*. Both work the same
on one server and in a cluster, from the VIP address or a node's own address.
The node a change is for does it itself. Either node's pages follow it.

## Settings → Network

For each node (a tab per node in a cluster):

- **As it is now** - the host name, the NetworkManager connection, the IPv4
  address with its prefix, the gateway, the DNS servers, the search domains,
  IPv6, and the address SNMP listens on (`snmp_bind`). *Read it again* asks the node at once (each
  node also says it by itself every five minutes).
- **New settings** - the host name (FQDN), IPv4 (address/prefix, gateway, DNS,
  search domains) and IPv6. *Check it* lists what will happen. *Change it and
  restart* does it.

It needs NetworkManager (`nmcli`), as AlmaLinux and Rocky 9 have. Without it the
page says so and the network is set by hand.

### What a change does, in order

1. **The node keeps its name.** If `node_name` is not set in config.json, it is
   written there first, so a new host name does not rename the node in acme.
2. **In a cluster, the other node is told the new address first.** Its
   `pg_hba.conf`, its subscription and its `ha_peer` move to the new address
   (the same as *The addresses of the two nodes* on High availability,
   docs/renaming-and-readdressing.md). It then waits for this node there.
3. **This node's own settings** that named the old address or host name change
   with it: `ha_address`, SNMP's address (`snmp_bind`), the mail greeting
   (`mail_helo`), the isemon name, `db_host`.
4. **Its own certificate** (Certificates and TLS), where it was made here, is
   made again with the new address and name in it. A certificate from an
   authority is not changed: the page says what it names, and you get a new one.
5. **Maintenance.** The VIP address moves to the other node.
6. **NetworkManager** (`nmcli connection modify`), the host name
   (`hostnamectl`) and this machine's lines in `/etc/hosts` (the old file is
   kept as `/etc/hosts.acme-before`) - then a **reboot** 8 seconds later.
7. **Back up**, the node checks that it has the new address, waits for
   replication to run both ways (the link between the databases makes its
   certificate again for the new address by itself), and comes **out of
   maintenance**. keepalived, nginx and the firewall are written again from
   the database with the new addresses on both nodes.

The page shows each step with a progress bar. If the page was opened at the
node's own old address or name, it waits for the restart and then goes to the
new one. You sign in there again: a sign-in belongs to the address the page was
opened at.

When it is over, the steps stay on the page until *Hide this* is pressed,
or for 6 hours (a day when the change failed). A restart or a power-off that
is over has *Hide this* too, and goes by itself half an hour after it began.

If the node comes up without the new address, the job says so and the node
stays in maintenance. The network is then put right at its console
(`nmtui`, or `nmcli connection modify …`). The settings it had before are kept in
the job and in `/etc/hosts.acme-before`.

**Change one node at a time.** Change the VIP address (High availability)
first when it moves to another network too. A new address outside the web
address's network is refused unless you tick that it is meant to be so.

### IPv6 (dual stack)

Switched on for a node, by hand (address/prefix, gateway, DNS) or automatically
(SLAAC/DHCPv6):

- acme's own DNS server listens on IPv4 and IPv6 alike (`dns_listen`,
  `0.0.0.0,::` by default - [dns-server.md](dns-server.md)).
- nginx answers on IPv6 too (`listen [::]:…` is in acme.conf).
- The firewall (Firewall and access) covers IPv4 and IPv6 alike.
- The VIP address takes an IPv6 address of its own under *High availability →
  …and its IPv6 address*. The same VRRP instance moves it with the IPv4 one
  (`virtual_ipaddress_excluded` - the nodes keep speaking VRRP over IPv4), and
  nginx listens on it.
- **Replication between the databases stays on IPv4.**

## Settings → Restart and power off

A card per node (answering or not, its address, how long the machine has been up
and how long acme has run on it - a restart of the service is not one of the machine
(1.0.87) -, its version) with **Restart** and **Power off**. `acme --restarts` shows
both too (*machine up since*, *acme started*). From the command line, `acme --restart-nodes
NODE,NODE|all` restarts them one at a time and `acme --power-off-nodes NODE,NODE|all` switches
them off together (both ask first; `--yes`); in the console both are under *The pages'
certificates, updates, restarts, tests*. In a cluster:

| | |
|---|---|
| **Restart one after the other** | the other node first, then this one. Each goes into maintenance (the VIP address moves away), restarts, and comes back into service before the next starts. The pages, the DNS server and the renewals never stop. |
| **Restart both at once** | both at the same moment: a minute or two with nothing answering. |
| **Power off both** | both switched off; someone switches them on at the machines. |

A single node restarted in a cluster goes into maintenance first, the same way.
The page follows each node (*going down*, *restarting*, *starting*, *up again*)
with a countdown. It reloads when its own node is back. The page answers through
the other node meanwhile when it was opened at the VIP address, and waits when
it was opened at the restarting node itself.

Each node's own part is written in the database, so a node that restarts picks
up where it was when it is back: out of maintenance, then the next node's turn.
A node that has not come back in 15 minutes is marked as failed. It stays in
maintenance until it does.

Everything is in Events: who asked, what each node did.

## On trial (1.0.137)

A new network is put in on trial: unless somebody presses *Keep it* (the
banner on every page, or `acme --change-keep net --node NODE`) within
`net_confirm_min` minutes (10), the node goes back to its old network by itself
- also at once when it comes up without its new address. See
[changes-that-go-back.md](changes-that-go-back.md).

### What going back puts back (1.0.140)

Before a change on trial each node keeps what it has, and going back puts
exactly that back - not the old values worked out again:

- **The network itself**: the root helper keeps the connection's whole
  NetworkManager profile (every address, route, MTU, DHCP or set by hand -
  a network from DHCP can go back too), the host name, `/etc/hosts` and the
  IPv6 switch (in `/var/lib/acme-net`, root's alone), and loads them back.
- **This node's settings and certificate**: `snmp_bind`, `mail_helo`,
  `isemon_hostname`, `db_host`, `ha_address` and the pages' own certificate as
  they were.
- **The other node**: told the old address again - its `pg_hba.conf` lets the
  old address in and the trial's address out, its subscription and `ha_peer`
  move back.
- **Checked after the reboot**, each a step of the job: the address,
  replication both ways, the link between the databases encrypted and checked
  (verify-full) on both nodes with this node's certificate naming the old
  address, and the VIP address (keepalived) set up again.

## The settings by key

Settings → System updates and Settings → Restart and power off - also `acme --set KEY=VALUE`:

| Setting | Default | |
|---------|---------|--|
| Look for updates every day (`osup_check`) | `0` | Each node looks what dnf (or apt) has waiting, every day at the time below - for the cards here, the alerts and the report. Nothing is put in. |
| At (`osup_check_at`) | `06:15` | When, as `HH:MM` on this machine's clock. |
| Updates on a schedule (`osup_auto`) | `0` | The updates put in by themselves in the window below, one node at a time as by hand - each out of service while it is updated, the VIP address on the other. Off until switched on. |
| Which (`osup_auto_what`) | `security` | Only the security updates (dnf --security, unattended-upgrade on apt), or every update. (`security` - only the security updates; `all` - every update) |
| How often (`osup_auto_every`) | `weekly` | A day, a week or a month. (`daily` - every day; `weekly` - every week, on the day below; `monthly` - on the first of every month) |
| On the day (`osup_auto_day`) | `7` | The day a weekly update goes. (`1` - Monday; `2` - Tuesday; `3` - Wednesday; `4` - Thursday; `5` - Friday; `6` - Saturday; `7` - Sunday) |
| At (`osup_auto_at`) | `04:45` | When, as `HH:MM` - a quiet hour, away from the backups. |
| After the update (`osup_auto_reboot`) | `auto` | A node that needs a restart after the update - restarted by itself, one after the other, or offered on the page. (`auto` - restarted by itself where an update needs it; `ask` - a restart offered on the page) |
| A restart on a schedule (`power_auto`) | `0` | The nodes restarted in the window below, one after the other, each out of service while it is. Off until switched on. |
| How often (`power_auto_every`) | `weekly` | A week or a month. (`weekly` - every week, on the day below; `monthly` - on the first of every month) |
| On the day (`power_auto_day`) | `7` | The day a weekly restart goes. (`1` - Monday; `2` - Tuesday; `3` - Wednesday; `4` - Thursday; `5` - Friday; `6` - Saturday; `7` - Sunday) |
| At (`power_auto_at`) | `05:40` | When, as `HH:MM` on this machine's clock. |
| Only the nodes that need one (`power_auto_needed`) | `1` | Only the nodes an update left waiting for a restart; off: every node, every time. |
