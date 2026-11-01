# Sign-in protection

*Settings → Sign-in protection* (1.0.137). Two things, each switched and tuned
there (or with `acme --set`):

1. **Guessing from one place held back** - RADIUS, off by default.
2. **Changes that could cut the server off taken back** unless somebody keeps
   them - a node's new network, and the firewall and who may reach the pages;
   on by default.

## 1. Guessing from one place (RADIUS)

Without it, only each token counts its own wrong codes (`rate_limit_tries`,
`lockout_after`). From one place somebody may still try every name a few times
a day, or lock everybody's token on purpose.

Switched on, the place each request comes from is counted too: the
`Calling-Station-Id` the VPN sends - the address the person connects to the VPN
from (a MAC address on Wi-Fi; IPv6 counted by its /64). A request without one
is not counted.

| Setting | Default | What it is |
|---|---|---|
| `radius_guard` | 0 (off) | the switch |
| `radius_guard_tries` | 20 | refusals from one place within the window - and it is blocked |
| `radius_guard_names` | 5 | different names refused from one place within the window - and it is blocked (0: not counted) |
| `radius_guard_window_min` | 15 | the window the refusals are counted over |
| `radius_guard_block_min` | 30 | how long a place stays blocked |
| `radius_guard_trusted` | (none) | addresses or networks never blocked: an office behind one address, a monitor |

Counted: wrong passwords, wrong codes, names nobody has. Not counted: refusals
that are the server's own trouble (a directory away, a realm not set up, a code
that could not be sent).

A blocked place is refused at once - nothing of its requests is checked (no
directory bind, no code), and **nobody's token counts them**, so a guesser can
no longer lock other people's tokens either. The refusal says why in the log
(*the step: sign-in protection*), and Events has a line when a place is blocked.

**Who is counted and who is blocked** is in the table under the settings, with
the tokens locked by wrong codes: how many refusals and names against the limit
(a bar that fills), how long a block still runs, the names tried. Type a name or
an address to see only those; *Clear* lets one in again at once, *Clear these* /
*Clear them all* the ones shown. The same rows are in *Accounts → Locked out*.

Each node counts what reaches it (in memory, as the pages' sign-ins are); both
nodes' lists are shown, and clearing reaches the other node within seconds.

```bash
acme --set radius_guard=1
acme --set radius_guard_tries=20
acme --set radius_guard_names=5
acme --set radius_guard_trusted='198.51.100.7 203.0.113.0/24'
```

## 2. Changes taken back unless kept

| Setting | Default | |
|---|---|---|
| `net_confirm_min` | 10 | a node's new network (Settings → Network) goes back unless kept within these minutes; 0: kept at once |
| `fw_confirm_min` | 5 | a change of the firewall or of who may reach the pages goes back unless kept within these minutes; 0: kept at once |

While a change waits, **every page shows a banner** with the time left,
*Keep it* and *Put the old back now*; `acme --status` and the console say so too.

```bash
acme --change-keep net --node acme2     # keep the new network of acme2
acme --change-back net --node acme2     # go back to the old one now
acme --change-keep fw                  # keep the firewall change
acme --change-back fw
```

In the console: *Cluster → Keep or put back a change on trial*.

**The network.** The node keeps what it had (its NetworkManager connection and
host name), puts the new one in, restarts - and waits. Not kept in time, or
come up without its new address at all, it asks itself for the old network:
the same job the other way round (a restart, the other node of a cluster told
the old address again). In a cluster the other node's `pg_hba.conf` lets both
addresses in while the new one is on trial, so it can still be told; kept, only
the new one stays. Only a network set by hand can be put back by itself - one
from DHCP is said so and kept at once.

**The firewall.** What was set before the first change of a trial (acme's rules,
your own, the automatic ones switched off, who may reach which page) is kept;
further changes within the trial move its deadline on. Not kept, one node puts
it all back and every node puts that in within seconds.

Keep a change only once you have checked that what it could have cut off still
answers: the node at its new address; SSH, the pages and RADIUS after a
firewall change.
