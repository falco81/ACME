# Time (NTP)

A code from the authenticator app is worked out from the clock. A node whose
clock is off by more than a few seconds refuses codes that are right. When the
two nodes of a cluster disagree, a code can be right on one and wrong on the
other. *Settings → Time* watches the clock of every node and sets the time
servers for the whole cluster. It uses chrony, as AlmaLinux and Rocky 9 do.

## What the page shows

- **A card per node**:
  - how far off the time servers it is (chrony's system time offset), and
    whether it is synchronised;
  - the source it follows, its stratum, the last correction, the frequency
    error, root delay and dispersion, the leap status;
  - its time zone, and its own time now.

  *Read it again* asks the node at once (each node says it by itself every
  minute). *Step it now* sets the clock to the servers' time at once
  (`chronyc makestep`), for a clock that is far off.
- **Between the two nodes**: how far apart their clocks are.
- **Where the time comes from**: each node's sources, as `chronyc sources`
  lists them:
  - the state (*followed*, *combined*, *not combined*, *unreachable*, *false
    ticker*, *too variable*);
  - the stratum, how often it is asked, the last eight tries (reach), when it
    was last heard, and its offset with the error.

A node whose clock is not synchronised, or is more than a second off, says so
under *Problems* on the overview and in `acme --status`.

## The time servers

**acme sets the time servers** off (the default): each machine keeps its own
`/etc/chrony.conf` - AlmaLinux's pool, or what was set by hand. It is shown and
checked here, not changed.

**On**: the same settings on every node.

| Setting | |
|---|---|
| Servers | a host name or address each; *one server* or *a pool* (several addresses behind one name); **iburst** (synchronised in seconds after a start), **preferred**, **NTS** (Network Time Security - the server proves who it is; needs TCP 4460 out, e.g. time.cloudflare.com). Ready-made: cz.pool.ntp.org, pool.ntp.org, time.cloudflare.com, tik.cesnet.cz, tak.cesnet.cz |
| The nodes take each other too | in a cluster, each node is one more source for the other (`server OTHER iburst`, `allow OTHER`). With the servers out of reach the two still keep one time, which is what codes need. |
| Step when off by more than / in the first updates | chrony's `makestep` - further off than this, the clock jumps instead of being slewed; 3 updates is after a boot, -1 is any time |
| Sources that have to agree | `minsources` |
| Serve the time to | networks that may ask these nodes for the time (`allow`, UDP 123) - routers or targets, say. The firewall (Firewall and access) opens it by itself as *NTP (time served)*. |
| Time zone | `timedatectl set-timezone`, on every node. The logs and the times on the pages use it; codes do not depend on it. |

How it is written: in `/etc/chrony.conf`, the file's own `server`, `pool`,
`peer`, `sourcedir`, `makestep`, `allow` and `minsources` lines are commented
out (`#acme# …`), and acme's lines go between two marks at the end. The file as it
was is kept in `/etc/chrony.conf.acme-before`. chronyd is enabled and restarted.
Switched off again, the marked lines go and the file's own lines come back.

Each node puts the settings in by itself within seconds of a save. Its card
says when it did, and what failed if anything did. chrony is installed when it
is missing - and by install.sh, on a fresh install and on every upgrade
(1.0.122), where it is also enabled and started.
