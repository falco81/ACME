# Changes that go back by themselves unless kept

(1.0.137.) A change that could cut the server off - a node's new network, a
change of the firewall or of who may reach the pages - is put in on trial, and
goes back by itself unless somebody keeps it. The two settings are where the
change is made (*Settings → Network* and *Settings → Firewall and access*),
or `acme --set`:

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
the new one stays. What exactly is put back is in
[network-and-power.md](network-and-power.md).

**The firewall.** What was set before the first change of a trial (acme's rules,
your own, the automatic ones switched off, who may reach which page) is kept;
further changes within the trial move its deadline on. Not kept, one node puts
it all back and every node puts that in within seconds.

Keep a change only once you have checked that what it could have cut off still
answers: the node at its new address; SSH, the pages and acme's DNS server
after a firewall change.
