# The firewall and who may reach the pages

Settings → **Firewall and access** looks after two things, on every node of
the cluster at once:

1. **Who may reach which pages.** The enrolment pages (`/`, the certificate
   portal), the
   administration (`/admin/`) and the health check (`/healthz`) all answer
   on ports 80 and 443, so a firewall cannot tell them apart. nginx does: each
   of the three has an allow list in `/etc/nginx/conf.d/acme.conf`, between
   `# PORTAL-ALLOW-BEGIN/END`, `# ADMIN-ALLOW-BEGIN/END` and
   `# HEALTH-ALLOW-BEGIN/END`. Each is *everybody* or *only from* a list of
   addresses and networks (IPv4 and IPv6). The other node, the VIP address
   (VIP) and the machine itself (127.0.0.1, ::1) are always let in, so
   everything inside the cluster keeps working. The VIP address's server
   (`acme_vip.conf`) is a copy of the node's and has the same lists.

2. **The machine's firewall** - iptables and ip6tables (the
   `iptables-services` package on AlmaLinux / RHEL). Off by default: nothing
   is touched until it is turned on.

## What acme changes in the firewall

Only a chain of its own, `ACME-IN`, jumped to first from `INPUT`:

```
INPUT ─► ACME-IN: the other node ─► your rules (in your order) ─► what acme needs ─► the rest of INPUT
```

At the bottom of *Settings → Firewall*, *The whole firewall* shows each node's filter table as `iptables-save` shows it - every chain, ACME-IN's lines marked - read by root after every change and again on *Read it again* (1.0.68).

`ACME-IN` holds ACCEPT rules for what acme needs, plus whatever you add. It starts with three fixed rules no rule of yours can override: loopback (`-i lo`), answers to connections this machine opened itself (`conntrack ESTABLISHED,RELATED` - LDAP, DNS, mail, replication), and on IPv6 neighbour discovery (ICMPv6 133-136). Then the other node of the cluster, so no rule of yours can shut it out.
Anything it does not match goes back to INPUT and on to the rules that were
there before (your SSH, Zabbix, the final REJECT…). acme never changes those.

It is put in at once (`iptables-restore --noflush`, all of the chain in one
go) and also written into `/etc/sysconfig/iptables` and
`/etc/sysconfig/ip6tables`, between lines that start `# acme:`, so it is
there after a reboot. Each file is checked with `iptables-restore --test`
first and left as it was if the check fails. A later `service iptables save`
does no harm: acme finds its lines again by their names.

Turned off, the jump and the chain are taken away (live and in the files),
and nothing else.

### What acme lets in by itself

| Rule | IPv4 / IPv6 | Let in | Can be turned off |
|---|---|---|---|
| SSH | both | tcp 22 from anywhere | yes - keep a rule of your own if you do |
| ICMP / ICMPv6 | both | ping; IPv6 needs ICMPv6 for neighbour discovery | yes |
| DHCPv6 client | 6 | udp 546 from fe80::/10 | yes |
| HTTP / HTTPS | both | tcp 80,443 - from everybody when one of the three page lists is for everybody, else from the networks of the three lists; tcp 80 from everybody anyway while the pages' own certificate is renewed over HTTP-01 (the CA asks from the internet) | yes |
| NTP (time served) | as the network | udp 123 from the networks under *Settings → Time → Serve the time to* | yes |
| Signing in with a certificate | as the network | tcp `certlogin_port` (8443) from the networks that may reach the pages of the parts switched on (from everybody when one of them is for everybody) - only while one is on ([certificate-sign-in.md](certificate-sign-in.md)) | yes |
| SNMPv3 | as the network | udp 161 (the port set) from the networks under *Settings → Monitoring → Only from*, from everywhere when none is set - only while SNMPv3 is on | yes |
| The other node | as the node | everything from the other node (replication, its pages, the health check, its answers) | no |
| VRRP | as the node | IP protocol 112 from the other node, while the VIP address is on | no |

They follow what is set up: the cluster made, the VIP address turned on,
SNMPv3 or the time served switched on - and the rules change within a few
seconds.

acme's own DNS server (for DNS-01) is not opened by itself: add a rule of
your own for udp and tcp 53 from where the CA's questions come (from
anywhere, usually) - [dns-server.md](dns-server.md).

### Rules of your own

Accept, drop or reject; TCP, UDP, ICMP, VRRP or any protocol; a port, a
range (`8000-8100`) or several (`80,443`); from an address or a network;
IPv4, IPv6 or both; for every node or one. They come after the other node and before the rest of acme's own in
`ACME-IN`, in the order shown, so a DROP of yours wins over what acme lets in.
Each one carries its note as an iptables comment (`acme: Zabbix agent`).

## Before turning it on

```
dnf install iptables-services
systemctl disable --now firewalld        # if it is running
systemctl enable --now iptables ip6tables
```

If firewalld is running, acme leaves the firewall to it and says so on the
page. What firewalld must let in is in [tls-and-vip.md](tls-and-vip.md).

## Doing it by hand instead

The same as acme does, on each node (here acme1 = 192.168.42.32, acme2 =
192.168.42.33, acme's own DNS server answering everybody):

```
iptables -N ACME-IN
iptables -I INPUT 1 -j ACME-IN
iptables -A ACME-IN -i lo -j ACCEPT
iptables -A ACME-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A ACME-IN -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A ACME-IN -p udp --dport 53 -j ACCEPT
iptables -A ACME-IN -p tcp --dport 53 -j ACCEPT
iptables -A ACME-IN -s 192.168.42.33 -j ACCEPT
iptables -A ACME-IN -s 192.168.42.33 -p vrrp -j ACCEPT
service iptables save
```

(on acme2 the other node is 192.168.42.32), and the same with `ip6tables` for
IPv6.

## Checking

```
iptables -S ACME-IN; ip6tables -S ACME-IN
grep -n acme /etc/sysconfig/iptables
acme --web-status                  # what root did last, node by node
```

## On trial (1.0.137)

A change of the firewall or of who may reach the pages goes back by itself
unless kept within `fw_confirm_min` minutes (5): the banner on every page, or
`acme --change-keep fw`. See [changes-that-go-back.md](changes-that-go-back.md).
