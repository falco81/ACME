# Certificates, TLS, and the VIP address

Certificates and TLS: *Settings → Certificates and TLS*. The VIP address:
*Settings → High availability → The VIP address*. A full
administrator, or the command line. From 1.0.47.

- **Certificates and TLS** for each node's own name, and for the web
  address's name: upload a certificate (PEM, PFX / PKCS#12, with or without a
  password), make a request (CSR) here, or make a self-signed one; choose the
  protocols, the ciphers, the DH parameters and HSTS.
- **The VIP address**: in a cluster of two, one more IP address for
  the pages and the administration that is on one node at a time
  (active/standby) and moves to the other node by itself when the node
  holding it is not well. The node holding it is also the one that renews
  and deploys the certificates ([high-availability.md](high-availability.md)).

With the VIP address off, everything works as before - including a load
balancer of your own ([load-balancers.md](load-balancers.md)).

---

## How it is put in place

The service runs as `acme` and may not change nginx, keepalived or the
firewall. What is asked on the pages is kept in the database (so both
nodes know it; keys are sealed with the key of the sealed secrets) and each node then asks
root for its own part: the daemon writes `/var/lib/acme/web/request.json`,
systemd (`acme-web.path`) starts `acme-web.service`, which runs
`/usr/local/lib/acme/acme_web.py` as root. That helper:

- checks every value against the one shape it may have (addresses, names,
  interface names, cipher lists - and certificates and keys are read by
  openssl, the key must be the certificate's own);
- writes the files: `/etc/nginx/certs/acme.pem` (certificate + chain),
  `acme.key`, `acme-ca.pem` (the root, for `ssl_trusted_certificate`),
  `acme-dh.pem`; for the VIP address `acme-vip.*` and
  `/etc/nginx/conf.d/acme_vip.conf`; `/etc/keepalived/keepalived.conf`;
- asks nginx (`nginx -t`) and keepalived (`keepalived -t`) before reloading
  them, and **puts every file back as it was** when either says no;
- writes what it did to `/var/lib/acme/web/status.json` - shown on the pages
  and by `acme --web-status`.

It never touches a `keepalived.conf` that is not acme's own (it refuses, and
says so). `install.sh` (1.0.47 and later) installs the helper and the units.

---

## Certificates

### Download (1.0.191)

*Download* on a certificate's card opens a window with the format: the certificate
as PEM (`.crt`), with its chain (`.pem`), as DER (`.cer`), PKCS#7 with its chain
(`.p7b`) - or **with its private key**: PKCS#12 (`.pfx`) or PEM with the key
locked (PKCS#8, AES-256). With the key, a password of 10 characters at least,
typed twice, locks the file - never without one; *For older Windows* makes a PFX
with 3DES that Windows before 10 (1709) and Server 2016 open. Full administrators
only; each download with the key is an event (*warn*). On the command line:
`acme --tls-for NODE|vip --tls-export pfx FILE` (the password asked for; `--legacy`).

Two certificates of the same names (an RSA one and an ECDSA one beside it - ACME's "both", or
both uploaded together, below): *Download* asks which - *RSA*, *ECDSA*, or *Both (.zip)*: one
.zip with the two files (`rsa.pfx`, `ecdsa.pfx`...) in the format chosen, each key locked with
the same password (as otp 1.0.240). Events say which one went.

### Upload

On the pages: *Upload…* on the node's (or the VIP address's) card. Drop the
files, or paste PEM:

| You have | Send |
|---|---|
| `.pfx` / `.p12` (Windows, an export from a CA) | the file; its password in *Password* (empty if none). Old PFX files (RC2/3DES) are read too |
| `.crt` / `.cer` / `.pem` + `.key` | both files; add the chain (intermediate) and the root if you have them |
| one `.pem` with everything | that file |
| a key with a passphrase | the key and the passphrase in *Password* |

The certificates are sorted by themselves: the one that belongs to the key,
the chain up from it in order, the root (self-signed). The chain is checked
against the root when a root is given. The password is used once to open
the file and is not kept.

**An RSA and an ECDSA certificate of the same names together** (as otp 1.0.240): both keys in
the PEM, two PFX files, or one of each - both are put in, the RSA one the main one and the
ECDSA one beside it, as ACME's "both" keeps them: nginx gives each client the one it takes.
One alone is as until now - and a second one there before is dropped. Two RSA, two ECDSA,
certificates of other names, or a key without its certificate are refused.

Command line:

```bash
acme --tls-import /root/acme1.pfx --tls-for acme1                    # ACME_TLS_PASSWORD=... for its password
acme --tls-import cert.pem key.pem chain.pem root.pem --tls-for acme1
acme --tls-import acme.pfx --tls-for vip                            # the VIP address's own
acme --tls-import rsa.pfx ecdsa.pfx --tls-for acme1                  # both, the ECDSA one beside
```

### Request (CSR)

*Request…*: the name (CN), other names (SAN, names or addresses), the key
(RSA 2048/3072/4096 or EC P-256), organisation, unit, city, country. The key
is made on the node and stays there (sealed in the database); copy or
download the request, give it to your CA, then *Upload…* only the
certificate it sends back.

### Self-signed

*Self-signed…*: for a test, or until the real one comes. Browsers warn until
it is trusted by hand.

### The whole chain (1.0.89)

nginx must send the certificate **with every intermediate authority** up to (not
including) a root. Browsers fetch a missing intermediate themselves (from the
certificate's *Authority Information Access → CA Issuers* address) and say nothing;
curl, Python, Java, Go, rsyslog, the other applications (acme push) and monitoring
do not, and refuse the connection (`unable to get local issuer certificate`).

So whatever comes - an upload, a PFX, a request signed elsewhere, ACME, acme push,
`--tls-import` - is checked against **the system's roots**
(`/etc/pki/tls/certs/ca-bundle.crt`) as such a client checks it, and a chain that
does not reach one is completed as browsers do it: the intermediate fetched from its
CA Issuers address (at most four steps, kept a day). What is fetched is trusted only
as a link to a root of the system; a root is never sent.

The card shows it in the line **Chain**:

| | |
|---|---|
| green `complete - 3 certificates up to <root>` | checked against the system's roots |
| green `… (fetched: <CN> - it was not sent with the certificate)` | completed by fetching |
| green `… - a private root: only clients that trust it take it` | a private CA, its root given here |
| red `incomplete - the authority <CN> is not sent and could not be completed (<why>)` | it cannot be completed |
| red `it leads to <CN>, a root the system does not trust (a private CA?)` | a root nobody here trusts |
| `self-signed - no chain` | no chain, no buttons |

What nginx has in its file now is checked too (nothing fetched) - a certificate put
in before 1.0.89 shows red until it is completed. The buttons:

- **Complete the chain** (red chain) / **Check the chain** - the certificate kept is
  checked again and completed from its CA Issuers addresses; nginx is given the whole
  chain within seconds. The second (ECDSA) certificate beside it too.
- **Upload the missing authority** (red chain only) - when it cannot be fetched (no
  CA Issuers address, no way out to it, a private CA): the dialog names the authority
  missing; paste its certificate (PEM) or read a `.pem/.crt/.cer/.der` file. Only
  certificates of authorities, never a key; intermediates go into the chain in order,
  a root is kept to check with and never sent. The certificate and its key stay.

After every time nginx is given its part, acme connects to it as a client that
fetches nothing (the system's roots, plus a private root kept) and shows the result
under the card; a refusal is an event. **In a cluster** it is the same for every
node's card and for the **VIP address**: the profiles are in the database, so a
chain completed on either node is put in on the node it is for (the VIP one on both
nodes), and the VIP certificate is checked on its address by the node holding it
(keepalived).

Command line: `acme --tls-chain [--tls-for NODE|vip]`,
`acme --tls-chain-add FILE [--tls-for NODE|vip]` (exit 4 while incomplete).

### Which certificate goes where

- **A node's own**: what is answered on `https://acme1.example.cz/` - the
  node's own name. Without one, the self-signed certificate `install.sh` made.
- **The VIP address's own**: answered on the VIP address itself - for its
  name (`acme.example.cz`), for its IP address typed in the browser, and for
  a client that sends no name at all. nginx listens on the address on both
  nodes (`net.ipv4.ip_nonlocal_bind = 1`, in `/etc/sysctl.d/90-acme-vip.conf`),
  so the node that takes the address over answers on it at once. Without a
  certificate of its own, the VIP address answers with the certificate of
  the node it is on - so either give each node a certificate that also names
  `acme.example.cz`, or give the VIP address its own.
- A certificate is put in when the node's helper has finished everything
  asked of it - including DH parameters, which made on the node take
  minutes (4096 bits up to ten). The card shows how far it is.

A certificate that ran out is refused on the pages. The cards show how many days are
left (orange under 21 days).

### TLS settings

*TLS settings…* on a card, or on the command line:

| Choice | Protocols | Ciphers |
|---|---|---|
| **Standard** (default) | TLS 1.2, 1.3 | ECDHE with AES-GCM and ChaCha20 only |
| **Mozilla intermediate** | TLS 1.2, 1.3 | the same plus DHE (for old clients) |
| **Mozilla modern** | TLS 1.3 only | chosen by TLS 1.3 itself |
| **Custom** | TLS 1.2 and/or 1.3 | any OpenSSL cipher list (checked with `openssl ciphers`) |

- **DH parameters** - only DHE ciphers use them: none; an RFC 7919 group
  (ffdhe2048/3072/4096, ready at once - recommended); or made on the node
  (2048 takes seconds, 4096 minutes; made once and kept).
- **The server chooses the cipher** (`ssl_prefer_server_ciphers`).
- **HSTS** - off, 6 months, 1 year, 2 years.

```bash
acme --tls-preset intermediate --tls-dh ffdhe2048 --tls-hsts 31536000 --tls-for acme1
```

*Stop looking after it* (the bin on a card): acme no longer changes that
node's TLS; nginx keeps the files it has.

---

### Certificates from acme (acme push)

The card under the certificates lets another acme put its certificates on
these pages and renew them (each node's, the VIP address's): switch it on,
*Pair with an acme* shows a one-time code for that acme's target *An
application of ours*, or paste that acme's key. Every request of it is
signed, the private key travels sealed to this server, and a certificate
must hold the name of the pages it goes to. What it puts in is kept as an
upload here would be - every node takes it within seconds, and Automatic
certificates leaves those pages alone. The card also shows *This acme's own
key*, for pasting into an application this acme pushes to. The protocol:
[acme-push-protocol.md](acme-push-protocol.md).

## The VIP address

### How it works

keepalived (VRRP, unicast between the two nodes) holds the address on one
node. Every two seconds it asks `/usr/libexec/keepalived/acme-vip-check` two
questions:

1. **May this node hold it?** acme answers in `/run/acme/vip-state`, written
   every three seconds. The node may hold it only if **all** of these hold:
   - its own pages answer `GET https://127.0.0.1/healthz` with `200 ok` - which
     goes through nginx and PHP-FPM to the daemon and the database;
   - its API is listening;
   - it is not in maintenance (so also not being upgraded);
   - it is not being rebuilt from the other node.

   Two failed checks in a row (about six seconds) and the node gives the
   address up. If acme itself stops, the file goes stale and the node gives it
   up as well. If the whole node is gone, the other stops hearing it and
   takes the address within about three seconds.
2. **Is it the node the address is meant to be on?** - the one chosen with
   *Move it here* (by default the first node). That node gets priority, so
   the address goes back to it once it is well again (keepalived waits five
   seconds more, then three without the other's word: about ten seconds after
   acme says it is well).

When the address moves, the new node announces it (gratuitous ARP), and the
browsers' next requests go there. Signed-in sessions stay valid: they are
in the database.

### Turning it on

1. Pick a free address in the nodes' own network (`192.0.2.10/24`) and a DNS
   name for it (`acme.example.cz` → `192.0.2.10`).
2. A VRRP id (1-255) that no other VRRP on that network uses (other
   keepalived pairs, routers with VRRP/HSRP using VRRP). Default 51.
3. Open VRRP between the nodes (below).
4. On the pages: the address with its prefix, its name, the VRRP id; the
   interface per node if it is not the one with the node's own address.
   *Save*, then *Turn it on*. Each node installs keepalived
   (`dnf install keepalived`, AlmaLinux AppStream) if it is missing, writes
   its file and starts it. Within seconds the table shows which node holds it.

```bash
acme --vip-set 192.0.2.10/24 --vip-fqdn acme.example.cz --vip-vrid 51
acme --vip-set 192.0.2.10/24 --vip-iface acme1=ens192 --vip-iface acme2=ens192   # other interfaces
acme --vip on
acme --web-status
```

A certificate of the VIP address's own needs its name (*FQDN*). Taken away afterwards (as
otp 1.0.242), the node's certificate serves the address until a name is given again - said in
the log every hour (`vip-noname`); given a name, its own certificate is back on it. (Before,
each node's root helper refused the whole request for it, and no change of nginx, keepalived or
the firewall reached the node again.)

### Moving it by hand, and back

*Move it here* on a node's row, or `acme --vip-move acme2`. It stays there
(it is now the node it is meant to be on) until moved again. It still leaves
that node by itself when the node is not well.

### Maintenance and upgrades

Nothing to do: a node in maintenance - by hand, or during an upgrade from the
pages or `install.sh --upgrade` - gives the address up, and the other takes it.
When the node is back in service and is the preferred one, the address
returns to it.

### Turning it off

*Turn it off…*, or `acme --vip off`: keepalived stops on both nodes and its
file is removed; the address is on neither node. The nodes keep answering on
their own addresses; a load balancer of your own works as before.

### On both nodes at once (split brain)

If the nodes cannot hear each other's VRRP - VRRP blocked by a firewall, or
the network between them split while both still run - each thinks the other
is gone and both take the address. The pages say so in red.

- Check that IP protocol 112 is allowed **both ways** between the nodes
  (below), and that both use the same VRRP id.
- `journalctl -u keepalived` on both.
- Until it is fixed, take one node out: `acme --maintenance on` on it.

With two nodes and no third party this cannot be ruled out entirely; it is
the same for any keepalived pair.

### What it does not do

- It is for the **pages** (HTTP/HTTPS). SNMP, acme's own DNS server and
  replication stay on the nodes' own addresses.
- Both nodes must be in **one layer-2 network** (one VLAN) with the address.
  In clouds that do not allow an address to move by ARP (AWS, Azure, GCP),
  use their load balancer instead.
- VMware: nothing special is needed - keepalived uses the node's own MAC
  address, so no "MAC address changes" or "forged transmits" in the port
  group.

---

## What to open in the firewall

`install.sh` opens HTTPS/HTTP in firewalld; `acme --ha-setup` and
`--ha-join` open PostgreSQL to the other node; turning the VIP address on
opens VRRP from the other node. Other firewalls in the path (between the
VLANs, in front of the servers) need the same.

### Into each node

| From | Port / protocol | What |
|---|---|---|
| browsers, the load balancer | TCP 443 (and 80, redirected to 443) | the pages, the administration, `/healthz` |
| the CAs' validation servers (DNS-01 with acme's own DNS server) | UDP and TCP 53 | acme's DNS server (if used - [dns-server.md](dns-server.md)) |
| the CAs' validation servers (HTTP-01 here) | TCP 80 | the challenge files |
| the other node | TCP 5432 | PostgreSQL replication (replicated cluster) |
| the other node | IP protocol 112 (VRRP) | the VIP address (when on) |
| administrators | TCP 22 | SSH |
| monitoring | TCP 443 `/healthz`, ICMP | |

### Out of each node

| To | Port | What |
|---|---|---|
| domain controllers | TCP 636 (LDAPS) or 389 (+StartTLS); 3269/3268 for a global catalog | Active Directory |
| the other node | TCP 5432 | PostgreSQL replication |
| the other node | IP protocol 112 | VRRP |
| DNS, NTP | UDP/TCP 53, UDP 123 | names, the clock (certificates and the app codes need it right) |
| the CAs | TCP 443 | ACME (Let's Encrypt…), MS AD CS, SCEP - the issuers |
| the targets | TCP 22 (SSH), 443 (APIs) or what the target needs | deploying the certificates |
| mail server | TCP 25 / 587 / 465 | alerts, reports, codes (if used) |
| isemon | UDP or TCP 514 | logs (if used) |
| package repositories | TCP 443 | `dnf` (keepalived, PostgreSQL, updates) |

### firewalld (AlmaLinux)

What the tools add, for reference (acme2 at 192.0.2.12, seen from acme1):

```bash
firewall-cmd --permanent --add-service=https --add-service=http
firewall-cmd --permanent --add-port=53/udp --add-port=53/tcp           # only for acme's own DNS server
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.12/32" port port="5432" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.12" protocol value="vrrp" accept'
firewall-cmd --reload
firewall-cmd --list-all
```

### iptables

When the nodes run plain iptables instead of firewalld (on acme1; on acme2 the
same with 192.0.2.11):

```bash
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT                         # acme's own DNS server, if used
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -s 192.0.2.12/32 --dport 5432 -j ACCEPT      # replication
iptables -A INPUT -p vrrp -s 192.0.2.12/32 -j ACCEPT                  # VRRP (protocol 112)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -j DROP
# keep them over a reboot (AlmaLinux: dnf install iptables-services)
service iptables save
```

IPv6 (ip6tables) the same with the IPv6 addresses; VRRP over IPv6 is
`-p vrrp` too. `-p vrrp` and `-p 112` are the same.

### nftables

```
table inet acme {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport { 80, 443 } accept
    meta l4proto { udp, tcp } th dport 53 accept     # acme's own DNS server, if used
    ip saddr 192.0.2.12 tcp dport 5432 accept
    ip saddr 192.0.2.12 ip protocol vrrp accept
    tcp dport 22 accept
    icmp type echo-request accept
  }
}
```

### A firewall in front of the nodes, or between VLANs

- TCP 443 from the users' and administrators' networks to the VIP address
  **and** to both nodes (a browser may be sent to a node's own name).
- Out to the CAs and the targets from **both** nodes: either may be the one
  that renews and deploys.
- UDP and TCP 53 from the internet to the addresses the NS records name, when
  acme's own DNS server answers DNS-01.

---

## Troubleshooting

| Seen | Why, and what to do |
|---|---|
| a node's row: *failed: keepalived ... is not acme's* | `/etc/keepalived/keepalived.conf` exists for something else: move it away, *Try again* |
| *failed: nginx does not take it* | the reason is nginx's own; nothing was changed. Usually a certificate/key pair or a cipher list |
| *no interface here holds ...* | choose the interface for that node |
| holds it: neither; may hold it: no - *its pages do not answer* | nginx or PHP-FPM down on that node: `systemctl status nginx php-fpm` |
| *in maintenance* | `acme --maintenance off` |
| the address on neither node, both healthy | `journalctl -u keepalived`; VRRP blocked one way; a different VRRP id on each (save again) |
| *being put in…* stays | `systemctl status acme-web.path acme-web.service`; `install.sh --upgrade` once on the command line puts the units in |
| the browser still sees the old certificate | it may be shown the other node's; check both cards, and the name it asks for |


## Where the VIP address goes back to (1.0.52)

Settings → High availability → The VIP address, *When the node it left is
well again*:

- **always back to NODE** (the default; the first node unless chosen): the
  preferred node gets 50 more VRRP priority while it is healthy, so the
  address returns to it within a few seconds after a failover. Moving the
  address by hand makes the other node the preferred one.
- **it stays where it is**: no preference. The node that holds the address
  (keepalived MASTER) keeps it; after a failover it stays on the node it went
  to, also when the first one is well again. It moves only when its node
  fails (maintenance, an upgrade, /healthz failing, the API not listening, the
  node gone) or when moved by hand (*Move it here*, `acme --vip-move NODE`) -
  and then stays there.

```bash
acme --vip-return acme1      # always back to acme1
acme --vip-return stay      # stays where it is
```

Every move is in Settings → High availability → **History**.
