# DNS server over SSH - setup for acme

acme signs in to **your own authoritative DNS server over SSH** and puts the TXT record straight into the zone there - no API and no TSIG key over the network. It knows BIND (`nsupdate -l`, `nsupdate -k`, or the zone file edited + `rndc reload`), PowerDNS (`pdnsutil` or its HTTP API on localhost), Knot DNS (`knotc` transaction), NSD (zone file + `nsd-control reload`), dnsmasq (`txt-record` lines), Unbound (`unbound-control local_data`), Windows DNS (PowerShell over OpenSSH) and commands of your own. Only acme's own value is added and taken away; other TXT records at the name stay.

**Find out what runs there** (the button under the form) signs in and runs **read-only** commands only, then fills the form in: which server, its zones and files, keys, whether sudo works.

## What you need

- SSH (TCP 22, or your port) from acme to the DNS server - the zone's **primary** (secondaries get the change by NOTIFY).
- A dedicated account there (e.g. `acme`) with acme's public SSH key.
- The rights that account needs for the chosen *How* (below) - a group membership or a narrow sudo rule.

## Set up the DNS server

1. Create the account and allow acme's key (made in acme's form, ed25519):

   ```sh
   useradd -m -s /bin/sh acme
   install -d -m 700 -o acme -g acme ~acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' >> ~acme/.ssh/authorized_keys
   chown acme:acme ~acme/.ssh/authorized_keys; chmod 600 ~acme/.ssh/authorized_keys
   ```

2. Pin the server's host key in acme (*Host keys*):

   ```sh
   ssh-keyscan -t ed25519 ns1.example.com
   ```

3. Give the rights for the way you choose - **BIND with `nsupdate -l` is the simplest** (no key to manage):

   ```text
   zone "example.com" {
       type primary;
       file "/var/lib/bind/db.example.com";        # a directory named may write (journal)
       update-policy { grant local-ddns zonesub TXT; };
   };
   ```

   then `rndc reconfig`, and let the account read `/run/named/session.key`: `usermod -aG bind acme` (Debian; group `named` on RHEL), or *Through sudo* with:

   ```text
   acme ALL=(root) NOPASSWD: /usr/bin/nsupdate
   ```

   Other ways, in short:

   | How | Rights the account needs |
   |---|---|
   | `nsupdate -k KEYFILE` | read a TSIG key file (`tsig-keygen -a hmac-sha256 acme-key`), granted in `update-policy` |
   | BIND zone file | write the file and its directory, run `rndc` (group `bind`), or sudo for `/bin/sh -s` (a root shell - prefer the group) |
   | `pdnsutil` | `acme ALL=(root) NOPASSWD: /usr/bin/pdnsutil` (or the backend's group) |
   | PowerDNS HTTP API | `api=yes`, `api-key=…`, `webserver=yes`, `webserver-address=127.0.0.1`; `curl` on the server |
   | Knot | group `knot` (the control socket) or `acme ALL=(root) NOPASSWD: /usr/sbin/knotc` |
   | NSD | `nsd-control-setup` done; write the zone files (sudo) |
   | dnsmasq | `conf-dir=/etc/dnsmasq.d/,*.conf`; sudo for the file and `systemctl restart dnsmasq` |
   | Windows DNS | OpenSSH Server; the account in **DnsAdmins** |

## Fill in acme

| acme field | What to put there |
|---|---|
| DNS server | `ns1.example.com:22` |
| User / Signs in with / The SSH key | `acme`, a private key (made here) |
| Host keys | the `ssh-keyscan` line(s); or *Trust the first key seen* |
| How | as *Find out what runs there* suggests, e.g. `nsupdate -l` |
| Through sudo | on only when you set a sudo rule above |
| Zone / Zones there | empty (filled in by *Find out*), or the zone(s) |
| Key file there / Zone files / … | only the fields shown for the chosen *How* |
| TTL (s) | 60 (advanced) |

## Check it

- **Find out what runs there**: read-only, shows what acme would do.
- **Test** changes nothing: it checks nsupdate and the key, reads and checks zone files, runs `rndc status` / `pdnsutil list-all-zones` / `knotc zone-status` … `nsupdate -l` cannot be tried without changing the zone.
- A **dry run** of the certificate puts a random test TXT record in, waits until the name servers answer it, and takes it away.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.example.com
```

## Common problems

| Problem | Fix |
|---|---|
| Host key refused | The server's key changed or is not pinned - update *Host keys*. |
| `nsupdate`: "update failed: REFUSED" | `update-policy` lacks `local-ddns` (or the key) for TXT. |
| "permission denied" on `session.key` | Add the account to group `bind`/`named`, or use sudo. |
| `sudo: a password is required` | The sudoers line is missing or names another path (`command -v nsupdate`). |
| Zone file refused | `$INCLUDE`, several SOAs or a raw/map zone - use a dynamic zone (`nsupdate`) instead. |
| Windows: record not removed | *Zone* must be the zone exactly as DNS Manager shows it. |
