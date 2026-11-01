# acme's own DNS server

acme carries a small **authoritative** DNS server (`acmelib/certs/dnsserver.py`)
so that DNS-01 needs nobody's DNS credentials: your DNS points the
`_acme-challenge` names at acme **once**, and from then on acme puts in and
takes away the TXT records itself, in its own zone.

It answers only for its own zones, never recursively, on UDP and TCP.

## How a domain is pointed at acme

You need one zone that acme serves, say `acme.example.net`, delegated to acme
from its parent `example.net`:

```
; in example.net (its parent zone), once
acme.example.net.        NS     ns1.acme.example.net.
acme.example.net.        NS     ns2.acme.example.net.        ; the second node of a cluster
ns1.acme.example.net.    A      203.0.113.10                 ; glue: acme's public address
ns2.acme.example.net.    A      203.0.113.11
```

UDP and TCP port 53 of those addresses must reach acme (a port forward on the
firewall is enough; nothing else of acme has to be reachable).

Then, for every name a certificate holds, **once**, in that name's own DNS:

```
_acme-challenge.www.example.com.   CNAME   www.example.com.acme.example.net.
_acme-challenge.example.com.       CNAME   example.com.acme.example.net.     ; also for *.example.com
```

The CA follows the CNAME and asks acme. A wildcard `*.example.com` is proved at
`_acme-challenge.example.com`, so `example.com` and `*.example.com` share one
CNAME - acme serves both TXT values at once.

### The choices of the challenge `dns_builtin`

| Where in acme's zone | `_acme-challenge.www.example.com` is a CNAME to | When |
|---|---|---|
| NAME.zone (default) | `www.example.com.acme.example.net.` | each name apart; the usual choice |
| a fixed label | `validation.acme.example.net.` | one CNAME target for everything (a DNS hoster's template) |
| `_acme-challenge.NAME` itself | - (no CNAME) | you delegate `_acme-challenge.www.example.com` (or a whole zone) to acme by NS and list it among acme's zones |

NS delegation of one name, instead of a CNAME:

```
; in example.com
_acme-challenge.www.example.com.   NS   ns1.acme.example.net.
```

and `_acme-challenge.www.example.com` added to **Settings → DNS server → zones**.

**Test** on the challenge prints exactly these records for your settings, asks
acme's server, checks through public resolvers that the internet sends the zone
to acme, puts a short-lived probe record in and looks for it from outside, and
looks up the CNAME of every name listed under "Names to check".

## Settings

| Setting | Default | |
|---|---|---|
| `dns_listen` | `0.0.0.0,::` | addresses to listen on, comma separated (IPv6 missing on the machine is no failure) |
| `dns_port` | `53` | |
| `dns_zone` | - | the zone(s), comma separated; the first is the one relative names belong to |
| `dns_ns_names` | `ns1.<zone>` | its NS records (the same for every zone) |
| `dns_ns_addresses` | - | glue: `ns1.acme.example.net=203.0.113.10, ns2...=...`, or bare addresses (one per NS name in order when the counts match, else all for each) |
| `dns_soa_mail` | `hostmaster.<zone>` | the SOA's mailbox, `hostmaster@example.net` |
| `dns_ttl` | `60` | TTL of records without one, of the SOA/NS, and the negative TTL |
| `dns_static` | - | records of your own, a line each: `name type value [ttl]` or `name ttl type value`; `@` is the apex, a name ending in `.` is absolute, others are relative to the first zone; `;` and `#` begin comments |
| `dns_rate` | `100` | answers a second to one source network (/24, /56) before it is slowed; `0` switches the limit off |
| `dns_cache` | `1` | seconds before the records are read from the database again |

Examples of `dns_static`:

```
@                CAA   0 issue "letsencrypt.org"
www              A     203.0.113.80 300
_dmarc  3600     TXT   "v=DMARC1; p=none"
mail             MX    10 mx.example.net.
```

## What it answers

* **SOA**, **NS** (with glue A/AAAA for name servers inside its zones in the
  additional section), **A/AAAA**, **TXT**, **CNAME**, **CAA**, **MX**, **SRV** -
  from the table `dns_records` and the static lines. `ANY` gets what is at the name.
* A CNAME is followed while the target is in acme's zones; outside, the
  resolver follows it.
* A name that is not there: **NXDOMAIN** with the SOA in the authority section.
  A name that is there without the type asked (or an empty non-terminal such as
  `example.com.acme.example.net` above `_acme-challenge…`): **NOERROR/NODATA**
  with the SOA.
* Names outside its zones, zone transfers (AXFR/IXFR) and dynamic updates:
  **REFUSED**; other opcodes **NOTIMP**. Recursion is never offered (RA=0).
* **EDNS0**: the OPT is echoed with 1232 bytes of room (the DNS flag day size);
  a version other than 0 gets BADVERS. An answer larger than the room (512
  without EDNS) is sent **truncated (TC)** and the resolver asks again over TCP.
* Names are matched regardless of case and the question goes back byte for byte
  (0x20 randomisation keeps working).
* Several TXT values at one name are all answered - two orders, or a name and
  its wildcard, at the same moment.
* Rows of `dns_records` past their `expires` are not answered; an hour later the
  leading node deletes them.
* The **rate limit** is a token bucket per source network; over it, every other
  answer is dropped and the rest go back empty with TC (a real resolver then asks
  over TCP, which is not limited; a reflection attack gets nothing to amplify).
  TCP: at most 64 connections, 100 questions and 10 s idle each.
* The parser never raises on what arrives: a message that cannot be read gets
  FORMERR (or nothing, when not even its header is there); a message that is an
  answer is never answered.

## A cluster

Both nodes run the server and read the same `dns_records` (shared or
replicated database), at most a second old, so either answers the same - put
both in the NS records. The SOA serial is the newest record's time plus a sum
of the settings that shape the answers, so both nodes give the same serial.
If the database cannot be read, the last records read are answered for a
minute, then SERVFAIL (never "not there", which resolvers would keep).

## When it does not listen

`acme --status`, `GET /api/dns` and the challenge's Test show `state()`:
`listening`, `failed` (each address and protocol with the reason), `queries`,
the counters by outcome, `last_error`.

* *permission denied for port 53*: the daemon runs as the user acme and needs
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` (and `CapabilityBoundingSet=` to
  include it) in `acme.service` - the installer sets it.
* *port 53/udp is already taken*: systemd-resolved's stub listens on
  127.0.0.53:53 - listen on the public address only (`dns_listen=203.0.113.10`),
  or `DNSStubListener=no` in `/etc/systemd/resolved.conf`; or another DNS server
  runs on the machine.
* *not an address of this machine*: `dns_listen` names an address the machine
  does not have (after a change of address, see Settings → Network).

The firewall must let UDP and TCP 53 in (Settings → Firewall).

## Checking it by hand

```
dig @ns1.acme.example.net acme.example.net SOA +norec
dig @ns1.acme.example.net www.example.com.acme.example.net TXT +norec
dig _acme-challenge.www.example.com TXT          # through your resolver: CNAME + TXT
```
