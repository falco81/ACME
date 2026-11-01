# Settings → DNS: which DNS servers acme asks

acme looks names up for many things: the CNAME at `_acme-challenge` of a name,
the zone and its name servers, whether a TXT record can be seen, the address of
a CA, of a DNS provider's API, of a target. Settings → DNS says, for each of
these **functions**, which DNS servers are asked: named **sets** of servers,
added, tested and chosen on one card.

This is not acme's own DNS server (Settings → DNS server,
[dns-server.md](dns-server.md)), which *answers* others.

## The sets

A set is a name, its servers, how they are asked, a timeout and a note.

| | |
|---|---|
| Name | as every name in acme: letters, digits, spaces and `. _ @ + -`, starting with a letter or a digit, 120 at most (`store.safe_name` / `NAME_RE`) |
| Servers | one address a line, at most 8, asked in their order until one answers (NOERROR or NXDOMAIN): `192.0.2.53`, `192.0.2.53:5353`, `2001:db8::53`, `[2001:db8::53]:5353` - addresses only, a DNS server is never looked up by a name |
| Protocol | **UDP, TCP when an answer is cut short** (the default); **TCP only**; **DNS over TLS** (RFC 7858, port 853 unless said; the server's certificate is checked against *Server name for TLS*, else against its address) |
| Timeout | how long each server is waited for, 0.5 to 30 s (3 s) |

Two are there from the start:

- **The system's** - built in, never changed or deleted: the servers of
  `/etc/resolv.conf`, read each time, as the machine has them (Settings →
  Network sets them).
- **Public** - Cloudflare, Google and Quad9 (1.1.1.1, 8.8.8.8, 9.9.9.9): made
  once, at the first start of this version. It may be changed or deleted;
  deleted, it is not made again.

**Test** looks a name up through a set - A, AAAA, TXT, CNAME, NS, MX, SOA,
CAA, SRV or PTR - asking every server of the set at once, its own way, and
shows what each answered and how long it took, the server whose answer counts
(the first in the set's order that answered) and the records. From the form,
Test tries the set as it is typed, before it is saved.

## The functions

| Function | What it looks up | Default |
|---|---|---|
| **Validation checks** (`validation`) | the guides, the readiness of a certificate, the check before the CA is asked, dry runs, the wait for a DNS record: the CNAME at `_acme-challenge`, the zone (SOA), its name servers (NS), the TXT record, the address a name points at for HTTP-01 (`_dns.py`, `_common.py` DnsChallenge/HttpChallenge, `dns_builtin`, `readiness.py`, `httpinfo.py`) | The system's |
| **The public view** (`public`) | "as the internet sees it": whether public resolvers see the test value of a dry run (`auth+public`), the delegation of acme's own DNS server | Public |
| **CAs and APIs** (`apis`) | the names of the HTTPS addresses modules reach with `ctx.http` - ACME directories, DNS providers' APIs, commercial CAs' APIs | The system's |
| **Targets** (`targets`) | the names of targets and servers acme reaches over SSH or their API while it deploys a certificate or puts a file in place (HTTP-01 over SSH) | The system's |
| **The appliance's own ACME** (`acme`) | Settings → Automatic certificates: the CA of this server's own certificates, its DNS API, whether the TXT record is seen | The system's |
| **Mail going direct** (`mail`) | the recipients' MX records and their servers' addresses | The system's |

A function asks the set chosen for it; with none chosen, the setting it had
before this card if that is set - **DNS servers for ACME** (`acme_resolvers`)
for the validation checks and the appliance's own ACME, **DNS servers for the
recipients' domains** (`mail_dns`) for mail - so an installation that set those
goes on as it did (the card says so under the function); else its default.
Choosing "The system's" explicitly overrides those old settings too.

A validation's own fields **Resolvers** and **Public resolvers** still come
first, for that validation alone (empty: Settings → DNS). The value those
fields had as their default before (`1.1.1.1 8.8.8.8 9.9.9.9`) counts as
empty, so a validation saved with it follows the card.

The validation guide says which sets it asked ("DNS looked up through
'...', the public view through '...'"), the public-resolver step says "asked
through 'Public' (1.1.1.1, ...)", and a job's debug lines say "names looked up
through the DNS set ...". The card's first table shows where each set is used.

Always the system's resolver (`/etc/hosts`, nsswitch), whatever is chosen: the
database, the other node of a cluster, the proxy, Active Directory, syslog and
isemon, SNMP, the backups' destinations and the names in the firewall's rules.

### How it works

- `acmelib/certs/dnssets.py`: `dns_set_for(purpose)` -> (set, how);
  `resolver(purpose)` -> a `Resolver` - a list of the servers, so everything
  that took a list of resolvers takes it, which also asks them its own way
  (`_dns.ask_any` hands the question to it). `_dns.resolver(purpose, given, ctx)`
  is what the modules call.
- Names looked up through `socket.getaddrinfo` - `ctx.http` (urllib), a
  target's own connections during a deployment - are redirected to the set in
  the thread that asks, as the engine's `acme_dns_scope()` does for its own
  ACME (`with dnssets.scope('apis'): ...`). The proxy, the database and the
  other node are never redirected.
- SSH (an outside program) is given the address the set answers
  (`-o HostName=`, the host key still checked under acme's alias).
- The engine's own DNS client (the appliance's ACME, mail) asks
  `dns_set_servers(purpose)` (engine part 272): it speaks port 53, UDP then
  TCP, so only a set's servers on port 53 are used there.
- The sets are the tables `dns_sets` and `dns_set_uses` (`schema.py`): in
  every backup, in the configuration's export, and on both nodes of a cluster.
  They are read from the database at most every 5 seconds.

## Roles

Everybody signed in sees the card and may test a set kept; a full
administrator adds, changes, deletes and chooses, and tests a set not saved
yet. Every change is an event (Settings: "the DNS set ... was added by ...").

## The API and the command line

    GET  /api/dnssets             the sets, the functions, where each set is used
    POST /api/dnssets/save        {name, old_name?, servers, protocol, tls_name, timeout, note}
    POST /api/dnssets/delete      {name}
    POST /api/dnssets/assign      {purpose, set}    ('' : its default)
    POST /api/dnssets/test        {name, qname, qtype}   (or a set's fields instead of name)

    acme --dns-sets
    acme --dns-set-add "Company DNS" --servers 10.0.0.53,10.0.1.53 [--protocol tcp] [--dns-timeout 2] [--note ...]
    acme --dns-set-add "Quad9 TLS" --servers 9.9.9.9 --protocol dot --tls-name dns.quad9.net
    acme --dns-set-edit "Company DNS" --servers 10.0.0.54 [--name NEW]
    acme --dns-set-test "Company DNS" intranet.example.com A
    acme --dns-assign validation "Company DNS"
    acme --dns-assign validation default
    acme --dns-set-del "Company DNS" --yes

The console has it under Certificates → DNS sets.
