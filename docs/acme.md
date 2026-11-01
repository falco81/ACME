# Automatic certificates - ACME (1.0.169)

*Settings → Automatic certificates*, for a full administrator, off until switched
on. The certificate of the VIP address - and, where asked, each node's own - is
ordered from an ACME CA and renewed by itself when fewer than `acme_days` (30)
days are left - or, for a certificate that lasts less (short-lived certificates),
when a third of its life is left. A failed try is tried again after 6 hours; the alerts tell of a
certificate running out as always.

| Setting | |
|---|---|
| `acme_ca` | Let's Encrypt, its staging (to try - browsers do not trust it), or another (`acme_url`, `acme_ca_pem` for its root): step-ca, an internal CA |
| `acme_for` | the VIP address (or this node where there is none), each node's own name, or both |
| `acme_node_name` | a node's DNS name; empty: its full host name |
| `acme_challenge` | HTTP-01 or DNS-01 |
| `acme_key` | **Both: RSA 2048 + ECDSA P-256** (advised, the default), Both: RSA 4096 + ECDSA P-384, or one: ECDSA P-256 or P-384, RSA 2048, 3072 or 4096 |
| `acme_account_key` | the account's key: ECDSA P-256 (ES256), P-384 (ES384), RSA 2048/3072/4096 (RS256) - a change makes a new account |
| `acme_profile` | the CA's own, or classic, tlsserver, shortlived (6 days) - where the CA offers profiles |

**The keys** (1.0.196) are what Let's Encrypt takes: RSA of 2048, 3072 or 4096
bits, ECDSA P-256 or P-384 - for the account and for a certificate alike, never the
same key for both. **Both** is what it advises: an RSA certificate, given
by default, and a much smaller ECDSA one beside it, for the clients that take it -
two orders of the same name (the second has no challenge left to answer), and
nginx given the two (`ssl_certificate` twice, RSA first; the ECDSA files
`acme-ecdsa.pem/.key`, `acme-vip-ecdsa.pem/.key`). The keys show on the ACME card
(*Keys*), beside the certificate's key, beside the account and in the order's
steps. A certificate put in by hand on Certificates and TLS leaves the ECDSA one
out. Every renewal makes new keys; the account's key
is never one of a certificate.

**Profiles**: where the CA offers them (Let's Encrypt: classic, tlsserver,
shortlived), the one chosen is asked for; *shortlived* lasts 6 days and is renewed
at a third of its life, every two days or so. A CA without them makes its own.

**When it is renewed**: where the CA tells (ARI, RFC 9773 - Let's Encrypt does),
at a moment picked in the window the CA gives, asked every 6 hours - earlier too,
when the CA says so (a revocation). Each renewal tells the CA which certificate it
replaces. Otherwise, when fewer than `acme_days` days are left, or a third of its
life. The CA's Retry-After is waited for; the chain is the one the CA sends, never
one written in here. Let's Encrypt has no OCSP any more: nothing is stapled.

The account key (ECDSA P-256 unless chosen otherwise) is made once and kept sealed in
the database; every request is signed with it (ES256, ES384 or RS256, with openssl). An account the CA no longer knows
(deleted, deactivated) is made anew by itself, with a new key, and the request asked
again. The certificate and its key go
where an uploaded one goes, and every node serving it puts it in.

## In a cluster

The VIP address's certificate is renewed by one node - the first by name of the
nodes heard from; a node's own by that node. Both nodes serve it. *Order it now*
works for any of them from any node (1.0.170): the CA's question and the
certificate are kept in the database, and the node it is for - every node, for
the VIP address - puts it in.

## The names (1.0.170)

Each card has *Its name…*: the DNS name of that certificate - this node's, the
other node's, or the VIP address's (the same as *Settings → High availability →
the VIP address's name*). Unsaid, a node's certificate is for the name of the
certificate it has now (as *Certificates and TLS* shows it), else the full host
name that node says of itself. A node's own settings show the other nodes'
values under their box anywhere on the pages, each changed from there.

The certificate has the name as its subject (CN) and among its alternative names
(SAN, DNS). An ACME CA checks only names: it takes no organisation, unit, city,
state or country (Let's Encrypt leaves them out whatever the request says) - the
request acme makes has only the name. For a certificate with those, use
*Certificates and TLS → Request (CSR)* and a CA of your own.

## Beside Certificates and TLS (1.0.170)

Each certificate says who renews it - *ACME renews it*, or *its own certificate
is kept*. Switching ACME on takes in the certificates with none, a self-signed
one or one from the CA; **one uploaded or answered to a request (a CA of your
own) is kept as it is**: ACME does not replace it until *Look after it* (or
*Order it now*) on its card. Putting a certificate in by hand on *Certificates
and TLS* - upload, self-signed - takes it out of ACME's care (asked first); *Let
go* too. The TLS settings of a certificate (protocols, ciphers, DH, HSTS) stay
as they are whichever way the certificate came.

## HTTP-01 - the CA asks port 80

nginx sends `http://NAME/.well-known/acme-challenge/TOKEN` to `acme.php`, which
asks the daemon; the answer is kept in the database, so **whichever node has the
VIP address answers it**. Every node's port-80 server has the names in its
`server_name` and the location - put in by the root helper when ACME is switched
on. *Try port 80* asks it from the node as the CA will (a firewall in front of
the servers may still stop the CA from outside). The name must point at the web
address (or the node), and port 80 must be open to the CA.

## DNS-01 - nothing open to the internet

For servers the CA cannot see: the CA reads `_acme-challenge.NAME TXT`. Who puts
it there (`acme_dns`):

- **RFC 2136** (BIND, PowerDNS, Knot, ...): `nsupdate` (`dnf install bind-utils`)
  with a TSIG key - `acme_dns_server`, `acme_dns_zone`, `acme_dns_tsig_name`,
  `acme_dns_tsig_alg`, `acme_dns_tsig_secret` (sealed). The key is written to a
  file only acme reads (0600) for the moment nsupdate runs - never on its command
  line. On BIND, a key allowed to change only those records:

  ```
  tsig-keygen -a hmac-sha256 acme-acme. > /etc/named/acme-acme.key
  zone "example.cz" {
      ...
      update-policy { grant acme-acme. name _acme-challenge.acme.example.cz. TXT; };
  };
  ```
- **Cloudflare**: `acme_dns_token` (sealed), a token with *Zone - DNS - Edit*.
- **acme-dns**: `acme_dns_url`, `acme_dns_user`, `acme_dns_key` (sealed),
  `acme_dns_subdomain` from its registration; `_acme-challenge.NAME` a CNAME to
  `SUBDOMAIN.auth.example.cz` once.
- **deSEC** (1.0.170, free - desec.io): `acme_desec_domain` (your domain there,
  `yourname.dedyn.io` or one of your own whose DNS is at deSEC) and
  `acme_desec_token` (sealed). A name outside that domain gets a CNAME in your
  DNS, once - see below. deSEC's records live at least an hour (its minimum
  TTL). acme asks deSEC's own name servers (`ns1.desec.io`, `ns2.desec.org` - asked
  straight, never through a resolver) until both have the record, then waits a
  minute more before it asks the CA: deSEC is anycast, and the CA checks from
  several places of the world - one deSEC had not reached yet answered
  `During secondary validation: NXDOMAIN`.
- **By hand**: the record is shown on the page; the order waits up to an hour
  for *It is in DNS*. Renewals wait for you the same way.

### A CNAME in your DNS, once (1.0.170)

The CA follows a CNAME at `_acme-challenge.NAME`. So the TXT records can go into
a zone acme may write to - deSEC, a zone at Cloudflare, one your BIND serves
(`acme_dns_alias`, *The TXT records go into*) - while your own DNS, wherever it
is and whether or not it has an API, only has one CNAME per name, put in once:

```
_acme-challenge.acme.example.cz.   CNAME  _acme-challenge.acme.yourname.dedyn.io.
_acme-challenge.acme1.example.cz.  CNAME  _acme-challenge.acme1.yourname.dedyn.io.
_acme-challenge.acme2.example.cz.  CNAME  _acme-challenge.acme2.yourname.dedyn.io.
```

**A domain of your own at deSEC** (`acme.example.cz` rather than a free
`yourname.dedyn.io`): the zone above it must send the internet there - once, in
`example.cz`, wherever its DNS is kept:

```
acme.example.cz.   NS   ns1.desec.io.
acme.example.cz.   NS   ns2.desec.org.
```

(and the DS records deSEC shows, if `example.cz` is signed with DNSSEC). Without
them the CA follows the CNAME into a name nobody serves and says `NXDOMAIN looking
up TXT for _acme-challenge.NAME` - though the record is there at deSEC. A
`dedyn.io` domain is delegated by deSEC itself.

The card **In your DNS** on the page lists exactly these for the certificates
asked for (and, for HTTP-01, where each name is to point), with the steps of the
way chosen and **Check DNS**, which looks each record up from the node as the CA
will. Renewals then go by themselves: acme puts the TXT record in at deSEC, the CA
follows the CNAME, acme takes it away again.

After the record is put in, `acme_dns_wait` seconds (30) are waited for DNS to
carry it; it is taken away again once the CA has looked (RFC 2136, Cloudflare).

## No DNS server of your own, nothing open to the internet

DNS-01 needs the CA to read a TXT record of the name - so whoever keeps the DNS
of the domain has to let acme put it there:

- **deSEC** (free, desec.io): an account and a free domain (`yourname.dedyn.io`)
  there, a token, and one CNAME per name in your own DNS - once. Nothing else
  moves; acme needs only to reach `desec.io` and the CA over HTTPS. Renewals go by
  themselves. The simplest where your DNS has no API.
- **Cloudflare** (free plan): move the DNS of the domain to Cloudflare (the
  domain stays where it is registered; only its name servers change), make an API
  token with *Zone - DNS - Edit* for that zone, choose *Cloudflare*. acme needs
  only to reach `api.cloudflare.com` and the CA over HTTPS (through the proxy
  where one is set). Fully automatic, renewals too.
- **acme-dns**: one CNAME, put in once at whoever keeps your DNS -
  `_acme-challenge.acme.example.cz CNAME <subdomain>.auth.acme-dns.io` - and the
  acme-dns server takes the records from then on. A public acme-dns server is a
  service run by somebody else; your own needs a machine reachable from the
  internet on port 53.
- **The DNS provider's own API** (other than Cloudflare): not built in - delegate
  `_acme-challenge.NAME` by a CNAME to a zone at Cloudflare (or acme-dns) instead.
- **A CA of your own** (step-ca, an internal ACME CA): HTTP-01 inside the network,
  nothing on the internet at all - for browsers that trust that CA.

