# acme's own DNS server - setup for acme

With this challenge acme answers the DNS-01 TXT records **itself**, from its built-in authoritative DNS server - no credentials for anybody's DNS are needed. The counterpart to set up is your DNS: once, you delegate a zone to acme (e.g. `acme.example.net`) and, once per name, point `_acme-challenge.NAME` at acme with a CNAME. After that, acme puts in and takes away the TXT records on its own. See also `docs/dns-server.md`.

## What you need

- A zone for acme's DNS server, e.g. `acme.example.net`, set in **Settings → DNS server** (`dns_zone`), with its NS names and glue addresses (`dns_ns_names`, `dns_ns_addresses`).
- **UDP and TCP port 53** of acme reachable from the internet (a public address or a port forward on the firewall). Nothing else of acme needs to be reachable.
- Access to the parent zone (`example.net`) to add the delegation, and to the DNS of each name to add one CNAME.

## Set up your DNS

1. In the **parent zone** (`example.net`), delegate acme's zone - once:

   ```text
   acme.example.net.        NS   ns1.acme.example.net.
   acme.example.net.        NS   ns2.acme.example.net.   ; a second node of a cluster
   ns1.acme.example.net.    A    203.0.113.10            ; glue: acme's public address
   ns2.acme.example.net.    A    203.0.113.11
   ```

2. Open UDP and TCP port 53 to acme on the firewall (or forward them).
3. For **each name** of a certificate, once, in that name's own DNS (choose by *Where in that zone*):

   | Where in that zone | Record |
   |---|---|
   | NAME.zone (default) | `_acme-challenge.www.example.com. CNAME www.example.com.acme.example.net.` |
   | a fixed label | `_acme-challenge.www.example.com. CNAME validation.acme.example.net.` |
   | `_acme-challenge.NAME` itself | `_acme-challenge.www.example.com. NS ns1.acme.example.net.` - and add `_acme-challenge.www.example.com` to acme's zones |

   A wildcard `*.example.com` uses the same record as `example.com`.

## Fill in acme

| acme field | What to put there |
|---|---|
| acme's zone | One of the zones of Settings → DNS server, e.g. `acme.example.net`; empty = the first |
| Where in that zone | `NAME.zone`, `a fixed label`, or `_acme-challenge.NAME itself` - must match the records above |
| The fixed label | With *a fixed label*: the label, default `validation` |
| Refuse a name not pointed at acme | On: a name whose CNAME does not lead to acme fails at once with the record to add |
| Names to check in Test | Names whose CNAME Test should look up, one per line |
| Test from outside | On (default): Test puts a short-lived TXT record in and asks public resolvers for it |
| TTL of the records (s), Public resolvers, Resolvers | (advanced) defaults are fine |

## Check it

- **Test** in acme prints the records to put in for your settings, asks acme's own server, checks through public resolvers that the internet sends the zone to acme, puts a probe record in and looks for it from outside, and looks up the CNAME of every name under *Names to check in Test*.
- From any machine on the internet:

  ```sh
  dig +short NS acme.example.net
  dig @203.0.113.10 SOA acme.example.net +norecurse
  dig +short CNAME _acme-challenge.www.example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `acme's DNS server does not answer on … port 53` | The server is off or listens elsewhere - see Settings → DNS server. |
| `… is not delegated to acme yet` | The NS (and glue A) records in the parent zone are missing or wrong. |
| `a test record … was not seen` | UDP/TCP 53 is not reachable from the internet - check the firewall / port forward (TCP too). |
| A name fails with "not pointed at acme" | Add its `_acme-challenge` CNAME (Test shows the exact record). |
