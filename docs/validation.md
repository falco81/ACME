# Proving names: the challenges

An ACME CA (Let's Encrypt) issues a certificate only for names acme proves it
controls - by **DNS-01** (a TXT record at `_acme-challenge.NAME`) or **HTTP-01**
(a file at `http://NAME/.well-known/acme-challenge/TOKEN`). A challenge
(Settings → Validations, `cert_challenges`) says how; a certificate may use a
different challenge per name (`challenge_map`).

acme itself never has to be reachable from the internet: for DNS-01 the
records go to a DNS server (acme's own - only its port 53 - or somebody
else's); for HTTP-01 the files go over SSH to the web servers the names
already point at.

Wildcards (`*.example.com`) can only be proved by DNS-01.

## The modules

| Kind | What it does | Needs |
|---|---|---|
| `dns_builtin` | TXT records in **acme's own DNS server** ([dns-server.md](dns-server.md)) | a zone delegated to acme; `_acme-challenge.NAME CNAME NAME.<zone>` once per name |
| `rfc2136` | **dynamic UPDATE with TSIG** (hmac-sha256/-512/-384/-224/-sha1/-md5) to BIND, Knot, PowerDNS, Windows DNS; zone found by SOA | the primary's address; a key allowed to change TXT |
| `cloudflare` | Cloudflare API | an API token (Zone:DNS:Edit, Zone:Read) |
| `powerdns` | PowerDNS Authoritative HTTP API | API URL and key |
| `route53` | Amazon Route 53 (SigV4 signed here) | access key with ListHostedZonesByName, ListResourceRecordSets, ChangeResourceRecordSets, GetChange |
| `azure_dns` | Azure DNS (OAuth2 client credentials) | an app registration with DNS Zone Contributor |
| `gcloud_dns` | Google Cloud DNS (service account JWT, RS256 by openssl) | a service account key (JSON) with dns.admin |
| `hetzner` | Hetzner Console/Cloud API zones, or the old dns.hetzner.com | API token |
| `digitalocean` | DigitalOcean Domains | personal access token |
| `ovh` | OVHcloud API | application key/secret, consumer key on /domain/zone/* |
| `acme_dns` | an [acme-dns](https://github.com/joohoi/acme-dns) server | account(s); `_acme-challenge.NAME CNAME <fulldomain>` once |
| `ssh_dns` | commands on the DNS server over SSH: `nsupdate -l`, `nsupdate -k`, PowerShell `Add-DnsServerResourceRecord` (Windows DNS via OpenSSH), or your own (edit a zone file + `rndc reload`) | an SSH account there (sudo optional) |
| `script` | a program on this machine (`present`/`cleanup`, dehydrated- or lego-style), `ACME_*` variables | the program |
| `manual` | shows the record to put in by hand; waits until the zone's name servers have it (or until it is confirmed) | someone there |
| `http_local` | HTTP-01 answered by acme's own nginx on port 80 | the name pointing at acme, port 80 open |
| `http_ssh` | HTTP-01: the token file written over SSH on **every** web server the name points at | an SSH account on each, the nginx block below |

### Waiting for DNS

Every DNS-01 module (except `dns_builtin`, which asks acme's own server) waits
before the CA is told to look:

1. **Where the record goes.** `_acme-challenge.NAME` is looked up first; if it
   is a CNAME (a delegation to another zone - to acme-dns, to a zone at a
   provider with an API) the record is written where the CNAME ends, as the CA
   will follow it ("Follow a CNAME", on by default).
2. **The zone** comes from the provider (its zone list) or from the SOA.
3. **Seen by** (`propagation`): by default every name server of the zone (its NS
   records) is asked straight, without recursion, until each has the value - so
   no resolver caches "not there" in the meantime. `auth+public` then also
   asks public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9); `resolvers` asks only the
   resolvers set; `none` asks nothing. When the name servers cannot be reached
   from acme (an outbound firewall), the resolvers are asked instead, and the
   job says so.
4. **Delay**: at least that many seconds after the record is put in.

The ACME issuer decides how long it waits in all (its own setting); the job
log says, server by server, what has been seen.

### Several orders at once

Every module adds its value next to values already at the name and takes only
its own away again, so `example.com` and `*.example.com` (one TXT name, two
values), or two renewals at once, do not take each other's records away.
(acme-dns keeps only the newest two values per account: give a certificate
with more names one account per name - the `accounts` field.)

## HTTP-01 on web servers over SSH (`http_ssh`)

acme never takes connections from the internet. The names point at your web
servers (several behind DNS round-robin or a load balancer); for each
validation acme

1. connects over SSH to **every** host listed (`host` or `host:port`; key or
   password; host keys pinned as `known_hosts` lines - `ssh-keyscan -t ed25519 HOST`),
2. writes `/var/www/acme-challenge/.well-known/acme-challenge/<token>` (the
   folder is made if missing; with sudo: written to `/tmp`, then `sudo -n install`),
   runs the optional *command after*,
3. fails - and takes the file off the hosts that got it - unless **all** hosts
   succeeded (the CA may ask any of them),
4. before the CA is asked, fetches `http://<each host's address>/.well-known/acme-challenge/<token>`
   with `Host: NAME` (or `http://NAME/...`, or nothing) and compares,
5. afterwards removes the file from every host.

**Test** writes a probe file on each host, reads it back over SSH, fetches it
over HTTP from that host, and removes it.

The SSH account needs only to write that folder. Without sudo:

```
useradd -r -m -s /bin/sh acme
install -d -o acme -g acme -m 0755 /var/www/acme-challenge/.well-known/acme-challenge
# the public key acme shows: into ~acme/.ssh/authorized_keys, best with
# restrict,from="<acme's address>" ssh-ed25519 AAAA...
```

With sudo, a sudoers line for exactly that:

```
acme ALL=(root) NOPASSWD: /usr/bin/mkdir -p /var/www/acme-challenge/.well-known/acme-challenge, \
     /usr/bin/install -m 644 /tmp/.acme-* /var/www/acme-challenge/.well-known/acme-challenge/*, \
     /usr/bin/rm -f /var/www/acme-challenge/.well-known/acme-challenge/*
```

### nginx on those web servers

A server on port 80 that serves only the challenge files, from that folder, and
sends everything else to HTTPS (or 404s it). `default_server`, so it also
answers when asked by address with any `Host` (acme's check and the CA alike):

```nginx
# /etc/nginx/conf.d/acme-challenge.conf
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # HTTP-01: files acme writes over SSH, nothing else
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme-challenge;
        default_type text/plain;
        try_files $uri =404;
        autoindex off;
        access_log /var/log/nginx/acme-challenge.log;
    }

    # everything else: to HTTPS (or: return 404;)
    location / {
        return 301 https://$host$request_uri;
    }
}
```

With a server block of your own on port 80 already, put just the `location
^~ /.well-known/acme-challenge/ { root /var/www/acme-challenge; ... }` into it
(before any redirect). Apache: `Alias /.well-known/acme-challenge/
/var/www/acme-challenge/.well-known/acme-challenge/` with `Require all granted`.

Behind a load balancer: let `/.well-known/acme-challenge/` through on port 80
to every pool member (no redirect to HTTPS before it - a redirect to HTTPS is
followed by the CA, but only to port 443 of the same name).

## DNS-01 over SSH (`ssh_dns`)

* **BIND on that machine**: `nsupdate -l` uses BIND's local session key; the
  zone needs `update-policy local;` (or `{ grant local-ddns zonesub any; };`).
  The SSH user must read `/run/named/session.key` (group bind/named) or use sudo.
* **A TSIG key file there**: `nsupdate -k /etc/bind/acme.key`, sent to the
  server set (127.0.0.1 by default).
* **Windows DNS**: OpenSSH Server on the DNS server (or a machine with the
  DnsServer RSAT module, `-ComputerName`); the account in DnsAdmins. The zone
  must be set as DNS Manager shows it.
* **Your own commands**: `{fqdn} {relative} {zone} {value} {ttl} {name}` are
  put in shell-quoted, e.g. a zone file included by the real one:

  ```
  add:  printf '%s 60 IN TXT "%s"\n' {fqdn}. {value} >> /var/named/acme-challenge.inc && rndc reload {zone}
  del:  sed -i /{value}/d /var/named/acme-challenge.inc && rndc reload {zone}
  ```
  (the zone's SOA serial must change for secondaries: prefer `nsupdate -l`).

## RFC 2136 (`rfc2136`)

BIND:

```
tsig-keygen -a hmac-sha256 acme-key > /etc/bind/acme-key.conf    # include it in named.conf
zone "example.com" {
    type primary; file "...";
    update-policy { grant acme-key zonesub TXT; };   # TXT records only, anywhere in the zone
};
```

Knot: `acl: [{id: acme, key: acme-key, action: update, update-type: [TXT]}]`.
PowerDNS: `dnsupdate=yes`, the key in `tsigkeys`, `TSIG-ALLOW-DNSUPDATE` metadata
on the zone. Windows DNS signs updates only with GSS-TSIG (Kerberos), which acme
does not speak: use `ssh_dns` with PowerShell, or set the zone to "Nonsecure and
secure" dynamic updates, restrict it to acme's address, and leave the key empty.

**Test** sends an UPDATE whose only content is the prerequisite "the zone's
SOA exists" - the key, the zone and the server's permission are tried and
nothing is changed.

## A script (`script`)

```
#!/bin/sh
# /etc/acme/hooks/dns.sh present|cleanup RECORD VALUE
case "$1" in
  present) my-dns-cli add  "$2" TXT "$3" ;;
  cleanup) my-dns-cli del  "$2" TXT "$3" ;;
esac
```

The environment holds `ACME_ACTION ACME_NAME ACME_RECORD ACME_CHALLENGE_NAME
ACME_TXT ACME_TOKEN ACME_ZONE ACME_TTL` and the variables set on the challenge;
nothing of acme's own environment. Exit 0 or the order fails with the script's
last words.
